//! LUKS2 integration via the `cryptsetup` CLI (>= 2.4).
//!
//! The binding state lives in a LUKS2 *token* in the volume header - the same place Clevis
//! and systemd-cryptenroll keep theirs. That keeps the state with the volume and lets the
//! initramfs find it without any baked-in files.
//!
//! Updates (key rotation) are crash-safe without relying on newer cryptsetup features: the new
//! state is imported as a *second* token with a higher generation number, then the old token
//! is removed. Each step is one atomic LUKS2 metadata commit; readers always use the token
//! with the highest generation, so an interruption at any point leaves a usable binding.

use crate::state::{run_with_stdin, validate, ClientState, StateStore};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const TOKEN_TYPE: &str = "zknbe";

fn cryptsetup() -> Command {
    Command::new(std::env::var("ZKNBE_CRYPTSETUP").unwrap_or_else(|_| "cryptsetup".into()))
}

fn run(cmd: &mut Command) -> Result<Vec<u8>> {
    run_with_stdin(cmd, b"")
}

pub struct Header {
    pub keyslots: Vec<u32>,
    /// (token id, token JSON)
    pub tokens: Vec<(u32, Value)>,
}

pub struct Binding {
    pub token_id: u32,
    pub keyslot: u32,
    pub generation: u64,
    pub state: ClientState,
    /// Older zknbe tokens left behind by an interrupted update.
    pub stale_tokens: Vec<u32>,
}

fn numeric_keys(v: Option<&Value>) -> Vec<u32> {
    v.and_then(Value::as_object)
        .map(|m| m.keys().filter_map(|k| k.parse().ok()).collect())
        .unwrap_or_default()
}

pub fn parse_header(json_text: &str) -> Result<Header> {
    let meta: Value =
        serde_json::from_str(json_text).context("cannot parse LUKS2 metadata from cryptsetup")?;
    let mut tokens: Vec<(u32, Value)> = meta
        .get("tokens")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.parse().ok()?, v.clone())))
                .collect()
        })
        .unwrap_or_default();
    tokens.sort_by_key(|(id, _)| *id);
    let mut keyslots = numeric_keys(meta.get("keyslots"));
    keyslots.sort_unstable();
    Ok(Header { keyslots, tokens })
}

pub fn read_header(device: &Path) -> Result<Header> {
    let out = run(cryptsetup()
        .arg("luksDump")
        .arg("--dump-json-metadata")
        .arg(device))
    .with_context(|| format!("{} is not a readable LUKS2 volume", device.display()))?;
    parse_header(&String::from_utf8_lossy(&out))
}

pub fn binding_from_header(header: &Header) -> Result<Option<Binding>> {
    let generation = |t: &Value| t.get("generation").and_then(Value::as_u64).unwrap_or(0);
    let mut ours: Vec<&(u32, Value)> = header
        .tokens
        .iter()
        .filter(|(_, t)| t.get("type").and_then(Value::as_str) == Some(TOKEN_TYPE))
        .collect();
    ours.sort_by_key(|(_, t)| std::cmp::Reverse(generation(t)));
    let Some((token_id, token)) = ours.first() else {
        return Ok(None);
    };
    let keyslot = token
        .get("keyslots")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("zknbe token has no keyslot"))?;
    let state: ClientState = serde_json::from_value(
        token
            .get("zknbe")
            .cloned()
            .ok_or_else(|| anyhow!("zknbe token has no payload"))?,
    )
    .context("zknbe token payload is corrupt")?;
    validate(&state)?;
    Ok(Some(Binding {
        token_id: *token_id,
        keyslot,
        generation: generation(token),
        state,
        stale_tokens: ours[1..].iter().map(|(id, _)| *id).collect(),
    }))
}

pub fn find_binding(device: &Path) -> Result<Option<Binding>> {
    binding_from_header(&read_header(device)?)
}

pub fn token_json(keyslot: u32, generation: u64, state: &ClientState) -> Result<String> {
    Ok(json!({
        "type": TOKEN_TYPE,
        "keyslots": [keyslot.to_string()],
        "generation": generation,
        "zknbe": serde_json::to_value(state)?,
    })
    .to_string())
}

/// Write the binding as a new token and retire any previous ones.
pub fn write_token(device: &Path, keyslot: u32, state: &ClientState) -> Result<()> {
    let header = read_header(device)?;
    let previous = binding_from_header(&header)?;
    let generation = previous.as_ref().map(|b| b.generation + 1).unwrap_or(1);
    let free_id = (0..32u32)
        .find(|id| !header.tokens.iter().any(|(used, _)| used == id))
        .ok_or_else(|| anyhow!("no free LUKS2 token slot on {}", device.display()))?;
    let mut cmd = cryptsetup();
    cmd.arg("token")
        .arg("import")
        .arg("--token-id")
        .arg(free_id.to_string())
        .arg(device);
    run_with_stdin(&mut cmd, token_json(keyslot, generation, state)?.as_bytes())
        .with_context(|| format!("cannot write zknbe token to {}", device.display()))?;
    // The new token is durable; the old ones are now garbage. Failing to remove them is
    // harmless (readers prefer the highest generation) and is retried on the next write.
    if let Some(prev) = previous {
        for id in std::iter::once(prev.token_id).chain(prev.stale_tokens) {
            let _ = remove_token(device, id);
        }
    }
    Ok(())
}

pub fn remove_token(device: &Path, token_id: u32) -> Result<()> {
    run(cryptsetup()
        .arg("token")
        .arg("remove")
        .arg("--token-id")
        .arg(token_id.to_string())
        .arg(device))?;
    Ok(())
}

pub fn first_free_keyslot(header: &Header) -> Result<u32> {
    (0..32u32)
        .find(|s| !header.keyslots.contains(s))
        .ok_or_else(|| anyhow!("no free LUKS keyslot"))
}

/// A private scratch file on tmpfs, removed (after overwriting) on drop.
struct ScratchFile(PathBuf);

impl ScratchFile {
    fn create(contents: &[u8]) -> Result<Self> {
        use std::io::Write;
        let dir = ["/run", "/dev/shm"]
            .iter()
            .map(Path::new)
            .find(|p| p.is_dir())
            .map(Path::to_path_buf)
            .unwrap_or_else(std::env::temp_dir);
        let path = dir.join(format!(
            ".zknbe-{}-{}",
            std::process::id(),
            zknbe_core::encoding::b64(&zknbe_core::keys::random_bytes::<9>())
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&path)
            .with_context(|| format!("cannot create {}", path.display()))?;
        let file = ScratchFile(path);
        f.write_all(contents)?;
        f.sync_all()?;
        Ok(file)
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        if let Ok(len) = std::fs::metadata(&self.0).map(|m| m.len()) {
            let _ = std::fs::write(&self.0, vec![0u8; len as usize]);
        }
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Add `passphrase` to `keyslot`. Authorisation comes from `existing_key_file`, or, if none
/// is given, cryptsetup prompts for an existing passphrase on the terminal.
pub fn add_key(
    device: &Path,
    keyslot: u32,
    passphrase: &str,
    existing_key_file: Option<&Path>,
) -> Result<()> {
    let new_key = ScratchFile::create(passphrase.as_bytes())?;
    let mut cmd = cryptsetup();
    cmd.arg("luksAddKey")
        .arg("--key-slot")
        .arg(keyslot.to_string());
    if let Some(k) = existing_key_file {
        cmd.arg("--key-file").arg(k);
    }
    cmd.arg(device).arg(&new_key.0);
    let status = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("cannot run cryptsetup")?;
    if !status.success() {
        bail!("cryptsetup luksAddKey failed");
    }
    Ok(())
}

/// Check that `passphrase` opens `keyslot` without activating the volume.
pub fn test_passphrase(device: &Path, keyslot: u32, passphrase: &str) -> Result<()> {
    run_with_stdin(
        cryptsetup()
            .arg("open")
            .arg("--test-passphrase")
            .arg("--key-file=-")
            .arg("--key-slot")
            .arg(keyslot.to_string())
            .arg(device),
        passphrase.as_bytes(),
    )?;
    Ok(())
}

pub fn open(device: &Path, name: &str, keyslot: u32, passphrase: &str) -> Result<()> {
    run_with_stdin(
        cryptsetup()
            .arg("open")
            .arg("--type=luks2")
            .arg("--key-file=-")
            .arg("--key-slot")
            .arg(keyslot.to_string())
            .arg(device)
            .arg(name),
        passphrase.as_bytes(),
    )?;
    Ok(())
}

/// Destroy a keyslot. Refuses to remove the last one.
pub fn kill_keyslot(device: &Path, keyslot: u32) -> Result<()> {
    let header = read_header(device)?;
    if !header.keyslots.contains(&keyslot) {
        return Ok(());
    }
    if header.keyslots.len() < 2 {
        bail!(
            "refusing to remove the only keyslot of {}",
            device.display()
        );
    }
    run(cryptsetup()
        .arg("luksKillSlot")
        .arg("--batch-mode")
        .arg(device)
        .arg(keyslot.to_string()))?;
    Ok(())
}

/// [`StateStore`] backed by the zknbe token in a LUKS2 header.
pub struct LuksStore(pub PathBuf);

impl StateStore for LuksStore {
    fn load(&self) -> Result<ClientState> {
        Ok(find_binding(&self.0)?
            .ok_or_else(|| anyhow!("{} has no zknbe binding", self.0.display()))?
            .state)
    }

    fn save(&self, state: &ClientState) -> Result<()> {
        let binding = find_binding(&self.0)?
            .ok_or_else(|| anyhow!("{} has no zknbe binding", self.0.display()))?;
        write_token(&self.0, binding.keyslot, state)
    }

    fn describe(&self) -> String {
        format!("LUKS2 volume {}", self.0.display())
    }
}

/// LUKS volumes on this machine that carry a zknbe binding.
pub fn discover() -> Vec<PathBuf> {
    let Ok(out) = Command::new("blkid")
        .args(["-t", "TYPE=crypto_LUKS", "-o", "device"])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| PathBuf::from(l.trim()))
        .filter(|p| !p.as_os_str().is_empty())
        .filter(|p| matches!(find_binding(p), Ok(Some(_))))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{SecretStorage, ServerEntry, STATE_VERSION};

    fn sample_state() -> ClientState {
        ClientState {
            version: STATE_VERSION,
            device_id: "0f9b2c3e-0000-4000-8000-000000000001".into(),
            name: "web01".into(),
            threshold: 1,
            secret: SecretStorage::Plain {
                value: "c2VjcmV0".into(),
            },
            key_check: "chk".into(),
            servers: vec![ServerEntry {
                url: "http://ks1".into(),
                server_id: "sid".into(),
                server_pubkey: "spk".into(),
                share_index: 1,
                epoch: 4,
                oprf_pubkey: "opk".into(),
                wrapped_share: "ws".into(),
                heartbeat_interval_secs: 120,
            }],
        }
    }

    #[test]
    fn token_roundtrips_through_luks_metadata() {
        let token: Value =
            serde_json::from_str(&token_json(3, 1, &sample_state()).unwrap()).unwrap();
        // Shape of `cryptsetup luksDump --dump-json-metadata`.
        let dump = json!({
            "keyslots": { "0": { "type": "luks2" }, "3": { "type": "luks2" } },
            "tokens": {
                "0": { "type": "systemd-tpm2", "keyslots": ["1"] },
                "2": token,
            },
            "segments": {}, "digests": {}, "config": {}
        })
        .to_string();
        let header = parse_header(&dump).unwrap();
        assert_eq!(header.keyslots, vec![0, 3]);
        assert_eq!(first_free_keyslot(&header).unwrap(), 1);
        let binding = binding_from_header(&header).unwrap().unwrap();
        assert_eq!(
            (binding.token_id, binding.keyslot, binding.generation),
            (2, 3, 1)
        );
        assert_eq!(binding.state.servers[0].epoch, 4);
        assert!(binding.stale_tokens.is_empty());
    }

    #[test]
    fn interrupted_update_resolves_to_the_newest_generation() {
        let mut newer = sample_state();
        newer.servers[0].epoch = 5;
        let old: Value = serde_json::from_str(&token_json(3, 7, &sample_state()).unwrap()).unwrap();
        let new: Value = serde_json::from_str(&token_json(3, 8, &newer).unwrap()).unwrap();
        // The crash happened after importing the new token but before removing the old one.
        let dump = json!({ "keyslots": { "3": {} }, "tokens": { "0": old, "1": new } }).to_string();
        let binding = binding_from_header(&parse_header(&dump).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!((binding.token_id, binding.generation), (1, 8));
        assert_eq!(binding.state.servers[0].epoch, 5);
        assert_eq!(binding.stale_tokens, vec![0]);
    }

    #[test]
    fn header_without_binding() {
        let header = parse_header(r#"{"keyslots":{"0":{}},"tokens":{}}"#).unwrap();
        assert!(binding_from_header(&header).unwrap().is_none());
    }
}
