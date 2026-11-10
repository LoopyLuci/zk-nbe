//! The device-side binding state and where it is kept.
//!
//! Nothing in the state is sufficient to derive the volume key: the wrapped shares can only
//! be opened with the key servers' help. The one sensitive field is the device secret, which
//! is either stored in the clear (protection then rests on key-server policy alone, like
//! Clevis/Tang) or sealed to the machine's TPM 2.0.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;
use zknbe_core::encoding::{b64, unb64, unb64_array};
use zknbe_core::keys::DeviceSecret;

pub const STATE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClientState {
    pub version: u32,
    pub device_id: String,
    pub name: String,
    /// How many key servers must cooperate to unlock.
    pub threshold: u8,
    pub secret: SecretStorage,
    /// Detects a wrong reconstruction before the key is handed to cryptsetup.
    pub key_check: String,
    pub servers: Vec<ServerEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerEntry {
    pub url: String,
    pub server_id: String,
    /// Pinned Ed25519 identity of the key server (authenticated by the enrolment token).
    pub server_pubkey: String,
    pub share_index: u8,
    /// Epoch of the server-side OPRF key the share below is wrapped under.
    pub epoch: u64,
    pub oprf_pubkey: String,
    pub wrapped_share: String,
    pub heartbeat_interval_secs: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SecretStorage {
    /// Device secret stored as-is next to the state.
    Plain { value: String },
    /// Device secret sealed to the TPM with `systemd-creds` (bound to the given PCRs).
    SystemdCreds { blob: String, pcrs: String },
}

impl SecretStorage {
    pub fn plain(secret: &DeviceSecret) -> Self {
        SecretStorage::Plain {
            value: b64(secret.as_bytes()),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            SecretStorage::Plain { .. } => "plain (not hardware-bound)".into(),
            SecretStorage::SystemdCreds { pcrs, .. } => format!("TPM2-sealed, PCRs {pcrs}"),
        }
    }

    pub fn load(&self) -> Result<DeviceSecret> {
        match self {
            SecretStorage::Plain { value } => Ok(DeviceSecret::from_bytes(
                unb64_array(value).map_err(|_| anyhow!("corrupt device secret in state"))?,
            )),
            SecretStorage::SystemdCreds { blob, .. } => {
                let out = run_with_stdin(
                    Command::new("systemd-creds").args(["decrypt", "--name=zknbe", "-", "-"]),
                    blob.as_bytes(),
                )
                .context(
                    "TPM unsealing failed: the boot chain measured into the bound PCRs changed, \
                     or this is not the machine the secret was sealed on",
                )?;
                let out = Zeroizing::new(out);
                let bytes = Zeroizing::new(
                    unb64(String::from_utf8_lossy(&out).trim())
                        .map_err(|_| anyhow!("unexpected output from systemd-creds"))?,
                );
                Ok(DeviceSecret::from_bytes(bytes[..].try_into().map_err(
                    |_| anyhow!("unsealed secret has wrong length"),
                )?))
            }
        }
    }

    /// Seal `secret` to the local TPM, bound to `pcrs` (e.g. "7" or "7+11").
    pub fn seal_tpm(secret: &DeviceSecret, pcrs: &str) -> Result<Self> {
        if pcrs.is_empty() || !pcrs.chars().all(|c| c.is_ascii_digit() || c == '+') {
            bail!("PCR list must look like '7' or '7+11'");
        }
        let plain = Zeroizing::new(b64(secret.as_bytes()));
        let out = run_with_stdin(
            Command::new("systemd-creds").args([
                "encrypt",
                "--with-key=tpm2",
                &format!("--tpm2-pcrs={pcrs}"),
                "--name=zknbe",
                "-",
                "-",
            ]),
            plain.as_bytes(),
        )
        .context(
            "sealing to the TPM with systemd-creds failed (needs systemd >= 250 and a TPM 2.0)",
        )?;
        let blob: String = String::from_utf8_lossy(&out)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if blob.is_empty() {
            bail!("systemd-creds produced no output");
        }
        Ok(SecretStorage::SystemdCreds {
            blob,
            pcrs: pcrs.to_string(),
        })
    }
}

/// Run a command, feed `input` on stdin, return stdout; fail with stderr on non-zero exit.
pub fn run_with_stdin(cmd: &mut Command, input: &[u8]) -> Result<Vec<u8>> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot run '{program}' (is it installed?)"))?;
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        // The child may exit without reading (e.g. usage error); the exit status tells.
        let _ = stdin.write_all(input);
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        // Tools like cryptsetup print their whole usage text on some errors; the last line is
        // the actual message.
        let stderr = String::from_utf8_lossy(&out.stderr);
        let reason = stderr
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("no error output");
        bail!("{program} failed: {}", reason.trim());
    }
    Ok(out.stdout)
}

pub trait StateStore: Send + Sync {
    fn load(&self) -> Result<ClientState>;
    /// Must be atomic: after a crash either the old or the new state is readable.
    fn save(&self, state: &ClientState) -> Result<()>;
    fn describe(&self) -> String;
}

pub fn validate(state: &ClientState) -> Result<()> {
    if state.version != STATE_VERSION {
        bail!(
            "unsupported state version {} (this build understands {})",
            state.version,
            STATE_VERSION
        );
    }
    let n = state.servers.len();
    if n == 0 || n > 255 || state.threshold == 0 || state.threshold as usize > n {
        bail!(
            "corrupt state: threshold {} of {} servers",
            state.threshold,
            n
        );
    }
    Ok(())
}

/// State in a regular file. Suitable for generic key release and testing. For boot-time
/// unlocking prefer the LUKS2 header store: a file baked into an initramfs goes stale when
/// the agent rotates keys.
pub struct FileStore(pub PathBuf);

impl StateStore for FileStore {
    fn load(&self) -> Result<ClientState> {
        let text = std::fs::read_to_string(&self.0)
            .with_context(|| format!("cannot read state file {}", self.0.display()))?;
        let state: ClientState = serde_json::from_str(&text)
            .with_context(|| format!("state file {} is corrupt", self.0.display()))?;
        validate(&state)?;
        Ok(state)
    }

    fn save(&self, state: &ClientState) -> Result<()> {
        let dir = self
            .0
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let tmp = dir.join(format!(
            ".{}.tmp{}",
            self.0
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("state"),
            std::process::id()
        ));
        let write = || -> Result<()> {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(serde_json::to_string_pretty(state)?.as_bytes())?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, &self.0)?;
            #[cfg(unix)]
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
            Ok(())
        };
        write().map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e.context(format!("cannot write state file {}", self.0.display()))
        })
    }

    fn describe(&self) -> String {
        format!("file {}", self.0.display())
    }
}
