//! zknbe – device-side client for ZK-NBE.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use zknbe_client::agent::{self, AgentOptions};
use zknbe_client::askpass;
use zknbe_client::luks::{self, LuksStore};
use zknbe_client::net::Http;
use zknbe_client::ops::{self, EnrollTarget, RotateOutcome};
use zknbe_client::state::{ClientState, FileStore, SecretStorage, StateStore};
use zknbe_core::encoding::parse_duration;

#[derive(Parser)]
#[command(
    name = "zknbe",
    version,
    about = "Network-bound disk encryption with zero-knowledge key servers"
)]
struct Cli {
    /// Per-request network timeout.
    #[arg(long, global = true, value_parser = parse_duration, default_value = "5s")]
    timeout: u64,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct Target {
    /// Binding stored in a state file.
    #[arg(long)]
    state: Option<PathBuf>,
    /// Binding stored in the header of this LUKS2 volume.
    #[arg(long)]
    luks: Option<PathBuf>,
}

impl Target {
    fn store(&self) -> Box<dyn StateStore> {
        match (&self.state, &self.luks) {
            (Some(p), _) => Box::new(FileStore(p.clone())),
            (_, Some(d)) => Box::new(LuksStore(d.clone())),
            _ => unreachable!("clap enforces exactly one target"),
        }
    }
}

#[derive(Args)]
struct EnrollArgs {
    /// Device name shown to administrators (defaults to the host name).
    #[arg(long)]
    name: Option<String>,
    /// Number of key servers that must cooperate to unlock (default: all of them).
    #[arg(long, short = 't')]
    threshold: Option<u8>,
    /// A key server and its single-use enrolment token, as URL=TOKEN. Repeat per server.
    #[arg(long = "server", short = 's', required = true, value_parser = EnrollTarget::parse)]
    servers: Vec<EnrollTarget>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enrol with key servers and write the binding to a state file.
    Enroll {
        /// Where to write the binding state (must not exist).
        #[arg(long)]
        state: PathBuf,
        #[command(flatten)]
        enroll: EnrollArgs,
    },
    /// Obtain the key from the key servers and print it on stdout.
    Unlock {
        #[command(flatten)]
        target: Target,
        /// Keep retrying for this long if servers are unreachable (e.g. 2m).
        #[arg(long, value_parser = parse_duration, default_value = "0")]
        retry_for: u64,
    },
    /// Show the binding and the live status on every key server.
    Status {
        #[command(flatten)]
        target: Target,
    },
    /// Rotate the per-device key on every reachable key server now.
    Rotate {
        #[command(flatten)]
        target: Target,
    },
    /// Run the heartbeat agent (renews leases, rotates keys, reacts to revocation).
    Agent {
        /// LUKS2 volume to look after (repeatable). Default: all bound volumes found.
        #[arg(long)]
        luks: Vec<PathBuf>,
        /// State file to look after (repeatable).
        #[arg(long)]
        state: Vec<PathBuf>,
        /// Shell command to run once this device is revoked beyond recovery,
        /// e.g. "systemctl poweroff".
        #[arg(long, env = "ZKNBE_ON_REVOKED")]
        on_revoked: Option<String>,
        /// Run a single cycle and exit (0 healthy, 3 revoked, 4 degraded).
        #[arg(long)]
        once: bool,
    },
    /// Bind, open and inspect LUKS2 volumes.
    #[command(subcommand)]
    Luks(LuksCmd),
    /// Seal or unseal the device secret with the TPM.
    #[command(subcommand)]
    Tpm(TpmCmd),
    /// Answer systemd password prompts for bound volumes (used in the initramfs).
    Askpass {
        /// Keep running and answer prompts as they appear.
        #[arg(long)]
        watch: bool,
        /// Without --watch: how long to keep retrying unanswered prompts.
        #[arg(long, value_parser = parse_duration, default_value = "2m")]
        retry_for: u64,
        #[arg(long, default_value = "/run/systemd/ask-password", hide = true)]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum LuksCmd {
    /// Enrol with key servers and add a network-bound keyslot to a LUKS2 volume.
    Bind {
        device: PathBuf,
        #[command(flatten)]
        enroll: EnrollArgs,
        /// Keyslot to use (default: first free).
        #[arg(long)]
        keyslot: Option<u32>,
        /// Existing key file authorising the change (default: prompt for a passphrase).
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// Seal the device secret to the TPM, bound to these PCRs (e.g. 7 or 7+11).
        #[arg(long)]
        tpm2_pcrs: Option<String>,
    },
    /// Unlock a bound volume and map it as /dev/mapper/NAME.
    Open {
        device: PathBuf,
        name: String,
        #[arg(long, value_parser = parse_duration, default_value = "0")]
        retry_for: u64,
    },
    /// Print the passphrase of a bound volume (for crypttab keyscripts).
    Passphrase {
        device: PathBuf,
        #[arg(long, value_parser = parse_duration, default_value = "0")]
        retry_for: u64,
    },
    /// Remove the binding: destroy the keyslot and the token.
    Unbind {
        device: PathBuf,
        /// Leave the keyslot in place and remove only the token.
        #[arg(long)]
        keep_keyslot: bool,
    },
    /// Show the binding stored in a volume header.
    Status { device: PathBuf },
}

#[derive(Subcommand)]
enum TpmCmd {
    /// Seal the device secret to this machine's TPM 2.0 (via systemd-creds).
    Seal {
        #[command(flatten)]
        target: Target,
        /// PCRs to bind to. 7 = Secure Boot state.
        #[arg(long, default_value = "7")]
        pcrs: String,
    },
    /// Store the device secret unsealed again (e.g. before a firmware update changes PCRs).
    Unseal {
        #[command(flatten)]
        target: Target,
    },
}

fn log(msg: &str) {
    eprintln!("zknbe: {msg}");
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "device".into())
}

fn do_enroll(http: &Http, args: &EnrollArgs) -> Result<(ClientState, zknbe_core::keys::MasterKey)> {
    let name = args.name.clone().unwrap_or_else(hostname);
    let threshold = args.threshold.unwrap_or(args.servers.len().min(255) as u8);
    if args.servers.iter().any(|s| s.url.starts_with("http://")) {
        log(
            "note: using plain http:// - the protocol is authenticated end-to-end, but device \
             ids and timing are visible on the wire",
        );
    }
    ops::enroll(http, &name, threshold, &args.servers)
}

fn print_secret(secret: &str) -> Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(secret.as_bytes())?;
    out.flush()?;
    Ok(())
}

fn status(http: &Http, store: &dyn StateStore) -> Result<()> {
    let state = store.load()?;
    println!("binding:    {}", store.describe());
    println!("device:     {} ({})", state.name, state.device_id);
    println!(
        "quorum:     {} of {} key servers",
        state.threshold,
        state.servers.len()
    );
    println!("secret:     {}", state.secret.describe());
    let secret = state.secret.load()?;
    for (entry, report) in state
        .servers
        .iter()
        .zip(ops::heartbeat_all(http, &state, &secret))
    {
        match report.result {
            Ok(hb) => println!(
                "  {:<40} {:<9} epoch {} (server {}){}{}",
                entry.url,
                hb.state.as_str(),
                entry.epoch,
                hb.current_epoch,
                if hb.lease_secs > 0 {
                    format!(", lease {}s", hb.lease_secs)
                } else {
                    String::new()
                },
                if hb.rotate_due { ", rotation due" } else { "" },
            ),
            Err(e) => println!("  {:<40} {e}", entry.url),
        }
    }
    Ok(())
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("zknbe: error: {e:#}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32> {
    let cli = Cli::parse();
    let http = Http::new(Duration::from_secs(cli.timeout.max(1)));

    match cli.cmd {
        Cmd::Enroll { state, enroll } => {
            if state.exists() {
                bail!(
                    "{} already exists; refusing to overwrite a binding",
                    state.display()
                );
            }
            let (st, _master) = do_enroll(&http, &enroll)?;
            FileStore(state.clone()).save(&st)?;
            log(&format!(
                "enrolled '{}' as {} ({} of {} servers required)",
                st.name,
                st.device_id,
                st.threshold,
                st.servers.len()
            ));
            log(&format!(
                "retrieve the key with: zknbe unlock --state {}",
                state.display()
            ));
        }

        Cmd::Unlock { target, retry_for } => {
            let store = target.store();
            let pass = ops::unlock_with_retry(
                &http,
                &|| store.load(),
                Duration::from_secs(retry_for),
                &log,
            )?;
            print_secret(&pass)?;
        }

        Cmd::Status { target } => status(&http, target.store().as_ref())?,

        Cmd::Rotate { target } => {
            let store = target.store();
            let mut state = store.load()?;
            let secret = state.secret.load()?;
            let reports = ops::heartbeat_all(&http, &state, &secret);
            let mut failed = false;
            for (index, report) in reports.iter().enumerate() {
                let outcome = match &report.result {
                    Ok(hb) => ops::rotate_server(
                        &http,
                        store.as_ref(),
                        &mut state,
                        &secret,
                        index,
                        hb,
                        true,
                    ),
                    Err(e) => Err(anyhow!("{e}")),
                };
                match outcome {
                    Ok(RotateOutcome::Rotated { from, to }) => {
                        println!("{}: rotated, epoch {from} -> {to}", report.url)
                    }
                    Ok(RotateOutcome::Committed(e)) => {
                        println!("{}: completed pending rotation to epoch {e}", report.url)
                    }
                    Ok(RotateOutcome::UpToDate) => println!("{}: up to date", report.url),
                    Err(e) => {
                        failed = true;
                        println!("{}: FAILED: {e:#}", report.url)
                    }
                }
            }
            return Ok(if failed { 1 } else { 0 });
        }

        Cmd::Agent {
            luks: devices,
            state,
            on_revoked,
            once,
        } => {
            let mut stores: Vec<Box<dyn StateStore>> = Vec::new();
            let devices = if devices.is_empty() && state.is_empty() {
                luks::discover()
            } else {
                devices
            };
            stores.extend(
                devices
                    .into_iter()
                    .map(|d| Box::new(LuksStore(d)) as Box<dyn StateStore>),
            );
            stores.extend(
                state
                    .into_iter()
                    .map(|p| Box::new(FileStore(p)) as Box<dyn StateStore>),
            );
            if stores.is_empty() {
                bail!("no bound volumes found; pass --luks DEVICE or --state FILE");
            }
            for s in &stores {
                log(&format!("watching {}", s.describe()));
            }
            return Ok(agent::run(
                &http,
                AgentOptions {
                    stores,
                    on_revoked,
                    once,
                },
                &log,
            ));
        }

        Cmd::Luks(LuksCmd::Bind {
            device,
            enroll,
            keyslot,
            key_file,
            tpm2_pcrs,
        }) => {
            let header = luks::read_header(&device)?;
            if luks::binding_from_header(&header)?.is_some() {
                bail!(
                    "{} is already bound; run 'zknbe luks unbind' first",
                    device.display()
                );
            }
            let slot = match keyslot {
                Some(s) if header.keyslots.contains(&s) => bail!("keyslot {s} is in use"),
                Some(s) => s,
                None => luks::first_free_keyslot(&header)?,
            };
            let (mut state, master) = do_enroll(&http, &enroll)?;
            let orphan_hint = format!(
                "The device is enrolled on the key servers as {} but the volume was not bound. \
                 Revoke and delete that device id with zknbectl, then retry with fresh tokens.",
                state.device_id
            );
            if let Some(pcrs) = &tpm2_pcrs {
                let secret = state.secret.load()?;
                state.secret =
                    SecretStorage::seal_tpm(&secret, pcrs).with_context(|| orphan_hint.clone())?;
            }
            let pass = master.passphrase(&state.device_id);
            log(&format!("adding keyslot {slot} to {}", device.display()));
            luks::add_key(&device, slot, &pass, key_file.as_deref())
                .with_context(|| orphan_hint.clone())?;
            if let Err(e) = luks::write_token(&device, slot, &state) {
                let _ = luks::kill_keyslot(&device, slot);
                return Err(e.context(orphan_hint));
            }

            // Prove the whole path end to end before telling the operator it works.
            let fresh = ops::unlock(&http, &LuksStore(device.clone()).load()?)
                .context("binding written, but the verification unlock failed")?;
            luks::test_passphrase(&device, slot, &fresh)
                .context("binding written, but the recovered key does not open the keyslot")?;
            log(&format!(
                "bound {} (keyslot {slot}) as device {}; verified a full network unlock",
                device.display(),
                state.device_id
            ));
            log("keep your existing passphrase or recovery key: it is the break-glass path");
            if tpm2_pcrs.is_none() {
                log("the device secret is stored unsealed; consider 'zknbe tpm seal'");
            }
        }

        Cmd::Luks(LuksCmd::Open {
            device,
            name,
            retry_for,
        }) => {
            let binding = luks::find_binding(&device)?
                .ok_or_else(|| anyhow!("{} has no zknbe binding", device.display()))?;
            let store = LuksStore(device.clone());
            let pass = ops::unlock_with_retry(
                &http,
                &|| store.load(),
                Duration::from_secs(retry_for),
                &log,
            )?;
            luks::open(&device, &name, binding.keyslot, &pass)?;
            log(&format!(
                "opened {} as /dev/mapper/{name}",
                device.display()
            ));
        }

        Cmd::Luks(LuksCmd::Passphrase { device, retry_for }) => {
            let store = LuksStore(device);
            let pass = ops::unlock_with_retry(
                &http,
                &|| store.load(),
                Duration::from_secs(retry_for),
                &log,
            )?;
            print_secret(&pass)?;
        }

        Cmd::Luks(LuksCmd::Unbind {
            device,
            keep_keyslot,
        }) => {
            let binding = luks::find_binding(&device)?
                .ok_or_else(|| anyhow!("{} has no zknbe binding", device.display()))?;
            if !keep_keyslot {
                luks::kill_keyslot(&device, binding.keyslot)?;
            }
            for id in std::iter::once(binding.token_id).chain(binding.stale_tokens.iter().copied())
            {
                luks::remove_token(&device, id)?;
            }
            log(&format!(
                "unbound {}; now revoke device {} on the key servers (zknbectl device revoke)",
                device.display(),
                binding.state.device_id
            ));
        }

        Cmd::Luks(LuksCmd::Status { device }) => {
            let binding = luks::find_binding(&device)?
                .ok_or_else(|| anyhow!("{} has no zknbe binding", device.display()))?;
            println!(
                "keyslot:    {} (token {}, generation {})",
                binding.keyslot, binding.token_id, binding.generation
            );
            status(&http, &LuksStore(device))?;
        }

        Cmd::Tpm(TpmCmd::Seal { target, pcrs }) => {
            let store = target.store();
            let mut state = store.load()?;
            let secret = state.secret.load()?;
            state.secret = SecretStorage::seal_tpm(&secret, &pcrs)?;
            // Make sure it can be unsealed before the plain copy is replaced.
            if state.secret.load()?.as_bytes() != secret.as_bytes() {
                bail!("TPM round-trip check failed; state left unchanged");
            }
            store.save(&state)?;
            log(&format!("device secret sealed to TPM PCRs {pcrs}"));
        }

        Cmd::Tpm(TpmCmd::Unseal { target }) => {
            let store = target.store();
            let mut state = store.load()?;
            state.secret = SecretStorage::plain(&state.secret.load()?);
            store.save(&state)?;
            log("device secret is now stored unsealed");
        }

        Cmd::Askpass {
            watch,
            retry_for,
            dir,
        } => {
            askpass::run(&http, &dir, watch, Duration::from_secs(retry_for), &log)?;
        }
    }
    Ok(0)
}
