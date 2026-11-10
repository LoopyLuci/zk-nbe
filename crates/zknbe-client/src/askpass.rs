//! systemd password-agent for the initramfs.
//!
//! When systemd-cryptsetup needs a passphrase it drops an `ask.*` file into
//! `/run/systemd/ask-password/` (see systemd's "Password Agents" specification). This agent
//! answers those requests for volumes that carry a zknbe binding. Requests it cannot answer
//! are left alone, so the console prompt keeps working as the break-glass path.

use crate::luks;
use crate::net::Http;
use crate::ops::{recover_master, UnlockError};
use anyhow::{anyhow, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub struct AskRequest {
    pub device: PathBuf,
    pub socket: PathBuf,
}

/// Parse an `ask.*` file; `None` if it is not a cryptsetup request.
pub fn parse_ask_file(text: &str) -> Option<AskRequest> {
    let mut device = None;
    let mut socket = None;
    for line in text.lines() {
        if let Some(id) = line.strip_prefix("Id=cryptsetup:") {
            device = Some(PathBuf::from(id.trim()));
        } else if let Some(s) = line.strip_prefix("Socket=") {
            socket = Some(PathBuf::from(s.trim()));
        }
    }
    Some(AskRequest {
        device: device?,
        socket: socket?,
    })
}

#[cfg(unix)]
fn answer(socket: &Path, passphrase: &str) -> Result<()> {
    use std::os::unix::net::UnixDatagram;
    use zeroize::Zeroizing;
    let msg = Zeroizing::new(format!("+{passphrase}"));
    UnixDatagram::unbound()?.send_to(msg.as_bytes(), socket)?;
    Ok(())
}

#[cfg(not(unix))]
fn answer(_socket: &Path, _passphrase: &str) -> Result<()> {
    Err(anyhow!("the password agent is only available on Linux"))
}

enum Attempt {
    Answered,
    NotOurs,
    Refused(String),
    Retry(String),
}

fn attempt(http: &Http, req: &AskRequest) -> Attempt {
    let binding = match luks::find_binding(&req.device) {
        Ok(Some(b)) => b,
        Ok(None) => return Attempt::NotOurs,
        Err(e) => return Attempt::Retry(format!("{e:#}")),
    };
    let secret = match binding.state.secret.load() {
        Ok(s) => s,
        Err(e) => return Attempt::Refused(format!("{e:#}")),
    };
    match recover_master(http, &binding.state, &secret) {
        Ok(master) => {
            let pass = master.passphrase(&binding.state.device_id);
            match answer(&req.socket, &pass) {
                Ok(()) => Attempt::Answered,
                Err(e) => Attempt::Retry(format!("cannot answer prompt: {e}")),
            }
        }
        Err(e @ UnlockError { .. }) if e.is_final(binding.state.servers.len()) => {
            Attempt::Refused(e.to_string())
        }
        Err(e) => Attempt::Retry(e.to_string()),
    }
}

/// How long the prompt directory must stay empty before a `--watch` run exits.
const IDLE_EXIT: Duration = Duration::from_secs(10);

/// Answer pending prompts. With `watch`, keep running for as long as any prompt exists (also
/// ones for other agents, so a `.path` unit does not restart us in a loop) and exit once the
/// directory has been empty for a while; otherwise return once nothing is left to retry or
/// `retry_for` has elapsed.
pub fn run(
    http: &Http,
    dir: &Path,
    watch: bool,
    retry_for: Duration,
    log: &dyn Fn(&str),
) -> Result<()> {
    let deadline = Instant::now() + retry_for;
    let mut settled: HashSet<PathBuf> = HashSet::new();
    let mut last_error: Option<String> = None;
    let mut idle_since = Instant::now();
    loop {
        let mut pending = 0;
        let entries = std::fs::read_dir(dir)
            .map(|rd| rd.flatten().collect::<Vec<_>>())
            .unwrap_or_default();
        // Forget prompts that went away, so a re-asked prompt is handled again.
        let present: HashSet<PathBuf> = entries.iter().map(|e| e.path()).collect();
        settled.retain(|p| present.contains(p));

        for entry in entries {
            let path = entry.path();
            let is_ask = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("ask."));
            if !is_ask || settled.contains(&path) {
                continue;
            }
            let Some(req) = std::fs::read_to_string(&path)
                .ok()
                .and_then(|t| parse_ask_file(&t))
            else {
                settled.insert(path);
                continue;
            };
            match attempt(http, &req) {
                Attempt::Answered => {
                    log(&format!("unlocked {}", req.device.display()));
                    settled.insert(path);
                }
                Attempt::NotOurs => {
                    settled.insert(path);
                }
                Attempt::Refused(why) => {
                    log(&format!(
                        "{}: key release refused, falling back to the passphrase prompt:\n{why}",
                        req.device.display()
                    ));
                    settled.insert(path);
                }
                Attempt::Retry(why) => {
                    pending += 1;
                    if last_error.as_deref() != Some(&why) {
                        log(&format!(
                            "{}: not unlocked yet: {why}",
                            req.device.display()
                        ));
                        last_error = Some(why);
                    }
                }
            }
        }

        if watch {
            if present.iter().any(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("ask."))
            }) {
                idle_since = Instant::now();
            } else if idle_since.elapsed() >= IDLE_EXIT {
                return Ok(());
            }
        } else {
            if pending == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(anyhow!("gave up: {}", last_error.unwrap_or_default()));
            }
        }
        std::thread::sleep(Duration::from_millis(if pending > 0 { 2000 } else { 500 }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cryptsetup_requests_only() {
        let ask = "[Ask]\nPID=312\nSocket=/run/systemd/ask-password/sck.8f3a\nAcceptCached=0\n\
                   Echo=0\nNotAfter=0\nMessage=Please enter passphrase for disk root\n\
                   Id=cryptsetup:/dev/block/259:3\n";
        let req = parse_ask_file(ask).unwrap();
        assert_eq!(req.device, PathBuf::from("/dev/block/259:3"));
        assert_eq!(
            req.socket,
            PathBuf::from("/run/systemd/ask-password/sck.8f3a")
        );
        assert!(parse_ask_file("[Ask]\nSocket=/x\nId=sudo:whatever\n").is_none());
    }
}
