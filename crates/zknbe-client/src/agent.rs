//! The runtime agent: heartbeats (lease renewal), key rotation and the revocation hook.

use crate::net::Http;
use crate::ops::{heartbeat_all, rotate_server, RotateOutcome};
use crate::state::StateStore;
use anyhow::Result;
use std::time::Duration;
use zknbe_core::proto::DeviceState;

pub struct Cycle {
    /// Seconds until the next heartbeat is due (the shortest interval any server asked for).
    pub next_interval: u64,
    /// Enough key servers report this device revoked that it can never unlock again.
    pub revoked: bool,
    /// Servers that answered and consider the device active.
    pub healthy: usize,
    pub total: usize,
}

/// One heartbeat round for one binding.
pub fn run_cycle(http: &Http, store: &dyn StateStore, log: &dyn Fn(&str)) -> Result<Cycle> {
    let mut state = store.load()?;
    let secret = state.secret.load()?;
    let reports = heartbeat_all(http, &state, &secret);

    let total = state.servers.len();
    let mut next_interval = state
        .servers
        .iter()
        .map(|s| s.heartbeat_interval_secs)
        .min()
        .unwrap_or(120);
    let mut revoked = 0usize;
    let mut healthy = 0usize;

    for (index, report) in reports.iter().enumerate() {
        let hb = match &report.result {
            Ok(hb) => hb,
            Err(e) => {
                log(&format!("{}: heartbeat failed: {e}", report.url));
                continue;
            }
        };
        next_interval = next_interval.min(hb.heartbeat_interval_secs.max(5));
        match hb.state {
            DeviceState::Active => healthy += 1,
            DeviceState::Revoked => {
                revoked += 1;
                log(&format!("{}: this device has been REVOKED", report.url));
                continue;
            }
            DeviceState::Locked => {
                log(&format!(
                    "{}: device is LOCKED (lease lapsed) - the next boot will not unlock until an \
                     administrator runs 'zknbectl device approve'",
                    report.url
                ));
                continue;
            }
            DeviceState::Suspended => {
                log(&format!(
                    "{}: device is suspended by an administrator",
                    report.url
                ));
                continue;
            }
        }
        match rotate_server(http, store, &mut state, &secret, index, hb, false) {
            Ok(RotateOutcome::UpToDate) => {}
            Ok(RotateOutcome::Committed(epoch)) => log(&format!(
                "{}: completed interrupted rotation to epoch {epoch}",
                report.url
            )),
            Ok(RotateOutcome::Rotated { from, to }) => log(&format!(
                "{}: rotated key, epoch {from} -> {to}",
                report.url
            )),
            Err(e) => log(&format!("{}: key rotation failed: {e:#}", report.url)),
        }
    }

    Ok(Cycle {
        next_interval,
        revoked: total - revoked < state.threshold as usize,
        healthy,
        total,
    })
}

pub struct AgentOptions {
    pub stores: Vec<Box<dyn StateStore>>,
    /// Shell command run once when a binding is found revoked beyond recovery.
    pub on_revoked: Option<String>,
    pub once: bool,
}

/// Returns the process exit code for `--once` runs: 0 healthy, 3 revoked, 4 degraded.
pub fn run(http: &Http, opts: AgentOptions, log: &dyn Fn(&str)) -> i32 {
    let mut hook_fired = false;
    loop {
        let mut sleep_for = 120u64;
        let mut any_revoked = false;
        let mut degraded = false;
        for store in &opts.stores {
            match run_cycle(http, store.as_ref(), log) {
                Ok(cycle) => {
                    sleep_for = sleep_for.min(cycle.next_interval);
                    any_revoked |= cycle.revoked;
                    degraded |= cycle.healthy < cycle.total;
                }
                Err(e) => {
                    degraded = true;
                    log(&format!("{}: {e:#}", store.describe()));
                }
            }
        }
        if any_revoked && !hook_fired {
            hook_fired = true;
            if let Some(cmd) = &opts.on_revoked {
                log(&format!("device revoked: running on-revoked hook: {cmd}"));
                match std::process::Command::new("sh").arg("-c").arg(cmd).status() {
                    Ok(s) if s.success() => {}
                    Ok(s) => log(&format!("on-revoked hook exited with {s}")),
                    Err(e) => log(&format!("cannot run on-revoked hook: {e}")),
                }
            }
        }
        if opts.once {
            return if any_revoked {
                3
            } else if degraded {
                4
            } else {
                0
            };
        }
        // Jitter by up to 10% so a fleet does not heartbeat in lockstep.
        let jitter = rand::random::<u64>() % (sleep_for / 10 + 1);
        std::thread::sleep(Duration::from_secs(
            sleep_for.max(5) - jitter.min(sleep_for / 2),
        ));
    }
}
