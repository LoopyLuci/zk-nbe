//! zknbectl – administer a ZK-NBE key server.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use ipnet::IpNet;
use serde::de::DeserializeOwned;
use std::path::PathBuf;
use std::time::Duration;
use zknbe_core::encoding::parse_duration;
use zknbe_core::proto::{DeviceState, ErrorResponse};
use zknbe_server::admin_api::*;
use zknbe_server::config::{LeaseExpiry, PolicyPatch};
use zknbe_server::store::{AuditRecord, AuditVerification};

#[derive(Parser)]
#[command(name = "zknbectl", version, about = "Administer a ZK-NBE key server")]
struct Cli {
    /// Admin API base URL.
    #[arg(
        long,
        global = true,
        env = "ZKNBE_ADMIN_URL",
        default_value = "http://127.0.0.1:7422"
    )]
    url: String,
    /// Admin token (prefer --token-file or the environment over the command line).
    #[arg(long, global = true, env = "ZKNBE_ADMIN_TOKEN", hide_env_values = true)]
    token: Option<String>,
    /// File containing the admin token.
    #[arg(
        long,
        global = true,
        env = "ZKNBE_ADMIN_TOKEN_FILE",
        default_value = "/var/lib/zknbe/admin.token"
    )]
    token_file: PathBuf,
    /// Print raw JSON instead of tables.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show server identity and device counts.
    Status,
    /// Manage single-use enrolment tokens.
    #[command(subcommand)]
    Token(TokenCmd),
    /// Inspect and control enrolled devices.
    #[command(subcommand)]
    Device(DeviceCmd),
    /// Read and verify the tamper-evident audit log.
    #[command(subcommand)]
    Audit(AuditCmd),
}

#[derive(Args, Default)]
struct PolicyArgs {
    /// How long a device may be silent before it is locked (e.g. 15m).
    #[arg(long, value_parser = parse_duration)]
    lease_ttl: Option<u64>,
    /// Heartbeat interval advertised to the device (e.g. 2m).
    #[arg(long, value_parser = parse_duration)]
    heartbeat: Option<u64>,
    /// What happens when the lease lapses: lock (default) or allow.
    #[arg(long, value_parser = parse_expiry)]
    on_lease_expiry: Option<LeaseExpiry>,
    /// Key rotation interval (e.g. 7d); 0 disables rotation.
    #[arg(long, value_parser = parse_duration)]
    rotation_interval: Option<u64>,
    /// Restrict requests to this network (repeatable). Replaces the existing list.
    #[arg(long = "allow-cidr")]
    allow_cidr: Vec<IpNet>,
    /// Remove any network restriction.
    #[arg(long, conflicts_with = "allow_cidr")]
    allow_any_network: bool,
}

impl PolicyArgs {
    fn patch(&self) -> PolicyPatch {
        PolicyPatch {
            lease_ttl_secs: self.lease_ttl,
            heartbeat_interval_secs: self.heartbeat,
            on_lease_expiry: self.on_lease_expiry,
            rotation_interval_secs: self.rotation_interval,
            allowed_cidrs: if self.allow_any_network {
                Some(Vec::new())
            } else if self.allow_cidr.is_empty() {
                None
            } else {
                Some(self.allow_cidr.clone())
            },
        }
    }
}

fn parse_expiry(s: &str) -> Result<LeaseExpiry, String> {
    match s {
        "lock" => Ok(LeaseExpiry::Lock),
        "allow" => Ok(LeaseExpiry::Allow),
        _ => Err("expected 'lock' or 'allow'".into()),
    }
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Create an enrolment token for one device.
    Create {
        /// Label for the token (typically the host name).
        #[arg(long)]
        name: String,
        /// Token validity (e.g. 1h).
        #[arg(long, value_parser = parse_duration, default_value = "1h")]
        ttl: u64,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    List,
    /// Delete a token (unused tokens become unusable).
    Delete {
        id: String,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    List,
    /// Show one device (by id, unique id prefix, or name).
    Show {
        device: String,
    },
    /// Unlock a locked device, or pre-authorise downtime for an active one.
    Approve {
        device: String,
        /// How long the lease check is waived (e.g. 30m, 4h).
        #[arg(long, value_parser = parse_duration)]
        window: Option<u64>,
    },
    /// Approve every device that is currently locked (e.g. after a site-wide outage).
    ApproveAllLocked {
        #[arg(long, value_parser = parse_duration)]
        window: Option<u64>,
        #[arg(long)]
        yes: bool,
    },
    /// Temporarily refuse key release (reversible).
    Suspend {
        device: String,
    },
    /// Re-enable a suspended device.
    Resume {
        device: String,
    },
    /// Destroy the device's key on this server. IRREVERSIBLE.
    Revoke {
        device: String,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Delete the record of a revoked device.
    Delete {
        device: String,
    },
    /// Change a device's policy.
    Policy {
        device: String,
        #[command(flatten)]
        policy: PolicyArgs,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Show the most recent audit records.
    List {
        #[arg(long, default_value_t = 30)]
        limit: i64,
        /// Only records for this device.
        #[arg(long)]
        device: Option<String>,
    },
    /// Recompute the hash chain and report the head hash.
    Verify,
}

struct Client {
    base: String,
    token: String,
    agent: ureq::Agent,
    json: bool,
}

impl Client {
    fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T> {
        let text = self.call_text(method, path, body)?;
        serde_json::from_str(&text).context("unexpected response from server")
    }

    fn call_text(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<String> {
        let url = format!("{}{}", self.base.trim_end_matches('/'), path);
        let actor = std::env::var("SUDO_USER")
            .or_else(|_| std::env::var("USER"))
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_default();
        let req = self
            .agent
            .request(method, &url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("X-Zknbe-Actor", &actor);
        let result = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        match result {
            Ok(resp) => Ok(resp.into_string()?),
            Err(ureq::Error::Status(code, resp)) => {
                let text = resp.into_string().unwrap_or_default();
                match serde_json::from_str::<ErrorResponse>(&text) {
                    Ok(e) => bail!("{} ({})", e.message, e.error),
                    Err(_) => bail!("server returned HTTP {code}: {}", text.trim()),
                }
            }
            Err(e) => Err(anyhow!("cannot reach admin API at {}: {e}", self.base)),
        }
    }

    /// Resolve an id, a unique id prefix, or a unique name to a device.
    fn resolve(&self, needle: &str) -> Result<DeviceView> {
        let all: Vec<DeviceView> = self.call("GET", "/admin/v1/devices", None)?;
        if let Some(d) = all.iter().find(|d| d.id == needle) {
            return Ok(d.clone());
        }
        let matches: Vec<&DeviceView> = all
            .iter()
            .filter(|d| d.name == needle || d.id.starts_with(needle))
            .collect();
        match matches.len() {
            0 => bail!("no device matches '{needle}'"),
            1 => Ok(matches[0].clone()),
            n => bail!("'{needle}' is ambiguous ({n} devices match); use the full id"),
        }
    }

    fn show<T: serde::Serialize>(&self, value: &T, human: impl FnOnce()) -> Result<()> {
        if self.json {
            println!("{}", serde_json::to_string_pretty(value)?);
        } else {
            human();
        }
        Ok(())
    }
}

fn rel(now: i64, ts: i64) -> String {
    let d = ts - now;
    let abs = d.abs();
    let body = match abs {
        0..=2 => return "just now".into(),
        3..=119 => format!("{abs}s"),
        120..=7199 => format!("{}m", abs / 60),
        7200..=172_799 => format!("{}h", abs / 3600),
        _ => format!("{}d", abs / 86400),
    };
    if d > 0 {
        format!("in {body}")
    } else {
        format!("{body} ago")
    }
}

fn opt_rel(now: i64, ts: Option<i64>) -> String {
    ts.map(|t| rel(now, t)).unwrap_or_else(|| "never".into())
}

fn lease_text(d: &DeviceView) -> String {
    if d.state != DeviceState::Active {
        return "-".into();
    }
    if d.policy.on_lease_expiry == LeaseExpiry::Allow {
        return "no expiry".into();
    }
    if d.grace_until > d.now && d.grace_until > d.lease_until {
        return format!("approved, ends {}", rel(d.now, d.grace_until));
    }
    if d.lease_until >= d.now {
        format!("expires {}", rel(d.now, d.lease_until))
    } else {
        format!("EXPIRED {}", rel(d.now, d.lease_until))
    }
}

fn print_device(d: &DeviceView) {
    println!("id:           {}", d.id);
    println!("name:         {}", d.name);
    println!(
        "state:        {}{}",
        d.state.as_str(),
        d.state_reason
            .as_ref()
            .map(|r| format!(" ({r})"))
            .unwrap_or_default()
    );
    println!("lease:        {}", lease_text(d));
    println!(
        "last seen:    {} from {}",
        opt_rel(d.now, d.last_seen),
        d.last_ip.as_deref().unwrap_or("-")
    );
    println!("enrolled:     {}", rel(d.now, d.enrolled_at));
    println!(
        "key:          epoch {}{}, created {}, {} evaluation(s)",
        d.current_epoch,
        d.pending_epoch
            .map(|e| format!(" (rotation to {e} in flight)"))
            .unwrap_or_default(),
        rel(d.now, d.key_created_at),
        d.evaluations
    );
    println!("fingerprint:  {}", d.key_fingerprint);
    let p = &d.policy;
    println!(
        "policy:       lease {}s, heartbeat {}s, on expiry {}, rotation {}",
        p.lease_ttl_secs,
        p.heartbeat_interval_secs,
        if p.on_lease_expiry == LeaseExpiry::Lock {
            "lock"
        } else {
            "allow"
        },
        if p.rotation_interval_secs == 0 {
            "off".to_string()
        } else {
            format!("{}s", p.rotation_interval_secs)
        },
    );
    println!(
        "networks:     {}",
        if p.allowed_cidrs.is_empty() {
            "any".to_string()
        } else {
            p.allowed_cidrs
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
}

fn confirm(prompt: &str) -> Result<bool> {
    use std::io::Write;
    eprint!("{prompt} [type 'yes' to continue]: ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim() == "yes")
}

fn main() {
    if let Err(e) = run() {
        eprintln!("zknbectl: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let token = match &cli.token {
        Some(t) => t.clone(),
        None => std::fs::read_to_string(&cli.token_file)
            .with_context(|| {
                format!(
                    "cannot read admin token from {} (use --token-file or ZKNBE_ADMIN_TOKEN)",
                    cli.token_file.display()
                )
            })?
            .trim()
            .to_string(),
    };
    let c = Client {
        base: cli.url.clone(),
        token,
        agent: ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(20))
            .build(),
        json: cli.json,
    };

    match cli.cmd {
        Cmd::Status => {
            let s: StatusView = c.call("GET", "/admin/v1/status", None)?;
            c.show(&s, || {
                println!("zknbed {}  server id {}", s.version, s.server_id);
                println!("identity key {}", s.server_pubkey);
                for state in ["active", "locked", "suspended", "revoked"] {
                    println!(
                        "{:>10}: {}",
                        state,
                        s.devices.get(state).copied().unwrap_or(0)
                    );
                }
            })
        }

        Cmd::Token(TokenCmd::Create { name, ttl, policy }) => {
            let req = CreateTokenRequest {
                name,
                ttl_secs: Some(ttl),
                policy: policy.patch(),
            };
            let r: CreateTokenResponse =
                c.call("POST", "/admin/v1/tokens", Some(serde_json::to_value(req)?))?;
            c.show(&r, || {
                eprintln!("Single-use enrolment token (valid {}s, shown once):", ttl);
                println!("{}", r.token);
            })
        }
        Cmd::Token(TokenCmd::List) => {
            let list: Vec<TokenView> = c.call("GET", "/admin/v1/tokens", None)?;
            c.show(&list, || {
                println!("{:<14} {:<24} {:<8} USED BY", "ID", "NAME", "STATUS");
                for t in &list {
                    println!(
                        "{:<14} {:<24} {:<8} {}",
                        t.id,
                        t.name,
                        t.status,
                        t.used_by.as_deref().unwrap_or("-")
                    );
                }
            })
        }
        Cmd::Token(TokenCmd::Delete { id }) => {
            let v: serde_json::Value = c.call("DELETE", &format!("/admin/v1/tokens/{id}"), None)?;
            c.show(&v, || println!("deleted token {id}"))
        }

        Cmd::Device(DeviceCmd::List) => {
            let list: Vec<DeviceView> = c.call("GET", "/admin/v1/devices", None)?;
            c.show(&list, || {
                println!(
                    "{:<36} {:<20} {:<10} {:<12} {:<26} EPOCH",
                    "ID", "NAME", "STATE", "LAST SEEN", "LEASE"
                );
                for d in &list {
                    println!(
                        "{:<36} {:<20} {:<10} {:<12} {:<26} {}",
                        d.id,
                        d.name,
                        d.state.as_str(),
                        opt_rel(d.now, d.last_seen),
                        lease_text(d),
                        d.current_epoch
                    );
                }
            })
        }
        Cmd::Device(DeviceCmd::Show { device }) => {
            let d = c.resolve(&device)?;
            c.show(&d, || print_device(&d))
        }
        Cmd::Device(DeviceCmd::Approve { device, window }) => {
            let id = c.resolve(&device)?.id;
            let body = serde_json::to_value(ApproveRequest {
                window_secs: window,
            })?;
            let d: DeviceView = c.call(
                "POST",
                &format!("/admin/v1/devices/{id}/approve"),
                Some(body),
            )?;
            c.show(&d, || print_device(&d))
        }
        Cmd::Device(DeviceCmd::ApproveAllLocked { window, yes }) => {
            let list: Vec<DeviceView> = c.call("GET", "/admin/v1/devices", None)?;
            let locked: Vec<&DeviceView> = list
                .iter()
                .filter(|d| d.state == DeviceState::Locked)
                .collect();
            if locked.is_empty() {
                println!("no locked devices");
                return Ok(());
            }
            for d in &locked {
                eprintln!(
                    "  {}  {}  last seen {}",
                    d.id,
                    d.name,
                    opt_rel(d.now, d.last_seen)
                );
            }
            if !yes
                && !confirm(&format!(
                    "Approve {} locked device(s)? Make sure none of them is missing or stolen.",
                    locked.len()
                ))?
            {
                bail!("aborted");
            }
            for d in locked {
                let body = serde_json::to_value(ApproveRequest {
                    window_secs: window,
                })?;
                let _: DeviceView = c.call(
                    "POST",
                    &format!("/admin/v1/devices/{}/approve", d.id),
                    Some(body),
                )?;
                println!("approved {} ({})", d.name, d.id);
            }
            Ok(())
        }
        Cmd::Device(DeviceCmd::Suspend { device }) => {
            let id = c.resolve(&device)?.id;
            let d: DeviceView = c.call("POST", &format!("/admin/v1/devices/{id}/suspend"), None)?;
            c.show(&d, || print_device(&d))
        }
        Cmd::Device(DeviceCmd::Resume { device }) => {
            let id = c.resolve(&device)?.id;
            let d: DeviceView = c.call("POST", &format!("/admin/v1/devices/{id}/resume"), None)?;
            c.show(&d, || print_device(&d))
        }
        Cmd::Device(DeviceCmd::Revoke { device, yes }) => {
            let target = c.resolve(&device)?;
            if !yes
                && !confirm(&format!(
                    "Revoke '{}' ({})? Its key on this server is destroyed and cannot be restored.",
                    target.name, target.id
                ))?
            {
                bail!("aborted");
            }
            let d: DeviceView = c.call(
                "POST",
                &format!("/admin/v1/devices/{}/revoke", target.id),
                None,
            )?;
            c.show(&d, || print_device(&d))
        }
        Cmd::Device(DeviceCmd::Delete { device }) => {
            let id = c.resolve(&device)?.id;
            let v: serde_json::Value =
                c.call("DELETE", &format!("/admin/v1/devices/{id}"), None)?;
            c.show(&v, || println!("deleted device {id}"))
        }
        Cmd::Device(DeviceCmd::Policy { device, policy }) => {
            let id = c.resolve(&device)?.id;
            let d: DeviceView = c.call(
                "POST",
                &format!("/admin/v1/devices/{id}/policy"),
                Some(serde_json::to_value(policy.patch())?),
            )?;
            c.show(&d, || print_device(&d))
        }

        Cmd::Audit(AuditCmd::List { limit, device }) => {
            let mut path = format!("/admin/v1/audit?limit={limit}");
            if let Some(d) = device {
                path.push_str(&format!("&device={}", c.resolve(&d)?.id));
            }
            let list: Vec<AuditRecord> = c.call("GET", &path, None)?;
            let s: StatusView = c.call("GET", "/admin/v1/status", None)?;
            c.show(&list, || {
                for r in list.iter().rev() {
                    println!(
                        "{:>6}  {:<9} {:<22} {:<36} {:<14} {}",
                        r.seq,
                        rel(s.now, r.ts),
                        r.event,
                        r.device_id.as_deref().unwrap_or("-"),
                        r.actor,
                        r.detail
                    );
                }
            })
        }
        Cmd::Audit(AuditCmd::Verify) => {
            let v: AuditVerification = c.call("GET", "/admin/v1/audit/verify", None)?;
            c.show(&v, || {
                if v.ok {
                    println!(
                        "audit chain intact: {} record(s), head {}",
                        v.records,
                        v.head.as_deref().unwrap_or("-")
                    );
                } else {
                    println!(
                        "AUDIT CHAIN BROKEN at seq {}",
                        v.first_bad_seq.map(|s| s.to_string()).unwrap_or_default()
                    );
                }
            })?;
            if !v.ok {
                std::process::exit(2);
            }
            Ok(())
        }
    }
}
