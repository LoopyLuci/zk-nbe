//! Server configuration (TOML) and the per-device policy model.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub server: ServerSection,
    /// Policy applied to newly created enrolment tokens unless overridden.
    pub defaults: Policy,
    pub limits: Limits,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct ServerSection {
    /// Device-facing listener. Safe to expose: every request is authenticated end-to-end.
    pub listen: SocketAddr,
    /// Admin listener. Keep on loopback, or front it with TLS + network ACLs.
    pub admin_listen: SocketAddr,
    pub data_dir: PathBuf,
    /// Reverse proxies whose `X-Forwarded-For` header is trusted for client-IP policy.
    pub trusted_proxies: Vec<IpNet>,
    /// Defaults to `<data_dir>/admin.token`; generated on first start.
    pub admin_token_file: Option<PathBuf>,
    /// Key-encryption key for secrets at rest. Defaults to `<data_dir>/master.key`;
    /// generated on first start. Put it on separate media / a secrets manager mount if you can.
    pub master_key_file: Option<PathBuf>,
}

impl Default for ServerSection {
    fn default() -> Self {
        ServerSection {
            listen: "0.0.0.0:7421".parse().unwrap(),
            admin_listen: "127.0.0.1:7422".parse().unwrap(),
            data_dir: PathBuf::from("/var/lib/zknbe"),
            trusted_proxies: Vec::new(),
            admin_token_file: None,
            master_key_file: None,
        }
    }
}

impl ServerSection {
    pub fn admin_token_path(&self) -> PathBuf {
        self.admin_token_file
            .clone()
            .unwrap_or_else(|| self.data_dir.join("admin.token"))
    }
    pub fn master_key_path(&self) -> PathBuf {
        self.master_key_file
            .clone()
            .unwrap_or_else(|| self.data_dir.join("master.key"))
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LeaseExpiry {
    /// A device that goes silent for longer than its lease is locked until an admin approves it.
    Lock,
    /// Never lock automatically (Tang-like availability; revocation is manual only).
    Allow,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    /// How long a device may stay silent before it is considered missing.
    pub lease_ttl_secs: u64,
    /// How often the agent should heartbeat (advertised to the device).
    pub heartbeat_interval_secs: u64,
    pub on_lease_expiry: LeaseExpiry,
    /// Rotate the per-device OPRF key this often; 0 disables rotation.
    pub rotation_interval_secs: u64,
    /// If non-empty, requests must originate from one of these networks.
    pub allowed_cidrs: Vec<IpNet>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            lease_ttl_secs: 900,
            heartbeat_interval_secs: 120,
            on_lease_expiry: LeaseExpiry::Lock,
            rotation_interval_secs: 7 * 86400,
            allowed_cidrs: Vec::new(),
        }
    }
}

impl Policy {
    pub fn validate(&self) -> Result<(), String> {
        if self.heartbeat_interval_secs < 5 {
            return Err("heartbeat_interval_secs must be at least 5".into());
        }
        if self.lease_ttl_secs < self.heartbeat_interval_secs.saturating_mul(2) {
            return Err(
                "lease_ttl_secs must be at least twice heartbeat_interval_secs, otherwise one \
                 lost heartbeat locks the device"
                    .into(),
            );
        }
        if self.rotation_interval_secs != 0 && self.rotation_interval_secs < 60 {
            return Err("rotation_interval_secs must be 0 (disabled) or at least 60".into());
        }
        Ok(())
    }

    pub fn ip_allowed(&self, ip: IpAddr) -> bool {
        // Compare IPv4-mapped IPv6 addresses as IPv4.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        self.allowed_cidrs.is_empty() || self.allowed_cidrs.iter().any(|n| n.contains(&ip))
    }

    pub fn apply(&self, patch: &PolicyPatch) -> Policy {
        Policy {
            lease_ttl_secs: patch.lease_ttl_secs.unwrap_or(self.lease_ttl_secs),
            heartbeat_interval_secs: patch
                .heartbeat_interval_secs
                .unwrap_or(self.heartbeat_interval_secs),
            on_lease_expiry: patch.on_lease_expiry.unwrap_or(self.on_lease_expiry),
            rotation_interval_secs: patch
                .rotation_interval_secs
                .unwrap_or(self.rotation_interval_secs),
            allowed_cidrs: patch
                .allowed_cidrs
                .clone()
                .unwrap_or_else(|| self.allowed_cidrs.clone()),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_ttl_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_lease_expiry: Option<LeaseExpiry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_cidrs: Option<Vec<IpNet>>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Per-device cap on key evaluations.
    pub evaluations_per_minute: u32,
    pub challenge_ttl_secs: u64,
    pub max_pending_challenges: usize,
    /// Default one-off window granted by `zknbectl device approve`.
    pub approve_window_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            evaluations_per_minute: 12,
            challenge_ttl_secs: 60,
            max_pending_challenges: 100_000,
            approve_window_secs: 900,
        }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("invalid config {}: {e}", path.display()))?;
        cfg.defaults
            .validate()
            .map_err(|e| anyhow::anyhow!("[defaults] {e}"))?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_validation_and_cidrs() {
        let mut p = Policy::default();
        p.validate().unwrap();
        assert!(p.ip_allowed("203.0.113.9".parse().unwrap()));
        p.allowed_cidrs = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(p.ip_allowed("10.2.3.4".parse().unwrap()));
        assert!(p.ip_allowed("::ffff:10.2.3.4".parse().unwrap()));
        assert!(!p.ip_allowed("192.168.1.1".parse().unwrap()));
        p.lease_ttl_secs = p.heartbeat_interval_secs;
        assert!(p.validate().is_err());
    }

    #[test]
    fn config_parses_and_rejects_unknown_keys() {
        let cfg: Config = toml::from_str(
            "[server]\nlisten = \"127.0.0.1:1\"\n[defaults]\non_lease_expiry = \"allow\"\n",
        )
        .unwrap();
        assert_eq!(cfg.defaults.on_lease_expiry, LeaseExpiry::Allow);
        assert!(toml::from_str::<Config>("[server]\nlistne = \"x\"\n").is_err());
    }
}
