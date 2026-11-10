//! Shared server state: storage, identity, clock, single-use challenges and rate limiting.

use crate::config::Config;
use crate::error::{ApiError, ApiResult};
use crate::store::Store;
use axum::http::StatusCode;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use zknbe_core::encoding::{b64, unb64_array, Transcript};
use zknbe_core::keys::{random_bytes, Identity};

/// Wall clock with a test-controllable offset.
#[derive(Default)]
pub struct Clock {
    offset: AtomicI64,
}

impl Clock {
    pub fn now(&self) -> i64 {
        let real = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        real as i64 + self.offset.load(Ordering::Relaxed)
    }

    /// Move the clock forward (tests only).
    pub fn advance(&self, secs: i64) {
        self.offset.fetch_add(secs, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct Metrics {
    pub evaluations: AtomicU64,
    pub denials: AtomicU64,
    pub auth_failures: AtomicU64,
    pub heartbeats: AtomicU64,
    pub rotations: AtomicU64,
    pub enrollments: AtomicU64,
    pub auto_locks: AtomicU64,
}

pub struct AppState {
    pub cfg: Config,
    pub store: Store,
    pub identity: Identity,
    pub server_id: String,
    pub server_pubkey: String,
    pub clock: Clock,
    pub metrics: Metrics,
    admin_token_hash: [u8; 32],
    /// nonce -> (device id, expiry). In memory on purpose: a restart invalidates all challenges.
    challenges: Mutex<HashMap<String, (String, i64)>>,
    /// device id -> (window start, evaluations in window)
    rate: Mutex<HashMap<String, (i64, u32)>>,
}

fn write_secret_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

/// Read a secret file, creating it with fresh random contents on first start.
fn load_or_create(path: &Path, prefix: &str) -> anyhow::Result<String> {
    if !path.exists() {
        let value = format!("{prefix}{}", b64(&random_bytes::<32>()));
        write_secret_file(path, &value)
            .map_err(|e| anyhow::anyhow!("cannot create {}: {e}", path.display()))?;
        tracing::warn!("generated new secret file {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "{} is accessible by group/other (mode {:o}); run chmod 600",
                path.display(),
                mode & 0o777
            );
        }
    }
    let value = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    Ok(value.trim().to_string())
}

impl AppState {
    pub fn init(cfg: Config) -> anyhow::Result<AppState> {
        let dir = &cfg.server.data_dir;
        std::fs::create_dir_all(dir)
            .map_err(|e| anyhow::anyhow!("cannot create data dir {}: {e}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }

        let kek_text = load_or_create(&cfg.server.master_key_path(), "")?;
        let kek: [u8; 32] = unb64_array(&kek_text).map_err(|_| {
            anyhow::anyhow!(
                "{} must contain a base64url-encoded 32-byte key",
                cfg.server.master_key_path().display()
            )
        })?;
        let admin_token = load_or_create(&cfg.server.admin_token_path(), "zka1.")?;
        if admin_token.len() < 32 {
            anyhow::bail!("admin token is too short; use at least 32 random characters");
        }

        let store = Store::open(&dir.join("zknbe.db"), kek)?;
        let (server_id, identity) = store
            .tx(|tx| {
                let aad = Transcript::new("at-rest/identity").finish();
                match (tx.meta_get("server_id")?, tx.meta_get("identity")?) {
                    (Some(id), Some(sealed)) => {
                        let seed = tx.unseal(&aad, &sealed)?;
                        let seed: [u8; 32] = seed[..]
                            .try_into()
                            .map_err(|_| ApiError::internal("identity seed length"))?;
                        Ok((
                            String::from_utf8_lossy(&id).into_owned(),
                            Identity::from_seed(&seed),
                        ))
                    }
                    _ => {
                        let id = b64(&random_bytes::<16>());
                        let identity = Identity::generate();
                        tx.meta_set("server_id", id.as_bytes())?;
                        tx.meta_set("identity", &tx.seal(&aad, &identity.seed()[..]))?;
                        Ok((id, identity))
                    }
                }
            })
            .map_err(|e| anyhow::anyhow!("cannot initialise server identity: {}", e.message))?;

        Ok(AppState {
            server_pubkey: b64(&identity.public()),
            server_id,
            identity,
            store,
            clock: Clock::default(),
            metrics: Metrics::default(),
            admin_token_hash: Sha256::digest(admin_token.as_bytes()).into(),
            challenges: Mutex::new(HashMap::new()),
            rate: Mutex::new(HashMap::new()),
            cfg,
        })
    }

    pub fn admin_token_ok(&self, presented: &str) -> bool {
        use subtle::ConstantTimeEq;
        let h: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        h.ct_eq(&self.admin_token_hash).into()
    }

    pub fn issue_challenge(&self, device_id: &str) -> ApiResult<String> {
        let now = self.clock.now();
        let mut map = self.challenges.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() >= self.cfg.limits.max_pending_challenges {
            map.retain(|_, (_, exp)| *exp > now);
            if map.len() >= self.cfg.limits.max_pending_challenges {
                return Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "busy",
                    "too many pending challenges, retry shortly",
                ));
            }
        }
        let nonce = b64(&random_bytes::<24>());
        map.insert(
            nonce.clone(),
            (
                device_id.to_string(),
                now + self.cfg.limits.challenge_ttl_secs as i64,
            ),
        );
        Ok(nonce)
    }

    /// Consume a challenge. Each nonce authorises exactly one request from one device.
    pub fn take_challenge(&self, nonce: &str, device_id: &str) -> bool {
        let now = self.clock.now();
        let mut map = self.challenges.lock().unwrap_or_else(|p| p.into_inner());
        match map.remove(nonce) {
            Some((dev, exp)) => dev == device_id && exp > now,
            None => false,
        }
    }

    pub fn purge_challenges(&self) {
        let now = self.clock.now();
        self.challenges
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, (_, exp)| *exp > now);
        self.rate
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, (start, _)| now - *start < 60);
    }

    /// Fixed-window limiter on key evaluations per device.
    pub fn rate_ok(&self, device_id: &str) -> bool {
        let now = self.clock.now();
        let mut map = self.rate.lock().unwrap_or_else(|p| p.into_inner());
        let entry = map.entry(device_id.to_string()).or_insert((now, 0));
        if now - entry.0 >= 60 {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.cfg.limits.evaluations_per_minute
    }
}
