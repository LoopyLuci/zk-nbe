//! SQLite persistence. All secrets at rest (per-device OPRF keys, token secrets, the server
//! identity seed) are sealed under the key-encryption key before they touch the database.
//!
//! Every handler runs inside one transaction ([`Store::tx`]) so policy checks, state
//! transitions and the audit record commit atomically.

use crate::config::Policy;
use crate::error::{ApiError, ApiResult};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;
use zeroize::Zeroizing;
use zknbe_core::encoding::{b64, Transcript};
use zknbe_core::oprf::OprfKey;
use zknbe_core::proto::DeviceState;
use zknbe_core::wrap;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    id          TEXT PRIMARY KEY,
    secret      BLOB NOT NULL,
    name        TEXT NOT NULL,
    policy      TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER,
    used_by     TEXT
);
CREATE TABLE IF NOT EXISTS devices (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    auth_pubkey      BLOB NOT NULL,
    state            TEXT NOT NULL,
    policy           TEXT NOT NULL,
    cur_epoch        INTEGER NOT NULL,
    cur_key          BLOB,
    cur_key_created  INTEGER NOT NULL,
    pend_epoch       INTEGER,
    pend_key         BLOB,
    enrolled_at      INTEGER NOT NULL,
    last_seen        INTEGER,
    last_ip          TEXT,
    lease_until      INTEGER NOT NULL,
    grace_until      INTEGER NOT NULL DEFAULT 0,
    state_reason     TEXT,
    eval_count       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit (
    seq        INTEGER PRIMARY KEY,
    ts         INTEGER NOT NULL,
    event      TEXT NOT NULL,
    device_id  TEXT,
    actor      TEXT NOT NULL,
    detail     TEXT NOT NULL,
    hash       BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_device ON audit(device_id);
"#;

pub struct Store {
    conn: Mutex<Connection>,
    kek: Zeroizing<[u8; 32]>,
}

pub struct Tx<'a> {
    tx: rusqlite::Transaction<'a>,
    kek: &'a [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub auth_pubkey: [u8; 32],
    pub state: DeviceState,
    pub policy: Policy,
    pub cur_epoch: u64,
    pub cur_key: Option<Vec<u8>>,
    pub cur_key_created: i64,
    pub pend_epoch: Option<u64>,
    pub pend_key: Option<Vec<u8>>,
    pub enrolled_at: i64,
    pub last_seen: Option<i64>,
    pub last_ip: Option<String>,
    pub lease_until: i64,
    pub grace_until: i64,
    pub state_reason: Option<String>,
    pub eval_count: u64,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub id: String,
    pub secret: Zeroizing<Vec<u8>>,
    pub name: String,
    pub policy: Policy,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub used_by: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditRecord {
    pub seq: i64,
    pub ts: i64,
    pub event: String,
    pub device_id: Option<String>,
    pub actor: String,
    pub detail: serde_json::Value,
    pub hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditVerification {
    pub ok: bool,
    pub records: i64,
    /// Hash of the newest record. Anchor it externally to detect truncation of the log.
    pub head: Option<String>,
    pub first_bad_seq: Option<i64>,
}

fn key_aad(device_id: &str, epoch: u64) -> Vec<u8> {
    Transcript::new("at-rest/oprf-key")
        .str(device_id)
        .u64(epoch)
        .finish()
}

fn audit_hash(
    prev: &[u8],
    seq: i64,
    ts: i64,
    event: &str,
    device_id: Option<&str>,
    actor: &str,
    detail: &str,
) -> Vec<u8> {
    let body = Transcript::new("audit")
        .bytes(prev)
        .u64(seq as u64)
        .u64(ts as u64)
        .str(event)
        .str(device_id.unwrap_or(""))
        .str(actor)
        .str(detail)
        .finish();
    Sha256::digest(body).to_vec()
}

impl Store {
    pub fn open(path: &Path, kek: [u8; 32]) -> anyhow::Result<Store> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        // Zero freed pages so destroyed key ciphertexts do not linger in the file.
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store {
            conn: Mutex::new(conn),
            kek: Zeroizing::new(kek),
        })
    }

    /// Run `f` in a transaction. Commits when `f` succeeds *and* when it returns a client-facing
    /// error (so that denials still persist their audit trail and state transitions); rolls
    /// back only on internal errors.
    pub fn tx<T>(&self, f: impl FnOnce(&Tx) -> ApiResult<T>) -> ApiResult<T> {
        let mut conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let tx = Tx {
            tx: conn.transaction()?,
            kek: &self.kek,
        };
        let result = f(&tx);
        match &result {
            Err(e) if e.is_internal() => {}
            _ => tx.tx.commit()?,
        }
        result
    }
}

impl Tx<'_> {
    // ------------------------------------------------------------ meta

    pub fn meta_get(&self, key: &str) -> ApiResult<Option<Vec<u8>>> {
        Ok(self
            .tx
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn meta_set(&self, key: &str, value: &[u8]) -> ApiResult<()> {
        self.tx.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        wrap::seal(self.kek, aad, plaintext)
    }

    pub fn unseal(&self, aad: &[u8], sealed: &[u8]) -> ApiResult<Zeroizing<Vec<u8>>> {
        wrap::open(self.kek, aad, sealed)
            .map(Zeroizing::new)
            .map_err(|_| {
                ApiError::internal(
                    "at-rest decryption failed: wrong master key or corrupt database",
                )
            })
    }

    // ------------------------------------------------------------ audit

    pub fn audit(
        &self,
        ts: i64,
        event: &str,
        device_id: Option<&str>,
        actor: &str,
        detail: serde_json::Value,
    ) -> ApiResult<()> {
        let last: Option<(i64, Vec<u8>)> = self
            .tx
            .query_row(
                "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (seq, prev) = match last {
            Some((seq, hash)) => (seq + 1, hash),
            None => (1, Vec::new()),
        };
        let detail = detail.to_string();
        let hash = audit_hash(&prev, seq, ts, event, device_id, actor, &detail);
        self.tx.execute(
            "INSERT INTO audit(seq, ts, event, device_id, actor, detail, hash) \
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![seq, ts, event, device_id, actor, detail, hash],
        )?;
        tracing::info!(target: "audit", seq, event, device = device_id.unwrap_or("-"), actor, %detail);
        Ok(())
    }

    pub fn audit_list(&self, limit: i64, device_id: Option<&str>) -> ApiResult<Vec<AuditRecord>> {
        let mut stmt = self.tx.prepare(
            "SELECT seq, ts, event, device_id, actor, detail, hash FROM audit \
             WHERE (?1 IS NULL OR device_id = ?1) ORDER BY seq DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![device_id, limit], |r| {
            let detail: String = r.get(5)?;
            let hash: Vec<u8> = r.get(6)?;
            Ok(AuditRecord {
                seq: r.get(0)?,
                ts: r.get(1)?,
                event: r.get(2)?,
                device_id: r.get(3)?,
                actor: r.get(4)?,
                detail: serde_json::from_str(&detail).unwrap_or(serde_json::Value::String(detail)),
                hash: b64(&hash),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn audit_verify(&self) -> ApiResult<AuditVerification> {
        let mut stmt = self.tx.prepare(
            "SELECT seq, ts, event, device_id, actor, detail, hash FROM audit ORDER BY seq ASC",
        )?;
        let mut rows = stmt.query([])?;
        let mut prev: Vec<u8> = Vec::new();
        let mut expected_seq = 1i64;
        let mut out = AuditVerification {
            ok: true,
            records: 0,
            head: None,
            first_bad_seq: None,
        };
        while let Some(r) = rows.next()? {
            let seq: i64 = r.get(0)?;
            let device_id: Option<String> = r.get(3)?;
            let event: String = r.get(2)?;
            let actor: String = r.get(4)?;
            let detail: String = r.get(5)?;
            let hash: Vec<u8> = r.get(6)?;
            let want = audit_hash(
                &prev,
                seq,
                r.get(1)?,
                &event,
                device_id.as_deref(),
                &actor,
                &detail,
            );
            if seq != expected_seq || want != hash {
                out.ok = false;
                out.first_bad_seq = Some(seq.min(expected_seq));
                break;
            }
            out.records += 1;
            out.head = Some(b64(&hash));
            prev = hash;
            expected_seq += 1;
        }
        Ok(out)
    }

    // ------------------------------------------------------------ tokens

    pub fn token_insert(&self, t: &Token) -> ApiResult<()> {
        let aad = Transcript::new("at-rest/token").str(&t.id).finish();
        self.tx.execute(
            "INSERT INTO tokens(id, secret, name, policy, created_at, expires_at) \
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                t.id,
                self.seal(&aad, &t.secret),
                t.name,
                serde_json::to_string(&t.policy).map_err(ApiError::internal)?,
                t.created_at,
                t.expires_at
            ],
        )?;
        Ok(())
    }

    fn token_from_row(&self, r: &Row) -> rusqlite::Result<(Token, Vec<u8>, String)> {
        Ok((
            Token {
                id: r.get(0)?,
                secret: Zeroizing::new(Vec::new()),
                name: r.get(2)?,
                policy: Policy::default(),
                created_at: r.get(4)?,
                expires_at: r.get(5)?,
                used_at: r.get(6)?,
                used_by: r.get(7)?,
            },
            r.get(1)?,
            r.get(3)?,
        ))
    }

    fn token_finish(&self, raw: (Token, Vec<u8>, String)) -> ApiResult<Token> {
        let (mut t, sealed, policy) = raw;
        let aad = Transcript::new("at-rest/token").str(&t.id).finish();
        t.secret = self.unseal(&aad, &sealed)?;
        t.policy = serde_json::from_str(&policy).map_err(ApiError::internal)?;
        Ok(t)
    }

    pub fn token_get(&self, id: &str) -> ApiResult<Option<Token>> {
        let raw = self
            .tx
            .query_row(
                "SELECT id, secret, name, policy, created_at, expires_at, used_at, used_by \
                 FROM tokens WHERE id = ?1",
                [id],
                |r| self.token_from_row(r),
            )
            .optional()?;
        raw.map(|r| self.token_finish(r)).transpose()
    }

    pub fn tokens_list(&self) -> ApiResult<Vec<Token>> {
        let mut stmt = self.tx.prepare(
            "SELECT id, secret, name, policy, created_at, expires_at, used_at, used_by \
             FROM tokens ORDER BY created_at DESC",
        )?;
        let raws = stmt
            .query_map([], |r| self.token_from_row(r))?
            .collect::<Result<Vec<_>, _>>()?;
        raws.into_iter().map(|r| self.token_finish(r)).collect()
    }

    pub fn token_mark_used(&self, id: &str, now: i64, device_id: &str) -> ApiResult<()> {
        // Keep the row for the audit trail but destroy the secret.
        self.tx.execute(
            "UPDATE tokens SET used_at = ?2, used_by = ?3, secret = ?4 WHERE id = ?1",
            params![id, now, device_id, {
                let aad = Transcript::new("at-rest/token").str(id).finish();
                self.seal(&aad, b"")
            }],
        )?;
        Ok(())
    }

    pub fn token_delete(&self, id: &str) -> ApiResult<bool> {
        Ok(self.tx.execute("DELETE FROM tokens WHERE id = ?1", [id])? > 0)
    }

    // ------------------------------------------------------------ devices

    pub fn seal_key(&self, device_id: &str, epoch: u64, key: &OprfKey) -> Vec<u8> {
        let bytes = Zeroizing::new(key.to_bytes());
        self.seal(&key_aad(device_id, epoch), &bytes[..])
    }

    pub fn open_key(&self, device_id: &str, epoch: u64, sealed: &[u8]) -> ApiResult<OprfKey> {
        let bytes = self.unseal(&key_aad(device_id, epoch), sealed)?;
        let arr: Zeroizing<[u8; 32]> = Zeroizing::new(
            bytes[..]
                .try_into()
                .map_err(|_| ApiError::internal("bad key length"))?,
        );
        OprfKey::from_bytes(&arr).map_err(ApiError::internal)
    }

    pub fn device_insert(&self, d: &Device) -> ApiResult<()> {
        self.tx.execute(
            "INSERT INTO devices(id, name, auth_pubkey, state, policy, cur_epoch, cur_key, \
             cur_key_created, enrolled_at, last_seen, last_ip, lease_until, grace_until) \
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                d.id,
                d.name,
                d.auth_pubkey.as_slice(),
                d.state.as_str(),
                serde_json::to_string(&d.policy).map_err(ApiError::internal)?,
                d.cur_epoch as i64,
                d.cur_key,
                d.cur_key_created,
                d.enrolled_at,
                d.last_seen,
                d.last_ip,
                d.lease_until,
                d.grace_until
            ],
        )?;
        Ok(())
    }

    const DEVICE_COLS: &'static str = "id, name, auth_pubkey, state, policy, cur_epoch, cur_key, \
        cur_key_created, pend_epoch, pend_key, enrolled_at, last_seen, last_ip, lease_until, \
        grace_until, state_reason, eval_count";

    fn device_from_row(r: &Row) -> rusqlite::Result<Device> {
        let bad = |i: usize, msg: &str| {
            rusqlite::Error::FromSqlConversionFailure(
                i,
                rusqlite::types::Type::Text,
                msg.to_string().into(),
            )
        };
        let pubkey: Vec<u8> = r.get(2)?;
        let state: String = r.get(3)?;
        let policy: String = r.get(4)?;
        Ok(Device {
            id: r.get(0)?,
            name: r.get(1)?,
            auth_pubkey: pubkey
                .try_into()
                .map_err(|_| bad(2, "auth_pubkey length"))?,
            state: DeviceState::parse(&state).ok_or_else(|| bad(3, "unknown state"))?,
            policy: serde_json::from_str(&policy).map_err(|_| bad(4, "policy json"))?,
            cur_epoch: r.get::<_, i64>(5)? as u64,
            cur_key: r.get(6)?,
            cur_key_created: r.get(7)?,
            pend_epoch: r.get::<_, Option<i64>>(8)?.map(|e| e as u64),
            pend_key: r.get(9)?,
            enrolled_at: r.get(10)?,
            last_seen: r.get(11)?,
            last_ip: r.get(12)?,
            lease_until: r.get(13)?,
            grace_until: r.get(14)?,
            state_reason: r.get(15)?,
            eval_count: r.get::<_, i64>(16)? as u64,
        })
    }

    pub fn device_get(&self, id: &str) -> ApiResult<Option<Device>> {
        Ok(self
            .tx
            .query_row(
                &format!("SELECT {} FROM devices WHERE id = ?1", Self::DEVICE_COLS),
                [id],
                Self::device_from_row,
            )
            .optional()?)
    }

    pub fn devices_list(&self) -> ApiResult<Vec<Device>> {
        let mut stmt = self.tx.prepare(&format!(
            "SELECT {} FROM devices ORDER BY name, id",
            Self::DEVICE_COLS
        ))?;
        let rows = stmt.query_map([], Self::device_from_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn device_set_state(
        &self,
        id: &str,
        state: DeviceState,
        reason: Option<&str>,
    ) -> ApiResult<()> {
        self.tx.execute(
            "UPDATE devices SET state = ?2, state_reason = ?3 WHERE id = ?1",
            params![id, state.as_str(), reason],
        )?;
        Ok(())
    }

    /// Record a sign of life and extend the lease.
    pub fn device_touch(
        &self,
        id: &str,
        now: i64,
        ip: &str,
        lease_until: i64,
        evaluated: bool,
    ) -> ApiResult<()> {
        self.tx.execute(
            "UPDATE devices SET last_seen = ?2, last_ip = ?3, lease_until = ?4, \
             eval_count = eval_count + ?5 WHERE id = ?1",
            params![id, now, ip, lease_until, evaluated as i64],
        )?;
        Ok(())
    }

    pub fn device_set_grace(&self, id: &str, grace_until: i64) -> ApiResult<()> {
        self.tx.execute(
            "UPDATE devices SET grace_until = ?2 WHERE id = ?1",
            params![id, grace_until],
        )?;
        Ok(())
    }

    pub fn device_set_policy(&self, id: &str, policy: &Policy) -> ApiResult<()> {
        self.tx.execute(
            "UPDATE devices SET policy = ?2 WHERE id = ?1",
            params![
                id,
                serde_json::to_string(policy).map_err(ApiError::internal)?
            ],
        )?;
        Ok(())
    }

    pub fn device_set_pending(&self, id: &str, epoch: u64, sealed_key: &[u8]) -> ApiResult<()> {
        self.tx.execute(
            "UPDATE devices SET pend_epoch = ?2, pend_key = ?3 WHERE id = ?1",
            params![id, epoch as i64, sealed_key],
        )?;
        Ok(())
    }

    /// Make the pending key current. The previous key is overwritten: after this, state
    /// captured before the rotation can no longer be used against this server.
    pub fn device_promote_pending(&self, id: &str, now: i64) -> ApiResult<()> {
        self.tx.execute(
            "UPDATE devices SET cur_epoch = pend_epoch, cur_key = pend_key, cur_key_created = ?2, \
             pend_epoch = NULL, pend_key = NULL WHERE id = ?1 AND pend_epoch IS NOT NULL",
            params![id, now],
        )?;
        Ok(())
    }

    /// Crypto-shred: destroy all key material for the device.
    pub fn device_destroy_keys(&self, id: &str) -> ApiResult<()> {
        self.tx.execute(
            "UPDATE devices SET cur_key = NULL, pend_key = NULL, pend_epoch = NULL WHERE id = ?1",
            [id],
        )?;
        Ok(())
    }

    pub fn device_delete(&self, id: &str) -> ApiResult<()> {
        self.tx.execute("DELETE FROM devices WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn device_state_counts(&self) -> ApiResult<Vec<(String, i64)>> {
        let mut stmt = self
            .tx
            .prepare("SELECT state, COUNT(*) FROM devices GROUP BY state")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}
