//! Administrative API. Served on its own listener (loopback by default) and guarded by a
//! bearer token. Types here are shared with `zknbectl`.

use crate::config::{Policy, PolicyPatch};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::store::{AuditRecord, AuditVerification, Device, Token};
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use zeroize::Zeroizing;
use zknbe_core::encoding::b64;
use zknbe_core::keys::random_bytes;
use zknbe_core::proto::{DeviceState, TOKEN_PREFIX};

type St = State<Arc<AppState>>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceView {
    pub id: String,
    pub name: String,
    pub state: DeviceState,
    pub state_reason: Option<String>,
    pub policy: Policy,
    pub key_fingerprint: String,
    pub current_epoch: u64,
    pub pending_epoch: Option<u64>,
    pub key_created_at: i64,
    pub enrolled_at: i64,
    pub last_seen: Option<i64>,
    pub last_ip: Option<String>,
    pub lease_until: i64,
    pub grace_until: i64,
    pub evaluations: u64,
    /// Server time when this view was produced, so clients can compute relative ages.
    pub now: i64,
}

impl DeviceView {
    fn from(d: Device, now: i64) -> Self {
        use sha2::{Digest, Sha256};
        DeviceView {
            key_fingerprint: b64(&Sha256::digest(d.auth_pubkey)[..9]),
            id: d.id,
            name: d.name,
            state: d.state,
            state_reason: d.state_reason,
            policy: d.policy,
            current_epoch: d.cur_epoch,
            pending_epoch: d.pend_epoch,
            key_created_at: d.cur_key_created,
            enrolled_at: d.enrolled_at,
            last_seen: d.last_seen,
            last_ip: d.last_ip,
            lease_until: d.lease_until,
            grace_until: d.grace_until,
            evaluations: d.eval_count,
            now,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenView {
    pub id: String,
    pub name: String,
    pub policy: Policy,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub used_by: Option<String>,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CreateTokenRequest {
    pub name: String,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub policy: PolicyPatch,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateTokenResponse {
    /// The full enrolment token. Shown once; hand it to `zknbe enroll`.
    pub token: String,
    pub id: String,
    pub expires_at: i64,
    pub policy: Policy,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ApproveRequest {
    #[serde(default)]
    pub window_secs: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StatusView {
    pub version: String,
    pub server_id: String,
    pub server_pubkey: String,
    pub now: i64,
    pub devices: std::collections::BTreeMap<String, i64>,
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<i64>,
    device: Option<String>,
}

pub fn router(st: Arc<AppState>) -> Router {
    Router::new()
        .route("/admin/v1/status", get(status))
        .route("/admin/v1/tokens", get(tokens_list).post(token_create))
        .route("/admin/v1/tokens/:id", delete(token_delete))
        .route("/admin/v1/devices", get(devices_list))
        .route(
            "/admin/v1/devices/:id",
            get(device_get).delete(device_delete),
        )
        .route("/admin/v1/devices/:id/approve", post(device_approve))
        .route("/admin/v1/devices/:id/suspend", post(device_suspend))
        .route("/admin/v1/devices/:id/resume", post(device_resume))
        .route("/admin/v1/devices/:id/revoke", post(device_revoke))
        .route("/admin/v1/devices/:id/policy", post(device_policy))
        .route("/admin/v1/audit", get(audit_list))
        .route("/admin/v1/audit/verify", get(audit_verify))
        .route("/metrics", get(metrics))
        .layer(middleware::from_fn_with_state(st.clone(), require_admin))
        .with_state(st)
}

async fn require_admin(State(st): St, req: Request, next: Next) -> Response {
    let ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| st.admin_token_ok(t.trim()))
        .unwrap_or(false);
    if !ok {
        return ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "admin token required",
        )
        .into_response();
    }
    next.run(req).await
}

/// Free-form operator label for the audit log (`zknbectl` sends the local user name).
/// It is informational only: everyone holding the admin token has the same authority.
fn actor(headers: &HeaderMap) -> String {
    let label: String = headers
        .get("x-zknbe-actor")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "-_.@".contains(*c))
        .take(48)
        .collect();
    if label.is_empty() {
        "admin".into()
    } else {
        format!("admin:{label}")
    }
}

fn load(tx: &crate::store::Tx, id: &str) -> ApiResult<Device> {
    tx.device_get(id)?
        .ok_or_else(|| ApiError::not_found(format!("no device with id {id}")))
}

async fn status(State(st): St) -> ApiResult<Json<StatusView>> {
    let now = st.clock.now();
    st.store.tx(|tx| {
        Ok(Json(StatusView {
            version: env!("CARGO_PKG_VERSION").into(),
            server_id: st.server_id.clone(),
            server_pubkey: st.server_pubkey.clone(),
            now,
            devices: tx.device_state_counts()?.into_iter().collect(),
        }))
    })
}

// -------------------------------------------------------------------- tokens

fn token_view(t: Token, now: i64) -> TokenView {
    let status = if t.used_at.is_some() {
        "used"
    } else if t.expires_at <= now {
        "expired"
    } else {
        "valid"
    };
    TokenView {
        id: t.id,
        name: t.name,
        policy: t.policy,
        created_at: t.created_at,
        expires_at: t.expires_at,
        used_at: t.used_at,
        used_by: t.used_by,
        status: status.into(),
    }
}

async fn token_create(
    State(st): St,
    headers: HeaderMap,
    Json(req): Json<CreateTokenRequest>,
) -> ApiResult<Json<CreateTokenResponse>> {
    let now = st.clock.now();
    if req.name.is_empty() || req.name.len() > 64 {
        return Err(ApiError::bad_request("name must be 1-64 characters"));
    }
    let ttl = req.ttl_secs.unwrap_or(3600);
    if !(60..=30 * 86400).contains(&ttl) {
        return Err(ApiError::bad_request(
            "ttl must be between 1 minute and 30 days",
        ));
    }
    let policy = st.cfg.defaults.apply(&req.policy);
    policy.validate().map_err(ApiError::bad_request)?;

    let id = b64(&random_bytes::<9>());
    let secret = Zeroizing::new(random_bytes::<32>());
    let token = Token {
        id: id.clone(),
        secret: Zeroizing::new(secret.to_vec()),
        name: req.name.clone(),
        policy: policy.clone(),
        created_at: now,
        expires_at: now + ttl as i64,
        used_at: None,
        used_by: None,
    };
    st.store.tx(|tx| {
        tx.token_insert(&token)?;
        tx.audit(
            now,
            "token.created",
            None,
            &actor(&headers),
            json!({ "token": id, "name": req.name, "expires_at": token.expires_at }),
        )
    })?;
    Ok(Json(CreateTokenResponse {
        token: format!("{TOKEN_PREFIX}.{id}.{}", b64(&secret[..])),
        id,
        expires_at: token.expires_at,
        policy,
    }))
}

async fn tokens_list(State(st): St) -> ApiResult<Json<Vec<TokenView>>> {
    let now = st.clock.now();
    st.store.tx(|tx| {
        Ok(Json(
            tx.tokens_list()?
                .into_iter()
                .map(|t| token_view(t, now))
                .collect(),
        ))
    })
}

async fn token_delete(
    State(st): St,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let now = st.clock.now();
    st.store.tx(|tx| {
        if !tx.token_delete(&id)? {
            return Err(ApiError::not_found("no such token"));
        }
        tx.audit(
            now,
            "token.deleted",
            None,
            &actor(&headers),
            json!({ "token": id }),
        )?;
        Ok(Json(json!({ "deleted": id })))
    })
}

// -------------------------------------------------------------------- devices

async fn devices_list(State(st): St) -> ApiResult<Json<Vec<DeviceView>>> {
    let now = st.clock.now();
    st.store.tx(|tx| {
        Ok(Json(
            tx.devices_list()?
                .into_iter()
                .map(|d| DeviceView::from(d, now))
                .collect(),
        ))
    })
}

async fn device_get(State(st): St, Path(id): Path<String>) -> ApiResult<Json<DeviceView>> {
    let now = st.clock.now();
    st.store
        .tx(|tx| Ok(Json(DeviceView::from(load(tx, &id)?, now))))
}

/// Unlock a `locked` device, or pre-authorise downtime for an `active` one: for the next
/// `window_secs` the lease check is waived.
async fn device_approve(
    State(st): St,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<ApproveRequest>>,
) -> ApiResult<Json<DeviceView>> {
    let now = st.clock.now();
    let window = body
        .and_then(|b| b.window_secs)
        .unwrap_or(st.cfg.limits.approve_window_secs);
    if !(60..=30 * 86400).contains(&window) {
        return Err(ApiError::bad_request(
            "window must be between 1 minute and 30 days",
        ));
    }
    st.store.tx(|tx| {
        let dev = load(tx, &id)?;
        match dev.state {
            DeviceState::Locked | DeviceState::Active => {}
            other => {
                return Err(ApiError::conflict(
                    "invalid_state",
                    format!("cannot approve a {} device", other.as_str()),
                ))
            }
        }
        tx.device_set_state(&id, DeviceState::Active, None)?;
        tx.device_set_grace(&id, now + window as i64)?;
        tx.audit(
            now,
            "device.approved",
            Some(&id),
            &actor(&headers),
            json!({ "window_secs": window, "previous_state": dev.state.as_str() }),
        )?;
        Ok(Json(DeviceView::from(load(tx, &id)?, now)))
    })
}

async fn device_suspend(
    State(st): St,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<DeviceView>> {
    let now = st.clock.now();
    st.store.tx(|tx| {
        let dev = load(tx, &id)?;
        if dev.state == DeviceState::Revoked {
            return Err(ApiError::conflict("invalid_state", "device is revoked"));
        }
        tx.device_set_state(
            &id,
            DeviceState::Suspended,
            Some("suspended by administrator"),
        )?;
        tx.device_set_grace(&id, 0)?;
        tx.audit(
            now,
            "device.suspended",
            Some(&id),
            &actor(&headers),
            json!({}),
        )?;
        Ok(Json(DeviceView::from(load(tx, &id)?, now)))
    })
}

async fn device_resume(
    State(st): St,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<DeviceView>> {
    let now = st.clock.now();
    st.store.tx(|tx| {
        let dev = load(tx, &id)?;
        if dev.state != DeviceState::Suspended {
            return Err(ApiError::conflict(
                "invalid_state",
                "device is not suspended",
            ));
        }
        let window = st.cfg.limits.approve_window_secs;
        tx.device_set_state(&id, DeviceState::Active, None)?;
        tx.device_set_grace(&id, now + window as i64)?;
        tx.audit(
            now,
            "device.resumed",
            Some(&id),
            &actor(&headers),
            json!({ "window_secs": window }),
        )?;
        Ok(Json(DeviceView::from(load(tx, &id)?, now)))
    })
}

/// Irreversible: destroys the device's key material on this server.
async fn device_revoke(
    State(st): St,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<DeviceView>> {
    let now = st.clock.now();
    st.store.tx(|tx| {
        let dev = load(tx, &id)?;
        tx.device_destroy_keys(&id)?;
        tx.device_set_state(&id, DeviceState::Revoked, Some("revoked by administrator"))?;
        tx.device_set_grace(&id, 0)?;
        tx.audit(
            now,
            "device.revoked",
            Some(&id),
            &actor(&headers),
            json!({ "previous_state": dev.state.as_str() }),
        )?;
        Ok(Json(DeviceView::from(load(tx, &id)?, now)))
    })
}

/// Remove the record of a revoked device.
async fn device_delete(
    State(st): St,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let now = st.clock.now();
    st.store.tx(|tx| {
        let dev = load(tx, &id)?;
        if dev.state != DeviceState::Revoked {
            return Err(ApiError::conflict(
                "invalid_state",
                "revoke the device before deleting it",
            ));
        }
        tx.device_delete(&id)?;
        tx.audit(
            now,
            "device.deleted",
            Some(&id),
            &actor(&headers),
            json!({ "name": dev.name }),
        )?;
        Ok(Json(json!({ "deleted": id })))
    })
}

async fn device_policy(
    State(st): St,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(patch): Json<PolicyPatch>,
) -> ApiResult<Json<DeviceView>> {
    let now = st.clock.now();
    st.store.tx(|tx| {
        let dev = load(tx, &id)?;
        let policy = dev.policy.apply(&patch);
        policy.validate().map_err(ApiError::bad_request)?;
        tx.device_set_policy(&id, &policy)?;
        tx.audit(
            now,
            "device.policy_changed",
            Some(&id),
            &actor(&headers),
            serde_json::to_value(&patch).map_err(ApiError::internal)?,
        )?;
        Ok(Json(DeviceView::from(load(tx, &id)?, now)))
    })
}

// -------------------------------------------------------------------- audit & metrics

async fn audit_list(
    State(st): St,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditRecord>>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 10_000);
    st.store
        .tx(|tx| Ok(Json(tx.audit_list(limit, q.device.as_deref())?)))
}

async fn audit_verify(State(st): St) -> ApiResult<Json<AuditVerification>> {
    st.store.tx(|tx| Ok(Json(tx.audit_verify()?)))
}

async fn metrics(State(st): St) -> ApiResult<String> {
    let counts = st.store.tx(|tx| tx.device_state_counts())?;
    let m = &st.metrics;
    let mut out = String::new();
    out.push_str("# TYPE zknbe_devices gauge\n");
    for state in ["active", "locked", "suspended", "revoked"] {
        let n = counts
            .iter()
            .find(|(s, _)| s == state)
            .map(|(_, n)| *n)
            .unwrap_or(0);
        out.push_str(&format!("zknbe_devices{{state=\"{state}\"}} {n}\n"));
    }
    for (name, value) in [
        ("zknbe_evaluations_total", &m.evaluations),
        ("zknbe_denials_total", &m.denials),
        ("zknbe_auth_failures_total", &m.auth_failures),
        ("zknbe_heartbeats_total", &m.heartbeats),
        ("zknbe_rotations_total", &m.rotations),
        ("zknbe_enrollments_total", &m.enrollments),
        ("zknbe_auto_locks_total", &m.auto_locks),
    ] {
        out.push_str(&format!(
            "# TYPE {name} counter\n{name} {}\n",
            value.load(Ordering::Relaxed)
        ));
    }
    Ok(out)
}
