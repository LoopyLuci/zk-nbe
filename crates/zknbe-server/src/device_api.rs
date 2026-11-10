//! Device-facing API: enrolment, challenge, key evaluation, heartbeat and key rotation.

use crate::config::LeaseExpiry;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::store::{Device, Tx};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use zknbe_core::encoding::{b64, unb64, unb64_array};
use zknbe_core::keys::{enroll_mac, verify_enroll_mac, verify_signature};
use zknbe_core::oprf::OprfKey;
use zknbe_core::proto::*;

type St = State<Arc<AppState>>;

pub fn router(st: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/v1/info", get(info))
        .route("/v1/enroll", post(enroll))
        .route("/v1/challenge", post(challenge))
        .route("/v1/evaluate", post(evaluate))
        .route("/v1/heartbeat", post(heartbeat))
        .route("/v1/rotate/begin", post(rotate_begin))
        .route("/v1/rotate/commit", post(rotate_commit))
        .with_state(st)
}

/// The address policy is evaluated against: the TCP peer, unless the peer is a configured
/// trusted proxy, in which case the right-most `X-Forwarded-For` entry.
fn client_ip(st: &AppState, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    let peer_ip = peer.ip();
    if st
        .cfg
        .server
        .trusted_proxies
        .iter()
        .any(|n| n.contains(&peer_ip))
    {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
    }
    peer_ip
}

fn valid_device_id(id: &str) -> bool {
    (8..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| !c.is_control())
}

async fn info(State(st): St) -> Json<InfoResponse> {
    Json(InfoResponse {
        protocol: PROTOCOL_VERSION,
        version: env!("CARGO_PKG_VERSION").to_string(),
        server_id: st.server_id.clone(),
        server_pubkey: st.server_pubkey.clone(),
    })
}

// -------------------------------------------------------------------- enrolment

async fn enroll(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<EnrollRequest>,
) -> ApiResult<Json<EnrollResponse>> {
    let ip = client_ip(&st, peer, &headers);
    let now = st.clock.now();
    let invalid = || {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "enrolment token rejected",
        )
    };

    if !valid_device_id(&req.device_id) {
        return Err(ApiError::bad_request(
            "device_id must be 8-64 characters of [A-Za-z0-9-]",
        ));
    }
    if !valid_name(&req.name) {
        return Err(ApiError::bad_request(
            "name must be 1-64 printable characters",
        ));
    }
    let auth_pubkey: [u8; 32] =
        unb64_array(&req.auth_pubkey).map_err(|_| ApiError::bad_request("bad auth_pubkey"))?;
    let mac = unb64(&req.mac).map_err(|_| invalid())?;
    let sig = unb64(&req.sig).map_err(|_| invalid())?;
    let transcript = req.transcript();

    st.store.tx(|tx| {
        let token = tx.token_get(&req.token_id)?.ok_or_else(invalid)?;
        if token.used_at.is_some() || token.expires_at <= now {
            return Err(invalid());
        }
        verify_enroll_mac(&token.secret, &transcript, &mac).map_err(|_| invalid())?;
        // Proof of possession of the auth key being registered.
        verify_signature(&auth_pubkey, &transcript, &sig).map_err(|_| invalid())?;

        if tx.device_get(&req.device_id)?.is_some() {
            return Err(ApiError::conflict(
                "device_exists",
                "a device with this id already exists",
            ));
        }

        let key = OprfKey::generate();
        let epoch = 1u64;
        let device = Device {
            id: req.device_id.clone(),
            name: req.name.clone(),
            auth_pubkey,
            state: DeviceState::Active,
            policy: token.policy.clone(),
            cur_epoch: epoch,
            cur_key: Some(tx.seal_key(&req.device_id, epoch, &key)),
            cur_key_created: now,
            pend_epoch: None,
            pend_key: None,
            enrolled_at: now,
            last_seen: Some(now),
            last_ip: Some(ip.to_string()),
            lease_until: now + token.policy.lease_ttl_secs as i64,
            grace_until: 0,
            state_reason: None,
            eval_count: 0,
        };
        tx.device_insert(&device)?;
        tx.token_mark_used(&token.id, now, &device.id)?;
        tx.audit(
            now,
            "device.enrolled",
            Some(&device.id),
            "device",
            json!({ "name": device.name, "token": token.id, "ip": ip.to_string() }),
        )?;
        st.metrics.enrollments.fetch_add(1, Ordering::Relaxed);

        let mut resp = EnrollResponse {
            server_id: st.server_id.clone(),
            server_pubkey: st.server_pubkey.clone(),
            epoch,
            oprf_pubkey: b64(&key.public()),
            heartbeat_interval_secs: device.policy.heartbeat_interval_secs,
            mac: String::new(),
        };
        resp.mac = b64(&enroll_mac(&token.secret, &resp.transcript(&req)));
        Ok(Json(resp))
    })
}

// -------------------------------------------------------------------- challenge

async fn challenge(
    State(st): St,
    Json(req): Json<ChallengeRequest>,
) -> ApiResult<Json<ChallengeResponse>> {
    if !valid_device_id(&req.device_id) {
        return Err(ApiError::bad_request("bad device_id"));
    }
    // Issued whether or not the device exists, so this endpoint is not an existence oracle.
    Ok(Json(ChallengeResponse {
        nonce: st.issue_challenge(&req.device_id)?,
        ttl_secs: st.cfg.limits.challenge_ttl_secs,
    }))
}

/// Check the single-use nonce and the device signature. Every failure looks the same.
fn authenticate(
    st: &AppState,
    tx: &Tx,
    device_id: &str,
    nonce: &str,
    transcript: &[u8],
    sig: &str,
) -> ApiResult<Device> {
    let fail = || {
        st.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        ApiError::unauthorized()
    };
    let nonce_ok = st.take_challenge(nonce, device_id);
    let device = tx.device_get(device_id)?;
    let (Some(device), true) = (device, nonce_ok) else {
        return Err(fail());
    };
    let sig = unb64(sig).map_err(|_| fail())?;
    verify_signature(&device.auth_pubkey, transcript, &sig).map_err(|_| fail())?;
    Ok(device)
}

fn lease_ok(dev: &Device, now: i64) -> bool {
    dev.policy.on_lease_expiry == LeaseExpiry::Allow
        || now <= dev.lease_until
        || now <= dev.grace_until
}

fn lock_for_expired_lease(st: &AppState, tx: &Tx, dev: &Device, now: i64) -> ApiResult<()> {
    let reason = format!("lease expired {}s ago", now - dev.lease_until);
    tx.device_set_state(&dev.id, DeviceState::Locked, Some(&reason))?;
    tx.audit(
        now,
        "device.locked",
        Some(&dev.id),
        "system",
        json!({ "reason": "lease_expired", "last_seen": dev.last_seen, "lease_until": dev.lease_until }),
    )?;
    st.metrics.auto_locks.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// The policy gate in front of anything that releases or changes key material.
fn gate(st: &AppState, tx: &Tx, dev: &Device, ip: IpAddr, now: i64, action: &str) -> ApiResult<()> {
    let deny = |code: &'static str, message: &str| -> ApiResult<()> {
        tx.audit(
            now,
            "request.denied",
            Some(&dev.id),
            "device",
            json!({ "action": action, "reason": code, "ip": ip.to_string() }),
        )?;
        st.metrics.denials.fetch_add(1, Ordering::Relaxed);
        Err(ApiError::forbidden(code, message))
    };
    match dev.state {
        DeviceState::Active => {}
        DeviceState::Revoked => return deny("revoked", "device is revoked"),
        DeviceState::Suspended => return deny("suspended", "device is suspended"),
        DeviceState::Locked => {
            return deny("locked", "device is locked pending administrator approval")
        }
    }
    if !dev.policy.ip_allowed(ip) {
        return deny(
            "network_denied",
            "request origin is not permitted by policy",
        );
    }
    if !lease_ok(dev, now) {
        lock_for_expired_lease(st, tx, dev, now)?;
        return deny(
            "locked",
            "lease expired; device is locked pending administrator approval",
        );
    }
    Ok(())
}

// -------------------------------------------------------------------- evaluate

async fn evaluate(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<EvaluateRequest>,
) -> ApiResult<Json<EvaluateResponse>> {
    let ip = client_ip(&st, peer, &headers);
    let now = st.clock.now();
    let transcript = req.transcript(&st.server_id);

    st.store.tx(|tx| {
        let dev = authenticate(&st, tx, &req.device_id, &req.nonce, &transcript, &req.sig)?;
        gate(&st, tx, &dev, ip, now, "evaluate")?;
        if !st.rate_ok(&dev.id) {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many evaluations; retry in a minute",
            ));
        }

        let sealed = if req.epoch == dev.cur_epoch {
            dev.cur_key.as_ref()
        } else if Some(req.epoch) == dev.pend_epoch {
            dev.pend_key.as_ref()
        } else {
            None
        }
        .ok_or_else(|| {
            ApiError::conflict(
                "epoch_mismatch",
                format!(
                    "no key for epoch {} (current epoch is {})",
                    req.epoch, dev.cur_epoch
                ),
            )
        })?;
        let blinded: [u8; 32] =
            unb64_array(&req.blinded).map_err(|_| ApiError::bad_request("bad blinded element"))?;
        let key = tx.open_key(&dev.id, req.epoch, sealed)?;
        let eval = key
            .evaluate(&blinded)
            .map_err(|_| ApiError::bad_request("bad blinded element"))?;

        let lease = dev.policy.lease_ttl_secs;
        tx.device_touch(&dev.id, now, &ip.to_string(), now + lease as i64, true)?;
        tx.audit(
            now,
            "key.evaluated",
            Some(&dev.id),
            "device",
            json!({ "epoch": req.epoch, "ip": ip.to_string() }),
        )?;
        st.metrics.evaluations.fetch_add(1, Ordering::Relaxed);

        let mut resp = EvaluateResponse {
            epoch: req.epoch,
            evaluated: b64(&eval.evaluated),
            proof_c: b64(&eval.proof_c),
            proof_s: b64(&eval.proof_s),
            lease_secs: lease,
            sig: String::new(),
        };
        resp.sig = b64(&st.identity.sign(&resp.transcript(&st.server_id, &req)));
        Ok(Json(resp))
    })
}

// -------------------------------------------------------------------- heartbeat

async fn heartbeat(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> ApiResult<Json<HeartbeatResponse>> {
    let ip = client_ip(&st, peer, &headers);
    let now = st.clock.now();
    let transcript = req.transcript(&st.server_id);

    st.store.tx(|tx| {
        let dev = authenticate(&st, tx, &req.device_id, &req.nonce, &transcript, &req.sig)?;
        st.metrics.heartbeats.fetch_add(1, Ordering::Relaxed);

        // A heartbeat never fails for an authenticated device: it returns the *signed* state,
        // so the agent can act on "revoked" knowing it really came from the key server.
        let mut state = dev.state;
        let mut lease_secs = 0u64;
        if state == DeviceState::Active {
            if !lease_ok(&dev, now) {
                // The device was silent for longer than its lease. Possession of the device
                // secret alone must not be enough to revive it.
                lock_for_expired_lease(&st, tx, &dev, now)?;
                state = DeviceState::Locked;
            } else if !dev.policy.ip_allowed(ip) {
                // Wrong network: report state but do not extend the lease.
                tx.audit(
                    now,
                    "request.denied",
                    Some(&dev.id),
                    "device",
                    json!({ "action": "heartbeat", "reason": "network_denied", "ip": ip.to_string() }),
                )?;
                st.metrics.denials.fetch_add(1, Ordering::Relaxed);
                lease_secs = (dev.lease_until - now).max(0) as u64;
            } else {
                lease_secs = dev.policy.lease_ttl_secs;
                tx.device_touch(&dev.id, now, &ip.to_string(), now + lease_secs as i64, false)?;
            }
        }

        let rotation = dev.policy.rotation_interval_secs as i64;
        let mut resp = HeartbeatResponse {
            state,
            lease_secs,
            current_epoch: dev.cur_epoch,
            pending_epoch: dev.pend_epoch.unwrap_or(0),
            rotate_due: state == DeviceState::Active
                && rotation > 0
                && now - dev.cur_key_created >= rotation,
            heartbeat_interval_secs: dev.policy.heartbeat_interval_secs,
            sig: String::new(),
        };
        resp.sig = b64(&st.identity.sign(&resp.transcript(&st.server_id, &req)));
        Ok(Json(resp))
    })
}

// -------------------------------------------------------------------- rotation

async fn rotate_begin(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RotateBeginRequest>,
) -> ApiResult<Json<RotateBeginResponse>> {
    let ip = client_ip(&st, peer, &headers);
    let now = st.clock.now();
    let transcript = req.transcript(&st.server_id);

    st.store.tx(|tx| {
        let dev = authenticate(&st, tx, &req.device_id, &req.nonce, &transcript, &req.sig)?;
        gate(&st, tx, &dev, ip, now, "rotate_begin")?;
        if req.client_epoch != dev.cur_epoch {
            // Either the client already moved to the pending epoch (it must commit first) or
            // its state is stale. Never discard a pending key the client may depend on.
            return Err(ApiError::conflict(
                "epoch_mismatch",
                format!(
                    "client is at epoch {}, server current epoch is {}",
                    req.client_epoch, dev.cur_epoch
                ),
            ));
        }
        let epoch = dev.cur_epoch.max(dev.pend_epoch.unwrap_or(0)) + 1;
        let key = OprfKey::generate();
        tx.device_set_pending(&dev.id, epoch, &tx.seal_key(&dev.id, epoch, &key))?;
        tx.audit(
            now,
            "key.rotate_begin",
            Some(&dev.id),
            "device",
            json!({ "epoch": epoch }),
        )?;

        let mut resp = RotateBeginResponse {
            epoch,
            oprf_pubkey: b64(&key.public()),
            sig: String::new(),
        };
        resp.sig = b64(&st.identity.sign(&resp.transcript(&st.server_id, &req)));
        Ok(Json(resp))
    })
}

async fn rotate_commit(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RotateCommitRequest>,
) -> ApiResult<Json<RotateCommitResponse>> {
    let ip = client_ip(&st, peer, &headers);
    let now = st.clock.now();
    let transcript = req.transcript(&st.server_id);

    st.store.tx(|tx| {
        let dev = authenticate(&st, tx, &req.device_id, &req.nonce, &transcript, &req.sig)?;
        gate(&st, tx, &dev, ip, now, "rotate_commit")?;
        if Some(req.epoch) == dev.pend_epoch {
            tx.device_promote_pending(&dev.id, now)?;
            tx.audit(
                now,
                "key.rotated",
                Some(&dev.id),
                "device",
                json!({ "epoch": req.epoch, "previous": dev.cur_epoch }),
            )?;
            st.metrics.rotations.fetch_add(1, Ordering::Relaxed);
        } else if req.epoch != dev.cur_epoch {
            return Err(ApiError::conflict(
                "epoch_mismatch",
                format!("epoch {} is neither pending nor current", req.epoch),
            ));
        } // else: already committed (retry after a lost response) – idempotent success.

        let mut resp = RotateCommitResponse {
            current_epoch: req.epoch,
            sig: String::new(),
        };
        resp.sig = b64(&st.identity.sign(&resp.transcript(&st.server_id, &req)));
        Ok(Json(resp))
    })
}

// -------------------------------------------------------------------- sweeper

/// Lock every active device whose lease has lapsed. Runs periodically so that a stolen
/// machine shows up as `locked` (and in the audit log) even if it never calls in again.
pub fn sweep(st: &AppState) -> ApiResult<usize> {
    let now = st.clock.now();
    st.purge_challenges();
    st.store.tx(|tx| {
        let mut locked = 0;
        for dev in tx.devices_list()? {
            if dev.state == DeviceState::Active && !lease_ok(&dev, now) {
                lock_for_expired_lease(st, tx, &dev, now)?;
                locked += 1;
            }
        }
        Ok(locked)
    })
}
