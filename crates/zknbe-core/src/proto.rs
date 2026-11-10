//! Wire protocol: JSON bodies over HTTP. Binary values are base64url (no padding) strings.
//!
//! Every device request is signed with the device's Ed25519 auth key over a transcript that
//! includes a single-use server nonce; every response is signed with the key server's identity
//! key over a transcript that includes the same nonce. Signatures cover the *encoded strings*
//! exactly as transmitted, so there is no canonicalisation step to get wrong.
//!
//! Because both directions are authenticated end-to-end and the OPRF exchange is
//! information-theoretically blinded, the protocol does not depend on TLS for its security
//! (TLS is still recommended for metadata privacy).

use crate::encoding::Transcript;
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;
pub const TOKEN_PREFIX: &str = "zkt1";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InfoResponse {
    pub protocol: u32,
    pub version: String,
    pub server_id: String,
    pub server_pubkey: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorResponse {
    /// Stable machine-readable code, e.g. `locked`, `revoked`, `unauthorized`.
    pub error: String,
    pub message: String,
}

// ---------------------------------------------------------------- enrolment

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EnrollRequest {
    pub token_id: String,
    pub device_id: String,
    pub name: String,
    pub auth_pubkey: String,
    pub client_nonce: String,
    /// HMAC under the token secret – proves the caller holds the token without sending it.
    pub mac: String,
    /// Signature by the auth key – proof of possession.
    pub sig: String,
}

impl EnrollRequest {
    pub fn transcript(&self) -> Vec<u8> {
        Transcript::new("enroll-request")
            .str(&self.token_id)
            .str(&self.device_id)
            .str(&self.name)
            .str(&self.auth_pubkey)
            .str(&self.client_nonce)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EnrollResponse {
    pub server_id: String,
    pub server_pubkey: String,
    pub epoch: u64,
    pub oprf_pubkey: String,
    pub heartbeat_interval_secs: u64,
    /// HMAC under the token secret – authenticates the server's keys to the client.
    pub mac: String,
}

impl EnrollResponse {
    pub fn transcript(&self, req: &EnrollRequest) -> Vec<u8> {
        Transcript::new("enroll-response")
            .bytes(&req.transcript())
            .str(&self.server_id)
            .str(&self.server_pubkey)
            .u64(self.epoch)
            .str(&self.oprf_pubkey)
            .u64(self.heartbeat_interval_secs)
            .finish()
    }
}

// ---------------------------------------------------------------- challenge

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChallengeRequest {
    pub device_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChallengeResponse {
    pub nonce: String,
    pub ttl_secs: u64,
}

/// Common prefix of every signed request / response transcript.
fn bound(label: &str, server_id: &str, device_id: &str, nonce: &str) -> Transcript {
    Transcript::new(label)
        .str(server_id)
        .str(device_id)
        .str(nonce)
}

// ---------------------------------------------------------------- evaluate

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvaluateRequest {
    pub device_id: String,
    pub nonce: String,
    pub epoch: u64,
    pub blinded: String,
    pub sig: String,
}

impl EvaluateRequest {
    pub fn transcript(&self, server_id: &str) -> Vec<u8> {
        bound("evaluate-request", server_id, &self.device_id, &self.nonce)
            .u64(self.epoch)
            .str(&self.blinded)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvaluateResponse {
    pub epoch: u64,
    pub evaluated: String,
    pub proof_c: String,
    pub proof_s: String,
    pub lease_secs: u64,
    pub sig: String,
}

impl EvaluateResponse {
    pub fn transcript(&self, server_id: &str, req: &EvaluateRequest) -> Vec<u8> {
        bound("evaluate-response", server_id, &req.device_id, &req.nonce)
            .u64(self.epoch)
            .str(&req.blinded)
            .str(&self.evaluated)
            .str(&self.proof_c)
            .str(&self.proof_s)
            .u64(self.lease_secs)
            .finish()
    }
}

// ---------------------------------------------------------------- heartbeat

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HeartbeatRequest {
    pub device_id: String,
    pub nonce: String,
    pub sig: String,
}

impl HeartbeatRequest {
    pub fn transcript(&self, server_id: &str) -> Vec<u8> {
        bound("heartbeat-request", server_id, &self.device_id, &self.nonce).finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceState {
    /// Key release permitted, subject to lease and network policy.
    Active,
    /// The lease lapsed (device went silent); an administrator must approve the next unlock.
    Locked,
    /// Administratively disabled; reversible.
    Suspended,
    /// Key material destroyed; irreversible.
    Revoked,
}

impl DeviceState {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceState::Active => "active",
            DeviceState::Locked => "locked",
            DeviceState::Suspended => "suspended",
            DeviceState::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "active" => DeviceState::Active,
            "locked" => DeviceState::Locked,
            "suspended" => DeviceState::Suspended,
            "revoked" => DeviceState::Revoked,
            _ => return None,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HeartbeatResponse {
    pub state: DeviceState,
    /// Seconds of lease remaining (0 when not active).
    pub lease_secs: u64,
    pub current_epoch: u64,
    /// 0 when no rotation is in flight.
    pub pending_epoch: u64,
    pub rotate_due: bool,
    pub heartbeat_interval_secs: u64,
    pub sig: String,
}

impl HeartbeatResponse {
    pub fn transcript(&self, server_id: &str, req: &HeartbeatRequest) -> Vec<u8> {
        bound("heartbeat-response", server_id, &req.device_id, &req.nonce)
            .str(self.state.as_str())
            .u64(self.lease_secs)
            .u64(self.current_epoch)
            .u64(self.pending_epoch)
            .u64(self.rotate_due as u64)
            .u64(self.heartbeat_interval_secs)
            .finish()
    }
}

// ---------------------------------------------------------------- rotation

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotateBeginRequest {
    pub device_id: String,
    pub nonce: String,
    /// The epoch the client's stored share is currently wrapped under.
    pub client_epoch: u64,
    pub sig: String,
}

impl RotateBeginRequest {
    pub fn transcript(&self, server_id: &str) -> Vec<u8> {
        bound(
            "rotate-begin-request",
            server_id,
            &self.device_id,
            &self.nonce,
        )
        .u64(self.client_epoch)
        .finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotateBeginResponse {
    pub epoch: u64,
    pub oprf_pubkey: String,
    pub sig: String,
}

impl RotateBeginResponse {
    pub fn transcript(&self, server_id: &str, req: &RotateBeginRequest) -> Vec<u8> {
        bound(
            "rotate-begin-response",
            server_id,
            &req.device_id,
            &req.nonce,
        )
        .u64(self.epoch)
        .str(&self.oprf_pubkey)
        .finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotateCommitRequest {
    pub device_id: String,
    pub nonce: String,
    pub epoch: u64,
    pub sig: String,
}

impl RotateCommitRequest {
    pub fn transcript(&self, server_id: &str) -> Vec<u8> {
        bound(
            "rotate-commit-request",
            server_id,
            &self.device_id,
            &self.nonce,
        )
        .u64(self.epoch)
        .finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotateCommitResponse {
    pub current_epoch: u64,
    pub sig: String,
}

impl RotateCommitResponse {
    pub fn transcript(&self, server_id: &str, req: &RotateCommitRequest) -> Vec<u8> {
        bound(
            "rotate-commit-response",
            server_id,
            &req.device_id,
            &req.nonce,
        )
        .u64(self.current_epoch)
        .finish()
    }
}
