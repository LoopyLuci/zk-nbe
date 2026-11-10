//! Protocol operations: enrol, unlock, heartbeat, rotate.

use crate::net::{Http, NetError};
use crate::state::{ClientState, SecretStorage, ServerEntry, StateStore, STATE_VERSION};
use anyhow::{anyhow, bail, Context, Result};
use zeroize::Zeroizing;
use zknbe_core::encoding::{b64, unb64, unb64_array};
use zknbe_core::keys::{
    enroll_mac, random_bytes, share_aad, verify_enroll_mac, verify_signature, DeviceSecret,
    MasterKey,
};
use zknbe_core::oprf::{Blinding, Evaluation};
use zknbe_core::proto::*;
use zknbe_core::shamir::{self, Share};
use zknbe_core::wrap;

/// One key server as seen by one device.
pub struct Session<'a> {
    pub http: &'a Http,
    pub device_id: &'a str,
    pub secret: &'a DeviceSecret,
    pub url: &'a str,
    pub server_id: &'a str,
    pub server_pubkey: &'a str,
}

impl<'a> Session<'a> {
    pub fn new(
        http: &'a Http,
        device_id: &'a str,
        secret: &'a DeviceSecret,
        entry: &'a ServerEntry,
    ) -> Self {
        Session {
            http,
            device_id,
            secret,
            url: &entry.url,
            server_id: &entry.server_id,
            server_pubkey: &entry.server_pubkey,
        }
    }

    fn nonce(&self) -> Result<String, NetError> {
        let c: ChallengeResponse = self.http.post(
            self.url,
            "/v1/challenge",
            &ChallengeRequest {
                device_id: self.device_id.to_string(),
            },
        )?;
        Ok(c.nonce)
    }

    fn sign(&self, transcript: &[u8]) -> String {
        b64(&self.secret.sign(transcript))
    }

    fn verify(&self, transcript: &[u8], sig: &str) -> Result<(), NetError> {
        let bad = || {
            NetError::Verification(format!(
                "response from {} is not signed by the pinned server identity",
                self.url
            ))
        };
        let key: [u8; 32] = unb64_array(self.server_pubkey).map_err(|_| bad())?;
        let sig = unb64(sig).map_err(|_| bad())?;
        verify_signature(&key, transcript, &sig).map_err(|_| bad())
    }

    /// One OPRF evaluation: returns `F(k_epoch, x)` where `x` is derived from the device secret.
    /// The server sees only a uniformly random group element.
    pub fn evaluate(&self, epoch: u64, oprf_pubkey: &str) -> Result<Zeroizing<[u8; 64]>, NetError> {
        let input = self.secret.oprf_input(self.server_id);
        let blinding = Blinding::new(&input[..]);
        let mut req = EvaluateRequest {
            device_id: self.device_id.to_string(),
            nonce: self.nonce()?,
            epoch,
            blinded: b64(&blinding.blinded()),
            sig: String::new(),
        };
        req.sig = self.sign(&req.transcript(self.server_id));
        let resp: EvaluateResponse = self.http.post(self.url, "/v1/evaluate", &req)?;
        self.verify(&resp.transcript(self.server_id, &req), &resp.sig)?;

        let malformed =
            |what: &str| NetError::Verification(format!("malformed {what} from {}", self.url));
        if resp.epoch != epoch {
            return Err(malformed("epoch"));
        }
        let eval = Evaluation {
            evaluated: unb64_array(&resp.evaluated).map_err(|_| malformed("evaluation"))?,
            proof_c: unb64_array(&resp.proof_c).map_err(|_| malformed("proof"))?,
            proof_s: unb64_array(&resp.proof_s).map_err(|_| malformed("proof"))?,
        };
        let pinned: [u8; 32] = unb64_array(oprf_pubkey).map_err(|_| malformed("pinned key"))?;
        let out = blinding.finalize(&eval, &pinned).map_err(|e| {
            NetError::Verification(format!(
                "{} did not evaluate with the pinned key: {e}",
                self.url
            ))
        })?;
        Ok(Zeroizing::new(out))
    }

    pub fn heartbeat(&self) -> Result<HeartbeatResponse, NetError> {
        let mut req = HeartbeatRequest {
            device_id: self.device_id.to_string(),
            nonce: self.nonce()?,
            sig: String::new(),
        };
        req.sig = self.sign(&req.transcript(self.server_id));
        let resp: HeartbeatResponse = self.http.post(self.url, "/v1/heartbeat", &req)?;
        self.verify(&resp.transcript(self.server_id, &req), &resp.sig)?;
        Ok(resp)
    }

    fn rotate_begin(&self, client_epoch: u64) -> Result<RotateBeginResponse, NetError> {
        let mut req = RotateBeginRequest {
            device_id: self.device_id.to_string(),
            nonce: self.nonce()?,
            client_epoch,
            sig: String::new(),
        };
        req.sig = self.sign(&req.transcript(self.server_id));
        let resp: RotateBeginResponse = self.http.post(self.url, "/v1/rotate/begin", &req)?;
        self.verify(&resp.transcript(self.server_id, &req), &resp.sig)?;
        Ok(resp)
    }

    fn rotate_commit(&self, epoch: u64) -> Result<(), NetError> {
        let mut req = RotateCommitRequest {
            device_id: self.device_id.to_string(),
            nonce: self.nonce()?,
            epoch,
            sig: String::new(),
        };
        req.sig = self.sign(&req.transcript(self.server_id));
        let resp: RotateCommitResponse = self.http.post(self.url, "/v1/rotate/commit", &req)?;
        self.verify(&resp.transcript(self.server_id, &req), &resp.sig)?;
        if resp.current_epoch != epoch {
            return Err(NetError::Verification(
                "commit acknowledged the wrong epoch".into(),
            ));
        }
        Ok(())
    }
}

fn seal_share(
    secret: &DeviceSecret,
    oprf_output: &[u8; 64],
    device_id: &str,
    server_id: &str,
    epoch: u64,
    share: &Share,
) -> String {
    let key = secret.share_wrap_key(oprf_output, device_id, server_id, epoch);
    b64(&wrap::seal(
        &key,
        &share_aad(device_id, server_id, epoch, share.index),
        &share.data,
    ))
}

fn open_share(
    secret: &DeviceSecret,
    oprf_output: &[u8; 64],
    device_id: &str,
    entry: &ServerEntry,
) -> Result<Share, NetError> {
    let corrupt = || {
        NetError::Verification(format!(
            "stored share for {} does not decrypt (local state is corrupt or out of sync)",
            entry.url
        ))
    };
    let key = secret.share_wrap_key(oprf_output, device_id, &entry.server_id, entry.epoch);
    let sealed = unb64(&entry.wrapped_share).map_err(|_| corrupt())?;
    let data = wrap::open(
        &key,
        &share_aad(device_id, &entry.server_id, entry.epoch, entry.share_index),
        &sealed,
    )
    .map_err(|_| corrupt())?;
    Ok(Share {
        index: entry.share_index,
        data,
    })
}

// ------------------------------------------------------------------ enrolment

#[derive(Clone)]
pub struct EnrollTarget {
    pub url: String,
    pub token: String,
}

impl EnrollTarget {
    /// Parse `URL=TOKEN`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (url, token) = s
            .rsplit_once('=')
            .ok_or("expected URL=TOKEN, e.g. https://ks1.example.com=zkt1.…")?;
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err("server URL must start with http:// or https://".into());
        }
        Ok(EnrollTarget {
            url: url.trim_end_matches('/').to_string(),
            token: token.to_string(),
        })
    }
}

fn split_token(token: &str) -> Result<(String, Zeroizing<Vec<u8>>)> {
    let mut parts = token.trim().split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(TOKEN_PREFIX), Some(id), Some(secret), None) => Ok((
            id.to_string(),
            Zeroizing::new(unb64(secret).map_err(|_| anyhow!("malformed enrolment token"))?),
        )),
        _ => bail!("malformed enrolment token (expected {TOKEN_PREFIX}.<id>.<secret>)"),
    }
}

/// Enrol this device with every target and build the binding state.
///
/// Returns the state (to be persisted by the caller) and the freshly generated volume master
/// key (to derive the passphrase from; never stored).
pub fn enroll(
    http: &Http,
    name: &str,
    threshold: u8,
    targets: &[EnrollTarget],
) -> Result<(ClientState, MasterKey)> {
    let n = targets.len();
    if n == 0 || n > 255 {
        bail!("between 1 and 255 key servers are required");
    }
    if threshold == 0 || threshold as usize > n {
        bail!("threshold must be between 1 and the number of servers ({n})");
    }
    let tokens: Vec<_> = targets
        .iter()
        .map(|t| split_token(&t.token))
        .collect::<Result<_>>()?;

    // Pre-flight before consuming any single-use token.
    let mut seen_ids = Vec::new();
    for t in targets {
        let info: InfoResponse = http
            .get(&t.url, "/v1/info")
            .with_context(|| format!("key server {}", t.url))?;
        if info.protocol != PROTOCOL_VERSION {
            bail!(
                "{} speaks protocol {}, this client speaks {}",
                t.url,
                info.protocol,
                PROTOCOL_VERSION
            );
        }
        if seen_ids.contains(&info.server_id) {
            bail!(
                "{} is the same key server as another --server entry; servers must be independent",
                t.url
            );
        }
        seen_ids.push(info.server_id);
    }

    let secret = DeviceSecret::generate();
    let device_id = uuid::Uuid::new_v4().to_string();
    let master = MasterKey::generate();
    let shares =
        shamir::split(master.as_bytes(), threshold, n as u8).map_err(|e| anyhow!("{e}"))?;
    let mut servers = Vec::with_capacity(n);

    for (i, (target, (token_id, token_secret))) in targets.iter().zip(&tokens).enumerate() {
        let step = || -> Result<ServerEntry> {
            let mut req = EnrollRequest {
                token_id: token_id.clone(),
                device_id: device_id.clone(),
                name: name.to_string(),
                auth_pubkey: b64(&secret.auth_public()),
                client_nonce: b64(&random_bytes::<16>()),
                mac: String::new(),
                sig: String::new(),
            };
            let transcript = req.transcript();
            req.mac = b64(&enroll_mac(token_secret, &transcript));
            req.sig = b64(&secret.sign(&transcript));
            let resp: EnrollResponse = http.post(&target.url, "/v1/enroll", &req)?;
            // The token secret authenticates the server's keys: a man-in-the-middle without
            // the token cannot substitute its own.
            let mac = unb64(&resp.mac).map_err(|_| anyhow!("malformed enrolment response"))?;
            verify_enroll_mac(token_secret, &resp.transcript(&req), &mac).map_err(|_| {
                anyhow!(
                    "enrolment response is not authenticated by the token: possible interception"
                )
            })?;

            let mut entry = ServerEntry {
                url: target.url.clone(),
                server_id: resp.server_id,
                server_pubkey: resp.server_pubkey,
                share_index: shares[i].index,
                epoch: resp.epoch,
                oprf_pubkey: resp.oprf_pubkey,
                wrapped_share: String::new(),
                heartbeat_interval_secs: resp.heartbeat_interval_secs,
            };
            let out = Session::new(http, &device_id, &secret, &entry)
                .evaluate(entry.epoch, &entry.oprf_pubkey)?;
            entry.wrapped_share = seal_share(
                &secret,
                &out,
                &device_id,
                &entry.server_id,
                entry.epoch,
                &shares[i],
            );
            Ok(entry)
        };
        match step() {
            Ok(entry) => servers.push(entry),
            Err(e) => {
                let cleanup = format!(
                    "
Device id {device_id} may now be registered on: {}. Revoke and delete it                      there (zknbectl device revoke/delete), then enrol again with fresh tokens.",
                    targets[..=i].iter().map(|t| t.url.as_str()).collect::<Vec<_>>().join(", ")
                );
                return Err(e.context(format!("enrolment with {} failed{cleanup}", target.url)));
            }
        }
    }

    let state = ClientState {
        version: STATE_VERSION,
        key_check: master.check_value(&device_id),
        device_id,
        name: name.to_string(),
        threshold,
        secret: SecretStorage::plain(&secret),
        servers,
    };
    Ok((state, master))
}

// ------------------------------------------------------------------ unlock

#[derive(Debug)]
pub struct UnlockError {
    pub needed: usize,
    pub obtained: usize,
    pub failures: Vec<(String, NetError)>,
}

impl UnlockError {
    /// True when enough servers *refused on policy grounds* that no quorum is reachable until
    /// an administrator intervenes – retrying is pointless.
    pub fn is_final(&self, total: usize) -> bool {
        let denied = self
            .failures
            .iter()
            .filter(|(_, e)| e.is_policy_denial())
            .count();
        total - denied < self.needed
    }
}

impl std::fmt::Display for UnlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "only {} of the required {} key servers released a share",
            self.obtained, self.needed
        )?;
        for (url, e) in &self.failures {
            write!(f, "\n  {url}: {e}")?;
        }
        Ok(())
    }
}

impl std::error::Error for UnlockError {}

/// Contact all key servers in parallel and reconstruct the master key from any `threshold`
/// of them.
pub fn recover_master(
    http: &Http,
    state: &ClientState,
    secret: &DeviceSecret,
) -> Result<MasterKey, UnlockError> {
    let results: Vec<Result<Share, NetError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = state
            .servers
            .iter()
            .map(|entry| {
                scope.spawn(move || {
                    let out = Session::new(http, &state.device_id, secret, entry)
                        .evaluate(entry.epoch, &entry.oprf_pubkey)?;
                    open_share(secret, &out, &state.device_id, entry)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(NetError::Transport("worker panicked".into())))
            })
            .collect()
    });

    let needed = state.threshold as usize;
    let mut shares = Vec::new();
    let mut failures = Vec::new();
    for (entry, result) in state.servers.iter().zip(results) {
        match result {
            Ok(share) => shares.push(share),
            Err(e) => failures.push((entry.url.clone(), e)),
        }
    }
    if shares.len() < needed {
        return Err(UnlockError {
            needed,
            obtained: shares.len(),
            failures,
        });
    }
    let master = shamir::combine(&shares[..needed])
        .ok()
        .map(Zeroizing::new)
        .and_then(|bytes| MasterKey::from_slice(&bytes).ok())
        .filter(|m| m.matches(&state.device_id, &state.key_check));
    match master {
        Some(m) => Ok(m),
        None => {
            failures.push((
                "local state".into(),
                NetError::Verification(
                    "reconstructed key does not match the stored check value".into(),
                ),
            ));
            Err(UnlockError {
                needed,
                obtained: shares.len(),
                failures,
            })
        }
    }
}

/// The disk passphrase, or an error describing which servers refused and why.
pub fn unlock(http: &Http, state: &ClientState) -> Result<Zeroizing<String>> {
    let secret = state.secret.load()?;
    let master = recover_master(http, state, &secret)?;
    Ok(master.passphrase(&state.device_id))
}

/// Keep trying until `retry_for` has elapsed – at boot the network may not be up yet.
/// Gives up early when retrying cannot help: the device secret cannot be unsealed, or enough
/// key servers refused on policy grounds that no quorum is reachable.
pub fn unlock_with_retry(
    http: &Http,
    load_state: &dyn Fn() -> Result<ClientState>,
    retry_for: std::time::Duration,
    log: &dyn Fn(&str),
) -> Result<Zeroizing<String>> {
    let deadline = std::time::Instant::now() + retry_for;
    let mut delay = std::time::Duration::from_secs(1);
    loop {
        let (err, is_final) = match load_state() {
            Err(e) => (e, false),
            Ok(state) => match state.secret.load() {
                Err(e) => (e, true),
                Ok(secret) => match recover_master(http, &state, &secret) {
                    Ok(master) => return Ok(master.passphrase(&state.device_id)),
                    Err(e) => {
                        let is_final = e.is_final(state.servers.len());
                        (anyhow::Error::new(e), is_final)
                    }
                },
            },
        };
        if is_final || std::time::Instant::now() + delay > deadline {
            return Err(err);
        }
        log(&format!(
            "unlock attempt failed, retrying in {}s: {err:#}",
            delay.as_secs()
        ));
        std::thread::sleep(delay);
        delay = (delay * 2).min(std::time::Duration::from_secs(15));
    }
}

// ------------------------------------------------------------------ heartbeat & rotation

pub struct HeartbeatReport {
    pub url: String,
    pub result: Result<HeartbeatResponse, NetError>,
}

pub fn heartbeat_all(
    http: &Http,
    state: &ClientState,
    secret: &DeviceSecret,
) -> Vec<HeartbeatReport> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = state
            .servers
            .iter()
            .map(|entry| {
                scope.spawn(move || Session::new(http, &state.device_id, secret, entry).heartbeat())
            })
            .collect();
        handles
            .into_iter()
            .zip(&state.servers)
            .map(|(h, entry)| HeartbeatReport {
                url: entry.url.clone(),
                result: h
                    .join()
                    .unwrap_or_else(|_| Err(NetError::Transport("worker panicked".into()))),
            })
            .collect()
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum RotateOutcome {
    /// Nothing to do.
    UpToDate,
    /// A rotation interrupted earlier (after the local state was saved) was completed.
    Committed(u64),
    /// The server key was rotated and the local share re-wrapped under the new epoch.
    Rotated { from: u64, to: u64 },
}

/// Rotate the OPRF key held by server `index`, crash-safely:
///
/// 1. recover the share with the current key,
/// 2. ask the server to create a *pending* key (the current one stays valid),
/// 3. re-wrap the share under the pending key and persist the state atomically,
/// 4. commit – the server destroys the old key.
///
/// A crash before 3 leaves the old state valid; a crash between 3 and 4 leaves the new state
/// valid (the server serves pending keys) and the commit is replayed on the next run.
/// After step 4, any copy of the old state (a disk image, a backup) is useless against this
/// server.
pub fn rotate_server(
    http: &Http,
    store: &dyn StateStore,
    state: &mut ClientState,
    secret: &DeviceSecret,
    index: usize,
    hb: &HeartbeatResponse,
    force: bool,
) -> Result<RotateOutcome> {
    let device_id = state.device_id.clone();
    let entry = state.servers[index].clone();
    let session = Session::new(http, &device_id, secret, &entry);

    if hb.pending_epoch != 0 && hb.pending_epoch == entry.epoch {
        session.rotate_commit(entry.epoch)?;
        return Ok(RotateOutcome::Committed(entry.epoch));
    }
    if entry.epoch != hb.current_epoch {
        bail!(
            "local state is at epoch {} but {} is at epoch {}: the state is stale (restored from \
             a backup?) and can no longer be used with this server",
            entry.epoch,
            entry.url,
            hb.current_epoch
        );
    }
    if !(hb.rotate_due || force) {
        return Ok(RotateOutcome::UpToDate);
    }

    let old_out = session.evaluate(entry.epoch, &entry.oprf_pubkey)?;
    let share = open_share(secret, &old_out, &device_id, &entry)?;

    let begun = session.rotate_begin(entry.epoch)?;
    if begun.epoch <= entry.epoch {
        bail!("{} proposed a non-increasing epoch", entry.url);
    }
    let new_out = session.evaluate(begun.epoch, &begun.oprf_pubkey)?;

    let updated = &mut state.servers[index];
    updated.epoch = begun.epoch;
    updated.oprf_pubkey = begun.oprf_pubkey.clone();
    updated.wrapped_share = seal_share(
        secret,
        &new_out,
        &device_id,
        &entry.server_id,
        begun.epoch,
        &share,
    );
    if let Err(e) = store.save(state) {
        state.servers[index] = entry; // keep the in-memory view consistent with disk
        return Err(
            e.context("could not persist rotated state; rotation abandoned (old key still valid)")
        );
    }

    session.rotate_commit(begun.epoch)?;
    Ok(RotateOutcome::Rotated {
        from: entry.epoch,
        to: begun.epoch,
    })
}
