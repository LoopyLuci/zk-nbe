//! End-to-end tests: real key servers on loopback sockets, the real client library, the real
//! admin API. Only the clock is simulated.

use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use zknbe_client::agent::run_cycle;
use zknbe_client::net::{Http, NetError};
use zknbe_client::ops::{self, EnrollTarget, RotateOutcome, UnlockError};
use zknbe_client::state::{ClientState, FileStore, StateStore};
use zknbe_core::encoding::b64;
use zknbe_core::oprf::Blinding;
use zknbe_core::proto::*;
use zknbe_server::config::Config;
use zknbe_server::device_api::sweep;
use zknbe_server::state::AppState;

struct TestServer {
    st: Arc<AppState>,
    url: String,
    admin_url: String,
    admin_token: String,
    dir: tempfile::TempDir,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    _rt: tokio::runtime::Runtime,
}

impl TestServer {
    fn start() -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.server.data_dir = dir.path().to_path_buf();
        let st = Arc::new(AppState::init(cfg).unwrap());
        let admin_token = std::fs::read_to_string(dir.path().join("admin.token"))
            .unwrap()
            .trim()
            .to_string();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (dev_l, adm_l) = rt.block_on(async {
            (
                tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
                tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
            )
        });
        let url = format!("http://{}", dev_l.local_addr().unwrap());
        let admin_url = format!("http://{}", adm_l.local_addr().unwrap());
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let st2 = st.clone();
        rt.spawn(async move {
            zknbe_server::serve(st2, dev_l, adm_l, async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
        });
        TestServer {
            st,
            url,
            admin_url,
            admin_token,
            dir,
            stop: Some(stop),
            _rt: rt,
        }
    }

    fn admin(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, (u16, Value)> {
        let req = ureq::request(method, &format!("{}{}", self.admin_url, path))
            .set("Authorization", &format!("Bearer {}", self.admin_token));
        let result = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        match result {
            Ok(r) => Ok(r.into_json().unwrap()),
            Err(ureq::Error::Status(code, r)) => Err((code, r.into_json().unwrap_or(Value::Null))),
            Err(e) => panic!("admin transport error: {e}"),
        }
    }

    fn token(&self, policy: Value) -> String {
        self.admin(
            "POST",
            "/admin/v1/tokens",
            Some(json!({ "name": "test", "policy": policy })),
        )
        .unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn target(&self) -> EnrollTarget {
        EnrollTarget {
            url: self.url.clone(),
            token: self.token(json!({})),
        }
    }

    fn device(&self, id: &str) -> Value {
        self.admin("GET", &format!("/admin/v1/devices/{id}"), None)
            .unwrap()
    }

    fn shutdown(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        // Give the listener a moment to close so connections are refused, not hung.
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn http() -> Http {
    Http::new(Duration::from_secs(3))
}

fn enroll(servers: &[&TestServer], threshold: u8) -> (ClientState, String) {
    let targets: Vec<EnrollTarget> = servers.iter().map(|s| s.target()).collect();
    let (state, master) = ops::enroll(&http(), "host-under-test", threshold, &targets).unwrap();
    let pass = master.passphrase(&state.device_id).to_string();
    (state, pass)
}

fn unlock_err(state: &ClientState) -> UnlockError {
    ops::unlock(&http(), state)
        .unwrap_err()
        .downcast::<UnlockError>()
        .unwrap()
}

fn codes(e: &UnlockError) -> Vec<Option<String>> {
    e.failures
        .iter()
        .map(|(_, e)| e.code().map(str::to_string))
        .collect()
}

// ---------------------------------------------------------------------------------------

#[test]
fn two_of_three_unlocks_and_survives_one_server_outage() {
    let mut servers = [
        TestServer::start(),
        TestServer::start(),
        TestServer::start(),
    ];
    let (state, pass) = enroll(&[&servers[0], &servers[1], &servers[2]], 2);

    assert_eq!(*ops::unlock(&http(), &state).unwrap(), pass);
    assert_eq!(
        *ops::unlock(&http(), &state).unwrap(),
        pass,
        "unlock must be deterministic"
    );

    servers[0].shutdown();
    assert_eq!(
        *ops::unlock(&http(), &state).unwrap(),
        pass,
        "one server down: quorum still met"
    );

    servers[1].shutdown();
    let err = unlock_err(&state);
    assert_eq!((err.needed, err.obtained), (2, 1));
    assert!(!err.is_final(3), "an outage is retryable, not a refusal");
}

#[test]
fn key_server_stores_nothing_derived_from_the_disk_key() {
    let server = TestServer::start();
    let (state, pass) = enroll(&[&server], 1);
    ops::unlock(&http(), &state).unwrap();

    let zknbe_client::state::SecretStorage::Plain {
        value: device_secret,
    } = &state.secret
    else {
        panic!("expected plain secret")
    };
    let mut haystack = Vec::new();
    for entry in std::fs::read_dir(server.dir.path()).unwrap() {
        haystack.extend(std::fs::read(entry.unwrap().path()).unwrap());
    }
    let contains = |needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
    assert!(
        contains(state.device_id.as_bytes()),
        "sanity: the device id is on the server"
    );
    assert!(!contains(pass.as_bytes()));
    assert!(!contains(device_secret.as_bytes()));
    assert!(!contains(state.key_check.as_bytes()));
    assert!(!contains(state.servers[0].wrapped_share.as_bytes()));
}

#[test]
fn revocation_destroys_the_key_and_is_final() {
    let server = TestServer::start();
    let (state, _) = enroll(&[&server], 1);
    let id = &state.device_id;

    let view = server
        .admin("POST", &format!("/admin/v1/devices/{id}/revoke"), None)
        .unwrap();
    assert_eq!(view["state"], "revoked");

    let err = unlock_err(&state);
    assert_eq!(codes(&err), vec![Some("revoked".into())]);
    assert!(err.is_final(1));

    // Not reversible: no key is left to resume with.
    for action in ["resume", "approve"] {
        let (status, _) = server
            .admin("POST", &format!("/admin/v1/devices/{id}/{action}"), None)
            .unwrap_err();
        assert_eq!(status, 409, "{action} on a revoked device");
    }
    assert!(unlock_err(&state).is_final(1));

    // The agent sees the signed revocation.
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore(dir.path().join("state.json"));
    store.save(&state).unwrap();
    assert!(run_cycle(&http(), &store, &|_| {}).unwrap().revoked);
}

#[test]
fn revoking_a_minority_of_servers_keeps_quorum_but_a_majority_kills_it() {
    let servers = [
        TestServer::start(),
        TestServer::start(),
        TestServer::start(),
    ];
    let (state, pass) = enroll(&[&servers[0], &servers[1], &servers[2]], 2);
    let revoke = |s: &TestServer| {
        s.admin(
            "POST",
            &format!("/admin/v1/devices/{}/revoke", state.device_id),
            None,
        )
        .unwrap()
    };
    revoke(&servers[0]);
    assert_eq!(*ops::unlock(&http(), &state).unwrap(), pass);
    revoke(&servers[1]);
    assert!(unlock_err(&state).is_final(3));
}

#[test]
fn silent_device_is_locked_until_an_admin_approves() {
    let server = TestServer::start();
    let (state, pass) = enroll(&[&server], 1);
    let id = &state.device_id;
    let secret = state.secret.load().unwrap();

    // Heartbeats keep the lease alive across more than one TTL (default 900s).
    for _ in 0..3 {
        server.st.clock.advance(600);
        let hb = ops::heartbeat_all(&http(), &state, &secret)
            .remove(0)
            .result
            .unwrap();
        assert_eq!(hb.state, DeviceState::Active);
        assert_eq!(hb.lease_secs, 900);
    }
    assert_eq!(*ops::unlock(&http(), &state).unwrap(), pass);

    // The machine disappears for longer than its lease (stolen, in transit...).
    server.st.clock.advance(901);
    assert_eq!(
        sweep(&server.st).unwrap(),
        1,
        "sweeper locks the silent device"
    );
    assert_eq!(server.device(id)["state"], "locked");

    // Holding the device secret is not enough to revive it: neither unlock nor heartbeat.
    assert_eq!(codes(&unlock_err(&state)), vec![Some("locked".into())]);
    let hb = ops::heartbeat_all(&http(), &state, &secret)
        .remove(0)
        .result
        .unwrap();
    assert_eq!((hb.state, hb.lease_secs), (DeviceState::Locked, 0));
    assert_eq!(codes(&unlock_err(&state)), vec![Some("locked".into())]);

    // Administrator confirms the machine is where it should be.
    let view = server
        .admin("POST", &format!("/admin/v1/devices/{id}/approve"), None)
        .unwrap();
    assert_eq!(view["state"], "active");
    assert_eq!(*ops::unlock(&http(), &state).unwrap(), pass);
}

#[test]
fn lease_expiry_is_enforced_at_request_time_even_before_the_sweeper_runs() {
    let server = TestServer::start();
    let (state, _) = enroll(&[&server], 1);
    server.st.clock.advance(5000);
    assert_eq!(codes(&unlock_err(&state)), vec![Some("locked".into())]);
    assert_eq!(server.device(&state.device_id)["state"], "locked");
}

#[test]
fn approve_pre_authorises_planned_downtime() {
    let server = TestServer::start();
    let (state, pass) = enroll(&[&server], 1);
    let id = &state.device_id;
    server
        .admin(
            "POST",
            &format!("/admin/v1/devices/{id}/approve"),
            Some(json!({ "window_secs": 14400 })),
        )
        .unwrap();
    server.st.clock.advance(10_000); // long maintenance, well past the 900s lease
    assert_eq!(sweep(&server.st).unwrap(), 0);
    assert_eq!(*ops::unlock(&http(), &state).unwrap(), pass);
    // Once the window closes without a heartbeat, the normal rule applies again.
    server.st.clock.advance(14_400);
    assert_eq!(codes(&unlock_err(&state)), vec![Some("locked".into())]);
}

#[test]
fn allow_policy_never_auto_locks() {
    let server = TestServer::start();
    let target = EnrollTarget {
        url: server.url.clone(),
        token: server.token(json!({ "on_lease_expiry": "allow" })),
    };
    let (state, _) = ops::enroll(&http(), "tang-like", 1, &[target]).unwrap();
    server.st.clock.advance(1_000_000);
    assert_eq!(sweep(&server.st).unwrap(), 0);
    ops::unlock(&http(), &state).unwrap();
}

#[test]
fn suspend_and_resume() {
    let server = TestServer::start();
    let (state, pass) = enroll(&[&server], 1);
    let id = &state.device_id;
    server
        .admin("POST", &format!("/admin/v1/devices/{id}/suspend"), None)
        .unwrap();
    assert_eq!(codes(&unlock_err(&state)), vec![Some("suspended".into())]);
    server
        .admin("POST", &format!("/admin/v1/devices/{id}/resume"), None)
        .unwrap();
    assert_eq!(*ops::unlock(&http(), &state).unwrap(), pass);
}

#[test]
fn network_policy_gates_key_release() {
    let server = TestServer::start();
    let (state, pass) = enroll(&[&server], 1);
    let path = format!("/admin/v1/devices/{}/policy", state.device_id);

    server
        .admin(
            "POST",
            &path,
            Some(json!({ "allowed_cidrs": ["10.0.0.0/8"] })),
        )
        .unwrap();
    assert_eq!(
        codes(&unlock_err(&state)),
        vec![Some("network_denied".into())]
    );
    // A heartbeat from the wrong network must not extend the lease either.
    let secret = state.secret.load().unwrap();
    let before = server.device(&state.device_id)["lease_until"]
        .as_i64()
        .unwrap();
    server.st.clock.advance(100);
    ops::heartbeat_all(&http(), &state, &secret)
        .remove(0)
        .result
        .unwrap();
    assert_eq!(
        server.device(&state.device_id)["lease_until"]
            .as_i64()
            .unwrap(),
        before
    );

    server
        .admin(
            "POST",
            &path,
            Some(json!({ "allowed_cidrs": ["127.0.0.0/8"] })),
        )
        .unwrap();
    assert_eq!(*ops::unlock(&http(), &state).unwrap(), pass);

    let (status, body) = server
        .admin("POST", &path, Some(json!({ "lease_ttl_secs": 10 })))
        .unwrap_err();
    assert_eq!((status, body["error"].as_str()), (400, Some("bad_request")));
}

#[test]
fn rotation_invalidates_old_state_copies() {
    let server = TestServer::start();
    let (mut state, pass) = enroll(&[&server], 1);
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore(dir.path().join("state.json"));
    store.save(&state).unwrap();
    let stolen_copy = state.clone(); // e.g. an attacker imaged the disk last week

    let secret = state.secret.load().unwrap();
    let hb = ops::heartbeat_all(&http(), &state, &secret)
        .remove(0)
        .result
        .unwrap();
    assert!(!hb.rotate_due);
    assert_eq!(
        ops::rotate_server(&http(), &store, &mut state, &secret, 0, &hb, false).unwrap(),
        RotateOutcome::UpToDate
    );
    assert_eq!(
        ops::rotate_server(&http(), &store, &mut state, &secret, 0, &hb, true).unwrap(),
        RotateOutcome::Rotated { from: 1, to: 2 }
    );

    // Same disk passphrase, new server key, persisted state follows.
    assert_eq!(*ops::unlock(&http(), &store.load().unwrap()).unwrap(), pass);
    assert_ne!(
        state.servers[0].oprf_pubkey,
        stolen_copy.servers[0].oprf_pubkey
    );
    assert_eq!(server.device(&state.device_id)["current_epoch"], 2);

    // The old copy is dead: the server destroyed the epoch-1 key.
    assert_eq!(
        codes(&unlock_err(&stolen_copy)),
        vec![Some("epoch_mismatch".into())]
    );
}

#[test]
fn rotation_becomes_due_and_the_agent_performs_it() {
    let server = TestServer::start();
    let target = EnrollTarget {
        url: server.url.clone(),
        token: server.token(json!({ "rotation_interval_secs": 300 })),
    };
    let (state, master) = ops::enroll(&http(), "rotating", 1, &[target]).unwrap();
    let pass = master.passphrase(&state.device_id).to_string();
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore(dir.path().join("state.json"));
    store.save(&state).unwrap();

    run_cycle(&http(), &store, &|_| {}).unwrap();
    assert_eq!(store.load().unwrap().servers[0].epoch, 1, "not due yet");
    server.st.clock.advance(301);
    let cycle = run_cycle(&http(), &store, &|_| {}).unwrap();
    assert_eq!((cycle.healthy, cycle.total, cycle.revoked), (1, 1, false));
    let rotated = store.load().unwrap();
    assert_eq!(rotated.servers[0].epoch, 2);
    assert_eq!(*ops::unlock(&http(), &rotated).unwrap(), pass);
}

/// A store whose save can be made to fail before or after the data reaches the disk,
/// simulating a crash at either side of the commit point.
struct CrashyStore {
    inner: FileStore,
    fail_before_write: std::sync::atomic::AtomicBool,
    fail_after_write: std::sync::atomic::AtomicBool,
}

impl StateStore for CrashyStore {
    fn load(&self) -> anyhow::Result<ClientState> {
        self.inner.load()
    }
    fn save(&self, state: &ClientState) -> anyhow::Result<()> {
        use std::sync::atomic::Ordering::SeqCst;
        if self.fail_before_write.load(SeqCst) {
            anyhow::bail!("simulated crash before write");
        }
        self.inner.save(state)?;
        if self.fail_after_write.load(SeqCst) {
            anyhow::bail!("simulated crash after write");
        }
        Ok(())
    }
    fn describe(&self) -> String {
        "crashy".into()
    }
}

#[test]
fn rotation_is_crash_safe_on_both_sides_of_the_commit() {
    use std::sync::atomic::Ordering::SeqCst;
    let server = TestServer::start();
    let (mut state, pass) = enroll(&[&server], 1);
    let dir = tempfile::tempdir().unwrap();
    let store = CrashyStore {
        inner: FileStore(dir.path().join("state.json")),
        fail_before_write: false.into(),
        fail_after_write: false.into(),
    };
    store.save(&state).unwrap();
    let secret = state.secret.load().unwrap();
    let hb = || {
        ops::heartbeat_all(&http(), &store.load().unwrap(), &secret)
            .remove(0)
            .result
            .unwrap()
    };

    // Crash before the new state is written: the old state keeps working.
    store.fail_before_write.store(true, SeqCst);
    assert!(ops::rotate_server(&http(), &store, &mut state, &secret, 0, &hb(), true).is_err());
    store.fail_before_write.store(false, SeqCst);
    assert_eq!(state.servers[0].epoch, 1);
    assert_eq!(*ops::unlock(&http(), &store.load().unwrap()).unwrap(), pass);
    assert_eq!(server.device(&state.device_id)["pending_epoch"], 2);

    // Crash after the new state is written but before the commit: the new state works
    // (the server still serves the pending key)...
    store.fail_after_write.store(true, SeqCst);
    assert!(ops::rotate_server(&http(), &store, &mut state, &secret, 0, &hb(), true).is_err());
    store.fail_after_write.store(false, SeqCst);
    let on_disk = store.load().unwrap();
    assert_eq!(
        on_disk.servers[0].epoch, 3,
        "abandoned pending epoch 2 was superseded"
    );
    assert_eq!(*ops::unlock(&http(), &on_disk).unwrap(), pass);
    assert_eq!(server.device(&state.device_id)["current_epoch"], 1);

    // ...and the next agent run finishes the job.
    let mut state = on_disk;
    assert_eq!(
        ops::rotate_server(&http(), &store, &mut state, &secret, 0, &hb(), false).unwrap(),
        RotateOutcome::Committed(3)
    );
    let view = server.device(&state.device_id);
    assert_eq!(
        (
            view["current_epoch"].as_u64(),
            view["pending_epoch"].as_u64()
        ),
        (Some(3), None)
    );
    assert_eq!(*ops::unlock(&http(), &store.load().unwrap()).unwrap(), pass);
}

#[test]
fn client_detects_impersonated_or_misbehaving_servers() {
    let server = TestServer::start();
    let rogue = TestServer::start();
    let (state, _) = enroll(&[&server], 1);

    // Requests redirected to a different server: it does not know the device.
    let mut redirected = state.clone();
    redirected.servers[0].url = rogue.url.clone();
    assert_eq!(
        codes(&unlock_err(&redirected)),
        vec![Some("unauthorized".into())]
    );

    // A server answering with a key other than the pinned one fails the DLEQ proof.
    let mut wrong_oprf = state.clone();
    wrong_oprf.servers[0].oprf_pubkey = b64(&zknbe_core::oprf::OprfKey::generate().public());
    let err = unlock_err(&wrong_oprf);
    assert!(
        matches!(err.failures[0].1, NetError::Verification(_)),
        "{err}"
    );

    // Responses not signed by the pinned identity are rejected.
    let mut wrong_identity = state.clone();
    wrong_identity.servers[0].server_pubkey = b64(&zknbe_core::keys::Identity::generate().public());
    let err = unlock_err(&wrong_identity);
    assert!(
        matches!(err.failures[0].1, NetError::Verification(_)),
        "{err}"
    );

    // A corrupted local share is caught by the AEAD, not passed to cryptsetup.
    let mut corrupt = state.clone();
    let other = enroll(&[&rogue], 1).0;
    corrupt.servers[0].wrapped_share = other.servers[0].wrapped_share.clone();
    assert!(matches!(
        unlock_err(&corrupt).failures[0].1,
        NetError::Verification(_)
    ));
}

#[test]
fn server_rejects_replays_forgeries_and_malformed_input() {
    let server = TestServer::start();
    let (state, _) = enroll(&[&server], 1);
    let entry = &state.servers[0];
    let secret = state.secret.load().unwrap();
    let h = http();
    let nonce = || -> String {
        h.post::<_, ChallengeResponse>(
            &server.url,
            "/v1/challenge",
            &ChallengeRequest {
                device_id: state.device_id.clone(),
            },
        )
        .unwrap()
        .nonce
    };
    let build = |nonce: String, signer: &zknbe_core::keys::DeviceSecret, blinded: String| {
        let mut req = EvaluateRequest {
            device_id: state.device_id.clone(),
            nonce,
            epoch: entry.epoch,
            blinded,
            sig: String::new(),
        };
        req.sig = b64(&signer.sign(&req.transcript(&entry.server_id)));
        req
    };
    let send =
        |req: &EvaluateRequest| h.post::<_, EvaluateResponse>(&server.url, "/v1/evaluate", req);
    let blinded = || b64(&Blinding::new(b"x").blinded());
    let code = |r: Result<EvaluateResponse, NetError>| r.unwrap_err().code().map(str::to_string);

    // A valid request works exactly once.
    let req = build(nonce(), &secret, blinded());
    send(&req).unwrap();
    assert_eq!(
        code(send(&req)),
        Some("unauthorized".into()),
        "replayed nonce"
    );

    // Signed by someone who does not hold the device secret.
    let intruder = zknbe_core::keys::DeviceSecret::generate();
    assert_eq!(
        code(send(&build(nonce(), &intruder, blinded()))),
        Some("unauthorized".into())
    );

    // Never-issued nonce.
    assert_eq!(
        code(send(&build(b64(&[7u8; 24]), &secret, blinded()))),
        Some("unauthorized".into())
    );

    // Tampered after signing.
    let mut tampered = build(nonce(), &secret, blinded());
    tampered.blinded = blinded();
    assert_eq!(code(send(&tampered)), Some("unauthorized".into()));

    // Expired nonce.
    let stale = build(nonce(), &secret, blinded());
    server.st.clock.advance(61);
    assert_eq!(code(send(&stale)), Some("unauthorized".into()));

    // The identity element would make the output independent of the key.
    assert_eq!(
        code(send(&build(nonce(), &secret, b64(&[0u8; 32])))),
        Some("bad_request".into())
    );

    // Unknown devices are indistinguishable from bad signatures.
    let mut unknown = build(nonce(), &secret, blinded());
    unknown.device_id = "00000000-0000-4000-8000-000000000000".into();
    assert_eq!(code(send(&unknown)), Some("unauthorized".into()));
}

#[test]
fn evaluations_are_rate_limited_per_device() {
    let server = TestServer::start();
    let (state, _) = enroll(&[&server], 1); // enrolment used 1 of 12 evaluations
    for _ in 0..11 {
        ops::unlock(&http(), &state).unwrap();
    }
    assert_eq!(
        codes(&unlock_err(&state)),
        vec![Some("rate_limited".into())]
    );
    server.st.clock.advance(61);
    ops::unlock(&http(), &state).unwrap();
}

#[test]
fn enrolment_tokens_are_single_use_authenticated_and_expire() {
    let server = TestServer::start();
    let enroll_with = |token: String| {
        ops::enroll(
            &http(),
            "h",
            1,
            &[EnrollTarget {
                url: server.url.clone(),
                token,
            }],
        )
        .map(|_| ())
        .map_err(|e| format!("{e:#}"))
    };

    let token = server.token(json!({}));
    enroll_with(token.clone()).unwrap();
    assert!(
        enroll_with(token.clone())
            .unwrap_err()
            .contains("invalid_token"),
        "reuse"
    );

    // Right token id, wrong secret: the MAC does not verify.
    let fresh = server.token(json!({}));
    let mut parts: Vec<&str> = fresh.split('.').collect();
    let forged_secret = b64(&[1u8; 32]);
    parts[2] = &forged_secret;
    assert!(
        enroll_with(parts.join("."))
            .unwrap_err()
            .contains("invalid_token"),
        "forged"
    );
    enroll_with(fresh).unwrap(); // the failed attempt did not burn the real token

    let expiring = server.token(json!({}));
    server.st.clock.advance(3601);
    assert!(
        enroll_with(expiring).unwrap_err().contains("invalid_token"),
        "expired"
    );

    assert!(enroll_with("garbage".into())
        .unwrap_err()
        .contains("malformed"));
}

#[test]
fn enrolling_twice_with_the_same_server_is_refused() {
    let server = TestServer::start();
    let err = ops::enroll(&http(), "h", 1, &[server.target(), server.target()])
        .map(|_| ())
        .unwrap_err();
    assert!(format!("{err:#}").contains("independent"), "{err:#}");
}

#[test]
fn admin_api_requires_the_token() {
    let server = TestServer::start();
    for auth in [None, Some("Bearer wrong"), Some("Basic abc")] {
        let mut req = ureq::get(&format!("{}/admin/v1/devices", server.admin_url));
        if let Some(a) = auth {
            req = req.set("Authorization", a);
        }
        match req.call() {
            Err(ureq::Error::Status(401, _)) => {}
            other => panic!("expected 401, got {other:?}"),
        }
    }
    // The admin API is not reachable through the device listener at all.
    match ureq::get(&format!("{}/admin/v1/devices", server.url))
        .set("Authorization", &format!("Bearer {}", server.admin_token))
        .call()
    {
        Err(ureq::Error::Status(404, _)) => {}
        other => panic!("expected 404, got {other:?}"),
    }
}

#[test]
fn audit_log_records_decisions_and_detects_tampering() {
    let server = TestServer::start();
    let (state, _) = enroll(&[&server], 1);
    let id = &state.device_id;
    ops::unlock(&http(), &state).unwrap();
    server
        .admin("POST", &format!("/admin/v1/devices/{id}/suspend"), None)
        .unwrap();
    let _ = ops::unlock(&http(), &state);
    server
        .admin("POST", &format!("/admin/v1/devices/{id}/revoke"), None)
        .unwrap();

    let log = server
        .admin(
            "GET",
            &format!("/admin/v1/audit?limit=100&device={id}"),
            None,
        )
        .unwrap();
    let mut events: Vec<&str> = log
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["event"].as_str().unwrap())
        .collect();
    events.reverse();
    assert_eq!(
        events,
        [
            "device.enrolled",
            "key.evaluated", // wrapping the share at enrolment
            "key.evaluated",
            "device.suspended",
            "request.denied",
            "device.revoked"
        ]
    );

    let verify = || server.admin("GET", "/admin/v1/audit/verify", None).unwrap();
    assert_eq!(verify()["ok"], true);

    // Someone with database access rewrites history.
    let db = rusqlite::Connection::open(server.dir.path().join("zknbe.db")).unwrap();
    db.execute(
        "UPDATE audit SET detail = '{}' WHERE event = 'request.denied'",
        [],
    )
    .unwrap();
    let v = verify();
    assert_eq!(v["ok"], false);
    assert!(v["first_bad_seq"].as_i64().is_some());
}

#[test]
fn server_identity_and_keys_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.server.data_dir = dir.path().to_path_buf();
    let first = AppState::init(cfg.clone()).unwrap();
    let (id, key) = (first.server_id.clone(), first.server_pubkey.clone());
    drop(first);
    let second = AppState::init(cfg.clone()).unwrap();
    assert_eq!(
        (second.server_id.clone(), second.server_pubkey.clone()),
        (id, key)
    );
    drop(second);

    // With the wrong master key the server refuses to start rather than serve garbage.
    std::fs::write(dir.path().join("master.key"), b64(&[9u8; 32])).unwrap();
    assert!(AppState::init(cfg).is_err());
}
