# Development guide

How the code is organised, the rules it relies on, and how to change it safely.
Read [DESIGN.md](DESIGN.md) first for the ideas; this page is about the code.

## Setup

```bash
cargo build --workspace
cargo test --workspace                       # ~10 s, any OS
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Requirements: current stable Rust and a C compiler (bundled SQLite, `ring`). No services, containers
or network access are needed for the test suite.

The LUKS path only exists on Linux:

```bash
cargo build --release
sudo scripts/luks-e2e.sh      # needs cryptsetup >= 2.4, python3, the dm-crypt kernel module
```

It uses a file-backed volume in a temp directory and cleans up after itself. On Windows, run
it inside WSL2. Set `ZKNBE_CRYPTSETUP=/path/to/cryptsetup` to use a specific binary and
`BIN=/path/to/dir` if the binaries are not in `target/release`.

## Code map

```
crates/zknbe-core/            pure cryptography + wire types. No I/O, no async, no clock.
  src/oprf.rs                 blind / evaluate / finalize, DLEQ proof
  src/shamir.rs               t-of-n secret sharing over GF(2^8)
  src/keys.rs                 key hierarchy (HKDF derivations), Ed25519 helpers, enrolment MAC
  src/wrap.rs                 ChaCha20-Poly1305 seal/open
  src/proto.rs                request/response structs and the transcript each one signs
  src/encoding.rs             base64url, Transcript builder, duration parsing

crates/zknbe-server/          the key server
  src/config.rs               TOML config, Policy, PolicyPatch
  src/store.rs                SQLite schema + every query; sealing of secrets at rest; audit chain
  src/state.rs                AppState: identity, clock, challenge nonces, rate limiter
  src/device_api.rs           device endpoints, the policy gate, the lease sweeper
  src/admin_api.rs            admin endpoints, shared view types
  src/lib.rs                  serve(): both listeners + sweeper task
  src/main.rs                 zknbed binary
  src/bin/zknbectl.rs         admin CLI (HTTP client of admin_api)

crates/zknbe-client/          the device side
  src/net.rs                  HTTP transport, NetError
  src/state.rs                ClientState, SecretStorage (plain / TPM), StateStore trait, FileStore
  src/luks.rs                 cryptsetup wrapper, LUKS2 token store (LuksStore)
  src/ops.rs                  enrol, unlock, heartbeat, rotate — the protocol logic
  src/agent.rs                heartbeat loop
  src/askpass.rs              systemd password-agent
  src/main.rs                 zknbe binary
  tests/e2e.rs                end-to-end tests (real servers on loopback, simulated clock)

dist/                         systemd units, dracut module, initramfs-tools hook, example config
scripts/luks-e2e.sh           real-LUKS test
scripts/gen-cli-docs.sh       regenerates docs/CLI.md
```

## How a request flows

`POST /v1/evaluate`, the request that matters most:

1. `device_api::evaluate` extracts the client address and builds the signed transcript.
2. `Store::tx` opens **one SQLite transaction** for everything that follows.
3. `authenticate` consumes the single-use nonce and verifies the Ed25519 signature.
   Any failure returns the same `unauthorized`.
4. `gate` applies policy in a fixed order: device state → network → lease.
   A lapsed lease flips the device to `locked` right here.
5. Rate limit, epoch lookup, unseal the OPRF key, evaluate, produce the DLEQ proof.
6. Renew the lease, append the audit record, sign the response.
7. The transaction commits — **also when the request was denied**, so the audit record and
   any state transition persist. Only internal errors roll back.

On the client, `ops::recover_master` runs one `Session::evaluate` per key server in parallel,
verifies each response (signature, then DLEQ against the pinned key), unwraps each share, and
combines the first `threshold` of them.

## Invariants — do not break these

These are the properties the security argument rests on. Each is pinned by a test; if you have
to change that test to make your change pass, stop and think.

| Invariant | Where enforced | Test |
|---|---|---|
| Nothing derived from the device secret, OPRF output, shares or master key ever reaches the server | `ops.rs` (what is sent), `proto.rs` (what can be sent) | `key_server_stores_nothing_derived_from_the_disk_key` |
| Every device request consumes a fresh nonce and is signed over a transcript containing server id, device id and nonce | `device_api::authenticate`, `proto.rs` | `server_rejects_replays_forgeries_and_malformed_input` |
| Every server response the client acts on is verified against pinned keys | `ops::Session::verify`, `Blinding::finalize` | `client_detects_impersonated_or_misbehaving_servers` |
| A lapsed lease can only be cleared by an admin `approve` — never by a heartbeat | `device_api::heartbeat`, `gate` | `silent_device_is_locked_until_an_admin_approves` |
| Revocation destroys key material and cannot be undone | `admin_api::device_revoke`, `Store::device_destroy_keys` | `revocation_destroys_the_key_and_is_final` |
| The server never discards a key the client may still depend on | `device_api::rotate_begin` / `rotate_commit` | `rotation_is_crash_safe_on_both_sides_of_the_commit` |
| State saves are atomic (old or new, never neither) | `FileStore::save`, `luks::write_token` | same, plus `interrupted_update_resolves_to_the_newest_generation` |
| Decision, state change and audit record commit together | `Store::tx` | `audit_log_records_decisions_and_detects_tampering` |
| The identity element is rejected as an OPRF input | `oprf::decode_element` | `rejects_identity_and_garbage_elements` |
| Secrets at rest are sealed under the key-encryption key with context-binding associated data | `store.rs` (`seal_key`, `token_insert`) | `server_identity_and_keys_survive_a_restart` |

General rules:

* **`zknbe-core` stays pure.** No I/O, no time, no randomness other than `OsRng`.
* **Wrap secrets in `Zeroizing` / derive `ZeroizeOnDrop`.** Never log or `Debug`-print them.
* **Compare secrets in constant time** (`subtle::ConstantTimeEq`).
* **Do not hand-roll encodings for signed data.** Use `Transcript`; it length-prefixes every field.
* **Unauthenticated errors must not distinguish causes** (no "unknown device" vs "bad signature").
* **Time comes from `AppState::clock`**, never `SystemTime::now()` directly — tests advance it.
* **Never remove or weaken the recovery path.** The client must not delete a keyslot it did
  not create, and must refuse to remove the last one.

## Changing the wire protocol

The protocol is versioned (`PROTOCOL_VERSION`, the `zknbe/v1` transcript prefix, `/v1/` paths).
Deployed devices cannot be updated atomically with servers, so:

* Adding an *optional* response field that is not security relevant: fine, but it is not
  covered by the signature unless you add it to the transcript — and adding it to the
  transcript is a breaking change.
* Anything that changes a transcript, a derivation label or an endpoint's semantics: new
  protocol version, with servers supporting both for a transition period.
* The client state format has its own `STATE_VERSION`; old bindings must keep loading.

Update [PROTOCOL.md](PROTOCOL.md) in the same change.

## Recipes

**Add a policy field** — `config.rs` (`Policy`, `PolicyPatch`, `apply`, `validate`, defaults) →
enforce it in `device_api::gate` → flag in `zknbectl` `PolicyArgs` → `dist/config/zknbed.toml` →
an e2e test → `OPERATIONS.md`. `Policy` is stored as JSON per device with
`#[serde(default)]`, so existing rows pick up the default.

**Add an admin action** — handler + route in `admin_api.rs` (inside `Store::tx`, with an
`audit` record) → subcommand in `zknbectl.rs` → e2e test → regenerate `CLI.md`.

**Add a device endpoint** — request/response structs with `transcript()` in `proto.rs` →
handler in `device_api.rs` using `authenticate` (+ `gate` if it touches keys) → method on
`ops::Session` that verifies the response signature → e2e test → `PROTOCOL.md`.

**Change the database schema** — there is no migration framework yet. `SCHEMA` uses
`CREATE TABLE IF NOT EXISTS`, which does not alter existing tables. A schema change must add
a `schema_version` entry in `meta` and an explicit upgrade step; do not ship one without it.

**Change a CLI flag or help text** — `cargo build && scripts/gen-cli-docs.sh`, commit
`docs/CLI.md`.

## Tests

| Layer | Location | What it covers |
|---|---|---|
| Unit | `#[cfg(test)]` in each module | primitives, parsing, config validation |
| End-to-end | `crates/zknbe-client/tests/e2e.rs` | every protocol path and policy decision through real HTTP |
| System | `scripts/luks-e2e.sh` | cryptsetup integration, the three binaries, exit codes |

Writing an e2e test: `TestServer::start()` gives you a server on a random port with its own
temp directory; `server.st.clock.advance(secs)` moves time; `server.admin(method, path, body)`
calls the admin API; `enroll(&[&server], threshold)` returns a `ClientState` and the expected
passphrase. Tests run in parallel and must not share state or sleep to wait for time to pass.

Not covered by automation, and therefore needing a manual test report in any PR that touches
them: `dist/dracut`, `dist/initramfs-tools`, `dist/systemd`, and TPM sealing
(`SecretStorage::SystemdCreds`).

## Releasing

1. Update `version` in the root `Cargo.toml` and add a section to `CHANGELOG.md`.
2. `cargo test --workspace`, `scripts/luks-e2e.sh`, `scripts/gen-cli-docs.sh`.
3. Tag `vX.Y.Z` and push the tag.
