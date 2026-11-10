# AGENTS.md

Instructions for AI coding agents working in this repository. Humans: see
[CONTRIBUTING.md](CONTRIBUTING.md).

## What this is

ZK-NBE unlocks LUKS-encrypted disks at boot with the help of remote key servers that can
refuse (revocation, lapsed lease, wrong network) and that never learn the disk key. Rust
workspace, three crates, three binaries: `zknbed` (key server), `zknbectl` (admin CLI),
`zknbe` (device client).

This is security software. A change that compiles and passes tests can still be wrong.
Prefer small, explicit changes; when unsure whether something weakens a guarantee, stop and
ask rather than guess.

## Commands

```bash
cargo build --workspace
cargo test --workspace                                    # must pass; ~10 s; any OS
cargo fmt --all                                           # CI checks formatting
cargo clippy --workspace --all-targets -- -D warnings     # CI denies warnings
scripts/gen-cli-docs.sh                                   # after any CLI/help change (needs a build)
sudo scripts/luks-e2e.sh                                  # Linux + root only; real LUKS2 volume
```

Run one test: `cargo test -p zknbe-client --test e2e rotation_is_crash_safe`.

## Where things are

| Need to change… | Go to |
|---|---|
| Cryptography, message formats, signed transcripts | `crates/zknbe-core/src/` |
| Server policy decisions (who gets a key evaluation) | `crates/zknbe-server/src/device_api.rs` → `gate`, `authenticate` |
| Database schema and queries | `crates/zknbe-server/src/store.rs` |
| Admin API / `zknbectl` | `crates/zknbe-server/src/admin_api.rs`, `src/bin/zknbectl.rs` |
| Client protocol logic | `crates/zknbe-client/src/ops.rs` |
| LUKS / cryptsetup | `crates/zknbe-client/src/luks.rs` |
| Boot integration | `dist/` |
| End-to-end tests | `crates/zknbe-client/tests/e2e.rs` |

Full code map, request flow and recipes: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Hard rules

1. **Never send or store on the server anything derived from** the device secret, the OPRF
   input or output, a key share, the master key or the passphrase.
2. **Never weaken authentication or verification**: every device request is nonce-bound and
   signed; every response the client uses is verified against pinned keys. Do not add
   "skip verification" flags, fallbacks or debug bypasses.
3. **A lapsed lease is cleared only by an admin `approve`.** Heartbeats must not revive it.
4. **Never touch a user's recovery path**: do not delete keyslots the client did not create,
   and keep the refusal to remove the last keyslot.
5. **Do not log, print or `Debug`-format secrets.** Keep them in `Zeroizing`.
6. **Do not change a transcript, derivation label or endpoint meaning** without a protocol
   version bump — it breaks every deployed device. See "Changing the wire protocol" in
   DEVELOPMENT.md.
7. **Do not edit an existing test to make a change pass** if it is listed in the invariants
   table in DEVELOPMENT.md. That table maps each security property to its test.
8. **Do not add dependencies casually**, especially cryptographic ones. Justify each in the PR.
9. **Use `AppState::clock`** for time on the server; tests rely on advancing it.
10. **`zknbe-core` has no I/O.** Keep it that way.

## Gotchas

* `docs/CLI.md` is generated. Edit help strings in the source, then run the script.
* cryptsetup 2.4 has no `--token-replace`; token updates use the two-step, generation-numbered
  write in `luks::write_token`. Do not "simplify" it.
* Committing on denial is deliberate: `Store::tx` commits when a handler returns a non-internal
  error so that audit records and lock transitions persist.
* `unauthorized` is intentionally the same for unknown device, bad nonce and bad signature.
* Line endings are LF everywhere (`.gitattributes`); the shell scripts in `dist/` and
  `scripts/` break with CRLF.
* The LUKS code paths cannot run on Windows or macOS. On Windows use WSL2 for
  `scripts/luks-e2e.sh`. If you cannot run it, say so in your summary instead of claiming the
  LUKS path is verified.
* Not covered by any automated test: `dist/dracut`, `dist/initramfs-tools`, `dist/systemd`,
  TPM sealing. Changes there need a human to test on real hardware; state that plainly.

## Definition of done

* `cargo fmt --all -- --check`, clippy with `-D warnings`, and `cargo test --workspace` pass.
* New behaviour has a test; security-relevant behaviour has an end-to-end test.
* Docs updated in the same change: `docs/CLI.md` (regenerated), `docs/PROTOCOL.md` for wire
  changes, `docs/OPERATIONS.md` for operator-visible changes, `dist/config/zknbed.toml` for
  config keys, `CHANGELOG.md` for anything user-visible.
* Your summary says what you ran and what you could not run.
