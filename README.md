# ZK-NBE — zero-knowledge network-bound disk encryption

[![CI](https://github.com/LoopyLuci/zk-nbe/actions/workflows/ci.yml/badge.svg)](https://github.com/LoopyLuci/zk-nbe/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: unaudited](https://img.shields.io/badge/status-unaudited-orange.svg)

Unattended boot for LUKS-encrypted machines, with a kill switch.

**New here?** Start with [Getting started in ten minutes](docs/GETTING-STARTED.md) (any OS, no
disk needed), or browse [all documentation](docs/README.md).

A machine bound with ZK-NBE unlocks its disk at boot by talking to one or more **key servers**.
The servers can refuse — because an administrator revoked the machine, because it went silent
for too long, or because it is calling from the wrong network — and then the disk stays locked.
The servers themselves never learn anything about the disk key: a full compromise of a key
server, its database and its master key yields nothing that helps decrypt any disk.

```
        boot                         key server (×n, any t suffice)
   ┌──────────────┐  blinded element   ┌───────────────────────────┐
   │ initramfs    │ ─────────────────▶ │ policy: state · lease ·   │
   │  zknbe       │ ◀───────────────── │         network · rate    │
   │              │  evaluation+proof  │ per-device random OPRF key│
   └──────┬───────┘                    └───────────────────────────┘
          │ unblind → unwrap share → combine t shares → LUKS passphrase
          ▼
     cryptsetup open                   running system: zknbe agent heartbeats,
                                       renews the lease, rotates keys
```

## What you get

| | |
|---|---|
| **Zero-knowledge key release** | Verifiable OPRF over ristretto255. The server sees one uniformly random group element per unlock and proves (DLEQ) that it answered with the right key. |
| **Revocation that is cryptographic** | `zknbectl device revoke` destroys the server's per-device key. Without it the wrapped share on the machine is undecryptable — forever. |
| **Liveness leases** | Machines heartbeat. A machine silent for longer than its lease is *locked*: possession of the hardware is no longer enough, an administrator must approve the next unlock. |
| **Threshold** | Bind to *n* independent key servers, require any *t*. One compromised or offline server neither leaks nor blocks. Servers share nothing with each other. |
| **Key rotation with forward security** | The agent periodically replaces each server-side key. A copy of the disk header taken before a rotation is useless afterwards. Rotation is crash-safe. |
| **Hardware binding (optional)** | The device secret can be sealed to the TPM 2.0 (PCR-bound), so it cannot be lifted from the disk or used after boot-chain tampering. |
| **No TLS dependency** | Every request and response is signed end-to-end and enrolment is MAC-authenticated by the token, so the protocol is safe over plain HTTP (like Tang). |
| **Operable** | Single static-linkable binaries, SQLite storage, hash-chained audit log, Prometheus metrics, policy per device, break-glass passphrase always preserved. |

## Quick start

```bash
cargo build --release      # produces zknbed, zknbectl, zknbe in target/release
```

**Key server** (repeat on each server for a threshold setup):

```bash
zknbed --config /etc/zknbe/zknbed.toml        # see dist/config/zknbed.toml
zknbectl token create --name web01             # prints a single-use enrolment token
```

**Machine to protect** (LUKS2 volume, cryptsetup ≥ 2.4):

```bash
zknbe luks bind /dev/nvme0n1p3 --threshold 2 \
    --server https://ks1.example.com=zkt1.… \
    --server https://ks2.example.com=zkt1.… \
    --server https://ks3.example.com=zkt1.…
zknbe tpm seal --luks /dev/nvme0n1p3 --pcrs 7      # recommended
systemctl enable --now zknbe-agent                  # heartbeats + rotation
# install the dracut module (dist/dracut) and rebuild the initramfs
```

**Day two**:

```bash
zknbectl device list
zknbectl device revoke web01          # stolen: destroy its key
zknbectl device approve web01         # locked after an outage: allow the next boot
zknbectl device approve web01 --window 4h   # planned long maintenance
zknbectl audit verify
```

## Documentation

| | |
|---|---|
| [Getting started](docs/GETTING-STARTED.md) | Ten-minute hands-on tour, plus a glossary |
| [Operations guide](docs/OPERATIONS.md) | Deploying key servers, binding machines, day-two tasks, troubleshooting |
| [Command reference](docs/CLI.md) | Every command and flag of `zknbe`, `zknbed`, `zknbectl` |
| [Design](docs/DESIGN.md) | How it works and why it is built this way |
| [Threat model](docs/THREAT-MODEL.md) | What is and is not protected, scenario by scenario |
| [Protocol](docs/PROTOCOL.md) | Wire format and cryptographic details |
| [Development guide](docs/DEVELOPMENT.md) | Code map, invariants, recipes for common changes |

## Repository layout

| Path | Contents |
|---|---|
| `crates/zknbe-core` | Cryptography and wire protocol (no I/O) |
| `crates/zknbe-server` | `zknbed` key server and `zknbectl` admin CLI |
| `crates/zknbe-client` | `zknbe` device client |
| `dist/` | systemd units, dracut module, initramfs-tools hook, example config |
| `scripts/` | Real-LUKS end-to-end test, CLI reference generator |
| `docs/` | The documentation above |

## Testing

```bash
cargo test --workspace                 # unit + end-to-end over real sockets (any OS)
sudo scripts/luks-e2e.sh               # real LUKS2 volume, 3 key servers (Linux, root)
```

## Status and honest limits

This is a complete, tested implementation of the design in `docs/`, but it is **new
cryptographic software that has not been independently audited**. Before trusting production
data to it, get the protocol and code reviewed.

Verified here: the full protocol and policy engine (automated tests), and bind / open / rotate /
password-agent / revoke / recovery against a real LUKS2 volume with cryptsetup 2.4.3.

Written but **not yet exercised on real hardware** — treat as starting points and test on your
distribution: the dracut module, the initramfs-tools hook, the systemd units, and TPM sealing
via `systemd-creds`.

Known boundaries (details in the threat model): a thief who takes the *whole* machine and gets
it back on an allowed network before the lease expires can boot it; an attacker with root on a
running machine already has the data; remote attestation (TPM quotes) is not implemented — the
TPM is used for local sealing only.

## Contributing

Contributions are welcome, especially reports from testing the boot integration on real
distributions. See [CONTRIBUTING.md](CONTRIBUTING.md). AI coding agents: start with
[AGENTS.md](AGENTS.md). Security issues: [SECURITY.md](SECURITY.md).

## Licence

[Apache License 2.0](LICENSE).
