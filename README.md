# ZK-NBE — zero-knowledge network-bound disk encryption

Unattended boot for LUKS-encrypted machines, with a kill switch.

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

## Repository layout

| Path | Contents |
|---|---|
| `crates/zknbe-core` | Cryptography and wire protocol (no I/O): OPRF + DLEQ, Shamir, key hierarchy, transcripts |
| `crates/zknbe-server` | `zknbed` key server and `zknbectl` admin CLI |
| `crates/zknbe-client` | `zknbe`: enrol, unlock, agent, LUKS2 token store, systemd password agent |
| `dist/` | systemd units, dracut module, initramfs-tools hook, example config |
| `scripts/luks-e2e.sh` | Full-stack test on a real LUKS2 volume |
| `docs/` | [Design](docs/DESIGN.md) · [Threat model](docs/THREAT-MODEL.md) · [Protocol](docs/PROTOCOL.md) · [Operations](docs/OPERATIONS.md) |

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
