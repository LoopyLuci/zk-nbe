# Design

## 1. Goal

Let an encrypted machine reboot unattended, while keeping the ability to make it permanently
unbootable from somewhere else — and do it without any party other than the machine itself
ever being able to derive the disk key.

Three properties, in priority order:

1. **Server learns nothing.** Not the key, not half of it, not anything that helps guess it.
2. **Server can say no, and "no" is enforced by cryptography.** Revocation and lease expiry
   must hold even against someone who has the disk and the machine.
3. **It must not make the machine fragile.** Outages, crashes mid-update and operator mistakes
   must never destroy the only way in.

## 2. The construction

### 2.1 Why an OPRF, not a split password and not a SNARK

The original idea — "half the password locally, half remotely" — and the reviewed proposal —
additive shares plus a zero-knowledge proof of correct reconstruction — both have the server
*hold a share of the key* and *send it* to the client. That has two problems:

* The share is key material. Its secrecy now depends on the server's storage, backups and
  transport, and the "proof that reconstruction is correct" cannot even be produced before the
  client has received the share it is supposed to be proving something about.
* Authorising the release needs a separate authentication mechanism bolted on.

An **oblivious pseudorandom function** solves the actual problem directly. The server holds a
random key `k` that has no mathematical relationship to the disk key. The client holds a secret
input `x`. The protocol lets the client compute `F(k, x)` such that:

* the server learns nothing about `x` or the output (it sees a uniformly random group element),
* the client learns nothing about `k`,
* the output cannot be computed without the server's live participation.

`F(k, x)` is then used as a key-encryption key on the client. The server never holds, sends or
can derive anything key-like; deleting `k` makes the output unrecoverable. No general-purpose
proof system is needed: the only proof in the protocol is a two-equation Chaum–Pedersen DLEQ
(a genuine non-interactive zero-knowledge proof) by which the *server* shows it used the key
the client pinned.

This is the same family of idea as Tang's McCallum–Relyea exchange, with three additions Tang
deliberately lacks: per-device keys (so individual devices can be revoked), authenticated
requests (so policy can be attached to a device), and state (leases, audit).

### 2.2 Key hierarchy

```
device secret  (32 random bytes; on the machine, optionally TPM-sealed)
  ├─ HKDF "auth"             → Ed25519 key; signs every request. Server stores the public key.
  ├─ HKDF "oprf-input" ‖ sid → x_i, the OPRF input for key server i
  └─ salt for share-wrap keys

N_i = F(k_i, x_i)            k_i: random scalar held only by key server i, one per device
  └─ HKDF(salt = device secret, info = device ‖ server ‖ epoch) → wrap key W_i

master key M (32 random bytes; exists only transiently in RAM)
  ├─ Shamir t-of-n over GF(2⁸) → shares m_1 … m_n
  │     each m_i stored on the machine as ChaCha20-Poly1305_{W_i}(m_i)
  ├─ HKDF "volume-passphrase" → LUKS passphrase (256-bit, base64url)
  └─ HKDF "key-check"         → detects wrong reconstruction
```

To unlock, the machine needs **both** its device secret **and** live answers from `t` key
servers. Either alone is useless:

* Key servers alone: they hold `k_i` but not `x_i`; `F(k_i, ·)` on an unknown 256-bit input is
  unpredictable, and the wrap key is additionally salted with the device secret.
* Machine alone: the wrapped shares are AEAD ciphertexts under keys it cannot compute.

### 2.3 Threshold without a distributed protocol

Each key server generates its own independent `k_i`. The threshold lives entirely on the
client: Shamir-split `M`, wrap share `i` under server `i`'s OPRF output. Consequences:

* Servers need no knowledge of each other, no DKG, no synchronised state. They can be run by
  different teams, in different clouds, on different software versions.
* Adding, replacing or rotating one server touches nothing on the others.
* A coalition of *all* key servers still learns nothing — they are missing the device secret.

(A threshold-OPRF with a shared key would save round-trips but couples the servers together and
adds a DKG. The independence is worth more here than the round-trips.)

### 2.4 Leases: liveness as a security property

Every device has a **lease**, extended by each heartbeat and each unlock. Policy decides what
happens when it lapses:

* `lock` (default): the device moves to `locked`. Nothing but an administrator's `approve`
  brings it back — in particular, heartbeats do not, so possession of the device secret is not
  enough to revive it.
* `allow`: never auto-lock (Tang-like availability; manual revocation only).

A normal reboot takes minutes and fits inside the lease (default 15 min). A machine that is
carried away is offline for longer than that, and comes back to a locked door. Planned long
downtime is pre-authorised with `zknbectl device approve --window 4h`.

The lease is enforced at request time *and* by a background sweep, so a missing machine shows
up as `locked` in listings, metrics and the audit log even if it never calls in again.

Device states: `active` → `locked` (automatic) → `active` (admin approve);
`active`/`locked` ⇄ `suspended` (admin, reversible); any → `revoked` (admin, key destroyed).

### 2.5 Rotation and forward security

"Periodically renew their keys" is implemented as **server-key rotation**:

1. The client recovers its share using the current key `k` (epoch *e*).
2. `rotate/begin`: the server creates a *pending* key `k'` (epoch *e+1*); `k` stays valid.
3. The client evaluates under `k'`, re-wraps the share, and atomically persists the new state.
4. `rotate/commit`: the server overwrites `k` with `k'`.

After step 4 the old wrapped share — in a stolen backup, a disk image, a decommissioned
snapshot — can never be opened: the key it depended on no longer exists. The disk passphrase
does not change, so no LUKS re-keying is needed.

Crash safety: a crash before 3 leaves the old state valid (the server still has `k`). A crash
between 3 and 4 leaves the new state valid (the server evaluates pending epochs too); the next
heartbeat sees `pending_epoch == local epoch` and replays the commit. The server refuses to
start a new rotation from a client that has already moved to the pending epoch, so it can
never discard a key the client depends on.

### 2.6 Where the state lives

In a **LUKS2 token** in the volume header, like Clevis and systemd-cryptenroll. The initramfs
needs only the binary: it finds the binding on the disk it is asked to unlock. This also
avoids a trap: state baked into an initramfs image would go stale at the first key rotation.

Token updates are crash-safe on any cryptsetup ≥ 2.4: write the new state as a second token
with a higher generation number, then delete the old one. Readers take the highest generation.

### 2.7 Hardware binding

With `zknbe tpm seal`, the device secret is stored as a `systemd-creds` blob sealed to the
TPM 2.0 and bound to chosen PCRs (default 7, Secure Boot state). Then:

* the secret cannot be read from the disk — it is bound to that one TPM;
* a modified boot chain (evil maid) changes the PCRs and the TPM refuses to unseal, so the
  attacker's code never gets the secret and cannot talk to the key servers as the device.

This gives the evil-maid resistance the reviewed proposal wanted from remote attestation,
enforced locally by the TPM rather than by server-side quote verification. Remote attestation
(quotes, EK/AK certificate chains, event-log replay against reference values) would add
*server-visible* evidence of boot state; it is a large subsystem with its own trust
infrastructure and is deliberately left as future work rather than half-implemented.

### 2.8 Transport

All device traffic is JSON over HTTP. Security does not rest on TLS:

* requests are signed (Ed25519) over a domain-separated, length-prefixed transcript that
  includes a single-use server nonce and the server's id — no replay, no cross-server relay;
* responses are signed by the server's identity key over a transcript including the same nonce;
* enrolment is authenticated in both directions by an HMAC keyed from the single-use token,
  which is never sent — so a man-in-the-middle can neither enrol in the device's place nor
  substitute the server's keys;
* the OPRF messages reveal nothing to an eavesdropper.

TLS (via a reverse proxy) is still recommended to hide device ids and traffic patterns.
The **admin API** is different: it uses a bearer token and therefore listens on loopback by
default and must only be exposed through TLS.

## 3. Components

| Component | Role |
|---|---|
| `zknbe-core` | OPRF/DLEQ, Shamir, HKDF hierarchy, AEAD wrapping, protocol messages and transcripts. No I/O, fully unit-tested. |
| `zknbed` | Key server: axum HTTP, SQLite (WAL, `synchronous=FULL`, `secure_delete`), all secrets at rest sealed under a key-encryption key, one transaction per request so decision + state change + audit record commit together. |
| `zknbectl` | Admin CLI over the admin API. |
| `zknbe` | Client: `luks bind/open/unbind/status`, `unlock`, `agent`, `rotate`, `tpm seal`, `askpass` (systemd password agent for the initramfs). |

## 4. Departures from the reviewed proposal

| Proposal | This design | Why |
|---|---|---|
| Server stores a key share, releases it encrypted | Server stores an unrelated OPRF key, releases nothing | Removes key material from the server entirely; revocation = deleting one scalar |
| Schnorr / zk-SNARK "proof of correct reconstruction" by the client | DLEQ proof by the *server*; Ed25519 request signatures by the client | The proposed statement cannot be proven before the share is received, and proves nothing the server needs. What needs proving is that the server used the pinned key. |
| Shamir shares of `K` held by KMS nodes | Shamir on the client, each share wrapped by an independent server's OPRF output | No dealer on the server side, no inter-server protocol, coalition of all servers learns nothing |
| mTLS with pinned certificates as the security layer | Application-layer signatures and MACs; TLS optional | Works in a minimal initramfs, no PKI to run, safe over plain HTTP |
| HMAC session heartbeats keyed from the TLS session | Challenge-signed heartbeats | Survives reconnects/restarts; replay-proof without session state |
| Remote TPM quote verification | Local TPM sealing to PCRs (remote attestation: future work) | Same evil-maid outcome with a fraction of the machinery; no fake attestation |
| Geofencing | CIDR allow-lists per device | IP geolocation is not a security boundary; network origin is at least honest about what it checks |
| HSM-protected share store | KEK-sealed SQLite; PKCS#11 KEK is future work | Stolen database rows are worthless *by construction* (not key shares), which lowers what an HSM would buy |
| "Stateless for unlock" | One atomic transaction per unlock | Leases, rate limits and audit are the point; state is small |

## 5. Future work

* Remote attestation (TPM quote + event log) as an additional policy input.
* KEK in PKCS#11 / cloud KMS; native TLS on the admin listener; multiple admin identities/RBAC.
* Webhook / alert on auto-lock; Kubernetes operator; packaged `.deb`/`.rpm`.
* Post-quantum mode. The blinding is information-theoretic, so recorded traffic never reveals
  the OPRF input. But the server key `k` is protected only by the discrete-log problem: the
  pinned public key `k·G` sits in the volume header, so an attacker with a large quantum
  computer *and* the device secret could recover `k` and unlock without the server, bypassing
  revocation. The disk cipher itself is unaffected. Closing this needs a post-quantum OPRF
  (still a research-grade primitive) or a redesign around a PQ KEM.
* Independent security audit and a formal model (Tamarin/ProVerif) of the protocol.
