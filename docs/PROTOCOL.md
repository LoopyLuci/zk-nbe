# Protocol (version 1)

JSON bodies over HTTP. Binary values are base64url without padding. Errors are
`{"error": "<code>", "message": "<text>"}` with an appropriate HTTP status.

## Primitives

| Purpose | Primitive |
|---|---|
| Group | ristretto255 (prime order, no cofactor pitfalls) |
| OPRF | 2HashDH: `F(k, x) = SHA-512(dst ‖ len(x) ‖ x ‖ k·H1(x))`, `H1` = SHA-512 → ristretto (Elligator) |
| Evaluation proof | Chaum–Pedersen DLEQ, Fiat–Shamir with SHA-512 |
| Signatures | Ed25519 (strict verification) |
| KDF | HKDF-SHA-256 |
| AEAD | ChaCha20-Poly1305, random 96-bit nonce |
| Secret sharing | Shamir over GF(2⁸) (AES polynomial), x-coordinates 1…n |
| Enrolment MAC | HMAC-SHA-256 keyed with HKDF(token secret) |

The OPRF follows the structure of RFC 9497's VOPRF mode but uses its own hash-to-group and
transcript encodings; it is not wire-compatible with RFC 9497 suites.

## Transcripts

Everything signed or MACed is a transcript:
`lp("zknbe/v1") ‖ lp(label) ‖ lp(field₁) ‖ …` where `lp(b)` is a 4-byte big-endian length followed
by `b`, and integers are 8-byte big-endian. Fields that travel as base64 strings are covered
*as transmitted* (the string bytes), so there is no canonicalisation step.

Request and response transcripts for device operations start with
`label, server_id, device_id, nonce`, binding every message to one server, one device and one
single-use challenge.

## Blinded evaluation

```
Client                                             Server (holds k, published Y = k·G)
x  = HKDF(device_secret, "oprf-input" ‖ server_id)
r  ← random scalar ≠ 0
B  = r · H1(x)                 ── B ──▶            reject if B is not a valid non-identity element
                                                   Z = k·B
                                                   t ← random;  A1 = t·G;  A2 = t·B
                                                   c = H(G, Y, B, Z, A1, A2);  s = t − c·k
                               ◀── Z, c, s ──
A1' = s·G + c·Y ;  A2' = s·B + c·Z
require c == H(G, Y, B, Z, A1', A2')
N = r⁻¹·Z ;  output = SHA-512(dst ‖ len(x) ‖ x ‖ N)
```

## Device endpoints

### `GET /v1/info`
→ `{protocol, version, server_id, server_pubkey}`. Unauthenticated; used as a pre-flight.

### `POST /v1/enroll`
```
→ {token_id, device_id, name, auth_pubkey, client_nonce, mac, sig}
← {server_id, server_pubkey, epoch, oprf_pubkey, heartbeat_interval_secs, mac}
```
* The token is `zkt1.<token_id>.<secret>`; only `token_id` is sent.
* `mac` (request) = HMAC over the request transcript; `sig` = Ed25519 by the key being
  registered (proof of possession).
* `mac` (response) = HMAC over a transcript containing the *request* transcript and all
  response fields — this is what authenticates `server_pubkey` and `oprf_pubkey` to the client.
* Tokens are single-use and expire; a failed attempt does not consume the token.
* Errors: `invalid_token` (401), `device_exists` (409).

### `POST /v1/challenge`
`→ {device_id}` `← {nonce, ttl_secs}`. Issued regardless of whether the device exists.
A nonce is valid for one request by that device id, for `ttl_secs` (default 60).

### `POST /v1/evaluate`
```
→ {device_id, nonce, epoch, blinded, sig}
← {epoch, evaluated, proof_c, proof_s, lease_secs, sig}
```
Server checks, in order: nonce + signature (`unauthorized`, 401 — identical for unknown
device, bad nonce, bad signature); device state (`revoked` / `suspended` / `locked`, 403);
source network (`network_denied`, 403); lease (lapsed → device becomes `locked`, 403);
rate limit (`rate_limited`, 429); epoch is current or pending (`epoch_mismatch`, 409).
On success the lease is renewed and the evaluation is audited.

### `POST /v1/heartbeat`
```
→ {device_id, nonce, sig}
← {state, lease_secs, current_epoch, pending_epoch, rotate_due, heartbeat_interval_secs, sig}
```
Always answers an authenticated device with its **signed** state (including `revoked`), so the
agent can act on it. Renews the lease only if the device is `active`, the lease has not
lapsed, and the source network is allowed. A lapsed lease moves the device to `locked`.

### `POST /v1/rotate/begin`
`→ {device_id, nonce, client_epoch, sig}` `← {epoch, oprf_pubkey, sig}`.
Same gate as `evaluate`. Requires `client_epoch == current_epoch`. Creates (or replaces) the
pending key; the current key remains valid.

### `POST /v1/rotate/commit`
`→ {device_id, nonce, epoch, sig}` `← {current_epoch, sig}`.
If `epoch` is the pending epoch: pending becomes current, the old key is overwritten.
If `epoch` is already current: success (idempotent retry). Otherwise `epoch_mismatch`.

## Admin endpoints (separate listener, `Authorization: Bearer <admin token>`)

| Method & path | Purpose |
|---|---|
| `GET /admin/v1/status` | server identity, device counts |
| `POST /admin/v1/tokens` `{name, ttl_secs?, policy?}` | create enrolment token |
| `GET /admin/v1/tokens` · `DELETE /admin/v1/tokens/:id` | list / delete tokens |
| `GET /admin/v1/devices` · `GET /admin/v1/devices/:id` | list / show |
| `POST /admin/v1/devices/:id/approve` `{window_secs?}` | unlock a locked device / pre-authorise downtime |
| `POST /admin/v1/devices/:id/suspend` · `/resume` | reversible disable |
| `POST /admin/v1/devices/:id/revoke` | destroy key material (irreversible) |
| `POST /admin/v1/devices/:id/policy` `{…}` | change policy fields |
| `DELETE /admin/v1/devices/:id` | delete a revoked device's record |
| `GET /admin/v1/audit?limit=&device=` · `GET /admin/v1/audit/verify` | audit log |
| `GET /metrics` | Prometheus text format |

## Client state (LUKS2 token)

```json
{
  "type": "zknbe",
  "keyslots": ["1"],
  "generation": 3,
  "zknbe": {
    "version": 1,
    "device_id": "…uuid…",
    "name": "web01",
    "threshold": 2,
    "secret": { "type": "plain", "value": "…" },
    "key_check": "…",
    "servers": [
      { "url": "https://ks1…", "server_id": "…", "server_pubkey": "…", "share_index": 1,
        "epoch": 4, "oprf_pubkey": "…", "wrapped_share": "…", "heartbeat_interval_secs": 120 }
    ]
  }
}
```
`secret` is `{"type":"plain","value":…}` or `{"type":"systemd-creds","blob":…,"pcrs":"7"}`.
Wrapped shares are bound (AEAD associated data) to device, server, epoch and share index.
