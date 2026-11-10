# Threat model

What ZK-NBE defends against, what it does not, and which configuration choices move the line.

## Assets

* The data on the encrypted volume (confidentiality).
* The ability to boot unattended (availability).
* The ability to revoke (the administrator's control).

## Parties and what they hold

| Party | Holds | Never holds |
|---|---|---|
| Machine | device secret (plain or TPM-sealed), wrapped shares, pinned server keys | server OPRF keys |
| Key server *i* | per-device OPRF key `k_i`, device auth *public* key, policy, audit log | device secret, OPRF input/output, shares, master key, passphrase |
| Administrator | admin token for each key server | any key material |

## Scenarios

### Disk stolen (drive pulled, RMA'd, decommissioned, backup of the header leaked)

* **Device secret TPM-sealed:** the thief has ciphertext only. The device secret cannot be
  unsealed off the original TPM, so the thief cannot even authenticate to the key servers.
  **Protected.**
* **Device secret plain:** the header contains everything the *machine* knows. The thief can
  ask the key servers. Protection is then exactly the server policy: revoke the device, or let
  the lease lapse (default 15 minutes of silence), or restrict by source network.
  **Protected once the device is revoked/locked or if the thief cannot reach the servers from
  an allowed network; exposed until then.** This is the same exposure as Clevis/Tang, with
  revocation and expiry added. Seal the secret to the TPM to remove it.
* An old copy of the header (taken before the last key rotation) is useless either way.

### Whole machine stolen

The machine will try to unlock itself when powered on. It succeeds only if all hold:
the device is still `active`, the lease has not lapsed, and the request arrives from an
allowed network. So:

* Revoke (or suspend) as soon as the theft is known → **protected, permanently**.
* Nobody notices: the machine was unplugged to be carried away, heartbeats stopped, and the
  lease lapses → **protected automatically** after `lease_ttl`.
* The thief powers it up within the lease, on a network the policy allows → **not protected.**
  No remote scheme can distinguish this from a legitimate reboot. Shrink the window with a
  short `lease_ttl` and an `allowed_cidrs` policy that only matches your own egress addresses.

A thief who keeps the machine *powered and connected* (never reboots) has a running, unlocked
system; that is outside what boot-time key release can address. The agent's `--on-revoked`
hook (e.g. power off) helps only while the machine can still reach a key server.

### Evil maid (boot chain modified to steal the key at next boot)

* **TPM-sealed secret bound to Secure Boot state (PCR 7) or more:** the modified chain produces
  different measurements, the TPM refuses to unseal, the implant has nothing to present to the
  key servers. **Protected** to the extent your PCR policy covers what was modified (PCR 7
  covers Secure Boot policy, not an unsigned initramfs — use a UKI and/or more PCRs for that).
* **Plain secret:** **not protected** — an implant in the initramfs can read the header and
  perform the unlock. (Also true of every non-TPM network-unlock scheme.)

### Key server compromised (full: database, master key, memory, network position)

The attacker obtains the OPRF keys. For each device they can now evaluate `F(k_i, ·)` — but they
do not know the input, which is derived from the device secret. **No disk can be decrypted**
with server-side material alone, even if *every* key server is compromised.

What the attacker can do: deny service (refuse to evaluate, delete keys), forge audit history
on that server, approve/revoke devices, and observe which devices boot when. With `t`-of-`n`
and `t ≤ n − 1`, one malicious server cannot block boots.

To decrypt, the attacker needs server compromise (`t` servers) **and** the device secret
(disk theft with a plain secret, or code execution on the unlocked machine).

### Network attacker (eavesdrop, modify, replay, redirect)

* Learns device ids, timing and source addresses if TLS is not used. Nothing else: blinded
  elements are uniformly random, evaluations are useless without the blinding factor.
* Cannot replay: every request consumes a single-use, short-lived server nonce.
* Cannot impersonate a server: responses are verified against the pinned identity key, and
  evaluations against the pinned OPRF public key (DLEQ proof).
* Cannot hijack enrolment: both directions are MACed with a key derived from the token secret,
  which is never transmitted.
* Can block traffic → the machine cannot unlock (use the recovery passphrase) and, if blocked
  for longer than the lease, gets locked.

### Malicious or mistaken administrator

Anyone with the admin token can revoke (irreversible denial of service to that device until
re-bound using the recovery passphrase) and approve locked devices. They cannot obtain disk
keys. The audit log is hash-chained (tampering with history is detectable by `audit verify`);
anchor the head hash externally to also detect truncation. There is a single admin role today.

### Attacker with root on the running machine

Out of scope: they already have the data, and can read the volume key from the kernel.
They can also extract the device secret and keep using the key servers until revoked.

## Residual risks and assumptions

* Standard assumptions: discrete log / DDH-style hardness in ristretto255, SHA-2, HKDF,
  ChaCha20-Poly1305, Ed25519; a working OS CSPRNG on both sides (including in the initramfs).
* Enrolment happens on a machine you trust at that moment (it handles the master key in RAM).
* Crypto-shredding on revocation overwrites the sealed key in SQLite (`secure_delete`); flash
  media and filesystem snapshots may retain old blocks. The retained data is ciphertext under
  the server's key-encryption key — protect that key and the database backups accordingly.
* The key-encryption key and admin token are files readable by the service user.
* Unauthenticated callers can request challenges; the pending-challenge table is bounded, but
  a flood can cause legitimate requests to be told to retry. Rate-limit at the network edge.
* Not quantum-safe with respect to revocation (see Design §5).
* No independent audit yet.

## Configuration guidance

| Want | Do |
|---|---|
| Stolen disk is useless immediately | `zknbe tpm seal` |
| Stolen machine locks itself fast | short `lease_ttl` (but ≥ reboot time), `on_lease_expiry = "lock"` |
| Unlock only from the datacentre | `allowed_cidrs` |
| Survive a key-server outage or compromise | 2-of-3 across independent servers |
| Site power cut must not need a human | longer `lease_ttl`, or `on_lease_expiry = "allow"` (weaker) |
| Always have a way in | keep the original LUKS passphrase / recovery key offline |
