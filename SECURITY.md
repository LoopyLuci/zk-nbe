# Security policy

## Status

ZK-NBE is new cryptographic software and **has not been independently audited**. Evaluate it
accordingly before protecting data you cannot afford to lose or leak, and always keep your
original LUKS passphrase or recovery key.

What it is designed to protect against, and what it is not, is written down in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private reporting instead:
<https://github.com/LoopyLuci/zk-nbe/security/advisories/new>

Include, as far as you can: what an attacker can achieve, what they need to start with (disk,
network position, a compromised key server, …), steps or a proof of concept, and the commit
you tested.

You should get an acknowledgement within a few days. Please allow time for a fix before
publishing details; you will be credited unless you prefer otherwise.

## In scope

* Recovering a disk key, or anything that helps derive one, from a key server, from network
  traffic, or from a device that has been revoked or locked.
* Bypassing revocation, lease expiry, network policy or rate limiting.
* Impersonating a key server or a device; replay or cross-server relay of requests.
* Tampering with the audit log without `zknbectl audit verify` detecting it.
* Loss of the recovery path, or state corruption that leaves a volume unbootable.
* Mistakes in the cryptographic constructions or their implementation.

## Known limitations (not vulnerabilities)

These are documented properties of the design; see the threat model for the reasoning.

* A whole machine stolen and powered on within its lease, on an allowed network, unlocks.
* An attacker with root on a running, unlocked machine has the data.
* Without TPM sealing, anyone who can read the LUKS header and reach the key servers can
  request the key until the device is revoked or locked.
* Revocation is not secure against an attacker with a large quantum computer.
* The admin API has a single role and must not be exposed without TLS.

## Supported versions

Only the latest release and the `main` branch receive fixes.
