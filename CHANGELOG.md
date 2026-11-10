# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Until 1.0, minor versions may contain breaking
changes; they will be called out here.

## [Unreleased]

## [0.1.0] - 2026-11-10

First public version. Protocol version 1, client state version 1.

### Added

- `zknbed` key server: per-device OPRF keys, lease / network / rate-limit policy, device
  states (`active`, `locked`, `suspended`, `revoked`), SQLite storage with secrets sealed at
  rest, hash-chained audit log, Prometheus metrics.
- `zknbectl` admin CLI: enrolment tokens, device control, policy, audit.
- `zknbe` device client: LUKS2 binding stored in a header token, threshold unlock across
  independent key servers, heartbeat agent, crash-safe key rotation, optional TPM 2.0 sealing
  of the device secret, systemd password agent for early boot.
- systemd units, dracut module and initramfs-tools hook (not yet validated on hardware).
- Documentation: getting started, operations, command reference, design, threat model,
  protocol, development guide.

[Unreleased]: https://github.com/LoopyLuci/zk-nbe/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/LoopyLuci/zk-nbe/releases/tag/v0.1.0
