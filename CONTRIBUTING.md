# Contributing

Thanks for helping. This project protects people's disks, so the bar is "correct and
understandable" before "clever".

## Quick start

```bash
git clone https://github.com/LoopyLuci/zk-nbe.git && cd zk-nbe
cargo test --workspace
```

Then read [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md): it has the code map, the invariants you
must not break, and step-by-step recipes for common changes.

## Ways to contribute

* **Test the boot integration on real systems.** The dracut module, the initramfs-tools hook,
  the systemd units and TPM sealing are written but not yet validated on hardware. A report
  saying "works / fails on distro X version Y, here is the log" is extremely valuable.
* **Review the cryptography and the protocol.** See [docs/PROTOCOL.md](docs/PROTOCOL.md) and
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). Suspected vulnerabilities go through
  [SECURITY.md](SECURITY.md), not public issues.
* **Fix bugs, improve docs, pick something from "Future work"** in
  [docs/DESIGN.md](docs/DESIGN.md). For anything larger than a bug fix, open an issue first so
  the approach can be agreed before you write the code.

## Pull request checklist

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] New behaviour is tested (end-to-end for anything security relevant)
- [ ] `scripts/gen-cli-docs.sh` re-run if commands, flags or help text changed
- [ ] Docs and `CHANGELOG.md` updated
- [ ] If you touched LUKS code: `scripts/luks-e2e.sh` passes (CI also runs it)
- [ ] If you touched `dist/` or TPM code: describe how you tested it by hand, on what system
- [ ] No change to signed transcripts, key derivations or endpoint semantics — or the PR says
      so in its first line and bumps the protocol version

Keep pull requests focused: one logical change each. Explain *why* in the description; the
diff already shows what.

## Style

* Rust: `rustfmt` defaults (`max_width = 100`), no clippy warnings, no `unsafe`.
* Errors a user will read should say what happened and what to do next.
* Comments explain constraints and reasons, not what the next line does.
* Commit messages: imperative subject line under ~70 characters, body if the reason is not
  obvious.

## Using AI coding agents

Welcome, with the same standards. [AGENTS.md](AGENTS.md) contains the rules agents are given
for this repository. You are responsible for what you submit: read the diff, run the tests,
and say in the PR what was and was not verified.

## Licence

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
