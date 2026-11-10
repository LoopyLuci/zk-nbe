<!-- One logical change per PR. Explain why; the diff shows what. -->

## What and why


## How it was tested

- [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
- [ ] New behaviour has a test
- [ ] `scripts/gen-cli-docs.sh` re-run (if CLI or help text changed)
- [ ] Docs and `CHANGELOG.md` updated
- [ ] Touches `dist/` or TPM code: tested by hand on (distro / hardware):

## Security impact

<!-- Does this change a signed transcript, a key derivation, the meaning of an endpoint, a
     policy decision, or anything in the invariants table in docs/DEVELOPMENT.md? Explain. -->
None / …
