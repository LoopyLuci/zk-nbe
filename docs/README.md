# Documentation

Pick the page that matches what you are trying to do.

| I want to… | Read |
|---|---|
| Try it out in ten minutes, on any OS | [Getting started](GETTING-STARTED.md) |
| Deploy key servers and protect real machines | [Operations guide](OPERATIONS.md) |
| Look up a command or flag | [Command reference](CLI.md) |
| Understand how and why it works | [Design](DESIGN.md) |
| Know exactly what it does and does not protect against | [Threat model](THREAT-MODEL.md) |
| Implement or review the wire protocol | [Protocol](PROTOCOL.md) |
| Change the code | [Development guide](DEVELOPMENT.md) and [CONTRIBUTING](../CONTRIBUTING.md) |
| Work on the repo as an AI coding agent | [AGENTS.md](../AGENTS.md) |
| Report a vulnerability | [SECURITY](../SECURITY.md) |

## Which documents are authoritative

| Topic | Source of truth |
|---|---|
| Commands and flags | the binaries' `--help`; `CLI.md` is generated from it |
| Message formats and transcripts | `crates/zknbe-core/src/proto.rs`; `PROTOCOL.md` describes it |
| Server configuration keys and defaults | `crates/zknbe-server/src/config.rs`; `dist/config/zknbed.toml` mirrors it |
| Security claims | `THREAT-MODEL.md`, each backed by a test named in `DEVELOPMENT.md` |

If a document and the code disagree, the code is right and the document has a bug — please
open an issue or fix it.
