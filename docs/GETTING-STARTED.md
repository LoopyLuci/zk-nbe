# Getting started

A ten-minute tour on one computer. You will run a key server, enrol a "device", fetch its key,
and then lock it out — with no disk, no root and no Linux required. It works the same on
Linux, macOS and Windows.

When you are ready to protect a real disk, continue with the
[Operations guide](OPERATIONS.md).

## 0. Build

You need a current stable [Rust toolchain](https://rustup.rs) and a C compiler (for the
bundled SQLite).

```bash
git clone https://github.com/LoopyLuci/zk-nbe.git
cd zk-nbe
cargo build --release
```

This produces three programs in `target/release/`:

| Program | What it is |
|---|---|
| `zknbed` | the key server |
| `zknbectl` | the admin tool for the key server |
| `zknbe` | the client that runs on the machine you want to protect |

The examples below assume `target/release` is on your `PATH`.

## 1. Start a key server

Create a small config file that keeps everything in a local folder:

```toml
# demo.toml
[server]
listen = "127.0.0.1:7421"        # devices talk to this port
admin_listen = "127.0.0.1:7422"  # zknbectl talks to this port
data_dir = "./demo-data"
```

```bash
zknbed --config demo.toml
```

Leave it running and open a second terminal. On first start the server created its database,
its master key and an admin token in `./demo-data`. Tell the admin tool where the token is:

```bash
export ZKNBE_ADMIN_TOKEN_FILE=./demo-data/admin.token     # PowerShell: $env:ZKNBE_ADMIN_TOKEN_FILE = "./demo-data/admin.token"
zknbectl status
```

```text
zknbed 0.1.0  server id f9V9Ac7pivusXNvQLztaAg
identity key Qm1EV1N_4MG2uDqgeH4pFknNQBWtCfzawP0ms8jpPxU
    active: 0
    locked: 0
 suspended: 0
   revoked: 0
```

## 2. Enrol a device

A device joins with a **single-use enrolment token** that the administrator creates:

```bash
zknbectl token create --name demo-host
```

```text
Single-use enrolment token (valid 3600s, shown once):
zkt1.jjXcW4HLM2tR.R2…
```

On the "device" (here: the same computer), enrol using that token. The binding is written to a
state file:

```bash
zknbe enroll --state demo.json --name demo-host \
    --server http://127.0.0.1:7421=zkt1.jjXcW4HLM2tR.R2…
```

```text
zknbe: enrolled 'demo-host' as 514f2c3f-dce2-40a5-b244-05e50741ca07 (1 of 1 servers required)
```

> For a real disk you would use `zknbe luks bind /dev/…` instead: it does the same enrolment
> and stores the binding inside the LUKS2 header rather than in a file.

## 3. Unlock

```bash
zknbe unlock --state demo.json
```

This prints a 43-character key. Run it again: the same key comes back. That key is what would
open the disk. The key server never saw it — look for yourself:

```bash
zknbectl device list
zknbectl audit list
```

The server knows that `demo-host` exists and that it asked for a key evaluation, and nothing
else. The key is derived on the device from a secret in `demo.json` combined with the server's
answer; neither side can produce it alone.

## 4. Say no

Suspend the device and try again:

```bash
zknbectl device suspend demo-host
zknbe unlock --state demo.json
```

```text
zknbe: error: only 0 of the required 1 key servers released a share
  http://127.0.0.1:7421: device is suspended [suspended, HTTP 403]
```

`suspend` is reversible (`zknbectl device resume demo-host`). **Revoke** is not — it destroys
the server's key for that device, so the key from step 3 can never be derived again by anyone:

```bash
zknbectl device resume demo-host
zknbectl device revoke demo-host --yes
zknbe unlock --state demo.json        # refused, permanently
```

## 5. Things to try next

* **Leases.** Enrol a device with a short lease and no heartbeats, then wait:
  `zknbectl token create --name sleepy --lease-ttl 60s --heartbeat 30s`.
  After a minute of silence `zknbectl device list` shows it as `locked`, and unlocking fails
  until you run `zknbectl device approve sleepy`. Run `zknbe agent --state sleepy.json` to see
  heartbeats keep it alive instead.
* **Threshold.** Start three servers on different ports (three config files) and enrol with
  `--threshold 2 --server …=… --server …=… --server …=…`. Stop any one server: unlocking still
  works. Stop two: it does not.
* **Rotation.** `zknbe rotate --state demo.json`, then compare the old and new state files:
  the key is unchanged, but a copy of the old file no longer works.
* **Tamper evidence.** `zknbectl audit verify`.

## What the pieces are called

| Term | Meaning |
|---|---|
| **Device** | A machine (or volume) enrolled with one or more key servers. |
| **Key server** | A `zknbed` instance. Holds one random key per device and decides whether to use it. |
| **Binding** | What the device stores: its secret, the key servers it uses, and its wrapped key shares. Lives in a LUKS2 header token or a state file. |
| **Enrolment token** | Single-use secret that lets one device register with one key server. |
| **Lease** | How long a device may stay silent before the server stops trusting it. Renewed by heartbeats. |
| **Locked** | The lease ran out. An administrator must `approve` the device before it can unlock again. |
| **Suspended / revoked** | Disabled by an administrator: reversibly / permanently. |
| **Threshold (t of n)** | The device is bound to n key servers and needs answers from any t of them. |
| **Epoch** | Version number of a device's key on one server; goes up at each rotation. |
| **Recovery passphrase** | Your ordinary LUKS passphrase. ZK-NBE adds a keyslot and never removes yours. |

Next: [Operations guide](OPERATIONS.md) · [Command reference](CLI.md) ·
[How it works](DESIGN.md) · [What it protects against](THREAT-MODEL.md)
