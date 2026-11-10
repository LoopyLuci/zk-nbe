# Operations guide

Deploying and running ZK-NBE for real. If you have not used it before, do the
[ten-minute tour](GETTING-STARTED.md) first; every command is detailed in the
[command reference](CLI.md).

## Building and installing

```bash
cargo build --release
sudo make install            # binaries, units, example config (see Makefile; honours DESTDIR/PREFIX)
```

For the initramfs a static client is convenient:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release -p zknbe-client --target x86_64-unknown-linux-musl   # needs musl-gcc
```

Requirements on protected machines: LUKS2, cryptsetup ≥ 2.4, and for TPM sealing
systemd ≥ 250 with a TPM 2.0.

## Running a key server

```bash
sudo useradd --system --home /var/lib/zknbe --shell /usr/sbin/nologin zknbe
sudo install -D -m 0644 dist/config/zknbed.toml /etc/zknbe/zknbed.toml
sudo systemctl enable --now zknbed
sudo zknbectl status
```

On first start the server creates in its data directory:

| File | What | Back up? |
|---|---|---|
| `zknbe.db` | devices, sealed OPRF keys, tokens, audit log | **Yes.** Losing it means every device bound to this server loses this server's share. |
| `master.key` | key-encryption key for the database | **Yes, separately from the database.** Either one alone is useless. |
| `admin.token` | bearer token for the admin API | Treat as a root credential. |

A restored backup that predates a key rotation no longer matches devices that rotated since.
Back up at least as often as the rotation interval, or use `t < n` so one server's loss is
tolerated and re-bind afterwards.

**Exposure.** The device port (7421) may face the networks your machines boot from. Put a
TLS-terminating reverse proxy in front if you want to hide metadata; list it under
`trusted_proxies` so network policy sees the real client address. The admin port (7422) is
loopback-only by default: use `zknbectl` on the server, or `ssh -L 7422:127.0.0.1:7422`.

**Run more than one.** Use three servers in separate failure domains and bind 2-of-3. Servers
are fully independent — there is nothing to cluster.

**Monitoring.** Scrape `/metrics` on the admin listener (bearer token). Alert on
`zknbe_auto_locks_total` increasing (a machine went missing), on `zknbe_denials_total`, and on
`zknbe_devices{state="locked"} > 0`. The audit log is also emitted to the journal
(`target=audit`). Run `zknbectl audit verify` periodically and store the reported head hash
somewhere the server cannot modify.

## Binding a machine

1. On each key server: `zknbectl token create --name <host> [policy flags]`.
   Policy can be set per token: `--lease-ttl 15m --heartbeat 2m --allow-cidr 10.20.0.0/16
   --rotation-interval 7d --on-lease-expiry lock`.
2. On the machine:
   ```bash
   zknbe luks bind /dev/nvme0n1p3 -t 2 -s https://ks1…=<token1> -s https://ks2…=<token2> -s https://ks3…=<token3>
   ```
   This enrols, adds a keyslot (you are asked for an existing passphrase), stores the binding
   in the LUKS2 header, and then performs a real network unlock to prove it works.
   **Your existing passphrase stays valid. Keep it — it is the recovery path.**
3. Seal the device secret (recommended): `zknbe tpm seal --luks /dev/nvme0n1p3 --pcrs 7`.
4. Enable the agent: `systemctl enable --now zknbe-agent`.
5. Early-boot unlock:
   * **dracut** (Fedora, RHEL, openSUSE, …): copy `dist/dracut/60zknbe` to
     `/usr/lib/dracut/modules.d/`, give the initramfs networking (`ip=dhcp` or a static `ip=`
     on the kernel command line), run `dracut -f`.
   * **initramfs-tools** (Debian, Ubuntu): install `dist/initramfs-tools/hook` as
     `/etc/initramfs-tools/hooks/zknbe` and `dist/initramfs-tools/keyscript` as
     `/usr/lib/zknbe/keyscript`, add `keyscript=/usr/lib/zknbe/keyscript` to the volume's
     `/etc/crypttab` options, enable networking in the initramfs, run `update-initramfs -u`.
   * **Data volumes unlocked after boot:** `systemctl enable zknbe-askpass.path` and mark the
     volume `_netdev` in `/etc/crypttab`.
6. Reboot once while you are able to type the passphrase, to confirm.

> The boot-integration files and TPM sealing have not been validated on real hardware by the
> project yet. Test them on your distribution before relying on them.

## Everyday tasks

| Task | Command |
|---|---|
| See everything | `zknbectl device list` · `zknbe luks status <dev>` |
| Machine stolen / decommissioned | `zknbectl device revoke <name>` on enough servers to break the quorum (n − t + 1; simplest: all) |
| Unsure, investigate first | `zknbectl device suspend <name>` … `resume` |
| Machine locked after an outage | verify it is where it should be, then `zknbectl device approve <name>` |
| Whole site was down | `zknbectl device approve-all-locked` |
| Planned long downtime | `zknbectl device approve <name> --window 4h` *before* shutting down |
| Change policy | `zknbectl device policy <name> --lease-ttl 30m --allow-cidr 10.0.0.0/8` |
| Rotate now | `zknbe rotate --luks <dev>` |
| Stop using ZK-NBE on a volume | `zknbe luks unbind <dev>`, then revoke on the servers |
| Firmware / Secure Boot change (PCRs will change) | `zknbe tpm unseal --luks <dev>` before, `zknbe tpm seal …` after |

## Choosing the lease

`lease_ttl` is the longest a machine may be silent and still boot unattended. It must exceed
your slowest normal reboot (firmware + POST can take many minutes on servers) and should be as
short as you can otherwise tolerate. `heartbeat_interval` must be at most half of it.

With `on_lease_expiry = "lock"`, any event that silences machines for longer than the lease —
a power cut, a network partition between machines and key servers — leaves them `locked`.
Running machines keep running; they will need `approve` before their next reboot. Decide in
advance who is allowed to run `approve-all-locked` and how they verify nothing is missing.

## Failure handling

| Symptom at boot | Meaning | Action |
|---|---|---|
| Falls back to passphrase prompt, log says `unreachable` | no network in initramfs, or servers down | fix networking / servers; type the recovery passphrase meanwhile |
| `locked` | lease lapsed | `zknbectl device approve` |
| `network_denied` | request came from outside `allowed_cidrs` | fix the policy or the network |
| `revoked` | key destroyed on that server | re-bind using the recovery passphrase |
| `TPM unsealing failed` | boot chain changed or different machine | recovery passphrase, then `tpm unseal`/`seal` again |
| `epoch_mismatch` / "state is stale" | header restored from an old backup | recovery passphrase, `luks unbind`, bind again |
| `VERIFICATION FAILED` | a response was not from the pinned server | investigate the network path / the server before retrying |

## Verifying an installation

```bash
cargo test --workspace
sudo scripts/luks-e2e.sh     # needs cryptsetup, python3, dm-crypt; uses a file-backed volume
```
