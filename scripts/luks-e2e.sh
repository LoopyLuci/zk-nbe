#!/usr/bin/env bash
# Full-stack test against a real LUKS2 volume (file-backed, needs root + dm-crypt).
#
#   cargo build --release && sudo scripts/luks-e2e.sh
#
# Starts three key servers, binds a volume 2-of-3, and exercises open, rotation, the agent,
# the systemd password-agent path, revocation and the recovery passphrase.
set -euo pipefail

BIN=${BIN:-target/release}
CRYPTSETUP=${ZKNBE_CRYPTSETUP:-cryptsetup}
export ZKNBE_CRYPTSETUP=$CRYPTSETUP
BASE_PORT=${BASE_PORT:-17421}
work=$(mktemp -d)
pids=()
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
cleanup() {
    $CRYPTSETUP close zknbe-e2e 2>/dev/null || true
    for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
    rm -rf "$work"
}
trap cleanup EXIT

step "starting 3 key servers"
servers=()
for i in 1 2 3; do
    dev_port=$((BASE_PORT + i * 10)); adm_port=$((BASE_PORT + i * 10 + 1))
    mkdir -p "$work/ks$i"
    cat > "$work/ks$i.toml" <<CFG
[server]
listen = "127.0.0.1:$dev_port"
admin_listen = "127.0.0.1:$adm_port"
data_dir = "$work/ks$i"
CFG
    "$BIN/zknbed" --config "$work/ks$i.toml" 2> "$work/ks$i.log" &
    pids+=($!)
    servers+=("http://127.0.0.1:$dev_port")
done
ctl() { local i=$1; shift; "$BIN/zknbectl" --url "http://127.0.0.1:$((BASE_PORT + i * 10 + 1))" --token-file "$work/ks$i/admin.token" "$@"; }
for i in 1 2 3; do
    for _ in $(seq 50); do ctl $i status >/dev/null 2>&1 && break; sleep 0.1; done
    ctl $i status >/dev/null || fail "key server $i did not start: $(cat "$work/ks$i.log")"
done

step "creating a LUKS2 volume with a recovery passphrase"
vol="$work/volume.img"
truncate -s 32M "$vol"
printf 'correct horse battery staple' > "$work/recovery.key"
$CRYPTSETUP luksFormat --batch-mode --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "$vol" "$work/recovery.key"

step "binding 2-of-3"
args=()
for i in 1 2 3; do args+=(--server "${servers[$((i-1))]}=$(ctl $i token create --name e2e-host)"); done
"$BIN/zknbe" luks bind "$vol" --name e2e-host --threshold 2 --key-file "$work/recovery.key" "${args[@]}"
"$BIN/zknbe" luks status "$vol"
ctl 1 device list

step "network unlock"
"$BIN/zknbe" luks open "$vol" zknbe-e2e
[ -b /dev/mapper/zknbe-e2e ] || fail "mapping missing"
$CRYPTSETUP close zknbe-e2e

step "unlock with one key server down"
kill "${pids[2]}"; wait "${pids[2]}" 2>/dev/null || true
"$BIN/zknbe" luks open "$vol" zknbe-e2e
$CRYPTSETUP close zknbe-e2e

step "key rotation updates the LUKS token in place"
before=$("$BIN/zknbe" luks passphrase "$vol")
"$BIN/zknbe" rotate --luks "$vol" || true   # server 3 is down: partial rotation is expected
after=$("$BIN/zknbe" luks passphrase "$vol")
[ "$before" = "$after" ] || fail "passphrase changed across rotation"
"$BIN/zknbe" luks status "$vol" | grep -q 'epoch 2' || fail "epoch did not advance"
"$BIN/zknbe" luks open "$vol" zknbe-e2e && $CRYPTSETUP close zknbe-e2e

step "agent cycle"
"$BIN/zknbe" agent --luks "$vol" --once && fail "agent should report degraded (server 3 down)" || rc=$?
[ "${rc:-0}" = 4 ] || fail "agent exit code ${rc:-0}, expected 4 (degraded)"

step "systemd password-agent protocol"
askdir="$work/ask"; mkdir -p "$askdir"
python3 - "$askdir" "$vol" "$after" <<'PY' &
import socket, sys, os
askdir, vol, expect = sys.argv[1:4]
sock_path = os.path.join(askdir, "sck.test")
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.bind(sock_path); s.settimeout(30)
with open(os.path.join(askdir, "ask.test"), "w") as f:
    f.write(f"[Ask]\nPID=1\nSocket={sock_path}\nAcceptCached=0\nEcho=0\nNotAfter=0\nMessage=test\nId=cryptsetup:{vol}\n")
data = s.recv(4096).decode()
sys.exit(0 if data == "+" + expect else 1)
PY
listener=$!
sleep 0.5
"$BIN/zknbe" askpass --dir "$askdir" --retry-for 20s
wait $listener || fail "password agent sent the wrong answer"

step "revocation: 2 of 3 servers revoke => volume can no longer be unlocked over the network"
id=$(ctl 1 --json device show e2e-host | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
ctl 1 device revoke "$id" --yes >/dev/null
ctl 2 device revoke "$id" --yes >/dev/null
if "$BIN/zknbe" luks open "$vol" zknbe-e2e 2> "$work/denied.log"; then fail "unlock succeeded after revocation"; fi
grep -q revoked "$work/denied.log" || fail "expected a 'revoked' refusal: $(cat "$work/denied.log")"
"$BIN/zknbe" agent --luks "$vol" --once --on-revoked "touch $work/hook-fired" || true
[ -e "$work/hook-fired" ] || fail "on-revoked hook did not run"

step "break-glass: the recovery passphrase still opens the volume"
$CRYPTSETUP open --test-passphrase --key-file "$work/recovery.key" "$vol"

step "unbind"
"$BIN/zknbe" luks unbind "$vol"
$CRYPTSETUP luksDump "$vol" | grep -q zknbe && fail "token still present"
ctl 1 audit verify

printf '\n\033[1;32mALL LUKS END-TO-END CHECKS PASSED\033[0m\n'
