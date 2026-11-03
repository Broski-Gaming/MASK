#!/usr/bin/env bash
# MORP testnet across Linux network namespaces: one namespace per "machine",
# connected by a virtual Ethernet bridge on 10.77.0.0/24. No root needed
# (uses an unprivileged user namespace).
#
#   machine   address      runs
#   auth      10.77.0.10   mask-authority
#   m1        10.77.0.11   entry1 (:7101), rv1 (:7104)        family m1
#   m2        10.77.0.12   middle1 (:7102), rv2 (:7104)       family m2
#   m3        10.77.0.13   entry2 (:7101), middle2 (:7102)    family m3
#   svc       10.77.0.20   mask-service host (hidden website)
#   cli       10.77.0.30   client (mask-service fetch / verify, or the browser)
#
# svc and cli get routes ONLY to the authority and the two entry relays, so
# a direct client → service connection is impossible, not just unused.
#
# Steps: start everything, fetch the .morp site from cli, cut m2's network
# cable (no FIN, no warning), check the network routes around it, then stop
# everything with SIGTERM and check every process exited cleanly.
#
# Usage:
#   cargo build --workspace
#   scripts/netns-testnet.sh            # automated checks, prints PASS/FAIL
#   scripts/netns-testnet.sh --browser  # also open MASK Browser in "cli"
#
# Environment: MASK_BIN (default target/debug), MASK_NETNS_KEEP=1 keeps logs.
set -euo pipefail

BROWSER=0
[[ "${1:-}" == "--browser" ]] && BROWSER=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${MASK_BIN:-$ROOT/target/debug}"
for b in mask-authority mask-relay mask-service; do
    [[ -x "$BIN/$b" ]] || { echo "missing $BIN/$b (run: cargo build --workspace)"; exit 2; }
done

if [[ -z "${MASK_NETNS_INSIDE:-}" ]]; then
    command -v unshare >/dev/null && command -v nsenter >/dev/null && command -v ip >/dev/null \
        || { echo "needs unshare, nsenter (util-linux) and ip (iproute2)"; exit 2; }
    exec unshare --user --map-root-user --net --kill-child \
        env MASK_NETNS_INSIDE=1 MASK_BIN="$BIN" "$0" "$@"
fi

# ---------------------------------------------------------------- inside
WORK="$(mktemp -d /tmp/mask-netns.XXXXXX)"
FAILS=0
declare -A NS_PID PROC_PID
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
info() { echo "....  $*"; }

cleanup() {
    for p in "${PROC_PID[@]}"; do kill -9 "$p" 2>/dev/null || true; done
    for p in "${NS_PID[@]}"; do kill -9 "$p" 2>/dev/null || true; done
    if [[ "${MASK_NETNS_KEEP:-}" == 1 || $FAILS -gt 0 ]]; then
        echo "logs kept in $WORK"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

# The "switch": a bridge in the outer namespace.
ip link set lo up
ip link add br0 type bridge
ip link set br0 up

# machine NAME HOST [ONLY_HOSTS...]: a namespace with 10.77.0.HOST. With
# ONLY_HOSTS it gets a /32 address and routes to those hosts only.
machine() {
    local name=$1 host=$2; shift 2
    unshare --net sleep infinity &
    NS_PID[$name]=$!
    sleep 0.1
    ip link add "v-$name" type veth peer name eth0 netns "${NS_PID[$name]}"
    ip link set "v-$name" master br0 up
    if [[ $# -eq 0 ]]; then
        in_ns "$name" ip addr add "10.77.0.$host/24" dev eth0
        in_ns "$name" ip link set eth0 up
    else
        in_ns "$name" ip addr add "10.77.0.$host/32" dev eth0
        in_ns "$name" ip link set eth0 up
        for peer in "$@"; do in_ns "$name" ip route add "10.77.0.$peer/32" dev eth0; done
    fi
    in_ns "$name" ip link set lo up
}
in_ns() { local name=$1; shift; nsenter --net="/proc/${NS_PID[$name]}/ns/net" -- "$@"; }

# start NAME MACHINE CMD...: run a component in a machine, logging to WORK.
start() {
    local name=$1 m=$2; shift 2
    NO_COLOR=1 RUST_LOG=info in_ns "$m" "$@" >"$WORK/$name.log" 2>&1 &
    PROC_PID[$name]=$!
}
wait_for() { # SECONDS DESCRIPTION COMMAND...
    local t=$1 what=$2; shift 2
    for _ in $(seq $((t * 4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done
    fail "timed out: $what"; return 1
}

machine auth 10
machine m1 11
machine m2 12
machine m3 13
machine svc 20 10 11 13
machine cli 30 10 11 13
info "6 namespaces on bridge br0 (10.77.0.0/24); work dir $WORK"

# --------------------------------------------------------------- config
cd "$WORK"
"$BIN/mask-authority" keys --data-dir auth --name auth1 --address 10.77.0.10:7300 >auth-block.toml
{ echo 'name = "netns-testnet"'; echo 'scope = "private"'; echo; cat auth-block.toml; } >network.toml
cat >authority.toml <<EOF
name = "auth1"
listen = "10.77.0.10:7300"
network = "network.toml"
approved_relays = "approved-relays.toml"
data_dir = "auth"
consensus_interval_secs = 10
consensus_lifetime_secs = 120
probe_interval_secs = 2
EOF
RELAYS="entry1:entry:m1:11:7101 rv1:rendezvous:m1:11:7104 middle1:middle:m2:12:7102 rv2:rendezvous:m2:12:7104 entry2:entry:m3:13:7101 middle2:middle:m3:13:7102"
: >approved-relays.toml
for r in $RELAYS; do
    IFS=: read -r nick role m host port <<<"$r"
    cat >"$nick.toml" <<EOF
nickname = "$nick"
role = "$role"
listen = "10.77.0.$host:$port"
family = "$m"
network = "network.toml"
data_dir = "relays/$nick"
consensus_refresh_secs = 2
keepalive_secs = 2
EOF
    "$BIN/mask-relay" --config "$nick.toml" --print-identity | grep -v '^#' >>approved-relays.toml
done
pass "configs written; relay identities approved"

# ---------------------------------------------------------------- start
start authority auth "$BIN/mask-authority" run --config authority.toml
for r in $RELAYS; do
    IFS=: read -r nick role m host port <<<"$r"
    start "$nick" "$m" "$BIN/mask-relay" --config "$nick.toml"
done
consensus_has() { in_ns cli "$BIN/mask-authority" status --network network.toml | grep -q "$1 relay(s)"; }
wait_for 40 "6 relays in the consensus" consensus_has 6 && pass "authority lists 6 healthy relays"
all_installed() {
    for r in $RELAYS; do grep -q "installed a new consensus relays=6" "${r%%:*}.log" || return 1; done
}
wait_for 30 "relays installing the consensus" all_installed && pass "every relay installed the signed consensus"

URL=$("$BIN/mask-service" --services-dir services create | grep -o 'morp://[a-z2-7]*\.morp/')
mkdir -p site
echo "<title>Hello from svc via MORP</title><h1>Hello across network namespaces</h1><p>served by svc, fetched by cli</p>" >site/index.html
start host svc "$BIN/mask-service" --network network.toml --services-dir services host "$URL" --site site
wait_for 40 "the hidden service to publish" grep -q "Serving morp://" host.log && pass "hidden service up at $URL"

# ---------------------------------------------------------------- checks
if in_ns cli ping -c1 -W1 10.77.0.20 >/dev/null 2>&1; then
    fail "cli can reach svc directly"
else
    pass "cli has no route to svc (10.77.0.20): direct connections are impossible"
fi
if in_ns svc ss -Htln | awk '{print $4}' | grep -vqE '^127\.'; then
    fail "svc listens on a non-loopback address"
else
    pass "svc listens only on 127.0.0.1 (its local web app)"
fi

fetch() { in_ns cli "$BIN/mask-service" --network network.toml fetch "$URL" / 2>"$WORK/fetch.err"; }
page=""
for _ in 1 2 3 4 5; do page=$(fetch) && break; sleep 1; done
if grep -q "Hello across network namespaces" <<<"$page"; then
    pass "cli fetched the .morp page through MORP relays ($(tail -1 "$WORK/fetch.err"))"
else
    fail "fetch from cli: $(cat "$WORK/fetch.err")"
fi
if in_ns cli "$BIN/mask-service" --network network.toml verify "$URL" >verify.out 2>&1; then
    pass "service authenticated: $(grep '^3\.' verify.out)"
else
    fail "verify: $(cat verify.out)"
fi
joined=$(grep -l "circuits joined" rv1.log rv2.log 2>/dev/null | wc -l)
[[ $joined -ge 1 ]] && pass "rendezvous relay joined separate client and service circuits" \
    || fail "no rendezvous join logged"
if grep -q "Hello across" entry1.log entry2.log middle1.log middle2.log rv1.log rv2.log authority.log; then
    fail "a relay or the authority logged page content"
else
    pass "no relay or authority log contains page content"
fi

if [[ $BROWSER == 1 ]]; then
    info "opening MASK Browser in the cli namespace (close it to continue)"
    MASK_NETWORK="$WORK/network.toml" in_ns cli "$ROOT/target/debug/mask-browser" "$URL" \
        >"$WORK/browser.log" 2>&1 &
    BPID=$!
    sleep 8
    info "browser TCP connections (cli namespace):"
    in_ns cli ss -Htn | awk '{print "        " $4 " -> " $5}'
    wait "$BPID" || true
fi

# ------------------------------------------------ disconnected machine
info "cutting m2's network cable (middle1 + rv2 vanish without closing TCP)"
ip link set v-m2 down
gone() { in_ns cli "$BIN/mask-authority" status --network network.toml | grep -q "4 relay(s)"; }
wait_for 60 "authority dropping m2's relays" gone && pass "authority dropped the unreachable relays (health probes)"
sleep 6 # keepalives (2 s) tear down circuits through m2; the host replaces lost intro points
page=""
for _ in $(seq 10); do page=$(fetch) && break; sleep 2; done
if grep -q "Hello across network namespaces" <<<"$page"; then
    pass "site still loads after losing a machine"
else
    fail "fetch after losing m2: $(cat "$WORK/fetch.err")"
fi
grep -q "keepalives" entry1.log entry2.log middle2.log 2>/dev/null \
    && pass "keepalives detected the vanished relays" || info "no keepalive failure logged (no live links to m2)"

# -------------------------------------------------------------- shutdown
stop() { # NAME: SIGTERM and require a clean exit
    local name=$1 pid=${PROC_PID[$1]}
    kill -TERM "$pid" 2>/dev/null || true
    if wait "$pid"; then return 0; else return 1; fi
}
ok=1
stop host || { ok=0; fail "host did not stop cleanly"; }
grep -q "withdrawing the descriptor" host.log || { ok=0; fail "host did not withdraw its descriptor"; }
for r in $RELAYS; do stop "${r%%:*}" || { ok=0; fail "${r%%:*} did not stop cleanly"; }; done
stop authority || { ok=0; fail "authority did not stop cleanly"; }
PROC_PID=()
[[ $ok == 1 ]] && pass "SIGTERM: host withdrew its descriptor; every process exited cleanly"

echo
if [[ $FAILS -eq 0 ]]; then echo "ALL CHECKS PASSED"; else echo "$FAILS CHECK(S) FAILED"; fi
exit $(( FAILS > 0 ))
