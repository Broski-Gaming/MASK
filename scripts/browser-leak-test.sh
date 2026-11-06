#!/usr/bin/env bash
# Live leak test of MASK Browser in an isolated namespace (no root needed).
#
# Inside a new user + network + mount namespace:
#   - the only network is loopback: nothing can leave, and every attempt is
#     visible;
#   - systemd-resolved is hidden (its socket is NOT confined by network
#     namespaces: lookups through it would reach the host's resolver) and
#     resolv.conf points at a DNS canary on 127.0.0.1:53, so EVERY name
#     lookup by any process is recorded;
#   - tcpdump records all traffic for the packet-level checks below.
# Then tests/browser_leaks.rs runs the real browser against hostile .morp
# and clearnet pages (see that file for what is tried and checked).
#
# Usage:  cargo build --workspace && scripts/browser-leak-test.sh
# Needs:  unshare (util-linux), ip (iproute2), tcpdump, a running desktop
#         (Wayland or X11). MASK_LEAK_KEEP=1 keeps the capture.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -z "${MASK_LEAK_INSIDE:-}" ]]; then
    for tool in unshare ip tcpdump; do
        command -v "$tool" >/dev/null || { echo "needs $tool"; exit 2; }
    done
    [[ -n "${WAYLAND_DISPLAY:-}${DISPLAY:-}" ]] || { echo "needs a desktop session (WAYLAND_DISPLAY or DISPLAY)"; exit 2; }
    exec unshare --user --map-root-user --net --mount --kill-child \
        env MASK_LEAK_INSIDE=1 "$0" "$@"
fi

FAILS=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
WORK="$(mktemp -d /tmp/mask-leak.XXXXXX)"

ip link set lo up
# Hide systemd-resolved and nscd; answer every lookup from our canary.
for dir in /run/systemd/resolve /run/nscd; do
    [[ -d $dir ]] && mount -t tmpfs tmpfs "$dir"
done
echo "nameserver 127.0.0.1" >"$WORK/resolv.conf"
if [[ -L /etc/resolv.conf ]]; then
    # The usual systemd setup: resolv.conf -> /run/systemd/resolve/stub-resolv.conf.
    target="$(readlink -f /etc/resolv.conf || true)"
    mkdir -p "$(dirname "${target:-/run/systemd/resolve/stub-resolv.conf}")"
    cp "$WORK/resolv.conf" "${target:-/run/systemd/resolve/stub-resolv.conf}"
else
    mount --bind "$WORK/resolv.conf" /etc/resolv.conf
fi
grep -q "^nameserver 127.0.0.1" /etc/resolv.conf && pass "the only DNS resolver is the canary (127.0.0.1:53)" \
    || fail "could not redirect DNS"
if ip route get 1.1.1.1 >/dev/null 2>&1; then fail "a route to the internet exists"; else pass "no route off this machine"; fi

tcpdump -i lo -nn -U -Z root -w "$WORK/leak.pcap" >/dev/null 2>"$WORK/tcpdump.err" &
TCPDUMP=$!
sleep 1

cd "$ROOT"
if MASK_LEAK_DNS_CANARY=1 cargo test --offline -q --test browser_leaks -- --ignored --nocapture \
    >"$WORK/test.log" 2>&1; then
    pass "browser leak test (see below)"
else
    fail "browser leak test:"
    grep -E "panicked|assert" -A 3 "$WORK/test.log" | head -20
fi
grep -E "what a .morp page sees|DNS queries seen|internet canary saw" "$WORK/test.log" | sed 's/^/      /'
sleep 1
kill -INT "$TCPDUMP" 2>/dev/null || true
wait "$TCPDUMP" 2>/dev/null || true

# Packet-level checks on the capture (tolerate a truncated last packet).
read_pcap() { tcpdump -Z root -nn -r "$WORK/leak.pcap" "$@" 2>/dev/null || true; }
dns=$(read_pcap 'port 53' | grep -c "\.morp" || true)
[[ $dns -eq 0 ]] && pass "packet capture: no DNS packet mentions .morp" || fail "packet capture: $dns DNS packet(s) mention .morp"
stun=$(read_pcap 'udp and not port 53' | wc -l)
[[ $stun -eq 0 ]] && pass "packet capture: no UDP at all besides DNS (no WebRTC/STUN, no QUIC)" \
    || fail "packet capture: $stun unexpected UDP packet(s)"
offhost=$(read_pcap 'not (src net 127.0.0.0/8 and dst net 127.0.0.0/8)' | wc -l)
[[ $offhost -eq 0 ]] && pass "packet capture: every packet stayed on 127.0.0.0/8" || fail "packet capture: $offhost packet(s) left loopback"
total=$(read_pcap | wc -l)
# A capture with nothing in it would make every check above pass vacuously.
[[ $total -gt 100 ]] && pass "packet capture recorded the run ($total packets on loopback)" \
    || fail "packet capture is (nearly) empty ($total packets): checks above are not meaningful"
tcp_ports=$(read_pcap 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0' | awk '{print $5}' | sed 's/.*\.//; s/:$//' | sort -u | tr '\n' ' ')
echo "....  TCP connections were opened only to loopback ports: $tcp_ports"

if [[ "${MASK_LEAK_KEEP:-}" != 1 && $FAILS -eq 0 ]]; then rm -rf "$WORK"; else echo "kept $WORK"; fi
echo
if [[ $FAILS -eq 0 ]]; then echo "ALL CHECKS PASSED"; else echo "$FAILS CHECK(S) FAILED"; fi
exit $(( FAILS > 0 ))
