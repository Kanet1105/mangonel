#!/usr/bin/env bash
# A stress test of mangonel-router in the namespaces e2e-env.sh builds.
# mangonel-trafficgen floods it from test-node-0 with UDP for the upstream,
# every destination port a flow and a NAT session of its own, and the script
# reports how much of the flood came out of the router and whether it still
# serves a node afterwards.
#
#   scripts/e2e-stress.sh
#
# It builds the router and the generator, rebuilds the topology from nothing
# and takes it down again. sudo is implied, as for e2e-env.sh.
#
#   WORKERS=n    router workers and generator threads, a queue each (default
#                2). A machine with fewer cores to spare runs fewer.
#   DURATION=s   seconds to send for (default 5)
#   FLOWS=n      destination ports to vary over (default 1024)
#   SIZE=bytes   size of each packet on the wire (default 64)
#   ROUTER=      the router to test (default target/release/mangonel-router)
#   TRAFFICGEN=  the generator (default target/release/mangonel-trafficgen)
#
# It reports the throughput in gigabits a second: what the generator sent and
# what the upstream received, which is what the router forwarded. It fails if
# the router stops, nothing is received, or the router no longer serves a node
# once the flood is over. How much was received is not judged: a generator can
# always send more than a router forwards.

set -Eeuo pipefail
cd "$(dirname "$0")/.."

NAME=e2e-stress
WORKERS="${WORKERS:-2}"
DURATION="${DURATION:-5}"
FLOWS="${FLOWS:-1024}"
SIZE="${SIZE:-64}"
ROUTER="${ROUTER:-target/release/mangonel-router}"
TRAFFICGEN="${TRAFFICGEN:-target/release/mangonel-trafficgen}"
# The topology never outlives the run: the counts are read off a router that
# has stopped.
KEEP=0
# A LAN address no node is leased, for the flood to come from.
SOURCE=10.0.0.250

# shellcheck source=scripts/e2e-lib.sh
. scripts/e2e-lib.sh

# The packets the upstream's device has received so far.
upstream_received() {
    upstream cat /sys/class/net/eth0/statistics/rx_packets
}

# Floods the router and prints how much the generator sent.
flood() {
    local threads="$1" gateway_mac
    gateway_mac=$(ip netns exec "$GATEWAY" cat /sys/class/net/lan-0/address)
    # A hop limit above one, or the router would be right to drop it all.
    if ! node 0 "$TRAFFICGEN" udp eth0 -m "$gateway_mac" -A "$SOURCE" -a "$UPSTREAM" \
        -l 64 -d "$FLOWS" -s "$SIZE" -t "$threads" --duration "$DURATION" \
        >"$TMP/trafficgen.log" 2>&1; then
        cat "$TMP/trafficgen.log" >&2
        die "the generator failed"
    fi
    sed -n 's/^mangonel-trafficgen: \([0-9]* pkt\/s [0-9.]* Gbit\/s\)$/  sending \1/p' \
        "$TMP/trafficgen.log"
}

# throughput LABEL WHO PACKETS SECONDS: a line with the rate that PACKETS of
# SIZE bytes over SECONDS come to, in gigabits and packets a second, and WHO
# counted them. Like SIZE, a gigabit counts the frame and its check sequence,
# not the preamble or the gap between frames.
throughput() {
    awk -v label="$1" -v who="$2" -v packets="$3" -v seconds="$4" -v size="$SIZE" 'BEGIN {
        if (seconds <= 0) seconds = 1
        printf "  %-10s %.2f Gbit/s, %d pkt/s by the %s (%d packets in %.2f s)\n", label,
            packets * size * 8 / seconds / 1e9, packets / seconds, who, packets, seconds
    }'
}

# After the router has stopped: sums what its workers counted, as
# "received sent dropped".
router_counted() {
    awk '/^mangonel-router: worker [0-9]+ received/ {
            received += $5; sent += $7; dropped += $9
         }
         END { print received + 0, sent + 0, dropped + 0 }' "$TMP/router.log"
}

run() {
    local expected spare tool name before arrived summary sent seconds received forwarded dropped
    for tool in ip ethtool ping sed grep awk; do
        command -v "$tool" >/dev/null || die "$tool is not installed"
    done
    for name in WORKERS DURATION FLOWS SIZE; do
        [[ ${!name} =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer, not '${!name}'"
    done
    [ -x "$ROUTER" ] || die "$ROUTER is not built"
    [ -x "$TRAFFICGEN" ] || die "$TRAFFICGEN is not built"
    [ -x "$LEASE" ] || die "$LEASE is not built"

    spare=$(spare_cores)
    expected=$((WORKERS < spare ? WORKERS : spare))
    if [ "$expected" -ne "$WORKERS" ]; then
        echo "$NAME: only $spare cores to spare, so $expected workers instead of $WORKERS"
    fi

    TMP=$(mktemp -d)
    trap cleanup EXIT
    # The same count at both ends of every pair: the generator and the router
    # each bind every queue of their end.
    "$TOPOLOGY" down
    QUEUES="$expected" "$TOPOLOGY" up >/dev/null
    start_router --wan "wan=$EXTERNAL/24,$UPSTREAM" --lan lan-0 --lan lan-1

    echo "flooding for $DURATION seconds: $SIZE-byte packets over $FLOWS flows, a thread on each of $expected queue(s)"
    before=$(upstream_received)
    flood "$expected"
    # The last packets are still on their way through.
    sleep 1
    arrived=$(($(upstream_received) - before))
    # "sent N packets in S s, R pkt/s, G Gbit/s"
    summary=$(grep '^mangonel-trafficgen: sent ' "$TMP/trafficgen.log") || true
    sent=$(sed -n 's/.* sent \([0-9]*\) packets .*/\1/p' <<<"$summary")
    seconds=$(sed -n 's/.* in \([0-9.]*\) s,.*/\1/p' <<<"$summary")

    echo "afterwards:"
    if kill -0 "$ROUTER_PID" 2>/dev/null; then
        ok "the router is still running"
    else
        bad "the router is still running"
    fi
    lease 1 10.0.1 "$UPSTREAM"
    expect "node-1 pings the upstream through the router" node 1 "${PING[@]}" "$UPSTREAM"

    stop_router
    read -r received forwarded dropped <<<"$(router_counted)"
    echo "throughput:"
    if [ "${sent:-0}" -gt 0 ]; then
        # Both over the time the generator sent for.
        throughput "sent" "generator" "$sent" "$seconds"
        throughput "received" "upstream" "$arrived" "$seconds"
        echo "             $(awk -v a="$arrived" -v s="$sent" 'BEGIN { printf "%.1f", a * 100 / s }')% of what was sent"
    fi
    echo "  router     received $received, sent $forwarded, dropped $dropped"
    grep '^mangonel-router: worker' "$TMP/router.log" | sed 's/^mangonel-router: /             /'
    if [ "${sent:-0}" -gt 0 ] && [ "$arrived" -gt 0 ] && [ "$forwarded" -gt 0 ]; then
        ok "the flood reached the upstream through the router"
    else
        bad "the flood reached the upstream through the router"
    fi

    if [ "$FAIL" -ne 0 ]; then
        exit 1
    fi
    echo "all passed"
}

main() {
    if [ "$(id -u)" -ne 0 ]; then
        # Built as the caller, so nothing under target/ ends up owned by root.
        cargo build --release -p mangonel-router -p mangonel-trafficgen
        cargo build --release -p mangonel-dhcp --example lease
        exec sudo -- env WORKERS="$WORKERS" DURATION="$DURATION" FLOWS="$FLOWS" SIZE="$SIZE" \
            ROUTER="$ROUTER" TRAFFICGEN="$TRAFFICGEN" "$0" "$@"
    fi
    run
}

main "$@"
