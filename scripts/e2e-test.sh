#!/usr/bin/env bash
# End-to-end tests of mangonel-router in the namespaces e2e-env.sh builds. The
# router runs in test-gateway, and the nodes ask everything of it that a host
# behind a gateway would.
#
#   scripts/e2e-test.sh
#
# It builds the router, rebuilds the topology from nothing, runs every test and
# takes the topology down again. sudo is implied, as for e2e-env.sh.
#
# The gateway's ports are born with different queue counts, WORKERS on the
# narrowest, so the router has to level them before it can bind.
#
#   WORKERS=n  queues on the narrowest port, hence workers (default 2). A
#              machine with fewer cores to spare runs fewer.
#   KEEP=1     leave the topology up and the router running afterwards, to
#              poke at from a node: ip netns exec test-node-0 ping 203.0.113.1
#   ROUTER=    the router to test (default target/release/mangonel-router)
#
# What it checks, from the nodes unless said otherwise:
#   - every gateway port ends with one queue per worker
#   - each node leases an address, a router and a resolver from the gateway
#   - the gateway answers pings on each of its addresses
#   - nodes behind different LAN ports reach each other
#   - nodes reach the upstream over ICMP, TCP and UDP, and the upstream sees
#     the gateway's WAN address, not theirs
#   - many flows at once all get through, carried by more than one worker
#   - the upstream reaches the gateway's WAN address
#   - with dnsmasq installed: started with no WAN address, the gateway leases
#     one from the upstream and forwards through it

set -Eeuo pipefail
cd "$(dirname "$0")/.."

NAME=e2e-test
WORKERS="${WORKERS:-2}"
KEEP="${KEEP:-0}"
ROUTER="${ROUTER:-target/release/mangonel-router}"
# A resolver only the upstream's DHCP server names.
LEASED_DNS=203.0.113.53
TCP_PORT=8080
UDP_PORT=9000

# shellcheck source=scripts/e2e-lib.sh
. scripts/e2e-lib.sh

# The upstream's services answer with the address they were asked from, which
# is how a node learns what it looks like from outside. A client asks COUNT
# times, each from a new port, and prints every distinct answer.
write_probe() {
    cat >"$TMP/probe.py" <<'EOF'
import socket
import sys

mode, protocol, host, port = sys.argv[1:5]
kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
if mode == "serve":
    server = socket.socket(socket.AF_INET, kind)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, int(port)))
    if protocol == "tcp":
        server.listen(128)
        while True:
            connection, peer = server.accept()
            connection.sendall(peer[0].encode())
            connection.close()
    else:
        while True:
            _, peer = server.recvfrom(64)
            server.sendto(peer[0].encode(), peer)
else:
    seen = set()
    for _ in range(int(sys.argv[5])):
        client = socket.socket(socket.AF_INET, kind)
        client.settimeout(3)
        client.connect((host, int(port)))
        if protocol == "udp":
            client.send(b"?")
        seen.add(client.recv(64).decode())
        client.close()
    print(" ".join(sorted(seen)))
EOF
}

# asks N PROTOCOL COUNT: what the upstream saw node N as, over COUNT flows.
asks() {
    local port="$TCP_PORT"
    if [ "$2" = udp ]; then
        port="$UDP_PORT"
    fi
    node "$1" python3 "$TMP/probe.py" ask "$2" "$UPSTREAM" "$port" "$3" 2>/dev/null
}

# Brings the topology up with a different queue count behind each gateway port
# and trims what the router cannot reach.
build_topology() {
    local expected="$1"
    "$TOPOLOGY" down
    QUEUES_WAN=$((WORKERS + 2)) QUEUES_LAN_0="$WORKERS" QUEUES_LAN_1=$((WORKERS + 1)) \
        "$TOPOLOGY" up >/dev/null

    # A veth takes an XDP program only while it has at least as many receive
    # queues as its peer has transmit queues. The router levels its own ends;
    # the far ends are someone else's machine, so they are levelled here.
    upstream ethtool -L eth0 rx "$expected" tx "$expected"
    ip netns exec "$SWITCH" ethtool -L lan-1 rx "$expected" tx "$expected"
    if [ "$WORKERS" -ne "$expected" ]; then
        node 0 ethtool -L eth0 rx "$expected" tx "$expected"
    fi
}

test_queues() {
    local expected="$1" port counts workers
    workers=$(sed -n 's/^mangonel-router: \([0-9]*\) workers on cores .*/\1/p' "$TMP/router.log")
    if [ "$workers" = "$expected" ]; then
        ok "the router runs $workers workers, one per queue of the narrowest port"
    else
        bad "the router runs '$workers' workers, not $expected"
    fi
    for port in wan lan-0 lan-1; do
        counts=$(queues "$GATEWAY" "$port")
        if [ "$counts" = "$expected $expected" ]; then
            ok "$port has $expected receive and transmit queues"
        else
            bad "$port has '$counts' receive and transmit queues, not $expected each"
        fi
    done
}

test_leases() {
    local dns="$1"
    lease 0 10.0.0 "$dns"
    lease 1 10.0.1 "$dns"
    lease 2 10.0.1 "$dns"
    if [ "${ADDRESS[1]:-}" != "${ADDRESS[2]:-}" ]; then
        ok "node-1 and node-2 share a LAN port and hold different addresses"
    else
        bad "node-1 and node-2 were both leased '${ADDRESS[1]:-}'"
    fi
}

test_gateway_addresses() {
    expect "node-0 pings its gateway 10.0.0.1" node 0 "${PING[@]}" 10.0.0.1
    expect "node-1 pings its gateway 10.0.1.1" node 1 "${PING[@]}" 10.0.1.1
    expect "node-2 pings its gateway 10.0.1.1" node 2 "${PING[@]}" 10.0.1.1
    expect "node-0 pings the gateway's other LAN address 10.0.1.1" node 0 "${PING[@]}" 10.0.1.1
    expect "node-1 pings the gateway's WAN address $EXTERNAL" node 1 "${PING[@]}" "$EXTERNAL"
}

test_between_lans() {
    # A node whose lease failed has no address, and its test fails with it.
    local first="${ADDRESS[0]:-}" second="${ADDRESS[1]:-}"
    expect "node-0 pings node-1 at $second across the gateway" node 0 "${PING[@]}" "$second"
    expect "node-2 pings node-0 at $first across the gateway" node 2 "${PING[@]}" "$first"
}

test_upstream() {
    local n seen
    for n in 0 1 2; do
        expect "node-$n pings the upstream $UPSTREAM" node "$n" "${PING[@]}" "$UPSTREAM"
    done
    if ! command -v python3 >/dev/null; then
        skip "TCP and UDP through the gateway: python3 is not installed"
        return
    fi
    for n in 0 1 2; do
        seen=$(asks "$n" tcp 1) || true
        if [ "$seen" = "$EXTERNAL" ]; then
            ok "node-$n reaches the upstream over TCP as $EXTERNAL"
        else
            bad "node-$n over TCP was seen by the upstream as '$seen', not $EXTERNAL"
        fi
        seen=$(asks "$n" udp 1) || true
        if [ "$seen" = "$EXTERNAL" ]; then
            ok "node-$n reaches the upstream over UDP as $EXTERNAL"
        else
            bad "node-$n over UDP was seen by the upstream as '$seen', not $EXTERNAL"
        fi
    done
}

# Every node at once, each flow from a port of its own, so the flows spread
# over the queues in both directions.
test_many_flows() {
    local n protocol seen pid pids=()
    command -v python3 >/dev/null || return 0
    for n in 0 1 2; do
        for protocol in tcp udp; do
            asks "$n" "$protocol" 100 >"$TMP/flows-$n-$protocol" &
            pids+=($!)
        done
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || true
    done
    for n in 0 1 2; do
        for protocol in tcp udp; do
            seen=$(cat "$TMP/flows-$n-$protocol")
            if [ "$seen" = "$EXTERNAL" ]; then
                ok "100 $protocol flows from node-$n all return, each seen as $EXTERNAL"
            else
                bad "100 $protocol flows from node-$n: the upstream saw '$seen'"
            fi
        done
    done
}

test_from_upstream() {
    expect "the upstream pings the gateway at $EXTERNAL" upstream "${PING[@]}" "$EXTERNAL"
}

# After the router has stopped: what each worker counted.
test_workers() {
    local expected="$1" busy
    busy=$(grep -c '^mangonel-router: worker [0-9]* received [1-9]' "$TMP/router.log") || true
    if [ "$expected" -lt 2 ]; then
        skip "more than one worker carries traffic: only one runs"
    elif [ "$busy" -ge 2 ]; then
        ok "$busy of $expected workers carried traffic"
    else
        bad "$busy of $expected workers carried traffic"
        grep '^mangonel-router: worker' "$TMP/router.log" || true
    fi
}

# The router again, this time told only its devices: it has to lease the WAN
# address from the upstream before anything gets through.
test_leased_wan() {
    local waited=0
    if ! command -v dnsmasq >/dev/null; then
        skip "the gateway leases its WAN address: dnsmasq is not installed"
        return
    fi
    ip netns exec "$WAN" dnsmasq --keep-in-foreground --conf-file=/dev/null --user=root \
        --port=0 --interface=eth0 --bind-interfaces --no-ping \
        --dhcp-range="$EXTERNAL,$EXTERNAL,255.255.255.0,10m" \
        --dhcp-option=option:router,"$UPSTREAM" \
        --dhcp-option=option:dns-server,"$LEASED_DNS" \
        --dhcp-leasefile="$TMP/upstream.leases" --pid-file= \
        >"$TMP/dnsmasq.log" 2>&1 &
    # Ended like the probes, by the topology going down.
    disown

    start_router --wan wan --lan lan-0 --lan lan-1
    until upstream ping -q -c 1 -W 1 "$EXTERNAL" >/dev/null 2>&1; do
        if [ "$waited" -ge 20 ]; then
            bad "the gateway leases $EXTERNAL from the upstream"
            cat "$TMP/dnsmasq.log"
            return
        fi
        waited=$((waited + 1))
    done
    ok "the gateway leased $EXTERNAL from the upstream and answers on it"
    expect "node-0 pings the upstream through the leased address" node 0 "${PING[@]}" "$UPSTREAM"
    expect "node-1 pings the upstream through the leased address" node 1 "${PING[@]}" "$UPSTREAM"
    # The gateway hands on the resolver its own lease named.
    lease 0 10.0.0 "$LEASED_DNS"
}

run() {
    local expected spare tool
    for tool in ip ethtool ping sed grep; do
        command -v "$tool" >/dev/null || die "$tool is not installed"
    done
    [[ $WORKERS =~ ^[1-9][0-9]*$ ]] || die "WORKERS must be a positive integer, not '$WORKERS'"
    [ -x "$ROUTER" ] || die "$ROUTER is not built"
    [ -x "$LEASE" ] || die "$LEASE is not built"

    spare=$(spare_cores)
    expected=$((WORKERS < spare ? WORKERS : spare))
    if [ "$expected" -ne "$WORKERS" ]; then
        echo "e2e-test: only $spare cores to spare, so $expected workers instead of $WORKERS"
    fi

    TMP=$(mktemp -d)
    trap cleanup EXIT
    build_topology "$expected"
    write_probe
    # Taking the topology down ends these, which no shell needs to report:
    # hence no function in between, and no job left to mention.
    if command -v python3 >/dev/null; then
        ip netns exec "$WAN" python3 "$TMP/probe.py" serve tcp "$UPSTREAM" "$TCP_PORT" &
        disown
        ip netns exec "$WAN" python3 "$TMP/probe.py" serve udp "$UPSTREAM" "$UDP_PORT" &
        disown
    fi

    echo "with a WAN address given:"
    start_router --wan "wan=$EXTERNAL/24,$UPSTREAM" --lan lan-0 --lan lan-1
    test_queues "$expected"
    test_leases "$UPSTREAM"
    test_gateway_addresses
    test_between_lans
    test_upstream
    test_many_flows
    test_from_upstream
    stop_router
    test_workers "$expected"

    echo "with the WAN address leased:"
    test_leased_wan
    if [ "$KEEP" != 1 ]; then
        stop_router
    elif [ -z "$ROUTER_PID" ]; then
        start_router --wan "wan=$EXTERNAL/24,$UPSTREAM" --lan lan-0 --lan lan-1
    fi

    if [ "$FAIL" -ne 0 ]; then
        exit 1
    fi
    echo "all passed"
}

main() {
    if [ "$(id -u)" -ne 0 ]; then
        # Built as the caller, so nothing under target/ ends up owned by root.
        cargo build --release -p mangonel-router
        cargo build --release -p mangonel-dhcp --example lease
        exec sudo -- env WORKERS="$WORKERS" KEEP="$KEEP" ROUTER="$ROUTER" "$0" "$@"
    fi
    run
}

main "$@"
