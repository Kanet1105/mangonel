#!/usr/bin/env bash
# The network namespaces mangonel's end-to-end tests run in.
#
#   up      build the topology below; refuses if any part of it exists
#   down    kill whatever runs inside it, then delete it
#   status  list every namespace's links and addresses
#   check   verify the wiring (up runs it last)
#
# Every box is a network namespace and every link a veth pair, so nothing here
# touches the host's interfaces, firewall or NetworkManager.
#
#   test-wan      test-gateway              test-switch               test-node-1
#   +------+      +---------------+         +------------+            +------+
#   | eth0 +------+ wan     lan-1 +---------+ lan-1      |      +-----+ eth0 |
#   +------+      |               |         |     node-1 +------+     +------+
#                 | tap-0   lan-0 +----+    | br0 node-2 +------------ test-node-2 eth0
#                 +---------------+    |    +------------+
#                                      |
#                                      |    test-node-0
#                                      +----- eth0
#
#   namespace     iface   MAC                IPv4
#   test-gateway  wan     02:00:00:01:00:01  none; 203.0.113.2/24 is mangonel's to claim
#   test-gateway  lan-0   02:00:00:01:00:02  none; 10.0.0.1/24 is mangonel's to claim
#   test-gateway  lan-1   02:00:00:01:00:03  none; 10.0.1.1/24 is mangonel's to claim
#   test-gateway  tap-0   02:00:00:01:00:10  none; the host stack's door, see below
#   test-wan      eth0    02:00:00:02:00:01  203.0.113.1/24, the upstream router
#   test-switch   br0     02:00:00:03:00:00  none; a dumb switch with no IP stack
#   test-switch   lan-1   02:00:00:03:00:01  bridge port, peer of test-gateway lan-1
#   test-switch   node-N  02:00:00:03:01:0N  bridge port, peer of test-node-N eth0, N = 1, 2
#   test-node-0   eth0    02:00:00:04:00:00  none; peer of test-gateway lan-0
#   test-node-N   eth0    02:00:00:04:00:0N  none, neither v4 nor v6; the gateway hands them out
#
# The gateway's kernel gets no address and does not forward, so whatever crosses
# it crossed through mangonel. test-wan has no route back to the LANs, like a
# real upstream, so LAN traffic needs NAT to get a reply.
#
# tap-0 is a persistent multi-queue TAP for the gateway's own kernel stack: a
# DHCP server or sshd binds to it, and the data plane copies frames between it
# and a LAN port. Open it with IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE and give it
# the MAC and address of the LAN port it fronts. It has no carrier until a
# process holds a queue open, so check leaves it out of the carrier test.
#
# Run the gateway in its namespace:    ip netns exec test-gateway <command>
# Watch the LAN from the switch:       ip netns exec test-switch tcpdump -i br0
#
# QUEUES=n sets every veth's queue count (default 1). AF_XDP binds one socket
# per queue, and a veth gets one queue per CPU unless told otherwise.

set -Eeuo pipefail

QUEUES="${QUEUES:-1}"

GATEWAY=test-gateway
WAN=test-wan
SWITCH=test-switch
NODES=(test-node-0 test-node-1 test-node-2)
ALL=("$GATEWAY" "$WAN" "$SWITCH" "${NODES[@]}")

UPSTREAM_IP=203.0.113.1/24

# The ethtool settings for a veth end that faces the gateway. With tx checksum
# offload off the kernel finishes checksums before a frame crosses the pair,
# instead of leaving the partial sum it would hand a real NIC, which AF_XDP
# would read as garbage, and no segmentation offload means frames arrive no
# larger than the MTU. gro on is how veth enables NAPI without an XDP program,
# and the gateway's AF_XDP transmit into this end needs NAPI on.
FACING_GATEWAY=(tx off tso off gso off gro on)

FAIL=0

die() {
    echo "e2e-env: $*" >&2
    exit 1
}

ok() {
    echo "  ok    $*"
}

bad() {
    echo "  FAIL  $*"
    FAIL=1
}

ns_exists() {
    ip netns list | awk '{ print $1 }' | grep -qx -- "$1"
}

# veth NS1 IF1 MAC1 NS2 IF2 MAC2: one pair with an end in each namespace. Both
# ends are born inside their namespace, so a name like eth0 never collides with
# the host's.
veth() {
    ip link add "$2" address "$3" netns "$1" \
        numtxqueues "$QUEUES" numrxqueues "$QUEUES" \
        type veth peer name "$5" address "$6" netns "$4" \
        numtxqueues "$QUEUES" numrxqueues "$QUEUES"
}

up() {
    local ns i port
    for ns in "${ALL[@]}"; do
        ! ns_exists "$ns" || die "$ns exists; run '$0 down' first"
    done
    trap 'echo "e2e-env: up failed, tearing down" >&2; down' ERR

    for ns in "${ALL[@]}"; do
        ip netns add "$ns"
        ip -n "$ns" link set lo up
    done

    veth "$GATEWAY" wan 02:00:00:01:00:01 "$WAN" eth0 02:00:00:02:00:01
    veth "$GATEWAY" lan-0 02:00:00:01:00:02 "${NODES[0]}" eth0 02:00:00:04:00:00
    veth "$GATEWAY" lan-1 02:00:00:01:00:03 "$SWITCH" lan-1 02:00:00:03:00:01
    for i in 1 2; do
        veth "${NODES[i]}" eth0 "02:00:00:04:00:0$i" "$SWITCH" "node-$i" "02:00:00:03:01:0$i"
    done

    # A dumb switch has no IP stack, so it never puts frames of its own on the
    # LAN. `all` covers the ports that already exist, `default` the bridge.
    ip netns exec "$SWITCH" sysctl -q -w \
        net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
    ip -n "$SWITCH" link add br0 address 02:00:00:03:00:00 type bridge
    ip -n "$SWITCH" link set br0 up
    for port in lan-1 node-1 node-2; do
        ip -n "$SWITCH" link set "$port" master br0 up
    done

    # The gateway's kernel stays out of the data path. A new namespace inherits
    # the host's IPv4 forwarding setting, so say no explicitly.
    ip netns exec "$GATEWAY" sysctl -q -w \
        net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0
    ip -n "$GATEWAY" link set wan up
    ip -n "$GATEWAY" link set lan-0 up
    ip -n "$GATEWAY" link set lan-1 up
    ip -n "$GATEWAY" tuntap add dev tap-0 mode tap multi_queue
    ip -n "$GATEWAY" link set tap-0 address 02:00:00:01:00:10 up

    ip -n "$WAN" addr add "$UPSTREAM_IP" dev eth0
    ip -n "$WAN" link set eth0 up

    # Nodes come up with no address at all. The kernel makes a link-local IPv6
    # address when a link comes up unless addrgenmode is none beforehand.
    for ns in "${NODES[@]}"; do
        ip -n "$ns" link set eth0 addrgenmode none
        ip -n "$ns" link set eth0 up
    done

    # The three veth ends that face the gateway: the upstream, the switch port
    # on lan-1, and node-0 itself on lan-0.
    ip netns exec "$WAN" ethtool -K eth0 "${FACING_GATEWAY[@]}" >/dev/null
    ip netns exec "$SWITCH" ethtool -K lan-1 "${FACING_GATEWAY[@]}" >/dev/null
    ip netns exec "${NODES[0]}" ethtool -K eth0 "${FACING_GATEWAY[@]}" >/dev/null

    trap - ERR
    check
}

down() {
    local ns
    for ns in "${ALL[@]}"; do
        ns_exists "$ns" || continue
        # A namespace outlives its name while anything still runs inside it.
        ip netns pids "$ns" | xargs -r kill || true
        ip netns del "$ns"
    done
}

status() {
    local ns
    for ns in "${ALL[@]}"; do
        echo "== $ns"
        if ns_exists "$ns"; then
            ip -n "$ns" -br addr
        else
            echo "absent"
        fi
    done
    if ns_exists "$SWITCH"; then
        echo "== $SWITCH bridge ports"
        bridge -n "$SWITCH" link
    fi
}

check() {
    local ns dead ports ll
    for ns in "${ALL[@]}"; do
        ns_exists "$ns" || die "$ns is absent; run '$0 up' first"
    done
    echo "check:"

    # Every link but lo and the TAP, which has no carrier until opened.
    for ns in "${ALL[@]}"; do
        dead=$(ip -n "$ns" -br link |
            awk '$1 != "lo" && $1 !~ /^tap-/ && $4 !~ /LOWER_UP/ { sub(/@.*/, "", $1); print $1 }' |
            paste -sd ' ')
        if [ -z "$dead" ]; then
            ok "$ns: every link has carrier"
        else
            bad "$ns: no carrier on $dead"
        fi
    done

    if ip -n "$GATEWAY" -d link show dev tap-0 | grep -q 'tun type tap'; then
        ok "$GATEWAY: tap-0 is a TAP"
    else
        bad "$GATEWAY: tap-0 is missing or not a TAP"
    fi

    ports=$(bridge -n "$SWITCH" link |
        awk '/master br0 state forwarding/ { sub(/@.*/, "", $2); print $2 }' |
        sort | paste -sd ' ')
    if [ "$ports" = "lan-1 node-1 node-2" ]; then
        ok "$SWITCH: lan-1 node-1 node-2 forward on br0"
    else
        bad "$SWITCH: ports forwarding on br0 are '$ports', not 'lan-1 node-1 node-2'"
    fi

    for ns in "${NODES[@]}"; do
        if ip -n "$ns" addr show dev eth0 | grep -q inet; then
            bad "$ns: eth0 has an address and should start with none"
        else
            ok "$ns: eth0 has no address"
        fi
    done

    # The gateway's kernel owns nothing but the link-local address it gave
    # itself, so that is what the upstream can reach. DAD keeps it tentative
    # for about a second, hence the deadline.
    ll=$(ip -n "$GATEWAY" -6 -br addr show dev wan scope link |
        awk '{ sub(/\/.*/, "", $3); print $3; exit }')
    if [ -z "$ll" ]; then
        echo "  skip  $WAN -> $GATEWAY wan: the gateway has no link-local address; is IPv6 off?"
    elif ip netns exec "$WAN" ping -6 -q -c 1 -w 5 "$ll%eth0" >/dev/null; then
        ok "$WAN eth0 -> $GATEWAY wan ($ll) answers"
    else
        bad "$WAN eth0 -> $GATEWAY wan ($ll) does not answer"
    fi

    [ "$FAIL" -eq 0 ] || exit 1
}

main() {
    local cmd="${1:-}" tool
    case "$cmd" in
        up | down | status | check) ;;
        *)
            echo "usage: $0 up|down|status|check" >&2
            exit 2
            ;;
    esac
    if [ "$(id -u)" -ne 0 ]; then
        exec sudo -- env QUEUES="$QUEUES" "$0" "$@"
    fi
    [[ $QUEUES =~ ^[1-9][0-9]*$ ]] || die "QUEUES must be a positive integer, not '$QUEUES'"
    for tool in ip bridge ethtool sysctl ping; do
        command -v "$tool" >/dev/null || die "$tool is not installed"
    done
    "$cmd"
}

main "$@"
