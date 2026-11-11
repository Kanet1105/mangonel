# Shared by the e2e scripts: the names of the topology e2e-env.sh builds, and
# what it takes to run the router in it and ask things of it from the nodes.
# Sourced, not run. The script that sources it has changed to the repository's
# root and set NAME (for its messages), ROUTER and KEEP.

LEASE=target/release/examples/lease
TOPOLOGY=scripts/e2e-env.sh

GATEWAY=test-gateway
WAN=test-wan
SWITCH=test-switch
# The upstream's address, and the one it leaves the gateway.
UPSTREAM=203.0.113.1
EXTERNAL=203.0.113.2

FAIL=0
ROUTER_PID=
TMP=
# The address each node leased, by node number.
ADDRESS=()

die() {
    echo "$NAME: $*" >&2
    exit 1
}

ok() {
    echo "  ok    $*"
}

bad() {
    echo "  FAIL  $*"
    FAIL=1
}

skip() {
    echo "  skip  $*"
}

# expect WHAT COMMAND...: the command has to succeed.
expect() {
    local what="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        ok "$what"
    else
        bad "$what"
    fi
}

node() {
    local n="$1"
    shift
    ip netns exec "test-node-$n" "$@"
}

upstream() {
    ip netns exec "$WAN" "$@"
}

# Every reply has to arrive: with -c and -w, ping fails on any that does not.
PING=(ping -q -c 3 -i 0.2 -w 5)

# cpus LIST: every CPU in a kernel list such as 0-3,8.
cpus() {
    local range cpu
    for range in ${1//,/ }; do
        for ((cpu = ${range%-*}; cpu <= ${range#*-}; cpu++)); do
            echo "$cpu"
        done
    done
}

# The cores the router will find: of the CPUs this process may run on, one per
# physical core, less CPU 0's unless that is the only one.
spare_cores() {
    local allowed cpu sibling first count=0 zero=0
    allowed=" $(cpus "$(sed -n 's/^Cpus_allowed_list:[[:space:]]*//p' /proc/self/status)" | tr '\n' ' ')"
    for cpu in $allowed; do
        # The lowest allowed sibling stands for its core.
        first=
        for sibling in $(cpus "$(cat "/sys/devices/system/cpu/cpu$cpu/topology/thread_siblings_list")"); do
            if [[ $allowed == *" $sibling "* ]]; then
                first=$sibling
                break
            fi
        done
        if [ "$first" = "$cpu" ]; then
            count=$((count + 1))
            if [ "$cpu" -eq 0 ]; then
                zero=1
            fi
        fi
    done
    if [ "$count" -gt 1 ] && [ "$zero" -eq 1 ]; then
        count=$((count - 1))
    fi
    echo "$count"
}

# queues NAMESPACE DEVICE: its receive and transmit queue counts.
queues() {
    ip netns exec "$1" sh -c "
        echo \$(ls -d /sys/class/net/$2/queues/rx-* | wc -l) \
             \$(ls -d /sys/class/net/$2/queues/tx-* | wc -l)"
}

# start_router ARGUMENT...: runs the router in the gateway and waits until its
# workers are bound.
start_router() {
    local waited=0
    # Not through a function: ip then becomes the router, so the pid kept is
    # the router's own and not a subshell's.
    ip netns exec "$GATEWAY" "$ROUTER" "$@" >"$TMP/router.log" 2>&1 &
    ROUTER_PID=$!
    until grep -q '^mangonel-router: ready$' "$TMP/router.log"; do
        if ! kill -0 "$ROUTER_PID" 2>/dev/null; then
            cat "$TMP/router.log" >&2
            die "the router exited while starting"
        fi
        if [ "$waited" -ge 150 ]; then
            cat "$TMP/router.log" >&2
            die "the router was not ready within 15 seconds"
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
}

# Asks the router to stop and waits for it, so its log ends with what each
# worker counted.
stop_router() {
    local waited=0
    [ -n "$ROUTER_PID" ] || return 0
    kill -TERM "$ROUTER_PID" 2>/dev/null || true
    while kill -0 "$ROUTER_PID" 2>/dev/null; do
        if [ "$waited" -ge 50 ]; then
            kill -KILL "$ROUTER_PID" 2>/dev/null || true
            bad "the router stops when told to"
            break
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
    wait "$ROUTER_PID" 2>/dev/null || true
    ROUTER_PID=
}

cleanup() {
    local status=$?
    trap - EXIT
    if [ "$KEEP" = 1 ] && [ -n "$ROUTER_PID" ]; then
        echo "$NAME: the router is left running as pid $ROUTER_PID, logging to $TMP/router.log"
        echo "$NAME: take it all down with: $TOPOLOGY down"
        exit "$status"
    fi
    stop_router
    "$TOPOLOGY" down || true
    if [ "$status" -ne 0 ] && [ -s "$TMP/router.log" ]; then
        echo "$NAME: the router's log:" >&2
        cat "$TMP/router.log" >&2
    fi
    rm -rf "$TMP"
    exit "$status"
}

# lease N SUBNET DNS: has node N lease an address and configures what it got,
# which must be in SUBNET with the gateway as router and DNS as resolver.
lease() {
    local n="$1" subnet="$2" dns="$3" got address router
    if ! got=$(node "$n" "$LEASE" eth0 10 2>&1); then
        bad "node-$n leases an address: $got"
        return
    fi
    address=${got#address=}
    address=${address%% *}
    router=${got#* router=}
    router=${router%% *}
    if [[ $address == "$subnet".*/24 && $router == "$subnet.1" && $got == *" dns=$dns "* ]]; then
        ok "node-$n leased $address with router $router and resolver $dns"
    else
        bad "node-$n leased '$got', not an address in $subnet.0/24 with resolver $dns"
    fi
    ADDRESS[n]=${address%/*}
    ip -n "test-node-$n" addr replace "$address" dev eth0
    ip -n "test-node-$n" route replace default via "$router"
}
