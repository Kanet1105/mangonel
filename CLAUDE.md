# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

mangonel is a WAN/LAN gateway whose data plane runs in userspace over AF_XDP (Linux only). `mangonel-router` is the daemon that wires the library crates together. The `mangonel` binary is still an empty `main`.

## Commands

```sh
scripts/deps.sh           # install libxdp/libbpf headers + libclang (bindgen needs them)
scripts/build.sh          # cargo test --workspace, then cargo build --release
scripts/lint.sh           # cargo sort --workspace -g; cargo +nightly fmt; cargo clippy --release

cargo test -p mangonel-dhcp                               # one crate
cargo test -p mangonel-libxdp default_frames_fill_one_socket  # one test (name filter)
cargo bench -p mangonel-ring                              # criterion: Ring vs ArrayQueue vs Mutex<VecDeque>
cargo run -p mangonel-nic --example dump [ifname ...]     # print what Nic sees per interface
cargo run -p mangonel-dhcp --example lease -- <ifname>    # lease an address with the crate's client and print it
scripts/e2e-env.sh up|down|status|check                   # netns topology for e2e tests; sudo is implied
scripts/e2e-test.sh                                       # the router's e2e tests in that topology; sudo is implied

# The router by hand, in a topology that is up. Without --wan and --lan it asks:
sudo ip netns exec test-gateway target/release/mangonel-router
sudo ip netns exec test-gateway target/release/mangonel-router \
    --wan wan=203.0.113.2/24,203.0.113.1 --lan lan-0 --lan lan-1
```

- `scripts/e2e-test.sh` builds as the caller, then takes the topology down and up again before it starts, so nothing else should be using it. `WORKERS=n` sets the queues on the narrowest gateway port (default 2), `KEEP=1` leaves the topology and the router running afterwards, and `ROUTER=` names another binary to test. TCP and UDP checks need `python3`, and the leased-WAN check needs `dnsmasq`; each is skipped without its tool.
- A veth accepts an XDP program only while it has at least as many receive queues as its peer has transmit queues. The router levels the gateway's ends; `e2e-test.sh` trims the far ends before it starts the router. By hand, `QUEUES=n scripts/e2e-env.sh up` keeps both ends equal.
- `scripts/lint.sh` rewrites files (`cargo sort` and `fmt`), so it does more than check.
- `rustfmt.toml` uses nightly-only options (`group_imports = "StdExternalCrate"`, `imports_granularity = "Crate"`, comments wrapped at 100 columns, `imports_layout = "Vertical"`). Always format with `cargo +nightly fmt`. Stable `cargo fmt` gives different output.
- There is no CI yet. Code must build on Rust **1.88.0**.
- Unit tests need no privileges. Binding a socket needs root, or CAP_NET_ADMIN plus CAP_SYS_RESOURCE (`bind` raises RLIMIT_MEMLOCK).
- `mangonel-libxdp-sys` generates bindings from the system's `xdp/xsk.h` at build time. If the headers live outside the default paths, set `BINDGEN_EXTRA_CLANG_ARGS=-I...` and `RUSTFLAGS=-L...`.

## Architecture

The crates are listed from the bottom of the stack up.

- **mangonel-libxdp-sys**: bindgen one-to-one bindings, with no logic of its own. `generate_inline_functions(true)` is load-bearing. The xsk ring accessors are `static inline` in `xsk.h`, but libxdp exports them as symbols, so they link.
- **mangonel-libxdp**: safe AF_XDP wrapper (details below).
- **mangonel-nic**: interface facts needed before binding (index, MAC, MTU, driver, queue/channel counts, NUMA node). It combines ioctl/ethtool, sysfs and `/proc/net/route`. `Nic` is a snapshot; it does not update live.
- **mangonel-ring**: generic bounded MPMC ring `Ring<T>` (details below).
- **mangonel-wire**: in-place views over frame bytes, generic over `AsRef<[u8]>` for reading and `AsMut<[u8]>` for writing, so an XDP frame's `&mut [u8]` is viewed without copying. Ethernet II, 802.1Q, ARP, IPv4, IPv6 (with extension-header skipping), ICMPv4, ICMPv6, Neighbor Discovery (RS/RA/NS/NA and options), UDP and TCP. The crate-level `parse(&mut [u8])` splits a frame into a `Frame` (Ethernet header with MAC accessors, optional VLAN tag, and a `Packet` enum of ARP/IPv4/IPv6/Other), all writable at once; the IP views hand the transport header on through `payload_mut`, or `Ipv6::upper_layer_mut` past extension headers; `Ipv4::dhcp` and `Ipv6::dhcp` return a per-family `Dhcp` enum whose variants carry exactly what the matching `mangonel-dhcp` handler takes besides `now`. Modules follow the layers: `data_link::ethernet` (header, `arp`, `vlan`), `network::ipv4` and `network::ipv6` (header, `icmp`, `dhcp`, and `ipv6::ndp`), `transport` (`tcp`, `udp`); every `mod.rs` only declares and re-exports. Each view's `parse` checks lengths and the fixed fields a header is recognised by; `init` zeroes a header and writes those fields so the setters can fill the rest. `checksum` has the RFC 1071 sum, the transport pseudo-header and the RFC 1624 incremental update that `Ipv4::decrement_ttl` uses. Protocol numbers and message types are newtypes with associated consts (`network::ipv4::Protocol::UDP`, `network::ipv6::Protocol::FRAGMENT`, `network::ipv6::icmp::Kind::ECHO_REQUEST`), not enums, so unknown values survive. No dependencies beyond `thiserror`.
- **mangonel-dhcp**: DHCPv4 and DHCPv6 servers and clients as sans-I/O state machines over `dhcproto`. The caller owns the sockets or frames and the clock: it passes a UDP payload and `now` in and gets packets to send, lease events and the next wake time out. `v4::server` and `v6::server` each serve one pool plus per-MAC reservations, which may lie outside the pool and are never handed to anyone else; `v4::client` and `v6::client` each hold one lease. Nothing in it needs privileges or threads, so its tests run anywhere.
- **mangonel-router**: the daemon, a binary crate with no library target (details below). It takes one WAN device and a list of LAN devices, holds their configuration in a control panel, and forwards with one run-to-completion worker per queue.

### libxdp ownership model

- **One global umem per process** (`static UMEM: OnceLock<Umem>` in `umem.rs`). The first `bind(iface, queue, XdpConfig)` creates it from the config's frame layout. Later binds reuse it and must repeat the same layout, or `bind` fails. Ring depths are per socket. Because every socket shares the umem, a descriptor received on any socket can be sent on any other without copying. The `BIND` mutex in `xdp.rs` serializes socket creation and deletion (the `Drop` impl of `XdpSocket` takes it too), because libxdp's umem bookkeeping is unsynchronized. `bind` releases it before the `XdpSocket` exists, because the lock is not reentrant. Size `frame_count` for every socket with `XdpConfig::frames_for(n)`.
- `Umem` is a shallow handle: `Clone` copies the pointers, and nothing frees it on drop. `Umem::free(self)` deletes the kernel umem and unmaps the area explicitly. libxdp refuses with `EBUSY` while any socket is still bound to the umem.
- `XdpSocket` drives all four rings from one thread. Each ring gets exactly one driver because `send` and `receive` take `&mut self` and the socket is `Send` but deliberately not `Sync`. It reaches the umem through `Umem::global()`.
- **Frame lifecycle**: the umem's frame pool (`Umem::pool()`, a `Ring<u64>`) is seeded with every frame address. `receive` first returns completed tx frames to the pool, then tops up the fill ring from it, then fills the buffer with one `XdpDescriptor` (`{ address, length }`) per rx entry. `send` only queues the front of the buffer on tx and kicks. Because completions are harvested only in `receive`, a socket that is sent on must also be received on, or its completion ring fills and tx stalls. `socket.drop(&mut buffer)` returns frames to the pool without sending them. `send` and `drop` empty each slot they consume and skip empty ones (`XdpDescriptor::default()` is empty, and `as_slice` panics on it), so safe code cannot hand a frame back twice. A descriptor that goes out of scope still holding a frame leaks it. To originate a packet, `socket.allocate(&mut buffer)` takes zero-length frames out of the pool, and `XdpDescriptor::set_length` resizes a frame up to its `capacity()`, the rest of its umem frame. Bytes gained hold whatever the frame last carried, so every one must be written.
- **Drop order matters.** Rings are created before the umem, which saves the fill/completion pair. The `Drop` impl of `XdpSocket` deletes the xsk socket before its fields drop. Ring structs are boxed for stable addresses because libxdp saves pointers to them.
- Forced bind modes (`XDP_COPY`/`XDP_ZEROCOPY`) go in `bind_flags`, never in `xdp_flags`. `xdp_flags` has bits with the same values that mean SKB/DRV attach mode.

### Router (`mangonel-router`)

- **Startup** (`main.rs`): the ports come from the flags or, when neither `--wan` nor `--lan` is given, from the questionnaire. They are submitted to the control panel, then the data plane starts and prints `mangonel-router: ready`. SIGINT and SIGTERM stop it, and each worker's received, sent and dropped counts are printed on the way out.
- **Flags** (`cli.rs`, clap): `--wan DEVICE[=ADDRESS/PREFIX,GATEWAY]` and one `--lan DEVICE[=ADDRESS/PREFIX][,static]` per segment; giving one kind requires the other. A WAN given no address leases one over DHCP. The Nth LAN given none takes `10.0.N.1/24`, and a LAN leases the rest of its subnet to its hosts unless it is `,static`. `Wan` and `Lan` print as they parse, and each builds its own control-panel port. Scripts and `e2e-test.sh` start the router this way.
- **Questionnaire** (`prompt.rs`, cliclack): choose the WAN device from every device but the loopback, choose its mode (DHCP, or Static with an address and gateway), then choose a LAN device, its mode (DHCP leases to its hosts, Static leaves them to set their own) and the gateway's address on it, repeating while "Add additional lan device?" is answered yes and a device is left. Answers are validated by building the port the control panel would get, plus a check that subnets do not overlap. It ends by printing the equivalent flags. It needs a terminal; Escape or Ctrl-C cancels with exit status 1.
- **Control panel** (`control/`): the `data-plane` branch's `ControlPlane`, renamed `ControlPanel`. One thread writes a left-right `State` (WAN and LAN ports keyed by MAC, extended ACLs, and which ACL filters each port in each direction); `Reader::enter` reads it without a lock. `State::revision` counts the changes applied, so a worker rebuilds its copy of the configuration only when it moves. Only `set_wan` and `set_lan` have a caller so far, hence the module-wide `dead_code` expectation.
- **Queue levelling** (`data/plane.rs`): the worker count is the smallest of each port's queue limit, the available cores and `--workers`. A port's limit is its channel maximum in the layout it runs now, which is the one `Nic::set_queue_count` asks in: `max_combined` when it has combined channels, else `min(max_rx, max_tx)`, else its current count when the driver has no channels API. Every port is set to that count with `Nic::set_queue_count` before anything binds, because a frame arriving on a queue no worker owns would bypass the gateway. Available cores (`data/cores.rs`) are the CPUs the process may run on, one per physical core, on the NICs' NUMA node when they share one, and without CPU 0 unless it is the only one.
- **Workers** (`data/worker.rs`): worker `i` pins itself, binds queue `i` of every port, and loops: receive up to 64 frames per port, run each through the pipeline, send one batch per egress port, and drop what a tx ring refuses. No frame is handed to another thread.
- **Pipeline** (`data/pipeline.rs`): no I/O, and generic over `Frame`, so its tests drive it with heap buffers. An IPv4 packet goes through the header checksum, the inbound ACL and DHCP, then by the side it arrived on. From a LAN, the source must be on the segment; a gateway address gets an echo reply; another LAN's subnet is routed; the rest is source-NATed out of the WAN. From the WAN, only the WAN address is accepted: the reply to a NAT session is translated back and routed, and an echo request is answered. A forwarded packet then passes the outbound ACL, loses a hop and gets its MACs. ARP for a port's own address is answered in place.
- **Shared state**: the two directions of a flow arrive on different queues, so three things are shared. `nat.rs` is one table in 64 shards, each behind a mutex; a flow's external port is drawn from the ports whose `(port - 1024) % 64` is its shard, so both directions take the same single lock. A TCP session idles for 7440 s only while it is established; one never answered, or closed by FIN or RST, goes after 240 s, so half-open connections cannot use up the ports. `neighbor.rs` is the ARP table behind a mutex with a generation counter; a worker looks up in a private copy and refreshes it when the counter moves. An entry lasts 300 s from the neighbour's last ARP, and in its last 30 s the neighbour is asked again, so one in use is not forgotten. `dhcp.rs` holds a `v4::server` per LAN port and a `v4::client` per leasing WAN port, one mutex per port, taken only by DHCP messages and timers. New resolvers, as when the WAN lease arrives, are set on a running server without dropping its leases.
- **Unresolved next hops**: the frame is parked on its worker, at most 8 per neighbour and 64 neighbours, and an ARP request goes out in a frame from `allocate`. `Pipeline::finish` releases the frames once any worker has learned the answer, asks again each second and drops them after three tries.
- **Timers**: worker 0 runs them once a second: NAT, neighbour and lease expiry, questions to neighbours about to lapse, and the DHCP clients.
- **Not there yet**: IPv6, VLAN-tagged and multicast frames, fragments that need NAT or are addressed to the gateway, and anything for the gateway itself other than echo and DHCP are dropped. No ICMP errors are generated, and none are translated back through NAT. DHCP leases are not kept across a restart.

### Rings (`mangonel-ring`)

`Ring<T>` uses DPDK `rte_ring`'s split head/tail design: CAS to claim a range, touch its slots, then commit in claim order. There are no per-slot sequence numbers. The design is batch-first: it wins 5–30× with bursts and loses to crossbeam `ArrayQueue` at burst 1. It is tuned for at most 2 contending threads. Don't propose switching to Vyukov-style queues. libxdp uses a `Ring<u64>` of frame addresses as the umem's free-frame ring.

- Every grant must commit exactly once and promptly. A stalled grant wedges the ring.
- Grants (`BulkWrite::write`, `BulkRead::read`) commit on `Drop`. Slots are `Option<T>` so readers can skip unwritten gaps. If one thread holds two grants of the same kind, it deadlocks: the grants drop in reverse order, so the later commit waits forever on the earlier one.
- Cursors wrap. Write index loops with `!=` and `wrapping_add`, never as `a..b` ranges.
- The orderings are deliberate. Opposite-tail and initial-head loads are Acquire, commits are Release, and head CASes are `AcqRel`/`Acquire`. Never weaken them to `Relaxed`. TSan catches regressions that plain x86 runs miss.

## Conventions

- **Errors vs panics**: environmental failures return `Result`. A violated invariant is a panic whose message ends in `"... This is a bug."`, checked once at the boundary that establishes it. A public error type wraps a private enum (`XdpError(Error)`) so variants don't leak into the API.
- **Casts**: workspace clippy `cast_*` lints warn on incidental casts, because the code crosses kernel ABI widths (`u32` ring indices, `u64` umem addresses, `usize` lengths). Use `u64::from`/`try_from`. Where truncation is intended, add a scoped `#[expect(clippy::cast_possible_truncation)]` with a reason.
- Every `unsafe` block and `unsafe impl` gets a `// SAFETY:` comment. libxdp pins its `unsafe impl Send/Sync` with compile-time `assert_send`/`assert_sync` checks at the end of `xdp.rs`. Keep that list in sync.
- Keep doc comments to one short sentence that states the contract. Don't write multi-paragraph rustdoc or restate the signature.
- Put a blank line before a `return` or tail expression when a statement precedes it in the same block. rustfmt removes the blank line when the return is the block's only statement; leave that as is.
- Crates use `#![warn(unreachable_pub)]` and `pub(crate)` internals.
- Workspace deps are declared with `default-features = false`, and each crate opts into the features it needs. Keep `cargo sort -g` ordering.
- Don't add `#[inline]` hints. Release builds use LTO with `codegen-units = 1` for cross-crate inlining.
- Commits are GPG-signed; never pass `--no-gpg-sign`. Never add `Co-Authored-By: Claude` (or any Claude/Anthropic attribution) to commits or PRs.
