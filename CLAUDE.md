# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

mangonel is a WAN/LAN gateway whose data plane runs in userspace over AF_XDP (Linux only). The `mangonel` binary is still an empty `main`. The library crates are built and tested on their own and are not wired together yet.

## Commands

```sh
just deps                 # install libxdp/libbpf headers + libclang (bindgen needs them)
just build                # cargo test --workspace, then cargo build --release
just lint                 # cargo sort --workspace -g; cargo +nightly fmt; cargo clippy --release

cargo test -p mangonel-gateway                            # one crate
cargo test -p mangonel-libxdp default_frames_fill_one_socket  # one test (name filter)
cargo bench -p mangonel-ring                              # criterion: Ring vs ArrayQueue vs Mutex<VecDeque>
cargo run -p mangonel-nic --example dump [ifname ...]     # print what Nic sees per interface
scripts/e2e-env.sh up|down|status|check                   # netns topology for e2e tests; sudo is implied
```

- `just lint` rewrites files (`cargo sort` and `fmt`), so it does more than check.
- `rustfmt.toml` uses nightly-only options (`group_imports = "StdExternalCrate"`, `imports_granularity = "Crate"`, comments wrapped at 100 columns, `imports_layout = "Vertical"`). Always format with `cargo +nightly fmt`. Stable `cargo fmt` gives different output.
- CI (`.github/workflows/ci.yml`) runs `just build` and `just lint` on Ubuntu, Fedora and Arch with Rust **1.88.0**, so code must build on that toolchain. CI triggers only on pushes and PRs to `dev`, not `main`.
- Unit tests need no privileges. Binding a socket needs root, or CAP_NET_ADMIN plus CAP_SYS_RESOURCE (`bind` raises RLIMIT_MEMLOCK).
- `mangonel-libxdp-sys` generates bindings from the system's `xdp/xsk.h` at build time. If the headers live outside the default paths, set `BINDGEN_EXTRA_CLANG_ARGS=-I...` and `RUSTFLAGS=-L...`.

## Architecture

The crates are listed from the bottom of the stack up.

- **mangonel-libxdp-sys**: bindgen one-to-one bindings, with no logic of its own. `generate_inline_functions(true)` is load-bearing. The xsk ring accessors are `static inline` in `xsk.h`, but libxdp exports them as symbols, so they link.
- **mangonel-libxdp**: safe AF_XDP wrapper (details below).
- **mangonel-nic**: interface facts needed before binding (index, MAC, MTU, driver, queue/channel counts, NUMA node). It combines ioctl/ethtool, sysfs and `/proc/net/route`. `Nic` is a snapshot; it does not update live.
- **mangonel-ring**: generic bounded MPMC ring `Ring<T>` (details below).
- **mangonel-dhcp**: DHCPv4 and DHCPv6 servers and clients as sans-I/O state machines over `dhcproto`. The caller owns the sockets or frames and the clock: it passes a UDP payload and `now` in and gets packets to send, lease events and the next wake time out. `v4::server` and `v6::server` each serve one pool; `v4::client` and `v6::client` each hold one lease. Nothing in it needs privileges or threads, so its tests run anywhere.
- **mangonel-gateway**: both planes, as modules of one crate so they can refer to each other.
  - `data`: `DataPlane::new(Vec<Nic>, Reader)` sizes the workers to the NIC with the fewest queues (capped by the physical cores on the NICs' NUMA node, CPU 0's core left to the OS), sets every NIC to that many queues, and spawns one pinned worker per queue index, bound to that queue on every NIC. Each worker runs a frame to completion in Cisco's order: inbound ACL, then route and NAT (source NAT after routing going out, destination NAT before routing coming in), then outbound ACL. NAT (`nat.rs`) is per worker: each owns a slice of the external ports, and a WAN reply landing on another worker's queue is handed to the owner over a per-pair `Ring`. Workers must never call the control plane's blocking write path (`ControlPlane`'s change methods) from the packet loop.
  - `control`: configuration (WAN/LAN ports keyed by MAC, Cisco-style extended ACLs, ACL attached per port and direction). It lives in a `left_right` structure. A dedicated thread owns the `WriteHandle`. `ControlPlane`'s change methods send an `Op` down an mpsc queue and block until the op has been checked and published; share it by reference or `Arc`. `State::check` validates every op before it is appended, so `Absorb` never fails. Data-plane threads each hold their own `Reader` (it is `Send`, not `Sync`) and must keep `ReadGuard`s short, because a held guard blocks the next publish.

### libxdp ownership model

- **One global umem per process** (`static UMEM: OnceLock<Umem>` in `umem.rs`). The first `bind(iface, queue, XdpConfig)` creates it from the config's frame layout. Later binds reuse it and must repeat the same layout, or `bind` fails. Ring depths are per socket. Because every socket shares the umem, a descriptor received on any socket can be sent on any other without copying. The `BIND` mutex in `xdp.rs` serializes socket creation and deletion (the `Drop` impl of `XdpSocket` takes it too), because libxdp's umem bookkeeping is unsynchronized. `bind` releases it before the `XdpSocket` exists, because the lock is not reentrant. Size `frame_count` for every socket with `XdpConfig::frames_for(n)`.
- `Umem` is a shallow handle: `Clone` copies the pointers, and nothing frees it on drop. `Umem::free(self)` deletes the kernel umem and unmaps the area explicitly. libxdp refuses with `EBUSY` while any socket is still bound to the umem.
- `XdpSocket` drives all four rings from one thread. Each ring gets exactly one driver because `send` and `receive` take `&mut self` and the socket is `Send` but deliberately not `Sync`. It reaches the umem through `Umem::global()`.
- **Frame lifecycle**: the umem's frame pool (`Umem::pool()`, a `Ring<u64>`) is seeded with every frame address. `receive` first returns completed tx frames to the pool, then tops up the fill ring from it, then fills the buffer with one `XdpDescriptor` (`{ address, length }`) per rx entry. `send` only queues the front of the buffer on tx and kicks. Because completions are harvested only in `receive`, a socket that is sent on must also be received on, or its completion ring fills and tx stalls. `socket.drop(&mut buffer)` returns frames to the pool without sending them. `send` and `drop` empty each slot they consume and skip empty ones (`XdpDescriptor::default()` is empty, and `as_slice` panics on it), so safe code cannot hand a frame back twice. A descriptor that goes out of scope still holding a frame leaks it.
- **Drop order matters.** Rings are created before the umem, which saves the fill/completion pair. The `Drop` impl of `XdpSocket` deletes the xsk socket before its fields drop. Ring structs are boxed for stable addresses because libxdp saves pointers to them.
- Forced bind modes (`XDP_COPY`/`XDP_ZEROCOPY`) go in `bind_flags`, never in `xdp_flags`. `xdp_flags` has bits with the same values that mean SKB/DRV attach mode.

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
