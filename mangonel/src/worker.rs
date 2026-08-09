use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use core_affinity::CoreId;
use mangonel_libxdp::{FramePool, Umem, XdpDescriptor, XdpSocket};

use crate::net::{Neighbors, Router, Side};

/// Descriptors processed per receive call.
const BATCH_SIZE: usize = 64;

/// The core ids allowed for this process, in kernel order.
/// Cpusets and isolcpus leave holes, so these are iterated
/// rather than `0..n`. `None` when the set is unknown or
/// empty.
pub(crate) fn allowed_cores() -> Option<Vec<CoreId>> {
    core_affinity::get_core_ids().filter(|cores| !cores.is_empty())
}

/// Round-robin over the allowed cores, sparing the first —
/// where the OS and the control thread live — when there
/// is more than one.
//
// NUMA: filter to the interface's node once the node
// cpulists are probed.
pub(crate) fn assign_core(cores: &[CoreId], index: usize) -> CoreId {
    if cores.len() > 1 {
        cores[1 + index % (cores.len() - 1)]
    } else {
        cores[0]
    }
}

/// Forwards between one WAN queue and one LAN queue, both
/// directions, over a shared frame pool.
///
/// With `router` set, each frame is routed at L3 — parsed,
/// TTL-decremented, MAC-rewritten — and dropped if it does
/// not resolve; without it, frames cross unchanged (L2).
/// The neighbor table is per-worker, learned from this
/// queue's traffic.
#[expect(
    clippy::too_many_arguments,
    reason = "one pinned worker's whole context; a struct would only move the arguments"
)]
pub(crate) fn forward(
    mut wan: XdpSocket,
    mut lan: XdpSocket,
    mut pool: FramePool,
    umem: Umem,
    router: Option<Arc<Router>>,
    running: &AtomicBool,
    wan_counter: &AtomicU64,
    lan_counter: &AtomicU64,
) {
    let router = router.as_deref();
    let mut neighbors = Neighbors::default();
    let mut batch: [XdpDescriptor; BATCH_SIZE] = std::array::from_fn(|_| XdpDescriptor::default());
    while running.load(Ordering::Relaxed) {
        let to_lan = pump(
            &mut wan,
            &mut lan,
            Side::Wan,
            Side::Lan,
            &mut pool,
            &umem,
            router,
            &mut neighbors,
            &mut batch,
        );
        let to_wan = pump(
            &mut lan,
            &mut wan,
            Side::Lan,
            Side::Wan,
            &mut pool,
            &umem,
            router,
            &mut neighbors,
            &mut batch,
        );

        wan_counter.fetch_add(u64::from(to_lan), Ordering::Relaxed);
        lan_counter.fetch_add(u64::from(to_wan), Ordering::Relaxed);
        if to_lan == 0 && to_wan == 0 {
            std::hint::spin_loop();
        }
    }
}

/// Receives a batch on `from`, routes (or passes) each
/// frame, and transmits out `to`. Returns how many were
/// forwarded (the rest dropped). The batch is fully
/// consumed before returning: the next receive would
/// otherwise overwrite minted descriptors and leak their
/// frames.
#[expect(
    clippy::too_many_arguments,
    reason = "single-threaded hot path; grouping into a struct would only move the arguments"
)]
fn pump(
    from: &mut XdpSocket,
    to: &mut XdpSocket,
    ingress: Side,
    egress: Side,
    pool: &mut FramePool,
    umem: &Umem,
    router: Option<&Router>,
    neighbors: &mut Neighbors,
    batch: &mut [XdpDescriptor],
) -> u32 {
    let received = from.receive(batch, pool);
    if received == 0 {
        return 0;
    }

    let mut forwarded = received;
    if let Some(router) = router {
        forwarded = 0;
        for descriptor in &mut batch[..received as usize] {
            // Scope the frame borrow so set_drop can take the
            // descriptor back afterwards.
            let keep = {
                let frame = descriptor.data_mut(umem);
                router.forward(frame, ingress, egress, neighbors)
            };
            if keep {
                forwarded += 1;
            } else {
                descriptor.set_drop();
            }
        }
    }

    // send consumes a partial front when the tx ring is full;
    // retry the tail. A send that makes no progress means the
    // egress is stalled (congested or link down): drop the
    // rest to the pool rather than spin forever, which both
    // frees the frames and keeps the worker responsive to
    // shutdown. Every iteration advances `consumed`, so this
    // always terminates.
    let mut consumed: u32 = 0;
    while consumed < received {
        let tail = &mut batch[consumed as usize..received as usize];
        let sent = to.send(tail, pool);
        consumed += sent;
        if sent == 0 {
            let tail = &mut batch[consumed as usize..received as usize];
            for descriptor in tail.iter_mut() {
                descriptor.set_drop();
            }
            consumed += to.send(tail, pool);
        }
    }

    forwarded
}
