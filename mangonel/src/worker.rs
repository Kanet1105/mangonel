use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use core_affinity::CoreId;
use mangonel_libxdp::{FramePool, XdpDescriptor, XdpSocket};

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
/// directions, over a shared frame pool. `wan` and `lan`
/// bind the same umem, so a frame received on one is
/// transmitted on the other with no copy, and its
/// completion returns to `pool` — the pool cannot starve
/// under asymmetric traffic because both interfaces draw
/// from and return to it.
///
/// Forwarding is L2: the frame goes out unchanged. L3
/// routing — parse, FIB lookup, TTL, MAC rewrite — is the
/// per-packet step that will sit between receive and send.
pub(crate) fn forward(
    mut wan: XdpSocket,
    mut lan: XdpSocket,
    mut pool: FramePool,
    running: &AtomicBool,
    wan_counter: &AtomicU64,
    lan_counter: &AtomicU64,
) {
    let mut batch: [XdpDescriptor; BATCH_SIZE] = std::array::from_fn(|_| XdpDescriptor::default());
    while running.load(Ordering::Relaxed) {
        let to_lan = pump(&mut wan, &mut lan, &mut pool, &mut batch);
        let to_wan = pump(&mut lan, &mut wan, &mut pool, &mut batch);

        wan_counter.fetch_add(u64::from(to_lan), Ordering::Relaxed);
        lan_counter.fetch_add(u64::from(to_wan), Ordering::Relaxed);
        if to_lan == 0 && to_wan == 0 {
            std::hint::spin_loop();
        }
    }
}

/// Receives a batch on `from` and transmits it out `to`,
/// returning how many were forwarded. The batch is fully
/// consumed before returning: the next receive would
/// otherwise overwrite minted descriptors and leak their
/// frames.
fn pump(
    from: &mut XdpSocket,
    to: &mut XdpSocket,
    pool: &mut FramePool,
    batch: &mut [XdpDescriptor],
) -> u32 {
    let received = from.receive(batch, pool);
    if received == 0 {
        return 0;
    }

    // L3 processing goes here.

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
            // Drops need no tx slot, so this consumes the rest.
            consumed += to.send(tail, pool);
        }
    }

    received
}
