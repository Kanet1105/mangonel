use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use core_affinity::CoreId;
use mangonel_libxdp::{XdpDescriptor, XdpReceiver, XdpSender};

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

/// Receive, mark every frame for drop, send, count — the
/// substrate loop. It proves the queue's path and meters
/// it, and blackholes the interface until forwarding
/// exists.
pub(crate) fn run(
    mut sender: XdpSender,
    mut receiver: XdpReceiver,
    running: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
) {
    let mut batch: [XdpDescriptor; BATCH_SIZE] = std::array::from_fn(|_| XdpDescriptor::default());
    while running.load(Ordering::Relaxed) {
        let received = receiver.receive(&mut batch);
        if received == 0 {
            std::hint::spin_loop();
            continue;
        }

        for descriptor in &mut batch[..received as usize] {
            descriptor.set_drop();
        }

        // The batch must be fully consumed before the next receive
        // overwrites the slots: an overwritten minted
        // descriptor leaks its frame for good. Drop-marked
        // descriptors need no tx slots, so this loop runs once
        // today; it keeps the retry-with-tail shape every
        // later worker needs.
        let mut consumed: u32 = 0;
        while consumed < received {
            consumed += sender.send(&mut batch[consumed as usize..received as usize]);
        }

        counter.fetch_add(u64::from(received), Ordering::Relaxed);
    }
}
