use std::ptr::{NonNull, null_mut};

use libc::{MSG_DONTWAIT, POLLIN, poll, pollfd, sendto};
use mangonel_libxdp_sys::{xsk_socket, xsk_socket__delete, xsk_socket__fd};

use crate::{
    descriptor::XdpDescriptor,
    ring::{Consumer, Producer},
    umem::Umem,
};

/// Free frames backing a worker's sockets.
///
/// A plain stack, not a concurrent ring: a worker drives
/// all its sockets from one thread, so the pool needs no
/// synchronization. Sharing one pool across a worker's
/// interfaces is what makes forwarding sound — a frame
/// received on one socket and transmitted on another
/// completes back into this same pool, so no per-socket
/// pool can starve under asymmetric traffic.
pub struct FramePool {
    free: Vec<u64>,
}

impl FramePool {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            free: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn push(&mut self, address: u64) {
        self.free.push(address);
    }

    pub(crate) fn pop(&mut self) -> Option<u64> {
        self.free.pop()
    }

    /// Free frames currently held.
    pub fn len(&self) -> usize {
        self.free.len()
    }

    pub fn is_empty(&self) -> bool {
        self.free.is_empty()
    }
}

/// One bound AF_XDP queue: receive and transmit over its
/// four rings, drawing free frames from — and returning
/// them to — an external [`FramePool`].
///
/// Not `Clone` and not `Sync`: one worker thread owns the
/// socket and its pool, so the rings have exactly one
/// driver.
pub struct XdpSocket {
    socket: NonNull<xsk_socket>,
    tx_ring: Producer,
    rx_ring: Consumer,
    fill_ring: Producer,
    completion_ring: Consumer,
    /// Held so the umem cannot be freed first.
    umem: Umem,
}

// SAFETY: moved to its worker thread at spawn. A raw socket
// pointer and rings, none with thread affinity. Never
// shared — not `Sync`, not `Clone` — so each ring has a
// single driver.
unsafe impl Send for XdpSocket {}

impl XdpSocket {
    pub(crate) fn new(
        socket: NonNull<xsk_socket>,
        tx_ring: Producer,
        rx_ring: Consumer,
        fill_ring: Producer,
        completion_ring: Consumer,
        umem: Umem,
    ) -> Self {
        Self {
            socket,
            tx_ring,
            rx_ring,
            fill_ring,
            completion_ring,
            umem,
        }
    }

    /// The umem the socket's frames live in — for the
    /// descriptor slice accessors.
    pub fn umem(&self) -> &Umem {
        &self.umem
    }

    /// Fills the front of `buffer` with one minted
    /// descriptor per received frame, overwriting the
    /// slots; returns the count. Tops the fill ring up
    /// from `pool` first.
    ///
    /// Overwriting a slot that still holds a minted
    /// descriptor leaks its frame, so reuse slots only
    /// after [`Self::send`] has consumed them.
    #[must_use = "the count says how many descriptors were filled with received frames"]
    pub fn receive(&mut self, buffer: &mut [XdpDescriptor], pool: &mut FramePool) -> u32 {
        let size = u32::try_from(buffer.len())
            .unwrap_or(u32::MAX)
            .min(self.rx_ring.size());
        self.fill(pool);
        self.poll();
        let umem_id = self.umem.id();
        let (available, index) = self.rx_ring.peek(size);
        let mut offset: u32 = 0;
        while offset < available {
            let descriptor = self.rx_ring.descriptor(index + offset);
            // Minted: the sole handle to the frame until send
            // consumes it — what as_slice_mut's exclusivity
            // rests on.
            buffer[offset as usize] = XdpDescriptor {
                address: descriptor.addr,
                length: descriptor.len,
                umem_id,
                is_drop: false,
            };
            offset += 1;
        }
        self.rx_ring.release(offset);

        offset
    }

    /// Consumes the minted descriptors at the front of
    /// `buffer`: drop-marked ones return to `pool`, the
    /// rest queue for transmit. Returns how many were
    /// consumed; retry with the unconsumed tail —
    /// resending the whole buffer panics on the
    /// consumed front.
    ///
    /// # Panics
    ///
    /// Panics when a descriptor in the batch is empty or
    /// from a different umem. Validated before the ring
    /// is touched, so the ring is never left
    /// half-reserved.
    #[must_use = "fewer descriptors than passed may have been consumed; the count says how many"]
    pub fn send(&mut self, buffer: &mut [XdpDescriptor], pool: &mut FramePool) -> u32 {
        let size = u32::try_from(buffer.len())
            .unwrap_or(u32::MAX)
            .min(self.tx_ring.size());
        // Validate before reserving: a caught panic after reserve
        // would desync the producer index for good.
        let umem_id = self.umem.id();
        let mut transmit_count: u32 = 0;
        for descriptor in &buffer[..size as usize] {
            assert!(
                descriptor.umem_id == umem_id,
                "Sent a XdpDescriptor that is not backed by this socket's umem: it is empty \
                 (already consumed, or never minted) or was minted against a different umem."
            );
            if !descriptor.is_drop {
                transmit_count += 1;
            }
        }
        // Clamped to the ring's free space: an unclamped
        // all-or-nothing reserve makes no progress until the
        // ring can seat the whole batch.
        let request = transmit_count.min(self.tx_ring.free(transmit_count));
        let (tx_available, tx_index) = self.tx_ring.reserve(request);
        // Consumption stops at the first transmit without a slot,
        // keeping the consumed front contiguous for
        // retry-with-tail.
        let mut written: u32 = 0;
        let mut consumed: u32 = 0;
        for descriptor in &mut buffer[..size as usize] {
            if descriptor.is_drop {
                pool.push(descriptor.address);
            } else {
                if written == tx_available {
                    break;
                }
                self.tx_ring.set_descriptor(
                    tx_index + written,
                    descriptor.address,
                    descriptor.length,
                );
                written += 1;
            }
            // An empty descriptor is the proof this handle can no
            // longer reach the frame.
            *descriptor = XdpDescriptor::default();
            consumed += 1;
        }
        self.tx_ring.submit(written);
        self.kick();
        // Drain every completion available, not just this batch's
        // worth; nothing else returns frames to the pool.
        self.complete(pool);

        consumed
    }

    /// Tops the fill ring up from `pool`.
    fn fill(&mut self, pool: &mut FramePool) {
        let size = u32::try_from(pool.len())
            .unwrap_or(u32::MAX)
            .min(self.fill_ring.size());
        // Clamp to the ring's free space: reserve is
        // all-or-nothing, so an unclamped request sized to the
        // full ring succeeds only once the kernel has drained
        // it completely, starving RX in bursts meanwhile. The
        // kernel only consumes fill entries, so the space
        // cannot shrink between these two calls.
        let size = size.min(self.fill_ring.free(size));
        let (available, index) = self.fill_ring.reserve(size);
        let mut offset: u32 = 0;
        while offset < available {
            let address = pool
                .pop()
                .expect("Fill ring reserved more than the pool holds. This is a bug.");
            self.fill_ring.set_fill_address(index + offset, address);
            offset += 1;
        }
        self.fill_ring.submit(offset);
    }

    /// Returns every completed tx frame to `pool`.
    fn complete(&mut self, pool: &mut FramePool) {
        let (filled, index) = self.completion_ring.peek(self.completion_ring.size());
        let mut offset: u32 = 0;
        while offset < filled {
            pool.push(self.completion_ring.completion_address(index + offset));
            offset += 1;
        }
        self.completion_ring.release(offset);
    }

    /// Wakes the driver; non-blocking and carries no data.
    fn kick(&mut self) {
        unsafe { sendto(self.socket_fd(), null_mut(), 0, MSG_DONTWAIT, null_mut(), 0) };
    }

    fn poll(&mut self) {
        let mut poll_fd_struct = pollfd {
            fd: self.socket_fd(),
            events: POLLIN,
            revents: 0,
        };
        unsafe { poll(&mut poll_fd_struct, 1, 0) };
    }

    pub(crate) fn socket_fd(&self) -> i32 {
        unsafe { xsk_socket__fd(self.socket.as_ptr()) }
    }
}

impl Drop for XdpSocket {
    fn drop(&mut self) {
        // Runs before the `umem` field drops, so socket delete
        // precedes umem delete. The umem's other references —
        // the binding's clone and the other sockets' — keep
        // it alive until the last socket is gone, so every
        // xsk_socket__delete precedes the single
        // xsk_umem__delete.
        unsafe { xsk_socket__delete(self.socket.as_ptr()) }
    }
}
