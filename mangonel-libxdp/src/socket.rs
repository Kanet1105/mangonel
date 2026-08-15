use std::ptr::{NonNull, null_mut};

use libc::{MSG_DONTWAIT, POLLIN, poll, pollfd, sendto};
use mangonel_libxdp_sys::{xsk_socket, xsk_socket__delete, xsk_socket__fd};

use crate::{
    descriptor::XdpDescriptor,
    pool::FramePool,
    ring::{Consumer, Producer},
    umem::Umem,
};

/// One bound AF_XDP queue: receive and transmit over its
/// four rings, drawing free frames from — and returning
/// them to — its umem's shared [`FramePool`]. Sockets on
/// one umem sharing one pool is what makes forwarding
/// sound — a frame received on one socket and transmitted
/// on another completes back into the same pool, so no
/// per-socket pool can starve under asymmetric traffic.
///
/// Not `Clone` and not `Sync`: one worker thread owns the
/// socket, so the rings have exactly one driver. The
/// umem's pool is the shared piece.
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
    /// from the umem's pool first.
    ///
    /// Overwriting a slot that still holds a minted
    /// descriptor leaks its frame, so reuse slots only
    /// after [`Self::send`] has consumed them.
    #[must_use = "the count says how many descriptors were filled with received frames"]
    pub fn receive(&mut self, buffer: &mut [XdpDescriptor]) -> u32 {
        let size = u32::try_from(buffer.len())
            .unwrap_or(u32::MAX)
            .min(self.rx_ring.size());
        self.fill();
        self.poll();
        let umem_id = self.umem.id();
        let (available, index) = self.rx_ring.claim(size);
        let mut offset: u32 = 0;
        while offset < available {
            let descriptor = self.rx_ring.read_descriptor(index.wrapping_add(offset));
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
        self.rx_ring.commit(offset);

        offset
    }

    /// Consumes the minted descriptors at the front of
    /// `buffer`: drop-marked ones return to the umem's
    /// pool, the rest queue for transmit. Returns how many
    /// were consumed; retry with the unconsumed tail —
    /// resending the whole buffer panics on the
    /// consumed front.
    ///
    /// # Panics
    ///
    /// Panics when a descriptor in the batch is empty or
    /// from a different umem. Validated before the ring
    /// is touched, so the ring is never left
    /// half-claimed.
    #[must_use = "fewer descriptors than passed may have been consumed; the count says how many"]
    pub fn send(&mut self, buffer: &mut [XdpDescriptor]) -> u32 {
        let size = u32::try_from(buffer.len())
            .unwrap_or(u32::MAX)
            .min(self.tx_ring.size());
        // Validate before claiming: a caught panic after claim
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
        // all-or-nothing claim makes no progress until the
        // ring can seat the whole batch.
        let request = transmit_count.min(self.tx_ring.free(transmit_count));
        let (tx_available, tx_index) = self.tx_ring.claim(request);
        // Walk the consumed front first: it stops at the first
        // transmit without a tx slot, keeping it contiguous for
        // retry-with-tail, and its drop count sizes one pool
        // grant instead of a commit per drop.
        let mut written: u32 = 0;
        let mut consumed: u32 = 0;
        let mut drop_count: u32 = 0;
        for descriptor in &buffer[..size as usize] {
            if descriptor.is_drop {
                drop_count += 1;
            } else {
                if written == tx_available {
                    break;
                }
                written += 1;
            }
            consumed += 1;
        }
        let pool = self.umem.pool();
        let pool_index = (drop_count > 0).then(|| Self::pool_claim_write(pool, drop_count));

        let mut written: u32 = 0;
        let mut dropped: u32 = 0;
        for descriptor in &mut buffer[..consumed as usize] {
            if descriptor.is_drop {
                let pool_index =
                    pool_index.expect("A drop was counted, so the grant exists. This is a bug.");
                pool.write_at(
                    pool_index.wrapping_add(dropped) as usize,
                    descriptor.address,
                );
                dropped += 1;
            } else {
                self.tx_ring.write_descriptor(
                    tx_index.wrapping_add(written),
                    descriptor.address,
                    descriptor.length,
                );
                written += 1;
            }
            // An empty descriptor is the proof this handle can no
            // longer reach the frame.
            *descriptor = XdpDescriptor::default();
        }
        self.tx_ring.commit(written);
        if let Some(pool_index) = pool_index {
            pool.commit_write(pool_index as usize, drop_count);
        }
        self.kick();
        // Drain every completion available, not just this batch's
        // worth; nothing else returns frames to the pool.
        self.complete();

        consumed
    }

    /// Tops the fill ring up from the umem's pool.
    fn fill(&mut self) {
        // Clamp to the ring's free space: claim is
        // all-or-nothing, so an unclamped request sized to the
        // full ring succeeds only once the kernel has drained
        // it completely, starving RX in bursts meanwhile.
        let ring_size = self.fill_ring.size();
        let want = ring_size.min(self.fill_ring.free(ring_size));
        // The pool grant caps the claim at what the pool holds.
        let pool = self.umem.pool();
        let Some((count, pool_index)) = pool.claim_read(want) else {
            return;
        };

        // The kernel only consumes fill entries, so the free
        // space checked above cannot shrink: the claim seats
        // the whole grant.
        let (available, index) = self.fill_ring.claim(count);
        assert!(
            available == count,
            "Fill ring free space shrank below a granted burst. This is a bug."
        );
        let mut offset: u32 = 0;
        while offset < count {
            let address = pool.read_at(pool_index.wrapping_add(offset) as usize);
            self.fill_ring
                .write_fill_address(index.wrapping_add(offset), address);
            offset += 1;
        }
        self.fill_ring.commit(count);
        pool.commit_read(pool_index as usize, count);
    }

    /// Returns every completed tx frame to the umem's pool.
    fn complete(&mut self) {
        let (filled, index) = self.completion_ring.claim(self.completion_ring.size());
        if filled == 0 {
            return;
        }

        let pool = self.umem.pool();
        let pool_index = Self::pool_claim_write(pool, filled);
        let mut offset: u32 = 0;
        while offset < filled {
            pool.write_at(
                pool_index.wrapping_add(offset) as usize,
                self.completion_ring
                    .read_completion_address(index.wrapping_add(offset)),
            );
            offset += 1;
        }
        pool.commit_write(pool_index as usize, filled);
        self.completion_ring.commit(filled);
    }

    /// Reserves pool slots for frames leaving the datapath,
    /// waiting out transient claim gaps. The pool is sized
    /// to seat every frame it serves, so room for in-flight
    /// frames always exists; the wait only covers another
    /// worker's grant between claim and commit.
    fn pool_claim_write(pool: &FramePool, size: u32) -> u32 {
        loop {
            if let Some((available, index)) = pool.claim_write(size) {
                // claim_write caps grants at the pool's capacity;
                // committing the requested size against a capped
                // grant would corrupt the pool, so a burst must
                // never exceed it.
                assert!(
                    available == size,
                    "The pool capacity is smaller than a burst. This is a bug."
                );

                return index;
            }
            std::hint::spin_loop();
        }
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
