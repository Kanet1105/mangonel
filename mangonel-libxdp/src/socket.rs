use std::{
    ptr::{NonNull, null_mut},
    sync::Arc,
};

use libc::{MSG_DONTWAIT, POLLIN, SOL_XDP, getsockopt, poll, pollfd, sendto};
use mangonel_libxdp_sys::{
    XDP_OPTIONS, XDP_OPTIONS_ZEROCOPY, xdp_options, xsk_socket, xsk_socket__delete, xsk_socket__fd,
};

use crate::{
    descriptor::XdpDescriptor,
    pool::FramePool,
    ring::{Consumer, Producer},
    umem::Umem,
};

/// Wraps a bound socket and its rings into the two halves
/// that drive it. `umem` is what the socket's frames live
/// in; held so it cannot be freed first.
pub(crate) fn split(
    socket: NonNull<xsk_socket>,
    rx_ring: Consumer,
    tx_ring: Producer,
    fill_ring: Producer,
    completion_ring: Consumer,
    umem: Umem,
) -> (XdpSender, XdpReceiver) {
    let socket = Arc::new(XdpSocket {
        socket,
        rx_ring,
        tx_ring,
        fill_ring,
        completion_ring,
        umem,
    });

    (
        XdpSender {
            socket: socket.clone(),
        },
        XdpReceiver { socket },
    )
}

pub struct SocketHalf<'a> {
    socket: &'a Arc<XdpSocket>,
}

impl<'a> From<&'a XdpSender> for SocketHalf<'a> {
    fn from(value: &'a XdpSender) -> Self {
        Self {
            socket: &value.socket,
        }
    }
}

impl<'a> From<&'a XdpReceiver> for SocketHalf<'a> {
    fn from(value: &'a XdpReceiver) -> Self {
        Self {
            socket: &value.socket,
        }
    }
}

impl<'a> SocketHalf<'a> {
    pub(crate) fn umem(&self) -> &Umem {
        &self.socket.umem
    }

    pub fn is_zero_copy(&self) -> bool {
        self.socket.is_zero_copy()
    }
}

/// The transmit half of one bound AF_XDP queue: drives
/// its tx and completion rings. Not `Clone`, so those
/// rings have one driver. Made by [`crate::bind`] or
/// [`crate::bind_shared`]; the socket stays bound until
/// both halves drop.
pub struct XdpSender {
    socket: Arc<XdpSocket>,
}

impl XdpSender {
    /// Consumes the front of `buffer`, queueing live
    /// descriptors for transmit and passing empty slots
    /// through; returns the consumed count — retry with
    /// the unconsumed tail. Panics on a descriptor from a
    /// different umem.
    #[must_use = "fewer descriptors than passed may have been consumed; the count says how many"]
    pub fn send(&mut self, buffer: &mut [XdpDescriptor]) -> u32 {
        self.socket.send(buffer)
    }
}

/// The receive half of one bound AF_XDP queue: drives
/// its rx and fill rings. Not `Clone`, so those rings
/// have one driver. Made alongside [`XdpSender`].
pub struct XdpReceiver {
    socket: Arc<XdpSocket>,
}

impl XdpReceiver {
    /// Fills the front of `buffer` with one minted
    /// descriptor per received frame; returns the count.
    /// Overwriting a slot that still holds a live
    /// descriptor leaks its frame — consume slots first.
    #[must_use = "the count says how many descriptors were filled with received frames"]
    pub fn receive(&mut self, buffer: &mut [XdpDescriptor]) -> u32 {
        self.socket.receive(buffer)
    }
}

/// One bound AF_XDP queue: receive and transmit over its
/// four rings, recycling frames through the umem's shared
/// [`FramePool`]. Private: it is only ever driven through
/// the [`XdpSender`] and [`XdpReceiver`] halves that share
/// it, whose `&mut self` methods are what give each ring a
/// single driver. Deleted when the last half drops, with
/// every ring alive: libxdp dereferences all four while
/// deleting.
struct XdpSocket {
    socket: NonNull<xsk_socket>,
    rx_ring: Consumer,
    tx_ring: Producer,
    fill_ring: Producer,
    completion_ring: Consumer,
    /// Held so the umem cannot be freed first.
    umem: Umem,
}

// SAFETY: The socket pointer and rings have no thread
// affinity; the socket is only read for its fd, whose
// syscalls are thread-safe. The rings are driven only
// through the halves: rx and fill by `XdpReceiver`, tx and
// completion by `XdpSender`, each via `&mut self` on a
// non-`Clone` type, so no ring is touched from two threads
// at once even when the halves live on different ones. The
// type is private, so no other `&XdpSocket` exists. The
// umem synchronizes itself.
unsafe impl Send for XdpSocket {}
unsafe impl Sync for XdpSocket {}

impl Drop for XdpSocket {
    fn drop(&mut self) {
        // Runs before the fields drop, so the delete sees
        // every ring alive and precedes the xsk_umem__delete.
        unsafe { xsk_socket__delete(self.socket.as_ptr()) }
    }
}

impl XdpSocket {
    /// Whether the kernel bound this socket zero-copy. A
    /// failed getsockopt counts as no.
    fn is_zero_copy(&self) -> bool {
        let mut options = xdp_options { flags: 0 };
        let mut length = libc::socklen_t::try_from(size_of::<xdp_options>())
            .expect("xdp_options size overflows socklen_t. This is a bug.");
        let value = unsafe {
            getsockopt(
                self.socket_fd(),
                SOL_XDP,
                XDP_OPTIONS.cast_signed(),
                (&raw mut options).cast(),
                &raw mut length,
            )
        };

        value == 0 && options.flags & XDP_OPTIONS_ZEROCOPY != 0
    }

    /// Backs [`XdpReceiver::receive`]. `&self` only because
    /// the halves share this socket; the receiver's
    /// `&mut self` is the exclusivity.
    fn receive(&self, buffer: &mut [XdpDescriptor]) -> u32 {
        let size = u32::try_from(buffer.len())
            .unwrap_or(u32::MAX)
            .min(self.rx_ring.size());
        self.fill();
        self.poll();
        let (available, index) = self.rx_ring.claim(size);
        // Frames are power-of-two sized.
        let frame_mask = u64::from(self.umem.config().frame_size - 1);
        let mut offset: u32 = 0;
        while offset < available {
            let descriptor = self.rx_ring.read_descriptor(index.wrapping_add(offset));
            // The one kernel input the slice accessors trust:
            // a packet crossing its frame boundary would alias
            // other descriptors' frames.
            assert!(
                (descriptor.addr & frame_mask) + u64::from(descriptor.len) <= frame_mask + 1,
                "The kernel returned an rx descriptor crossing its frame boundary. This is a bug."
            );
            buffer[offset as usize] = XdpDescriptor {
                address: descriptor.addr,
                length: descriptor.len,
                umem: Some(self.umem.clone()),
            };
            offset += 1;
        }
        self.rx_ring.commit(offset);

        offset
    }

    /// Backs [`XdpSender::send`]; `&self` as
    /// [`Self::receive`].
    fn send(&self, buffer: &mut [XdpDescriptor]) -> u32 {
        let size = u32::try_from(buffer.len())
            .unwrap_or(u32::MAX)
            .min(self.tx_ring.size());
        // Validate before claiming: a caught panic after the
        // claim would desync the producer index for good.
        let umem_id = self.umem.id();
        let mut transmit_count: u32 = 0;
        for descriptor in &buffer[..size as usize] {
            if let Some(umem) = &descriptor.umem {
                assert!(
                    umem.id() == umem_id,
                    "Sent a XdpDescriptor that was minted against a different umem: its \
                     address indexes the wrong memory."
                );
                transmit_count += 1;
            }
        }
        // Clamp to the ring's free space: an unclamped
        // all-or-nothing claim makes no progress until the
        // ring can seat the whole batch.
        let request = transmit_count.min(self.tx_ring.free(transmit_count));
        let (tx_available, tx_index) = self.tx_ring.claim(request);
        // Stop at the first live descriptor without a tx
        // slot, keeping the consumed front contiguous.
        let mut written: u32 = 0;
        let mut consumed: u32 = 0;
        for descriptor in &mut buffer[..size as usize] {
            if descriptor.umem.is_some() {
                if written == tx_available {
                    break;
                }
                self.tx_ring.write_descriptor(
                    tx_index.wrapping_add(written),
                    descriptor.address,
                    descriptor.length,
                );
                written += 1;
                // Ownership of the frame moved to the tx ring.
                descriptor.defuse();
            }
            consumed += 1;
        }
        self.tx_ring.commit(written);
        self.kick();
        // Nothing else returns tx frames to the pool.
        self.complete();

        consumed
    }

    /// Tops the fill ring up from the umem's pool.
    fn fill(&self) {
        // Clamp to the ring's free space: an unclamped
        // all-or-nothing claim would starve RX in bursts.
        let ring_size = self.fill_ring.size();
        let want = ring_size.min(self.fill_ring.free(ring_size));
        let pool = self.umem.pool();
        let Some((count, pool_index)) = pool.claim_read(want) else {
            return;
        };

        // The kernel only consumes fill entries, so the free
        // space checked above cannot shrink.
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
    fn complete(&self) {
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

    /// Claims pool slots for frames leaving the datapath.
    /// Room always exists — an in-flight frame holds no
    /// pool slot — so the spin only covers another
    /// worker's open grant.
    fn pool_claim_write(pool: &FramePool, size: u32) -> u32 {
        loop {
            if let Some((available, index)) = pool.claim_write(size) {
                // A capped grant committed at the requested size
                // would corrupt the pool.
                assert!(
                    available == size,
                    "The pool capacity is smaller than a burst. This is a bug."
                );

                return index;
            }
            std::hint::spin_loop();
        }
    }

    /// Wakes the driver; non-blocking, carries no data.
    fn kick(&self) {
        unsafe { sendto(self.socket_fd(), null_mut(), 0, MSG_DONTWAIT, null_mut(), 0) };
    }

    fn poll(&self) {
        let mut poll_fd_struct = pollfd {
            fd: self.socket_fd(),
            events: POLLIN,
            revents: 0,
        };
        unsafe { poll(&mut poll_fd_struct, 1, 0) };
    }

    fn socket_fd(&self) -> i32 {
        unsafe { xsk_socket__fd(self.socket.as_ptr()) }
    }
}
