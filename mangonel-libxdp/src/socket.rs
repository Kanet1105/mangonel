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
    ring::{Consumer, Producer},
    umem::Umem,
    xdp::XdpConfig,
};

/// One bound AF_XDP queue, driven from one thread through
/// both directions. `Send` but not `Sync`; [`Self::split`]
/// it into an [`XdpSender`] and an [`XdpReceiver`] to drive
/// the directions from different threads. Made by
/// [`crate::bind`] or [`crate::bind_shared`].
pub struct XdpSocket {
    socket: Socket,
}

impl XdpSocket {
    /// Wraps a bound socket and its rings. `umem` is what
    /// the socket's frames live in; held so it cannot be
    /// freed first.
    pub(crate) fn new(
        socket: NonNull<xsk_socket>,
        rx_ring: Consumer,
        tx_ring: Producer,
        fill_ring: Producer,
        completion_ring: Consumer,
        umem: Umem,
    ) -> Self {
        Self {
            socket: Socket {
                socket,
                rx_ring,
                tx_ring,
                fill_ring,
                completion_ring,
                umem,
            },
        }
    }

    /// Splits into the transmit and receive halves, which
    /// may run on different threads. The socket stays bound
    /// until both halves drop.
    // Shared only between the halves, whose `Send` impls
    // carry the justification `Sync` would otherwise give.
    #[expect(clippy::arc_with_non_send_sync)]
    pub fn split(self) -> (XdpSender, XdpReceiver) {
        let socket = Arc::new(self.socket);

        (
            XdpSender {
                socket: socket.clone(),
            },
            XdpReceiver { socket },
        )
    }

    /// As [`XdpSender::send`].
    #[must_use = "fewer descriptors than passed may have been consumed; the count says how many"]
    pub fn send(&mut self, buffer: &mut [XdpDescriptor]) -> u32 {
        self.socket.send(buffer)
    }

    /// As [`XdpReceiver::receive`].
    #[must_use = "the count says how many descriptors were filled with received frames"]
    pub fn receive(&mut self, buffer: &mut [XdpDescriptor]) -> u32 {
        self.socket.receive(buffer)
    }

    pub fn config(&self) -> SocketConfig {
        self.socket.config()
    }

    pub(crate) fn umem(&self) -> &Umem {
        &self.socket.umem
    }
}

/// The transmit half of one bound AF_XDP queue: drives
/// its tx and completion rings. Not `Clone`, so those
/// rings have one driver. Made by [`XdpSocket::split`].
pub struct XdpSender {
    socket: Arc<Socket>,
}

// SAFETY: `Socket` is `Send`; sharing it with the receiver
// is sound because this half only drives the tx and
// completion rings, via `&mut self` on a non-`Clone` type,
// while the receiver only drives rx and fill. Everything
// else reached through the shared socket is its fd, whose
// syscalls are thread-safe, and the umem, which
// synchronizes itself.
unsafe impl Send for XdpSender {}

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

    pub fn config(&self) -> SocketConfig {
        self.socket.config()
    }
}

/// The receive half of one bound AF_XDP queue: drives
/// its rx and fill rings. Not `Clone`, so those rings
/// have one driver. Made by [`XdpSocket::split`].
pub struct XdpReceiver {
    socket: Arc<Socket>,
}

// SAFETY: As for `XdpSender`, with this half driving only
// the rx and fill rings.
unsafe impl Send for XdpReceiver {}

impl XdpReceiver {
    /// Fills the front of `buffer` with one minted
    /// descriptor per received frame; returns the count.
    /// Overwriting a slot that still holds a live
    /// descriptor leaks its frame — consume slots first.
    #[must_use = "the count says how many descriptors were filled with received frames"]
    pub fn receive(&mut self, buffer: &mut [XdpDescriptor]) -> u32 {
        self.socket.receive(buffer)
    }

    pub fn config(&self) -> SocketConfig {
        self.socket.config()
    }
}

/// What a bound socket was given: the depths and umem
/// layout it runs with, and the bind mode the kernel
/// granted. Fixed for the socket's lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketConfig {
    pub xdp: XdpConfig,
    /// Whether the driver bound zero-copy rather than
    /// falling back to copy mode.
    pub zero_copy: bool,
}

/// One bound AF_XDP queue: receive and transmit over its
/// four rings, recycling frames through the umem's shared
/// [`FramePool`](crate::pool::FramePool). Private: it is
/// only ever driven through [`XdpSocket`] or the
/// [`XdpSender`] and [`XdpReceiver`] halves that share it,
/// whose `&mut self` methods are what give each ring a
/// single driver. Deleted when its last owner drops, with
/// every ring alive: libxdp dereferences all four while
/// deleting.
struct Socket {
    socket: NonNull<xsk_socket>,
    rx_ring: Consumer,
    tx_ring: Producer,
    fill_ring: Producer,
    completion_ring: Consumer,
    /// Held so the umem cannot be freed first.
    umem: Umem,
}

// SAFETY: The socket pointer and rings have no thread
// affinity, so the socket may move between threads. It is
// deliberately not `Sync`: its `&self` methods drive the
// rings unsynchronized, so only the halves, which each
// drive disjoint rings, may share it across threads.
unsafe impl Send for Socket {}

impl Drop for Socket {
    fn drop(&mut self) {
        // Runs before the fields drop, so the delete sees
        // every ring alive and precedes the
        // xsk_umem__delete.
        unsafe { xsk_socket__delete(self.socket.as_ptr()) }
    }
}

impl Socket {
    /// Zero-copy is asked of the kernel each call; a failed
    /// getsockopt counts as no.
    fn config(&self) -> SocketConfig {
        let umem = self.umem.shared().config();

        // Each pair is created at one depth.
        debug_assert_eq!(self.rx_ring.size(), self.fill_ring.size());
        debug_assert_eq!(self.tx_ring.size(), self.completion_ring.size());

        SocketConfig {
            xdp: XdpConfig {
                receive_depth: self.rx_ring.size(),
                send_depth: self.tx_ring.size(),
                frame_size: umem.frame_size,
                frame_headroom: umem.frame_headroom,
                frame_count: self.umem.shared().frame_count(),
            },
            zero_copy: self.zero_copy(),
        }
    }

    fn zero_copy(&self) -> bool {
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
    /// the halves share this socket; the caller's
    /// `&mut self` is the exclusivity.
    fn receive(&self, buffer: &mut [XdpDescriptor]) -> u32 {
        let size = u32::try_from(buffer.len())
            .unwrap_or(u32::MAX)
            .min(self.rx_ring.size());
        self.fill();
        self.poll();
        let (available, index) = self.rx_ring.claim(size);
        let shared = self.umem.shared();
        // Frames are power-of-two sized.
        let frame_mask = u64::from(shared.config().frame_size - 1);
        // Count the whole batch at once rather than each
        // descriptor; see `UmemShared`.
        if available > 0 {
            shared.lend(available);
        }
        let mut offset: u32 = 0;
        while offset < available {
            let descriptor = self.rx_ring.read_descriptor(index.wrapping_add(offset));
            // The one kernel input the slice accessors
            // trust: a packet crossing its
            // frame boundary would alias
            // other descriptors' frames.
            assert!(
                (descriptor.addr & frame_mask) + u64::from(descriptor.len) <= frame_mask + 1,
                "The kernel returned an rx descriptor crossing its frame boundary. This is a bug."
            );
            buffer[offset as usize] = XdpDescriptor {
                address: descriptor.addr,
                length: descriptor.len,
                umem: Some(NonNull::from(shared)),
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
        // Validate before claiming: a caught panic after
        // the claim would desync the producer index
        // for good.
        // Identity by address is sound: a umem's shared
        // half is freed only once no descriptor
        // points at it, so its address cannot be
        // reused under a live one.
        let shared = self.umem.shared();
        let own = NonNull::from(shared);
        let mut transmit_count: u32 = 0;
        for descriptor in &buffer[..size as usize] {
            if let Some(umem) = descriptor.umem {
                assert!(
                    umem == own,
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
                // Ownership of the frame moved to the tx
                // ring.
                descriptor.defuse();
            }
            consumed += 1;
        }
        self.tx_ring.commit(written);
        if written > 0 {
            shared.reclaim(written);
        }
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
        let pool = self.umem.shared().pool();
        let Some((count, pool_index)) = pool.claim_read(want) else {
            return;
        };

        // The kernel only consumes fill entries, so the
        // free space checked above cannot shrink.
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

        let pool = self.umem.shared().pool();
        let pool_index = pool.claim_write_all(filled);
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
