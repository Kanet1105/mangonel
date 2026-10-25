use std::{
    hint::spin_loop,
    ptr::{NonNull, null_mut},
    sync::PoisonError,
};

use libc::{MSG_DONTWAIT, POLLIN, SOL_XDP, getsockopt, poll, pollfd, sendto};
use mangonel_libxdp_sys::{
    XDP_OPTIONS, XDP_OPTIONS_ZEROCOPY, xdp_options, xsk_socket, xsk_socket__delete, xsk_socket__fd,
};

use crate::{
    descriptor::XdpDescriptor,
    ring::{Consumer, Producer},
    umem::Umem,
    xdp::{BIND, XdpConfig},
};

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
/// frame pool. Its `&mut self` methods give each ring a
/// single driver. Made by [`crate::bind`]; deleted on drop
/// with every ring alive: libxdp dereferences all four
/// while deleting.
pub struct XdpSocket {
    socket: NonNull<xsk_socket>,
    rx_ring: Consumer,
    tx_ring: Producer,
    fill_ring: Producer,
    completion_ring: Consumer,
}

// SAFETY: The socket pointer and rings have no thread
// affinity, so the socket may move between threads. It is
// deliberately not `Sync`: its private `&self` methods
// drive the rings unsynchronized.
unsafe impl Send for XdpSocket {}

impl Drop for XdpSocket {
    fn drop(&mut self) {
        let _bind = BIND.lock().unwrap_or_else(PoisonError::into_inner);
        // Runs before the fields drop, so the delete sees
        // every ring alive.
        unsafe { xsk_socket__delete(self.socket.as_ptr()) }
    }
}

impl XdpSocket {
    /// Wraps a bound socket and its rings.
    pub(crate) fn new(
        socket: NonNull<xsk_socket>,
        rx_ring: Consumer,
        tx_ring: Producer,
        fill_ring: Producer,
        completion_ring: Consumer,
    ) -> Self {
        Self {
            socket,
            rx_ring,
            tx_ring,
            fill_ring,
            completion_ring,
        }
    }

    /// Zero-copy is asked of the kernel each call; a failed
    /// getsockopt counts as no.
    pub fn config(&self) -> SocketConfig {
        let umem = Umem::global();
        let config = umem.config();

        // Each pair is created at one depth.
        debug_assert_eq!(self.rx_ring.size(), self.fill_ring.size());
        debug_assert_eq!(self.tx_ring.size(), self.completion_ring.size());

        SocketConfig {
            xdp: XdpConfig {
                receive_depth: self.rx_ring.size(),
                send_depth: self.tx_ring.size(),
                frame_size: config.frame_size,
                frame_headroom: config.frame_headroom,
                frame_count: umem.frame_count(),
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

    /// Tops the fill ring up from the umem's pool.
    fn fill(&self) {
        // Ask for at most the ring's free space: an
        // all-or-nothing claim of the whole ring would
        // starve RX in bursts.
        let free = self.fill_ring.free(self.fill_ring.size());
        if free == 0 {
            return;
        }

        let pool = Umem::global().pool();
        let Ok(mut grant) = pool.bulk_read(free as usize) else {
            return;
        };
        let granted = u32::try_from(grant.size())
            .expect("A grant exceeded the u32 it was asked for. This is a bug.");

        // The kernel only consumes fill entries, so the
        // free space checked above cannot shrink.
        let (claimed, index) = self.fill_ring.claim(granted);
        assert!(
            claimed == granted,
            "Fill ring free space shrank below a granted burst. This is a bug."
        );
        for offset in 0..claimed {
            let address = grant
                .read()
                .expect("The frame pool has a gap: every writer fills its grant. This is a bug.");
            self.fill_ring
                .write_fill_address(index.wrapping_add(offset), address);
        }
        // Freed before the kernel sees the frames, so none
        // can come back while their slots are still held.
        drop(grant);
        self.fill_ring.commit(claimed);
    }

    /// Fills the front of `buffer` with one minted
    /// descriptor per received frame; returns the count.
    /// Overwriting a slot whose frame was not sent leaks
    /// it — consume slots first. Also returns this
    /// socket's sent frames to the pool.
    #[must_use = "the count says how many descriptors were filled with received frames"]
    pub fn receive(&mut self, buffer: &mut [XdpDescriptor]) -> u32 {
        // Before fill, so frames just sent can be refilled.
        self.complete();
        self.fill();
        self.poll();

        // Frames are power-of-two sized.
        let frame_mask = u64::from(Umem::global().config().frame_size - 1);

        let want = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        let (claimed, index) = self.rx_ring.claim(want);
        for offset in 0..claimed {
            let descriptor = self.rx_ring.read_descriptor(index.wrapping_add(offset));

            // The one kernel input the slice accessors
            // trust: a packet crossing its
            // frame boundary would alias
            // other descriptors' frames.
            assert!(
                (descriptor.addr & frame_mask) + u64::from(descriptor.len) <= frame_mask + 1,
                "The kernel returned an rx descriptor crossing its frame boundary. This is a bug."
            );

            buffer[offset as usize] = XdpDescriptor::new(descriptor.addr, descriptor.len);
        }
        self.rx_ring.commit(claimed);

        claimed
    }

    /// Queues the front of `buffer` for transmit; returns
    /// how many were queued — retry with the rest. Sent
    /// frames return to the pool in [`Self::receive`], so
    /// keep receiving on this socket.
    #[must_use = "fewer descriptors than passed may have been consumed; the count says how many"]
    pub fn send(&mut self, buffer: &mut [XdpDescriptor]) -> u32 {
        let want = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // Clamp to the ring's free space: an unclamped
        // all-or-nothing claim makes no progress until the
        // ring can seat the whole batch.
        let free = self.tx_ring.free(want).min(want);
        let (claimed, tx_index) = self.tx_ring.claim(free);
        for offset in 0..claimed {
            let descriptor = &buffer[offset as usize];
            self.tx_ring.write_descriptor(
                tx_index.wrapping_add(offset),
                descriptor.address(),
                descriptor.length(),
            );
        }
        self.tx_ring.commit(claimed);
        self.kick();

        claimed
    }

    /// Returns `buffer`'s frames to the umem's pool instead
    /// of sending them.
    pub fn drop(&mut self, buffer: &[XdpDescriptor]) {
        let pool = Umem::global().pool();
        let mut offset = 0;
        while offset < buffer.len() {
            // As in `complete`: a failed or short claim only
            // waits on a reader yet to commit.
            let Ok(mut grant) = pool.bulk_write(buffer.len() - offset) else {
                spin_loop();
                continue;
            };

            for _ in 0..grant.size() {
                grant
                    .write(buffer[offset].address())
                    .expect("Wrote past the grant. This is a bug.");
                offset += 1;
            }
        }
    }

    /// Returns every completed tx frame to the umem's pool.
    fn complete(&self) {
        let (claimed, index) = self.completion_ring.claim(self.completion_ring.size());
        if claimed == 0 {
            return;
        }

        let pool = Umem::global().pool();
        let mut offset: u32 = 0;
        while offset < claimed {
            // Each frame out of the pool has a free slot, so
            // a failed or short claim only waits on a reader
            // yet to commit.
            let Ok(mut grant) = pool.bulk_write((claimed - offset) as usize) else {
                spin_loop();
                continue;
            };

            for _ in 0..grant.size() {
                grant
                    .write(
                        self.completion_ring
                            .read_completion_address(index.wrapping_add(offset)),
                    )
                    .expect("Wrote past the grant. This is a bug.");
                offset += 1;
            }
        }
        self.completion_ring.commit(claimed);
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
