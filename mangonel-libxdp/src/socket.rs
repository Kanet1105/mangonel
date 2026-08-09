use std::{
    ptr::{NonNull, null_mut},
    sync::Arc,
};

use libc::{MSG_DONTWAIT, POLLIN, poll, pollfd, sendto};
use mangonel_libxdp_sys::{xsk_socket, xsk_socket__delete, xsk_socket__fd};
use rtrb::{Consumer as DescConsumer, Producer as DescProducer};

use crate::{
    descriptor::XdpDescriptor,
    ring::{Consumer, Producer},
    umem::Umem,
};

pub struct XdpSender {
    socket: Socket,
    desc_producer: DescProducer<u64>,
}

impl XdpSender {
    pub(crate) fn new(socket: Socket, desc_producer: DescProducer<u64>) -> Self {
        Self {
            socket,
            desc_producer,
        }
    }

    /// Consumes the minted descriptors at the front of
    /// `buffer`: drop-marked ones return to the pool, the
    /// rest queue for transmit. Returns how many were
    /// consumed; retry with the unconsumed tail — resending
    /// the whole buffer panics on the consumed front.
    ///
    /// # Panics
    ///
    /// Panics when a descriptor in the batch is empty or
    /// from a different umem. Validated before the ring is
    /// touched, so the ring is never left half-reserved.
    #[must_use = "fewer descriptors than passed may have been consumed; the count says how many"]
    pub fn send(&mut self, buffer: &mut [XdpDescriptor]) -> u32 {
        let size = u32::try_from(buffer.len())
            .unwrap_or(u32::MAX)
            .min(self.socket.tx_ring().size());
        // Validate before reserving: a caught panic after reserve
        // would desync the producer index for good.
        let umem_id = self.socket.umem().id();
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
        let tx_ring = self.socket.tx_ring();
        // Clamped to the ring's free space for the same reason as
        // in fill: an unclamped all-or-nothing reserve makes
        // no progress at all until the ring can seat the
        // whole batch.
        let request = transmit_count.min(tx_ring.free(transmit_count));
        let (tx_available, tx_index) = tx_ring.reserve(request);
        // Consumption stops at the first transmit without a slot,
        // keeping the consumed front contiguous for
        // retry-with-tail.
        let mut written: u32 = 0;
        let mut consumed: u32 = 0;
        for descriptor in &mut buffer[..size as usize] {
            if descriptor.is_drop {
                self.desc_producer
                    .push(descriptor.address)
                    .expect("XdpDescriptor queue is full. This is a bug.");
            } else {
                if written == tx_available {
                    break;
                }
                tx_ring.set_descriptor(tx_index + written, descriptor.address, descriptor.length);
                written += 1;
            }
            // An empty descriptor is the proof this handle can no
            // longer reach the frame.
            *descriptor = XdpDescriptor::default();
            consumed += 1;
        }
        tx_ring.submit(written);
        self.kick();
        // Drain every completion available, not just this batch's
        // worth; nothing else returns frames to the pool.
        self.complete();

        consumed
    }

    /// Wakes the driver; non-blocking and carries no data.
    fn kick(&mut self) {
        unsafe {
            sendto(
                self.socket.socket_fd(),
                null_mut(),
                0,
                MSG_DONTWAIT,
                null_mut(),
                0,
            )
        };
    }

    fn complete(&mut self) {
        let size = u32::try_from(self.desc_producer.slots())
            .expect("XdpDescriptor producer slots overflow u32. This is a bug.");
        let completion_ring = self.socket.completion_ring();
        let (filled, index) = completion_ring.peek(size);
        let mut offset: u32 = 0;
        while offset < filled {
            let address = completion_ring.completion_address(index + offset);
            self.desc_producer
                .push(address)
                .expect("XdpDescriptor queue is full. This is a bug.");
            offset += 1;
        }
        completion_ring.release(offset);
    }
}

pub struct XdpReceiver {
    socket: Socket,
    /// Recycled frames: tx completions and drops, the
    /// pool's only entry points.
    desc_consumer: DescConsumer<u64>,
}

impl XdpReceiver {
    pub(crate) fn new(socket: Socket, desc_consumer: DescConsumer<u64>) -> Self {
        Self {
            socket,
            desc_consumer,
        }
    }

    /// Fills the front of `buffer` with one minted
    /// descriptor per received frame, overwriting the
    /// slots; returns the count. Overwriting a slot still
    /// holding a minted descriptor leaks its frame.
    #[must_use = "the count says how many descriptors were filled with received frames"]
    pub fn receive(&mut self, buffer: &mut [XdpDescriptor]) -> u32 {
        let size = u32::try_from(buffer.len())
            .unwrap_or(u32::MAX)
            .min(self.socket.rx_ring().size());
        self.fill();
        self.poll();
        let umem_id = self.socket.umem().id();
        let rx_ring = self.socket.rx_ring();
        let (available, index) = rx_ring.peek(size);
        let mut offset: u32 = 0;
        while offset < available {
            let descriptor = rx_ring.descriptor(index + offset);
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
        rx_ring.release(offset);

        offset
    }

    fn fill(&mut self) {
        let fill_ring = self.socket.fill_ring();
        let size = u32::try_from(self.desc_consumer.slots())
            .expect("XdpDescriptor consumer slots overflow u32. This is a bug.")
            .min(fill_ring.size());
        // Clamp to the ring's free space: reserve is
        // all-or-nothing, so an unclamped request sized to
        // the full ring succeeds only once the kernel has
        // drained it completely, starving RX in bursts meanwhile.
        // The kernel only consumes fill entries, so the
        // space cannot shrink between these two calls.
        let size = size.min(fill_ring.free(size));
        let (available, index) = fill_ring.reserve(size);
        let mut offset: u32 = 0;
        while offset < available {
            let address = match self.desc_consumer.pop() {
                Ok(address) => address,
                Err(_) => panic!(
                    "Fill ring has more available slots than the descriptor consumer. This is a bug."
                ),
            };
            fill_ring.set_fill_address(index + offset, address);
            offset += 1;
        }
        fill_ring.submit(offset);
    }

    fn poll(&mut self) {
        let mut poll_fd_struct = pollfd {
            fd: self.socket.socket_fd(),
            events: POLLIN,
            revents: 0,
        };
        unsafe { poll(&mut poll_fd_struct, 1, 0) };
    }
}

pub struct Socket {
    inner: Arc<SocketInner>,
}

impl Clone for Socket {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Socket {
    pub(crate) fn new(
        socket: NonNull<xsk_socket>,
        tx_ring: Producer,
        rx_ring: Consumer,
        fill_ring: Producer,
        completion_ring: Consumer,
        umem: Umem,
    ) -> Self {
        Self {
            inner: SocketInner {
                socket,
                tx_ring,
                rx_ring,
                fill_ring,
                completion_ring,
                umem,
            }
            .into(),
        }
    }

    pub(crate) fn socket_fd(&self) -> i32 {
        unsafe { xsk_socket__fd(self.inner.socket.as_ptr()) }
    }

    fn umem(&self) -> &Umem {
        &self.inner.umem
    }

    /// For the exclusive use of `XdpSender`; bind hands it
    /// to exactly one half. See the `Sync` impl on
    /// [`SocketInner`].
    fn tx_ring(&self) -> &Producer {
        &self.inner.tx_ring
    }

    /// For `XdpReceiver` only; as [`Self::tx_ring`].
    fn rx_ring(&self) -> &Consumer {
        &self.inner.rx_ring
    }

    /// For `XdpReceiver` only; as [`Self::tx_ring`].
    fn fill_ring(&self) -> &Producer {
        &self.inner.fill_ring
    }

    /// For `XdpSender` only; as [`Self::tx_ring`].
    fn completion_ring(&self) -> &Consumer {
        &self.inner.completion_ring
    }
}

/// Owns the socket's four rings: `Drop` runs
/// `xsk_socket__delete`, which reads them to unmap ring
/// memory, before any field drops.
struct SocketInner {
    socket: NonNull<xsk_socket>,
    tx_ring: Producer,
    rx_ring: Consumer,
    fill_ring: Producer,
    completion_ring: Consumer,
    /// Held so the umem cannot be freed first.
    umem: Umem,
}

// SAFETY: Reached via the fd (read-only), the Umem (Sync),
// and Drop after all refs are gone. The rings are mutable
// state; soundness rests on each being reached by exactly
// one half — tx and completion by XdpSender, rx and fill by
// XdpReceiver — which bind establishes by construction.
unsafe impl Send for SocketInner {}
unsafe impl Sync for SocketInner {}

impl Drop for SocketInner {
    fn drop(&mut self) {
        // Runs before the `umem` field drops, so socket delete
        // always precedes umem delete (which fails -EBUSY
        // while a socket is bound).
        unsafe { xsk_socket__delete(self.socket.as_ptr()) }
    }
}
