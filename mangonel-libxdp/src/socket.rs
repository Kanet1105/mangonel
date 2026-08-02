use std::{
    ffi::{CString, NulError},
    ptr::{NonNull, null_mut},
    sync::Arc,
};

use libc::{MSG_DONTWAIT, POLLIN, poll, pollfd, sendto};
use mangonel_libxdp_sys::{
    XDP_COPY, XDP_ZEROCOPY, XSK_RING_PROD__DEFAULT_NUM_DESCS, XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    XSK_UMEM__DEFAULT_FRAME_SIZE, xsk_socket, xsk_socket__create, xsk_socket__delete,
    xsk_socket__fd, xsk_socket_config, xsk_socket_config__bindgen_ty_1,
};
use rtrb::{Consumer as DescConsumer, Producer as DescProducer, RingBuffer};

use crate::{
    descriptor::XdpDescriptor,
    error::XdpError,
    ring::{Consumer, Producer, ring_buffer},
    umem::Umem,
    util,
};

/// Size of a single umem frame, and the chunk stride the
/// kernel divides the umem region into. Must be a power of
/// two between 2048 and the page size.
const FRAME_SIZE: u32 = XSK_UMEM__DEFAULT_FRAME_SIZE;

/// Headroom reserved inside each frame, ahead of the packet
/// data.
const FRAME_HEADROOM_SIZE: u32 = XSK_UMEM__DEFAULT_FRAME_HEADROOM;

/// Number of descriptors in each ring. Must be a power of
/// two.
const RING_SIZE: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS;

/// Opens an AF_XDP socket on `interface_name` / `queue_id`
/// and splits it into its two halves, which are `Send` and
/// may be driven from separate threads.
///
/// The returned [`Umem`] owns the memory backing the
/// frames, along with the fill and completion rings; it
/// must outlive both halves, so hold it for as
/// long as either is in use.
///
/// # Panics
///
/// Panics when libxdp reports success but leaves one of the
/// four rings unpopulated or hands back a null socket —
/// broken contracts rather than recoverable failures.
pub fn create_xdp_socket(
    interface_name: impl AsRef<str>,
    queue_id: u32,
    use_hugetlb: bool,
    force_zero_copy: bool,
) -> Result<(XdpSender, XdpReceiver, Umem), XdpError> {
    // Increase the maximum size of the process's virtual
    // memory.
    util::setrlimit().map_err(SocketError::Setrlimit)?;

    // Initialize the UMEM, which maps the memory backing the
    // frames and owns the fill and completion rings, so
    // they cannot be dropped out from under
    // xsk_umem__delete however the caller drops its handles.
    let umem = Umem::new(FRAME_SIZE, FRAME_HEADROOM_SIZE, RING_SIZE, use_hugetlb)?;

    // Initialize XDP socket.
    let mut socket = null_mut();

    let interface_name =
        CString::new(interface_name.as_ref()).map_err(SocketError::InvalidInterfaceName)?;

    let mut xdp_flags = 0;
    match force_zero_copy {
        true => xdp_flags |= XDP_ZEROCOPY,
        false => xdp_flags |= XDP_COPY,
    }

    let socket_config = xsk_socket_config {
        rx_size: RING_SIZE,
        tx_size: RING_SIZE,
        __bindgen_anon_1: xsk_socket_config__bindgen_ty_1 { libbpf_flags: 0 },
        xdp_flags,
        bind_flags: 0,
    };

    let (tx_ring, rx_ring) = ring_buffer(RING_SIZE)?;

    let value = unsafe {
        xsk_socket__create(
            &mut socket,
            interface_name.as_ptr(),
            queue_id,
            umem.as_ptr(),
            rx_ring.as_ptr(),
            tx_ring.as_ptr(),
            &socket_config,
        )
    };
    if value.is_negative() {
        return Err(SocketError::Initialize(std::io::Error::from_raw_os_error(-value)).into());
    }

    // Establish the invariant the ring accessors rely on, as in
    // Umem::new: both rings went into xsk_socket__create
    // zeroed and come back mapped.
    assert!(
        tx_ring.is_registered() && rx_ring.is_registered(),
        "xsk_socket__create left a ring unpopulated. This is a bug."
    );

    let socket = Socket {
        inner: SocketInner {
            socket: NonNull::new(socket)
                .expect("xsk_socket__create returned null pointer. This is a bug."),
            tx_ring,
            rx_ring,
            umem: umem.clone(),
        }
        .into(),
    };

    // Prefill the frame pool with every frame in the umem: the
    // region holds enough for all four rings to be full at
    // once, and the ring buffer is sized to that same pool
    // — the addresses in circulation are exactly the ones
    // created here, so a recycle can never find it full.
    let frame_count = umem.frame_count();
    let (mut desc_producer, desc_consumer) = RingBuffer::<u64>::new(frame_count as usize);
    (0..frame_count).for_each(|desc_index| {
        let address = u64::from(desc_index) * u64::from(FRAME_SIZE);
        desc_producer
            .push(address)
            .expect("Prefilled more addresses than the ring buffer holds. This is a bug.");
    });

    // From here on each ring is reached by exactly one half: tx
    // and completion only by XdpSender, rx and fill only by
    // XdpReceiver. That split is what makes the Sync impls
    // on SocketInner and Umem sound.
    let tx_socket = XdpSender {
        socket: socket.clone(),
        desc_producer,
    };
    let rx_socket = XdpReceiver {
        socket,
        desc_consumer,
    };
    Ok((tx_socket, rx_socket, umem))
}

struct Socket {
    inner: Arc<SocketInner>,
}

impl Clone for Socket {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Socket {
    #[inline]
    fn socket_fd(&self) -> i32 {
        unsafe { xsk_socket__fd(self.inner.socket.as_ptr()) }
    }

    #[inline]
    fn umem(&self) -> &Umem {
        &self.inner.umem
    }

    /// The tx ring, for the exclusive use of `XdpSender`.
    ///
    /// See the `Sync` impl on [`SocketInner`]: nothing in
    /// the type system stops a second thread from
    /// calling this, so `create_xdp_socket` is responsible
    /// for handing it to exactly one socket half.
    #[inline]
    fn tx_ring(&self) -> &Producer {
        &self.inner.tx_ring
    }

    /// The rx ring, for the exclusive use of `XdpReceiver`.
    /// Same contract as [`Self::tx_ring`].
    #[inline]
    fn rx_ring(&self) -> &Consumer {
        &self.inner.rx_ring
    }
}

/// Owns the rx/tx rings for the same reason `UmemInner`
/// owns the fill and completion rings: `Drop` runs
/// `xsk_socket__delete` before any field drops,
/// and that call reads `rx->ring` and `tx->ring` to unmap
/// the ring memory, so both structs must still be allocated
/// — whichever order the caller drops the two halves in.
struct SocketInner {
    socket: NonNull<xsk_socket>,
    tx_ring: Producer,
    rx_ring: Consumer,
    /// The umem this socket is bound to, held so it cannot
    /// be freed first.
    umem: Umem,
}

// SAFETY: SocketInner is reached via xsk_socket__fd
// (read-only), shared reads of the Umem (which is Sync for
// the reasons given on its own impl), and
// xsk_socket__delete in Drop, which runs only after all Arc
// refs are gone.
//
// The rx and tx rings carry mutable state and are not safe
// to touch from two threads at once. They live here only so
// they outlive that teardown call. As with the umem's fill
// and completion rings, soundness rests on each being
// reached by exactly one socket half — the tx ring by
// XdpSender, the rx ring by XdpReceiver — which
// create_xdp_socket establishes by construction, not by
// type.
unsafe impl Send for SocketInner {}
unsafe impl Sync for SocketInner {}

impl Drop for SocketInner {
    fn drop(&mut self) {
        // The `umem` field drops after this body returns, so
        // xsk_socket__delete always precedes
        // xsk_umem__delete. libxdp refuses the latter with
        // -EBUSY while a socket is still bound, and the first
        // socket bound to a umem shares its file
        // descriptor.
        unsafe { xsk_socket__delete(self.socket.as_ptr()) }
    }
}

pub struct XdpSender {
    socket: Socket,
    desc_producer: DescProducer<u64>,
}

impl XdpSender {
    /// Consumes the minted descriptors at the front of
    /// `buffer`: ones marked
    /// with [`XdpDescriptor::set_drop`] are recycled
    /// straight back to the frame pool, the rest are
    /// queued for transmit.
    ///
    /// Returns how many were consumed — fewer than
    /// `buffer.len()` when the tx ring is short on
    /// space. Retry with the unconsumed tail
    /// (`&mut buffer[n..]`); resending the whole buffer
    /// panics on the already-consumed front.
    ///
    /// # Panics
    ///
    /// Panics when any descriptor in the attempted batch —
    /// the first `min(buffer.len(), ring size)` entries
    /// — is empty or from a different socket. Validated
    /// before the ring is touched, so the panic cannot
    /// leave the tx ring half-reserved.
    #[inline]
    #[must_use = "fewer descriptors than passed may have been consumed; the count says how many"]
    pub fn send(&mut self, buffer: &mut [XdpDescriptor]) -> u32 {
        let size = u32::try_from(buffer.len())
            .unwrap_or(u32::MAX)
            .min(RING_SIZE);
        // Validate the whole batch before reserving: a panic after
        // reserve would leave reserved-but-unsubmitted
        // slots, desyncing the producer index for the rest
        // of the socket's life if the panic were caught.
        let umem_id = self.socket.umem().id();
        let mut transmit_count: u32 = 0;
        for descriptor in &buffer[..size as usize] {
            assert!(
                descriptor.umem_id == umem_id,
                "Sent a XdpDescriptor this socket's receiver did not mint: it is empty \
                 (already consumed, or never minted) or belongs to a different socket."
            );
            if !descriptor.is_drop {
                transmit_count += 1;
            }
        }
        let tx_ring = self.socket.tx_ring();
        let (tx_available, tx_index) = tx_ring.reserve(transmit_count);
        // reserve is all-or-nothing: every transmit in the batch
        // has a slot or none does. Consumption stops at the
        // first transmit without one, so the consumed front
        // stays contiguous for retry-with-tail.
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
            // Consumed: the frame is in flight again, and an empty
            // descriptor is the proof this handle can no
            // longer reach it.
            *descriptor = XdpDescriptor::default();
            consumed += 1;
        }
        tx_ring.submit(written);
        self.kick();
        // Drain every completion available, not just this batch's
        // worth: completions from earlier, larger bursts
        // may still be waiting, and nothing else returns
        // them to the pool.
        self.complete();
        consumed
    }

    /// Wakes the driver so it picks up what was just
    /// submitted to the tx ring. The `sendto` carries
    /// no data — the descriptors are already in the ring —
    /// and is non-blocking, so a failure only means the
    /// kernel was already busy.
    #[inline]
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

    #[inline]
    fn complete(&mut self) {
        let size = u32::try_from(self.desc_producer.slots())
            .expect("XdpDescriptor producer slots overflow u32. This is a bug.");
        let completion_ring = self.socket.umem().completion_ring();
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
    /// Recycled frames from `XdpSender`: tx completions and
    /// dropped descriptors. The pool's only entry point
    /// — even dropped packets return through the
    /// sender.
    desc_consumer: DescConsumer<u64>,
}

impl XdpReceiver {
    /// Fills the front of `buffer` with minted descriptors,
    /// one received frame each, overwriting whatever
    /// the slots held. Returns how many arrived —
    /// at most `buffer.len()`, capped at the ring size.
    ///
    /// Overwriting a slot that still holds a minted
    /// descriptor leaks that frame from the pool —
    /// there is no other handle to bring it back — so
    /// reuse buffer slots only after `send` has consumed
    /// their descriptors.
    #[inline]
    #[must_use = "the count says how many descriptors were filled with received frames"]
    pub fn receive(&mut self, buffer: &mut [XdpDescriptor]) -> u32 {
        let size = u32::try_from(buffer.len())
            .unwrap_or(u32::MAX)
            .min(RING_SIZE);
        self.fill();
        self.poll();
        let umem_id = self.socket.umem().id();
        let rx_ring = self.socket.rx_ring();
        let (available, index) = rx_ring.peek(size);
        let mut offset: u32 = 0;
        while offset < available {
            let descriptor = rx_ring.descriptor(index + offset);
            // Minted: the sole handle to the frame until send consumes
            // it — what XdpDescriptor::as_slice_mut's
            // exclusivity rests on.
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

    #[inline]
    fn fill(&mut self) {
        let size = u32::try_from(self.desc_consumer.slots())
            .expect("XdpDescriptor consumer slots overflow u32. This is a bug.")
            .min(RING_SIZE);
        let fill_ring = self.socket.umem().fill_ring();
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

    #[inline]
    fn poll(&mut self) {
        let mut poll_fd_struct = pollfd {
            fd: self.socket.socket_fd(),
            events: POLLIN,
            revents: 0,
        };
        unsafe { poll(&mut poll_fd_struct, 1, 0) };
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SocketError {
    #[error("Interface name contains null character(s): {0}")]
    InvalidInterfaceName(NulError),
    #[error("Failed to initialize socket: {0}")]
    Initialize(std::io::Error),
    #[error("Failed to set RLIMIT_MEMLOCK (try running as root): {0}")]
    Setrlimit(std::io::Error),
}

// The tx/rx split exists so the two halves can drive one
// socket from separate threads; a failure here means a
// refactor broke that — most likely by removing one of the
// unsafe Send/Sync impls, which nothing else in the crate
// would catch.
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<XdpSender>();
    assert_send::<XdpReceiver>();
    assert_send::<Umem>();
};
