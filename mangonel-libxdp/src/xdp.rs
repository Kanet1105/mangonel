use std::{
    ffi::{CString, NulError},
    io,
    ptr::{NonNull, null_mut},
};

use libc::{SOL_XDP, getsockopt};
use mangonel_libxdp_sys::{
    XDP_OPTIONS, XDP_OPTIONS_ZEROCOPY, xdp_options, xsk_socket__create_shared, xsk_socket_config,
    xsk_socket_config__bindgen_ty_1,
};
use mangonel_nic::nic::Nic;

use crate::{
    ring::{Consumer, DEFAULT_RING_SIZE, Producer, RingError, ring_buffer},
    socket::{FramePool, XdpSocket},
    umem::{DEFAULT_FRAME_HEADROOM, DEFAULT_FRAME_SIZE, Umem, UmemError},
};

/// Rings a frame can occupy at once: fill, rx, tx,
/// completion.
const RINGS_PER_SOCKET: u32 = 4;

/// What [`bind`] returns: one [`XdpSocket`] per queue, one
/// seeded [`FramePool`] per queue, the umem backing them,
/// and whether the kernel bound zero-copy.
///
/// `pools[i]` holds queue `i`'s share of the umem's frames.
/// It is the worker's pool: a socket added over the same
/// umem with [`bind_with_umem`] shares it, so a frame
/// forwarded between the two interfaces returns to the pool
/// it left.
pub struct Binding {
    pub sockets: Vec<XdpSocket>,
    pub pools: Vec<FramePool>,
    pub umem: Umem,
    pub zero_copy: bool,
}

/// One queue's rings, allocated before its socket binds.
/// A slot is taken only after a successful bind: an
/// unclaimed fill/completion pair must outlive the umem,
/// whose delete dereferences the pair saved at creation.
struct QueueRings {
    fill: Producer,
    completion: Consumer,
    tx: Producer,
    rx: Consumer,
}

/// Opens one [`XdpSocket`] per usable queue (`min(rx, tx)`)
/// on the interface, socket `i` bound to queue `i`, all
/// sharing one [`Umem`].
///
/// The umem is sized for `umem_interfaces` interfaces
/// sharing it: pass `1` for a lone interface, or the total
/// when [`bind_with_umem`] will add more, so every socket's
/// rings and every pool have frames. The umem must outlive
/// every socket. Attach and copy mode are the kernel's
/// preference; the returned bool is whether it bound
/// zero-copy.
///
/// # Panics
///
/// Panics on broken libxdp/kernel contracts: unpopulated
/// rings, a null socket, an interface with zero queues.
pub fn bind(interface_name: impl AsRef<str>, umem_interfaces: u32) -> Result<Binding, XdpError> {
    let interface_name = interface_name.as_ref();

    // The umem mapping counts against RLIMIT_MEMLOCK.
    setrlimit().map_err(Error::Setrlimit)?;

    let queue_count = Nic::open(interface_name).map_err(Error::Nic)?.xdp_queues();
    // The kernel refuses zero-queue interfaces, and counting
    // errors rather than reporting zero.
    assert!(
        queue_count > 0,
        "The interface reports zero queues. This is a bug."
    );

    // All rings, created before the umem: on every error path
    // the umem — declared later, dropped first — is deleted
    // while any unclaimed pair it references is alive.
    let mut queue_rings = (0..queue_count)
        .map(|_| {
            let (fill, completion) = ring_buffer(DEFAULT_RING_SIZE)?;
            let (tx, rx) = ring_buffer(DEFAULT_RING_SIZE)?;

            Ok(Some(QueueRings {
                fill,
                completion,
                tx,
                rx,
            }))
        })
        .collect::<Result<Vec<_>, RingError>>()?;

    // Sized for every ring of every queue of every sharing
    // interface being full at once, so the pools never starve.
    let frame_count = DEFAULT_RING_SIZE
        .checked_mul(RINGS_PER_SOCKET)
        .and_then(|frames| frames.checked_mul(queue_count))
        .and_then(|frames| frames.checked_mul(umem_interfaces))
        .ok_or(Error::TooManyQueues { queue_count })?;

    let umem = {
        let first = queue_rings[0]
            .as_ref()
            .expect("Queue rings taken before any bind. This is a bug.");

        Umem::new(
            DEFAULT_FRAME_SIZE,
            DEFAULT_FRAME_HEADROOM,
            frame_count,
            false,
            &first.fill,
            &first.completion,
        )?
    };

    let interface = CString::new(interface_name).map_err(Error::InvalidInterfaceName)?;
    let socket_config = socket_config();

    // Every frame lives in some pool: one pool per queue, each
    // its own disjoint slice of the umem.
    let frames_per_pool = frame_count / queue_count;
    let mut sockets = Vec::with_capacity(queue_count as usize);
    let mut pools = Vec::with_capacity(queue_count as usize);
    // Set from queue 0; every queue on an interface binds in
    // the same mode.
    let mut zero_copy = false;
    for queue_id in 0..queue_count {
        let slot = &mut queue_rings[queue_id as usize];
        let rings = slot
            .as_ref()
            .expect("Queue rings taken twice. This is a bug.");

        // Queue 0's fill/completion pointers are the pair saved
        // at umem creation, binding the umem's owning
        // socket; the rest are fresh and bind with
        // XDP_SHARED_UMEM.
        let mut socket = null_mut();
        let value = unsafe {
            xsk_socket__create_shared(
                &mut socket,
                interface.as_ptr(),
                queue_id,
                umem.as_ptr(),
                rings.rx.as_ptr(),
                rings.tx.as_ptr(),
                rings.fill.as_ptr(),
                rings.completion.as_ptr(),
                &socket_config,
            )
        };
        if value.is_negative() {
            // Bound sockets drop with `sockets`, before the umem;
            // unclaimed rings drop after it.
            return Err(Error::Initialize {
                queue_id,
                source: io::Error::from_raw_os_error(-value),
            }
            .into());
        }

        // The invariant the ring accessors rely on.
        assert!(
            rings.tx.is_registered()
                && rings.rx.is_registered()
                && rings.fill.is_registered()
                && rings.completion.is_registered(),
            "xsk_socket__create_shared left a ring unpopulated. This is a bug."
        );

        // Claimed: the socket owns its rings past delete.
        let QueueRings {
            fill,
            completion,
            tx,
            rx,
        } = slot
            .take()
            .expect("Queue rings taken twice. This is a bug.");

        let socket = XdpSocket::new(
            NonNull::new(socket)
                .expect("xsk_socket__create_shared returned a null pointer. This is a bug."),
            tx,
            rx,
            fill,
            completion,
            umem.clone(),
        );

        // Once per interface: every queue lands in the same mode.
        if queue_id == 0 {
            zero_copy = warn_copy_mode(interface_name, socket.socket_fd());
        }

        // This queue's disjoint slice of the umem's frames.
        let mut pool = FramePool::new(frames_per_pool as usize);
        for index in 0..frames_per_pool {
            let frame = u64::from(queue_id * frames_per_pool + index);
            pool.push(frame * u64::from(DEFAULT_FRAME_SIZE));
        }

        sockets.push(socket);
        pools.push(pool);
    }

    Ok(Binding {
        sockets,
        pools,
        umem,
        zero_copy,
    })
}

/// Opens one [`XdpSocket`] per usable queue on the
/// interface, sharing an existing `umem`: a frame received
/// on either interface may be transmitted on the other with
/// no copy. Binds with `XDP_SHARED_UMEM`, inheriting the
/// first bind's copy mode.
///
/// Brings no pools: these sockets share the per-queue pools
/// from the [`bind`] that created the umem — which is what
/// makes forwarding sound. Size that umem for both
/// interfaces via `bind`'s `umem_interfaces`.
///
/// # Panics
///
/// As [`bind`].
pub fn bind_with_umem(
    interface_name: impl AsRef<str>,
    umem: &Umem,
) -> Result<Vec<XdpSocket>, XdpError> {
    let interface_name = interface_name.as_ref();

    let queue_count = Nic::open(interface_name).map_err(Error::Nic)?.xdp_queues();
    // As in bind.
    assert!(
        queue_count > 0,
        "The interface reports zero queues. This is a bug."
    );

    let interface = CString::new(interface_name).map_err(Error::InvalidInterfaceName)?;
    let socket_config = socket_config();

    let mut sockets = Vec::with_capacity(queue_count as usize);
    for queue_id in 0..queue_count {
        // Fresh rings; none can be the umem's saved pair, so no
        // drop-order care is needed.
        let (fill_ring, completion_ring) = ring_buffer(DEFAULT_RING_SIZE)?;
        let (tx_ring, rx_ring) = ring_buffer(DEFAULT_RING_SIZE)?;

        let mut socket = null_mut();
        let value = unsafe {
            xsk_socket__create_shared(
                &mut socket,
                interface.as_ptr(),
                queue_id,
                umem.as_ptr(),
                rx_ring.as_ptr(),
                tx_ring.as_ptr(),
                fill_ring.as_ptr(),
                completion_ring.as_ptr(),
                &socket_config,
            )
        };
        if value.is_negative() {
            return Err(Error::Initialize {
                queue_id,
                source: io::Error::from_raw_os_error(-value),
            }
            .into());
        }

        // As in bind.
        assert!(
            tx_ring.is_registered()
                && rx_ring.is_registered()
                && fill_ring.is_registered()
                && completion_ring.is_registered(),
            "xsk_socket__create_shared left a ring unpopulated. This is a bug."
        );

        let socket = XdpSocket::new(
            NonNull::new(socket)
                .expect("xsk_socket__create_shared returned a null pointer. This is a bug."),
            tx_ring,
            rx_ring,
            fill_ring,
            completion_ring,
            umem.clone(),
        );

        // As in bind.
        if queue_id == 0 {
            warn_copy_mode(interface_name, socket.socket_fd());
        }

        sockets.push(socket);
    }

    Ok(sockets)
}

/// Zero flags: native attach and zero-copy where the driver
/// supports them, with fallback. When forcing a mode,
/// XDP_COPY/XDP_ZEROCOPY belong in bind_flags — never
/// xdp_flags, whose same-valued bits mean SKB/DRV attach
/// mode.
fn socket_config() -> xsk_socket_config {
    xsk_socket_config {
        rx_size: DEFAULT_RING_SIZE,
        tx_size: DEFAULT_RING_SIZE,
        __bindgen_anon_1: xsk_socket_config__bindgen_ty_1 { libbpf_flags: 0 },
        xdp_flags: 0,
        bind_flags: 0,
    }
}

/// Raises the locked-memory limit the umem mapping counts
/// against. Fails without root or CAP_SYS_RESOURCE — an
/// environmental condition the caller can act on, so an
/// error rather than a panic.
fn setrlimit() -> Result<(), io::Error> {
    let value = unsafe {
        let rlimit = libc::rlimit {
            // RLIM_INFINITY is the constant matching libc::rlimit's field
            // width; the 64-suffixed one belongs to the rlimit64 API.
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };

        libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit)
    };
    if value.is_negative() {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Whether the kernel bound the socket zero-copy. A failed
/// getsockopt counts as no.
fn is_zero_copy(fd: i32) -> bool {
    let mut options = xdp_options { flags: 0 };
    let mut length = libc::socklen_t::try_from(size_of::<xdp_options>())
        .expect("xdp_options size overflows socklen_t. This is a bug.");
    let value = unsafe {
        getsockopt(
            fd,
            SOL_XDP,
            XDP_OPTIONS.cast_signed(),
            (&raw mut options).cast(),
            &raw mut length,
        )
    };

    value == 0 && options.flags & XDP_OPTIONS_ZEROCOPY != 0
}

/// Warns on stderr when the interface fell back to copy
/// mode — silent, and an order of magnitude slower, if left
/// undetected — and returns whether it bound zero-copy.
fn warn_copy_mode(interface_name: &str, fd: i32) -> bool {
    let zero_copy = is_zero_copy(fd);
    if !zero_copy {
        tracing::warn!(
            interface = interface_name,
            "driver lacks zero-copy support; running in copy mode"
        );
    }

    zero_copy
}

/// The error type for this crate: any failure reported
/// while setting up or driving an AF_XDP socket.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct XdpError(Error);

/// Private aggregate of every failure, so none of the
/// variants leak into the public API.
#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Ring(#[from] RingError),
    #[error(transparent)]
    Umem(#[from] UmemError),
    #[error("Failed to raise RLIMIT_MEMLOCK (need root or CAP_SYS_RESOURCE): {0}")]
    Setrlimit(io::Error),
    #[error("Interface name contains null character(s): {0}")]
    InvalidInterfaceName(NulError),
    #[error("Failed to query the interface: {0}")]
    Nic(mangonel_nic::nic::Error),
    #[error("The interface's queue count '{queue_count}' overflows the umem frame count.")]
    TooManyQueues { queue_count: u32 },
    #[error("Failed to initialize the socket for queue {queue_id}: {source}")]
    Initialize { queue_id: u32, source: io::Error },
}

impl From<Error> for XdpError {
    fn from(error: Error) -> Self {
        Self(error)
    }
}

impl From<RingError> for XdpError {
    fn from(error: RingError) -> Self {
        Self(error.into())
    }
}

impl From<UmemError> for XdpError {
    fn from(error: UmemError) -> Self {
        Self(error.into())
    }
}

// Guards the unsafe Send impls the worker move rests on;
// nothing else in the crate would catch their removal.
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<XdpSocket>();
    assert_send::<FramePool>();
    assert_send::<Umem>();
};
