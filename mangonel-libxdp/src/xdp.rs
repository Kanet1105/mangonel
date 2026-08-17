use std::{
    ffi::{CString, NulError},
    io,
    ptr::{NonNull, null_mut},
};

use mangonel_libxdp_sys::{
    xsk_socket__create_shared, xsk_socket_config, xsk_socket_config__bindgen_ty_1,
};

use crate::{
    pool::FramePool,
    ring::{Consumer, DEFAULT_RING_SIZE, Producer, RingError, ring_buffer},
    socket::XdpSocket,
    umem::{DEFAULT_FRAME_HEADROOM, DEFAULT_FRAME_SIZE, Umem, UmemError},
};

/// Rings a frame can occupy at once: rx, tx, fill,
/// completion.
const RINGS_PER_SOCKET: u32 = 4;

/// Opens one [`XdpSocket`] on one queue of the interface,
/// with a fresh umem sized for `share_count` sockets — this
/// one plus every [`bind_shared`] partner that will join
/// it; more shares still work, on a thinner frame margin.
/// Queue ids run in `0..` the interface's usable queue
/// count. Attach and copy mode are the kernel's
/// preference; see [`XdpSocket::is_zero_copy`] for what it
/// chose.
///
/// # Panics
///
/// Panics on a zero `share_count`, and on broken
/// libxdp/kernel contracts: unpopulated rings, a null
/// socket.
pub fn bind(
    interface_name: impl AsRef<str>,
    queue_id: u32,
    share_count: usize,
) -> Result<XdpSocket, XdpError> {
    // A umem serves at least the socket bound over it.
    assert!(
        share_count > 0,
        "The share count '{share_count}' sizes a umem for no sockets."
    );

    // The umem mapping counts against RLIMIT_MEMLOCK.
    setrlimit().map_err(Error::Setrlimit)?;

    // Sized for every ring of every sharing socket being
    // full at once, so the pool never starves.
    let frame_count = u32::try_from(share_count)
        .ok()
        .and_then(|sockets| sockets.checked_mul(DEFAULT_RING_SIZE))
        .and_then(|frames| frames.checked_mul(RINGS_PER_SOCKET))
        .ok_or(Error::TooManySockets { share_count })?;

    // Rings before the umem: the umem — declared later,
    // dropped first on error paths — is deleted while the
    // fill/completion pair it saves at creation is alive.
    let (fill, completion) = ring_buffer(DEFAULT_RING_SIZE)?;
    let (tx, rx) = ring_buffer(DEFAULT_RING_SIZE)?;
    let umem = Umem::new(
        DEFAULT_FRAME_SIZE,
        DEFAULT_FRAME_HEADROOM,
        frame_count,
        false,
        &fill,
        &completion,
    )?;

    create_socket(
        interface_name.as_ref(),
        queue_id,
        rx,
        tx,
        fill,
        completion,
        umem,
    )
}

/// Opens one [`XdpSocket`] on one queue, sharing
/// `socket`'s umem: a frame received on either socket may
/// be transmitted on the other with no copy, and both draw
/// from — and complete back into — the same frame pool,
/// which is what makes forwarding between them sound.
/// Binds with `XDP_SHARED_UMEM`, inheriting the first
/// bind's copy mode. Count every share in the [`bind`]
/// `share_count` that sized the umem.
///
/// # Panics
///
/// As [`bind`].
pub fn bind_shared(
    interface_name: impl AsRef<str>,
    queue_id: u32,
    socket: &XdpSocket,
) -> Result<XdpSocket, XdpError> {
    // Fresh rings; none can be the umem's saved pair, so no
    // drop-order care is needed.
    let (fill, completion) = ring_buffer(DEFAULT_RING_SIZE)?;
    let (tx, rx) = ring_buffer(DEFAULT_RING_SIZE)?;

    create_socket(
        interface_name.as_ref(),
        queue_id,
        rx,
        tx,
        fill,
        completion,
        socket.umem().clone(),
    )
}

/// Binds one socket over the rings and umem. `umem` is
/// deliberately the last parameter: parameters drop in
/// reverse order, so on an error path an owning umem is
/// deleted while the fill/completion pair it saved is
/// still alive.
fn create_socket(
    interface_name: &str,
    queue_id: u32,
    rx: Consumer,
    tx: Producer,
    fill: Producer,
    completion: Consumer,
    umem: Umem,
) -> Result<XdpSocket, XdpError> {
    let interface = CString::new(interface_name).map_err(Error::InvalidInterfaceName)?;
    let socket_config = socket_config();

    // For the umem's owning socket the fill/completion
    // pointers are the pair saved at umem creation; for a
    // sharing socket they are fresh and bind with
    // XDP_SHARED_UMEM.
    let mut socket = null_mut();
    let value = unsafe {
        xsk_socket__create_shared(
            &mut socket,
            interface.as_ptr(),
            queue_id,
            umem.as_ptr(),
            rx.as_ptr(),
            tx.as_ptr(),
            fill.as_ptr(),
            completion.as_ptr(),
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

    // The invariant the ring accessors rely on.
    assert!(
        rx.is_registered()
            && tx.is_registered()
            && fill.is_registered()
            && completion.is_registered(),
        "xsk_socket__create_shared left a ring unpopulated. This is a bug."
    );

    let socket = XdpSocket::new(
        NonNull::new(socket)
            .expect("xsk_socket__create_shared returned a null pointer. This is a bug."),
        rx,
        tx,
        fill,
        completion,
        umem,
    );
    warn_copy_mode(interface_name, &socket);

    Ok(socket)
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

/// Warns on stderr when the socket fell back to copy mode
/// — silent, and an order of magnitude slower, if left
/// undetected.
fn warn_copy_mode(interface_name: &str, socket: &XdpSocket) {
    if !socket.is_zero_copy() {
        tracing::warn!(
            interface = interface_name,
            "driver lacks zero-copy support; running in copy mode"
        );
    }
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
    #[error("The share count '{share_count}' overflows the umem frame count.")]
    TooManySockets { share_count: usize },
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
