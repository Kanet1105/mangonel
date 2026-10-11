use std::{
    ffi::{CString, NulError},
    io,
    ptr::{NonNull, null_mut},
    sync::{Mutex, PoisonError},
};

use mangonel_libxdp_sys::{
    XSK_RING_PROD__DEFAULT_NUM_DESCS, XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    XSK_UMEM__DEFAULT_FRAME_SIZE, xsk_socket, xsk_socket__create_shared, xsk_socket_config,
    xsk_socket_config__bindgen_ty_1,
};

use crate::{
    descriptor::XdpDescriptor,
    ring::{Consumer, Producer, RingError, ring_buffer},
    socket::{XdpReceiver, XdpSender, XdpSocket},
    umem::{Umem, UmemError},
};

/// Libxdp's default ring depth, for both directions.
pub const DEFAULT_RECEIVE_DEPTH: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS;
pub const DEFAULT_SEND_DEPTH: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS;
/// Libxdp's default frame size, also the smallest one
/// supported.
pub const DEFAULT_FRAME_SIZE: u32 = XSK_UMEM__DEFAULT_FRAME_SIZE;
pub const DEFAULT_FRAME_HEADROOM: u32 = XSK_UMEM__DEFAULT_FRAME_HEADROOM;

/// What [`bind`] asks for: the depth of each direction and
/// the umem's frame layout. The depths are per socket; the
/// layout is set by the first bind and repeated by the
/// rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XdpConfig {
    /// Packets in flight on receive: sizes the rx and fill
    /// rings. A power of two.
    pub receive_depth: u32,
    /// Packets in flight on send: sizes the tx and
    /// completion rings. A power of two.
    pub send_depth: u32,
    /// Bytes per umem frame: a power of two, from
    /// [`DEFAULT_FRAME_SIZE`] up to the page size.
    pub frame_size: u32,
    /// Bytes reserved before each frame's packet data.
    pub frame_headroom: u32,
    /// Frames in the umem, shared by every socket on it:
    /// 1 to 2^30. [`Self::frames_for`] sizes it so the
    /// pool never starves.
    pub frame_count: u32,
}

impl Default for XdpConfig {
    /// Libxdp's defaults, with frames for one socket.
    fn default() -> Self {
        let mut config = Self {
            receive_depth: DEFAULT_RECEIVE_DEPTH,
            send_depth: DEFAULT_SEND_DEPTH,
            frame_size: DEFAULT_FRAME_SIZE,
            frame_headroom: DEFAULT_FRAME_HEADROOM,
            frame_count: 0,
        };
        config.frame_count = config
            .frames_for(1)
            .expect("The default depths overflow the frame count. This is a bug.");

        config
    }
}

impl XdpConfig {
    /// Frames that fill every ring of `socket_count`
    /// sockets at these depths at once: the count at which
    /// the pool never starves. `None` on overflow.
    pub fn frames_for(&self, socket_count: u32) -> Option<u32> {
        // Each direction is a pair of rings.
        self.receive_depth
            .checked_add(self.send_depth)?
            .checked_mul(2)?
            .checked_mul(socket_count)
    }
}

/// Serializes socket creation and deletion: libxdp's umem
/// bookkeeping is unsynchronized, and only the first bind
/// may create the umem.
pub(crate) static BIND: Mutex<()> = Mutex::new(());

/// Binds one queue on the global umem, which the first
/// call creates laid out by `config`; later calls must
/// repeat that layout. Every socket shares the umem, so
/// frames forward between them without copying.
/// [`XdpSocket::split`] it to drive send and receive from
/// different threads. Panics on broken libxdp/kernel
/// contracts.
pub fn bind(
    interface_name: impl AsRef<str>,
    queue_id: u32,
    config: XdpConfig,
) -> Result<XdpSocket, XdpError> {
    let interface_name = interface_name.as_ref();

    // The umem mapping counts against RLIMIT_MEMLOCK.
    setrlimit().map_err(Error::Setrlimit)?;

    // Rings before the umem, which saves the
    // fill/completion pair at creation. Each direction's
    // two rings share its depth.
    let (fill, rx) = ring_buffer(config.receive_depth)?;
    let (tx, completion) = ring_buffer(config.send_depth)?;

    let guard = BIND.lock().unwrap_or_else(PoisonError::into_inner);
    let socket = if let Some(umem) = Umem::existing() {
        check_layout(umem, &config)?;

        create_xsk(interface_name, queue_id, &rx, &tx, &fill, &completion, umem)?
    } else {
        let umem = Umem::new(
            config.frame_size,
            config.frame_headroom,
            config.frame_count,
            false,
            &fill,
            &completion,
        )?;
        match create_xsk(
            interface_name,
            queue_id,
            &rx,
            &tx,
            &fill,
            &completion,
            &umem,
        ) {
            Ok(socket) => {
                // Global only once its first socket exists,
                // so a failed first bind leaves none behind.
                umem.publish();

                socket
            }
            Err(error) => {
                // Freed while the fill/completion pair it
                // saved is alive.
                umem.free()?;

                return Err(error.into());
            }
        }
    };
    // Released before the `XdpSocket` exists: its drop
    // takes the lock, which is not reentrant.
    drop(guard);

    // Sound, but the fill ring can never be topped up.
    let frame_count = Umem::global().frame_count();
    if frame_count < config.receive_depth {
        println!(
            "warning: {interface_name}: {frame_count} frames is fewer than the receive depth {}; \
             receive will drop under load",
            config.receive_depth
        );
    }

    let socket = XdpSocket::new(socket, rx, tx, fill, completion);
    // Silent and an order of magnitude slower if left
    // undetected.
    if !socket.config().zero_copy {
        println!("warning: {interface_name}: driver lacks zero-copy support; running in copy mode");
    }

    Ok(socket)
}

/// Fails unless `config` repeats the existing umem's
/// layout.
fn check_layout(umem: &Umem, config: &XdpConfig) -> Result<(), Error> {
    let existing = umem.config();
    let frame_count = umem.frame_count();
    if existing.frame_size != config.frame_size
        || existing.frame_headroom != config.frame_headroom
        || frame_count != config.frame_count
    {
        return Err(Error::UmemLayout {
            frame_size: existing.frame_size,
            frame_headroom: existing.frame_headroom,
            frame_count,
        });
    }

    Ok(())
}

/// Creates the kernel socket over the rings and `umem`,
/// which stay with the caller.
fn create_xsk(
    interface_name: &str,
    queue_id: u32,
    rx: &Consumer,
    tx: &Producer,
    fill: &Producer,
    completion: &Consumer,
    umem: &Umem,
) -> Result<NonNull<xsk_socket>, Error> {
    let interface = CString::new(interface_name).map_err(Error::InvalidInterfaceName)?;
    let socket_config = socket_config(rx.size(), tx.size());

    // The first socket passes the umem's saved
    // fill/completion pair; later ones pass fresh rings and
    // bind with XDP_SHARED_UMEM.
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
        });
    }

    // The invariant the ring accessors rely on.
    assert!(
        rx.is_registered()
            && tx.is_registered()
            && fill.is_registered()
            && completion.is_registered(),
        "xsk_socket__create_shared left a ring unpopulated. This is a bug."
    );

    Ok(NonNull::new(socket)
        .expect("xsk_socket__create_shared returned a null pointer. This is a bug."))
}

/// Zero flags: native attach and zero-copy with fallback.
/// When forcing a mode, XDP_COPY/XDP_ZEROCOPY belong in
/// bind_flags — never xdp_flags, whose same-valued bits
/// mean SKB/DRV attach mode.
fn socket_config(rx_size: u32, tx_size: u32) -> xsk_socket_config {
    xsk_socket_config {
        rx_size,
        tx_size,
        __bindgen_anon_1: xsk_socket_config__bindgen_ty_1 { libbpf_flags: 0 },
        xdp_flags: 0,
        bind_flags: 0,
    }
}

/// Raises the locked-memory limit the umem mapping counts
/// against; fails without root or CAP_SYS_RESOURCE.
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
    #[error("Failed to initialize the socket for queue {queue_id}: {source}")]
    Initialize { queue_id: u32, source: io::Error },
    #[error(
        "The umem already exists with {frame_count} frames of {frame_size} bytes and \
         {frame_headroom} bytes of headroom; bind with that layout."
    )]
    UmemLayout {
        frame_size: u32,
        frame_headroom: u32,
        frame_count: u32,
    },
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

// Guards the unsafe Send and Sync impls the worker move
// rests on; nothing else in the crate would catch their
// removal.
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<XdpSocket>();
    assert_send::<XdpSender>();
    assert_send::<XdpReceiver>();
    assert_send::<Umem>();
    assert_send::<XdpDescriptor>();

    const fn assert_sync<T: Sync>() {}
    assert_sync::<Umem>();
    assert_sync::<XdpDescriptor>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_frames_fill_one_socket() {
        let config = XdpConfig::default();
        assert_eq!(
            config.frame_count,
            2 * (DEFAULT_RECEIVE_DEPTH + DEFAULT_SEND_DEPTH)
        );
        assert_eq!(config.frames_for(3), Some(3 * config.frame_count));
        assert_eq!(config.frames_for(u32::MAX), None);
    }
}
