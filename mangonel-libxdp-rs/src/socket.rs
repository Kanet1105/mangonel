use std::{
    collections::VecDeque,
    ffi::{CString, NulError},
    ptr::{null_mut, NonNull},
    sync::Arc,
};

use libc::{poll, pollfd, sendto, MSG_DONTWAIT, POLLIN};
use mangonel_libxdp_sys::{
    xsk_socket, xsk_socket__create, xsk_socket__delete, xsk_socket__fd, xsk_socket_config,
    xsk_socket_config__bindgen_ty_1, XDP_COPY, XDP_ZEROCOPY, XSK_RING_PROD__DEFAULT_NUM_DESCS,
    XSK_UMEM__DEFAULT_FRAME_HEADROOM, XSK_UMEM__DEFAULT_FRAME_SIZE,
};

use crate::{
    buffer::Buffer,
    descriptor::Descriptor,
    ring::{ConsumerRing, ConsumerRingUninit, ProducerRing, ProducerRingUninit, RingError},
    umem::{Umem, UmemError},
    util::setrlimit,
};

#[derive(Debug)]
pub struct SocketBuilder {
    pub frame_size: u32,
    pub frame_headroom_size: u32,
    pub ring_size: u32,
    pub use_hugetlb: bool,
    pub force_zero_copy: bool,
}

impl Default for SocketBuilder {
    fn default() -> Self {
        Self {
            frame_size: XSK_UMEM__DEFAULT_FRAME_SIZE,
            frame_headroom_size: XSK_UMEM__DEFAULT_FRAME_HEADROOM,
            ring_size: XSK_RING_PROD__DEFAULT_NUM_DESCS,
            use_hugetlb: false,
            force_zero_copy: false,
        }
    }
}

impl SocketBuilder {
    /// # Panics
    ///
    /// The function panics when [`setrlimit()`] panic conditions are met.
    pub fn build(
        self,
        interface_name: impl AsRef<str>,
        queue_id: u32,
    ) -> Result<(RxSocket, TxSocket), SocketError> {
        setrlimit();

        let (rx_socket, tx_socket) = Socket::init(
            self.frame_size,
            self.frame_headroom_size,
            self.ring_size,
            self.use_hugetlb,
            self.force_zero_copy,
            interface_name,
            queue_id,
        )?;

        Ok((rx_socket, tx_socket))
    }
}

pub struct Socket {
    inner: Arc<SocketInner>,
}

struct SocketInner(NonNull<xsk_socket>);

unsafe impl Send for SocketInner {}

unsafe impl Sync for SocketInner {}

impl Drop for SocketInner {
    fn drop(&mut self) {
        unsafe { xsk_socket__delete(self.0.as_ptr()) }
    }
}

impl Clone for Socket {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Socket {
    pub fn init(
        frame_size: u32,
        frame_headroom_size: u32,
        ring_size: u32,
        use_hugetlb: bool,
        force_zero_copy: bool,
        interface_name: impl AsRef<str>,
        queue_id: u32,
    ) -> Result<(RxSocket, TxSocket), SocketError> {
        let umem = Umem::new(frame_size, frame_headroom_size, ring_size, use_hugetlb)?;

        let mut rx_ring = ConsumerRingUninit::new(ring_size)?;
        let mut tx_ring = ProducerRingUninit::new(ring_size)?;

        let mut xdp_flags = 0;
        match force_zero_copy {
            true => xdp_flags |= XDP_ZEROCOPY,
            false => xdp_flags |= XDP_COPY,
        }

        let interface_name =
            CString::new(interface_name.as_ref()).map_err(SocketError::InvalidInterfaceName)?;

        let socket_config = xsk_socket_config {
            rx_size: ring_size,
            tx_size: ring_size,
            __bindgen_anon_1: xsk_socket_config__bindgen_ty_1 { libbpf_flags: 0 },
            xdp_flags,
            bind_flags: 0,
        };
        let mut socket = null_mut();

        let value = unsafe {
            xsk_socket__create(
                &mut socket,
                interface_name.as_ptr(),
                queue_id,
                umem.as_ptr(),
                rx_ring.as_mut_ptr(),
                tx_ring.as_mut_ptr(),
                &socket_config,
            )
        };
        if value.is_negative() {
            return Err(SocketError::Initialize(std::io::Error::from_raw_os_error(
                -value,
            )));
        }

        let inner = SocketInner(NonNull::new(socket).unwrap());
        let socket = Self {
            inner: Arc::new(inner),
        };

        // Pre-fill the buffer with addresses.
        let mut prefilled_buffer = VecDeque::<u64>::with_capacity(ring_size as usize);
        (0..ring_size).for_each(|descriptor_index: u32| {
            let offset = descriptor_index * (frame_headroom_size + frame_size);
            prefilled_buffer.push(offset as u64);
        });
        umem.fill(&mut prefilled_buffer);

        let rx_socket = RxSocket::new(socket.clone(), rx_ring.init()?, umem.clone());
        let tx_socket = TxSocket::new(socket.clone(), tx_ring.init()?, umem.clone());

        Ok((rx_socket, tx_socket))
    }

    #[inline(always)]
    pub(crate) fn socket_fd(&self) -> i32 {
        unsafe { xsk_socket__fd(self.inner.0.as_ptr()) }
    }

    #[inline(always)]
    pub(crate) fn poll_fd(&self) {
        let mut poll_fd_struct = pollfd {
            fd: self.socket_fd(),
            events: POLLIN,
            revents: 0,
        };

        unsafe { poll(&mut poll_fd_struct, 1, 0) };
    }

    #[inline(always)]
    pub(crate) fn send_fd(&self) {
        unsafe { sendto(self.socket_fd(), null_mut(), 0, MSG_DONTWAIT, null_mut(), 0) };
    }
}

pub struct RxSocket {
    socket: Socket,
    rx_ring: ConsumerRing,
    umem: Umem,
}

impl RxSocket {
    pub fn new(socket: Socket, rx_ring: ConsumerRing, umem: Umem) -> Self {
        Self {
            socket,
            rx_ring,
            umem,
        }
    }

    #[inline(always)]
    pub fn umem(&self) -> Umem {
        self.umem.clone()
    }

    #[inline(always)]
    pub fn rx_burst<T>(&mut self, buffer: &mut T) -> u32
    where
        T: Buffer<Descriptor>,
    {
        if self.umem.needs_wakeup() {
            self.socket.poll_fd();
        }

        let mut index: u32 = 0;
        let size = std::cmp::min(buffer.free() as u32, self.rx_ring.size);

        let received = self.rx_ring.peek(size, &mut index);
        if received > 0 {
            for _ in 0..received {
                let descriptor_ptr = self.rx_ring.rx_descriptor(index);
                let descriptor = Descriptor::from((descriptor_ptr, &self.umem));
                buffer.push(descriptor);
                index += 1;
            }

            self.rx_ring.release(received);
        }

        received
    }
}

pub struct TxSocket {
    socket: Socket,
    tx_ring: ProducerRing,
    umem: Umem,
}

impl TxSocket {
    pub fn new(socket: Socket, tx_ring: ProducerRing, umem: Umem) -> Self {
        Self {
            socket,
            tx_ring,
            umem,
        }
    }

    #[inline(always)]
    pub fn umem(&self) -> Umem {
        self.umem.clone()
    }

    #[inline(always)]
    pub fn tx_burst<T>(&mut self, buffer: &mut T) -> u32
    where
        T: Buffer<Descriptor>,
    {
        let mut index: u32 = 0;

        let available = self.tx_ring.reserve(buffer.count(), &mut index);
        if available > 0 {
            for _ in 0..available {
                let descriptor = buffer.pop().unwrap();
                let descriptor_ptr = self.tx_ring.tx_descriptor(index);
                unsafe {
                    (*descriptor_ptr).addr = descriptor.address();
                    (*descriptor_ptr).len = descriptor.length();
                }
                index += 1;
            }

            self.tx_ring.submit(available);
        }

        if self.tx_ring.needs_wakeup() {
            self.socket.send_fd();
        }

        available
    }
}

#[derive(Debug)]
pub enum SocketError {
    Umem(UmemError),
    Ring(RingError),
    InvalidInterfaceName(NulError),
    Initialize(std::io::Error),
    SocketIsNull,
}

impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for SocketError {}

impl From<UmemError> for SocketError {
    fn from(value: UmemError) -> Self {
        Self::Umem(value)
    }
}

impl From<RingError> for SocketError {
    fn from(value: RingError) -> Self {
        Self::Ring(value)
    }
}
