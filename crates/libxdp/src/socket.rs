use crate::{
    descriptor::Descriptor,
    mmap::{Mmap, MmapError},
    ring::{
        BufferReader, BufferWriter, CompletionRing, FillRing, FreeRing, FreeRingReader,
        FreeRingWriter, RingError, RxRing, TxRing,
    },
    umem::{Umem, UmemError},
    util,
};
use libc::{poll, pollfd, sendto, MSG_DONTWAIT, POLLIN};
use mangonel_libxdp_sys::{
    xsk_socket, xsk_socket__create, xsk_socket__delete, xsk_socket__fd, xsk_socket_config,
    xsk_socket_config__bindgen_ty_1, XDP_COPY, XDP_ZEROCOPY, XSK_RING_PROD__DEFAULT_NUM_DESCS,
    XSK_UMEM__DEFAULT_FRAME_HEADROOM, XSK_UMEM__DEFAULT_FRAME_SIZE,
};
use std::{
    ffi::{CString, NulError},
    ptr::{null_mut, NonNull},
    sync::Arc,
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
    ) -> Result<(TxSocket, RxSocket), SocketError> {
        Socket::init(
            self.frame_size,
            self.frame_headroom_size,
            self.ring_size,
            self.use_hugetlb,
            self.force_zero_copy,
            interface_name,
            queue_id,
        )
    }
}

pub struct Socket {
    inner: Arc<SocketInner>,
}

struct SocketInner {
    socket: NonNull<xsk_socket>,
    umem: Umem,
}

unsafe impl Send for SocketInner {}

unsafe impl Sync for SocketInner {}

impl Drop for SocketInner {
    fn drop(&mut self) {
        unsafe { xsk_socket__delete(self.socket.as_ptr()) }
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
    ) -> Result<(TxSocket, RxSocket), SocketError> {
        // Increase the maximum size of the process's virtual memory.
        util::setrlimit();

        // Initialize the memory map.
        let length = (frame_size + frame_headroom_size) * ring_size;
        let mmap = Mmap::new(length as usize, use_hugetlb)?;

        // Initialize XDP ring buffers.
        let fill_ring = FillRing::new(ring_size)?;
        let completion_ring = CompletionRing::new(ring_size)?;
        let rx_ring = RxRing::new(ring_size)?;
        let tx_ring = TxRing::new(ring_size)?;

        // Initialize XDP UMEM.
        let umem = Umem::new(
            mmap,
            &fill_ring,
            &completion_ring,
            frame_size,
            frame_headroom_size,
            ring_size,
        )?;

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
            rx_size: ring_size,
            tx_size: ring_size,
            __bindgen_anon_1: xsk_socket_config__bindgen_ty_1 { libbpf_flags: 0 },
            xdp_flags,
            bind_flags: 0,
        };

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
            return Err(SocketError::Initialize(std::io::Error::from_raw_os_error(
                -value,
            )));
        }

        let socket = Self {
            inner: SocketInner {
                socket: NonNull::new(socket).ok_or(SocketError::SocketIsNull)?,
                umem,
            }
            .into(),
        };

        // Prefill the descriptor buffer.
        let mut prefilled_buffer = Vec::<u64>::with_capacity(ring_size as usize);
        (0..ring_size).for_each(|descriptor_index| {
            let address = descriptor_index * (frame_size + frame_headroom_size);
            prefilled_buffer.push(address as u64);
        });
        let (free_writer, free_reader) = FreeRing::from_vec(prefilled_buffer)?;

        let tx_socket = TxSocket::new(
            socket.clone(),
            ring_size,
            completion_ring,
            tx_ring,
            free_writer,
        );
        let rx_socket = RxSocket::new(socket, ring_size, fill_ring, rx_ring, free_reader);
        Ok((tx_socket, rx_socket))
    }

    #[inline(always)]
    pub fn socket_fd(&self) -> i32 {
        unsafe { xsk_socket__fd(self.inner.socket.as_ptr()) }
    }

    #[inline(always)]
    pub fn umem(&self) -> &Umem {
        &self.inner.umem
    }
}

pub struct RxSocket {
    socket: Socket,
    ring_size: u32,
    fill_ring: FillRing,
    rx_ring: RxRing,
    free_ring: FreeRingReader<u64>,
}

impl RxSocket {
    fn new(
        socket: Socket,
        ring_size: u32,
        fill_ring: FillRing,
        rx_ring: RxRing,
        free_ring: FreeRingReader<u64>,
    ) -> Self {
        Self {
            socket,
            ring_size,
            fill_ring,
            rx_ring,
            free_ring,
        }
    }

    #[inline(always)]
    fn poll(&self) {
        let mut poll_fd_struct = pollfd {
            fd: self.socket.socket_fd(),
            events: POLLIN,
            revents: 0,
        };
        unsafe { poll(&mut poll_fd_struct, 1, 0) };
    }

    #[inline(always)]
    fn fill(&mut self, size: u32) {
        let (free_filled, free_index) = self.free_ring.filled(size);
        let (fill_available, fill_index) = self.fill_ring.available(free_filled);
        let mut offset: u32 = 0;
        while offset < fill_available {
            let descriptor_address = self.free_ring.get(free_index + offset);
            let target = self.fill_ring.get_mut(fill_index + offset);
            *target = *descriptor_address;
            offset += 1;
        }
        self.free_ring.advance_index(offset);
        self.fill_ring.advance_index(offset);
    }

    #[inline(always)]
    pub fn read(&mut self) -> RxIter<'_> {
        self.fill(self.socket.umem().umem_config().fill_size);
        self.poll();
        RxIter::new(self)
    }
}

pub struct RxIter<'a> {
    rx_socket: &'a mut RxSocket,
    length: u32,
    index: u32,
    offset: u32,
}

impl<'a> Iterator for RxIter<'a> {
    type Item = Descriptor;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset < self.length {
            let descriptor_ref = self.rx_socket.rx_ring.get(self.index + self.offset);
            let descriptor = Descriptor::new(descriptor_ref, self.rx_socket.socket.umem());
            self.offset += 1;
            Some(descriptor)
        } else {
            None
        }
    }
}

impl<'a> RxIter<'a> {
    #[inline(always)]
    pub fn new(rx_socket: &'a mut RxSocket) -> Self {
        let (rx_filled, rx_index) = rx_socket.rx_ring.filled(rx_socket.ring_size);
        rx_socket.rx_ring.advance_index(rx_filled);
        Self {
            rx_socket,
            length: rx_filled,
            index: rx_index,
            offset: 0,
        }
    }
}

pub struct TxSocket {
    socket: Socket,
    ring_size: u32,
    completion_ring: CompletionRing,
    tx_ring: TxRing,
    free_ring: FreeRingWriter<u64>,
}

impl TxSocket {
    fn new(
        socket: Socket,
        ring_size: u32,
        completion_ring: CompletionRing,
        tx_ring: TxRing,
        free_ring: FreeRingWriter<u64>,
    ) -> Self {
        Self {
            socket,
            ring_size,
            completion_ring,
            tx_ring,
            free_ring,
        }
    }

    #[inline(always)]
    fn send(&mut self) {
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

    #[inline(always)]
    fn complete(&mut self, size: u32) {
        let (completion_filled, completion_index) = self.completion_ring.filled(size);
        let (free_available, free_index) = self.free_ring.available(completion_filled);
        let mut offset: u32 = 0;
        while offset < free_available {
            let descriptor_address = self.completion_ring.get(completion_index + offset);
            let target = self.free_ring.get_mut(free_index + offset);
            *target = *descriptor_address;
            offset += 1;
        }
        self.completion_ring.advance_index(offset);
        self.free_ring.advance_index(offset);
    }

    #[inline(always)]
    pub fn free(&mut self, mut iter: impl Iterator<Item = Descriptor>) {
        let (free_available, free_index) = self.free_ring.available(self.ring_size);
        let mut offset: u32 = 0;
        while offset < free_available {
            if let Some(descriptor) = iter.next() {
                let empty = self.free_ring.get_mut(free_index + offset);
                *empty = descriptor.address;
                offset += 1;
            } else {
                break;
            }
        }
        self.free_ring.advance_index(offset);
    }

    #[inline(always)]
    pub fn write(&mut self, mut iter: impl Iterator<Item = Descriptor>) {
        let (tx_available, tx_index) = self.tx_ring.available(self.ring_size);
        let mut offset: u32 = 0;
        while offset < tx_available {
            if let Some(descriptor) = iter.next() {
                let descriptor_mut = self.tx_ring.get_mut(tx_index + offset);
                descriptor_mut.addr = descriptor.address;
                descriptor_mut.len = descriptor.length;
                offset += 1;
            } else {
                break;
            }
        }
        self.tx_ring.advance_index(offset);

        self.send();
        self.complete(self.ring_size);
    }
}

pub enum SocketError {
    Mmap(MmapError),
    Ring(RingError),
    Umem(UmemError),
    InvalidInterfaceName(NulError),
    Initialize(std::io::Error),
    SocketIsNull,
}

impl std::fmt::Debug for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mmap(error) => write!(f, "{}", error),
            Self::Ring(error) => write!(f, "{}", error),
            Self::Umem(error) => write!(f, "{}", error),
            Self::InvalidInterfaceName(error) => {
                write!(f, "Interface name contains null character(s): {}", error)
            }
            Self::Initialize(error) => write!(f, "Failed to initialize XDP socket: {}", error),
            Self::SocketIsNull => write!(f, "Socket returned null. This is a bug."),
        }
    }
}

impl std::error::Error for SocketError {}

impl From<MmapError> for SocketError {
    fn from(value: MmapError) -> Self {
        Self::Mmap(value)
    }
}

impl From<RingError> for SocketError {
    fn from(value: RingError) -> Self {
        Self::Ring(value)
    }
}

impl From<UmemError> for SocketError {
    fn from(value: UmemError) -> Self {
        Self::Umem(value)
    }
}
