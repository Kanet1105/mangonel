use std::{
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
    descriptor::Descriptor,
    mmap::{Mmap, MmapError},
    ring_buffer::{
        BufferReader, BufferWriter, CompletionRing, FillRing, RingBuffer, RingBufferReader,
        RingBufferWriter, RingError, RxRing, TxRing,
    },
    umem::{Umem, UmemError},
    util,
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
        util::setrlimit();

        let length = (frame_size + frame_headroom_size) * ring_size;
        let mmap = Mmap::new(length as usize, use_hugetlb).map_err(SocketError::Mmap)?;

        let (umem, fill_ring, completion_ring) =
            Umem::new(mmap, frame_size, frame_headroom_size, ring_size)
                .map_err(SocketError::Umem)?;

        let mut socket = null_mut();
        let interface_name =
            CString::new(interface_name.as_ref()).map_err(SocketError::InvalidInterfaceName)?;
        let rx_ring = RxRing::new(ring_size).map_err(SocketError::Ring)?;
        let tx_ring = TxRing::new(ring_size).map_err(SocketError::Ring)?;
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

        let mut prefilled_buffer = Vec::<u64>::with_capacity(ring_size as usize);
        (0..ring_size).for_each(|descriptor_index| {
            let address = descriptor_index * (frame_size + frame_headroom_size);
            prefilled_buffer.push(address as u64);
        });
        let (buffer_writer, buffer_reader) =
            RingBuffer::from_vec(prefilled_buffer).map_err(SocketError::Ring)?;

        let tx_socket = TxSocket::new(socket.clone(), completion_ring, tx_ring, buffer_writer);
        let rx_socket = RxSocket::new(socket, fill_ring, rx_ring, buffer_reader);

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

pub struct TxSocket {
    socket: Socket,
    completion_ring: CompletionRing,
    tx_ring: TxRing,
    buffer_writer: RingBufferWriter<u64>,
}

impl TxSocket {
    fn new(
        socket: Socket,
        completion_ring: CompletionRing,
        tx_ring: TxRing,
        buffer_writer: RingBufferWriter<u64>,
    ) -> Self {
        Self {
            socket,
            completion_ring,
            tx_ring,
            buffer_writer,
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
    fn complete(&mut self, size: u32) -> u32 {
        let (filled, reader_index) = self.completion_ring.filled(size);
        if filled > 0 {
            println!("[Complete] Filled: {}", filled);
        }
        let (available, writer_index) = self.buffer_writer.available(size);
        if available > 0 {
            println!("[Complete] Available: {}", available);
        }

        if filled > 0 {
            for offset in 0..filled {
                let data = self.completion_ring.get(reader_index + offset);
                let empty = self.buffer_writer.get_mut(writer_index + offset);
                *empty = *data;
            }
            self.buffer_writer.advance_index(filled);
            self.completion_ring.advance_index(filled);

            filled
        } else {
            0
        }
    }

    #[inline(always)]
    pub fn write(&mut self, buffer: &[Descriptor]) -> u32 {
        let (available, index) = self.tx_ring.available(buffer.len() as u32);

        if available > 0 {
            for offset in 0..available {
                let data = self.tx_ring.get_mut(index + offset);
                data.addr = buffer[offset as usize].address();
                data.len = buffer[offset as usize].length();
            }
            self.tx_ring.advance_index(available);
            self.send();
            self.complete(self.socket.umem().umem_config().comp_size);

            available
        } else {
            0
        }
    }
}

pub struct RxSocket {
    socket: Socket,
    fill_ring: FillRing,
    rx_ring: RxRing,
    buffer_reader: RingBufferReader<u64>,
}

impl RxSocket {
    fn new(
        socket: Socket,
        fill_ring: FillRing,
        rx_ring: RxRing,
        buffer_reader: RingBufferReader<u64>,
    ) -> Self {
        Self {
            socket,
            fill_ring,
            rx_ring,
            buffer_reader,
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
    fn fill(&mut self, size: u32) -> u32 {
        let (filled, reader_index) = self.buffer_reader.filled(size);
        if filled > 0 {
            println!("[Fill] Filled: {}", filled);
        }
        let (available, writer_index) = self.fill_ring.available(filled);
        if available > 0 {
            println!("[Fill] Available: {}", available);
        }

        if available > 0 {
            for offset in 0..available {
                let data = self.buffer_reader.get(reader_index + offset);
                let empty = self.fill_ring.get_mut(writer_index + offset);
                *empty = *data;
            }
            self.buffer_reader.advance_index(available);
            self.fill_ring.advance_index(available);

            available
        } else {
            0
        }
    }

    #[inline(always)]
    pub fn read(&mut self, buffer: &mut [Descriptor], burst_size: u32) -> u32 {
        self.poll();
        self.fill(self.socket.umem().umem_config().fill_size);
        let (filled, index) = self.rx_ring.filled(burst_size);

        if filled > 0 {
            for offset in 0..filled {
                let descriptor_ref = self.rx_ring.get(index + offset);
                let descriptor = Descriptor::from(descriptor_ref);
                buffer[offset as usize] = descriptor;
            }
            self.rx_ring.advance_index(filled);

            filled
        } else {
            0
        }
    }
}

#[derive(Debug)]
pub enum SocketError {
    Mmap(MmapError),
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
