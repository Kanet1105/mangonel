use crate::{
    descriptor::Descriptor,
    mmap::{Mmap, MmapError},
    ring::{Consumer, Producer, RingError, ring_buffer},
    umem::{Umem, UmemError},
    util,
};
use libc::{MSG_DONTWAIT, POLLIN, poll, pollfd, sendto};
use mangonel_libxdp_sys::{
    XDP_COPY, XDP_ZEROCOPY, XSK_RING_PROD__DEFAULT_NUM_DESCS, XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    XSK_UMEM__DEFAULT_FRAME_SIZE, xsk_socket, xsk_socket__create, xsk_socket__delete,
    xsk_socket__fd, xsk_socket_config, xsk_socket_config__bindgen_ty_1,
};
use std::{
    ffi::{CString, NulError},
    ptr::{NonNull, null_mut},
    sync::{
        Arc,
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
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
    ) -> Result<(TxSocket, RxSocket, Umem), SocketError> {
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
    ) -> Result<(TxSocket, RxSocket, Umem), SocketError> {
        // Increase the maximum size of the process's virtual memory.
        util::setrlimit();

        // Initialize the memory map.
        let length = (frame_size + frame_headroom_size) * ring_size;
        let mmap = Mmap::new(length as usize, use_hugetlb)?;

        // Initialize XDP UMEM.
        let (umem, fill_ring, completion_ring) =
            Umem::new(mmap, frame_size, frame_headroom_size, ring_size)?;

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

        let (tx_ring, rx_ring) = ring_buffer(ring_size)?;

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
            inner: SocketInner(NonNull::new(socket).ok_or(SocketError::SocketIsNull)?).into(),
        };

        // Prefill the descriptor buffer.
        let (descriptor_writer, descriptor_reader) = mpsc::sync_channel(ring_size as usize);
        (0..ring_size).for_each(|descriptor_index| {
            let address = descriptor_index * (frame_size + frame_headroom_size);
            descriptor_writer.try_send(address as u64).unwrap();
        });

        let tx_socket = TxSocket {
            socket: socket.clone(),
            ring_size,
            completion_ring,
            tx_ring,
            descriptor_writer,
        };
        let rx_socket = RxSocket {
            socket,
            ring_size,
            fill_ring,
            rx_ring,
            descriptor_reader,
        };
        Ok((tx_socket, rx_socket, umem))
    }

    #[inline(always)]
    pub fn socket_fd(&self) -> i32 {
        unsafe { xsk_socket__fd(self.inner.0.as_ptr()) }
    }
}
pub struct TxSocket {
    socket: Socket,
    ring_size: u32,
    completion_ring: Consumer,
    tx_ring: Producer,
    descriptor_writer: SyncSender<u64>,
}

impl TxSocket {
    #[inline(always)]
    pub fn write(&mut self, buffer: &[Descriptor]) -> u32 {
        let size = self.ring_size.max(buffer.len() as u32);
        let (tx_available, tx_index) = self.tx_ring.reserve(size);
        let mut offset: u32 = 0;
        while offset < tx_available {
            let descriptor_mut = self.tx_ring.descriptor(tx_index + offset);
            descriptor_mut.addr = buffer[offset as usize].address;
            descriptor_mut.len = buffer[offset as usize].length;
            offset += 1;
        }
        self.tx_ring.submit(offset);
        self.send();
        self.complete(size);
        offset
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
        let (filled, index) = self.completion_ring.peek(size);
        let mut offset: u32 = 0;
        while offset < filled {
            let descriptor = self.completion_ring.descriptor(index + offset);
            match self.descriptor_writer.try_send(descriptor.addr) {
                Err(TrySendError::Full(_)) => break,
                Err(TrySendError::Disconnected(_)) => {
                    panic!("Descriptor sender disconnected. This is a bug.");
                }
                Ok(_) => offset += 1,
            }
        }
        self.completion_ring.release(offset);
    }
}

pub struct RxSocket {
    socket: Socket,
    ring_size: u32,
    fill_ring: Producer,
    rx_ring: Consumer,
    descriptor_reader: Receiver<u64>,
}

impl RxSocket {
    #[inline(always)]
    pub fn read(&mut self, buffer: &mut [Descriptor]) -> u32 {
        let size = self.ring_size.max(buffer.len() as u32);
        self.fill(size);
        self.poll();
        let (availble, index) = self.rx_ring.peek(size);
        let mut offset: u32 = 0;
        while offset < availble {
            let descriptor = self.rx_ring.descriptor(index + offset);
            buffer[offset as usize].address = descriptor.addr;
            buffer[offset as usize].length = descriptor.len;
            offset += 1;
        }
        self.rx_ring.release(offset);
        offset
    }

    #[inline(always)]
    fn fill(&mut self, size: u32) {
        let (available, index) = self.fill_ring.reserve(size);
        let mut offset: u32 = 0;
        while offset < available {
            let descriptor_address = match self.descriptor_reader.try_recv() {
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    panic!("{:?}", "Descriptor receiver disconnected. This is a bug.")
                }
                Ok(address) => address,
            };
            let descriptor = self.fill_ring.fill_address(index + offset);
            *descriptor = descriptor_address;
            offset += 1;
        }
        self.fill_ring.submit(offset);
    }

    #[inline(always)]
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
pub enum SocketError {
    #[error(transparent)]
    Mmap(#[from] MmapError),
    #[error(transparent)]
    Ring(#[from] RingError),
    #[error(transparent)]
    Umem(#[from] UmemError),
    #[error("Interface name contains null character(s): {0}")]
    InvalidInterfaceName(NulError),
    #[error("Failed to initialize socket: {0}")]
    Initialize(std::io::Error),
    #[error("Socket returned Null. This is a bug.")]
    SocketIsNull,
}
