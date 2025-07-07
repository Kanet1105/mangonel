use crate::util::is_power_of_two;
use mangonel_libxdp_sys::{
    xdp_desc, xsk_ring_cons, xsk_ring_cons__comp_addr, xsk_ring_cons__peek, xsk_ring_cons__release,
    xsk_ring_cons__rx_desc, xsk_ring_prod, xsk_ring_prod__fill_addr, xsk_ring_prod__reserve,
    xsk_ring_prod__submit, xsk_ring_prod__tx_desc,
};
use std::{
    mem::MaybeUninit,
    ptr::NonNull,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

pub trait BufferReader<T: Copy> {
    /// Returns the number of filled indices and the current index.
    fn filled(&self, size: u32) -> (u32, u32);

    fn get(&self, index: u32) -> &T;

    fn advance_index(&mut self, offset: u32);
}

pub trait BufferWriter<T: Copy> {
    /// Returns the number of available indices and the current index.
    fn available(&self, size: u32) -> (u32, u32);

    fn get_mut(&mut self, index: u32) -> &mut T;

    fn advance_index(&mut self, offset: u32);
}

pub struct RingBuffer<T: Copy> {
    inner: Arc<RingBufferInner<T>>,
}

struct RingBufferInner<T: Copy> {
    buffer: NonNull<Vec<T>>,
    capacity: u32,
    head: AtomicU32,
    tail: AtomicU32,
}

unsafe impl<T: Copy> Send for RingBuffer<T> {}

impl<T: Copy> Clone for RingBuffer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: Copy> RingBuffer<T> {
    pub fn with_capacity(
        capacity: u32,
    ) -> Result<(RingBufferWriter<T>, RingBufferReader<T>), RingError> {
        let mut buffer = Vec::<T>::with_capacity(capacity as usize);
        let t = unsafe { MaybeUninit::<T>::zeroed().assume_init() };
        (0..capacity).for_each(|_| buffer.push(t));
        let buffer_ptr = Box::into_raw(Box::new(buffer));

        let ring_buffer = Self {
            inner: RingBufferInner {
                buffer: NonNull::new(buffer_ptr).ok_or(RingError::Initialize)?,
                capacity,
                head: 0.into(),
                tail: 0.into(),
            }
            .into(),
        };

        let writer = RingBufferWriter::new(ring_buffer.clone());
        let reader = RingBufferReader::new(ring_buffer);
        Ok((writer, reader))
    }

    pub fn from_vec(vec: Vec<T>) -> Result<(RingBufferWriter<T>, RingBufferReader<T>), RingError> {
        let capacity = vec.len() as u32;
        let buffer_ptr = Box::into_raw(Box::new(vec));
        let ring_buffer = Self {
            inner: RingBufferInner {
                buffer: NonNull::new(buffer_ptr).ok_or(RingError::Initialize)?,
                capacity,
                head: 0.into(),
                tail: capacity.into(),
            }
            .into(),
        };

        let writer = RingBufferWriter::new(ring_buffer.clone());
        let reader = RingBufferReader::new(ring_buffer);
        Ok((writer, reader))
    }

    #[inline(always)]
    pub fn buffer_mut(&mut self) -> &mut Vec<T> {
        unsafe { self.inner.buffer.as_ptr().as_mut().unwrap() }
    }

    #[inline(always)]
    pub fn buffer_ref(&self) -> &Vec<T> {
        unsafe { self.inner.buffer.as_ref() }
    }

    #[inline(always)]
    pub fn capacity(&self) -> u32 {
        self.inner.capacity
    }

    #[inline(always)]
    pub fn head_index(&self) -> u32 {
        self.inner.head.load(Ordering::SeqCst)
    }

    #[inline(always)]
    pub fn tail_index(&self) -> u32 {
        self.inner.tail.load(Ordering::SeqCst)
    }

    #[inline(always)]
    fn advance_head_index(&self, offset: u32) -> u32 {
        self.inner.head.fetch_add(offset, Ordering::SeqCst)
    }

    #[inline(always)]
    fn advance_tail_index(&self, offset: u32) -> u32 {
        self.inner.tail.fetch_add(offset, Ordering::SeqCst)
    }
}

pub struct RingBufferReader<T: Copy> {
    ring_buffer: RingBuffer<T>,
}

impl<T: Copy> BufferReader<T> for RingBufferReader<T> {
    #[inline(always)]
    fn filled(&self, size: u32) -> (u32, u32) {
        let head_index = self.ring_buffer.head_index();
        let tail_index = self.ring_buffer.tail_index();

        let filled = head_index.wrapping_sub(tail_index);
        if filled > size {
            (size, tail_index)
        } else {
            (filled, tail_index)
        }
    }

    #[inline(always)]
    fn get(&self, index: u32) -> &T {
        let index = index % self.ring_buffer.capacity();
        let ring_buffer = self.ring_buffer.buffer_ref();
        ring_buffer.get(index as usize).unwrap()
    }

    #[inline(always)]
    fn advance_index(&mut self, offset: u32) {
        self.ring_buffer.advance_tail_index(offset);
    }
}

impl<T: Copy> RingBufferReader<T> {
    fn new(ring_buffer: RingBuffer<T>) -> Self {
        Self { ring_buffer }
    }
}

pub struct RingBufferWriter<T: Copy> {
    ring_buffer: RingBuffer<T>,
}

impl<T: Copy> BufferWriter<T> for RingBufferWriter<T> {
    #[inline(always)]
    fn available(&self, size: u32) -> (u32, u32) {
        let head_index = self.ring_buffer.head_index();
        let tail_index = self.ring_buffer.tail_index();
        let capacity = self.ring_buffer.capacity();

        let available = capacity - head_index.wrapping_sub(tail_index);
        if available > size {
            (size, head_index)
        } else {
            (available, head_index)
        }
    }

    #[inline(always)]
    fn get_mut(&mut self, index: u32) -> &mut T {
        let index = index % self.ring_buffer.capacity();
        let ring_buffer = self.ring_buffer.buffer_mut();
        ring_buffer.get_mut(index as usize).unwrap()
    }

    #[inline(always)]
    fn advance_index(&mut self, offset: u32) {
        self.ring_buffer.advance_head_index(offset);
    }
}

impl<T: Copy> RingBufferWriter<T> {
    fn new(ring_buffer: RingBuffer<T>) -> Self {
        Self { ring_buffer }
    }
}

pub struct FillRing {
    ring_buffer: NonNull<xsk_ring_prod>,
}

unsafe impl Send for FillRing {}

impl BufferWriter<u64> for FillRing {
    #[inline(always)]
    fn available(&self, size: u32) -> (u32, u32) {
        let mut index = 0;
        let available = unsafe { xsk_ring_prod__reserve(self.as_ptr(), size, &mut index) };
        (available, index)
    }

    #[inline(always)]
    fn get_mut(&mut self, index: u32) -> &mut u64 {
        unsafe {
            xsk_ring_prod__fill_addr(self.as_ptr(), index)
                .as_mut()
                .unwrap()
        }
    }

    #[inline(always)]
    fn advance_index(&mut self, offset: u32) {
        unsafe { xsk_ring_prod__submit(self.as_ptr(), offset) }
    }
}

impl FillRing {
    pub fn new(size: u32) -> Result<Self, RingError> {
        if !is_power_of_two(size) {
            return Err(RingError::IsNotPowerOfTwo(size));
        }

        let ring = unsafe { MaybeUninit::<xsk_ring_prod>::zeroed().assume_init() };
        let ring_ptr = Box::into_raw(Box::new(ring));
        Ok(Self {
            ring_buffer: NonNull::new(ring_ptr).ok_or(RingError::Initialize)?,
        })
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *mut xsk_ring_prod {
        self.ring_buffer.as_ptr()
    }
}

pub struct CompletionRing {
    ring_buffer: NonNull<xsk_ring_cons>,
}

unsafe impl Send for CompletionRing {}

impl BufferReader<u64> for CompletionRing {
    #[inline(always)]
    fn filled(&self, size: u32) -> (u32, u32) {
        let mut index = 0;
        let filled = unsafe { xsk_ring_cons__peek(self.as_ptr(), size, &mut index) };
        (filled, index)
    }

    #[inline(always)]
    fn get(&self, index: u32) -> &u64 {
        unsafe {
            xsk_ring_cons__comp_addr(self.as_ptr(), index)
                .as_ref()
                .unwrap()
        }
    }

    #[inline(always)]
    fn advance_index(&mut self, offset: u32) {
        unsafe { xsk_ring_cons__release(self.as_ptr(), offset) }
    }
}

impl CompletionRing {
    pub fn new(size: u32) -> Result<Self, RingError> {
        if !is_power_of_two(size) {
            return Err(RingError::IsNotPowerOfTwo(size));
        }

        let ring = unsafe { MaybeUninit::<xsk_ring_cons>::zeroed().assume_init() };
        let ring_ptr = Box::into_raw(Box::new(ring));
        Ok(Self {
            ring_buffer: NonNull::new(ring_ptr).ok_or(RingError::Initialize)?,
        })
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *mut xsk_ring_cons {
        self.ring_buffer.as_ptr()
    }
}

pub struct TxRing {
    ring_buffer: NonNull<xsk_ring_prod>,
}

unsafe impl Send for TxRing {}

impl BufferWriter<xdp_desc> for TxRing {
    #[inline(always)]
    fn available(&self, size: u32) -> (u32, u32) {
        let mut index = 0;
        let available = unsafe { xsk_ring_prod__reserve(self.as_ptr(), size, &mut index) };
        (available, index)
    }

    #[inline(always)]
    fn get_mut(&mut self, index: u32) -> &mut xdp_desc {
        unsafe {
            xsk_ring_prod__tx_desc(self.as_ptr(), index)
                .as_mut()
                .unwrap()
        }
    }

    #[inline(always)]
    fn advance_index(&mut self, offset: u32) {
        unsafe { xsk_ring_prod__submit(self.as_ptr(), offset) }
    }
}

impl TxRing {
    pub fn new(size: u32) -> Result<Self, RingError> {
        if !is_power_of_two(size) {
            return Err(RingError::IsNotPowerOfTwo(size));
        }

        let ring = unsafe { MaybeUninit::<xsk_ring_prod>::zeroed().assume_init() };
        let ring_ptr = Box::into_raw(Box::new(ring));
        Ok(Self {
            ring_buffer: NonNull::new(ring_ptr).ok_or(RingError::Initialize)?,
        })
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *mut xsk_ring_prod {
        self.ring_buffer.as_ptr()
    }
}

pub struct RxRing {
    ring_buffer: NonNull<xsk_ring_cons>,
}

unsafe impl Send for RxRing {}

impl BufferReader<xdp_desc> for RxRing {
    #[inline(always)]
    fn filled(&self, size: u32) -> (u32, u32) {
        let mut index = 0;
        let filled = unsafe { xsk_ring_cons__peek(self.as_ptr(), size, &mut index) };
        (filled, index)
    }

    #[inline(always)]
    fn get(&self, index: u32) -> &xdp_desc {
        unsafe {
            xsk_ring_cons__rx_desc(self.as_ptr(), index)
                .as_ref()
                .unwrap()
        }
    }

    #[inline(always)]
    fn advance_index(&mut self, offset: u32) {
        unsafe { xsk_ring_cons__release(self.as_ptr(), offset) }
    }
}

impl RxRing {
    pub fn new(size: u32) -> Result<Self, RingError> {
        if !is_power_of_two(size) {
            return Err(RingError::IsNotPowerOfTwo(size));
        }

        let ring = unsafe { MaybeUninit::<xsk_ring_cons>::zeroed().assume_init() };
        let ring_ptr = Box::into_raw(Box::new(ring));
        Ok(Self {
            ring_buffer: NonNull::new(ring_ptr).ok_or(RingError::Initialize)?,
        })
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *mut xsk_ring_cons {
        self.ring_buffer.as_ptr()
    }
}

pub enum RingError {
    IsNotPowerOfTwo(u32),
    Initialize,
}

impl std::fmt::Debug for RingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::fmt::Display for RingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IsNotPowerOfTwo(size) => {
                write!(f, "The ring size '{}' is not the power of two.", size)
            }
            Self::Initialize => write!(f, "Failed to initialize the ring buffer."),
        }
    }
}

impl std::error::Error for RingError {}
