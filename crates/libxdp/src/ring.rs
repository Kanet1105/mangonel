use crate::util::is_power_of_two;
use mangonel_libxdp_sys::{
    xdp_desc, xsk_ring_cons, xsk_ring_cons__comp_addr, xsk_ring_cons__peek, xsk_ring_cons__release,
    xsk_ring_cons__rx_desc, xsk_ring_prod, xsk_ring_prod__fill_addr, xsk_ring_prod__reserve,
    xsk_ring_prod__submit, xsk_ring_prod__tx_desc,
};
use std::mem::MaybeUninit;

pub fn ring_buffer(size: u32) -> Result<(Producer, Consumer), RingError> {
    if !is_power_of_two(size) {
        return Err(RingError::IsNotPowerOfTwo(size));
    }

    let producer = Producer {
        head: Box::new(MaybeUninit::<xsk_ring_prod>::zeroed()),
    };

    let consumer = Consumer {
        tail: Box::new(MaybeUninit::<xsk_ring_cons>::zeroed()),
    };

    Ok((producer, consumer))
}

/// Ring producer handle.
///
/// The inner `MaybeUninit` is zero-initialized here and later populated by
/// `xsk_umem__create` or `xsk_socket__create` before any reads occur.
pub struct Producer {
    head: Box<MaybeUninit<xsk_ring_prod>>,
}

// SAFETY: A Producer is exclusively owned by a single TxSocket or RxSocket and
// is never shared. The raw pointers inside xsk_ring_prod point into a
// kernel-mapped ring that is safe to access from any thread, provided there is
// no concurrent access — which is guaranteed by &mut self on mutating methods.
unsafe impl Send for Producer {}

impl Producer {
    #[inline(always)]
    pub fn as_ptr(&self) -> *mut xsk_ring_prod {
        self.head.as_ptr() as *mut _
    }

    #[inline(always)]
    pub fn reserve(&self, size: u32) -> (u32, u32) {
        let mut index = 0;
        let available = unsafe { xsk_ring_prod__reserve(self.as_ptr(), size, &mut index) };
        (available, index)
    }

    #[inline(always)]
    pub fn descriptor(&mut self, index: u32) -> &mut xdp_desc {
        unsafe {
            xsk_ring_prod__tx_desc(self.as_ptr(), index)
                .as_mut()
                .unwrap()
        }
    }

    #[inline(always)]
    pub fn fill_address(&mut self, index: u32) -> &mut u64 {
        unsafe {
            xsk_ring_prod__fill_addr(self.as_ptr(), index)
                .as_mut()
                .unwrap()
        }
    }

    #[inline(always)]
    pub fn submit(&self, offset: u32) {
        unsafe { xsk_ring_prod__submit(self.as_ptr(), offset) };
    }
}

/// Ring consumer handle.
///
/// The inner `MaybeUninit` is zero-initialized here and later populated by
/// `xsk_umem__create` or `xsk_socket__create` before any reads occur.
pub struct Consumer {
    tail: Box<MaybeUninit<xsk_ring_cons>>,
}

// SAFETY: Same reasoning as Producer — exclusively owned, no concurrent access.
unsafe impl Send for Consumer {}

impl Consumer {
    #[inline(always)]
    pub fn as_ptr(&self) -> *mut xsk_ring_cons {
        self.tail.as_ptr() as *mut _
    }

    #[inline(always)]
    pub fn peek(&self, size: u32) -> (u32, u32) {
        let mut index = 0;
        let filled = unsafe { xsk_ring_cons__peek(self.as_ptr(), size, &mut index) };
        (filled, index)
    }

    #[inline(always)]
    pub fn descriptor(&self, index: u32) -> &xdp_desc {
        unsafe {
            xsk_ring_cons__rx_desc(self.as_ptr(), index)
                .as_ref()
                .unwrap()
        }
    }

    #[inline(always)]
    pub fn completion_address(&self, index: u32) -> &u64 {
        unsafe {
            xsk_ring_cons__comp_addr(self.as_ptr(), index)
                .as_ref()
                .unwrap()
        }
    }

    #[inline(always)]
    pub fn release(&self, offset: u32) {
        unsafe { xsk_ring_cons__release(self.as_ptr(), offset) };
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RingError {
    #[error("The ring size '{0}' is not the power of two.")]
    IsNotPowerOfTwo(u32),
    #[error("Failed to initialize the ring buffer.")]
    Initialize,
}
