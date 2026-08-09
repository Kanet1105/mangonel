use std::ptr::NonNull;

use mangonel_libxdp_sys::{
    xdp_desc, xsk_ring_cons, xsk_ring_cons__comp_addr, xsk_ring_cons__peek, xsk_ring_cons__release,
    xsk_ring_cons__rx_desc, xsk_ring_prod, xsk_ring_prod__fill_addr, xsk_ring_prod__reserve,
    xsk_ring_prod__submit, xsk_ring_prod__tx_desc,
};

pub fn ring_buffer(size: u32) -> Result<(Producer, Consumer), RingError> {
    if !size.is_power_of_two() {
        return Err(RingError { size });
    }

    let producer = Producer {
        head: NonNull::from(Box::leak(Box::new(xsk_ring_prod::default()))),
        size,
    };

    let consumer = Consumer {
        tail: NonNull::from(Box::leak(Box::new(xsk_ring_cons::default()))),
        size,
    };

    Ok((producer, consumer))
}

/// Ring producer handle.
///
/// Heap-allocated so the struct keeps a stable address:
/// `xsk_umem__create` saves the pointer to the fill and
/// completion rings and dereferences it again later, so the
/// allocation must not move once registered.
/// Zero-initialized here, then populated by
/// `xsk_umem__create` or `xsk_socket__create` before any
/// reads.
pub struct Producer {
    head: NonNull<xsk_ring_prod>,
    size: u32,
}

impl Drop for Producer {
    fn drop(&mut self) {
        drop(unsafe { Box::from_raw(self.head.as_ptr()) });
    }
}

impl Producer {
    #[inline]
    pub fn as_ptr(&self) -> *mut xsk_ring_prod {
        self.head.as_ptr()
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    /// Whether libxdp has populated this ring.
    ///
    /// `ring_buffer` hands out a zeroed struct;
    /// `xsk_umem__create` and `xsk_socket__create` fill
    /// it in. Every accessor below is pointer
    /// arithmetic off `ring`, so they are only meaningful —
    /// and only sound — once this returns true. Checked
    /// once by whoever registers the ring,
    /// which is what lets the accessors skip the check per
    /// slot.
    pub fn is_registered(&self) -> bool {
        // SAFETY: The allocation is live for the lifetime of self
        // and holds an initialized xsk_ring_prod. Read
        // through the raw pointer rather than a reference:
        // libxdp keeps its own pointer to this struct and writes
        // through it during umem and socket creation.
        unsafe { !(*self.as_ptr()).ring.is_null() }
    }

    #[inline]
    pub fn reserve(&self, size: u32) -> (u32, u32) {
        let mut index = 0;
        let available = unsafe { xsk_ring_prod__reserve(self.as_ptr(), size, &mut index) };
        (available, index)
    }

    /// Writes a tx descriptor into the slot at `index`.
    ///
    /// Writes by value rather than lending `&mut` into the
    /// ring: a reference returned from `&self` would
    /// claim an exclusivity this method cannot
    /// enforce — two calls with the same index (or indices
    /// `size` apart, which the mask folds together)
    /// would yield aliasing `&mut`. [`Consumer`]
    /// already reads by copy for the same reason.
    #[inline]
    pub fn set_descriptor(&self, index: u32, address: u64, length: u32) {
        // SAFETY: The ring is registered, so
        // `xsk_ring_prod__tx_desc` returns `&ring[index &
        // mask]` — a non-null pointer to a slot inside the
        // mapped ring, which this producer owns between reserve and
        // submit. The writes go through the raw pointer, so
        // no reference into the ring outlives this call.
        unsafe {
            let slot = xsk_ring_prod__tx_desc(self.as_ptr(), index);
            (*slot).addr = address;
            (*slot).len = length;
            // The kernel rejects descriptors with unknown option bits,
            // so this is zeroed explicitly rather than
            // trusting the recycled slot's residue to still
            // be zero.
            (*slot).options = 0;
        }
    }

    /// Writes a frame address into the fill-ring slot at
    /// `index`. Same write-by-value contract as
    /// [`Self::set_descriptor`].
    #[inline]
    pub fn set_fill_address(&self, index: u32, address: u64) {
        // SAFETY: As above, for the fill ring.
        unsafe { *xsk_ring_prod__fill_addr(self.as_ptr(), index) = address }
    }

    #[inline]
    pub fn submit(&self, offset: u32) {
        unsafe { xsk_ring_prod__submit(self.as_ptr(), offset) };
    }
}

/// Ring consumer handle.
///
/// Heap-allocated for the same reason as [`Producer`]: the
/// address must stay stable once libxdp has been handed a
/// pointer to it.
pub struct Consumer {
    tail: NonNull<xsk_ring_cons>,
    size: u32,
}

impl Drop for Consumer {
    fn drop(&mut self) {
        drop(unsafe { Box::from_raw(self.tail.as_ptr()) });
    }
}

impl Consumer {
    #[inline]
    pub fn as_ptr(&self) -> *mut xsk_ring_cons {
        self.tail.as_ptr()
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    /// Whether libxdp has populated this ring. Same
    /// contract as [`Producer::is_registered`].
    pub fn is_registered(&self) -> bool {
        // SAFETY: Same reasoning as Producer::is_registered.
        unsafe { !(*self.as_ptr()).ring.is_null() }
    }

    #[inline]
    pub fn peek(&self, size: u32) -> (u32, u32) {
        let mut index = 0;
        let filled = unsafe { xsk_ring_cons__peek(self.as_ptr(), size, &mut index) };
        (filled, index)
    }

    /// Copies the slot out rather than lending a reference
    /// into the ring: the kernel may write this slot
    /// again as soon as `release` hands it back, and
    /// a live `&xdp_desc` would be asserting that cannot
    /// happen.
    #[inline]
    pub fn descriptor(&self, index: u32) -> xdp_desc {
        // SAFETY: The ring is registered, so
        // `xsk_ring_cons__rx_desc` returns `&ring[index &
        // mask]` — a non-null pointer to an initialized slot
        // inside the mapped ring. The index is masked into range,
        // so no index can push it out of bounds; one
        // outside the range peek reported reads
        // a stale descriptor, which is a correctness bug and not
        // unsound.
        unsafe { xsk_ring_cons__rx_desc(self.as_ptr(), index).read() }
    }

    /// Copies the address out, for the same reason as
    /// [`Self::descriptor`].
    #[inline]
    pub fn completion_address(&self, index: u32) -> u64 {
        // SAFETY: As above, for the completion ring.
        unsafe { xsk_ring_cons__comp_addr(self.as_ptr(), index).read() }
    }

    #[inline]
    pub fn release(&self, offset: u32) {
        unsafe { xsk_ring_cons__release(self.as_ptr(), offset) };
    }
}

#[derive(Debug, thiserror::Error)]
#[error("The ring size '{size}' is not a power of two.")]
pub(crate) struct RingError {
    pub(crate) size: u32,
}
