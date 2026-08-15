use std::ptr::NonNull;

use mangonel_libxdp_sys::{
    XSK_RING_PROD__DEFAULT_NUM_DESCS, xdp_desc, xsk_prod_nb_free, xsk_ring_cons,
    xsk_ring_cons__comp_addr, xsk_ring_cons__peek, xsk_ring_cons__release, xsk_ring_cons__rx_desc,
    xsk_ring_prod, xsk_ring_prod__fill_addr, xsk_ring_prod__reserve, xsk_ring_prod__submit,
    xsk_ring_prod__tx_desc,
};

pub const DEFAULT_RING_SIZE: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS;

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

/// Ring producer handle. Heap-allocated for a stable
/// address: libxdp saves the pointer at registration and
/// dereferences it later. Zeroed until then.
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
    pub fn as_ptr(&self) -> *mut xsk_ring_prod {
        self.head.as_ptr()
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    /// Whether libxdp has populated this ring. The
    /// accessors below are only sound once true; checked
    /// once by whoever registers the ring.
    pub fn is_registered(&self) -> bool {
        // SAFETY: The allocation is live for self's lifetime. Read
        // through the raw pointer: libxdp writes through its
        // own pointer to this struct.
        unsafe { !(*self.as_ptr()).ring.is_null() }
    }

    /// Free slots in the ring, refreshing the cached
    /// consumer index when fewer than `want` are cached.
    /// May return more than `want`.
    pub fn free(&self, want: u32) -> u32 {
        unsafe { xsk_prod_nb_free(self.as_ptr(), want) }
    }

    /// All-or-nothing: grants `size` slots or none. Every
    /// claim moves the cached producer index at once and
    /// must be matched by a commit of exactly the granted
    /// count — committing less desyncs the ring for good.
    ///
    /// Wraps `xsk_ring_prod__reserve`.
    pub fn claim(&self, size: u32) -> (u32, u32) {
        let mut index = 0;
        let available = unsafe { xsk_ring_prod__reserve(self.as_ptr(), size, &mut index) };

        (available, index)
    }

    /// Writes a tx descriptor into the slot at `index`. By
    /// value, not `&mut` into the ring: two calls with
    /// aliasing indices would otherwise yield aliasing
    /// `&mut`.
    pub fn write_descriptor(&self, index: u32, address: u64, length: u32) {
        // SAFETY: The ring is registered; the index is masked into
        // range, and the slot is owned by this producer
        // between claim and commit. No reference outlives
        // the call.
        unsafe {
            let slot = xsk_ring_prod__tx_desc(self.as_ptr(), index);
            (*slot).addr = address;
            (*slot).len = length;
            // The kernel rejects unknown option bits; recycled slot
            // residue is not trusted to be zero.
            (*slot).options = 0;
        }
    }

    /// Writes a fill-ring address into the slot at `index`.
    /// Same contract as [`Self::write_descriptor`].
    pub fn write_fill_address(&self, index: u32, address: u64) {
        // SAFETY: As above, for the fill ring.
        unsafe { *xsk_ring_prod__fill_addr(self.as_ptr(), index) = address }
    }

    /// Publishes the claimed slots to the consumer side.
    ///
    /// Wraps `xsk_ring_prod__submit`.
    pub fn commit(&self, offset: u32) {
        unsafe { xsk_ring_prod__submit(self.as_ptr(), offset) };
    }
}

/// Ring consumer handle. Heap-allocated for the same
/// reason as [`Producer`].
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
    pub fn as_ptr(&self) -> *mut xsk_ring_cons {
        self.tail.as_ptr()
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    /// As [`Producer::is_registered`].
    pub fn is_registered(&self) -> bool {
        // SAFETY: As Producer::is_registered.
        unsafe { !(*self.as_ptr()).ring.is_null() }
    }

    /// Up to `size`: grants the filled run and advances the
    /// cached consumer index — a claim, not a look; two
    /// claims return different windows. Every claim must be
    /// matched by a commit of exactly the granted count.
    ///
    /// Wraps `xsk_ring_cons__peek`.
    pub fn claim(&self, size: u32) -> (u32, u32) {
        let mut index = 0;
        let filled = unsafe { xsk_ring_cons__peek(self.as_ptr(), size, &mut index) };

        (filled, index)
    }

    /// Copies the slot out: the kernel may rewrite it as
    /// soon as `commit` hands it back.
    pub fn read_descriptor(&self, index: u32) -> xdp_desc {
        // SAFETY: The ring is registered and the index is masked
        // into range; an index beyond what claim reported
        // reads stale data, which is a bug but not unsound.
        unsafe { xsk_ring_cons__rx_desc(self.as_ptr(), index).read() }
    }

    /// Copies the address out; as [`Self::read_descriptor`].
    pub fn read_completion_address(&self, index: u32) -> u64 {
        // SAFETY: As above, for the completion ring.
        unsafe { xsk_ring_cons__comp_addr(self.as_ptr(), index).read() }
    }

    /// Hands the claimed slots back to the kernel side.
    ///
    /// Wraps `xsk_ring_cons__release`.
    pub fn commit(&self, offset: u32) {
        unsafe { xsk_ring_cons__release(self.as_ptr(), offset) };
    }
}

#[derive(Debug, thiserror::Error)]
#[error("The ring size '{size}' is not a power of two.")]
pub(crate) struct RingError {
    pub(crate) size: u32,
}
