use libc::{
    MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE, mmap, munmap,
};
use std::{
    ffi::c_void,
    ptr::{NonNull, null_mut},
};

#[derive(Debug)]
pub struct Mmap {
    address: NonNull<c_void>,
    length: usize,
}

// SAFETY: The mmap'd region is process-wide virtual memory with no thread
// affinity in Linux. The address is stable for the lifetime of the Mmap.
// Concurrent access to non-overlapping frame regions (TX vs RX) is safe.
unsafe impl Send for Mmap {}
unsafe impl Sync for Mmap {}

impl Drop for Mmap {
    /// # Panics
    ///
    /// The program panics when it fails to clean up. This is not a problem
    /// while it is running and each [`RxSocket`] and [`TxSocket`] is referring
    /// to it. However, we want to see the error when it happens.
    fn drop(&mut self) {
        let value = unsafe { munmap(self.address.as_ptr(), self.length) };
        if value.is_negative() {
            panic!("{:?}", MmapError::Free(std::io::Error::last_os_error()));
        }
    }
}

impl Mmap {
    pub fn new(length: usize, hugetlb: bool) -> Result<Self, MmapError> {
        let protection_mode = PROT_READ | PROT_WRITE;
        let mut flags = MAP_PRIVATE | MAP_ANONYMOUS;
        if hugetlb {
            flags |= MAP_HUGETLB;
        }

        let address = unsafe { mmap(null_mut(), length, protection_mode, flags, -1, 0) };
        if address == MAP_FAILED {
            return Err(MmapError::Initialize(std::io::Error::last_os_error()));
        }

        Ok(Self {
            address: NonNull::new(address).ok_or(MmapError::MmapIsNull)?,
            length,
        })
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut c_void {
        self.address.as_ptr()
    }

    #[inline]
    pub fn length(&self) -> usize {
        self.length
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MmapError {
    #[error("Failed to initialize Mmap: {0}")]
    Initialize(std::io::Error),
    #[error("Mmap returned Null. This is a bug.")]
    MmapIsNull,
    #[error("Failed to free Mmap: {0}")]
    Free(std::io::Error),
}
