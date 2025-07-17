use libc::{
    mmap, munmap, MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE,
};
use std::{
    ffi::c_void,
    ptr::{null_mut, NonNull},
};

#[derive(Debug)]
pub struct Mmap {
    address: NonNull<c_void>,
    length: usize,
}

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

    #[inline(always)]
    pub fn as_ptr(&self) -> *mut c_void {
        self.address.as_ptr()
    }

    #[inline(always)]
    pub fn offset(&self, count: isize) -> *mut c_void {
        unsafe { self.as_ptr().offset(count) }
    }

    #[inline(always)]
    pub fn length(&self) -> usize {
        self.length
    }
}

pub enum MmapError {
    Initialize(std::io::Error),
    MmapIsNull,
    Free(std::io::Error),
}

impl std::fmt::Debug for MmapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl std::fmt::Display for MmapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initialize(error) => write!(f, "Failed to initialize Mmap: {error}"),
            Self::MmapIsNull => write!(f, "Mmap returned null. This is a bug."),
            Self::Free(error) => write!(f, "Failed to free Mmap: {error}"),
        }
    }
}

impl std::error::Error for MmapError {}
