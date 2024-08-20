use std::{
    ffi::c_void,
    ptr::{null_mut, NonNull},
};

use libc::{
    mmap, munmap, MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE,
};

#[derive(Debug)]
pub struct Mmap {
    address: NonNull<c_void>,
    length: usize,
}

impl Drop for Mmap {
    fn drop(&mut self) {
        let value = unsafe { munmap(self.address.as_ptr(), self.length) };
        if value.is_negative() {
            panic!("{:?}", MmapError::Free(std::io::Error::last_os_error()));
        }
    }
}

impl Mmap {
    pub fn new(
        frame_size: u32,
        headroom_size: u32,
        descriptor_count: u32,
        hugetlb: bool,
    ) -> Result<Self, MmapError> {
        let frame_size = frame_size
            .checked_add(headroom_size)
            .ok_or(MmapError::InvalidFrameSize(frame_size, headroom_size))?;
        let length = frame_size
            .checked_mul(descriptor_count)
            .ok_or(MmapError::InvalidLength(frame_size, descriptor_count))?
            as usize;

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
    InvalidFrameSize(u32, u32),
    InvalidLength(u32, u32),
    Initialize(std::io::Error),
    MmapIsNull,
    Free(std::io::Error),
}

impl std::fmt::Debug for MmapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFrameSize(frame_size, headroom_size) => write!(
                f,
                "frame size ({}) + headroom size ({}) exceeds u32::MAX.",
                frame_size, headroom_size
            ),
            Self::InvalidLength(frame_size, descriptor_count) => write!(
                f,
                "frame size ({}) * descriptor count ({}) exceeds u32::MAX.",
                frame_size, descriptor_count
            ),
            Self::Initialize(error) => write!(f, "Failed to initialize `Mmap`: {:?}", error),
            Self::MmapIsNull => write!(f, "Mmap address is null"),
            Self::Free(error) => write!(f, ""),
        }
    }
}

impl std::fmt::Display for MmapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for MmapError {}
