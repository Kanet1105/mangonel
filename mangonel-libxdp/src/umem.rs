use std::{
    ffi::c_void,
    io,
    ptr::{NonNull, null_mut},
    sync::Arc,
};

use libc::{
    MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE, mmap, munmap,
};
use mangonel_libxdp_sys::{
    xsk_umem, xsk_umem__create, xsk_umem__delete, xsk_umem__get_data, xsk_umem_config,
};

use crate::{
    ring::{Consumer, Producer},
    util::{MIN_FRAME_SIZE, max_frame_size},
};

struct UmemArea {
    address: NonNull<c_void>,
    length: usize,
}

impl Drop for UmemArea {
    fn drop(&mut self) {
        let value = unsafe { munmap(self.address.as_ptr(), self.length) };
        if value.is_negative() {
            panic!(
                "munmap() returned {}: {}.",
                value,
                io::Error::from_raw_os_error(-value)
            );
        }
    }
}

impl UmemArea {
    fn new(length: usize, use_hugetlb: bool) -> Result<Self, UmemError> {
        let protection_mode = PROT_READ | PROT_WRITE;
        let mut flag = MAP_PRIVATE | MAP_ANONYMOUS;
        if use_hugetlb {
            flag |= MAP_HUGETLB;
        }

        let address = unsafe { mmap(null_mut(), length, protection_mode, flag, -1, 0) };
        if address == MAP_FAILED {
            return Err(UmemError::MapMemory(io::Error::last_os_error()));
        }

        let area = Self {
            address: NonNull::new(address).expect("mmap() returned a null pointer. This is a bug."),
            length,
        };
        Ok(area)
    }
}

pub struct Umem {
    inner: Arc<UmemInner>,
}

impl Clone for Umem {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Umem {
    pub(crate) fn new(
        frame_size: u32,
        frame_headroom: u32,
        frame_count: u32,
        use_hugetlb: bool,
        fill_ring: &Producer,
        completion_ring: &Consumer,
    ) -> Result<Self, UmemError> {
        if !frame_size.is_power_of_two() {
            return Err(UmemError::FrameSizeNotPowerOfTwo { frame_size });
        }

        let max_frame_size = max_frame_size();
        if frame_size < MIN_FRAME_SIZE || frame_size > max_frame_size {
            return Err(UmemError::FrameSizeOutOfRange {
                frame_size,
                min: MIN_FRAME_SIZE,
                max: max_frame_size,
            });
        }

        let length = (frame_size as usize)
            .checked_mul(frame_count as usize)
            .ok_or(UmemError::AreaTooLarge)?;

        let umem_area = UmemArea::new(length, use_hugetlb)?;

        let umem_config = xsk_umem_config {
            fill_size: fill_ring.size(),
            comp_size: completion_ring.size(),
            frame_size,
            frame_headroom,
            flags: 0,
        };

        let mut umem_ptr = null_mut::<xsk_umem>();
        let value = unsafe {
            xsk_umem__create(
                &mut umem_ptr,
                umem_area.address.as_ptr(),
                u64::try_from(umem_area.length)
                    .expect("Umem area length exceeds u64. This is a bug."),
                fill_ring.as_ptr(),
                completion_ring.as_ptr(),
                &umem_config,
            )
        };
        if value.is_negative() {
            return Err(UmemError::Initialize(io::Error::from_raw_os_error(-value)));
        }

        assert!(
            fill_ring.is_registered() && completion_ring.is_registered(),
            "xsk_umem__create left a ring unpopulated. This is a bug."
        );

        let umem = Self {
            inner: UmemInner {
                umem: NonNull::new(umem_ptr)
                    .expect("xsk_umem__create() returned a null pointer. This is a bug."),
                area: umem_area,
                config: umem_config,
            }
            .into(),
        };
        Ok(umem)
    }

    #[inline]
    pub(crate) fn as_ptr(&self) -> *mut xsk_umem {
        self.inner.umem.as_ptr()
    }

    #[inline]
    pub(crate) fn config(&self) -> &xsk_umem_config {
        &self.inner.config
    }

    #[inline]
    pub(crate) fn get_data(&self, address: u64, length: usize) -> Option<*mut c_void> {
        let start = usize::try_from(address).ok()?;
        if start.checked_add(length)? > self.inner.area.length {
            return None;
        }
        Some(unsafe { xsk_umem__get_data(self.inner.area.address.as_ptr(), address) })
    }
}

struct UmemInner {
    umem: NonNull<xsk_umem>,
    area: UmemArea,
    config: xsk_umem_config,
}

impl Drop for UmemInner {
    fn drop(&mut self) {
        let value = unsafe { xsk_umem__delete(self.umem.as_ptr()) };
        if value.is_negative() {
            panic!(
                "Failed to free Umem: {}",
                io::Error::from_raw_os_error(-value)
            );
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UmemError {
    #[error("The frame size '{frame_size}' is not a power of two.")]
    FrameSizeNotPowerOfTwo { frame_size: u32 },
    #[error("The frame size '{frame_size}' is outside the supported range {min}..={max}.")]
    FrameSizeOutOfRange { frame_size: u32, min: u32, max: u32 },
    #[error("The umem area is too large to address.")]
    AreaTooLarge,
    #[error("Failed to map memory: {0}")]
    MapMemory(io::Error),
    #[error("Failed to initialize Umem: {0}")]
    Initialize(io::Error),
}
