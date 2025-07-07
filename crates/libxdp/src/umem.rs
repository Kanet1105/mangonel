use crate::{
    mmap::Mmap,
    ring::{CompletionRing, FillRing, RingError},
};
use mangonel_libxdp_sys::{
    xsk_umem, xsk_umem__create, xsk_umem__delete, xsk_umem__get_data, xsk_umem_config,
};
use std::{
    ffi::c_void,
    ptr::{null_mut, NonNull},
    sync::Arc,
};

#[derive(Debug)]
pub struct Umem {
    inner: Arc<UmemInner>,
}

#[derive(Debug)]
struct UmemInner {
    umem: NonNull<xsk_umem>,
    umem_config: xsk_umem_config,
    mmap: Mmap,
}

impl Drop for UmemInner {
    /// # Panics
    ///
    /// The program panics when it fails to clean up. This is not a problem
    /// while it is running and either [`RxSocket`] and [`TxSocket`] is
    /// referring to it. However, we want to see the error when it happens.
    fn drop(&mut self) {
        let value = unsafe { xsk_umem__delete(self.umem.as_ptr()) };
        if value.is_negative() {
            panic!(
                "{:?}",
                UmemError::Free(std::io::Error::from_raw_os_error(-value))
            );
        }
    }
}

unsafe impl Send for Umem {}

impl Clone for Umem {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Umem {
    pub fn new(
        mmap: Mmap,
        frame_size: u32,
        frame_headroom_size: u32,
        ring_size: u32,
    ) -> Result<(Self, FillRing, CompletionRing), UmemError> {
        let mut umem_ptr = null_mut::<xsk_umem>();
        let fill_ring = FillRing::new(ring_size).map_err(UmemError::Ring)?;
        let completion_ring = CompletionRing::new(ring_size).map_err(UmemError::Ring)?;
        let umem_config = xsk_umem_config {
            fill_size: ring_size,
            comp_size: ring_size,
            frame_size,
            frame_headroom: frame_headroom_size,
            flags: 0,
        };

        let value = unsafe {
            xsk_umem__create(
                &mut umem_ptr,
                mmap.as_ptr(),
                mmap.length().try_into().unwrap(),
                fill_ring.as_ptr(),
                completion_ring.as_ptr(),
                &umem_config,
            )
        };
        if value.is_negative() {
            return Err(UmemError::Initialize(std::io::Error::from_raw_os_error(
                -value,
            )));
        }

        let umem = Self {
            inner: UmemInner {
                umem: NonNull::new(umem_ptr).ok_or(UmemError::UmemIsNull)?,
                umem_config,
                mmap,
            }
            .into(),
        };

        Ok((umem, fill_ring, completion_ring))
    }

    #[inline(always)]
    pub fn umem_config(&self) -> &xsk_umem_config {
        &self.inner.umem_config
    }

    #[inline(always)]
    pub fn mmap(&self) -> &Mmap {
        &self.inner.mmap
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *mut xsk_umem {
        self.inner.umem.as_ptr()
    }

    #[inline(always)]
    pub fn get_data(&self, address: u64) -> *mut c_void {
        unsafe { xsk_umem__get_data(self.inner.mmap.as_ptr(), address) }
    }
}

#[derive(Debug)]
pub enum UmemError {
    Ring(RingError),
    Initialize(std::io::Error),
    UmemIsNull,
    Free(std::io::Error),
}

impl std::fmt::Display for UmemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for UmemError {}
