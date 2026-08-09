use std::{
    ffi::c_void,
    io,
    ptr::{NonNull, null_mut},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use libc::{
    _SC_PAGE_SIZE, MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE,
    mmap, munmap, sysconf,
};
use mangonel_libxdp_sys::{
    XSK_UMEM__DEFAULT_FRAME_HEADROOM, XSK_UMEM__DEFAULT_FRAME_SIZE, xsk_umem, xsk_umem__create,
    xsk_umem__delete, xsk_umem__get_data, xsk_umem_config,
};

use crate::ring::{Consumer, Producer};

// Also the minimum frame size.
pub const DEFAULT_FRAME_SIZE: u32 = XSK_UMEM__DEFAULT_FRAME_SIZE;

pub const DEFAULT_FRAME_HEADROOM: u32 = XSK_UMEM__DEFAULT_FRAME_HEADROOM;

/// The huge page size in bytes, from /proc/meminfo. `None`
/// when the kernel exposes no huge page support.
fn huge_page_size() -> Option<usize> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = meminfo.lines().find(|l| l.starts_with("Hugepagesize:"))?;
    let kilobytes = line.split_whitespace().nth(1)?.parse::<usize>().ok()?;
    kilobytes.checked_mul(1024)
}

fn max_frame_size() -> u32 {
    let value = unsafe { sysconf(_SC_PAGE_SIZE) };
    u32::try_from(value).expect("sysconf(_SC_PAGESIZE) returned an implausible page size.")
}

/// Umem ids start at 1 and are never reused, so an empty
/// `XdpDescriptor`'s zeroed id can never match a live umem.
static NEXT_UMEM_ID: AtomicUsize = AtomicUsize::new(1);

pub struct Umem {
    inner: Arc<UmemInner>,
}

// SAFETY: The region is process-wide memory with a stable
// address for the lifetime of the Umem.
unsafe impl Send for Umem {}

// SAFETY: Umem holds no mutable state after creation — the
// rings belong to the sockets. Which frames a thread may
// touch is governed by XdpDescriptor's mint rule, not by
// this type.
unsafe impl Sync for Umem {}

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
        if frame_size < DEFAULT_FRAME_SIZE || frame_size > max_frame_size {
            return Err(UmemError::FrameSizeOutOfRange {
                frame_size,
                min: DEFAULT_FRAME_SIZE,
                max: max_frame_size,
            });
        }

        let mut length = (frame_size as usize)
            .checked_mul(frame_count as usize)
            .ok_or(UmemError::AreaTooLarge)?;

        // munmap — in Drop, where failure panics — rejects a
        // MAP_HUGETLB length that is not a multiple of the
        // huge page size, though mmap rounds it up itself.
        if use_hugetlb {
            let huge_page_size = huge_page_size().ok_or(UmemError::HugePageSize)?;
            length = length
                .checked_next_multiple_of(huge_page_size)
                .ok_or(UmemError::AreaTooLarge)?;
        }

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
                id: NEXT_UMEM_ID.fetch_add(1, Ordering::Relaxed),
                frame_count,
            }
            .into(),
        };

        Ok(umem)
    }

    /// Process-unique id carried by every `XdpDescriptor`
    /// minted against this umem.
    #[inline]
    pub(crate) fn id(&self) -> usize {
        self.inner.id
    }

    /// Number of frames the region holds.
    #[inline]
    pub fn frame_count(&self) -> u32 {
        self.inner.frame_count
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
    id: usize,
    frame_count: u32,
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

#[derive(Debug, thiserror::Error)]
pub enum UmemError {
    #[error("The frame size '{frame_size}' is not a power of two.")]
    FrameSizeNotPowerOfTwo { frame_size: u32 },
    #[error("The frame size '{frame_size}' is outside the supported range {min}..={max}.")]
    FrameSizeOutOfRange { frame_size: u32, min: u32, max: u32 },
    #[error("The umem area is too large to address.")]
    AreaTooLarge,
    #[error("Failed to read the huge page size from /proc/meminfo.")]
    HugePageSize,
    #[error("Failed to map memory: {0}")]
    MapMemory(io::Error),
    #[error("Failed to initialize Umem: {0}")]
    Initialize(io::Error),
}
