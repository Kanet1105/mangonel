use std::{
    ffi::c_void,
    io,
    ptr::{NonNull, null_mut},
    sync::OnceLock,
};

use libc::{
    _SC_PAGE_SIZE, MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE,
    mmap, munmap, sysconf,
};
use mangonel_libxdp_sys::{
    xsk_umem, xsk_umem__create, xsk_umem__delete, xsk_umem__get_data, xsk_umem_config,
};
use mangonel_ring::Ring;

use crate::{
    ring::{Consumer, Producer},
    umem::UmemError::UnmapMemory,
    xdp::DEFAULT_FRAME_SIZE,
};

/// The most frames a umem may hold: its pool's capacity
/// cap.
const MAX_FRAME_COUNT: u32 = 1 << 30;

/// The huge page size in bytes, from /proc/meminfo.
fn huge_page_size() -> Result<usize, UmemError> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").map_err(UmemError::ReadMeminfo)?;

    meminfo
        .lines()
        .find(|l| l.starts_with("Hugepagesize:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|kilobytes| kilobytes.parse::<usize>().ok())
        .and_then(|kilobytes| kilobytes.checked_mul(1024))
        .ok_or(UmemError::HugePageSize)
}

fn max_frame_size() -> Result<u32, UmemError> {
    let value = unsafe { sysconf(_SC_PAGE_SIZE) };

    u32::try_from(value).map_err(|_| UmemError::PageSize { value })
}

// Shallow: clones share one kernel umem, area and pool, and
// nothing here frees them.
#[derive(Clone)]
pub(crate) struct Umem {
    umem: NonNull<xsk_umem>,
    area: UmemArea,
    config: xsk_umem_config,
    pool: Ring<u64>,
}

// SAFETY: The kernel umem has no thread affinity, and the
// area and pool are `Send`.
unsafe impl Send for Umem {}

// SAFETY: The kernel umem pointer is read-only after
// `new`, and the area and pool are `Sync`.
unsafe impl Sync for Umem {}

/// The one umem every socket shares, set by
/// [`Umem::publish`].
static UMEM: OnceLock<Umem> = OnceLock::new();

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

        // The pool rounds its capacity up to a power of two
        // no larger than this.
        if frame_count == 0 || frame_count > MAX_FRAME_COUNT {
            return Err(UmemError::FrameCountOutOfRange {
                frame_count,
                max: MAX_FRAME_COUNT,
            });
        }

        let max_frame_size = max_frame_size()?;
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

        // munmap rejects a MAP_HUGETLB length that is not a
        // multiple of the huge page size, though mmap rounds
        // it up itself.
        if use_hugetlb {
            let huge_page_size = huge_page_size()?;
            length = length
                .checked_next_multiple_of(huge_page_size)
                .ok_or(UmemError::AreaTooLarge)?;
        }

        // Every frame starts in the pool. Seeded before the
        // area and kernel umem exist, so an error here has
        // nothing to free.
        let pool = Ring::new((frame_count as usize).next_power_of_two())?;
        let mut grant = pool.bulk_write(frame_count as usize)?;
        for frame in 0..frame_count {
            grant.write(u64::from(frame) * u64::from(frame_size))?;
        }
        drop(grant);

        let area = UmemArea::map(length, use_hugetlb)?;

        let config = xsk_umem_config {
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
                area.address.as_ptr(),
                u64::try_from(area.length).expect("Umem area length exceeds u64. This is a bug."),
                fill_ring.as_ptr(),
                completion_ring.as_ptr(),
                &config,
            )
        };
        if value.is_negative() {
            let error = io::Error::from_raw_os_error(-value);
            // The area has no Drop; unmap it or it leaks.
            area.unmap()?;

            return Err(UmemError::Initialize(error));
        }

        assert!(
            fill_ring.is_registered() && completion_ring.is_registered(),
            "xsk_umem__create left a ring unpopulated. This is a bug."
        );

        Ok(Self {
            umem: NonNull::new(umem_ptr)
                .expect("xsk_umem__create returned a null pointer. This is a bug."),
            area,
            config,
            pool,
        })
    }

    /// Makes this the global umem. Panics if one exists.
    pub(crate) fn publish(self) -> &'static Umem {
        if UMEM.set(self).is_err() {
            panic!("A second umem was published. This is a bug.");
        }

        Self::global()
    }

    /// `None` before [`Self::publish`].
    pub(crate) fn existing() -> Option<&'static Umem> {
        UMEM.get()
    }

    /// Panics before [`Self::publish`].
    pub(crate) fn global() -> &'static Umem {
        UMEM.get().expect("No umem exists yet. This is a bug.")
    }

    pub(crate) fn as_ptr(&self) -> *mut xsk_umem {
        self.umem.as_ptr()
    }

    pub(crate) fn config(&self) -> &xsk_umem_config {
        &self.config
    }

    pub(crate) fn pool(&self) -> &Ring<u64> {
        &self.pool
    }

    /// Frames the area holds.
    pub(crate) fn frame_count(&self) -> u32 {
        u32::try_from(self.area.length / self.config.frame_size as usize)
            .expect("The umem frame count overflows u32. This is a bug.")
    }

    /// The address `length` bytes at `address` start at;
    /// errors if they fall outside the area.
    pub(crate) fn get_data(&self, address: u64, length: usize) -> Result<*mut c_void, UmemError> {
        let out_of_range = || UmemError::DataOutOfRange {
            address,
            length,
            area_length: self.area.length,
        };
        let end = usize::try_from(address)
            .ok()
            .and_then(|start| start.checked_add(length))
            .ok_or_else(out_of_range)?;
        if end > self.area.length {
            return Err(out_of_range());
        }

        Ok(unsafe { xsk_umem__get_data(self.area.address.as_ptr(), address) })
    }

    /// Deletes the kernel umem, then unmaps the area. On a
    /// failed delete nothing is freed. libxdp's delete
    /// fails with EBUSY while it still counts any
    /// socket bound to the umem. So free only succeeds
    /// after every socket on that umem has been
    /// deleted.
    pub(crate) fn free(self) -> Result<(), UmemError> {
        let value = unsafe { xsk_umem__delete(self.umem.as_ptr()) };
        if value.is_negative() {
            return Err(UmemError::Delete(io::Error::from_raw_os_error(-value)));
        }

        self.area.unmap()
    }
}

// Shallow: clones share one mapping, unmapped at most once.
#[derive(Clone)]
struct UmemArea {
    address: NonNull<c_void>,
    length: usize,
}

// SAFETY: The mapping is process-wide memory with no
// thread affinity.
unsafe impl Send for UmemArea {}

// SAFETY: `&UmemArea` only reads the address and length.
// Which frames a thread may touch is governed by
// XdpDescriptor's mint rule, not by this type.
unsafe impl Sync for UmemArea {}

impl UmemArea {
    fn map(length: usize, use_hugetlb: bool) -> Result<Self, UmemError> {
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

    fn unmap(self) -> Result<(), UmemError> {
        let value = unsafe { munmap(self.address.as_ptr(), self.length) };
        if value.is_negative() {
            return Err(UnmapMemory(io::Error::from_raw_os_error(-value)));
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UmemError {
    #[error("The frame size '{frame_size}' is not a power of two.")]
    FrameSizeNotPowerOfTwo { frame_size: u32 },

    #[error("The frame size '{frame_size}' is outside the supported range {min}..={max}.")]
    FrameSizeOutOfRange { frame_size: u32, min: u32, max: u32 },

    #[error("The frame count '{frame_count}' is outside the supported range 1..={max}.")]
    FrameCountOutOfRange { frame_count: u32, max: u32 },

    #[error("The umem area is too large to address.")]
    AreaTooLarge,

    #[error("Failed to read /proc/meminfo: {0}")]
    ReadMeminfo(io::Error),

    #[error("/proc/meminfo has no valid Hugepagesize entry.")]
    HugePageSize,

    #[error("sysconf(_SC_PAGESIZE) returned an implausible page size '{value}'.")]
    PageSize { value: libc::c_long },

    #[error("Failed to map memory: {0}")]
    MapMemory(io::Error),

    #[error("Failed to unmap memory: {0}")]
    UnmapMemory(io::Error),

    #[error("Failed to initialize Umem: {0}")]
    Initialize(io::Error),

    #[error("Failed to delete Umem: {0}")]
    Delete(io::Error),

    #[error("Failed to seed the frame pool: {0}")]
    Ring(#[from] mangonel_ring::Error),

    #[error("The {length} bytes at '{address}' fall outside the {area_length}-byte umem area.")]
    DataOutOfRange {
        address: u64,
        length: usize,
        area_length: usize,
    },
}
