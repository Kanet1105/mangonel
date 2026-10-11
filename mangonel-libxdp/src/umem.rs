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
    xsk_umem, xsk_umem__create, xsk_umem__delete, xsk_umem__get_data, xsk_umem_config,
};

use crate::{
    pool::{CacheAligned, FramePool},
    ring::{Consumer, Producer},
    xdp::DEFAULT_FRAME_SIZE,
};

/// The most frames a umem may hold: its pool's capacity
/// cap.
const MAX_FRAME_COUNT: u32 = 1 << 30;

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

/// The sockets' handle on a umem. Clones share one kernel
/// umem, deleted when the last clone drops.
#[derive(Clone)]
pub(crate) struct Umem {
    inner: Arc<UmemInner>,
}

struct UmemInner {
    umem: NonNull<xsk_umem>,
    /// Boxed apart from the kernel umem: descriptors point
    /// at it without a reference count, so it may have to
    /// outlive this struct.
    shared: NonNull<UmemShared>,
}

// SAFETY: The kernel umem has no thread affinity, and
// `UmemShared` is `Send`.
unsafe impl Send for UmemInner {}

// SAFETY: The rings belong to the sockets; everything else
// is reached through `UmemShared`, which is `Sync`.
unsafe impl Sync for UmemInner {}

impl Drop for UmemInner {
    fn drop(&mut self) {
        let value = unsafe { xsk_umem__delete(self.umem.as_ptr()) };
        if value.is_negative() {
            panic!(
                "Failed to free Umem: {}",
                io::Error::from_raw_os_error(-value)
            );
        }

        // SAFETY: Boxed in `Umem::new` and released only
        // here, once, as the last socket goes.
        unsafe { UmemShared::release(self.shared) };
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

        // The pool rounds its capacity up to a power of two
        // no larger than this.
        if frame_count == 0 || frame_count > MAX_FRAME_COUNT {
            return Err(UmemError::FrameCountOutOfRange {
                frame_count,
                max: MAX_FRAME_COUNT,
            });
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

        // munmap — in Drop, where failure panics — rejects
        // a MAP_HUGETLB length that is not a
        // multiple of the huge page size, though
        // mmap rounds it up itself.
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

        // Every frame starts in the pool; the capacity
        // rounds up to the pool's power-of-two
        // requirement.
        let pool = FramePool::new((frame_count as usize).next_power_of_two());
        let (available, index) = pool
            .claim_write(frame_count)
            .expect("Seeding an empty pool cannot fail. This is a bug.");
        assert!(
            available == frame_count,
            "Seeding claimed fewer frames than the pool was sized for. This is a bug."
        );
        for frame in 0..frame_count {
            pool.write_at(
                index.wrapping_add(frame) as usize,
                u64::from(frame) * u64::from(frame_size),
            );
        }
        pool.commit_write(index as usize, available);

        let shared = Box::new(UmemShared::new(umem_area, umem_config, pool));
        let umem = Self {
            inner: Arc::new(UmemInner {
                umem: NonNull::new(umem_ptr)
                    .expect("xsk_umem__create() returned a null pointer. This is a bug."),
                shared: NonNull::from(Box::leak(shared)),
            }),
        };

        Ok(umem)
    }

    pub(crate) fn as_ptr(&self) -> *mut xsk_umem {
        self.inner.umem.as_ptr()
    }

    pub(crate) fn shared(&self) -> &UmemShared {
        // SAFETY: Released only when the last `Umem` clone
        // drops, so it outlives `&self`.
        unsafe { self.inner.shared.as_ref() }
    }
}

/// Everything a descriptor reaches through its umem: the
/// frame memory, its layout, and the pool frames recycle
/// into.
///
/// Descriptors point here without a reference count, which
/// would cost two contended atomics per packet. Instead
/// `outstanding` counts live descriptors, moved once per
/// batch: [`Self::lend`] as frames are minted and
/// [`Self::reclaim`] as they leave through send or drop.
/// When the last socket goes, [`Self::release`] frees this
/// only if none are left; otherwise it leaks it, so a
/// forgotten descriptor never reads unmapped memory.
pub(crate) struct UmemShared {
    area: UmemArea,
    config: xsk_umem_config,
    /// Shared by every socket on this umem.
    pool: FramePool,
    /// Live descriptors minted against this umem. Padded
    /// so its writes do not evict the read-mostly fields
    /// above from every core's cache.
    outstanding: CacheAligned<AtomicUsize>,
}

// SAFETY: The area is process-wide memory with a stable
// address until `release` frees it.
unsafe impl Send for UmemShared {}

// SAFETY: After creation the only mutable state is the
// pool and the counter, which synchronize themselves.
// Which frames a thread may touch is governed by
// XdpDescriptor's mint rule, not by this type.
unsafe impl Sync for UmemShared {}

impl UmemShared {
    fn new(area: UmemArea, config: xsk_umem_config, pool: FramePool) -> Self {
        Self {
            area,
            config,
            pool,
            outstanding: CacheAligned(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn config(&self) -> &xsk_umem_config {
        &self.config
    }

    /// Frames the area holds; the umem is sized in whole
    /// frames, so this is exact.
    pub(crate) fn frame_count(&self) -> u32 {
        u32::try_from(self.area.length / self.config.frame_size as usize)
            .expect("The umem frame count overflows u32. This is a bug.")
    }

    /// Crate-only: the claim/commit contract stays behind
    /// the socket API.
    pub(crate) fn pool(&self) -> &FramePool {
        &self.pool
    }

    pub(crate) fn get_data(&self, address: u64, length: usize) -> Option<*mut c_void> {
        let start = usize::try_from(address).ok()?;
        if start.checked_add(length)? > self.area.length {
            return None;
        }

        Some(unsafe { xsk_umem__get_data(self.area.address.as_ptr(), address) })
    }

    /// Counts `count` descriptors about to be minted.
    ///
    /// Relaxed: only a socket mints, and a live socket
    /// keeps [`Self::release`] from running, so nothing
    /// reads the counter concurrently with a lend.
    pub(crate) fn lend(&self, count: u32) {
        self.outstanding
            .0
            .fetch_add(count as usize, Ordering::Relaxed);
    }

    /// Uncounts `count` descriptors that have given up
    /// their frames. Must be the caller's last access
    /// to `self` through those descriptors: once the
    /// count reaches zero, `release` may free it.
    ///
    /// Release pairs with `release`'s Acquire, so every
    /// access made through the descriptors happens before
    /// the area is unmapped.
    pub(crate) fn reclaim(&self, count: u32) {
        let previous = self
            .outstanding
            .0
            .fetch_sub(count as usize, Ordering::Release);
        debug_assert!(
            previous >= count as usize,
            "Reclaimed more descriptors than were lent. This is a bug."
        );
    }

    /// Frees the allocation if no descriptor still points
    /// at it; otherwise leaks it with a warning. Returns
    /// whether it was freed.
    ///
    /// # Safety
    ///
    /// `shared` must come from `Box::leak`, no socket may
    /// remain to mint more descriptors, and this must run
    /// at most once.
    unsafe fn release(shared: NonNull<Self>) -> bool {
        // SAFETY: The caller guarantees it is still live.
        let outstanding = unsafe { shared.as_ref() }
            .outstanding
            .0
            .load(Ordering::Acquire);
        if outstanding != 0 {
            tracing::warn!(
                outstanding,
                "umem dropped while descriptors still hold its frames; leaking its memory"
            );

            return false;
        }

        // SAFETY: From `Box::leak`, released once, and with
        // nothing left pointing at it.
        drop(unsafe { Box::from_raw(shared.as_ptr()) });

        true
    }
}

pub(crate) struct UmemArea {
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
    #[error("The frame count '{frame_count}' is outside the supported range 1..={max}.")]
    FrameCountOutOfRange { frame_count: u32, max: u32 },
    #[error("The umem area is too large to address.")]
    AreaTooLarge,
    #[error("Failed to read the huge page size from /proc/meminfo.")]
    HugePageSize,
    #[error("Failed to map memory: {0}")]
    MapMemory(io::Error),
    #[error("Failed to initialize Umem: {0}")]
    Initialize(io::Error),
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A umem's descriptor-facing half with every frame in
    /// its pool. Builds no kernel umem, so it needs no
    /// privilege; release it with [`release`].
    pub(crate) fn shared(frame_count: u32) -> NonNull<UmemShared> {
        let frame_size = DEFAULT_FRAME_SIZE;
        let area = UmemArea::new((frame_size * frame_count) as usize, false).unwrap();
        let config = xsk_umem_config {
            fill_size: 4,
            comp_size: 4,
            frame_size,
            frame_headroom: 0,
            flags: 0,
        };
        let pool = FramePool::new((frame_count as usize).next_power_of_two());
        let index = pool.claim_write_all(frame_count);
        for frame in 0..frame_count {
            pool.write_at(
                index.wrapping_add(frame) as usize,
                u64::from(frame) * u64::from(frame_size),
            );
        }
        pool.commit_write(index as usize, frame_count);

        NonNull::from(Box::leak(Box::new(UmemShared::new(area, config, pool))))
    }

    pub(crate) fn release(shared: NonNull<UmemShared>) -> bool {
        // SAFETY: From `shared` above, with no socket.
        unsafe { UmemShared::release(shared) }
    }

    pub(crate) fn outstanding(shared: NonNull<UmemShared>) -> usize {
        unsafe { shared.as_ref() }
            .outstanding
            .0
            .load(Ordering::Relaxed)
    }

    #[test]
    fn release_frees_only_when_nothing_is_lent() {
        let umem = shared(4);
        let view = unsafe { umem.as_ref() };
        view.lend(3);
        view.reclaim(3);
        assert!(release(umem));

        let umem = shared(4);
        unsafe { umem.as_ref() }.lend(1);
        // Leaked on purpose: a descriptor still points
        // here.
        assert!(!release(umem));
    }
}
