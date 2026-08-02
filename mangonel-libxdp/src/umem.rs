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
    _SC_PAGESIZE, MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE, mmap,
    munmap, sysconf,
};
use mangonel_libxdp_sys::{
    xsk_umem, xsk_umem__create, xsk_umem__delete, xsk_umem__get_data, xsk_umem_config,
};

use crate::ring::{Consumer, Producer, RingError, ring_buffer};

/// Frames are sized so that every ring can be full at the
/// same time: the fill, rx, tx, and completion rings each
/// hold at most `ring_size` entries.
const RINGS_PER_UMEM: u32 = 4;

/// Source of process-unique ids for umems, handed to
/// descriptors as their mint token. Not an address:
/// addresses are reused, and a later umem mapping a dropped
/// umem's base would let stale descriptors pass the mint
/// check and alias the new socket's frames. Ids are never
/// reused, so the check cannot be fooled. Starts at 1,
/// leaving 0 as the empty-descriptor sentinel.
static NEXT_UMEM_ID: AtomicUsize = AtomicUsize::new(1);

/// The kernel's floor on the umem chunk size,
/// `XDP_UMEM_MIN_CHUNK_SIZE`. It lives in the kernel rather
/// than in the uapi headers, so there is no binding
/// to import and the value is restated here.
const MIN_FRAME_SIZE: u32 = 2048;

/// The kernel caps a umem chunk at one page, so the ceiling
/// on `frame_size` is only known at runtime. glibc answers
/// `_SC_PAGESIZE` out of the auxiliary vector, so this
/// costs no syscall.
fn max_frame_size() -> u32 {
    let value = unsafe { sysconf(_SC_PAGESIZE) };
    u32::try_from(value).expect("sysconf(_SC_PAGESIZE) returned an implausible page size.")
}

/// The system's default huge page size, from
/// `/proc/meminfo`, or `None` when the kernel does not
/// report one. There is no sysconf for this; parsing
/// meminfo is what libhugetlbfs itself does.
fn huge_page_size() -> Option<usize> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = meminfo.lines().find(|l| l.starts_with("Hugepagesize:"))?;
    let kilobytes = line.split_whitespace().nth(1)?.parse::<usize>().ok()?;
    kilobytes.checked_mul(1024)
}

pub struct Umem {
    inner: Arc<UmemInner>,
}

// SAFETY: Umem is sent between threads so that both
// XdpSender and XdpReceiver (on different threads) can read
// packet data from the shared memory region. The region is
// process-wide virtual memory with no thread affinity in
// Linux, its address is stable for the lifetime of the
// Umem, and concurrent reads into non-overlapping frame
// regions are safe.
unsafe impl Send for Umem {}

// SAFETY: `config`, `as_ptr`, and `get_data` are read-only,
// so sharing them is fine; this lets SocketInner hold a
// Umem and stay Sync, which the two halves need in order to
// be Send.
//
// The fill and completion rings are the exception: they
// carry mutable state. They live here only to outlive
// xsk_umem__delete and xsk_socket__delete, which
// dereference them during teardown. Soundness rests on each
// being reached by exactly one half — fill by XdpReceiver,
// completion by XdpSender — which create_xdp_socket
// establishes by construction, not by type.
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
        frame_headroom_size: u32,
        ring_size: u32,
        use_hugetlb: bool,
    ) -> Result<Self, UmemError> {
        // In aligned mode the kernel masks every fill-ring address
        // with `~(frame_size - 1)`, so a non-power-of-two
        // frame size makes addressing meaningless and is
        // rejected at registration. Checked here,
        // before any syscall, for a named error instead of a bare
        // EINVAL.
        if !frame_size.is_power_of_two() {
            return Err(UmemError::FrameSizeNotPowerOfTwo { frame_size });
        }

        // A chunk also has to be large enough to hold
        // XDP_PACKET_HEADROOM plus a packet, and small
        // enough that the kernel can back it with a single
        // page. Both bounds are enforced at registration; checking
        // them here turns the same bare EINVAL into a
        // message naming the range.
        let max_frame_size = max_frame_size();
        if frame_size < MIN_FRAME_SIZE || frame_size > max_frame_size {
            return Err(UmemError::FrameSizeOutOfRange {
                frame_size,
                min: MIN_FRAME_SIZE,
                max: max_frame_size,
            });
        }

        // ring_buffer validates that ring_size is a power of two;
        // called before the mapping so a bad ring size is
        // reported as a RingError rather than as an mmap
        // failure over a nonsensical length.
        let (fill_ring, completion_ring) = ring_buffer(ring_size)?;

        // The kernel divides the region into chunks of exactly
        // `frame_size` and rejects a length that is not a
        // whole multiple of it, so headroom must
        // not enter the stride — it is reserved inside each chunk,
        // not appended to it.
        //
        // One frame per ring entry would starve the pool: a frame
        // can be resident in the fill, rx, tx, or
        // completion ring at any moment, so it is sized for
        // all four being full at once.
        let frame_count = ring_size
            .checked_mul(RINGS_PER_UMEM)
            .ok_or(UmemError::AreaTooLarge)?;
        let mut length = (frame_size as usize)
            .checked_mul(frame_count as usize)
            .ok_or(UmemError::AreaTooLarge)?;

        // A MAP_HUGETLB length must be a multiple of the huge page
        // size: mmap rounds a short length up on its own,
        // but munmap rejects the original un-rounded length
        // — and munmap runs in Drop, where failure is a
        // panic. Rounding here keeps the two calls in agreement.
        if use_hugetlb {
            let huge_page_size = huge_page_size().ok_or(UmemError::HugePageSize)?;
            length = length
                .checked_next_multiple_of(huge_page_size)
                .ok_or(UmemError::AreaTooLarge)?;
        }

        // UmemArea owns the mapping from here on: every early
        // return below drops it and unmaps, and once
        // UmemInner is built its Drop takes over.
        let umem_area = UmemArea::new(length, use_hugetlb)?;

        let mut umem_ptr = null_mut::<xsk_umem>();
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

        // Establish the invariant the ring accessors rely on: both
        // rings went in zeroed, xsk_umem__create maps them
        // and writes the `ring` pointers, and this is the
        // one point where "registered" is confirmed — the
        // per-slot accessors index off those pointers without
        // re-checking.
        assert!(
            fill_ring.is_registered() && completion_ring.is_registered(),
            "xsk_umem__create left a ring unpopulated. This is a bug."
        );

        let umem = Self {
            inner: UmemInner {
                umem: NonNull::new(umem_ptr)
                    .expect("xsk_umem__create returned null pointer. This is a bug."),
                umem_area,
                fill_ring,
                completion_ring,
                umem_config,
                frame_count,
                // Relaxed suffices: only uniqueness matters, not ordering
                // against any other memory operation.
                id: NEXT_UMEM_ID.fetch_add(1, Ordering::Relaxed),
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
        &self.inner.umem_config
    }

    /// The fill ring, for the exclusive use of
    /// `XdpReceiver`.
    ///
    /// See the `Sync` impl above: nothing in the type
    /// system stops a second thread from calling this,
    /// so `create_xdp_socket` is responsible for handing
    /// it to exactly one socket half.
    #[inline]
    pub(crate) fn fill_ring(&self) -> &Producer {
        &self.inner.fill_ring
    }

    /// The completion ring, for the exclusive use of
    /// `XdpSender`. Same contract
    /// as [`Self::fill_ring`].
    #[inline]
    pub(crate) fn completion_ring(&self) -> &Consumer {
        &self.inner.completion_ring
    }

    /// Number of frames the umem was sized for, and so the
    /// size of the frame pool the socket should put
    /// into circulation.
    #[inline]
    pub(crate) fn frame_count(&self) -> u32 {
        self.inner.frame_count
    }

    /// Process-unique mint token for descriptors; see
    /// [`NEXT_UMEM_ID`] for why it is not the region's
    /// base address. Never zero — the counter starts at
    /// 1 — which is what lets zero mean "empty descriptor".
    #[inline]
    pub(crate) fn id(&self) -> usize {
        self.inner.id
    }

    /// Returns a pointer to `length` bytes at `address`
    /// within the umem region, or `None` if that range
    /// falls outside it.
    ///
    /// `xsk_umem__get_data` is plain pointer arithmetic
    /// with no validation, so this is the only place
    /// the region bound can be enforced.
    #[inline]
    pub(crate) fn get_data(&self, address: u64, length: usize) -> Option<*mut c_void> {
        let start = usize::try_from(address).ok()?;
        if start.checked_add(length)? > self.inner.umem_area.length {
            return None;
        }
        Some(unsafe { xsk_umem__get_data(self.inner.umem_area.address.as_ptr(), address) })
    }
}

/// Owning the rings is load-bearing: `Drop` runs
/// `xsk_umem__delete` before any field drops, and that call
/// reads `fill_save->ring` and `comp_save->ring` —
/// the pointers libxdp saved to the two ring structs — to
/// unmap the ring memory, so both structs must still be
/// allocated, whatever order the caller drops its handles
/// in. The call never touches the region itself; it stays
/// mapped until `umem_area` drops.
struct UmemInner {
    umem: NonNull<xsk_umem>,
    umem_area: UmemArea,
    fill_ring: Producer,
    completion_ring: Consumer,
    umem_config: xsk_umem_config,
    /// Number of frames the region was sized for. Stored
    /// rather than derived from the region length,
    /// which hugetlb rounding can leave larger than
    /// `frame_size * frame_count`.
    frame_count: u32,
    /// Process-unique mint token; see [`NEXT_UMEM_ID`].
    id: usize,
}

impl Drop for UmemInner {
    fn drop(&mut self) {
        // Runs before any field is dropped, so both ring structs
        // are still allocated for xsk_umem__delete to
        // dereference.
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
            panic!("Failed to unmap memory: {}", io::Error::last_os_error());
        }
    }
}

impl UmemArea {
    fn new(length: usize, use_hugetlb: bool) -> Result<Self, UmemError> {
        let protection_mode = PROT_READ | PROT_WRITE;
        let mut flags = MAP_PRIVATE | MAP_ANONYMOUS;
        if use_hugetlb {
            flags |= MAP_HUGETLB;
        }
        let address = unsafe { mmap(null_mut(), length, protection_mode, flags, -1, 0) };
        if address == MAP_FAILED {
            return Err(UmemError::MapMemory(io::Error::last_os_error()));
        }
        Ok(Self {
            address: NonNull::new(address).expect("mmap returned null pointer. This is a bug."),
            length,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UmemError {
    #[error("The frame size '{frame_size}' is not a power of two.")]
    FrameSizeNotPowerOfTwo { frame_size: u32 },
    #[error("The frame size '{frame_size}' is outside the supported range {min}..={max}.")]
    FrameSizeOutOfRange { frame_size: u32, min: u32, max: u32 },
    #[error("The umem area is too large to address.")]
    AreaTooLarge,
    #[error("Could not determine the huge page size from /proc/meminfo.")]
    HugePageSize,
    #[error("Failed to map memory: {0}")]
    MapMemory(io::Error),
    #[error("Failed to initialize Umem: {0}")]
    Initialize(io::Error),
    #[error(transparent)]
    Ring(#[from] RingError),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ring size used below. Small enough that the mapping
    /// the accepting case performs is a few pages
    /// rather than tens of megabytes.
    const RING_SIZE: u32 = 8;

    #[test]
    fn validates_frame_and_ring_geometry_before_mapping() {
        // Every check runs ahead of the length arithmetic and the
        // mapping, so bad geometry is reported as such rather than
        // surfacing as a failed mmap.
        for frame_size in [0, 3, 1000, 4095, 4097, 6144, u32::MAX] {
            assert!(
                matches!(
                    Umem::new(frame_size, 0, RING_SIZE, false),
                    Err(UmemError::FrameSizeNotPowerOfTwo { frame_size: got }) if got == frame_size
                ),
                "frame size {frame_size} should have been rejected"
            );
        }
        // A frame size that would overflow `usize` is still
        // reported as the size being wrong, not as an
        // oversized area.
        assert!(matches!(
            Umem::new(u32::MAX, 0, u32::MAX, false),
            Err(UmemError::FrameSizeNotPowerOfTwo { .. })
        ));

        // Powers of two, so these clear the first check and land on
        // the range check: below XDP_UMEM_MIN_CHUNK_SIZE, then
        // above the page size.
        for frame_size in [2, 512, 1024, max_frame_size() * 2] {
            assert!(
                matches!(
                    Umem::new(frame_size, 0, RING_SIZE, false),
                    Err(UmemError::FrameSizeOutOfRange { .. })
                ),
                "frame size {frame_size} is out of range and should have been rejected"
            );
        }

        // Ring sizes are checked separately, in ring_buffer.
        for ring_size in [0, 3] {
            assert!(
                matches!(
                    Umem::new(4096, 0, ring_size, false),
                    Err(UmemError::Ring(_))
                ),
                "ring size {ring_size} should have been rejected"
            );
        }
        // The frame pool is RINGS_PER_UMEM times the ring size, so
        // this overflows the frame count before anything is mapped.
        assert!(matches!(
            Umem::new(4096, 0, 1 << 30, false),
            Err(UmemError::AreaTooLarge)
        ));

        // The bounds must leave a satisfiable range, or every call
        // would fail confusingly. Registering a umem needs
        // CAP_NET_RAW, so an unprivileged run stops at
        // xsk_umem__create with EPERM; either outcome means the
        // geometry itself was accepted, which is all this asserts.
        assert!(MIN_FRAME_SIZE <= max_frame_size());
        for frame_size in [MIN_FRAME_SIZE, max_frame_size()] {
            assert!(
                !matches!(
                    Umem::new(frame_size, 0, RING_SIZE, false),
                    Err(UmemError::FrameSizeNotPowerOfTwo { .. })
                        | Err(UmemError::FrameSizeOutOfRange { .. })
                ),
                "frame size {frame_size} should have been accepted"
            );
        }
    }

    #[test]
    fn the_huge_page_size_is_a_sane_power_of_two() {
        // Guards the meminfo parsing: a kernel built with hugetlb
        // support (any AF_XDP-capable one) reports Hugepagesize,
        // and it is a power of two no smaller than a base
        // page.
        let size = huge_page_size().expect("/proc/meminfo reports no Hugepagesize");
        assert!(size.is_power_of_two() && size >= 4096);
    }
}
