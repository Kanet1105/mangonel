use libc::{_SC_PAGE_SIZE, sysconf};
use mangonel_libxdp_sys::{
    XSK_RING_PROD__DEFAULT_NUM_DESCS, XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    XSK_UMEM__DEFAULT_FRAME_SIZE,
};

pub const MIN_FRAME_SIZE: u32 = 2048;
pub const DEFAULT_FRAME_SIZE: u32 = XSK_UMEM__DEFAULT_FRAME_SIZE;
pub const DEFAULT_FRAME_HEADROOM: u32 = XSK_UMEM__DEFAULT_FRAME_HEADROOM;
pub const DEFAULT_RING_SIZE: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS;

pub fn max_frame_size() -> u32 {
    let value = unsafe { sysconf(_SC_PAGE_SIZE) };
    u32::try_from(value).expect("sysconf(_SC_PAGESIZE) returned an implausible page size.")
}

pub fn setrlimit() {
    let value = unsafe {
        let rlimit = libc::rlimit {
            // RLIM_INFINITY is the constant matching libc::rlimit's field
            // width; the 64-suffixed one belongs to the rlimit64 API.
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };

        libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit)
    };
    if value.is_negative() {
        panic!("Failed to set rlimit: {}", std::io::Error::last_os_error());
    }
}
