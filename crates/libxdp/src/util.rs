pub fn is_power_of_two(size: u32) -> bool {
    if size == 0 {
        return false;
    }

    (size & (size - 1)) == 0
}

/// # Panics
///
/// The function panics under the following conditions:
/// - the system fails to allow unlimited locking of memory.
/// - the program does not have the permission to do so.
pub fn setrlimit() {
    let value = unsafe {
        let rlimit = libc::rlimit {
            rlim_cur: libc::RLIM64_INFINITY,
            rlim_max: libc::RLIM64_INFINITY,
        };

        libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit)
    };
    if value.is_negative() {
        panic!("{}", std::io::Error::from_raw_os_error(-value));
    }
}
