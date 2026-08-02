pub fn setrlimit() -> Result<(), std::io::Error> {
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
        // setrlimit is POSIX: -1 with the reason in errno, unlike
        // libxdp's -errno returns — so last_os_error, not
        // from_raw_os_error.
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}
