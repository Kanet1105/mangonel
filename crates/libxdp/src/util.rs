pub fn setrlimit() -> Result<(), std::io::Error> {
    let value = unsafe {
        let rlimit = libc::rlimit {
            rlim_cur: libc::RLIM64_INFINITY,
            rlim_max: libc::RLIM64_INFINITY,
        };

        libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit)
    };

    if value.is_negative() {
        return Err(std::io::Error::from_raw_os_error(-value));
    }

    Ok(())
}
