use std::ffi::CStr;

pub fn check_system_info() -> Result<(), SystemInfoError> {
    // Check OS.
    if !cfg!(target_os = "linux") {
        return Err(SystemInfoError::UnsupportedOs);
    }

    // Check kernel version.
    let mut utsname = unsafe { std::mem::zeroed::<libc::utsname>() };
    if unsafe { libc::uname(&mut utsname) } != 0 {
        return Err(SystemInfoError::KernelVersionNotFound);
    }

    let release = unsafe { CStr::from_ptr(utsname.release.as_ptr()) }
        .to_str()
        .map_err(|_| SystemInfoError::ParseKernelVersion)?;
    let mut parts = release.splitn(3, '.');

    let major: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or(SystemInfoError::ParseKernelVersion)?;
    let minor: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or(SystemInfoError::ParseKernelVersion)?;

    // Requires kernel version 5.10 or newer.
    if (major, minor) < (5, 10) {
        return Err(SystemInfoError::UnsupportedKernelVersion { major, minor });
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SystemInfoError {
    #[error("Unsupported OS. Currently supports Linux only")]
    UnsupportedOs,
    #[error("Kernel version not found")]
    KernelVersionNotFound,
    #[error("Failed to parse kernel version")]
    ParseKernelVersion,
    #[error("Unsupported kernel version {major}.{minor}. Requires 5.10 or newer")]
    UnsupportedKernelVersion { major: u32, minor: u32 },
}
