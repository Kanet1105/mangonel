use std::{
    ffi::{CStr, CString},
    fs,
    path::{Path, PathBuf},
};

/// Checks that the current system meets the minimum requirements.
///
/// Verifies that the operating system is Linux and that the kernel version
/// is 5.10 or newer (required for io_uring support). Returns a
/// [`SystemInfoError`] if any check fails.
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

/// Returns the default shared library search paths on Linux.
///
/// Parses `/etc/ld.so.conf` (recursively following `include` directives) and
/// appends the built-in default paths. Uses `libc::glob` to expand wildcard
/// patterns in `include` directives.
pub fn default_library_paths() -> Result<Vec<PathBuf>, SystemInfoError> {
    let mut paths = Vec::new();
    parse_ld_so_conf(Path::new("/etc/ld.so.conf"), &mut paths)?;

    // Append the built-in default library paths.
    for default in &["/lib", "/usr/lib", "/lib64", "/usr/lib64"] {
        let p = PathBuf::from(default);
        if p.is_dir() && !paths.contains(&p) {
            paths.push(p);
        }
    }

    // Append the multiarch path (e.g. /usr/lib/x86_64-linux-gnu).
    let mut utsname = unsafe { std::mem::zeroed::<libc::utsname>() };
    if unsafe { libc::uname(&mut utsname) } == 0 {
        let machine = unsafe { CStr::from_ptr(utsname.machine.as_ptr()) }
            .to_str()
            .unwrap_or("");
        let multiarch = PathBuf::from(format!("/usr/lib/{machine}-linux-gnu"));
        if multiarch.is_dir() && !paths.contains(&multiarch) {
            paths.push(multiarch);
        }
    }

    Ok(paths)
}

fn parse_ld_so_conf(
    path: &std::path::Path,
    paths: &mut Vec<std::path::PathBuf>,
) -> Result<(), SystemInfoError> {
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(()), // Silently skip missing files.
    };

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(pattern) = line.strip_prefix("include") {
            let pattern = pattern.trim();
            for included_path in glob_paths(pattern)? {
                parse_ld_so_conf(&included_path, paths)?;
            }
        } else {
            let p = PathBuf::from(line);
            if p.is_dir() && !paths.contains(&p) {
                paths.push(p);
            }
        }
    }

    Ok(())
}

/// Uses `libc::glob` to expand a glob pattern into a list of paths.
fn glob_paths(pattern: &str) -> Result<Vec<std::path::PathBuf>, SystemInfoError> {
    let c_pattern = CString::new(pattern).map_err(|_| SystemInfoError::GlobExpansionFailed)?;
    let mut glob_buf: libc::glob_t = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::glob(c_pattern.as_ptr(), 0, None, &mut glob_buf) };

    let result = if ret == 0 {
        let count = glob_buf.gl_pathc as usize;
        let mut results = Vec::with_capacity(count);
        for i in 0..count {
            let c_str = unsafe { CStr::from_ptr(*glob_buf.gl_pathv.add(i)) };
            if let Ok(s) = c_str.to_str() {
                results.push(PathBuf::from(s));
            }
        }
        Ok(results)
    } else {
        Ok(Vec::new()) // No matches is not an error.
    };

    unsafe { libc::globfree(&mut glob_buf) };
    result
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
    #[error("Failed to expand glob pattern")]
    GlobExpansionFailed,
}

#[test]
fn test_default_library_paths() {
    let paths = default_library_paths().unwrap();
    println!("{:?}", paths);
}
