//! Which CPUs the transmit threads take, and pinning to
//! them.

use std::{
    io,
    mem,
};

/// The CPUs the calling thread may run on, highest first.
/// A router under test on the same machine pins its workers
/// from the low end, so starting from the top leaves it its
/// cores for as long as there are enough.
pub(crate) fn from_the_top() -> io::Result<Vec<usize>> {
    // SAFETY: A CPU set is a plain bitmask, for which all
    // zeroes is the valid empty set.
    let mut set: libc::cpu_set_t = unsafe { mem::zeroed() };
    // SAFETY: The kernel fills the set, whose own size is
    // passed; pid 0 names the calling thread.
    let result = unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut set) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let size = usize::try_from(libc::CPU_SETSIZE).unwrap_or(0);

    Ok((0..size)
        .rev()
        // SAFETY: Every CPU tested is below CPU_SETSIZE.
        .filter(|cpu| unsafe { libc::CPU_ISSET(*cpu, &set) })
        .collect())
}

/// Restricts the calling thread to `cpu`.
pub(crate) fn pin(cpu: usize) -> io::Result<()> {
    if !usize::try_from(libc::CPU_SETSIZE).is_ok_and(|size| cpu < size) {
        return Err(io::ErrorKind::InvalidInput.into());
    }

    // SAFETY: As above: all zeroes is the empty set.
    let mut set: libc::cpu_set_t = unsafe { mem::zeroed() };
    // SAFETY: `cpu` is below CPU_SETSIZE, checked above, so
    // the bit lies inside the set.
    unsafe { libc::CPU_SET(cpu, &mut set) };
    // SAFETY: The set is initialized and the size passed is
    // its own; pid 0 names the calling thread.
    let result = unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn the_allowed_cpus_come_highest_first() {
        let cpus = from_the_top().unwrap();
        assert!(!cpus.is_empty());
        assert!(cpus.windows(2).all(|pair| pair[0] > pair[1]));
    }

    #[test]
    fn pin_restricts_the_thread_to_one_cpu() {
        // On a thread of its own, so the test runner's
        // affinity is left alone.
        thread::spawn(|| {
            let cpu = from_the_top().unwrap()[0];
            pin(cpu).unwrap();
            assert_eq!(from_the_top().unwrap(), [cpu]);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn pin_rejects_a_cpu_no_set_can_name() {
        assert!(pin(usize::MAX).is_err());
    }
}
