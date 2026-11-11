//! Which cores the workers run on, and pinning to them.

use std::{
    fs,
    io,
    mem,
};

use crate::data::Error;

/// One CPU per physical core that this process may run on,
/// on NUMA node `node` when given. CPU 0's core is left to
/// the OS unless it is the only one.
pub(crate) fn available(node: Option<i32>) -> Result<Vec<usize>, Error> {
    let allowed = allowed()?;
    let candidates = match node {
        Some(node) => read_cpu_list(format!("/sys/devices/system/node/node{node}/cpulist"))?,
        None => allowed.clone(),
    };
    let candidates: Vec<usize> = candidates
        .into_iter()
        .filter(|cpu| allowed.contains(cpu))
        .collect();

    let mut cores = Vec::new();
    for &cpu in &candidates {
        let siblings = read_cpu_list(format!(
            "/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
        ))?;
        // The lowest allowed sibling stands for its core.
        if siblings
            .into_iter()
            .find(|sibling| allowed.contains(sibling))
            == Some(cpu)
        {
            cores.push(cpu);
        }
    }
    // CPU 0 takes the interrupts and whatever else is not
    // pinned, so a worker goes there only for want of
    // another core.
    if cores.len() > 1 {
        cores.retain(|cpu| *cpu != 0);
    }

    Ok(cores)
}

/// Restricts the calling thread to `core`.
pub(crate) fn pin(core: usize) -> io::Result<()> {
    if !usize::try_from(libc::CPU_SETSIZE).is_ok_and(|size| core < size) {
        return Err(io::ErrorKind::InvalidInput.into());
    }

    // SAFETY: A CPU set is a plain bitmask, for which all
    // zeroes is the valid empty set.
    let mut set: libc::cpu_set_t = unsafe { mem::zeroed() };
    // SAFETY: `core` is below CPU_SETSIZE, checked above,
    // so the bit lies inside the set.
    unsafe { libc::CPU_SET(core, &mut set) };
    // SAFETY: The set is initialized and the size passed is
    // its own; pid 0 names the calling thread.
    let result = unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// The CPUs the calling thread may run on, lowest first.
fn allowed() -> Result<Vec<usize>, Error> {
    // SAFETY: As in `pin`: all zeroes is the empty set.
    let mut set: libc::cpu_set_t = unsafe { mem::zeroed() };
    // SAFETY: The kernel fills the set, whose own size is
    // passed; pid 0 names the calling thread.
    let result = unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut set) };
    if result != 0 {
        return Err(Error::Affinity(io::Error::last_os_error()));
    }
    let size = usize::try_from(libc::CPU_SETSIZE).unwrap_or(0);

    Ok((0..size)
        // SAFETY: Every CPU tested is below CPU_SETSIZE.
        .filter(|cpu| unsafe { libc::CPU_ISSET(*cpu, &set) })
        .collect())
}

fn read_cpu_list(path: String) -> Result<Vec<usize>, Error> {
    let list = fs::read_to_string(&path).map_err(|error| Error::Sysfs(path.clone(), error))?;

    cpu_list(&list).ok_or_else(|| Error::Sysfs(path, io::ErrorKind::InvalidData.into()))
}

/// Parses a kernel CPU list such as `0-3,8,16-19`.
fn cpu_list(list: &str) -> Option<Vec<usize>> {
    let mut cpus = Vec::new();
    for range in list.trim().split(',').filter(|range| !range.is_empty()) {
        let (start, end) = range.split_once('-').unwrap_or((range, range));
        cpus.extend(start.parse::<usize>().ok()?..=end.parse().ok()?);
    }

    Some(cpus)
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn cpu_lists_parse() {
        assert_eq!(cpu_list("0-3,8,16-17\n"), Some(vec![0, 1, 2, 3, 8, 16, 17]));
        assert_eq!(cpu_list("5"), Some(vec![5]));
        assert_eq!(cpu_list(""), Some(vec![]));
        assert_eq!(cpu_list("1-x"), None);
    }

    #[test]
    fn available_cores_are_allowed_and_one_per_core() {
        let cores = available(None).unwrap();
        let allowed = allowed().unwrap();
        assert!(!cores.is_empty());
        assert!(cores.iter().all(|core| allowed.contains(core)));
        // CPU 0 only when there is nothing else.
        assert!(cores.len() == 1 || !cores.contains(&0));
    }

    #[test]
    fn pin_restricts_the_thread_to_one_core() {
        // On a thread of its own, so the test runner's
        // affinity is left alone.
        thread::spawn(|| {
            let core = *allowed().unwrap().last().unwrap();
            pin(core).unwrap();
            assert_eq!(allowed().unwrap(), [core]);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn pin_rejects_a_core_no_set_can_name() {
        assert!(pin(usize::MAX).is_err());
    }
}
