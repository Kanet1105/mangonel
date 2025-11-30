use core_affinity::CoreId;
use std::thread::{self, JoinHandle};

/// Get the number of available cores.
pub fn available_cores() -> Result<usize, Error> {
    core_affinity::get_core_ids()
        .map(|core_ids| core_ids.len())
        .ok_or(Error::GetCoreIDs)
}

fn get_core_id(core_id: usize) -> Result<CoreId, Error> {
    core_affinity::get_core_ids()
        .ok_or(Error::GetCoreIDs)?
        .into_iter()
        .find(|core| core.id == core_id)
        .ok_or(Error::InvalidCoreId(core_id))
}

/// Spawns a worker thread pinned to the specific core by core ID.
pub fn spawn<F, T>(core_id: usize, function: F) -> Result<JoinHandle<T>, Error>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let core_id = get_core_id(core_id)?;
    let handle = thread::spawn(move || {
        if core_affinity::set_for_current(core_id) {
            function()
        } else {
            panic!("Unable to pin the thread to {core_id:?}. This is a bug.");
        }
    });
    Ok(handle)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to get core IDs")]
    GetCoreIDs,
    #[error("Invalid core ID: {0}")]
    InvalidCoreId(usize),
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{thread, thread::JoinHandle, time::Duration};

    #[test]
    fn test_available_cores() {
        let cores = available_cores();
        assert!(cores.is_ok());
        let cores = cores.unwrap();
        assert!(cores > 0);
        println!("Available cores: {}", cores);
    }

    #[test]
    fn test_spawn_valid_core() {
        let cores = available_cores().unwrap();
        if cores > 0 {
            let handle = spawn(0, || {
                println!("Hello from core 0");
                42
            });
            assert!(handle.is_ok());
            let result = handle.unwrap().join().unwrap();
            assert_eq!(result, 42);
        }
    }

    #[test]
    fn test_spawn_invalid_core() {
        let worker = spawn(usize::MAX, move || {
            thread::sleep(Duration::from_millis(100))
        });
        assert!(worker.is_err());
        if let Err(Error::InvalidCoreId(id)) = worker {
            assert_eq!(id, usize::MAX);
        } else {
            panic!("Expected InvalidCoreId error");
        }
    }

    #[test]
    fn spawn_multiple_workers() {
        let handles: Result<Vec<JoinHandle<()>>, _> = (0..10)
            .map(|_| spawn(0, move || thread::sleep(Duration::from_millis(100))))
            .collect();
        assert!(handles.is_ok());
        for handle in handles.unwrap() {
            handle.join().unwrap();
        }
    }
}
