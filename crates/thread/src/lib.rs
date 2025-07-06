use core_affinity::CoreId;
use std::thread::{self, JoinHandle};

/// Get the number of available cores.
pub fn available_cores() -> Result<usize, ThreadError> {
    core_affinity::get_core_ids()
        .map(|core_ids| core_ids.len())
        .ok_or(ThreadError::UnableToGetCoreIds)
}

fn get_core_id(core_id: usize) -> Result<CoreId, ThreadError> {
    core_affinity::get_core_ids()
        .ok_or(ThreadError::UnableToGetCoreIds)?
        .into_iter()
        .find(|core| core.id == core_id)
        .ok_or(ThreadError::InvalidCoreId(core_id))
}

/// Spawns a worker thread pinned to the specific core by core ID.
pub fn spawn<F, T>(core_id: usize, function: F) -> Result<JoinHandle<T>, ThreadError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let core_id = get_core_id(core_id)?;
    let handle = thread::spawn(move || {
        if core_affinity::set_for_current(core_id) {
            function()
        } else {
            panic!("Unable to pin the thread to {:?}. This is a bug.", core_id);
        }
    });
    Ok(handle)
}

pub enum ThreadError {
    UnableToGetCoreIds,
    InvalidCoreId(usize),
}

impl std::fmt::Debug for ThreadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnableToGetCoreIds => write!(f, "Unable to get core IDs"),
            Self::InvalidCoreId(core_id) => write!(f, "Invalid core ID: {}", core_id),
        }
    }
}

impl std::fmt::Display for ThreadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ThreadError {}

#[cfg(test)]
mod test {
    use crate::{spawn, ThreadError};
    use std::{
        thread,
        thread::{sleep, JoinHandle},
        time::Duration,
    };

    #[test]
    fn works() {
        let worker = spawn(usize::MAX, move || {
            thread::sleep(Duration::from_millis(1500))
        });
        assert!(worker.is_err());
    }

    #[test]
    fn spawn_multiple_workers() {
        let handles: Result<Vec<JoinHandle<()>>, _> = (0..10_000)
            .map(|_| spawn(0, move || thread::sleep(Duration::from_millis(1500))))
            .collect();
        for handle in handles.unwrap() {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_join_multiple_workers() {
        let mut handles = Vec::<Option<JoinHandle<Result<(), ThreadError>>>>::new();

        let handle_1 = spawn(0, move || {
            sleep(Duration::from_millis(3000));
            Ok(())
        })
        .unwrap();
        handles.push(Some(handle_1));

        let handle_2 = spawn(1, move || Err(ThreadError::UnableToGetCoreIds)).unwrap();
        handles.push(Some(handle_2));

        loop {
            for worker in handles.iter_mut() {
                if let Some(handle) = worker.take() {
                    if handle.is_finished() {
                        handle.join().unwrap().unwrap();
                    } else {
                        worker.replace(handle);
                    }
                }
            }
        }
    }
}
