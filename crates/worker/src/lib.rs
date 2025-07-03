use core_affinity::CoreId;
use std::thread::{self, JoinHandle};

/// Spawns a worker thread pinned to the specific core by core ID.
///
pub fn spawn_worker<F, T>(
    core_id: usize,
    function: F,
) -> Result<JoinHandle<Result<T, WorkerError>>, WorkerError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let core_ids = core_affinity::get_core_ids().ok_or(WorkerError::UnableToGetCoreIds)?;
    let core_id = CoreId { id: core_id };
    if !core_ids.contains(&core_id) {
        return Err(WorkerError::PinThreadToCore(core_id));
    }

    let handle = thread::spawn(move || {
        if core_affinity::set_for_current(core_id) {
            Ok(function())
        } else {
            Err(WorkerError::PinThreadToCore(core_id))
        }
    });
    Ok(handle)
}

pub enum WorkerError {
    UnableToGetCoreIds,
    PinThreadToCore(CoreId),
}

impl std::fmt::Debug for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnableToGetCoreIds => write!(f, "Unable to get core"),
            Self::PinThreadToCore(core_id) => {
                write!(f, "Unable to pin thread to the core (ID = {})", core_id.id)
            }
        }
    }
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for WorkerError {}

#[test]
fn works() {
    use std::time::Duration;

    let worker_1 = spawn_worker(0, move || thread::sleep(Duration::from_millis(1500)));
    assert!(worker_1.is_ok());

    let worker_2 = spawn_worker(usize::MAX, move || {
        thread::sleep(Duration::from_millis(1500))
    });
    assert!(worker_2.is_err());
    drop(worker_2);

    worker_1.unwrap().join().unwrap().unwrap();
}

#[test]
fn spawn_multiple_workers() {
    use std::time::Duration;

    let handles: Vec<JoinHandle<Result<(), WorkerError>>> = (0..10_000)
        .map(|_| spawn_worker(0, move || thread::sleep(Duration::from_millis(1500))).unwrap())
        .collect();

    for handle in handles {
        handle.join().unwrap().unwrap();
    }
}
