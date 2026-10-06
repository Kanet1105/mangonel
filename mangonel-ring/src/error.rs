#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ring size {0} must be a power of two")]
    InvalidSize(usize),

    #[error("batch size {batch_size} must be 1 to {ring_size}, the ring size")]
    InvalidBatchSize { batch_size: usize, ring_size: usize },

    #[error("not enough free slots: requested {requested}, available {available}")]
    InsufficientSpace { requested: usize, available: usize },

    #[error("not enough items: requested {requested}, available {available}")]
    InsufficientItems { requested: usize, available: usize },
}
