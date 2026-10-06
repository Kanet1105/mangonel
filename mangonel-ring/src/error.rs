#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ring size {0} must be a power of two")]
    InvalidSize(usize),

    #[error("batch size {batch_size} must be 1 to {ring_size}, the ring size")]
    InvalidBatchSize { batch_size: usize, ring_size: usize },

    #[error("requested {requested} slots, but only {available} are available")]
    Insufficient { requested: usize, available: usize },

    #[error("all {0} granted slots have been used")]
    GrantExhausted(usize),
}
