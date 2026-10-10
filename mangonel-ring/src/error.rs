#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Ring size: {0} is not the power of two.")]
    IsNotPowerOfTwo(usize),

    #[error("Claim size must be greater than zero.")]
    ZeroClaimSize,

    #[error("Ring is full.")]
    RingIsFull,

    #[error("Ring is empty.")]
    RingIsEmpty,
}
