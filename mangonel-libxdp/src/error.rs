use crate::{ring::RingError, socket::SocketError, umem::UmemError};

/// The error type for this crate: any failure reported
/// while setting up or driving an AF_XDP socket.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct XdpError(Error);

/// Private aggregate of every module's error, so none of
/// them leak into the public API.
#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Ring(#[from] RingError),
    #[error(transparent)]
    Umem(#[from] UmemError),
    #[error(transparent)]
    Socket(#[from] SocketError),
}

impl From<RingError> for XdpError {
    fn from(error: RingError) -> Self {
        Self(error.into())
    }
}

impl From<UmemError> for XdpError {
    fn from(error: UmemError) -> Self {
        Self(error.into())
    }
}

impl From<SocketError> for XdpError {
    fn from(error: SocketError) -> Self {
        Self(error.into())
    }
}
