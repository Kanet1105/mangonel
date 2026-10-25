//! One error type for every module, so callers can `?`
//! across the whole gateway.

use std::io;

use crate::{control, data};

/// Any error a gateway module returns.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Control(#[from] control::Error),

    #[error(transparent)]
    Data(#[from] data::Error),

    /// From [`control::ControlPlane::spawn`].
    #[error(transparent)]
    Io(#[from] io::Error),
}

// Through control::Error, so a rejected config has one
// shape whichever way it arrives.
impl From<control::ConfigError> for Error {
    fn from(error: control::ConfigError) -> Self {
        Self::Control(error.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_errors_arrive_as_control_errors() {
        let error = control::ConfigError::AutoDnsWithoutDhcp;
        assert!(matches!(
            Error::from(error.clone()),
            Error::Control(control::Error::Config(inner)) if inner == error
        ));
    }
}
