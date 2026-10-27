//! Why a message was rejected or a configuration refused.

use std::net::IpAddr;

use dhcproto::error::DecodeError;
use thiserror::Error as ThisError;

/// Why a message was rejected or a configuration refused.
///
/// # Examples
/// ```
/// use mangonel_dhcp::{Error, v4::server::Server};
///
/// let mut server = Server::new(mangonel_dhcp::v4::server::Config {
///     address: "10.0.0.1".parse()?,
///     prefix: 24,
///     pool_start: "10.0.0.10".parse()?,
///     pool_end: "10.0.0.200".parse()?,
///     dns: vec![],
///     lease_time: std::time::Duration::from_secs(60),
/// })?;
/// let garbage = [0u8; 3];
/// assert!(matches!(
///     server.handle(&garbage, std::time::Instant::now()),
///     Err(Error::Decode(_))
/// ));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("malformed message: {0}")]
    Decode(#[from] DecodeError),
    #[error("prefix /{0} leaves no room for a pool")]
    PrefixTooLong(u8),
    #[error("pool start {0} is after pool end {1}")]
    PoolReversed(IpAddr, IpAddr),
    #[error("pool {0} - {1} is not a host range inside the subnet")]
    PoolOutsideSubnet(IpAddr, IpAddr),
    #[error("server address {0} is inside its own pool")]
    AddressInPool(IpAddr),
    #[error("a lifetime of zero")]
    ZeroLifetime,
    #[error("preferred lifetime is longer than the valid lifetime")]
    PreferredOutlivesValid,
}
