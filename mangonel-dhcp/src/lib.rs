//! mangonel-dhcp: DHCPv4 and DHCPv6 servers and clients
//! for the gateway, without any I/O of their own.
//!
//! Every server and client here is a state machine over
//! bytes. The caller owns the sockets or frames and the
//! clock: it hands a UDP payload and `now` in, and gets
//! packets to send, lease events and a wake-up time out.
//! That keeps the crate free of privileges and threads,
//! so it tests on its own. [`dhcproto`] does the encoding
//! and decoding.
//!
//! The server for a LAN pool lives in [`v4::server`] and
//! [`v6::server`]; the client for a WAN port in
//! [`v4::client`] and [`v6::client`].

#![warn(unreachable_pub)]

mod error;
mod rng;
pub mod v4;
pub mod v6;

pub use error::Error;
