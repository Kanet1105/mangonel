//! Ethernet II, with the ARP that rides on it.

pub mod arp;
pub mod header;

pub use arp::Arp;
pub use header::{
    EtherType,
    Ethernet,
    HEADER_LEN,
};
