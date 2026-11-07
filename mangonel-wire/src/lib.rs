//! In-place views over the frames a gateway forwards.
//!
//! Each view wraps the bytes it was parsed from, so reading
//! a field decodes it where it lies and writing one encodes
//! it there. Nothing is copied. `parse` checks only what the
//! accessors rely on: lengths and the fixed fields a header
//! is recognised by. A view over `&mut [u8]` reads and
//! writes; one over `&[u8]` only reads. [`parse`] takes a
//! whole frame apart into a [`Frame`], and
//! [`Ipv4::transport_mut`] and [`Ipv6::transport_mut`] carry
//! on into a [`Transport`].
//!
//! # Examples
//! ```
//! use mangonel_wire::{Packet, Transport};
//!
//! # let mut data = [0u8; 60];
//! # data[12..14].copy_from_slice(&[0x08, 0x00]);
//! # let mut ip = mangonel_wire::Ipv4::init(&mut data[14..])?;
//! # ip.set_total_length(28)?;
//! # ip.set_protocol(mangonel_wire::Protocol::UDP);
//! # mangonel_wire::Udp::init(ip.payload_mut())?;
//! let mut frame = mangonel_wire::parse(&mut data[..])?;
//! match frame.packet_mut() {
//!     Packet::Arp(arp) => { /* answer it */ }
//!     Packet::Ipv4(ip) => match ip.transport_mut()? {
//!         Transport::Udp(udp) => assert_eq!(udp.length(), 8),
//!         _ => {}
//!     },
//!     _ => {}
//! }
//! let (dst, src) = (frame.destination(), frame.source());
//! frame.set_destination(src);
//! frame.set_source(dst);
//! # Ok::<(), mangonel_wire::Error>(())
//! ```
//!
//! Building a frame from the setters up:
//! ```
//! use std::net::Ipv4Addr;
//!
//! use mangonel_wire::{Ethernet, Ipv4, Protocol, Udp, ethernet::EtherType};
//!
//! let mut frame = [0u8; 64];
//! let mut eth = Ethernet::parse(&mut frame[..])?;
//! eth.set_destination([2, 0, 0, 1, 0, 2]);
//! eth.set_source([2, 0, 0, 4, 0, 0]);
//! eth.set_ethertype(EtherType::IPV4);
//! let mut ip = Ipv4::init(eth.payload_mut())?;
//! ip.set_total_length(28)?;
//! ip.set_ttl(64);
//! ip.set_protocol(Protocol::UDP);
//! ip.set_source(Ipv4Addr::new(10, 0, 0, 2));
//! ip.set_destination(Ipv4Addr::new(10, 0, 0, 1));
//! ip.fill_checksum();
//! let (src, dst) = (ip.source(), ip.destination());
//! let mut udp = Udp::init(ip.payload_mut())?;
//! udp.set_source_port(68);
//! udp.set_destination_port(67);
//! udp.fill_checksum(src.into(), dst.into());
//!
//! let eth = Ethernet::parse(&frame[..])?;
//! let ip = Ipv4::parse(eth.payload())?;
//! assert!(ip.verify_checksum());
//! assert_eq!(ip.protocol(), Protocol::UDP);
//! # Ok::<(), mangonel_wire::Error>(())
//! ```

#![warn(unreachable_pub)]

pub mod arp;
pub mod checksum;
mod error;
pub mod ethernet;
mod field;
mod frame;
pub mod icmpv4;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod nd;
mod protocol;
pub mod tcp;
mod transport;
pub mod udp;
pub mod vlan;

pub use arp::Arp;
pub use error::Error;
pub use ethernet::Ethernet;
pub use frame::{
    Frame,
    Packet,
    parse,
};
pub use icmpv4::Icmpv4;
pub use icmpv6::Icmpv6;
pub use ipv4::Ipv4;
pub use ipv6::Ipv6;
pub use protocol::Protocol;
pub use tcp::Tcp;
pub use transport::Transport;
pub use udp::Udp;
pub use vlan::Vlan;
