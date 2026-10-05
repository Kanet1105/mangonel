//! mangonel-data-plane: AF_XDP workers that forward packets
//! under the control plane's configuration.
//!
//! Frames flow through two stages. [`IoThread`]s own the
//! sockets: they receive, pick each frame's worker by flow
//! through the shared [`Buckets`] table, and send whatever
//! the workers hand back. Workers only process, connected
//! to every I/O thread by a [`WorkerLink`].

#![warn(unreachable_pub)]

mod buckets;
mod flow;
mod io;

pub use buckets::{Buckets, DEFAULT_BUCKET_COUNT};
pub use flow::flow_hash;
pub use io::{IoConfig, IoStats, IoThread, Packet, PortId, WorkerLink};
/// The rings a [`WorkerLink`] is made of.
pub use mangonel_ring::spsc;
