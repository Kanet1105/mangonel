//! A bounded multi-producer, multi-consumer ring in the
//! style of DPDK's `rte_ring`.
//!
//! Threads claim slots in bulk with [`Ring::bulk_write`]
//! and [`Ring::bulk_read`], and dropping the grant
//! commits them in claim order.

mod bulk;
mod error;
mod ring;

pub use bulk::{BulkRead, BulkWrite};
pub use error::Error;
pub use ring::Ring;
