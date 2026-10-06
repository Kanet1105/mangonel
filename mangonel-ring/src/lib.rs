//! mangonel-ring: bounded lock-free rings that move batches
//! between threads.
//!
//! - [`spsc`]: one producer, one consumer, any `T: Send`.
//! - [`mpmc`]: any number of producers and consumers
//!   sharing one ring of `T: Copy`, through claimed ranges
//!   read and written in place.
//!
//! Both touch the shared cursors a fixed number of times
//! per batch rather than per item.

#![warn(unreachable_pub)]

pub mod mpmc;
pub mod spsc;
mod error;

pub use error::Error;
