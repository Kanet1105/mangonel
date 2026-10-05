//! mangonel-ring: bounded lock-free rings that move batches
//! between threads.
//!
//! - [`spsc`]: one producer, one consumer, any `T: Send`.

#![warn(unreachable_pub)]

pub mod spsc;
