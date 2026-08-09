//! Mangonel: an AF_XDP router.
//!
//! [`state::State`] owns interface attachments; each
//! attachment pins one worker per queue. The workers
//! currently receive, count, and drop — the substrate the
//! forwarding path will grow on. [`api`] is the control
//! contract the daemon serves.

pub mod api;
pub mod config;
pub mod state;
mod worker;
