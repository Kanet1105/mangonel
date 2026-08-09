//! Mangonel: an AF_XDP router.
//!
//! [`state::State`] owns interface attachments; each
//! attachment pins one worker per queue. The workers
//! currently receive, count, and drop — the substrate the
//! forwarding path will grow on.

pub mod state;
mod worker;
