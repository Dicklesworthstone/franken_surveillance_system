#![forbid(unsafe_code)]
//! Root-last coordination between immutable child custody and canonical authority history.
//!
//! This crate is the semantic narrow waist between `fss-object` and `fss-ledger`: object custody
//! never imports authority, and the ledger never learns how objects are stored. The coordinator
//! proves every exact child root verified immediately before the authority batch is allowed to
//! cross the durable commit boundary.

mod error;
mod publisher;

#[cfg(test)]
mod tests;

pub use error::PublicationError;
pub use publisher::AuthorityPublisher;
