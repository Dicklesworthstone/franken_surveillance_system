#![forbid(unsafe_code)]
//! Source-preserving recorded RTP ingestion. No sockets or credential handling.
mod framing;
pub use framing::*;
/// Ordered recorded-RTP picture grouping through the existing AVC receiver.
pub mod avc;
/// Source-first publication, capsule linkage and verified readback.
pub mod import;
/// Root-based read-only verification and explicitly committed crash recovery.
pub mod recovery;
/// Recorded packets through the real sequence and H.264 kernels.
pub mod replay;
