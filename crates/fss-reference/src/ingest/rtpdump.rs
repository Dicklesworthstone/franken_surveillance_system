#![forbid(unsafe_code)]
//! Source-preserving recorded RTP ingestion. No sockets or credential handling.
mod framing;
pub use framing::*;
/// Recorded packets through the real sequence and H.264 kernels.
pub mod replay;
