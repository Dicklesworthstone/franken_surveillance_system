#![forbid(unsafe_code)]
//! Source-preserving recorded RTP ingestion. No sockets or credential handling.
mod framing;
pub use framing::*;
/// Ordered recorded-RTP picture grouping through the existing AVC receiver.
pub mod avc;
/// Source-linked native H.264 pixels from bounded ordered recorded RTP.
pub mod decode;
/// Verified neural packages over current-custody native color frames.
pub mod detect;
/// Ordered recorded-RTP NAL reconstruction through the existing HEVC receiver.
pub mod hevc;
/// Source-first publication, capsule linkage and verified readback.
pub mod import;
/// Complete portable receipt streams with fresh native verification.
pub mod receipt_stream;
/// Root-based read-only verification and explicitly committed crash recovery.
pub mod recovery;
/// Recorded packets through the real sequence and H.264 kernels.
pub mod replay;
/// Source-witnessed anonymous tracking of one explicitly selected neural class.
pub mod track;
