#![forbid(unsafe_code)]
//! Original interleaved RTP/RTCP custody, shared by native AVC, HEVC and JPEG owners.
//! The source inventory, wire preparation and cold prefix selection are codec-neutral.

#[path = "datagram_archive/source.rs"]
mod source;
pub use source::*;

/// Native AVC capture with original-datagram publication before further media progress.
#[path = "datagram_archive/live.rs"]
pub mod live;

#[cfg(test)]
#[path = "datagram_archive/tests/live.rs"]
mod live_tests;
