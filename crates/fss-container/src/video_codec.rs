#![forbid(unsafe_code)]
//! Shared video coding identity for source-preserving container parsers.

/// Video coding declared by the selected container video stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoCodec {
    /// H.264 (`avc1` with `avcC`).
    Avc,
    /// H.265 (`hvc1` or `hev1` with `hvcC`); base layer only.
    Hevc,
}
