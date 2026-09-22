#![forbid(unsafe_code)]
//! Baseline-profile H.264 pixel decode, scalar reference slice.
//!
//! This crate owns the first genuine H.264 *pixel* decode stage: network
//! abstraction layer units enter, reconstructed luma samples eventually leave,
//! with every stage bounded, deterministic, and receipt-bearing. It composes
//! on top of `fss-packet`'s AVC syntax custody (SPS/PPS, NAL framing) and
//! `fss-core` budgets/digests; it never parses parameter sets a second time
//! and never trusts a NAL that `fss-packet` refused.
//!
//! Stage map (implemented / planned, in decode order):
//! 1. [`rbsp`] — NAL header, emulation-prevention removal (RBSP extraction),
//!    trailing-bit discipline. Implemented; round-trip and spec-vector tested.
//! 2. `bits` — bounds-checked bit reader with the spec's ue/se/te mappings
//!    over RBSP bytes. Implemented; golden-vector tested.
//! 3. `cavlc` — CAVLC residual coefficient decoding (Table 9-5 coeff_token
//!    contexts, level/total_zeros/run_before). Next slice.
//! 4. intra prediction and reconstruction to luma planes. Planned.
//!
//! Everything here is a scalar reference: correctness receipts first,
//! optimization only after an operation-cost row and a differential oracle
//! (FFmpeg, sealed lab lane) exist, per the repository constitution.
#![allow(clippy::module_name_repetitions)]

pub mod bits;
pub mod cavlc;
pub mod rbsp;
mod tables;
#[cfg(test)]
mod tables_tests;

use fss_packet::avc::AvcError;

/// Typed decode failure for this crate. Wraps `fss-packet` syntax refusals
/// verbatim so upstream custody and decode reject with one vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The NAL or its payload violated a hard bound.
    Limit,
    /// Structural corruption (impossible syntax, bad trailing bits, failed
    /// emulation-prevention invariants).
    Malformed,
    /// A NAL of an unexpected type reached this stage.
    UnexpectedNal,
    /// Syntax declared by the stream exceeds the admitted profile/tool set.
    Unsupported,
    /// Propagated `fss-packet` syntax error.
    Packet(AvcError),
}

impl From<AvcError> for DecodeError {
    fn from(value: AvcError) -> Self {
        match value {
            AvcError::Limit => Self::Limit,
            AvcError::Malformed => Self::Malformed,
            AvcError::UnexpectedNal => Self::UnexpectedNal,
            AvcError::UnsupportedProfile | AvcError::UnsupportedSampleFormat => Self::Unsupported,
            other => Self::Packet(other),
        }
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Limit => write!(f, "h264 decode input exceeded hard limits"),
            Self::Malformed => write!(f, "h264 bitstream is structurally malformed"),
            Self::UnexpectedNal => write!(f, "unexpected nal unit type at this decode stage"),
            Self::Unsupported => write!(f, "h264 syntax outside the admitted baseline tool set"),
            Self::Packet(err) => write!(f, "avc syntax refusal: {err}"),
        }
    }
}
impl std::error::Error for DecodeError {}
