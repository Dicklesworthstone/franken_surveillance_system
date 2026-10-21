#![forbid(unsafe_code)]
//! Conservative admission accounting for retained inter-predicted video ranges.
//!
//! One unit reserves one encoded byte or one sample of the caller's coded-luma capacity.
//! Each access unit reserves both before entering the codec, including pictures buffered for
//! display reordering, malformed pictures and skipped RASL pictures. Out-of-band parameter
//! sets reserve their encoded bytes. These are admission units, not JPEG codec work, measured
//! CPU instructions, wall time or the number of visible output pixels.

use super::{RecordedDecodeError, checkpoint};
use crate::ReplayCx;

/// Stable accounting model printed with every video-motion work receipt.
pub const VIDEO_DECODE_WORK_MODEL: &str = "encoded_bytes_plus_coded_luma_capacity.v1";
/// Independent native admission axes; unspent encoded bytes never enlarge luma capacity.
pub const VIDEO_DECODE_SEPARATE_AXIS_POLICY: &str =
    "encoded_bytes_and_coded_luma_capacity_independent_ceilings.v1";

/// A cumulative owner-supplied allowance shared by range creation and every decode step.
#[derive(Debug)]
pub struct RecordedVideoDecodeBudget {
    maximum: u64,
    used: u64,
    axes: Option<(u64, u64)>,
    encoded_bytes: u64,
    coded_luma_capacity: u64,
}

impl RecordedVideoDecodeBudget {
    /// Creates an allowance; zero permits no encoded input or picture work.
    #[must_use]
    pub const fn new(maximum: u64) -> Self {
        Self {
            maximum,
            used: 0,
            axes: None,
            encoded_bytes: 0,
            coded_luma_capacity: 0,
        }
    }

    /// Independently cap encoded bytes and coded-luma admission before codec work. Unused
    /// source bytes cannot be borrowed to enlarge the pixel allowance, or vice versa.
    /// Picture capacity is the caller's codec ceiling, including buffered and skipped pictures;
    /// it is deliberately distinct from pixels observed in successful display-order outputs.
    pub fn with_separate_limits(
        maximum_encoded_bytes: u64,
        maximum_coded_luma_capacity: u64,
    ) -> Result<Self, RecordedDecodeError> {
        let maximum = maximum_encoded_bytes
            .checked_add(maximum_coded_luma_capacity)
            .ok_or(RecordedDecodeError::Limit)?;
        Ok(Self {
            maximum,
            used: 0,
            axes: Some((maximum_encoded_bytes, maximum_coded_luma_capacity)),
            encoded_bytes: 0,
            coded_luma_capacity: 0,
        })
    }

    /// Units reserved so far, including unsuccessful and buffered decode work.
    #[must_use]
    pub const fn used(&self) -> u64 {
        self.used
    }

    /// Units still available. Gaps, failures and new ranges never renew this allowance.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.maximum - self.used
    }

    /// Encoded bytes admitted to the codec, including parameter sets and failed work.
    #[must_use]
    pub const fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }

    /// Conservative per-access-unit luma capacity admitted before native decode.
    #[must_use]
    pub const fn coded_luma_capacity(&self) -> u64 {
        self.coded_luma_capacity
    }

    pub(super) fn reserve(
        &mut self,
        encoded_bytes: usize,
        coded_luma_capacity: u64,
        cx: &ReplayCx,
    ) -> Result<(), RecordedDecodeError> {
        checkpoint(cx, "recorded_video:reserve")?;
        let bytes = u64::try_from(encoded_bytes).map_err(|_| RecordedDecodeError::Limit)?;
        let units = bytes
            .checked_add(coded_luma_capacity)
            .ok_or(RecordedDecodeError::Limit)?;
        let used = self
            .used
            .checked_add(units)
            .ok_or(RecordedDecodeError::Limit)?;
        let encoded_total = self
            .encoded_bytes
            .checked_add(bytes)
            .ok_or(RecordedDecodeError::Limit)?;
        let luma_total = self
            .coded_luma_capacity
            .checked_add(coded_luma_capacity)
            .ok_or(RecordedDecodeError::Limit)?;
        if used > self.maximum
            || self
                .axes
                .is_some_and(|(encoded, luma)| encoded_total > encoded || luma_total > luma)
        {
            return Err(RecordedDecodeError::Limit);
        }
        self.used = used;
        self.encoded_bytes = encoded_total;
        self.coded_luma_capacity = luma_total;
        Ok(())
    }
}
