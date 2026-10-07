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

/// A cumulative owner-supplied allowance shared by range creation and every decode step.
#[derive(Debug)]
pub struct RecordedVideoDecodeBudget {
    maximum: u64,
    used: u64,
}

impl RecordedVideoDecodeBudget {
    /// Creates an allowance; zero permits no encoded input or picture work.
    #[must_use]
    pub const fn new(maximum: u64) -> Self {
        Self { maximum, used: 0 }
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

    pub(super) fn reserve(
        &mut self,
        encoded_bytes: usize,
        coded_luma_capacity: u64,
        cx: &ReplayCx,
    ) -> Result<(), RecordedDecodeError> {
        checkpoint(cx, "recorded_video:reserve")?;
        let units = u64::try_from(encoded_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_add(coded_luma_capacity))
            .ok_or(RecordedDecodeError::Limit)?;
        let used = self
            .used
            .checked_add(units)
            .ok_or(RecordedDecodeError::Limit)?;
        if used > self.maximum {
            return Err(RecordedDecodeError::Limit);
        }
        self.used = used;
        Ok(())
    }
}
