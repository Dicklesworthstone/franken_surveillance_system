#![forbid(unsafe_code)]
//! Constant-memory live adapter for the fixed conservative screen. An owner pins one
//! source generation and supplies increasing positions. Work per call is bounded;
//! live streams cannot exhaust a retained-range frame or cumulative sample ceiling.

use super::{HealthError, HealthFrame, HealthObservation, HealthScreen, MAX_HEALTH_PIXELS};
use crate::ReplayCx;
use fss_core::ContentDigest;

/// One ordered source generation, retaining only the preceding measurement.
/// A changed generation needs a fresh owner; lower source positions are refused.
#[derive(Debug)]
pub struct SequentialHealthScreen {
    generation: ContentDigest,
    last_segment: Option<u64>,
    samples_used: u64,
    screen: HealthScreen,
}

impl SequentialHealthScreen {
    /// Binds a fresh temporal baseline to an exact source/interpretation generation.
    #[must_use]
    pub fn new(generation: ContentDigest) -> Self {
        Self {
            generation,
            last_segment: None,
            samples_used: 0,
            screen: HealthScreen::new(MAX_HEALTH_PIXELS as u64),
        }
    }

    /// Completed sample work, including exact retries and cancelled calls.
    #[must_use]
    pub const fn samples_used(&self) -> u64 {
        self.samples_used
    }

    /// Screens with replay-owner cancellation at each row and before digesting.
    pub fn observe(
        &mut self,
        frame: HealthFrame<'_>,
        cx: &ReplayCx,
    ) -> Result<HealthObservation, HealthError> {
        self.observe_with_checkpoint(frame, || {
            cx.checkpoint("sensor_health:sequential_row")
                .map_err(|_| HealthError::Cancelled)
        })
    }

    /// Screens with an explicit live owner's admission/cancellation checkpoint. The
    /// callback runs before work, before every row, and before the luma digest.
    /// Exact immediate retries are idempotent but pay full validation cost.
    pub fn observe_with_checkpoint(
        &mut self,
        frame: HealthFrame<'_>,
        check: impl FnMut() -> Result<(), HealthError>,
    ) -> Result<HealthObservation, HealthError> {
        if frame.source_generation != self.generation
            || self.last_segment.is_some_and(|last| frame.segment < last)
        {
            return Err(HealthError::ReplayedSource);
        }
        // Monotonic source positions replace the retained-range replay set. Preserve
        // the predecessor so policy streaks and their digest chain survive tick boundaries.
        self.screen.seen.clear();
        self.screen.used_samples = 0;
        let segment = frame.segment;
        let observation = self.screen.observe_with(frame, check);
        self.samples_used = self.samples_used.saturating_add(self.screen.samples_used());
        if observation.is_ok() {
            self.last_segment = Some(segment);
        }
        observation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::{CaptureInterval, TimestampNs};

    fn frame<'a>(generation: ContentDigest, segment: u64, pixels: &'a [u8]) -> HealthFrame<'a> {
        HealthFrame {
            source_generation: generation,
            segment,
            capsule_digest: ContentDigest::sha256(&segment.to_le_bytes()),
            capture: CaptureInterval {
                earliest: TimestampNs(segment.into()),
                latest: TimestampNs(segment.into()),
            },
            dimensions: [2, 1],
            gap_before: false,
            pixels,
        }
    }

    #[test]
    fn live_stream_does_not_exhaust_a_range_budget_or_reset_its_streak() -> Result<(), HealthError>
    {
        let generation = ContentDigest::sha256(b"generation");
        let mut screen = SequentialHealthScreen::new(generation);
        for segment in 1..=65_537 {
            let observed = screen
                .observe_with_checkpoint(frame(generation, segment, &[40, 200]), || Ok(()))?;
            assert_eq!(observed.repeated_frames, segment as u32);
            assert_eq!(screen.screen.seen.len(), 1);
        }
        assert_eq!(screen.samples_used(), 131_074);
        Ok(())
    }

    #[test]
    fn retries_are_exact_and_stale_or_changed_generation_is_refused() -> Result<(), HealthError> {
        let generation = ContentDigest::sha256(b"generation");
        let mut screen = SequentialHealthScreen::new(generation);
        let input = frame(generation, 2, &[40, 200]);
        let first = screen.observe_with_checkpoint(input, || Ok(()))?;
        assert_eq!(screen.observe_with_checkpoint(input, || Ok(()))?, first);
        assert_eq!(
            screen.observe_with_checkpoint(frame(generation, 1, &[40, 200]), || Ok(())),
            Err(HealthError::ReplayedSource)
        );
        assert_eq!(
            screen.observe_with_checkpoint(frame(generation, 2, &[40, 201]), || Ok(())),
            Err(HealthError::ReplayedSource)
        );
        assert_eq!(
            screen.observe_with_checkpoint(
                frame(ContentDigest::sha256(b"other"), 3, &[40, 200]),
                || Ok(())
            ),
            Err(HealthError::ReplayedSource)
        );
        assert_eq!(screen.samples_used(), 6);
        let mut gap = frame(generation, 3, &[40, 200]);
        gap.gap_before = true;
        assert!(
            screen
                .observe_with_checkpoint(gap, || Ok(()))?
                .baseline_reset
        );
        Ok(())
    }

    #[test]
    fn cancelled_work_is_charged_without_advancing_history() -> Result<(), HealthError> {
        let generation = ContentDigest::sha256(b"generation");
        let mut screen = SequentialHealthScreen::new(generation);
        let mut checkpoints = 0;
        let result = screen.observe_with_checkpoint(frame(generation, 1, &[40, 200]), || {
            checkpoints += 1;
            if checkpoints == 3 {
                Err(HealthError::Cancelled)
            } else {
                Ok(())
            }
        });
        assert_eq!(result, Err(HealthError::Cancelled));
        assert_eq!(screen.samples_used(), 2);
        assert_eq!(screen.last_segment, None);
        assert!(
            screen
                .observe_with_checkpoint(frame(generation, 1, &[40, 200]), || Ok(()))?
                .baseline_reset
        );
        Ok(())
    }
}
