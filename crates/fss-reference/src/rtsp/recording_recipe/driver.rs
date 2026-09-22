#![forbid(unsafe_code)]
//! Execute retained timing decisions through the existing source-verified recording owner.
use super::*;
use crate::rtsp::datagram_reconstruction::recording::{RecordingReplayFailure, RecordingReplayRetirement, RecordingReplayStep};
use crate::rtsp::recording_capture::{CapturePoll, TimedCapture};
use fss_geometry::WorkBudget;
use fss_publication::{LocalRootPublisher, PublishCancellation};

/// Existing reconstruction output plus explicit, actually applied timing decisions.
#[derive(Debug)]
#[must_use]
pub enum RecipeReplayStep {
    /// Original source, media, timing request, recording window, stop or prefix result.
    /// A returned TimingRequired is matched now and applied automatically on the next step.
    Replay(RecordingReplayStep),
    /// The exact recorded decision was accepted, with all unselected originals still owned.
    TimingApplied {
        /// Zero-based index in the immutable recipe.
        index: usize,
        /// Complete retained request and timing choice.
        decision: RecordingTimingDecision,
        /// Existing collection result; it is not a publication receipt.
        outcome: TimedCapture,
    },
    /// Explicit fixed-policy finalization was requested after every timing decision was consumed.
    PrefixFinalizing,
    /// Terminal ownership has already been transferred.
    Ended,
}
/// Remaining source and derived work; recipe mismatch never silently discards a held picture.
#[derive(Debug)]
#[must_use]
pub struct RecipeReplayRetirement {
    /// Exact recipe used for this attempt.
    pub recipe: ContentDigest,
    /// Number of timing decisions whose successful results were returned by this wrapper.
    pub timings_applied: usize,
    /// Native failure/cancellation state, including any withheld timing result or recording.
    pub recording: Option<Box<RecordingReplayRetirement>>,
    /// Original result which failed recipe admission, if any.
    pub withheld: Option<Box<RecordingReplayStep>>,
}
/// Safe clock refusals leave retirement absent; fatal errors transfer every held original.
#[derive(Debug)]
pub struct RecipeReplayFailure {
    /// Typed reason, without raw source or paths.
    pub reason: RecordingRecipeError,
    /// Present when this attempt stopped and transferred ownership.
    pub retirement: Option<Box<RecipeReplayRetirement>>,
}
impl std::fmt::Display for RecipeReplayFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { std::fmt::Display::fmt(&self.reason, f) }
}
impl std::error::Error for RecipeReplayFailure {}

/// No manual timing/inner-owner escape. One call advances one native operation, not an unbounded
/// replay loop. Stored receive time, current storage time and explicit media ticks stay separate.
#[derive(Debug)]
#[must_use]
pub struct PlannedRecordingReplay<'a> {
    recipe: &'a RecordingRecipe,
    inner: DatagramRecordingReplay<'a>,
    timing_index: usize,
    timing_pending: bool,
    finalize_pending: bool,
    closed: bool,
}
impl<'a> PlannedRecordingReplay<'a> {
    /// Revalidate source and all external configuration ceilings. Operational step/deadline/byte
    /// budgets are caller-supplied, never restored from the portable recipe.
    pub fn new(recipe: &'a RecordingRecipe, archive: &'a DatagramArchive, limits: RecordingRecipeLimits,
        bounds: AvcReplayBounds, now_ns: u64) -> Result<Self, RecordingRecipeError> {
        limits.validate()?;
        if recipe.source != archive.pin() { return Err(RecordingRecipeError::Mismatch); }
        if recipe.bytes.len() > limits.max_bytes || recipe.timings.len() > limits.max_timings {
            return Err(RecordingRecipeError::Limit);
        }
        codec::check_limits(recipe.avc.limits, recipe.recording.limits, limits)?;
        let inner = DatagramRecordingReplay::new(archive, recipe.avc.spec(), recipe.recording.clone(), bounds, now_ns)
            .map_err(RecordingRecipeError::Replay)?;
        if inner.interpretation() != recipe.interpretation { return Err(RecordingRecipeError::Mismatch); }
        Ok(Self { recipe, inner, timing_index: 0, timing_pending: false, finalize_pending: false, closed: false })
    }
    /// Number of original observations read; remains fixed during timing application.
    pub fn observations_read(&self) -> u64 { self.inner.observations_read() }
    /// Number of successfully returned timing applications.
    pub fn timings_applied(&self) -> usize { self.timing_index }
    /// One bounded source/capture operation or exact timing/finalization command.
    pub fn step(&mut self, publisher: &LocalRootPublisher, now_ns: u64,
        cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>)
        -> Result<RecipeReplayStep, RecipeReplayFailure> {
        if self.closed { return Ok(RecipeReplayStep::Ended); }
        if self.timing_pending {
            let Some(decision) = self.recipe.timings.get(self.timing_index).copied() else {
                return Err(self.fail(RecordingRecipeError::MissingTiming, None));
            };
            let outcome = self.inner.supply_timing(decision.timing, now_ns, cancel, budget)
                .map_err(|e| self.native_failure(e))?;
            let index = self.timing_index;
            self.timing_index += 1; self.timing_pending = false;
            return Ok(RecipeReplayStep::TimingApplied { index, decision, outcome });
        }
        if self.finalize_pending {
            self.inner.finish_prefix(now_ns, cancel, budget).map_err(|e| self.native_failure(e))?;
            self.finalize_pending = false;
            return Ok(RecipeReplayStep::PrefixFinalizing);
        }
        let step = self.inner.step(publisher, now_ns, cancel, budget).map_err(|e| self.native_failure(e))?;
        match &step {
            RecordingReplayStep::Capture(CapturePoll::TimingRequired(picture)) => {
                let Some(decision) = self.recipe.timings.get(self.timing_index) else {
                    return Err(self.fail(RecordingRecipeError::MissingTiming, Some(step)));
                };
                if decision.picture != *picture || decision.observations_read != self.inner.observations_read() {
                    return Err(self.fail(RecordingRecipeError::Mismatch, Some(step)));
                }
                self.timing_pending = true;
            }
            RecordingReplayStep::Capture(CapturePoll::Backpressure(_)) => {
                return Err(self.fail(RecordingRecipeError::CollectionPressure, Some(step)));
            }
            RecordingReplayStep::PrefixReady { .. } => {
                if self.timing_index != self.recipe.timings.len() {
                    return Err(self.fail(RecordingRecipeError::UnusedTiming, Some(step)));
                }
                self.finalize_pending = true;
            }
            RecordingReplayStep::FinishedPrefix { .. } | RecordingReplayStep::Stopped { .. } => self.closed = true,
            RecordingReplayStep::Ended => return Err(self.fail(RecordingRecipeError::Closed, Some(step))),
            _ => {},
        }
        Ok(RecipeReplayStep::Replay(step))
    }
    /// Cancel without a seal, source read, publication, cleanup or invented terminal frame.
    pub fn cancel(&mut self) -> Option<RecipeReplayRetirement> {
        if self.closed { return None; }
        self.closed = true;
        Some(RecipeReplayRetirement { recipe: self.recipe.identity, timings_applied: self.timing_index,
            recording: self.inner.cancel().map(Box::new), withheld: None })
    }
    fn fail(&mut self, reason: RecordingRecipeError, withheld: Option<RecordingReplayStep>) -> RecipeReplayFailure {
        self.closed = true;
        RecipeReplayFailure { reason, retirement: Some(Box::new(RecipeReplayRetirement {
            recipe: self.recipe.identity, timings_applied: self.timing_index,
            recording: self.inner.cancel().map(Box::new), withheld: withheld.map(Box::new) })) }
    }
    fn native_failure(&mut self, failure: RecordingReplayFailure) -> RecipeReplayFailure {
        // A recipe cannot correct an invalid stored timing choice. Only clock regression is
        // retryable; every other native refusal fences this wrapper and preserves held work.
        if failure.retirement.is_none() && matches!(&failure.reason,
            RecordingReplayError::Replay(crate::rtsp::datagram_reconstruction::AvcReplayError::ClockReversed)) {
            return RecipeReplayFailure { reason: RecordingRecipeError::Replay(failure.reason), retirement: None };
        }
        self.closed = true;
        RecipeReplayFailure { reason: RecordingRecipeError::Replay(failure.reason),
            retirement: Some(Box::new(RecipeReplayRetirement {
                recipe: self.recipe.identity, timings_applied: self.timing_index,
                recording: failure.retirement.or_else(|| self.inner.cancel().map(Box::new)), withheld: None })) }
    }
}
