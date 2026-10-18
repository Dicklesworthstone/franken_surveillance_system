#![forbid(unsafe_code)]
//! Author the existing portable recipe by matching explicit timing against cold native requests.
//! No guessed clock, implicit seal, camera connection, publication, or alternate recipe format.

use super::*;
use crate::rtsp::datagram_reconstruction::hevc::HevcReplayError;
use crate::rtsp::datagram_reconstruction::hevc::recording::{
    HevcRecordingReplayFailure, HevcRecordingReplayRetirement, HevcRecordingReplayStep,
};
use crate::rtsp::hevc_recording_capture::{HevcCapturePoll, TimedHevcCapture};
use crate::rtsp::hevc_recording_collector::HevcCollectionSeal;
use fss_geometry::WorkBudget;
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};

/// One independently supplied timing choice for the next picture in the selected source.
/// The RTP timestamp is a matching guard, NOT the origin of decode time or duration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimingInput {
    /// Exact expected raw RTP timestamp, including its original wrapping behavior.
    pub rtp_timestamp: u32,
    /// Explicit media ticks under the independently supplied timing evidence.
    pub timing: HevcRecordingTiming,
}

/// Typed failure. A normal native stop is never converted to a successfully authored recipe.
#[derive(Debug)]
pub enum AuthoringError {
    /// Existing configuration, timing, native replay, current custody or resource refusal.
    Recipe(RecordingRecipeError),
    /// Native loss/discontinuity stopped reconstruction; the original trigger is retained.
    Stopped,
}
impl std::fmt::Display for AuthoringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Recipe(error) => std::fmt::Display::fmt(error, f),
            Self::Stopped => f.write_str("HEVC recipe authoring stopped by native source failure"),
        }
    }
}
impl std::error::Error for AuthoringError {}

/// Exact remaining ownership. A candidate withheld by revocation is not an authoring success.
#[derive(Debug)]
#[must_use]
pub struct AuthoringRetirement {
    /// Original independently selected datagram prefix.
    pub source: DatagramPin,
    /// Timing outcomes already returned normally, not merely attempted choices.
    pub timings_applied: usize,
    /// Existing native failure/cancellation ownership, if not already in withheld output.
    pub recording: Option<Box<HevcRecordingReplayRetirement>>,
    /// Original timing request, stopped result or final retirement rejected by this wrapper.
    pub withheld: Option<Box<HevcRecordingReplayStep>>,
    /// Complete instructions withheld after a post-computation current-authority refusal.
    pub candidate: Option<Box<RecordingRecipe>>,
}

/// Clock reversal is the only nonterminal refusal; every other failure returns custody once.
#[derive(Debug)]
pub struct AuthoringFailure {
    /// Typed failure, without source payloads or private paths.
    pub reason: AuthoringError,
    /// Absent only for an unchanged safe clock refusal.
    pub retirement: Option<Box<AuthoringRetirement>>,
}
impl std::fmt::Display for AuthoringFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for AuthoringFailure {}

/// One bounded native operation. Process every transferred original before the next step.
#[derive(Debug)]
#[must_use]
pub enum AuthoringStep {
    /// Unchanged source/capture output, including preview windows. No publication occurs.
    /// TimingRequired has been matched and its explicit choice is applied on the next step.
    Replay(HevcRecordingReplayStep),
    /// One exact timing choice accepted by native capture, with its original released input.
    TimingApplied {
        /// Zero-based position in the supplied timing schedule.
        index: usize,
        /// Complete native request and accepted timing, committed into the final recipe.
        decision: RecordingTimingDecision,
        /// Native collection disposition; not a recording or source-custody receipt.
        outcome: TimedHevcCapture,
    },
    /// The fixed native policy seals a verified prefix only after all choices were consumed.
    PrefixFinalizing(HevcCollectionSeal),
    /// Complete canonical recipe, created only after the native program finished successfully.
    Finished {
        /// Existing version-one recipe; publication still needs separate explicit authority.
        recipe: Box<RecordingRecipe>,
        /// Incomplete originals, fragments, groups and post-EOB input remain distinct.
        retained: Box<HevcRecordingReplayRetirement>,
    },
    /// Terminal ownership was already returned. No repeat recipe or receipt.
    Ended,
}

/// Bounded authoring over one exact cold source. Requests are observed, not forged by a caller.
/// Every supplied timing row must match and execute; no implicit cadence or defaults exist.
/// Preview windows cannot turn a later timing mismatch into a successful authoring result.
#[must_use]
pub struct RecordingRecipeAuthor<'a> {
    archive: &'a DatagramArchive,
    hevc: HevcReplaySpec,
    recording: Option<HevcRecordingReplaySpec>,
    limits: RecordingRecipeLimits,
    inputs: Vec<TimingInput>,
    decisions: Vec<RecordingTimingDecision>,
    inner: DatagramHevcRecordingReplay<'a>,
    applied: usize,
    pending: Option<RecordingTimingDecision>,
    finalize_pending: bool,
    finalized: bool,
    closed: bool,
}
impl std::fmt::Debug for RecordingRecipeAuthor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingRecipeAuthor")
            .field("source", &self.archive.pin())
            .field("timings", &self.inputs.len())
            .field("applied", &self.applied)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}
impl<'a> RecordingRecipeAuthor<'a> {
    /// Validate original interpretation, all explicit timing, and external ceilings before reads.
    /// The supplied schedule is immutable for this attempt. Replacing it requires a new author.
    pub fn new(
        archive: &'a DatagramArchive,
        hevc: HevcReplaySpec,
        recording: HevcRecordingReplaySpec,
        inputs: Vec<TimingInput>,
        limits: RecordingRecipeLimits,
        bounds: HevcReplayBounds,
        now_ns: u64,
    ) -> Result<Self, RecordingRecipeError> {
        limits.validate()?;
        codec::check_limits(hevc, &recording, limits)?;
        if inputs.len() > limits.max_timings {
            return Err(RecordingRecipeError::Limit);
        }
        let mut end = None;
        for row in &inputs {
            let t = row.timing;
            let next = t
                .decode_time
                .checked_add(u64::from(t.duration))
                .ok_or(RecordingRecipeError::Timing)?;
            if t.duration == 0
                || end.is_some_and(|n| t.decode_time < n)
                || t.decode_time
                    .checked_add_signed(i64::from(t.composition_offset))
                    .is_none()
            {
                return Err(RecordingRecipeError::Timing);
            }
            end = Some(next);
        }
        let mut decisions = Vec::new();
        decisions
            .try_reserve_exact(inputs.len())
            .map_err(|_| RecordingRecipeError::Limit)?;
        let inner = DatagramHevcRecordingReplay::new(
            archive,
            hevc,
            copy_spec(&recording, limits.configuration)?,
            bounds,
            now_ns,
        )
        .map_err(RecordingRecipeError::Replay)?;
        Ok(Self {
            archive,
            hevc,
            recording: Some(recording),
            limits,
            inputs,
            decisions,
            inner,
            applied: 0,
            pending: None,
            finalize_pending: false,
            finalized: false,
            closed: false,
        })
    }

    /// Exact number of source observations read, never inferred from timing rows.
    pub fn observations_read(&self) -> u64 {
        self.inner.observations_read()
    }
    /// Number of timing applications returned successfully.
    pub fn timings_applied(&self) -> usize {
        self.applied
    }

    /// One native source/capture step OR one explicit timing/finalization operation.
    /// Current authority and the shared work budget are inherited by every native operation.
    pub fn step(
        &mut self,
        p: &LocalRootPublisher,
        now_ns: u64,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> Result<AuthoringStep, AuthoringFailure> {
        if self.closed {
            return Ok(AuthoringStep::Ended);
        }
        if let Some(decision) = self.pending {
            let outcome = self
                .inner
                .supply_timing(decision.timing, now_ns, cancel, budget)
                .map_err(|e| self.native_failure(e))?;
            let index = self.applied;
            // Capacity was reserved before any source read or timing admission.
            self.decisions.push(decision);
            self.applied += 1;
            self.pending = None;
            return Ok(AuthoringStep::TimingApplied {
                index,
                decision,
                outcome,
            });
        }
        if self.finalize_pending {
            let seal = self
                .inner
                .finish_prefix(now_ns, cancel, budget)
                .map_err(|e| self.native_failure(e))?;
            self.finalize_pending = false;
            self.finalized = true;
            return Ok(AuthoringStep::PrefixFinalizing(seal));
        }
        let step = self
            .inner
            .step(p, now_ns, cancel, budget)
            .map_err(|e| self.native_failure(e))?;
        match &step {
            HevcRecordingReplayStep::Capture(event) => match &**event {
                HevcCapturePoll::TimingRequired(picture) => {
                    let Some(row) = self.inputs.get(self.applied) else {
                        return Err(self.fail(RecordingRecipeError::MissingTiming, Some(step)));
                    };
                    if row.rtp_timestamp != picture.rtp_timestamp {
                        return Err(self.fail(RecordingRecipeError::Mismatch, Some(step)));
                    }
                    self.pending = Some(RecordingTimingDecision {
                        observations_read: self.inner.observations_read(),
                        picture: *picture,
                        timing: row.timing,
                    });
                }
                HevcCapturePoll::Backpressure { .. } => {
                    return Err(self.fail(RecordingRecipeError::CollectionPressure, Some(step)));
                }
                _ => {}
            },
            HevcRecordingReplayStep::PrefixReady { .. } => {
                if self.applied != self.inputs.len() {
                    return Err(self.fail(RecordingRecipeError::UnusedTiming, Some(step)));
                }
                self.finalize_pending = true;
            }
            HevcRecordingReplayStep::Stopped { .. } => {
                let mut failure = self.fail(RecordingRecipeError::Closed, Some(step));
                failure.reason = AuthoringError::Stopped;
                return Err(failure);
            }
            HevcRecordingReplayStep::Ended => {
                return Err(self.fail(RecordingRecipeError::Closed, Some(step)));
            }
            _ => {}
        }
        if let HevcRecordingReplayStep::FinishedPrefix { retained } = step {
            if !self.finalized || self.applied != self.inputs.len() {
                return Err(self.fail(
                    RecordingRecipeError::UnusedTiming,
                    Some(HevcRecordingReplayStep::FinishedPrefix { retained }),
                ));
            }
            // Price complete bounded canonical encoding/revalidation before constructing it.
            if let Err(error) = budget.charge(self.limits.max_bytes as u64 * 4 + 4096) {
                return Err(self.fail(
                    RecordingRecipeError::Source(DatagramArchiveError::Work(error)),
                    Some(HevcRecordingReplayStep::FinishedPrefix { retained }),
                ));
            }
            let Some(recording) = self.recording.take() else {
                return Err(self.fail(
                    RecordingRecipeError::Closed,
                    Some(HevcRecordingReplayStep::FinishedPrefix { retained }),
                ));
            };
            let recipe = match RecordingRecipe::new(
                self.archive,
                self.hevc,
                recording,
                std::mem::take(&mut self.decisions),
                self.limits,
            ) {
                Ok(recipe) => recipe,
                Err(error) => {
                    return Err(self.fail(
                        error,
                        Some(HevcRecordingReplayStep::FinishedPrefix { retained }),
                    ));
                }
            };
            if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
                let mut failure = self.fail(
                    RecordingRecipeError::Source(DatagramArchiveError::Cancelled),
                    Some(HevcRecordingReplayStep::FinishedPrefix { retained }),
                );
                if let Some(state) = &mut failure.retirement {
                    state.candidate = Some(Box::new(recipe));
                }
                return Err(failure);
            }
            self.closed = true;
            return Ok(AuthoringStep::Finished {
                recipe: Box::new(recipe),
                retained,
            });
        }
        Ok(AuthoringStep::Replay(step))
    }

    /// Return all remaining native ownership without source reads, sealing or publication.
    pub fn cancel(&mut self) -> Option<AuthoringRetirement> {
        if self.closed {
            return None;
        }
        self.closed = true;
        Some(AuthoringRetirement {
            source: self.archive.pin(),
            timings_applied: self.applied,
            recording: self.inner.cancel().map(Box::new),
            withheld: None,
            candidate: None,
        })
    }
    fn fail(
        &mut self,
        reason: RecordingRecipeError,
        withheld: Option<HevcRecordingReplayStep>,
    ) -> AuthoringFailure {
        self.closed = true;
        AuthoringFailure {
            reason: AuthoringError::Recipe(reason),
            retirement: Some(Box::new(AuthoringRetirement {
                source: self.archive.pin(),
                timings_applied: self.applied,
                recording: self.inner.cancel().map(Box::new),
                withheld: withheld.map(Box::new),
                candidate: None,
            })),
        }
    }
    fn native_failure(&mut self, failure: HevcRecordingReplayFailure) -> AuthoringFailure {
        if failure.retirement.is_none()
            && matches!(
                &failure.reason,
                HevcRecordingReplayError::Replay(HevcReplayError::ClockReversed)
            )
        {
            return AuthoringFailure {
                reason: AuthoringError::Recipe(RecordingRecipeError::Replay(failure.reason)),
                retirement: None,
            };
        }
        self.closed = true;
        AuthoringFailure {
            reason: AuthoringError::Recipe(RecordingRecipeError::Replay(failure.reason)),
            retirement: Some(Box::new(AuthoringRetirement {
                source: self.archive.pin(),
                timings_applied: self.applied,
                recording: failure
                    .retirement
                    .or_else(|| self.inner.cancel().map(Box::new)),
                withheld: None,
                candidate: None,
            })),
        }
    }
}
