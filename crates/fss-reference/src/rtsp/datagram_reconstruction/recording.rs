#![forbid(unsafe_code)]
//! Cold source -> receiver -> explicit timing -> existing immutable recording windows.

use super::*;
use crate::rtsp::recording::RecordingScope;
use crate::rtsp::recording_capture::{
    CaptureError, CapturePoll, CaptureRetirement, RecordingCapture, TimedCapture,
};
use crate::rtsp::recording_collector::{
    CollectorError, CollectorLimits, RecordingCollector, RecordingTiming,
};

/// Independent recording interpretation; it never grants source read or publication authority.
#[derive(Clone, Debug)]
pub struct RecordingReplaySpec {
    /// Owner-selected sensor/stream/history anchor; generation and receive clock must match source.
    pub scope: RecordingScope,
    /// Explicit decode/presentation tick rate, never inferred from RTP arrival.
    pub time_scale: u32,
    /// Existing bounded source/picture collection policy, included in this interpretation.
    pub limits: CollectorLimits,
    /// Accepted evidence for the media clock and per-picture timing decision source.
    pub timing_evidence: ContentDigest,
}

/// Runtime and recoverable timing refusals remain distinguishable.
#[derive(Debug)]
pub enum RecordingReplayError {
    /// Wrong source generation/receive clock or invalid recording/timing interpretation.
    Configuration,
    /// Current storage/cancellation/reconstruction refused progress.
    Replay(AvcReplayError),
    /// The existing recording collector refused input, timing, or sealing.
    Capture(CaptureError),
    /// Final prefix sealing requires that the exact retained prefix was first exhausted.
    PrefixNotReady,
    /// No new command is accepted after terminal ownership transfer or finalization.
    Closed,
}
impl std::fmt::Display for RecordingReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recording reconstruction refused: {self:?}")
    }
}
impl std::error::Error for RecordingReplayError {}

/// Which original lower-level result stopped this recording interpretation.
#[derive(Debug)]
pub enum RecordingReplayStop {
    /// Malformed source, source restart or in-band codec termination; never transport EOF.
    Source(Box<AvcReplayStep>),
    /// Existing discontinuity/deadline/codec refusal with its exact capture retirement.
    Collection(Box<CapturePoll>),
}

/// Every transferred result is distinct from publication or full-stream completion.
#[derive(Debug)]
#[must_use]
pub enum RecordingReplayStep {
    /// Original datagram/RTCP/admission or deterministic virtual-clock advance.
    Source(Box<AvcReplayStep>),
    /// One existing receiver event entered capture; no source was read by this transfer.
    MediaQueued,
    /// Unchanged timing request, original receiver event, pressure or prepared recording.
    /// A Window is the ordinary PreparedRecording and can use the existing root-last publisher.
    Capture(Box<CapturePoll>),
    /// No more source is read. Explicitly call finish_prefix to seal only completed groups,
    /// or cancel to retain them unsealed. Waiting does not renew the current deadline.
    PrefixReady {
        /// Exact bounded input, not a stream-completeness claim.
        source: DatagramPin,
        /// Immutable source/receiver/recording interpretation, excluding future timing choices.
        interpretation: ContentDigest,
    },
    /// Explicit final prefix sealing/draining completed. Incomplete originals and receiver
    /// state remain in retained; this does not claim that a camera or TCP stream reached EOF.
    FinishedPrefix {
        /// Every unsealed source and lower-level prefix retirement transfers once.
        retained: Box<RecordingReplayRetirement>,
    },
    /// Reconstruction stopped without sealing a fake terminal window.
    Stopped {
        /// The exact original invalidating event.
        trigger: RecordingReplayStop,
        /// Other still-owned input, never silently discarded or republished.
        retained: Box<RecordingReplayRetirement>,
    },
    /// Terminal ownership was already transferred.
    Ended,
}

/// Full remaining bounded ownership after stop, cancellation or a withheld output.
#[derive(Debug)]
#[must_use]
pub struct RecordingReplayRetirement {
    /// Source/configuration/scheduler/recording policy commitment.
    pub interpretation: ContentDigest,
    /// Exact selected source prefix.
    pub source: DatagramPin,
    /// Original lower-level failure/receiver state, unless its terminal output already owns it.
    pub replay: Option<AvcReplayRetirement>,
    /// Completed/unsealed originals and any picture still awaiting explicit timing.
    pub capture: Option<CaptureRetirement>,
    /// Exact PrefixExhausted result, including incomplete receiver accounting.
    pub prefix: Option<Box<AvcReplayStep>>,
    /// A receiver event refused before capture admission, intact.
    pub unoffered_media: Option<Box<AvcReceivePoll>>,
    /// Result withheld by a post-computation authority/budget failure, including prepared media.
    pub withheld: Option<Box<RecordingReplayStep>>,
    /// Timing outcome withheld after its admission; unselected originals remain owned here.
    pub withheld_timing: Option<TimedCapture>,
}

/// Invalid timing/clock commands can be corrected in place. Fatal errors transfer all ownership.
#[derive(Debug)]
pub struct RecordingReplayFailure {
    /// Typed reason without source bytes, paths, or credentials.
    pub reason: RecordingReplayError,
    /// Present only when this call fenced the entire reconstruction owner.
    pub retirement: Option<Box<RecordingReplayRetirement>>,
}
impl std::fmt::Display for RecordingReplayFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for RecordingReplayFailure {}

/// Exclusive composition with no mutable receiver/collector escape or hidden output queue.
/// Source reads stop while capture owns a pending event, timing request or prepared window.
/// The current clock governs collection residence; stored receive timestamps remain unchanged.
#[derive(Debug)]
#[must_use]
pub struct DatagramRecordingReplay<'a> {
    replay: DatagramAvcReplay<'a>,
    capture: Option<RecordingCapture>,
    interpretation: ContentDigest,
    prefix: Option<Box<AvcReplayStep>>,
    finalizing: bool,
    closed: bool,
    now_ns: u64,
    remaining_steps: u64,
    deadline_ns: u64,
    capture_cost: u64,
}
impl<'a> DatagramRecordingReplay<'a> {
    /// Validate every source/configuration binding before source I/O. Actual per-picture timing
    /// remains explicit; this constructor does not guess duration from timestamps or frame rate.
    pub fn new(
        archive: &'a DatagramArchive,
        avc: AvcReplaySpec<'_>,
        recording: RecordingReplaySpec,
        bounds: AvcReplayBounds,
        now_ns: u64,
    ) -> std::result::Result<Self, RecordingReplayError> {
        if recording.scope.generation != archive.scope().binding.key().generation
            || recording.scope.receive_clock != archive.scope().receive_clock
            || recording.timing_evidence.algorithm() != DigestAlgorithm::Sha256
            || recording.timing_evidence.bytes() == [0; 32]
        {
            return Err(RecordingReplayError::Configuration);
        }
        let collector = RecordingCollector::new(
            recording.scope.clone(),
            archive.scope().binding.key(),
            avc.payload_type,
            recording.time_scale,
            recording.limits,
        )
        .map_err(|e| RecordingReplayError::Capture(CaptureError::Collection(e)))?;
        let replay = DatagramAvcReplay::new(archive, avc, bounds, now_ns)
            .map_err(RecordingReplayError::Replay)?;
        let interpretation = interpretation(replay.interpretation(), &recording)?;
        let capture_cost = (recording.limits.max_source_bytes as u64
            + recording.limits.max_picture_bytes as u64)
            * 8
            + (recording.limits.max_nals as u64 + recording.limits.max_source_spans as u64) * 128
            + 4096;
        Ok(Self {
            replay,
            capture: Some(RecordingCapture::new(collector)),
            interpretation,
            prefix: None,
            finalizing: false,
            closed: false,
            now_ns,
            remaining_steps: bounds.max_steps,
            deadline_ns: bounds.deadline_ns,
            capture_cost,
        })
    }
    /// Complete frozen interpretation. Actual supplied timing/seal choices are additionally
    /// bound by the returned recording root; this is not a durable lineage publication itself.
    pub fn interpretation(&self) -> ContentDigest {
        self.interpretation
    }
    /// Original observation count; it cannot advance while picture timing is outstanding.
    pub fn observations_read(&self) -> u64 {
        self.replay.observations_read()
    }
    /// The independently selected source prefix; no hidden latest-head following.
    pub fn source(&self) -> DatagramPin {
        self.replay.source()
    }

    /// Supply exact media ticks to the existing held picture. Invalid timing retains it for
    /// correction, and a post-admission cancellation retains the complete TimedCapture outcome.
    pub fn supply_timing(
        &mut self,
        timing: RecordingTiming,
        now_ns: u64,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> std::result::Result<TimedCapture, RecordingReplayFailure> {
        self.guard(now_ns, cancel, budget)?;
        if self.finalizing {
            return Err(safe(RecordingReplayError::Closed));
        }
        let result = self
            .capture
            .as_mut()
            .ok_or_else(|| safe(RecordingReplayError::Closed))?
            .supply_timing(timing, now_ns);
        let result = result.map_err(|e| self.capture_error(e))?;
        if let Err(error) = current(cancel, budget) {
            let mut failure = self.fatal(RecordingReplayError::Replay(error), None, None, None);
            if let Some(retired) = &mut failure.retirement {
                retired.withheld_timing = Some(result);
            }
            return Err(failure);
        }
        Ok(result)
    }
    /// Explicitly seal a completed packet-disjoint prefix without claiming codec/transport EOF.
    /// Useful to relieve collection pressure before the selected source prefix is exhausted.
    pub fn seal(
        &mut self,
        now_ns: u64,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> std::result::Result<bool, RecordingReplayFailure> {
        self.guard(now_ns, cancel, budget)?;
        if self.finalizing {
            return Err(safe(RecordingReplayError::Closed));
        }
        let result = self
            .capture
            .as_mut()
            .ok_or_else(|| safe(RecordingReplayError::Closed))?
            .seal(now_ns);
        let sealed = result.map_err(|e| self.capture_error(e))?;
        current(cancel, budget)
            .map_err(|e| self.fatal(RecordingReplayError::Replay(e), None, None, None))?;
        Ok(sealed)
    }
    /// Only after PrefixReady: seal existing completed groups, then step to transfer any window
    /// and the incomplete remainder. No receiver finish, invented boundary or source read occurs.
    pub fn finish_prefix(
        &mut self,
        now_ns: u64,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> std::result::Result<(), RecordingReplayFailure> {
        self.guard(now_ns, cancel, budget)?;
        if self.finalizing {
            return Err(safe(RecordingReplayError::Closed));
        }
        if self.prefix.is_none() {
            return Err(safe(RecordingReplayError::PrefixNotReady));
        }
        let result = self
            .capture
            .as_mut()
            .ok_or_else(|| safe(RecordingReplayError::Closed))?
            .seal(now_ns);
        let _ = result.map_err(|e| self.capture_error(e))?;
        self.finalizing = true;
        current(cancel, budget)
            .map_err(|e| self.fatal(RecordingReplayError::Replay(e), None, None, None))
    }
    /// Drain capture first. Read at most one new original only after the collector is ready.
    /// Retain complete lower-level output when any later authority/budget check refuses it.
    pub fn step(
        &mut self,
        publisher: &LocalRootPublisher,
        now_ns: u64,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> std::result::Result<RecordingReplayStep, RecordingReplayFailure> {
        if self.closed {
            return Ok(RecordingReplayStep::Ended);
        }
        self.guard(now_ns, cancel, budget)?;
        let step = self.advance(publisher, now_ns, cancel, budget)?;
        if let Err(error) = current(cancel, budget) {
            return Err(self.fatal(RecordingReplayError::Replay(error), None, Some(step), None));
        }
        Ok(step)
    }
    fn advance(
        &mut self,
        publisher: &LocalRootPublisher,
        now_ns: u64,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> std::result::Result<RecordingReplayStep, RecordingReplayFailure> {
        let result = self
            .capture
            .as_mut()
            .ok_or_else(|| safe(RecordingReplayError::Closed))?
            .poll(now_ns);
        match result {
            Err(error) => {
                return Err(self.fatal(RecordingReplayError::Capture(error), None, None, None));
            }
            Ok(event @ CapturePoll::Stopped { .. }) => {
                // The original stop event already owns the capture retirement.
                self.capture = None;
                let retained = self.retire(None, None, None);
                return Ok(RecordingReplayStep::Stopped {
                    trigger: RecordingReplayStop::Collection(Box::new(event)),
                    retained: Box::new(retained),
                });
            }
            Ok(event @ (CapturePoll::Ended { .. } | CapturePoll::InputEnded)) => {
                return Err(self.fatal(
                    RecordingReplayError::Replay(AvcReplayError::Invariant),
                    None,
                    Some(RecordingReplayStep::Capture(Box::new(event))),
                    None,
                ));
            }
            Ok(CapturePoll::Pending { .. }) => {}
            Ok(event) => return Ok(RecordingReplayStep::Capture(Box::new(event))),
        }
        if self.prefix.is_some() {
            if self.finalizing {
                return Ok(RecordingReplayStep::FinishedPrefix {
                    retained: Box::new(self.retire(None, None, None)),
                });
            }
            return Ok(self.prefix_ready());
        }
        let step = match self.replay.step(publisher, now_ns, cancel, budget) {
            Ok(step) => step,
            Err(failure) => {
                return Err(match failure.retirement {
                    Some(retired) => self.fatal(
                        RecordingReplayError::Replay(failure.reason),
                        Some(*retired),
                        None,
                        None,
                    ),
                    None => safe(RecordingReplayError::Replay(failure.reason)),
                });
            }
        };
        match step {
            AvcReplayStep::Media { event, .. } => {
                let result = self
                    .capture
                    .as_mut()
                    .ok_or_else(|| safe(RecordingReplayError::Closed))?
                    .offer(event, now_ns);
                if let Err(refusal) = result {
                    return Err(self.fatal(
                        RecordingReplayError::Capture(refusal.reason),
                        None,
                        None,
                        Some(refusal.event),
                    ));
                }
                Ok(RecordingReplayStep::MediaQueued)
            }
            step @ AvcReplayStep::PrefixExhausted { .. } => {
                self.prefix = Some(Box::new(step));
                Ok(self.prefix_ready())
            }
            step @ (AvcReplayStep::InputRefused { .. }
            | AvcReplayStep::CodecEnded { .. }
            | AvcReplayStep::Rtp {
                retired: Some(_), ..
            }
            | AvcReplayStep::Ended) => {
                let retained = self.retire(None, None, None);
                Ok(RecordingReplayStep::Stopped {
                    trigger: RecordingReplayStop::Source(Box::new(step)),
                    retained: Box::new(retained),
                })
            }
            step => Ok(RecordingReplayStep::Source(Box::new(step))),
        }
    }
    /// Transfer every held input without sealing, storage I/O, camera contact or deletion.
    pub fn cancel(&mut self) -> Option<RecordingReplayRetirement> {
        if self.closed {
            None
        } else {
            Some(self.retire(None, None, None))
        }
    }
    fn prefix_ready(&self) -> RecordingReplayStep {
        RecordingReplayStep::PrefixReady {
            source: self.source(),
            interpretation: self.interpretation,
        }
    }
    fn capture_error(&mut self, reason: CaptureError) -> RecordingReplayFailure {
        if matches!(
            reason,
            CaptureError::Closed | CaptureError::Collection(CollectorError::Deadline)
        ) {
            self.fatal(RecordingReplayError::Capture(reason), None, None, None)
        } else {
            safe(RecordingReplayError::Capture(reason))
        }
    }
    fn retire(
        &mut self,
        replay: Option<AvcReplayRetirement>,
        withheld: Option<RecordingReplayStep>,
        unoffered_media: Option<Box<AvcReceivePoll>>,
    ) -> RecordingReplayRetirement {
        self.closed = true;
        RecordingReplayRetirement {
            interpretation: self.interpretation,
            source: self.source(),
            replay: replay.or_else(|| self.replay.cancel()),
            capture: self.capture.take().map(|mut c| c.cancel()),
            prefix: self.prefix.take(),
            unoffered_media,
            withheld: withheld.map(Box::new),
            withheld_timing: None,
        }
    }
    fn fatal(
        &mut self,
        reason: RecordingReplayError,
        replay: Option<AvcReplayRetirement>,
        withheld: Option<RecordingReplayStep>,
        unoffered_media: Option<Box<AvcReceivePoll>>,
    ) -> RecordingReplayFailure {
        RecordingReplayFailure {
            reason,
            retirement: Some(Box::new(self.retire(replay, withheld, unoffered_media))),
        }
    }
    fn guard(
        &mut self,
        now_ns: u64,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> std::result::Result<(), RecordingReplayFailure> {
        if self.closed {
            return Err(safe(RecordingReplayError::Closed));
        }
        if now_ns < self.now_ns {
            return Err(safe(RecordingReplayError::Replay(
                AvcReplayError::ClockReversed,
            )));
        }
        let result = if now_ns >= self.deadline_ns {
            Err(DatagramArchiveError::Deadline.into())
        } else if self.remaining_steps == 0 {
            Err(DatagramArchiveError::Limit.into())
        } else {
            current(cancel, budget).and_then(|()| {
                budget
                    .charge(self.capture_cost)
                    .map_err(|e| AvcReplayError::Source(DatagramArchiveError::Work(e)))
            })
        };
        result.map_err(|e| self.fatal(RecordingReplayError::Replay(e), None, None, None))?;
        self.now_ns = now_ns;
        self.remaining_steps -= 1;
        Ok(())
    }
}
fn safe(reason: RecordingReplayError) -> RecordingReplayFailure {
    RecordingReplayFailure {
        reason,
        retirement: None,
    }
}

fn interpretation(
    receiver: ContentDigest,
    spec: &RecordingReplaySpec,
) -> std::result::Result<ContentDigest, RecordingReplayError> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.datagram_recording_interpretation.v1");
    e.digest(receiver);
    e.digest(spec.timing_evidence);
    e.text(spec.scope.sensor.as_str());
    e.text(spec.scope.stream.as_str());
    e.u64(spec.scope.generation);
    e.digest(spec.scope.anchor);
    e.digest(spec.scope.receive_clock);
    e.u32(spec.time_scale);
    let CollectorLimits {
        max_packets,
        max_source_bytes,
        max_samples,
        max_picture_bytes,
        max_nals,
        max_source_spans,
        max_age_ns,
    } = spec.limits;
    for n in [
        max_packets,
        max_source_bytes,
        max_samples,
        max_picture_bytes,
        max_nals,
        max_source_spans,
    ] {
        e.u64(u64::try_from(n).map_err(|_| RecordingReplayError::Configuration)?);
    }
    e.u64(max_age_ns);
    let bytes = e
        .finish_checked()
        .map_err(|_| RecordingReplayError::Configuration)?;
    ContentDigest::try_sha256(&bytes).map_err(|_| RecordingReplayError::Configuration)
}
