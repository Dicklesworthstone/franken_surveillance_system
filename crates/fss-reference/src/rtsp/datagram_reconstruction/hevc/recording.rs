#![forbid(unsafe_code)]
//! Cold HEVC originals -> native grouping -> explicit timing -> verified recording windows.
//! No source exhaustion is converted into receiver/assembler EOF. Every source-bearing event
//! and incomplete NAL/group remains owned. The existing collector replays originals on seal.

use super::*;
use crate::rtsp::hevc_client::pictures::HevcPictureClientPoll as Event;
use crate::rtsp::hevc_recording_capture::{
    CaptureError, HevcCapturePoll, HevcCaptureRetirement, HevcRecordingCapture, TimedHevcCapture,
};
use crate::rtsp::hevc_recording_collector::{HevcCollectionSeal, HevcRecordingCollector};
use crate::rtsp::recording::RecordingScope;
use crate::rtsp::recording::hevc::HevcRecordingTiming;
use crate::rtsp::recording_collector::{CollectorError, CollectorLimits};
use fss_packet::H265NalUnit;
use fss_packet::hevc::{
    HevcAssembler, HevcAssemblyError, HevcAssemblyLimits, HevcAssemblyRetirement, HevcConfiguration,
};

/// An explicit recording interpretation, not an authority or a recovered camera configuration.
#[derive(Debug)]
pub struct HevcRecordingReplaySpec {
    /// Original sensor/stream/history; generation and receive clock must match the source.
    pub scope: RecordingScope,
    /// Separately supplied validated VPS/SPS/PPS. Exact bytes bind the interpretation.
    pub configuration: HevcConfiguration,
    /// Owner-selected media tick rate. Receive time and RTP time never supply DTS.
    pub time_scale: u32,
    /// Independent current-operation collection bounds, including residence time.
    pub limits: CollectorLimits,
    /// Native grouping bounds. Group age uses historical receive time, not storage time.
    pub assembly: HevcAssemblyLimits,
    /// Explicit evidence for subsequent per-picture timing decisions.
    pub timing_evidence: ContentDigest,
}

/// Source-prefix exhaustion and a real in-band EOB remain distinguishable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HevcReplayBoundary {
    /// All selected observations drained; incomplete groups/fragments remain unverified.
    RetainedPrefix,
    /// A real EOB NAL ended grouping. Later selected observations are NOT silently read.
    EndOfBitstream,
}

/// Typed source, grouping, collection or safe input refusal.
#[derive(Debug)]
pub enum HevcRecordingReplayError {
    /// Incompatible source clock/generation, invalid scope or missing timing evidence.
    Configuration,
    /// Original source/current-authority/native receiver refusal.
    Replay(HevcReplayError),
    /// Native HEVC grouping refused. Its original NALs are retained separately.
    Assembly(HevcAssemblyError),
    /// Existing recording collection, timing or sealing refusal.
    Capture(CaptureError),
    /// Explicit final sealing requires a previously observed bounded input boundary.
    PrefixNotReady,
    /// No new input command after finalization or terminal ownership transfer.
    Closed,
}
impl std::fmt::Display for HevcRecordingReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HEVC recording reconstruction refused: {self:?}")
    }
}
impl std::error::Error for HevcRecordingReplayError {}

/// The original result that invalidated this recording interpretation.
#[derive(Debug)]
pub enum HevcRecordingReplayStop {
    /// Original refused/restarted source event. Never relabeled as EOF.
    Source(Box<HevcReplayStep>),
    /// Native loss/group/timing invalidation with the existing capture retirement.
    Collection(Box<HevcCapturePoll>),
}

/// All prepared output and original observations remain distinct from durable publication.
#[derive(Debug)]
#[must_use]
pub enum HevcRecordingReplayStep {
    /// Existing original-datagram admission, RTCP diagnosis or historical clock progress.
    Source(Box<HevcReplayStep>),
    /// One native source/group event entered capture; no additional source read occurred.
    MediaQueued,
    /// Existing timing request, prepared recording, source output or bounded pressure.
    Capture(Box<HevcCapturePoll>),
    /// No further source reads. Explicit finish_prefix seals only verified completed groups.
    PrefixReady {
        /// Selected input inventory; use observations_read to distinguish a consumed prefix.
        source: DatagramPin,
        /// Source, parameters, native bounds and timing-evidence interpretation.
        interpretation: ContentDigest,
        /// Original observations actually read; may be smaller than source after EOB.
        observations_read: u64,
        /// Why new source admission has stopped. Neither case proves transport EOF.
        boundary: HevcReplayBoundary,
    },
    /// Explicit sealing drained; all unfinished source/NAL/group ownership transfers once.
    FinishedPrefix {
        /// Exact remainder, including the original boundary and queued post-EOB NALs.
        retained: Box<HevcRecordingReplayRetirement>,
    },
    /// Original loss/refusal stopped collection without fabricating a final window.
    Stopped {
        /// Original source or native capture trigger.
        trigger: HevcRecordingReplayStop,
        /// Every other outstanding obligation and owned input.
        retained: Box<HevcRecordingReplayRetirement>,
    },
    /// All terminal ownership already transferred.
    Ended,
}

/// Complete bounded ownership after cancellation, failure or explicit prefix finalization.
#[derive(Debug)]
#[must_use]
pub struct HevcRecordingReplayRetirement {
    /// Exact source/recording interpretation, not a publication receipt.
    pub interpretation: ContentDigest,
    /// Independently accepted source inventory.
    pub source: DatagramPin,
    /// Original observations actually read.
    pub observations_read: u64,
    /// The observed input boundary, if any.
    pub boundary: Option<HevcReplayBoundary>,
    /// Raw receiver state, unless the original prefix or withheld output already owns it.
    pub replay: Option<HevcReplayRetirement>,
    /// Unsealed originals, ready recording and an event awaiting timing.
    pub capture: Option<HevcCaptureRetirement>,
    /// Unverified grouping never completed by an invented EOF.
    pub assembly: Option<HevcAssemblyRetirement>,
    /// Exact unconsumed complete NALs from at most one native packet output; no allocation on cancel.
    pub queued_nals: std::vec::IntoIter<H265NalUnit>,
    /// Original PrefixExhausted or source event deferred behind a grouping invalidation.
    pub held_source: Option<Box<HevcReplayStep>>,
    /// A native event refused before capture took ownership.
    pub unoffered: Option<Box<Event>>,
    /// Output withheld by a post-computation authority/work refusal.
    pub withheld: Option<Box<HevcRecordingReplayStep>>,
    /// Successful timing outcome withheld after current authorization was withdrawn.
    pub withheld_timing: Option<TimedHevcCapture>,
    /// Seal releases withheld after current authorization was withdrawn.
    pub withheld_seal: Option<HevcCollectionSeal>,
}

/// Safe timing/clock refusals retain the same owner; fatal calls transfer ownership once.
#[derive(Debug)]
pub struct HevcRecordingReplayFailure {
    /// Typed failure without payload, credential, path or URI text.
    pub reason: HevcRecordingReplayError,
    /// Present only when this call ended the complete reconstruction owner.
    pub retirement: Option<Box<HevcRecordingReplayRetirement>>,
}
impl std::fmt::Display for HevcRecordingReplayFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for HevcRecordingReplayFailure {}
type RecordingResult<T> = std::result::Result<T, HevcRecordingReplayFailure>;

/// Exclusive cold composition. Capture and its one native packet's NALs drain before more input.
/// Grouping uses historical time; collection residence and authority use the current clock.
/// No mutable inner-owner access, I/O worker, guessed media timing or publication side effect.
#[derive(Debug)]
#[must_use]
pub struct DatagramHevcRecordingReplay<'a> {
    replay: DatagramHevcReplay<'a>,
    assembly: HevcAssembler,
    capture: Option<HevcRecordingCapture>,
    queued: std::vec::IntoIter<H265NalUnit>,
    queued_ns: u64,
    held: Option<Box<HevcReplayStep>>,
    boundary: Option<HevcReplayBoundary>,
    eob: bool,
    interpretation: ContentDigest,
    finalizing: bool,
    closed: bool,
    now_ns: u64,
    remaining_steps: u64,
    deadline_ns: u64,
    capture_cost: u64,
}
impl<'a> DatagramHevcRecordingReplay<'a> {
    /// Validate source/clock/configuration and all ceilings without I/O. Parameter sets
    /// are supplied by the explicit caller; source metadata cannot choose a codec or grant.
    pub fn new(
        archive: &'a DatagramArchive,
        hevc: HevcReplaySpec,
        recording: HevcRecordingReplaySpec,
        bounds: HevcReplayBounds,
        now_ns: u64,
    ) -> std::result::Result<Self, HevcRecordingReplayError> {
        if recording.scope.generation != archive.scope().binding.key().generation
            || recording.scope.receive_clock != archive.scope().receive_clock
            || recording.timing_evidence.algorithm() != DigestAlgorithm::Sha256
            || recording.timing_evidence.bytes() == [0; 32]
        {
            return Err(HevcRecordingReplayError::Configuration);
        }
        let assembly = HevcAssembler::new(archive.scope().binding.key(), recording.assembly)
            .map_err(HevcRecordingReplayError::Assembly)?;
        recording
            .limits
            .validate()
            .map_err(|e| HevcRecordingReplayError::Capture(CaptureError::Collection(e)))?;
        let replay = DatagramHevcReplay::new(archive, hevc, bounds, now_ns)
            .map_err(HevcRecordingReplayError::Replay)?;
        let interpretation = recording_profile::digest(replay.interpretation(), &recording)?;
        // Validated native ceilings bound this reservation; it is not a measured cost claim.
        let capture_cost = (recording.limits.max_source_bytes as u64
            + recording.limits.max_picture_bytes as u64
            + recording.assembly.max_bytes as u64)
            * 8
            + (recording.limits.max_nals as u64
                + recording.limits.max_source_spans as u64
                + recording.assembly.max_source_spans as u64)
                * 128
            + 4096;
        let collector = HevcRecordingCollector::new(
            recording.scope,
            archive.scope().binding.key(),
            hevc.payload_type,
            recording.configuration,
            recording.time_scale,
            recording.limits,
        )
        .map_err(|e| HevcRecordingReplayError::Capture(CaptureError::Collection(e)))?;
        Ok(Self {
            replay,
            assembly,
            capture: Some(HevcRecordingCapture::new(collector)),
            queued: Vec::new().into_iter(),
            queued_ns: 0,
            held: None,
            boundary: None,
            eob: false,
            interpretation,
            finalizing: false,
            closed: false,
            now_ns,
            remaining_steps: bounds.max_steps,
            deadline_ns: bounds.deadline_ns,
            capture_cost,
        })
    }
    /// Frozen policy/configuration interpretation; actual timings also bind each recording root.
    pub fn interpretation(&self) -> ContentDigest {
        self.interpretation
    }
    /// Original observations read; unchanged while explicit timing or output is outstanding.
    pub fn observations_read(&self) -> u64 {
        self.replay.observations_read()
    }
    /// Full independently selected inventory, not implicit inclusion of future roots.
    pub fn source(&self) -> DatagramPin {
        self.replay.source()
    }

    /// Supply exact per-picture media ticks. Safe refusal preserves the picture and its deadline.
    pub fn supply_timing(
        &mut self,
        timing: HevcRecordingTiming,
        now_ns: u64,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> RecordingResult<TimedHevcCapture> {
        self.guard(now_ns, cancel, budget)?;
        if self.finalizing {
            return Err(safe(HevcRecordingReplayError::Closed));
        }
        let outcome = self
            .capture
            .as_mut()
            .ok_or_else(|| safe(HevcRecordingReplayError::Closed))?
            .supply_timing(timing, now_ns)
            .map_err(|e| self.capture_error(e))?;
        if let Err(e) = current(cancel, budget) {
            let mut failure = self.fatal(HevcRecordingReplayError::Replay(e), None, None, None);
            if let Some(r) = &mut failure.retirement {
                r.withheld_timing = Some(outcome);
            }
            return Err(failure);
        }
        Ok(outcome)
    }
    /// Seal an actual completed prefix without changing native source/assembly cursors.
    /// Return every release to its owner; no bytes are implicitly deleted or published.
    pub fn seal(
        &mut self,
        now_ns: u64,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> RecordingResult<HevcCollectionSeal> {
        self.seal_inner(false, now_ns, cancel, budget)
    }
    /// After PrefixReady only: explicitly seal completed pictures, then drain Window and
    /// FinishedPrefix. The remaining fragment/group is cancelled, NEVER finished into a picture.
    pub fn finish_prefix(
        &mut self,
        now_ns: u64,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> RecordingResult<HevcCollectionSeal> {
        self.seal_inner(true, now_ns, cancel, budget)
    }
    fn seal_inner(
        &mut self,
        finalizing: bool,
        now_ns: u64,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> RecordingResult<HevcCollectionSeal> {
        self.guard(now_ns, cancel, budget)?;
        if self.finalizing {
            return Err(safe(HevcRecordingReplayError::Closed));
        }
        if finalizing && self.boundary.is_none() {
            return Err(safe(HevcRecordingReplayError::PrefixNotReady));
        }
        let outcome = self
            .capture
            .as_mut()
            .ok_or_else(|| safe(HevcRecordingReplayError::Closed))?
            .seal(now_ns)
            .map_err(|e| self.capture_error(e))?;
        self.finalizing = finalizing;
        if let Err(e) = current(cancel, budget) {
            let mut failure = self.fatal(HevcRecordingReplayError::Replay(e), None, None, None);
            if let Some(r) = &mut failure.retirement {
                r.withheld_seal = Some(outcome);
            }
            return Err(failure);
        }
        Ok(outcome)
    }
    /// One capture, NAL, timer or source step. An unanswered picture timing request blocks reads.
    pub fn step(
        &mut self,
        publisher: &LocalRootPublisher,
        now_ns: u64,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> RecordingResult<HevcRecordingReplayStep> {
        if self.closed {
            return Ok(HevcRecordingReplayStep::Ended);
        }
        self.guard(now_ns, cancel, budget)?;
        let output = self.advance(publisher, now_ns, cancel, budget)?;
        if let Err(e) = current(cancel, budget) {
            return Err(self.fatal(
                HevcRecordingReplayError::Replay(e),
                None,
                Some(output),
                None,
            ));
        }
        Ok(output)
    }
    fn advance(
        &mut self,
        publisher: &LocalRootPublisher,
        now_ns: u64,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> RecordingResult<HevcRecordingReplayStep> {
        let result = self
            .capture
            .as_mut()
            .ok_or_else(|| safe(HevcRecordingReplayError::Closed))?
            .poll(now_ns);
        match result {
            Err(e) => {
                return Err(self.fatal(HevcRecordingReplayError::Capture(e), None, None, None));
            }
            Ok(event @ HevcCapturePoll::Stopped { .. }) => {
                self.capture = None; // this event already owns the capture retirement
                return Ok(HevcRecordingReplayStep::Stopped {
                    trigger: HevcRecordingReplayStop::Collection(Box::new(event)),
                    retained: Box::new(self.retire(None, None, None)),
                });
            }
            Ok(event @ (HevcCapturePoll::Ended { .. } | HevcCapturePoll::Sealed(_))) => {
                return Err(self.fatal(
                    HevcRecordingReplayError::Replay(HevcReplayError::Invariant),
                    None,
                    Some(HevcRecordingReplayStep::Capture(Box::new(event))),
                    None,
                ));
            }
            Ok(HevcCapturePoll::Pending { .. }) => {}
            Ok(event) => return Ok(HevcRecordingReplayStep::Capture(Box::new(event))),
        }
        if let Some(boundary) = self.boundary {
            if self.finalizing {
                return Ok(HevcRecordingReplayStep::FinishedPrefix {
                    retained: Box::new(self.retire(None, None, None)),
                });
            }
            return Ok(self.prefix_ready(boundary));
        }
        if self.eob {
            self.boundary = Some(HevcReplayBoundary::EndOfBitstream);
            return Ok(self.prefix_ready(HevcReplayBoundary::EndOfBitstream));
        }
        if let Some(nal) = self.queued.next() {
            let eob = nal.nal_type() == 37;
            let step = self.assembly.push(nal, self.queued_ns);
            // Native capture will fence a refused or invalidating assembly result first.
            self.eob = eob;
            return self.offer(
                Event::Assembly {
                    step,
                    retirement: None,
                },
                now_ns,
            );
        }
        let step = match self.replay.step(publisher, now_ns, cancel, budget) {
            Ok(step) => step,
            Err(failure) => {
                return Err(match failure.retirement {
                    Some(r) => self.fatal(
                        HevcRecordingReplayError::Replay(failure.reason),
                        Some(*r),
                        None,
                        None,
                    ),
                    None => safe(HevcRecordingReplayError::Replay(failure.reason)),
                });
            }
        };
        // Assembly expiration is bounded by the raw scheduler's actual next event. Source
        // admission can already have happened, but no new NAL enters grouping before this
        // invalidation. Retain the exact source output if expiration stops collection.
        match self.assembly.expire(self.replay.replay_ns()) {
            Ok(Some(retired)) => {
                self.held = Some(Box::new(step));
                return self.offer(Event::PictureRetired(retired), now_ns);
            }
            Err(e) => {
                return Err(self.fatal(
                    HevcRecordingReplayError::Assembly(e),
                    None,
                    Some(HevcRecordingReplayStep::Source(Box::new(step))),
                    None,
                ));
            }
            Ok(None) => {}
        }
        match step {
            HevcReplayStep::Media { replay_ns, event } => {
                let event = match event {
                    H265ReceivePoll::Packet {
                        source,
                        reconstruction: Ok(out),
                    } => {
                        let picture = if out.gap_before || out.discarded.is_some() {
                            self.assembly.discard_gap()
                        } else {
                            None
                        };
                        let queued_nals = out.nals.len();
                        self.queued = out.nals.into_iter();
                        self.queued_ns = replay_ns;
                        Event::Source {
                            source,
                            status: out.status,
                            queued_nals,
                            gap_before: out.gap_before,
                            fragment: out.discarded,
                            picture,
                        }
                    }
                    H265ReceivePoll::Packet {
                        source,
                        reconstruction: Err(error),
                    } => Event::CodecRefused {
                        source,
                        error,
                        picture: self.assembly.discard_gap(),
                    },
                    H265ReceivePoll::Gap { gap, discarded } => Event::Gap {
                        gap,
                        fragment: discarded,
                        picture: self.assembly.discard_gap(),
                    },
                    H265ReceivePoll::FragmentDiscarded(fragment) => Event::FragmentRetired {
                        fragment,
                        picture: self.assembly.discard_gap(),
                    },
                    event => {
                        return Err(self.fatal(
                            HevcRecordingReplayError::Replay(HevcReplayError::Invariant),
                            None,
                            Some(HevcRecordingReplayStep::Source(Box::new(
                                HevcReplayStep::Media { replay_ns, event },
                            ))),
                            None,
                        ));
                    }
                };
                self.offer(event, now_ns)
            }
            step @ HevcReplayStep::PrefixExhausted { .. } => {
                self.held = Some(Box::new(step));
                self.boundary = Some(HevcReplayBoundary::RetainedPrefix);
                Ok(self.prefix_ready(HevcReplayBoundary::RetainedPrefix))
            }
            step @ (HevcReplayStep::InputRefused { .. }
            | HevcReplayStep::CodecEnded { .. }
            | HevcReplayStep::Ended) => Ok(self.stop_source(step)),
            step @ HevcReplayStep::Rtp { .. } => {
                let invalid = matches!(&step, HevcReplayStep::Rtp { admission, retired, .. }
                    if retired.is_some() || admission.discarded.is_some() || admission.transport.discarded.is_some());
                if invalid {
                    Ok(self.stop_source(step))
                } else {
                    Ok(HevcRecordingReplayStep::Source(Box::new(step)))
                }
            }
            step => Ok(HevcRecordingReplayStep::Source(Box::new(step))),
        }
    }
    fn stop_source(&mut self, step: HevcReplayStep) -> HevcRecordingReplayStep {
        HevcRecordingReplayStep::Stopped {
            trigger: HevcRecordingReplayStop::Source(Box::new(step)),
            retained: Box::new(self.retire(None, None, None)),
        }
    }
    fn offer(&mut self, event: Event, now_ns: u64) -> RecordingResult<HevcRecordingReplayStep> {
        let result = self
            .capture
            .as_mut()
            .ok_or_else(|| safe(HevcRecordingReplayError::Closed))?
            .offer(event, now_ns);
        if let Err(refusal) = result {
            return Err(self.fatal(
                HevcRecordingReplayError::Capture(refusal.reason),
                None,
                None,
                Some(refusal.event),
            ));
        }
        Ok(HevcRecordingReplayStep::MediaQueued)
    }
    fn prefix_ready(&self, boundary: HevcReplayBoundary) -> HevcRecordingReplayStep {
        HevcRecordingReplayStep::PrefixReady {
            source: self.source(),
            interpretation: self.interpretation,
            observations_read: self.observations_read(),
            boundary,
        }
    }
    /// Transfer all owned originals, queued NALs and prepared media without sealing or I/O.
    pub fn cancel(&mut self) -> Option<HevcRecordingReplayRetirement> {
        if self.closed {
            None
        } else {
            Some(self.retire(None, None, None))
        }
    }
    fn capture_error(&mut self, e: CaptureError) -> HevcRecordingReplayFailure {
        if matches!(
            e,
            CaptureError::Closed | CaptureError::Collection(CollectorError::Deadline)
        ) {
            self.fatal(HevcRecordingReplayError::Capture(e), None, None, None)
        } else {
            safe(HevcRecordingReplayError::Capture(e))
        }
    }
    fn retire(
        &mut self,
        replay: Option<HevcReplayRetirement>,
        withheld: Option<HevcRecordingReplayStep>,
        unoffered: Option<Box<Event>>,
    ) -> HevcRecordingReplayRetirement {
        self.closed = true;
        HevcRecordingReplayRetirement {
            interpretation: self.interpretation,
            source: self.source(),
            observations_read: self.observations_read(),
            boundary: self.boundary,
            replay: replay.or_else(|| self.replay.cancel()),
            capture: self.capture.take().map(|mut c| c.cancel()),
            assembly: self.assembly.cancel(),
            queued_nals: std::mem::replace(&mut self.queued, Vec::new().into_iter()),
            held_source: self.held.take(),
            unoffered,
            withheld: withheld.map(Box::new),
            withheld_timing: None,
            withheld_seal: None,
        }
    }
    fn fatal(
        &mut self,
        reason: HevcRecordingReplayError,
        replay: Option<HevcReplayRetirement>,
        withheld: Option<HevcRecordingReplayStep>,
        unoffered: Option<Box<Event>>,
    ) -> HevcRecordingReplayFailure {
        HevcRecordingReplayFailure {
            reason,
            retirement: Some(Box::new(self.retire(replay, withheld, unoffered))),
        }
    }
    fn guard(
        &mut self,
        now_ns: u64,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> RecordingResult<()> {
        if self.closed {
            return Err(safe(HevcRecordingReplayError::Closed));
        }
        if now_ns < self.now_ns {
            return Err(safe(HevcRecordingReplayError::Replay(
                HevcReplayError::ClockReversed,
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
                    .map_err(|e| HevcReplayError::Source(DatagramArchiveError::Work(e)))
            })
        };
        result.map_err(|e| self.fatal(HevcRecordingReplayError::Replay(e), None, None, None))?;
        self.now_ns = now_ns;
        self.remaining_steps -= 1;
        Ok(())
    }
}
fn safe(reason: HevcRecordingReplayError) -> HevcRecordingReplayFailure {
    HevcRecordingReplayFailure {
        reason,
        retirement: None,
    }
}
#[path = "recording_profile.rs"]
mod recording_profile;
