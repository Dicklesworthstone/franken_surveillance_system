#![forbid(unsafe_code)]
//! Bounded event bridge from the existing plain/Digest HEVC picture client to recording.
//!
//! The caller owns upstream I/O, authorization and timer delivery. This bridge
//! owns collection ordering and automatically fences every supplied invalidation.

use super::hevc_client::{HevcClientPoll, pictures::HevcPictureClientPoll as Event};
use super::hevc_recording_collector::{
    HevcCollectionAdmission, HevcCollectionRetirement, HevcCollectionSeal, HevcRecordingCollector,
};
use super::recording::hevc::{HevcRecordingTiming, PreparedHevcRecording};
pub use super::recording_capture::{CaptureError, MAX_PENDING_EVENT_AGE_NS};
use super::recording_collector::{CollectionStop, CollectorError};
use fss_packet::hevc::{HevcAssemblyStep, HevcBoundary, HevcPictureGroup};
use fss_packet::{H265ReceivePoll, ReorderDisposition, StreamKey};

/// Payload-free request for explicit owner timing; RTP time is never used as DTS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HevcPictureTimingRequest {
    /// Exact owner stream epoch.
    pub key: StreamKey,
    /// Unconverted RTP timestamp.
    pub rtp_timestamp: u32,
    /// Observed IDR classification, not a random-access certificate.
    pub idr: bool,
    /// Observed boundary, never upgraded from an unverified EOF tail.
    pub boundary: HevcBoundary,
    /// Held reconstructed NAL bytes, not decoded pixels.
    pub bytes: usize,
}
impl HevcPictureTimingRequest {
    fn new(p: &HevcPictureGroup) -> Self {
        Self {
            key: p.key(),
            rtp_timestamp: p.timestamp(),
            idr: matches!(p.prefix().nal_type, 19 | 20),
            boundary: p.boundary(),
            bytes: p.byte_len(),
        }
    }
}

/// An unconsumed event returned on admission failure, including every original source.
#[derive(Debug)]
pub struct HevcCaptureRefusal {
    /// Typed refusal; no event ownership was accepted.
    pub reason: CaptureError,
    /// Exact original event available for an ordered retry.
    pub event: Box<Event>,
}
impl std::fmt::Display for HevcCaptureRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for HevcCaptureRefusal {}

/// Successful timing admission still transfers the original picture event intact.
#[derive(Debug)]
pub struct TimedHevcCapture {
    /// Selected/awaiting-IDR result and released original packet ownership.
    pub admission: HevcCollectionAdmission,
    /// Original event, including the borrowed picture, EOB and remote-session receipts.
    pub event: Box<Event>,
}

/// Complete local ownership on EOF, failure or cancellation. No upstream I/O is cancelled here.
#[derive(Debug)]
pub struct HevcCaptureRetirement {
    /// Prepared root plus unsealed originals and process-local picture commitments.
    pub collection: HevcCollectionRetirement,
    /// One held event/picture, including any unprocessed source or terminal receipts.
    pub event: Option<Box<Event>>,
}

/// One bounded capture step; no return silently loses a source-bearing receiver event.
#[derive(Debug)]
pub enum HevcCapturePoll {
    /// Original event after any required source retention. EOF tails remain in
    /// this event, not selected or assigned invented timing.
    Receiver(Box<Event>),
    /// One picture is retained until explicit timing succeeds, cancellation, or expiry.
    TimingRequired(HevcPictureTimingRequest),
    /// Exact prepared window for the existing source-first/root-last publisher.
    Window(Box<PreparedHevcRecording>),
    /// EOF sealing released source bytes. A ready Window and final Ended follow.
    Sealed(HevcCollectionSeal),
    /// An accepted source event remains held while the owner seals or cancels.
    Backpressure {
        /// Retry-safe collector refusal, not a packet loss assertion.
        reason: CollectorError,
        /// Fixed event/source deadline, not an immediate busy-poll hint.
        wake_at_ns: Option<u64>,
    },
    /// Explicit input invalidation or expiry stopped collection without sealing unsafe work.
    Stopped {
        /// Collection deadline or input-discontinuity cause.
        reason: CollectionStop,
        /// Additional local refusal, when there was one.
        error: Option<CollectorError>,
        /// All retained source, picture and prepared-root ownership.
        retained: Box<HevcCaptureRetirement>,
    },
    /// No local work. The caller must ALSO drive the upstream client's timer.
    Pending {
        /// Earliest retained-event or collection deadline.
        wake_at_ns: Option<u64>,
    },
    /// EOF drain completed. Remaining originals transfer only on the first terminal poll.
    Ended {
        /// Trailing original ownership, absent on repeated polls.
        retained: Option<Box<HevcCaptureRetirement>>,
    },
}

/// One-event/one-picture bridge over the existing collector and HEVC client event vocabulary.
///
/// Offer every upstream event in order and drain this bridge before polling the
/// client again. Complete pictures require supply_timing. Control/authentication
/// and RTCP events retain their original ownership and meaning. The bridge has
/// no mutable collector escape hatch or alternate injected picture API. It does
/// not open sockets, infer source authority, or replace the upstream timer owner.
#[derive(Debug)]
pub struct HevcRecordingCapture {
    collector: HevcRecordingCollector,
    event: Option<Box<Event>>,
    event_deadline_ns: Option<u64>,
    timing_required: bool,
    blocked: bool,
    input_ended: bool,
    finished: bool,
    closed: bool,
    last_ns: u64,
}
impl HevcRecordingCapture {
    /// Take exclusive collection ownership; no I/O or effect capability is granted.
    pub fn new(collector: HevcRecordingCollector) -> Self {
        Self {
            collector,
            event: None,
            event_deadline_ns: None,
            timing_required: false,
            blocked: false,
            input_ended: false,
            finished: false,
            closed: false,
            last_ns: 0,
        }
    }
    /// Read-only source/window accounting; mutation must use the ordered event contract.
    pub fn collector(&self) -> &HevcRecordingCollector {
        &self.collector
    }
    /// Immediate only for runnable local work. Missing timing and capacity pressure
    /// wait on fixed deadlines instead of resetting them or busy-polling.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.closed {
            return None;
        }
        if self.collector.has_ready()
            || (self.event.is_some() && !self.timing_required && !self.blocked)
            || (self.input_ended && self.event.is_none())
        {
            return Some(self.last_ns);
        }
        earlier(self.collector.next_wake_ns(), self.event_deadline_ns)
    }
    /// Retain exactly one event. All refused events are returned intact and must
    /// be retried before the owner requests more upstream progress.
    pub fn offer(&mut self, event: Event, now: u64) -> std::result::Result<(), HevcCaptureRefusal> {
        let result = self.check_time(now).and_then(|()| {
            if self.closed || self.input_ended {
                return Err(CaptureError::Closed);
            }
            if self.event.is_some() || self.collector.has_ready() {
                return Err(CaptureError::Backpressure);
            }
            self.collector
                .check_admission(now)
                .map_err(CaptureError::Collection)
        });
        if let Err(reason) = result {
            return Err(HevcCaptureRefusal {
                reason,
                event: Box::new(event),
            });
        }
        let Some(deadline) = now.checked_add(MAX_PENDING_EVENT_AGE_NS) else {
            return Err(HevcCaptureRefusal {
                reason: CaptureError::Collection(CollectorError::Deadline),
                event: Box::new(event),
            });
        };
        self.event = Some(Box::new(event));
        self.event_deadline_ns = Some(deadline);
        self.blocked = false;
        self.last_ns = now;
        Ok(())
    }
    /// Apply explicit timing without taking the original event until collection
    /// succeeds. Invalid timing/capacity keeps the exact picture and original deadline.
    pub fn supply_timing(
        &mut self,
        timing: HevcRecordingTiming,
        now: u64,
    ) -> std::result::Result<TimedHevcCapture, CaptureError> {
        self.check_live(now)?;
        if !self.timing_required {
            return Err(CaptureError::NoPicture);
        }
        let picture = self
            .event
            .as_deref()
            .and_then(picture)
            .ok_or(CaptureError::NoPicture)?;
        let admission = self
            .collector
            .push_picture(picture, timing, now)
            .map_err(CaptureError::Collection)?;
        let event = self.event.take().ok_or(CaptureError::NoPicture)?;
        self.input_ended |= terminal(&event);
        self.timing_required = false;
        self.event_deadline_ns = None;
        self.last_ns = now;
        Ok(TimedHevcCapture { admission, event })
    }
    /// Explicitly seal a completed prefix to relieve pressure. A queued failure
    /// cannot be bypassed by sealing before poll processes its invalidation.
    pub fn seal(&mut self, now: u64) -> std::result::Result<HevcCollectionSeal, CaptureError> {
        self.check_live(now)?;
        if self.event.as_deref().is_some_and(invalidates) {
            return Err(CaptureError::Backpressure);
        }
        let output = self.collector.seal(now).map_err(CaptureError::Collection)?;
        self.last_ns = now;
        self.blocked = false;
        Ok(output)
    }
    /// Process one original event, timing request, ready window or terminal step.
    pub fn poll(&mut self, now: u64) -> std::result::Result<HevcCapturePoll, CaptureError> {
        self.check_time(now)?;
        self.last_ns = now;
        if self.closed {
            return Ok(HevcCapturePoll::Ended { retained: None });
        }
        if let Some(collection) = self
            .collector
            .expire(now)
            .map_err(CaptureError::Collection)?
        {
            return Ok(self.stopped(
                CollectionStop::Deadline,
                Some(CollectorError::Deadline),
                collection,
            ));
        }
        if self.event_deadline_ns.is_some_and(|at| now >= at) {
            let collection = self.collector.retire(CollectionStop::Deadline);
            return Ok(self.stopped(
                CollectionStop::Deadline,
                Some(CollectorError::Deadline),
                collection,
            ));
        }
        if self.event.as_deref().is_some_and(invalidates) {
            let collection = self.collector.invalidate();
            return Ok(self.stopped(CollectionStop::InputDiscontinuity, None, collection));
        }
        if let Some(window) = self.collector.take_ready() {
            return Ok(HevcCapturePoll::Window(Box::new(window)));
        }
        if self.finished {
            self.closed = true;
            return Ok(HevcCapturePoll::Ended {
                retained: Some(Box::new(self.cancel())),
            });
        }
        if self.timing_required {
            let p = self
                .event
                .as_deref()
                .and_then(picture)
                .ok_or(CaptureError::NoPicture)?;
            return Ok(HevcCapturePoll::TimingRequired(
                HevcPictureTimingRequest::new(p),
            ));
        }
        if self.input_ended && self.event.is_none() {
            let sealed = self
                .collector
                .finish(now)
                .map_err(CaptureError::Collection)?;
            self.finished = true;
            return Ok(HevcCapturePoll::Sealed(sealed));
        }
        let Some(event) = self.event.take() else {
            return Ok(HevcCapturePoll::Pending {
                wake_at_ns: self.next_wake_ns(),
            });
        };
        if let Event::Source { source, .. } = event.as_ref()
            && let Err(error) = self.collector.push_ordered(source, now)
        {
            self.event = Some(event);
            if matches!(
                error,
                CollectorError::Capacity
                    | CollectorError::Allocation
                    | CollectorError::Backpressure
            ) {
                self.blocked = true;
                return Ok(HevcCapturePoll::Backpressure {
                    reason: error,
                    wake_at_ns: self.next_wake_ns(),
                });
            }
            let collection = self.collector.invalidate();
            return Ok(self.stopped(CollectionStop::InputDiscontinuity, Some(error), collection));
        }
        if let Some(p) = picture(&event) {
            let request = HevcPictureTimingRequest::new(p);
            self.event = Some(event);
            self.timing_required = true;
            return Ok(HevcCapturePoll::TimingRequired(request));
        }
        self.input_ended |= terminal(&event);
        self.event_deadline_ns = None;
        self.blocked = false;
        Ok(HevcCapturePoll::Receiver(event))
    }
    /// Transfer all retained capture work; independently cancel/drain upstream I/O.
    /// Neither this method nor Drop sends TEARDOWN or deletes a published recording.
    pub fn cancel(&mut self) -> HevcCaptureRetirement {
        self.closed = true;
        self.event_deadline_ns = None;
        self.timing_required = false;
        HevcCaptureRetirement {
            collection: self.collector.cancel(),
            event: self.event.take(),
        }
    }
    fn stopped(
        &mut self,
        reason: CollectionStop,
        error: Option<CollectorError>,
        collection: HevcCollectionRetirement,
    ) -> HevcCapturePoll {
        self.closed = true;
        self.event_deadline_ns = None;
        self.timing_required = false;
        HevcCapturePoll::Stopped {
            reason,
            error,
            retained: Box::new(HevcCaptureRetirement {
                collection,
                event: self.event.take(),
            }),
        }
    }
    fn check_live(&self, now: u64) -> std::result::Result<(), CaptureError> {
        self.check_time(now)?;
        if self.closed || self.finished {
            return Err(CaptureError::Closed);
        }
        if self.event_deadline_ns.is_some_and(|at| now >= at) {
            return Err(CaptureError::Collection(CollectorError::Deadline));
        }
        self.collector
            .check_admission(now)
            .map_err(CaptureError::Collection)
    }
    fn check_time(&self, now: u64) -> std::result::Result<(), CaptureError> {
        if now < self.last_ns {
            Err(CaptureError::Collection(CollectorError::ClockReversed))
        } else {
            Ok(())
        }
    }
}

fn picture(event: &Event) -> Option<&HevcPictureGroup> {
    match event {
        Event::Assembly {
            step: HevcAssemblyStep::Accepted(output),
            ..
        } => output.picture.as_ref(),
        _ => None,
    }
}
fn terminal(event: &Event) -> bool {
    matches!(
        event,
        Event::Ended { .. }
            | Event::Assembly {
                retirement: Some(_),
                ..
            }
    )
}
fn invalidates(event: &Event) -> bool {
    match event {
        Event::Source {
            gap_before,
            fragment,
            picture,
            ..
        } => *gap_before || fragment.is_some() || picture.is_some(),
        Event::CodecRefused { .. }
        | Event::Gap { .. }
        | Event::FragmentRetired { .. }
        | Event::PictureRetired(_)
        | Event::QueueRetired(_)
        | Event::Fault { .. } => true,
        Event::Assembly { step, .. } => match step {
            HevcAssemblyStep::Refused(_) => true,
            HevcAssemblyStep::Accepted(output) => output.retired.is_some(),
        },
        Event::Client { event, work } => work.is_some() || client_invalidates(event),
        Event::Ended {
            client,
            interrupted_picture,
            tail,
        } => {
            interrupted_picture.is_some()
                || client.as_deref().is_some_and(client_invalidates)
                || tail.as_ref().is_some_and(|output| output.retired.is_some())
        }
        Event::Pending { .. } => false,
    }
}
fn client_invalidates(event: &HevcClientPoll) -> bool {
    match event {
        HevcClientPoll::Fault { .. } => true,
        HevcClientPoll::Rtp {
            admission,
            retirement,
            ..
        } => {
            retirement.is_some()
                || admission.discarded.is_some()
                || admission.transport.discarded.is_some()
                || admission.transport.disposition == ReorderDisposition::RestartRequired
        }
        HevcClientPoll::Ended { media, .. } => {
            matches!(media, Some(H265ReceivePoll::Ended { discarded: Some(_) }))
        }
        // Raw media cannot be substituted for picture-client source/assembly events.
        HevcClientPoll::Media(progress) => !matches!(progress, H265ReceivePoll::Pending { .. }),
        // RTCP validity is deliberately independent of video continuity. Ordinary
        // Control, AuthenticationRequired and Backpressure are not media loss.
        HevcClientPoll::Control { .. }
        | HevcClientPoll::Rtcp { .. }
        | HevcClientPoll::AuthenticationRequired { .. }
        | HevcClientPoll::Backpressure { .. }
        | HevcClientPoll::KeepAliveDue
        | HevcClientPoll::Pending { .. } => false,
    }
}
fn earlier(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
