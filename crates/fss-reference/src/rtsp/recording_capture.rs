#![forbid(unsafe_code)]
//! Ownership-preserving event bridge from AvcReceiver/RTSP media output to recording.

use fss_packet::avc::{AvcAssemblyOutput, AvcAssemblyStep, AvcBoundary, AvcPictureGroup,
    AvcReceivePoll, AvcRetirementReason};
use fss_packet::StreamKey;

use super::recording::PreparedRecording;
use super::recording_collector::{CollectedPicture, CollectedSource, CollectionStop,
    CollectorAdmission, CollectorCancellation, CollectorError, RecordingCollector,
    RecordingTiming, UnsealedRecording};

/// Fixed lifetime for one offered event or picture waiting for explicit timing.
pub const MAX_PENDING_EVENT_AGE_NS: u64 = 5_000_000_000;

/// Payload-free event-driver refusals. The rejected input remains caller owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureError {
    /// Collector binding, budget, clock, provenance, or timing refusal.
    Collection(CollectorError),
    /// Process the retained event, timing request, or output before admitting another event.
    Backpressure,
    /// No completed picture is currently waiting for explicit timing.
    NoPicture,
    /// Capture reached terminal EOF, cancellation, or a source discontinuity.
    Closed,
}
impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recording capture refusal: {self:?}")
    }
}
impl std::error::Error for CaptureError {}

/// Event admission failure owns the exact unconsumed event, including any source bytes.
#[derive(Debug)]
pub struct CaptureRefusal {
    /// Reason for refusing to retain the event.
    pub reason: CaptureError,
    /// Unconsumed original receiver event; retry it before polling further upstream input.
    pub event: Box<AvcReceivePoll>,
}

impl std::fmt::Display for CaptureRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.reason) }
}
impl std::error::Error for CaptureRefusal {}

/// Payload-free description of a held picture. Timing must come from an explicit owner basis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PictureTimingRequest {
    /// Exact receiver epoch.
    pub key: StreamKey,
    /// Raw source RTP timestamp; not converted to DTS or capture time.
    pub rtp_timestamp: u32,
    /// Parsed frame number, not a unique durable frame identity.
    pub frame_num: u16,
    /// Syntactically observed IDR, not verified decodability.
    pub idr: bool,
    /// Boundary evidence retained without upgrading a sender marker.
    pub boundary: AvcBoundary,
    /// Reconstructed NAL bytes held for this picture.
    pub bytes: usize,
}
impl PictureTimingRequest {
    fn for_picture(p: &AvcPictureGroup) -> Self {
        Self { key: p.key(), rtp_timestamp: p.timestamp(), frame_num: p.identity().frame_num(),
            idr: p.identity().idr_pic_id().is_some(), boundary: p.boundary(), bytes: p.byte_len() }
    }
}

/// Selection after timing admission. A skipped startup picture remains fully owned.
#[derive(Debug)]
pub enum TimedCapture {
    /// Picture joined the active window; poll for any ready prepared window.
    Collected {
        /// A prior packet-disjoint window was sealed by this IDR.
        window_ready: bool,
        /// Unselected originals preceding the first admitted IDR.
        unselected: Vec<CollectedSource>,
    },
    /// The completed picture was not an admissible packet-disjoint IDR start.
    AwaitingIdr {
        /// Exact unselected picture and supplied timing.
        picture: Box<CollectedPicture>,
        /// Exact unselected original prefix, not silently dropped source.
        unselected: Vec<CollectedSource>,
    },
}

/// Terminal ownership for every layer this event bridge retained.
#[derive(Debug)]
pub struct CaptureRetirement {
    /// Ready output and unsealed source/pictures; a ready plan is never retracted.
    pub collection: CollectorCancellation,
    /// At most one accepted receiver event not yet forwarded/consumed.
    pub event: Option<AvcReceivePoll>,
    /// At most one complete picture still waiting for timing.
    pub picture: Option<AvcPictureGroup>,
    /// Trailing originals after a successful EOF seal, if not yet delivered.
    pub trailing: Option<UnsealedRecording>,
}

/// One bounded output. Receiver events containing originals remain caller-visible.
#[derive(Debug)]
pub enum CapturePoll {
    /// Original receiver event after source retention; completed pictures instead request timing.
    Receiver(AvcReceivePoll),
    /// A completed picture is held, not silently assigned guessed media timing.
    TimingRequired(PictureTimingRequest),
    /// Immutable source-linked window; caller must publish/reconcile these exact bytes.
    Window(PreparedRecording),
    /// An accepted source event remains held while collection needs space.
    Backpressure(CollectorError),
    /// The receiver ended with a non-recordable tail or metadata-only retirement.
    /// Exact tail ownership is transferred without promoting EOF to a verified boundary.
    Tail(AvcAssemblyOutput),
    /// Receiver EOF was observed; continue polling to seal completed windows and return originals.
    InputEnded,
    /// Source/codec invalidation or an expired collection lifetime fenced this capture.
    Stopped {
        /// Why new recording work is no longer accepted.
        reason: CollectionStop,
        /// Local collection refusal, when the stop did not originate in a typed receiver event.
        error: Option<CollectorError>,
        /// Exact ready and pending ownership, including the original invalidating event.
        retained: Box<CaptureRetirement>,
    },
    /// All accepted work is drained; arrange this wake even without new input.
    Pending {
        /// Fixed pending-source deadline, absent when quiescent.
        wake_at_ns: Option<u64>,
    },
    /// EOF completed; trailing originals are transferred exactly once.
    Ended {
        /// Unselected input after the last completed recorded picture.
        trailing: Option<UnsealedRecording>,
    },
}

/// A one-event/one-picture bridge to continuous recording. It owns no socket or receiver task.
///
/// Feed AvcReceiver outputs in order (or the AVC media outputs from RtspAvcClient).
/// Process each offered event before requesting more upstream output. All explicit
/// loss/refusal/retirement events fence pending collection automatically. The
/// upstream receiver and its full-ingress custody/cancellation obligations remain
/// owned by the caller. This layer supplies no authentication or retention policy.
#[derive(Debug)]
pub struct RecordingCapture {
    collector: RecordingCollector,
    event: Option<AvcReceivePoll>,
    picture: Option<AvcPictureGroup>,
    trailing: Option<UnsealedRecording>,
    last_now_ns: u64,
    event_deadline_ns: Option<u64>,
    input_ended: bool,
    closed: bool,
}
impl RecordingCapture {
    /// Take exclusive ownership of a configured collector without granting any I/O authority.
    pub fn new(collector: RecordingCollector) -> Self {
        Self { collector, event: None, picture: None, trailing: None,
            last_now_ns: 0, event_deadline_ns: None, input_ended: false, closed: false }
    }
    /// Read-only collector accounting; mutation must preserve this bridge's event ordering.
    pub fn collector(&self) -> &RecordingCollector { &self.collector }
    /// Ready work wakes immediately, while missing timing waits on the fixed source deadline.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.closed { return None; }
        if self.collector.has_ready() || (self.picture.is_none() && (self.event.is_some() || self.input_ended)) {
            return Some(self.last_now_ns);
        }
        match (self.collector.next_wake_ns(), self.event_deadline_ns) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Retain one event. Failure returns it intact and never copies over accepted work.
    pub fn offer(&mut self, event: AvcReceivePoll, now_ns: u64) -> Result<(), CaptureRefusal> {
        let result = self.check_time(now_ns).and_then(|()| {
            if self.closed || self.input_ended { return Err(CaptureError::Closed); }
            if self.event.is_some() || self.picture.is_some() || self.collector.has_ready() {
                return Err(CaptureError::Backpressure);
            }
            self.collector.check_admission(now_ns).map_err(CaptureError::Collection)
        });
        if let Err(reason) = result { return Err(CaptureRefusal { reason, event: Box::new(event) }); }
        let Some(deadline) = now_ns.checked_add(MAX_PENDING_EVENT_AGE_NS) else {
            return Err(CaptureRefusal { reason: CaptureError::Collection(CollectorError::Deadline), event: Box::new(event) });
        };
        self.event = Some(event); self.event_deadline_ns = Some(deadline); self.last_now_ns = now_ns;
        Ok(())
    }

    /// Supply explicit timing for the held group. A refused timing/collection
    /// admission keeps that same picture for corrected timing or an explicit seal/retry.
    pub fn supply_timing(&mut self, timing: RecordingTiming, now_ns: u64) -> Result<TimedCapture, CaptureError> {
        self.check_time(now_ns)?;
        if self.closed { return Err(CaptureError::Closed); }
        if self.event_deadline_ns.is_some_and(|at| now_ns >= at) {
            return Err(CaptureError::Collection(CollectorError::Deadline));
        }
        let picture = self.picture.take().ok_or(CaptureError::NoPicture)?;
        match self.collector.push_picture(CollectedPicture { picture, timing }, now_ns) {
            CollectorAdmission::Accepted { window_ready, unselected } => {
                self.last_now_ns = now_ns; self.event_deadline_ns = None;
                Ok(TimedCapture::Collected { window_ready, unselected })
            }
            CollectorAdmission::AwaitingIdr { picture, unselected } => {
                self.last_now_ns = now_ns; self.event_deadline_ns = None;
                Ok(TimedCapture::AwaitingIdr { picture: Box::new(picture), unselected })
            }
            CollectorAdmission::Refused { reason, picture } => {
                self.picture = Some(picture.picture);
                Err(CaptureError::Collection(reason))
            }
        }
    }

    /// Seal an existing completed prefix to relieve bounded pressure. Pending
    /// invalidation events must be processed first; they cannot be bypassed by sealing.
    pub fn seal(&mut self, now_ns: u64) -> Result<bool, CaptureError> {
        self.check_time(now_ns)?;
        if self.closed { return Err(CaptureError::Closed); }
        if self.event_deadline_ns.is_some_and(|at| now_ns >= at) {
            return Err(CaptureError::Collection(CollectorError::Deadline));
        }
        if self.event.as_ref().is_some_and(discontinuity) { return Err(CaptureError::Backpressure); }
        let sealed = self.collector.seal(now_ns).map_err(CaptureError::Collection)?;
        self.last_now_ns = now_ns;
        Ok(sealed)
    }

    /// Progress one retained event, ready window, timing request, or terminal drain.
    pub fn poll(&mut self, now_ns: u64) -> Result<CapturePoll, CaptureError> {
        self.check_time(now_ns)?;
        self.last_now_ns = now_ns;
        if self.closed { return Ok(CapturePoll::Ended { trailing: None }); }
        if self.collector.next_wake_ns().is_some_and(|at| now_ns >= at)
            || self.event_deadline_ns.is_some_and(|at| now_ns >= at) {
            return Ok(CapturePoll::Stopped { reason: CollectionStop::Deadline, error: Some(CollectorError::Deadline),
                retained: Box::new(self.stop(CollectionStop::Deadline)) });
        }
        if let Some(window) = self.collector.take_ready() { return Ok(CapturePoll::Window(window)); }
        if let Some(picture) = &self.picture { return Ok(CapturePoll::TimingRequired(PictureTimingRequest::for_picture(picture))); }
        if let Some(trailing) = self.trailing.take() {
            self.closed = true;
            return Ok(CapturePoll::Ended { trailing: Some(trailing) });
        }
        if self.input_ended {
            match self.collector.finish(now_ns) {
                Ok(trailing) => {
                    if let Some(window) = self.collector.take_ready() {
                        self.trailing = Some(trailing);
                        return Ok(CapturePoll::Window(window));
                    }
                    self.closed = true;
                    return Ok(CapturePoll::Ended { trailing: Some(trailing) });
                }
                Err(error) => return Err(CaptureError::Collection(error)),
            }
        }
        let Some(event) = self.event.take() else {
            return Ok(CapturePoll::Pending { wake_at_ns: self.collector.next_wake_ns() });
        };
        if discontinuity(&event) {
            self.event = Some(event);
            return Ok(CapturePoll::Stopped { reason: CollectionStop::InputDiscontinuity, error: None,
                retained: Box::new(self.stop(CollectionStop::InputDiscontinuity)) });
        }
        if let AvcReceivePoll::Source { source, .. } = &event
            && let Err(reason) = self.collector.push_ordered(source, now_ns) {
                self.event = Some(event);
                if matches!(reason, CollectorError::Capacity | CollectorError::Allocation | CollectorError::Backpressure) {
                    return Ok(CapturePoll::Backpressure(reason));
                }
                return Ok(CapturePoll::Stopped { reason: CollectionStop::InputDiscontinuity, error: Some(reason),
                    retained: Box::new(self.stop(CollectionStop::InputDiscontinuity)) });
            }
        match event {
            AvcReceivePoll::Picture(picture)
            | AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(AvcAssemblyOutput { picture: Some(picture), retired: None })) => {
                let request = PictureTimingRequest::for_picture(&picture);
                self.picture = Some(picture);
                Ok(CapturePoll::TimingRequired(request))
            }
            AvcReceivePoll::Ended { tail, .. } => {
                self.input_ended = true;
                match tail {
                    Some(out) if out.picture.as_ref().is_some_and(|p| p.boundary() != AvcBoundary::EndOfInputUnverified) => {
                        // Discontinuity validation above proved that no retirement is lost.
                        let Some(picture) = out.picture else { return Ok(CapturePoll::InputEnded); };
                        let request = PictureTimingRequest::for_picture(&picture);
                        self.picture = Some(picture);
                        Ok(CapturePoll::TimingRequired(request))
                    }
                    Some(out) => { self.event_deadline_ns = None; Ok(CapturePoll::Tail(out)) }
                    None => { self.event_deadline_ns = None; Ok(CapturePoll::InputEnded) }
                }
            }
            other => { self.event_deadline_ns = None; Ok(CapturePoll::Receiver(other)) }
        }
    }

    /// Cancel only this recording bridge. Caller separately drains/cancels its upstream owner.
    pub fn cancel(&mut self) -> CaptureRetirement { self.stop(CollectionStop::Cancelled) }

    fn stop(&mut self, reason: CollectionStop) -> CaptureRetirement {
        self.closed = true; self.event_deadline_ns = None;
        let mut collection = self.collector.cancel();
        collection.pending.reason = reason;
        CaptureRetirement { collection, event: self.event.take(), picture: self.picture.take(), trailing: self.trailing.take() }
    }
    fn check_time(&self, now_ns: u64) -> Result<(), CaptureError> {
        if now_ns < self.last_now_ns { return Err(CaptureError::Collection(CollectorError::ClockReversed)); }
        self.collector.check_time(now_ns).map_err(CaptureError::Collection)
    }
}

fn discontinuity(event: &AvcReceivePoll) -> bool {
    match event {
        AvcReceivePoll::Source { gap_before, fragment, picture, .. } => *gap_before || fragment.is_some() || picture.is_some(),
        AvcReceivePoll::CodecRefused { .. } | AvcReceivePoll::Gap { .. }
        | AvcReceivePoll::FragmentRetired { .. } | AvcReceivePoll::PictureRetired(_)
        | AvcReceivePoll::Assembly(AvcAssemblyStep::Refused(_)) => true,
        AvcReceivePoll::Picture(p) => p.discontinuity_before(),
        AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(out)) => out.retired.is_some()
            || out.picture.as_ref().is_some_and(AvcPictureGroup::discontinuity_before),
        AvcReceivePoll::Ended { fragment, interrupted_picture, tail } => fragment.is_some() || interrupted_picture.is_some()
            || tail.as_ref().is_some_and(|out| {
                out.picture.as_ref().is_some_and(AvcPictureGroup::discontinuity_before)
                    || out.retired.as_ref().is_some_and(|r| out.picture.is_some() || r.reason != AvcRetirementReason::NoPrimaryPicture)
            }),
        _ => false,
    }
}
