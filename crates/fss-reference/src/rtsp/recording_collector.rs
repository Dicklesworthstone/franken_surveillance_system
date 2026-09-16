#![forbid(unsafe_code)]
//! Bounded IDR-led recording collection. Neither admission nor sealing is publication.

use fss_container::TimedAvcPicture;
use fss_core::ContentDigest;
use fss_packet::avc::{AvcBoundary, AvcPictureGroup};
use fss_packet::{OrderedRtpPacket, PacketLimits, RtpPacket, StreamKey};

use super::recording::{
    MAX_RECORDING_MAPPINGS, MAX_RECORDING_PACKETS, MAX_RECORDING_SAMPLES,
    PreparedRecording, RecordingError, RecordingPacket, RecordingScope, prepare_recording,
};

/// Independent retained-source, derivative, metadata, and owner-clock limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectorLimits {
    /// Original datagrams, including next-picture lookahead; at most 4,096.
    pub max_packets: usize,
    /// Exact retained datagram bytes; at most 16 MiB.
    pub max_source_bytes: usize,
    /// Completed picture groups per window; at most 256.
    pub max_samples: usize,
    /// Sum of completed NAL byte lengths; at most 16 MiB.
    pub max_picture_bytes: usize,
    /// NALs in an active window; at most 16,384.
    pub max_nals: usize,
    /// Source spans in an active window; at most 16,384.
    pub max_source_spans: usize,
    /// Lifetime from the oldest retained source's collection admission; 1 ns..60 s.
    pub max_age_ns: u64,
}
impl Default for CollectorLimits {
    fn default() -> Self {
        Self { max_packets: MAX_RECORDING_PACKETS, max_source_bytes: 8 * 1024 * 1024,
            max_samples: MAX_RECORDING_SAMPLES, max_picture_bytes: 8 * 1024 * 1024,
            max_nals: MAX_RECORDING_MAPPINGS, max_source_spans: MAX_RECORDING_MAPPINGS,
            max_age_ns: 10_000_000_000 }
    }
}
impl CollectorLimits {
    /// Reject unsupported policies instead of widening or clamping them.
    pub fn validate(self) -> Result<(), CollectorError> {
        if !(1..=MAX_RECORDING_PACKETS).contains(&self.max_packets)
            || !(12..=16 * 1024 * 1024).contains(&self.max_source_bytes)
            || !(1..=MAX_RECORDING_SAMPLES).contains(&self.max_samples)
            || !(1..=16 * 1024 * 1024).contains(&self.max_picture_bytes)
            || !(1..=MAX_RECORDING_MAPPINGS).contains(&self.max_nals)
            || !(1..=MAX_RECORDING_MAPPINGS).contains(&self.max_source_spans)
            || !(1..=60_000_000_000).contains(&self.max_age_ns)
        { return Err(CollectorError::Configuration); }
        Ok(())
    }
}

/// Explicit media timing. No DTS/duration is inferred from RTP or arrival times.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordingTiming {
    /// Decode time in the collector's declared media ticks.
    pub decode_time: u64,
    /// Positive duration in those ticks.
    pub duration: u32,
    /// Signed presentation-minus-decode offset, including B-picture ordering.
    pub composition_offset: i32,
}

/// Owned picture and its independently supplied timing; returned intact on refusal.
#[derive(Debug, Eq, PartialEq)]
pub struct CollectedPicture {
    /// Source-linked group, not a decoded/complete picture certificate.
    pub picture: AvcPictureGroup,
    /// Explicit timing in the configured media clock.
    pub timing: RecordingTiming,
}
impl CollectedPicture {
    fn timed(&self) -> TimedAvcPicture<'_> {
        TimedAvcPicture { picture: &self.picture, decode_time: self.timing.decode_time,
            duration: self.timing.duration, composition_offset: self.timing.composition_offset }
    }
}

/// Owned copy of one original datagram. Debug contains metadata only.
#[derive(Eq, PartialEq)]
pub struct CollectedSource {
    sequence: u64,
    received_ns: u64,
    admitted_ns: u64,
    bytes: Vec<u8>,
}
impl CollectedSource {
    /// Exact original datagram, not a repacketized derivative.
    pub fn bytes(&self) -> &[u8] { &self.bytes }
    /// Validated extended sequence within the configured receiver epoch.
    pub fn sequence(&self) -> u64 { self.sequence }
    /// Preserved receive time; it can decrease after sequence reordering.
    pub fn received_ns(&self) -> u64 { self.received_ns }
    /// View suitable for the existing canonical recording format.
    pub fn as_packet(&self) -> RecordingPacket<'_> {
        RecordingPacket { sequence: self.sequence, received_ns: self.received_ns, bytes: &self.bytes }
    }
}
impl std::fmt::Debug for CollectedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectedSource").field("sequence", &self.sequence)
            .field("received_ns", &self.received_ns).field("bytes", &self.bytes.len()).finish()
    }
}

/// Payload-free refusal. Caller input and all previously retained bytes survive failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorError {
    /// Invalid owner scope, time scale, or limits.
    Configuration,
    /// Input key/SSRC/payload type differs from the configured binding.
    StreamMismatch,
    /// The instance is finished or cancelled.
    Closed,
    /// Supplied collection time moved backwards.
    ClockReversed,
    /// An immutable prepared window must be taken before accepting more input.
    Backpressure,
    /// A retained-source, picture, or metadata budget would be exceeded.
    Capacity,
    /// A bounded allocation failed before admission.
    Allocation,
    /// A datagram is malformed or its raw/extended sequence binding is inconsistent.
    Source,
    /// Source/picture replay, overlap, or decreasing sequence order.
    SourceOrder,
    /// A picture refers to an original datagram not retained by this owner.
    MissingSource,
    /// Invalid, overflowing, overlapping, or internally noncontiguous media timing.
    Timeline,
    /// Exact SPS/PPS bytes changed without a new stream generation.
    ConfigurationChanged,
    /// An incomplete/discontinuous group cannot be admitted as a recording sample.
    UnverifiedPicture,
    /// The fixed pending-source deadline was reached; poll or cancel to recover the bytes.
    Deadline,
    /// Sealing failed; the existing canonical/provenance verifier's reason is retained.
    Recording(RecordingError),
}
impl std::fmt::Display for CollectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recording collection refusal: {self:?}")
    }
}
impl std::error::Error for CollectorError {}

/// Why retained inputs left collection without becoming a prepared recording.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionStop {
    /// Explicit transport/codec/picture invalidation; not evidence of physical absence.
    InputDiscontinuity,
    /// Fixed owner-clock lifetime expired.
    Deadline,
    /// Owner deliberately stopped the collection.
    Cancelled,
    /// No additional picture can claim these trailing originals after EOF.
    EndOfInput,
    /// Explicit owner abandonment, for example after an unsealable packet boundary.
    OwnerDiscard,
}

/// All unsealed originals and completed derivatives, transferred rather than silently dropped.
#[derive(Debug, Eq, PartialEq)]
pub struct UnsealedRecording {
    /// Exact receiver epoch, not a new durable identity.
    pub key: StreamKey,
    /// Why collection stopped for these inputs.
    pub reason: CollectionStop,
    /// Exact original datagrams, including next-picture lookahead.
    pub sources: Vec<CollectedSource>,
    /// Completed but unpublished picture groups and their supplied timing.
    pub pictures: Vec<CollectedPicture>,
}

/// Explicit result of picture admission. Awaiting-IDR and refused pictures retain ownership.
#[derive(Debug)]
pub enum CollectorAdmission {
    /// Picture retained. Any older window is available through `take_ready`.
    Accepted {
        /// Whether this admission sealed a packet-disjoint prior window.
        window_ready: bool,
        /// Originals before the first selected IDR, never silently called recorded.
        unselected: Vec<CollectedSource>,
    },
    /// No safe IDR start yet. The last source packet stays for possible shared-NAL lookahead.
    AwaitingIdr {
        /// Exact completed picture that was not selected for recording.
        picture: CollectedPicture,
        /// Older original packets not needed by any future selected window.
        unselected: Vec<CollectedSource>,
    },
    /// No picture was consumed and no existing collection state advanced.
    Refused {
        /// Typed reason and explicit recovery requirement.
        reason: CollectorError,
        /// Original owned input, available for retry or independent custody.
        picture: CollectedPicture,
    },
}

/// Terminal transfer. A previously sealed window is preserved, not retroactively cancelled.
#[derive(Debug)]
pub struct CollectorCancellation {
    /// Immutable prepared output that the caller still owns and may reconcile separately.
    pub ready: Option<PreparedRecording>,
    /// Exact inputs that did not become a prepared window.
    pub pending: UnsealedRecording,
}

/// Bounded continuous collection around the existing verified recording preparation.
///
/// Feed ordered source events before their completed pictures. One ready window
/// backpressures new admissions; there is no unbounded queue or eviction. IDR cuts
/// must not split an original datagram. A shared-packet IDR stays in the current
/// window until a later safe cut or an explicit seal. Timers never fabricate a
/// terminal picture. Full ingress custody, I/O, publication and capture-time
/// authority remain outside this collector.
pub struct RecordingCollector {
    scope: RecordingScope,
    key: StreamKey,
    payload_type: u8,
    time_scale: u32,
    limits: CollectorLimits,
    sources: Vec<CollectedSource>,
    pictures: Vec<CollectedPicture>,
    ready: Option<PreparedRecording>,
    source_bytes: usize,
    picture_bytes: usize,
    nals: usize,
    spans: usize,
    configuration: Option<(ContentDigest, ContentDigest)>,
    last_source: Option<u64>,
    last_picture_source: Option<(u64, usize)>,
    last_end: Option<u64>,
    skipped_through: Option<u64>,
    last_now_ns: u64,
    deadline_ns: Option<u64>,
    closed: bool,
}
impl std::fmt::Debug for RecordingCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingCollector").field("key", &self.key)
            .field("source_bytes", &self.source_bytes).field("picture_bytes", &self.picture_bytes)
            .field("samples", &self.pictures.len()).field("ready", &self.ready.is_some())
            .field("deadline_ns", &self.deadline_ns).field("closed", &self.closed).finish_non_exhaustive()
    }
}
impl RecordingCollector {
    /// Bind one canonical scope to a receiver epoch and explicit media tick rate.
    pub fn new(scope: RecordingScope, key: StreamKey, payload_type: u8,
        time_scale: u32, limits: CollectorLimits) -> Result<Self, CollectorError>
    {
        limits.validate()?;
        if key.ingress == 0 || key.generation == 0 || key.generation != scope.generation
            || payload_type > 127 || time_scale == 0 { return Err(CollectorError::Configuration); }
        Ok(Self { scope, key, payload_type, time_scale, limits, sources: Vec::new(),
            pictures: Vec::new(), ready: None, source_bytes: 0, picture_bytes: 0, nals: 0, spans: 0,
            configuration: None, last_source: None, last_picture_source: None, last_end: None,
            skipped_through: None, last_now_ns: 0, deadline_ns: None, closed: false })
    }
    /// Number of source packets, including next-picture lookahead.
    pub fn retained_packets(&self) -> usize { self.sources.len() }
    /// Retained exact original payload bytes, excluding any sealed output.
    pub fn retained_source_bytes(&self) -> usize { self.source_bytes }
    /// Retained completed NAL bytes, excluding original packets and any sealed output.
    pub fn retained_picture_bytes(&self) -> usize { self.picture_bytes }
    /// Completed samples waiting for a safe window cut.
    pub fn retained_samples(&self) -> usize { self.pictures.len() }
    /// Whether one immutable window must be handed to the publication owner.
    pub fn has_ready(&self) -> bool { self.ready.is_some() }
    /// Oldest retained source's fixed collection deadline. No ambient clock is read.
    pub fn next_wake_ns(&self) -> Option<u64> { self.deadline_ns }
    /// Transfer the exact sealed bytes once. This is not a durable publication acknowledgement.
    pub fn take_ready(&mut self) -> Option<PreparedRecording> { self.ready.take() }

    /// Copy a receiver-owned source while leaving its original event with the caller.
    pub fn push_ordered(&mut self, source: &OrderedRtpPacket, now_ns: u64) -> Result<(), CollectorError> {
        self.push_source(source.key(), RecordingPacket { sequence: source.sequence(),
            received_ns: source.received_ns(), bytes: source.bytes() }, now_ns)
    }

    /// Retain exact wire bytes transactionally. Receive times may reverse after
    /// reordering; only collection time must be monotonic. The caller retains its
    /// original on every outcome, including allocation/budget/deadline refusal.
    pub fn push_source(&mut self, key: StreamKey, source: RecordingPacket<'_>, now_ns: u64)
        -> Result<(), CollectorError>
    {
        self.check_admission(now_ns)?;
        if key != self.key { return Err(CollectorError::StreamMismatch); }
        let packet = RtpPacket::parse(source.bytes, PacketLimits::default()).map_err(|_| CollectorError::Source)?;
        if packet.ssrc() != self.key.ssrc || packet.payload_type() != self.payload_type {
            return Err(CollectorError::StreamMismatch);
        }
        if packet.sequence() != source.sequence as u16 { return Err(CollectorError::Source); }
        if self.last_source.is_some_and(|last| source.sequence <= last) { return Err(CollectorError::SourceOrder); }
        if self.sources.len() == self.limits.max_packets
            || source.bytes.len() > self.limits.max_source_bytes.saturating_sub(self.source_bytes)
        { return Err(CollectorError::Capacity); }
        let deadline = now_ns.checked_add(self.limits.max_age_ns).ok_or(CollectorError::Deadline)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(source.bytes.len()).map_err(|_| CollectorError::Allocation)?;
        reserve_one(&mut self.sources, self.limits.max_packets)?;
        bytes.extend_from_slice(source.bytes);
        self.sources.push(CollectedSource { sequence: source.sequence, received_ns: source.received_ns,
            admitted_ns: now_ns, bytes });
        self.source_bytes += source.bytes.len();
        self.last_source = Some(source.sequence);
        self.last_now_ns = now_ns;
        self.deadline_ns = self.deadline_ns.or(Some(deadline));
        Ok(())
    }

    /// Accept explicit timing for one completed picture. On a safe next IDR,
    /// atomically seal the prior window before retaining the new picture. A
    /// preparation failure leaves both the old window and input available.
    pub fn push_picture(&mut self, picture: CollectedPicture, now_ns: u64) -> CollectorAdmission {
        match self.admit_picture(&picture, now_ns) {
            Ok((waiting, window_ready, unselected, plan)) => {
                self.last_now_ns = now_ns;
                self.last_picture_source = Some(plan.last);
                self.last_end = Some(plan.end);
                if waiting {
                    self.skipped_through = Some(plan.last.0);
                    CollectorAdmission::AwaitingIdr { picture, unselected }
                } else {
                    self.configuration = Some(plan.configuration);
                    self.picture_bytes += picture.picture.byte_len();
                    self.nals += plan.nals;
                    self.spans += plan.spans;
                    self.pictures.push(picture);
                    CollectorAdmission::Accepted { window_ready, unselected }
                }
            }
            Err(reason) => CollectorAdmission::Refused { reason, picture },
        }
    }

    /// Explicitly seal all completed active pictures; lookahead originals stay
    /// retained for the next IDR. No incomplete receiver picture is invented.
    pub fn seal(&mut self, now_ns: u64) -> Result<bool, CollectorError> {
        self.check_admission(now_ns)?;
        let changed = self.seal_active()?;
        self.last_now_ns = now_ns;
        Ok(changed)
    }

    /// Expire once, returning every unsealed byte. A ready window is unaffected.
    /// Admission at or after a deadline cannot clear it by completing a picture.
    pub fn poll(&mut self, now_ns: u64) -> Result<Option<UnsealedRecording>, CollectorError> {
        self.check_time(now_ns)?;
        self.last_now_ns = now_ns;
        Ok(if self.deadline_ns.is_some_and(|at| now_ns >= at) {
            Some(self.retire(CollectionStop::Deadline))
        } else { None })
    }

    /// Invalidate pending collection before forwarding a transport/codec failure.
    /// All originals are transferred to the caller; already sealed output survives.
    pub fn interrupt(&mut self, now_ns: u64, reason: CollectionStop) -> Result<UnsealedRecording, CollectorError> {
        self.check_time(now_ns)?;
        self.last_now_ns = now_ns;
        Ok(self.retire(reason))
    }

    /// Seal completed groups, close admission, and return all trailing originals.
    /// Drain a ready window first. A refused seal leaves this operation retryable.
    pub fn finish(&mut self, now_ns: u64) -> Result<UnsealedRecording, CollectorError> {
        self.check_admission(now_ns)?;
        self.seal_active()?;
        self.last_now_ns = now_ns;
        self.closed = true;
        Ok(self.retire(CollectionStop::EndOfInput))
    }

    /// Cancel and transfer ready/unsealed ownership separately; no I/O or deletion.
    pub fn cancel(&mut self) -> CollectorCancellation {
        self.closed = true;
        CollectorCancellation { ready: self.ready.take(), pending: self.retire(CollectionStop::Cancelled) }
    }

    pub(super) fn check_time(&self, now_ns: u64) -> Result<(), CollectorError> {
        if now_ns < self.last_now_ns { return Err(CollectorError::ClockReversed); }
        Ok(())
    }
    pub(super) fn check_admission(&self, now_ns: u64) -> Result<(), CollectorError> {
        self.check_time(now_ns)?;
        if self.closed { return Err(CollectorError::Closed); }
        if self.deadline_ns.is_some_and(|at| now_ns >= at) { return Err(CollectorError::Deadline); }
        if self.ready.is_some() { return Err(CollectorError::Backpressure); }
        Ok(())
    }

    fn admit_picture(&mut self, input: &CollectedPicture, now_ns: u64)
        -> Result<(bool, bool, Vec<CollectedSource>, PicturePlan), CollectorError>
    {
        self.check_admission(now_ns)?;
        let plan = self.picture_plan(input)?;
        let idr = input.picture.identity().idr_pic_id().is_some();
        let waiting = self.pictures.is_empty() && (!idr
            || self.skipped_through.is_some_and(|seq| plan.first.0 <= seq));
        let cut = !self.pictures.is_empty() && idr
            && self.last_picture_source.is_some_and(|last| plan.first.0 > last.0);
        if self.last_end.is_some_and(|end| input.timing.decode_time < end
            || (!waiting && !self.pictures.is_empty() && !cut && input.timing.decode_time != end))
        { return Err(CollectorError::Timeline); }
        let fresh = self.pictures.is_empty() || cut;
        if !waiting {
            let (samples, bytes, nals, spans) = if fresh { (0, 0, 0, 0) }
                else { (self.pictures.len(), self.picture_bytes, self.nals, self.spans) };
            if samples >= self.limits.max_samples
                || input.picture.byte_len() > self.limits.max_picture_bytes.saturating_sub(bytes)
                || plan.nals > self.limits.max_nals.saturating_sub(nals)
                || plan.spans > self.limits.max_source_spans.saturating_sub(spans)
            { return Err(CollectorError::Capacity); }
            if !cut { reserve_one(&mut self.pictures, self.limits.max_samples)?; }
        }
        // Reserve the ownership-transfer result before any successful seal mutates state.
        // A waiting picture leaves its final packet in case another group shares it.
        let release_before = if waiting { plan.last.0 } else if fresh { plan.first.0 } else { 0 };
        let release_count = self.sources.partition_point(|s| s.sequence < release_before);
        let mut unselected = Vec::new();
        unselected.try_reserve_exact(release_count).map_err(|_| CollectorError::Allocation)?;
        if cut { self.seal_active()?; }
        let remaining_release = self.sources.partition_point(|s| s.sequence < release_before);
        for source in self.sources.drain(..remaining_release) {
            self.source_bytes -= source.bytes.len();
            unselected.push(source);
        }
        self.refresh_deadline();
        Ok((waiting, cut, unselected, plan))
    }

    fn picture_plan(&self, input: &CollectedPicture) -> Result<PicturePlan, CollectorError> {
        let picture = &input.picture;
        if picture.key() != self.key { return Err(CollectorError::StreamMismatch); }
        if !picture.saw_first_macroblock() || picture.discontinuity_before()
            || picture.boundary() == AvcBoundary::EndOfInputUnverified
        { return Err(CollectorError::UnverifiedPicture); }
        let configuration = (ContentDigest::sha256(picture.sps().nal_bytes()), ContentDigest::sha256(picture.pps().nal_bytes()));
        if self.configuration.is_some_and(|prior| prior != configuration) { return Err(CollectorError::ConfigurationChanged); }
        let end = input.timing.decode_time.checked_add(u64::from(input.timing.duration)).ok_or(CollectorError::Timeline)?;
        if input.timing.duration == 0
            || input.timing.decode_time.checked_add_signed(i64::from(input.timing.composition_offset)).is_none()
        { return Err(CollectorError::Timeline); }
        let first = picture.nals().first().and_then(|n| n.sources().first()).ok_or(CollectorError::Source)?;
        let last = picture.nals().last().and_then(|n| n.sources().last()).ok_or(CollectorError::Source)?;
        if self.last_picture_source.is_some_and(|(seq, end)| first.sequence < seq
            || (first.sequence == seq && first.wire_range.start < end))
        { return Err(CollectorError::SourceOrder); }
        let mut spans = 0_usize;
        for nal in picture.nals() {
            spans = spans.checked_add(nal.sources().len()).ok_or(CollectorError::Capacity)?;
            if spans > self.limits.max_source_spans { return Err(CollectorError::Capacity); }
            for span in nal.sources() {
                let index = self.sources.binary_search_by_key(&span.sequence, |s| s.sequence)
                    .map_err(|_| CollectorError::MissingSource)?;
                if span.wire_range.start > span.wire_range.end || span.wire_range.end > self.sources[index].bytes.len() {
                    return Err(CollectorError::Source);
                }
            }
        }
        Ok(PicturePlan { first: (first.sequence, first.wire_range.start),
            last: (last.sequence, last.wire_range.end), end, configuration, nals: picture.nals().len(), spans })
    }

    fn seal_active(&mut self) -> Result<bool, CollectorError> {
        let Some(last) = self.pictures.last() else { return Ok(false); };
        let last_sequence = last.picture.nals().last().and_then(|n| n.sources().last())
            .ok_or(CollectorError::Source)?.sequence;
        let source_count = self.sources.partition_point(|s| s.sequence <= last_sequence);
        let mut packets = Vec::new();
        packets.try_reserve_exact(source_count).map_err(|_| CollectorError::Allocation)?;
        packets.extend(self.sources[..source_count].iter().map(CollectedSource::as_packet));
        let mut timed = Vec::new();
        timed.try_reserve_exact(self.pictures.len()).map_err(|_| CollectorError::Allocation)?;
        timed.extend(self.pictures.iter().map(CollectedPicture::timed));
        let prepared = prepare_recording(self.scope.clone(), self.time_scale, &timed, &packets)
            .map_err(CollectorError::Recording)?;
        // Preparation replays all originals. Shared-packet suffixes and extra NALs
        // cannot be lost by shortening source bytes to make a cut appear valid.
        drop(timed);
        drop(packets);
        self.ready = Some(prepared);
        for source in self.sources.drain(..source_count) { self.source_bytes -= source.bytes.len(); }
        self.pictures.clear();
        self.picture_bytes = 0; self.nals = 0; self.spans = 0;
        self.refresh_deadline();
        Ok(true)
    }
    fn refresh_deadline(&mut self) {
        self.deadline_ns = self.sources.first().and_then(|s| s.admitted_ns.checked_add(self.limits.max_age_ns));
    }
    fn retire(&mut self, reason: CollectionStop) -> UnsealedRecording {
        let sources = std::mem::take(&mut self.sources);
        let pictures = std::mem::take(&mut self.pictures);
        // Keep replay/configuration/timeline high-water marks across local interruptions.
        self.skipped_through = self.last_source;
        self.source_bytes = 0; self.picture_bytes = 0; self.nals = 0; self.spans = 0; self.deadline_ns = None;
        UnsealedRecording { key: self.key, reason, sources, pictures }
    }
}

struct PicturePlan {
    first: (u64, usize),
    last: (u64, usize),
    end: u64,
    configuration: (ContentDigest, ContentDigest),
    nals: usize,
    spans: usize,
}
fn reserve_one<T>(values: &mut Vec<T>, maximum: usize) -> Result<(), CollectorError> {
    if values.len() >= maximum { return Err(CollectorError::Capacity); }
    if values.len() == values.capacity() {
        let target = (values.len() + 1).saturating_mul(2).min(maximum);
        values.try_reserve_exact(target - values.len()).map_err(|_| CollectorError::Allocation)?;
    }
    Ok(())
}
