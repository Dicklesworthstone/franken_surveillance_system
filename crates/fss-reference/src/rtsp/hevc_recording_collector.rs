#![forbid(unsafe_code)]
//! Continuous, bounded HEVC window selection over the existing replay-verified recorder.
//!
//! Pictures are borrowed, not copied or retained. The collector retains original
//! packets and small picture commitments; sealing replays the real codec owners.
//! Neither selection nor a prepared root proves publication or camera coverage.

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_packet::{H265SourceSpan, OrderedRtpPacket, PacketLimits, RtpPacket, StreamKey};
use fss_packet::hevc::{HevcBoundary, HevcConfiguration, HevcPictureGroup};
use super::recording::{RecordingPacket, RecordingScope};
use super::recording::hevc::{HevcRecordingTiming, PreparedHevcRecording, prepare_hevc_recording};
use super::recording_collector::{CollectionStop, CollectorError as E, CollectorLimits};

type Result<T> = std::result::Result<T, E>;

/// One retained original datagram; Debug never prints its payload.
#[derive(Eq, PartialEq)]
pub struct HevcCollectedSource {
    sequence: u64,
    received_ns: u64,
    admitted_ns: u64,
    bytes: Vec<u8>,
}
impl HevcCollectedSource {
    /// Exact original bytes, including RTP framing, extensions and padding.
    pub fn bytes(&self) -> &[u8] { &self.bytes }
    /// Validated extended sequence in this owner epoch.
    pub fn sequence(&self) -> u64 { self.sequence }
    /// Original receive time; sequence reordering may make this nonmonotonic.
    pub fn received_ns(&self) -> u64 { self.received_ns }
    /// Borrow for the unchanged canonical source-pack representation.
    pub fn as_packet(&self) -> RecordingPacket<'_> {
        RecordingPacket { sequence: self.sequence, received_ns: self.received_ns, bytes: &self.bytes }
    }
}
impl std::fmt::Debug for HevcCollectedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HevcCollectedSource").field("sequence", &self.sequence)
            .field("received_ns", &self.received_ns).field("bytes", &self.bytes.len()).finish()
    }
}

/// Process-local commitment to a borrowed picture and explicit timing, not a new durable schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HevcCollectedPicture {
    /// Explicit owner-supplied track timing.
    pub timing: HevcRecordingTiming,
    /// Original RTP timestamp, not a capture-time estimate.
    pub rtp_timestamp: u32,
    /// Observed grouping boundary, rechecked against original packets on sealing.
    pub boundary: HevcBoundary,
    /// Observed IDR type, not decoder-verified random access.
    pub idr: bool,
    /// Complete NAL count committed by this picture.
    pub nals: usize,
    /// Original reconstructed NAL bytes committed, not retained a second time.
    pub bytes: usize,
    /// Original source-span count committed by this picture.
    pub source_spans: usize,
    /// Hash commitment to all NAL bytes and exact original source maps.
    pub content: ContentDigest,
    first: (u64, usize),
    last: (u64, usize),
    witness_sequence: u64,
}

/// Selection output. Borrowed input remains caller-owned on every outcome.
#[derive(Debug)]
pub enum HevcCollectionAdmission {
    /// Picture selected; a next IDR may have sealed the prior window.
    Accepted {
        /// One exact prepared root is available through take_ready.
        window_ready: bool,
        /// Originals no longer needed by active collection. Some may already
        /// occur in a sealed source object; release is NOT permission to delete custody.
        released: Vec<HevcCollectedSource>,
    },
    /// No packet-aligned, verified-boundary IDR start yet. The borrowed picture
    /// is still owned by the caller; skipped samples never become evidence of absence.
    AwaitingIdr {
        /// Original prefix no longer needed by a future selected window.
        released: Vec<HevcCollectedSource>,
    },
}

/// Result of an explicit seal. It is not a storage acknowledgement.
#[derive(Debug)]
pub struct HevcCollectionSeal {
    /// Whether a completed prefix became a prepared immutable window.
    pub window_ready: bool,
    /// Original bytes released from active collection, not from independent custody.
    pub released: Vec<HevcCollectedSource>,
}

/// Terminal transfer of every retained original and prepared root, without implicit deletion.
#[derive(Debug)]
pub struct HevcCollectionRetirement {
    /// Exact owner key; process-local ingress is not serialized into recordings.
    pub key: StreamKey,
    /// Why this attempt ended.
    pub reason: CollectionStop,
    /// Already prepared output is preserved even if a later operation failed.
    pub ready: Option<PreparedHevcRecording>,
    /// All remaining exact datagrams, including shared boundary lookahead.
    pub sources: Vec<HevcCollectedSource>,
    /// Small commitments/timings for unsealed pictures. Their borrowed objects
    /// were never consumed; the original datagrams above remain independently inspectable.
    pub pictures: Vec<HevcCollectedPicture>,
}

/// One active window and at most one prepared output, with no I/O or hidden worker.
///
/// Supply ordered Source events before their pictures, and complete each picture
/// admission before polling further upstream. A next packet-aligned IDR seals the
/// prior window through its actual closing-witness packet. Adjacent roots can
/// share whole source packets; they never share media samples. Cuts that would
/// split a packet's media, or whose witness packet closes both pictures, defer.
/// No RTP marker or EOF creates a boundary. All sealed output is replay-verified.
pub struct HevcRecordingCollector {
    scope: RecordingScope,
    key: StreamKey,
    payload_type: u8,
    configuration: HevcConfiguration,
    time_scale: u32,
    limits: CollectorLimits,
    sources: Vec<HevcCollectedSource>,
    pictures: Vec<HevcCollectedPicture>,
    ready: Option<PreparedHevcRecording>,
    source_bytes: usize,
    picture_bytes: usize,
    nals: usize,
    spans: usize,
    last_source: Option<u64>,
    last_picture: Option<(u64, usize)>,
    last_end: Option<u64>,
    last_ns: u64,
    closed: bool,
    stop_reason: Option<CollectionStop>,
}
impl std::fmt::Debug for HevcRecordingCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HevcRecordingCollector").field("key", &self.key)
            .field("source_bytes", &self.source_bytes).field("samples", &self.pictures.len())
            .field("ready", &self.ready.is_some()).field("closed", &self.closed).finish_non_exhaustive()
    }
}
impl HevcRecordingCollector {
    /// Pin exact source/configuration, canonical scope, explicit timescale and budgets.
    pub fn new(scope: RecordingScope, key: StreamKey, payload_type: u8,
        configuration: HevcConfiguration, time_scale: u32, limits: CollectorLimits) -> Result<Self>
    {
        limits.validate()?;
        if key.ingress == 0 || key.generation == 0 || key.generation != scope.generation
            || payload_type > 127 || time_scale == 0 { return Err(E::Configuration); }
        Ok(Self { scope, key, payload_type, configuration, time_scale, limits,
            sources: Vec::new(), pictures: Vec::new(), ready: None, source_bytes: 0,
            picture_bytes: 0, nals: 0, spans: 0, last_source: None, last_picture: None,
            last_end: None, last_ns: 0, closed: false, stop_reason: None })
    }
    /// Original datagrams retained, including boundary lookahead.
    pub fn retained_packets(&self) -> usize { self.sources.len() }
    /// Original wire bytes; excludes the independently bounded ready plan.
    pub fn retained_source_bytes(&self) -> usize { self.source_bytes }
    /// Selected, completed pictures awaiting a cut.
    pub fn retained_samples(&self) -> usize { self.pictures.len() }
    /// Whether a prepared window backpressures further admissions.
    pub fn has_ready(&self) -> bool { self.ready.is_some() }
    /// Fixed age of the oldest retained original. Window rotation never refreshes it.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.closed { return None; }
        self.sources.first().and_then(|p| p.admitted_ns.checked_add(self.limits.max_age_ns))
    }
    /// Transfer prepared bytes exactly once, not a durable-publication receipt.
    pub fn take_ready(&mut self) -> Option<PreparedHevcRecording> { self.ready.take() }

    /// Retain a copy while the caller continues to own the original Source event.
    pub fn push_ordered(&mut self, source: &OrderedRtpPacket, now: u64) -> Result<()> {
        self.push_source(source.key(), RecordingPacket { sequence: source.sequence(),
            received_ns: source.received_ns(), bytes: source.bytes() }, now)
    }
    /// Transactional original-source admission. A gap requires explicit invalidation,
    /// not silently starting another source epoch with the same pending pictures.
    pub fn push_source(&mut self, key: StreamKey, source: RecordingPacket<'_>, now: u64) -> Result<()> {
        self.check_admission(now)?;
        if key != self.key { return Err(E::StreamMismatch); }
        let packet = RtpPacket::parse(source.bytes, PacketLimits::default()).map_err(|_| E::Source)?;
        if packet.ssrc() != key.ssrc || packet.payload_type() != self.payload_type { return Err(E::StreamMismatch); }
        if packet.sequence() != source.sequence as u16 { return Err(E::Source); }
        if self.last_source.is_some_and(|last| last.checked_add(1) != Some(source.sequence)) { return Err(E::SourceOrder); }
        if self.sources.len() == self.limits.max_packets
            || source.bytes.len() > self.limits.max_source_bytes.saturating_sub(self.source_bytes)
        { return Err(E::Capacity); }
        now.checked_add(self.limits.max_age_ns).ok_or(E::Deadline)?;
        let mut bytes = reserved(source.bytes.len(), self.limits.max_source_bytes)?;
        reserve_one(&mut self.sources, self.limits.max_packets)?;
        bytes.extend_from_slice(source.bytes);
        self.sources.push(HevcCollectedSource { sequence: source.sequence,
            received_ns: source.received_ns, admitted_ns: now, bytes });
        self.source_bytes += source.bytes.len(); self.last_source = Some(source.sequence); self.last_ns = now;
        Ok(())
    }

    /// Borrow one completed picture and explicit timing. Every failure leaves all
    /// semantic state and caller-owned input unchanged; corrected timing is retryable.
    pub fn push_picture(&mut self, picture: &HevcPictureGroup, timing: HevcRecordingTiming,
        now: u64) -> Result<HevcCollectionAdmission>
    {
        self.check_admission(now)?;
        let end = timing.decode_time.checked_add(u64::from(timing.duration)).ok_or(E::Timeline)?;
        if timing.duration == 0 || timing.decode_time.checked_add_signed(i64::from(timing.composition_offset)).is_none()
            || self.last_end.is_some_and(|last| timing.decode_time != last) { return Err(E::Timeline); }
        let receipt = self.describe(picture, timing)?;
        let starts_packet = self.starts_packet(picture)?;
        let waiting = self.pictures.is_empty() && (!receipt.idr || !starts_packet);
        let cut = !waiting && receipt.idr && starts_packet && self.pictures.last().is_some_and(|last|
            last.last.0 < receipt.first.0 && last.witness_sequence < receipt.witness_sequence);
        let (bytes, nals, spans, samples) = if cut { (0, 0, 0, 0) }
            else { (self.picture_bytes, self.nals, self.spans, self.pictures.len()) };
        if !waiting && (samples == self.limits.max_samples
            || receipt.bytes > self.limits.max_picture_bytes.saturating_sub(bytes)
            || receipt.nals > self.limits.max_nals.saturating_sub(nals)
            || receipt.source_spans > self.limits.max_source_spans.saturating_sub(spans)) { return Err(E::Capacity); }
        let release_before = if waiting { Some(receipt.last.0) }
            else if cut || self.pictures.is_empty() { Some(receipt.first.0) } else { None };
        let release_count = release_before.map_or(0, |seq| self.sources.partition_point(|s| s.sequence < seq));
        let mut released = reserved(release_count, self.limits.max_packets)?;
        if !waiting && !cut { reserve_one(&mut self.pictures, self.limits.max_samples)?; }
        // The old pictures and all their witness packets remain untouched until
        // native replay, remux, fingerprints and all fallible reservations succeed.
        let plan = if cut { Some(self.prepare_prefix()?) } else { None };
        if cut { self.clear_pictures(); self.ready = plan; }
        for packet in self.sources.drain(..release_count) { self.source_bytes -= packet.bytes.len(); released.push(packet); }
        self.last_picture = Some(receipt.last); self.last_end = Some(end); self.last_ns = now;
        if waiting { return Ok(HevcCollectionAdmission::AwaitingIdr { released }); }
        self.picture_bytes += receipt.bytes; self.nals += receipt.nals; self.spans += receipt.source_spans;
        self.pictures.push(receipt);
        Ok(HevcCollectionAdmission::Accepted { window_ready: cut, released })
    }

    /// Seal only the already-observed prefix. Whole boundary packets remain in the
    /// source pack. Shared-packet extra completed pictures refuse rather than being lost.
    pub fn seal(&mut self, now: u64) -> Result<HevcCollectionSeal> {
        self.check_admission(now)?;
        let Some(last) = self.pictures.last() else {
            self.last_ns = now;
            return Ok(HevcCollectionSeal { window_ready: false, released: Vec::new() });
        };
        // Retain the final media packet too: an AP may share it with the next prefix.
        let count = self.sources.partition_point(|p| p.sequence < last.last.0);
        let mut released = reserved(count, self.limits.max_packets)?;
        let plan = self.prepare_prefix()?;
        for p in self.sources.drain(..count) { self.source_bytes -= p.bytes.len(); released.push(p); }
        self.clear_pictures(); self.ready = Some(plan); self.last_ns = now;
        Ok(HevcCollectionSeal { window_ready: true, released })
    }
    /// EOF seals completed groups only. It never invents timing or closes a live
    /// unverified tail. Take any ready plan, then cancel to recover trailing originals.
    pub fn finish(&mut self, now: u64) -> Result<HevcCollectionSeal> {
        let sealed = self.seal(now)?;
        self.closed = true; self.stop_reason = Some(CollectionStop::EndOfInput);
        Ok(sealed)
    }
    /// Expire all pending collection, preserving ready output and source ownership.
    pub fn expire(&mut self, now: u64) -> Result<Option<HevcCollectionRetirement>> {
        self.check_time(now)?;
        self.last_ns = now;
        Ok(if self.next_wake_ns().is_some_and(|at| now >= at) {
            Some(self.retire(CollectionStop::Deadline))
        } else { None })
    }
    /// Terminal source/codec invalidation; it cannot flush a plausible but unsafe prefix.
    pub fn invalidate(&mut self) -> HevcCollectionRetirement { self.retire(CollectionStop::InputDiscontinuity) }
    /// Transfer all retained ownership. Previously prepared roots are not retracted.
    pub fn cancel(&mut self) -> HevcCollectionRetirement {
        let reason = self.stop_reason.unwrap_or(CollectionStop::Cancelled);
        self.retire(reason)
    }
    pub(crate) fn check_admission(&self, now: u64) -> Result<()> {
        self.check_time(now)?;
        if self.closed { return Err(E::Closed); }
        if self.next_wake_ns().is_some_and(|at| now >= at) { return Err(E::Deadline); }
        if self.ready.is_some() { return Err(E::Backpressure); }
        Ok(())
    }
    fn check_time(&self, now: u64) -> Result<()> {
        if now < self.last_ns { Err(E::ClockReversed) } else { Ok(()) }
    }
    fn clear_pictures(&mut self) {
        self.pictures.clear(); self.picture_bytes = 0; self.nals = 0; self.spans = 0;
    }
    pub(crate) fn retire(&mut self, reason: CollectionStop) -> HevcCollectionRetirement {
        self.closed = true; self.stop_reason = Some(reason); self.source_bytes = 0; self.picture_bytes = 0; self.nals = 0; self.spans = 0;
        HevcCollectionRetirement { key: self.key, reason, ready: self.ready.take(),
            sources: std::mem::take(&mut self.sources), pictures: std::mem::take(&mut self.pictures) }
    }
    fn describe(&self, p: &HevcPictureGroup, timing: HevcRecordingTiming) -> Result<HevcCollectedPicture> {
        if p.key() != self.key { return Err(E::StreamMismatch); }
        if p.discontinuity_before() || p.boundary() == HevcBoundary::EndOfInputUnverified
            || !p.prefix().first_slice || p.slice_count() == 0 { return Err(E::UnverifiedPicture); }
        if !matches!(p.prefix().nal_type, 0..=5 | 19 | 20) { return Err(E::UnverifiedPicture); }
        if p.prefix().pps_id != self.configuration.pps_id() { return Err(E::ConfigurationChanged); }
        if p.nals().len() > self.limits.max_nals || p.source_span_count() > self.limits.max_source_spans
            || p.byte_len() > self.limits.max_picture_bytes { return Err(E::Capacity); }
        let mut first = None;
        let mut last = self.last_picture;
        for nal in p.nals() {
            if nal.key() != self.key { return Err(E::StreamMismatch); }
            if nal.layer_id() != 0 || nal.temporal_id_plus_one() > self.configuration.temporal_layers() { return Err(E::ConfigurationChanged); }
            let expected = match nal.nal_type() { 32 => Some(self.configuration.vps()),
                33 => Some(self.configuration.sps()), 34 => Some(self.configuration.pps()), _ => None };
            if expected.is_some_and(|b| b != nal.bytes()) { return Err(E::ConfigurationChanged); }
            for span in nal.sources() {
                let start = span.fragment_header_range.as_ref().map_or(span.wire_range.start, |r| r.start);
                let at = (span.sequence, start);
                if last.is_some_and(|previous| at < previous) { return Err(E::SourceOrder); }
                let index = self.sources.binary_search_by_key(&span.sequence, |s| s.sequence).map_err(|_| E::MissingSource)?;
                let source = &self.sources[index];
                let packet = RtpPacket::parse(&source.bytes, PacketLimits::default()).map_err(|_| E::Source)?;
                if packet.timestamp() != nal.timestamp() { return Err(E::Source); }
                let wire = source.bytes.get(span.wire_range.clone()).ok_or(E::Source)?;
                if wire != nal.bytes().get(span.nal_range.clone()).ok_or(E::Source)? { return Err(E::Source); }
                first = first.or(Some(at)); last = Some((span.sequence, span.wire_range.end));
            }
        }
        let content = fingerprint(p.nals().iter().map(|n| (n.bytes(), n.sources())))?;
        Ok(HevcCollectedPicture { timing, rtp_timestamp: p.timestamp(), boundary: p.boundary(),
            idr: matches!(p.prefix().nal_type, 19 | 20), nals: p.nals().len(), bytes: p.byte_len(),
            source_spans: p.source_span_count(), content, first: first.ok_or(E::MissingSource)?,
            last: last.ok_or(E::MissingSource)?,
            witness_sequence: self.sources.last().ok_or(E::MissingSource)?.sequence })
    }
    fn starts_packet(&self, p: &HevcPictureGroup) -> Result<bool> {
        let span = p.nals().first().and_then(|n| n.sources().first()).ok_or(E::MissingSource)?;
        let index = self.sources.binary_search_by_key(&span.sequence, |s| s.sequence).map_err(|_| E::MissingSource)?;
        let packet = RtpPacket::parse(&self.sources[index].bytes, PacketLimits::default()).map_err(|_| E::Source)?;
        let start = packet.payload_range().start;
        let payload = packet.payload();
        let kind = payload.first().ok_or(E::Source)? >> 1 & 63;
        Ok(match kind {
            48 => span.fragment_header_range.is_none() && span.wire_range.start == start + 4,
            49 => span.fragment_header_range.as_ref().is_some_and(|r| r.start == start)
                && payload.get(2).is_some_and(|b| b & 0x80 != 0),
            0..=47 => span.fragment_header_range.is_none() && span.wire_range.start == start,
            _ => false,
        })
    }
    fn prepare_prefix(&self) -> Result<PreparedHevcRecording> {
        let witness = self.pictures.last().ok_or(E::UnverifiedPicture)?.witness_sequence;
        let end = self.sources.partition_point(|p| p.sequence <= witness);
        let mut packets = reserved(end, self.limits.max_packets)?;
        packets.extend(self.sources[..end].iter().map(HevcCollectedSource::as_packet));
        let mut timings = reserved(self.pictures.len(), self.limits.max_samples)?;
        timings.extend(self.pictures.iter().map(|p| p.timing));
        let plan = prepare_hevc_recording(self.scope.clone(), &self.configuration, self.time_scale, &timings, &packets)
            .map_err(E::Recording)?;
        if plan.samples().len() != self.pictures.len() { return Err(E::Source); }
        for (sample, observed) in plan.samples().iter().zip(&self.pictures) {
            if sample.rtp_timestamp != observed.rtp_timestamp || sample.boundary != observed.boundary
                || sample.idr != observed.idr || sample.mappings.len() != observed.nals { return Err(E::Source); }
            let mappings = plan.mappings().get(sample.mappings.clone()).ok_or(E::Source)?;
            let mut inputs = reserved(mappings.len(), self.limits.max_nals)?;
            for mapping in mappings {
                let bytes = plan.objects().media.get(mapping.range.clone()).ok_or(E::Source)?;
                inputs.push((bytes, mapping.sources.as_slice()));
            }
            if fingerprint(inputs.into_iter())? != observed.content { return Err(E::Source); }
        }
        Ok(plan)
    }
}

fn fingerprint<'a>(nals: impl Iterator<Item = (&'a [u8], &'a [H265SourceSpan])>) -> Result<ContentDigest> {
    // Called only after the enclosing NAL/span ceilings were checked. Encode
    // per-NAL digests rather than duplicating large media bodies in scratch memory.
    let mut e = CanonicalEncoder::new();
    e.text("fss.hevc.collection.picture.v1");
    for (bytes, sources) in nals {
        e.digest(ContentDigest::sha256(bytes)); e.u64(sources.len() as u64);
        for s in sources {
            e.u64(s.sequence); e.u64(s.wire_range.start as u64); e.u64(s.wire_range.end as u64);
            e.u64(s.nal_range.start as u64); e.u64(s.nal_range.end as u64);
            e.bool(s.fragment_header_range.is_some());
            if let Some(r) = &s.fragment_header_range { e.u64(r.start as u64); e.u64(r.end as u64); }
        }
    }
    let bytes = e.finish_checked().map_err(|_| E::Capacity)?;
    Ok(ContentDigest::sha256(&bytes))
}
fn reserved<T>(count: usize, max: usize) -> Result<Vec<T>> {
    if count > max { return Err(E::Capacity); }
    let mut out = Vec::new(); out.try_reserve_exact(count).map_err(|_| E::Allocation)?; Ok(out)
}
fn reserve_one<T>(out: &mut Vec<T>, max: usize) -> Result<()> {
    if out.len() == max { return Err(E::Capacity); }
    if out.len() == out.capacity() {
        let target = (out.len() + 1).saturating_mul(2).min(max);
        out.try_reserve_exact(target - out.len()).map_err(|_| E::Allocation)?;
    }
    Ok(())
}
