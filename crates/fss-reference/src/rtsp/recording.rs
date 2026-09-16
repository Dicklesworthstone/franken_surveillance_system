#![forbid(unsafe_code)]
//! Sealed, source-linked recording windows over the reference RTP/AVC path.
//!
//! A window is independent, IDR-led, and immutable. Preparation owns no I/O or
//! mutable mux cursor. Original RTP bytes, timing/boundary receipts, initialization
//! and media are four root-linked objects. These are local unencrypted reference
//! artifacts, not permission to disclose footage or an authentication certificate.

mod verify;
mod wire;

use std::ops::Range;
use fss_container::{AvcMuxer, Mp4Limits, NalMapping, SampleMapping, TimedAvcPicture};
use fss_core::{CanonicalEncode, ContentDigest, SensorId, StreamId};
use fss_object::ObjectManifest;
use fss_packet::StreamKey;

/// Maximum combined child payload bytes and root manifest bytes for one window.
pub const MAX_RECORDING_BYTES: usize = 32 * 1024 * 1024;
/// Maximum original datagrams in one independently retrievable window.
pub const MAX_RECORDING_PACKETS: usize = 4096;
/// Maximum picture samples in one window.
pub const MAX_RECORDING_SAMPLES: usize = 256;
/// Maximum NAL mappings and source spans (each independently) in one window.
pub const MAX_RECORDING_MAPPINGS: usize = 16_384;
/// Typed manifest kind. Its metadata child is the canonical recording index.
pub const RECORDING_KIND: &str = "avc_recording_window_v1";

/// Owner-supplied canonical scope, not authority inferred from an RTP header.
/// Ingress handles are process-local and deliberately never serialized here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingScope {
    /// Canonical sensor identity.
    pub sensor: SensorId,
    /// Canonical logical stream identity.
    pub stream: StreamId,
    /// Nonzero stream epoch bound to the supplied receiver's StreamKey generation.
    pub generation: u64,
    /// Exact owner authority/metadata anchor; a reference, not a claim of its custody.
    pub anchor: ContentDigest,
    /// Exact epoch/basis of the supplied receive clock; receive time is not capture time.
    pub receive_clock: ContentDigest,
}

/// Borrowed original wire bytes. Input order is increasing extended sequence, not arrival order.
#[derive(Clone, Copy)]
pub struct RecordingPacket<'a> {
    /// Receiver-validated extended sequence in this stream epoch.
    pub sequence: u64,
    /// Original receive time in the scope's declared monotonic clock basis.
    pub received_ns: u64,
    /// Whole original RTP datagram, including extensions and padding.
    pub bytes: &'a [u8],
}
impl std::fmt::Debug for RecordingPacket<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingPacket").field("sequence", &self.sequence)
            .field("received_ns", &self.received_ns).field("bytes", &self.bytes.len()).finish()
    }
}

/// Payload-free preparation/readback failures. Refusal never consumes caller source objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordingError {
    /// Zero, inconsistent or unauthorized-by-caller scope/binding.
    Scope,
    /// A fixed count, byte, work or allocation ceiling was reached.
    Limit,
    /// Unsupported/corrupt canonical index, source pack, or container layout.
    Malformed,
    /// Supplied object bytes do not match the named SHA-256 objects/root closure.
    Digest,
    /// Original datagrams do not reconstruct exactly the recorded NALs and source spans.
    Source,
    /// Media remux refused source framing, timing, configuration or ownership.
    Media(fss_container::Mp4Error),
}
impl std::fmt::Display for RecordingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recording window refusal: {self:?}")
    }
}
impl std::error::Error for RecordingError {}

type Result<T> = std::result::Result<T, RecordingError>;

/// Ordered roles for the four children of a recording root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordingRole {
    /// Original datagrams are staged before any derivative.
    Source,
    /// Exact decoder configuration and media time scale.
    Initialization,
    /// Encoded MP4 media, without transcoding.
    Media,
    /// Canonical stable scope, object identities, sample receipts and source maps.
    Index,
}

/// Immutable role-ordered children supplied to pure verification.
#[derive(Clone, Copy)]
pub struct RecordingObjects<'a> {
    /// Original RTP datagrams in the canonical source pack.
    pub source: &'a [u8],
    /// MP4 ftyp + moov initialization.
    pub initialization: &'a [u8],
    /// MP4 moof + mdat fragment.
    pub media: &'a [u8],
    /// Canonical window index.
    pub index: &'a [u8],
}
impl std::fmt::Debug for RecordingObjects<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingObjects").field("source_bytes", &self.source.len())
            .field("initialization_bytes", &self.initialization.len())
            .field("media_bytes", &self.media.len()).field("index_bytes", &self.index.len()).finish()
    }
}

/// Reverified content and byte provenance, not decoded pictures, capture continuity,
/// encryption, authority-anchor custody, or a persistent retrievability certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingSummary {
    /// Exact root reverified by this read.
    pub root: ContentDigest,
    /// Canonical owner scope retained without process-local aliases.
    pub scope: RecordingScope,
    /// Number of exact original datagrams.
    pub packets: usize,
    /// Number of primary-picture groups, not decoder-certified complete frames.
    pub samples: usize,
    /// Number of source-linked NALs (including initialization relocation).
    pub nals: usize,
    /// Explicit media tick rate.
    pub time_scale: u32,
    /// Half-open decode interval in media ticks; not a capture-time interval.
    pub decode_interval: Range<u64>,
}

/// Fully owned deterministic plan. Keep it until publication is durable or its
/// exact root is reconciled. A retry uses these same bytes, never remuxes again.
pub struct PreparedRecording {
    manifest: ObjectManifest,
    source: Vec<u8>,
    initialization: Vec<u8>,
    media: Vec<u8>,
    index: Vec<u8>,
    summary: RecordingSummary,
}
impl std::fmt::Debug for PreparedRecording {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRecording").field("root", &self.manifest.root())
            .field("packets", &self.summary.packets).field("samples", &self.summary.samples).finish()
    }
}
impl PreparedRecording {
    /// Exact root-last manifest; this does not publish it.
    pub fn manifest(&self) -> &ObjectManifest { &self.manifest }
    /// Exact immutable child bytes, in their typed roles.
    pub fn objects(&self) -> RecordingObjects<'_> {
        RecordingObjects { source: &self.source, initialization: &self.initialization,
            media: &self.media, index: &self.index }
    }
    /// Verified content accounting from preparation.
    pub fn summary(&self) -> &RecordingSummary { &self.summary }
    /// Combined retained payload bytes including the root manifest.
    pub fn byte_len(&self) -> usize {
        self.source.len() + self.initialization.len() + self.media.len()
            + self.index.len() + self.manifest.canonical_bytes().len()
    }
    /// Stage in this order so source custody never waits for derivative publication.
    pub fn children(&self) -> [(RecordingRole, ContentDigest, &[u8]); 4] {
        [(RecordingRole::Source, ContentDigest::sha256(&self.source), &self.source),
         (RecordingRole::Initialization, ContentDigest::sha256(&self.initialization), &self.initialization),
         (RecordingRole::Media, ContentDigest::sha256(&self.media), &self.media),
         (RecordingRole::Index, ContentDigest::sha256(&self.index), &self.index)]
    }
}

#[derive(Clone, Debug)]
struct Index {
    scope: RecordingScope,
    ssrc: u32,
    payload_type: u8,
    time_scale: u32,
    source: ContentDigest,
    initialization: ContentDigest,
    media: ContentDigest,
    sps: Range<usize>,
    pps: Range<usize>,
    samples: Vec<SampleMapping>,
    mappings: Vec<NalMapping>,
}

/// Seal one bounded, independently decodable-in-principle, IDR-led recording window.
/// The existing muxer validates actual source groups. This creates a fresh local
/// fragment cursor (sequence one); it neither consumes nor changes a live recorder.
/// The caller must provide exactly the packets used by the groups, with no extra
/// NALs or missing fragments, and separately authorize retention of their full bytes.
pub fn prepare_recording(
    scope: RecordingScope,
    time_scale: u32,
    pictures: &[TimedAvcPicture<'_>],
    packets: &[RecordingPacket<'_>],
) -> Result<PreparedRecording> {
    if pictures.is_empty() || pictures.len() > MAX_RECORDING_SAMPLES { return Err(RecordingError::Limit); }
    let first = pictures[0].picture;
    let key = first.key();
    if scope.generation == 0 || scope.generation != key.generation { return Err(RecordingError::Scope); }
    let source = wire::encode_packets(packets)?;
    let first_packet = packets.first().ok_or(RecordingError::Source)?;
    let payload_type = fss_packet::RtpPacket::parse(first_packet.bytes, fss_packet::PacketLimits::default())
        .map_err(|_| RecordingError::Source)?.payload_type();
    let mut muxer = AvcMuxer::new(key, first.sps().clone(), first.pps().clone(), time_scale, Mp4Limits::default())
        .map_err(RecordingError::Media)?;
    let fragment = muxer.fragment(pictures).map_err(RecordingError::Media)?;
    let init = muxer.initialization();
    let index = Index {
        scope, ssrc: key.ssrc, payload_type, time_scale,
        source: ContentDigest::sha256(&source), initialization: ContentDigest::sha256(init.bytes()),
        media: ContentDigest::sha256(fragment.bytes()), sps: init.sps_range(), pps: init.pps_range(),
        samples: fragment.samples().to_vec(), mappings: fragment.mappings().to_vec(),
    };
    let encoded = wire::encode_index(&index)?;
    let manifest = ObjectManifest::new(RECORDING_KIND,
        [index.source, index.initialization, index.media], Some(ContentDigest::sha256(&encoded)))
        .map_err(|_| RecordingError::Digest)?;
    let objects = RecordingObjects { source: &source, initialization: init.bytes(),
        media: fragment.bytes(), index: &encoded };
    let summary = verify_recording(&manifest, objects, &index.scope)?;
    Ok(PreparedRecording { manifest, source, initialization: init.bytes().to_vec(),
        media: fragment.bytes().to_vec(), index: encoded, summary })
}

/// Verify every child digest, exact closure, canonical field and byte-provenance
/// relation before returning any successful summary. The expected scope must come
/// from the owner, never from untrusted bundle metadata. Authority/capture claims
/// are not created by this verification. No I/O or source-codec decoding occurs.
pub fn verify_recording(
    manifest: &ObjectManifest,
    objects: RecordingObjects<'_>,
    expected_scope: &RecordingScope,
) -> Result<RecordingSummary> {
    let total = [objects.source.len(), objects.initialization.len(), objects.media.len(),
        objects.index.len(), manifest.canonical_bytes().len()].into_iter()
        .try_fold(0_usize, |sum, n| sum.checked_add(n)).ok_or(RecordingError::Limit)?;
    if total > MAX_RECORDING_BYTES { return Err(RecordingError::Limit); }
    let index = wire::decode_index(objects.index)?;
    if &index.scope != expected_scope || index.scope.generation == 0 { return Err(RecordingError::Scope); }
    if ContentDigest::sha256(objects.source) != index.source
        || ContentDigest::sha256(objects.initialization) != index.initialization
        || ContentDigest::sha256(objects.media) != index.media { return Err(RecordingError::Digest); }
    let expected = ObjectManifest::new(RECORDING_KIND,
        [index.source, index.initialization, index.media], Some(ContentDigest::sha256(objects.index)))
        .map_err(|_| RecordingError::Digest)?;
    if manifest != &expected { return Err(RecordingError::Digest); }
    let packets = wire::decode_packets(objects.source)?;
    verify::content(&index, objects, &packets)?;
    let first = index.samples.first().ok_or(RecordingError::Malformed)?;
    let last = index.samples.last().ok_or(RecordingError::Malformed)?;
    Ok(RecordingSummary { root: manifest.root(), scope: index.scope,
        packets: packets.len(), samples: index.samples.len(), nals: index.mappings.len(),
        time_scale: index.time_scale,
        decode_interval: first.decode_time..last.decode_time.checked_add(u64::from(last.duration))
            .ok_or(RecordingError::Malformed)? })
}

fn key(index: &Index) -> StreamKey {
    // Verification uses a fresh process-local ingress, not a recovered durable handle.
    StreamKey { ingress: 1, generation: index.scope.generation, ssrc: index.ssrc }
}
fn bounded_vec<T>(count: usize, maximum: usize) -> Result<Vec<T>> {
    if count > maximum { return Err(RecordingError::Limit); }
    let mut output = Vec::new();
    output.try_reserve_exact(count).map_err(|_| RecordingError::Limit)?;
    Ok(output)
}
