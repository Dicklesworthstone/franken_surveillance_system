#![forbid(unsafe_code)]
//! Replay-verified HEVC recording windows using the existing four-child recording waist.
//!
//! Original RTP packets, codec initialization, MP4 media and a canonical index
//! have one immutable root. A window begins at an observed IDR and requires a
//! source-observed closing boundary. Trailing boundary-witness NALs are retained
//! in the source child and counted separately, never fabricated into the media.
//! This proves byte relationships, not decoding, live continuity or authorization.

/// Exact-root durable readback through the shared bounded publication owner.
pub mod local;

mod replay;
mod wire;

use super::{
    MAX_RECORDING_BYTES, MAX_RECORDING_MAPPINGS, MAX_RECORDING_PACKETS, MAX_RECORDING_SAMPLES,
    PreparedRecording, RecordingError, RecordingObjects, RecordingPacket, RecordingScope,
    RecordingSummary, bounded_vec,
};
use fss_container::{HevcNalMapping, HevcSampleMapping};
use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::ObjectManifest;
use fss_packet::hevc::HevcConfiguration;
use fss_packet::{PacketLimits, RtpPacket};
use std::ops::Range;

type Result<T> = std::result::Result<T, RecordingError>;

/// Separate immutable manifest kind; AVC readers never interpret this as AVC.
pub const HEVC_RECORDING_KIND: &str = "hevc_recording_window_v1";
/// At most one bounded trailing picture/prefix remains as source-only boundary evidence.
pub const MAX_HEVC_LOOKAHEAD_NALS: usize = 256;

/// Owner-supplied sample timing, not inferred from RTP, arrival, VUI or a frame rate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HevcRecordingTiming {
    /// Decode time in the explicitly supplied track time scale.
    pub decode_time: u64,
    /// Positive sample duration in track ticks.
    pub duration: u32,
    /// Signed presentation-minus-decode offset.
    pub composition_offset: i32,
}

/// Point-in-time verification of byte provenance; no new custody/coverage/decode claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HevcRecordingVerification {
    /// Common stable recording identity, scope and media accounting.
    pub recording: RecordingSummary,
    /// Complete trailing NALs retained only in source, after the last media picture.
    /// These include its boundary witness, not extra media samples or a verified EOF tail.
    pub source_only_nals: usize,
}

/// Sealed immutable source and derivative bytes, ready for the existing publisher.
/// Only preparation and verified readback construct this type; it has no mutable bytes.
pub struct PreparedHevcRecording {
    plan: PreparedRecording,
    index: Index,
}
impl std::fmt::Debug for PreparedHevcRecording {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedHevcRecording")
            .field("root", &self.manifest().root())
            .field("packets", &self.summary().packets)
            .field("samples", &self.summary().samples)
            .field("source_only_nals", &self.source_only_nals())
            .finish_non_exhaustive()
    }
}
impl PreparedHevcRecording {
    /// Codec-verified plan accepted by the unchanged RecordingPublication state machine.
    /// A plan is not a publication receipt and never grants filesystem/export authority.
    pub fn publication_plan(&self) -> &PreparedRecording {
        &self.plan
    }
    /// Root-last manifest, with exactly the source, initialization, media and index children.
    pub fn manifest(&self) -> &ObjectManifest {
        self.plan.manifest()
    }
    /// Exact immutable bytes. Apply the explicit owner's privacy/retention policy.
    pub fn objects(&self) -> RecordingObjects<'_> {
        self.plan.objects()
    }
    /// Common media accounting; packets may also contain separately counted lookahead.
    pub fn summary(&self) -> &RecordingSummary {
        self.plan.summary()
    }
    /// All retained child payload bytes plus canonical manifest bytes.
    pub fn byte_len(&self) -> usize {
        self.plan.byte_len()
    }
    /// Complete source-only trailing NALs, not silently discarded or remuxed as samples.
    pub fn source_only_nals(&self) -> usize {
        self.index.source_only_nals
    }
    /// Replay-verified sample timings and actual source-observed grouping boundaries.
    pub fn samples(&self) -> &[HevcSampleMapping] {
        &self.index.samples
    }
    /// Replay-verified packet-to-NAL-to-MP4 ranges, including synthesized FU headers.
    pub fn mappings(&self) -> &[HevcNalMapping] {
        &self.index.mappings
    }
    /// Exact original out-of-band VPS, SPS and PPS locations in initialization.
    /// These have no invented RTP source spans.
    pub fn parameter_ranges(&self) -> &[Range<usize>; 3] {
        &self.index.parameters
    }
    /// Borrow all original RTP datagrams, with their unchanged receive times.
    pub fn packets(&self) -> Result<Vec<RecordingPacket<'_>>> {
        super::wire::decode_packets(self.objects().source)
    }
}

struct Index {
    scope: RecordingScope,
    ssrc: u32,
    payload_type: u8,
    time_scale: u32,
    source: ContentDigest,
    initialization: ContentDigest,
    media: ContentDigest,
    parameters: [Range<usize>; 3],
    source_only_nals: usize,
    samples: Vec<HevcSampleMapping>,
    mappings: Vec<HevcNalMapping>,
}

/// Reconstruct, group and remux one bounded source recording without touching live cursors.
///
/// Supply ordered full RTP datagrams, including the NAL that proves the final
/// picture boundary. Every packet must be contiguous in extended sequence and
/// every FU complete. No probation packet, unrelated stream, silent gap or
/// unverified EOF picture is admitted. Exactly timings.len() boundary-closed
/// pictures are remuxed; at most MAX_HEVC_LOOKAHEAD_NALS trailing complete NALs
/// may remain as source-only evidence. Nothing is synthesized to close a picture.
///
/// Reconstruction runs at synthetic replay time zero, not the saved arrival
/// clock. This is a new offline derivation, never a claim that live deadlines
/// succeeded. Original receive times remain intact in the shared source format.
pub fn prepare_hevc_recording(
    scope: RecordingScope,
    configuration: &HevcConfiguration,
    time_scale: u32,
    timings: &[HevcRecordingTiming],
    packets: &[RecordingPacket<'_>],
) -> Result<PreparedHevcRecording> {
    if scope.generation == 0 {
        return Err(RecordingError::Scope);
    }
    replay::validate_timings(timings, time_scale)?;
    let source = super::wire::encode_packets(packets)?;
    let first = packets.first().ok_or(RecordingError::Source)?;
    let packet = RtpPacket::parse(first.bytes, PacketLimits::default())
        .map_err(|_| RecordingError::Source)?;
    let reconstructed = replay::run(
        scope.generation,
        packet.ssrc(),
        packet.payload_type(),
        configuration,
        time_scale,
        timings,
        packets,
    )?;
    let fragment = &reconstructed.fragment;
    let mut samples = bounded_vec(fragment.samples().len(), MAX_RECORDING_SAMPLES)?;
    samples.extend_from_slice(fragment.samples());
    let mut mappings = bounded_vec(fragment.mappings().len(), MAX_RECORDING_MAPPINGS)?;
    for mapping in fragment.mappings() {
        let mut sources = bounded_vec(mapping.sources.len(), MAX_RECORDING_MAPPINGS)?;
        sources.extend_from_slice(&mapping.sources);
        mappings.push(HevcNalMapping {
            sample: mapping.sample,
            nal: mapping.nal,
            range: mapping.range.clone(),
            sources,
        });
    }
    let index = Index {
        scope,
        ssrc: packet.ssrc(),
        payload_type: packet.payload_type(),
        time_scale,
        source: ContentDigest::sha256(&source),
        initialization: ContentDigest::sha256(&reconstructed.initialization),
        media: ContentDigest::sha256(fragment.bytes()),
        parameters: reconstructed.parameters,
        source_only_nals: reconstructed.source_only_nals,
        samples,
        mappings,
    };
    let encoded = wire::encode(&index)?;
    let manifest = manifest_for(&index, &encoded)?;
    check_total(
        &manifest,
        RecordingObjects {
            source: &source,
            initialization: &reconstructed.initialization,
            media: fragment.bytes(),
            index: &encoded,
        },
    )?;
    let summary = summary(&manifest, &index, packets.len())?;
    let plan = PreparedRecording {
        manifest,
        source,
        initialization: reconstructed.initialization,
        media: copy(fragment.bytes())?,
        index: encoded,
        summary,
    };
    Ok(PreparedHevcRecording { plan, index })
}

/// Verify the exact root closure and replay all original packets before accepting any index claim.
///
/// The existing HEVC depacketizer, assembler, configuration reader and muxer are
/// the semantic owners. Their reproduced initialization, media, samples, mapping
/// ranges, boundary classes and FU source spans must all match byte-for-byte.
/// Merely rehashing a forged map, boundary, packet, or sample index is insufficient.
/// The caller supplies expected scope; object metadata cannot grant authority.
pub fn verify_hevc_recording(
    manifest: &ObjectManifest,
    objects: RecordingObjects<'_>,
    expected_scope: &RecordingScope,
) -> Result<HevcRecordingVerification> {
    check_total(manifest, objects)?;
    let index = wire::decode(objects.index)?;
    if &index.scope != expected_scope || index.scope.generation == 0 {
        return Err(RecordingError::Scope);
    }
    if manifest != &manifest_for(&index, objects.index)?
        || index.source != ContentDigest::sha256(objects.source)
        || index.initialization != ContentDigest::sha256(objects.initialization)
        || index.media != ContentDigest::sha256(objects.media)
    {
        return Err(RecordingError::Digest);
    }
    let configuration = replay::configuration(objects.initialization, &index.parameters)?;
    let mut timings = bounded_vec(index.samples.len(), MAX_RECORDING_SAMPLES)?;
    for sample in &index.samples {
        let offset = i128::from(sample.presentation_time) - i128::from(sample.decode_time);
        timings.push(HevcRecordingTiming {
            decode_time: sample.decode_time,
            duration: sample.duration,
            composition_offset: i32::try_from(offset).map_err(|_| RecordingError::Malformed)?,
        });
    }
    let packets = super::wire::decode_packets(objects.source)?;
    let replayed = replay::run(
        index.scope.generation,
        index.ssrc,
        index.payload_type,
        &configuration,
        index.time_scale,
        &timings,
        &packets,
    )?;
    if replayed.initialization != objects.initialization
        || replayed.parameters != index.parameters
        || replayed.fragment.bytes() != objects.media
        || replayed.fragment.samples() != index.samples
        || replayed.fragment.mappings() != index.mappings
        || replayed.source_only_nals != index.source_only_nals
    {
        return Err(RecordingError::Source);
    }
    Ok(HevcRecordingVerification {
        recording: summary(manifest, &index, packets.len())?,
        source_only_nals: index.source_only_nals,
    })
}

fn manifest_for(index: &Index, encoded: &[u8]) -> Result<ObjectManifest> {
    ObjectManifest::new(
        HEVC_RECORDING_KIND,
        [index.source, index.initialization, index.media],
        Some(ContentDigest::sha256(encoded)),
    )
    .map_err(|_| RecordingError::Digest)
}
fn summary(manifest: &ObjectManifest, index: &Index, packets: usize) -> Result<RecordingSummary> {
    let first = index.samples.first().ok_or(RecordingError::Malformed)?;
    let last = index.samples.last().ok_or(RecordingError::Malformed)?;
    Ok(RecordingSummary {
        root: manifest.root(),
        scope: index.scope.clone(),
        packets,
        samples: index.samples.len(),
        nals: index.mappings.len(),
        time_scale: index.time_scale,
        decode_interval: first.decode_time
            ..last
                .decode_time
                .checked_add(u64::from(last.duration))
                .ok_or(RecordingError::Malformed)?,
    })
}
fn check_total(manifest: &ObjectManifest, objects: RecordingObjects<'_>) -> Result<()> {
    let total = [
        objects.source.len(),
        objects.initialization.len(),
        objects.media.len(),
        objects.index.len(),
        manifest.canonical_bytes().len(),
    ]
    .into_iter()
    .try_fold(0_usize, |sum, n| sum.checked_add(n))
    .ok_or(RecordingError::Limit)?;
    if total > MAX_RECORDING_BYTES {
        return Err(RecordingError::Limit);
    }
    Ok(())
}
fn copy(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut result = bounded_vec(bytes.len(), MAX_RECORDING_BYTES)?;
    result.extend_from_slice(bytes);
    Ok(result)
}
