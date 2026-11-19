#![forbid(unsafe_code)]
//! Canonical native transport ancestry, metadata-only membership and bounded source replay.

use super::*;
use crate::retained_source::RetainedSource;
use super::super::file_adapter::{
    CaptureHint, FileImportManifest, FileIngestLimits, FileOmissionSpan, SegmentSpan,
};
use fss_core::{
    CanonicalDecoder, CanonicalEncode, CapsuleId, ClockBasis, DigestAlgorithm, SensorCapsule,
    SensorId, StreamId,
};
use std::collections::BTreeSet;

pub(super) struct Proof {
    pub(super) request: MpegTsImportRequest,
    pub(super) receipt: TsExtractionReceipt,
    pub(super) original_chunks: Vec<(ContentDigest, u64)>,
    pub(super) scan_digest: ContentDigest,
}

fn digest(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest, FileIngestError> {
    let value = d.digest()?;
    if value.algorithm() != DigestAlgorithm::Sha256 { return Err(corrupt("digest algorithm")); }
    Ok(value)
}
fn size(d: &mut CanonicalDecoder<'_>) -> Result<usize, FileIngestError> {
    usize::try_from(d.u64()?).map_err(|_| corrupt("size overflow"))
}
fn request(bytes: &[u8]) -> Result<MpegTsImportRequest, FileIngestError> {
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != REQUEST_DOMAIN { return Err(corrupt("request domain")); }
    let sensor = SensorId::parse(d.text()?)?;
    let stream = StreamId::parse(d.text()?)?;
    let receive = TimestampNs(d.i128()?);
    let capture_hint = if d.bool()? {
        Some(CaptureHint {
            start_ns: TimestampNs(d.i128()?),
            uncertainty_ns: d.u64()?,
            assumed_fps: f64::from_bits(d.u64()?),
        })
    } else { None };
    let mut limits = FileIngestLimits::standard();
    limits.max_file_bytes = d.u64()?;
    limits.chunk_bytes = d.u64()?;
    limits.max_segments = size(&mut d)?;
    limits.max_batch_deltas = size(&mut d)?;
    limits.annexb_limits.max_input_bytes = size(&mut d)?;
    limits.annexb_limits.max_nal_bytes = size(&mut d)?;
    limits.annexb_limits.max_nals = size(&mut d)?;
    limits.annexb_limits.max_aus = size(&mut d)?;
    limits.annexb_limits.max_leading_garbage_bytes = size(&mut d)?;
    limits.mjpeg_limits.max_input_bytes = size(&mut d)?;
    limits.mjpeg_limits.max_frame_bytes = size(&mut d)?;
    limits.mjpeg_limits.max_frames = size(&mut d)?;
    limits.mjpeg_limits.max_marker_segments_per_frame = size(&mut d)?;
    limits.mjpeg_limits.max_dimension = u32::try_from(d.u64()?).map_err(|_| corrupt("dimension"))?;
    let program = if d.bool()? {
        Some(u16::try_from(d.u64()?).map_err(|_| corrupt("program"))?)
    } else { None };
    let video_pid = if d.bool()? {
        Some(u16::try_from(d.u64()?).map_err(|_| corrupt("PID"))?)
    } else { None };
    let transport_limits = TsLimits {
        max_input_bytes: size(&mut d)?,
        max_packets: size(&mut d)?,
        max_psi_sections: size(&mut d)?,
        max_pes: size(&mut d)?,
        max_pes_bytes: size(&mut d)?,
        max_payload_spans: size(&mut d)?,
        max_elementary_bytes: size(&mut d)?,
    };
    d.ensure_finished()?;
    let mut file = FileIngestRequest::new("", sensor, stream);
    file.limits = limits;
    file.receive_time = Some(receive);
    file.capture_hint = capture_hint;
    let value = MpegTsImportRequest { file, selection: TsSelection { program, video_pid }, transport_limits };
    value.validate().map_err(|_| corrupt("request"))?;
    if value.encode() != bytes { return Err(corrupt("noncanonical request")); }
    Ok(value)
}

impl Proof {
    fn validate(&self) -> Result<(), FileIngestError> {
        self.request.validate().map_err(|_| corrupt("request"))?;
        let source_bytes = self.receipt.source_bytes();
        let chunk_bytes = self.request.file.limits.chunk_bytes;
        let count = source_bytes.div_ceil(chunk_bytes);
        if source_bytes == 0
            || source_bytes > self.request.file.limits.max_file_bytes
            || source_bytes > MAX_BYTES
            || self.receipt.elementary_bytes() == 0
            || self.receipt.elementary_bytes() > MAX_BYTES
            || self.receipt.selection() != self.request.selection
            || self.receipt.limits() != self.request.transport_limits
            || self.original_chunks.len() as u64 != count
            || self.original_chunks.len() > MAX_OBJECTS
            || self.scan_digest.algorithm() != DigestAlgorithm::Sha256
        {
            return Err(corrupt("extraction policy or original closure"));
        }
        for (index, (digest, bytes)) in self.original_chunks.iter().enumerate() {
            let expected = chunk_bytes.min(source_bytes - index as u64 * chunk_bytes);
            if digest.algorithm() != DigestAlgorithm::Sha256 || *bytes != expected {
                return Err(corrupt("original chunk length or identity"));
            }
        }
        Ok(())
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, FileIngestError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        let request = self.request.encode();
        if request.len() > 4096 { return Err(corrupt("request byte bound")); }
        e.bytes(&request);
        e.bytes(&self.receipt.to_bytes().map_err(|_| corrupt("extraction receipt"))?);
        e.digest(self.scan_digest);
        e.u64(self.original_chunks.len() as u64);
        for (digest, bytes) in &self.original_chunks { e.digest(*digest); e.u64(*bytes); }
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_PROOF_BYTES { return Err(corrupt("proof byte ceiling")); }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, FileIngestError> {
        if bytes.len() > MAX_PROOF_BYTES { return Err(corrupt("proof byte ceiling")); }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != DOMAIN { return Err(corrupt("proof domain")); }
        let request_bytes = d.bytes()?;
        if request_bytes.len() > 4096 { return Err(corrupt("request byte bound")); }
        let request = request(request_bytes)?;
        let receipt = TsExtractionReceipt::from_bytes(d.bytes()?)
            .map_err(|_| corrupt("extraction receipt"))?;
        let scan_digest = digest(&mut d)?;
        let count = size(&mut d)?;
        if count > MAX_OBJECTS || count > d.remaining() / 41 {
            return Err(corrupt("original chunk count"));
        }
        let mut original_chunks = Vec::with_capacity(count);
        for _ in 0..count { original_chunks.push((digest(&mut d)?, d.u64()?)); }
        d.ensure_finished()?;
        let value = Self { request, receipt, original_chunks, scan_digest };
        if value.encode()? != bytes { return Err(corrupt("noncanonical proof")); }
        Ok(value)
    }
}

/// Binds all native access-unit boundaries, omitted elementary bytes and exact capsule authority.
pub(super) fn scan_digest(
    spans: &[SegmentSpan],
    omissions: &[FileOmissionSpan],
    capsules: &[SensorCapsule],
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(SCAN_DOMAIN);
    e.u64(spans.len() as u64);
    for span in spans {
        e.u64(span.segment_index as u64);
        e.u64(span.offset);
        e.u64(span.len);
        e.digest(span.segment_sha256);
        e.text(span.capsule_id.as_str());
        e.bool(span.gap_before);
    }
    e.u64(omissions.len() as u64);
    for omission in omissions {
        e.u64(omission.offset);
        e.u64(omission.len);
        e.text(&omission.reason);
    }
    e.u64(capsules.len() as u64);
    for capsule in capsules { e.digest(ContentDigest::sha256(&capsule.canonical_bytes())); }
    ContentDigest::sha256(&e.finish())
}

fn proof_digest(manifest: &FileImportManifest) -> Result<Option<ContentDigest>, FileIngestError> {
    if manifest.adapter_id != ADAPTER { return Ok(None); }
    let suffix = manifest.adapter_generation.strip_prefix(GENERATION)
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .ok_or_else(|| corrupt("adapter generation"))?;
    Ok(Some(ContentDigest::parse(&format!("sha256:{suffix}"))?))
}

fn proof(
    deployment: &dyn RetainedSource,
    manifest: &FileImportManifest,
    cx: &ReplayCx,
    reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
) -> Result<Option<(ContentDigest, Proof)>, FileIngestError> {
    let Some(digest) = proof_digest(manifest)? else { return Ok(None); };
    checkpoint(cx)?;
    // Reserve the finite metadata ceiling before I/O. A cursor pays this once, then retains
    // the exact verified proof; its normal metadata revalidation still checks current custody.
    reserve(MAX_PROOF_BYTES as u64)?;
    deployment.check_object_available(digest)?;
    let bytes = deployment.read_object_bounded(digest, MAX_PROOF_BYTES)?;
    if ContentDigest::sha256(&bytes) != digest { return Err(corrupt("proof digest")); }
    Ok(Some((digest, Proof::decode(&bytes)?)))
}

fn load_media(
    deployment: &dyn RetainedSource,
    proof: &Proof,
    cx: &ReplayCx,
    reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
) -> Result<Vec<u8>, FileIngestError> {
    let mut original = Vec::new();
    original.try_reserve_exact(proof.receipt.source_bytes() as usize)
        .map_err(|_| corrupt("original allocation"))?;
    for (digest, length) in &proof.original_chunks {
        checkpoint(cx)?;
        reserve(*length)?;
        deployment.check_object_available(*digest)?;
        let bytes = deployment.read_object_bounded(*digest, *length as usize)?;
        if bytes.len() as u64 != *length || ContentDigest::sha256(&bytes) != *digest {
            return Err(corrupt("original transport chunk"));
        }
        original.extend_from_slice(&bytes);
    }
    let video = proof.receipt.verify_bounded_with_checkpoint(
        &original, proof.request.transport_limits,
        &mut || checkpoint(cx).map_err(|_| TsError::Cancelled),
    ).map_err(|_| corrupt("native transport reconstruction"))?;
    let scan = proof.request.scan(&proof.receipt, video.elementary_stream(), cx)?;
    if scan_digest(&scan.segment_spans, &scan.omission_spans, &scan.capsules) != proof.scan_digest {
        return Err(corrupt("native access-unit or capsule map"));
    }
    checkpoint(cx)?;
    Ok(video.into_elementary_stream())
}

/// One bounded source-verified elementary stream, keyed to the complete canonical origin proof.
/// Final consuming publications independently re-read custody; a cache never certifies disk health.
pub(crate) struct OriginCache {
    digest: ContentDigest,
    proof: Proof,
    media: Vec<u8>,
}
impl fmt::Debug for OriginCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginCache").field("proof", &self.digest).finish_non_exhaustive()
    }
}
pub(crate) fn verify_range_budgeted(
    deployment: &dyn RetainedSource,
    manifest: &FileImportManifest,
    offset: u64,
    bytes: &[u8],
    cx: &ReplayCx,
    cache: &mut Option<OriginCache>,
    reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
) -> Result<(), FileIngestError> {
    let Some(digest) = proof_digest(manifest)? else { return Ok(()); };
    checkpoint(cx)?;
    deployment.check_object_available(digest)?;
    if cache.as_ref().is_none_or(|cached| cached.digest != digest) {
        let (_, proof) = proof(deployment, manifest, cx, reserve)?
            .ok_or_else(|| corrupt("missing source proof"))?;
        let media = load_media(deployment, &proof, cx, reserve)?;
        *cache = Some(OriginCache { digest, proof, media });
    }
    let verified = cache.as_ref().ok_or_else(|| corrupt("source cache"))?;
    // Keep current erasure checks even when this cursor already verified the source bytes.
    for (original, _) in &verified.proof.original_chunks {
        checkpoint(cx)?;
        deployment.check_object_available(*original)?;
    }
    let start = usize::try_from(offset).map_err(|_| corrupt("range start"))?;
    let end = start.checked_add(bytes.len()).ok_or_else(|| corrupt("range end"))?;
    if cache.as_ref().and_then(|value| value.media.get(start..end)) != Some(bytes) {
        return Err(corrupt("elementary bytes differ from original transport"));
    }
    checkpoint(cx)
}
pub(crate) fn verify_originals(
    deployment: &dyn RetainedSource,
    manifest: &FileImportManifest,
    cx: &ReplayCx,
) -> Result<(), FileIngestError> {
    let Some((_, proof)) = proof(deployment, manifest, cx, &mut |_| Ok(()))? else { return Ok(()); };
    let _ = load_media(deployment, &proof, cx, &mut |_| Ok(()))?;
    checkpoint(cx)
}
pub(crate) fn verify_membership(
    deployment: &dyn RetainedSource,
    manifest: &FileImportManifest,
    held: &BTreeSet<ContentDigest>,
    capsules: &BTreeMap<&str, ContentDigest>,
    import_hex: &str,
    cx: &ReplayCx,
) -> Result<(), FileIngestError> {
    let Some((digest, proof)) = proof(deployment, manifest, cx, &mut |_| Ok(()))? else { return Ok(()); };
    if !held.contains(&digest)
        || proof.original_chunks.iter().any(|(d, _)| !held.contains(d))
        || hex(proof.request.identity(proof.receipt.source_digest()).map_err(|_| corrupt("identity"))?) != import_hex
        || manifest.limits_digest != proof.request.digest().map_err(|_| corrupt("request digest"))?
        || manifest.input_sha256 != proof.receipt.elementary_digest()
        || manifest.input_bytes != proof.receipt.elementary_bytes()
        || manifest.chunk_bytes != proof.request.file.limits.chunk_bytes
        || manifest.format != format(proof.receipt.codec()).as_str()
        || manifest.capture_time_label != proof.request.time_label()
        || manifest.detector_evidence != DETECTOR
        || manifest.segment_spans.is_empty()
        || manifest.segment_spans.len() > proof.request.file.limits.max_segments
        || manifest.omission_spans.len() > MAX_SEGMENTS
    {
        return Err(corrupt("retained import origin binding"));
    }
    let file = &proof.request.file;
    let receive_time = file.receive_time.ok_or_else(|| corrupt("receive time"))?;
    let mut expected = Vec::with_capacity(manifest.segment_spans.len());
    for (index, span) in manifest.segment_spans.iter().enumerate() {
        checkpoint(cx)?;
        let capsule_id = CapsuleId::parse(format!("capsule:{import_hex}:{index:06}"))?;
        if span.segment_index != index || span.capsule_id != capsule_id {
            return Err(corrupt("access-unit identity"));
        }
        let capsule = SensorCapsule {
            capsule_id,
            sensor_id: file.sensor_id.clone(),
            stream_id: file.stream_id.clone(),
            sequence: index as u64,
            capture: FileIngestAdapter::compute_capture_interval(index, file.capture_hint.as_ref(), receive_time)?,
            receive_time,
            clock_basis: ClockBasis::Estimated,
            source_digest: span.segment_sha256,
            source_bytes: span.len,
            gap_before: span.gap_before,
            frame_count: 1,
        };
        let object = format!("object:capsule:{}", span.capsule_id.as_str());
        if capsules.get(object.as_str()).copied() != Some(ContentDigest::sha256(&capsule.canonical_bytes())) {
            return Err(corrupt("sensor, stream, capture or capsule authority"));
        }
        expected.push(capsule);
    }
    if scan_digest(&manifest.segment_spans, &manifest.omission_spans, &expected) != proof.scan_digest {
        return Err(corrupt("access-unit and omission map"));
    }
    checkpoint(cx)
}
