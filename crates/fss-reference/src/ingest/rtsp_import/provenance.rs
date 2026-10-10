#![forbid(unsafe_code)]
//! Retained native packet ancestry, exact container maps and bounded verified-window caching.

use super::*;
use fss_core::{
    CanonicalDecoder, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, SensorCapsule,
    SensorId, StreamId,
};
use fss_object::ObjectManifest;
use super::super::file_adapter::{FileOmissionSpan, SegmentSpan};
use crate::rtsp::recording::{
    PreparedRecording, RecordingObjects, verify_recording,
    hevc::{HEVC_RECORDING_KIND, verify_hevc_recording}, RECORDING_KIND,
};
use std::collections::BTreeSet;

const MAX_OMISSIONS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectRef {
    digest: ContentDigest,
    bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct FrameOrigin {
    offset: u64,
    bytes: u64,
    digest: ContentDigest,
    capture: CaptureInterval,
}
pub(super) struct Proof {
    pub(super) request: RtspImportRequest,
    manifest: Vec<u8>,
    objects: [ObjectRef; 4],
    media_digest: ContentDigest,
    media_bytes: u64,
    frames: Vec<FrameOrigin>,
    omissions: Vec<FileOmissionSpan>,
}

pub(super) struct Window {
    root: Vec<u8>,
    source: Vec<u8>,
    initialization: Vec<u8>,
    fragment: Vec<u8>,
    index: Vec<u8>,
    pub(super) samples: usize,
}
impl Window {
    pub(super) fn from_verified(
        plan: &PreparedRecording,
        request: &RtspImportRequest,
    ) -> Result<Self, RtspImportError> {
        let o = plan.objects();
        let media_len = o.initialization.len().checked_add(o.media.len())
            .ok_or(RtspImportError::Invalid("media size overflow"))?;
        if plan.byte_len() as u64 > request.max_original_bytes
            || media_len as u64 > request.max_media_bytes
            || plan.summary().samples == 0
            || plan.summary().samples > request.max_frames
            || plan.manifest().root() != request.root
            || plan.summary().scope != request.source
        {
            return Err(RtspImportError::Invalid("selected window exceeds exact scope or bounds"));
        }
        Ok(Self {
            root: plan.manifest().canonical_bytes(),
            source: o.source.to_vec(),
            initialization: o.initialization.to_vec(),
            fragment: o.media.to_vec(),
            index: o.index.to_vec(),
            samples: plan.summary().samples,
        })
    }
    pub(super) fn media_len(&self) -> usize {
        self.initialization.len() + self.fragment.len()
    }
    pub(super) fn media(&self) -> Result<Vec<u8>, FileIngestError> {
        let mut out = Vec::new();
        out.try_reserve_exact(self.media_len()).map_err(|_| corrupt("media allocation"))?;
        out.extend_from_slice(&self.initialization);
        out.extend_from_slice(&self.fragment);
        Ok(out)
    }
    pub(super) fn payloads(&self) -> [(ContentDigest, &[u8]); 5] {
        [
            (ContentDigest::sha256(&self.root), &self.root),
            (ContentDigest::sha256(&self.source), &self.source),
            (ContentDigest::sha256(&self.initialization), &self.initialization),
            (ContentDigest::sha256(&self.fragment), &self.fragment),
            (ContentDigest::sha256(&self.index), &self.index),
        ]
    }
    fn objects(&self) -> RecordingObjects<'_> {
        RecordingObjects {
            source: &self.source,
            initialization: &self.initialization,
            media: &self.fragment,
            index: &self.index,
        }
    }
    fn matches_range(&self, offset: u64, bytes: &[u8]) -> bool {
        let Ok(start) = usize::try_from(offset) else { return false; };
        let Some(end) = start.checked_add(bytes.len()) else { return false; };
        if end > self.media_len() { return false; }
        let split = self.initialization.len();
        if start >= split {
            return self.fragment.get(start - split..end - split) == Some(bytes);
        }
        let first = (split - start).min(bytes.len());
        self.initialization.get(start..start + first) == bytes.get(..first)
            && (first == bytes.len()
                || self.fragment.get(..bytes.len() - first) == bytes.get(first..))
    }
}

impl Proof {
    pub(super) fn new(
        request: RtspImportRequest,
        window: &Window,
        media: &[u8],
        scan: &ScannedSegments,
    ) -> Result<Self, FileIngestError> {
        let payloads = window.payloads();
        let object = |at: usize| ObjectRef {
            digest: payloads[at].0,
            bytes: payloads[at].1.len() as u64,
        };
        let value = Self {
            request,
            manifest: window.root.clone(),
            objects: [object(1), object(2), object(3), object(4)],
            media_digest: ContentDigest::sha256(media),
            media_bytes: media.len() as u64,
            frames: scan.segment_spans.iter().zip(&scan.capsules).map(|(span, capsule)| FrameOrigin {
                offset: span.offset,
                bytes: span.len,
                digest: span.segment_sha256,
                capture: capsule.capture,
            }).collect(),
            omissions: scan.omission_spans.clone(),
        };
        value.validate()?;
        Ok(value)
    }
    pub(super) fn frames(&self) -> usize { self.frames.len() }
    pub(super) fn encode(&self) -> Result<Vec<u8>, FileIngestError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        self.request.encode(&mut e);
        e.bytes(&self.manifest);
        for object in &self.objects {
            e.digest(object.digest);
            e.u64(object.bytes);
        }
        e.digest(self.media_digest);
        e.u64(self.media_bytes);
        e.u64(self.frames.len() as u64);
        for frame in &self.frames {
            e.u64(frame.offset);
            e.u64(frame.bytes);
            e.digest(frame.digest);
            e.i128(frame.capture.earliest.0);
            e.i128(frame.capture.latest.0);
        }
        e.u64(self.omissions.len() as u64);
        for span in &self.omissions {
            e.u64(span.offset);
            e.u64(span.len);
            e.text(&span.reason);
        }
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_PROOF_BYTES { return Err(corrupt("proof byte ceiling")); }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, FileIngestError> {
        if bytes.len() > MAX_PROOF_BYTES { return Err(corrupt("proof byte ceiling")); }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != DOMAIN || d.text()? != "fss.rtsp_recording_import_request.v1" {
            return Err(corrupt("unknown proof or request"));
        }
        let codec = match d.text()? {
            "avc" => RtspImportCodec::Avc,
            "hevc" => RtspImportCodec::Hevc,
            _ => return Err(corrupt("unknown codec")),
        };
        let slot = SlotName::parse(d.text()?).map_err(|_| corrupt("slot"))?;
        let root = digest(&mut d)?;
        let source = RecordingScope {
            sensor: SensorId::parse(d.text()?)?,
            stream: StreamId::parse(d.text()?)?,
            generation: d.u64()?,
            anchor: digest(&mut d)?,
            receive_clock: digest(&mut d)?,
        };
        let receive_time = TimestampNs(d.i128()?);
        let capture_origin = if d.bool()? {
            Some(RtspCaptureOrigin {
                start_ns: TimestampNs(d.i128()?),
                uncertainty_ns: d.u64()?,
            })
        } else { None };
        let request = RtspImportRequest {
            codec, slot, root, source, receive_time, capture_origin,
            max_frames: usize::try_from(d.u64()?).map_err(|_| corrupt("sample ceiling"))?,
            max_original_bytes: d.u64()?,
            max_media_bytes: d.u64()?,
        };
        request.validate().map_err(|_| corrupt("request"))?;
        let manifest = d.bytes()?;
        if manifest.len() > 4096 { return Err(corrupt("native manifest size")); }
        let manifest = manifest.to_vec();
        let mut read_object = || -> Result<ObjectRef, FileIngestError> {
            Ok(ObjectRef { digest: digest(&mut d)?, bytes: d.u64()? })
        };
        let objects = [read_object()?, read_object()?, read_object()?, read_object()?];
        let media_digest = digest(&mut d)?;
        let media_bytes = d.u64()?;
        let n = count(&mut d, MAX_FRAMES, 81)?;
        let mut frames = Vec::with_capacity(n);
        for _ in 0..n {
            frames.push(FrameOrigin {
                offset: d.u64()?,
                bytes: d.u64()?,
                digest: digest(&mut d)?,
                capture: CaptureInterval::new(TimestampNs(d.i128()?), TimestampNs(d.i128()?))?,
            });
        }
        let n = count(&mut d, MAX_OMISSIONS, 24)?;
        let mut omissions = Vec::with_capacity(n);
        for _ in 0..n {
            let offset = d.u64()?;
            let len = d.u64()?;
            let reason = d.text()?;
            if reason.len() > 256 { return Err(corrupt("omission reason bound")); }
            omissions.push(FileOmissionSpan { offset, len, reason: reason.to_owned() });
        }
        d.ensure_finished()?;
        let value = Self { request, manifest, objects, media_digest, media_bytes, frames, omissions };
        if value.encode()? != bytes { return Err(corrupt("noncanonical proof")); }
        Ok(value)
    }
    fn validate(&self) -> Result<(), FileIngestError> {
        self.request.validate().map_err(|_| corrupt("request"))?;
        let root = ObjectManifest::from_canonical_bytes(&self.manifest)?;
        let kind = match self.request.codec { RtspImportCodec::Avc => RECORDING_KIND, RtspImportCodec::Hevc => HEVC_RECORDING_KIND };
        let expected = ObjectManifest::new(
            kind,
            self.objects[..3].iter().map(|o| o.digest),
            Some(self.objects[3].digest),
        )?;
        let original_bytes = self.objects.iter().try_fold(self.manifest.len() as u64, |n, o| {
            n.checked_add(o.bytes).ok_or_else(|| corrupt("original byte overflow"))
        })?;
        if root != expected
            || root.root() != self.request.root
            || self.manifest.len() > 4096
            || original_bytes > self.request.max_original_bytes
            || self.objects.iter().any(|o| o.bytes == 0 || o.bytes > MAX_ORIGINAL_BYTES)
            || self.media_bytes == 0
            || self.media_bytes > self.request.max_media_bytes
            || self.objects[1].bytes.checked_add(self.objects[2].bytes) != Some(self.media_bytes)
            || self.frames.is_empty()
            || self.frames.len() > self.request.max_frames
            || self.omissions.len() > MAX_OMISSIONS
        { return Err(corrupt("original closure or bounds")); }
        let mut previous = 0u64;
        let mut spans = Vec::with_capacity(self.frames.len() + self.omissions.len());
        for frame in &self.frames {
            let end = frame.offset.checked_add(frame.bytes).ok_or_else(|| corrupt("frame overflow"))?;
            if frame.offset < previous || end > self.media_bytes || frame.bytes == 0
                || frame.capture.earliest > frame.capture.latest
                || frame.capture.latest > self.request.receive_time
                || (self.request.capture_origin.is_none()
                    && frame.capture != CaptureInterval::new(TimestampNs(0), self.request.receive_time)?)
            { return Err(corrupt("frame order, bytes or time")); }
            previous = end;
            spans.push((frame.offset, end));
        }
        for omission in &self.omissions {
            let end = omission.offset.checked_add(omission.len).ok_or_else(|| corrupt("omission overflow"))?;
            if !omission.is_container_structure() || omission.len == 0 || end > self.media_bytes || omission.reason.len() > 256 {
                return Err(corrupt("container accounting"));
            }
            spans.push((omission.offset, end));
        }
        spans.sort_unstable();
        let mut cursor = 0u64;
        for (start, end) in spans {
            if start != cursor { return Err(corrupt("container bytes not tiled")); }
            cursor = end;
        }
        if cursor != self.media_bytes { return Err(corrupt("unaccounted media")); }
        Ok(())
    }
    fn verify_window(&self, window: &Window, cx: &ReplayCx) -> Result<(), FileIngestError> {
        let root = ObjectManifest::from_canonical_bytes(&window.root)?;
        let summary = match self.request.codec {
            RtspImportCodec::Avc => verify_recording(&root, window.objects(), &self.request.source),
            RtspImportCodec::Hevc => verify_hevc_recording(&root, window.objects(), &self.request.source).map(|v| v.recording),
        }.map_err(|_| corrupt("native packet/source reconstruction"))?;
        if summary.samples != self.frames.len() { return Err(corrupt("native sample count")); }
        checkpoint(cx)?;
        let media = window.media()?;
        if ContentDigest::sha256(&media) != self.media_digest || media.len() as u64 != self.media_bytes {
            return Err(corrupt("reconstructed MP4"));
        }
        let scan = self.request.scan(&media, cx)?;
        let rebuilt = Self::new(self.request.clone(), window, &media, &scan)?;
        if rebuilt.encode()? != self.encode()? { return Err(corrupt("native container or timing map")); }
        checkpoint(cx)
    }
}
fn digest(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest, FileIngestError> {
    let value = d.digest()?;
    if value.algorithm() != DigestAlgorithm::Sha256 { return Err(corrupt("digest algorithm")); }
    Ok(value)
}
fn count(d: &mut CanonicalDecoder<'_>, max: usize, minimum: usize) -> Result<usize, FileIngestError> {
    let n = usize::try_from(d.u64()?).map_err(|_| corrupt("collection overflow"))?;
    if n > max || n > d.remaining() / minimum { return Err(corrupt("collection bound")); }
    Ok(n)
}
fn proof(
    deployment: &ReferenceDeployment,
    manifest: &FileImportManifest,
    cx: &ReplayCx,
) -> Result<Option<(ContentDigest, Proof)>, FileIngestError> {
    if manifest.adapter_id != ADAPTER { return Ok(None); }
    checkpoint(cx)?;
    let hex = manifest.adapter_generation.strip_prefix(GENERATION)
        .filter(|h| h.len() == 64).ok_or_else(|| corrupt("adapter generation"))?;
    let digest = ContentDigest::parse(&format!("sha256:{hex}"))?;
    if deployment.publisher().tombstones().any(|d| *d == digest) { return Err(corrupt("deleted proof")); }
    let bytes = deployment.publisher().spool().read_bounded(digest, MAX_PROOF_BYTES)?;
    if bytes.len() > MAX_PROOF_BYTES || ContentDigest::sha256(&bytes) != digest { return Err(corrupt("proof digest")); }
    Ok(Some((digest, Proof::decode(&bytes)?)))
}
fn load_window(
    deployment: &ReferenceDeployment,
    proof: &Proof,
    cx: &ReplayCx,
    reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
) -> Result<Window, FileIngestError> {
    let read = |digest: ContentDigest, length: u64, reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>| {
        checkpoint(cx)?;
        reserve(length)?;
        if deployment.publisher().tombstones().any(|d| *d == digest) { return Err(corrupt("deleted original")); }
        let maximum = usize::try_from(length).map_err(|_| corrupt("object length"))?;
        let bytes = deployment.publisher().spool().read_bounded(digest, maximum)?;
        if bytes.len() as u64 != length || ContentDigest::sha256(&bytes) != digest { return Err(corrupt("original payload")); }
        Ok::<_, FileIngestError>(bytes)
    };
    let root = read(proof.request.root, proof.manifest.len() as u64, reserve)?;
    if root != proof.manifest { return Err(corrupt("original root")); }
    let mut children = Vec::with_capacity(4);
    for object in &proof.objects { children.push(read(object.digest, object.bytes, reserve)?); }
    let mut children = children.into_iter();
    let window = Window {
        root,
        source: children.next().ok_or_else(|| corrupt("source"))?,
        initialization: children.next().ok_or_else(|| corrupt("initialization"))?,
        fragment: children.next().ok_or_else(|| corrupt("fragment"))?,
        index: children.next().ok_or_else(|| corrupt("index"))?,
        samples: proof.frames.len(),
    };
    proof.verify_window(&window, cx)?;
    Ok(window)
}

/// One bounded source-verified window held in the actual read cursor. It never establishes future
/// on-disk availability; publication guards independently re-read the complete original closure.
pub(crate) struct OriginCache {
    digest: ContentDigest,
    window: Window,
}
impl fmt::Debug for OriginCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginCache").field("proof", &self.digest).finish_non_exhaustive()
    }
}
pub(crate) fn verify_range_budgeted(
    deployment: &ReferenceDeployment,
    manifest: &FileImportManifest,
    offset: u64,
    bytes: &[u8],
    cx: &ReplayCx,
    cache: &mut Option<OriginCache>,
    reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
) -> Result<(), FileIngestError> {
    let Some((digest, proof)) = proof(deployment, manifest, cx)? else { return Ok(()); };
    if cache.as_ref().is_none_or(|cached| cached.digest != digest) {
        let window = load_window(deployment, &proof, cx, reserve)?;
        *cache = Some(OriginCache { digest, window });
    }
    if !cache.as_ref().ok_or_else(|| corrupt("source cache"))?.window.matches_range(offset, bytes) {
        return Err(corrupt("MP4 bytes differ from native packet reconstruction"));
    }
    checkpoint(cx)
}
pub(crate) fn verify_originals(
    deployment: &ReferenceDeployment,
    manifest: &FileImportManifest,
    cx: &ReplayCx,
) -> Result<(), FileIngestError> {
    let Some((_, proof)) = proof(deployment, manifest, cx)? else { return Ok(()); };
    let _ = load_window(deployment, &proof, cx, &mut |_| Ok(()))?;
    checkpoint(cx)
}
pub(crate) fn verify_membership(
    deployment: &ReferenceDeployment,
    manifest: &FileImportManifest,
    held: &BTreeSet<ContentDigest>,
    capsules: &BTreeMap<&str, ContentDigest>,
    import_hex: &str,
    cx: &ReplayCx,
) -> Result<(), FileIngestError> {
    let Some((digest, proof)) = proof(deployment, manifest, cx)? else { return Ok(()); };
    if !held.contains(&digest) || !held.contains(&proof.request.root)
        || proof.objects.iter().any(|o| !held.contains(&o.digest))
        || hex(proof.request.identity().map_err(|_| corrupt("identity"))?) != import_hex
        || manifest.limits_digest != proof.request.digest().map_err(|_| corrupt("request digest"))?
        || manifest.input_sha256 != proof.media_digest
        || manifest.input_bytes != proof.media_bytes
        || manifest.chunk_bytes != CHUNK_BYTES as u64
        || manifest.format != proof.request.codec.format().as_str()
        || manifest.capture_time_label != proof.request.time_label()
        || manifest.detector_evidence != "native_rtsp_recording:reconstructed_mp4:original_rtp_retained"
        || manifest.segment_spans.len() != proof.frames.len()
        || manifest.omission_spans != proof.omissions
    { return Err(corrupt("retained import origin binding")); }
    for (index, (span, frame)) in manifest.segment_spans.iter().zip(&proof.frames).enumerate() {
        checkpoint(cx)?;
        let expected_id = CapsuleId::parse(format!("capsule:{import_hex}:{index:06}"))?;
        if span != &(SegmentSpan {
            segment_index: index,
            offset: frame.offset,
            len: frame.bytes,
            segment_sha256: frame.digest,
            capsule_id: expected_id.clone(),
            gap_before: false,
        }) { return Err(corrupt("sample map")); }
        let capsule = SensorCapsule {
            capsule_id: expected_id,
            sensor_id: proof.request.source.sensor.clone(),
            stream_id: proof.request.source.stream.clone(),
            sequence: index as u64,
            capture: frame.capture,
            receive_time: proof.request.receive_time,
            clock_basis: ClockBasis::Estimated,
            source_digest: frame.digest,
            source_bytes: frame.bytes,
            gap_before: false,
            frame_count: 1,
        };
        let object = format!("object:capsule:{}", span.capsule_id.as_str());
        if capsules.get(object.as_str()).copied() != Some(ContentDigest::sha256(&capsule.canonical_bytes())) {
            return Err(corrupt("sensor, time or capsule binding"));
        }
    }
    checkpoint(cx)
}
