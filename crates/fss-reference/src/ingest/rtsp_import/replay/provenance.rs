#![forbid(unsafe_code)]
//! Cold verification of the complete recorder companion, original windows and imported sample map.

use super::*;
use crate::ingest::file_adapter::{FileOmissionSpan, SegmentSpan};
use crate::rtsp::recording::{
    RECORDING_KIND, RecordingSummary,
    hevc::{HEVC_RECORDING_KIND, verify_hevc_recording},
    verify_recording,
};
use fss_core::{
    CanonicalDecoder, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, SensorCapsule,
    SensorId, StreamId,
};
use fss_object::ObjectManifest;

const MAX_OMISSIONS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectRef {
    digest: ContentDigest,
    bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct WindowReference {
    root: Vec<u8>,
    objects: [ObjectRef; 4],
}
impl WindowReference {
    pub(super) fn new(window: &Window) -> Self {
        let payloads = window.payloads();
        let object = |index: usize| ObjectRef {
            digest: payloads[index].0,
            bytes: payloads[index].1.len() as u64,
        };
        Self {
            root: window.root.clone(),
            objects: [object(1), object(2), object(3), object(4)],
        }
    }
    fn validate(
        &self,
        descriptor: &ReplayWindowProof,
        codec: RtspImportCodec,
    ) -> Result<(), FileIngestError> {
        let expected = ObjectManifest::new(
            match codec {
                RtspImportCodec::Avc => RECORDING_KIND,
                RtspImportCodec::Hevc => HEVC_RECORDING_KIND,
            },
            self.objects[..3].iter().map(|o| o.digest),
            Some(self.objects[3].digest),
        )?;
        let bytes = self
            .objects
            .iter()
            .try_fold(self.root.len() as u64, |n, o| n.checked_add(o.bytes))
            .ok_or_else(|| corrupt("replay window byte overflow"))?;
        if self.root.len() > 4096
            || ObjectManifest::from_canonical_bytes(&self.root)? != expected
            || expected.root() != descriptor.root()
            || bytes != descriptor.byte_len() as u64
            || self
                .objects
                .iter()
                .map(|o| o.digest)
                .ne(descriptor.original_leaf_digests())
            || self
                .objects
                .iter()
                .any(|o| o.bytes == 0 || o.bytes > super::super::MAX_ORIGINAL_BYTES)
        {
            return Err(corrupt("replay original closure or bounds"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct FrameOrigin {
    offset: u64,
    bytes: u64,
    digest: ContentDigest,
    capture: CaptureInterval,
}

pub(super) struct Proof {
    request: RtspReplayImportRequest,
    receipt_root: Vec<u8>,
    receipt_metadata: Vec<u8>,
    windows: Vec<WindowReference>,
    media_digest: ContentDigest,
    media_bytes: u64,
    frames: Vec<FrameOrigin>,
    omissions: Vec<FileOmissionSpan>,
}
impl Proof {
    pub(super) fn new(
        request: RtspReplayImportRequest,
        receipt: &ReplayReceipt,
        windows: Vec<WindowReference>,
        media: &[u8],
        scan: &ScannedSegments,
    ) -> Result<Self, FileIngestError> {
        verify_scan(&request, receipt, scan)?;
        let value = Self {
            request,
            receipt_root: receipt.manifest().canonical_bytes(),
            receipt_metadata: receipt.metadata_bytes().to_vec(),
            windows,
            media_digest: ContentDigest::sha256(media),
            media_bytes: media.len() as u64,
            frames: scan
                .segment_spans
                .iter()
                .zip(&scan.capsules)
                .map(|(s, c)| FrameOrigin {
                    offset: s.offset,
                    bytes: s.len,
                    digest: s.segment_sha256,
                    capture: c.capture,
                })
                .collect(),
            omissions: scan.omission_spans.clone(),
        };
        value.validate()?;
        Ok(value)
    }
    pub(super) fn receipt(&self) -> Result<ReplayReceipt, FileIngestError> {
        if self
            .receipt_root
            .len()
            .checked_add(self.receipt_metadata.len())
            .is_none_or(|n| n > MAX_REPLAY_RECEIPT_BYTES)
        {
            return Err(corrupt("replay companion metadata envelope"));
        }
        let receipt = decode_retained_receipt(
            &self.receipt_metadata,
            self.request.replay_codec(),
            &self.request.scope,
            self.request.request_identity,
            self.request.receipt_root,
        )
        .map_err(|_| corrupt("replay companion pins or metadata"))?;
        if receipt.manifest().canonical_bytes() != self.receipt_root {
            return Err(corrupt("replay companion manifest differs"));
        }
        admit(&self.request, &receipt)?;
        Ok(receipt)
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, FileIngestError> {
        self.validate()?;
        let mut out = CanonicalEncoder::new();
        out.text(PROOF_DOMAIN);
        self.request.encode(&mut out);
        out.bytes(&self.receipt_root);
        out.bytes(&self.receipt_metadata);
        out.u64(self.windows.len() as u64);
        for window in &self.windows {
            out.bytes(&window.root);
            for object in &window.objects {
                out.digest(object.digest);
                out.u64(object.bytes);
            }
        }
        out.digest(self.media_digest);
        out.u64(self.media_bytes);
        out.u64(self.frames.len() as u64);
        for frame in &self.frames {
            out.u64(frame.offset);
            out.u64(frame.bytes);
            out.digest(frame.digest);
            out.i128(frame.capture.earliest.0);
            out.i128(frame.capture.latest.0);
        }
        out.u64(self.omissions.len() as u64);
        for omission in &self.omissions {
            out.u64(omission.offset);
            out.u64(omission.len);
            out.text(&omission.reason);
        }
        let bytes = out.finish_checked()?;
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(corrupt("replay proof byte ceiling"));
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, FileIngestError> {
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(corrupt("replay proof byte ceiling"));
        }
        let mut input = CanonicalDecoder::new(bytes);
        if input.text()? != PROOF_DOMAIN || input.text()? != REQUEST_DOMAIN {
            return Err(corrupt("replay proof or request domain"));
        }
        let codec = match input.text()? {
            "avc" => RtspImportCodec::Avc,
            "hevc" => RtspImportCodec::Hevc,
            _ => return Err(corrupt("replay import codec")),
        };
        let receipt_root = digest(&mut input)?;
        let request_identity = digest(&mut input)?;
        let recording = RecordingScope {
            sensor: SensorId::parse(input.text()?)?,
            stream: StreamId::parse(input.text()?)?,
            generation: input.u64()?,
            anchor: digest(&mut input)?,
            receive_clock: digest(&mut input)?,
        };
        let scope = CatalogScope {
            recording,
            decode_clock: digest(&mut input)?,
            time_scale: input.u32()?,
        };
        let receive_time = TimestampNs(input.i128()?);
        let capture_origin = if input.bool()? {
            Some(RtspCaptureOrigin {
                start_ns: TimestampNs(input.i128()?),
                uncertainty_ns: input.u64()?,
            })
        } else {
            None
        };
        let preserve_decode_gaps = input.bool()?;
        let max_windows =
            usize::try_from(input.u64()?).map_err(|_| corrupt("replay window limit"))?;
        let max_frames =
            usize::try_from(input.u64()?).map_err(|_| corrupt("replay frame limit"))?;
        let request = RtspReplayImportRequest {
            codec,
            receipt_root,
            request_identity,
            scope,
            receive_time,
            capture_origin,
            preserve_decode_gaps,
            max_windows,
            max_frames,
            max_original_bytes: input.u64()?,
            max_media_bytes: input.u64()?,
        };
        request
            .validate()
            .map_err(|_| corrupt("replay import request"))?;
        let receipt_root = blob(&mut input, MAX_REPLAY_RECEIPT_BYTES)?;
        let receipt_metadata = blob(&mut input, MAX_REPLAY_RECEIPT_BYTES)?;
        let n = count(&mut input, MAX_WINDOWS, 172)?;
        let mut windows = Vec::with_capacity(n);
        for _ in 0..n {
            let root = blob(&mut input, 4096)?;
            let mut object = || -> Result<ObjectRef, FileIngestError> {
                Ok(ObjectRef {
                    digest: digest(&mut input)?,
                    bytes: input.u64()?,
                })
            };
            windows.push(WindowReference {
                root,
                objects: [object()?, object()?, object()?, object()?],
            });
        }
        let media_digest = digest(&mut input)?;
        let media_bytes = input.u64()?;
        let n = count(&mut input, MAX_FRAMES, 81)?;
        let mut frames = Vec::with_capacity(n);
        for _ in 0..n {
            frames.push(FrameOrigin {
                offset: input.u64()?,
                bytes: input.u64()?,
                digest: digest(&mut input)?,
                capture: CaptureInterval::new(
                    TimestampNs(input.i128()?),
                    TimestampNs(input.i128()?),
                )?,
            });
        }
        let n = count(&mut input, MAX_OMISSIONS, 24)?;
        let mut omissions = Vec::with_capacity(n);
        for _ in 0..n {
            let offset = input.u64()?;
            let len = input.u64()?;
            let reason = input.text()?;
            if reason.len() > 256 {
                return Err(corrupt("replay omission text ceiling"));
            }
            omissions.push(FileOmissionSpan {
                offset,
                len,
                reason: reason.to_owned(),
            });
        }
        input.ensure_finished()?;
        let value = Self {
            request,
            receipt_root,
            receipt_metadata,
            windows,
            media_digest,
            media_bytes,
            frames,
            omissions,
        };
        if value.encode()? != bytes {
            return Err(corrupt("noncanonical replay proof"));
        }
        Ok(value)
    }
    fn validate(&self) -> Result<(), FileIngestError> {
        self.request
            .validate()
            .map_err(|_| corrupt("replay import request"))?;
        let receipt = self.receipt()?;
        if self.windows.len() != receipt.windows().len()
            || self.frames.len() != receipt.windows().iter().map(|w| w.samples()).sum::<usize>()
            || self.frames.is_empty()
            || self.omissions.len() > MAX_OMISSIONS
        {
            return Err(corrupt("complete replay window/sample count"));
        }
        let first = self
            .windows
            .first()
            .ok_or_else(|| corrupt("empty replay proof"))?;
        let initialization = &first.objects[1];
        let mut media_bytes = initialization.bytes;
        for (window, descriptor) in self.windows.iter().zip(receipt.windows()) {
            window.validate(descriptor, self.request.codec)?;
            if &window.objects[1] != initialization {
                return Err(corrupt("replay initialization changes"));
            }
            media_bytes = media_bytes
                .checked_add(window.objects[2].bytes)
                .ok_or_else(|| corrupt("replay media overflow"))?;
        }
        if media_bytes == 0
            || media_bytes != self.media_bytes
            || media_bytes > self.request.max_media_bytes
        {
            return Err(corrupt("replay complete media bound"));
        }
        let mut previous = 0u64;
        let mut spans = Vec::with_capacity(self.frames.len() + self.omissions.len());
        for frame in &self.frames {
            let end = frame
                .offset
                .checked_add(frame.bytes)
                .ok_or_else(|| corrupt("replay frame overflow"))?;
            if frame.offset < previous
                || end > self.media_bytes
                || frame.bytes == 0
                || frame.capture.earliest > frame.capture.latest
                || frame.capture.latest > self.request.receive_time
                || (self.request.capture_origin.is_none()
                    && frame.capture
                        != CaptureInterval::new(TimestampNs(0), self.request.receive_time)?)
            {
                return Err(corrupt("replay frame order, bytes or time"));
            }
            previous = end;
            spans.push((frame.offset, end));
        }
        for omission in &self.omissions {
            let end = omission
                .offset
                .checked_add(omission.len)
                .ok_or_else(|| corrupt("replay omission overflow"))?;
            if !omission.is_container_structure()
                || omission.len == 0
                || end > self.media_bytes
                || omission.reason.len() > 256
            {
                return Err(corrupt("replay container accounting"));
            }
            spans.push((omission.offset, end));
        }
        spans.sort_unstable();
        let mut cursor = 0u64;
        for (start, end) in spans {
            if start != cursor {
                return Err(corrupt("replay container bytes not tiled"));
            }
            cursor = end;
        }
        if cursor != self.media_bytes {
            return Err(corrupt("replay media not completely accounted"));
        }
        Ok(())
    }
    fn held(&self, proof_digest: ContentDigest) -> BTreeSet<ContentDigest> {
        let mut held = BTreeSet::from([
            proof_digest,
            self.request.receipt_root,
            ContentDigest::sha256(&self.receipt_metadata),
        ]);
        for window in &self.windows {
            held.insert(ContentDigest::sha256(&window.root));
            held.extend(window.objects.iter().map(|o| o.digest));
        }
        held
    }
    pub(super) fn verify_companion(
        &self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
        reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
    ) -> Result<(), FileIngestError> {
        for expected in [&self.receipt_root, &self.receipt_metadata] {
            if read_original(
                deployment,
                ContentDigest::sha256(expected),
                expected.len() as u64,
                cx,
                reserve,
            )? != *expected
            {
                return Err(corrupt("retained replay companion differs"));
            }
        }
        checkpoint(cx)
    }
    fn load_media(
        &self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
        reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
    ) -> Result<Vec<u8>, FileIngestError> {
        let receipt = self.receipt()?;
        self.verify_companion(deployment, cx, reserve)?;
        let mut media = Vec::new();
        for (ordinal, (reference, descriptor)) in
            self.windows.iter().zip(receipt.windows()).enumerate()
        {
            let root = read_original(
                deployment,
                descriptor.root(),
                reference.root.len() as u64,
                cx,
                reserve,
            )?;
            if root != reference.root {
                return Err(corrupt("retained replay window root differs"));
            }
            let mut children = Vec::with_capacity(4);
            for object in &reference.objects {
                children.push(read_original(
                    deployment,
                    object.digest,
                    object.bytes,
                    cx,
                    reserve,
                )?);
            }
            let mut children = children.into_iter();
            let window = Window {
                root,
                source: children.next().ok_or_else(|| corrupt("replay source"))?,
                initialization: children
                    .next()
                    .ok_or_else(|| corrupt("replay initialization"))?,
                fragment: children.next().ok_or_else(|| corrupt("replay fragment"))?,
                index: children.next().ok_or_else(|| corrupt("replay index"))?,
                samples: descriptor.samples(),
            };
            let root = ObjectManifest::from_canonical_bytes(&window.root)?;
            let summary = match self.request.codec {
                RtspImportCodec::Avc => {
                    verify_recording(&root, window.objects(), &self.request.scope.recording)
                }
                RtspImportCodec::Hevc => {
                    verify_hevc_recording(&root, window.objects(), &self.request.scope.recording)
                        .map(|v| v.recording)
                }
            }
            .map_err(|_| corrupt("native replay source reconstruction"))?;
            check_summary(
                descriptor,
                &self.request.scope,
                &summary,
                window.payloads().iter().map(|(_, b)| b.len()).sum(),
            )?;
            checkpoint(cx)?;
            if ordinal == 0 {
                super::super::catalog::append_media(
                    &mut media,
                    &window.initialization,
                    self.request.max_media_bytes,
                )?;
            }
            super::super::catalog::append_fragment(
                &mut media,
                &window.fragment,
                ordinal,
                self.request.max_media_bytes,
            )?;
        }
        if media.len() as u64 != self.media_bytes
            || ContentDigest::sha256(&media) != self.media_digest
        {
            return Err(corrupt("reconstructed replay movie differs"));
        }
        let scan = self.request.scan(&media, cx)?;
        let rebuilt = Self::new(
            self.request.clone(),
            &receipt,
            self.windows.clone(),
            &media,
            &scan,
        )?;
        if rebuilt.encode()? != self.encode()? {
            return Err(corrupt("native replay sample or timing map"));
        }
        live(
            deployment,
            &self.held(ContentDigest::sha256(&self.encode()?)),
            cx,
        )?;
        Ok(media)
    }
}
fn check_summary(
    descriptor: &ReplayWindowProof,
    scope: &CatalogScope,
    summary: &RecordingSummary,
    bytes: usize,
) -> Result<(), FileIngestError> {
    if summary.root != descriptor.root()
        || summary.scope != scope.recording
        || summary.time_scale != scope.time_scale
        || summary.decode_interval != descriptor.decode_interval()
        || summary.samples != descriptor.samples()
        || summary.packets != descriptor.packets()
        || summary.nals != descriptor.nals()
        || bytes != descriptor.byte_len()
    {
        return Err(corrupt("replayed original differs from historical receipt"));
    }
    Ok(())
}
fn digest(input: &mut CanonicalDecoder<'_>) -> Result<ContentDigest, FileIngestError> {
    let value = input.digest()?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err(corrupt("replay digest"));
    }
    Ok(value)
}
fn count(
    input: &mut CanonicalDecoder<'_>,
    maximum: usize,
    minimum: usize,
) -> Result<usize, FileIngestError> {
    let n = usize::try_from(input.u64()?).map_err(|_| corrupt("replay collection overflow"))?;
    if n > maximum || n > input.remaining() / minimum {
        return Err(corrupt("replay collection bound"));
    }
    Ok(n)
}
fn blob(input: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<Vec<u8>, FileIngestError> {
    let bytes = input.bytes()?;
    if bytes.len() > maximum {
        return Err(corrupt("replay metadata bound"));
    }
    Ok(bytes.to_vec())
}
fn selected_digest(
    manifest: &FileImportManifest,
) -> Result<Option<ContentDigest>, FileIngestError> {
    if manifest.adapter_id != ADAPTER {
        return Ok(None);
    }
    let value = manifest
        .adapter_generation
        .strip_prefix(GENERATION)
        .filter(|v| v.len() == 64)
        .ok_or_else(|| corrupt("replay adapter generation"))?;
    Ok(Some(ContentDigest::parse(&format!("sha256:{value}"))?))
}
fn live(
    deployment: &ReferenceDeployment,
    held: &BTreeSet<ContentDigest>,
    cx: &ReplayCx,
) -> Result<(), FileIngestError> {
    checkpoint(cx)?;
    if deployment
        .publisher()
        .tombstones()
        .any(|d| held.contains(d))
    {
        return Err(corrupt("deleted replay origin"));
    }
    Ok(())
}
pub(super) fn proof(
    deployment: &ReferenceDeployment,
    digest: ContentDigest,
    cx: &ReplayCx,
    reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
) -> Result<Proof, FileIngestError> {
    live(deployment, &BTreeSet::from([digest]), cx)?;
    reserve(MAX_PROOF_BYTES as u64)?;
    let bytes = deployment
        .publisher()
        .spool()
        .read_bounded(digest, MAX_PROOF_BYTES)?;
    if bytes.len() > MAX_PROOF_BYTES || ContentDigest::sha256(&bytes) != digest {
        return Err(corrupt("replay proof digest"));
    }
    let proof = Proof::decode(&bytes)?;
    live(deployment, &proof.held(digest), cx)?;
    Ok(proof)
}
fn read_original(
    deployment: &ReferenceDeployment,
    digest: ContentDigest,
    length: u64,
    cx: &ReplayCx,
    reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
) -> Result<Vec<u8>, FileIngestError> {
    checkpoint(cx)?;
    reserve(length)?;
    live(deployment, &BTreeSet::from([digest]), cx)?;
    let maximum = usize::try_from(length).map_err(|_| corrupt("replay original length"))?;
    let bytes = deployment
        .publisher()
        .spool()
        .read_bounded(digest, maximum)?;
    if bytes.len() as u64 != length || ContentDigest::sha256(&bytes) != digest {
        return Err(corrupt("replay original payload"));
    }
    Ok(bytes)
}

/// Bounded source-verified movie retained by one read cursor. Every cached read still checks
/// current tombstones; publication independently replays the full original closure.
pub(crate) struct OriginCache {
    digest: ContentDigest,
    media: Vec<u8>,
    held: BTreeSet<ContentDigest>,
}
impl fmt::Debug for OriginCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayOriginCache")
            .field("proof", &self.digest)
            .finish_non_exhaustive()
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
    let Some(digest) = selected_digest(manifest)? else {
        return Ok(());
    };
    if cache.as_ref().is_none_or(|cached| cached.digest != digest) {
        let proof = proof(deployment, digest, cx, reserve)?;
        let media = proof.load_media(deployment, cx, reserve)?;
        *cache = Some(OriginCache {
            digest,
            media,
            held: proof.held(digest),
        });
    }
    let cached = cache
        .as_ref()
        .ok_or_else(|| corrupt("replay source cache"))?;
    live(deployment, &cached.held, cx)?;
    let start = usize::try_from(offset).map_err(|_| corrupt("replay range offset"))?;
    let end = start
        .checked_add(bytes.len())
        .ok_or_else(|| corrupt("replay range overflow"))?;
    if cached.media.get(start..end) != Some(bytes) {
        return Err(corrupt(
            "movie bytes differ from native replay reconstruction",
        ));
    }
    checkpoint(cx)
}
pub(crate) fn verify_originals(
    deployment: &ReferenceDeployment,
    manifest: &FileImportManifest,
    cx: &ReplayCx,
) -> Result<(), FileIngestError> {
    let Some(digest) = selected_digest(manifest)? else {
        return Ok(());
    };
    let proof = proof(deployment, digest, cx, &mut |_| Ok(()))?;
    let _ = proof.load_media(deployment, cx, &mut |_| Ok(()))?;
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
    let Some(digest) = selected_digest(manifest)? else {
        return Ok(());
    };
    let proof = proof(deployment, digest, cx, &mut |_| Ok(()))?;
    if !proof.held(digest).is_subset(held)
        || manifest.adapter_generation != format!("{}{}", GENERATION, hex(digest))
        || hex(proof
            .request
            .identity()
            .map_err(|_| corrupt("replay identity"))?)
            != import_hex
        || manifest.limits_digest
            != proof
                .request
                .digest()
                .map_err(|_| corrupt("replay request digest"))?
        || manifest.input_sha256 != proof.media_digest
        || manifest.input_bytes != proof.media_bytes
        || manifest.chunk_bytes != CHUNK_BYTES as u64
        || manifest.format != proof.request.codec.format().as_str()
        || manifest.capture_time_label != proof.request.time_label()
        || manifest.detector_evidence != EVIDENCE
        || manifest.segment_spans.len() != proof.frames.len()
        || manifest.omission_spans != proof.omissions
    {
        return Err(corrupt("retained replay origin binding"));
    }
    let gaps = gap_indices(&proof.receipt()?)?;
    for (index, (span, frame)) in manifest.segment_spans.iter().zip(&proof.frames).enumerate() {
        checkpoint(cx)?;
        let expected_id = CapsuleId::parse(format!("capsule:{import_hex}:{index:06}"))?;
        let gap = gaps.contains(&index);
        if span
            != &(SegmentSpan {
                segment_index: index,
                offset: frame.offset,
                len: frame.bytes,
                segment_sha256: frame.digest,
                capsule_id: expected_id.clone(),
                gap_before: gap,
            })
        {
            return Err(corrupt("replay sample map"));
        }
        let capsule = SensorCapsule {
            capsule_id: expected_id,
            sensor_id: proof.request.scope.recording.sensor.clone(),
            stream_id: proof.request.scope.recording.stream.clone(),
            sequence: index as u64,
            capture: frame.capture,
            receive_time: proof.request.receive_time,
            clock_basis: ClockBasis::Estimated,
            source_digest: frame.digest,
            source_bytes: frame.bytes,
            gap_before: gap,
            frame_count: 1,
        };
        let object = format!("object:capsule:{}", span.capsule_id.as_str());
        if capsules.get(object.as_str()).copied()
            != Some(ContentDigest::sha256(&capsule.canonical_bytes()))
        {
            return Err(corrupt("replay sensor, time or capsule binding"));
        }
    }
    checkpoint(cx)
}
