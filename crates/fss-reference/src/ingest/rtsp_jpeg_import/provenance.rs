#![forbid(unsafe_code)]
//! Original packet closure and current cold replay for ordinary retained JPEG consumers.

use super::replay::{FrameOrigin, Reconstruction};
use super::request::{read_digest, read_size};
use super::*;
use crate::ingest::file_adapter::FileImportManifest;
use fss_core::{
    CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval, ClockBasis, SensorCapsule,
};
use std::collections::BTreeSet;

pub(super) const DETECTOR_EVIDENCE: &str = "native_rtp_jpeg:reconstructed_jpeg_stream:original_datagrams_retained:pinned_prefix:capture_unknown:entropy_unchecked";

pub(super) struct OriginalReader<'a> {
    publisher: &'a LocalRootPublisher,
    reads: &'a ReadMeter,
    collected: Option<&'a mut BTreeMap<ContentDigest, Vec<u8>>>,
    max_original: u64,
    original_bytes: u64,
}
impl<'a> OriginalReader<'a> {
    pub(super) fn new(
        publisher: &'a LocalRootPublisher,
        reads: &'a ReadMeter,
        collected: Option<&'a mut BTreeMap<ContentDigest, Vec<u8>>>,
        max_original: u64,
    ) -> Self {
        Self {
            publisher,
            reads,
            collected,
            max_original,
            original_bytes: 0,
        }
    }
}
impl DatagramObjectReader for OriginalReader<'_> {
    fn read_object(
        &mut self,
        digest: ContentDigest,
        maximum: usize,
        cancel: &dyn PublishCancellation,
        work: &mut WorkBudget<'_>,
    ) -> Result<Vec<u8>, DatagramArchiveError> {
        if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
            return Err(DatagramArchiveError::Cancelled);
        }
        self.reads
            .reserve(maximum as u64)
            .map_err(|_| DatagramArchiveError::Limit)?;
        work.charge(self.publisher.limits().max_tombstones as u64)?;
        if self.publisher.tombstones().any(|d| *d == digest) {
            return Err(DatagramArchiveError::Tombstoned);
        }
        let bytes = self
            .publisher
            .spool()
            .read_bounded(digest, maximum)
            .map_err(DatagramArchiveError::Spool)?;
        if let Some(objects) = self.collected.as_mut() {
            if let Some(prior) = objects.get(&digest) {
                if *prior != bytes {
                    return Err(DatagramArchiveError::Source);
                }
            } else {
                self.original_bytes = self
                    .original_bytes
                    .checked_add(bytes.len() as u64)
                    .filter(|n| *n <= self.max_original)
                    .ok_or(DatagramArchiveError::Limit)?;
                work.charge(bytes.len() as u64)?;
                objects.insert(digest, bytes.clone());
            }
        }
        if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
            return Err(DatagramArchiveError::Cancelled);
        }
        Ok(bytes)
    }
}

pub(super) struct Proof {
    pub request: JpegImportRequest,
    pub interpretation: ContentDigest,
    pub originals: Vec<(ContentDigest, u64)>,
    pub frames: Vec<FrameOrigin>,
    pub diagnostics: Vec<u8>,
}
impl Proof {
    pub(super) fn new(
        request: JpegImportRequest,
        originals: &BTreeMap<ContentDigest, Vec<u8>>,
        result: &Reconstruction,
    ) -> Result<Self, JpegImportError> {
        let value = Self {
            request,
            interpretation: result.interpretation,
            originals: originals
                .iter()
                .map(|(d, b)| (*d, b.len() as u64))
                .collect(),
            frames: result.frames.clone(),
            diagnostics: result.diagnostics.clone(),
        };
        value.encode()?;
        Ok(value)
    }
    pub(super) fn original_bytes(&self) -> u64 {
        self.originals.iter().map(|(_, n)| n).sum()
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, FileIngestError> {
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.bytes(&self.request.encode().map_err(|_| corrupt("request"))?);
        e.digest(self.interpretation);
        if self.originals.is_empty()
            || self.originals.len() > MAX_SOURCE_DATAGRAMS * 3
            || self.original_bytes() > self.request.max_original_bytes
            || self.originals.windows(2).any(|w| w[0].0 >= w[1].0)
            || self.frames.is_empty()
            || self.frames.len() > self.request.max_frames
            || self.diagnostics.len() > MAX_PROOF_BYTES / 4
        {
            return Err(corrupt("proof bounds or canonical object order"));
        }
        e.u64(self.originals.len() as u64);
        for (digest, length) in &self.originals {
            e.digest(*digest);
            e.u64(*length);
        }
        e.u64(self.frames.len() as u64);
        let mut total = 0u64;
        for frame in &self.frames {
            total = total
                .checked_add(frame.bytes)
                .ok_or_else(|| corrupt("media length"))?;
            if frame.bytes == 0
                || frame.bytes > self.request.replay.jpeg.max_frame_bytes as u64
                || total > self.request.max_media_bytes
                || frame.lineage.len() > MAX_PROOF_BYTES / 2
                || ContentDigest::sha256(&frame.lineage) != frame.provenance
            {
                return Err(corrupt("frame proof"));
            }
            e.digest(frame.encoded);
            e.u64(frame.bytes);
            e.bool(frame.gap_before);
            e.digest(frame.provenance);
            e.bytes(&frame.lineage);
        }
        e.bytes(&self.diagnostics);
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(corrupt("proof byte bound"));
        }
        Ok(bytes)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, FileIngestError> {
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(corrupt("proof byte bound"));
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != DOMAIN {
            return Err(corrupt("proof domain"));
        }
        let request = JpegImportRequest::decode(d.bytes()?)?;
        let interpretation = read_digest(&mut d)?;
        let count = read_size(&mut d)?;
        if count > MAX_SOURCE_DATAGRAMS * 3 || count > d.remaining() / 41 {
            return Err(corrupt("original count"));
        }
        let mut originals = Vec::with_capacity(count);
        for _ in 0..count {
            let digest = read_digest(&mut d)?;
            let bytes = d.u64()?;
            if bytes > 65535 {
                return Err(corrupt("original object length"));
            }
            originals.push((digest, bytes));
        }
        let count = read_size(&mut d)?;
        if count > MAX_FRAMES || count > d.remaining() / 83 {
            return Err(corrupt("frame count"));
        }
        let mut frames = Vec::with_capacity(count);
        for _ in 0..count {
            let encoded = read_digest(&mut d)?;
            let bytes = d.u64()?;
            let gap_before = d.bool()?;
            let provenance = read_digest(&mut d)?;
            let lineage = d.bytes()?;
            if lineage.len() > MAX_PROOF_BYTES / 2 {
                return Err(corrupt("frame lineage"));
            }
            frames.push(FrameOrigin {
                encoded,
                bytes,
                gap_before,
                provenance,
                lineage: lineage.to_vec(),
            });
        }
        let diagnostics = d.bytes()?.to_vec();
        d.ensure_finished()?;
        let result = Self {
            request,
            interpretation,
            originals,
            frames,
            diagnostics,
        };
        if result.encode()? != bytes {
            return Err(corrupt("noncanonical proof"));
        }
        Ok(result)
    }
    pub(super) fn identity(&self) -> Result<ContentDigest, FileIngestError> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_jpeg_import_identity.v1");
        e.digest(ContentDigest::sha256(&self.encode()?));
        Ok(ContentDigest::sha256(&e.finish()))
    }
    fn matches(
        &self,
        result: &Reconstruction,
        manifest: &FileImportManifest,
    ) -> Result<(), FileIngestError> {
        if self.interpretation != result.interpretation
            || self.frames != result.frames
            || self.diagnostics != result.diagnostics
            || result.media.len() as u64 != manifest.input_bytes
            || ContentDigest::sha256(&result.media) != manifest.input_sha256
        {
            return Err(corrupt(
                "native replay disagrees with retained reconstruction",
            ));
        }
        Ok(())
    }
}

struct ReadAccess<'a>(&'a ReplayCx);
impl PublishCancellation for ReadAccess<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        checkpoint(self.0).is_err()
    }
}
struct RetainedReader<'a> {
    deployment: &'a ReferenceDeployment,
    reserve: &'a mut dyn FnMut(u64) -> Result<(), FileIngestError>,
    expected: &'a [(ContentDigest, u64)],
    seen: BTreeSet<ContentDigest>,
    error: Option<FileIngestError>,
}
impl DatagramObjectReader for RetainedReader<'_> {
    fn read_object(
        &mut self,
        digest: ContentDigest,
        maximum: usize,
        cancel: &dyn PublishCancellation,
        work: &mut WorkBudget<'_>,
    ) -> Result<Vec<u8>, DatagramArchiveError> {
        if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
            return Err(DatagramArchiveError::Cancelled);
        }
        let at = self
            .expected
            .binary_search_by_key(&digest, |(d, _)| *d)
            .map_err(|_| DatagramArchiveError::Source)?;
        let length = self.expected[at].1;
        if length > maximum as u64 {
            return Err(DatagramArchiveError::Limit);
        }
        if let Err(error) = (self.reserve)(length) {
            self.error = Some(error);
            return Err(DatagramArchiveError::Limit);
        }
        work.charge(self.deployment.publisher().limits().max_tombstones as u64)?;
        if self
            .deployment
            .publisher()
            .tombstones()
            .any(|d| *d == digest)
        {
            return Err(DatagramArchiveError::Tombstoned);
        }
        let bytes = self
            .deployment
            .publisher()
            .spool()
            .read_bounded(digest, length as usize)
            .map_err(DatagramArchiveError::Spool)?;
        if bytes.len() as u64 != length {
            return Err(DatagramArchiveError::Source);
        }
        self.seen.insert(digest);
        Ok(bytes)
    }
}

fn proof(
    deployment: &ReferenceDeployment,
    manifest: &FileImportManifest,
    cx: &ReplayCx,
    reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
) -> Result<Option<(ContentDigest, Proof)>, FileIngestError> {
    if manifest.adapter_id != ADAPTER {
        return Ok(None);
    }
    checkpoint(cx)?;
    let hex = manifest
        .adapter_generation
        .strip_prefix(GENERATION)
        .filter(|s| s.len() == 64)
        .ok_or_else(|| corrupt("adapter generation"))?;
    let digest = ContentDigest::parse(&format!("sha256:{hex}"))?;
    reserve(MAX_PROOF_BYTES as u64)?;
    if deployment.publisher().tombstones().any(|d| *d == digest) {
        return Err(corrupt("proof tombstone"));
    }
    let bytes = deployment
        .publisher()
        .spool()
        .read_bounded(digest, MAX_PROOF_BYTES)?;
    if ContentDigest::sha256(&bytes) != digest {
        return Err(corrupt("proof digest"));
    }
    let proof = Proof::decode(&bytes)?;
    checkpoint(cx)?;
    Ok(Some((digest, proof)))
}

fn verify(
    deployment: &ReferenceDeployment,
    proof: &Proof,
    manifest: &FileImportManifest,
    cx: &ReplayCx,
    reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
) -> Result<Vec<u8>, FileIngestError> {
    let access = ReadAccess(cx);
    // Recovery is a separate bounded pass. Replay has exactly the same intrinsic
    // admission ceiling as initial import, with additional finite verification overhead.
    let overhead = proof.request.pin.payload_bytes * 16
        + proof.request.pin.datagrams * 100_000
        + proof.request.pin.datagrams * 6 * deployment.publisher().limits().max_tombstones as u64;
    let mut work = WorkBudget::new(MAX_REPLAY_WORK.saturating_add(overhead));
    let mut reader = RetainedReader {
        deployment,
        reserve,
        expected: &proof.originals,
        seen: BTreeSet::new(),
        error: None,
    };
    let operation = (|| {
        let prefix = DetachedDatagramPrefix::recover(
            proof.request.source.clone(),
            proof.request.archive_limits,
            proof.request.pin,
            &mut reader,
            &access,
            &mut work,
        )
        .map_err(|_| corrupt("original packet closure"))?;
        if reader.seen.len() != proof.originals.len() {
            return Err(corrupt("extra original proof objects"));
        }
        let result = replay::reconstruct(&prefix, &proof.request, &mut reader, &access, &mut work)
            .map_err(|_| corrupt("native packet replay"))?;
        proof.matches(&result, manifest)?;
        checkpoint(cx)?;
        Ok(result.media)
    })();
    if let Some(error) = reader.error {
        return Err(error);
    }
    // A current cancellation observed inside the native source callback is not
    // corrupt packet evidence. Preserve that owner refusal even on the error path.
    checkpoint(cx)?;
    operation
}

pub(crate) fn verify_membership(
    deployment: &ReferenceDeployment,
    manifest: &FileImportManifest,
    held: &BTreeSet<ContentDigest>,
    capsules: &BTreeMap<&str, ContentDigest>,
    import_hex: &str,
    cx: &ReplayCx,
) -> Result<(), FileIngestError> {
    let Some((digest, proof)) = proof(deployment, manifest, cx, &mut |_| Ok(()))? else {
        return Ok(());
    };
    let expected_identity = proof.identity()?.to_text();
    if !held.contains(&digest)
        || expected_identity.strip_prefix("sha256:") != Some(import_hex)
        || proof.originals.iter().any(|(d, _)| !held.contains(d))
        || !proof
            .originals
            .iter()
            .any(|(d, _)| *d == proof.request.pin.head)
        || manifest.limits_digest != proof.request.digest().map_err(|_| corrupt("request"))?
        || manifest.capture_time_label != "unknown"
        || manifest.format != "mjpeg"
        || manifest.detector_evidence != DETECTOR_EVIDENCE
        || manifest.chunk_bytes != CHUNK_BYTES as u64
        || !manifest.omission_spans.is_empty()
        || manifest.segment_spans.len() != proof.frames.len()
    {
        return Err(corrupt("publication and proof binding"));
    }
    let capture = CaptureInterval::new(TimestampNs(0), proof.request.receive_time)?;
    let mut end = 0;
    for (index, (frame, span)) in proof.frames.iter().zip(&manifest.segment_spans).enumerate() {
        checkpoint(cx)?;
        if span.segment_index != index
            || span.offset != end
            || span.len != frame.bytes
            || span.segment_sha256 != frame.encoded
            || span.gap_before != frame.gap_before
            || span.capsule_id.as_str() != format!("capsule:{import_hex}:{index:06}")
        {
            return Err(corrupt("frame membership"));
        }
        let object = format!("object:capsule:{}", span.capsule_id.as_str());
        let actual = capsules
            .get(object.as_str())
            .ok_or_else(|| corrupt("capsule authority"))?;
        let capsule = SensorCapsule {
            capsule_id: span.capsule_id.clone(),
            sensor_id: proof.request.sensor.clone(),
            stream_id: proof.request.stream.clone(),
            sequence: index as u64,
            capture,
            receive_time: proof.request.receive_time,
            clock_basis: ClockBasis::Estimated,
            source_digest: frame.encoded,
            source_bytes: frame.bytes,
            gap_before: frame.gap_before,
            frame_count: 1,
        };
        if ContentDigest::sha256(&capsule.canonical_bytes()) != *actual {
            return Err(corrupt("physical mapping or clock rebound"));
        }
        end += span.len;
    }
    if end != manifest.input_bytes {
        return Err(corrupt("media tiling"));
    }
    // This is only publication/authority membership. Every byte read takes the mandatory
    // budgeted native replay below; opening metadata must not perform an unpriced replay
    // repeatedly before a sequential reader can use its bounded verified-origin cache.
    checkpoint(cx)
}

pub(crate) struct OriginCache {
    manifest: ContentDigest,
    media: Vec<u8>,
}
impl fmt::Debug for OriginCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginCache")
            .field("manifest", &self.manifest)
            .field("media_bytes", &self.media.len())
            .finish()
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
    if manifest.adapter_id != ADAPTER {
        *cache = None;
        return Ok(());
    }
    checkpoint(cx)?;
    let identity = manifest.canonical_digest();
    if cache.as_ref().is_none_or(|c| c.manifest != identity) {
        let (_, proof) =
            proof(deployment, manifest, cx, reserve)?.ok_or_else(|| corrupt("missing proof"))?;
        let media = verify(deployment, &proof, manifest, cx, reserve)?;
        *cache = Some(OriginCache {
            manifest: identity,
            media,
        });
    }
    let start = usize::try_from(offset).map_err(|_| corrupt("offset"))?;
    let end = start
        .checked_add(bytes.len())
        .ok_or_else(|| corrupt("range overflow"))?;
    if cache.as_ref().and_then(|c| c.media.get(start..end)) != Some(bytes) {
        return Err(corrupt("derived range"));
    }
    checkpoint(cx)
}

pub(crate) fn verify_originals(
    deployment: &ReferenceDeployment,
    manifest: &FileImportManifest,
    cx: &ReplayCx,
) -> Result<(), FileIngestError> {
    let Some((_, proof)) = proof(deployment, manifest, cx, &mut |_| Ok(()))? else {
        return Ok(());
    };
    verify(deployment, &proof, manifest, cx, &mut |_| Ok(()))?;
    Ok(())
}
