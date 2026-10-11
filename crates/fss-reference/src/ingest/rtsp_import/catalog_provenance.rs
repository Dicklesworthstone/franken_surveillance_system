#![forbid(unsafe_code)]
//! Exact catalog ancestry and bounded cold replay of every original native recording.

use super::super::file_adapter::{FileOmissionSpan, SegmentSpan};
use super::catalog::{self, RtspCatalogImportRequest};
use super::provenance::Window;
use super::*;
use crate::rtsp::recording::{
    RECORDING_KIND, RecordingSummary,
    hevc::{HEVC_RECORDING_KIND, verify_hevc_recording},
    verify_recording,
};
use crate::rtsp::recording_catalog::{
    CatalogEntry, CatalogScope, MAX_CATALOG_BYTES, hevc::verify_hevc_catalog, verify_catalog,
};
use fss_core::{
    CanonicalDecoder, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, SensorCapsule,
    SensorId, StreamId,
};
use fss_object::ObjectManifest;
use std::collections::BTreeSet;

const DOMAIN: &str = "fss.rtsp_catalog_import.v1";
const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
const MAX_OMISSIONS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CatalogTable {
    root: Vec<u8>,
    index: Vec<u8>,
}
impl CatalogTable {
    pub(super) fn load(
        publisher: &LocalRootPublisher,
        request: &RtspCatalogImportRequest,
        cancel: &dyn PublishCancellation,
    ) -> Result<Self, RtspImportError> {
        Ok(match request.codec {
            RtspImportCodec::Avc => {
                let c = crate::rtsp::recording_catalog::local::load_catalog(
                    publisher,
                    &request.slot,
                    request.root,
                    &request.scope,
                    cancel,
                )
                .map_err(source_error)?;
                Self {
                    root: c.manifest().canonical_bytes(),
                    index: c.index_bytes().to_vec(),
                }
            }
            RtspImportCodec::Hevc => {
                let c = crate::rtsp::recording_catalog::hevc::local::load_hevc_catalog(
                    publisher,
                    &request.slot,
                    request.root,
                    &request.scope,
                    cancel,
                )
                .map_err(source_error)?;
                Self {
                    root: c.manifest().canonical_bytes(),
                    index: c.index_bytes().to_vec(),
                }
            }
        })
    }
    pub(super) fn entries(
        &self,
        request: &RtspCatalogImportRequest,
    ) -> Result<Vec<CatalogEntry>, FileIngestError> {
        if self
            .root
            .len()
            .checked_add(self.index.len())
            .is_none_or(|n| n > MAX_CATALOG_BYTES)
        {
            return Err(corrupt("catalog metadata ceiling"));
        }
        let root = ObjectManifest::from_canonical_bytes(&self.root)?;
        if root.root() != request.root {
            return Err(corrupt("catalog root"));
        }
        let entries = match request.codec {
            RtspImportCodec::Avc => verify_catalog(&root, &self.index, &request.scope)
                .map_err(|_| corrupt("native AVC catalog"))?
                .entries()
                .to_vec(),
            RtspImportCodec::Hevc => verify_hevc_catalog(&root, &self.index, &request.scope)
                .map_err(|_| corrupt("native HEVC catalog"))?
                .entries()
                .to_vec(),
        };
        let original_bytes =
            entries
                .iter()
                .try_fold((self.root.len() + self.index.len()) as u64, |n, e| {
                    n.checked_add(e.byte_len() as u64)
                        .ok_or_else(|| corrupt("catalog byte overflow"))
                })?;
        let frames = entries.iter().try_fold(0usize, |n, e| {
            n.checked_add(e.samples())
                .ok_or_else(|| corrupt("catalog sample overflow"))
        })?;
        if entries.is_empty()
            || entries.len() > request.max_windows
            || frames > request.max_frames
            || original_bytes > request.max_original_bytes
            || entries
                .windows(2)
                .any(|w| w[0].decode_interval().end != w[1].decode_interval().start)
        {
            return Err(corrupt(
                "complete catalog exceeds bounds or contains a decode gap",
            ));
        }
        Ok(entries)
    }
    pub(super) fn insert_payloads(&self, payloads: &mut BTreeMap<ContentDigest, Vec<u8>>) {
        payloads.insert(ContentDigest::sha256(&self.root), self.root.clone());
        payloads.insert(ContentDigest::sha256(&self.index), self.index.clone());
    }
    pub(super) fn check_window(
        entry: &CatalogEntry,
        request: &RtspCatalogImportRequest,
        summary: &RecordingSummary,
        bytes: usize,
    ) -> Result<(), FileIngestError> {
        if summary.root != entry.root()
            || summary.scope != request.scope.recording
            || summary.time_scale != request.scope.time_scale
            || summary.decode_interval != entry.decode_interval()
            || summary.samples != entry.samples()
            || summary.packets != entry.packets()
            || summary.nals != entry.nals()
            || bytes != entry.byte_len()
        {
            return Err(corrupt("replayed window differs from catalog descriptor"));
        }
        Ok(())
    }
}
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
        let p = window.payloads();
        let object = |i: usize| ObjectRef {
            digest: p[i].0,
            bytes: p[i].1.len() as u64,
        };
        Self {
            root: window.root.clone(),
            objects: [object(1), object(2), object(3), object(4)],
        }
    }
    fn validate(
        &self,
        entry: &CatalogEntry,
        codec: RtspImportCodec,
    ) -> Result<(), FileIngestError> {
        let kind = match codec {
            RtspImportCodec::Avc => RECORDING_KIND,
            RtspImportCodec::Hevc => HEVC_RECORDING_KIND,
        };
        let expected = ObjectManifest::new(
            kind,
            self.objects[..3].iter().map(|o| o.digest),
            Some(self.objects[3].digest),
        )?;
        let bytes = self
            .objects
            .iter()
            .try_fold(self.root.len() as u64, |n, o| {
                n.checked_add(o.bytes)
                    .ok_or_else(|| corrupt("window byte overflow"))
            })?;
        if self.root.len() > 4096
            || ObjectManifest::from_canonical_bytes(&self.root)? != expected
            || expected.root() != entry.root()
            || bytes != entry.byte_len() as u64
            || self
                .objects
                .iter()
                .any(|o| o.bytes == 0 || o.bytes > super::MAX_ORIGINAL_BYTES)
        {
            return Err(corrupt("catalog window closure or bounds"));
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
pub(super) struct CatalogProof {
    request: RtspCatalogImportRequest,
    table: CatalogTable,
    windows: Vec<WindowReference>,
    media_digest: ContentDigest,
    media_bytes: u64,
    frames: Vec<FrameOrigin>,
    omissions: Vec<FileOmissionSpan>,
}
impl CatalogProof {
    pub(super) fn new(
        request: RtspCatalogImportRequest,
        table: CatalogTable,
        windows: Vec<WindowReference>,
        media: &[u8],
        scan: &ScannedSegments,
    ) -> Result<Self, FileIngestError> {
        let value = Self {
            request,
            table,
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
    pub(super) fn encode(&self) -> Result<Vec<u8>, FileIngestError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        self.request.encode(&mut e);
        e.bytes(&self.table.root);
        e.bytes(&self.table.index);
        e.u64(self.windows.len() as u64);
        for window in &self.windows {
            e.bytes(&window.root);
            for o in &window.objects {
                e.digest(o.digest);
                e.u64(o.bytes);
            }
        }
        e.digest(self.media_digest);
        e.u64(self.media_bytes);
        e.u64(self.frames.len() as u64);
        for f in &self.frames {
            e.u64(f.offset);
            e.u64(f.bytes);
            e.digest(f.digest);
            e.i128(f.capture.earliest.0);
            e.i128(f.capture.latest.0);
        }
        e.u64(self.omissions.len() as u64);
        for s in &self.omissions {
            e.u64(s.offset);
            e.u64(s.len);
            e.text(&s.reason);
        }
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(corrupt("catalog proof byte ceiling"));
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, FileIngestError> {
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(corrupt("catalog proof byte ceiling"));
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != DOMAIN || d.text()? != "fss.rtsp_catalog_import_request.v1" {
            return Err(corrupt("unknown catalog proof or request"));
        }
        let codec = match d.text()? {
            "avc" => RtspImportCodec::Avc,
            "hevc" => RtspImportCodec::Hevc,
            _ => return Err(corrupt("catalog codec")),
        };
        let slot = SlotName::parse(d.text()?).map_err(|_| corrupt("catalog slot"))?;
        let root = digest(&mut d)?;
        let recording = RecordingScope {
            sensor: SensorId::parse(d.text()?)?,
            stream: StreamId::parse(d.text()?)?,
            generation: d.u64()?,
            anchor: digest(&mut d)?,
            receive_clock: digest(&mut d)?,
        };
        let scope = CatalogScope {
            recording,
            decode_clock: digest(&mut d)?,
            time_scale: d.u32()?,
        };
        let receive_time = TimestampNs(d.i128()?);
        let capture_origin = if d.bool()? {
            Some(RtspCaptureOrigin {
                start_ns: TimestampNs(d.i128()?),
                uncertainty_ns: d.u64()?,
            })
        } else {
            None
        };
        let request = RtspCatalogImportRequest {
            codec,
            slot,
            root,
            scope,
            receive_time,
            capture_origin,
            max_windows: usize::try_from(d.u64()?).map_err(|_| corrupt("window ceiling"))?,
            max_frames: usize::try_from(d.u64()?).map_err(|_| corrupt("sample ceiling"))?,
            max_original_bytes: d.u64()?,
            max_media_bytes: d.u64()?,
        };
        request.validate().map_err(|_| corrupt("catalog request"))?;
        let table = CatalogTable {
            root: blob(&mut d, MAX_CATALOG_BYTES)?,
            index: blob(&mut d, MAX_CATALOG_BYTES)?,
        };
        let n = count(&mut d, catalog::MAX_WINDOWS, 172)?;
        let mut windows = Vec::with_capacity(n);
        for _ in 0..n {
            let root = blob(&mut d, 4096)?;
            let mut object = || -> Result<ObjectRef, FileIngestError> {
                Ok(ObjectRef {
                    digest: digest(&mut d)?,
                    bytes: d.u64()?,
                })
            };
            windows.push(WindowReference {
                root,
                objects: [object()?, object()?, object()?, object()?],
            });
        }
        let media_digest = digest(&mut d)?;
        let media_bytes = d.u64()?;
        let n = count(&mut d, catalog::MAX_FRAMES, 81)?;
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
            if reason.len() > 256 {
                return Err(corrupt("omission reason bound"));
            }
            omissions.push(FileOmissionSpan {
                offset,
                len,
                reason: reason.to_owned(),
            });
        }
        d.ensure_finished()?;
        let value = Self {
            request,
            table,
            windows,
            media_digest,
            media_bytes,
            frames,
            omissions,
        };
        if value.encode()? != bytes {
            return Err(corrupt("noncanonical catalog proof"));
        }
        Ok(value)
    }
    fn validate(&self) -> Result<(), FileIngestError> {
        self.request
            .validate()
            .map_err(|_| corrupt("catalog request"))?;
        let entries = self.table.entries(&self.request)?;
        if self.windows.len() != entries.len()
            || self.frames.len() != entries.iter().map(|e| e.samples()).sum::<usize>()
            || self.frames.is_empty()
            || self.omissions.len() > MAX_OMISSIONS
        {
            return Err(corrupt("catalog window or sample count"));
        }
        let first = self
            .windows
            .first()
            .ok_or_else(|| corrupt("empty catalog proof"))?;
        let initialization = &first.objects[1];
        let mut media_bytes = initialization.bytes;
        for (window, entry) in self.windows.iter().zip(&entries) {
            window.validate(entry, self.request.codec)?;
            if &window.objects[1] != initialization {
                return Err(corrupt("catalog initialization changes"));
            }
            media_bytes = media_bytes
                .checked_add(window.objects[2].bytes)
                .ok_or_else(|| corrupt("catalog media overflow"))?;
        }
        if media_bytes != self.media_bytes
            || media_bytes == 0
            || media_bytes > self.request.max_media_bytes
        {
            return Err(corrupt("complete catalog media bound"));
        }
        let mut previous = 0u64;
        let mut spans = Vec::with_capacity(self.frames.len() + self.omissions.len());
        for frame in &self.frames {
            let end = frame
                .offset
                .checked_add(frame.bytes)
                .ok_or_else(|| corrupt("frame overflow"))?;
            if frame.offset < previous
                || end > self.media_bytes
                || frame.bytes == 0
                || frame.capture.earliest > frame.capture.latest
                || frame.capture.latest > self.request.receive_time
                || (self.request.capture_origin.is_none()
                    && frame.capture
                        != CaptureInterval::new(TimestampNs(0), self.request.receive_time)?)
            {
                return Err(corrupt("catalog frame order, bytes or time"));
            }
            previous = end;
            spans.push((frame.offset, end));
        }
        for omission in &self.omissions {
            let end = omission
                .offset
                .checked_add(omission.len)
                .ok_or_else(|| corrupt("omission overflow"))?;
            if !omission.is_container_structure()
                || omission.len == 0
                || end > self.media_bytes
                || omission.reason.len() > 256
            {
                return Err(corrupt("catalog container accounting"));
            }
            spans.push((omission.offset, end));
        }
        spans.sort_unstable();
        let mut cursor = 0u64;
        for (start, end) in spans {
            if start != cursor {
                return Err(corrupt("catalog container bytes not tiled"));
            }
            cursor = end;
        }
        if cursor != self.media_bytes {
            return Err(corrupt("unaccounted catalog media"));
        }
        Ok(())
    }
    fn held(&self, proof_digest: ContentDigest) -> BTreeSet<ContentDigest> {
        let mut held = BTreeSet::from([
            proof_digest,
            self.request.root,
            ContentDigest::sha256(&self.table.index),
        ]);
        for w in &self.windows {
            held.insert(ContentDigest::sha256(&w.root));
            held.extend(w.objects.iter().map(|o| o.digest));
        }
        held
    }
    fn load_media(
        &self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
        reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
    ) -> Result<Vec<u8>, FileIngestError> {
        let entries = self.table.entries(&self.request)?;
        for expected in [&self.table.root, &self.table.index] {
            if read_original(
                deployment,
                ContentDigest::sha256(expected),
                expected.len() as u64,
                cx,
                reserve,
            )? != *expected
            {
                return Err(corrupt("retained native catalog differs"));
            }
        }
        let mut media = Vec::new();
        for (ordinal, (reference, entry)) in self.windows.iter().zip(&entries).enumerate() {
            let root = read_original(
                deployment,
                entry.root(),
                reference.root.len() as u64,
                cx,
                reserve,
            )?;
            if root != reference.root {
                return Err(corrupt("catalog original root"));
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
                source: children.next().ok_or_else(|| corrupt("source"))?,
                initialization: children.next().ok_or_else(|| corrupt("initialization"))?,
                fragment: children.next().ok_or_else(|| corrupt("fragment"))?,
                index: children.next().ok_or_else(|| corrupt("index"))?,
                samples: entry.samples(),
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
            .map_err(|_| corrupt("catalog native packet/source reconstruction"))?;
            let bytes = window.payloads().iter().map(|(_, b)| b.len()).sum();
            CatalogTable::check_window(entry, &self.request, &summary, bytes)?;
            checkpoint(cx)?;
            if ordinal == 0 {
                catalog::append_media(
                    &mut media,
                    &window.initialization,
                    self.request.max_media_bytes,
                )?;
            }
            catalog::append_media(&mut media, &window.fragment, self.request.max_media_bytes)?;
        }
        if media.len() as u64 != self.media_bytes
            || ContentDigest::sha256(&media) != self.media_digest
        {
            return Err(corrupt("reconstructed catalog MP4"));
        }
        let scan = self.request.scan(&media, cx)?;
        if scan.truncated_frames != 0 || scan.segment_spans.iter().any(|s| s.gap_before) {
            return Err(corrupt("catalog source sample continuity"));
        }
        let rebuilt = Self::new(
            self.request.clone(),
            self.table.clone(),
            self.windows.clone(),
            &media,
            &scan,
        )?;
        if rebuilt.encode()? != self.encode()? {
            return Err(corrupt("native catalog sample or capture map"));
        }
        checkpoint(cx)?;
        Ok(media)
    }
}

fn digest(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest, FileIngestError> {
    let value = d.digest()?;
    if value.algorithm() != DigestAlgorithm::Sha256 {
        return Err(corrupt("digest algorithm"));
    }
    Ok(value)
}
fn count(
    d: &mut CanonicalDecoder<'_>,
    max: usize,
    minimum: usize,
) -> Result<usize, FileIngestError> {
    let n = usize::try_from(d.u64()?).map_err(|_| corrupt("collection overflow"))?;
    if n > max || n > d.remaining() / minimum {
        return Err(corrupt("collection bound"));
    }
    Ok(n)
}
fn blob(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<Vec<u8>, FileIngestError> {
    let bytes = d.bytes()?;
    if bytes.len() > maximum {
        return Err(corrupt("catalog metadata bound"));
    }
    Ok(bytes.to_vec())
}
fn selected_digest(
    manifest: &FileImportManifest,
) -> Result<Option<ContentDigest>, FileIngestError> {
    if manifest.adapter_id != catalog::ADAPTER {
        return Ok(None);
    }
    let hex = manifest
        .adapter_generation
        .strip_prefix(catalog::GENERATION)
        .filter(|h| h.len() == 64)
        .ok_or_else(|| corrupt("catalog adapter generation"))?;
    Ok(Some(ContentDigest::parse(&format!("sha256:{hex}"))?))
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
        return Err(corrupt("deleted catalog origin"));
    }
    Ok(())
}
fn proof(
    deployment: &ReferenceDeployment,
    digest: ContentDigest,
    cx: &ReplayCx,
    reserve: &mut dyn FnMut(u64) -> Result<(), FileIngestError>,
) -> Result<CatalogProof, FileIngestError> {
    live(deployment, &BTreeSet::from([digest]), cx)?;
    reserve(MAX_PROOF_BYTES as u64)?;
    let bytes = deployment
        .publisher()
        .spool()
        .read_bounded(digest, MAX_PROOF_BYTES)?;
    if bytes.len() > MAX_PROOF_BYTES || ContentDigest::sha256(&bytes) != digest {
        return Err(corrupt("catalog proof digest"));
    }
    let proof = CatalogProof::decode(&bytes)?;
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
    if deployment.publisher().tombstones().any(|d| *d == digest) {
        return Err(corrupt("deleted catalog original"));
    }
    let maximum = usize::try_from(length).map_err(|_| corrupt("original length"))?;
    let bytes = deployment
        .publisher()
        .spool()
        .read_bounded(digest, maximum)?;
    if bytes.len() as u64 != length || ContentDigest::sha256(&bytes) != digest {
        return Err(corrupt("catalog original payload"));
    }
    Ok(bytes)
}

/// One bounded source-verified MP4 per retained read cursor. Packet packs are dropped after replay.
/// This immutable read snapshot does not certify future disk availability; publication independently
/// rereads the original closure, and current tombstones are checked even for cached sample reads.
pub(crate) struct OriginCache {
    digest: ContentDigest,
    media: Vec<u8>,
    held: BTreeSet<ContentDigest>,
}
impl fmt::Debug for OriginCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CatalogOriginCache")
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
    if cache.as_ref().is_none_or(|c| c.digest != digest) {
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
        .ok_or_else(|| corrupt("catalog source cache"))?;
    live(deployment, &cached.held, cx)?;
    let start = usize::try_from(offset).map_err(|_| corrupt("catalog range offset"))?;
    let end = start
        .checked_add(bytes.len())
        .ok_or_else(|| corrupt("catalog range overflow"))?;
    if cached.media.get(start..end) != Some(bytes) {
        return Err(corrupt(
            "MP4 bytes differ from native catalog reconstruction",
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
        || hex(proof
            .request
            .identity()
            .map_err(|_| corrupt("catalog identity"))?)
            != import_hex
        || manifest.limits_digest
            != proof
                .request
                .digest()
                .map_err(|_| corrupt("catalog request digest"))?
        || manifest.input_sha256 != proof.media_digest
        || manifest.input_bytes != proof.media_bytes
        || manifest.chunk_bytes != CHUNK_BYTES as u64
        || manifest.format != proof.request.codec.format().as_str()
        || manifest.capture_time_label != proof.request.time_label()
        || manifest.detector_evidence != catalog::EVIDENCE
        || manifest.segment_spans.len() != proof.frames.len()
        || manifest.omission_spans != proof.omissions
    {
        return Err(corrupt("retained catalog origin binding"));
    }
    for (index, (span, frame)) in manifest.segment_spans.iter().zip(&proof.frames).enumerate() {
        checkpoint(cx)?;
        let expected_id = CapsuleId::parse(format!("capsule:{import_hex}:{index:06}"))?;
        if span
            != &(SegmentSpan {
                segment_index: index,
                offset: frame.offset,
                len: frame.bytes,
                segment_sha256: frame.digest,
                capsule_id: expected_id.clone(),
                gap_before: false,
            })
        {
            return Err(corrupt("catalog sample map"));
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
            gap_before: false,
            frame_count: 1,
        };
        let object = format!("object:capsule:{}", span.capsule_id.as_str());
        if capsules.get(object.as_str()).copied()
            != Some(ContentDigest::sha256(&capsule.canonical_bytes()))
        {
            return Err(corrupt("catalog sensor, time or capsule binding"));
        }
    }
    checkpoint(cx)
}
