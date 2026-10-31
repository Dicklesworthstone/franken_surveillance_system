#![forbid(unsafe_code)]
//! Explicit durable publication of native, already-masked H.264/H.265 frames.
//!
//! The canonical object manifest retains the existing native frame receipt verbatim as
//! metadata and packed I420 as a child. Its versioned kind additionally binds the requested
//! range length and display-output position. No second codec receipt format is invented.
//! Source custody, current privacy policy and the final cognition batch are required on every
//! cold read. Checksums prove retained consistency, not independent correctness of decoding.
//! Normal range decoding remains unpublished; this is an explicit owner-authorized operation.

use std::collections::BTreeSet;

use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, ContentDigest, DigestAlgorithm,
    EvidenceDelta, LedgerAnchor, ObjectId, Plane, SensorCapsule,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use super::privacy_mask::{MaskBinding, PrivacyMaskError, current_mask, decode_marker};
use super::recorded_decode::h264::{
    H264_FRAME_RECEIPT_DOMAIN, RecordedH264Frame, h264_decoder_identity,
};
use super::recorded_decode::h265::{
    H265_FRAME_RECEIPT_DOMAIN, RecordedH265Frame, h265_decoder_identity,
    h265_tiles_decoder_identity,
};
use super::recorded_decode::{RecordedDecodeError, source_capsule};
use super::{RetainedFileImport, RetainedReadLimits};
use crate::{ReferenceDeployment, ReplayCx};

type Result<T> = std::result::Result<T, RecordedDecodeError>;
const MAX_METADATA_BYTES: usize = 4096;
const MAX_PIXELS: usize = 4_194_304;
const MAX_RANGE_SEGMENTS: usize = 65_536;
const KIND: &str = "recorded-video-frame:v1:";
/// Cancellation boundary after a frame root is visible, before its completion authority.
pub const STAGE_VIDEO_PUBLICATION_COMMIT: &str = "video_publication:commit";

/// Read/allocation ceilings, checked on both new publications and completed reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VideoPublicationLimits {
    /// Bounds for verifying the original recording, including prediction/configuration bytes.
    pub source: RetainedReadLimits,
    /// Maximum visible luma samples; never more than the native four-megapixel ceiling.
    pub maximum_pixels: usize,
}
impl Default for VideoPublicationLimits {
    fn default() -> Self {
        Self {
            source: RetainedReadLimits::default(),
            maximum_pixels: MAX_PIXELS,
        }
    }
}

/// Only sealed native decoder frames can enter the publication writer.
#[derive(Clone, Copy, Debug)]
pub enum NativeVideoFrame<'a> {
    /// A frame actually returned by the retained H.264 range decoder.
    H264(&'a RecordedH264Frame),
    /// A frame actually returned by the retained H.265 range decoder.
    H265(&'a RecordedH265Frame),
}
impl<'a> NativeVideoFrame<'a> {
    fn parts(self) -> (Vec<u8>, usize, u64, [&'a [u8]; 3]) {
        match self {
            Self::H264(f) => (
                f.receipt().encoded(),
                f.range_segment_count(),
                f.output_index(),
                [f.pixels(), f.cb(), f.cr()],
            ),
            Self::H265(f) => (
                f.receipt().encoded(),
                f.range_segment_count(),
                f.output_index(),
                [f.pixels(), f.cb(), f.cr()],
            ),
        }
    }
}

/// Native codec named by the unchanged, retained frame receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishedVideoCodec {
    /// Progressive eight-bit 4:2:0 AVC.
    H264,
    /// Eight-bit 4:2:0 HEVC.
    H265,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Binding {
    codec: PublishedVideoCodec,
    import_identity: ContentDigest,
    import_root: ContentDigest,
    manifest_digest: ContentDigest,
    range_start: u64,
    segment: u64,
    source_offset: u64,
    capsule_digest: ContentDigest,
    capsule: SensorCapsule,
    dimensions: [u32; 2],
    decode_index: u64,
    luma: ContentDigest,
    i420: ContentDigest,
    mask_policy: Option<ContentDigest>,
}
impl Binding {
    // Decode only the existing, exact v2 receipt formats. Codec-specific fields are consumed
    // and validated, never translated into JPEG provenance or an invented frame identity.
    fn read(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(RecordedDecodeError::Limit);
        }
        let mut d = CanonicalDecoder::new(bytes);
        let codec = match d.text()? {
            H264_FRAME_RECEIPT_DOMAIN => PublishedVideoCodec::H264,
            H265_FRAME_RECEIPT_DOMAIN => PublishedVideoCodec::H265,
            _ => return Err(RecordedDecodeError::InvalidReceipt),
        };
        let import_identity = sha(&mut d)?;
        let import_root = sha(&mut d)?;
        let manifest_digest = sha(&mut d)?;
        let range_start = d.u64()?;
        let segment = d.u64()?;
        let source_offset = d.u64()?;
        let capsule_digest = sha(&mut d)?;
        let capsule = SensorCapsule::decode_canonical(&mut d)?;
        let dimensions = [d.u32()?, d.u32()?];
        match codec {
            PublishedVideoCodec::H264 => {
                let _idr = d.bool()?;
            }
            PublishedVideoCodec::H265 => {
                let nal_type = d.u8()?;
                if nal_type > 31 {
                    return Err(RecordedDecodeError::InvalidReceipt);
                }
                let _picture_order_count = d.u32()?;
            }
        }
        let decode_index = d.u64()?;
        let luma = sha(&mut d)?;
        let i420 = sha(&mut d)?;
        let decoder = sha(&mut d)?;
        let known_decoder = match codec {
            PublishedVideoCodec::H264 => decoder == h264_decoder_identity(),
            PublishedVideoCodec::H265 => {
                decoder == h265_decoder_identity() || decoder == h265_tiles_decoder_identity()
            }
        };
        let mask_policy = decode_marker(&mut d)?;
        d.ensure_finished()?;
        if !known_decoder
            || capsule_digest != ContentDigest::sha256(&capsule.try_canonical_bytes()?)
            || mask_policy.is_some_and(|p| p.algorithm() != DigestAlgorithm::Sha256)
        {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        Ok(Self {
            codec,
            import_identity,
            import_root,
            manifest_digest,
            range_start,
            segment,
            source_offset,
            capsule_digest,
            capsule,
            dimensions,
            decode_index,
            luma,
            i420,
            mask_policy,
        })
    }

    fn lengths(&self, limits: VideoPublicationLimits) -> Result<(usize, usize)> {
        let [w, h] = self.dimensions;
        if limits.maximum_pixels == 0
            || limits.maximum_pixels > MAX_PIXELS
            || w == 0
            || h == 0
            || w > 4096
            || h > 4096
        {
            return Err(RecordedDecodeError::Limit);
        }
        let y = (w as usize)
            .checked_mul(h as usize)
            .ok_or(RecordedDecodeError::Limit)?;
        let c = (w.div_ceil(2) as usize)
            .checked_mul(h.div_ceil(2) as usize)
            .ok_or(RecordedDecodeError::Limit)?;
        if y > limits.maximum_pixels {
            return Err(RecordedDecodeError::Limit);
        }
        Ok((y, c))
    }

    fn source_gate(
        &self,
        deployment: &ReferenceDeployment,
        count: usize,
        output: u64,
        limits: VideoPublicationLimits,
        cx: &ReplayCx,
    ) -> Result<MaskBinding> {
        checkpoint(cx, "video_publication:source")?;
        self.lengths(limits)?;
        if count == 0
            || count > MAX_RANGE_SEGMENTS
            || output >= count as u64
            || self.decode_index >= count as u64
        {
            return Err(RecordedDecodeError::Limit);
        }
        let end = self
            .range_start
            .checked_add(count as u64)
            .ok_or(RecordedDecodeError::Limit)?;
        if self.segment < self.range_start
            || self.segment >= end
            || (self.codec == PublishedVideoCodec::H264
                && self.segment - self.range_start != self.decode_index)
        {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        let retained =
            RetainedFileImport::open(deployment, self.import_identity, limits.source, cx)?;
        let format = retained.manifest().format.as_str();
        let admitted = match self.codec {
            PublishedVideoCodec::H264 => matches!(format, "annexb" | "mp4avc" | "mkvavc"),
            PublishedVideoCodec::H265 => matches!(format, "hevc" | "mp4hevc" | "mkvhevc"),
        };
        if !admitted
            || retained.import_root() != self.import_root
            || retained.manifest_digest() != self.manifest_digest
            || end > retained.manifest().segment_spans.len() as u64
        {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        let segment = usize::try_from(self.segment).map_err(|_| RecordedDecodeError::Limit)?;
        let (capsule, digest) = source_capsule(deployment, &retained, segment)?;
        if capsule != self.capsule
            || digest != self.capsule_digest
            || retained.manifest().segment_spans[segment].offset != self.source_offset
        {
            return Err(RecordedDecodeError::CustodyMismatch);
        }
        let mask = current_mask(deployment, &capsule.sensor_id)?;
        if mask.policy_digest() != self.mask_policy {
            return Err(PrivacyMaskError::UnmaskedAccessRefused.into());
        }
        // Verify the WHOLE original, not just this picture's compressed access unit. B pictures
        // and container parameter sets may depend on bytes elsewhere in the requested range.
        // This bounded reference path intentionally trades repeated I/O for no stale source cache.
        retained.verify_source(deployment, limits.source, cx)?;
        Ok(mask)
    }

    fn manifest(
        &self,
        receipt: ContentDigest,
        count: usize,
        output: u64,
    ) -> Result<ObjectManifest> {
        let mut children = BTreeSet::from([
            self.import_root,
            self.manifest_digest,
            self.capsule_digest,
            self.i420,
        ]);
        children.remove(&receipt);
        Ok(ObjectManifest::new(
            kind(count, output),
            children,
            Some(receipt),
        )?)
    }

    fn delta(&self, manifest: &ObjectManifest) -> Result<EvidenceDelta> {
        let name = hex(manifest.root());
        Ok(EvidenceDelta {
            delta_id: format!("delta:recorded-video:{name}"),
            family: "decode_receipt".to_owned(),
            object_id: ObjectId::parse(format!("object:recorded-video:{name}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: self.capsule.capture,
            plane: Plane::Cognition,
            payload_digest: manifest
                .metadata_digest()
                .ok_or(RecordedDecodeError::InvalidReceipt)?,
            witness_digest: Some(manifest.root()),
            operation_id: None,
        })
    }
}

/// A completed, source-verified native video frame publication.
///
/// Access is admitted at `publish`/`open`, like other retained frame handles. A caller crossing
/// a policy/authority boundary must reopen instead of reusing an earlier in-memory handle.
/// This is retained cognition, never a continuity, absence or effect-completion certificate.
#[derive(Clone)]
pub struct PublishedVideoFrame {
    binding: Binding,
    receipt: Vec<u8>,
    i420: Vec<u8>,
    luma_len: usize,
    chroma_len: usize,
    range_count: usize,
    output_index: u64,
    root: ContentDigest,
    anchor: LedgerAnchor,
    mask: MaskBinding,
}
impl std::fmt::Debug for PublishedVideoFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublishedVideoFrame")
            .field("root", &self.root)
            .field("codec", &self.binding.codec)
            .field("dimensions", &self.binding.dimensions)
            .field("segment", &self.binding.segment)
            .finish_non_exhaustive()
    }
}
impl PublishedVideoFrame {
    /// Retain an actual native frame. All source and privacy checks precede derivative staging.
    /// Repeating a completed publication validates its custody without repairing damage. A cut
    /// between root publication and completion can resume the exact same immutable graph.
    pub fn publish(
        deployment: &mut ReferenceDeployment,
        frame: NativeVideoFrame<'_>,
        limits: VideoPublicationLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "video_publication:begin")?;
        let (receipt, range_count, output_index, planes) = frame.parts();
        let binding = Binding::read(&receipt)?;
        let (luma_len, chroma_len) = binding.lengths(limits)?;
        if planes[0].len() != luma_len
            || planes[1].len() != chroma_len
            || planes[2].len() != chroma_len
        {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        let mask = binding.source_gate(deployment, range_count, output_index, limits, cx)?;
        let mut i420 = Vec::new();
        i420.try_reserve_exact(luma_len + 2 * chroma_len)
            .map_err(|_| RecordedDecodeError::Limit)?;
        for plane in planes {
            i420.extend_from_slice(plane);
        }
        verify_pixels(&binding, &i420, luma_len, chroma_len)?;
        let manifest =
            binding.manifest(ContentDigest::sha256(&receipt), range_count, output_index)?;
        let root = manifest.root();
        let completion = batch_id(root)?;
        if deployment
            .ledger()
            .batches()
            .iter()
            .any(|b| b.batch_id == completion)
        {
            return Self::open(deployment, root, limits, cx);
        }
        let slot = slot(root)?;
        let visible = deployment.publisher().root(&slot).map(|r| r.root);
        if visible.is_some_and(|r| r != root) {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        // Do not restage or repair the children of an already visible root, including an
        // interrupted publication. Require those exact retained bytes before resuming authority.
        if visible.is_some() {
            verify_visible(deployment, &slot, &manifest)?;
            if read(
                deployment,
                ContentDigest::sha256(&receipt),
                MAX_METADATA_BYTES,
            )? != receipt
                || read(deployment, binding.i420, i420.len())? != i420
            {
                return Err(RecordedDecodeError::InvalidReceipt);
            }
        } else {
            for bytes in [receipt.as_slice(), i420.as_slice()] {
                checkpoint(cx, "video_publication:stage")?;
                let digest = deployment.publisher_mut().stage_object(bytes)?;
                deployment.publisher_mut().verify_object(digest)?;
            }
            deployment
                .publisher_mut()
                .stage_manifest(&slot, &manifest)?;
        }
        let delta = binding.delta(&manifest)?;
        let children = closure(&manifest);
        deployment.publish_and_commit(&slot, &manifest, binding.capsule.capture, cx)?;
        checkpoint(cx, STAGE_VIDEO_PUBLICATION_COMMIT)?;
        let anchor = deployment.append_batch(completion, vec![delta], children, cx)?;
        // No fallible work after the final authority commit.
        cx.checkpoint_post_commit("video_publication:complete");
        Ok(Self {
            binding,
            receipt,
            i420,
            luma_len,
            chroma_len,
            range_count,
            output_index,
            root,
            anchor,
            mask,
        })
    }

    /// Reopen an exact completed publication without another codec invocation or original path.
    /// Reads and verifies source custody, current privacy policy, exact authority/manifest closure,
    /// the unchanged native receipt, and packed pixels. Missing completion is never success.
    pub fn open(
        deployment: &ReferenceDeployment,
        root: ContentDigest,
        limits: VideoPublicationLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "video_publication:open")?;
        if root.algorithm() != DigestAlgorithm::Sha256 {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        let completion = batch_id(root)?;
        let batch = deployment
            .ledger()
            .batches()
            .iter()
            .find(|b| b.batch_id == completion)
            .ok_or(RecordedDecodeError::Unavailable)?;
        if batch.deltas.len() != 1 {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        let manifest =
            ObjectManifest::from_canonical_bytes(&read(deployment, root, MAX_METADATA_BYTES)?)?;
        let (range_count, output_index) = parse_kind(manifest.kind())?;
        let digest = manifest
            .metadata_digest()
            .ok_or(RecordedDecodeError::InvalidReceipt)?;
        let receipt = read(deployment, digest, MAX_METADATA_BYTES)?;
        let binding = Binding::read(&receipt)?;
        let expected = binding.manifest(digest, range_count, output_index)?;
        if manifest != expected
            || manifest.root() != root
            || batch.deltas[0] != binding.delta(&manifest)?
            || batch.children != closure(&manifest)
        {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        verify_visible(deployment, &slot(root)?, &manifest)?;
        let mask = binding.source_gate(deployment, range_count, output_index, limits, cx)?;
        let (luma_len, chroma_len) = binding.lengths(limits)?;
        let i420 = read(deployment, binding.i420, luma_len + 2 * chroma_len)?;
        verify_pixels(&binding, &i420, luma_len, chroma_len)?;
        checkpoint(cx, "video_publication:read_complete")?;
        Ok(Self {
            binding,
            receipt,
            i420,
            luma_len,
            chroma_len,
            range_count,
            output_index,
            root,
            anchor: batch.new_anchor.clone(),
            mask,
        })
    }

    /// Exact immutable publication identity, not the native receipt digest.
    pub fn publication_root(&self) -> ContentDigest {
        self.root
    }
    /// Final cognition-completion anchor, not an unrelated later ledger head.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// Native codec owning the retained frame receipt.
    pub fn codec(&self) -> PublishedVideoCodec {
        self.binding.codec
    }
    /// Exact original recording identity.
    pub fn import_identity(&self) -> ContentDigest {
        self.binding.import_identity
    }
    /// Source access-unit index (decode order, not display order).
    pub fn segment_index(&self) -> u64 {
        self.binding.segment
    }
    /// Random-access segment from which native prediction began.
    pub fn range_start(&self) -> u64 {
        self.binding.range_start
    }
    /// Original requested access-unit count, including HEVC skipped RASL units.
    pub fn range_segment_count(&self) -> usize {
        self.range_count
    }
    /// Exact display-output position within the requested range.
    pub fn output_index(&self) -> u64 {
        self.output_index
    }
    /// Visible luma width and height.
    pub fn dimensions(&self) -> [u32; 2] {
        self.binding.dimensions
    }
    /// Unchanged canonical native H.264/H.265 v2 receipt bytes.
    pub fn codec_receipt(&self) -> &[u8] {
        &self.receipt
    }
    /// Exact original capsule, including conservative source timing.
    pub fn capsule(&self) -> &SensorCapsule {
        &self.binding.capsule
    }
    /// Current-at-admission privacy policy, or the explicit no-policy marker.
    pub fn mask_policy(&self) -> Option<ContentDigest> {
        self.binding.mask_policy
    }
    /// Verified packed Y, Cb, Cr in native I420 order.
    pub fn i420(&self) -> &[u8] {
        &self.i420
    }
    /// Verified tight row-major luma plane.
    pub fn pixels(&self) -> &[u8] {
        &self.i420[..self.luma_len]
    }
    /// Verified tight Cb plane; odd dimensions use ceiling division by two.
    pub fn cb(&self) -> &[u8] {
        &self.i420[self.luma_len..self.luma_len + self.chroma_len]
    }
    /// Verified tight Cr plane.
    pub fn cr(&self) -> &[u8] {
        &self.i420[self.luma_len + self.chroma_len..]
    }
    /// Native RGB rendering, retaining the privacy policy's fixed RGB fill.
    pub fn to_rgb(&self) -> Result<Vec<u8>> {
        let mut rgb = super::recorded_decode::video_rgb::i420_to_rgb(
            self.pixels(),
            self.cb(),
            self.cr(),
            self.dimensions(),
        )?;
        self.mask.apply_rgb(&mut rgb, self.dimensions())?;
        Ok(rgb)
    }
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| RecordedDecodeError::Cancelled)
}
fn sha(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest> {
    let digest = d.digest()?;
    if digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err(RecordedDecodeError::InvalidReceipt);
    }
    Ok(digest)
}
fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn kind(count: usize, output: u64) -> String {
    format!("{KIND}{count}:{output}")
}
fn parse_kind(value: &str) -> Result<(usize, u64)> {
    let (count, output) = value
        .strip_prefix(KIND)
        .and_then(|s| s.split_once(':'))
        .ok_or(RecordedDecodeError::InvalidReceipt)?;
    let count: usize = count
        .parse()
        .map_err(|_| RecordedDecodeError::InvalidReceipt)?;
    let output: u64 = output
        .parse()
        .map_err(|_| RecordedDecodeError::InvalidReceipt)?;
    if count == 0
        || count > MAX_RANGE_SEGMENTS
        || output >= count as u64
        || kind(count, output) != value
    {
        return Err(RecordedDecodeError::InvalidReceipt);
    }
    Ok((count, output))
}
fn slot(root: ContentDigest) -> Result<SlotName> {
    SlotName::parse(&format!("fv-{}", hex(root))).map_err(|_| RecordedDecodeError::InvalidReceipt)
}
fn batch_id(root: ContentDigest) -> Result<BatchId> {
    Ok(BatchId::parse(format!(
        "batch:recorded-video:{}",
        hex(root)
    ))?)
}
fn closure(manifest: &ObjectManifest) -> Vec<ContentDigest> {
    let mut children = manifest.children().to_vec();
    children.push(manifest.root());
    children.sort_unstable();
    children.dedup();
    children
}
fn read(
    deployment: &ReferenceDeployment,
    digest: ContentDigest,
    maximum: usize,
) -> Result<Vec<u8>> {
    let bytes = deployment
        .publisher()
        .spool()
        .read_bounded(digest, maximum)?;
    if ContentDigest::sha256(&bytes) != digest {
        return Err(RecordedDecodeError::InvalidReceipt);
    }
    Ok(bytes)
}
fn verify_visible(
    deployment: &ReferenceDeployment,
    slot: &SlotName,
    manifest: &ObjectManifest,
) -> Result<()> {
    if deployment
        .publisher()
        .root(slot)
        .is_none_or(|r| r.root != manifest.root())
        || read(deployment, manifest.root(), MAX_METADATA_BYTES)? != manifest.canonical_bytes()
    {
        return Err(RecordedDecodeError::InvalidReceipt);
    }
    Ok(())
}
fn verify_pixels(binding: &Binding, bytes: &[u8], y: usize, c: usize) -> Result<()> {
    if bytes.len() != y + 2 * c
        || ContentDigest::sha256(bytes) != binding.i420
        || ContentDigest::sha256(&bytes[..y]) != binding.luma
    {
        return Err(RecordedDecodeError::InvalidReceipt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_range_binding_is_canonical_and_bounded() {
        assert_eq!(parse_kind(&kind(3, 2)).ok(), Some((3, 2)));
        for s in [
            "recorded-video-frame:v1:03:2",
            "recorded-video-frame:v1:3:02",
            "recorded-video-frame:v1:0:0",
            "recorded-video-frame:v1:3:3",
            "recorded-video-frame:v1:65537:0",
            "recorded-video-frame:v1:3:1:2",
            "recorded-video-frame:v2:3:1",
            "recorded-video-frame:v1:+3:1",
        ] {
            assert!(parse_kind(s).is_err(), "{s}");
        }
    }
}
