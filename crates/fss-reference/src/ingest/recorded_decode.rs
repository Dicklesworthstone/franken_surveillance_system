#![forbid(unsafe_code)]
//! Canonical JPEG decoding of retained source, with restart-safe derived publications.
//!
//! The operator-authorized deployment is the I/O boundary. The production codec owns all JPEG
//! semantics. This module only binds its complete output to retained source custody and the
//! original capsule; it does not infer colour interpretation, orientation, timestamps or coverage.
//! Binary format ownership and recovery rules are in docs/RETAINED_DECODE_WORKFLOW.md.

use std::collections::BTreeSet;
use std::fmt;

pub use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits};
use fss_codec_mjpeg::{DecodeError, DecodeReceipt, decode_luma, decoder_identity};
use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, DigestAlgorithm, EvidenceDelta, LedgerAnchor, ObjectId, Plane, SensorCapsule,
};
use fss_object::{ObjectError, ObjectManifest, SpoolError};
use fss_publication::{LocalPublicationError, SlotName};

use super::{FileIngestError, RetainedFileImport, RetainedReadLimits};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

/// Receipt format owned by the retained-media composition, not a second JPEG implementation.
pub const RECORDED_DECODE_DOMAIN: &str = "fss.recorded_luma_receipt.v1";
/// Maximum canonical receipt allocation; receipts contain identities, not pixel arrays.
pub const MAX_RECORDED_DECODE_RECEIPT_BYTES: usize = 4_096;
/// Boundary after decode, before any derived object is staged.
pub const STAGE_RECORDED_DECODE: &str = "recorded_decode:decoded";
/// Boundary after root publication, before final decode-receipt authority.
pub const STAGE_RECORDED_DECODE_COMMIT: &str = "recorded_decode:commit_receipt";

/// Explicit source selection, format interpretation, and independent read/decode bounds.
#[derive(Clone, Debug)]
pub struct RecordedDecodeRequest {
    /// Exact completed import, never a path or an implicit latest recording.
    pub import_identity: ContentDigest,
    /// Zero-based source segment in the immutable import manifest.
    pub segment_index: usize,
    /// Operator-supplied source contract; the decoder refuses inconsistent component layouts.
    pub interpretation: ComponentInterpretation,
    /// Custody-read ceilings, including the returned compressed segment.
    pub read_limits: RetainedReadLimits,
    /// Codec ceilings, validated before reading the compressed segment.
    pub decode_limits: DecodeLimits,
}

/// Typed refusal; unsuccessful decoding never returns partial pixels.
#[derive(Debug)]
pub enum RecordedDecodeError {
    /// Source is not in the JPEG/MJPEG admitted subset.
    UnsupportedMedia,
    /// A completed, currently published decode does not exist for this exact request.
    Unavailable,
    /// Receipt, source, publication or dimensions disagree.
    InvalidReceipt,
    /// A caller bound or a hard receipt/image bound was exceeded.
    Limit,
    /// Owner cancellation was observed at a composition boundary.
    Cancelled,
    /// Retained source recovery or reading failed.
    Source(FileIngestError),
    /// The canonical production codec refused the image.
    Codec(DecodeError),
    /// A shared semantic contract failed.
    Contract(ContractError),
    /// Deployment authority or custody failed.
    Reference(ReferenceError),
    /// The immutable manifest is invalid.
    Object(ObjectError),
    /// Root-last publication failed.
    Publication(LocalPublicationError),
    /// A stored object could not be verified or read.
    Spool(SpoolError),
}

impl fmt::Display for RecordedDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedMedia => f.write_str("recorded decode requires JPEG/MJPEG source"),
            Self::Unavailable => f.write_str("completed recorded decode unavailable"),
            Self::InvalidReceipt => f.write_str("recorded decode provenance or receipt mismatch"),
            Self::Limit => f.write_str("recorded decode bound exceeded"),
            Self::Cancelled => f.write_str("recorded decode cancelled"),
            Self::Source(e) => write!(f, "recorded source: {e}"),
            Self::Codec(e) => write!(f, "recorded JPEG: {e}"),
            Self::Contract(e) => write!(f, "recorded decode contract: {e}"),
            Self::Reference(e) => write!(f, "recorded decode deployment: {e}"),
            Self::Object(e) => write!(f, "recorded decode manifest: {e}"),
            Self::Publication(e) => write!(f, "recorded decode publication: {e}"),
            Self::Spool(e) => write!(f, "recorded decode custody: {e}"),
        }
    }
}
impl std::error::Error for RecordedDecodeError {}
macro_rules! conversion {
    ($source:ty, $variant:ident) => {
        impl From<$source> for RecordedDecodeError {
            fn from(error: $source) -> Self { Self::$variant(error) }
        }
    };
}
conversion!(FileIngestError, Source);
conversion!(DecodeError, Codec);
conversion!(ContractError, Contract);
conversion!(ReferenceError, Reference);
conversion!(ObjectError, Object);
conversion!(LocalPublicationError, Publication);
conversion!(SpoolError, Spool);

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), RecordedDecodeError> {
    cx.checkpoint(stage).map_err(|_| RecordedDecodeError::Cancelled)
}

fn validate_limits(limits: DecodeLimits) -> Result<(), RecordedDecodeError> {
    if limits.maximum_bytes == 0 || limits.maximum_bytes > 16 * 1024 * 1024
        || limits.maximum_dimension == 0 || limits.maximum_dimension > 4096
        || limits.maximum_pixels == 0 || limits.maximum_pixels > 4_194_304
        || limits.maximum_markers == 0 || limits.maximum_markers > 4096
    { return Err(RecordedDecodeError::Limit); }
    Ok(())
}

fn sha(bytes: [u8; 32]) -> ContentDigest { ContentDigest::new(DigestAlgorithm::Sha256, bytes) }
fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|byte| format!("{byte:02x}")).collect()
}
fn interpretation_tag(value: ComponentInterpretation) -> u8 {
    match value { ComponentInterpretation::Grayscale => 0, ComponentInterpretation::YCbCr => 1 }
}
fn key(import_root: ContentDigest, segment: u64, interpretation: ComponentInterpretation) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text("fss.recorded_luma_key.v1");
    e.digest(import_root);
    e.u64(segment);
    e.digest(sha(decoder_identity()));
    e.u8(interpretation_tag(interpretation));
    ContentDigest::sha256(&e.finish())
}
fn slot(identity: ContentDigest) -> Result<SlotName, RecordedDecodeError> {
    SlotName::parse(&format!("fd-{}", hex(identity))).map_err(|_| RecordedDecodeError::InvalidReceipt)
}
fn batch_id(identity: ContentDigest) -> Result<BatchId, RecordedDecodeError> {
    Ok(BatchId::parse(format!("batch:recorded-decode:{}", hex(identity)))?)
}

/// Complete immutable source-to-luma provenance. A checksum alone is not publisher authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedDecodeReceipt {
    import_identity: ContentDigest,
    import_root: ContentDigest,
    manifest_digest: ContentDigest,
    source_anchor: LedgerAnchor,
    segment_index: u64,
    source_offset: u64,
    capsule_digest: ContentDigest,
    capsule: SensorCapsule,
    width: u32,
    height: u32,
    codec: DecodeReceipt,
    work_units: u64,
}

impl RecordedDecodeReceipt {
    /// Exact derived identity; admission ceilings do not change successfully decoded pixels.
    #[must_use]
    pub fn identity(&self) -> ContentDigest { key(self.import_root, self.segment_index, self.codec.interpretation) }
    /// Original source capsule, including conservative capture interval and clock basis.
    #[must_use]
    pub fn capsule(&self) -> &SensorCapsule { &self.capsule }
    /// Coded width and height; no orientation or geometric transform has been applied.
    #[must_use]
    pub fn dimensions(&self) -> [u32; 2] { [self.width, self.height] }
    /// Accounting and identities from the canonical codec.
    #[must_use]
    pub fn codec(&self) -> DecodeReceipt { self.codec }
    /// Successful codec work units, not elapsed time or CPU/energy measurements.
    #[must_use]
    pub fn work_units(&self) -> u64 { self.work_units }
    /// Import completion anchor, not the later publication anchor of the decoded derivative.
    #[must_use]
    pub fn source_anchor(&self) -> &LedgerAnchor { &self.source_anchor }
    /// Exact import identity.
    #[must_use]
    pub fn import_identity(&self) -> ContentDigest { self.import_identity }
    /// Original immutable segment index.
    #[must_use]
    pub fn segment_index(&self) -> u64 { self.segment_index }
    /// Canonical receipt bytes under a bounded, versioned format.
    pub fn encoded(&self) -> Result<Vec<u8>, RecordedDecodeError> {
        self.validate()?;
        let bytes = self.try_canonical_bytes()?;
        if bytes.len() > MAX_RECORDED_DECODE_RECEIPT_BYTES { return Err(RecordedDecodeError::Limit); }
        Ok(bytes)
    }
    /// Content address for the complete receipt, including source timing and codec accounting.
    pub fn digest(&self) -> Result<ContentDigest, RecordedDecodeError> {
        Ok(ContentDigest::sha256(&self.encoded()?))
    }
    /// Decodes an authority-addressed v1 receipt; unknown versions, truncation and suffixes fail.
    pub fn decode(bytes: &[u8], expected: ContentDigest) -> Result<Self, RecordedDecodeError> {
        if bytes.len() > MAX_RECORDED_DECODE_RECEIPT_BYTES { return Err(RecordedDecodeError::Limit); }
        if ContentDigest::sha256(bytes) != expected { return Err(RecordedDecodeError::InvalidReceipt); }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != b"FSSYREC1" || d.u32()? != 1 || d.text()? != RECORDED_DECODE_DOMAIN {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        let import_identity = d.digest()?;
        let import_root = d.digest()?;
        let manifest_digest = d.digest()?;
        let source_anchor = LedgerAnchor::decode_canonical(&mut d)?;
        let segment_index = d.u64()?;
        let source_offset = d.u64()?;
        let capsule_digest = d.digest()?;
        let capsule = SensorCapsule::decode_canonical(&mut d)?;
        let width = d.u32()?;
        let height = d.u32()?;
        let encoded_sha256 = decode_sha(&mut d)?;
        let luma_sha256 = decode_sha(&mut d)?;
        let decoder = decode_sha(&mut d)?;
        let interpretation = match d.u8()? {
            0 => ComponentInterpretation::Grayscale,
            1 => ComponentInterpretation::YCbCr,
            _ => return Err(RecordedDecodeError::InvalidReceipt),
        };
        let mut integer = || -> Result<usize, RecordedDecodeError> {
            usize::try_from(d.u64()?).map_err(|_| RecordedDecodeError::Limit)
        };
        let codec = DecodeReceipt {
            encoded_sha256, luma_sha256, decoder, interpretation,
            mcus: integer()?, entropy_blocks: integer()?, restarts: integer()?,
            metadata_segments: integer()?, metadata_bytes: integer()?,
        };
        let work_units = d.u64()?;
        d.ensure_finished()?;
        let receipt = Self {
            import_identity, import_root, manifest_digest, source_anchor, segment_index,
            source_offset, capsule_digest, capsule, width, height, codec, work_units,
        };
        if receipt.encoded()? != bytes { return Err(RecordedDecodeError::InvalidReceipt); }
        Ok(receipt)
    }
    fn validate(&self) -> Result<(), RecordedDecodeError> {
        let pixels = u64::from(self.width) * u64::from(self.height);
        if self.width == 0 || self.height == 0 || self.width > 4096 || self.height > 4096
            || pixels > 4_194_304 || self.capsule.source_bytes == 0
            || self.capsule.source_bytes > 16 * 1024 * 1024 || self.codec.mcus == 0
            || self.codec.entropy_blocks < self.codec.mcus
            || self.codec.restarts >= self.codec.mcus || self.codec.metadata_segments > 4096
            || self.codec.metadata_bytes as u64 > self.capsule.source_bytes
        { return Err(RecordedDecodeError::Limit); }
        if self.codec.decoder != decoder_identity()
            || self.capsule.source_digest != sha(self.codec.encoded_sha256)
            || ContentDigest::sha256(&self.capsule.try_canonical_bytes()?) != self.capsule_digest
            || self.capsule.capture.earliest > self.capsule.capture.latest
            || self.capsule.receive_time < self.capsule.capture.earliest
            || [self.import_identity, self.import_root, self.manifest_digest, self.capsule_digest]
                .iter().any(|digest| digest.algorithm() != DigestAlgorithm::Sha256)
        { return Err(RecordedDecodeError::InvalidReceipt); }
        Ok(())
    }
    fn manifest(&self) -> Result<ObjectManifest, RecordedDecodeError> {
        let metadata = self.digest()?;
        let mut children = BTreeSet::from([
            self.import_root, self.manifest_digest, self.capsule_digest,
            sha(self.codec.encoded_sha256), sha(self.codec.luma_sha256),
        ]);
        children.remove(&metadata);
        Ok(ObjectManifest::new(slot(self.identity())?.as_str(), children, Some(metadata))?)
    }
    fn delta(&self, root: ContentDigest) -> Result<EvidenceDelta, RecordedDecodeError> {
        let name = hex(self.identity());
        Ok(EvidenceDelta {
            delta_id: format!("delta:recorded-decode:{name}"),
            family: "decode_receipt".to_owned(),
            object_id: ObjectId::parse(format!("object:recorded-decode:{name}"))?,
            prior_generation: None, new_generation: 1, validity: self.capsule.capture,
            plane: Plane::Cognition, payload_digest: self.digest()?, witness_digest: Some(root),
            operation_id: None,
        })
    }
}

fn decode_sha(d: &mut CanonicalDecoder<'_>) -> Result<[u8; 32], RecordedDecodeError> {
    let value = d.digest()?;
    if value.algorithm() != DigestAlgorithm::Sha256 { return Err(RecordedDecodeError::InvalidReceipt); }
    Ok(value.bytes())
}

impl CanonicalEncode for RecordedDecodeReceipt {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.bytes(b"FSSYREC1"); e.u32(1); e.text(RECORDED_DECODE_DOMAIN);
        e.digest(self.import_identity); e.digest(self.import_root); e.digest(self.manifest_digest);
        self.source_anchor.encode_canonical(e);
        e.u64(self.segment_index); e.u64(self.source_offset); e.digest(self.capsule_digest);
        self.capsule.encode_canonical(e); e.u32(self.width); e.u32(self.height);
        e.digest(sha(self.codec.encoded_sha256)); e.digest(sha(self.codec.luma_sha256));
        e.digest(sha(self.codec.decoder)); e.u8(interpretation_tag(self.codec.interpretation));
        for value in [self.codec.mcus, self.codec.entropy_blocks, self.codec.restarts,
            self.codec.metadata_segments, self.codec.metadata_bytes] { e.u64(value as u64); }
        e.u64(self.work_units);
    }
}

fn source_capsule(
    deployment: &ReferenceDeployment, retained: &RetainedFileImport, index: usize,
) -> Result<(SensorCapsule, ContentDigest), RecordedDecodeError> {
    let span = retained.manifest().segment_spans.get(index).ok_or(RecordedDecodeError::Unavailable)?;
    let source_batch = BatchId::parse(format!("batch:file-import:{}:c0", hex(retained.import_identity())))?;
    let batch = deployment.ledger().batches().iter().find(|b| b.batch_id == source_batch)
        .ok_or(RecordedDecodeError::Unavailable)?;
    let object = format!("object:capsule:{}", span.capsule_id.as_str());
    let delta = batch.deltas.iter().find(|d| d.object_id.as_str() == object
        && d.family == "sensor_capsule" && d.plane == Plane::Authority
        && d.prior_generation.is_none() && d.new_generation == 1)
        .ok_or(RecordedDecodeError::InvalidReceipt)?;
    if !batch.children.contains(&delta.payload_digest) { return Err(RecordedDecodeError::InvalidReceipt); }
    let bytes = deployment.publisher().spool().read(delta.payload_digest)?;
    if bytes.len() > MAX_RECORDED_DECODE_RECEIPT_BYTES
        || ContentDigest::sha256(&bytes) != delta.payload_digest
    { return Err(RecordedDecodeError::InvalidReceipt); }
    let capsule = SensorCapsule::from_canonical_bytes(&bytes)?;
    if capsule.capsule_id != span.capsule_id || capsule.source_digest != span.segment_sha256
        || capsule.source_bytes != span.len || capsule.capture != delta.validity
        || capsule.gap_before != span.gap_before
    { return Err(RecordedDecodeError::InvalidReceipt); }
    Ok((capsule, delta.payload_digest))
}

fn source(
    deployment: &ReferenceDeployment, request: &RecordedDecodeRequest, cx: &ReplayCx,
) -> Result<(RetainedFileImport, SensorCapsule, ContentDigest, Vec<u8>), RecordedDecodeError> {
    checkpoint(cx, "recorded_decode:source")?;
    validate_limits(request.decode_limits)?;
    let retained = RetainedFileImport::open(deployment, request.import_identity, request.read_limits, cx)?;
    if retained.manifest().format != "mjpeg" { return Err(RecordedDecodeError::UnsupportedMedia); }
    let span = retained.manifest().segment_spans.get(request.segment_index)
        .ok_or(RecordedDecodeError::Unavailable)?;
    if span.len > request.decode_limits.maximum_bytes as u64 { return Err(RecordedDecodeError::Limit); }
    let (capsule, digest) = source_capsule(deployment, &retained, request.segment_index)?;
    let bytes = retained.read_segment(deployment, request.segment_index, request.read_limits, cx)?;
    Ok((retained, capsule, digest, bytes))
}

/// Fully decoded pixels and provenance from a completed root-last publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedFrame {
    receipt: RecordedDecodeReceipt,
    pixels: Vec<u8>,
    publication_root: ContentDigest,
    authority_anchor: LedgerAnchor,
}

impl RecordedFrame {
    /// Decode exact retained source using the canonical codec, retain pixels and receipt, then
    /// publish the graph root and append the final typed decode delta. No inference/effect runs.
    ///
    /// Repeated successful requests are authority-idempotent. A cut after root publication but
    /// before the final delta leaves an explicit incomplete decode; repeating this call resumes
    /// it. `open` never calls an incomplete decode complete. Staged objects may remain on error.
    /// Parent cancellation is checked at composition boundaries; supply a cancellable codec
    /// budget for cancellation within a frame. A shared budget accumulates across frame calls.
    pub fn decode_and_publish(
        deployment: &mut ReferenceDeployment, request: &RecordedDecodeRequest,
        budget: &mut DecodeBudget<'_>, cx: &ReplayCx,
    ) -> Result<Self, RecordedDecodeError> {
        // Authority-idempotent fast path: a decode whose receipt batch is already committed
        // reopens from retained custody and the ledger without codec work, new claims, or a
        // new anchor. Any miss (no batch yet, including the post-root resume case) proceeds.
        if let Ok(existing) = Self::open(deployment, request, cx) {
            return Ok(existing);
        }
        let (retained, capsule, capsule_digest, encoded) = source(deployment, request, cx)?;
        let used_before = budget.used();
        let image = decode_luma(&encoded, capsule.source_digest.bytes(), request.interpretation,
            request.decode_limits, budget)?;
        checkpoint(cx, STAGE_RECORDED_DECODE)?;
        let [width, height] = image.dimensions();
        let receipt = RecordedDecodeReceipt {
            import_identity: retained.import_identity(), import_root: retained.import_root(),
            manifest_digest: retained.manifest_digest(), source_anchor: retained.authority_anchor().clone(),
            segment_index: request.segment_index as u64,
            source_offset: retained.manifest().segment_spans[request.segment_index].offset,
            capsule_digest, capsule, width, height, codec: image.receipt(),
            work_units: budget.used().checked_sub(used_before).ok_or(RecordedDecodeError::InvalidReceipt)?,
        };
        let pixels = image.pixels().to_vec();
        drop(image);
        let receipt_bytes = receipt.encoded()?;
        let manifest = receipt.manifest()?;
        let slot = slot(receipt.identity())?;
        let visible_root = deployment.publisher().root(&slot).map(|root| root.root);
        if let Some(existing) = &visible_root {
            if *existing != manifest.root() {
                return Err(RecordedDecodeError::InvalidReceipt);
            }
        }
        for bytes in [encoded.as_slice(), pixels.as_slice(), receipt_bytes.as_slice()] {
            checkpoint(cx, "recorded_decode:stage")?;
            let digest = deployment.publisher_mut().stage_object(bytes)?;
            deployment.publisher_mut().verify_object(digest)?;
        }
        // `stage_manifest` refuses a visible slot by design; a resume after the root-to-receipt
        // interruption finds the identical root already published and only owes the ledger batch.
        if visible_root.is_none() {
            deployment.publisher_mut().stage_manifest(&slot, &manifest)?;
        }
        deployment.publish_and_commit(&slot, &manifest, receipt.capsule.capture, cx)?;
        checkpoint(cx, STAGE_RECORDED_DECODE_COMMIT)?;
        let mut children = manifest.children().to_vec();
        children.push(manifest.root());
        let anchor = deployment.append_batch(batch_id(receipt.identity())?,
            vec![receipt.delta(manifest.root())?], children, cx)?;
        // No fallible work after the final authority commit: cancellation cannot erase success.
        cx.checkpoint_post_commit("recorded_decode:complete");
        Ok(Self { receipt, pixels, publication_root: manifest.root(), authority_anchor: anchor })
    }

    /// Reopen completed decoded pixels without the original input file or another codec run.
    /// Revalidates source custody, exact receipt/delta/manifest closure, and all pixel bytes.
    /// Checksums establish retained consistency; use `verify_by_replay` to reproduce the decode.
    pub fn open(
        deployment: &ReferenceDeployment, request: &RecordedDecodeRequest, cx: &ReplayCx,
    ) -> Result<Self, RecordedDecodeError> {
        let (retained, capsule, capsule_digest, _encoded) = source(deployment, request, cx)?;
        let identity = key(retained.import_root(), request.segment_index as u64, request.interpretation);
        let target = batch_id(identity)?;
        let batch = deployment.ledger().batches().iter().find(|b| b.batch_id == target)
            .ok_or(RecordedDecodeError::Unavailable)?;
        if batch.deltas.len() != 1 { return Err(RecordedDecodeError::InvalidReceipt); }
        let delta = &batch.deltas[0];
        let bytes = deployment.publisher().spool().read(delta.payload_digest)?;
        let receipt = RecordedDecodeReceipt::decode(&bytes, delta.payload_digest)?;
        if receipt.identity() != identity || receipt.import_identity != retained.import_identity()
            || receipt.import_root != retained.import_root() || receipt.manifest_digest != retained.manifest_digest()
            || receipt.source_anchor != *retained.authority_anchor() || receipt.capsule != capsule
            || receipt.capsule_digest != capsule_digest || receipt.codec.interpretation != request.interpretation
            || receipt.source_offset != retained.manifest().segment_spans[request.segment_index].offset
        { return Err(RecordedDecodeError::InvalidReceipt); }
        let maximum = request.decode_limits;
        if receipt.width > maximum.maximum_dimension || receipt.height > maximum.maximum_dimension
            || u64::from(receipt.width) * u64::from(receipt.height) > maximum.maximum_pixels as u64
            || receipt.codec.metadata_segments > maximum.maximum_markers
        { return Err(RecordedDecodeError::Limit); }
        let manifest = receipt.manifest()?;
        if *delta != receipt.delta(manifest.root())? { return Err(RecordedDecodeError::InvalidReceipt); }
        let mut children = manifest.children().to_vec(); children.push(manifest.root()); children.sort_unstable(); children.dedup();
        if batch.children != children { return Err(RecordedDecodeError::InvalidReceipt); }
        let slot = slot(identity)?;
        let visible = deployment.publisher().root(&slot).ok_or(RecordedDecodeError::Unavailable)?;
        if visible.root != manifest.root()
            || deployment.publisher().spool().read(manifest.root())? != manifest.canonical_bytes()
        { return Err(RecordedDecodeError::InvalidReceipt); }
        let pixels = deployment.publisher().spool().read(sha(receipt.codec.luma_sha256))?;
        if pixels.len() as u64 != u64::from(receipt.width) * u64::from(receipt.height)
            || ContentDigest::sha256(&pixels) != sha(receipt.codec.luma_sha256)
        { return Err(RecordedDecodeError::InvalidReceipt); }
        checkpoint(cx, "recorded_decode:read_complete")?;
        Ok(Self { receipt, pixels, publication_root: manifest.root(), authority_anchor: batch.new_anchor.clone() })
    }
    /// Reproduce the complete canonical decoder output; never changes authority or storage.
    pub fn verify_by_replay(
        &self, deployment: &ReferenceDeployment, request: &RecordedDecodeRequest,
        budget: &mut DecodeBudget<'_>, cx: &ReplayCx,
    ) -> Result<(), RecordedDecodeError> {
        let reopened = Self::open(deployment, request, cx)?;
        if reopened != *self { return Err(RecordedDecodeError::InvalidReceipt); }
        let (_, capsule, _, bytes) = source(deployment, request, cx)?;
        let before = budget.used();
        let image = decode_luma(&bytes, capsule.source_digest.bytes(), request.interpretation,
            request.decode_limits, budget)?;
        if image.dimensions() != self.receipt.dimensions() || image.receipt() != self.receipt.codec
            || image.pixels() != self.pixels || budget.used() - before != self.receipt.work_units
        { return Err(RecordedDecodeError::InvalidReceipt); }
        checkpoint(cx, "recorded_decode:replay_complete")?;
        Ok(())
    }
    /// Complete source and codec provenance.
    #[must_use]
    pub fn receipt(&self) -> &RecordedDecodeReceipt { &self.receipt }
    /// Tight row-major full-range Y, not RGB and not an oriented display rendering.
    #[must_use]
    pub fn pixels(&self) -> &[u8] { &self.pixels }
    /// Durable immutable graph root, also witnessed by the final decode delta.
    #[must_use]
    pub fn publication_root(&self) -> ContentDigest { self.publication_root }
    /// Exact final decode-receipt anchor; retries do not substitute the latest global anchor.
    #[must_use]
    pub fn authority_anchor(&self) -> &LedgerAnchor { &self.authority_anchor }
    /// Portable binary PGM rendering. The export digest differs from the raw luma digest.
    #[must_use]
    pub fn pgm_bytes(&self) -> Vec<u8> {
        let mut bytes = format!("P5\n{} {}\n255\n", self.receipt.width, self.receipt.height).into_bytes();
        bytes.extend_from_slice(&self.pixels);
        bytes
    }
}

#[cfg(test)]
mod tests;
