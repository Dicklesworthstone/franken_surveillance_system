#![forbid(unsafe_code)]
//! Retained receipts of source-determined JPEG decode refusals, and the per-capsule decode
//! outcome composition (fss-2h5zq.41).
//!
//! A successful decode is receipted by [`RecordedDecodeReceipt`] (`fss.recorded_luma_receipt.v2`)
//! and its bytes are unchanged here. A refusal the source itself determines (the canonical codec
//! found the exact custody bytes malformed, truncated, outside the admitted coding subset under
//! the requested interpretation, or outside the requested decode bounds) is never silent: it is
//! retained as a [`RecordedDecodeRefusal`] (`fss.recorded_decode_refusal.v1`) that binds the same
//! import, anchor, span, capsule and decoder identity as a successful receipt, plus the exact
//! decode limits and the registered error identity. It is published root-last and referenced by
//! a cognition `decode_receipt` delta, exactly like a decoded frame.
//!
//! Refusals that do not describe the source are never receipted and stay typed errors:
//! custody failures (refused before any codec work), caller budget exhaustion, cancellation
//! (a cancelled decode exposes no authority), request-level bounds and privacy-mask errors.
//! A refusal is a derived record, never retained evidence and never an absence claim.

use std::collections::BTreeSet;

use fss_codec_mjpeg::{DecodeError, decode_luma, decoder_identity};
use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    DigestAlgorithm, EvidenceDelta, LedgerAnchor, ObjectId, Plane, SensorCapsule,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use super::super::privacy_mask::{binding_digest, current_mask, decode_marker, encode_marker};
use super::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeError,
    RecordedDecodeRequest, RecordedFrame, checkpoint, decode_sha, hex, interpretation_tag, sha,
    source, validate_limits,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Registered digest domain of a retained decode refusal (SCHEMA-DOMAIN-RECORDED-DECODE-REFUSAL-001).
pub const RECORDED_DECODE_REFUSAL_DOMAIN: &str = "fss.recorded_decode_refusal.v1";
/// Maximum canonical refusal allocation; a refusal holds identities, never pixels.
pub const MAX_RECORDED_DECODE_REFUSAL_BYTES: usize = 4_096;
const MAGIC: &[u8] = b"FSSYRFU1";
const VERSION: u32 = 1;

/// Why the canonical codec refused the exact custody bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalKind {
    /// Invalid byte syntax, tables, entropy, padding or restart sequence.
    Malformed,
    /// Coding or component layout outside the admitted subset for the requested interpretation.
    Unsupported,
    /// A required byte is absent; no concealment is performed.
    Truncated,
    /// Dimensions, pixels, markers or coefficients exceed the bound limits.
    Bounds,
}

impl RefusalKind {
    /// Source-determined codec refusals only; budget, cancellation and digest refusals are not.
    #[must_use]
    pub fn from_codec(error: DecodeError) -> Option<Self> {
        match error {
            DecodeError::Malformed => Some(Self::Malformed),
            DecodeError::Unsupported => Some(Self::Unsupported),
            DecodeError::Truncated => Some(Self::Truncated),
            DecodeError::Limit => Some(Self::Bounds),
            DecodeError::SourceMismatch | DecodeError::BudgetExhausted | DecodeError::Cancelled => {
                None
            }
        }
    }
    /// Stable lowercase label (`malformed`, `unsupported`, `truncated`, `bounds`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Unsupported => "unsupported",
            Self::Truncated => "truncated",
            Self::Bounds => "bounds",
        }
    }
    /// Registered error identity (registries/ERRORS.md) the decode operation reports.
    #[must_use]
    pub const fn error_id(self) -> &'static str {
        match self {
            Self::Bounds => "ERR-DECODE-BOUNDS-001",
            Self::Malformed | Self::Unsupported | Self::Truncated => "ERR-DECODE-001",
        }
    }
    const fn tag(self) -> u8 {
        match self {
            Self::Malformed => 1,
            Self::Unsupported => 2,
            Self::Truncated => 3,
            Self::Bounds => 4,
        }
    }
    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Malformed),
            2 => Some(Self::Unsupported),
            3 => Some(Self::Truncated),
            4 => Some(Self::Bounds),
            _ => None,
        }
    }
}

/// Canonical limit axes: bytes, dimension, pixels, markers.
fn limit_axes(limits: DecodeLimits) -> [u64; 4] {
    [
        limits.maximum_bytes as u64,
        u64::from(limits.maximum_dimension),
        limits.maximum_pixels as u64,
        limits.maximum_markers as u64,
    ]
}
fn axes_limits(axes: [u64; 4]) -> Result<DecodeLimits, RecordedDecodeError> {
    let size = |value: u64| usize::try_from(value).map_err(|_| RecordedDecodeError::Limit);
    Ok(DecodeLimits {
        maximum_bytes: size(axes[0])?,
        maximum_dimension: u32::try_from(axes[1]).map_err(|_| RecordedDecodeError::Limit)?,
        maximum_pixels: size(axes[2])?,
        maximum_markers: size(axes[3])?,
    })
}
fn encode_limits(e: &mut CanonicalEncoder, axes: [u64; 4]) {
    for axis in axes {
        e.u64(axis);
    }
}

fn refusal_key(
    import_root: ContentDigest,
    segment: u64,
    interpretation: ComponentInterpretation,
    mask: ContentDigest,
    limits: [u64; 4],
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text("fss.recorded_decode_refusal_key.v1");
    e.digest(import_root);
    e.u64(segment);
    e.digest(sha(decoder_identity()));
    e.u8(interpretation_tag(interpretation));
    e.digest(mask);
    encode_limits(&mut e, limits);
    ContentDigest::sha256(&e.finish())
}
fn refusal_slot(identity: ContentDigest) -> Result<SlotName, RecordedDecodeError> {
    SlotName::parse(&format!("fd-refusal-{}", hex(identity)))
        .map_err(|_| RecordedDecodeError::InvalidReceipt)
}
fn refusal_batch(identity: ContentDigest) -> Result<BatchId, RecordedDecodeError> {
    Ok(BatchId::parse(format!(
        "batch:recorded-decode:refusal:{}",
        hex(identity)
    ))?)
}

/// Immutable record of one source-determined refusal: the same source lineage as a successful
/// receipt, the decoder generation, the exact limits and the registered error identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedDecodeRefusal {
    import_identity: ContentDigest,
    import_root: ContentDigest,
    manifest_digest: ContentDigest,
    source_anchor: LedgerAnchor,
    segment_index: u64,
    source_offset: u64,
    capsule_digest: ContentDigest,
    capsule: SensorCapsule,
    decoder: [u8; 32],
    interpretation: ComponentInterpretation,
    limits: [u64; 4],
    kind: RefusalKind,
    work_units: u64,
    mask_policy: Option<ContentDigest>,
}

impl RecordedDecodeRefusal {
    /// Derived identity: source span, decoder generation, interpretation, mask binding and
    /// limits (a bounds refusal depends on them); work accounting is not part of it.
    #[must_use]
    pub fn identity(&self) -> ContentDigest {
        refusal_key(
            self.import_root,
            self.segment_index,
            self.interpretation,
            binding_digest(self.mask_policy),
            self.limits,
        )
    }
    /// Why the codec refused the bytes.
    #[must_use]
    pub fn kind(&self) -> RefusalKind {
        self.kind
    }
    /// Registered error identity of the refusal.
    #[must_use]
    pub fn error_id(&self) -> &'static str {
        self.kind.error_id()
    }
    /// Original source capsule (source digest, byte count, capture interval).
    #[must_use]
    pub fn capsule(&self) -> &SensorCapsule {
        &self.capsule
    }
    /// SHA-256 of the canonical capsule bytes.
    #[must_use]
    pub fn capsule_digest(&self) -> ContentDigest {
        self.capsule_digest
    }
    /// Canonical fss-codec-mjpeg decoder identity (the decoder generation).
    #[must_use]
    pub fn decoder(&self) -> [u8; 32] {
        self.decoder
    }
    /// Exact decode limits the refusal was observed under.
    pub fn limits(&self) -> Result<DecodeLimits, RecordedDecodeError> {
        axes_limits(self.limits)
    }
    /// Codec work units spent before the refusal.
    #[must_use]
    pub fn work_units(&self) -> u64 {
        self.work_units
    }
    /// Original immutable segment index.
    #[must_use]
    pub fn segment_index(&self) -> u64 {
        self.segment_index
    }
    /// Byte offset of the segment in the imported file.
    #[must_use]
    pub fn source_offset(&self) -> u64 {
        self.source_offset
    }
    /// Exact import identity.
    #[must_use]
    pub fn import_identity(&self) -> ContentDigest {
        self.import_identity
    }
    /// Import completion anchor.
    #[must_use]
    pub fn source_anchor(&self) -> &LedgerAnchor {
        &self.source_anchor
    }
    /// Canonical bytes under the bounded, versioned format.
    pub fn encoded(&self) -> Result<Vec<u8>, RecordedDecodeError> {
        self.validate()?;
        let bytes = self.try_canonical_bytes()?;
        if bytes.len() > MAX_RECORDED_DECODE_REFUSAL_BYTES {
            return Err(RecordedDecodeError::Limit);
        }
        Ok(bytes)
    }
    /// Content address of the complete refusal record.
    pub fn digest(&self) -> Result<ContentDigest, RecordedDecodeError> {
        Ok(ContentDigest::sha256(&self.encoded()?))
    }
    /// Decodes authority-addressed refusal bytes; unknown versions, truncation, suffixes and
    /// non-canonical encodings fail closed.
    pub fn decode(bytes: &[u8], expected: ContentDigest) -> Result<Self, RecordedDecodeError> {
        if bytes.len() > MAX_RECORDED_DECODE_REFUSAL_BYTES {
            return Err(RecordedDecodeError::Limit);
        }
        if ContentDigest::sha256(bytes) != expected {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != MAGIC || d.u32()? != VERSION || d.text()? != RECORDED_DECODE_REFUSAL_DOMAIN
        {
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
        let decoder = decode_sha(&mut d)?;
        let interpretation = match d.u8()? {
            0 => ComponentInterpretation::Grayscale,
            1 => ComponentInterpretation::YCbCr,
            _ => return Err(RecordedDecodeError::InvalidReceipt),
        };
        let limits = [d.u64()?, d.u64()?, d.u64()?, d.u64()?];
        let kind = RefusalKind::from_tag(d.u8()?).ok_or(RecordedDecodeError::InvalidReceipt)?;
        if d.text()? != kind.error_id() {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        let work_units = d.u64()?;
        let mask_policy = decode_marker(&mut d)?;
        d.ensure_finished()?;
        let refusal = Self {
            import_identity,
            import_root,
            manifest_digest,
            source_anchor,
            segment_index,
            source_offset,
            capsule_digest,
            capsule,
            decoder,
            interpretation,
            limits,
            kind,
            work_units,
            mask_policy,
        };
        if refusal.encoded()? != bytes {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        Ok(refusal)
    }
    fn validate(&self) -> Result<(), RecordedDecodeError> {
        let limits = axes_limits(self.limits)?;
        validate_limits(limits)?;
        if self.capsule.source_bytes == 0 || self.capsule.source_bytes > limits.maximum_bytes as u64
        {
            return Err(RecordedDecodeError::Limit);
        }
        if self.decoder != decoder_identity()
            || self.capsule.source_digest.algorithm() != DigestAlgorithm::Sha256
            || ContentDigest::sha256(&self.capsule.try_canonical_bytes()?) != self.capsule_digest
            || self.capsule.capture.earliest > self.capsule.capture.latest
            || self.capsule.receive_time < self.capsule.capture.earliest
            || [
                self.import_identity,
                self.import_root,
                self.manifest_digest,
                self.capsule_digest,
            ]
            .iter()
            .any(|digest| digest.algorithm() != DigestAlgorithm::Sha256)
        {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        Ok(())
    }
    fn manifest(&self) -> Result<ObjectManifest, RecordedDecodeError> {
        let metadata = self.digest()?;
        let mut children = BTreeSet::from([
            self.import_root,
            self.manifest_digest,
            self.capsule_digest,
            self.capsule.source_digest,
        ]);
        children.remove(&metadata);
        Ok(ObjectManifest::new(
            refusal_slot(self.identity())?.as_str(),
            children,
            Some(metadata),
        )?)
    }
    fn delta(&self, root: ContentDigest) -> Result<EvidenceDelta, RecordedDecodeError> {
        let name = hex(self.identity());
        Ok(EvidenceDelta {
            delta_id: format!("delta:recorded-decode-refusal:{name}"),
            family: "decode_receipt".to_owned(),
            object_id: ObjectId::parse(format!("object:recorded-decode-refusal:{name}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: self.capsule.capture,
            plane: Plane::Cognition,
            payload_digest: self.digest()?,
            witness_digest: Some(root),
            operation_id: None,
        })
    }
}

impl CanonicalEncode for RecordedDecodeRefusal {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.bytes(MAGIC);
        e.u32(VERSION);
        e.text(RECORDED_DECODE_REFUSAL_DOMAIN);
        e.digest(self.import_identity);
        e.digest(self.import_root);
        e.digest(self.manifest_digest);
        self.source_anchor.encode_canonical(e);
        e.u64(self.segment_index);
        e.u64(self.source_offset);
        e.digest(self.capsule_digest);
        self.capsule.encode_canonical(e);
        e.digest(sha(self.decoder));
        e.u8(interpretation_tag(self.interpretation));
        encode_limits(e, self.limits);
        e.u8(self.kind.tag());
        e.text(self.kind.error_id());
        e.u64(self.work_units);
        encode_marker(e, self.mask_policy);
    }
}

/// A refusal published root-last and committed by its final `decode_receipt` delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedRefusal {
    refusal: RecordedDecodeRefusal,
    publication_root: ContentDigest,
    authority_anchor: LedgerAnchor,
}

impl RetainedRefusal {
    /// The retained refusal record.
    #[must_use]
    pub fn refusal(&self) -> &RecordedDecodeRefusal {
        &self.refusal
    }
    /// Durable graph root witnessed by the refusal delta.
    #[must_use]
    pub fn publication_root(&self) -> ContentDigest {
        self.publication_root
    }
    /// Anchor of the refusal batch.
    #[must_use]
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.authority_anchor
    }

    /// Reopens the committed refusal for this exact request (source, interpretation, current
    /// mask binding and limits) from the ledger and spool, revalidating source custody and the
    /// complete receipt/delta/manifest/root closure. `Unavailable` when none was committed.
    pub fn open(
        deployment: &ReferenceDeployment,
        request: &RecordedDecodeRequest,
        cx: &ReplayCx,
    ) -> Result<Self, RecordedDecodeError> {
        let (retained, capsule, capsule_digest, _bytes) = source(deployment, request, cx)?;
        let mask = current_mask(deployment, &capsule.sensor_id)?;
        let identity = refusal_key(
            retained.import_root(),
            request.segment_index as u64,
            request.interpretation,
            mask.digest(),
            limit_axes(request.decode_limits),
        );
        let target = refusal_batch(identity)?;
        let batch = deployment
            .ledger()
            .batches()
            .iter()
            .find(|b| b.batch_id == target)
            .ok_or(RecordedDecodeError::Unavailable)?;
        if batch.deltas.len() != 1 {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        let delta = &batch.deltas[0];
        let bytes = deployment.publisher().spool().read(delta.payload_digest)?;
        let refusal = RecordedDecodeRefusal::decode(&bytes, delta.payload_digest)?;
        if refusal.identity() != identity
            || refusal.import_identity != retained.import_identity()
            || refusal.import_root != retained.import_root()
            || refusal.manifest_digest != retained.manifest_digest()
            || refusal.source_anchor != *retained.authority_anchor()
            || refusal.capsule != capsule
            || refusal.capsule_digest != capsule_digest
            || refusal.interpretation != request.interpretation
            || refusal.limits != limit_axes(request.decode_limits)
            || refusal.mask_policy != mask.policy_digest()
            || refusal.source_offset
                != retained.manifest().segment_spans[request.segment_index].offset
        {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        let manifest = refusal.manifest()?;
        if *delta != refusal.delta(manifest.root())? {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        let mut children = manifest.children().to_vec();
        children.push(manifest.root());
        children.sort_unstable();
        children.dedup();
        if batch.children != children {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        let visible = deployment
            .publisher()
            .root(&refusal_slot(identity)?)
            .ok_or(RecordedDecodeError::Unavailable)?;
        if visible.root != manifest.root()
            || deployment.publisher().spool().read(manifest.root())? != manifest.canonical_bytes()
        {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        checkpoint(cx, "recorded_decode:refusal_read_complete")?;
        Ok(Self {
            refusal,
            publication_root: manifest.root(),
            authority_anchor: batch.new_anchor.clone(),
        })
    }

    /// Re-runs the canonical codec on the retained custody bytes and requires the identical
    /// refusal kind and work accounting; never changes authority or storage.
    pub fn verify_by_replay(
        &self,
        deployment: &ReferenceDeployment,
        request: &RecordedDecodeRequest,
        budget: &mut DecodeBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<(), RecordedDecodeError> {
        if Self::open(deployment, request, cx)? != *self {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        let (_, capsule, _, bytes) = source(deployment, request, cx)?;
        let before = budget.used();
        let observed = match decode_luma(
            &bytes,
            capsule.source_digest.bytes(),
            request.interpretation,
            request.decode_limits,
            budget,
        ) {
            Ok(_) => return Err(RecordedDecodeError::InvalidReceipt),
            Err(error) => {
                RefusalKind::from_codec(error).ok_or(RecordedDecodeError::Codec(error))?
            }
        };
        if observed != self.refusal.kind || budget.used() - before != self.refusal.work_units {
            return Err(RecordedDecodeError::InvalidReceipt);
        }
        checkpoint(cx, "recorded_decode:refusal_replay_complete")?;
        Ok(())
    }
}

/// Outcome of decoding one retained capsule: never silent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapsuleDecode {
    /// Decoded, masked and published with its `fss.recorded_luma_receipt.v2` receipt.
    Decoded(Box<RecordedFrame>),
    /// The codec refused the exact custody bytes; the refusal is published and receipted.
    Refused(Box<RetainedRefusal>),
}

/// Decodes one retained capsule of a complete import and retains its outcome.
///
/// Custody is verified before any codec work ([`super::verify_custody`]; a mismatch is
/// [`RecordedDecodeError::CustodyMismatch`] and nothing is decoded). A successful decode is
/// [`RecordedFrame::decode_and_publish`]. A source-determined codec refusal is published
/// root-last as a [`RecordedDecodeRefusal`] and committed by a cognition `decode_receipt` delta in
/// batch `batch:recorded-decode:refusal:<identity>`. Repeating the call reopens a committed
/// refusal without codec work and resumes one cut between root and delta. Budget exhaustion,
/// cancellation, custody, request-bound and privacy-mask failures return typed errors and retain
/// nothing new.
pub fn decode_capsule(
    deployment: &mut ReferenceDeployment,
    request: &RecordedDecodeRequest,
    budget: &mut DecodeBudget<'_>,
    cx: &ReplayCx,
) -> Result<CapsuleDecode, RecordedDecodeError> {
    match RetainedRefusal::open(deployment, request, cx) {
        Ok(retained) => return Ok(CapsuleDecode::Refused(Box::new(retained))),
        Err(RecordedDecodeError::Unavailable) => {}
        Err(error) => return Err(error),
    }
    let before = budget.used();
    let kind = match RecordedFrame::decode_and_publish(deployment, request, budget, cx) {
        Ok(frame) => return Ok(CapsuleDecode::Decoded(Box::new(frame))),
        Err(RecordedDecodeError::Codec(error)) => match RefusalKind::from_codec(error) {
            Some(kind) => kind,
            None => return Err(RecordedDecodeError::Codec(error)),
        },
        Err(error) => return Err(error),
    };
    let work_units = budget
        .used()
        .checked_sub(before)
        .ok_or(RecordedDecodeError::InvalidReceipt)?;
    checkpoint(cx, "recorded_decode:refused")?;
    let (retained, capsule, capsule_digest, encoded) = source(deployment, request, cx)?;
    let mask = current_mask(deployment, &capsule.sensor_id)?;
    let refusal = RecordedDecodeRefusal {
        import_identity: retained.import_identity(),
        import_root: retained.import_root(),
        manifest_digest: retained.manifest_digest(),
        source_anchor: retained.authority_anchor().clone(),
        segment_index: request.segment_index as u64,
        source_offset: retained.manifest().segment_spans[request.segment_index].offset,
        capsule_digest,
        capsule,
        decoder: decoder_identity(),
        interpretation: request.interpretation,
        limits: limit_axes(request.decode_limits),
        kind,
        work_units,
        mask_policy: mask.policy_digest(),
    };
    let refusal_bytes = refusal.encoded()?;
    let manifest = refusal.manifest()?;
    let slot = refusal_slot(refusal.identity())?;
    let visible_root = deployment.publisher().root(&slot).map(|root| root.root);
    if let Some(existing) = &visible_root
        && *existing != manifest.root()
    {
        return Err(RecordedDecodeError::InvalidReceipt);
    }
    for bytes in [encoded.as_slice(), refusal_bytes.as_slice()] {
        checkpoint(cx, "recorded_decode:refusal_stage")?;
        let digest = deployment.publisher_mut().stage_object(bytes)?;
        deployment.publisher_mut().verify_object(digest)?;
    }
    if visible_root.is_none() {
        deployment
            .publisher_mut()
            .stage_manifest(&slot, &manifest)?;
    }
    deployment.publish_and_commit(&slot, &manifest, refusal.capsule.capture, cx)?;
    checkpoint(cx, "recorded_decode:refusal_commit")?;
    let mut children = manifest.children().to_vec();
    children.push(manifest.root());
    let anchor = deployment.append_batch(
        refusal_batch(refusal.identity())?,
        vec![refusal.delta(manifest.root())?],
        children,
        cx,
    )?;
    cx.checkpoint_post_commit("recorded_decode:refusal_complete");
    Ok(CapsuleDecode::Refused(Box::new(RetainedRefusal {
        refusal,
        publication_root: manifest.root(),
        authority_anchor: anchor,
    })))
}
