#![forbid(unsafe_code)]
//! Canonical `MediaDerivativeReceipt` lineage (`DOC-041`, bead `fss-x4a.5.41`).
//!
//! Ensures every crop, resize, colorspace conversion, transcode, clip, thumbnail, privacy
//! redaction, enhancement, or model tensor input remains cryptographically linked to retained
//! source custody — or carries an explicit, policy-authorized source-omission witness — and
//! NEVER impersonates raw source evidence (`INV-003`, `INV-040`).
//!
//! Core invariants:
//! - `is_source_custody` is strictly `false` on both construction and canonical decode.
//! - Multi-stage transformation chains compose via `parent_derivative_digests` without losing
//!   intermediate digests or privacy boundaries.
//! - Mask-before-egress verification (`verify_egress_eligible`) refuses external egress when
//!   privacy redaction is required but not proven in the receipt's transform chain.
//! - Nondeterministic accelerator paths must explicitly declare `ReproducibilityClass::BoundedTolerance`
//!   or `NondeterministicHardware` and never masquerade as `BitExactScalar`.

use core::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, Generation, TimestampNs,
};

use crate::buffer_accounting::MAX_OWNER_ID_BYTES;
use crate::source_lineage::{MAX_SOURCE_SPANS, MAX_TRANSFORM_STEPS, SourceByteSpan, TransformStep};

/// Registered digest domain for canonical media derivative receipts
/// (`SCHEMA-DOMAIN-TENSOR-MEDIA-DERIVATIVE-RECEIPT-001`).
pub const MEDIA_DERIVATIVE_RECEIPT_DOMAIN: &str = "fss.tensor.media_derivative_receipt.v1";

/// Canonical binary format version for [`MediaDerivativeReceipt`].
pub const MEDIA_DERIVATIVE_RECEIPT_FORMAT_VERSION: u32 = 1;

/// Maximum parent derivative receipts chained into one composite derivative.
pub const MAX_PARENT_DERIVATIVES: usize = 32;

/// Closed taxonomy of media derivatives covered by `DOC-041`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MediaDerivativeKind {
    /// Spatial crop extracted from a decoded frame.
    Crop,
    /// Resized image derivative.
    Resize,
    /// Color-space converted frame.
    ColorConvert,
    /// Re-encoded / transcoded media derivative (e.g., JPEG/MJPEG rendition).
    Transcode,
    /// Time-bounded exported clip derivative.
    Clip,
    /// Low-resolution preview thumbnail derivative.
    Thumbnail,
    /// Privacy-masked / redacted derivative.
    PrivacyRedaction,
    /// Deterministic visual enhancement derivative.
    Enhancement,
    /// Canonical model input tensor derivative.
    ModelTensorInput,
}

impl MediaDerivativeKind {
    /// Stable machine-readable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Crop => "crop",
            Self::Resize => "resize",
            Self::ColorConvert => "color_convert",
            Self::Transcode => "transcode",
            Self::Clip => "clip",
            Self::Thumbnail => "thumbnail",
            Self::PrivacyRedaction => "privacy_redaction",
            Self::Enhancement => "enhancement",
            Self::ModelTensorInput => "model_tensor_input",
        }
    }
}

impl CanonicalEncode for MediaDerivativeKind {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::Crop => 1,
            Self::Resize => 2,
            Self::ColorConvert => 3,
            Self::Transcode => 4,
            Self::Clip => 5,
            Self::Thumbnail => 6,
            Self::PrivacyRedaction => 7,
            Self::Enhancement => 8,
            Self::ModelTensorInput => 9,
        });
    }
}

impl CanonicalDecode for MediaDerivativeKind {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Crop),
            2 => Ok(Self::Resize),
            3 => Ok(Self::ColorConvert),
            4 => Ok(Self::Transcode),
            5 => Ok(Self::Clip),
            6 => Ok(Self::Thumbnail),
            7 => Ok(Self::PrivacyRedaction),
            8 => Ok(Self::Enhancement),
            9 => Ok(Self::ModelTensorInput),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Explicit source custody linkage or authorized omission record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceCustodyBinding {
    /// Linked directly to a retained upstream `EvidenceAnchor` and exact source byte spans.
    RetainedAnchor {
        /// Digest of the upstream `EvidenceAnchor` / source custody object.
        evidence_anchor_digest: ContentDigest,
        /// Exact source byte spans contributing to this derivative.
        source_spans: Vec<SourceByteSpan>,
    },
    /// Ephemeral/unretained source input with explicit policy-authorized omission witness.
    ExplicitOmission {
        /// Machine-readable omission reason (e.g., `ephemeral_live_preview_policy`).
        omission_reason: String,
        /// Digest of the owner retention/privacy policy authorizing source omission.
        omission_policy_digest: ContentDigest,
    },
}

impl CanonicalEncode for SourceCustodyBinding {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::RetainedAnchor {
                evidence_anchor_digest,
                source_spans,
            } => {
                encoder.u8(1);
                encoder.digest(*evidence_anchor_digest);
                encoder.u64(source_spans.len() as u64);
                for span in source_spans {
                    span.encode_canonical(encoder);
                }
            }
            Self::ExplicitOmission {
                omission_reason,
                omission_policy_digest,
            } => {
                encoder.u8(2);
                encoder.text(omission_reason);
                encoder.digest(*omission_policy_digest);
            }
        }
    }
}

impl CanonicalDecode for SourceCustodyBinding {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => {
                let evidence_anchor_digest = decoder.digest()?;
                let count = usize::try_from(decoder.u64()?)
                    .map_err(|_| ContractError::InvalidIdentifier)?;
                if count == 0 || count > MAX_SOURCE_SPANS {
                    return Err(ContractError::InvalidIdentifier);
                }
                let mut source_spans = Vec::with_capacity(count);
                for _ in 0..count {
                    source_spans.push(SourceByteSpan::decode_canonical(decoder)?);
                }
                Ok(Self::RetainedAnchor {
                    evidence_anchor_digest,
                    source_spans,
                })
            }
            2 => {
                let omission_reason = decoder.text()?.to_owned();
                if check_clean_no_latest(&omission_reason, "omission_reason").is_err() {
                    return Err(ContractError::InvalidIdentifier);
                }
                let omission_policy_digest = decoder.digest()?;
                Ok(Self::ExplicitOmission {
                    omission_reason,
                    omission_policy_digest,
                })
            }
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Honest reproducibility and loss declaration for the derivative computation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReproducibilityClass {
    /// Bit-exact deterministic pure-Rust scalar reference path.
    BitExactScalar,
    /// Deterministic within registered numeric tolerance against scalar reference.
    BoundedTolerance,
    /// Optional hardware/accelerator path whose non-bit-exact behavior is explicitly disclosed.
    NondeterministicHardware,
}

impl CanonicalEncode for ReproducibilityClass {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::BitExactScalar => 1,
            Self::BoundedTolerance => 2,
            Self::NondeterministicHardware => 3,
        });
    }
}

impl CanonicalDecode for ReproducibilityClass {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::BitExactScalar),
            2 => Ok(Self::BoundedTolerance),
            3 => Ok(Self::NondeterministicHardware),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Root-last publication state of the derivative bytes + receipt pair.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DerivativePublicationState {
    /// Bytes staged; receipt root not yet published (must NOT be exposed as durable).
    Staged,
    /// Receipt root published last after derivative bytes became durable.
    RootPublished,
    /// Tombstoned / deleted under graph-complete deletion policy.
    DeletedTombstone,
}

impl CanonicalEncode for DerivativePublicationState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(match self {
            Self::Staged => 1,
            Self::RootPublished => 2,
            Self::DeletedTombstone => 3,
        });
    }
}

impl CanonicalDecode for DerivativePublicationState {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Staged),
            2 => Ok(Self::RootPublished),
            3 => Ok(Self::DeletedTombstone),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Typed fail-closed refusal for `MediaDerivativeReceipt` operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DerivativeReceiptError {
    /// Identifier, format label, or generation is malformed or uses `"latest"`.
    InvalidField(&'static str),
    /// Transform chain or source custody binding is invalid.
    InvalidLineage(&'static str),
    /// Egress refused because mask-before-egress or root-last publication is not satisfied.
    EgressDenied(&'static str),
    /// Limit on parent derivatives, spans, or transforms exceeded.
    LimitExceeded(&'static str),
    /// Cooperative cancellation observed before sealing receipt.
    Cancelled,
}

impl fmt::Display for DerivativeReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(f_name) => write!(f, "invalid media derivative field: {f_name}"),
            Self::InvalidLineage(why) => write!(f, "invalid media derivative lineage: {why}"),
            Self::EgressDenied(why) => write!(f, "media derivative egress denied: {why}"),
            Self::LimitExceeded(what) => write!(f, "media derivative limit exceeded: {what}"),
            Self::Cancelled => write!(f, "media derivative receipt sealing cancelled"),
        }
    }
}

impl std::error::Error for DerivativeReceiptError {}

/// Canonical, tamper-evident lineage receipt for any media derivative (`DOC-041`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaDerivativeReceipt {
    /// Format version (`MEDIA_DERIVATIVE_RECEIPT_FORMAT_VERSION`).
    pub format_version: u32,
    /// Stable receipt identifier.
    pub receipt_id: String,
    /// Exact derivative class.
    pub kind: MediaDerivativeKind,
    /// Content digest of the derivative payload bytes.
    pub derivative_digest: ContentDigest,
    /// Exact byte length of the derivative payload (`> 0`).
    pub derivative_bytes: u64,
    /// Machine-readable output format/profile (e.g., `image/jpeg;baseline-q85`, `tensor/u8`).
    pub format_profile: String,
    /// Source custody anchor + spans OR explicit policy-authorized source omission.
    pub source_binding: SourceCustodyBinding,
    /// Ordered parent `MediaDerivativeReceipt` digests for multi-stage derivative composition.
    pub parent_derivative_digests: Vec<ContentDigest>,
    /// Ordered transform chain producing this derivative.
    pub transforms: Vec<TransformStep>,
    /// Pinned implementation/toolchain/numeric-policy identity string (no `"latest"`).
    pub implementation_identity: String,
    /// Pinned generation fence (`!= 0`).
    pub generation: Generation,
    /// Privacy policy generation digest under which masking/redaction was evaluated.
    pub privacy_policy_digest: ContentDigest,
    /// Retention/deletion lineage group digest for graph-complete deletion.
    pub retention_group_digest: ContentDigest,
    /// Whether this derivative is lossy relative to its input.
    pub is_lossy: bool,
    /// Whether privacy masking has been applied and attested in `transforms` or parent chain.
    pub privacy_masked: bool,
    /// Honest reproducibility class.
    pub reproducibility: ReproducibilityClass,
    /// Root-last publication state.
    pub publication_state: DerivativePublicationState,
    /// Creation timestamp and explicit bounded clock uncertainty in nanoseconds.
    pub created_at_ns: TimestampNs,
    /// Non-negative clock uncertainty bound in nanoseconds.
    pub clock_uncertainty_ns: u64,
    /// Always `false`: derivatives NEVER inherit raw source custody status.
    pub is_source_custody: bool,
    /// Domain-separated SHA-256 digest over all fields above.
    pub receipt_digest: ContentDigest,
}

fn check_clean_no_latest(val: &str, field: &'static str) -> Result<(), DerivativeReceiptError> {
    if val.is_empty()
        || val.len() > MAX_OWNER_ID_BYTES
        || val
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(DerivativeReceiptError::InvalidField(field));
    }
    if val
        .split(['-', '_', ':', '/', '@', '.', '+'])
        .any(|tok| tok.eq_ignore_ascii_case("latest"))
    {
        return Err(DerivativeReceiptError::InvalidField(field));
    }
    Ok(())
}

/// Builder input for sealing a [`MediaDerivativeReceipt`].
#[derive(Clone, Debug)]
pub struct DerivativeReceiptRequest {
    /// Stable receipt identifier.
    pub receipt_id: String,
    /// Derivative category.
    pub kind: MediaDerivativeKind,
    /// Content digest of the derivative payload.
    pub derivative_digest: ContentDigest,
    /// Positive derivative payload size in bytes.
    pub derivative_bytes: u64,
    /// Output format/profile identifier.
    pub format_profile: String,
    /// Source custody binding or explicit omission witness.
    pub source_binding: SourceCustodyBinding,
    /// Optional upstream derivative receipts chained into this derivative.
    pub parent_receipts: Vec<MediaDerivativeReceipt>,
    /// Ordered transforms applied at this stage.
    pub transforms: Vec<TransformStep>,
    /// Implementation/toolchain/numeric policy identity.
    pub implementation_identity: String,
    /// Pinned generation (`!= 0`).
    pub generation: Generation,
    /// Privacy policy digest.
    pub privacy_policy_digest: ContentDigest,
    /// Retention/deletion lineage group digest.
    pub retention_group_digest: ContentDigest,
    /// Lossy transformation flag.
    pub is_lossy: bool,
    /// Reproducibility class.
    pub reproducibility: ReproducibilityClass,
    /// Root-last publication state.
    pub publication_state: DerivativePublicationState,
    /// Creation timestamp.
    pub created_at_ns: TimestampNs,
    /// Clock uncertainty bound in nanoseconds.
    pub clock_uncertainty_ns: u64,
}

impl MediaDerivativeReceipt {
    /// Seals a verified `MediaDerivativeReceipt`, composing parent derivative digests and privacy
    /// masking provenance while strictly enforcing `is_source_custody == false`.
    pub fn seal(
        req: DerivativeReceiptRequest,
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<Self, DerivativeReceiptError> {
        if is_cancelled() {
            return Err(DerivativeReceiptError::Cancelled);
        }
        check_clean_no_latest(&req.receipt_id, "receipt_id")?;
        check_clean_no_latest(&req.format_profile, "format_profile")?;
        check_clean_no_latest(&req.implementation_identity, "implementation_identity")?;
        if req.derivative_bytes == 0 {
            return Err(DerivativeReceiptError::InvalidField(
                "derivative_bytes_zero",
            ));
        }
        if req.generation.0 == 0 {
            return Err(DerivativeReceiptError::InvalidField("generation_zero"));
        }
        if req.parent_receipts.len() > MAX_PARENT_DERIVATIVES {
            return Err(DerivativeReceiptError::LimitExceeded("parent_receipts"));
        }
        if req.transforms.is_empty() {
            return Err(DerivativeReceiptError::InvalidLineage("empty_transforms"));
        }
        if req.transforms.len() > MAX_TRANSFORM_STEPS {
            return Err(DerivativeReceiptError::LimitExceeded("transforms"));
        }

        match &req.source_binding {
            SourceCustodyBinding::RetainedAnchor { source_spans, .. } => {
                if source_spans.is_empty() {
                    return Err(DerivativeReceiptError::InvalidLineage("empty_source_spans"));
                }
                if source_spans.len() > MAX_SOURCE_SPANS {
                    return Err(DerivativeReceiptError::LimitExceeded("source_spans"));
                }
                for span in source_spans {
                    if is_cancelled() {
                        return Err(DerivativeReceiptError::Cancelled);
                    }
                    span.validate().map_err(|_| {
                        DerivativeReceiptError::InvalidLineage("invalid_source_span")
                    })?;
                }
            }
            SourceCustodyBinding::ExplicitOmission {
                omission_reason, ..
            } => {
                check_clean_no_latest(omission_reason, "omission_reason")?;
            }
        }

        let mut parent_digests = Vec::with_capacity(req.parent_receipts.len());
        let mut inherited_masked = !req.parent_receipts.is_empty();
        for parent in &req.parent_receipts {
            if is_cancelled() {
                return Err(DerivativeReceiptError::Cancelled);
            }
            if !parent.verify_digest() || parent.is_source_custody {
                return Err(DerivativeReceiptError::InvalidLineage(
                    "invalid_parent_receipt",
                ));
            }
            if parent.publication_state == DerivativePublicationState::DeletedTombstone {
                return Err(DerivativeReceiptError::InvalidLineage(
                    "deleted_parent_receipt",
                ));
            }
            if parent_digests.contains(&parent.receipt_digest) {
                return Err(DerivativeReceiptError::InvalidLineage(
                    "duplicate_parent_receipt",
                ));
            }
            // Inheriting privacy_masked across a privacy-policy change would silently skip newly
            // added mask zones; only inherit when the parent was masked under the EXACT same policy.
            if !parent.privacy_masked || parent.privacy_policy_digest != req.privacy_policy_digest {
                inherited_masked = false;
            }
            parent_digests.push(parent.receipt_digest);
        }

        let mut stage_masked = false;
        for step in &req.transforms {
            if is_cancelled() {
                return Err(DerivativeReceiptError::Cancelled);
            }
            step.validate()
                .map_err(|_| DerivativeReceiptError::InvalidLineage("invalid_transform_step"))?;
            if let TransformStep::PrivacyMask {
                mask_policy_digest, ..
            } = step
            {
                if *mask_policy_digest != req.privacy_policy_digest {
                    return Err(DerivativeReceiptError::InvalidLineage(
                        "privacy_mask_policy_mismatch",
                    ));
                }
                stage_masked = true;
            }
        }
        if req.kind == MediaDerivativeKind::PrivacyRedaction && !stage_masked {
            return Err(DerivativeReceiptError::InvalidLineage(
                "privacy_redaction_requires_mask_step",
            ));
        }

        if is_cancelled() {
            return Err(DerivativeReceiptError::Cancelled);
        }

        let mut receipt = Self {
            format_version: MEDIA_DERIVATIVE_RECEIPT_FORMAT_VERSION,
            receipt_id: req.receipt_id,
            kind: req.kind,
            derivative_digest: req.derivative_digest,
            derivative_bytes: req.derivative_bytes,
            format_profile: req.format_profile,
            source_binding: req.source_binding,
            parent_derivative_digests: parent_digests,
            transforms: req.transforms,
            implementation_identity: req.implementation_identity,
            generation: req.generation,
            privacy_policy_digest: req.privacy_policy_digest,
            retention_group_digest: req.retention_group_digest,
            is_lossy: req.is_lossy,
            privacy_masked: stage_masked || inherited_masked,
            reproducibility: req.reproducibility,
            publication_state: req.publication_state,
            created_at_ns: req.created_at_ns,
            clock_uncertainty_ns: req.clock_uncertainty_ns,
            is_source_custody: false,
            receipt_digest: ContentDigest::sha256(b"pending"),
        };
        receipt.receipt_digest = receipt.computed_digest();
        Ok(receipt)
    }

    /// Enforces root-last publication and mask-before-egress before exposing derivative bytes
    /// across any external model, network, or export boundary.
    pub fn verify_egress_eligible(
        &self,
        require_privacy_mask: bool,
    ) -> Result<(), DerivativeReceiptError> {
        if !self.verify_digest() || self.is_source_custody {
            return Err(DerivativeReceiptError::EgressDenied(
                "corrupt_or_forged_receipt",
            ));
        }
        if self.publication_state != DerivativePublicationState::RootPublished {
            return Err(DerivativeReceiptError::EgressDenied("not_root_published"));
        }
        if require_privacy_mask && !self.privacy_masked {
            return Err(DerivativeReceiptError::EgressDenied(
                "privacy_mask_required",
            ));
        }
        Ok(())
    }

    /// Recomputes the exact domain-separated SHA-256 digest over all canonical fields.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(MEDIA_DERIVATIVE_RECEIPT_DOMAIN);
        encoder.u32(self.format_version);
        encoder.text(&self.receipt_id);
        self.kind.encode_canonical(&mut encoder);
        encoder.digest(self.derivative_digest);
        encoder.u64(self.derivative_bytes);
        encoder.text(&self.format_profile);
        self.source_binding.encode_canonical(&mut encoder);
        encoder.u64(self.parent_derivative_digests.len() as u64);
        for d in &self.parent_derivative_digests {
            encoder.digest(*d);
        }
        encoder.u64(self.transforms.len() as u64);
        for step in &self.transforms {
            step.encode_canonical(&mut encoder);
        }
        encoder.text(&self.implementation_identity);
        encoder.u64(self.generation.0);
        encoder.digest(self.privacy_policy_digest);
        encoder.digest(self.retention_group_digest);
        encoder.u8(u8::from(self.is_lossy));
        encoder.u8(u8::from(self.privacy_masked));
        self.reproducibility.encode_canonical(&mut encoder);
        self.publication_state.encode_canonical(&mut encoder);
        encoder.i128(self.created_at_ns.0);
        encoder.u64(self.clock_uncertainty_ns);
        encoder.u8(u8::from(self.is_source_custody));
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns `true` iff `receipt_digest` matches [`Self::computed_digest`].
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.receipt_digest == self.computed_digest()
    }
}

impl CanonicalEncode for MediaDerivativeReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.format_version);
        encoder.text(&self.receipt_id);
        self.kind.encode_canonical(encoder);
        encoder.digest(self.derivative_digest);
        encoder.u64(self.derivative_bytes);
        encoder.text(&self.format_profile);
        self.source_binding.encode_canonical(encoder);
        encoder.u64(self.parent_derivative_digests.len() as u64);
        for d in &self.parent_derivative_digests {
            encoder.digest(*d);
        }
        encoder.u64(self.transforms.len() as u64);
        for step in &self.transforms {
            step.encode_canonical(encoder);
        }
        encoder.text(&self.implementation_identity);
        encoder.u64(self.generation.0);
        encoder.digest(self.privacy_policy_digest);
        encoder.digest(self.retention_group_digest);
        encoder.u8(u8::from(self.is_lossy));
        encoder.u8(u8::from(self.privacy_masked));
        self.reproducibility.encode_canonical(encoder);
        self.publication_state.encode_canonical(encoder);
        encoder.i128(self.created_at_ns.0);
        encoder.u64(self.clock_uncertainty_ns);
        encoder.u8(u8::from(self.is_source_custody));
        encoder.digest(self.receipt_digest);
    }
}

fn decode_bool(decoder: &mut CanonicalDecoder<'_>) -> Result<bool, ContractError> {
    match decoder.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ContractError::InvalidIdentifier),
    }
}

impl CanonicalDecode for MediaDerivativeReceipt {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let format_version = decoder.u32()?;
        if format_version != MEDIA_DERIVATIVE_RECEIPT_FORMAT_VERSION {
            return Err(ContractError::InvalidIdentifier);
        }
        let receipt_id = decoder.text()?.to_owned();
        if check_clean_no_latest(&receipt_id, "receipt_id").is_err() {
            return Err(ContractError::InvalidIdentifier);
        }
        let kind = MediaDerivativeKind::decode_canonical(decoder)?;
        let derivative_digest = decoder.digest()?;
        let derivative_bytes = decoder.u64()?;
        let format_profile = decoder.text()?.to_owned();
        if derivative_bytes == 0
            || check_clean_no_latest(&format_profile, "format_profile").is_err()
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let source_binding = SourceCustodyBinding::decode_canonical(decoder)?;
        let parent_count =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
        if parent_count > MAX_PARENT_DERIVATIVES {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut parent_derivative_digests = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            let parent_digest = decoder.digest()?;
            if parent_derivative_digests.contains(&parent_digest) {
                return Err(ContractError::InvalidIdentifier);
            }
            parent_derivative_digests.push(parent_digest);
        }
        let step_count =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidIdentifier)?;
        if step_count == 0 || step_count > MAX_TRANSFORM_STEPS {
            return Err(ContractError::InvalidIdentifier);
        }
        let mut transforms = Vec::with_capacity(step_count);
        for _ in 0..step_count {
            transforms.push(TransformStep::decode_canonical(decoder)?);
        }
        let implementation_identity = decoder.text()?.to_owned();
        if check_clean_no_latest(&implementation_identity, "implementation_identity").is_err() {
            return Err(ContractError::InvalidIdentifier);
        }
        let generation = Generation(decoder.u64()?);
        if generation.0 == 0 {
            return Err(ContractError::InvalidIdentifier);
        }
        let privacy_policy_digest = decoder.digest()?;
        let retention_group_digest = decoder.digest()?;
        let is_lossy = decode_bool(decoder)?;
        let privacy_masked = decode_bool(decoder)?;
        let reproducibility = ReproducibilityClass::decode_canonical(decoder)?;
        let publication_state = DerivativePublicationState::decode_canonical(decoder)?;
        let created_at_ns = TimestampNs(decoder.i128()?);
        let clock_uncertainty_ns = decoder.u64()?;
        let is_source_custody = decode_bool(decoder)?;
        let receipt_digest = decoder.digest()?;

        // Strict structural invariants enforced even against recomputed-SHA-256 forgeries.
        let mut has_stage_mask = false;
        for step in &transforms {
            if let TransformStep::PrivacyMask {
                mask_policy_digest, ..
            } = step
            {
                if *mask_policy_digest != privacy_policy_digest {
                    return Err(ContractError::InvalidIdentifier);
                }
                has_stage_mask = true;
            }
        }
        if is_source_custody
            || (kind == MediaDerivativeKind::PrivacyRedaction && !has_stage_mask)
            || (has_stage_mask && !privacy_masked)
            || (parent_derivative_digests.is_empty() && privacy_masked != has_stage_mask)
        {
            return Err(ContractError::InvalidIdentifier);
        }

        let receipt = Self {
            format_version,
            receipt_id,
            kind,
            derivative_digest,
            derivative_bytes,
            format_profile,
            source_binding,
            parent_derivative_digests,
            transforms,
            implementation_identity,
            generation,
            privacy_policy_digest,
            retention_group_digest,
            is_lossy,
            privacy_masked,
            reproducibility,
            publication_state,
            created_at_ns,
            clock_uncertainty_ns,
            is_source_custody,
            receipt_digest,
        };
        if !receipt.verify_digest() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(receipt)
    }
}
