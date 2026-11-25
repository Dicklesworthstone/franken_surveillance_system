#![forbid(unsafe_code)]
//! Realization of hydration ladder level H3: `source_evidence` (`FSS-210`, `fss-x4a.24.10`).
//!
//! Normative row (`architecture/semantic_hydration.json`, `registries/AGENT_ABSTRACTIONS.md`):
//! - Level: `H3`
//! - Name: `source_evidence`
//! - Content: `authorized original encoded packets, object bytes, exact metadata, or full-resolution media`
//! - Owner: `fss-agent-core`
//! - Raw private media: `true` (explicitly gated by capability + privacy class!)
//!
//! Constitutional hard gates and invariants:
//! 1. **Explicit source authorization:** requires non-empty `authorization_grant_id`, non-empty
//!    `required_capabilities`, and an authorized `privacy_class` (never ambient or unauthenticated).
//! 2. **Exact immutable custody:** binds `handle_id`, `subject_id`, `subject_digest`,
//!    `source_id`, `source_custody_digest`, `anchor`, `contract_basis`, and `proof_roots` (must
//!    contain `subject_digest`, `source_custody_digest`, and `payload_digest`).
//! 3. **Non-degraded completeness:** rejects `Unknown`, `NotObservable`, `Unauthorized`, and `Stale`
//!    so an H3 payload never launders a coverage gap or revoked read as authoritative evidence.
//! 4. **Zero laboratory origin & zero implicit effect authority:** H3 evidence is production
//!    source custody (`is_quarantined() == false`), NEVER laboratory material (`fss.h4_*`), and
//!    carrying H3 bytes NEVER grants effect execution authority (`grants_effect_authority() == false`).
//! 5. **Bounded canonical binary codec:** implements [`CanonicalEncode`] and [`CanonicalDecode`]
//!    with allocation-bomb guards before every `Vec::with_capacity` and full self-validation on
//!    decode (`fss.h3_source_evidence.v1`), bridging cleanly into [`HydrationArtifact::publish`].

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Completeness, HydrationArtifact, HydrationError, HydrationLevel, MAX_REQUEST_SET_ITEMS,
    SemanticHandle, completeness_code, decode_optional_text, decode_text_set, encode_optional_text,
    encode_text_set, valid_text,
};
use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::ContractError;
use crate::{
    BudgetVector, CaptureInterval, ContentDigest, ContractBasis, LedgerAnchor, TimestampNs,
};

/// Stable identifier for hydration ladder level H3.
pub const H3_LEVEL_ID: &str = "H3";
/// Stable name for hydration ladder level H3.
pub const H3_LEVEL_NAME: &str = "source_evidence";
/// Normative content declaration for hydration ladder level H3 from `architecture/semantic_hydration.json`.
pub const H3_CONTENT: &str =
    "authorized original encoded packets, object bytes, exact metadata, or full-resolution media";
/// Owning subsystem for hydration ladder level H3.
pub const H3_OWNER: &str = "fss-agent-core";
/// Canonical schema discriminator tag for H3 source evidence binary envelopes.
pub const H3_SCHEMA: &str = "fss.h3_source_evidence.v1";
/// Registered media type for canonical H3 source evidence payloads inside [`HydrationArtifact`].
pub const H3_CONTENT_TYPE: &str = "application/vnd.fss.h3-source-evidence+canonical";
/// Hard ceiling on raw payload bytes carried in one bounded H3 source evidence artifact (16 MiB).
pub const MAX_H3_RAW_BYTES: usize = 16 * 1024 * 1024;
/// Hard ceiling on exact metadata key/value entries in one H3 metadata payload.
pub const MAX_H3_METADATA_ENTRIES: usize = 256;
/// Hard ceiling on proof roots attached to one H3 source evidence record.
pub const MAX_H3_PROOF_ROOTS: usize = 1_024;
/// Hard ceiling on identifier/codec label bytes inside H3 payloads.
pub const MAX_H3_LABEL_LEN: usize = 128;

fn valid_label(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && !value.chars().any(char::is_control)
}

fn non_zero_digest(digest: ContentDigest) -> bool {
    digest.bytes().iter().any(|&b| b != 0)
}

fn completeness_from_code(code: u8) -> Result<Completeness, ContractError> {
    match code {
        1 => Ok(Completeness::Complete),
        2 => Ok(Completeness::Bounded),
        3 => Ok(Completeness::Partial),
        4 => Ok(Completeness::Unknown),
        5 => Ok(Completeness::NotObservable),
        6 => Ok(Completeness::Unauthorized),
        7 => Ok(Completeness::Stale),
        _ => Err(ContractError::InvalidIdentifier),
    }
}

/// Concrete normative source-evidence payload carried by an authorized [`H3SourceEvidence`] artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum H3SourcePayload {
    /// Original encoded media/sensor packet bytes from owner-authorized custody.
    EncodedPacketBatch {
        /// Codec or wire framing label (e.g. `"h264/annexb"`, `"mjpeg"`, `"opus"`).
        codec: String,
        /// Exact number of packets enclosed (`>= 1`).
        packet_count: u32,
        /// Conservative capture interval covering the enclosed packets.
        capture_interval: CaptureInterval,
        /// Exact immutable raw encoded packet bytes (`1..=MAX_H3_RAW_BYTES`).
        raw_bytes: Vec<u8>,
    },
    /// Exact immutable content-addressed object bytes referenced by a manifest root.
    ImmutableObjectBytes {
        /// Content-addressed manifest or object root digest.
        object_root: ContentDigest,
        /// Stable MIME / media type label (e.g. `"application/octet-stream"`).
        media_type: String,
        /// Exact immutable object payload bytes (`1..=MAX_H3_RAW_BYTES`).
        raw_bytes: Vec<u8>,
    },
    /// Exact canonical source metadata record (non-summarized, source-faithful key/value fields).
    ExactSourceMetadata {
        /// Exact source metadata schema tag (e.g. `"onvif.rtsp.sdp.v1"`).
        metadata_schema: String,
        /// Exact sensor stream generation number.
        stream_generation: u64,
        /// Ordered canonical key/value metadata fields (`1..=MAX_H3_METADATA_ENTRIES`).
        fields: BTreeMap<String, String>,
    },
    /// Authorized full-resolution media frame/clip requiring explicit raw private media disclosure.
    FullResolutionMedia {
        /// Codec or container label (e.g. `"jpeg"`, `"fmp4/h264"`).
        codec: String,
        /// Frame width in pixels (`>= 1`).
        width_px: u32,
        /// Frame height in pixels (`>= 1`).
        height_px: u32,
        /// Conservative capture interval of the media.
        capture_interval: CaptureInterval,
        /// Exact full-resolution media bytes (`1..=MAX_H3_RAW_BYTES`).
        raw_bytes: Vec<u8>,
    },
}

impl H3SourcePayload {
    /// Stable payload family label.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::EncodedPacketBatch { .. } => "encoded_packet_batch",
            Self::ImmutableObjectBytes { .. } => "immutable_object_bytes",
            Self::ExactSourceMetadata { .. } => "exact_source_metadata",
            Self::FullResolutionMedia { .. } => "full_resolution_media",
        }
    }

    /// True iff this payload carries raw private media requiring explicit media read disclosure.
    #[must_use]
    pub const fn contains_raw_media(&self) -> bool {
        matches!(
            self,
            Self::EncodedPacketBatch { .. } | Self::FullResolutionMedia { .. }
        )
    }

    /// Exact raw payload byte footprint (or canonical encoded metadata size).
    #[must_use]
    pub fn byte_len(&self) -> usize {
        match self {
            Self::EncodedPacketBatch { raw_bytes, .. }
            | Self::ImmutableObjectBytes { raw_bytes, .. }
            | Self::FullResolutionMedia { raw_bytes, .. } => raw_bytes.len(),
            Self::ExactSourceMetadata { fields, .. } => fields
                .iter()
                .map(|(k, v)| k.len().saturating_add(v.len()))
                .sum(),
        }
    }

    /// Validates all structural and security bounds of this payload.
    pub fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::EncodedPacketBatch {
                codec,
                packet_count,
                capture_interval,
                raw_bytes,
            } => {
                if !valid_label(codec, MAX_H3_LABEL_LEN)
                    || *packet_count == 0
                    || capture_interval.latest < capture_interval.earliest
                    || raw_bytes.is_empty()
                    || raw_bytes.len() > MAX_H3_RAW_BYTES
                {
                    return Err(ContractError::InvalidIdentifier);
                }
            }
            Self::ImmutableObjectBytes {
                object_root,
                media_type,
                raw_bytes,
            } => {
                if !non_zero_digest(*object_root)
                    || !valid_label(media_type, MAX_H3_LABEL_LEN)
                    || raw_bytes.is_empty()
                    || raw_bytes.len() > MAX_H3_RAW_BYTES
                {
                    return Err(ContractError::InvalidIdentifier);
                }
            }
            Self::ExactSourceMetadata {
                metadata_schema,
                stream_generation,
                fields,
            } => {
                if !valid_label(metadata_schema, MAX_H3_LABEL_LEN)
                    || *stream_generation == 0
                    || fields.is_empty()
                    || fields.len() > MAX_H3_METADATA_ENTRIES
                {
                    return Err(ContractError::InvalidIdentifier);
                }
                for (k, v) in fields {
                    if !valid_label(k, MAX_H3_LABEL_LEN) || !valid_text(v) {
                        return Err(ContractError::InvalidIdentifier);
                    }
                }
            }
            Self::FullResolutionMedia {
                codec,
                width_px,
                height_px,
                capture_interval,
                raw_bytes,
            } => {
                if !valid_label(codec, MAX_H3_LABEL_LEN)
                    || *width_px == 0
                    || *height_px == 0
                    || capture_interval.latest < capture_interval.earliest
                    || raw_bytes.is_empty()
                    || raw_bytes.len() > MAX_H3_RAW_BYTES
                {
                    return Err(ContractError::InvalidIdentifier);
                }
            }
        }
        Ok(())
    }

    /// Computes the canonical SHA-256 digest of this typed source payload.
    pub fn payload_digest(&self) -> Result<ContentDigest, ContractError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(H3_SCHEMA);
        enc.text("payload");
        self.encode_canonical(&mut enc);
        Ok(ContentDigest::sha256(&enc.finish_checked()?))
    }
}

impl CanonicalEncode for H3SourcePayload {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::EncodedPacketBatch {
                codec,
                packet_count,
                capture_interval,
                raw_bytes,
            } => {
                encoder.u8(1);
                encoder.text(codec);
                encoder.u32(*packet_count);
                capture_interval.encode_canonical(encoder);
                encoder.bytes(raw_bytes);
            }
            Self::ImmutableObjectBytes {
                object_root,
                media_type,
                raw_bytes,
            } => {
                encoder.u8(2);
                encoder.digest(*object_root);
                encoder.text(media_type);
                encoder.bytes(raw_bytes);
            }
            Self::ExactSourceMetadata {
                metadata_schema,
                stream_generation,
                fields,
            } => {
                encoder.u8(3);
                encoder.text(metadata_schema);
                encoder.u64(*stream_generation);
                encoder.u32(fields.len() as u32);
                for (k, v) in fields {
                    encoder.text(k);
                    encoder.text(v);
                }
            }
            Self::FullResolutionMedia {
                codec,
                width_px,
                height_px,
                capture_interval,
                raw_bytes,
            } => {
                encoder.u8(4);
                encoder.text(codec);
                encoder.u32(*width_px);
                encoder.u32(*height_px);
                capture_interval.encode_canonical(encoder);
                encoder.bytes(raw_bytes);
            }
        }
    }
}

impl CanonicalDecode for H3SourcePayload {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let payload = match decoder.u8()? {
            1 => {
                let codec = decoder.text()?.to_owned();
                let packet_count = decoder.u32()?;
                let capture_interval = CaptureInterval::decode_canonical(decoder)?;
                let raw_bytes = decoder.bytes()?.to_vec();
                Self::EncodedPacketBatch {
                    codec,
                    packet_count,
                    capture_interval,
                    raw_bytes,
                }
            }
            2 => {
                let object_root = decoder.digest()?;
                let media_type = decoder.text()?.to_owned();
                let raw_bytes = decoder.bytes()?.to_vec();
                Self::ImmutableObjectBytes {
                    object_root,
                    media_type,
                    raw_bytes,
                }
            }
            3 => {
                let metadata_schema = decoder.text()?.to_owned();
                let stream_generation = decoder.u64()?;
                let count = decoder.u32()? as usize;
                if count == 0
                    || count > MAX_H3_METADATA_ENTRIES
                    || count.saturating_mul(10) > decoder.remaining()
                {
                    return Err(ContractError::InvalidIdentifier);
                }
                let mut fields = BTreeMap::new();
                for _ in 0..count {
                    let k = decoder.text()?.to_owned();
                    let v = decoder.text()?.to_owned();
                    if let Some(prev) = fields.keys().next_back()
                        && prev >= &k
                    {
                        return Err(ContractError::InvalidIdentifier);
                    }
                    fields.insert(k, v);
                }
                Self::ExactSourceMetadata {
                    metadata_schema,
                    stream_generation,
                    fields,
                }
            }
            4 => {
                let codec = decoder.text()?.to_owned();
                let width_px = decoder.u32()?;
                let height_px = decoder.u32()?;
                let capture_interval = CaptureInterval::decode_canonical(decoder)?;
                let raw_bytes = decoder.bytes()?.to_vec();
                Self::FullResolutionMedia {
                    codec,
                    width_px,
                    height_px,
                    capture_interval,
                    raw_bytes,
                }
            }
            _ => return Err(ContractError::InvalidIdentifier),
        };
        payload.validate()?;
        Ok(payload)
    }
}

/// Parameters used to construct an authorized [`H3SourceEvidence`] artifact.
#[derive(Clone, Debug, PartialEq)]
pub struct H3SourceEvidenceParams {
    /// Content-derived semantic handle identity.
    pub handle_id: String,
    /// Stable canonical subject identity.
    pub subject_id: String,
    /// Immutable subject digest.
    pub subject_digest: ContentDigest,
    /// Stable sensor/stream source identity.
    pub source_id: String,
    /// Exact source custody commitment (e.g. retained spool object or packfile digest).
    pub source_custody_digest: ContentDigest,
    /// Explicit authorization grant identity authorizing H3 disclosure.
    pub authorization_grant_id: String,
    /// Privacy class authorized for this H3 disclosure (e.g. `"private:property"`).
    pub privacy_class: String,
    /// Non-empty capabilities required to admit this H3 disclosure (e.g. `"ReadMedia"`).
    pub required_capabilities: BTreeSet<String>,
    /// Concrete source evidence payload.
    pub payload: H3SourcePayload,
    /// Exact authority anchor of the descriptor revision.
    pub anchor: LedgerAnchor,
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Conservative resource cost quoted for H3 hydration.
    pub estimated_cost: BudgetVector,
    /// Publication timestamp.
    pub published_at: TimestampNs,
    /// Retention expiry timestamp (`retention_until > published_at`).
    pub retention_until: TimestampNs,
    /// Retained provenance roots (must include `subject_digest` and `source_custody_digest`).
    pub proof_roots: BTreeSet<ContentDigest>,
    /// Completeness at H3 (must be `Complete`, `Bounded`, or `Partial`).
    pub completeness: Completeness,
    /// Applied transform, matching the handle descriptor when any.
    pub applied_transform: Option<String>,
}

/// Strongly typed realization of hydration ladder level H3 (`source_evidence`).
///
/// Enforces explicit capability & privacy authorization, immutable source custody binding,
/// non-degraded completeness, zero laboratory origin, and zero implicit effect authority.
#[derive(Clone, Debug, PartialEq)]
pub struct H3SourceEvidence {
    handle_id: String,
    subject_id: String,
    subject_digest: ContentDigest,
    source_id: String,
    source_custody_digest: ContentDigest,
    authorization_grant_id: String,
    privacy_class: String,
    required_capabilities: BTreeSet<String>,
    payload: H3SourcePayload,
    payload_digest: ContentDigest,
    anchor: LedgerAnchor,
    contract_basis: ContractBasis,
    estimated_cost: BudgetVector,
    published_at: TimestampNs,
    retention_until: TimestampNs,
    proof_roots: BTreeSet<ContentDigest>,
    completeness: Completeness,
    applied_transform: Option<String>,
    evidence_digest: ContentDigest,
}

impl H3SourceEvidence {
    /// Constructs and seals an [`H3SourceEvidence`] artifact after verifying every H3 gate.
    pub fn new(params: H3SourceEvidenceParams) -> Result<Self, HydrationError> {
        params.payload.validate()?;
        let payload_digest = params.payload.payload_digest()?;
        let mut proof_roots = params.proof_roots;
        proof_roots.insert(payload_digest);
        if let H3SourcePayload::ImmutableObjectBytes { object_root, .. } = params.payload {
            proof_roots.insert(object_root);
        }
        let mut record = Self {
            handle_id: params.handle_id,
            subject_id: params.subject_id,
            subject_digest: params.subject_digest,
            source_id: params.source_id,
            source_custody_digest: params.source_custody_digest,
            authorization_grant_id: params.authorization_grant_id,
            privacy_class: params.privacy_class,
            required_capabilities: params.required_capabilities,
            payload: params.payload,
            payload_digest,
            anchor: params.anchor,
            contract_basis: params.contract_basis,
            estimated_cost: params.estimated_cost,
            published_at: params.published_at,
            retention_until: params.retention_until,
            proof_roots,
            completeness: params.completeness,
            applied_transform: params.applied_transform,
            evidence_digest: ContentDigest::sha256(b"unsealed-h3-source-evidence"),
        };
        record.validate()?;
        record.evidence_digest = record.computed_digest()?;
        Ok(record)
    }

    /// Hydration level (always [`HydrationLevel::H3`]).
    #[must_use]
    pub const fn level(&self) -> HydrationLevel {
        HydrationLevel::H3
    }

    /// Stable handle identity.
    #[must_use]
    pub fn handle_id(&self) -> &str {
        &self.handle_id
    }

    /// Stable subject identity.
    #[must_use]
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }

    /// Immutable subject digest.
    #[must_use]
    pub const fn subject_digest(&self) -> ContentDigest {
        self.subject_digest
    }

    /// Stable sensor/stream source identity.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Exact immutable source custody digest.
    #[must_use]
    pub const fn source_custody_digest(&self) -> ContentDigest {
        self.source_custody_digest
    }

    /// Explicit authorization grant identity.
    #[must_use]
    pub fn authorization_grant_id(&self) -> &str {
        &self.authorization_grant_id
    }

    /// Privacy class authorized for this disclosure.
    #[must_use]
    pub fn privacy_class(&self) -> &str {
        &self.privacy_class
    }

    /// Required capability grants for this disclosure.
    #[must_use]
    pub const fn required_capabilities(&self) -> &BTreeSet<String> {
        &self.required_capabilities
    }

    /// Concrete typed source-evidence payload.
    #[must_use]
    pub const fn payload(&self) -> &H3SourcePayload {
        &self.payload
    }

    /// Canonical SHA-256 digest of the typed source payload.
    #[must_use]
    pub const fn payload_digest(&self) -> ContentDigest {
        self.payload_digest
    }

    /// Sealed canonical H3 record digest.
    #[must_use]
    pub const fn evidence_digest(&self) -> ContentDigest {
        self.evidence_digest
    }

    /// H3 source custody is production evidence, never quarantined laboratory output.
    #[must_use]
    pub const fn is_quarantined(&self) -> bool {
        false
    }

    /// Reading H3 source evidence NEVER grants effect execution authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Verifies that this H3 artifact matches `handle` across immutable identity, privacy class,
    /// required capabilities, anchor, contract basis, and applied transform.
    pub fn verify_against_handle(&self, handle: &SemanticHandle) -> Result<(), HydrationError> {
        handle.verify()?;
        self.validate()?;
        if !handle.levels.contains(&HydrationLevel::H3) {
            return Err(HydrationError::LevelUnavailable);
        }
        if self.handle_id != handle.handle_id
            || self.subject_id != handle.subject_id
            || self.subject_digest != handle.subject_digest
            || self.source_id != handle.source_id
            || self.applied_transform != handle.applied_transform
        {
            return Err(ContractError::DigestMismatch.into());
        }
        if self.anchor != handle.anchor {
            return Err(ContractError::StaleAnchor.into());
        }
        if self.contract_basis != handle.contract_basis {
            return Err(ContractError::GenerationConflict.into());
        }
        if self.privacy_class != handle.privacy_class {
            return Err(HydrationError::PrivacyDenied);
        }
        let handle_caps = handle
            .capabilities_for(HydrationLevel::H3)
            .ok_or(HydrationError::LevelUnavailable)?;
        if !handle_caps.is_subset(&self.required_capabilities) {
            return Err(HydrationError::CapabilityDenied);
        }
        Ok(())
    }

    /// Validates every constitutional and structural invariant of this H3 record.
    pub fn validate(&self) -> Result<(), HydrationError> {
        if !valid_text(&self.handle_id)
            || !valid_text(&self.subject_id)
            || !valid_text(&self.source_id)
            || !valid_label(&self.authorization_grant_id, MAX_H3_LABEL_LEN)
            || !valid_label(&self.privacy_class, MAX_H3_LABEL_LEN)
        {
            return Err(ContractError::InvalidIdentifier.into());
        }
        if !non_zero_digest(self.subject_digest) || !non_zero_digest(self.source_custody_digest) {
            return Err(ContractError::InvalidDigest.into());
        }
        if self.required_capabilities.is_empty()
            || self.required_capabilities.len() > MAX_REQUEST_SET_ITEMS
            || self
                .required_capabilities
                .iter()
                .any(|c| !valid_label(c, MAX_H3_LABEL_LEN))
        {
            return Err(HydrationError::CapabilityDenied);
        }
        if self.retention_until <= self.published_at {
            return Err(ContractError::InvertedTimeInterval.into());
        }
        if !self.estimated_cost.is_valid() {
            return Err(ContractError::EvidenceRequired.into());
        }
        if matches!(
            self.completeness,
            Completeness::Unknown
                | Completeness::NotObservable
                | Completeness::Unauthorized
                | Completeness::Stale
        ) {
            return Err(ContractError::EvidenceRequired.into());
        }
        if let Some(ref tf) = self.applied_transform
            && !valid_text(tf)
        {
            return Err(ContractError::InvalidIdentifier.into());
        }
        self.payload.validate()?;
        let computed_payload = self.payload.payload_digest()?;
        if computed_payload != self.payload_digest {
            return Err(ContractError::DigestMismatch.into());
        }
        if self.proof_roots.len() > MAX_H3_PROOF_ROOTS
            || !self.proof_roots.contains(&self.subject_digest)
            || !self.proof_roots.contains(&self.source_custody_digest)
            || !self.proof_roots.contains(&self.payload_digest)
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        if let H3SourcePayload::ImmutableObjectBytes { object_root, .. } = self.payload
            && !self.proof_roots.contains(&object_root)
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        Ok(())
    }

    /// Recomputes the domain-separated SHA-256 commitment digest (`fss.h3_source_evidence.v1`).
    pub fn computed_digest(&self) -> Result<ContentDigest, ContractError> {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        Ok(ContentDigest::sha256(&enc.finish_checked()?))
    }

    /// Bridges this verified H3 record into a sealed [`HydrationArtifact`] deliverable through
    /// [`crate::hydration::HydrationRequest::validate_delivery`].
    pub fn to_hydration_artifact(&self) -> Result<HydrationArtifact, HydrationError> {
        self.validate()?;
        if self.computed_digest()? != self.evidence_digest {
            return Err(ContractError::DigestMismatch.into());
        }
        let mut enc = CanonicalEncoder::new();
        self.encode_canonical(&mut enc);
        let bytes = enc.finish_checked()?;
        let mut roots = self.proof_roots.clone();
        roots.insert(self.evidence_digest);
        HydrationArtifact::publish(
            HydrationLevel::H3,
            H3_CONTENT_TYPE,
            bytes,
            roots,
            self.completeness,
            self.applied_transform.clone(),
        )
    }

    /// Decodes and cryptographically verifies an [`H3SourceEvidence`] payload carried inside a
    /// [`HydrationArtifact`].
    pub fn from_hydration_artifact(artifact: &HydrationArtifact) -> Result<Self, HydrationError> {
        artifact.verify()?;
        if artifact.level != HydrationLevel::H3
            || artifact.is_quarantined()
            || artifact.content_type != H3_CONTENT_TYPE
        {
            return Err(HydrationError::LevelUnavailable);
        }
        let mut dec = CanonicalDecoder::new(&artifact.payload);
        let decoded = Self::decode_canonical(&mut dec)?;
        dec.ensure_finished()?;
        if artifact.completeness != decoded.completeness
            || artifact.applied_transform != decoded.applied_transform
            || !artifact.proof_roots.contains(&decoded.evidence_digest)
        {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(decoded)
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.text(H3_SCHEMA);
        enc.text(&self.handle_id);
        enc.text(&self.subject_id);
        enc.digest(self.subject_digest);
        enc.text(&self.source_id);
        enc.digest(self.source_custody_digest);
        enc.text(&self.authorization_grant_id);
        enc.text(&self.privacy_class);
        encode_text_set(&self.required_capabilities, enc);
        self.payload.encode_canonical(enc);
        enc.digest(self.payload_digest);
        self.anchor.encode_canonical(enc);
        self.contract_basis.encode_canonical(enc);
        self.estimated_cost.encode_canonical(enc);
        self.published_at.encode_canonical(enc);
        self.retention_until.encode_canonical(enc);
        enc.u32(self.proof_roots.len() as u32);
        for root in &self.proof_roots {
            enc.digest(*root);
        }
        enc.u8(completeness_code(self.completeness));
        encode_optional_text(self.applied_transform.as_deref(), enc);
    }
}

impl CanonicalEncode for H3SourceEvidence {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.encode_body(encoder);
        encoder.digest(self.evidence_digest);
    }
}

impl CanonicalDecode for H3SourceEvidence {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != H3_SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let handle_id = decoder.text()?.to_owned();
        let subject_id = decoder.text()?.to_owned();
        let subject_digest = decoder.digest()?;
        let source_id = decoder.text()?.to_owned();
        let source_custody_digest = decoder.digest()?;
        let authorization_grant_id = decoder.text()?.to_owned();
        let privacy_class = decoder.text()?.to_owned();
        let required_capabilities =
            decode_text_set(decoder).map_err(|_| ContractError::InvalidIdentifier)?;
        let payload = H3SourcePayload::decode_canonical(decoder)?;
        let payload_digest = decoder.digest()?;
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let contract_basis = ContractBasis::decode_canonical(decoder)?;
        let estimated_cost = <BudgetVector as CanonicalDecode>::decode_canonical(decoder)?;
        let published_at = TimestampNs::decode_canonical(decoder)?;
        let retention_until = TimestampNs::decode_canonical(decoder)?;
        let root_count = decoder.u32()? as usize;
        if root_count == 0
            || root_count > MAX_H3_PROOF_ROOTS
            || root_count.saturating_mul(32) > decoder.remaining()
        {
            return Err(ContractError::EvidenceRequired);
        }
        let mut proof_roots = BTreeSet::new();
        for _ in 0..root_count {
            let root = decoder.digest()?;
            if let Some(prev) = proof_roots.iter().next_back()
                && *prev >= root
            {
                return Err(ContractError::InvalidIdentifier);
            }
            proof_roots.insert(root);
        }
        let completeness = completeness_from_code(decoder.u8()?)?;
        let applied_transform = decode_optional_text(decoder)?.map(str::to_owned);
        let evidence_digest = decoder.digest()?;

        let record = Self {
            handle_id,
            subject_id,
            subject_digest,
            source_id,
            source_custody_digest,
            authorization_grant_id,
            privacy_class,
            required_capabilities,
            payload,
            payload_digest,
            anchor,
            contract_basis,
            estimated_cost,
            published_at,
            retention_until,
            proof_roots,
            completeness,
            applied_transform,
            evidence_digest,
        };
        record
            .validate()
            .map_err(|_| ContractError::InvalidIdentifier)?;
        if record.computed_digest()? != evidence_digest {
            return Err(ContractError::DigestMismatch);
        }
        Ok(record)
    }
}
