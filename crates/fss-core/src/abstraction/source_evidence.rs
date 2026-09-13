#![forbid(unsafe_code)]
//! Source evidence realization (AGT-LAYER-002, INV-003).
//!
//! Authority plane types:
//! - [`SourceEvidenceRecord`]
//! - [`SourceEvidenceParams`]
//! - [`SourceEvidenceClassification`]

use core::fmt;
use core::str::FromStr;

use crate::agent::{KnowledgeStateBasis, RedactionMarker, RedactionReason, StaleBasis};
use crate::canonical::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
};
use crate::contract::{ContractError, KnowledgeState, Plane, ProvenanceClass};
use crate::evidence::SensorCapsule;
use crate::ids::{validate_id, PrivacyGeneration};
use crate::sensor_capsule::{OmissionReason, SourceCustody};
use crate::{ContentDigest, Generation, KnowledgeCell, LedgerAnchor};

use super::AgentAbstractionLayer;

/// Binary wire format version for [`SourceEvidenceRecord`] canonical encoding.
pub const SOURCE_EVIDENCE_RECORD_FORMAT_VERSION: u32 = 2;

/// Canonical classification of source evidence (AGT-LAYER-002, INV-003).
///
/// Under constitutional invariant INV-003, decode buffers, model inference outputs,
/// and derived cognitions can NEVER be promoted into source evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SourceEvidenceClassification {
    /// Raw network packets (e.g. PCAP, wire frames).
    RawWirePackets,
    /// Unmodified source payload file on disk/blob storage.
    SourcePayloadFile,
    /// Direct physical sensor hardware reading.
    PhysicalSensorMeasurement,
    /// Immutable sensor capsule with integrity proofs.
    SensorCapsule,
    /// Cryptographic continuity witness / hash chain link.
    ContinuityWitness,
    /// Decoded frame pixel buffer (PROHIBITED from source promotion).
    DecodedFrameBuffer,
    /// Model inference output / bounding box / embeddings (PROHIBITED from source promotion).
    ModelInferenceOutput,
    /// Derived cognition / belief (PROHIBITED from source promotion).
    DerivedCognition,
}

impl SourceEvidenceClassification {
    /// Returns true if this classification is permitted as authoritative source evidence.
    #[must_use]
    pub const fn is_permitted(&self) -> bool {
        matches!(
            self,
            Self::RawWirePackets
                | Self::SourcePayloadFile
                | Self::PhysicalSensorMeasurement
                | Self::SensorCapsule
                | Self::ContinuityWitness
        )
    }

    /// Returns true if this classification is prohibited from being promoted to source evidence.
    #[must_use]
    pub const fn is_prohibited(&self) -> bool {
        !self.is_permitted()
    }

    /// Canonical string identifier for this classification.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RawWirePackets => "raw_wire_packets",
            Self::SourcePayloadFile => "source_payload_file",
            Self::PhysicalSensorMeasurement => "physical_sensor_measurement",
            Self::SensorCapsule => "sensor_capsule",
            Self::ContinuityWitness => "continuity_witness",
            Self::DecodedFrameBuffer => "decoded_frame_buffer",
            Self::ModelInferenceOutput => "model_inference_output",
            Self::DerivedCognition => "derived_cognition",
        }
    }

    /// Parses from an exact canonical string token.
    ///
    /// Accepts only exact canonical tokens. Unknown tokens return
    /// [`ContractError::UnknownSourceEvidenceClassification`].
    pub fn parse(s: &str) -> Result<Self, ContractError> {
        match s {
            "raw_wire_packets" => Ok(Self::RawWirePackets),
            "source_payload_file" => Ok(Self::SourcePayloadFile),
            "physical_sensor_measurement" => Ok(Self::PhysicalSensorMeasurement),
            "sensor_capsule" => Ok(Self::SensorCapsule),
            "continuity_witness" => Ok(Self::ContinuityWitness),
            "decoded_frame_buffer" => Ok(Self::DecodedFrameBuffer),
            "model_inference_output" => Ok(Self::ModelInferenceOutput),
            "derived_cognition" => Ok(Self::DerivedCognition),
            _ => Err(ContractError::UnknownSourceEvidenceClassification(
                s.to_string(),
            )),
        }
    }
}

impl fmt::Display for SourceEvidenceClassification {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SourceEvidenceClassification {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl CanonicalEncode for SourceEvidenceClassification {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for SourceEvidenceClassification {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        Self::parse(text)
    }
}

/// Sanitizes storage handle: refuses directory traversal, padding, NUL,
/// newlines, and zero-width or control characters.
fn sanitize_storage_handle(handle: &str) -> Result<(), ContractError> {
    if handle.is_empty() || handle != handle.trim() {
        return Err(ContractError::SourceEvidenceEmptyStorageHandle);
    }
    if handle.contains("..") || handle.starts_with('/') || handle.starts_with('\\') {
        return Err(ContractError::SourceEvidenceEmptyStorageHandle);
    }
    for c in handle.chars() {
        if c == '\0'
            || c == '\n'
            || c == '\r'
            || ('\u{200B}'..='\u{200F}').contains(&c)
            || c == '\u{FEFF}'
            || c == '\u{2060}'
            || c.is_control()
        {
            return Err(ContractError::SourceEvidenceEmptyStorageHandle);
        }
    }
    Ok(())
}

/// An authoritative source evidence record (AGT-LAYER-002, INV-003).
///
/// Output: "Immutable sensor capsules, source objects, continuity and time evidence."
/// Prohibition: "Cannot promote decode or model output into source evidence."
///
/// Fields are strictly private to prevent post-validation tampering. Access is provided
/// via immutable public accessors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceEvidenceRecord {
    evidence_id: String,
    anchor: LedgerAnchor,
    generation: Generation,
    statement: String,
    provenance: ProvenanceClass,
    classification: SourceEvidenceClassification,
    custody: SourceCustody,
    omission: Option<OmissionReason>,
    capsule: Option<SensorCapsule>,
    continuity_witness: Option<ContentDigest>,
}

/// Parameters for constructing a [`SourceEvidenceRecord`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceEvidenceParams {
    /// Stable evidence identifier.
    pub evidence_id: String,
    /// Authoritative ledger anchor.
    pub anchor: LedgerAnchor,
    /// Generation of the capture/source system.
    pub generation: Generation,
    /// Statement or description (1..=512 bytes).
    pub statement: String,
    /// Provenance class (must be `Observed`).
    pub provenance: ProvenanceClass,
    /// Strongly typed evidence classification.
    pub classification: SourceEvidenceClassification,
    /// Source custody status.
    pub custody: SourceCustody,
    /// Explicit omission reason if source bytes are omitted.
    pub omission: Option<OmissionReason>,
    /// Immutable sensor capsule, if available.
    pub capsule: Option<SensorCapsule>,
    /// Continuity witness digest.
    pub continuity_witness: Option<ContentDigest>,
}

impl SourceEvidenceRecord {
    /// Constructs and validates a new source evidence record.
    pub fn new(params: SourceEvidenceParams) -> Result<Self, ContractError> {
        let record = Self {
            evidence_id: params.evidence_id,
            anchor: params.anchor,
            generation: params.generation,
            statement: params.statement,
            provenance: params.provenance,
            classification: params.classification,
            custody: params.custody,
            omission: params.omission,
            capsule: params.capsule,
            continuity_witness: params.continuity_witness,
        };
        record.validate()?;
        Ok(record)
    }

    /// Stable evidence identifier accessor.
    #[must_use]
    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    /// Authoritative ledger anchor accessor.
    #[must_use]
    pub fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }

    /// Generation accessor.
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Evidence statement accessor.
    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    /// Provenance class accessor.
    #[must_use]
    pub const fn provenance(&self) -> ProvenanceClass {
        self.provenance
    }

    /// Classification accessor.
    #[must_use]
    pub const fn classification(&self) -> SourceEvidenceClassification {
        self.classification
    }

    /// Custody status accessor.
    #[must_use]
    pub fn custody(&self) -> &SourceCustody {
        &self.custody
    }

    /// Omission reason accessor.
    #[must_use]
    pub const fn omission(&self) -> Option<OmissionReason> {
        self.omission
    }

    /// Sensor capsule accessor.
    #[must_use]
    pub const fn capsule(&self) -> Option<&SensorCapsule> {
        self.capsule.as_ref()
    }

    /// Continuity witness accessor.
    #[must_use]
    pub const fn continuity_witness(&self) -> Option<ContentDigest> {
        self.continuity_witness
    }

    /// Validates constitutional invariants for this source evidence record (INV-003).
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_id(&self.evidence_id)?;
        if self.evidence_id == "." || self.evidence_id == ".." || self.evidence_id == ":" {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.anchor.site_lineage.is_empty() {
            return Err(ContractError::SourceEvidenceMissingAnchor);
        }
        if self.generation.0 == 0 {
            return Err(ContractError::GenerationConflict);
        }
        if self.statement.is_empty() || self.statement.len() > 512 {
            return Err(ContractError::SourceEvidenceStatementMalformed);
        }
        // Constitutional Prohibition: "Cannot promote decode or model output into source evidence."
        // Provenance MUST be Observed; Derived, Predicted, etc. are strictly prohibited.
        if self.provenance != ProvenanceClass::Observed {
            return Err(ContractError::ProhibitedEvidencePromotion);
        }
        // Typed classification check: Cannot promote decode buffer or model output
        if self.classification.is_prohibited() {
            return Err(ContractError::ProhibitedEvidencePromotion);
        }

        // Bind classification to actual payload presence
        if self.classification == SourceEvidenceClassification::SensorCapsule
            && self.capsule.is_none()
        {
            return Err(ContractError::SourceEvidenceCapsuleRequired);
        }
        if self.classification == SourceEvidenceClassification::ContinuityWitness
            && self.continuity_witness.is_none()
        {
            return Err(ContractError::SourceEvidenceWitnessRequired);
        }

        // Invariant INV-003: Every retained observation names exact source bytes
        // or records why source retention was forbidden.
        match &self.custody {
            SourceCustody::Retained {
                source_digest,
                source_bytes,
                storage_handle,
            } => {
                sanitize_storage_handle(storage_handle)?;
                if *source_bytes == 0 {
                    return Err(ContractError::EvidenceRequired);
                }
                if *source_bytes == u64::MAX {
                    return Err(ContractError::ArithmeticOverflow);
                }
                if source_digest.bytes() == [0u8; 32] {
                    return Err(ContractError::InvalidDigest);
                }
                if self.omission.is_some() {
                    return Err(ContractError::SourceEvidenceRetainedWithOmission);
                }
                if let Some(capsule) = &self.capsule {
                    if capsule.source_digest != *source_digest {
                        return Err(ContractError::DigestMismatch);
                    }
                    if capsule.source_bytes != *source_bytes {
                        return Err(ContractError::SourceEvidenceByteCountMismatch);
                    }
                }
                if self
                    .continuity_witness
                    .is_some_and(|w| w == *source_digest)
                {
                    return Err(ContractError::SourceEvidenceWitnessEqualsSourceDigest);
                }
            }
            SourceCustody::NotRetained => {
                // Must record a valid typed omission reason, and it cannot be None
                match self.omission {
                    Some(reason) if reason != OmissionReason::None => {}
                    _ => return Err(ContractError::SourceEvidenceOmissionRequired),
                }
                if self.continuity_witness.is_some() {
                    return Err(ContractError::SourceEvidenceNotRetainedWithWitness);
                }
                if self.capsule.as_ref().is_some_and(|c| {
                    c.source_bytes > 0
                        || c.source_digest.bytes() != [0u8; 32]
                        || c.frame_count > 0
                }) {
                    return Err(ContractError::SourceEvidenceNotRetainedWithCapsuleBytes);
                }
            }
        }

        // Temporal cross-checks on capsule
        if self.capsule.as_ref().is_some_and(|c| {
            c.capture.earliest > c.capture.latest || c.receive_time < c.capture.earliest
        }) {
            return Err(ContractError::InvertedTimeInterval);
        }

        // Continuity witness non-zero check
        if self
            .continuity_witness
            .is_some_and(|w| w.bytes() == [0u8; 32])
        {
            return Err(ContractError::InvalidDigest);
        }

        Ok(())
    }

    /// Returns the abstraction layer for this record (`AGT-LAYER-002`).
    #[must_use]
    pub const fn layer(&self) -> AgentAbstractionLayer {
        AgentAbstractionLayer::SourceEvidence
    }

    /// Returns the semantic plane (`Plane::Authority`).
    #[must_use]
    pub const fn plane(&self) -> Plane {
        Plane::Authority
    }

    /// Returns whether this record may claim authority.
    #[must_use]
    pub const fn may_claim_authority(&self) -> bool {
        true
    }

    /// Returns whether this record may authorize effects.
    #[must_use]
    pub const fn may_authorize_effects(&self) -> bool {
        false
    }

    /// Converts this source evidence record into a canonical [`KnowledgeCell`].
    ///
    /// Truthful knowledge state derivation:
    /// - For `Retained` custody: `KnowledgeState::Known` when unbroken (`gap_before == false`),
    ///   or `KnowledgeState::Stale` with [`StaleBasis`] when `gap_before == true`.
    /// - For `NotRetained` custody:
    ///   - `OmissionReason::PrivacyRedaction` -> `KnowledgeState::Redacted` with [`RedactionMarker`].
    ///   - `OmissionReason::CapabilityFiltered` -> `KnowledgeState::Redacted` with [`RedactionMarker`].
    ///   - `OmissionReason::UpstreamMissing` -> `KnowledgeState::NotObservable`.
    ///   - Other reasons -> `KnowledgeState::Unknown`.
    #[must_use]
    pub fn to_knowledge_cell(&self) -> KnowledgeCell {
        let (knowledge_state, state_basis, evidence) = match &self.custody {
            SourceCustody::Retained { source_digest, .. } => {
                let mut ev = vec![*source_digest];
                if let Some(capsule) = &self.capsule {
                    let meta_digest = capsule.metadata_digest();
                    if !ev.contains(&meta_digest) {
                        ev.push(meta_digest);
                    }
                }
                if let Some(witness) = self.continuity_witness.filter(|w| !ev.contains(w)) {
                    ev.push(witness);
                }
                if self.capsule.as_ref().is_some_and(|c| c.gap_before) {
                    let stale_basis = if self.anchor.commit_sequence > 0 {
                        let mut older_anchor = self.anchor.clone();
                        older_anchor.commit_sequence =
                            self.anchor.commit_sequence.saturating_sub(1);
                        StaleBasis::OlderAnchor {
                            valid_at: Box::new(older_anchor),
                            current: Box::new(self.anchor.clone()),
                        }
                    } else {
                        StaleBasis::OlderGeneration {
                            valid_at: Generation(self.generation.0.saturating_sub(1)),
                            current: self.generation,
                        }
                    };
                    (
                        KnowledgeState::Stale,
                        Some(KnowledgeStateBasis::Stale(stale_basis)),
                        ev,
                    )
                } else {
                    (KnowledgeState::Known, None, ev)
                }
            }
            SourceCustody::NotRetained => match self.omission {
                Some(OmissionReason::PrivacyRedaction) => (
                    KnowledgeState::Redacted,
                    Some(KnowledgeStateBasis::Redaction(RedactionMarker {
                        reason: RedactionReason::PrivacyProjection,
                        privacy_generation: PrivacyGeneration::canonical_v1(),
                    })),
                    Vec::new(),
                ),
                Some(OmissionReason::CapabilityFiltered) => (
                    KnowledgeState::Redacted,
                    Some(KnowledgeStateBasis::Redaction(RedactionMarker {
                        reason: RedactionReason::CapabilityProjection,
                        privacy_generation: PrivacyGeneration::canonical_v1(),
                    })),
                    Vec::new(),
                ),
                Some(OmissionReason::UpstreamMissing) => {
                    (KnowledgeState::NotObservable, None, Vec::new())
                }
                _ => (KnowledgeState::Unknown, None, Vec::new()),
            },
        };

        KnowledgeCell {
            claim_id: self.evidence_id.clone(),
            statement: self.statement.clone(),
            knowledge_state,
            provenance: self.provenance,
            hypothesis: None,
            evidence,
            contradictions: vec![],
            valid_until: None,
            state_basis,
        }
    }

    /// Serializes this record to canonical bytes.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        encoder.finish()
    }

    /// Decodes a source evidence record from canonical bytes, rejecting trailing data.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let record = Self::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;
        Ok(record)
    }

    /// Computes canonical content digest of this record's canonical encoding.
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_canonical_bytes())
    }
}

impl CanonicalEncode for SourceEvidenceRecord {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(SOURCE_EVIDENCE_RECORD_FORMAT_VERSION);
        encoder.text(&self.evidence_id);
        self.anchor.encode_canonical(encoder);
        encoder.u64(self.generation.0);
        encoder.text(&self.statement);
        self.provenance.encode_canonical(encoder);
        self.classification.encode_canonical(encoder);
        self.custody.encode_canonical(encoder);
        match self.omission {
            Some(reason) => {
                encoder.bool(true);
                reason.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        match &self.capsule {
            Some(capsule) => {
                encoder.bool(true);
                capsule.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        match self.continuity_witness {
            Some(witness) => {
                encoder.bool(true);
                encoder.digest(witness);
            }
            None => encoder.bool(false),
        }
    }
}

impl CanonicalDecode for SourceEvidenceRecord {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let version = decoder.u32()?;
        if version != SOURCE_EVIDENCE_RECORD_FORMAT_VERSION {
            return Err(ContractError::UnsupportedSourceEvidenceVersion(version));
        }
        let evidence_id = decoder.text()?.to_owned();
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let generation = Generation(decoder.u64()?);
        let statement = decoder.text()?.to_owned();
        let provenance = ProvenanceClass::decode_canonical(decoder)?;
        let classification = SourceEvidenceClassification::decode_canonical(decoder)?;
        let custody = SourceCustody::decode_canonical(decoder)?;
        let has_omission = decoder.bool()?;
        let omission = if has_omission {
            Some(OmissionReason::decode_canonical(decoder)?)
        } else {
            None
        };
        let has_capsule = decoder.bool()?;
        let capsule = if has_capsule {
            Some(SensorCapsule::decode_canonical(decoder)?)
        } else {
            None
        };
        let has_continuity = decoder.bool()?;
        let continuity_witness = if has_continuity {
            Some(decoder.digest()?)
        } else {
            None
        };
        decoder.ensure_finished()?;

        let record = Self {
            evidence_id,
            anchor,
            generation,
            statement,
            provenance,
            classification,
            custody,
            omission,
            capsule,
            continuity_witness,
        };
        record.validate()?;
        Ok(record)
    }
}
