#![forbid(unsafe_code)]
//! Source evidence realization (AGT-LAYER-002, INV-003).
//!
//! Authority plane types:
//! - [`SourceEvidenceRecord`]
//! - [`SourceEvidenceParams`]
//! - [`SourceEvidenceClassification`]

use core::fmt;
use core::str::FromStr;

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::{ContractError, KnowledgeState, Plane, ProvenanceClass};
use crate::evidence::SensorCapsule;
use crate::ids::validate_id;
use crate::sensor_capsule::{OmissionReason, SourceCustody};
use crate::{ContentDigest, Generation, KnowledgeCell, LedgerAnchor};

use super::AgentAbstractionLayer;

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
    /// Accepts only exact canonical tokens. Tokens with leading/trailing whitespace,
    /// non-matching case, or substring variations are rejected with [`ContractError::InvalidIdentifier`].
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
            _ => Err(ContractError::InvalidIdentifier),
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

/// An authoritative source evidence record (AGT-LAYER-002, INV-003).
///
/// Output: "Immutable sensor capsules, source objects, continuity and time evidence."
/// Prohibition: "Cannot promote decode or model output into source evidence."
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceEvidenceRecord {
    /// Stable evidence identifier (e.g. `source:packet:cam01:seq1024`).
    pub evidence_id: String,
    /// Exact authoritative ledger anchor.
    pub anchor: LedgerAnchor,
    /// Generation identifier for the active capture/source system.
    pub generation: Generation,
    /// Human-readable evidence description or statement.
    pub statement: String,
    /// Epistemic provenance: strictly `ProvenanceClass::Observed`.
    pub provenance: ProvenanceClass,
    /// Strongly typed evidence classification.
    pub classification: SourceEvidenceClassification,
    /// Source custody status binding exact source bytes to storage.
    pub custody: SourceCustody,
    /// Explicit omission reason if source bytes were omitted (INV-003).
    pub omission: Option<OmissionReason>,
    /// Immutable sensor capsule with integrity proofs, if available.
    pub capsule: Option<SensorCapsule>,
    /// Continuity witness digest proving unbroken stream/timing continuity.
    pub continuity_witness: Option<ContentDigest>,
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
    /// Statement or description.
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

    /// Validates constitutional invariants for this source evidence record (INV-003).
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_id(&self.evidence_id)?;
        if self.anchor.site_lineage.is_empty() {
            return Err(ContractError::SourceEvidenceMissingAnchor);
        }
        if self.generation.0 == 0 {
            return Err(ContractError::GenerationConflict);
        }
        if self.statement.is_empty() || self.statement.len() > 512 {
            return Err(ContractError::InvalidIdentifier);
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

        // Invariant INV-003: Every retained observation names exact source bytes
        // or records why source retention was forbidden.
        match &self.custody {
            SourceCustody::Retained {
                source_digest,
                source_bytes,
                storage_handle,
            } => {
                if storage_handle.trim().is_empty() {
                    return Err(ContractError::SourceEvidenceEmptyStorageHandle);
                }
                if *source_bytes == 0 {
                    return Err(ContractError::EvidenceRequired);
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
            }
            SourceCustody::NotRetained => {
                // Must record a valid typed omission reason, and it cannot be None
                match self.omission {
                    Some(reason) if reason != OmissionReason::None => {}
                    _ => return Err(ContractError::SourceEvidenceOmissionRequired),
                }
                if let Some(capsule) = &self.capsule {
                    if capsule.source_bytes > 0 || capsule.source_digest.bytes() != [0u8; 32] {
                        return Err(ContractError::SourceEvidenceNotRetainedWithCapsuleBytes);
                    }
                }
            }
        }

        if let Some(witness) = self.continuity_witness {
            if witness.bytes() == [0u8; 32] {
                return Err(ContractError::InvalidDigest);
            }
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
    /// - For `Retained` custody: `KnowledgeState::Known`, binding exact source digests.
    /// - For `NotRetained` custody: `KnowledgeState::NotObservable` if upstream missing,
    ///   or `KnowledgeState::Unknown` otherwise, with empty evidence (no manufactured evidence roots).
    #[must_use]
    pub fn to_knowledge_cell(&self) -> KnowledgeCell {
        let (knowledge_state, evidence) = match &self.custody {
            SourceCustody::Retained { source_digest, .. } => {
                let mut ev = vec![*source_digest];
                if let Some(capsule) = &self.capsule {
                    let meta_digest = capsule.metadata_digest();
                    if !ev.contains(&meta_digest) {
                        ev.push(meta_digest);
                    }
                }
                if let Some(witness) = self.continuity_witness {
                    if !ev.contains(&witness) {
                        ev.push(witness);
                    }
                }
                (KnowledgeState::Known, ev)
            }
            SourceCustody::NotRetained => {
                let state = match self.omission {
                    Some(OmissionReason::UpstreamMissing) => KnowledgeState::NotObservable,
                    _ => KnowledgeState::Unknown,
                };
                (state, Vec::new())
            }
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
            state_basis: None,
        }
    }
}

impl CanonicalEncode for SourceEvidenceRecord {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
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
