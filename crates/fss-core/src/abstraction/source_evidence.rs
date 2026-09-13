#![forbid(unsafe_code)]
//! Source evidence realization (AGT-LAYER-002, INV-003).
//!
//! Authority plane types:
//! - [`SourceEvidenceRecord`]
//! - [`SourceEvidenceParams`]

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::{ContractError, KnowledgeState, Plane, ProvenanceClass};
use crate::{ContentDigest, Generation, KnowledgeCell, KnowledgeCellParams, LedgerAnchor};

use super::AgentAbstractionLayer;

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
    /// Exact source byte content digest (required unless `retention_forbidden_reason` is set per INV-003).
    pub source_bytes_digest: Option<ContentDigest>,
    /// Continuity witness digest proving unbroken stream/timing continuity.
    pub continuity_witness: Option<ContentDigest>,
    /// Explicit justification if source bytes could not be retained (INV-003 exemption).
    pub retention_forbidden_reason: Option<String>,
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
    /// Content digest of source bytes.
    pub source_bytes_digest: Option<ContentDigest>,
    /// Continuity witness digest.
    pub continuity_witness: Option<ContentDigest>,
    /// Reason why retention was forbidden, if applicable.
    pub retention_forbidden_reason: Option<String>,
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
            source_bytes_digest: params.source_bytes_digest,
            continuity_witness: params.continuity_witness,
            retention_forbidden_reason: params.retention_forbidden_reason,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates constitutional invariants for this source evidence record (INV-003).
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.evidence_id.is_empty() || self.evidence_id.len() > 128 {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.statement.is_empty() || self.statement.len() > 512 {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.anchor.site_lineage.is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.generation.0 == 0 {
            return Err(ContractError::GenerationConflict);
        }
        // Constitutional Prohibition: "Cannot promote decode or model output into source evidence."
        // Provenance MUST be Observed; Derived, ModelInference, etc. are strictly prohibited.
        if self.provenance != ProvenanceClass::Observed {
            return Err(ContractError::ProhibitedEvidencePromotion);
        }
        // Prohibition check against statement text claiming decode or model outputs
        let lower = self.statement.to_lowercase();
        if lower.contains("decoded frame")
            || lower.contains("model output")
            || lower.contains("vlm inference")
            || lower.contains("bounding box")
            || lower.contains("model prediction")
        {
            return Err(ContractError::ProhibitedEvidencePromotion);
        }
        // Invariant INV-003: Every retained observation names exact source bytes
        // or records why source retention was forbidden.
        if self.source_bytes_digest.is_none() && self.retention_forbidden_reason.is_none() {
            return Err(ContractError::EvidenceRequired);
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
    #[must_use]
    pub fn to_knowledge_cell(&self) -> KnowledgeCell {
        let evidence = if let Some(digest) = self.source_bytes_digest {
            vec![digest]
        } else {
            vec![]
        };
        let params = KnowledgeCellParams {
            claim_id: self.evidence_id.clone(),
            statement: self.statement.clone(),
            knowledge_state: KnowledgeState::Known,
            provenance: self.provenance,
            hypothesis: None,
            evidence,
            contradictions: vec![],
            valid_until: None,
            state_basis: None,
        };
        KnowledgeCell::new(params.clone())
            .unwrap_or_else(|_| KnowledgeCell::new_unvalidated(params))
    }
}

impl CanonicalEncode for SourceEvidenceRecord {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.evidence_id);
        self.anchor.encode_canonical(encoder);
        encoder.u64(self.generation.0);
        encoder.text(&self.statement);
        encoder.tag(crate::pricing::provenance_class_to_u8(self.provenance));
        match self.source_bytes_digest {
            Some(digest) => {
                encoder.u8(1);
                encoder.digest(digest);
            }
            None => encoder.u8(0),
        }
        match self.continuity_witness {
            Some(witness) => {
                encoder.u8(1);
                encoder.digest(witness);
            }
            None => encoder.u8(0),
        }
        match &self.retention_forbidden_reason {
            Some(reason) => {
                encoder.u8(1);
                encoder.text(reason);
            }
            None => encoder.u8(0),
        }
    }
}

impl CanonicalDecode for SourceEvidenceRecord {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let evidence_id = decoder.text()?.to_owned();
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let generation = Generation(decoder.u64()?);
        let statement = decoder.text()?.to_owned();
        let provenance = crate::pricing::provenance_class_from_u8(decoder.tag()?)?;
        let has_source = decoder.u8()?;
        let source_bytes_digest = match has_source {
            0 => None,
            1 => Some(decoder.digest()?),
            other => return Err(ContractError::UnknownEntryTag(other)),
        };
        let has_continuity = decoder.u8()?;
        let continuity_witness = match has_continuity {
            0 => None,
            1 => Some(decoder.digest()?),
            other => return Err(ContractError::UnknownEntryTag(other)),
        };
        let has_reason = decoder.u8()?;
        let retention_forbidden_reason = match has_reason {
            0 => None,
            1 => Some(decoder.text()?.to_owned()),
            other => return Err(ContractError::UnknownEntryTag(other)),
        };

        let record = Self {
            evidence_id,
            anchor,
            generation,
            statement,
            provenance,
            source_bytes_digest,
            continuity_witness,
            retention_forbidden_reason,
        };
        record.validate()?;
        Ok(record)
    }
}
