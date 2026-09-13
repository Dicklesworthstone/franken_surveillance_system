#![forbid(unsafe_code)]
//! Realization of hydration ladder level H1: semantic_synopsis (AGT-H1, fss-x4a.30.82.13).
//!
//! H1 represents the progressive hydration level exposing:
//! - typed facts ([`WorldFact`])
//! - knowledge states ([`KnowledgeState`])
//! - provenance ([`ProvenanceClass`])
//! - contradictions ([`Contradiction`])
//! - quality ([`SynopsisQuality`])
//! - omissions ([`OmissionReason`])
//!
//! H1 strictly forbids raw payload bytes, decoded media, decision crops/artifacts,
//! or laboratory replay bundles.

use core::fmt;
use std::collections::BTreeSet;

use super::{
    Completeness, HydrationError, HydrationLevel, SemanticHandle, decode_text_set, encode_text_set,
    valid_text,
};
use crate::agent::KnowledgeCell;
use crate::belief::{BeliefInterval, Contradiction};
use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::{ContractError, KnowledgeState, ProvenanceClass};
use crate::sensor_capsule::OmissionReason;
use crate::{BudgetVector, ContentDigest, ContractBasis, LedgerAnchor, TimestampNs, WorldFact};

/// Stable identifier for hydration ladder level H1.
pub const H1_LEVEL_ID: &str = "H1";

/// Stable name for hydration ladder level H1.
pub const H1_LEVEL_NAME: &str = "semantic_synopsis";

/// Normative content declaration for hydration ladder level H1 from the agent abstraction registry.
pub const H1_CONTENT: &str =
    "typed facts, knowledge states, provenance, contradictions, quality, and omissions";

/// Normative owning crate/module for hydration ladder level H1.
pub const H1_OWNER: &str = "fss-situation/fss-context-pack";

/// Canonical schema discriminator tag for H1 semantic synopsis binary envelopes.
pub const H1_SCHEMA: &str = "fss.h1_semantic_synopsis.v1";

/// Strongly typed classification of semantic synopsis content.
///
/// Prevents prohibited raw payloads, decodes, decision crops, or laboratory bundles
/// from being promoted to H1 semantic synopsis.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SynopsisClassification {
    /// Pure semantic synopsis containing typed facts and epistemic states.
    SemanticSynopsis,
    /// Epistemic belief synopsis with contradiction analysis.
    EpistemicBeliefSynopsis,
    /// Sensor and environment coverage/quality summary.
    CoverageQualitySynopsis,
    /// Multi-source corroboration synopsis.
    CorroborationSynopsis,
    /// Prohibited raw packet or payload stream (violates H1, belongs to H3).
    ProhibitedRawPayload,
    /// Prohibited decoded frame or media stream buffer (violates H1, belongs to H3).
    ProhibitedDecodedMedia,
    /// Prohibited redacted decision crop or artifact (violates H1, belongs to H2).
    ProhibitedDecisionArtifact,
    /// Prohibited laboratory expansion or replay bundle (violates H1, belongs to H4).
    ProhibitedLaboratoryReplay,
}

impl SynopsisClassification {
    /// Returns true if this classification is permitted for H1 semantic synopsis.
    #[must_use]
    pub const fn is_permitted(&self) -> bool {
        matches!(
            self,
            Self::SemanticSynopsis
                | Self::EpistemicBeliefSynopsis
                | Self::CoverageQualitySynopsis
                | Self::CorroborationSynopsis
        )
    }

    /// Returns true if this classification is prohibited for H1 semantic synopsis.
    #[must_use]
    pub const fn is_prohibited(&self) -> bool {
        !self.is_permitted()
    }

    /// Returns the canonical identifier string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SemanticSynopsis => "semantic_synopsis",
            Self::EpistemicBeliefSynopsis => "epistemic_belief_synopsis",
            Self::CoverageQualitySynopsis => "coverage_quality_synopsis",
            Self::CorroborationSynopsis => "corroboration_synopsis",
            Self::ProhibitedRawPayload => "prohibited_raw_payload",
            Self::ProhibitedDecodedMedia => "prohibited_decoded_media",
            Self::ProhibitedDecisionArtifact => "prohibited_decision_artifact",
            Self::ProhibitedLaboratoryReplay => "prohibited_laboratory_replay",
        }
    }

    /// Parses from schema spelling.
    pub fn from_name(s: &str) -> Result<Self, ContractError> {
        match s {
            "semantic_synopsis" => Ok(Self::SemanticSynopsis),
            "epistemic_belief_synopsis" => Ok(Self::EpistemicBeliefSynopsis),
            "coverage_quality_synopsis" => Ok(Self::CoverageQualitySynopsis),
            "corroboration_synopsis" => Ok(Self::CorroborationSynopsis),
            "prohibited_raw_payload" | "raw_payload" | "raw_bytes" | "raw_packets" => {
                Ok(Self::ProhibitedRawPayload)
            }
            "prohibited_decoded_media" | "decoded_frame" | "decoded_media" => {
                Ok(Self::ProhibitedDecodedMedia)
            }
            "prohibited_decision_artifact" | "decision_artifact" | "crop" | "keyframe" => {
                Ok(Self::ProhibitedDecisionArtifact)
            }
            "prohibited_laboratory_replay" | "laboratory_replay" | "replay_bundle" => {
                Ok(Self::ProhibitedLaboratoryReplay)
            }
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl CanonicalEncode for SynopsisClassification {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for SynopsisClassification {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let text = decoder.text()?;
        Self::from_name(text)
    }
}

impl fmt::Display for SynopsisClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for SynopsisClassification {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s)
    }
}

/// Strongly typed quality and completeness evaluation for an H1 semantic synopsis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SynopsisQuality {
    /// Conservative completeness classification across the synopsis domain.
    pub completeness: Completeness,
    /// Assessed belief/confidence interval, if derived.
    pub belief_interval: Option<BeliefInterval>,
    /// Temporal precision in nanoseconds.
    pub temporal_precision_ns: u64,
    /// Digest of calibration parameters or generation witness, if calibrated.
    pub calibration_digest: Option<ContentDigest>,
}

impl SynopsisQuality {
    /// Creates a new validated synopsis quality descriptor.
    pub fn new(
        completeness: Completeness,
        belief_interval: Option<BeliefInterval>,
        temporal_precision_ns: u64,
        calibration_digest: Option<ContentDigest>,
    ) -> Result<Self, HydrationError> {
        let quality = Self {
            completeness,
            belief_interval,
            temporal_precision_ns,
            calibration_digest,
        };
        quality.validate()?;
        Ok(quality)
    }

    /// Validates constitutional invariants for synopsis quality.
    pub fn validate(&self) -> Result<(), HydrationError> {
        if let Some(digest) = self.calibration_digest
            && digest.bytes().iter().all(|&b| b == 0)
        {
            return Err(ContractError::InvalidDigest.into());
        }
        Ok(())
    }

    /// Returns true if the synopsis quality represents a complete observation.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.completeness, Completeness::Complete)
    }
}

impl CanonicalEncode for SynopsisQuality {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.completeness.encode_canonical(encoder);
        match &self.belief_interval {
            Some(bi) => {
                encoder.bool(true);
                bi.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        encoder.u64(self.temporal_precision_ns);
        match self.calibration_digest {
            Some(digest) => {
                encoder.bool(true);
                encoder.digest(digest);
            }
            None => encoder.bool(false),
        }
    }
}

impl CanonicalDecode for SynopsisQuality {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let completeness = Completeness::decode_canonical(decoder)?;
        let has_belief = decoder.bool()?;
        let belief_interval = if has_belief {
            Some(BeliefInterval::decode_canonical(decoder)?)
        } else {
            None
        };
        let temporal_precision_ns = decoder.u64()?;
        let has_calibration = decoder.bool()?;
        let calibration_digest = if has_calibration {
            Some(decoder.digest()?)
        } else {
            None
        };
        let quality = Self {
            completeness,
            belief_interval,
            temporal_precision_ns,
            calibration_digest,
        };
        quality.validate().map_err(|e| match e {
            HydrationError::Contract(c) => c,
            _ => ContractError::InvalidIdentifier,
        })?;
        Ok(quality)
    }
}

/// Content specification used when extracting an H1 synopsis from a published [`SemanticHandle`].
#[derive(Clone, Debug, PartialEq)]
pub struct H1ContentSpec {
    /// Typed facts observed or established for this subject.
    pub facts: Vec<WorldFact>,
    /// Set of knowledge states represented across this synopsis.
    pub knowledge_states: BTreeSet<KnowledgeState>,
    /// Set of provenance classes represented in this synopsis.
    pub provenance_classes: BTreeSet<ProvenanceClass>,
    /// Known contradictions active within this synopsis scope.
    pub contradictions: Vec<Contradiction>,
    /// Quality and completeness evaluation of this synopsis.
    pub quality: SynopsisQuality,
    /// Explicit typed omission reasons if any facts/evidence were withheld.
    pub omissions: BTreeSet<OmissionReason>,
    /// Optional classification (defaults to `SemanticSynopsis`).
    pub classification: Option<SynopsisClassification>,
}

/// Parameters used to construct an [`H1SemanticSynopsis`] directly.
#[derive(Clone, Debug, PartialEq)]
pub struct H1SynopsisParams {
    /// Content-derived handle identifier.
    pub handle_id: String,
    /// Stable canonical subject identity.
    pub subject_id: String,
    /// Exact subject content digest.
    pub subject_digest: ContentDigest,
    /// Registered semantic type.
    pub semantic_type: String,
    /// Strongly typed synopsis classification.
    pub classification: SynopsisClassification,
    /// Authority anchor of this synopsis revision.
    pub anchor: LedgerAnchor,
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Conservative estimated resource cost to hydrate at H1.
    pub estimated_cost: BudgetVector,
    /// Required capability identifiers at H1.
    pub required_capabilities: BTreeSet<String>,
    /// Privacy class independently authorized at hydration time.
    pub privacy_class: String,
    /// Publication timestamp.
    pub published_at: TimestampNs,
    /// Time after which this synopsis must return an expired state.
    pub retention_until: TimestampNs,
    /// Typed facts observed or established for this subject.
    pub facts: Vec<WorldFact>,
    /// Set of knowledge states represented across this synopsis.
    pub knowledge_states: BTreeSet<KnowledgeState>,
    /// Set of provenance classes represented in this synopsis.
    pub provenance_classes: BTreeSet<ProvenanceClass>,
    /// Known contradictions active within this synopsis scope.
    pub contradictions: Vec<Contradiction>,
    /// Quality and completeness evaluation of this synopsis.
    pub quality: SynopsisQuality,
    /// Explicit typed omission reasons if any facts/evidence were withheld.
    pub omissions: BTreeSet<OmissionReason>,
}

/// Strongly typed representation of the H1 Semantic Synopsis level of the progressive hydration ladder.
///
/// Encapsulates the content specified by normative row H1:
/// typed facts, knowledge states, provenance, contradictions, quality, and omissions.
#[derive(Clone, Debug, PartialEq)]
pub struct H1SemanticSynopsis {
    /// Content-derived handle identifier.
    pub handle_id: String,
    /// Stable canonical subject identity.
    pub subject_id: String,
    /// Exact subject content digest.
    pub subject_digest: ContentDigest,
    /// Registered semantic type.
    pub semantic_type: String,
    /// Strongly typed synopsis classification.
    pub classification: SynopsisClassification,
    /// Authority anchor of this synopsis revision.
    pub anchor: LedgerAnchor,
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Conservative estimated resource cost to hydrate at H1.
    pub estimated_cost: BudgetVector,
    /// Required capability identifiers at H1.
    pub required_capabilities: BTreeSet<String>,
    /// Privacy class independently authorized at hydration time.
    pub privacy_class: String,
    /// Publication timestamp.
    pub published_at: TimestampNs,
    /// Time after which this synopsis must return an expired state.
    pub retention_until: TimestampNs,
    /// Typed facts observed or established for this subject.
    pub facts: Vec<WorldFact>,
    /// Set of knowledge states represented across this synopsis.
    pub knowledge_states: BTreeSet<KnowledgeState>,
    /// Set of provenance classes represented in this synopsis.
    pub provenance_classes: BTreeSet<ProvenanceClass>,
    /// Known contradictions active within this synopsis scope.
    pub contradictions: Vec<Contradiction>,
    /// Quality and completeness evaluation of this synopsis.
    pub quality: SynopsisQuality,
    /// Explicit typed omission reasons if any facts/evidence were withheld.
    pub omissions: BTreeSet<OmissionReason>,
}

impl H1SemanticSynopsis {
    /// Constructs an [`H1SemanticSynopsis`] from strongly typed parameters and validates all invariants.
    pub fn new(params: H1SynopsisParams) -> Result<Self, HydrationError> {
        let synopsis = Self {
            handle_id: params.handle_id,
            subject_id: params.subject_id,
            subject_digest: params.subject_digest,
            semantic_type: params.semantic_type,
            classification: params.classification,
            anchor: params.anchor,
            contract_basis: params.contract_basis,
            estimated_cost: params.estimated_cost,
            required_capabilities: params.required_capabilities,
            privacy_class: params.privacy_class,
            published_at: params.published_at,
            retention_until: params.retention_until,
            facts: params.facts,
            knowledge_states: params.knowledge_states,
            provenance_classes: params.provenance_classes,
            contradictions: params.contradictions,
            quality: params.quality,
            omissions: params.omissions,
        };
        synopsis.validate()?;
        Ok(synopsis)
    }

    /// Extracts and validates an H1 semantic synopsis from a published [`SemanticHandle`].
    pub fn from_semantic_handle(
        handle: &SemanticHandle,
        content: H1ContentSpec,
    ) -> Result<Self, HydrationError> {
        if !handle.levels.contains(&HydrationLevel::H1) {
            return Err(HydrationError::LevelUnavailable);
        }

        let estimated_cost = match handle.estimated_costs.get(&HydrationLevel::H1) {
            Some(cost) => *cost,
            None => BudgetVector::ZERO,
        };

        let required_capabilities = match handle.required_capabilities.get(&HydrationLevel::H1) {
            Some(caps) => caps.clone(),
            None => BTreeSet::new(),
        };

        let classification = match content.classification {
            Some(c) => c,
            None => SynopsisClassification::SemanticSynopsis,
        };

        let synopsis = Self {
            handle_id: handle.handle_id.clone(),
            subject_id: handle.subject_id.clone(),
            subject_digest: handle.subject_digest,
            semantic_type: handle.semantic_type.clone(),
            classification,
            anchor: handle.anchor.clone(),
            contract_basis: handle.contract_basis.clone(),
            estimated_cost,
            required_capabilities,
            privacy_class: handle.privacy_class.clone(),
            published_at: handle.published_at,
            retention_until: handle.retention_until,
            facts: content.facts,
            knowledge_states: content.knowledge_states,
            provenance_classes: content.provenance_classes,
            contradictions: content.contradictions,
            quality: content.quality,
            omissions: content.omissions,
        };

        synopsis.validate()?;
        Ok(synopsis)
    }

    /// Validates all load-bearing invariants for H1 semantic synopsis.
    pub fn validate(&self) -> Result<(), HydrationError> {
        if !valid_text(&self.handle_id)
            || !valid_text(&self.subject_id)
            || !valid_text(&self.semantic_type)
            || !valid_text(&self.privacy_class)
            || !valid_text(&self.anchor.site_lineage)
            || !valid_text(&self.contract_basis.semantic_protocol)
        {
            return Err(ContractError::InvalidIdentifier.into());
        }

        for cap in &self.required_capabilities {
            if !valid_text(cap) {
                return Err(ContractError::InvalidIdentifier.into());
            }
        }

        // Subject digest must not be zeroed
        if self.subject_digest.bytes().iter().all(|&b| b == 0) {
            return Err(ContractError::InvalidDigest.into());
        }

        // Retention must not precede publication
        if self.retention_until < self.published_at {
            return Err(HydrationError::ContinuationExpired);
        }

        // Constitutional check: Prohibited evidence classification cannot be promoted
        if self.classification.is_prohibited() {
            return Err(ContractError::ProhibitedEvidencePromotion.into());
        }

        // Validate synopsis quality
        self.quality.validate()?;

        // Knowledge states and provenance classes must not be empty
        if self.knowledge_states.is_empty() || self.provenance_classes.is_empty() {
            return Err(ContractError::InvalidIdentifier.into());
        }

        // Facts validation: each fact must be valid, canonically ordered, no duplicate fact_id
        for fact in &self.facts {
            fact.validate()?;
            // Fact provenance must be declared in the synopsis provenance set
            if !self.provenance_classes.contains(&fact.provenance) {
                return Err(ContractError::ProhibitedEvidencePromotion.into());
            }
        }
        for pair in self.facts.windows(2) {
            if pair[0].fact_id >= pair[1].fact_id {
                return Err(ContractError::NonCanonicalOrdering.into());
            }
        }

        // Contradictions validation: each contradiction verified, canonically ordered, no duplicates
        for contra in &self.contradictions {
            contra.verify().map_err(ContractError::from)?;
        }
        for pair in self.contradictions.windows(2) {
            if pair[0].contradiction_id() >= pair[1].contradiction_id() {
                return Err(ContractError::NonCanonicalOrdering.into());
            }
        }

        // Omissions check: cannot contain None as a reason; omissions must be genuine reasons
        if self.omissions.contains(&OmissionReason::None) {
            return Err(ContractError::InvalidIdentifier.into());
        }

        Ok(())
    }

    /// Returns the exact hydration level ([`HydrationLevel::H1`]).
    #[must_use]
    pub const fn level(&self) -> HydrationLevel {
        HydrationLevel::H1
    }

    /// Returns the normative level identifier (`"H1"`).
    #[must_use]
    pub const fn level_id(&self) -> &'static str {
        H1_LEVEL_ID
    }

    /// Returns the normative level name (`"semantic_synopsis"`).
    #[must_use]
    pub const fn level_name(&self) -> &'static str {
        H1_LEVEL_NAME
    }

    /// Returns the exact normative content declaration from the agent abstraction registry.
    #[must_use]
    pub const fn content_declaration(&self) -> &'static str {
        H1_CONTENT
    }

    /// Returns the normative owning crate/module.
    #[must_use]
    pub const fn owner(&self) -> &'static str {
        H1_OWNER
    }

    /// Returns the typed classification of this synopsis.
    #[must_use]
    pub const fn classification(&self) -> SynopsisClassification {
        self.classification
    }

    /// Returns the slice of typed world facts.
    #[must_use]
    pub fn facts(&self) -> &[WorldFact] {
        &self.facts
    }

    /// Looks up a typed world fact by its stable identifier.
    #[must_use]
    pub fn fact(&self, id: &str) -> Option<&WorldFact> {
        self.facts.iter().find(|f| f.fact_id == id)
    }

    /// Returns the set of knowledge states declared in this synopsis.
    #[must_use]
    pub const fn knowledge_states(&self) -> &BTreeSet<KnowledgeState> {
        &self.knowledge_states
    }

    /// Checks if a specific knowledge state is declared in this synopsis.
    #[must_use]
    pub fn has_knowledge_state(&self, state: KnowledgeState) -> bool {
        self.knowledge_states.contains(&state)
    }

    /// Returns the set of provenance classes declared in this synopsis.
    #[must_use]
    pub const fn provenance_classes(&self) -> &BTreeSet<ProvenanceClass> {
        &self.provenance_classes
    }

    /// Checks if a specific provenance class is declared in this synopsis.
    #[must_use]
    pub fn has_provenance(&self, prov: ProvenanceClass) -> bool {
        self.provenance_classes.contains(&prov)
    }

    /// Returns the slice of active contradictions in this synopsis.
    #[must_use]
    pub fn contradictions(&self) -> &[Contradiction] {
        &self.contradictions
    }

    /// Returns true if this synopsis contains active contradictions.
    #[must_use]
    pub fn has_contradictions(&self) -> bool {
        !self.contradictions.is_empty()
    }

    /// Returns the synopsis quality descriptor.
    #[must_use]
    pub const fn quality(&self) -> &SynopsisQuality {
        &self.quality
    }

    /// Returns true if the synopsis quality indicates complete observation.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.quality.is_complete()
    }

    /// Returns the set of omission reasons.
    #[must_use]
    pub const fn omissions(&self) -> &BTreeSet<OmissionReason> {
        &self.omissions
    }

    /// Returns true if any omissions are recorded.
    #[must_use]
    pub fn has_omissions(&self) -> bool {
        !self.omissions.is_empty()
    }

    /// Returns true if this synopsis has passed its retention expiration timestamp.
    #[must_use]
    pub fn is_expired_at(&self, now: TimestampNs) -> bool {
        now > self.retention_until
    }

    /// Checks whether a specific capability is required for H1 access.
    #[must_use]
    pub fn requires_capability(&self, cap: &str) -> bool {
        self.required_capabilities.contains(cap)
    }

    /// Checks whether the estimated cost fits within the provided budget.
    #[must_use]
    pub fn satisfies_budget(&self, budget: &BudgetVector) -> bool {
        self.estimated_cost.fits_within(*budget)
    }

    /// Converts this synopsis facts into canonical [`KnowledgeCell`] representations
    /// carrying exact source evidence digests.
    #[must_use]
    pub fn to_knowledge_cells(&self) -> Vec<KnowledgeCell> {
        self.facts
            .iter()
            .map(|fact| KnowledgeCell {
                claim_id: fact.fact_id.clone(),
                statement: fact.statement.clone(),
                knowledge_state: KnowledgeState::Known,
                provenance: fact.provenance,
                hypothesis: None,
                evidence: vec![fact.evidence_digest],
                contradictions: Vec::new(),
                valid_until: None,
                state_basis: None,
            })
            .collect()
    }

    /// Computes the deterministic canonical digest of this H1 semantic synopsis.
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Returns the deterministic canonical binary encoding of this synopsis.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        encoder.finish()
    }

    /// Decodes an [`H1SemanticSynopsis`] from canonical binary bytes and verifies no trailing bytes exist.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let synopsis = Self::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;
        Ok(synopsis)
    }
}

impl CanonicalEncode for H1SemanticSynopsis {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(H1_SCHEMA);
        encoder.text(&self.handle_id);
        encoder.text(&self.subject_id);
        encoder.digest(self.subject_digest);
        encoder.text(&self.semantic_type);
        self.classification.encode_canonical(encoder);
        self.anchor.encode_canonical(encoder);
        self.contract_basis.encode_canonical(encoder);
        self.estimated_cost.encode_canonical(encoder);
        encode_text_set(&self.required_capabilities, encoder);
        encoder.text(&self.privacy_class);
        self.published_at.encode_canonical(encoder);
        self.retention_until.encode_canonical(encoder);
        self.quality.encode_canonical(encoder);

        // Encode facts
        encoder.u64(self.facts.len() as u64);
        for fact in &self.facts {
            fact.encode_canonical(encoder);
        }

        // Encode knowledge states
        encoder.u64(self.knowledge_states.len() as u64);
        for ks in &self.knowledge_states {
            ks.encode_canonical(encoder);
        }

        // Encode provenance classes
        encoder.u64(self.provenance_classes.len() as u64);
        for p in &self.provenance_classes {
            p.encode_canonical(encoder);
        }

        // Encode contradictions
        encoder.u64(self.contradictions.len() as u64);
        for contra in &self.contradictions {
            contra.encode_canonical(encoder);
        }

        // Encode omissions
        encoder.u64(self.omissions.len() as u64);
        for omission in &self.omissions {
            omission.encode_canonical(encoder);
        }
    }
}

impl CanonicalDecode for H1SemanticSynopsis {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != H1_SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let handle_id = decoder.text()?.to_string();
        let subject_id = decoder.text()?.to_string();
        let subject_digest = decoder.digest()?;
        let semantic_type = decoder.text()?.to_string();
        let classification = SynopsisClassification::decode_canonical(decoder)?;
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let contract_basis = ContractBasis::decode_canonical(decoder)?;
        let estimated_cost = <BudgetVector as CanonicalDecode>::decode_canonical(decoder)?;
        let required_capabilities = decode_text_set(decoder)?;
        let privacy_class = decoder.text()?.to_string();
        let published_at = TimestampNs::decode_canonical(decoder)?;
        let retention_until = TimestampNs::decode_canonical(decoder)?;
        let quality = SynopsisQuality::decode_canonical(decoder)?;

        // Decode facts
        let facts_count = decoder.u64()? as usize;
        let mut facts = Vec::with_capacity(facts_count);
        let mut prev_fact_id: Option<String> = None;
        for _ in 0..facts_count {
            let fact = WorldFact::decode_canonical(decoder)?;
            if let Some(prev) = &prev_fact_id
                && fact.fact_id <= *prev
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
            prev_fact_id = Some(fact.fact_id.clone());
            facts.push(fact);
        }

        // Decode knowledge states
        let ks_count = decoder.u64()? as usize;
        let mut knowledge_states = BTreeSet::new();
        let mut prev_ks: Option<KnowledgeState> = None;
        for _ in 0..ks_count {
            let ks = KnowledgeState::decode_canonical(decoder)?;
            if let Some(prev) = prev_ks
                && ks <= prev
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
            prev_ks = Some(ks);
            knowledge_states.insert(ks);
        }

        // Decode provenance classes
        let prov_count = decoder.u64()? as usize;
        let mut provenance_classes = BTreeSet::new();
        let mut prev_prov: Option<ProvenanceClass> = None;
        for _ in 0..prov_count {
            let prov = ProvenanceClass::decode_canonical(decoder)?;
            if let Some(prev) = prev_prov
                && prov <= prev
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
            prev_prov = Some(prov);
            provenance_classes.insert(prov);
        }

        // Decode contradictions
        let contra_count = decoder.u64()? as usize;
        let mut contradictions = Vec::with_capacity(contra_count);
        let mut prev_contra_id: Option<String> = None;
        for _ in 0..contra_count {
            let contra = Contradiction::decode_canonical(decoder)?;
            if let Some(prev) = &prev_contra_id
                && contra.contradiction_id() <= prev.as_str()
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
            prev_contra_id = Some(contra.contradiction_id().to_string());
            contradictions.push(contra);
        }

        // Decode omissions
        let omission_count = decoder.u64()? as usize;
        let mut omissions = BTreeSet::new();
        let mut prev_omission: Option<OmissionReason> = None;
        for _ in 0..omission_count {
            let omission = OmissionReason::decode_canonical(decoder)?;
            if let Some(prev) = prev_omission
                && omission <= prev
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
            prev_omission = Some(omission);
            omissions.insert(omission);
        }

        let synopsis = Self {
            handle_id,
            subject_id,
            subject_digest,
            semantic_type,
            classification,
            anchor,
            contract_basis,
            estimated_cost,
            required_capabilities,
            privacy_class,
            published_at,
            retention_until,
            facts,
            knowledge_states,
            provenance_classes,
            contradictions,
            quality,
            omissions,
        };

        synopsis.validate().map_err(|e| match e {
            HydrationError::Contract(c) => c,
            HydrationError::ContinuationExpired => ContractError::InvertedTimeInterval,
            _ => ContractError::InvalidIdentifier,
        })?;

        Ok(synopsis)
    }
}
