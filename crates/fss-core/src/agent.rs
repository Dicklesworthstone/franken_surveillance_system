//! Agent-facing situation, possible-world, affordance, and handoff contracts.

use std::collections::BTreeSet;
use std::fmt;

use crate::{
    BudgetVector, CanonicalEncode, CanonicalEncoder, Completeness, ContentDigest, ContractError,
    Generation, HandoffId, HypothesisDisposition, KnowledgeState, LedgerAnchor, MissionId,
    ObligationId, PrincipalId, PrivacyGeneration, ProvenanceClass, SessionId, TimestampNs,
};

/// Exact semantic universe used to interpret an agent request or response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractBasis {
    /// Semantic protocol version.
    pub semantic_protocol: String,
    /// Digest of the JSON Schema catalog.
    pub schema_catalog_digest: ContentDigest,
    /// Ontology generation.
    pub ontology_generation_id: String,
    /// Public operation registry digest.
    pub operation_registry_digest: ContentDigest,
    /// View registry digest.
    pub view_registry_digest: ContentDigest,
    /// Capability registry digest.
    pub capability_registry_digest: ContentDigest,
    /// Error registry digest.
    pub error_registry_digest: ContentDigest,
    /// Cost registry digest.
    pub cost_registry_digest: ContentDigest,
    /// Producer release identity.
    pub producer_release_id: String,
    /// Accepted dated nightly identity.
    pub accepted_nightly: Option<String>,
}

/// Exact registry bytes and release identities used to build a contract basis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContractBasisRegistryBytes<'a> {
    /// Exact raw schema catalog bytes.
    pub schema_catalog: &'a [u8],
    /// Exact raw operation registry bytes.
    pub operations: &'a [u8],
    /// Exact raw view registry bytes.
    pub views: &'a [u8],
    /// Exact raw capability registry bytes.
    pub capabilities: &'a [u8],
    /// Exact raw error registry bytes.
    pub errors: &'a [u8],
    /// Exact raw cost registry bytes.
    pub costs: &'a [u8],
    /// Producer release identity.
    pub producer_release_id: &'a str,
    /// Accepted dated nightly identity.
    pub accepted_nightly: Option<&'a str>,
}

impl<'a> ContractBasisRegistryBytes<'a> {
    /// Builds a parameter struct with no accepted nightly specified.
    #[must_use]
    pub const fn new(
        schema_catalog: &'a [u8],
        operations: &'a [u8],
        views: &'a [u8],
        capabilities: &'a [u8],
        errors: &'a [u8],
        costs: &'a [u8],
        producer_release_id: &'a str,
    ) -> Self {
        Self {
            schema_catalog,
            operations,
            views,
            capabilities,
            errors,
            costs,
            producer_release_id,
            accepted_nightly: None,
        }
    }

    /// Sets the accepted nightly identifier.
    #[must_use]
    pub const fn with_accepted_nightly(mut self, accepted_nightly: &'a str) -> Self {
        self.accepted_nightly = Some(accepted_nightly);
        self
    }

    /// Validates that required identity invariants are satisfied.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.producer_release_id.is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(())
    }
}

impl ContractBasis {
    /// Builds a deterministic reference basis from exact registry bytes.
    #[must_use]
    pub fn from_registry_bytes(spec: ContractBasisRegistryBytes<'_>) -> Self {
        Self {
            semantic_protocol: "fss/1".to_owned(),
            schema_catalog_digest: ContentDigest::sha256(spec.schema_catalog),
            ontology_generation_id: "ontology:reference:v1".to_owned(),
            operation_registry_digest: ContentDigest::sha256(spec.operations),
            view_registry_digest: ContentDigest::sha256(spec.views),
            capability_registry_digest: ContentDigest::sha256(spec.capabilities),
            error_registry_digest: ContentDigest::sha256(spec.errors),
            cost_registry_digest: ContentDigest::sha256(spec.costs),
            producer_release_id: spec.producer_release_id.to_owned(),
            accepted_nightly: spec.accepted_nightly.map(ToOwned::to_owned),
        }
    }

    /// Validates that required identity invariants are satisfied.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.producer_release_id.is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(())
    }

    /// Returns the canonical basis digest.
    #[must_use]
    pub fn basis_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.agent_contract_basis.v1")
    }
}

impl CanonicalEncode for ContractBasis {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.semantic_protocol);
        encoder.digest(self.schema_catalog_digest);
        encoder.text(&self.ontology_generation_id);
        encoder.digest(self.operation_registry_digest);
        encoder.digest(self.view_registry_digest);
        encoder.digest(self.capability_registry_digest);
        encoder.digest(self.error_registry_digest);
        encoder.digest(self.cost_registry_digest);
        encoder.text(&self.producer_release_id);
        match &self.accepted_nightly {
            Some(value) => {
                encoder.bool(true);
                encoder.text(value);
            }
            None => encoder.bool(false),
        }
    }
}

/// Marker printed and hashed in place of a withheld `redacted` statement.
///
/// A redacted cell never exposes its statement through `Debug` or through its canonical
/// encoding, so neither diagnostics nor digests can serve as a dictionary oracle for the
/// withheld proposition.
pub const REDACTED_STATEMENT_MARKER: &str = "<redacted:statement-withheld>";

/// Which projection withholds a `redacted` proposition (KSTATE-007).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RedactionReason {
    /// Withheld by the current privacy projection.
    PrivacyProjection,
    /// Withheld by the current capability projection.
    CapabilityProjection,
}

impl RedactionReason {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrivacyProjection => "privacy_projection",
            Self::CapabilityProjection => "capability_projection",
        }
    }
}

/// Explicit typed marker naming the projection that withholds a `redacted` proposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactionMarker {
    /// Projection that withholds the proposition or its evidence.
    pub reason: RedactionReason,
    /// Exact privacy projection generation that applied the redaction.
    pub privacy_generation: PrivacyGeneration,
}

impl CanonicalEncode for RedactionMarker {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.reason.as_str());
        encoder.text(self.privacy_generation.as_str());
    }
}

/// Older anchor or generation at which a `stale` proposition was last valid (KSTATE-005).
///
/// Each variant names both the older point and the current point it is older than, so a
/// stale basis can never describe the current anchor or generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StaleBasis {
    /// The proposition was valid only at an older ledger anchor.
    OlderAnchor {
        /// Anchor at which the proposition was last valid.
        valid_at: Box<LedgerAnchor>,
        /// Current anchor the proposition has not been revalidated against.
        current: Box<LedgerAnchor>,
    },
    /// The proposition was valid only at an older generation.
    OlderGeneration {
        /// Generation at which the proposition was last valid.
        valid_at: Generation,
        /// Current generation the proposition has not been revalidated against.
        current: Generation,
    },
}

impl StaleBasis {
    /// Refuses a basis that is not strictly older than the current anchor or generation.
    ///
    /// Anchors from different site lineages are not comparable and are refused.
    pub fn validate(&self) -> Result<(), ContractError> {
        let strictly_older = match self {
            Self::OlderAnchor { valid_at, current } => {
                valid_at.site_lineage == current.site_lineage
                    && (valid_at.ledger_epoch, valid_at.commit_sequence)
                        < (current.ledger_epoch, current.commit_sequence)
            }
            Self::OlderGeneration { valid_at, current } => valid_at < current,
        };
        if strictly_older {
            Ok(())
        } else {
            Err(ContractError::StaleBasisNotOlder)
        }
    }
}

impl CanonicalEncode for StaleBasis {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::OlderAnchor { valid_at, current } => {
                encoder.u8(1);
                valid_at.encode_canonical(encoder);
                current.encode_canonical(encoder);
            }
            Self::OlderGeneration { valid_at, current } => {
                encoder.u8(2);
                encoder.u64(valid_at.0);
                encoder.u64(current.0);
            }
        }
    }
}

/// One outcome branch kept open while a consequential external outcome is unresolved.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReconciliationBranch {
    /// The consequential external outcome occurred.
    Occurred,
    /// The consequential external outcome did not occur.
    NotOccurred,
    /// The consequential external outcome occurred only in part.
    PartiallyOccurred,
}

impl ReconciliationBranch {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Occurred => "occurred",
            Self::NotOccurred => "not_occurred",
            Self::PartiallyOccurred => "partially_occurred",
        }
    }
}

/// Typed reconciliation basis for an `indeterminate` proposition (KSTATE-008).
///
/// Names the attempt or revision whose consequential external outcome is unresolved and the
/// branches that planning must keep open until that outcome is proved or safely negated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationBasis {
    /// Root of the attempt receipt or event revision whose outcome is unresolved.
    pub unresolved_outcome_root: ContentDigest,
    /// Reconciliation branches kept open until the outcome is proved or safely negated.
    pub branches: BTreeSet<ReconciliationBranch>,
}

impl ReconciliationBasis {
    /// Keeps both the occurred and the not-occurred branch open for `unresolved_outcome_root`.
    #[must_use]
    pub fn occurred_or_not(unresolved_outcome_root: ContentDigest) -> Self {
        Self {
            unresolved_outcome_root,
            branches: BTreeSet::from([
                ReconciliationBranch::Occurred,
                ReconciliationBranch::NotOccurred,
            ]),
        }
    }

    /// Refuses a basis that dropped the occurred or the not-occurred branch.
    ///
    /// An outcome that is neither proved nor safely negated keeps both branches open.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.branches.contains(&ReconciliationBranch::Occurred)
            && self.branches.contains(&ReconciliationBranch::NotOccurred)
        {
            Ok(())
        } else {
            Err(ContractError::ReconciliationBranchesIncomplete)
        }
    }
}

impl CanonicalEncode for ReconciliationBasis {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.unresolved_outcome_root);
        encoder.u64(self.branches.len() as u64);
        for branch in &self.branches {
            encoder.text(branch.as_str());
        }
    }
}

/// Typed state-specific basis that a knowledge cell must carry when its state names one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KnowledgeStateBasis {
    /// Redaction marker required by `redacted` (KSTATE-007).
    Redaction(RedactionMarker),
    /// Older anchor or generation required by `stale` (KSTATE-005).
    Stale(StaleBasis),
    /// Reconciliation basis and branches required by `indeterminate` (KSTATE-008).
    Reconciliation(ReconciliationBasis),
}

impl KnowledgeStateBasis {
    /// Returns the only knowledge state this basis may accompany.
    #[must_use]
    pub const fn knowledge_state(&self) -> KnowledgeState {
        match self {
            Self::Redaction(_) => KnowledgeState::Redacted,
            Self::Stale(_) => KnowledgeState::Stale,
            Self::Reconciliation(_) => KnowledgeState::Indeterminate,
        }
    }

    /// Validates the basis payload itself.
    pub fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Redaction(_) => Ok(()),
            Self::Stale(basis) => basis.validate(),
            Self::Reconciliation(basis) => basis.validate(),
        }
    }
}

impl CanonicalEncode for KnowledgeStateBasis {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::Redaction(marker) => {
                encoder.u8(1);
                marker.encode_canonical(encoder);
            }
            Self::Stale(basis) => {
                encoder.u8(2);
                basis.encode_canonical(encoder);
            }
            Self::Reconciliation(basis) => {
                encoder.u8(3);
                basis.encode_canonical(encoder);
            }
        }
    }
}

/// Returns the typed refusal for a state whose registry meaning requires a basis.
const fn required_basis_error(state: KnowledgeState) -> Option<ContractError> {
    match state {
        KnowledgeState::Redacted => Some(ContractError::RedactionMarkerRequired),
        KnowledgeState::Stale => Some(ContractError::StaleBasisRequired),
        KnowledgeState::Indeterminate => Some(ContractError::ReconciliationBasisRequired),
        KnowledgeState::Known
        | KnowledgeState::Estimated
        | KnowledgeState::Unknown
        | KnowledgeState::Conflicted
        | KnowledgeState::NotObservable
        | KnowledgeState::NotApplicable => None,
    }
}

/// Returns whether a knowledge state's registry meaning asserts present support for the
/// proposition, so an evidence-bearing provenance class must name that support.
///
/// `known` (KSTATE-001, "established ... by admissible evidence"), `estimated` (KSTATE-002,
/// "supported by a declared derivation or model"), and `conflicted` (KSTATE-004, "material
/// admissible evidence supports incompatible propositions") each name present evidence. Every
/// other state reports that support is absent, withheld, outdated, unresolved, or meaningless.
const fn asserts_present_support(state: KnowledgeState) -> bool {
    match state {
        KnowledgeState::Known | KnowledgeState::Estimated | KnowledgeState::Conflicted => true,
        KnowledgeState::Unknown
        | KnowledgeState::Stale
        | KnowledgeState::NotObservable
        | KnowledgeState::Redacted
        | KnowledgeState::Indeterminate
        | KnowledgeState::NotApplicable => false,
    }
}

/// One proposition with orthogonal epistemic, provenance, and hypothesis states.
///
/// `Debug` is implemented by hand so that a `redacted` cell never prints its statement.
#[derive(Clone, Eq, PartialEq)]
pub struct KnowledgeCell {
    /// Stable proposition identity.
    pub claim_id: String,
    /// Compact human-readable statement.
    pub statement: String,
    /// Epistemic state.
    pub knowledge_state: KnowledgeState,
    /// Provenance class.
    pub provenance: ProvenanceClass,
    /// Hypothesis disposition, when applicable.
    pub hypothesis: Option<HypothesisDisposition>,
    /// Evidence roots supporting the proposition.
    pub evidence: Vec<ContentDigest>,
    /// Contradicting evidence roots.
    pub contradictions: Vec<ContentDigest>,
    /// Validity end, when bounded.
    pub valid_until: Option<TimestampNs>,
    /// Typed basis required by states whose registry meaning names one; `None` otherwise.
    pub state_basis: Option<KnowledgeStateBasis>,
}

impl KnowledgeCell {
    /// Returns whether this cell may be used as an irreversible-effect premise.
    #[must_use]
    pub fn is_irreversible_effect_premise(&self, now: TimestampNs) -> bool {
        self.knowledge_state.may_authorize_irreversible_effect()
            && self.provenance.may_authorize_irreversible_effect()
            && self.validate().is_ok()
            && !self.evidence.is_empty()
            && self.contradictions.is_empty()
            && self.valid_until.is_none_or(|limit| now <= limit)
    }

    /// Validates that the typed state basis matches the knowledge state.
    ///
    /// A state whose registry meaning names a basis is refused without it, and a basis is
    /// refused on any state it does not belong to.
    ///
    /// An `observed` (PROV-001) or `derived` (PROV-002) cell whose knowledge state asserts
    /// present support for its proposition must bind source evidence or named input anchors.
    /// States that assert no present support (`unknown`, `stale`, `not_observable`, `redacted`,
    /// `indeterminate`, `not_applicable`) stay valid without evidence, so an honest unknown is
    /// never refused for lacking the support it reports it does not have.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.provenance == ProvenanceClass::Predicted
            && self.knowledge_state == KnowledgeState::Known
        {
            return Err(ContractError::PredictedKnownForbidden);
        }
        if matches!(
            self.provenance,
            ProvenanceClass::Observed | ProvenanceClass::Derived
        ) && asserts_present_support(self.knowledge_state)
            && self.evidence.is_empty()
        {
            return Err(ContractError::EvidenceRequired);
        }
        match (
            &self.state_basis,
            required_basis_error(self.knowledge_state),
        ) {
            (None, None) => Ok(()),
            (None, Some(error)) => Err(error),
            (Some(basis), _) if basis.knowledge_state() == self.knowledge_state => basis.validate(),
            (Some(_), Some(error)) => Err(error),
            (Some(_), None) => Err(ContractError::KnowledgeStateBasisMismatch),
        }
    }

    /// Verifies that this cell does not launder evidence from a weaker provenance cell.
    ///
    /// Per Constitution §8.3 and AGENTS.md, confidence is never used to erase the evidence
    /// class, and the same evidence digest cannot be re-used under a stronger provenance.
    pub fn verify_no_evidence_laundering(&self, prior: &KnowledgeCell) -> Result<(), ContractError> {
        if self.provenance.strength() > prior.provenance.strength()
            && self.evidence.iter().any(|e| prior.evidence.contains(e))
        {
            return Err(ContractError::EvidenceLaunderingDetected);
        }
        Ok(())
    }

    /// Consumes and returns the cell only when [`Self::validate`] accepts it.
    pub fn validated(self) -> Result<Self, ContractError> {
        self.validate()?;
        Ok(self)
    }

    /// Returns whether the statement is withheld from `Debug` output and canonical encoding.
    #[must_use]
    pub fn withholds_statement(&self) -> bool {
        self.knowledge_state == KnowledgeState::Redacted
            || matches!(self.state_basis, Some(KnowledgeStateBasis::Redaction(_)))
    }

    /// Returns the statement as it may be disclosed: [`REDACTED_STATEMENT_MARKER`] when withheld.
    #[must_use]
    pub fn disclosable_statement(&self) -> &str {
        if self.withholds_statement() {
            REDACTED_STATEMENT_MARKER
        } else {
            &self.statement
        }
    }

    /// Returns whether this knowledge cell has observed provenance (PROV-001).
    #[must_use]
    pub fn is_observed(&self) -> bool {
        self.provenance == ProvenanceClass::Observed
    }

    /// Returns whether this knowledge cell has derived provenance (PROV-002).
    #[must_use]
    pub fn is_derived(&self) -> bool {
        self.provenance == ProvenanceClass::Derived
    }

    /// Returns whether this knowledge cell has predicted provenance (PROV-003).
    #[must_use]
    pub fn is_predicted(&self) -> bool {
        self.provenance == ProvenanceClass::Predicted
    }

    /// Returns whether this knowledge cell has remembered provenance (PROV-004).
    #[must_use]
    pub fn is_remembered(&self) -> bool {
        self.provenance == ProvenanceClass::Remembered
    }

    /// Returns whether this knowledge cell has operator_asserted provenance (PROV-005).
    #[must_use]
    pub fn is_operator_asserted(&self) -> bool {
        self.provenance == ProvenanceClass::OperatorAsserted
    }

    /// Returns whether this knowledge cell has vendor_claimed provenance (PROV-006).
    #[must_use]
    pub fn is_vendor_claimed(&self) -> bool {
        self.provenance == ProvenanceClass::VendorClaimed
    }

    /// Returns whether this knowledge cell is an estimated proposition.
    #[must_use]
    pub fn is_estimated(&self) -> bool {
        self.knowledge_state == KnowledgeState::Estimated
    }

    /// Returns whether this knowledge cell is an unknown proposition.
    #[must_use]
    pub fn is_unknown(&self) -> bool {
        self.knowledge_state == KnowledgeState::Unknown
    }

    /// Returns whether this knowledge cell is a conflicted proposition.
    #[must_use]
    pub fn is_conflicted(&self) -> bool {
        self.knowledge_state == KnowledgeState::Conflicted
    }

    /// Returns whether this knowledge cell is a stale proposition.
    #[must_use]
    pub fn is_stale(&self) -> bool {
        self.knowledge_state == KnowledgeState::Stale
    }

    /// Returns whether this knowledge cell is a not_observable proposition.
    #[must_use]
    pub fn is_not_observable(&self) -> bool {
        self.knowledge_state == KnowledgeState::NotObservable
    }

    /// Returns whether this knowledge cell is a redacted proposition.
    #[must_use]
    pub fn is_redacted(&self) -> bool {
        self.knowledge_state == KnowledgeState::Redacted
    }

    /// Returns whether this knowledge cell is an indeterminate proposition.
    #[must_use]
    pub fn is_indeterminate(&self) -> bool {
        self.knowledge_state == KnowledgeState::Indeterminate
    }

    /// Returns whether this knowledge cell is a not_applicable proposition.
    #[must_use]
    pub fn is_not_applicable(&self) -> bool {
        self.knowledge_state == KnowledgeState::NotApplicable
    }

    /// Returns whether this cell requires explicit assumptions to be used in planning.
    #[must_use]
    pub fn requires_explicit_assumptions(&self) -> bool {
        self.knowledge_state.explicit_assumptions_required()
    }

    /// Returns whether this cell may support planning.
    #[must_use]
    pub fn may_support_planning(&self) -> bool {
        self.knowledge_state.may_support_planning()
    }

    /// Returns the component digest of this cell's canonical encoding.
    ///
    /// Unlike [`SituationFrame::frame_digest`] and [`SituationCapsule::decision_fingerprint`],
    /// this digest is computed without [`Self::validate`]. It is a component hash that is
    /// deliberately defined for a cell that validation refuses, so refusal reporting and change
    /// comparison can still name such a cell. It never binds a withheld statement (the encoding
    /// substitutes [`REDACTED_STATEMENT_MARKER`]), so it is not a statement oracle.
    ///
    /// A digest from this method is therefore not evidence that the cell is valid: a frame or
    /// capsule carrying a refused cell has no frame digest and no decision fingerprint.
    #[must_use]
    pub fn cell_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.agent_knowledge_cell.v1")
    }
}

impl fmt::Debug for KnowledgeCell {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("KnowledgeCell");
        debug.field("claim_id", &self.claim_id);
        if self.withholds_statement() {
            debug.field("statement", &format_args!("{REDACTED_STATEMENT_MARKER}"));
        } else {
            debug.field("statement", &self.statement);
        }
        debug
            .field("knowledge_state", &self.knowledge_state)
            .field("provenance", &self.provenance)
            .field("hypothesis", &self.hypothesis)
            .field("evidence", &self.evidence)
            .field("contradictions", &self.contradictions)
            .field("valid_until", &self.valid_until)
            .field("state_basis", &self.state_basis)
            .finish()
    }
}

impl CanonicalEncode for KnowledgeCell {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.claim_id);
        if self.withholds_statement() {
            encoder.text(REDACTED_STATEMENT_MARKER);
        } else {
            encoder.text(&self.statement);
        }
        encoder.text(self.knowledge_state.as_str());
        self.provenance.encode_canonical(encoder);
        match self.hypothesis {
            Some(value) => {
                encoder.bool(true);
                encoder.u8(hypothesis_code(value));
            }
            None => encoder.bool(false),
        }
        encode_sorted_digests(&self.evidence, encoder);
        encode_sorted_digests(&self.contradictions, encoder);
        match self.valid_until {
            Some(value) => {
                encoder.bool(true);
                value.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        match &self.state_basis {
            Some(basis) => {
                encoder.bool(true);
                basis.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
    }
}

/// One factorized possible world retained for decision robustness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PossibleWorld {
    /// Stable world identity.
    pub world_id: String,
    /// Short description.
    pub description: String,
    /// Claims that define this world.
    pub claim_ids: BTreeSet<String>,
    /// Evidence roots keeping this world live.
    pub evidence: Vec<ContentDigest>,
    /// Consequence severity if ignored.
    pub consequence_severity: u8,
    /// Whether policy protects this world from rank-only pruning.
    pub protected: bool,
}

impl CanonicalEncode for PossibleWorld {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.world_id);
        encoder.text(&self.description);
        encoder.u64(self.claim_ids.len() as u64);
        for claim in &self.claim_ids {
            encoder.text(claim);
        }
        encode_sorted_digests(&self.evidence, encoder);
        encoder.u8(self.consequence_severity);
        encoder.bool(self.protected);
    }
}

/// Evidence, possibility, and invariant frontier for one decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldEnvelope {
    /// Stable envelope identity.
    pub envelope_id: String,
    /// Objective identity.
    pub objective_id: String,
    /// Exact evidence anchor.
    pub anchor: LedgerAnchor,
    /// Nominal interpretation claim identities.
    pub nominal_claim_ids: BTreeSet<String>,
    /// Claims certified across all retained worlds.
    pub certified_core_claim_ids: BTreeSet<String>,
    /// Material alternative worlds.
    pub alternatives: Vec<PossibleWorld>,
    /// Protected high-loss residual worlds.
    pub adversarial_residuals: Vec<PossibleWorld>,
    /// Invariants shared by every retained world.
    pub common_invariants: BTreeSet<String>,
    /// Evidence handles that bound observability.
    pub coverage_boundary_handles: BTreeSet<String>,
}

impl WorldEnvelope {
    /// Validates that every protected residual remains represented.
    pub fn validate(&self) -> Result<(), ContractError> {
        let mut seen = BTreeSet::new();
        for world in self
            .alternatives
            .iter()
            .chain(self.adversarial_residuals.iter())
        {
            if world.world_id.is_empty()
                || world.claim_ids.is_empty()
                || world.evidence.is_empty()
                || !seen.insert(world.world_id.as_str())
            {
                return Err(ContractError::EvidenceRequired);
            }
        }
        if self
            .adversarial_residuals
            .iter()
            .any(|world| !world.protected || world.consequence_severity == 0)
        {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(())
    }

    /// Returns the envelope digest bound into plans, control envelopes, and situation frames.
    ///
    /// The envelope is validated first: an envelope refused by [`Self::validate`] (for example
    /// one whose adversarial residual is unprotected, or whose retained worlds repeat an
    /// identity) has no digest. `WorldEnvelope` deliberately does not implement
    /// [`CanonicalEncode`], so this is the only public way to hash an envelope, and a digest from
    /// it is evidence that the envelope validated.
    pub fn envelope_digest(&self) -> Result<ContentDigest, ContractError> {
        self.validate()?;
        Ok(domain_separated_digest(
            "fss.agent_world_envelope.v1",
            |encoder| self.encode_fields(encoder),
        ))
    }

    /// Returns all retained world identities in deterministic order.
    #[must_use]
    pub fn world_ids(&self) -> BTreeSet<String> {
        self.alternatives
            .iter()
            .chain(self.adversarial_residuals.iter())
            .map(|world| world.world_id.clone())
            .collect()
    }

    /// Appends the envelope's canonical representation. Callers validate first.
    fn encode_fields(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.envelope_id);
        encoder.text(&self.objective_id);
        self.anchor.encode_canonical(encoder);
        encode_sorted_text(&self.nominal_claim_ids, encoder);
        encode_sorted_text(&self.certified_core_claim_ids, encoder);
        let mut alternatives = self.alternatives.clone();
        alternatives.sort_by(|left, right| left.world_id.cmp(&right.world_id));
        encoder.u64(alternatives.len() as u64);
        for world in &alternatives {
            world.encode_canonical(encoder);
        }
        let mut residuals = self.adversarial_residuals.clone();
        residuals.sort_by(|left, right| left.world_id.cmp(&right.world_id));
        encoder.u64(residuals.len() as u64);
        for world in &residuals {
            world.encode_canonical(encoder);
        }
        encode_sorted_text(&self.common_invariants, encoder);
        encode_sorted_text(&self.coverage_boundary_handles, encoder);
    }
}

/// How an action relates to the retained possible-world frontier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AffordanceClass {
    /// Safe and useful in every protected world.
    Robust,
    /// Safe only after a named observable branch predicate.
    Conditional,
    /// Primarily gathers information.
    Probe,
    /// Waits for a named wake predicate.
    Wait,
    /// Preconditions or authority currently block it.
    Blocked,
    /// No implementation or capability exists.
    Unavailable,
}

impl AffordanceClass {
    /// Returns the stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Robust => "robust",
            Self::Conditional => "conditional",
            Self::Probe => "probe",
            Self::Wait => "wait",
            Self::Blocked => "blocked",
            Self::Unavailable => "unavailable",
        }
    }
}

/// A capability-valid next action with explicit cost and world support.
#[derive(Clone, Debug, PartialEq)]
pub struct ActionAffordance {
    /// Stable affordance identity.
    pub affordance_id: String,
    /// Public operation name.
    pub operation: String,
    /// Target semantic URI.
    pub target: String,
    /// Why the action is available or blocked.
    pub rationale: String,
    /// Classification against the possible-world frontier.
    pub class: AffordanceClass,
    /// Worlds in which this action is supported.
    pub supported_worlds: BTreeSet<String>,
    /// Worlds in which this action is harmful or invalid.
    pub unsafe_worlds: BTreeSet<String>,
    /// Required capability identities.
    pub required_capabilities: BTreeSet<String>,
    /// Expected resource cost.
    pub cost: BudgetVector,
    /// Whether the action can be safely compensated.
    pub reversible: bool,
    /// Optional observable branch predicate.
    pub branch_predicate: Option<String>,
}

impl ActionAffordance {
    /// Validates the classification against a world envelope.
    pub fn validate_against(&self, envelope: &WorldEnvelope) -> Result<(), ContractError> {
        let retained = envelope.world_ids();
        if !self.supported_worlds.is_subset(&retained) || !self.unsafe_worlds.is_subset(&retained) {
            return Err(ContractError::EvidenceRequired);
        }
        if !self.supported_worlds.is_disjoint(&self.unsafe_worlds) {
            return Err(ContractError::EvidenceRequired);
        }
        if self.class == AffordanceClass::Robust
            && (!self.unsafe_worlds.is_empty() || self.supported_worlds != retained)
        {
            return Err(ContractError::EvidenceRequired);
        }
        if self.class == AffordanceClass::Conditional && self.branch_predicate.is_none() {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(())
    }
}

impl CanonicalEncode for ActionAffordance {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.affordance_id);
        encoder.text(&self.operation);
        encoder.text(&self.target);
        encoder.text(&self.rationale);
        encoder.text(self.class.as_str());
        encode_sorted_text(&self.supported_worlds, encoder);
        encode_sorted_text(&self.unsafe_worlds, encoder);
        encode_sorted_text(&self.required_capabilities, encoder);
        encode_budget(self.cost, encoder);
        encoder.bool(self.reversible);
        match &self.branch_predicate {
            Some(value) => {
                encoder.bool(true);
                encoder.text(value);
            }
            None => encoder.bool(false),
        }
    }
}

/// Compact driver-facing frame answering NOW, CHANGED, WHY, UNKNOWN, AT RISK, and NEXT.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SituationFrame {
    /// Stable frame identity.
    pub frame_id: String,
    /// Objective identity.
    pub objective_id: String,
    /// Exact evidence anchor.
    pub anchor: LedgerAnchor,
    /// Possible-world frontier.
    pub world_envelope: WorldEnvelope,
    /// Selected knowledge cells.
    pub knowledge_cells: Vec<KnowledgeCell>,
    /// Current situation statements.
    pub now: Vec<String>,
    /// Meaningful changes.
    pub changed: Vec<String>,
    /// Causal or evidentiary explanation.
    pub why: Vec<String>,
    /// Material unknowns and contradictions.
    pub unknown: Vec<String>,
    /// Risks, invalidators, and urgent obligations.
    pub at_risk: Vec<String>,
    /// Nondominated next affordance identities.
    pub next: Vec<String>,
    /// Stable evidence handles.
    pub evidence_handles: BTreeSet<String>,
}

impl SituationFrame {
    /// Validates the frame's own invariants.
    ///
    /// The frame anchor and objective must match its world envelope, every knowledge cell must
    /// pass [`KnowledgeCell::validate`], and the world envelope must validate. Checks that need
    /// the enclosing capsule (its anchor and affordance frontier) live in
    /// [`SituationCapsule::validate`].
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.anchor != self.world_envelope.anchor
            || self.objective_id != self.world_envelope.objective_id
        {
            return Err(ContractError::StaleAnchor);
        }
        for cell in &self.knowledge_cells {
            cell.validate()?;
        }
        self.world_envelope.validate()
    }

    /// Returns the frame fingerprint.
    ///
    /// The frame is validated first: a frame refused by [`Self::validate`] (for example one
    /// carrying a basisless stale cell) has no fingerprint. `SituationFrame` deliberately does
    /// not implement [`CanonicalEncode`], so this is the only public way to hash a frame.
    pub fn frame_digest(&self) -> Result<ContentDigest, ContractError> {
        self.validate()?;
        Ok(domain_separated_digest(
            "fss.agent_situation_frame.v1",
            |encoder| self.encode_fields(encoder),
        ))
    }

    /// Appends the frame's canonical representation. Callers validate first.
    fn encode_fields(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.frame_id);
        encoder.text(&self.objective_id);
        self.anchor.encode_canonical(encoder);
        self.world_envelope.encode_fields(encoder);
        let mut cells = self.knowledge_cells.clone();
        cells.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
        encoder.u64(cells.len() as u64);
        for cell in &cells {
            cell.encode_canonical(encoder);
        }
        encode_text_vec(&self.now, encoder);
        encode_text_vec(&self.changed, encoder);
        encode_text_vec(&self.why, encoder);
        encode_text_vec(&self.unknown, encoder);
        encode_text_vec(&self.at_risk, encoder);
        encode_text_vec(&self.next, encoder);
        encode_sorted_text(&self.evidence_handles, encoder);
    }
}

/// Mission lifecycle state conforming to AGENT_OPERATING_MODEL.md §3.1.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MissionLifecycleState {
    /// Initial drafting state.
    Draft,
    /// Actively executing mission.
    Active,
    /// Temporarily paused.
    Paused,
    /// Awaiting required evidence.
    AwaitingEvidence,
    /// Awaiting explicit human or operator approval.
    AwaitingApproval,
    /// Executing approved plans.
    Executing,
    /// Reconciling external effect outcomes.
    Reconciling,
    /// Terminal: mission goals resolved.
    Resolved,
    /// Terminal: mission failed.
    Failed,
    /// Terminal: mission cancelled before completion.
    Cancelled,
    /// Indeterminate external outcome.
    Indeterminate,
    /// Terminal: mission concluded and closed.
    Closed,
}

impl MissionLifecycleState {
    /// Returns the stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::AwaitingEvidence => "awaiting_evidence",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Executing => "executing",
            Self::Reconciling => "reconciling",
            Self::Resolved => "resolved",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Indeterminate => "indeterminate",
            Self::Closed => "closed",
        }
    }

    /// Returns true if this state is terminal (no further operational progress transitions).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Resolved | Self::Failed | Self::Cancelled | Self::Closed
        )
    }
}

impl CanonicalEncode for MissionLifecycleState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

/// One mission-oriented situation publication.
#[derive(Clone, Debug, PartialEq)]
pub struct SituationCapsule {
    /// Capsule identity.
    pub capsule_id: String,
    /// Monotone capsule revision.
    pub revision: u64,
    /// Contract basis.
    pub contract_basis: ContractBasis,
    /// Mission identity.
    pub mission_id: MissionId,
    /// Session identity.
    pub session_id: SessionId,
    /// Principal identity.
    pub principal_id: PrincipalId,
    /// Exact current anchor.
    pub anchor: LedgerAnchor,
    /// Prior anchor when this is a delta-oriented publication.
    pub previous_anchor: Option<LedgerAnchor>,
    /// Driver-facing frame.
    pub frame: SituationFrame,
    /// Effect obligations.
    pub obligations: Vec<ObligationId>,
    /// Current affordance frontier.
    pub affordances: Vec<ActionAffordance>,
    /// Completeness of the capsule for its mission and view.
    pub completeness: Completeness,
    /// Creation time.
    pub created_at: TimestampNs,
    /// Optional mission lifecycle state.
    pub mission_state: Option<MissionLifecycleState>,
}

impl SituationCapsule {
    /// Validates the capsule, including every knowledge cell in its frame.
    ///
    /// A cell refused by [`KnowledgeCell::validate`] refuses the whole capsule with that cell's
    /// typed error, so it can never reach the decision fingerprint or a context pack.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.anchor != self.frame.anchor {
            return Err(ContractError::StaleAnchor);
        }
        // Every carried cell must hold the typed basis its state names (KSTATE-005/007/008);
        // a capsule is never a way around the per-cell refusal. The frame check also refuses an
        // envelope anchor or objective that diverges from the frame, before any cell check.
        self.frame.validate()?;
        for affordance in &self.affordances {
            affordance.validate_against(&self.frame.world_envelope)?;
        }
        let affordance_ids: BTreeSet<_> = self
            .affordances
            .iter()
            .map(|affordance| affordance.affordance_id.as_str())
            .collect();
        if self
            .frame
            .next
            .iter()
            .any(|next| !affordance_ids.contains(next.as_str()))
        {
            return Err(ContractError::NotFound);
        }
        Ok(())
    }

    /// Returns the decision fingerprint used for replay comparison.
    ///
    /// The capsule is validated first: a capsule refused by [`Self::validate`] has no
    /// fingerprint. `SituationCapsule` deliberately does not implement [`CanonicalEncode`], so
    /// `canonical_bytes`, `try_canonical_bytes`, and `canonical_digest` are unavailable for it;
    /// this method and [`Self::validated_digest`] are the only public ways to hash a capsule,
    /// and both validate. An invalid capsule (for example one whose frame carries a basisless
    /// stale cell) therefore can never be hashed into a replay, projection, or handoff root.
    pub fn decision_fingerprint(&self) -> Result<ContentDigest, ContractError> {
        self.validated_digest("fss.situation_capsule.v1")
    }

    /// Returns a domain-separated digest of the capsule's canonical encoding, validating first.
    ///
    /// This is the only way to derive an identity other than the decision fingerprint from a
    /// capsule: a capsule refused by [`Self::validate`] has no digest under any domain.
    pub fn validated_digest(&self, domain: &str) -> Result<ContentDigest, ContractError> {
        self.validate()?;
        Ok(domain_separated_digest(domain, |encoder| {
            self.encode_fields(encoder);
        }))
    }

    /// Appends the capsule's canonical representation. Callers validate first.
    fn encode_fields(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.capsule_id);
        encoder.u64(self.revision);
        self.contract_basis.encode_canonical(encoder);
        self.mission_id.encode_canonical(encoder);
        self.session_id.encode_canonical(encoder);
        self.principal_id.encode_canonical(encoder);
        self.anchor.encode_canonical(encoder);
        match &self.previous_anchor {
            Some(value) => {
                encoder.bool(true);
                value.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        self.frame.encode_fields(encoder);
        let mut obligations = self.obligations.clone();
        obligations.sort();
        encoder.u64(obligations.len() as u64);
        for obligation in &obligations {
            obligation.encode_canonical(encoder);
        }
        let mut affordances = self.affordances.clone();
        affordances.sort_by(|left, right| left.affordance_id.cmp(&right.affordance_id));
        encoder.u64(affordances.len() as u64);
        for affordance in &affordances {
            affordance.encode_canonical(encoder);
        }
        encoder.u8(completeness_code(self.completeness));
        self.created_at.encode_canonical(encoder);
        match self.mission_state {
            Some(state) => {
                encoder.bool(true);
                state.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
    }
}

/// Root-last handoff publication for resuming without hidden conversational state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffCapsule {
    /// Handoff identity.
    pub handoff_id: HandoffId,
    /// Mission identity.
    pub mission_id: MissionId,
    /// Source session.
    pub source_session_id: SessionId,
    /// Source principal.
    pub source_principal_id: PrincipalId,
    /// Evidence anchor.
    pub anchor: LedgerAnchor,
    /// Situation capsule root.
    pub situation_capsule_root: ContentDigest,
    /// Complete child-root set.
    pub child_roots: BTreeSet<ContentDigest>,
    /// Root of the handoff manifest and children.
    pub handoff_root: ContentDigest,
    /// Contract basis.
    pub contract_basis: ContractBasis,
    /// Creation time.
    pub created_at: TimestampNs,
    /// Expiry time.
    pub expires_at: TimestampNs,
}

/// Parameters for publishing a root-last `HandoffCapsule`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffPublishParams<I = Vec<ContentDigest>> {
    /// Stable handoff identifier.
    pub handoff_id: HandoffId,
    /// Owning mission identity.
    pub mission_id: MissionId,
    /// Producing session identity.
    pub source_session_id: SessionId,
    /// Producing principal identity.
    pub source_principal_id: PrincipalId,
    /// Authority anchor under which this handoff is sealed.
    pub anchor: LedgerAnchor,
    /// Root digest of the referenced situation capsule.
    pub situation_capsule_root: ContentDigest,
    /// Child proof roots that must be durable before this handoff is sealed.
    pub child_roots: I,
    /// Exact contract basis governing the handoff.
    pub contract_basis: ContractBasis,
    /// Creation time.
    pub created_at: TimestampNs,
    /// Expiry time.
    pub expires_at: TimestampNs,
}

impl HandoffCapsule {
    /// Materializes and seals a complete root-last handoff capsule.
    pub fn publish<I>(params: HandoffPublishParams<I>) -> Result<Self, ContractError>
    where
        I: IntoIterator<Item = ContentDigest>,
    {
        if params.expires_at < params.created_at {
            return Err(ContractError::InvertedTimeInterval);
        }
        let mut children: BTreeSet<_> = params.child_roots.into_iter().collect();
        if children.is_empty() {
            return Err(ContractError::IncompletePublicationGraph);
        }
        children.insert(params.situation_capsule_root);
        let mut capsule = Self {
            handoff_id: params.handoff_id,
            mission_id: params.mission_id,
            source_session_id: params.source_session_id,
            source_principal_id: params.source_principal_id,
            anchor: params.anchor,
            situation_capsule_root: params.situation_capsule_root,
            child_roots: children,
            handoff_root: ContentDigest::sha256(b"unpublished"),
            contract_basis: params.contract_basis,
            created_at: params.created_at,
            expires_at: params.expires_at,
        };
        capsule.handoff_root = capsule.computed_root();
        Ok(capsule)
    }

    /// Recomputes and verifies root and graph closure.
    pub fn verify(&self) -> Result<(), ContractError> {
        if !self.child_roots.contains(&self.situation_capsule_root) {
            return Err(ContractError::IncompletePublicationGraph);
        }
        if self.computed_root() != self.handoff_root {
            return Err(ContractError::DigestMismatch);
        }
        Ok(())
    }

    fn computed_root(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.handoff_id.encode_canonical(&mut encoder);
        self.mission_id.encode_canonical(&mut encoder);
        self.source_session_id.encode_canonical(&mut encoder);
        self.source_principal_id.encode_canonical(&mut encoder);
        self.anchor.encode_canonical(&mut encoder);
        encoder.digest(self.situation_capsule_root);
        encoder.u64(self.child_roots.len() as u64);
        for child in &self.child_roots {
            encoder.digest(*child);
        }
        self.contract_basis.encode_canonical(&mut encoder);
        self.created_at.encode_canonical(&mut encoder);
        self.expires_at.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }
}

fn encode_sorted_digests(values: &[ContentDigest], encoder: &mut CanonicalEncoder) {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    encoder.u64(sorted.len() as u64);
    for value in sorted {
        encoder.digest(value);
    }
}

fn encode_sorted_text(values: &BTreeSet<String>, encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

fn encode_text_vec(values: &[String], encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

fn encode_budget(value: BudgetVector, encoder: &mut CanonicalEncoder) {
    value.encode_to_canonical(encoder);
}

fn hypothesis_code(value: HypothesisDisposition) -> u8 {
    match value {
        HypothesisDisposition::Live => 1,
        HypothesisDisposition::Supported => 2,
        HypothesisDisposition::Disfavored => 3,
        HypothesisDisposition::Refuted => 4,
        HypothesisDisposition::Resolved => 5,
        HypothesisDisposition::Superseded => 6,
    }
}

fn completeness_code(value: Completeness) -> u8 {
    match value {
        Completeness::Complete => 1,
        Completeness::Bounded => 2,
        Completeness::Partial => 3,
        Completeness::Unknown => 4,
        Completeness::NotObservable => 5,
        Completeness::Unauthorized => 6,
        Completeness::Stale => 7,
    }
}

/// Computes the same domain-separated digest as [`CanonicalEncode::canonical_digest`] for a
/// value whose canonical encoding is private because it must be validated before hashing.
fn domain_separated_digest(
    domain: &str,
    encode: impl FnOnce(&mut CanonicalEncoder),
) -> ContentDigest {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text(domain);
    encode(&mut encoder);
    ContentDigest::sha256(&encoder.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basis() -> ContractBasis {
        ContractBasis::from_registry_bytes(
            ContractBasisRegistryBytes::new(
                b"schemas",
                b"operations",
                b"views",
                b"capabilities",
                b"errors",
                b"costs",
                "fss:0.0.1",
            )
            .with_accepted_nightly("nightly-2026-08-31"),
        )
    }

    #[test]
    fn handoff_requires_and_verifies_situation_root() -> Result<(), ContractError> {
        let situation_root = ContentDigest::sha256(b"situation");
        let capsule = HandoffCapsule::publish(HandoffPublishParams {
            handoff_id: HandoffId::parse("handoff:one")?,
            mission_id: MissionId::parse("mission:one")?,
            source_session_id: SessionId::parse("session:one")?,
            source_principal_id: PrincipalId::parse("principal:one")?,
            anchor: LedgerAnchor::genesis("site:one"),
            situation_capsule_root: situation_root,
            child_roots: [ContentDigest::sha256(b"case")],
            contract_basis: basis(),
            created_at: TimestampNs(10),
            expires_at: TimestampNs(20),
        })?;
        assert!(capsule.child_roots.contains(&situation_root));
        capsule.verify()
    }

    fn known_cell() -> KnowledgeCell {
        KnowledgeCell {
            claim_id: "claim:door".to_owned(),
            statement: "The door is closed.".to_owned(),
            knowledge_state: KnowledgeState::Known,
            provenance: ProvenanceClass::Observed,
            hypothesis: None,
            evidence: vec![ContentDigest::sha256(b"door-evidence")],
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        }
    }

    /// A stale cell with no typed stale basis: refused with `StaleBasisRequired`.
    fn basisless_stale_cell() -> KnowledgeCell {
        KnowledgeCell {
            claim_id: "claim:gate".to_owned(),
            statement: "The gate was closed at the last observation.".to_owned(),
            knowledge_state: KnowledgeState::Stale,
            provenance: ProvenanceClass::Observed,
            hypothesis: None,
            evidence: vec![ContentDigest::sha256(b"gate-evidence")],
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        }
    }

    fn capsule() -> Result<SituationCapsule, ContractError> {
        let anchor = LedgerAnchor::genesis("site:one");
        let world_envelope = WorldEnvelope {
            envelope_id: "world-envelope:one".to_owned(),
            objective_id: "objective:one".to_owned(),
            anchor: anchor.clone(),
            nominal_claim_ids: BTreeSet::from(["claim:door".to_owned()]),
            certified_core_claim_ids: BTreeSet::new(),
            alternatives: Vec::new(),
            adversarial_residuals: Vec::new(),
            common_invariants: BTreeSet::new(),
            coverage_boundary_handles: BTreeSet::new(),
        };
        let frame = SituationFrame {
            frame_id: "frame:one".to_owned(),
            objective_id: "objective:one".to_owned(),
            anchor: anchor.clone(),
            world_envelope,
            knowledge_cells: vec![known_cell()],
            now: vec!["The door is closed.".to_owned()],
            changed: Vec::new(),
            why: Vec::new(),
            unknown: Vec::new(),
            at_risk: Vec::new(),
            next: Vec::new(),
            evidence_handles: BTreeSet::new(),
        };
        let capsule = SituationCapsule {
            capsule_id: "situation:one".to_owned(),
            revision: 1,
            contract_basis: basis(),
            mission_id: MissionId::parse("mission:one")?,
            session_id: SessionId::parse("session:one")?,
            principal_id: PrincipalId::parse("principal:one")?,
            anchor,
            previous_anchor: None,
            frame,
            obligations: Vec::new(),
            affordances: Vec::new(),
            completeness: Completeness::Partial,
            created_at: TimestampNs(10),
            mission_state: None,
        };
        capsule.validate()?;
        Ok(capsule)
    }

    #[test]
    fn decision_fingerprint_refuses_capsule_with_basisless_stale_cell() -> Result<(), ContractError>
    {
        let valid = capsule()?;
        let fingerprint = valid.decision_fingerprint()?;

        let mut invalid = valid.clone();
        invalid.frame.knowledge_cells.push(basisless_stale_cell());
        assert_eq!(invalid.validate(), Err(ContractError::StaleBasisRequired));
        assert_eq!(
            invalid.decision_fingerprint(),
            Err(ContractError::StaleBasisRequired)
        );
        // No other domain is a way around the refusal.
        assert_eq!(
            invalid.validated_digest("fss.test_other_identity.v1"),
            Err(ContractError::StaleBasisRequired)
        );

        // The refusal is not a side effect of the fixture: the valid capsule still fingerprints
        // to the same root.
        assert_eq!(valid.decision_fingerprint(), Ok(fingerprint));
        Ok(())
    }

    #[test]
    fn frame_digest_refuses_invalid_frame() -> Result<(), ContractError> {
        let valid = capsule()?.frame;
        let digest = valid.frame_digest()?;

        let mut basisless = valid.clone();
        basisless.knowledge_cells.push(basisless_stale_cell());
        assert_eq!(basisless.validate(), Err(ContractError::StaleBasisRequired));
        assert_eq!(
            basisless.frame_digest(),
            Err(ContractError::StaleBasisRequired)
        );

        let mut drifted = valid.clone();
        drifted.world_envelope.objective_id = "objective:other".to_owned();
        assert_eq!(drifted.frame_digest(), Err(ContractError::StaleAnchor));

        assert_eq!(valid.frame_digest(), Ok(digest));
        Ok(())
    }

    /// Pins the documented `cell_digest` exemption: the component digest is defined for a cell
    /// that validation refuses, binds its refused state, and withholds a redacted statement,
    /// while every frame or capsule carrying that cell refuses to hash.
    #[test]
    fn cell_digest_is_an_unvalidated_component_digest() -> Result<(), ContractError> {
        let refused = basisless_stale_cell();
        assert_eq!(refused.validate(), Err(ContractError::StaleBasisRequired));
        assert_eq!(
            refused.cell_digest(),
            refused.canonical_digest("fss.agent_knowledge_cell.v1")
        );

        let mut relabelled = refused.clone();
        relabelled.knowledge_state = KnowledgeState::Known;
        relabelled.validate()?;
        assert_ne!(refused.cell_digest(), relabelled.cell_digest());

        let mut withheld = refused.clone();
        withheld.knowledge_state = KnowledgeState::Redacted;
        let mut other_statement = withheld.clone();
        other_statement.statement = "A different withheld statement.".to_owned();
        assert_eq!(withheld.cell_digest(), other_statement.cell_digest());

        let mut carrying = capsule()?;
        carrying.frame.knowledge_cells.push(refused);
        assert_eq!(
            carrying.frame.frame_digest(),
            Err(ContractError::StaleBasisRequired)
        );
        assert_eq!(
            carrying.decision_fingerprint(),
            Err(ContractError::StaleBasisRequired)
        );
        Ok(())
    }

    /// Compiles only while neither `SituationCapsule` nor `SituationFrame` implements
    /// [`CanonicalEncode`]: with an implementation, both marker impls apply and the `_` below
    /// is ambiguous. That keeps `canonical_digest`, `canonical_bytes`, and
    /// `try_canonical_bytes` from hashing an unvalidated capsule or frame.
    #[test]
    fn situation_capsule_and_frame_have_no_unvalidated_canonical_encoding() {
        trait AmbiguousIfCanonical<Marker> {
            fn probe() {}
        }
        impl<T: ?Sized> AmbiguousIfCanonical<()> for T {}
        impl<T: ?Sized + CanonicalEncode> AmbiguousIfCanonical<u8> for T {}
        <SituationCapsule as AmbiguousIfCanonical<_>>::probe();
        <SituationFrame as AmbiguousIfCanonical<_>>::probe();
    }

    fn residual_world(world_id: &str) -> PossibleWorld {
        PossibleWorld {
            world_id: world_id.to_owned(),
            description: "An intruder is present behind the door.".to_owned(),
            claim_ids: BTreeSet::from(["claim:intruder".to_owned()]),
            evidence: vec![ContentDigest::sha256(b"residual-evidence")],
            consequence_severity: 9,
            protected: true,
        }
    }

    #[test]
    fn envelope_digest_refuses_invalid_envelope() -> Result<(), ContractError> {
        let mut valid = capsule()?.frame.world_envelope;
        valid
            .adversarial_residuals
            .push(residual_world("world:intruder"));
        valid.validate()?;
        let digest = valid.envelope_digest()?;

        let mut unprotected = valid.clone();
        for world in &mut unprotected.adversarial_residuals {
            world.protected = false;
        }
        assert_eq!(unprotected.validate(), Err(ContractError::EvidenceRequired));
        assert_eq!(
            unprotected.envelope_digest(),
            Err(ContractError::EvidenceRequired)
        );

        let mut duplicated = valid.clone();
        duplicated
            .alternatives
            .push(residual_world("world:intruder"));
        assert_eq!(
            duplicated.envelope_digest(),
            Err(ContractError::EvidenceRequired)
        );

        let mut evidenceless = valid.clone();
        for world in &mut evidenceless.adversarial_residuals {
            world.evidence.clear();
        }
        assert_eq!(
            evidenceless.envelope_digest(),
            Err(ContractError::EvidenceRequired)
        );

        // The refusal is not a side effect of the fixture, and the digest still binds the
        // residual: dropping it changes the digest.
        assert_eq!(valid.envelope_digest(), Ok(digest));
        let mut without_residual = valid.clone();
        without_residual.adversarial_residuals.clear();
        assert_ne!(without_residual.envelope_digest()?, digest);
        Ok(())
    }

    /// Compiles only while `WorldEnvelope` does not implement [`CanonicalEncode`]: with an
    /// implementation, both marker impls apply and the `_` below is ambiguous. That keeps
    /// `canonical_digest`, `canonical_bytes`, and `try_canonical_bytes` from hashing an
    /// unvalidated envelope around [`WorldEnvelope::envelope_digest`].
    #[test]
    fn world_envelope_has_no_unvalidated_canonical_encoding() {
        trait AmbiguousIfCanonical<Marker> {
            fn probe() {}
        }
        impl<T: ?Sized> AmbiguousIfCanonical<()> for T {}
        impl<T: ?Sized + CanonicalEncode> AmbiguousIfCanonical<u8> for T {}
        <WorldEnvelope as AmbiguousIfCanonical<_>>::probe();
    }
}
