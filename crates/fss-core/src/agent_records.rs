#![forbid(unsafe_code)]
//! Durable agent semantic records: work claims, findings, learning
//! proposals, experience capsules, and execution episodes
//! (fss.agent_work_claim.v1, fss.agent_finding.v1,
//! fss.agent_learning_proposal.v1, fss.experience_capsule.v1,
//! fss.agent_execution_episode.v1).
//!
//! Each type mirrors its registered schema document with validated
//! constructors, canonical encoding, and a domain-separated digest under its
//! schema identity. Free-form schema objects travel as pinned canonical JSON
//! text so replay is byte-exact without inventing structure the registry
//! does not constrain.

use crate::agent_investigation::KnownStatement;
use crate::canonical::{CanonicalEncode, CanonicalEncoder};
use crate::contract::{ContractError, KnowledgeState};
use crate::digest::ContentDigest;
use crate::evidence::LedgerAnchor;
use crate::ids::validate_id;
use crate::{BudgetVector, MissionId, SessionId};

fn check_portable(value: &str, max_len: usize) -> Result<(), ContractError> {
    validate_id(value)?;
    if value.len() > max_len {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

fn check_str(value: &str, max_len: usize) -> Result<(), ContractError> {
    if value.is_empty() || value.len() > max_len {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

/// Validates the lowercase decision-digest spelling.
fn check_decision_digest(value: &str) -> Result<(), ContractError> {
    let bytes = value.as_bytes();
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if bytes.len() < 8
        || bytes.len() > 256
        || !alnum(bytes[0])
        || !bytes[1..]
            .iter()
            .all(|&b| alnum(b) || matches!(b, b':' | b'+' | b'.' | b'_' | b'-'))
    {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WorkClaim (fss.agent_work_claim.v1)
// ---------------------------------------------------------------------------

/// Lifecycle state of a work claim (registered enum).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkClaimState {
    /// Offered to the swarm.
    Offered,
    /// Claimed by a session.
    Claimed,
    /// Active work in progress.
    Active,
    /// Blocked by a dependency or authority.
    Blocked,
    /// Completed with a result root.
    Completed,
    /// Released unclaimed.
    Released,
    /// Expired past its lease.
    Expired,
    /// Superseded by a newer claim.
    Superseded,
}

impl WorkClaimState {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Claimed => "claimed",
            Self::Active => "active",
            Self::Blocked => "blocked",
            Self::Completed => "completed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
        }
    }
}

/// A swarm work claim (fss.agent_work_claim.v1).
///
/// CONSTITUTIONAL: a work claim never confers effect authority
/// (`confersEffectAuthority` is the literal `false` in the registry).
#[derive(Clone, Debug, PartialEq)]
pub struct WorkClaim {
    /// Claim identity.
    pub claim_id: String,
    /// Owning case identity, when case-bound.
    pub case_id: Option<String>,
    /// Owning session.
    pub owner_session_id: String,
    /// Scope descriptor (pinned canonical JSON).
    pub scope_json: String,
    /// Basis authority anchor.
    pub basis_anchor: LedgerAnchor,
    /// Lease incarnation (fencing token).
    pub lease_incarnation: u64,
    /// Creation time.
    pub created_at_ns: i128,
    /// Lease expiry.
    pub expires_at_ns: i128,
    /// Lifecycle state.
    pub state: WorkClaimState,
    /// Claim identities this claim depends on.
    pub dependencies: Vec<String>,
    /// Progress descriptor (pinned canonical JSON).
    pub progress_json: String,
    /// Result root digest, when completed.
    pub result_root: Option<String>,
}

impl WorkClaim {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_work_claim.v1";

    /// CONSTITUTIONAL: a work claim never confers effect authority.
    pub const CONFERS_EFFECT_AUTHORITY: bool = false;

    /// Validates and constructs a work claim.
    ///
    /// The lease incarnation must be at least 1 (fencing) and expiry strictly
    /// after creation.
    #[allow(clippy::too_many_arguments)] // constructor mirrors the registered schema field list 1:1
    pub fn new(
        claim_id: impl Into<String>,
        case_id: Option<String>,
        owner_session_id: impl Into<String>,
        scope_json: impl Into<String>,
        basis_anchor: LedgerAnchor,
        lease_incarnation: u64,
        created_at_ns: i128,
        expires_at_ns: i128,
        state: WorkClaimState,
        dependencies: Vec<String>,
        progress_json: impl Into<String>,
        result_root: Option<String>,
    ) -> Result<Self, ContractError> {
        let claim_id = claim_id.into();
        check_portable(&claim_id, 256)?;
        if let Some(case_id) = &case_id {
            check_portable(case_id, 256)?;
        }
        let owner_session_id = owner_session_id.into();
        check_portable(&owner_session_id, 256)?;
        let scope_json = scope_json.into();
        let progress_json = progress_json.into();
        if scope_json.is_empty() || progress_json.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        if lease_incarnation == 0 || expires_at_ns <= created_at_ns {
            return Err(ContractError::InvertedTimeInterval);
        }
        for dependency in &dependencies {
            check_str(dependency, 4096)?;
        }
        if let Some(root) = &result_root {
            check_decision_digest(root)?;
        }
        Ok(Self {
            claim_id,
            case_id,
            owner_session_id,
            scope_json,
            basis_anchor,
            lease_incarnation,
            created_at_ns,
            expires_at_ns,
            state,
            dependencies,
            progress_json,
            result_root,
        })
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn claim_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for WorkClaim {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.text(&self.claim_id);
        match &self.case_id {
            Some(case_id) => {
                encoder.bool(true);
                encoder.text(case_id);
            }
            None => encoder.bool(false),
        }
        encoder.text(&self.owner_session_id);
        encoder.text(&self.scope_json);
        self.basis_anchor.encode_canonical(encoder);
        encoder.u64(self.lease_incarnation);
        encoder.i128(self.created_at_ns);
        encoder.i128(self.expires_at_ns);
        encoder.text(self.state.as_str());
        encoder.u32(self.dependencies.len() as u32);
        for dependency in &self.dependencies {
            encoder.text(dependency);
        }
        encoder.text(&self.progress_json);
        match &self.result_root {
            Some(root) => {
                encoder.bool(true);
                encoder.text(root);
            }
            None => encoder.bool(false),
        }
        encoder.bool(Self::CONFERS_EFFECT_AUTHORITY);
    }
}

// ---------------------------------------------------------------------------
// AgentFinding (fss.agent_finding.v1)
// ---------------------------------------------------------------------------

/// A durable evidence-linked finding (fss.agent_finding.v1).
#[derive(Clone, Debug, PartialEq)]
pub struct AgentFinding {
    /// Finding identity.
    pub finding_id: String,
    /// Owning mission.
    pub mission_id: MissionId,
    /// Investigation branch, when branch-scoped.
    pub branch_id: Option<String>,
    /// Authoring principal.
    pub author_principal_id: String,
    /// Authority anchor.
    pub anchor: LedgerAnchor,
    /// The question answered or claim made.
    pub question_or_claim: String,
    /// Epistemic state (orthogonal typed coordinate).
    pub epistemic_state: KnowledgeState,
    /// Supporting evidence handles.
    pub supporting_evidence: Vec<String>,
    /// Contradicting evidence handles.
    pub contradictory_evidence: Vec<String>,
    /// Assumptions the finding rests on.
    pub assumptions: Vec<String>,
    /// Coverage handles bounding the claim.
    pub coverage: Vec<String>,
    /// Method receipts.
    pub method_receipts: Vec<String>,
    /// Affected object handles.
    pub affected_objects: Vec<String>,
    /// Suggested follow-ups.
    pub suggested_follow_up: Vec<String>,
    /// Creation time.
    pub created_at_ns: i128,
}

impl AgentFinding {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_finding.v1";

    /// Validates and constructs a finding.
    ///
    /// A finding without any supporting evidence is an unanchored claim and
    /// is refused.
    #[allow(clippy::too_many_arguments)] // constructor mirrors the registered schema field list 1:1
    pub fn new(
        finding_id: impl Into<String>,
        mission_id: MissionId,
        branch_id: Option<String>,
        author_principal_id: impl Into<String>,
        anchor: LedgerAnchor,
        question_or_claim: impl Into<String>,
        epistemic_state: KnowledgeState,
        supporting_evidence: Vec<String>,
        contradictory_evidence: Vec<String>,
        assumptions: Vec<String>,
        coverage: Vec<String>,
        method_receipts: Vec<String>,
        affected_objects: Vec<String>,
        suggested_follow_up: Vec<String>,
        created_at_ns: i128,
    ) -> Result<Self, ContractError> {
        let finding_id = finding_id.into();
        check_portable(&finding_id, 256)?;
        if let Some(branch_id) = &branch_id {
            check_portable(branch_id, 256)?;
        }
        let author_principal_id = author_principal_id.into();
        check_portable(&author_principal_id, 256)?;
        let question_or_claim = question_or_claim.into();
        check_str(&question_or_claim, 8192)?;
        if supporting_evidence.is_empty() || supporting_evidence.len() > 512 {
            return Err(ContractError::EvidenceRequired);
        }
        if contradictory_evidence.len() > 256
            || coverage.len() > 128
            || method_receipts.len() > 256
            || affected_objects.len() > 256
            || suggested_follow_up.len() > 64
        {
            return Err(ContractError::CountBoundExceeded);
        }
        for handle in supporting_evidence
            .iter()
            .chain(&contradictory_evidence)
            .chain(&coverage)
            .chain(&method_receipts)
            .chain(&affected_objects)
            .chain(&suggested_follow_up)
        {
            check_portable(handle, 256)?;
        }
        for assumption in &assumptions {
            check_str(assumption, 1024)?;
        }
        Ok(Self {
            finding_id,
            mission_id,
            branch_id,
            author_principal_id,
            anchor,
            question_or_claim,
            epistemic_state,
            supporting_evidence,
            contradictory_evidence,
            assumptions,
            coverage,
            method_receipts,
            affected_objects,
            suggested_follow_up,
            created_at_ns,
        })
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn finding_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for AgentFinding {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.text(&self.finding_id);
        self.mission_id.encode_canonical(encoder);
        match &self.branch_id {
            Some(branch) => {
                encoder.bool(true);
                encoder.text(branch);
            }
            None => encoder.bool(false),
        }
        encoder.text(&self.author_principal_id);
        self.anchor.encode_canonical(encoder);
        encoder.text(&self.question_or_claim);
        self.epistemic_state.encode_canonical(encoder);
        for group in [
            &self.supporting_evidence,
            &self.contradictory_evidence,
            &self.assumptions,
            &self.coverage,
            &self.method_receipts,
            &self.affected_objects,
            &self.suggested_follow_up,
        ] {
            encoder.u32(group.len() as u32);
            for entry in group {
                encoder.text(entry);
            }
        }
        encoder.i128(self.created_at_ns);
    }
}

// ---------------------------------------------------------------------------
// LearningProposal (fss.agent_learning_proposal.v1)
// ---------------------------------------------------------------------------

/// Registered learning proposal classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LearningClass {
    /// A fact candidate.
    FactCandidate,
    /// A procedure candidate.
    ProcedureCandidate,
    /// An anti-pattern candidate.
    AntiPatternCandidate,
    /// A diagnostic signature.
    DiagnosticSignature,
    /// An adapter quirk.
    AdapterQuirk,
    /// A model failure mode.
    ModelFailureMode,
    /// A coverage geometry lesson.
    CoverageGeometryLesson,
    /// A cost model update.
    CostModelUpdate,
    /// A policy review candidate.
    PolicyReviewCandidate,
    /// A benchmark fixture candidate.
    BenchmarkFixtureCandidate,
}

impl LearningClass {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FactCandidate => "fact_candidate",
            Self::ProcedureCandidate => "procedure_candidate",
            Self::AntiPatternCandidate => "anti_pattern_candidate",
            Self::DiagnosticSignature => "diagnostic_signature",
            Self::AdapterQuirk => "adapter_quirk",
            Self::ModelFailureMode => "model_failure_mode",
            Self::CoverageGeometryLesson => "coverage_geometry_lesson",
            Self::CostModelUpdate => "cost_model_update",
            Self::PolicyReviewCandidate => "policy_review_candidate",
            Self::BenchmarkFixtureCandidate => "benchmark_fixture_candidate",
        }
    }
}

/// Registered promotion states of a learning proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromotionState {
    /// Captured from an episode.
    Captured,
    /// Proposed for review.
    Proposed,
    /// Reviewed by an operator.
    Reviewed,
    /// Validated against held-out evidence.
    Validated,
    /// Running in shadow mode.
    Shadow,
    /// Promoted into active use.
    Promoted,
    /// Demoted from active use.
    Demoted,
    /// Retired.
    Retired,
    /// Revivable after expiry.
    Revivable,
}

impl PromotionState {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Captured => "captured",
            Self::Proposed => "proposed",
            Self::Reviewed => "reviewed",
            Self::Validated => "validated",
            Self::Shadow => "shadow",
            Self::Promoted => "promoted",
            Self::Demoted => "demoted",
            Self::Retired => "retired",
            Self::Revivable => "revivable",
        }
    }
}

/// An evidence-linked learning proposal (fss.agent_learning_proposal.v1).
///
/// Silent activation is structurally impossible: `promotion_state` starts at
/// `captured` and only the registered promotion ladder moves it; recording a
/// proposal never changes active policy or truth.
#[derive(Clone, Debug, PartialEq)]
pub struct LearningProposal {
    /// Proposal identity.
    pub proposal_id: String,
    /// Learning class.
    pub class: LearningClass,
    /// Originating episode identity.
    pub source_episode_id: String,
    /// The learned statement.
    pub statement: String,
    /// Applicability descriptor (pinned canonical JSON).
    pub applicability_json: String,
    /// Supporting evidence handles.
    pub supporting_evidence: Vec<String>,
    /// Contradicting evidence handles.
    pub contradicting_evidence: Vec<String>,
    /// Known counterexamples.
    pub counterexamples: Vec<String>,
    /// Confidence in `[0, 1]` (micro-scaling preserved by the caller).
    pub confidence_numerator: u32,
    /// Helpful outcomes observed.
    pub helpful_outcomes: i64,
    /// Harmful outcomes observed.
    pub harmful_outcomes: i64,
    /// Required validation steps before promotion.
    pub required_validation: Vec<String>,
    /// Current promotion state (starts at `captured`).
    pub promotion_state: PromotionState,
    /// Review deadline, when scheduled.
    pub review_after_ns: Option<i128>,
    /// Expiry deadline, when scheduled.
    pub expiry_ns: Option<i128>,
    /// Revival conditions, when specified.
    pub revival_conditions: Vec<String>,
    /// Decision digest.
    pub decision_digest: String,
}

impl LearningProposal {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_learning_proposal.v1";

    /// Validates and constructs a learning proposal.
    ///
    /// Confidence is a numerator over 1_000_000 (micro-confidence) and must
    /// not exceed the denominator. New proposals always start `captured`;
    /// the promotion ladder is the only path forward.
    #[allow(clippy::too_many_arguments)] // constructor mirrors the registered schema field list 1:1
    pub fn record(
        proposal_id: impl Into<String>,
        class: LearningClass,
        source_episode_id: impl Into<String>,
        statement: impl Into<String>,
        applicability_json: impl Into<String>,
        supporting_evidence: Vec<String>,
        contradicting_evidence: Vec<String>,
        counterexamples: Vec<String>,
        confidence_numerator: u32,
        helpful_outcomes: i64,
        harmful_outcomes: i64,
        required_validation: Vec<String>,
        review_after_ns: Option<i128>,
        expiry_ns: Option<i128>,
        revival_conditions: Vec<String>,
        decision_digest: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let proposal_id = proposal_id.into();
        let source_episode_id = source_episode_id.into();
        check_portable(&source_episode_id, 256)?;
        let statement = statement.into();
        check_str(&statement, 8192)?;
        let applicability_json = applicability_json.into();
        if applicability_json.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        if confidence_numerator > 1_000_000 {
            return Err(ContractError::InvalidProbabilityInterval);
        }
        for handle in supporting_evidence
            .iter()
            .chain(&contradicting_evidence)
            .chain(&counterexamples)
            .chain(&required_validation)
            .chain(&revival_conditions)
        {
            check_str(handle, 1024)?;
        }
        let decision_digest = decision_digest.into();
        check_decision_digest(&decision_digest)?;
        Ok(Self {
            proposal_id,
            class,
            source_episode_id,
            statement,
            applicability_json,
            supporting_evidence,
            contradicting_evidence,
            counterexamples,
            confidence_numerator,
            helpful_outcomes,
            harmful_outcomes,
            required_validation,
            promotion_state: PromotionState::Captured,
            review_after_ns,
            expiry_ns,
            revival_conditions,
            decision_digest,
        })
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn proposal_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for LearningProposal {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.text(&self.proposal_id);
        encoder.text(self.class.as_str());
        encoder.text(&self.source_episode_id);
        encoder.text(&self.statement);
        encoder.text(&self.applicability_json);
        encoder.u32(self.supporting_evidence.len() as u32);
        for handle in &self.supporting_evidence {
            encoder.text(handle);
        }
        encoder.u32(self.contradicting_evidence.len() as u32);
        for handle in &self.contradicting_evidence {
            encoder.text(handle);
        }
        encoder.u32(self.counterexamples.len() as u32);
        for counterexample in &self.counterexamples {
            encoder.text(counterexample);
        }
        encoder.u32(self.confidence_numerator);
        encoder.i128(i128::from(self.helpful_outcomes));
        encoder.i128(i128::from(self.harmful_outcomes));
        encoder.u32(self.required_validation.len() as u32);
        for step in &self.required_validation {
            encoder.text(step);
        }
        encoder.text(self.promotion_state.as_str());
        match self.review_after_ns {
            Some(at) => {
                encoder.bool(true);
                encoder.i128(at);
            }
            None => encoder.bool(false),
        }
        match self.expiry_ns {
            Some(at) => {
                encoder.bool(true);
                encoder.i128(at);
            }
            None => encoder.bool(false),
        }
        encoder.u32(self.revival_conditions.len() as u32);
        for condition in &self.revival_conditions {
            encoder.text(condition);
        }
        encoder.text(&self.decision_digest);
    }
}

// ---------------------------------------------------------------------------
// ExperienceCapsule (fss.experience_capsule.v1)
// ---------------------------------------------------------------------------

/// Registered evidence strength of an experience capsule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceStrength {
    /// Observed in a single episode.
    SingleEpisode,
    /// Corroborated across episodes.
    Corroborated,
    /// Validated on held-out data.
    HeldOutValidated,
    /// Proven.
    Proven,
}

impl EvidenceStrength {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleEpisode => "single_episode",
            Self::Corroborated => "corroborated",
            Self::HeldOutValidated => "held_out_validated",
            Self::Proven => "proven",
        }
    }
}

/// An experience capsule (fss.experience_capsule.v1).
#[derive(Clone, Debug, PartialEq)]
pub struct ExperienceCapsule {
    /// Experience identity.
    pub experience_id: String,
    /// Mission the experience came from.
    pub mission_id: MissionId,
    /// Deployment scope handles.
    pub deployment_scope: Vec<String>,
    /// Basis authority anchor.
    pub basis_anchor: LedgerAnchor,
    /// Situation signature (pinned canonical JSON).
    pub situation_signature_json: String,
    /// The objective pursued.
    pub objective: String,
    /// Initial epistemic map (statement-level states).
    pub initial_epistemic_map: Vec<KnownStatement>,
    /// Operations attempted.
    pub operations: Vec<String>,
    /// Outcome summary.
    pub outcome: String,
    /// Signals that predicted the outcome.
    pub predictive_signals: Vec<String>,
    /// Signals that misled.
    pub misleading_signals: Vec<String>,
    /// Assumptions that failed.
    pub failed_assumptions: Vec<String>,
    /// Observed cost.
    pub cost: BudgetVector,
    /// Applicability conditions.
    pub applicability: Vec<String>,
    /// Evidence strength.
    pub evidence_strength: EvidenceStrength,
    /// Micro-confidence numerator over 1_000_000.
    pub confidence_numerator: u32,
    /// Decay half-life in days.
    pub decay_half_life_days: u32,
    /// Privacy class.
    pub privacy_class: String,
    /// Creation time.
    pub created_at_ns: i128,
}

impl ExperienceCapsule {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.experience_capsule.v1";

    /// Validates and constructs an experience capsule.
    ///
    /// Confidence must stay within the micro-denominator and the outcome
    /// summary must be present: an experience with no recorded outcome
    /// teaches nothing.
    #[allow(clippy::too_many_arguments)] // constructor mirrors the registered schema field list 1:1
    pub fn new(
        experience_id: impl Into<String>,
        mission_id: MissionId,
        deployment_scope: Vec<String>,
        basis_anchor: LedgerAnchor,
        situation_signature_json: impl Into<String>,
        objective: impl Into<String>,
        initial_epistemic_map: Vec<KnownStatement>,
        operations: Vec<String>,
        outcome: impl Into<String>,
        predictive_signals: Vec<String>,
        misleading_signals: Vec<String>,
        failed_assumptions: Vec<String>,
        cost: BudgetVector,
        applicability: Vec<String>,
        evidence_strength: EvidenceStrength,
        confidence_numerator: u32,
        decay_half_life_days: u32,
        privacy_class: impl Into<String>,
        created_at_ns: i128,
    ) -> Result<Self, ContractError> {
        let experience_id = experience_id.into();
        check_portable(&experience_id, 256)?;
        for handle in &deployment_scope {
            check_str(handle, 1024)?;
        }
        let situation_signature_json = situation_signature_json.into();
        if situation_signature_json.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        let objective = objective.into();
        check_str(&objective, 4096)?;
        let outcome = outcome.into();
        check_str(&outcome, 8192)?;
        if confidence_numerator > 1_000_000 {
            return Err(ContractError::InvalidProbabilityInterval);
        }
        let privacy_class = privacy_class.into();
        check_str(&privacy_class, 1024)?;
        Ok(Self {
            experience_id,
            mission_id,
            deployment_scope,
            basis_anchor,
            situation_signature_json,
            objective,
            initial_epistemic_map,
            operations,
            outcome,
            predictive_signals,
            misleading_signals,
            failed_assumptions,
            cost,
            applicability,
            evidence_strength,
            confidence_numerator,
            decay_half_life_days,
            privacy_class,
            created_at_ns,
        })
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn experience_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for ExperienceCapsule {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.text(&self.experience_id);
        self.mission_id.encode_canonical(encoder);
        encoder.u32(self.deployment_scope.len() as u32);
        for scope in &self.deployment_scope {
            encoder.text(scope);
        }
        self.basis_anchor.encode_canonical(encoder);
        encoder.text(&self.situation_signature_json);
        encoder.text(&self.objective);
        encoder.u32(self.initial_epistemic_map.len() as u32);
        for statement in &self.initial_epistemic_map {
            encoder.text(&statement.statement_id);
            encoder.text(&statement.text);
            statement.epistemic_state.encode_canonical(encoder);
            encoder.u32(statement.basis.len() as u32);
            for basis in &statement.basis {
                encoder.text(basis);
            }
        }
        encoder.u32(self.operations.len() as u32);
        for operation in &self.operations {
            encoder.text(operation);
        }
        encoder.text(&self.outcome);
        encoder.u32(self.predictive_signals.len() as u32);
        for signal in &self.predictive_signals {
            encoder.text(signal);
        }
        encoder.u32(self.misleading_signals.len() as u32);
        for signal in &self.misleading_signals {
            encoder.text(signal);
        }
        encoder.u32(self.failed_assumptions.len() as u32);
        for assumption in &self.failed_assumptions {
            encoder.text(assumption);
        }
        self.cost.encode_canonical(encoder);
        encoder.u32(self.applicability.len() as u32);
        for condition in &self.applicability {
            encoder.text(condition);
        }
        encoder.text(self.evidence_strength.as_str());
        encoder.u32(self.confidence_numerator);
        encoder.u32(self.decay_half_life_days);
        encoder.text(&self.privacy_class);
        encoder.i128(self.created_at_ns);
    }
}

// ---------------------------------------------------------------------------
// ExecutionEpisode (fss.agent_execution_episode.v1)
// ---------------------------------------------------------------------------

/// One prediction recorded before execution and its observation.
#[derive(Clone, Debug, PartialEq)]
pub struct EpisodePrediction {
    /// Prediction identity.
    pub prediction_id: String,
    /// What was predicted.
    pub statement: String,
    /// The expected state.
    pub expected_state: String,
    /// The observed state, when observed.
    pub observed_state: Option<String>,
    /// Numeric error, when computable.
    pub error: Option<f64>,
}

/// The terminal outcome of an execution episode.
#[derive(Clone, Debug, PartialEq)]
pub struct EpisodeOutcome {
    /// Terminal state.
    pub state: EpisodeOutcomeState,
    /// Predicates that succeeded.
    pub success_predicates: Vec<String>,
    /// Predicates that failed.
    pub failed_predicates: Vec<String>,
    /// Predicates that stayed indeterminate.
    pub indeterminate_predicates: Vec<String>,
}

/// Registered episode outcome states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpisodeOutcomeState {
    /// All success predicates proved.
    Succeeded,
    /// Some success predicates proved.
    PartiallySucceeded,
    /// Failed.
    Failed,
    /// Cancelled.
    Cancelled,
    /// Cannot be established.
    Indeterminate,
}

impl EpisodeOutcomeState {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::PartiallySucceeded => "partially_succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// Registered attribution cause classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributionCauseClass {
    /// Evidence problem.
    Evidence,
    /// Hypothesis problem.
    Hypothesis,
    /// Context selection problem.
    ContextSelection,
    /// Model problem.
    Model,
    /// Calibration problem.
    Calibration,
    /// Adapter problem.
    Adapter,
    /// Policy problem.
    Policy,
    /// Execution problem.
    Execution,
    /// External cause.
    External,
    /// Budget cause.
    Budget,
    /// Authority cause.
    Authority,
    /// Memory cause.
    Memory,
    /// Unobservability.
    Unobservability,
}

impl AttributionCauseClass {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evidence => "evidence",
            Self::Hypothesis => "hypothesis",
            Self::ContextSelection => "context_selection",
            Self::Model => "model",
            Self::Calibration => "calibration",
            Self::Adapter => "adapter",
            Self::Policy => "policy",
            Self::Execution => "execution",
            Self::External => "external",
            Self::Budget => "budget",
            Self::Authority => "authority",
            Self::Memory => "memory",
            Self::Unobservability => "unobservability",
        }
    }
}

/// One attribution hypothesis for the episode outcome.
#[derive(Clone, Debug, PartialEq)]
pub struct AttributionHypothesis {
    /// Cause class.
    pub cause_class: AttributionCauseClass,
    /// The attribution statement.
    pub statement: String,
    /// Supporting evidence handles.
    pub supporting_evidence: Vec<String>,
    /// Contradicting evidence handles.
    pub contradicting_evidence: Vec<String>,
    /// Micro-confidence numerator over 1_000_000.
    pub confidence_numerator: u32,
}

/// An execution episode record (fss.agent_execution_episode.v1).
#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionEpisode {
    /// Episode identity.
    pub episode_id: String,
    /// Executing session.
    pub session_id: SessionId,
    /// Objective served.
    pub objective_id: String,
    /// Anchor at episode start.
    pub initial_anchor: LedgerAnchor,
    /// Anchor at episode end.
    pub terminal_anchor: LedgerAnchor,
    /// Digest of the executed plan.
    pub plan_digest: String,
    /// Predictions with observations.
    pub predictions: Vec<EpisodePrediction>,
    /// Step receipts.
    pub step_receipts: Vec<String>,
    /// Effect receipts.
    pub effect_receipts: Vec<String>,
    /// Obligation identities.
    pub obligations: Vec<String>,
    /// Terminal outcome.
    pub outcome: EpisodeOutcome,
    /// Resource use (pinned canonical JSON).
    pub resource_use_json: String,
    /// Attribution hypotheses.
    pub attribution_hypotheses: Vec<AttributionHypothesis>,
    /// Residual uncertainty statements.
    pub residual_uncertainty: Vec<String>,
    /// Decision digest.
    pub decision_digest: String,
}

impl ExecutionEpisode {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_execution_episode.v1";

    /// Validates and constructs an execution episode.
    ///
    /// Every attribution confidence must stay within the micro-denominator.
    #[allow(clippy::too_many_arguments)] // constructor mirrors the registered schema field list 1:1
    pub fn new(
        episode_id: impl Into<String>,
        session_id: SessionId,
        objective_id: impl Into<String>,
        initial_anchor: LedgerAnchor,
        terminal_anchor: LedgerAnchor,
        plan_digest: impl Into<String>,
        predictions: Vec<EpisodePrediction>,
        step_receipts: Vec<String>,
        effect_receipts: Vec<String>,
        obligations: Vec<String>,
        outcome: EpisodeOutcome,
        resource_use_json: impl Into<String>,
        attribution_hypotheses: Vec<AttributionHypothesis>,
        residual_uncertainty: Vec<String>,
        decision_digest: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let episode_id = episode_id.into();
        check_portable(&episode_id, 256)?;
        let objective_id = objective_id.into();
        check_portable(&objective_id, 256)?;
        let plan_digest = plan_digest.into();
        check_str(&plan_digest, 256)?;
        let resource_use_json = resource_use_json.into();
        if resource_use_json.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        for prediction in &predictions {
            check_portable(&prediction.prediction_id, 256)?;
            check_str(&prediction.statement, 4096)?;
            check_str(&prediction.expected_state, 4096)?;
        }
        for receipt in step_receipts.iter().chain(&effect_receipts).chain(&obligations) {
            check_str(receipt, 4096)?;
        }
        for attribution in &attribution_hypotheses {
            check_str(&attribution.statement, 4096)?;
            if attribution.confidence_numerator > 1_000_000 {
                return Err(ContractError::InvalidProbabilityInterval);
            }
        }
        for statement in &residual_uncertainty {
            check_str(statement, 4096)?;
        }
        let decision_digest = decision_digest.into();
        check_decision_digest(&decision_digest)?;
        Ok(Self {
            episode_id,
            session_id,
            objective_id,
            initial_anchor,
            terminal_anchor,
            plan_digest,
            predictions,
            step_receipts,
            effect_receipts,
            obligations,
            outcome,
            resource_use_json,
            attribution_hypotheses,
            residual_uncertainty,
            decision_digest,
        })
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn episode_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for ExecutionEpisode {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.text(&self.episode_id);
        self.session_id.encode_canonical(encoder);
        encoder.text(&self.objective_id);
        self.initial_anchor.encode_canonical(encoder);
        self.terminal_anchor.encode_canonical(encoder);
        encoder.text(&self.plan_digest);
        encoder.u32(self.predictions.len() as u32);
        for prediction in &self.predictions {
            encoder.text(&prediction.prediction_id);
            encoder.text(&prediction.statement);
            encoder.text(&prediction.expected_state);
            match &prediction.observed_state {
                Some(observed) => {
                    encoder.bool(true);
                    encoder.text(observed);
                }
                None => encoder.bool(false),
            }
            match prediction.error {
                Some(error) => {
                    encoder.bool(true);
                    encoder.text(&ryu_string(error));
                }
                None => encoder.bool(false),
            }
        }
        for group in [
            &self.step_receipts,
            &self.effect_receipts,
            &self.obligations,
        ] {
            encoder.u32(group.len() as u32);
            for entry in group {
                encoder.text(entry);
            }
        }
        encoder.text(self.outcome.state.as_str());
        for group in [
            &self.outcome.success_predicates,
            &self.outcome.failed_predicates,
            &self.outcome.indeterminate_predicates,
        ] {
            encoder.u32(group.len() as u32);
            for predicate in group {
                encoder.text(predicate);
            }
        }
        encoder.text(&self.resource_use_json);
        encoder.u32(self.attribution_hypotheses.len() as u32);
        for attribution in &self.attribution_hypotheses {
            encoder.text(attribution.cause_class.as_str());
            encoder.text(&attribution.statement);
            encoder.u32(attribution.supporting_evidence.len() as u32);
            for handle in &attribution.supporting_evidence {
                encoder.text(handle);
            }
            encoder.u32(attribution.contradicting_evidence.len() as u32);
            for handle in &attribution.contradicting_evidence {
                encoder.text(handle);
            }
            encoder.u32(attribution.confidence_numerator);
        }
        encoder.u32(self.residual_uncertainty.len() as u32);
        for statement in &self.residual_uncertainty {
            encoder.text(statement);
        }
        encoder.text(&self.decision_digest);
    }
}

/// Renders an [`f64`] losslessly enough for canonical digests (shortest
/// round-trip form via [`f64::to_string`]).
#[allow(clippy::all)]
fn ryu_string(value: f64) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = write!(out, "{value}");
    out
}
