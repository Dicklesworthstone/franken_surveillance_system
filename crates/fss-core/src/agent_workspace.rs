#![forbid(unsafe_code)]
//! Hypothesis workspace, control plan, and the schema-faithful feedback
//! proposal payload (fss.agent_hypothesis_workspace.v1,
//! fss.agent_control_plan.v1, fss.agent_feedback_proposal.v1).

use std::collections::BTreeSet;

use crate::canonical::{CanonicalEncode, CanonicalEncoder};
use crate::contract::ContractError;
use crate::digest::ContentDigest;
use crate::evidence::LedgerAnchor;
use crate::ids::validate_id;
use crate::{BudgetVector, PrincipalId, SessionId};

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

fn bounded_list(list: &[String], max_items: usize, max_len: usize) -> Result<(), ContractError> {
    if list.len() > max_items {
        return Err(ContractError::CountBoundExceeded);
    }
    for entry in list {
        check_str(entry, max_len)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HypothesisWorkspace (fss.agent_hypothesis_workspace.v1)
// ---------------------------------------------------------------------------

/// Registered status of a workspace hypothesis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceHypothesisStatus {
    /// Proposed.
    Proposed,
    /// Viable under current evidence.
    Viable,
    /// Currently leading.
    Leading,
    /// Weakened by evidence.
    Weakened,
    /// Refuted.
    Refuted,
    /// Merged into another hypothesis.
    Merged,
    /// Split into sub-hypotheses.
    Split,
    /// Retired.
    Retired,
}

impl WorkspaceHypothesisStatus {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Viable => "viable",
            Self::Leading => "leading",
            Self::Weakened => "weakened",
            Self::Refuted => "refuted",
            Self::Merged => "merged",
            Self::Split => "split",
            Self::Retired => "retired",
        }
    }
}

/// One hypothesis in a workspace.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkspaceHypothesis {
    /// Stable hypothesis identity.
    pub hypothesis_id: String,
    /// The proposition (up to 16 KiB).
    pub proposition: String,
    /// Registered status.
    pub status: WorkspaceHypothesisStatus,
    /// Supporting evidence handles.
    pub supporting_evidence: Vec<String>,
    /// Contradicting evidence handles.
    pub contradicting_evidence: Vec<String>,
    /// Missing evidence that would discriminate.
    pub missing_evidence: Vec<String>,
    /// Assumptions.
    pub assumptions: Vec<String>,
    /// Invalidators.
    pub invalidators: Vec<String>,
    /// Predictions.
    pub predictions: Vec<String>,
    /// Distinguishing tests.
    pub distinguishing_tests: Vec<String>,
    /// Consequences of accepting, rejecting, or leaving unresolved.
    pub consequences_accept: Vec<String>,
    /// Consequences of rejecting.
    pub consequences_reject: Vec<String>,
    /// Consequences of leaving unresolved.
    pub consequences_unresolved: Vec<String>,
}

/// Registered competition policy of a hypothesis workspace.
#[derive(Clone, Debug, PartialEq)]
pub struct CompetitionPolicy {
    /// Loss model identity.
    pub loss_model_id: String,
    /// Tie-break policy descriptor.
    pub tie_break_policy: String,
    /// Protected high-loss alternatives are retained against ranking.
    pub retain_high_loss_alternatives: bool,
}

/// A durable hypothesis workspace (AOP-006 payload surface).
#[derive(Clone, Debug, PartialEq)]
pub struct HypothesisWorkspace {
    /// Workspace identity.
    pub workspace_id: String,
    /// Objective the workspace serves.
    pub objective_id: String,
    /// Authority anchor.
    pub anchor: LedgerAnchor,
    /// Monotone revision.
    pub revision: u64,
    /// Competing hypotheses (1..=1024).
    pub hypotheses: Vec<WorkspaceHypothesis>,
    /// Registered competition policy.
    pub competition_policy: CompetitionPolicy,
    /// Decision digest.
    pub decision_digest: String,
}

impl HypothesisWorkspace {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_hypothesis_workspace.v1";

    /// Validates and constructs a workspace.
    ///
    /// Hypothesis identities must be unique; evidence groups are bounded at
    /// 4096 entries of at most 4096 characters.
    pub fn new(
        workspace_id: impl Into<String>,
        objective_id: impl Into<String>,
        anchor: LedgerAnchor,
        revision: u64,
        hypotheses: Vec<WorkspaceHypothesis>,
        competition_policy: CompetitionPolicy,
        decision_digest: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let workspace_id = workspace_id.into();
        check_portable(&workspace_id, 256)?;
        let objective_id = objective_id.into();
        check_portable(&objective_id, 256)?;
        if hypotheses.is_empty() || hypotheses.len() > 1024 {
            return Err(ContractError::CountBoundExceeded);
        }
        let mut ids = BTreeSet::new();
        for hypothesis in &hypotheses {
            check_portable(&hypothesis.hypothesis_id, 256)?;
            check_str(&hypothesis.proposition, 16_384)?;
            if !ids.insert(hypothesis.hypothesis_id.as_str()) {
                return Err(ContractError::InvalidIdentifier);
            }
            for group in [
                &hypothesis.supporting_evidence,
                &hypothesis.contradicting_evidence,
                &hypothesis.missing_evidence,
                &hypothesis.assumptions,
                &hypothesis.invalidators,
                &hypothesis.predictions,
                &hypothesis.distinguishing_tests,
                &hypothesis.consequences_accept,
                &hypothesis.consequences_reject,
                &hypothesis.consequences_unresolved,
            ] {
                bounded_list(group, 4096, 4096)?;
            }
        }
        check_portable(&competition_policy.loss_model_id, 256)?;
        check_str(&competition_policy.tie_break_policy, 4096)?;
        let decision_digest = decision_digest.into();
        check_decision_digest(&decision_digest)?;
        Ok(Self {
            workspace_id,
            objective_id,
            anchor,
            revision,
            hypotheses,
            competition_policy,
            decision_digest,
        })
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn workspace_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for HypothesisWorkspace {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.text(&self.workspace_id);
        encoder.text(&self.objective_id);
        self.anchor.encode_canonical(encoder);
        encoder.u64(self.revision);
        encoder.u32(self.hypotheses.len() as u32);
        for hypothesis in &self.hypotheses {
            encoder.text(&hypothesis.hypothesis_id);
            encoder.text(&hypothesis.proposition);
            encoder.text(hypothesis.status.as_str());
            for group in [
                &hypothesis.supporting_evidence,
                &hypothesis.contradicting_evidence,
                &hypothesis.missing_evidence,
                &hypothesis.assumptions,
                &hypothesis.invalidators,
                &hypothesis.predictions,
                &hypothesis.distinguishing_tests,
                &hypothesis.consequences_accept,
                &hypothesis.consequences_reject,
                &hypothesis.consequences_unresolved,
            ] {
                encoder.u32(group.len() as u32);
                for entry in group {
                    encoder.text(entry);
                }
            }
        }
        encoder.text(&self.competition_policy.loss_model_id);
        encoder.text(&self.competition_policy.tie_break_policy);
        encoder.bool(self.competition_policy.retain_high_loss_alternatives);
        encoder.text(&self.decision_digest);
    }
}

// ---------------------------------------------------------------------------
// ControlPlan (fss.agent_control_plan.v1)
// ---------------------------------------------------------------------------

/// Registered kind of a control plan step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlStepKind {
    /// Observe.
    Observe,
    /// Compute.
    Compute,
    /// Compare.
    Compare,
    /// Simulate.
    Simulate,
    /// Decide.
    Decide,
    /// Prepare an effect.
    PrepareEffect,
    /// Commit an effect.
    CommitEffect,
    /// Wait.
    WaitFor,
    /// Verify.
    Verify,
    /// Repair.
    Repair,
    /// Learn.
    Learn,
    /// Checkpoint.
    Checkpoint,
}

impl ControlStepKind {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "Observe",
            Self::Compute => "Compute",
            Self::Compare => "Compare",
            Self::Simulate => "Simulate",
            Self::Decide => "Decide",
            Self::PrepareEffect => "PrepareEffect",
            Self::CommitEffect => "CommitEffect",
            Self::WaitFor => "WaitFor",
            Self::Verify => "Verify",
            Self::Repair => "Repair",
            Self::Learn => "Learn",
            Self::Checkpoint => "Checkpoint",
        }
    }
}

/// Registered robustness class of a control plan step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepRobustness {
    /// Robust across the envelope.
    RobustAcrossEnvelope,
    /// Conditional on named worlds.
    ConditionalOnNamedWorlds,
    /// Primarily gathers information.
    InformationGathering,
    /// Wait and watch.
    WaitAndWatch,
    /// Not applicable.
    NotApplicable,
}

impl StepRobustness {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RobustAcrossEnvelope => "robust_across_envelope",
            Self::ConditionalOnNamedWorlds => "conditional_on_named_worlds",
            Self::InformationGathering => "information_gathering",
            Self::WaitAndWatch => "wait_and_watch",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Registered reversibility of a control plan step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepReversibility {
    /// Read-only.
    ReadOnly,
    /// Fully reversible.
    FullyReversible,
    /// Compensatable.
    Compensatable,
    /// Irreversible.
    Irreversible,
    /// Unknown.
    Unknown,
}

impl StepReversibility {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::FullyReversible => "fully_reversible",
            Self::Compensatable => "compensatable",
            Self::Irreversible => "irreversible",
            Self::Unknown => "unknown",
        }
    }
}

/// Registered risk level of a control plan step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepRisk {
    /// No risk.
    None,
    /// Low.
    Low,
    /// Moderate.
    Moderate,
    /// High.
    High,
    /// Critical.
    Critical,
}

impl StepRisk {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Moderate => "moderate",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// One step of a control plan.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlStep {
    /// Stable step identity.
    pub step_id: String,
    /// Registered step kind.
    pub kind: ControlStepKind,
    /// Owning subsystem or role.
    pub owner: String,
    /// Verb describing the action.
    pub verb: String,
    /// Robustness classification.
    pub robustness_class: StepRobustness,
    /// Supported world identities.
    pub supported_world_ids: Vec<String>,
    /// Unsafe world identities.
    pub unsafe_world_ids: Vec<String>,
    /// Preconditions.
    pub preconditions: Vec<String>,
    /// Read witnesses.
    pub read_witnesses: Vec<String>,
    /// Write witnesses.
    pub write_witnesses: Vec<String>,
    /// Negative witnesses.
    pub negative_witnesses: Vec<String>,
    /// Required capabilities.
    pub required_capabilities: Vec<String>,
    /// Step budget (pinned canonical JSON object of numeric dimensions).
    pub budget_json: String,
    /// Expected information gain.
    pub expected_information_gain: f64,
    /// Expected objective gain.
    pub expected_objective_gain: f64,
    /// Risk level.
    pub risk: StepRisk,
    /// Privacy exposure.
    pub privacy_exposure: f64,
    /// Reversibility.
    pub reversibility: StepReversibility,
    /// Success transition targets.
    pub success_transition: Vec<String>,
    /// Failure transition targets.
    pub failure_transition: Vec<String>,
    /// Cancel transition targets.
    pub cancel_transition: Vec<String>,
    /// Indeterminate transition targets.
    pub indeterminate_transition: Vec<String>,
    /// Terminal proof expectations.
    pub terminal_proof: Vec<String>,
}

/// One directed edge between control plan steps.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlEdge {
    /// Source step id.
    pub from: String,
    /// Target step id.
    pub to: String,
    /// Condition guarding the edge.
    pub condition: String,
    /// Edge priority.
    pub priority: i64,
}

/// An immutable witnessed control plan (AOP-007 response payload).
#[derive(Clone, Debug, PartialEq)]
pub struct ControlPlan {
    /// Plan identity.
    pub plan_id: String,
    /// Objective the plan serves.
    pub objective_id: String,
    /// Basis authority anchor.
    pub basis_anchor: LedgerAnchor,
    /// Situation frame digest the plan was compiled over.
    pub situation_frame_digest: String,
    /// World envelope digest.
    pub world_envelope_digest: ContentDigest,
    /// Hypothesis workspace digest, when the plan is case-conditioned.
    pub hypothesis_workspace_digest: Option<String>,
    /// Capability projection.
    pub capability_projection: Vec<String>,
    /// Plan budget.
    pub budget: BudgetVector,
    /// Steps.
    pub steps: Vec<ControlStep>,
    /// Edges.
    pub edges: Vec<ControlEdge>,
    /// Entry step identities.
    pub entry_steps: Vec<String>,
    /// Terminal predicates.
    pub terminal_predicates: Vec<String>,
    /// Decision digest.
    pub decision_digest: String,
}

impl ControlPlan {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_control_plan.v1";

    /// Validates and constructs a control plan.
    ///
    /// Fails closed unless entry steps and edges reference existing steps and
    /// the decision digest carries the registered lowercase spelling.
    #[allow(clippy::too_many_arguments)] // constructor mirrors the registered schema field list 1:1
    pub fn compile(
        plan_id: impl Into<String>,
        objective_id: impl Into<String>,
        basis_anchor: LedgerAnchor,
        situation_frame_digest: impl Into<String>,
        world_envelope_digest: ContentDigest,
        hypothesis_workspace_digest: Option<String>,
        capability_projection: Vec<String>,
        budget: BudgetVector,
        steps: Vec<ControlStep>,
        edges: Vec<ControlEdge>,
        entry_steps: Vec<String>,
        terminal_predicates: Vec<String>,
        decision_digest: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let plan_id = plan_id.into();
        check_portable(&plan_id, 256)?;
        let objective_id = objective_id.into();
        check_portable(&objective_id, 256)?;
        let situation_frame_digest = situation_frame_digest.into();
        check_decision_digest(&situation_frame_digest)?;
        let decision_digest = decision_digest.into();
        check_decision_digest(&decision_digest)?;
        bounded_list(&capability_projection, 4096, 4096)?;
        if steps.is_empty() || steps.len() > 4096 {
            return Err(ContractError::CountBoundExceeded);
        }
        let ids: BTreeSet<&str> = steps.iter().map(|s| s.step_id.as_str()).collect();
        if ids.len() != steps.len() {
            return Err(ContractError::InvalidIdentifier);
        }
        for step in &steps {
            check_portable(&step.step_id, 256)?;
            check_portable(&step.owner, 256)?;
            check_str(&step.verb, 4096)?;
            bounded_list(&step.supported_world_ids, 256, 256)?;
            bounded_list(&step.unsafe_world_ids, 256, 256)?;
            bounded_list(&step.preconditions, 4096, 4096)?;
            bounded_list(&step.read_witnesses, 4096, 4096)?;
            bounded_list(&step.write_witnesses, 4096, 4096)?;
            bounded_list(&step.negative_witnesses, 4096, 4096)?;
            bounded_list(&step.required_capabilities, 4096, 4096)?;
            check_str(&step.budget_json, 65_536)?;
            if step.privacy_exposure < 0.0 {
                return Err(ContractError::InvalidIdentifier);
            }
            bounded_list(&step.success_transition, 4096, 4096)?;
            bounded_list(&step.failure_transition, 4096, 4096)?;
            bounded_list(&step.cancel_transition, 4096, 4096)?;
            bounded_list(&step.indeterminate_transition, 4096, 4096)?;
            bounded_list(&step.terminal_proof, 4096, 4096)?;
        }
        if edges.len() > 16_384 {
            return Err(ContractError::CountBoundExceeded);
        }
        for edge in &edges {
            if !ids.contains(edge.from.as_str()) || !ids.contains(edge.to.as_str()) {
                return Err(ContractError::NotFound);
            }
            check_str(&edge.condition, 4096)?;
        }
        bounded_list(&entry_steps, 4096, 4096)?;
        for entry in &entry_steps {
            if !ids.contains(entry.as_str()) {
                return Err(ContractError::NotFound);
            }
        }
        bounded_list(&terminal_predicates, 4096, 4096)?;
        Ok(Self {
            plan_id,
            objective_id,
            basis_anchor,
            situation_frame_digest,
            world_envelope_digest,
            hypothesis_workspace_digest,
            capability_projection,
            budget,
            steps,
            edges,
            entry_steps,
            terminal_predicates,
            decision_digest,
        })
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn plan_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for ControlPlan {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.text(&self.plan_id);
        encoder.text(&self.objective_id);
        self.basis_anchor.encode_canonical(encoder);
        encoder.text(&self.situation_frame_digest);
        encoder.digest(self.world_envelope_digest);
        match &self.hypothesis_workspace_digest {
            Some(digest) => {
                encoder.bool(true);
                encoder.text(digest);
            }
            None => encoder.bool(false),
        }
        encoder.u32(self.capability_projection.len() as u32);
        for capability in &self.capability_projection {
            encoder.text(capability);
        }
        self.budget.encode_canonical(encoder);
        encoder.u32(self.steps.len() as u32);
        for step in &self.steps {
            encoder.text(&step.step_id);
            encoder.text(step.kind.as_str());
            encoder.text(&step.owner);
            encoder.text(&step.verb);
            encoder.text(step.robustness_class.as_str());
            for group in [
                &step.supported_world_ids,
                &step.unsafe_world_ids,
                &step.preconditions,
                &step.read_witnesses,
                &step.write_witnesses,
                &step.negative_witnesses,
                &step.required_capabilities,
            ] {
                encoder.u32(group.len() as u32);
                for entry in group {
                    encoder.text(entry);
                }
            }
            encoder.text(&step.budget_json);
            let bits = step.expected_information_gain.to_bits();
            encoder.u64(bits);
            let bits = step.expected_objective_gain.to_bits();
            encoder.u64(bits);
            encoder.text(step.risk.as_str());
            let bits = step.privacy_exposure.to_bits();
            encoder.u64(bits);
            encoder.text(step.reversibility.as_str());
            for group in [
                &step.success_transition,
                &step.failure_transition,
                &step.cancel_transition,
                &step.indeterminate_transition,
                &step.terminal_proof,
            ] {
                encoder.u32(group.len() as u32);
                for entry in group {
                    encoder.text(entry);
                }
            }
        }
        encoder.u32(self.edges.len() as u32);
        for edge in &self.edges {
            encoder.text(&edge.from);
            encoder.text(&edge.to);
            encoder.text(&edge.condition);
            encoder.i128(i128::from(edge.priority));
        }
        encoder.u32(self.entry_steps.len() as u32);
        for entry in &self.entry_steps {
            encoder.text(entry);
        }
        encoder.u32(self.terminal_predicates.len() as u32);
        for predicate in &self.terminal_predicates {
            encoder.text(predicate);
        }
        encoder.text(&self.decision_digest);
    }
}

// ---------------------------------------------------------------------------
// AgentFeedbackProposal (fss.agent_feedback_proposal.v1)
// ---------------------------------------------------------------------------

/// Registered feedback kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackProposalKind {
    /// Correction.
    Correction,
    /// Adjudication.
    Adjudication,
    /// Helpful signal.
    Helpful,
    /// Harmful signal.
    Harmful,
    /// Missing evidence.
    MissingEvidence,
    /// Bad affordance.
    BadAffordance,
    /// Bad summary.
    BadSummary,
    /// Adapter quirk.
    AdapterQuirk,
    /// Runbook candidate.
    RunbookCandidate,
    /// Hard negative candidate.
    HardNegativeCandidate,
    /// Policy candidate.
    PolicyCandidate,
    /// Model candidate.
    ModelCandidate,
}

impl FeedbackProposalKind {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Correction => "correction",
            Self::Adjudication => "adjudication",
            Self::Helpful => "helpful",
            Self::Harmful => "harmful",
            Self::MissingEvidence => "missing_evidence",
            Self::BadAffordance => "bad_affordance",
            Self::BadSummary => "bad_summary",
            Self::AdapterQuirk => "adapter_quirk",
            Self::RunbookCandidate => "runbook_candidate",
            Self::HardNegativeCandidate => "hard_negative_candidate",
            Self::PolicyCandidate => "policy_candidate",
            Self::ModelCandidate => "model_candidate",
        }
    }
}

/// Registered requested dispositions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestedDisposition {
    /// Record only.
    RecordOnly,
    /// Create a learning proposal.
    CreateLearningProposal,
    /// Open a case.
    OpenCase,
    /// Requalify.
    Requalify,
    /// Deprecate.
    Deprecate,
    /// Operator review.
    OperatorReview,
}

impl RequestedDisposition {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordOnly => "record_only",
            Self::CreateLearningProposal => "create_learning_proposal",
            Self::OpenCase => "open_case",
            Self::Requalify => "requalify",
            Self::Deprecate => "deprecate",
            Self::OperatorReview => "operator_review",
        }
    }
}

/// Registered privacy classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackPrivacyClass {
    /// Public.
    Public,
    /// Operational.
    Operational,
    /// Private.
    Private,
    /// Restricted.
    Restricted,
    /// Secret reference only.
    SecretReferenceOnly,
}

impl FeedbackPrivacyClass {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Operational => "operational",
            Self::Private => "private",
            Self::Restricted => "restricted",
            Self::SecretReferenceOnly => "secret_reference_only",
        }
    }
}

/// The schema-faithful feedback proposal payload (AOP-013 request payload).
///
/// `active_policy_mutation` is the literal `false` in the registry: a
/// feedback proposal never mutates active policy by being recorded.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentFeedbackProposal {
    /// Feedback identity.
    pub feedback_id: String,
    /// Submitting principal.
    pub principal_id: PrincipalId,
    /// Submitting session.
    pub session_id: SessionId,
    /// Basis authority anchor.
    pub basis_anchor: LedgerAnchor,
    /// Feedback target (pinned canonical JSON).
    pub target_json: String,
    /// Feedback kind.
    pub kind: FeedbackProposalKind,
    /// Statement.
    pub statement: String,
    /// Supporting evidence handles (lowercase digest spelling).
    pub supporting_evidence: Vec<String>,
    /// Contradicting evidence handles.
    pub contradicting_evidence: Vec<String>,
    /// Requested disposition.
    pub requested_disposition: RequestedDisposition,
    /// Privacy class.
    pub privacy_class: FeedbackPrivacyClass,
    /// Creation time.
    pub created_at_ns: i128,
}

impl AgentFeedbackProposal {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_feedback_proposal.v1";

    /// CONSTITUTIONAL: recording a proposal never mutates active policy.
    pub const ACTIVE_POLICY_MUTATION: bool = false;

    /// Validates and constructs a feedback proposal.
    #[allow(clippy::too_many_arguments)] // constructor mirrors the registered schema field list 1:1
    pub fn new(
        feedback_id: impl Into<String>,
        principal_id: PrincipalId,
        session_id: SessionId,
        basis_anchor: LedgerAnchor,
        target_json: impl Into<String>,
        kind: FeedbackProposalKind,
        statement: impl Into<String>,
        supporting_evidence: Vec<String>,
        contradicting_evidence: Vec<String>,
        requested_disposition: RequestedDisposition,
        privacy_class: FeedbackPrivacyClass,
        created_at_ns: i128,
    ) -> Result<Self, ContractError> {
        let feedback_id = feedback_id.into();
        check_portable(&feedback_id, 256)?;
        let target_json = target_json.into();
        check_str(&target_json, 65_536)?;
        let statement = statement.into();
        check_str(&statement, 16_384)?;
        for handle in supporting_evidence.iter().chain(&contradicting_evidence) {
            check_decision_digest(handle)?;
        }
        if supporting_evidence.len() > 4096 || contradicting_evidence.len() > 4096 {
            return Err(ContractError::CountBoundExceeded);
        }
        Ok(Self {
            feedback_id,
            principal_id,
            session_id,
            basis_anchor,
            target_json,
            kind,
            statement,
            supporting_evidence,
            contradicting_evidence,
            requested_disposition,
            privacy_class,
            created_at_ns,
        })
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn proposal_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for AgentFeedbackProposal {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.text(&self.feedback_id);
        self.principal_id.encode_canonical(encoder);
        self.session_id.encode_canonical(encoder);
        self.basis_anchor.encode_canonical(encoder);
        encoder.text(&self.target_json);
        encoder.text(self.kind.as_str());
        encoder.text(&self.statement);
        encoder.u32(self.supporting_evidence.len() as u32);
        for handle in &self.supporting_evidence {
            encoder.text(handle);
        }
        encoder.u32(self.contradicting_evidence.len() as u32);
        for handle in &self.contradicting_evidence {
            encoder.text(handle);
        }
        encoder.text(self.requested_disposition.as_str());
        encoder.text(self.privacy_class.as_str());
        encoder.i128(self.created_at_ns);
        encoder.bool(Self::ACTIVE_POLICY_MUTATION);
    }
}
