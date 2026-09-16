#![forbid(unsafe_code)]
//! Mission, objective, session, and workspace-capsule contracts
//! (fss.agent_mission.v1, fss.agent_objective_contract.v1,
//! fss.agent_session.v1, fss.agent_session_capsule.v1).
//!
//! Each type mirrors its registered schema document
//! (`schemas/<name>.v1.json`, `registries/SCHEMAS.md`) with validated
//! constructors, canonical encoding, and a domain-separated digest under its
//! schema identity. Constructors enforce the schema's own constraints
//! (identifier alphabets, ordering bounds, statuses) plus the registry
//! foreign keys (registered views) - nothing here invents semantics.

use std::collections::BTreeSet;

use crate::agent_view::AgentView;
use crate::canonical::{CanonicalEncode, CanonicalEncoder};
use crate::contract::ContractError;
use crate::digest::ContentDigest;
use crate::evidence::LedgerAnchor;
use crate::ids::validate_id;
use crate::{BudgetVector, MissionId, PrincipalId, SessionId};

/// Validates the portable identifier alphabet used by the session/mission
/// schemas (`^[A-Za-z0-9][A-Za-z0-9:._+/-]*$`, bounded).
fn validate_portable(value: &str, max_len: usize) -> Result<(), ContractError> {
    validate_id(value)?;
    if value.len() > max_len {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

/// Validates the lowercase decision-digest spelling
/// (`^[a-z0-9][a-z0-9:+._-]{7,255}$`).
fn validate_decision_digest(value: &str) -> Result<(), ContractError> {
    let bytes = value.as_bytes();
    let alphanumeric = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if bytes.is_empty()
        || !alphanumeric(bytes[0])
        || bytes.len() < 8
        || bytes.len() > 256
        || !bytes[1..]
            .iter()
            .all(|&b| alphanumeric(b) || matches!(b, b':' | b'+' | b'.' | b'_' | b'-'))
    {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

/// Lifecycle state of a mission (registered enum, `fss.agent_mission.v1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionState {
    /// Drafted, not yet active.
    Draft,
    /// Active and driving work.
    Active,
    /// Temporarily paused.
    Paused,
    /// Waiting on evidence before advancing.
    AwaitingEvidence,
    /// Waiting on an operator approval.
    AwaitingApproval,
    /// Plan execution in progress.
    Executing,
    /// Reconciling an indeterminate outcome.
    Reconciling,
    /// Reached a terminal answer.
    Resolved,
    /// Terminal failure.
    Failed,
    /// Cancelled by its owner.
    Cancelled,
    /// Outcome cannot yet be established.
    Indeterminate,
    /// Closed and archived.
    Closed,
}

impl MissionState {
    /// Returns the stable registry spelling.
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
}

/// The mission contract (AOP payload of `session.open`).
#[derive(Clone, Debug, PartialEq)]
pub struct MissionContract {
    /// Mission identity.
    pub mission_id: MissionId,
    /// Monotone revision.
    pub revision: u64,
    /// Deployment identity.
    pub deployment_id: String,
    /// Lifecycle state.
    pub state: MissionState,
    /// Decision objective.
    pub objective: String,
    /// Success criteria.
    pub success_criteria: Vec<String>,
    /// Failure criteria.
    pub failure_criteria: Vec<String>,
    /// Stop criteria.
    pub stop_criteria: Vec<String>,
    /// Granted capabilities.
    pub capabilities: BTreeSet<String>,
    /// Privacy scope grants.
    pub privacy_scope: BTreeSet<String>,
    /// Baseline anchor.
    pub baseline_anchor: LedgerAnchor,
    /// Current anchor.
    pub current_anchor: LedgerAnchor,
    /// Budgets.
    pub budgets: BudgetVector,
    /// Decision deadline.
    pub decision_deadline_ns: i128,
    /// Creation time.
    pub created_at_ns: i128,
}

/// Validated parameters for a mission contract.
#[derive(Clone, Debug)]
pub struct MissionContractParams {
    /// Mission identity.
    pub mission_id: MissionId,
    /// Monotone mission revision.
    pub revision: u64,
    /// Deployment the mission runs against.
    pub deployment_id: String,
    /// Lifecycle state.
    pub state: MissionState,
    /// Decision objective.
    pub objective: String,
    /// Success criteria.
    pub success_criteria: Vec<String>,
    /// Failure criteria.
    pub failure_criteria: Vec<String>,
    /// Stop criteria.
    pub stop_criteria: Vec<String>,
    /// Granted capabilities.
    pub capabilities: BTreeSet<String>,
    /// Privacy scope grants.
    pub privacy_scope: BTreeSet<String>,
    /// Baseline authority anchor.
    pub baseline_anchor: LedgerAnchor,
    /// Current authority anchor.
    pub current_anchor: LedgerAnchor,
    /// Mission budget.
    pub budgets: BudgetVector,
    /// Absolute decision deadline.
    pub decision_deadline_ns: i128,
    /// Creation time.
    pub created_at_ns: i128,
}

impl MissionContract {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_mission.v1";

    /// Validates and constructs a mission contract.
    ///
    /// Fails closed on identifier violations, an empty objective, and a
    /// decision deadline at or before creation.
    pub fn new(params: MissionContractParams) -> Result<Self, ContractError> {
        let MissionContractParams {
            mission_id,
            revision,
            deployment_id,
            state,
            objective,
            success_criteria,
            failure_criteria,
            stop_criteria,
            capabilities,
            privacy_scope,
            baseline_anchor,
            current_anchor,
            budgets,
            decision_deadline_ns,
            created_at_ns,
        } = params;
        validate_portable(&deployment_id, 256)?;
        if objective.is_empty() || objective.len() > 4096 {
            return Err(ContractError::InvalidIdentifier);
        }
        for criterion in success_criteria
            .iter()
            .chain(&failure_criteria)
            .chain(&stop_criteria)
        {
            if criterion.is_empty() || criterion.len() > 1024 {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        if decision_deadline_ns <= created_at_ns {
            return Err(ContractError::InvertedTimeInterval);
        }
        Ok(Self {
            mission_id,
            revision,
            deployment_id,
            state,
            objective,
            success_criteria,
            failure_criteria,
            stop_criteria,
            capabilities,
            privacy_scope,
            baseline_anchor,
            current_anchor,
            budgets,
            decision_deadline_ns,
            created_at_ns,
        })
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn mission_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for MissionContract {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.mission_id.encode_canonical(encoder);
        encoder.u64(self.revision);
        encoder.text(&self.deployment_id);
        encoder.text(self.state.as_str());
        encoder.text(&self.objective);
        for group in [&self.success_criteria, &self.failure_criteria, &self.stop_criteria] {
            encoder.u32(group.len() as u32);
            for criterion in group {
                encoder.text(criterion);
            }
        }
        encoder.u32(self.capabilities.len() as u32);
        for capability in &self.capabilities {
            encoder.text(capability);
        }
        encoder.u32(self.privacy_scope.len() as u32);
        for scope in &self.privacy_scope {
            encoder.text(scope);
        }
        self.baseline_anchor.encode_canonical(encoder);
        self.current_anchor.encode_canonical(encoder);
        self.budgets.encode_canonical(encoder);
        encoder.i128(self.decision_deadline_ns);
        encoder.i128(self.created_at_ns);
    }
}

/// Scope dimensions of an objective contract.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ObjectiveScope {
    /// Deployment identities in scope.
    pub deployments: Vec<String>,
    /// Zones in scope.
    pub zones: Vec<String>,
    /// Subjects in scope.
    pub subjects: Vec<String>,
    /// Devices in scope.
    pub devices: Vec<String>,
    /// Time intervals in scope.
    pub time_intervals: Vec<String>,
    /// Data classes in scope.
    pub data_classes: Vec<String>,
}

/// The objective contract compiled by `plan` (AOP-007 payload).
#[derive(Clone, Debug, PartialEq)]
pub struct ObjectiveContract {
    /// Objective identity.
    pub objective_id: String,
    /// Requesting principal and the digest of the originating request.
    pub source_principal: String,
    /// Originating request digest.
    pub source_request_digest: String,
    /// Desired outcome.
    pub desired_outcome: String,
    /// Success predicates.
    pub success_predicates: Vec<String>,
    /// Failure predicates.
    pub failure_predicates: Vec<String>,
    /// Stop conditions.
    pub stop_conditions: Vec<String>,
    /// Hard constraints.
    pub hard_constraints: Vec<String>,
    /// Soft preferences.
    pub soft_preferences: Vec<String>,
    /// Scope dimensions.
    pub scope: ObjectiveScope,
    /// Budgets.
    pub budgets: BudgetVector,
    /// Allowed action targets.
    pub allowed_actions: Vec<String>,
    /// Required approvals.
    pub required_approvals: Vec<String>,
    /// Terminal-proof expectations as stable handles.
    pub terminal_proof: Vec<String>,
    /// Lowercase decision digest binding this objective's decision basis.
    pub decision_digest: String,
}

/// Validated parameters for an objective contract.
#[derive(Clone, Debug)]
pub struct ObjectiveContractParams {
    /// Objective identity.
    pub objective_id: String,
    /// Requesting principal.
    pub source_principal: String,
    /// Digest of the originating request.
    pub source_request_digest: String,
    /// Desired outcome statement.
    pub desired_outcome: String,
    /// Success predicates.
    pub success_predicates: Vec<String>,
    /// Failure predicates.
    pub failure_predicates: Vec<String>,
    /// Stop conditions.
    pub stop_conditions: Vec<String>,
    /// Hard constraints.
    pub hard_constraints: Vec<String>,
    /// Soft preferences.
    pub soft_preferences: Vec<String>,
    /// Scope dimensions.
    pub scope: ObjectiveScope,
    /// Objective budget.
    pub budgets: BudgetVector,
    /// Allowed action targets.
    pub allowed_actions: Vec<String>,
    /// Required approval identities.
    pub required_approvals: Vec<String>,
    /// Terminal-proof expectations.
    pub terminal_proof: Vec<String>,
    /// Lowercase decision digest binding the decision basis.
    pub decision_digest: String,
}

impl ObjectiveContract {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_objective_contract.v1";

    /// Validates and constructs an objective contract.
    pub fn new(params: ObjectiveContractParams) -> Result<Self, ContractError> {
        let ObjectiveContractParams {
            objective_id,
            source_principal,
            source_request_digest,
            desired_outcome,
            success_predicates,
            failure_predicates,
            stop_conditions,
            hard_constraints,
            soft_preferences,
            scope,
            budgets,
            allowed_actions,
            required_approvals,
            terminal_proof,
            decision_digest,
        } = params;
        validate_portable(&objective_id, 256)?;
        if source_principal.is_empty() || source_principal.len() > 256 {
            return Err(ContractError::InvalidIdentifier);
        }
        validate_decision_digest(&source_request_digest)?;
        validate_decision_digest(&decision_digest)?;
        if desired_outcome.is_empty() || desired_outcome.len() > 4096 {
            return Err(ContractError::InvalidIdentifier);
        }
        for predicate in success_predicates
            .iter()
            .chain(&failure_predicates)
            .chain(&stop_conditions)
            .chain(&hard_constraints)
        {
            if predicate.is_empty() || predicate.len() > 1024 {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        Ok(Self {
            objective_id,
            source_principal,
            source_request_digest,
            desired_outcome,
            success_predicates,
            failure_predicates,
            stop_conditions,
            hard_constraints,
            soft_preferences,
            scope,
            budgets,
            allowed_actions,
            required_approvals,
            terminal_proof,
            decision_digest,
        })
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn objective_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for ObjectiveContract {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.text(&self.objective_id);
        encoder.text(&self.source_principal);
        encoder.text(&self.source_request_digest);
        encoder.text(&self.desired_outcome);
        for group in [
            &self.success_predicates,
            &self.failure_predicates,
            &self.stop_conditions,
            &self.hard_constraints,
            &self.soft_preferences,
        ] {
            encoder.u32(group.len() as u32);
            for entry in group {
                encoder.text(entry);
            }
        }
        for group in [
            &self.scope.deployments,
            &self.scope.zones,
            &self.scope.subjects,
            &self.scope.devices,
            &self.scope.time_intervals,
            &self.scope.data_classes,
        ] {
            encoder.u32(group.len() as u32);
            for entry in group {
                encoder.text(entry);
            }
        }
        self.budgets.encode_canonical(encoder);
        for group in [&self.allowed_actions, &self.required_approvals, &self.terminal_proof] {
            encoder.u32(group.len() as u32);
            for entry in group {
                encoder.text(entry);
            }
        }
        encoder.text(&self.decision_digest);
    }
}

/// The agent session negotiated by `session.open` (AOP-001 durable record).
#[derive(Clone, Debug, PartialEq)]
pub struct AgentSession {
    /// Session identity.
    pub session_id: SessionId,
    /// Mission identity.
    pub mission_id: MissionId,
    /// Requesting principal.
    pub principal_id: PrincipalId,
    /// Granted capabilities.
    pub capabilities: BTreeSet<String>,
    /// Privacy scope grants.
    pub privacy_scope: BTreeSet<String>,
    /// Current anchor.
    pub current_anchor: LedgerAnchor,
    /// Registered default view.
    pub view: AgentView,
    /// Token budget.
    pub token_budget: u64,
    /// Symbol-table generation.
    pub symbol_table_generation: u64,
    /// Last acknowledged situation fingerprint, when pinned.
    pub last_acknowledged_situation_fingerprint: Option<ContentDigest>,
    /// Creation time.
    pub created_at_ns: i128,
    /// Expiry time.
    pub expires_at_ns: i128,
}

/// Validated parameters for an agent session.
#[derive(Clone, Debug)]
pub struct AgentSessionParams {
    /// Session identity.
    pub session_id: SessionId,
    /// Mission the session serves.
    pub mission_id: MissionId,
    /// Requesting principal.
    pub principal_id: PrincipalId,
    /// Granted capabilities.
    pub capabilities: BTreeSet<String>,
    /// Privacy scope grants.
    pub privacy_scope: BTreeSet<String>,
    /// Current authority anchor.
    pub current_anchor: LedgerAnchor,
    /// Registered view identity (`AVIEW-###`).
    pub view_id: String,
    /// Token budget of the session.
    pub token_budget: u64,
    /// Symbol-table generation.
    pub symbol_table_generation: u64,
    /// Last acknowledged situation fingerprint, when pinned.
    pub last_acknowledged_situation_fingerprint: Option<ContentDigest>,
    /// Creation time.
    pub created_at_ns: i128,
    /// Expiry time.
    pub expires_at_ns: i128,
}

impl AgentSession {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_session.v1";

    /// Validates and constructs a session.
    ///
    /// The view must be registered, the token budget at least 1, and expiry
    /// strictly after creation: a zero-budget or already-expired session is
    /// refused rather than negotiated.
    pub fn new(params: AgentSessionParams) -> Result<Self, ContractError> {
        let AgentSessionParams {
            session_id,
            mission_id,
            principal_id,
            capabilities,
            privacy_scope,
            current_anchor,
            view_id,
            token_budget,
            symbol_table_generation,
            last_acknowledged_situation_fingerprint,
            created_at_ns,
            expires_at_ns,
        } = params;
        let view = AgentView::from_id(&view_id)?;
        if token_budget == 0 || expires_at_ns <= created_at_ns {
            return Err(ContractError::InvertedTimeInterval);
        }
        Ok(Self {
            session_id,
            mission_id,
            principal_id,
            capabilities,
            privacy_scope,
            current_anchor,
            view,
            token_budget,
            symbol_table_generation,
            last_acknowledged_situation_fingerprint,
            created_at_ns,
            expires_at_ns,
        })
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn session_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for AgentSession {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.session_id.encode_canonical(encoder);
        self.mission_id.encode_canonical(encoder);
        self.principal_id.encode_canonical(encoder);
        encoder.u32(self.capabilities.len() as u32);
        for capability in &self.capabilities {
            encoder.text(capability);
        }
        encoder.u32(self.privacy_scope.len() as u32);
        for scope in &self.privacy_scope {
            encoder.text(scope);
        }
        self.current_anchor.encode_canonical(encoder);
        encoder.text(self.view.id());
        encoder.u64(self.token_budget);
        encoder.u64(self.symbol_table_generation);
        match self.last_acknowledged_situation_fingerprint {
            Some(fingerprint) => {
                encoder.bool(true);
                encoder.digest(fingerprint);
            }
            None => encoder.bool(false),
        }
        encoder.i128(self.created_at_ns);
        encoder.i128(self.expires_at_ns);
    }
}

/// The workspace capsule published and restored by `session.resume` and
/// `handoff` (AOP payload of resume; durable workspace revision).
#[derive(Clone, Debug, PartialEq)]
pub struct SessionCapsule {
    /// Session identity.
    pub session_id: SessionId,
    /// Monotone revision.
    pub revision: u64,
    /// Workspace principal.
    pub principal: String,
    /// Projected capabilities.
    pub capability_projection: Vec<String>,
    /// Digest of the objective this workspace serves.
    pub objective_digest: String,
    /// Base anchor.
    pub base_anchor: LedgerAnchor,
    /// Current anchor.
    pub current_anchor: LedgerAnchor,
    /// Digest of the situation capsule this workspace was built over.
    pub situation_capsule_digest: String,
    /// Active hypotheses.
    pub active_hypotheses: Vec<String>,
    /// Carried assumptions.
    pub assumptions: Vec<String>,
    /// Material unknowns.
    pub unknowns: Vec<String>,
    /// Not-observable domains.
    pub not_observable_domains: Vec<String>,
    /// Epistemic debt: stale or unvalidated material carried explicitly.
    pub epistemic_debt: Vec<String>,
    /// Open obligations.
    pub open_obligations: Vec<String>,
    /// Budget ledger.
    pub budget_ledger: BudgetVector,
    /// Bookmarked evidence.
    pub bookmarked_evidence: Vec<ContentDigest>,
    /// Next actions.
    pub next_actions: Vec<String>,
    /// Lowercase decision digest binding the workspace decision basis.
    pub decision_digest: String,
}

/// Validated parameters for a workspace capsule.
#[derive(Clone, Debug)]
pub struct SessionCapsuleParams {
    /// Owning session identity.
    pub session_id: SessionId,
    /// Monotone workspace revision.
    pub revision: u64,
    /// Workspace principal.
    pub principal: String,
    /// Projected capabilities.
    pub capability_projection: Vec<String>,
    /// Digest of the objective this workspace serves.
    pub objective_digest: String,
    /// Base authority anchor.
    pub base_anchor: LedgerAnchor,
    /// Current authority anchor.
    pub current_anchor: LedgerAnchor,
    /// Situation capsule digest the workspace was built over.
    pub situation_capsule_digest: String,
    /// Active hypotheses.
    pub active_hypotheses: Vec<String>,
    /// Carried assumptions.
    pub assumptions: Vec<String>,
    /// Material unknowns.
    pub unknowns: Vec<String>,
    /// Domains that are not observable.
    pub not_observable_domains: Vec<String>,
    /// Epistemic debt carried explicitly.
    pub epistemic_debt: Vec<String>,
    /// Open obligations.
    pub open_obligations: Vec<String>,
    /// Budget ledger.
    pub budget_ledger: BudgetVector,
    /// Bookmarked evidence digests.
    pub bookmarked_evidence: Vec<ContentDigest>,
    /// Next actions.
    pub next_actions: Vec<String>,
    /// Lowercase decision digest binding the workspace decision basis.
    pub decision_digest: String,
}

impl SessionCapsule {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_session_capsule.v1";

    /// Validates and constructs a workspace capsule.
    ///
    /// The current anchor must be at or after the base anchor within the same
    /// lineage and epoch, and the decision digests must carry the registered
    /// lowercase spelling.
    pub fn new(params: SessionCapsuleParams) -> Result<Self, ContractError> {
        let SessionCapsuleParams {
            session_id,
            revision,
            principal,
            capability_projection,
            objective_digest,
            base_anchor,
            current_anchor,
            situation_capsule_digest,
            active_hypotheses,
            assumptions,
            unknowns,
            not_observable_domains,
            epistemic_debt,
            open_obligations,
            budget_ledger,
            bookmarked_evidence,
            next_actions,
            decision_digest,
        } = params;
        if principal.is_empty() || principal.len() > 256 {
            return Err(ContractError::InvalidIdentifier);
        }
        validate_decision_digest(&objective_digest)?;
        validate_decision_digest(&objective_digest)?;
        validate_decision_digest(&situation_capsule_digest)?;
        validate_decision_digest(&decision_digest)?;
        if base_anchor.site_lineage != current_anchor.site_lineage
            || base_anchor.ledger_epoch != current_anchor.ledger_epoch
            || (current_anchor.commit_sequence, current_anchor.adapter_registry_epoch)
                < (base_anchor.commit_sequence, base_anchor.adapter_registry_epoch)
        {
            return Err(ContractError::InvalidAnchorSuccessor);
        }
        Ok(Self {
            session_id,
            revision,
            principal,
            capability_projection,
            objective_digest,
            base_anchor,
            current_anchor,
            situation_capsule_digest,
            active_hypotheses,
            assumptions,
            unknowns,
            not_observable_domains,
            epistemic_debt,
            open_obligations,
            budget_ledger,
            bookmarked_evidence,
            next_actions,
            decision_digest,
        })
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn capsule_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for SessionCapsule {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.session_id.encode_canonical(encoder);
        encoder.u64(self.revision);
        encoder.text(&self.principal);
        encoder.u32(self.capability_projection.len() as u32);
        for capability in &self.capability_projection {
            encoder.text(capability);
        }
        encoder.text(&self.objective_digest);
        self.base_anchor.encode_canonical(encoder);
        self.current_anchor.encode_canonical(encoder);
        encoder.text(&self.situation_capsule_digest);
        for group in [
            &self.active_hypotheses,
            &self.assumptions,
            &self.unknowns,
            &self.not_observable_domains,
            &self.epistemic_debt,
            &self.open_obligations,
        ] {
            encoder.u32(group.len() as u32);
            for entry in group {
                encoder.text(entry);
            }
        }
        self.budget_ledger.encode_canonical(encoder);
        encoder.u32(self.bookmarked_evidence.len() as u32);
        for digest in &self.bookmarked_evidence {
            encoder.digest(*digest);
        }
        encoder.u32(self.next_actions.len() as u32);
        for action in &self.next_actions {
            encoder.text(action);
        }
        encoder.text(&self.decision_digest);
    }
}
