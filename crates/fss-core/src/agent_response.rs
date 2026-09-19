#![forbid(unsafe_code)]
//! The agent response envelope (fss.agent_response_envelope.v1) — the
//! single decision-bearing reply contract of `fss/1`.

use crate::agent::ContractBasis;
use crate::agent_operation::AgentOperation;
use crate::agent_view::AgentView;
use crate::canonical::{CanonicalEncode, CanonicalEncoder};
use crate::contract::ContractError;
use crate::contract_basis::ContractBasisError;
use crate::contract_basis::registered_operation;
use crate::digest::ContentDigest;
use crate::evidence::LedgerAnchor;
use crate::{Completeness, KnowledgeState};

/// Registered outcome of a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseOutcome {
    /// Ok.
    Ok,
    /// Error.
    Error,
    /// Cancelled.
    Cancelled,
    /// Panicked.
    Panicked,
    /// Partial.
    Partial,
    /// Indeterminate.
    Indeterminate,
    /// Refused.
    Refused,
}

impl ResponseOutcome {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
            Self::Panicked => "panicked",
            Self::Partial => "partial",
            Self::Indeterminate => "indeterminate",
            Self::Refused => "refused",
        }
    }
}

/// Registered durable task states of a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseTaskState {
    /// No durable task.
    None,
    /// Task accepted.
    Accepted,
    /// Task running.
    Running,
    /// Task waiting.
    Waiting,
    /// Task blocked.
    Blocked,
    /// Task terminal.
    Terminal,
    /// Task outcome indeterminate.
    Indeterminate,
}

impl ResponseTaskState {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Accepted => "accepted",
            Self::Running => "running",
            Self::Waiting => "waiting",
            Self::Blocked => "blocked",
            Self::Terminal => "terminal",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// Registered safe-retry guidance of a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseSafeRetry {
    /// Same request is safe.
    YesSameRequest,
    /// Retry after refresh is safe.
    YesAfterRefresh,
    /// Retry after reconcile is safe.
    YesAfterReconcile,
    /// Retry is not safe.
    No,
    /// Retry is not applicable.
    NotApplicable,
}

impl ResponseSafeRetry {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::YesSameRequest => "yes_same_request",
            Self::YesAfterRefresh => "yes_after_refresh",
            Self::YesAfterReconcile => "yes_after_reconcile",
            Self::No => "no",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Execution boundary summary of a response.
#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionBoundary {
    /// Effect steps that completed.
    pub completed: Vec<String>,
    /// Effect steps that never started.
    pub not_started: Vec<String>,
    /// Effect steps that may have occurred.
    pub possibly_occurred: Vec<String>,
    /// Truth preserved across the boundary.
    pub preserved_truth: Vec<String>,
    /// Truth invalidated across the boundary.
    pub invalidated: Vec<String>,
}

/// The validated `fss/1` agent response envelope.
///
/// Every decision-bearing field of the registered schema is queryable. The
/// payload travels as pinned canonical JSON text (byte-exact under the
/// digest); its own schema enforcement belongs to the boundary owning that
/// schema.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentResponseEnvelope {
    /// Exact contract basis.
    pub contract_basis: ContractBasis,
    /// Resolved registered operation.
    pub operation: AgentOperation,
    /// Answered request identity.
    pub request_id: String,
    /// Monotone response revision (>= 1).
    pub response_revision: u64,
    /// Responding principal.
    pub principal_id: String,
    /// Session identity, when session-bound.
    pub session_id: Option<String>,
    /// Mission identity, when mission-bound.
    pub mission_id: Option<String>,
    /// Trace identity.
    pub trace_id: String,
    /// Anchor the request was evaluated at.
    pub input_anchor: LedgerAnchor,
    /// Anchor after execution, when the response is effectful.
    pub output_anchor: Option<LedgerAnchor>,
    /// Workspace revision, when pinned.
    pub workspace_revision: Option<u64>,
    /// Effective view.
    pub effective_view: AgentView,
    /// Effective capabilities.
    pub effective_capabilities: Vec<String>,
    /// Effective privacy projection (pinned canonical JSON).
    pub effective_privacy_projection_json: String,
    /// Outcome.
    pub outcome: ResponseOutcome,
    /// Durable task identity, when carried.
    pub task_id: Option<String>,
    /// Durable task state.
    pub task_state: Option<ResponseTaskState>,
    /// Registered error identity, when the outcome is an error.
    pub error_id: Option<String>,
    /// Response payload schema.
    pub payload_schema: String,
    /// Payload (pinned canonical JSON).
    pub payload_json: String,
    /// Payload digest.
    pub payload_digest: ContentDigest,
    /// Epistemic state of the answer.
    pub epistemic_state: KnowledgeState,
    /// Completeness of the answer.
    pub completeness: Completeness,
    /// Warnings.
    pub warnings: Vec<String>,
    /// Contradictions.
    pub contradictions: Vec<String>,
    /// Degradation notices.
    pub degradation: Vec<String>,
    /// Budget summary (pinned canonical JSON).
    pub budgets_json: String,
    /// Proof pointers.
    pub proof_pointers: Vec<String>,
    /// Recommended affordances.
    pub affordances: Vec<String>,
    /// Decision fingerprint.
    pub decision_fingerprint: ContentDigest,
    /// Compression receipt id, when compressed.
    pub compression_receipt_id: Option<String>,
    /// Validity horizon.
    pub valid_until_ns: Option<i128>,
    /// Continuation token, when the answer continues.
    pub continuation: Option<String>,
    /// Idempotency key, when bound to a durable task.
    pub idempotency_key: Option<String>,
    /// Registered recovery class spelling.
    pub recovery_class: String,
    /// Safe-retry guidance.
    pub safe_retry: ResponseSafeRetry,
    /// Whether a resnapshot is required before further decisions.
    pub resnapshot_required: bool,
    /// Execution boundary summary.
    pub execution_boundary: ExecutionBoundary,
    /// Creation time.
    pub created_at_ns: i128,
}

impl AgentResponseEnvelope {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_response_envelope.v1";

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn envelope_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }

    /// Validates envelope-level invariants (fail closed).
    ///
    /// Refuses a zero revision, an error outcome without a registered error
    /// identity, and out-of-bound handle lists.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.response_revision == 0 {
            return Err(ContractError::CountBoundExceeded);
        }
        if self.outcome == ResponseOutcome::Error && self.error_id.is_none() {
            return Err(ContractError::NotFound);
        }
        for list in [
            &self.effective_capabilities,
            &self.warnings,
            &self.contradictions,
            &self.degradation,
            &self.proof_pointers,
            &self.affordances,
        ] {
            if list.len() > 4096 {
                return Err(ContractError::CountBoundExceeded);
            }
            for entry in list {
                check_str_public(entry, 4096)?;
            }
        }
        Ok(())
    }
}

impl AgentResponseEnvelope {
    /// Validates and constructs a response envelope (fail closed).
    ///
    /// Enforcement: the operation resolves against the registered rows; the
    /// revision is at least 1; an `error` outcome carries a registered error
    /// identity; the payload is present; handle lists are bounded.
    #[allow(clippy::too_many_arguments)] // constructor mirrors the registered schema field list 1:1
    pub fn new(
        contract_basis: ContractBasis,
        operation_name: &str,
        request_id: impl Into<String>,
        response_revision: u64,
        principal_id: impl Into<String>,
        session_id: Option<String>,
        mission_id: Option<String>,
        trace_id: impl Into<String>,
        input_anchor: LedgerAnchor,
        output_anchor: Option<LedgerAnchor>,
        workspace_revision: Option<u64>,
        effective_view: AgentView,
        effective_capabilities: Vec<String>,
        effective_privacy_projection_json: impl Into<String>,
        outcome: ResponseOutcome,
        task_id: Option<String>,
        task_state: Option<crate::agent_response::ResponseTaskState>,
        error_id: Option<String>,
        payload_schema: impl Into<String>,
        payload_json: impl Into<String>,
        payload_digest: ContentDigest,
        epistemic_state: KnowledgeState,
        completeness: Completeness,
        warnings: Vec<String>,
        contradictions: Vec<String>,
        degradation: Vec<String>,
        budgets_json: impl Into<String>,
        proof_pointers: Vec<String>,
        affordances: Vec<String>,
        decision_fingerprint: ContentDigest,
        compression_receipt_id: Option<String>,
        valid_until_ns: Option<i128>,
        continuation: Option<String>,
        idempotency_key: Option<String>,
        recovery_class: impl Into<String>,
        safe_retry: ResponseSafeRetry,
        resnapshot_required: bool,
        execution_boundary: ExecutionBoundary,
        created_at_ns: i128,
    ) -> Result<Self, ContractBasisError> {
        let operation = AgentOperation::from_id(operation_name)
            .or_else(|_| AgentOperation::from_name(operation_name))
            .map_err(ContractBasisError::Contract)?;
        registered_operation(&contract_basis, operation.name())?;
        if response_revision == 0 {
            return Err(ContractBasisError::Contract(
                ContractError::CountBoundExceeded,
            ));
        }
        if outcome == ResponseOutcome::Error && error_id.is_none() {
            return Err(ContractBasisError::Contract(ContractError::NotFound));
        }
        let request_id = request_id.into();
        check_str_public(&request_id, 256).map_err(ContractBasisError::Contract)?;
        let principal_id = principal_id.into();
        check_str_public(&principal_id, 256).map_err(ContractBasisError::Contract)?;
        let trace_id = trace_id.into();
        check_str_public(&trace_id, 256).map_err(ContractBasisError::Contract)?;
        let payload_schema = payload_schema.into();
        check_str_public(&payload_schema, 256).map_err(ContractBasisError::Contract)?;
        let payload_json = payload_json.into();
        if payload_json.is_empty() {
            return Err(ContractBasisError::Contract(
                ContractError::EvidenceRequired,
            ));
        }
        for list in [
            &effective_capabilities,
            &warnings,
            &contradictions,
            &degradation,
            &proof_pointers,
            &affordances,
        ] {
            if list.len() > 4096 {
                return Err(ContractBasisError::Contract(
                    ContractError::CountBoundExceeded,
                ));
            }
            for entry in list {
                check_str_public(entry, 4096).map_err(ContractBasisError::Contract)?;
            }
        }
        let recovery_class = recovery_class.into();
        check_str_public(&recovery_class, 64).map_err(ContractBasisError::Contract)?;
        let budgets_json = budgets_json.into();
        check_str_public(&budgets_json, 65_536).map_err(ContractBasisError::Contract)?;
        let effective_privacy_projection_json = effective_privacy_projection_json.into();
        check_str_public(&effective_privacy_projection_json, 65_536)
            .map_err(ContractBasisError::Contract)?;
        Ok(Self {
            contract_basis,
            operation,
            request_id,
            response_revision,
            principal_id,
            session_id,
            mission_id,
            trace_id,
            input_anchor,
            output_anchor,
            workspace_revision,
            effective_view,
            effective_capabilities,
            effective_privacy_projection_json,
            outcome,
            task_id,
            task_state,
            error_id,
            payload_schema,
            payload_json,
            payload_digest,
            epistemic_state,
            completeness,
            warnings,
            contradictions,
            degradation,
            budgets_json,
            proof_pointers,
            affordances,
            decision_fingerprint,
            compression_receipt_id,
            valid_until_ns,
            continuation,
            idempotency_key,
            recovery_class,
            safe_retry,
            resnapshot_required,
            execution_boundary,
            created_at_ns,
        })
    }
}

fn check_str_public(value: &str, max_len: usize) -> Result<(), ContractError> {
    if value.is_empty() || value.len() > max_len {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

impl CanonicalEncode for AgentResponseEnvelope {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.contract_basis.encode_canonical(encoder);
        encoder.text(self.operation.id());
        encoder.text(&self.request_id);
        encoder.u64(self.response_revision);
        encoder.text(&self.principal_id);
        match &self.session_id {
            Some(value) => {
                encoder.bool(true);
                encoder.text(value);
            }
            None => encoder.bool(false),
        }
        match &self.mission_id {
            Some(value) => {
                encoder.bool(true);
                encoder.text(value);
            }
            None => encoder.bool(false),
        }
        encoder.text(&self.trace_id);
        self.input_anchor.encode_canonical(encoder);
        match &self.output_anchor {
            Some(anchor) => {
                encoder.bool(true);
                anchor.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        match self.workspace_revision {
            Some(revision) => {
                encoder.bool(true);
                encoder.u64(revision);
            }
            None => encoder.bool(false),
        }
        encoder.text(self.effective_view.id());
        encoder.u32(self.effective_capabilities.len() as u32);
        for capability in &self.effective_capabilities {
            encoder.text(capability);
        }
        encoder.text(&self.effective_privacy_projection_json);
        encoder.text(self.outcome.as_str());
        match &self.task_id {
            Some(task) => {
                encoder.bool(true);
                encoder.text(task);
            }
            None => encoder.bool(false),
        }
        match self.task_state {
            Some(state) => {
                encoder.bool(true);
                encoder.text(state.as_str());
            }
            None => encoder.bool(false),
        }
        match &self.error_id {
            Some(error) => {
                encoder.bool(true);
                encoder.text(error);
            }
            None => encoder.bool(false),
        }
        encoder.text(&self.payload_schema);
        encoder.text(&self.payload_json);
        encoder.digest(self.payload_digest);
        self.epistemic_state.encode_canonical(encoder);
        self.completeness.encode_canonical(encoder);
        for group in [&self.warnings, &self.contradictions, &self.degradation] {
            encoder.u32(group.len() as u32);
            for entry in group {
                encoder.text(entry);
            }
        }
        encoder.text(&self.budgets_json);
        encoder.u32(self.proof_pointers.len() as u32);
        for pointer in &self.proof_pointers {
            encoder.text(pointer);
        }
        encoder.u32(self.affordances.len() as u32);
        for affordance in &self.affordances {
            encoder.text(affordance);
        }
        encoder.digest(self.decision_fingerprint);
        match &self.compression_receipt_id {
            Some(receipt) => {
                encoder.bool(true);
                encoder.text(receipt);
            }
            None => encoder.bool(false),
        }
        match self.valid_until_ns {
            Some(at) => {
                encoder.bool(true);
                encoder.i128(at);
            }
            None => encoder.bool(false),
        }
        match &self.continuation {
            Some(token) => {
                encoder.bool(true);
                encoder.text(token);
            }
            None => encoder.bool(false),
        }
        match &self.idempotency_key {
            Some(key) => {
                encoder.bool(true);
                encoder.text(key);
            }
            None => encoder.bool(false),
        }
        encoder.text(&self.recovery_class);
        encoder.text(self.safe_retry.as_str());
        encoder.bool(self.resnapshot_required);
        encoder.u32(self.execution_boundary.completed.len() as u32);
        for entry in &self.execution_boundary.completed {
            encoder.text(entry);
        }
        encoder.u32(self.execution_boundary.not_started.len() as u32);
        for entry in &self.execution_boundary.not_started {
            encoder.text(entry);
        }
        encoder.u32(self.execution_boundary.possibly_occurred.len() as u32);
        for entry in &self.execution_boundary.possibly_occurred {
            encoder.text(entry);
        }
        encoder.u32(self.execution_boundary.preserved_truth.len() as u32);
        for entry in &self.execution_boundary.preserved_truth {
            encoder.text(entry);
        }
        encoder.u32(self.execution_boundary.invalidated.len() as u32);
        for entry in &self.execution_boundary.invalidated {
            encoder.text(entry);
        }
        encoder.i128(self.created_at_ns);
    }
}
