#![forbid(unsafe_code)]
//! The `fss/1` agent request envelope (AOP transport-free semantic boundary).
//!
//! Normative sources:
//! - `schemas/agent_request_envelope.v1.json`
//!   (`SCHEMA-AGENT-REQUEST-001`): the interchange schema.
//! - `architecture/agent_operations.json` via
//!   [`crate::agent_operation`]: the request is resolved against the
//!   registered operation rows at construction and fails closed.
//!
//! The envelope binds the exact contract basis, the resolved registered
//! operation, identities, anchor preconditions, one registered view, stable
//! targets, the typed payload schema (which must equal the operation row's
//! registered request payload schema), the budget, the privacy projection,
//! idempotency, continuation, taint, and hydration bounds. The typed payload
//! itself travels as its canonical JSON text and is pinned byte-exactly by
//! the request digest; enforcement of the payload against
//! `payload_schema` belongs to the boundary that owns that schema.
//!
//! Effect authority stays out: an effectful operation request is refused
//! unless it carries an idempotency key, and nothing here starts an effect.

use crate::agent::ContractBasis;
use crate::agent_operation::AgentOperation;
use crate::contract_basis::registered_operation;
use crate::agent_view::AgentView;
use crate::canonical::{CanonicalEncode, CanonicalEncoder};
use crate::contract::ContractError;
use crate::contract_basis::ContractBasisError;
use crate::digest::ContentDigest;
use crate::evidence::LedgerAnchor;
use crate::ids::validate_id;
use crate::{BudgetVector, HydrationLevel, MissionId, PrincipalId, SessionId, TimestampNs};

/// Requested privacy projection of one agent request.
#[derive(Clone, Debug, PartialEq)]
pub struct PrivacyProjection {
    /// Why the data is processed (decision purpose).
    pub purpose: String,
    /// Exact policy generation governing the projection.
    pub policy_generation_id: String,
    /// Domains the request may read.
    pub allowed_domains: Vec<String>,
    /// Domains redacted from the request.
    pub redacted_domains: Vec<String>,
}

/// Taint declaration of one agent request.
#[derive(Clone, Debug, PartialEq)]
pub struct RequestTaint {
    /// Whether the request carries untrusted control text.
    pub contains_untrusted_control_text: bool,
    /// Secret-free references to the taint sources.
    pub sources: Vec<String>,
}

/// Validated parameters for one agent request envelope.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentRequestEnvelopeParams {
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Canonical operation name (`session.open`, ...); resolved against the
    /// registered rows and refused if unknown.
    pub operation_name: String,
    /// Stable request identity.
    pub request_id: String,
    /// Requesting principal.
    pub principal_id: PrincipalId,
    /// Owning agent session.
    pub session_id: SessionId,
    /// Mission the request serves.
    pub mission_id: MissionId,
    /// Anchor precondition, when the request is anchor-pinned.
    pub input_anchor: Option<LedgerAnchor>,
    /// Workspace revision precondition, when pinned.
    pub expected_workspace_revision: Option<u64>,
    /// Registered view identity (`AVIEW-###`).
    pub view_id: String,
    /// Stable semantic target URIs (`fss://...`).
    pub target_uris: Vec<String>,
    /// Must equal the operation row's registered request payload schema.
    pub payload_schema: String,
    /// Canonical JSON text of the typed payload.
    pub payload_json: String,
    /// Bound cost of the request.
    pub budget: BudgetVector,
    /// Optional absolute deadline.
    pub deadline_ns: Option<i128>,
    /// Requested privacy projection (purpose, policy generation, domains).
    pub privacy: PrivacyProjection,
    /// Required for effectful operations.
    pub idempotency_key: Option<String>,
    /// Continuation token, when resuming.
    pub continuation: Option<String>,
    /// Decision fingerprint precondition, when pinned.
    pub expected_decision_fingerprint: Option<ContentDigest>,
    /// Maximum hydration ladder level the response may use.
    pub max_hydration_level: HydrationLevel,
    /// Whether bounded compression receipts are acceptable.
    pub accept_compression: bool,
    /// Taint declaration for untrusted inputs.
    pub taint: RequestTaint,
    /// Deterministic creation time.
    pub created_at: TimestampNs,
}

/// The validated `fss/1` agent request envelope (AOP transport-free).
#[derive(Clone, Debug, PartialEq)]
pub struct AgentRequestEnvelope {
    contract_basis: ContractBasis,
    operation: AgentOperation,
    request_id: String,
    principal_id: PrincipalId,
    session_id: SessionId,
    mission_id: MissionId,
    input_anchor: Option<LedgerAnchor>,
    expected_workspace_revision: Option<u64>,
    view: AgentView,
    target_uris: Vec<String>,
    payload_schema: String,
    payload_json: String,
    budget: BudgetVector,
    deadline_ns: Option<i128>,
    privacy: PrivacyProjection,
    idempotency_key: Option<String>,
    continuation: Option<String>,
    expected_decision_fingerprint: Option<ContentDigest>,
    max_hydration_level: HydrationLevel,
    accept_compression: bool,
    taint: RequestTaint,
    created_at: TimestampNs,
}

impl AgentRequestEnvelope {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_request_envelope.v1";

    /// Validates and constructs an envelope (fail closed).
    ///
    /// Enforcement at this boundary:
    /// - `operation_name` resolves against the basis through the registered
    ///   operation rows ([`ContractBasisError`]);
    /// - `view_id` must be a registered view ([`ContractError::InvalidIdentifier`]);
    /// - `payload_schema` must equal the operation row's registered request
    ///   payload schema ([`ContractError::InvalidIdentifier`]);
    /// - effectful operations require an idempotency key
    ///   ([`ContractError::InvalidEffectTransition`]);
    /// - targets are bounded (<= 256, each `fss://` and <= 2048 chars) and
    ///   taint sources <= 128, privacy domain lists <= 256
    ///   ([`ContractError::CountBoundExceeded`]);
    /// - a deadline at or before creation is refused
    ///   ([`ContractError::InvertedTimeInterval`]);
    /// - the payload must be present ([`ContractError::EvidenceRequired`]).
    pub fn new(params: AgentRequestEnvelopeParams) -> Result<Self, ContractBasisError> {
        let operation = registered_operation(&params.contract_basis, &params.operation_name)?;
        let view = AgentView::from_id(&params.view_id)
            .map_err(|_| ContractBasisError::Contract(ContractError::InvalidIdentifier))?;
        if params.payload_schema != operation.request_payload_schema() {
            return Err(ContractBasisError::Contract(ContractError::InvalidIdentifier));
        }
        validate_id(&params.request_id).map_err(|_| {
            ContractBasisError::Contract(ContractError::InvalidIdentifier)
        })?;
        if params.request_id.len() > 256 {
            return Err(ContractBasisError::Contract(
                ContractError::InvalidIdentifier,
            ));
        }
        if params.payload_json.is_empty() {
            return Err(ContractBasisError::Contract(ContractError::EvidenceRequired));
        }
        if params.target_uris.len() > 256
            || params.taint.sources.len() > 128
            || params.privacy.allowed_domains.len() > 256
            || params.privacy.redacted_domains.len() > 256
        {
            return Err(ContractBasisError::Contract(
                ContractError::CountBoundExceeded,
            ));
        }
        for target in &params.target_uris {
            if !target.starts_with("fss://") || target.len() > 2048 {
                return Err(ContractBasisError::Contract(
                    ContractError::InvalidIdentifier,
                ));
            }
        }
        if operation.effectful() && params.idempotency_key.is_none() {
            return Err(ContractBasisError::Contract(
                ContractError::InvalidEffectTransition,
            ));
        }
        if let Some(deadline) = params.deadline_ns
            && deadline <= params.created_at.0
        {
            return Err(ContractBasisError::Contract(
                ContractError::InvertedTimeInterval,
            ));
        }
        if params.privacy.purpose.is_empty() || params.privacy.policy_generation_id.is_empty() {
            return Err(ContractBasisError::Contract(ContractError::InvalidIdentifier));
        }
        Ok(Self {
            contract_basis: params.contract_basis,
            operation,
            request_id: params.request_id,
            principal_id: params.principal_id,
            session_id: params.session_id,
            mission_id: params.mission_id,
            input_anchor: params.input_anchor,
            expected_workspace_revision: params.expected_workspace_revision,
            view,
            target_uris: params.target_uris,
            payload_schema: params.payload_schema,
            payload_json: params.payload_json,
            budget: params.budget,
            deadline_ns: params.deadline_ns,
            privacy: params.privacy,
            idempotency_key: params.idempotency_key,
            continuation: params.continuation,
            expected_decision_fingerprint: params.expected_decision_fingerprint,
            max_hydration_level: params.max_hydration_level,
            accept_compression: params.accept_compression,
            taint: params.taint,
            created_at: params.created_at,
        })
    }

    /// Returns the resolved registered operation.
    #[must_use]
    pub const fn operation(&self) -> AgentOperation {
        self.operation
    }

    /// Returns the exact contract basis.
    #[must_use]
    pub const fn contract_basis(&self) -> &ContractBasis {
        &self.contract_basis
    }

    /// Returns the request identity.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the registered view.
    #[must_use]
    pub const fn view(&self) -> AgentView {
        self.view
    }

    /// Returns the payload schema (equals the operation row's registered
    /// request payload schema).
    #[must_use]
    pub fn payload_schema(&self) -> &str {
        &self.payload_schema
    }

    /// Returns the pinned canonical JSON payload text.
    #[must_use]
    pub fn payload_json(&self) -> &str {
        &self.payload_json
    }

    /// Returns the idempotency key, required for effectful operations.
    #[must_use]
    pub fn idempotency_key(&self) -> Option<&str> {
        self.idempotency_key.as_deref()
    }

    /// Returns the domain-separated canonical digest of the full envelope.
    #[must_use]
    pub fn request_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for AgentRequestEnvelope {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.contract_basis.encode_canonical(encoder);
        encoder.text(self.operation.id());
        encoder.text(&self.request_id);
        self.principal_id.encode_canonical(encoder);
        self.session_id.encode_canonical(encoder);
        self.mission_id.encode_canonical(encoder);
        match &self.input_anchor {
            Some(anchor) => {
                encoder.bool(true);
                anchor.encode_canonical(encoder);
            }
            None => encoder.bool(false),
        }
        match self.expected_workspace_revision {
            Some(revision) => {
                encoder.bool(true);
                encoder.u64(revision);
            }
            None => encoder.bool(false),
        }
        encoder.text(self.view.id());
        encoder.u32(self.target_uris.len() as u32);
        for target in &self.target_uris {
            encoder.text(target);
        }
        encoder.text(&self.payload_schema);
        encoder.text(&self.payload_json);
        self.budget.encode_canonical(encoder);
        match self.deadline_ns {
            Some(deadline) => {
                encoder.bool(true);
                encoder.i128(deadline);
            }
            None => encoder.bool(false),
        }
        encoder.text(&self.privacy.purpose);
        encoder.text(&self.privacy.policy_generation_id);
        encoder.u32(self.privacy.allowed_domains.len() as u32);
        for domain in &self.privacy.allowed_domains {
            encoder.text(domain);
        }
        encoder.u32(self.privacy.redacted_domains.len() as u32);
        for domain in &self.privacy.redacted_domains {
            encoder.text(domain);
        }
        match &self.idempotency_key {
            Some(key) => {
                encoder.bool(true);
                encoder.text(key);
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
        match self.expected_decision_fingerprint {
            Some(fingerprint) => {
                encoder.bool(true);
                encoder.digest(fingerprint);
            }
            None => encoder.bool(false),
        }
        self.max_hydration_level.encode_canonical(encoder);
        encoder.bool(self.accept_compression);
        encoder.bool(self.taint.contains_untrusted_control_text);
        encoder.u32(self.taint.sources.len() as u32);
        for source in &self.taint.sources {
            encoder.text(source);
        }
        self.created_at.encode_canonical(encoder);
    }
}
