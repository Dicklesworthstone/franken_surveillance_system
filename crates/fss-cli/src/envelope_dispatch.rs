#![forbid(unsafe_code)]
//! Universal `fss/1` `AgentRequestEnvelope` / `AgentResponseEnvelope` dispatch with
//! operation-registry-owned typed payload validation (`FSS-242`).
//!
//! Semantic plane: `"cognition"` (pure request/response contract admission,
//! `ContractBasis` negotiation, operation-registry-owned payload validation,
//! compilation into the single canonical [`FssCommand`] owner path, and
//! deterministic refusal rendering; this module never mints effect authority —
//! [`DispatchReceipt::grants_effect_authority`] is always `false`, and any
//! effectful operation still executes solely through its native owner with
//! explicit operator approvals).
//!
//! # Guarantees
//! - Accepts canonical `fss.agent_request_envelope.v1` JSON (`schemas/agent_request_envelope.v1.json`)
//!   with strict `additionalProperties: false` parsing via `fss_core::json_input::parse_mcp_reply`.
//! - Negotiates `contractBasis` via `fss_core::contract_basis::negotiate_basis_with_superseded`,
//!   failing closed with `ERR-AGENT-SESSION-STALE-001` on superseded/tombstoned generations and
//!   `ERR-AGENT-PROTOCOL-001` on protocol, ontology, nightly, or registry-digest incompatibility.
//! - Resolves `operationId` (`AOP-001`..`AOP-014`) against `fss_core::registered_operation` and
//!   [`crate::crosswalk::REGISTERED_OPERATION_CROSSWALK`], verifying that `payloadSchema` matches
//!   the operation row's registered `request_payload_schema()`.
//! - Enforces launcher-owned [`DispatchAuthority`] (`root`, `principal`, `granted_capabilities`):
//!   request envelopes can never override deployment root, impersonate another principal, escalate
//!   capabilities, or inject authority keys inside typed payloads (`ERR-AUTH-DENIED-001`).
//! - Enforces effectful request safety: `AOP-008 commit` and `AOP-010 cancel` require a non-null
//!   `idempotencyKey` (`ERR-IDEMPOTENCY-CONFLICT-001`) and refuse tainted control text
//!   (`taint.containsUntrustedControlText == true`, `ERR-AUTH-DENIED-001`).
//! - Enforces pinned `inputAnchor` freshness via `fss_core::contract_basis::refuse_stale_anchor`
//!   before executing mutations (`ERR-AGENT-SESSION-STALE-001`).
//! - Validates every emitted `fss.agent_response_envelope.v1` against the operation registry's
//!   response payload schema allowlist (`ERR-AGENT-TRANSPORT-DIVERGED-001` on drift).
//! - Renders every pre-execution refusal and cancellation as a schema-valid
//!   `fss.agent_response_envelope.v1` built through `fss_core::AgentResponseEnvelope::new` and
//!   [`crate::agent_json::response_envelope`].

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

use fss_core::contract_basis::{
    ContractBasisError, is_hydration_contract_basis, is_probe_contract_basis,
    negotiate_basis_with_superseded, reference_contract_basis, refuse_stale_anchor,
    registered_operation, superseded_registry_digests,
};
use fss_core::json_input::{Value, parse_mcp_reply};
use fss_core::{
    AgentOperation, AgentRequestEnvelope, AgentRequestEnvelopeParams, AgentResponseEnvelope,
    AgentView, BudgetVector, CanonicalEncode, CanonicalEncoder, Completeness, ContentDigest,
    ContractBasis, EventId, ExecutionBoundary, HydrationLevel, HypothesisDisposition,
    InvestigationLifecycle, KnowledgeState, LedgerAnchor, MissionId, PrincipalId,
    PrivacyProjection, RequestTaint, ResponseOutcome, ResponseSafeRetry, ResponseTaskState,
    SensorId, SessionId, TimestampNs, validate_id,
};
use fss_reference::agent_orient::{OrientLimits, read_deployment};
use fss_reference::agent_session::checkpoint::journal::coordination::investigations::InvestigationChange;
use fss_reference::agent_session::checkpoint::journal::coordination::investigations::evolution::InvestigationCitation;
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::alert_reconcile::MAX_RECONCILE_STATEMENT_BYTES;
use fss_reference::deployment_session::claims::{
    ClaimAction, ClaimChange, ClaimRecovery, ClaimRequest, ClaimWork, DEFAULT_LEASE_MS,
    MAX_CLAIM_DEPENDENCIES,
};
use fss_reference::deployment_session::feedback::MAX_FEEDBACK_EVIDENCE;
use fss_reference::deployment_session::findings::{
    FindingAction, FindingDraft, FindingRequest, MAX_FINDING_CLAIM_BYTES, MAX_FINDING_EVIDENCE,
    MAX_FINDING_LINKS,
};
use fss_reference::deployment_session::investigation::CaseAction;
use fss_reference::deployment_session::{
    MAX_MISSION_BYTES, MAX_NOTE_BYTES, MAX_OBJECTIVE_BYTES, MAX_SESSION_TOKEN_BUDGET,
    SESSION_JOURNAL_FILE, SESSIONS_RELPATH,
};

use crate::agent_json::{self, array, object, optional_string, string, strings};
use crate::claim_cmd::ClaimArgs;
use crate::crosswalk::lookup_by_operation_id;
use crate::diagnostic::escape_json_str;
use crate::effect_cmd::EffectCommand;
use crate::error::{ERR_CLI_READ_CANCELLED, ExitIdentity};
use crate::feedback_cmd::parse_feedback_args;
use crate::finding_cmd::FindingArgs;
use crate::fss_cmd::{FssCommand, execute_live_fss_with_control, parse_fss_args};
use crate::investigate_cmd::{InvestigateArgs, decode_case_draft, decode_expansion};
use crate::query_cmd::QueryArgs;
use crate::query_cmd::ops_targets::OpsDispatch;
use crate::query_cmd::ops_targets::cameras::{CAMERAS_PAYLOAD_SCHEMA, CamerasQueryRequest};
use crate::query_cmd::ops_targets::fusion::{
    FUSION_PAYLOAD_SCHEMA, FusionEvidenceInput, FusionQueryRequest,
};
use crate::query_cmd::ops_targets::graph::{
    GRAPH_PAYLOAD_SCHEMA, GraphAlgorithmKind, GraphProjectionKind, GraphQueryRequest,
};
use crate::query_cmd::ops_targets::holds_masks::{
    HOLDS_PAYLOAD_SCHEMA, HoldsQueryRequest, PRIVACY_MASKS_PAYLOAD_SCHEMA, PrivacyMasksQueryRequest,
};
use crate::query_cmd::ops_targets::{CAP_AGENT_QUERY, CAP_OBSERVE_STATUS, CAP_RETENTION_PREPARE};
use crate::redact::sanitize_and_truncate;
use crate::request_control::RequestControl;
use crate::token::ArgToken;

/// Default maximum UTF-8 byte length admitted for an inbound `AgentRequestEnvelope` JSON document.
pub const MAX_REQUEST_ENVELOPE_BYTES: usize = 256 * 1024;
/// Default maximum UTF-8 byte length admitted for an outbound `AgentResponseEnvelope` JSON document.
pub const MAX_RESPONSE_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;

/// Registered error identity: protocol, schema, contract-basis, or operation-registry violation.
pub const ERR_AGENT_PROTOCOL: &str = "ERR-AGENT-PROTOCOL-001";
/// Registered error identity: stale basis, superseded generation, or stale anchor precondition.
pub const ERR_AGENT_SESSION_STALE: &str = "ERR-AGENT-SESSION-STALE-001";
/// Registered error identity: principal mismatch, missing grant, authority override, or tainted effect.
pub const ERR_AUTH_DENIED: &str = "ERR-AUTH-DENIED-001";
/// Registered error identity: declared request/response byte or token budget exceeded.
pub const ERR_BUDGET_EXHAUSTED: &str = "ERR-BUDGET-EXHAUSTED-001";
/// Registered error identity: missing or conflicting idempotency key on an effectful operation.
pub const ERR_IDEMPOTENCY_CONFLICT: &str = "ERR-IDEMPOTENCY-CONFLICT-001";
/// Registered error identity: response envelope drifted from the operation registry allowlist.
pub const ERR_AGENT_TRANSPORT_DIVERGED: &str = "ERR-AGENT-TRANSPORT-DIVERGED-001";

const MAX_LEASE_MS: u64 = 300_000;
const MAX_WAIT_MS: u64 = 10_000;
const MAX_ORIENT_BUDGET_TOKENS: u64 = 4_096;
const MAX_PAGE_ENTRIES: u64 = 32;
const MAX_RESIDUALS: usize = 256;

// Non-wire internal hash domain tags (intentionally not registered `fss.*.v1` wire schemas).
const DISPATCH_REQUEST_HASH_TAG: &str = "envelope-dispatch-request-v1";
const DISPATCH_RECEIPT_HASH_TAG: &str = "envelope-dispatch-receipt-v1";
const DISPATCH_REFUSAL_HASH_TAG: &str = "envelope-dispatch-refusal-v1";

/// Keys that request payloads may NEVER supply because deployment scope and authority are
/// launcher-owned.
const FORBIDDEN_AUTHORITY_OVERRIDE_KEYS: &[&str] = &[
    "root",
    "deployment_root",
    "deploymentRoot",
    "principal",
    "principal_id",
    "principalId",
    "granted_capabilities",
    "grantedCapabilities",
    "capabilities",
];

/// Launcher-owned execution authority pinned outside any untrusted client request envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchAuthority {
    /// Fixed local deployment root directory owned by the launcher.
    pub root: PathBuf,
    /// Authenticated principal identity owned by the launcher.
    pub principal: PrincipalId,
    /// Complete set of capability identifiers granted to this dispatch session.
    pub granted_capabilities: BTreeSet<String>,
    /// Server's active baseline `ContractBasis` (defaults to `reference_contract_basis()`).
    pub server_basis: ContractBasis,
    /// Hard ceiling on inbound `AgentRequestEnvelope` JSON bytes.
    pub max_request_bytes: usize,
    /// Hard ceiling on outbound `AgentResponseEnvelope` JSON bytes.
    pub max_response_bytes: usize,
}

impl DispatchAuthority {
    /// Constructs a launcher authority carrying all 14 registered `AOP-001`..`AOP-014`
    /// capabilities plus read-only operational observation (`CAP-OBSERVE-STATUS-001`,
    /// `CAP-RETENTION-PREPARE-001`).
    #[must_use]
    pub fn owner_standard(root: PathBuf, principal: PrincipalId) -> Self {
        let mut granted_capabilities = BTreeSet::new();
        for op in AgentOperation::ALL_OPERATIONS {
            for cap in op.required_capabilities() {
                granted_capabilities.insert((*cap).to_owned());
            }
        }
        granted_capabilities.insert(CAP_AGENT_QUERY.to_owned());
        granted_capabilities.insert(CAP_OBSERVE_STATUS.to_owned());
        granted_capabilities.insert(CAP_RETENTION_PREPARE.to_owned());
        Self {
            root,
            principal,
            granted_capabilities,
            server_basis: reference_contract_basis(),
            max_request_bytes: MAX_REQUEST_ENVELOPE_BYTES,
            max_response_bytes: MAX_RESPONSE_ENVELOPE_BYTES,
        }
    }

    /// Constructs a launcher authority with an explicit, caller-bounded capability set.
    #[must_use]
    pub fn with_capabilities(
        root: PathBuf,
        principal: PrincipalId,
        granted_capabilities: BTreeSet<String>,
    ) -> Self {
        Self {
            root,
            principal,
            granted_capabilities,
            server_basis: reference_contract_basis(),
            max_request_bytes: MAX_REQUEST_ENVELOPE_BYTES,
            max_response_bytes: MAX_RESPONSE_ENVELOPE_BYTES,
        }
    }
}

/// Deterministic builder for schema-valid `fss.agent_request_envelope.v1` JSON documents
/// (`schemas/agent_request_envelope.v1.json`).
#[derive(Clone, Debug, PartialEq)]
pub struct RequestEnvelopeSpec {
    /// Exact semantic contract basis (`fss.agent_contract_basis.v1`).
    pub contract_basis: ContractBasis,
    /// Registered `fss/1` operation (`AOP-001`..`AOP-014`).
    pub operation: AgentOperation,
    /// Stable request identifier.
    pub request_id: String,
    /// Authenticated principal identifier.
    pub principal_id: PrincipalId,
    /// Optional session identifier (when session-bound).
    pub session_id: Option<SessionId>,
    /// Optional mission identifier (when mission-bound).
    pub mission_id: Option<MissionId>,
    /// Optional anchor precondition (`fss.evidence_anchor.v1`).
    pub input_anchor: Option<LedgerAnchor>,
    /// Optional expected workspace revision.
    pub expected_workspace_revision: Option<u64>,
    /// Registered view (`AVIEW-001`..`AVIEW-008`).
    pub view: AgentView,
    /// Stable semantic target URIs (`fss://...`).
    pub target_uris: Vec<String>,
    /// Request payload schema (defaults to `operation.request_payload_schema()`).
    pub payload_schema: String,
    /// Canonical JSON object of the operation's typed payload.
    pub payload_json: String,
    /// Declared 11-dimension budget vector.
    pub budget: BudgetVector,
    /// Optional absolute deadline in nanoseconds (strictly `> created_at_ns` when present).
    pub deadline_ns: Option<i128>,
    /// Requested capabilities (`CAP-*`).
    pub requested_capabilities: Vec<String>,
    /// Requested privacy projection.
    pub requested_privacy_projection: PrivacyProjection,
    /// Optional idempotency key (required for effectful `AOP-008` and `AOP-010`).
    pub idempotency_key: Option<String>,
    /// Optional continuation token.
    pub continuation: Option<String>,
    /// Optional decision-fingerprint precondition.
    pub expected_decision_fingerprint: Option<ContentDigest>,
    /// Maximum hydration level (`H0`..`H4`).
    pub max_hydration_level: HydrationLevel,
    /// Whether bounded compression receipts are accepted.
    pub accept_compression: bool,
    /// Request taint metadata.
    pub taint: RequestTaint,
    /// Deterministic creation timestamp in nanoseconds.
    pub created_at_ns: i128,
}

impl RequestEnvelopeSpec {
    /// Builds a schema-valid request specification using `reference_contract_basis()`,
    /// the operation's registered `default_view()`, `request_payload_schema()`, and
    /// `required_capabilities()`.
    #[must_use]
    pub fn for_operation(
        operation: AgentOperation,
        request_id: impl Into<String>,
        principal_id: PrincipalId,
        payload_json: impl Into<String>,
    ) -> Self {
        let view = AgentView::from_id(operation.default_view()).unwrap_or(AgentView::Brief);
        let requested_capabilities = operation
            .required_capabilities()
            .iter()
            .map(|cap| (*cap).to_owned())
            .collect();
        Self {
            contract_basis: reference_contract_basis(),
            operation,
            request_id: request_id.into(),
            principal_id,
            session_id: None,
            mission_id: None,
            input_anchor: None,
            expected_workspace_revision: None,
            view,
            target_uris: Vec::new(),
            payload_schema: operation.request_payload_schema().to_owned(),
            payload_json: payload_json.into(),
            budget: BudgetVector::ZERO,
            deadline_ns: None,
            requested_capabilities,
            requested_privacy_projection: PrivacyProjection {
                purpose: "fss/1 universal envelope dispatch".to_owned(),
                policy_generation_id: "privacy-epoch:0".to_owned(),
                allowed_domains: vec!["metadata".to_owned()],
                redacted_domains: vec!["media-payloads".to_owned()],
            },
            idempotency_key: operation
                .effectful()
                .then(|| format!("idem:{}:default", operation.name())),
            continuation: None,
            expected_decision_fingerprint: None,
            max_hydration_level: HydrationLevel::H1,
            accept_compression: true,
            taint: RequestTaint {
                contains_untrusted_control_text: false,
                sources: Vec::new(),
            },
            created_at_ns: 1_700_000_000_000_000_000,
        }
    }

    /// Renders this specification as canonical `fss.agent_request_envelope.v1` JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        let input_anchor = self
            .input_anchor
            .as_ref()
            .map_or_else(|| "null".to_owned(), agent_json::evidence_anchor);
        let expected_workspace_revision = self
            .expected_workspace_revision
            .map_or_else(|| "null".to_owned(), |r| r.to_string());
        let deadline_ns = self
            .deadline_ns
            .map_or_else(|| "null".to_owned(), |d| d.to_string());
        let expected_decision_fingerprint = self
            .expected_decision_fingerprint
            .map(|d| d.to_text())
            .map(|s| string(&s))
            .unwrap_or_else(|| "null".to_owned());
        let privacy = object(&[
            (
                "purpose",
                string(&self.requested_privacy_projection.purpose),
            ),
            (
                "policyGenerationId",
                string(&self.requested_privacy_projection.policy_generation_id),
            ),
            (
                "allowedDomains",
                strings(&self.requested_privacy_projection.allowed_domains),
            ),
            (
                "redactedDomains",
                strings(&self.requested_privacy_projection.redacted_domains),
            ),
        ]);
        let taint = object(&[
            (
                "containsUntrustedControlText",
                self.taint.contains_untrusted_control_text.to_string(),
            ),
            ("sources", strings(&self.taint.sources)),
        ]);

        object(&[
            ("schema", string(AgentRequestEnvelope::SCHEMA)),
            (
                "contractBasis",
                agent_json::contract_basis(&self.contract_basis),
            ),
            ("operationId", string(self.operation.id())),
            ("requestId", string(&self.request_id)),
            ("principalId", string(self.principal_id.as_str())),
            (
                "sessionId",
                optional_string(self.session_id.as_ref().map(SessionId::as_str)),
            ),
            (
                "missionId",
                optional_string(self.mission_id.as_ref().map(MissionId::as_str)),
            ),
            ("inputAnchor", input_anchor),
            ("expectedWorkspaceRevision", expected_workspace_revision),
            ("viewId", string(self.view.id())),
            ("targetUris", strings(&self.target_uris)),
            ("payloadSchema", string(&self.payload_schema)),
            ("payload", self.payload_json.clone()),
            ("budget", agent_json::budget(&self.budget)),
            ("deadlineNs", deadline_ns),
            (
                "requestedCapabilities",
                strings(&self.requested_capabilities),
            ),
            ("requestedPrivacyProjection", privacy),
            (
                "idempotencyKey",
                optional_string(self.idempotency_key.as_deref()),
            ),
            (
                "continuation",
                optional_string(self.continuation.as_deref()),
            ),
            ("expectedDecisionFingerprint", expected_decision_fingerprint),
            (
                "maxHydrationLevel",
                string(self.max_hydration_level.as_str()),
            ),
            ("acceptCompression", self.accept_compression.to_string()),
            ("taint", taint),
            ("createdAtNs", self.created_at_ns.to_string()),
        ])
    }
}

/// Deterministic cryptographic receipt of one universal envelope dispatch validation and run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchReceipt {
    /// Resolved operation ID (`AOP-001`..`AOP-014`) or `"unknown"` when refused pre-resolution.
    pub operation_id: String,
    /// Resolved canonical operation name (`session.open`, ...) or `"unknown"`.
    pub operation_name: String,
    /// Request identifier echoed from the inbound envelope (or `"request:malformed"`).
    pub request_id: String,
    /// Registered request payload schema declared by the request envelope.
    pub request_payload_schema: String,
    /// Top-level response schema (`fss.agent_response_envelope.v1` or `fss.doctor.v1`).
    pub response_schema: String,
    /// Inner response `payloadSchema` when present.
    pub response_payload_schema: Option<String>,
    /// Envelope outcome (`ok`, `refused`, `cancelled`, `partial`, `indeterminate`, ...).
    pub outcome: String,
    /// Registered `ERR-*` identity when refused or errored.
    pub error_id: Option<String>,
    /// Canonical basis digest under which the request was evaluated.
    pub contract_basis_digest: ContentDigest,
    /// Domain-separated canonical digest of the inbound request envelope.
    pub request_digest: ContentDigest,
    /// SHA-256 digest of the emitted UTF-8 response JSON bytes.
    pub response_digest: ContentDigest,
    /// Whether the inbound request declared untrusted control text.
    pub tainted: bool,
    /// Always `false`: dispatch validation never grants effect authority.
    pub grants_effect_authority: bool,
    /// Deterministic SHA-256 receipt digest over all fields above.
    pub receipt_digest: ContentDigest,
}

impl DispatchReceipt {
    /// Deterministic JSON rendering suitable for `CAPLOG` / retained proof artifacts.
    #[must_use]
    pub fn to_json(&self) -> String {
        object(&[
            ("receiptKind", string("fss.envelope_dispatch_receipt")),
            ("operationId", string(&self.operation_id)),
            ("operationName", string(&self.operation_name)),
            ("requestId", string(&self.request_id)),
            ("requestPayloadSchema", string(&self.request_payload_schema)),
            ("responseSchema", string(&self.response_schema)),
            (
                "responsePayloadSchema",
                optional_string(self.response_payload_schema.as_deref()),
            ),
            ("outcome", string(&self.outcome)),
            ("errorId", optional_string(self.error_id.as_deref())),
            (
                "contractBasisDigest",
                string(&self.contract_basis_digest.to_text()),
            ),
            ("requestDigest", string(&self.request_digest.to_text())),
            ("responseDigest", string(&self.response_digest.to_text())),
            ("tainted", self.tainted.to_string()),
            (
                "grantsEffectAuthority",
                self.grants_effect_authority.to_string(),
            ),
            ("receiptDigest", string(&self.receipt_digest.to_text())),
        ])
    }
}

/// Complete result of dispatching one universal `AgentRequestEnvelope`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchOutcome {
    /// Canonical UTF-8 JSON response (`fss.agent_response_envelope.v1` or `fss.doctor.v1`).
    pub response_json: String,
    /// Stable CLI/control-plane exit identity (`SUCCESS`, `AGENT_REFUSED`, etc.).
    pub exit_identity: ExitIdentity,
    /// Deterministic cryptographic dispatch receipt (`grants_effect_authority == false`).
    pub receipt: DispatchReceipt,
}

#[derive(Clone, Debug)]
struct RefusalSpec {
    operation: AgentOperation,
    request_id: String,
    session_id: Option<String>,
    mission_id: Option<String>,
    view: AgentView,
    error_id: &'static str,
    outcome: ResponseOutcome,
    completeness: Completeness,
    recovery_class: &'static str,
    safe_retry: ResponseSafeRetry,
    resnapshot_required: bool,
    detail: String,
    remediation: String,
    request_payload_schema: String,
    request_digest: ContentDigest,
    tainted: bool,
}

/// Parsed and registry-validated `AgentRequestEnvelope` ready to compile into [`FssCommand`].
#[derive(Clone, Debug)]
struct ValidatedRequest {
    effective_basis: ContractBasis,
    operation: AgentOperation,
    request_id: String,
    session_id: Option<SessionId>,
    mission_id: Option<MissionId>,
    input_anchor: Option<LedgerAnchor>,
    expected_workspace_revision: Option<u64>,
    expected_decision_fingerprint: Option<ContentDigest>,
    view: AgentView,
    payload_schema: String,
    payload_obj: BTreeMap<String, Value>,
    budget: BudgetVector,
    continuation: Option<String>,
    taint: RequestTaint,
    request_digest: ContentDigest,
}

/// Dispatches one canonical `fss.agent_request_envelope.v1` JSON document against `authority`
/// without cancellation.
#[must_use]
pub fn dispatch_envelope_json(
    authority: &DispatchAuthority,
    raw_request_json: &str,
) -> DispatchOutcome {
    dispatch_envelope_json_with_control(authority, raw_request_json, &RequestControl::uncancelled())
}

/// Bridges a verified read-only [`fss_reference::nl_query_compiler::CompilationResult`] (`DOC-033`)
/// into the universal `AgentRequestEnvelope` dispatch path under explicit cancellation.
///
/// Guarantees:
/// - **NEVER** executes `ClarificationRequired` (`ERR-AGENT-AMBIGUOUS-001`),
///   `PreparedDraftOnly` (`ERR-AUTH-DENIED-001` — prose cannot cross an effect boundary),
///   `Blocked` (`ERR-AUTH-DENIED-001`), or `Refused` results; fails closed with a schema-valid
///   `AgentResponseEnvelope` refusal preserving the exact registered error identity and taint flag.
/// - Only `CompilationDisposition::Selected` non-effectful read/compute plans compile into a
///   typed `AgentRequestEnvelope` and execute through the single canonical owner path.
#[must_use]
pub fn dispatch_compiled_nl_query_with_control(
    authority: &DispatchAuthority,
    request_id: &str,
    compiled: &fss_reference::nl_query_compiler::CompilationResult,
    control: &RequestControl<'_>,
) -> DispatchOutcome {
    use fss_reference::nl_query_compiler::{CompilationDisposition, ERR_AGENT_AMBIGUOUS};

    let raw_digest = compiled.original_text_digest;
    let tainted = compiled.taint.contains_untrusted_control_text;

    if compiled.disposition != CompilationDisposition::Selected {
        let (error_id, recovery_class, safe_retry, detail) = match compiled.disposition {
            CompilationDisposition::ClarificationRequired => (
                compiled.error_id.unwrap_or(ERR_AGENT_AMBIGUOUS),
                "operator_action_required",
                ResponseSafeRetry::No,
                compiled.clarifications.first().cloned().unwrap_or_else(|| {
                    "Natural-language request is materially ambiguous.".to_owned()
                }),
            ),
            CompilationDisposition::PreparedDraftOnly => (
                ERR_AUTH_DENIED,
                "operator_action_required",
                ResponseSafeRetry::No,
                format!(
                    "Effectful natural-language prose was downgraded to witnessed draft `{}`; prose cannot cross an effect boundary without explicit operator approval.",
                    compiled
                        .prepared_intent_draft_id
                        .as_deref()
                        .unwrap_or("intent-draft:none")
                ),
            ),
            CompilationDisposition::Blocked => (
                compiled.error_id.unwrap_or(ERR_AUTH_DENIED),
                "operator_action_required",
                ResponseSafeRetry::No,
                compiled.warnings.first().cloned().unwrap_or_else(|| {
                    "Missing required capabilities for compiled query plan.".to_owned()
                }),
            ),
            CompilationDisposition::Refused => (
                compiled.error_id.unwrap_or(ERR_AGENT_PROTOCOL),
                if compiled.error_id == Some(ERR_AGENT_SESSION_STALE) {
                    "rebase_required"
                } else {
                    "never_unchanged"
                },
                if compiled.error_id == Some(ERR_AGENT_SESSION_STALE) {
                    ResponseSafeRetry::YesAfterRefresh
                } else {
                    ResponseSafeRetry::No
                },
                compiled
                    .warnings
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Natural-language compilation refused.".to_owned()),
            ),
            CompilationDisposition::Selected => unreachable!(),
        };
        let op = compiled
            .query_plan
            .as_ref()
            .map_or(AgentOperation::Query, |p| p.operation());
        return build_refusal_outcome(
            authority,
            RefusalSpec {
                operation: op,
                request_id: request_id.to_owned(),
                session_id: compiled
                    .query_plan
                    .as_ref()
                    .map(|p| p.session_id().as_str().to_owned()),
                mission_id: compiled
                    .query_plan
                    .as_ref()
                    .map(|p| p.mission_id().as_str().to_owned()),
                view: compiled.output_view,
                error_id,
                outcome: ResponseOutcome::Refused,
                completeness: compiled.completeness,
                recovery_class,
                safe_retry,
                resnapshot_required: error_id == ERR_AGENT_SESSION_STALE,
                detail,
                remediation: compiled.remediation.clone(),
                request_payload_schema: op.request_payload_schema().to_owned(),
                request_digest: raw_digest,
                tainted,
            },
        );
    }

    let Some(selected) = compiled.selected_compiled() else {
        return build_refusal_outcome(
            authority,
            RefusalSpec {
                operation: AgentOperation::Query,
                request_id: request_id.to_owned(),
                session_id: None,
                mission_id: None,
                view: compiled.output_view,
                error_id: ERR_AGENT_PROTOCOL,
                outcome: ResponseOutcome::Refused,
                completeness: Completeness::Unknown,
                recovery_class: "never_unchanged",
                safe_retry: ResponseSafeRetry::No,
                resnapshot_required: false,
                detail: "Compiled result lacked a selected interpretation.".to_owned(),
                remediation: "Recompile natural-language query.".to_owned(),
                request_payload_schema: AgentOperation::Query.request_payload_schema().to_owned(),
                request_digest: raw_digest,
                tainted,
            },
        );
    };

    // Defense in depth: compiled NL queries NEVER execute effectful operations.
    if selected.operation.effectful() || selected.effectful_intent_downgraded {
        return build_refusal_outcome(
            authority,
            RefusalSpec {
                operation: selected.operation,
                request_id: request_id.to_owned(),
                session_id: compiled
                    .query_plan
                    .as_ref()
                    .map(|p| p.session_id().as_str().to_owned()),
                mission_id: compiled
                    .query_plan
                    .as_ref()
                    .map(|p| p.mission_id().as_str().to_owned()),
                view: selected.output_view,
                error_id: ERR_AUTH_DENIED,
                outcome: ResponseOutcome::Refused,
                completeness: Completeness::Unauthorized,
                recovery_class: "operator_action_required",
                safe_retry: ResponseSafeRetry::No,
                resnapshot_required: false,
                detail: "Natural-language query plans may never cross an effect boundary."
                    .to_owned(),
                remediation: "Submit an explicit operator-approved AOP-007 plan -> AOP-008 commit."
                    .to_owned(),
                request_payload_schema: selected.operation.request_payload_schema().to_owned(),
                request_digest: raw_digest,
                tainted: true,
            },
        );
    }

    let payload_json = match selected.operation {
        AgentOperation::Doctor => "{}".to_owned(),
        AgentOperation::SessionOrient => {
            let view_name = match selected.output_view {
                AgentView::Pulse => "pulse",
                AgentView::EpistemicMap => "epistemic_map",
                _ => "brief",
            };
            object(&[("view", string(view_name))])
        }
        AgentOperation::Query => {
            let target = selected.query_target.as_deref().unwrap_or("events");
            let mut fields = vec![("target", string(target))];
            if target == "cameras"
                && let Some(cam) = selected.target_ids.first()
            {
                fields.push(("camera_id", string(cam)));
            } else if target == "events"
                && let Some(tid) = selected.target_ids.first()
            {
                if tid.starts_with("zone:") {
                    fields.push(("zone", string(tid)));
                } else if tid.starts_with("sensor:") {
                    fields.push(("sensor", string(tid)));
                }
            }
            object(&fields)
        }
        AgentOperation::Explain => {
            let q = selected.explain_question.as_deref().unwrap_or("why");
            let mut fields = vec![("question", string(q))];
            if let Some(ev) = selected.target_ids.first() {
                fields.push(("event_id", string(ev)));
            }
            object(&fields)
        }
        _ => {
            return build_refusal_outcome(
                authority,
                RefusalSpec {
                    operation: selected.operation,
                    request_id: request_id.to_owned(),
                    session_id: compiled
                        .query_plan
                        .as_ref()
                        .map(|p| p.session_id().as_str().to_owned()),
                    mission_id: compiled
                        .query_plan
                        .as_ref()
                        .map(|p| p.mission_id().as_str().to_owned()),
                    view: selected.output_view,
                    error_id: ERR_AGENT_PROTOCOL,
                    outcome: ResponseOutcome::Refused,
                    completeness: Completeness::Partial,
                    recovery_class: "operator_action_required",
                    safe_retry: ResponseSafeRetry::No,
                    resnapshot_required: false,
                    detail: format!(
                        "Compiled operation {} ({}) requires explicit cursor/operation parameters before live dispatch.",
                        selected.operation.id(),
                        selected.operation.name()
                    ),
                    remediation: "Supply explicit since-anchor or operation_id in the typed AgentRequestEnvelope.".to_owned(),
                    request_payload_schema: selected.operation.request_payload_schema().to_owned(),
                    request_digest: raw_digest,
                    tainted,
                },
            );
        }
    };

    let mut spec = RequestEnvelopeSpec::for_operation(
        selected.operation,
        request_id,
        authority.principal.clone(),
        payload_json,
    );
    spec.contract_basis = compiled.effective_basis.clone();
    spec.view = selected.output_view;
    spec.target_uris = compiled
        .resolved_uris
        .iter()
        .map(|u| u.uri.clone())
        .collect();
    spec.requested_capabilities = compiled.capability_projection.clone();
    spec.taint = RequestTaint {
        contains_untrusted_control_text: tainted,
        sources: compiled.taint.taint_sources.clone(),
    };
    dispatch_envelope_json_with_control(authority, &spec.to_json(), control)
}

/// Dispatches one canonical `fss.agent_request_envelope.v1` JSON document against `authority`
/// under explicit cooperative cancellation (`control`).
///
/// Every failure path fails closed with a schema-valid `fss.agent_response_envelope.v1`
/// refusal carrying a registered `ERR-*` identity, remediation guidance, and a deterministic
/// [`DispatchReceipt`] whose `grants_effect_authority` is always `false`.
#[must_use]
pub fn dispatch_envelope_json_with_control(
    authority: &DispatchAuthority,
    raw_request_json: &str,
    control: &RequestControl<'_>,
) -> DispatchOutcome {
    let raw_digest = ContentDigest::sha256(raw_request_json.as_bytes());

    if control.is_cancelled() {
        return build_refusal_outcome(
            authority,
            RefusalSpec {
                operation: AgentOperation::Doctor,
                request_id: "request:cancelled".to_owned(),
                session_id: None,
                mission_id: None,
                view: AgentView::Brief,
                error_id: ERR_CLI_READ_CANCELLED,
                outcome: ResponseOutcome::Cancelled,
                completeness: Completeness::Partial,
                recovery_class: "operator_action_required",
                safe_retry: ResponseSafeRetry::No,
                resnapshot_required: false,
                detail: "Request owner cancelled dispatch before admission.".to_owned(),
                remediation: "Start a fresh request with an active request owner.".to_owned(),
                request_payload_schema: AgentOperation::Doctor.request_payload_schema().to_owned(),
                request_digest: raw_digest,
                tainted: false,
            },
        );
    }

    if raw_request_json.is_empty() || raw_request_json.len() > authority.max_request_bytes {
        return build_refusal_outcome(
            authority,
            RefusalSpec {
                operation: AgentOperation::Doctor,
                request_id: "request:oversized".to_owned(),
                session_id: None,
                mission_id: None,
                view: AgentView::Brief,
                error_id: ERR_BUDGET_EXHAUSTED,
                outcome: ResponseOutcome::Refused,
                completeness: Completeness::Partial,
                recovery_class: "never_unchanged",
                safe_retry: ResponseSafeRetry::No,
                resnapshot_required: false,
                detail: format!(
                    "Inbound AgentRequestEnvelope size {} violates 1..={} byte bound.",
                    raw_request_json.len(),
                    authority.max_request_bytes
                ),
                remediation: "Reduce request payload size within max_request_bytes.".to_owned(),
                request_payload_schema: AgentOperation::Doctor.request_payload_schema().to_owned(),
                request_digest: raw_digest,
                tainted: false,
            },
        );
    }

    let validated = match parse_and_validate_request(authority, raw_request_json, raw_digest) {
        Ok(req) => req,
        Err(refusal) => return build_refusal_outcome(authority, *refusal),
    };

    if control.is_cancelled() {
        return build_refusal_outcome(
            authority,
            RefusalSpec {
                operation: validated.operation,
                request_id: validated.request_id,
                session_id: validated.session_id.as_ref().map(|s| s.as_str().to_owned()),
                mission_id: validated.mission_id.as_ref().map(|m| m.as_str().to_owned()),
                view: validated.view,
                error_id: ERR_CLI_READ_CANCELLED,
                outcome: ResponseOutcome::Cancelled,
                completeness: Completeness::Partial,
                recovery_class: "operator_action_required",
                safe_retry: ResponseSafeRetry::No,
                resnapshot_required: false,
                detail: "Request owner cancelled dispatch after validation and before execution."
                    .to_owned(),
                remediation: "Start a fresh request with an active request owner.".to_owned(),
                request_payload_schema: validated.payload_schema,
                request_digest: validated.request_digest,
                tainted: validated.taint.contains_untrusted_control_text,
            },
        );
    }

    // Check pinned inputAnchor freshness against the live deployment head BEFORE executing.
    if let Some(ref pinned_anchor) = validated.input_anchor {
        match read_deployment(&authority.root, &OrientLimits::default()) {
            Ok(snapshot) => {
                if let Err(err) = refuse_stale_anchor(pinned_anchor, &snapshot.anchor) {
                    return build_refusal_outcome(
                        authority,
                        RefusalSpec {
                            operation: validated.operation,
                            request_id: validated.request_id,
                            session_id: validated
                                .session_id
                                .as_ref()
                                .map(|s| s.as_str().to_owned()),
                            mission_id: validated
                                .mission_id
                                .as_ref()
                                .map(|m| m.as_str().to_owned()),
                            view: validated.view,
                            error_id: ERR_AGENT_SESSION_STALE,
                            outcome: ResponseOutcome::Refused,
                            completeness: Completeness::Stale,
                            recovery_class: "rebase_required",
                            safe_retry: ResponseSafeRetry::YesAfterRefresh,
                            resnapshot_required: true,
                            detail: sanitize_and_truncate(&err.to_string(), 320),
                            remediation: "Orient on the current deployment head and rebuild the request against the fresh anchor.".to_owned(),
                            request_payload_schema: validated.payload_schema,
                            request_digest: validated.request_digest,
                            tainted: validated.taint.contains_untrusted_control_text,
                        },
                    );
                }
            }
            Err(err) => {
                return build_refusal_outcome(
                    authority,
                    RefusalSpec {
                        operation: validated.operation,
                        request_id: validated.request_id,
                        session_id: validated.session_id.as_ref().map(|s| s.as_str().to_owned()),
                        mission_id: validated.mission_id.as_ref().map(|m| m.as_str().to_owned()),
                        view: validated.view,
                        error_id: ERR_AGENT_SESSION_STALE,
                        outcome: ResponseOutcome::Refused,
                        completeness: Completeness::Unknown,
                        recovery_class: "refresh_and_retry",
                        safe_retry: ResponseSafeRetry::YesAfterRefresh,
                        resnapshot_required: true,
                        detail: format!(
                            "Could not verify pinned inputAnchor against deployment head: {}",
                            sanitize_and_truncate(&err.to_string(), 240)
                        ),
                        remediation:
                            "Inspect deployment health with AOP-014 doctor before retrying."
                                .to_owned(),
                        request_payload_schema: validated.payload_schema,
                        request_digest: validated.request_digest,
                        tainted: validated.taint.contains_untrusted_control_text,
                    },
                );
            }
        }
    }

    // Enforce expectedWorkspaceRevision and pre-mutation expectedDecisionFingerprint preconditions
    // BEFORE executing any command so stale callers never mutate deployment/session state.
    if let Err(refusal) = verify_workspace_and_decision_preconditions(authority, &validated) {
        return build_refusal_outcome(authority, *refusal);
    }

    let command = match compile_operation_payload(authority, &validated) {
        Ok(cmd) => cmd,
        Err(refusal) => return build_refusal_outcome(authority, *refusal),
    };

    let Some((raw_response, exit_identity)) = execute_live_fss_with_control(command, control)
    else {
        return build_refusal_outcome(
            authority,
            RefusalSpec {
                operation: validated.operation,
                request_id: validated.request_id,
                session_id: validated.session_id.as_ref().map(|s| s.as_str().to_owned()),
                mission_id: validated.mission_id.as_ref().map(|m| m.as_str().to_owned()),
                view: validated.view,
                error_id: ERR_CLI_READ_CANCELLED,
                outcome: ResponseOutcome::Cancelled,
                completeness: Completeness::Partial,
                recovery_class: "operator_action_required",
                safe_retry: ResponseSafeRetry::No,
                resnapshot_required: false,
                detail: "Request owner cancelled execution before command start.".to_owned(),
                remediation: "Start a fresh request with an active request owner.".to_owned(),
                request_payload_schema: validated.payload_schema,
                request_digest: validated.request_digest,
                tainted: validated.taint.contains_untrusted_control_text,
            },
        );
    };

    // Enforce bounded non-truncating response size limits (authority ceiling + caller budget.bytes).
    let effective_byte_limit = if validated.budget.bytes > 0 {
        authority
            .max_response_bytes
            .min(usize::try_from(validated.budget.bytes).unwrap_or(usize::MAX))
    } else {
        authority.max_response_bytes
    };
    if raw_response.len() > effective_byte_limit {
        return build_refusal_outcome(
            authority,
            RefusalSpec {
                operation: validated.operation,
                request_id: validated.request_id,
                session_id: validated.session_id.as_ref().map(|s| s.as_str().to_owned()),
                mission_id: validated.mission_id.as_ref().map(|m| m.as_str().to_owned()),
                view: validated.view,
                error_id: ERR_BUDGET_EXHAUSTED,
                outcome: ResponseOutcome::Refused,
                completeness: Completeness::Partial,
                recovery_class: "refresh_and_retry",
                safe_retry: ResponseSafeRetry::YesAfterRefresh,
                resnapshot_required: false,
                detail: format!(
                    "Complete response ({} bytes) exceeds declared byte budget ({effective_byte_limit} bytes); nothing was truncated.",
                    raw_response.len()
                ),
                remediation: "Select a tighter view or smaller max_entries, or raise budget.bytes."
                    .to_owned(),
                request_payload_schema: validated.payload_schema,
                request_digest: validated.request_digest,
                tainted: validated.taint.contains_untrusted_control_text,
            },
        );
    }

    // Validate the emitted response envelope against the operation registry's response contract
    // (or the exact operational sub-target payload schema when explicitly selected under AOP-005).
    let expected_ops_schema =
        ops_subtarget_response_schema(validated.operation, &validated.payload_obj);
    match validate_response_envelope_for_target(
        &raw_response,
        validated.operation,
        &validated.effective_basis,
        &authority.principal,
        expected_ops_schema,
    ) {
        Ok(meta) => {
            // For read-only operations carrying expectedDecisionFingerprint, fail closed with
            // ERR-AGENT-SESSION-STALE-001 when the live decision fingerprint drifted.
            if let Some(expected_fp) = validated.expected_decision_fingerprint
                && is_readonly_operation(validated.operation)
                && meta.decision_fingerprint != Some(expected_fp)
            {
                return build_refusal_outcome(
                    authority,
                    RefusalSpec {
                        operation: validated.operation,
                        request_id: validated.request_id,
                        session_id: validated.session_id.as_ref().map(|s| s.as_str().to_owned()),
                        mission_id: validated.mission_id.as_ref().map(|m| m.as_str().to_owned()),
                        view: validated.view,
                        error_id: ERR_AGENT_SESSION_STALE,
                        outcome: ResponseOutcome::Refused,
                        completeness: Completeness::Stale,
                        recovery_class: "rebase_required",
                        safe_retry: ResponseSafeRetry::YesAfterRefresh,
                        resnapshot_required: true,
                        detail: format!(
                            "Observed decisionFingerprint ({}) drifted from expectedDecisionFingerprint ({}).",
                            meta.decision_fingerprint
                                .map_or_else(|| "none".to_owned(), |d| d.to_text()),
                            expected_fp.to_text()
                        ),
                        remediation: "Re-orient on the current deployment head and rebuild the request against the fresh decisionFingerprint.".to_owned(),
                        request_payload_schema: validated.payload_schema,
                        request_digest: validated.request_digest,
                        tainted: validated.taint.contains_untrusted_control_text,
                    },
                );
            }
            let response_digest = ContentDigest::sha256(raw_response.as_bytes());
            let receipt = build_dispatch_receipt(
                validated.operation.id(),
                validated.operation.name(),
                &validated.request_id,
                &validated.payload_schema,
                &meta.schema,
                meta.payload_schema,
                &meta.outcome,
                meta.error_id,
                validated.effective_basis.basis_digest(),
                validated.request_digest,
                response_digest,
                validated.taint.contains_untrusted_control_text,
            );
            DispatchOutcome {
                response_json: raw_response,
                exit_identity,
                receipt,
            }
        }
        Err(drift_detail) => build_refusal_outcome(
            authority,
            RefusalSpec {
                operation: validated.operation,
                request_id: validated.request_id,
                session_id: validated.session_id.as_ref().map(|s| s.as_str().to_owned()),
                mission_id: validated.mission_id.as_ref().map(|m| m.as_str().to_owned()),
                view: validated.view,
                error_id: ERR_AGENT_TRANSPORT_DIVERGED,
                outcome: ResponseOutcome::Refused,
                completeness: Completeness::Unknown,
                recovery_class: "operator_action_required",
                safe_retry: ResponseSafeRetry::No,
                resnapshot_required: false,
                detail: sanitize_and_truncate(&drift_detail, 320),
                remediation:
                    "Repair operation-registry response schema divergence and re-run qualification."
                        .to_owned(),
                request_payload_schema: validated.payload_schema,
                request_digest: validated.request_digest,
                tainted: validated.taint.contains_untrusted_control_text,
            },
        ),
    }
}

const fn is_readonly_operation(op: AgentOperation) -> bool {
    matches!(
        op,
        AgentOperation::SessionOrient
            | AgentOperation::SessionFollow
            | AgentOperation::Query
            | AgentOperation::Wait
            | AgentOperation::Explain
            | AgentOperation::Doctor
    )
}

fn verify_workspace_and_decision_preconditions(
    authority: &DispatchAuthority,
    validated: &ValidatedRequest,
) -> Result<(), Box<RefusalSpec>> {
    let need_rev = validated.expected_workspace_revision.is_some();
    let need_pre_fp = validated.expected_decision_fingerprint.is_some()
        && !is_readonly_operation(validated.operation);
    if !need_rev && !need_pre_fp {
        return Ok(());
    }

    let stale_err = |detail: String| {
        Box::new(RefusalSpec {
            operation: validated.operation,
            request_id: validated.request_id.clone(),
            session_id: validated.session_id.as_ref().map(|s| s.as_str().to_owned()),
            mission_id: validated.mission_id.as_ref().map(|m| m.as_str().to_owned()),
            view: validated.view,
            error_id: ERR_AGENT_SESSION_STALE,
            outcome: ResponseOutcome::Refused,
            completeness: Completeness::Stale,
            recovery_class: "rebase_required",
            safe_retry: ResponseSafeRetry::YesAfterRefresh,
            resnapshot_required: true,
            detail: sanitize_and_truncate(&detail, 320),
            remediation: "Re-orient on the current session workspace and rebuild the request against the fresh workspaceRevision and decisionFingerprint.".to_owned(),
            request_payload_schema: validated.payload_schema.clone(),
            request_digest: validated.request_digest,
            tainted: validated.taint.contains_untrusted_control_text,
        })
    };

    // Resolve effective session ID (rejecting conflicts between envelope.sessionId and payload.session).
    let payload_sess = match validated.payload_obj.get("session") {
        None => None,
        Some(v) => Some(
            bounded_text(Some(v), 128)
                .ok()
                .and_then(|s| SessionId::parse(s).ok())
                .ok_or_else(|| {
                    stale_err(
                        "Invalid session identifier while verifying workspace precondition."
                            .to_owned(),
                    )
                })?,
        ),
    };
    let effective_session = match (validated.session_id.as_ref(), payload_sess.as_ref()) {
        (Some(a), Some(b)) if a != b => {
            return Err(stale_err(
                "payload.session conflicts with envelope.sessionId during precondition check."
                    .to_owned(),
            ));
        }
        (Some(a), _) => a,
        (None, Some(b)) => b,
        (None, None) => {
            return Err(stale_err(
                "expectedWorkspaceRevision / pre-mutation expectedDecisionFingerprint requires an existing session-bound workspace.".to_owned(),
            ));
        }
    };

    let journal_path = authority
        .root
        .join(SESSIONS_RELPATH)
        .join(SESSION_JOURNAL_FILE);
    let bytes = fs::read(&journal_path).map_err(|_| {
        stale_err(
            "Session journal is absent or unreadable; workspace precondition cannot be verified."
                .to_owned(),
        )
    })?;
    let state = inspect_session_bytes(
        &bytes,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )
    .map_err(|_| {
        stale_err(
            "Session journal failed integrity check; workspace precondition refused.".to_owned(),
        )
    })?;
    let owned = state.sessions.iter().any(|entry| {
        entry.session.session_id == *effective_session
            && entry.session.principal_id == authority.principal
            && !entry.closed
    });
    if !owned {
        return Err(stale_err(
            "Target session is absent, closed, or not owned by the authenticated principal."
                .to_owned(),
        ));
    }

    let latest_ws = state
        .workspace_revisions
        .iter()
        .filter(|rev| rev.capsule().session_id == *effective_session)
        .max_by_key(|rev| rev.capsule().revision);

    if let Some(expected_rev) = validated.expected_workspace_revision {
        let observed_rev = latest_ws.map(|rev| rev.capsule().revision);
        if observed_rev != Some(expected_rev) {
            return Err(stale_err(format!(
                "Workspace revision mismatch: expected {expected_rev}, observed {}.",
                observed_rev.map_or_else(|| "none".to_owned(), |r| r.to_string())
            )));
        }
    }
    if need_pre_fp && let Some(expected_fp) = validated.expected_decision_fingerprint {
        let observed_fp = latest_ws.map(|rev| rev.capsule().decision_digest.as_str());
        if observed_fp != Some(expected_fp.to_text().as_str()) {
            return Err(stale_err(format!(
                "Pre-mutation decisionFingerprint mismatch: expected {}, observed {}.",
                expected_fp.to_text(),
                observed_fp.unwrap_or("none")
            )));
        }
    }
    Ok(())
}

/// Verified metadata extracted from a live response envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedResponseMeta {
    /// Top-level JSON `schema` (`fss.agent_response_envelope.v1` or `fss.doctor.v1`).
    pub schema: String,
    /// Inner `payloadSchema` when present.
    pub payload_schema: Option<String>,
    /// Envelope `outcome` (or doctor `verdict`).
    pub outcome: String,
    /// Envelope `errorId` when present.
    pub error_id: Option<String>,
    /// Envelope `decisionFingerprint` when present (`fss.agent_response_envelope.v1`).
    pub decision_fingerprint: Option<ContentDigest>,
}

fn ops_subtarget_response_schema(
    operation: AgentOperation,
    payload: &BTreeMap<String, Value>,
) -> Option<&'static str> {
    if operation != AgentOperation::Query {
        return None;
    }
    match payload.get("target").and_then(Value::text) {
        Some("cameras") => Some(CAMERAS_PAYLOAD_SCHEMA),
        Some("graph") => Some(GRAPH_PAYLOAD_SCHEMA),
        Some("fusion") => Some(FUSION_PAYLOAD_SCHEMA),
        Some("holds") => Some(HOLDS_PAYLOAD_SCHEMA),
        Some("privacy-masks") => Some(PRIVACY_MASKS_PAYLOAD_SCHEMA),
        _ => None,
    }
}

/// Validates an emitted raw JSON response against the operation-registry-owned contract for
/// `(operation, basis, expected_principal)`.
///
/// Refuses any response whose top-level schema, `operationId`, `principalId`,
/// `payloadSchema`, `payloadDigest`, `decisionFingerprint`, or `contractBasis` violates the
/// registered `fss/1` contract.
pub fn validate_response_envelope_against_registry(
    raw_response_json: &str,
    operation: AgentOperation,
    basis: &ContractBasis,
    expected_principal: &PrincipalId,
) -> Result<ValidatedResponseMeta, String> {
    validate_response_envelope_for_target(
        raw_response_json,
        operation,
        basis,
        expected_principal,
        None,
    )
}

fn validate_response_envelope_for_target(
    raw_response_json: &str,
    operation: AgentOperation,
    basis: &ContractBasis,
    expected_principal: &PrincipalId,
    expected_ops_subtarget_schema: Option<&'static str>,
) -> Result<ValidatedResponseMeta, String> {
    let parsed = parse_mcp_reply(raw_response_json.trim())
        .map_err(|err| format!("response JSON is malformed: {err}"))?;
    let root = parsed
        .object()
        .ok_or_else(|| "response JSON top-level value must be an object".to_owned())?;
    let schema = root
        .get("schema")
        .and_then(Value::text)
        .ok_or_else(|| "response JSON missing string field `schema`".to_owned())?;

    if schema == "fss.doctor.v1" {
        if operation != AgentOperation::Doctor {
            return Err(format!(
                "non-doctor operation {} emitted fss.doctor.v1",
                operation.id()
            ));
        }
        let verdict = root
            .get("verdict")
            .and_then(Value::text)
            .ok_or_else(|| "fss.doctor.v1 missing string field `verdict`".to_owned())?;
        return Ok(ValidatedResponseMeta {
            schema: schema.to_owned(),
            payload_schema: None,
            outcome: verdict.to_owned(),
            error_id: None,
            decision_fingerprint: None,
        });
    }

    if schema != AgentResponseEnvelope::SCHEMA {
        return Err(format!(
            "unexpected response schema `{schema}`; expected {}",
            AgentResponseEnvelope::SCHEMA
        ));
    }

    let op_id = root
        .get("operationId")
        .and_then(Value::text)
        .ok_or_else(|| "response envelope missing `operationId`".to_owned())?;
    if op_id != operation.id() {
        return Err(format!(
            "response operationId `{op_id}` != requested `{}`",
            operation.id()
        ));
    }

    let principal_id = root
        .get("principalId")
        .and_then(Value::text)
        .ok_or_else(|| "response envelope missing `principalId`".to_owned())?;
    if principal_id != expected_principal.as_str() {
        return Err(format!(
            "response principalId `{principal_id}` != authenticated `{}`",
            expected_principal.as_str()
        ));
    }

    if root.get("contractBasis").and_then(Value::object).is_none() {
        return Err("response envelope missing `contractBasis` object".to_owned());
    }

    let effective_view = root
        .get("effectiveViewId")
        .and_then(Value::text)
        .ok_or_else(|| "response envelope missing `effectiveViewId`".to_owned())?;
    if AgentView::from_id(effective_view).is_err() {
        return Err(format!(
            "response envelope has unregistered `effectiveViewId` `{effective_view}`"
        ));
    }

    let epistemic_state = root
        .get("epistemicState")
        .and_then(Value::text)
        .ok_or_else(|| "response envelope missing `epistemicState`".to_owned())?;
    if !matches!(
        epistemic_state,
        "known"
            | "estimated"
            | "unknown"
            | "conflicted"
            | "stale"
            | "not_observable"
            | "redacted"
            | "indeterminate"
            | "not_applicable"
    ) {
        return Err(format!(
            "response envelope has invalid `epistemicState` `{epistemic_state}`"
        ));
    }

    let completeness = root
        .get("completeness")
        .and_then(Value::text)
        .ok_or_else(|| "response envelope missing `completeness`".to_owned())?;
    if !matches!(
        completeness,
        "complete"
            | "bounded"
            | "partial"
            | "unknown"
            | "not_observable"
            | "unauthorized"
            | "stale"
    ) {
        return Err(format!(
            "response envelope has invalid `completeness` `{completeness}`"
        ));
    }

    let recovery_class = root
        .get("recoveryClass")
        .and_then(Value::text)
        .ok_or_else(|| "response envelope missing `recoveryClass`".to_owned())?;
    if !matches!(
        recovery_class,
        "never_unchanged"
            | "safe_read_retry"
            | "refresh_and_retry"
            | "rebase_required"
            | "backoff"
            | "reconciliation_required"
            | "operator_action_required"
            | "resume_from_continuation"
    ) {
        return Err(format!(
            "response envelope has invalid `recoveryClass` `{recovery_class}`"
        ));
    }

    let safe_retry = root
        .get("safeRetry")
        .and_then(Value::text)
        .ok_or_else(|| "response envelope missing `safeRetry`".to_owned())?;
    if !matches!(
        safe_retry,
        "yes_same_request" | "yes_after_refresh" | "yes_after_reconcile" | "no" | "not_applicable"
    ) {
        return Err(format!(
            "response envelope has invalid `safeRetry` `{safe_retry}`"
        ));
    }

    if root
        .get("resnapshotRequired")
        .and_then(Value::boolean)
        .is_none()
    {
        return Err("response envelope missing boolean `resnapshotRequired`".to_owned());
    }

    let boundary = root
        .get("executionBoundary")
        .and_then(Value::object)
        .ok_or_else(|| "response envelope missing `executionBoundary` object".to_owned())?;
    for bkey in [
        "completed",
        "notStarted",
        "possiblyOccurred",
        "preservedTruth",
        "invalidated",
    ] {
        if boundary.get(bkey).and_then(Value::array).is_none() {
            return Err(format!(
                "response envelope `executionBoundary.{bkey}` must be an array"
            ));
        }
    }

    let payload_digest = root
        .get("payloadDigest")
        .and_then(Value::text)
        .ok_or_else(|| "response envelope missing `payloadDigest`".to_owned())?;
    ContentDigest::parse(payload_digest)
        .map_err(|_| "response envelope `payloadDigest` is not a valid digest".to_owned())?;

    let decision_fp_raw = root
        .get("decisionFingerprint")
        .and_then(Value::text)
        .ok_or_else(|| "response envelope missing `decisionFingerprint`".to_owned())?;
    let decision_fp = ContentDigest::parse(decision_fp_raw)
        .map_err(|_| "response envelope `decisionFingerprint` is not a valid digest".to_owned())?;

    let payload_schema = root
        .get("payloadSchema")
        .and_then(Value::text)
        .ok_or_else(|| "response envelope missing `payloadSchema`".to_owned())?;
    if let Some(ops_schema) = expected_ops_subtarget_schema {
        if payload_schema != ops_schema {
            return Err(format!(
                "operational sub-target response payloadSchema `{payload_schema}` != expected `{ops_schema}`"
            ));
        }
    } else {
        let allowlist = operation
            .response_payload_schemas_for_basis(basis)
            .ok_or_else(|| "operation has no response allowlist under active basis".to_owned())?;
        if !allowlist.contains(&payload_schema) {
            return Err(format!(
                "response payloadSchema `{payload_schema}` is not in {} allowlist {allowlist:?}",
                operation.id()
            ));
        }
    }

    let outcome = root
        .get("outcome")
        .and_then(Value::text)
        .ok_or_else(|| "response envelope missing `outcome`".to_owned())?;
    if !matches!(
        outcome,
        "ok" | "error" | "cancelled" | "panicked" | "partial" | "indeterminate" | "refused"
    ) {
        return Err(format!(
            "response envelope has invalid `outcome` `{outcome}`"
        ));
    }
    let error_id = match root.get("errorId") {
        None | Some(Value::Null) => None,
        Some(Value::Text(s)) => {
            if !is_valid_error_id(s) {
                return Err(format!(
                    "response envelope `errorId` `{s}` does not match ^ERR-[A-Z0-9-]+-[0-9]{{3}}$"
                ));
            }
            Some(s.clone())
        }
        Some(_) => return Err("response envelope `errorId` must be string or null".to_owned()),
    };
    if matches!(outcome, "refused" | "error" | "cancelled" | "panicked") && error_id.is_none() {
        return Err(format!(
            "response envelope outcome `{outcome}` requires a registered non-null `errorId`"
        ));
    }

    Ok(ValidatedResponseMeta {
        schema: schema.to_owned(),
        payload_schema: Some(payload_schema.to_owned()),
        outcome: outcome.to_owned(),
        error_id,
        decision_fingerprint: Some(decision_fp),
    })
}

fn parse_and_validate_request(
    authority: &DispatchAuthority,
    raw_request_json: &str,
    raw_digest: ContentDigest,
) -> Result<ValidatedRequest, Box<RefusalSpec>> {
    let proto_err = |op: AgentOperation,
                     req_id: String,
                     payload_schema: String,
                     detail: String,
                     remediation: &str| {
        Box::new(RefusalSpec {
            operation: op,
            request_id: req_id,
            session_id: None,
            mission_id: None,
            view: AgentView::from_id(op.default_view()).unwrap_or(AgentView::Brief),
            error_id: ERR_AGENT_PROTOCOL,
            outcome: ResponseOutcome::Refused,
            completeness: Completeness::Unknown,
            recovery_class: "never_unchanged",
            safe_retry: ResponseSafeRetry::No,
            resnapshot_required: false,
            detail: sanitize_and_truncate(&detail, 320),
            remediation: remediation.to_owned(),
            request_payload_schema: payload_schema,
            request_digest: raw_digest,
            tainted: false,
        })
    };

    let parsed = parse_mcp_reply(raw_request_json.trim()).map_err(|err| {
        proto_err(
            AgentOperation::Doctor,
            "request:invalid-json".to_owned(),
            AgentOperation::Doctor.request_payload_schema().to_owned(),
            format!("Invalid AgentRequestEnvelope JSON: {err}"),
            "Send strictly valid canonical JSON conforming to schemas/agent_request_envelope.v1.json.",
        )
    })?;
    let root = parsed.object().ok_or_else(|| {
        proto_err(
            AgentOperation::Doctor,
            "request:not-object".to_owned(),
            AgentOperation::Doctor.request_payload_schema().to_owned(),
            "AgentRequestEnvelope must be a JSON object.".to_owned(),
            "Wrap the request in a valid fss.agent_request_envelope.v1 object.",
        )
    })?;

    const ENVELOPE_REQUIRED_KEYS: &[&str] = &[
        "schema",
        "contractBasis",
        "operationId",
        "requestId",
        "principalId",
        "sessionId",
        "missionId",
        "inputAnchor",
        "expectedWorkspaceRevision",
        "viewId",
        "targetUris",
        "payloadSchema",
        "payload",
        "budget",
        "deadlineNs",
        "requestedCapabilities",
        "requestedPrivacyProjection",
        "idempotencyKey",
        "continuation",
        "expectedDecisionFingerprint",
        "maxHydrationLevel",
        "acceptCompression",
        "taint",
        "createdAtNs",
    ];

    let req_id_hint = root
        .get("requestId")
        .and_then(Value::text)
        .filter(|s| validate_id(s).is_ok() && s.len() <= 256)
        .unwrap_or("request:invalid")
        .to_owned();
    let op_hint = root
        .get("operationId")
        .and_then(Value::text)
        .and_then(|id| AgentOperation::from_id(id).ok())
        .unwrap_or(AgentOperation::Doctor);
    let schema_hint = root
        .get("payloadSchema")
        .and_then(Value::text)
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .unwrap_or_else(|| op_hint.request_payload_schema())
        .to_owned();

    // Enforce additionalProperties: false and presence of every required field.
    for key in root.keys() {
        if !ENVELOPE_REQUIRED_KEYS.contains(&key.as_str()) {
            return Err(proto_err(
                op_hint,
                req_id_hint,
                schema_hint,
                format!("Unexpected top-level AgentRequestEnvelope field `{key}`."),
                "Remove unrecognized fields; schemas/agent_request_envelope.v1.json sets additionalProperties=false.",
            ));
        }
    }
    for req_key in ENVELOPE_REQUIRED_KEYS {
        if !root.contains_key(*req_key) {
            return Err(proto_err(
                op_hint,
                req_id_hint,
                schema_hint,
                format!("Missing required AgentRequestEnvelope field `{req_key}`."),
                "Populate all 24 required fields of schemas/agent_request_envelope.v1.json.",
            ));
        }
    }

    let schema = root.get("schema").and_then(Value::text).ok_or_else(|| {
        proto_err(
            op_hint,
            req_id_hint.clone(),
            schema_hint.clone(),
            "Envelope `schema` must be a string.".to_owned(),
            "Set schema to `fss.agent_request_envelope.v1`.",
        )
    })?;
    if schema != AgentRequestEnvelope::SCHEMA {
        return Err(proto_err(
            op_hint,
            req_id_hint,
            schema_hint,
            format!(
                "Unsupported request envelope schema `{schema}`; expected `{}`.",
                AgentRequestEnvelope::SCHEMA
            ),
            "Use `fss.agent_request_envelope.v1`.",
        ));
    }

    let request_id = root
        .get("requestId")
        .and_then(Value::text)
        .filter(|s| validate_id(s).is_ok() && s.len() <= 256)
        .ok_or_else(|| {
            proto_err(
                op_hint,
                "request:invalid".to_owned(),
                schema_hint.clone(),
                "Envelope `requestId` failed identifier validation.".to_owned(),
                "Provide a valid 1..=256-char identifier.",
            )
        })?
        .to_owned();

    // Resolve operationId against AgentOperation + crosswalk BEFORE basis profile matching.
    let operation_id_raw = root
        .get("operationId")
        .and_then(Value::text)
        .ok_or_else(|| {
            proto_err(
                AgentOperation::Doctor,
                request_id.clone(),
                schema_hint.clone(),
                "Envelope `operationId` must be a string.".to_owned(),
                "Address a registered AOP-001..AOP-014 operation.",
            )
        })?;
    let operation = AgentOperation::from_id(operation_id_raw).map_err(|_| {
        proto_err(
            AgentOperation::Doctor,
            request_id.clone(),
            schema_hint.clone(),
            format!("Unregistered operationId `{operation_id_raw}`."),
            "Address only registered AOP-001..AOP-014 operations from architecture/agent_operations.json.",
        )
    })?;
    if lookup_by_operation_id(operation.id()).is_none() {
        return Err(proto_err(
            operation,
            request_id,
            schema_hint,
            format!(
                "Operation `{}` is missing from REGISTERED_OPERATION_CROSSWALK.",
                operation.id()
            ),
            "Repair operation crosswalk registration.",
        ));
    }

    // Parse & negotiate ContractBasis strictly.
    let client_basis = parse_contract_basis_json(root.get("contractBasis")).map_err(|detail| {
        proto_err(
            operation,
            request_id.clone(),
            schema_hint.clone(),
            detail,
            "Supply a valid fss.agent_contract_basis.v1 object matching the active registry pins.",
        )
    })?;

    // Determine the exact server basis this request is allowed to negotiate against:
    // - baseline `authority.server_basis` (typically `reference_contract_basis()`),
    // - additive `probe_contract_basis()` ONLY when `operation == Investigate` and baseline has no custom nightly/overrides,
    // - additive `hydration_contract_basis()` ONLY when `operation == Query` and baseline has no custom nightly/overrides.
    let expected_basis = if authority.server_basis == reference_contract_basis()
        && ((operation == AgentOperation::Investigate && is_probe_contract_basis(&client_basis))
            || (operation == AgentOperation::Query && is_hydration_contract_basis(&client_basis)))
    {
        client_basis.clone()
    } else {
        authority.server_basis.clone()
    };

    let effective_basis = negotiate_basis_with_superseded(
        &expected_basis,
        &client_basis,
        &superseded_registry_digests(),
    )
    .map_err(|err| {
        basis_error_to_refusal(
            operation,
            request_id.clone(),
            schema_hint.clone(),
            raw_digest,
            &err,
        )
    })?;

    // Confirm operation resolves cleanly under the negotiated basis.
    registered_operation(&effective_basis, operation.name()).map_err(|err| {
        basis_error_to_refusal(
            operation,
            request_id.clone(),
            schema_hint.clone(),
            raw_digest,
            &err,
        )
    })?;

    // Validate viewId against registered AVIEW-001..AVIEW-008.
    let view_id_raw = root.get("viewId").and_then(Value::text).ok_or_else(|| {
        proto_err(
            operation,
            request_id.clone(),
            schema_hint.clone(),
            "Envelope `viewId` must be a string.".to_owned(),
            "Supply a registered AVIEW-001..AVIEW-008 identifier.",
        )
    })?;
    let view = AgentView::from_id(view_id_raw).map_err(|_| {
        proto_err(
            operation,
            request_id.clone(),
            schema_hint.clone(),
            format!("Unregistered viewId `{view_id_raw}`."),
            "Supply a registered AVIEW-001..AVIEW-008 identifier from architecture/agent_views.json.",
        )
    })?;

    // Validate payloadSchema against the operation row's owned request_payload_schema().
    let payload_schema = root
        .get("payloadSchema")
        .and_then(Value::text)
        .ok_or_else(|| {
            proto_err(
                operation,
                request_id.clone(),
                schema_hint.clone(),
                "Envelope `payloadSchema` must be a string.".to_owned(),
                "Set payloadSchema to the operation's registered requestPayloadSchema.",
            )
        })?
        .to_owned();
    if payload_schema != operation.request_payload_schema() {
        return Err(proto_err(
            operation,
            request_id,
            payload_schema.clone(),
            format!(
                "Operation {} ({}) requires payloadSchema `{}`, got `{payload_schema}`.",
                operation.id(),
                operation.name(),
                operation.request_payload_schema()
            ),
            "Set payloadSchema to the exact schema owned by this operation row in architecture/agent_operations.json.",
        ));
    }

    // Parse & verify principalId against launcher-owned DispatchAuthority.
    let principal_raw = root
        .get("principalId")
        .and_then(Value::text)
        .ok_or_else(|| {
            proto_err(
                operation,
                request_id.clone(),
                payload_schema.clone(),
                "Envelope `principalId` must be a string.".to_owned(),
                "Set principalId to the authenticated launcher principal.",
            )
        })?;
    let principal_id = PrincipalId::parse(principal_raw).map_err(|_| {
        proto_err(
            operation,
            request_id.clone(),
            payload_schema.clone(),
            "Envelope `principalId` failed principal syntax validation.".to_owned(),
            "Provide a valid PrincipalId.",
        )
    })?;
    if principal_id != authority.principal {
        return Err(Box::new(RefusalSpec {
            operation,
            request_id,
            session_id: None,
            mission_id: None,
            view,
            error_id: ERR_AUTH_DENIED,
            outcome: ResponseOutcome::Refused,
            completeness: Completeness::Unauthorized,
            recovery_class: "operator_action_required",
            safe_retry: ResponseSafeRetry::No,
            resnapshot_required: false,
            detail: format!(
                "Request principalId `{}` does not match authenticated launcher principal `{}`.",
                principal_id.as_str(),
                authority.principal.as_str()
            ),
            remediation: "Authenticate as the target principal; request envelopes cannot impersonate another principal.".to_owned(),
            request_payload_schema: payload_schema,
            request_digest: raw_digest,
            tainted: false,
        }));
    }

    // Parse optional sessionId and missionId.
    let session_id = parse_opt_id(root.get("sessionId"), "sessionId")
        .map_err(|d| {
            proto_err(
                operation,
                request_id.clone(),
                payload_schema.clone(),
                d,
                "Use valid sessionId or null.",
            )
        })?
        .map(|s| {
            SessionId::parse(s).map_err(|_| {
                proto_err(
                    operation,
                    request_id.clone(),
                    payload_schema.clone(),
                    "Invalid `sessionId` format.".to_owned(),
                    "Provide a valid SessionId or null.",
                )
            })
        })
        .transpose()?;
    let mission_id = parse_opt_id(root.get("missionId"), "missionId")
        .map_err(|d| {
            proto_err(
                operation,
                request_id.clone(),
                payload_schema.clone(),
                d,
                "Use valid missionId or null.",
            )
        })?
        .map(|m| {
            MissionId::parse(m).map_err(|_| {
                proto_err(
                    operation,
                    request_id.clone(),
                    payload_schema.clone(),
                    "Invalid `missionId` format.".to_owned(),
                    "Provide a valid MissionId or null.",
                )
            })
        })
        .transpose()?;

    // Parse requestedPrivacyProjection, budget, taint, hydration, timestamps, targetUris, capabilities.
    let privacy =
        parse_privacy_projection(root.get("requestedPrivacyProjection")).map_err(|d| {
            proto_err(
                operation,
                request_id.clone(),
                payload_schema.clone(),
                d,
                "Supply a valid requestedPrivacyProjection object.",
            )
        })?;
    let explicit_privacy_epoch = privacy
        .policy_generation_id
        .strip_prefix("privacy-epoch:")
        .and_then(|s| s.parse::<u64>().ok());

    let input_anchor = match root.get("inputAnchor") {
        Some(Value::Null) => None,
        Some(v) => Some(
            parse_evidence_anchor_json(v, explicit_privacy_epoch).map_err(|d| {
                proto_err(
                    operation,
                    request_id.clone(),
                    payload_schema.clone(),
                    d,
                    "Supply a valid fss.evidence_anchor.v1 object or null.",
                )
            })?,
        ),
        None => None,
    };

    let expected_workspace_revision = match root.get("expectedWorkspaceRevision") {
        Some(Value::Null) => None,
        Some(Value::Number(raw)) => Some(
            parse_u64_strict(raw, "expectedWorkspaceRevision").map_err(|d| {
                proto_err(
                    operation,
                    request_id.clone(),
                    payload_schema.clone(),
                    d,
                    "Use non-negative integer or null.",
                )
            })?,
        ),
        _ => {
            return Err(proto_err(
                operation,
                request_id,
                payload_schema,
                "`expectedWorkspaceRevision` must be a non-negative integer or null.".to_owned(),
                "Use non-negative integer or null.",
            ));
        }
    };

    let target_uris = parse_target_uris(root.get("targetUris")).map_err(|d| {
        proto_err(
            operation,
            request_id.clone(),
            payload_schema.clone(),
            d,
            "Supply at most 256 `fss://...` URIs.",
        )
    })?;

    let budget = parse_budget_vector_json(root.get("budget")).map_err(|d| {
        proto_err(
            operation,
            request_id.clone(),
            payload_schema.clone(),
            d,
            "Supply all 11 non-negative budget vector fields.",
        )
    })?;

    // Check inbound request byte budget immediately.
    if budget.bytes > 0 && (raw_request_json.len() as u64) > budget.bytes {
        return Err(Box::new(RefusalSpec {
            operation,
            request_id,
            session_id: session_id.as_ref().map(|s| s.as_str().to_owned()),
            mission_id: mission_id.as_ref().map(|m| m.as_str().to_owned()),
            view,
            error_id: ERR_BUDGET_EXHAUSTED,
            outcome: ResponseOutcome::Refused,
            completeness: Completeness::Partial,
            recovery_class: "refresh_and_retry",
            safe_retry: ResponseSafeRetry::YesAfterRefresh,
            resnapshot_required: false,
            detail: format!(
                "Request size {} bytes exceeds declared budget.bytes {}.",
                raw_request_json.len(),
                budget.bytes
            ),
            remediation: "Increase budget.bytes or shrink the request payload.".to_owned(),
            request_payload_schema: payload_schema,
            request_digest: raw_digest,
            tainted: false,
        }));
    }

    let created_at_ns = match root.get("createdAtNs") {
        Some(Value::Number(raw)) => parse_non_negative_i128(raw, "createdAtNs").map_err(|d| {
            proto_err(
                operation,
                request_id.clone(),
                payload_schema.clone(),
                d,
                "Supply non-negative integer createdAtNs.",
            )
        })?,
        _ => {
            return Err(proto_err(
                operation,
                request_id,
                payload_schema,
                "`createdAtNs` must be a non-negative integer.".to_owned(),
                "Supply non-negative integer createdAtNs.",
            ));
        }
    };
    let deadline_ns = match root.get("deadlineNs") {
        Some(Value::Null) => None,
        Some(Value::Number(raw)) => {
            let dl = parse_non_negative_i128(raw, "deadlineNs").map_err(|d| {
                proto_err(
                    operation,
                    request_id.clone(),
                    payload_schema.clone(),
                    d,
                    "Supply non-negative integer deadlineNs or null.",
                )
            })?;
            if dl <= created_at_ns {
                return Err(proto_err(
                    operation,
                    request_id,
                    payload_schema,
                    format!(
                        "Inverted deadline: deadlineNs ({dl}) <= createdAtNs ({created_at_ns})."
                    ),
                    "Set deadlineNs strictly greater than createdAtNs, or null.",
                ));
            }
            Some(dl)
        }
        _ => {
            return Err(proto_err(
                operation,
                request_id,
                payload_schema,
                "`deadlineNs` must be a non-negative integer or null.".to_owned(),
                "Supply non-negative integer deadlineNs or null.",
            ));
        }
    };

    // Validate requestedCapabilities syntax AND check launcher capability ceiling.
    let requested_capabilities = parse_requested_capabilities(root.get("requestedCapabilities"))
        .map_err(|d| {
            proto_err(
                operation,
                request_id.clone(),
                payload_schema.clone(),
                d,
                "Supply at most 256 CAP-* capability IDs.",
            )
        })?;
    for req_cap in &requested_capabilities {
        if !authority.granted_capabilities.contains(req_cap) {
            return Err(Box::new(RefusalSpec {
                operation,
                request_id,
                session_id: session_id.as_ref().map(|s| s.as_str().to_owned()),
                mission_id: mission_id.as_ref().map(|m| m.as_str().to_owned()),
                view,
                error_id: ERR_AUTH_DENIED,
                outcome: ResponseOutcome::Refused,
                completeness: Completeness::Unauthorized,
                recovery_class: "operator_action_required",
                safe_retry: ResponseSafeRetry::No,
                resnapshot_required: false,
                detail: format!(
                    "Requested capability `{req_cap}` exceeds launcher-granted authority."
                ),
                remediation: "Request only capabilities granted to this principal, or obtain operator authorization.".to_owned(),
                request_payload_schema: payload_schema,
                request_digest: raw_digest,
                tainted: false,
            }));
        }
    }
    let required_caps = operation
        .required_capabilities_for_basis(&effective_basis)
        .unwrap_or_else(|| operation.required_capabilities());
    for req_cap in required_caps {
        if !authority.granted_capabilities.contains(*req_cap) {
            return Err(Box::new(RefusalSpec {
                operation,
                request_id,
                session_id: session_id.as_ref().map(|s| s.as_str().to_owned()),
                mission_id: mission_id.as_ref().map(|m| m.as_str().to_owned()),
                view,
                error_id: ERR_AUTH_DENIED,
                outcome: ResponseOutcome::Refused,
                completeness: Completeness::Unauthorized,
                recovery_class: "operator_action_required",
                safe_retry: ResponseSafeRetry::No,
                resnapshot_required: false,
                detail: format!(
                    "Launcher lacks required capability `{req_cap}` for {} ({}).",
                    operation.id(),
                    operation.name()
                ),
                remediation: "Grant the operation's required capability in launcher authority."
                    .to_owned(),
                request_payload_schema: payload_schema,
                request_digest: raw_digest,
                tainted: false,
            }));
        }
    }

    let idempotency_key =
        parse_opt_id(root.get("idempotencyKey"), "idempotencyKey").map_err(|d| {
            proto_err(
                operation,
                request_id.clone(),
                payload_schema.clone(),
                d,
                "Supply valid idempotencyKey or null.",
            )
        })?;
    if operation.effectful() && idempotency_key.is_none() {
        return Err(Box::new(RefusalSpec {
            operation,
            request_id,
            session_id: session_id.as_ref().map(|s| s.as_str().to_owned()),
            mission_id: mission_id.as_ref().map(|m| m.as_str().to_owned()),
            view,
            error_id: ERR_IDEMPOTENCY_CONFLICT,
            outcome: ResponseOutcome::Refused,
            completeness: Completeness::Unknown,
            recovery_class: "never_unchanged",
            safe_retry: ResponseSafeRetry::No,
            resnapshot_required: false,
            detail: format!(
                "Effectful operation {} ({}) requires a non-null `idempotencyKey`.",
                operation.id(),
                operation.name()
            ),
            remediation: "Assign a stable idempotencyKey before submitting effectful operations."
                .to_owned(),
            request_payload_schema: payload_schema,
            request_digest: raw_digest,
            tainted: false,
        }));
    }

    let continuation = parse_opt_id(root.get("continuation"), "continuation").map_err(|d| {
        proto_err(
            operation,
            request_id.clone(),
            payload_schema.clone(),
            d,
            "Supply valid continuation token or null.",
        )
    })?;

    let expected_decision_fingerprint = match root.get("expectedDecisionFingerprint") {
        Some(Value::Null) => None,
        Some(Value::Text(s)) => Some(ContentDigest::parse(s).map_err(|_| {
            proto_err(
                operation,
                request_id.clone(),
                payload_schema.clone(),
                "`expectedDecisionFingerprint` must be a valid sha256 digest.".to_owned(),
                "Provide a valid ContentDigest or null.",
            )
        })?),
        _ => {
            return Err(proto_err(
                operation,
                request_id,
                payload_schema,
                "`expectedDecisionFingerprint` must be a digest string or null.".to_owned(),
                "Provide a valid ContentDigest or null.",
            ));
        }
    };

    let max_hydration_level = match root.get("maxHydrationLevel").and_then(Value::text) {
        Some("H0") => HydrationLevel::H0,
        Some("H1") => HydrationLevel::H1,
        Some("H2") => HydrationLevel::H2,
        Some("H3") => HydrationLevel::H3,
        Some("H4") => HydrationLevel::H4,
        _ => {
            return Err(proto_err(
                operation,
                request_id,
                payload_schema,
                "`maxHydrationLevel` must be one of H0, H1, H2, H3, H4.".to_owned(),
                "Set maxHydrationLevel to H0..H4.",
            ));
        }
    };

    let accept_compression = root
        .get("acceptCompression")
        .and_then(Value::boolean)
        .ok_or_else(|| {
            proto_err(
                operation,
                request_id.clone(),
                payload_schema.clone(),
                "`acceptCompression` must be a boolean.".to_owned(),
                "Set acceptCompression to true or false.",
            )
        })?;

    let taint = parse_request_taint(root.get("taint")).map_err(|d| {
        proto_err(
            operation,
            request_id.clone(),
            payload_schema.clone(),
            d,
            "Supply a valid taint object with containsUntrustedControlText and bounded sources.",
        )
    })?;

    // Tainted untrusted control text may NEVER directly drive an effectful commit or cancel.
    if taint.contains_untrusted_control_text && operation.effectful() {
        return Err(Box::new(RefusalSpec {
            operation,
            request_id,
            session_id: session_id.as_ref().map(|s| s.as_str().to_owned()),
            mission_id: mission_id.as_ref().map(|m| m.as_str().to_owned()),
            view,
            error_id: ERR_AUTH_DENIED,
            outcome: ResponseOutcome::Refused,
            completeness: Completeness::Unauthorized,
            recovery_class: "operator_action_required",
            safe_retry: ResponseSafeRetry::No,
            resnapshot_required: false,
            detail: format!(
                "Tainted untrusted control text is forbidden on effectful operation {} ({}).",
                operation.id(),
                operation.name()
            ),
            remediation: "Inspect and compile untrusted text via read-only/plan operations with explicit operator approval before committing effects.".to_owned(),
            request_payload_schema: payload_schema,
            request_digest: raw_digest,
            tainted: true,
        }));
    }

    let payload_val = root.get("payload").ok_or_else(|| {
        proto_err(
            operation,
            request_id.clone(),
            payload_schema.clone(),
            "Envelope missing `payload`.".to_owned(),
            "Provide a typed payload object matching payloadSchema.",
        )
    })?;
    let payload_obj = payload_val
        .object()
        .ok_or_else(|| {
            proto_err(
                operation,
                request_id.clone(),
                payload_schema.clone(),
                "Envelope `payload` must be a JSON object.".to_owned(),
                "Provide a typed payload object matching payloadSchema.",
            )
        })?
        .clone();

    // Reject explicit authority/scope override attempts inside the typed payload with ERR-AUTH-DENIED-001.
    for forbidden in FORBIDDEN_AUTHORITY_OVERRIDE_KEYS {
        if payload_obj.contains_key(*forbidden) {
            return Err(Box::new(RefusalSpec {
                operation,
                request_id,
                session_id: session_id.as_ref().map(|s| s.as_str().to_owned()),
                mission_id: mission_id.as_ref().map(|m| m.as_str().to_owned()),
                view,
                error_id: ERR_AUTH_DENIED,
                outcome: ResponseOutcome::Refused,
                completeness: Completeness::Unauthorized,
                recovery_class: "operator_action_required",
                safe_retry: ResponseSafeRetry::No,
                resnapshot_required: false,
                detail: format!(
                    "Payload attempted forbidden launcher-authority override via key `{forbidden}`."
                ),
                remediation: "Remove authority/scope override keys from payload; root, principal, and capability ceilings are launcher-owned.".to_owned(),
                request_payload_schema: payload_schema,
                request_digest: raw_digest,
                tainted: taint.contains_untrusted_control_text,
            }));
        }
    }

    let payload_canonical = crate::transcript_equivalence::render_canonical_json_normalized(
        payload_val,
        &BTreeSet::new(),
        &crate::transcript_equivalence::TokenNormalizer::none(),
    );

    // Construct the canonical `fss_core::AgentRequestEnvelope` when session & mission are bound,
    // or compute an unambiguous 24-field domain-separated canonical digest for stateless reads.
    let request_digest = if let (Some(sess), Some(miss)) = (session_id.clone(), mission_id.clone())
    {
        let core_envelope = AgentRequestEnvelope::new(AgentRequestEnvelopeParams {
            contract_basis: effective_basis.clone(),
            operation_name: operation.name().to_owned(),
            request_id: request_id.clone(),
            principal_id: principal_id.clone(),
            session_id: sess,
            mission_id: miss,
            input_anchor: input_anchor.clone(),
            expected_workspace_revision,
            view_id: view.id().to_owned(),
            target_uris,
            payload_schema: payload_schema.clone(),
            payload_json: payload_canonical,
            budget,
            deadline_ns,
            privacy,
            idempotency_key: idempotency_key.clone(),
            continuation: continuation.clone(),
            expected_decision_fingerprint,
            max_hydration_level,
            accept_compression,
            taint: taint.clone(),
            created_at: TimestampNs(created_at_ns),
        })
        .map_err(|err| {
            basis_error_to_refusal(
                operation,
                request_id.clone(),
                payload_schema.clone(),
                raw_digest,
                &err,
            )
        })?;
        core_envelope.request_digest()
    } else {
        let mut enc = CanonicalEncoder::new();
        enc.text(DISPATCH_REQUEST_HASH_TAG);
        effective_basis.encode_canonical(&mut enc);
        enc.text(operation.id());
        enc.text(&request_id);
        principal_id.encode_canonical(&mut enc);
        match &session_id {
            Some(s) => {
                enc.bool(true);
                s.encode_canonical(&mut enc);
            }
            None => enc.bool(false),
        }
        match &mission_id {
            Some(m) => {
                enc.bool(true);
                m.encode_canonical(&mut enc);
            }
            None => enc.bool(false),
        }
        match &input_anchor {
            Some(a) => {
                enc.bool(true);
                a.encode_canonical(&mut enc);
            }
            None => enc.bool(false),
        }
        match expected_workspace_revision {
            Some(rev) => {
                enc.bool(true);
                enc.u64(rev);
            }
            None => enc.bool(false),
        }
        enc.text(view.id());
        enc.u32(target_uris.len() as u32);
        for uri in &target_uris {
            enc.text(uri);
        }
        enc.text(&payload_schema);
        enc.text(&payload_canonical);
        budget.encode_canonical(&mut enc);
        match deadline_ns {
            Some(dl) => {
                enc.bool(true);
                enc.i128(dl);
            }
            None => enc.bool(false),
        }
        enc.u32(requested_capabilities.len() as u32);
        for cap in &requested_capabilities {
            enc.text(cap);
        }
        enc.text(&privacy.purpose);
        enc.text(&privacy.policy_generation_id);
        enc.u32(privacy.allowed_domains.len() as u32);
        for d in &privacy.allowed_domains {
            enc.text(d);
        }
        enc.u32(privacy.redacted_domains.len() as u32);
        for d in &privacy.redacted_domains {
            enc.text(d);
        }
        match &idempotency_key {
            Some(key) => {
                enc.bool(true);
                enc.text(key);
            }
            None => enc.bool(false),
        }
        match &continuation {
            Some(cont) => {
                enc.bool(true);
                enc.text(cont);
            }
            None => enc.bool(false),
        }
        match expected_decision_fingerprint {
            Some(fp) => {
                enc.bool(true);
                enc.digest(fp);
            }
            None => enc.bool(false),
        }
        enc.text(max_hydration_level.as_str());
        enc.bool(accept_compression);
        enc.bool(taint.contains_untrusted_control_text);
        enc.u32(taint.sources.len() as u32);
        for src in &taint.sources {
            enc.text(src);
        }
        enc.i128(created_at_ns);
        ContentDigest::sha256(&enc.finish())
    };

    Ok(ValidatedRequest {
        effective_basis,
        operation,
        request_id,
        session_id,
        mission_id,
        input_anchor,
        expected_workspace_revision,
        expected_decision_fingerprint,
        view,
        payload_schema,
        payload_obj,
        budget,
        continuation,
        taint,
        request_digest,
    })
}

fn basis_error_to_refusal(
    operation: AgentOperation,
    request_id: String,
    payload_schema: String,
    request_digest: ContentDigest,
    err: &ContractBasisError,
) -> Box<RefusalSpec> {
    let is_stale = matches!(err, ContractBasisError::StaleBasis { .. });
    let remediation = match err {
        ContractBasisError::IncompatibleBasis { refusal } => {
            refusal.remediation_guidance().to_owned()
        }
        ContractBasisError::StaleBasis { .. } => {
            "Rebase session onto the active ContractBasis and enumerate invalidated assumptions before proceeding.".to_owned()
        }
        _ => "Inspect ContractBasis pins and re-negotiate with session.open.".to_owned(),
    };
    Box::new(RefusalSpec {
        operation,
        request_id,
        session_id: None,
        mission_id: None,
        view: AgentView::from_id(operation.default_view()).unwrap_or(AgentView::Brief),
        error_id: err.error_id(),
        outcome: ResponseOutcome::Refused,
        completeness: if is_stale {
            Completeness::Stale
        } else {
            Completeness::Unknown
        },
        recovery_class: if is_stale {
            "rebase_required"
        } else {
            "never_unchanged"
        },
        safe_retry: if is_stale {
            ResponseSafeRetry::YesAfterRefresh
        } else {
            ResponseSafeRetry::No
        },
        resnapshot_required: is_stale,
        detail: sanitize_and_truncate(&err.to_string(), 320),
        remediation,
        request_payload_schema: payload_schema,
        request_digest,
        tainted: false,
    })
}

/// Compiles a validated universal request's operation-registry-owned typed payload into the
/// single canonical [`FssCommand`] executed identically by CLI, Rust API, and MCP.
fn compile_operation_payload(
    authority: &DispatchAuthority,
    req: &ValidatedRequest,
) -> Result<FssCommand, Box<RefusalSpec>> {
    let args = &req.payload_obj;
    let bad_payload_fn = |detail: &str| {
        Box::new(RefusalSpec {
            operation: req.operation,
            request_id: req.request_id.clone(),
            session_id: req.session_id.as_ref().map(|s| s.as_str().to_owned()),
            mission_id: req.mission_id.as_ref().map(|m| m.as_str().to_owned()),
            view: req.view,
            error_id: ERR_AGENT_PROTOCOL,
            outcome: ResponseOutcome::Refused,
            completeness: Completeness::Unknown,
            recovery_class: "never_unchanged",
            safe_retry: ResponseSafeRetry::No,
            resnapshot_required: false,
            detail: sanitize_and_truncate(detail, 320),
            remediation: format!(
                "Supply a valid `{}` payload conforming to operation {} ({}).",
                req.payload_schema,
                req.operation.id(),
                req.operation.name()
            ),
            request_payload_schema: req.payload_schema.clone(),
            request_digest: req.request_digest,
            tainted: req.taint.contains_untrusted_control_text,
        })
    };
    let bad_payload = &bad_payload_fn;

    let base = |cmd: &str| -> Vec<OsString> {
        vec![
            cmd.into(),
            "--json".into(),
            "--root".into(),
            authority.root.as_os_str().to_owned(),
        ]
    };
    let principal_flag =
        || -> OsString { format!("--principal={}", authority.principal.as_str()).into() };

    // Resolve session either from payload["session"] or envelope sessionId; reject conflicting values.
    let resolve_session = |required: bool| -> Result<Option<String>, Box<RefusalSpec>> {
        let from_payload = match args.get("session") {
            None => None,
            Some(v) => Some(bounded_text(Some(v), 128).map_err(bad_payload)?.to_owned()),
        };
        let from_env = req.session_id.as_ref().map(|s| s.as_str().to_owned());
        match (from_payload, from_env) {
            (Some(a), Some(b)) if a != b => Err(bad_payload(
                "payload.session conflicts with envelope.sessionId",
            )),
            (Some(a), _) => Ok(Some(a)),
            (None, Some(b)) => Ok(Some(b)),
            (None, None) if required => Err(bad_payload("operation requires session identifier")),
            (None, None) => Ok(None),
        }
    };

    let budget_exceeded = |requested_tokens: u64| {
        Box::new(RefusalSpec {
            operation: req.operation,
            request_id: req.request_id.clone(),
            session_id: req.session_id.as_ref().map(|s| s.as_str().to_owned()),
            mission_id: req.mission_id.as_ref().map(|m| m.as_str().to_owned()),
            view: req.view,
            error_id: ERR_BUDGET_EXHAUSTED,
            outcome: ResponseOutcome::Refused,
            completeness: Completeness::Partial,
            recovery_class: "refresh_and_retry",
            safe_retry: ResponseSafeRetry::YesAfterRefresh,
            resnapshot_required: false,
            detail: format!(
                "Payload budget_tokens ({requested_tokens}) exceeds envelope budget.tokens ({}).",
                req.budget.tokens
            ),
            remediation:
                "Lower payload.budget_tokens to <= envelope.budget.tokens or raise envelope.budget.tokens."
                    .to_owned(),
            request_payload_schema: req.payload_schema.clone(),
            request_digest: req.request_digest,
            tainted: req.taint.contains_untrusted_control_text,
        })
    };

    match req.operation {
        AgentOperation::SessionOpen => {
            allow_only(args, &["mission", "objective", "view", "budget_tokens"])
                .map_err(bad_payload)?;
            let mission =
                bounded_text(args.get("mission"), MAX_MISSION_BYTES).map_err(bad_payload)?;
            let objective =
                bounded_text(args.get("objective"), MAX_OBJECTIVE_BYTES).map_err(bad_payload)?;
            let mut argv = base("session");
            argv.insert(1, "open".into());
            // Always literal text; never stats or reads a file path.
            argv.push(format!("--mission-text={mission}").into());
            argv.push(format!("--objective={objective}").into());
            if let Some(v) = args.get("view") {
                let view = bounded_text(Some(v), 32).map_err(bad_payload)?;
                if !matches!(view, "pulse" | "brief" | "epistemic_map") {
                    return Err(bad_payload("unsupported session.open view"));
                }
                argv.push(format!("--view={view}").into());
            }
            if let Some(v) = args.get("budget_tokens") {
                let n = positive_u64(v, MAX_SESSION_TOKEN_BUDGET).map_err(bad_payload)?;
                if req.budget.tokens > 0 && n > req.budget.tokens {
                    return Err(budget_exceeded(n));
                }
                argv.push(format!("--budget-tokens={n}").into());
            }
            argv.push(principal_flag());
            parse_fss_args(argv).map_err(|e| bad_payload(&e.to_string()))
        }
        AgentOperation::SessionResume => {
            allow_only(args, &["handoff"]).map_err(bad_payload)?;
            let handoff = bounded_text(args.get("handoff"), 128).map_err(bad_payload)?;
            let mut argv = base("session");
            argv.insert(1, "resume".into());
            argv.push(format!("--handoff={handoff}").into());
            argv.push(principal_flag());
            parse_fss_args(argv).map_err(|e| bad_payload(&e.to_string()))
        }
        AgentOperation::SessionOrient => {
            allow_only(args, &["session", "view", "budget_tokens"]).map_err(bad_payload)?;
            let mut argv = base("orient");
            if let Some(session) = resolve_session(false)? {
                argv.push(format!("--session={session}").into());
            }
            if let Some(v) = args.get("view") {
                let view = bounded_text(Some(v), 32).map_err(bad_payload)?;
                if !matches!(view, "pulse" | "brief" | "epistemic_map") {
                    return Err(bad_payload("unsupported session.orient view"));
                }
                argv.push(format!("--view={view}").into());
            }
            if let Some(v) = args.get("budget_tokens") {
                let n = positive_u64(v, MAX_ORIENT_BUDGET_TOKENS).map_err(bad_payload)?;
                if req.budget.tokens > 0 && n > req.budget.tokens {
                    return Err(budget_exceeded(n));
                }
                argv.push(format!("--budget-tokens={n}").into());
            }
            argv.push(principal_flag());
            parse_fss_args(argv).map_err(|e| bad_payload(&e.to_string()))
        }
        AgentOperation::SessionFollow => {
            allow_only(
                args,
                &[
                    "since",
                    "view",
                    "max_entries",
                    "continuation",
                    "wait_ms",
                    "session",
                    "subscription",
                    "acknowledge",
                ],
            )
            .map_err(bad_payload)?;
            let since = bounded_text(args.get("since"), 256).map_err(bad_payload)?;
            let mut argv = base("follow");
            argv.push(format!("--since={since}").into());
            if let Some(v) = args.get("view") {
                let view = bounded_text(Some(v), 32).map_err(bad_payload)?;
                if !matches!(view, "pulse" | "brief") {
                    return Err(bad_payload("unsupported session.follow view"));
                }
                argv.push(format!("--view={view}").into());
            }
            if let Some(v) = args.get("max_entries") {
                let n = positive_u64(v, MAX_PAGE_ENTRIES).map_err(bad_payload)?;
                argv.push(format!("--max-entries={n}").into());
            }
            let cont = match (args.get("continuation"), req.continuation.as_deref()) {
                (Some(v), Some(env_c)) => {
                    let s = bounded_text(Some(v), 256).map_err(bad_payload)?;
                    if s != env_c {
                        return Err(bad_payload(
                            "payload.continuation conflicts with envelope.continuation",
                        ));
                    }
                    Some(s.to_owned())
                }
                (Some(v), None) => {
                    Some(bounded_text(Some(v), 256).map_err(bad_payload)?.to_owned())
                }
                (None, Some(env_c)) => Some(env_c.to_owned()),
                (None, None) => None,
            };
            if let Some(token) = cont {
                argv.push(format!("--continuation={token}").into());
            }
            if let Some(v) = args.get("wait_ms") {
                let n = positive_u64(v, fss_reference::agent_follow::wait::MAX_FOLLOW_WAIT_MS)
                    .map_err(bad_payload)?;
                argv.push(format!("--wait-ms={n}").into());
            }
            // Enforce payload.session vs envelope.sessionId consistency; emit `--session` only when
            // durable subscription scope is explicitly requested (otherwise `fss follow` forbids
            // `--session` without `--subscription`).
            let resolved_follow_session = resolve_session(false)?;
            let wants_durable_sub = args.contains_key("session")
                || args.contains_key("subscription")
                || args.contains_key("acknowledge");
            if wants_durable_sub && let Some(session) = resolved_follow_session {
                argv.push(format!("--session={session}").into());
            }
            for (field, option, maximum) in [
                ("subscription", "--subscription", 128),
                ("acknowledge", "--acknowledge", 71),
            ] {
                if let Some(v) = args.get(field) {
                    let text = bounded_text(Some(v), maximum).map_err(bad_payload)?;
                    argv.push(format!("{option}={text}").into());
                }
            }
            argv.push(principal_flag());
            parse_fss_args(argv).map_err(|e| bad_payload(&e.to_string()))
        }
        AgentOperation::Query => compile_query_payload(authority, req, bad_payload),
        AgentOperation::Investigate => {
            compile_investigate_payload(authority, req, resolve_session(true)?, bad_payload)
        }
        AgentOperation::Plan => {
            compile_plan_payload(authority, req, resolve_session(false)?, bad_payload)
        }
        AgentOperation::Commit => compile_commit_payload(authority, req, bad_payload),
        AgentOperation::Wait => {
            allow_only(args, &["operation_id", "deadline_ms"]).map_err(bad_payload)?;
            let op_id = bounded_text(args.get("operation_id"), 128).map_err(bad_payload)?;
            let deadline = positive_u64(
                args.get("deadline_ms")
                    .ok_or_else(|| bad_payload("wait requires deadline_ms"))?,
                MAX_WAIT_MS,
            )
            .map_err(bad_payload)?;
            let mut argv = base("wait");
            argv.push(format!("--operation={op_id}").into());
            argv.push(format!("--deadline-ms={deadline}").into());
            argv.push(principal_flag());
            parse_fss_args(argv).map_err(|e| bad_payload(&e.to_string()))
        }
        AgentOperation::Cancel => {
            let mut argv = base("cancel");
            if args.contains_key("session") {
                allow_only(args, &["session", "approve"]).map_err(bad_payload)?;
                let session = resolve_session(true)?
                    .ok_or_else(|| bad_payload("cancel session requires session id"))?;
                argv.push(format!("--session={session}").into());
            } else {
                allow_only(args, &["operation_id", "approve"]).map_err(bad_payload)?;
                let op_id = bounded_text(args.get("operation_id"), 128).map_err(bad_payload)?;
                argv.push(format!("--operation={op_id}").into());
            }
            if let Some(v) = args.get("approve") {
                let approve = bounded_text(Some(v), 71).map_err(bad_payload)?;
                argv.push(format!("--approve={approve}").into());
            }
            argv.push(principal_flag());
            let command = parse_fss_args(argv).map_err(|e| bad_payload(&e.to_string()))?;
            match &command {
                FssCommand::Effect(eff)
                    if matches!(
                        eff.as_ref(),
                        EffectCommand::Cancel(_) | EffectCommand::CancelSession(_)
                    ) =>
                {
                    Ok(command)
                }
                _ => Err(bad_payload(
                    "cancel payload did not compile to native cancel",
                )),
            }
        }
        AgentOperation::Explain => {
            allow_only(
                args,
                &[
                    "event_id",
                    "session",
                    "learning_root",
                    "view",
                    "budget_tokens",
                    "custody",
                    "at",
                    "question",
                    "from_revision_digest",
                    "to_revision_digest",
                    "counterfactual",
                ],
            )
            .map_err(bad_payload)?;
            let mut argv = base("explain");
            let question = match args.get("question") {
                None => "why",
                Some(v) => v
                    .text()
                    .filter(|s| matches!(*s, "why" | "why_not" | "what_changed" | "what_if"))
                    .ok_or_else(|| {
                        bad_payload("question must be why, why_not, what_changed, or what_if")
                    })?,
            };
            if args.contains_key("question") {
                argv.push(format!("--question={question}").into());
            }
            if question != "what_if" && args.contains_key("counterfactual") {
                return Err(bad_payload("counterfactual requires question=what_if"));
            }
            if question != "what_changed"
                && ["from_revision_digest", "to_revision_digest"]
                    .iter()
                    .any(|key| args.contains_key(*key))
            {
                return Err(bad_payload(
                    "from_revision_digest and to_revision_digest require question=what_changed",
                ));
            }
            if question == "what_if" {
                if [
                    "session",
                    "learning_root",
                    "at",
                    "custody",
                    "from_revision_digest",
                    "to_revision_digest",
                ]
                .iter()
                .any(|key| args.contains_key(*key))
                {
                    return Err(bad_payload(
                        "what_if requires current event metadata and one inline scenario without session, learning_root, at, custody, or revision digests",
                    ));
                }
                let event = bounded_text(args.get("event_id"), 128).map_err(bad_payload)?;
                let cf_val = args
                    .get("counterfactual")
                    .filter(|v| v.object().is_some())
                    .ok_or_else(|| bad_payload("what_if requires counterfactual object"))?;
                let cf_json = crate::transcript_equivalence::render_canonical_json_normalized(
                    cf_val,
                    &BTreeSet::new(),
                    &crate::transcript_equivalence::TokenNormalizer::none(),
                );
                argv.push(format!("--event-id={event}").into());
                argv.push(format!("--counterfactual={cf_json}").into());
            } else if question == "what_changed" {
                if ["session", "learning_root", "at", "custody"]
                    .iter()
                    .any(|key| args.contains_key(*key))
                {
                    return Err(bad_payload(
                        "what_changed requires current adjacent event metadata without session, learning_root, at, or custody",
                    ));
                }
                let event = bounded_text(args.get("event_id"), 128).map_err(bad_payload)?;
                let from_d =
                    bounded_text(args.get("from_revision_digest"), 71).map_err(bad_payload)?;
                let to_d = bounded_text(args.get("to_revision_digest"), 71).map_err(bad_payload)?;
                argv.push(format!("--event-id={event}").into());
                argv.push(format!("--from-revision-digest={from_d}").into());
                argv.push(format!("--to-revision-digest={to_d}").into());
            } else if let Some(lroot) = args.get("learning_root") {
                if question == "why_not" {
                    return Err(bad_payload(
                        "question=why_not applies to event_id, not learning_root inspection",
                    ));
                }
                if ["event_id", "at", "custody"]
                    .iter()
                    .any(|key| args.contains_key(*key))
                {
                    return Err(bad_payload(
                        "learning_root inspection cannot use event_id, at, or custody",
                    ));
                }
                let lroot_s = bounded_text(Some(lroot), 71).map_err(bad_payload)?;
                let session = resolve_session(true)?
                    .ok_or_else(|| bad_payload("learning_root requires session"))?;
                argv.push(format!("--learning-root={lroot_s}").into());
                argv.push(format!("--session={session}").into());
            } else {
                if args.contains_key("session") {
                    return Err(bad_payload(
                        "learning inspection requires both learning_root and session",
                    ));
                }
                let event = bounded_text(args.get("event_id"), 128).map_err(bad_payload)?;
                argv.push(format!("--event-id={event}").into());
                if let Some(v) = args.get("at") {
                    let at = bounded_text(Some(v), 256).map_err(bad_payload)?;
                    argv.push(format!("--at={at}").into());
                }
                if let Some(v) = args.get("custody") {
                    let custody = bounded_text(Some(v), 8).map_err(bad_payload)?;
                    if !matches!(custody, "yes" | "no") {
                        return Err(bad_payload("custody must be yes or no"));
                    }
                    argv.push(format!("--custody={custody}").into());
                }
            }
            let view = if let Some(v) = args.get("view") {
                let name = bounded_text(Some(v), 32).map_err(bad_payload)?;
                let av = match name {
                    "decision_diff" => AgentView::DecisionDiff,
                    "forensic" => AgentView::Forensic,
                    _ => return Err(bad_payload("unsupported explain view")),
                };
                argv.push(format!("--view={name}").into());
                av
            } else {
                AgentView::DecisionDiff
            };
            if let Some(v) = args.get("budget_tokens") {
                let n = positive_u64(v, u64::from(view.maximum_tokens())).map_err(bad_payload)?;
                if req.budget.tokens > 0 && n > req.budget.tokens {
                    return Err(budget_exceeded(n));
                }
                argv.push(format!("--budget-tokens={n}").into());
            }
            argv.push(principal_flag());
            parse_fss_args(argv).map_err(|e| bad_payload(&e.to_string()))
        }
        AgentOperation::Handoff => {
            allow_only(args, &["session", "note"]).map_err(bad_payload)?;
            let session = resolve_session(true)?
                .ok_or_else(|| bad_payload("handoff requires session identifier"))?;
            let mut argv = base("handoff");
            argv.push(format!("--session={session}").into());
            if let Some(v) = args.get("note") {
                let note = bounded_text(Some(v), MAX_NOTE_BYTES).map_err(bad_payload)?;
                argv.push(format!("--note={note}").into());
            }
            argv.push(principal_flag());
            parse_fss_args(argv).map_err(|e| bad_payload(&e.to_string()))
        }
        AgentOperation::Feedback => {
            allow_only(
                args,
                &[
                    "session",
                    "target",
                    "kind",
                    "statement",
                    "supporting",
                    "contradicting",
                    "disposition",
                ],
            )
            .map_err(bad_payload)?;
            let session = resolve_session(true)?
                .ok_or_else(|| bad_payload("feedback requires session identifier"))?;
            let target = bounded_text(args.get("target"), 16_384).map_err(bad_payload)?;
            let kind = bounded_text(args.get("kind"), 64).map_err(bad_payload)?;
            let statement = bounded_text(args.get("statement"), 16_384).map_err(bad_payload)?;
            let supporting = parse_digest_array(args.get("supporting"), MAX_FEEDBACK_EVIDENCE)
                .map_err(bad_payload)?;
            let contradicting =
                parse_digest_array(args.get("contradicting"), MAX_FEEDBACK_EVIDENCE)
                    .map_err(bad_payload)?;
            let total = supporting.len() + contradicting.len();
            if !(1..=MAX_FEEDBACK_EVIDENCE).contains(&total) {
                return Err(bad_payload(
                    "feedback requires 1..=256 total evidence handles",
                ));
            }
            let root_str = authority
                .root
                .to_str()
                .ok_or_else(|| bad_payload("launcher root is not valid UTF-8"))?;
            let mut values = vec![
                "feedback".to_owned(),
                "--json".to_owned(),
                format!("--root={root_str}"),
                format!("--principal={}", authority.principal.as_str()),
                format!("--session={session}"),
                format!("--target={target}"),
                format!("--kind={kind}"),
                format!("--statement={statement}"),
            ];
            if let Some(v) = args.get("disposition") {
                let disp = bounded_text(Some(v), 64).map_err(bad_payload)?;
                values.push(format!("--disposition={disp}"));
            }
            for (flag, list) in [("supporting", supporting), ("contradicting", contradicting)] {
                if !list.is_empty() {
                    let joined = list
                        .iter()
                        .map(|d| d.to_text())
                        .collect::<Vec<_>>()
                        .join(",");
                    values.push(format!("--{flag}={joined}"));
                }
            }
            let tokens: Vec<ArgToken> = values
                .into_iter()
                .enumerate()
                .map(|(index, value)| ArgToken::new(index, value))
                .collect();
            parse_feedback_args(&tokens)
                .map(|fb| FssCommand::Feedback(Box::new(fb)))
                .map_err(|e| bad_payload(&e.to_string()))
        }
        AgentOperation::Doctor => {
            if !args.is_empty() {
                return Err(bad_payload(
                    "AOP-014 doctor payload must be an empty object (no scope overrides)",
                ));
            }
            let argv = base("doctor");
            parse_fss_args(argv).map_err(|e| bad_payload(&e.to_string()))
        }
    }
}

fn compile_query_payload<F>(
    authority: &DispatchAuthority,
    req: &ValidatedRequest,
    bad_payload: &F,
) -> Result<FssCommand, Box<RefusalSpec>>
where
    F: Fn(&str) -> Box<RefusalSpec>,
{
    let args = &req.payload_obj;
    let target = args.get("target").and_then(Value::text).unwrap_or("events");

    // Operational read targets (`cameras`, `graph`, `fusion`, `holds`, `privacy-masks`).
    if matches!(
        target,
        "cameras" | "graph" | "fusion" | "holds" | "privacy-masks"
    ) {
        let session_id = match (args.get("session"), req.session_id.as_ref()) {
            (Some(v), Some(env_s)) => {
                let s = bounded_text(Some(v), 128).map_err(bad_payload)?;
                let parsed = SessionId::parse(s).map_err(|_| bad_payload("invalid session id"))?;
                if parsed != *env_s {
                    return Err(bad_payload(
                        "payload.session conflicts with envelope.sessionId",
                    ));
                }
                Some(parsed)
            }
            (Some(v), None) => {
                let s = bounded_text(Some(v), 128).map_err(bad_payload)?;
                Some(SessionId::parse(s).map_err(|_| bad_payload("invalid session id"))?)
            }
            (None, Some(env_s)) => Some(env_s.clone()),
            (None, None) => None,
        };
        let grants = authority.granted_capabilities.clone();
        let dispatch = match target {
            "cameras" => {
                allow_only(args, &["target", "session", "camera_id", "site_id"])
                    .map_err(bad_payload)?;
                OpsDispatch::Cameras(CamerasQueryRequest {
                    root: authority.root.clone(),
                    principal: authority.principal.clone(),
                    session_id,
                    camera_id: optional_clean_text(args, "camera_id", 128).map_err(bad_payload)?,
                    site_id: optional_clean_text(args, "site_id", 128).map_err(bad_payload)?,
                    granted_capabilities: grants,
                })
            }
            "graph" => {
                allow_only(
                    args,
                    &["target", "session", "projection", "algorithm", "root_node"],
                )
                .map_err(bad_payload)?;
                let proj = optional_clean_text(args, "projection", 64)
                    .map_err(bad_payload)?
                    .unwrap_or_else(|| "SensorCoverageGraph".to_owned());
                let algo = optional_clean_text(args, "algorithm", 64)
                    .map_err(bad_payload)?
                    .unwrap_or_else(|| "ALG-BRIDGE-001".to_owned());
                OpsDispatch::Graph(GraphQueryRequest {
                    root: authority.root.clone(),
                    principal: authority.principal.clone(),
                    session_id,
                    projection: GraphProjectionKind::parse(&proj)
                        .map_err(|_| bad_payload("unsupported graph projection"))?,
                    algorithm: GraphAlgorithmKind::parse(&algo)
                        .map_err(|_| bad_payload("unsupported graph algorithm"))?,
                    root_node: optional_clean_text(args, "root_node", 128).map_err(bad_payload)?,
                    granted_capabilities: grants,
                })
            }
            "fusion" => {
                allow_only(
                    args,
                    &[
                        "target",
                        "session",
                        "event_id",
                        "evidence",
                        "prior_lo",
                        "prior_hi",
                        "coverage",
                        "alert_threshold",
                        "retain_threshold",
                        "reject_threshold",
                        "min_independent_support",
                        "without_sensors",
                        "without_domains",
                    ],
                )
                .map_err(bad_payload)?;
                let event_id = optional_clean_text(args, "event_id", 128)
                    .map_err(bad_payload)?
                    .map(|s| EventId::parse(s).map_err(|_| bad_payload("invalid event_id")))
                    .transpose()?;
                let evidence = match args.get("evidence") {
                    None => Vec::new(),
                    Some(Value::Array(items)) if items.len() <= 32 => items
                        .iter()
                        .map(parse_fusion_evidence_item)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(bad_payload)?,
                    _ => return Err(bad_payload("evidence must be <=32 objects")),
                };
                let prior_lo = optional_i64(args, "prior_lo", -100_000, 100_000)
                    .map_err(bad_payload)?
                    .unwrap_or(-500);
                let prior_hi = optional_i64(args, "prior_hi", -100_000, 100_000)
                    .map_err(bad_payload)?
                    .unwrap_or(-400);
                if prior_lo > prior_hi {
                    return Err(bad_payload("prior_lo must be <= prior_hi"));
                }
                OpsDispatch::Fusion(FusionQueryRequest {
                    root: authority.root.clone(),
                    principal: authority.principal.clone(),
                    session_id,
                    event_id,
                    evidence,
                    prior: (prior_lo, prior_hi),
                    coverage_state: optional_clean_text(args, "coverage", 32)
                        .map_err(bad_payload)?
                        .unwrap_or_else(|| "complete".to_owned()),
                    alert_threshold: optional_i64(args, "alert_threshold", -100_000, 100_000)
                        .map_err(bad_payload)?
                        .unwrap_or(1000),
                    retain_threshold: optional_i64(args, "retain_threshold", -100_000, 100_000)
                        .map_err(bad_payload)?
                        .unwrap_or(0),
                    reject_threshold: optional_i64(args, "reject_threshold", -100_000, 100_000)
                        .map_err(bad_payload)?
                        .unwrap_or(-1000),
                    min_independent_support: optional_u64_range(
                        args,
                        "min_independent_support",
                        1,
                        16,
                    )
                    .map_err(bad_payload)?
                    .unwrap_or(2) as u32,
                    without_sensors: optional_string_vec(args, "without_sensors", 16, 128)
                        .map_err(bad_payload)?,
                    without_domains: optional_string_vec(args, "without_domains", 16, 128)
                        .map_err(bad_payload)?,
                    granted_capabilities: grants,
                })
            }
            "holds" => {
                allow_only(
                    args,
                    &[
                        "target",
                        "session",
                        "sensor",
                        "attested_earliest_ns",
                        "attested_latest_ns",
                    ],
                )
                .map_err(bad_payload)?;
                let sensor = optional_clean_text(args, "sensor", 128)
                    .map_err(bad_payload)?
                    .map(|s| SensorId::parse(s).map_err(|_| bad_payload("invalid sensor")))
                    .transpose()?;
                let attested_now_ns =
                    parse_optional_interval(args, "attested_earliest_ns", "attested_latest_ns")
                        .map_err(bad_payload)?;
                OpsDispatch::Holds(HoldsQueryRequest {
                    root: authority.root.clone(),
                    principal: authority.principal.clone(),
                    session_id,
                    sensor,
                    attested_now_ns,
                    granted_capabilities: grants,
                })
            }
            "privacy-masks" => {
                allow_only(args, &["target", "session", "sensor"]).map_err(bad_payload)?;
                let sensor = optional_clean_text(args, "sensor", 128)
                    .map_err(bad_payload)?
                    .map(|s| SensorId::parse(s).map_err(|_| bad_payload("invalid sensor")))
                    .transpose()?;
                OpsDispatch::PrivacyMasks(PrivacyMasksQueryRequest {
                    root: authority.root.clone(),
                    principal: authority.principal.clone(),
                    session_id,
                    sensor,
                    granted_capabilities: grants,
                })
            }
            _ => return Err(bad_payload("unsupported operational query target")),
        };
        return Ok(FssCommand::Query(QueryArgs {
            root: authority.root.clone(),
            at: None,
            request: fss_reference::agent_query::EventQueryRequest {
                filter: fss_reference::agent_query::EventQueryFilter {
                    event_id: None,
                    kind: None,
                    state: None,
                    zone: None,
                    from_ns: None,
                    through_ns: None,
                },
                principal: authority.principal.clone(),
                max_entries: fss_reference::agent_query::DEFAULT_QUERY_ENTRIES,
                expected_anchor: None,
                continuation: None,
            },
            ops: Some(dispatch),
        }));
    }

    // Standard read-only targets: `events`, `footage`, `sources`, `reports`, `localizations`.
    let resolve_continuation = || -> Result<Option<String>, Box<RefusalSpec>> {
        match (args.get("continuation"), req.continuation.as_deref()) {
            (Some(v), Some(env_c)) => {
                let s = bounded_text(Some(v), 256).map_err(bad_payload)?;
                if s != env_c {
                    return Err(bad_payload(
                        "payload.continuation conflicts with envelope.continuation",
                    ));
                }
                Ok(Some(s.to_owned()))
            }
            (Some(v), None) => Ok(Some(
                bounded_text(Some(v), 256).map_err(bad_payload)?.to_owned(),
            )),
            (None, Some(env_c)) => Ok(Some(env_c.to_owned())),
            (None, None) => Ok(None),
        }
    };
    let mut argv: Vec<OsString> = vec![
        "query".into(),
        "--json".into(),
        "--root".into(),
        authority.root.as_os_str().to_owned(),
    ];
    match target {
        "events" | "footage" => {
            allow_only(
                args,
                &[
                    "target",
                    "sensor",
                    "stream",
                    "event_id",
                    "kind",
                    "state",
                    "zone",
                    "from_ns",
                    "through_ns",
                    "max_entries",
                    "anchor",
                    "at",
                    "continuation",
                ],
            )
            .map_err(bad_payload)?;
            for (key, flag, bound) in [
                ("target", "target", 16),
                ("sensor", "sensor", 128),
                ("stream", "stream", 128),
                ("event_id", "event-id", 128),
                ("kind", "kind", 64),
                ("state", "state", 64),
                ("zone", "zone", 64),
                ("from_ns", "from-ns", 40),
                ("through_ns", "through-ns", 40),
                ("anchor", "anchor", 256),
                ("at", "at", 256),
            ] {
                if let Some(v) = args.get(key) {
                    let s = bounded_text(Some(v), bound).map_err(bad_payload)?;
                    argv.push(format!("--{flag}={s}").into());
                }
            }
            if let Some(cont) = resolve_continuation()? {
                argv.push(format!("--continuation={cont}").into());
            }
            if let Some(v) = args.get("max_entries") {
                let n = positive_u64(v, u64::from(fss_reference::agent_query::MAX_QUERY_ENTRIES))
                    .map_err(bad_payload)?;
                argv.push(format!("--max-entries={n}").into());
            }
        }
        "sources" => {
            allow_only(
                args,
                &[
                    "target",
                    "sensor",
                    "stream",
                    "max_entries",
                    "anchor",
                    "continuation",
                ],
            )
            .map_err(bad_payload)?;
            argv.push("--target=sources".into());
            for (key, flag, bound) in [
                ("sensor", "sensor", 128),
                ("stream", "stream", 128),
                ("anchor", "anchor", 256),
            ] {
                if let Some(v) = args.get(key) {
                    let s = bounded_text(Some(v), bound).map_err(bad_payload)?;
                    argv.push(format!("--{flag}={s}").into());
                }
            }
            if let Some(cont) = resolve_continuation()? {
                argv.push(format!("--continuation={cont}").into());
            }
            if let Some(v) = args.get("max_entries") {
                let n = positive_u64(v, MAX_PAGE_ENTRIES).map_err(bad_payload)?;
                argv.push(format!("--max-entries={n}").into());
            }
        }
        "reports" => {
            allow_only(
                args,
                &[
                    "target",
                    "family",
                    "from_ns",
                    "through_ns",
                    "max_entries",
                    "anchor",
                    "continuation",
                ],
            )
            .map_err(bad_payload)?;
            argv.push("--target=reports".into());
            for (key, flag, bound) in [
                ("family", "family", 64),
                ("from_ns", "from-ns", 40),
                ("through_ns", "through-ns", 40),
                ("anchor", "anchor", 256),
            ] {
                if let Some(v) = args.get(key) {
                    let s = bounded_text(Some(v), bound).map_err(bad_payload)?;
                    argv.push(format!("--{flag}={s}").into());
                }
            }
            if let Some(cont) = resolve_continuation()? {
                argv.push(format!("--continuation={cont}").into());
            }
            if let Some(v) = args.get("max_entries") {
                let n = positive_u64(v, MAX_PAGE_ENTRIES).map_err(bad_payload)?;
                argv.push(format!("--max-entries={n}").into());
            }
        }
        "localizations" => {
            allow_only(
                args,
                &[
                    "target",
                    "sensor",
                    "stream",
                    "import_id",
                    "twin_digest",
                    "max_entries",
                    "anchor",
                    "continuation",
                ],
            )
            .map_err(bad_payload)?;
            argv.push("--target=localizations".into());
            for (key, flag, bound) in [
                ("sensor", "sensor", 128),
                ("stream", "stream", 128),
                ("import_id", "import-id", 71),
                ("twin_digest", "twin-digest", 71),
                ("anchor", "anchor", 256),
            ] {
                if let Some(v) = args.get(key) {
                    let s = bounded_text(Some(v), bound).map_err(bad_payload)?;
                    argv.push(format!("--{flag}={s}").into());
                }
            }
            if let Some(cont) = resolve_continuation()? {
                argv.push(format!("--continuation={cont}").into());
            }
            if let Some(v) = args.get("max_entries") {
                let n = positive_u64(v, MAX_PAGE_ENTRIES).map_err(bad_payload)?;
                argv.push(format!("--max-entries={n}").into());
            }
        }
        _ => return Err(bad_payload("unsupported query target")),
    }
    argv.push(format!("--principal={}", authority.principal.as_str()).into());
    parse_fss_args(argv).map_err(|e| bad_payload(&e.to_string()))
}

fn compile_investigate_payload<F>(
    authority: &DispatchAuthority,
    req: &ValidatedRequest,
    session_opt: Option<String>,
    bad_payload: &F,
) -> Result<FssCommand, Box<RefusalSpec>>
where
    F: Fn(&str) -> Box<RefusalSpec>,
{
    let args = &req.payload_obj;
    let session_str =
        session_opt.ok_or_else(|| bad_payload("investigate requires session identifier"))?;
    let session = SessionId::parse(session_str).map_err(|_| bad_payload("invalid session id"))?;
    let transition = bounded_text(args.get("transition"), 32).map_err(bad_payload)?;

    let allow_inv = |extra: &[&str]| -> Result<(), Box<RefusalSpec>> {
        if args
            .keys()
            .all(|k| matches!(k.as_str(), "session" | "transition") || extra.contains(&k.as_str()))
        {
            Ok(())
        } else {
            Err(bad_payload("unexpected investigate payload field"))
        }
    };
    let req_id_field = |key: &str| -> Result<String, Box<RefusalSpec>> {
        let s = bounded_text(args.get(key), 128).map_err(bad_payload)?;
        validate_id(s).map_err(|_| bad_payload("invalid identifier in investigate payload"))?;
        Ok(s.to_owned())
    };
    let req_digest = |key: &str| -> Result<ContentDigest, Box<RefusalSpec>> {
        let s = bounded_text(args.get(key), 71).map_err(bad_payload)?;
        ContentDigest::parse(s).map_err(|_| bad_payload("invalid sha256 digest"))
    };

    // Work claims (`claim`, `claim-*`).
    if transition == "claim" || transition.starts_with("claim-") {
        let lease_ms_fn = || -> Result<u64, Box<RefusalSpec>> {
            match args.get("lease_ms") {
                None => Ok(DEFAULT_LEASE_MS),
                Some(v) => positive_u64(v, MAX_LEASE_MS).map_err(bad_payload),
            }
        };
        let action = match transition {
            "claim" => {
                allow_inv(&["case", "work", "lease_ms", "depends"])?;
                let work_raw = bounded_text(args.get("work"), 270).map_err(bad_payload)?;
                let work = match work_raw.split_once(':') {
                    None if work_raw == "case" => ClaimWork::Case,
                    Some(("hypothesis", id)) if !id.is_empty() && id.len() <= 256 => {
                        ClaimWork::Hypothesis(id.to_owned())
                    }
                    Some(("discriminator", id)) if !id.is_empty() && id.len() <= 256 => {
                        ClaimWork::Discriminator(id.to_owned())
                    }
                    Some(("probe", id)) if !id.is_empty() && id.len() <= 256 => {
                        ClaimWork::Probe(id.to_owned())
                    }
                    _ => return Err(bad_payload("invalid claim work scope")),
                };
                let depends = parse_id_array(args.get("depends"), MAX_CLAIM_DEPENDENCIES)
                    .map_err(bad_payload)?;
                ClaimAction::Acquire {
                    case_id: req_id_field("case")?,
                    work,
                    lease_ms: lease_ms_fn()?,
                    dependencies: depends.into_iter().collect(),
                }
            }
            "claim-inspect" => {
                allow_inv(&["claim"])?;
                ClaimAction::Inspect {
                    claim_id: req_id_field("claim")?,
                }
            }
            "claim-list" => {
                allow_inv(&[])?;
                ClaimAction::List
            }
            "claim-activate" => {
                allow_inv(&["claim", "expected"])?;
                ClaimAction::Change {
                    claim_id: req_id_field("claim")?,
                    expected: req_digest("expected")?,
                    change: ClaimChange::Activate,
                }
            }
            "claim-progress" => {
                allow_inv(&["claim", "expected", "artifact"])?;
                ClaimAction::Change {
                    claim_id: req_id_field("claim")?,
                    expected: req_digest("expected")?,
                    change: ClaimChange::Progress(req_digest("artifact")?),
                }
            }
            "claim-block" => {
                allow_inv(&["claim", "expected", "artifact"])?;
                ClaimAction::Change {
                    claim_id: req_id_field("claim")?,
                    expected: req_digest("expected")?,
                    change: ClaimChange::Block(req_digest("artifact")?),
                }
            }
            "claim-complete" => {
                allow_inv(&["claim", "expected", "result"])?;
                ClaimAction::Change {
                    claim_id: req_id_field("claim")?,
                    expected: req_digest("expected")?,
                    change: ClaimChange::Complete(req_digest("result")?),
                }
            }
            "claim-release" => {
                allow_inv(&["claim", "expected"])?;
                ClaimAction::Change {
                    claim_id: req_id_field("claim")?,
                    expected: req_digest("expected")?,
                    change: ClaimChange::Release,
                }
            }
            "claim-renew" => {
                allow_inv(&["claim", "expected", "lease_ms"])?;
                ClaimAction::Change {
                    claim_id: req_id_field("claim")?,
                    expected: req_digest("expected")?,
                    change: ClaimChange::Renew {
                        lease_ms: lease_ms_fn()?,
                    },
                }
            }
            "claim-expire" => {
                allow_inv(&["claim", "expected"])?;
                ClaimAction::Recover {
                    claim_id: req_id_field("claim")?,
                    expected: req_digest("expected")?,
                    recovery: ClaimRecovery::Expire,
                }
            }
            "claim-transfer" => {
                allow_inv(&["claim", "expected", "recipient"])?;
                let recipient = SessionId::parse(req_id_field("recipient")?)
                    .map_err(|_| bad_payload("invalid recipient session id"))?;
                ClaimAction::Recover {
                    claim_id: req_id_field("claim")?,
                    expected: req_digest("expected")?,
                    recovery: ClaimRecovery::Transfer(recipient),
                }
            }
            "claim-reclaim" => {
                allow_inv(&["claim", "expected", "lease_ms"])?;
                ClaimAction::Recover {
                    claim_id: req_id_field("claim")?,
                    expected: req_digest("expected")?,
                    recovery: ClaimRecovery::Reclaim {
                        lease_ms: lease_ms_fn()?,
                    },
                }
            }
            _ => return Err(bad_payload("unsupported claim transition")),
        };
        return Ok(FssCommand::Claim(Box::new(ClaimArgs {
            root: authority.root.clone(),
            request: ClaimRequest {
                session_id: session,
                principal: authority.principal.clone(),
                action,
            },
        })));
    }

    // Shared findings (`finding`, `finding-withdraw`, `finding-list`).
    if transition == "finding" || transition.starts_with("finding-") {
        let action = match transition {
            "finding" => {
                allow_inv(&[
                    "case",
                    "claim",
                    "state",
                    "supporting",
                    "contradicting",
                    "hypothesis",
                    "follow_up",
                    "disagrees_with",
                    "supersedes",
                ])?;
                let supporting = parse_digest_array(args.get("supporting"), MAX_FINDING_EVIDENCE)
                    .map_err(bad_payload)?;
                if supporting.is_empty() {
                    return Err(bad_payload("finding requires at least 1 supporting digest"));
                }
                let contradicting =
                    parse_digest_array(args.get("contradicting"), MAX_FINDING_EVIDENCE)
                        .map_err(bad_payload)?;
                let state = bounded_text(args.get("state"), 32)
                    .map_err(bad_payload)?
                    .parse::<KnowledgeState>()
                    .map_err(|_| bad_payload("invalid KnowledgeState in finding"))?;
                let hypothesis_id = args
                    .contains_key("hypothesis")
                    .then(|| req_id_field("hypothesis"))
                    .transpose()?;
                let supersedes = args
                    .contains_key("supersedes")
                    .then(|| req_id_field("supersedes"))
                    .transpose()?;
                FindingAction::Publish(FindingDraft {
                    case_id: req_id_field("case")?,
                    hypothesis_id,
                    claim: bounded_text(args.get("claim"), MAX_FINDING_CLAIM_BYTES)
                        .map_err(bad_payload)?
                        .to_owned(),
                    epistemic_state: state,
                    supporting: supporting.iter().map(|d| d.to_text()).collect(),
                    contradicting: contradicting.iter().map(|d| d.to_text()).collect(),
                    follow_up: parse_id_array(args.get("follow_up"), MAX_FINDING_LINKS)
                        .map_err(bad_payload)?,
                    disagrees_with: parse_id_array(args.get("disagrees_with"), MAX_FINDING_LINKS)
                        .map_err(bad_payload)?,
                    supersedes,
                })
            }
            "finding-withdraw" => {
                allow_inv(&["finding", "claim", "supporting"])?;
                let supporting = parse_digest_array(args.get("supporting"), MAX_FINDING_EVIDENCE)
                    .map_err(bad_payload)?;
                if supporting.is_empty() {
                    return Err(bad_payload(
                        "finding-withdraw requires at least 1 supporting digest",
                    ));
                }
                FindingAction::Withdraw {
                    finding_id: req_id_field("finding")?,
                    claim: bounded_text(args.get("claim"), MAX_FINDING_CLAIM_BYTES)
                        .map_err(bad_payload)?
                        .to_owned(),
                    supporting: supporting.iter().map(|d| d.to_text()).collect(),
                }
            }
            "finding-list" => {
                allow_inv(&["case"])?;
                let case_id = args
                    .contains_key("case")
                    .then(|| req_id_field("case"))
                    .transpose()?;
                FindingAction::List { case_id }
            }
            _ => return Err(bad_payload("unsupported finding transition")),
        };
        return Ok(FssCommand::Finding(Box::new(FindingArgs {
            root: authority.root.clone(),
            request: FindingRequest {
                session_id: session,
                principal: authority.principal.clone(),
                action,
            },
        })));
    }

    // Core case transitions (`open`, `expand`, `inspect`, `list`, `rebase`, `readmit`,
    // `activate`, `cite`, `assess`, `set-state`, `conclude`).
    let action = match transition {
        "open" => {
            allow_inv(&["draft"])?;
            let draft_val = args
                .get("draft")
                .ok_or_else(|| bad_payload("investigate open requires draft object"))?;
            let draft = decode_case_draft(draft_val).map_err(|e| bad_payload(&e.to_string()))?;
            CaseAction::Open(Box::new(draft))
        }
        "expand" => {
            allow_inv(&["case", "expected", "expansion"])?;
            let exp_val = args
                .get("expansion")
                .ok_or_else(|| bad_payload("investigate expand requires expansion object"))?;
            let (hypothesis, discriminator, probe) =
                decode_expansion(exp_val).map_err(|e| bad_payload(&e.to_string()))?;
            CaseAction::Expand {
                case_id: req_id_field("case")?,
                expected: req_digest("expected")?,
                hypothesis: Box::new(hypothesis),
                discriminator: Box::new(discriminator),
                probe,
            }
        }
        "inspect" => {
            allow_inv(&["case", "revision"])?;
            CaseAction::Inspect {
                case_id: req_id_field("case")?,
                revision: args
                    .contains_key("revision")
                    .then(|| req_digest("revision"))
                    .transpose()?,
            }
        }
        "list" => {
            allow_inv(&[])?;
            CaseAction::List
        }
        "rebase" => {
            allow_inv(&["case", "expected"])?;
            CaseAction::Rebase {
                case_id: req_id_field("case")?,
                expected: req_digest("expected")?,
            }
        }
        "readmit" => {
            allow_inv(&[
                "case",
                "expected",
                "hypothesis",
                "evidence",
                "side",
                "witness",
            ])?;
            let contradicts = match bounded_text(args.get("side"), 32).map_err(bad_payload)? {
                "support" => false,
                "contradiction" => true,
                _ => return Err(bad_payload("side must be support or contradiction")),
            };
            CaseAction::Readmit {
                case_id: req_id_field("case")?,
                expected: req_digest("expected")?,
                citation: InvestigationCitation {
                    hypothesis: req_id_field("hypothesis")?,
                    evidence: req_digest("evidence")?,
                    contradicts,
                },
                witness: req_digest("witness")?,
            }
        }
        "activate" => {
            allow_inv(&["case", "expected"])?;
            CaseAction::Change {
                case_id: req_id_field("case")?,
                expected: req_digest("expected")?,
                change: InvestigationChange::Activate,
            }
        }
        "cite" => {
            allow_inv(&["case", "expected", "hypothesis", "evidence", "side"])?;
            let contradicts = match bounded_text(args.get("side"), 32).map_err(bad_payload)? {
                "support" => false,
                "contradiction" => true,
                _ => return Err(bad_payload("side must be support or contradiction")),
            };
            CaseAction::Change {
                case_id: req_id_field("case")?,
                expected: req_digest("expected")?,
                change: InvestigationChange::Cite {
                    hypothesis: req_id_field("hypothesis")?,
                    evidence: req_digest("evidence")?,
                    contradicts,
                },
            }
        }
        "assess" => {
            allow_inv(&["case", "expected", "hypothesis", "disposition", "evidence"])?;
            let disposition =
                match bounded_text(args.get("disposition"), 32).map_err(bad_payload)? {
                    "supported" => HypothesisDisposition::Supported,
                    "disfavored" => HypothesisDisposition::Disfavored,
                    "refuted" => HypothesisDisposition::Refuted,
                    _ => return Err(bad_payload("unsupported hypothesis disposition")),
                };
            CaseAction::Change {
                case_id: req_id_field("case")?,
                expected: req_digest("expected")?,
                change: InvestigationChange::Assess {
                    hypothesis: req_id_field("hypothesis")?,
                    disposition,
                    evidence: req_digest("evidence")?,
                },
            }
        }
        "set-state" => {
            allow_inv(&["case", "expected", "state", "reason"])?;
            let state = match bounded_text(args.get("state"), 32).map_err(bad_payload)? {
                "awaiting_evidence" => InvestigationLifecycle::AwaitingEvidence,
                "awaiting_approval" => InvestigationLifecycle::AwaitingApproval,
                "blocked" => InvestigationLifecycle::Blocked,
                "indeterminate" => InvestigationLifecycle::Indeterminate,
                "cancelled" => InvestigationLifecycle::Cancelled,
                "closed" => InvestigationLifecycle::Closed,
                _ => return Err(bad_payload("unsupported investigation lifecycle state")),
            };
            CaseAction::Change {
                case_id: req_id_field("case")?,
                expected: req_digest("expected")?,
                change: InvestigationChange::SetState {
                    state,
                    reason: req_digest("reason")?,
                },
            }
        }
        "conclude" => {
            allow_inv(&[
                "case",
                "expected",
                "conclusion",
                "stop_rule",
                "assessment",
                "residual_unknowns",
            ])?;
            let refuted = match bounded_text(args.get("conclusion"), 32).map_err(bad_payload)? {
                "resolved" => false,
                "refuted" => true,
                _ => return Err(bad_payload("conclusion must be resolved or refuted")),
            };
            let residual_unknowns = parse_id_array(args.get("residual_unknowns"), MAX_RESIDUALS)
                .map_err(bad_payload)?
                .into_iter()
                .collect();
            CaseAction::Change {
                case_id: req_id_field("case")?,
                expected: req_digest("expected")?,
                change: InvestigationChange::Conclude {
                    refuted,
                    stop_rule: bounded_text(args.get("stop_rule"), 1024)
                        .map_err(bad_payload)?
                        .to_owned(),
                    assessment: req_digest("assessment")?,
                    residual_unknowns,
                },
            }
        }
        _ => return Err(bad_payload("unsupported investigate transition")),
    };

    Ok(FssCommand::Investigate(Box::new(InvestigateArgs {
        root: authority.root.clone(),
        session,
        principal: authority.principal.clone(),
        action,
    })))
}

fn compile_plan_payload<F>(
    authority: &DispatchAuthority,
    req: &ValidatedRequest,
    session_opt: Option<String>,
    bad_payload: &F,
) -> Result<FssCommand, Box<RefusalSpec>>
where
    F: Fn(&str) -> Box<RefusalSpec>,
{
    let args = &req.payload_obj;
    let intent = bounded_text(args.get("intent"), 32).map_err(bad_payload)?;
    let mut argv: Vec<OsString> = vec![
        "plan".into(),
        "--json".into(),
        "--root".into(),
        authority.root.as_os_str().to_owned(),
        format!("--principal={}", authority.principal.as_str()).into(),
    ];
    match intent {
        "alert" => {
            allow_only(
                args,
                &[
                    "intent",
                    "session",
                    "event_id",
                    "relay",
                    "path",
                    "plaintext_approval",
                    "disclosure_profile",
                    "metadata_approval",
                    "deadline_ms",
                    "case",
                    "approve",
                ],
            )
            .map_err(bad_payload)?;
            let session =
                session_opt.ok_or_else(|| bad_payload("plan alert requires session id"))?;
            argv.push("--intent=alert".into());
            argv.push(format!("--session={session}").into());
            for (key, flag, max_len) in [
                ("event_id", "--event-id", 128),
                ("relay", "--relay", 128),
                ("path", "--path", 4096),
                ("plaintext_approval", "--plaintext-approval", 71),
            ] {
                let val = bounded_text(args.get(key), max_len).map_err(bad_payload)?;
                argv.push(format!("{flag}={val}").into());
            }
            for (key, flag, max_len) in [
                ("disclosure_profile", "--disclosure-profile", 32),
                ("metadata_approval", "--metadata-approval", 71),
                ("case", "--case", 128),
                ("approve", "--approve", 71),
            ] {
                if let Some(v) = args.get(key) {
                    let s = bounded_text(Some(v), max_len).map_err(bad_payload)?;
                    argv.push(format!("{flag}={s}").into());
                }
            }
            let deadline = positive_u64(
                args.get("deadline_ms")
                    .ok_or_else(|| bad_payload("plan alert requires deadline_ms"))?,
                crate::alert_effect::MAX_DEADLINE_MS,
            )
            .map_err(bad_payload)?;
            argv.push(format!("--deadline-ms={deadline}").into());
        }
        "close" => {
            allow_only(args, &["intent", "session", "plan"]).map_err(bad_payload)?;
            let session =
                session_opt.ok_or_else(|| bad_payload("plan close requires session id"))?;
            let plan = bounded_text(args.get("plan"), 128).map_err(bad_payload)?;
            argv.push(format!("--session={session}").into());
            argv.push(format!("--close={plan}").into());
        }
        "mission-bind" => {
            allow_only(args, &["intent", "session", "plan", "decision_deadline_ns"])
                .map_err(bad_payload)?;
            let session =
                session_opt.ok_or_else(|| bad_payload("plan mission-bind requires session id"))?;
            let plan = bounded_text(args.get("plan"), 128).map_err(bad_payload)?;
            let dl_raw = match args.get("decision_deadline_ns") {
                Some(Value::Number(s)) | Some(Value::Text(s)) => s.as_str(),
                _ => return Err(bad_payload("mission-bind requires decision_deadline_ns")),
            };
            let dl = dl_raw
                .parse::<i128>()
                .ok()
                .filter(|v| *v > 0 && v.to_string() == dl_raw)
                .ok_or_else(|| bad_payload("decision_deadline_ns must be positive i128"))?;
            argv.push(format!("--session={session}").into());
            argv.push(format!("--mission-bind={plan}").into());
            argv.push(format!("--mission-deadline-ns={dl}").into());
        }
        "mission-assess" => {
            allow_only(args, &["intent", "session", "plan", "expected_mission"])
                .map_err(bad_payload)?;
            let session = session_opt
                .ok_or_else(|| bad_payload("plan mission-assess requires session id"))?;
            let plan = bounded_text(args.get("plan"), 128).map_err(bad_payload)?;
            let expected = bounded_text(args.get("expected_mission"), 71).map_err(bad_payload)?;
            argv.push(format!("--session={session}").into());
            argv.push(format!("--mission-assess={plan}").into());
            argv.push(format!("--expected-mission={expected}").into());
        }
        _ => return Err(bad_payload("unsupported plan intent")),
    }
    let command = parse_fss_args(argv).map_err(|e| bad_payload(&e.to_string()))?;
    match &command {
        FssCommand::Effect(eff)
            if matches!(
                eff.as_ref(),
                EffectCommand::Plan(_) | EffectCommand::Close(_) | EffectCommand::Mission(_)
            ) =>
        {
            Ok(command)
        }
        _ => Err(bad_payload("plan payload did not compile to native plan")),
    }
}

fn compile_commit_payload<F>(
    authority: &DispatchAuthority,
    req: &ValidatedRequest,
    bad_payload: &F,
) -> Result<FssCommand, Box<RefusalSpec>>
where
    F: Fn(&str) -> Box<RefusalSpec>,
{
    let args = &req.payload_obj;
    let intent = bounded_text(args.get("intent"), 32).map_err(bad_payload)?;
    let mut argv: Vec<OsString> = vec![
        "commit".into(),
        "--json".into(),
        "--root".into(),
        authority.root.as_os_str().to_owned(),
        format!("--principal={}", authority.principal.as_str()).into(),
    ];
    match intent {
        "dispatch" => {
            allow_only(args, &["intent", "plan", "approve"]).map_err(bad_payload)?;
            let plan = bounded_text(args.get("plan"), 128).map_err(bad_payload)?;
            let approve = bounded_text(args.get("approve"), 71).map_err(bad_payload)?;
            argv.push(format!("--plan={plan}").into());
            argv.push(format!("--approve={approve}").into());
        }
        "reconcile" => {
            allow_only(
                args,
                &[
                    "intent",
                    "operation_id",
                    "outcome",
                    "evidence",
                    "statement",
                    "approve",
                ],
            )
            .map_err(bad_payload)?;
            let outcome = bounded_text(args.get("outcome"), 32).map_err(bad_payload)?;
            if !matches!(outcome, "delivered" | "not_delivered") {
                return Err(bad_payload(
                    "reconcile outcome must be delivered or not_delivered",
                ));
            }
            let op_id = bounded_text(args.get("operation_id"), 128).map_err(bad_payload)?;
            let evidence = bounded_text(args.get("evidence"), 71).map_err(bad_payload)?;
            let statement = bounded_text(args.get("statement"), MAX_RECONCILE_STATEMENT_BYTES)
                .map_err(bad_payload)?;
            argv.push(format!("--reconcile={outcome}").into());
            argv.push(format!("--operation={op_id}").into());
            argv.push(format!("--evidence={evidence}").into());
            argv.push(format!("--statement={statement}").into());
            if let Some(v) = args.get("approve") {
                let approve = bounded_text(Some(v), 71).map_err(bad_payload)?;
                argv.push(format!("--approve={approve}").into());
            }
        }
        _ => return Err(bad_payload("unsupported commit intent")),
    }
    let command = parse_fss_args(argv).map_err(|e| bad_payload(&e.to_string()))?;
    match &command {
        FssCommand::Effect(eff)
            if matches!(
                eff.as_ref(),
                EffectCommand::Commit(_) | EffectCommand::Reconcile(_)
            ) =>
        {
            Ok(command)
        }
        _ => Err(bad_payload(
            "commit payload did not compile to native commit",
        )),
    }
}

fn build_refusal_outcome(authority: &DispatchAuthority, spec: RefusalSpec) -> DispatchOutcome {
    let basis = authority.server_basis.clone();
    let payload_schema = spec
        .operation
        .response_payload_schemas_for_basis(&basis)
        .and_then(|list| list.first().copied())
        .unwrap_or(fss_core::AgentCognitiveEnvelope::SCHEMA);
    let anchor = LedgerAnchor::genesis("site:envelope-dispatch");
    let privacy = agent_json::PrivacyProjection {
        purpose: "payload-free universal envelope refusal".to_owned(),
        policy_generation_id: "privacy-epoch:0".to_owned(),
        visible_domains: Vec::new(),
        redacted_domains: vec!["media-payloads".to_owned()],
    };
    let budgets_json = agent_json::budget_summary(&BudgetVector::ZERO, &BudgetVector::ZERO);
    let payload_json = "null".to_owned();
    let payload_digest = ContentDigest::sha256(payload_json.as_bytes());
    let mut fp_enc = CanonicalEncoder::new();
    fp_enc.text(DISPATCH_REFUSAL_HASH_TAG);
    fp_enc.text(spec.operation.id());
    fp_enc.text(spec.error_id);
    fp_enc.digest(spec.request_digest);
    let decision_fingerprint = ContentDigest::sha256(&fp_enc.finish());
    let trace_id = format!("trace:dispatch-refusal:{}", spec.request_digest.to_text());
    let trace_id_bounded = if trace_id.len() <= 256 {
        trace_id
    } else {
        trace_id[..256].to_owned()
    };
    let req_id_bounded = if validate_id(&spec.request_id).is_ok() && spec.request_id.len() <= 256 {
        spec.request_id.clone()
    } else {
        "request:malformed".to_owned()
    };

    let boundary = ExecutionBoundary {
        completed: Vec::new(),
        not_started: vec![spec.operation.name().to_owned()],
        possibly_occurred: Vec::new(),
        preserved_truth: vec![
            "No authority, cognition, or effect state was mutated by this refusal.".to_owned(),
        ],
        invalidated: Vec::new(),
    };

    let envelope = AgentResponseEnvelope::new(
        basis.clone(),
        spec.operation.name(),
        req_id_bounded.clone(),
        1,
        authority.principal.as_str(),
        spec.session_id,
        spec.mission_id,
        trace_id_bounded,
        anchor,
        None,
        None,
        spec.view,
        Vec::new(),
        privacy.envelope_json(),
        spec.outcome,
        None,
        Some(ResponseTaskState::None),
        Some(spec.error_id.to_owned()),
        payload_schema,
        payload_json,
        payload_digest,
        KnowledgeState::Unknown,
        spec.completeness,
        vec![sanitize_and_truncate(&spec.detail, 320)],
        Vec::new(),
        vec![sanitize_and_truncate(&spec.remediation, 320)],
        budgets_json,
        Vec::new(),
        Vec::new(),
        decision_fingerprint,
        None,
        None,
        None,
        None,
        spec.recovery_class,
        spec.safe_retry,
        spec.resnapshot_required,
        boundary,
        0,
    );

    let response_json = match envelope
        .ok()
        .and_then(|env| agent_json::response_envelope(&env, &[]))
    {
        Some(rendered) => rendered,
        None => {
            // Defensive fallback that still preserves schema-safe JSON and registered errorId.
            object(&[
                ("schema", string(AgentResponseEnvelope::SCHEMA)),
                ("contractBasis", agent_json::contract_basis(&basis)),
                ("operationId", string(spec.operation.id())),
                ("requestId", string(&req_id_bounded)),
                ("principalId", string(authority.principal.as_str())),
                ("outcome", string(spec.outcome.as_str())),
                ("errorId", string(spec.error_id)),
                ("payloadSchema", string(payload_schema)),
                ("payload", "null".to_owned()),
                ("payloadDigest", string(&payload_digest.to_text())),
                (
                    "decisionFingerprint",
                    string(&decision_fingerprint.to_text()),
                ),
                (
                    "warnings",
                    array(&[string(&sanitize_and_truncate(&spec.detail, 240))]),
                ),
            ])
        }
    };

    let response_digest = ContentDigest::sha256(response_json.as_bytes());
    let receipt = build_dispatch_receipt(
        spec.operation.id(),
        spec.operation.name(),
        &req_id_bounded,
        &spec.request_payload_schema,
        AgentResponseEnvelope::SCHEMA,
        Some(payload_schema.to_owned()),
        spec.outcome.as_str(),
        Some(spec.error_id.to_owned()),
        basis.basis_digest(),
        spec.request_digest,
        response_digest,
        spec.tainted,
    );
    DispatchOutcome {
        response_json,
        exit_identity: ExitIdentity::AGENT_REFUSED,
        receipt,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_dispatch_receipt(
    operation_id: &str,
    operation_name: &str,
    request_id: &str,
    request_payload_schema: &str,
    response_schema: &str,
    response_payload_schema: Option<String>,
    outcome: &str,
    error_id: Option<String>,
    contract_basis_digest: ContentDigest,
    request_digest: ContentDigest,
    response_digest: ContentDigest,
    tainted: bool,
) -> DispatchReceipt {
    let mut enc = CanonicalEncoder::new();
    enc.text(DISPATCH_RECEIPT_HASH_TAG);
    enc.text(operation_id);
    enc.text(operation_name);
    enc.text(request_id);
    enc.text(request_payload_schema);
    enc.text(response_schema);
    enc.text(response_payload_schema.as_deref().unwrap_or("<none>"));
    enc.text(outcome);
    enc.text(error_id.as_deref().unwrap_or("<none>"));
    enc.digest(contract_basis_digest);
    enc.digest(request_digest);
    enc.digest(response_digest);
    enc.bool(tainted);
    enc.bool(false); // grants_effect_authority is always false
    let receipt_digest = ContentDigest::sha256(&enc.finish());
    DispatchReceipt {
        operation_id: operation_id.to_owned(),
        operation_name: operation_name.to_owned(),
        request_id: request_id.to_owned(),
        request_payload_schema: request_payload_schema.to_owned(),
        response_schema: response_schema.to_owned(),
        response_payload_schema,
        outcome: outcome.to_owned(),
        error_id,
        contract_basis_digest,
        request_digest,
        response_digest,
        tainted,
        grants_effect_authority: false,
        receipt_digest,
    }
}

// ---------------------------------------------------------------------------
// Strict bounded JSON parsers for ContractBasis, EvidenceAnchor, Budget, Privacy, Taint
// ---------------------------------------------------------------------------

fn parse_contract_basis_json(val: Option<&Value>) -> Result<ContractBasis, String> {
    let obj = val
        .and_then(Value::object)
        .ok_or_else(|| "`contractBasis` must be a JSON object".to_owned())?;
    const REQUIRED: &[&str] = &[
        "schema",
        "semanticProtocol",
        "schemaCatalogDigest",
        "ontologyGenerationId",
        "operationRegistryDigest",
        "viewRegistryDigest",
        "capabilityRegistryDigest",
        "errorRegistryDigest",
        "costRegistryDigest",
        "producerReleaseId",
    ];
    const ALLOWED: &[&str] = &[
        "schema",
        "semanticProtocol",
        "schemaCatalogDigest",
        "ontologyGenerationId",
        "operationRegistryDigest",
        "viewRegistryDigest",
        "capabilityRegistryDigest",
        "errorRegistryDigest",
        "costRegistryDigest",
        "producerReleaseId",
        "acceptedNightly",
        "compatibilityNotes",
    ];
    for key in obj.keys() {
        if !ALLOWED.contains(&key.as_str()) {
            return Err(format!("unexpected contractBasis field `{key}`"));
        }
    }
    for req in REQUIRED {
        if !obj.contains_key(*req) {
            return Err(format!("missing required contractBasis field `{req}`"));
        }
    }
    let schema = obj
        .get("schema")
        .and_then(Value::text)
        .ok_or_else(|| "contractBasis.schema must be a string".to_owned())?;
    if schema != "fss.agent_contract_basis.v1" {
        return Err(format!(
            "contractBasis.schema `{schema}` != `fss.agent_contract_basis.v1`"
        ));
    }
    let req_str = |key: &str| -> Result<String, String> {
        obj.get(key)
            .and_then(Value::text)
            .filter(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control))
            .map(str::to_owned)
            .ok_or_else(|| format!("contractBasis.{key} must be a 1..=256 control-free string"))
    };
    let req_digest = |key: &str| -> Result<ContentDigest, String> {
        let s = req_str(key)?;
        ContentDigest::parse(&s).map_err(|_| format!("contractBasis.{key} is not a valid digest"))
    };
    let accepted_nightly = match obj.get("acceptedNightly") {
        None | Some(Value::Null) => None,
        Some(Value::Text(s))
            if !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control) =>
        {
            Some(s.clone())
        }
        Some(_) => {
            return Err(
                "contractBasis.acceptedNightly must be 1..=128 control-free string or null"
                    .to_owned(),
            );
        }
    };
    if let Some(notes) = obj.get("compatibilityNotes") {
        let arr = notes
            .array()
            .ok_or_else(|| "contractBasis.compatibilityNotes must be an array".to_owned())?;
        if arr.len() > 64 {
            return Err("contractBasis.compatibilityNotes exceeds 64 items".to_owned());
        }
        for item in arr {
            if item
                .text()
                .is_none_or(|s| s.is_empty() || s.len() > 1024 || s.chars().any(char::is_control))
            {
                return Err(
                    "contractBasis.compatibilityNotes items must be 1..=1024 control-free strings"
                        .to_owned(),
                );
            }
        }
    }
    Ok(ContractBasis {
        semantic_protocol: req_str("semanticProtocol")?,
        schema_catalog_digest: req_digest("schemaCatalogDigest")?,
        ontology_generation_id: req_str("ontologyGenerationId")?,
        operation_registry_digest: req_digest("operationRegistryDigest")?,
        view_registry_digest: req_digest("viewRegistryDigest")?,
        capability_registry_digest: req_digest("capabilityRegistryDigest")?,
        error_registry_digest: req_digest("errorRegistryDigest")?,
        cost_registry_digest: req_digest("costRegistryDigest")?,
        producer_release_id: req_str("producerReleaseId")?,
        accepted_nightly,
    })
}

fn parse_evidence_anchor_json(
    val: &Value,
    explicit_privacy_epoch: Option<u64>,
) -> Result<LedgerAnchor, String> {
    let obj = val
        .object()
        .ok_or_else(|| "`inputAnchor` must be a JSON object or null".to_owned())?;
    const REQUIRED: &[&str] = &[
        "schema",
        "deploymentId",
        "observationEpoch",
        "capsuleSequence",
        "authorityRoot",
        "deviceGeneration",
        "streamGeneration",
        "schemaEpoch",
        "policyEpoch",
        "adapterEpoch",
        "modelGeneration",
        "calibrationGeneration",
        "graphGeneration",
        "searchGeneration",
    ];
    const ALLOWED: &[&str] = &[
        "schema",
        "deploymentId",
        "observationEpoch",
        "capsuleSequence",
        "authorityRoot",
        "deviceGeneration",
        "streamGeneration",
        "schemaEpoch",
        "policyEpoch",
        "adapterEpoch",
        "modelGeneration",
        "calibrationGeneration",
        "graphGeneration",
        "searchGeneration",
        "privacyEpoch",
    ];
    for key in obj.keys() {
        if !ALLOWED.contains(&key.as_str()) {
            return Err(format!(
                "unexpected inputAnchor field `{key}` (additionalProperties=false)"
            ));
        }
    }
    for req in REQUIRED {
        if !obj.contains_key(*req) {
            return Err(format!("missing required inputAnchor field `{req}`"));
        }
    }
    let schema = obj
        .get("schema")
        .and_then(Value::text)
        .ok_or_else(|| "inputAnchor missing `schema`".to_owned())?;
    if schema != "fss.evidence_anchor.v1" {
        return Err(format!(
            "inputAnchor.schema `{schema}` != `fss.evidence_anchor.v1`"
        ));
    }
    let deployment_id = obj
        .get("deploymentId")
        .and_then(Value::text)
        .filter(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control))
        .ok_or_else(|| {
            "inputAnchor.deploymentId must be a non-empty control-free string".to_owned()
        })?;
    let req_u64 = |key: &str| -> Result<u64, String> {
        match obj.get(key) {
            Some(Value::Number(raw)) => parse_u64_strict(raw, key),
            _ => Err(format!("inputAnchor.{key} must be a non-negative integer")),
        }
    };
    let authority_root = obj
        .get("authorityRoot")
        .and_then(Value::text)
        .ok_or_else(|| "inputAnchor.authorityRoot must be a digest string".to_owned())?;
    let state_root = ContentDigest::parse(authority_root)
        .map_err(|_| "inputAnchor.authorityRoot is not a valid digest".to_owned())?;
    for req_gen in ["deviceGeneration", "streamGeneration"] {
        let gen_s = obj
            .get(req_gen)
            .and_then(Value::text)
            .ok_or_else(|| format!("inputAnchor.{req_gen} must be a generation string"))?;
        if !is_valid_generation_token(gen_s) {
            return Err(format!(
                "inputAnchor.{req_gen} does not match ^[a-z0-9][a-z0-9:+._-]{{7,255}}$"
            ));
        }
    }
    for opt_gen in [
        "modelGeneration",
        "calibrationGeneration",
        "graphGeneration",
        "searchGeneration",
    ] {
        match obj.get(opt_gen) {
            Some(Value::Null) => {}
            Some(Value::Text(s)) if is_valid_generation_token(s) => {}
            _ => {
                return Err(format!(
                    "inputAnchor.{opt_gen} must be null or match ^[a-z0-9][a-z0-9:+._-]{{7,255}}$"
                ));
            }
        }
    }
    let anchor_privacy_epoch = match obj.get("privacyEpoch") {
        None => None,
        Some(Value::Number(raw)) => Some(parse_u64_strict(raw, "privacyEpoch")?),
        Some(_) => {
            return Err("inputAnchor.privacyEpoch must be a non-negative integer".to_owned());
        }
    };
    let privacy_epoch = match (anchor_privacy_epoch, explicit_privacy_epoch) {
        (Some(a), Some(b)) if a != b => {
            return Err(format!(
                "inputAnchor.privacyEpoch ({a}) conflicts with requestedPrivacyProjection.policyGenerationId privacy-epoch:{b}"
            ));
        }
        (Some(a), _) => a,
        (None, Some(b)) => b,
        (None, None) => 0,
    };

    Ok(LedgerAnchor {
        site_lineage: deployment_id.to_owned(),
        ledger_epoch: req_u64("observationEpoch")?,
        commit_sequence: req_u64("capsuleSequence")?,
        adapter_registry_epoch: req_u64("adapterEpoch")?,
        schema_epoch: req_u64("schemaEpoch")?,
        policy_epoch: req_u64("policyEpoch")?,
        privacy_epoch,
        state_root,
    })
}

fn is_valid_generation_token(s: &str) -> bool {
    let bytes = s.as_bytes();
    (8..=256).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..].iter().all(|&b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b':' | b'+' | b'.' | b'_' | b'-')
        })
}

fn parse_budget_vector_json(val: Option<&Value>) -> Result<BudgetVector, String> {
    let obj = val
        .and_then(Value::object)
        .ok_or_else(|| "`budget` must be a JSON object".to_owned())?;
    const KEYS: &[&str] = &[
        "latencyMs",
        "tokens",
        "bytes",
        "modelCalls",
        "cpuMillis",
        "acceleratorMillis",
        "energyMilliJoules",
        "networkBytes",
        "storageOperations",
        "privacyExposure",
        "operatorAttentionSeconds",
    ];
    for key in obj.keys() {
        if !KEYS.contains(&key.as_str()) {
            return Err(format!("unexpected budget field `{key}`"));
        }
    }
    for key in KEYS {
        if !obj.contains_key(*key) {
            return Err(format!("missing required budget field `{key}`"));
        }
    }
    let u64_field = |key: &str| -> Result<u64, String> {
        match obj.get(key) {
            Some(Value::Number(raw)) => parse_u64_strict(raw, key),
            _ => Err(format!("budget.{key} must be a non-negative integer")),
        }
    };
    let f64_field = |key: &str| -> Result<f64, String> {
        match obj.get(key) {
            Some(Value::Number(raw)) => raw
                .parse::<f64>()
                .ok()
                .filter(|v| v.is_finite() && *v >= 0.0)
                .ok_or_else(|| format!("budget.{key} must be a finite non-negative number")),
            _ => Err(format!("budget.{key} must be a non-negative number")),
        }
    };
    let model_calls = u32::try_from(u64_field("modelCalls")?)
        .map_err(|_| "budget.modelCalls exceeds u32::MAX".to_owned())?;
    BudgetVector::builder()
        .latency_ms(u64_field("latencyMs")?)
        .tokens(u64_field("tokens")?)
        .bytes(u64_field("bytes")?)
        .model_calls(model_calls)
        .cpu_millis(u64_field("cpuMillis")?)
        .accelerator_millis(u64_field("acceleratorMillis")?)
        .energy_millijoules(u64_field("energyMilliJoules")?)
        .network_bytes(u64_field("networkBytes")?)
        .storage_operations(u64_field("storageOperations")?)
        .privacy_exposure(f64_field("privacyExposure")?)
        .operator_attention_seconds(f64_field("operatorAttentionSeconds")?)
        .build()
        .map_err(|err| format!("invalid budget vector: {err}"))
}

fn parse_privacy_projection(val: Option<&Value>) -> Result<PrivacyProjection, String> {
    let obj = val
        .and_then(Value::object)
        .ok_or_else(|| "`requestedPrivacyProjection` must be a JSON object".to_owned())?;
    const KEYS: &[&str] = &[
        "purpose",
        "policyGenerationId",
        "allowedDomains",
        "redactedDomains",
    ];
    for key in obj.keys() {
        if !KEYS.contains(&key.as_str()) {
            return Err(format!(
                "unexpected requestedPrivacyProjection field `{key}`"
            ));
        }
    }
    for key in KEYS {
        if !obj.contains_key(*key) {
            return Err(format!("missing requestedPrivacyProjection.{key}"));
        }
    }
    let purpose = obj
        .get("purpose")
        .and_then(Value::text)
        .filter(|s| !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control))
        .ok_or_else(|| {
            "requestedPrivacyProjection.purpose must be 1..=1024 control-free chars".to_owned()
        })?
        .to_owned();
    let policy_generation_id = obj
        .get("policyGenerationId")
        .and_then(Value::text)
        .filter(|s| validate_id(s).is_ok() && s.len() <= 256)
        .ok_or_else(|| {
            "requestedPrivacyProjection.policyGenerationId must be a valid 1..=256 identifier"
                .to_owned()
        })?
        .to_owned();
    let allowed_domains =
        parse_bounded_strings(obj.get("allowedDomains"), 256, 1024, "allowedDomains")?;
    let redacted_domains =
        parse_bounded_strings(obj.get("redactedDomains"), 256, 1024, "redactedDomains")?;
    Ok(PrivacyProjection {
        purpose,
        policy_generation_id,
        allowed_domains,
        redacted_domains,
    })
}

fn parse_request_taint(val: Option<&Value>) -> Result<RequestTaint, String> {
    let obj = val
        .and_then(Value::object)
        .ok_or_else(|| "`taint` must be a JSON object".to_owned())?;
    for key in obj.keys() {
        if !matches!(key.as_str(), "containsUntrustedControlText" | "sources") {
            return Err(format!("unexpected taint field `{key}`"));
        }
    }
    let contains_untrusted_control_text = obj
        .get("containsUntrustedControlText")
        .and_then(Value::boolean)
        .ok_or_else(|| "taint.containsUntrustedControlText must be a boolean".to_owned())?;
    let sources = parse_bounded_strings(obj.get("sources"), 128, 1024, "taint.sources")?;
    Ok(RequestTaint {
        contains_untrusted_control_text,
        sources,
    })
}

fn parse_target_uris(val: Option<&Value>) -> Result<Vec<String>, String> {
    let list = parse_bounded_strings(val, 256, 2048, "targetUris")?;
    for uri in &list {
        if !uri.starts_with("fss://") {
            return Err(format!(
                "targetUri `{}` must start with `fss://`",
                escape_json_str(&sanitize_and_truncate(uri, 64))
            ));
        }
    }
    Ok(list)
}

fn parse_requested_capabilities(val: Option<&Value>) -> Result<Vec<String>, String> {
    let list = parse_bounded_strings(val, 256, 128, "requestedCapabilities")?;
    for cap in &list {
        if !is_valid_capability_id(cap) {
            return Err(format!(
                "requested capability `{}` does not match ^CAP-[A-Z0-9-]+-[0-9]{{3}}$",
                sanitize_and_truncate(cap, 64)
            ));
        }
    }
    Ok(list)
}

fn is_valid_capability_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("CAP-") else {
        return false;
    };
    let Some((middle, suffix)) = rest.rsplit_once('-') else {
        return false;
    };
    !middle.is_empty()
        && middle
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
        && suffix.len() == 3
        && suffix.bytes().all(|b| b.is_ascii_digit())
}

fn is_valid_error_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("ERR-") else {
        return false;
    };
    let Some((middle, suffix)) = rest.rsplit_once('-') else {
        return false;
    };
    !middle.is_empty()
        && middle
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
        && suffix.len() == 3
        && suffix.bytes().all(|b| b.is_ascii_digit())
}

fn parse_bounded_strings(
    val: Option<&Value>,
    max_items: usize,
    max_len: usize,
    label: &str,
) -> Result<Vec<String>, String> {
    let items = val
        .and_then(Value::array)
        .ok_or_else(|| format!("`{label}` must be an array"))?;
    if items.len() > max_items {
        return Err(format!("`{label}` exceeds {max_items} items"));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let s = item
            .text()
            .filter(|s| !s.is_empty() && s.len() <= max_len && !s.chars().any(char::is_control))
            .ok_or_else(|| format!("`{label}` items must be 1..={max_len} control-free strings"))?;
        out.push(s.to_owned());
    }
    Ok(out)
}

fn parse_opt_id(val: Option<&Value>, field: &str) -> Result<Option<String>, String> {
    match val {
        Some(Value::Null) => Ok(None),
        Some(Value::Text(s)) if validate_id(s).is_ok() && s.len() <= 256 => Ok(Some(s.clone())),
        _ => Err(format!(
            "`{field}` must be a valid 1..=256 identifier or null"
        )),
    }
}

fn parse_u64_strict(raw: &str, field: &str) -> Result<u64, String> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("`{field}` must be a non-negative integer"));
    }
    raw.parse::<u64>()
        .map_err(|_| format!("`{field}` exceeds u64 range"))
}

fn parse_non_negative_i128(raw: &str, field: &str) -> Result<i128, String> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("`{field}` must be a non-negative integer"));
    }
    raw.parse::<i128>()
        .map_err(|_| format!("`{field}` exceeds i128 range"))
}

// ---------------------------------------------------------------------------
// Typed payload helper validators
// ---------------------------------------------------------------------------

fn allow_only(args: &BTreeMap<String, Value>, allowed: &[&str]) -> Result<(), &'static str> {
    if args.keys().all(|k| allowed.contains(&k.as_str())) {
        Ok(())
    } else {
        Err("unexpected field in operation payload (additionalProperties=false)")
    }
}

fn bounded_text(val: Option<&Value>, max_len: usize) -> Result<&str, &'static str> {
    val.and_then(Value::text)
        .filter(|s| !s.is_empty() && s.len() <= max_len && !s.contains('\0'))
        .ok_or("expected non-empty bounded NUL-free string")
}

fn optional_clean_text(
    args: &BTreeMap<String, Value>,
    key: &str,
    max_len: usize,
) -> Result<Option<String>, &'static str> {
    match args.get(key) {
        None => Ok(None),
        Some(v) => {
            let s = bounded_text(Some(v), max_len)?;
            if s.chars().any(char::is_control) {
                return Err("control character forbidden in text field");
            }
            Ok(Some(s.to_owned()))
        }
    }
}

fn positive_u64(val: &Value, max: u64) -> Result<u64, &'static str> {
    let Value::Number(raw) = val else {
        return Err("expected positive integer");
    };
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err("expected positive integer");
    }
    raw.parse::<u64>()
        .ok()
        .filter(|n| (1..=max).contains(n))
        .ok_or("integer out of allowed range")
}

fn optional_u64_range(
    args: &BTreeMap<String, Value>,
    key: &str,
    min: u64,
    max: u64,
) -> Result<Option<u64>, &'static str> {
    match args.get(key) {
        None => Ok(None),
        Some(Value::Number(raw)) => raw
            .parse::<u64>()
            .ok()
            .filter(|n| (min..=max).contains(n))
            .map(Some)
            .ok_or("integer out of allowed range"),
        Some(_) => Err("expected integer"),
    }
}

fn optional_i64(
    args: &BTreeMap<String, Value>,
    key: &str,
    min: i64,
    max: i64,
) -> Result<Option<i64>, &'static str> {
    match args.get(key) {
        None => Ok(None),
        Some(Value::Number(raw)) => raw
            .parse::<i64>()
            .ok()
            .filter(|n| (min..=max).contains(n))
            .map(Some)
            .ok_or("signed integer out of allowed range"),
        Some(_) => Err("expected signed integer"),
    }
}

fn optional_string_vec(
    args: &BTreeMap<String, Value>,
    key: &str,
    max_items: usize,
    max_len: usize,
) -> Result<Vec<String>, &'static str> {
    let Some(val) = args.get(key) else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = val else {
        return Err("expected array of strings");
    };
    if items.len() > max_items {
        return Err("array exceeds item bound");
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let s = bounded_text(Some(item), max_len)?;
        if s.chars().any(char::is_control) {
            return Err("control character forbidden in array string");
        }
        out.push(s.to_owned());
    }
    Ok(out)
}

fn parse_optional_interval(
    args: &BTreeMap<String, Value>,
    lo_key: &str,
    hi_key: &str,
) -> Result<Option<(i128, i128)>, &'static str> {
    let parse_one = |key: &str| -> Result<Option<i128>, &'static str> {
        match args.get(key) {
            None => Ok(None),
            Some(Value::Number(raw)) | Some(Value::Text(raw)) => raw
                .parse::<i128>()
                .ok()
                .filter(|v| v.to_string() == *raw)
                .map(Some)
                .ok_or("invalid canonical i128 timestamp"),
            Some(_) => Err("invalid i128 timestamp"),
        }
    };
    match (parse_one(lo_key)?, parse_one(hi_key)?) {
        (Some(a), Some(b)) if a <= b => Ok(Some((a, b))),
        (Some(_), Some(_)) => Err("interval earliest_ns must be <= latest_ns"),
        (None, None) => Ok(None),
        _ => Err("supply both interval endpoints or neither"),
    }
}

fn parse_fusion_evidence_item(val: &Value) -> Result<FusionEvidenceInput, &'static str> {
    let obj = val.object().ok_or("evidence item must be an object")?;
    allow_only(
        obj,
        &[
            "id",
            "sensor",
            "failure_domains",
            "llr_lo",
            "llr_hi",
            "calibration_generation",
            "uncalibrated_reason",
            "observability",
        ],
    )?;
    let llr = match (
        optional_i64(obj, "llr_lo", -100_000, 100_000)?,
        optional_i64(obj, "llr_hi", -100_000, 100_000)?,
    ) {
        (Some(lo), Some(hi)) if lo <= hi => Some((lo, hi)),
        (Some(_), Some(_)) => return Err("llr_lo must be <= llr_hi"),
        (None, None) => None,
        _ => return Err("supply both llr_lo and llr_hi or neither"),
    };
    Ok(FusionEvidenceInput {
        id: optional_clean_text(obj, "id", 128)?.ok_or("evidence item missing id")?,
        sensor: optional_clean_text(obj, "sensor", 128)?.ok_or("evidence item missing sensor")?,
        failure_domains: optional_string_vec(obj, "failure_domains", 16, 128)?
            .into_iter()
            .collect(),
        llr,
        calibration_generation: optional_clean_text(obj, "calibration_generation", 128)?,
        uncalibrated_reason: optional_clean_text(obj, "uncalibrated_reason", 256)?,
        observability: optional_clean_text(obj, "observability", 32)?
            .unwrap_or_else(|| "observed".to_owned()),
    })
}

fn parse_digest_array(
    val: Option<&Value>,
    max_items: usize,
) -> Result<Vec<ContentDigest>, &'static str> {
    let Some(val) = val else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = val else {
        return Err("expected array of sha256 digests");
    };
    if items.len() > max_items {
        return Err("digest array exceeds bound");
    }
    items
        .iter()
        .map(|item| {
            let s = item.text().ok_or("digest array item must be string")?;
            ContentDigest::parse(s).map_err(|_| "invalid sha256 digest in array")
        })
        .collect()
}

fn parse_id_array(val: Option<&Value>, max_items: usize) -> Result<Vec<String>, &'static str> {
    let Some(val) = val else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = val else {
        return Err("expected array of identifiers");
    };
    if items.len() > max_items {
        return Err("identifier array exceeds bound");
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let s = item.text().ok_or("identifier array item must be string")?;
        validate_id(s).map_err(|_| "invalid identifier in array")?;
        if !seen.insert(s) {
            return Err("duplicate identifier in array");
        }
        out.push(s.to_owned());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::contract_basis::{
        SUPERSEDED_CAPABILITY_REGISTRY_DIGEST_V1, SUPERSEDED_COST_REGISTRY_DIGEST_V1,
    };
    use std::error::Error;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn test_authority() -> TestResult<DispatchAuthority> {
        Ok(DispatchAuthority::owner_standard(
            PathBuf::from("/tmp/fss242-unit-nonexistent"),
            PrincipalId::parse("principal:fss242-unit")?,
        ))
    }

    #[test]
    fn incompatible_and_superseded_contract_bases_fail_closed_with_registered_errors() -> TestResult
    {
        let auth = test_authority()?;

        // 1. Wrong semantic protocol ("fss/2") -> ERR-AGENT-PROTOCOL-001
        let mut bad_proto = RequestEnvelopeSpec::for_operation(
            AgentOperation::Doctor,
            "req:bad-proto",
            auth.principal.clone(),
            "{}",
        );
        bad_proto.contract_basis.semantic_protocol = "fss/2".to_owned();
        let out = dispatch_envelope_json(&auth, &bad_proto.to_json());
        assert_eq!(out.exit_identity, ExitIdentity::AGENT_REFUSED);
        assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AGENT_PROTOCOL));
        assert!(!out.receipt.grants_effect_authority);
        assert!(out.response_json.contains("ERR-AGENT-PROTOCOL-001"));

        // 2. Superseded capabilities-v1 digest -> ERR-AGENT-SESSION-STALE-001 + resnapshotRequired=true
        let mut stale_cap = RequestEnvelopeSpec::for_operation(
            AgentOperation::Doctor,
            "req:stale-cap",
            auth.principal.clone(),
            "{}",
        );
        stale_cap.contract_basis.capability_registry_digest =
            ContentDigest::parse(SUPERSEDED_CAPABILITY_REGISTRY_DIGEST_V1)?;
        let out = dispatch_envelope_json(&auth, &stale_cap.to_json());
        assert_eq!(out.exit_identity, ExitIdentity::AGENT_REFUSED);
        assert_eq!(
            out.receipt.error_id.as_deref(),
            Some(ERR_AGENT_SESSION_STALE)
        );
        assert!(out.response_json.contains("\"resnapshotRequired\":true"));

        // 3. Superseded cost-v1 digest -> ERR-AGENT-SESSION-STALE-001
        let mut stale_cost = RequestEnvelopeSpec::for_operation(
            AgentOperation::Doctor,
            "req:stale-cost",
            auth.principal.clone(),
            "{}",
        );
        stale_cost.contract_basis.cost_registry_digest =
            ContentDigest::parse(SUPERSEDED_COST_REGISTRY_DIGEST_V1)?;
        let out = dispatch_envelope_json(&auth, &stale_cost.to_json());
        assert_eq!(
            out.receipt.error_id.as_deref(),
            Some(ERR_AGENT_SESSION_STALE)
        );
        Ok(())
    }

    #[test]
    fn operation_registry_payload_schema_and_additional_properties_fail_closed() -> TestResult {
        let auth = test_authority()?;

        // Wrong payloadSchema for AOP-001 (expects fss.agent_mission.v1)
        let mut bad_schema = RequestEnvelopeSpec::for_operation(
            AgentOperation::SessionOpen,
            "req:bad-payload-schema",
            auth.principal.clone(),
            r#"{"mission":"m","objective":"o"}"#,
        );
        bad_schema.payload_schema = "fss.agent_query_plan.v1".to_owned();
        let out = dispatch_envelope_json(&auth, &bad_schema.to_json());
        assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AGENT_PROTOCOL));

        // Unknown operationId -> ERR-AGENT-PROTOCOL-001
        let raw_bad_op = RequestEnvelopeSpec::for_operation(
            AgentOperation::Doctor,
            "req:unknown-op",
            auth.principal.clone(),
            "{}",
        )
        .to_json()
        .replace("\"operationId\":\"AOP-014\"", "\"operationId\":\"AOP-999\"");
        let out = dispatch_envelope_json(&auth, &raw_bad_op);
        assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AGENT_PROTOCOL));

        // Extra top-level envelope key (additionalProperties: false) -> ERR-AGENT-PROTOCOL-001
        let mut raw_extra = RequestEnvelopeSpec::for_operation(
            AgentOperation::Doctor,
            "req:extra-top",
            auth.principal.clone(),
            "{}",
        )
        .to_json();
        raw_extra.pop();
        raw_extra.push_str(",\"sneaky\":true}");
        let out = dispatch_envelope_json(&auth, &raw_extra);
        assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AGENT_PROTOCOL));

        // Extra payload key on AOP-014 doctor -> ERR-AGENT-PROTOCOL-001
        let bad_doc = RequestEnvelopeSpec::for_operation(
            AgentOperation::Doctor,
            "req:extra-doc",
            auth.principal.clone(),
            r#"{"unexpected":1}"#,
        );
        let out = dispatch_envelope_json(&auth, &bad_doc.to_json());
        assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AGENT_PROTOCOL));
        Ok(())
    }

    #[test]
    fn authority_overrides_capability_denial_tainted_effects_and_idempotency_fail_closed()
    -> TestResult {
        let auth = test_authority()?;

        // Principal impersonation -> ERR-AUTH-DENIED-001
        let other = PrincipalId::parse("principal:imposter")?;
        let spec =
            RequestEnvelopeSpec::for_operation(AgentOperation::Doctor, "req:imposter", other, "{}");
        let out = dispatch_envelope_json(&auth, &spec.to_json());
        assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AUTH_DENIED));

        // Payload root override -> ERR-AUTH-DENIED-001
        let root_override = RequestEnvelopeSpec::for_operation(
            AgentOperation::SessionOrient,
            "req:root-override",
            auth.principal.clone(),
            r#"{"root":"/etc"}"#,
        );
        let out = dispatch_envelope_json(&auth, &root_override.to_json());
        assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AUTH_DENIED));

        // Restricted launcher lacking CAP-AGENT-PLAN-COMMIT-001 -> ERR-AUTH-DENIED-001
        let restricted = DispatchAuthority::with_capabilities(
            auth.root.clone(),
            auth.principal.clone(),
            BTreeSet::from(["CAP-AGENT-QUERY-001".to_owned()]),
        );
        let commit_spec = RequestEnvelopeSpec::for_operation(
            AgentOperation::Commit,
            "req:no-cap",
            auth.principal.clone(),
            r#"{"intent":"dispatch","plan":"plan:1","approve":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}"#,
        );
        let out = dispatch_envelope_json(&restricted, &commit_spec.to_json());
        assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AUTH_DENIED));

        // Missing idempotencyKey on effectful AOP-008 commit -> ERR-IDEMPOTENCY-CONFLICT-001
        let mut no_idem = commit_spec.clone();
        no_idem.idempotency_key = None;
        let out = dispatch_envelope_json(&auth, &no_idem.to_json());
        assert_eq!(
            out.receipt.error_id.as_deref(),
            Some(ERR_IDEMPOTENCY_CONFLICT)
        );

        // Tainted control text on effectful AOP-008 commit -> ERR-AUTH-DENIED-001
        let mut tainted_commit = commit_spec;
        tainted_commit.taint = RequestTaint {
            contains_untrusted_control_text: true,
            sources: vec!["untrusted:chat".to_owned()],
        };
        let out = dispatch_envelope_json(&auth, &tainted_commit.to_json());
        assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AUTH_DENIED));
        assert!(out.receipt.tainted);

        // Pre-cancelled RequestControl -> cancelled + ERR-CLI-READ-CANCELLED-001
        let always = || true;
        let out = dispatch_envelope_json_with_control(
            &auth,
            &RequestEnvelopeSpec::for_operation(
                AgentOperation::Doctor,
                "req:cancelled",
                auth.principal.clone(),
                "{}",
            )
            .to_json(),
            &RequestControl::new(&always),
        );
        assert_eq!(out.receipt.outcome, "cancelled");
        assert_eq!(
            out.receipt.error_id.as_deref(),
            Some(ERR_CLI_READ_CANCELLED)
        );
        Ok(())
    }

    #[test]
    fn response_schema_validator_catches_planted_operation_and_allowlist_drift() -> TestResult {
        let basis = reference_contract_basis();
        let principal = PrincipalId::parse("principal:fss242-unit")?;
        let d = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let boundary = r#"{"completed":[],"notStarted":[],"possiblyOccurred":[],"preservedTruth":[],"invalidated":[]}"#;

        // Valid AOP-003 response passes
        let valid = format!(
            r#"{{"schema":"fss.agent_response_envelope.v1","contractBasis":{{}},"operationId":"AOP-003","principalId":"principal:fss242-unit","effectiveViewId":"AVIEW-002","epistemicState":"known","completeness":"complete","recoveryClass":"safe_read_retry","safeRetry":"yes_same_request","resnapshotRequired":false,"executionBoundary":{boundary},"outcome":"ok","errorId":null,"payloadSchema":"fss.situation_capsule.v1","payloadDigest":"{d}","decisionFingerprint":"{d}"}}"#
        );
        let meta = validate_response_envelope_against_registry(
            &valid,
            AgentOperation::SessionOrient,
            &basis,
            &principal,
        )
        .map_err(|e| format!("expected valid envelope: {e}"))?;
        assert_eq!(meta.decision_fingerprint, Some(ContentDigest::parse(d)?));

        // Refused/error envelope missing errorId MUST fail closed
        let missing_err_id = valid.replace(r#""outcome":"ok""#, r#""outcome":"refused""#);
        assert!(
            validate_response_envelope_against_registry(
                &missing_err_id,
                AgentOperation::SessionOrient,
                &basis,
                &principal,
            )
            .is_err()
        );

        // Malformed errorId pattern MUST fail closed
        let bad_err_id = valid
            .replace(r#""outcome":"ok""#, r#""outcome":"refused""#)
            .replace(r#""errorId":null"#, r#""errorId":"not-a-registered-err""#);
        assert!(
            validate_response_envelope_against_registry(
                &bad_err_id,
                AgentOperation::SessionOrient,
                &basis,
                &principal,
            )
            .is_err()
        );

        // Planted V2 cognitive payload under reference V1 basis MUST be refused
        let drifted_v2 = format!(
            r#"{{"schema":"fss.agent_response_envelope.v1","contractBasis":{{}},"operationId":"AOP-006","principalId":"principal:fss242-unit","effectiveViewId":"AVIEW-004","epistemicState":"known","completeness":"complete","recoveryClass":"safe_read_retry","safeRetry":"yes_same_request","resnapshotRequired":false,"executionBoundary":{boundary},"outcome":"ok","errorId":null,"payloadSchema":"fss.agent_cognitive_envelope.v2","payloadDigest":"{d}","decisionFingerprint":"{d}"}}"#
        );
        assert!(
            validate_response_envelope_against_registry(
                &drifted_v2,
                AgentOperation::Investigate,
                &basis,
                &principal,
            )
            .is_err()
        );
        // Same V2 payload IS allowed under explicit probe_contract_basis()!
        assert!(
            validate_response_envelope_against_registry(
                &drifted_v2,
                AgentOperation::Investigate,
                &fss_core::contract_basis::probe_contract_basis(),
                &principal,
            )
            .is_ok()
        );

        // Planted fss.doctor.v1 on non-doctor operation MUST be refused
        let fake_doc = r#"{"schema":"fss.doctor.v1","verdict":"ok"}"#;
        assert!(
            validate_response_envelope_against_registry(
                fake_doc,
                AgentOperation::SessionOrient,
                &basis,
                &principal,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn fresh_eyes_cycle24_hardening_regression_matrix() -> TestResult {
        let auth = test_authority()?;
        assert!(auth.granted_capabilities.contains(CAP_RETENTION_PREPARE));

        // 1. Stateless request_digest sensitivity across all previously-omitted fields.
        let base_spec = RequestEnvelopeSpec::for_operation(
            AgentOperation::Query,
            "req:digest-sens",
            auth.principal.clone(),
            r#"{"target":"events"}"#,
        );
        let raw_base = base_spec.to_json();
        let req_base = parse_and_validate_request(
            &auth,
            &raw_base,
            ContentDigest::sha256(raw_base.as_bytes()),
        )
        .map_err(|r| format!("base request should parse: {}", r.detail))?;

        let mut mod_deadline = base_spec.clone();
        mod_deadline.deadline_ns = Some(base_spec.created_at_ns + 5_000);
        let raw_dl = mod_deadline.to_json();
        let req_dl =
            parse_and_validate_request(&auth, &raw_dl, ContentDigest::sha256(raw_dl.as_bytes()))
                .map_err(|r| format!("deadline request should parse: {}", r.detail))?;
        assert_ne!(req_base.request_digest, req_dl.request_digest);

        let mut mod_taint_src = base_spec.clone();
        mod_taint_src.taint.sources = vec!["taint:user:prompt".to_owned()];
        let raw_ts = mod_taint_src.to_json();
        let req_ts =
            parse_and_validate_request(&auth, &raw_ts, ContentDigest::sha256(raw_ts.as_bytes()))
                .map_err(|r| format!("taint src request should parse: {}", r.detail))?;
        assert_ne!(req_base.request_digest, req_ts.request_digest);

        let mut mod_hydr = base_spec.clone();
        mod_hydr.max_hydration_level = HydrationLevel::H0;
        let raw_hy = mod_hydr.to_json();
        let req_hy =
            parse_and_validate_request(&auth, &raw_hy, ContentDigest::sha256(raw_hy.as_bytes()))
                .map_err(|r| format!("hydration request should parse: {}", r.detail))?;
        assert_ne!(req_base.request_digest, req_hy.request_digest);

        let mut mod_uri = base_spec.clone();
        mod_uri.target_uris = vec!["fss://deployment/events".to_owned()];
        let raw_uri = mod_uri.to_json();
        let req_uri =
            parse_and_validate_request(&auth, &raw_uri, ContentDigest::sha256(raw_uri.as_bytes()))
                .map_err(|r| format!("uri request should parse: {}", r.detail))?;
        assert_ne!(req_base.request_digest, req_uri.request_digest);

        // 2. inputAnchor strict schema validation: extra property and missing generation fail closed.
        let mut anchored = base_spec.clone();
        anchored.input_anchor = Some(LedgerAnchor::genesis("site:anchor-test"));
        let anchor_json_extra = anchored.to_json().replace(
            r#""searchGeneration":null"#,
            r#""searchGeneration":null,"sneaky":1"#,
        );
        let out_extra = dispatch_envelope_json(&auth, &anchor_json_extra);
        assert_eq!(
            out_extra.receipt.error_id.as_deref(),
            Some(ERR_AGENT_PROTOCOL)
        );

        let anchor_json_missing_gen = anchored
            .to_json()
            .replace(r#""searchGeneration":null"#, r#""privacyEpoch":0"#);
        let out_missing = dispatch_envelope_json(&auth, &anchor_json_missing_gen);
        assert_eq!(
            out_missing.receipt.error_id.as_deref(),
            Some(ERR_AGENT_PROTOCOL)
        );

        // Conflicting inputAnchor.privacyEpoch vs policyGenerationId privacy-epoch:0
        let anchor_privacy_conflict = anchored.to_json().replace(
            r#""searchGeneration":null"#,
            r#""searchGeneration":null,"privacyEpoch":7"#,
        );
        let out_priv = dispatch_envelope_json(&auth, &anchor_privacy_conflict);
        assert_eq!(
            out_priv.receipt.error_id.as_deref(),
            Some(ERR_AGENT_PROTOCOL)
        );

        // 3. AOP-011 explain mutual-exclusion parity with fss-mcp
        let d = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        for (tag, bad_explain_payload) in [
            ("why-with-rev-digests", format!(r#"{{"event_id":"ev:1","from_revision_digest":"{d}","to_revision_digest":"{d}"}}"#)),
            ("what_if-with-session", r#"{"question":"what_if","event_id":"ev:1","session":"session:1","counterfactual":{}}"#.to_owned()),
            ("what_changed-with-at", format!(r#"{{"question":"what_changed","event_id":"ev:1","at":"anchor:x","from_revision_digest":"{d}","to_revision_digest":"{d}"}}"#)),
            ("why_not-with-learning-root", format!(r#"{{"question":"why_not","learning_root":"{d}","session":"session:1"}}"#)),
            ("learning-root-with-event", format!(r#"{{"learning_root":"{d}","session":"session:1","event_id":"ev:1"}}"#)),
            ("session-without-learning-root", r#"{"event_id":"ev:1","session":"session:1"}"#.to_owned()),
        ] {
            let spec = RequestEnvelopeSpec::for_operation(
                AgentOperation::Explain,
                format!("req:explain:{tag}"),
                auth.principal.clone(),
                bad_explain_payload,
            );
            let out = dispatch_envelope_json(&auth, &spec.to_json());
            assert_eq!(
                out.receipt.error_id.as_deref(),
                Some(ERR_AGENT_PROTOCOL),
                "explain mutual exclusion `{tag}` must refuse with ERR-AGENT-PROTOCOL-001"
            );
        }

        // 4. payload.session vs envelope.sessionId conflict on follow and ops query targets
        let mut follow_conflict = RequestEnvelopeSpec::for_operation(
            AgentOperation::SessionFollow,
            "req:follow:conflict",
            auth.principal.clone(),
            r#"{"since":"anchor:site:0:none:abc","session":"session:other","subscription":"sub:1"}"#,
        );
        follow_conflict.session_id = Some(SessionId::parse("session:env")?);
        let out = dispatch_envelope_json(&auth, &follow_conflict.to_json());
        assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AGENT_PROTOCOL));

        let mut ops_conflict = RequestEnvelopeSpec::for_operation(
            AgentOperation::Query,
            "req:ops:conflict",
            auth.principal.clone(),
            r#"{"target":"cameras","session":"session:other"}"#,
        );
        ops_conflict.session_id = Some(SessionId::parse("session:env")?);
        let out = dispatch_envelope_json(&auth, &ops_conflict.to_json());
        assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AGENT_PROTOCOL));

        // 5. payload.continuation vs envelope.continuation conflict on query
        let mut query_cont_conflict = RequestEnvelopeSpec::for_operation(
            AgentOperation::Query,
            "req:query:cont-conflict",
            auth.principal.clone(),
            r#"{"target":"events","continuation":"continuation:a"}"#,
        );
        query_cont_conflict.continuation = Some("continuation:b".to_owned());
        let out = dispatch_envelope_json(&auth, &query_cont_conflict.to_json());
        assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AGENT_PROTOCOL));

        // 6. envelope.budget.tokens ceiling enforced against payload.budget_tokens
        let mut tok_budget = RequestEnvelopeSpec::for_operation(
            AgentOperation::SessionOrient,
            "req:budget:tokens",
            auth.principal.clone(),
            r#"{"view":"brief","budget_tokens":1600}"#,
        );
        tok_budget.budget = BudgetVector::builder().tokens(256).build()?;
        let out = dispatch_envelope_json(&auth, &tok_budget.to_json());
        assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_BUDGET_EXHAUSTED));

        // 7. expectedWorkspaceRevision without a session fails closed with ERR-AGENT-SESSION-STALE-001
        let mut stale_ws = RequestEnvelopeSpec::for_operation(
            AgentOperation::SessionOrient,
            "req:ws:nosession",
            auth.principal.clone(),
            "{}",
        );
        stale_ws.expected_workspace_revision = Some(1);
        let out = dispatch_envelope_json(&auth, &stale_ws.to_json());
        assert_eq!(
            out.receipt.error_id.as_deref(),
            Some(ERR_AGENT_SESSION_STALE)
        );
        assert!(out.response_json.contains("\"resnapshotRequired\":true"));

        // 8. Control characters in privacy.purpose / taint.sources fail closed
        let mut ctrl_purpose = base_spec;
        ctrl_purpose.requested_privacy_projection.purpose = "bad\npurpose".to_owned();
        let out = dispatch_envelope_json(&auth, &ctrl_purpose.to_json());
        assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AGENT_PROTOCOL));
        Ok(())
    }
}
