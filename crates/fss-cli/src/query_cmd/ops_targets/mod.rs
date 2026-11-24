#![forbid(unsafe_code)]
//! Typed operational targets (`cameras`, `graph`, `fusion`, `holds`, `privacy-masks`),
//! cognition-only discriminating probes (`probe-detect`, `probe-corroborate`), and
//! approval-gated operational intent families (`privacy-mask`, `evidence-hold`,
//! `retention-policy`, `camera-supervision`) for `fss/1` and `fss-mcp`.
//!
//! Semantic plane: `"cognition"` (router and read-only projection helpers; authority mutations
//! live strictly inside [`intents`] with explicit preview -> approval digest -> durable commit).

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;

use fss_core::{
    AgentResponseEnvelope, AgentView, BudgetVector, CanonicalEncoder, Completeness, ContentDigest,
    ContextAuthority, DigestAlgorithm, ExecutionBoundary, KnowledgeState, LedgerAnchor,
    OperationId, PrincipalId, ResponseOutcome, ResponseSafeRetry, ResponseTaskState,
    RootAuthoritySpec, SessionId,
};
use fss_reference::agent_orient::OrientLimits;
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::deletion::holds::{CAP_HOLD_COMMIT, CAP_HOLD_PREPARE};
use fss_reference::deployment_session::{SESSION_JOURNAL_FILE, SESSIONS_RELPATH};
use fss_reference::retained_source::{ImmutableRetainedReadLimits, ImmutableRetainedSource};
use fss_reference::{ADP_REPLAY_ROW_ID, ReplayCx};

use crate::agent_json;
use crate::error::ExitIdentity;
use crate::json_output::{object, string, strings};
use crate::query_cmd::MAX_QUERY_OUTPUT_BYTES;

/// Live camera telemetry (`fss-ipc`) with automatic read-only MVCC fallback.
pub mod cameras;
/// Read-only `fss-fusion` milliban LLR evaluation and sensor/domain counterfactual ablations.
pub mod fusion;
/// Certified Graph Atlas execution returning verified `GraphAlgorithmWitness` envelopes.
pub mod graph;
/// Read-only inspection of legal holds, retention policies, and per-sensor privacy masks.
pub mod holds_masks;
/// Approval-gated `plan` + `commit` operational intent families.
pub mod intents;
/// Cognition-only bounded discriminating probes (`probe-detect`, `probe-corroborate`).
pub mod probes;

#[cfg(test)]
mod tests;

/// Capability required for read-only operational query targets.
pub const CAP_AGENT_QUERY: &str = "CAP-AGENT-QUERY-001";
/// Capability required for cognition-only discriminating investigation probes.
pub const CAP_AGENT_INVESTIGATE: &str = "CAP-AGENT-INVESTIGATE-001";
/// Capability required for operational intent plan previews.
pub const CAP_AGENT_PLAN_PREPARE: &str = "CAP-AGENT-PLAN-PREPARE-001";
/// Capability required for operational intent commits.
pub const CAP_AGENT_PLAN_COMMIT: &str = "CAP-AGENT-PLAN-COMMIT-001";
/// Target-specific capability for live daemon status observation and camera supervision.
pub const CAP_OBSERVE_STATUS: &str = "CAP-OBSERVE-STATUS-001";
/// Re-exported retention prepare capability (`CAP-RETENTION-PREPARE-001`).
pub const CAP_RETENTION_PREPARE: &str = CAP_HOLD_PREPARE;
/// Re-exported retention commit capability (`CAP-RETENTION-COMMIT-001`).
pub const CAP_RETENTION_COMMIT: &str = CAP_HOLD_COMMIT;

/// Fail-closed error identity for missing capability grants.
pub const ERR_CAPABILITY_DENIED: &str = "ERR-CAPABILITY-DENIED-001";
/// Fail-closed error identity when a mutating commit omits its required approval digest.
pub const ERR_APPROVAL_REQUIRED: &str = "ERR-APPROVAL-REQUIRED-001";
/// Fail-closed error identity when a mutating commit presents a wrong or stale approval digest.
pub const ERR_APPROVAL_MISMATCH: &str = "ERR-APPROVAL-MISMATCH-001";
/// Fail-closed error identity when live daemon IPC is required while `fss-daemon` is offline.
pub const ERR_DAEMON_OFFLINE: &str = fss_ipc::ERR_DAEMON_OFFLINE_001;
/// Fail-closed error identity for violated operational bounds.
pub const ERR_OPS_BOUNDS: &str = "ERR-OPS-BOUNDS-001";
/// Canonical digest domain for fail-closed operational refusal fingerprints.
pub const OPS_REFUSAL_DOMAIN: &str = "fss.ops_targets.refusal.v1";

/// Maximum retained source bytes read by a single bounded operational read (64 MiB).
pub(crate) const MAX_OPS_READ_BYTES: usize = 64 * 1024 * 1024;
/// Maximum retained source read attempts by a single bounded operational read.
pub(crate) const MAX_OPS_READ_OBJECTS: usize = 32_768;

/// Unified typed operational dispatch carried cleanly through `QueryArgs::ops`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpsDispatch {
    /// `AOP-005 query --target cameras`.
    Cameras(cameras::CamerasQueryRequest),
    /// `AOP-005 query --target graph`.
    Graph(graph::GraphQueryRequest),
    /// `AOP-005 query --target fusion`.
    Fusion(fusion::FusionQueryRequest),
    /// `AOP-005 query --target holds`.
    Holds(holds_masks::HoldsQueryRequest),
    /// `AOP-005 query --target privacy-masks`.
    PrivacyMasks(holds_masks::PrivacyMasksQueryRequest),
    /// `AOP-006 investigate --transition probe-detect`.
    ProbeDetect(probes::ProbeDetectRequest),
    /// `AOP-006 investigate --transition probe-corroborate`.
    ProbeCorroborate(probes::ProbeCorroborateRequest),
    /// `AOP-007 plan` preview for an operational intent family.
    PlanIntent(intents::OpsIntentRequest),
    /// `AOP-008 commit` execution for an operational intent family.
    CommitIntent(intents::OpsIntentRequest),
}

/// Typed fail-closed error surface for operational targets, probes, and intents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpsError {
    /// Required capability was not granted by the launcher or verified session.
    CapabilityDenied(String),
    /// Mutating commit omitted its mandatory `approval_digest`.
    ApprovalRequired(String),
    /// Mutating commit supplied an approval digest that does not match the current preview.
    ApprovalMismatch(String),
    /// Live daemon IPC was requested while `fss-daemon` is stopped or unreachable.
    DaemonUnavailable(String),
    /// Input parameters failed strict typed validation.
    InvalidRequest(String),
    /// Bounded output, work, or collection ceiling exceeded.
    BoundsExceeded(String),
    /// Referenced deployment entity (event, import, sensor, hold) does not exist.
    NotFound(String),
    /// Deployment custody, read, or commit operation failed.
    OperationFailed(String),
    /// Cooperative request cancellation observed before completion.
    Cancelled,
}

impl OpsError {
    /// Registered stable machine error identity for this refusal.
    #[must_use]
    pub const fn error_id(&self) -> &'static str {
        match self {
            Self::CapabilityDenied(_) => ERR_CAPABILITY_DENIED,
            Self::ApprovalRequired(_) => ERR_APPROVAL_REQUIRED,
            Self::ApprovalMismatch(_) => ERR_APPROVAL_MISMATCH,
            Self::DaemonUnavailable(_) => ERR_DAEMON_OFFLINE,
            Self::InvalidRequest(_) => crate::error::ERR_CLI_MALFORMED_VALUE,
            Self::BoundsExceeded(_) => ERR_OPS_BOUNDS,
            Self::NotFound(_) => crate::orient_cmd::ERR_AGENT_EVENT_NOT_FOUND,
            Self::OperationFailed(_) | Self::Cancelled => {
                crate::orient_cmd::ERR_AGENT_CONTEXT_INCOMPLETE
            }
        }
    }

    /// Exit identity matching the CLI contract.
    #[must_use]
    pub const fn exit_identity(&self) -> ExitIdentity {
        match self {
            Self::InvalidRequest(_) => ExitIdentity::MALFORMED_VALUE,
            _ => ExitIdentity::AGENT_REFUSED,
        }
    }
}

impl fmt::Display for OpsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityDenied(detail)
            | Self::ApprovalRequired(detail)
            | Self::ApprovalMismatch(detail)
            | Self::DaemonUnavailable(detail)
            | Self::InvalidRequest(detail)
            | Self::BoundsExceeded(detail)
            | Self::NotFound(detail)
            | Self::OperationFailed(detail) => f.write_str(detail),
            Self::Cancelled => f.write_str("operational request cancelled before completion"),
        }
    }
}

impl std::error::Error for OpsError {}

/// Executes one typed operational query, probe, or intent under cooperative cancellation.
#[must_use]
pub fn execute_with_control(
    dispatch: &OpsDispatch,
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    let cancelled = || control.is_cancelled();
    match dispatch {
        OpsDispatch::Cameras(req) => cameras::execute(req, &cancelled),
        OpsDispatch::Graph(req) => graph::execute(req, &cancelled),
        OpsDispatch::Fusion(req) => fusion::execute(req, &cancelled),
        OpsDispatch::Holds(req) => holds_masks::execute_holds(req, &cancelled),
        OpsDispatch::PrivacyMasks(req) => holds_masks::execute_privacy_masks(req, &cancelled),
        OpsDispatch::ProbeDetect(req) => probes::execute_probe_detect(req, &cancelled),
        OpsDispatch::ProbeCorroborate(req) => probes::execute_probe_corroborate(req, &cancelled),
        OpsDispatch::PlanIntent(req) => intents::execute_plan(req, &cancelled),
        OpsDispatch::CommitIntent(req) => intents::execute_commit(req, &cancelled),
    }
}

/// Verifies optional retained session ownership (strictly read-only) and returns the explicit
/// launcher/CLI capability grants without ever allowing a session record to escalate authority.
pub(crate) fn resolve_effective_capabilities(
    root: &Path,
    principal: &PrincipalId,
    session_id: Option<&SessionId>,
    explicit: &BTreeSet<String>,
) -> Result<BTreeSet<String>, OpsError> {
    if let Some(session_id) = session_id {
        let journal_path = root.join(SESSIONS_RELPATH).join(SESSION_JOURNAL_FILE);
        if journal_path.exists() {
            let bytes = fs::read(&journal_path).map_err(|_| {
                OpsError::CapabilityDenied(
                    "retained session journal is unreadable for session verification".into(),
                )
            })?;
            let state = inspect_session_bytes(
                &bytes,
                DurableSessionLimits::default(),
                WorkClaimLimits::default(),
            )
            .map_err(|_| {
                OpsError::OperationFailed("retained session journal failed integrity check".into())
            })?;
            let owned = state.sessions.iter().any(|entry| {
                entry.session.session_id == *session_id && entry.session.principal_id == *principal
            });
            if !owned {
                return Err(OpsError::CapabilityDenied(
                    "session is unknown or not owned by the requesting principal".into(),
                ));
            }
        }
    }
    Ok(explicit.clone())
}

/// Verifies that every required capability ID is present in `effective`; fails closed otherwise.
pub(crate) fn require_capabilities(
    effective: &BTreeSet<String>,
    required: &[&str],
    context_label: &str,
) -> Result<(), OpsError> {
    for &cap in required {
        if !effective.contains(cap) {
            return Err(OpsError::CapabilityDenied(format!(
                "{context_label} requires explicit capability {cap}"
            )));
        }
    }
    Ok(())
}

/// Validates that a digest is a canonical nonzero SHA-256 digest.
pub(crate) fn is_valid_sha256(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes().iter().any(|&b| b != 0)
}

/// Validates that a deployment root exists as a regular directory containing `LAYOUT`.
pub(crate) fn ensure_deployment_root(root: &Path) -> Result<(), OpsError> {
    let dir_ok = fs::symlink_metadata(root).is_ok_and(|meta| meta.file_type().is_dir());
    let layout_ok =
        fs::symlink_metadata(root.join("LAYOUT")).is_ok_and(|meta| meta.file_type().is_file());
    if !dir_ok || !layout_ok {
        return Err(OpsError::NotFound(
            "existing deployment root with regular LAYOUT file is required".into(),
        ));
    }
    Ok(())
}

/// Builds a bounded read-only `ContextAuthority` + `ReplayCx` over `root`.
pub(crate) fn build_readonly_context(
    root: &Path,
    site_lineage: &str,
    principal: &PrincipalId,
    capabilities: &[&str],
) -> Result<(ContextAuthority, ReplayCx), OpsError> {
    let mut caps: Vec<String> = capabilities.iter().map(|s| (*s).to_owned()).collect();
    if !caps.iter().any(|c| c == ADP_REPLAY_ROW_ID) {
        caps.push(ADP_REPLAY_ROW_ID.to_owned());
    }
    let canonical_root = fs::canonicalize(root)
        .map_err(|_| OpsError::OperationFailed("failed to canonicalize deployment root".into()))?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:ops-targets-readonly".to_owned(),
        operation_id: OperationId::parse("operation:ops-targets-readonly")
            .map_err(|_| OpsError::OperationFailed("invalid readonly operation id".into()))?,
        principal: principal.as_str().to_owned(),
        capabilities: caps,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(MAX_OPS_READ_BYTES as u64)
            .storage_operations(MAX_OPS_READ_OBJECTS as u64)
            .build()
            .map_err(|_| OpsError::BoundsExceeded("invalid readonly budget vector".into()))?,
        privacy_scope: "private:property".to_owned(),
        retention_scope: "retention:current-deletion-restrictions".to_owned(),
        anchor_universe: ContentDigest::sha256(site_lineage.as_bytes()),
        generation: 1,
    })
    .map_err(|_| OpsError::OperationFailed("failed to build readonly context authority".into()))?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, canonical_root)
        .map_err(|_| OpsError::OperationFailed("failed to open readonly replay context".into()))?;
    Ok((authority, cx))
}

/// Opens a bounded read-only `ImmutableRetainedSource` over `root`.
pub(crate) fn open_readonly_source<'a>(
    root: &Path,
    cx: &'a ReplayCx,
    cancelled: &'a (dyn Fn() -> bool + Sync),
) -> Result<ImmutableRetainedSource<'a>, OpsError> {
    if cancelled() {
        return Err(OpsError::Cancelled);
    }
    let canonical_root = fs::canonicalize(root)
        .map_err(|_| OpsError::OperationFailed("failed to canonicalize deployment root".into()))?;
    ImmutableRetainedSource::open_cancellable(
        &canonical_root,
        ImmutableRetainedReadLimits {
            snapshot: OrientLimits::default(),
            max_read_bytes: MAX_OPS_READ_BYTES,
            max_read_objects: MAX_OPS_READ_OBJECTS,
        },
        cx,
        cancelled,
    )
    .map_err(|err| OpsError::OperationFailed(format!("retained source refused: {err}")))
}

/// Parameters for rendering a validated `AgentResponseEnvelope`.
pub(crate) struct OpsEnvelopeParams<'a> {
    /// Registered public operation name (`query`, `investigate`, `plan`, or `commit`).
    pub(crate) operation: &'static str,
    /// Audit principal label.
    pub(crate) principal: &'a PrincipalId,
    /// Optional owning session identity.
    pub(crate) session_id: Option<&'a SessionId>,
    /// Authority anchor pinning this response.
    pub(crate) anchor: LedgerAnchor,
    /// Registered agent view (`Case` or `Forensic`).
    pub(crate) view: AgentView,
    /// Capabilities exercised by this operation.
    pub(crate) capabilities: Vec<String>,
    /// Privacy projection purpose statement.
    pub(crate) privacy_purpose: &'static str,
    /// Domains explicitly disclosed in this payload.
    pub(crate) allowed_domains: &'a [&'static str],
    /// Domains explicitly redacted from this payload.
    pub(crate) redacted_domains: &'a [&'static str],
    /// Registered payload schema string.
    pub(crate) payload_schema: &'static str,
    /// Pre-serialized canonical JSON payload.
    pub(crate) payload_json: String,
    /// Epistemic state of the returned answer.
    pub(crate) epistemic_state: KnowledgeState,
    /// Completeness marker.
    pub(crate) completeness: Completeness,
    /// Non-droppable operational warnings.
    pub(crate) warnings: Vec<String>,
    /// Proof pointers binding this answer to authority and derived artifacts.
    pub(crate) proof_pointers: Vec<String>,
    /// Canonical decision fingerprint digest.
    pub(crate) decision_fingerprint: ContentDigest,
    /// Optional idempotency key for durable plan/commit operations.
    pub(crate) idempotency_key: Option<String>,
    /// Safe retry classification.
    pub(crate) safe_retry: ResponseSafeRetry,
    /// Recovery class label.
    pub(crate) recovery_class: &'static str,
    /// Explicit execution boundary statements.
    pub(crate) boundary: ExecutionBoundary,
    /// Evidence timestamp (ns).
    pub(crate) created_at_ns: i128,
}

/// Renders and validates a complete registered `AgentResponseEnvelope` (refusing > 256 KiB).
pub(crate) fn render_ok_envelope(
    root: &Path,
    params: OpsEnvelopeParams<'_>,
) -> (String, ExitIdentity) {
    if params.payload_json.len() > MAX_QUERY_OUTPUT_BYTES {
        return render_refusal_envelope(
            root,
            params.operation,
            params.principal,
            params.session_id,
            params.payload_schema,
            &OpsError::BoundsExceeded(
                "complete operational response exceeds 256 KiB ceiling; nothing was truncated"
                    .into(),
            ),
        );
    }
    let tokens = (params.payload_json.len() as u64).div_ceil(4).max(1);
    let consumed = BudgetVector::builder()
        .tokens(tokens)
        .bytes(params.payload_json.len() as u64)
        .build()
        .unwrap_or(BudgetVector::ZERO);
    let requested = BudgetVector::builder()
        .tokens(tokens.max(1024))
        .bytes(MAX_QUERY_OUTPUT_BYTES as u64)
        .build()
        .unwrap_or(consumed);
    let privacy = privacy_projection_json(
        &params.anchor,
        params.privacy_purpose,
        params.allowed_domains,
        params.redacted_domains,
    );
    let payload_digest = ContentDigest::sha256(params.payload_json.as_bytes());
    let fp_text = params.decision_fingerprint.to_text();
    let hex = fp_text.strip_prefix("sha256:").unwrap_or(&fp_text);
    let built = AgentResponseEnvelope::new(
        fss_core::reference_contract_basis(),
        params.operation,
        format!("request:{}:{hex}", params.operation),
        1,
        params.principal.as_str(),
        params.session_id.map(|id| id.as_str().to_owned()),
        None,
        format!("trace:{}:{hex}", params.operation),
        params.anchor,
        None,
        None,
        params.view,
        params.capabilities,
        privacy,
        ResponseOutcome::Ok,
        None,
        Some(ResponseTaskState::None),
        None,
        params.payload_schema,
        params.payload_json,
        payload_digest,
        params.epistemic_state,
        params.completeness,
        params.warnings,
        Vec::new(),
        vec!["Payload tokens are estimated deterministically as ceil(bytes / 4).".to_owned()],
        agent_json::budget_summary(&requested, &consumed),
        params.proof_pointers,
        Vec::new(),
        params.decision_fingerprint,
        None,
        None,
        None,
        params.idempotency_key,
        params.recovery_class,
        params.safe_retry,
        false,
        params.boundary,
        params.created_at_ns,
    );
    let rendered = built
        .ok()
        .filter(|env| env.validate().is_ok())
        .and_then(|env| agent_json::response_envelope(&env, &[]));
    match rendered {
        Some(out) if out.len() <= MAX_QUERY_OUTPUT_BYTES => (out, ExitIdentity::SUCCESS),
        Some(_) => render_refusal_envelope(
            root,
            params.operation,
            params.principal,
            params.session_id,
            params.payload_schema,
            &OpsError::BoundsExceeded(
                "serialized AgentResponseEnvelope exceeds 256 KiB ceiling; nothing was truncated"
                    .into(),
            ),
        ),
        None => render_refusal_envelope(
            root,
            params.operation,
            params.principal,
            params.session_id,
            params.payload_schema,
            &OpsError::OperationFailed("failed to validate operational response envelope".into()),
        ),
    }
}

/// Renders a payload-free fail-closed refusal envelope preserving exact error identities.
pub(crate) fn render_refusal_envelope(
    root: &Path,
    operation: &'static str,
    principal: &PrincipalId,
    session_id: Option<&SessionId>,
    payload_schema: &'static str,
    error: &OpsError,
) -> (String, ExitIdentity) {
    let mut enc = CanonicalEncoder::new();
    enc.text(OPS_REFUSAL_DOMAIN);
    enc.text(operation);
    enc.text(principal.as_str());
    enc.text(error.error_id());
    enc.text(&error.to_string());
    let fingerprint = ContentDigest::sha256(&enc.finish());
    let fp_text = fingerprint.to_text();
    let hex = fp_text.strip_prefix("sha256:").unwrap_or(&fp_text);
    let anchor = LedgerAnchor::genesis("site:ops-refusal");
    let privacy = privacy_projection_json(
        &anchor,
        "payload-free fail-closed operational refusal",
        &[],
        &["all-requested-operational-data"],
    );
    let payload_json = "null".to_owned();
    let payload_digest = ContentDigest::sha256(payload_json.as_bytes());
    let recovery = match error {
        OpsError::DaemonUnavailable(_) => "retry_when_daemon_running",
        OpsError::ApprovalRequired(_) | OpsError::ApprovalMismatch(_) => {
            "preview_and_supply_exact_approval"
        }
        _ => "operator_action_required",
    };
    let built = AgentResponseEnvelope::new(
        fss_core::reference_contract_basis(),
        operation,
        format!("request:{operation}:{hex}"),
        1,
        principal.as_str(),
        session_id.map(|id| id.as_str().to_owned()),
        None,
        format!("trace:{operation}:{hex}"),
        anchor,
        None,
        None,
        AgentView::Case,
        Vec::new(),
        privacy,
        ResponseOutcome::Refused,
        None,
        Some(ResponseTaskState::None),
        Some(error.error_id().to_owned()),
        payload_schema,
        payload_json,
        payload_digest,
        KnowledgeState::Unknown,
        Completeness::Partial,
        vec![error.to_string()],
        Vec::new(),
        vec!["Refused fail-closed before disclosing unauthorized or unapproved state.".to_owned()],
        agent_json::budget_summary(&BudgetVector::ZERO, &BudgetVector::ZERO),
        Vec::new(),
        Vec::new(),
        fingerprint,
        None,
        None,
        None,
        None,
        recovery,
        ResponseSafeRetry::No,
        false,
        ExecutionBoundary {
            completed: vec![format!("Refused fail-closed ({}).", error.error_id())],
            not_started: vec!["No unauthorized read, policy mutation, or effect occurred.".into()],
            possibly_occurred: Vec::new(),
            preserved_truth: vec!["Authority and effect boundaries remain intact.".into()],
            invalidated: Vec::new(),
        },
        0,
    );
    let rendered = built
        .ok()
        .filter(|env| env.validate().is_ok())
        .and_then(|env| agent_json::response_envelope(&env, &[]));
    match rendered {
        Some(out) => (out, error.exit_identity()),
        None => (
            crate::orient_cmd::execution_diagnostic(
                operation,
                root,
                error.error_id(),
                error.exit_identity(),
            ),
            error.exit_identity(),
        ),
    }
}

fn privacy_projection_json(
    anchor: &LedgerAnchor,
    purpose: &str,
    allowed: &[&str],
    redacted: &[&str],
) -> String {
    object(&[
        ("schema", string("fss.privacy_projection.v1")),
        (
            "policyGenerationId",
            string(&format!("privacy-epoch:{}", anchor.privacy_epoch)),
        ),
        ("purpose", string(purpose)),
        ("allowedDomains", strings(allowed.iter().copied())),
        ("redactedDomains", strings(redacted.iter().copied())),
        (
            "retentionClass",
            string("retention:current-deletion-restrictions"),
        ),
        ("auditRequired", "true".to_owned()),
    ])
}
