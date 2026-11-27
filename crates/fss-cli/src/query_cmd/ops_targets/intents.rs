#![forbid(unsafe_code)]
//! `AOP-007 plan` + `AOP-008 commit` operational intent families:
//! - `privacy-mask`: preview + exact approval digest + durable `PrivacyMaskPolicy`
//! - `evidence-hold`: preview + exact approval digest + durable `HoldRecord`
//! - `retention-policy`: preview + exact approval digest + durable `RetentionPolicyRecord`
//! - `camera-supervision`: preview + exact approval digest + bounded `fss-ipc` control dispatch
//!   (explicit `ERR-DAEMON-OFFLINE-001` refusal when offline; zero shell execution)
//!
//! Semantic plane: `"authority"` (every mutation requires preview -> exact approval digest ->
//! capability-checked durable commit with deterministic idempotency keys).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fss_core::{
    AgentView, BudgetVector, CanonicalEncode, CanonicalEncoder, CaptureInterval, Completeness,
    ContentDigest, ContextAuthority, ExecutionBoundary, KnowledgeState, LedgerAnchor, OperationId,
    PrincipalId, ResponseSafeRetry, RootAuthoritySpec, SensorId, SessionId, TimestampNs,
};
use fss_daemon::control::{
    DAEMON_STOP_TARGET, DaemonRuntimeDescriptor, control_op_approval_digest,
    daemon_stop_approval_digest, manifest_reload_approval_digest,
};
use fss_ipc::{
    BoundedControlOp, ControlOperationState, IpcClient, IpcClientConfig, IpcResponse,
    RetainedControlProgress, deployment_root_digest,
};
use fss_reference::agent_orient::{OrientLimits, read_deployment_cancellable};
use fss_reference::deletion::holds::{
    HoldError, HoldOutcome, HoldRequest, HoldState, commit_hold, preview_hold,
};
use fss_reference::deletion::retention::policy::{
    PolicyChangeRequest, PolicyError, PolicyOutcome, commit_policy_change, preview_policy_change,
};
use fss_reference::ingest::privacy_mask::{
    MaskDeclarationStatus, PrivacyMaskError, PrivacyMaskPolicy, declare_mask, preview_mask,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx};

use super::{
    CAP_AGENT_PLAN_COMMIT, CAP_AGENT_PLAN_PREPARE, CAP_OBSERVE_STATUS, CAP_RETENTION_COMMIT,
    CAP_RETENTION_PREPARE, OpsEnvelopeParams, OpsError, ensure_deployment_root, is_valid_sha256,
    render_ok_envelope, render_refusal_envelope, require_capabilities,
    resolve_effective_capabilities,
};
use crate::error::ExitIdentity;
use crate::json_output::{object, string};

#[cfg(test)]
#[path = "intents_control_tests.rs"]
mod control_tests;

/// Registered payload schema for operational `plan` previews.
pub const OPS_PLAN_PAYLOAD_SCHEMA: &str = "fss.agent_ops_intent_plan.v1";
/// Registered payload schema for operational `commit` executions.
pub const OPS_COMMIT_PAYLOAD_SCHEMA: &str = "fss.agent_ops_intent_commit.v1";
/// Canonical digest domain for `privacy-mask` operational intents.
pub const INTENT_PRIVACY_MASK_DOMAIN: &str = "fss.ops_targets.intent_privacy_mask.v1";
/// Canonical digest domain for `evidence-hold` operational intents.
pub const INTENT_EVIDENCE_HOLD_DOMAIN: &str = "fss.ops_targets.intent_evidence_hold.v1";
/// Canonical digest domain for `retention-policy` operational intents.
pub const INTENT_RETENTION_POLICY_DOMAIN: &str = "fss.ops_targets.intent_retention_policy.v1";
/// Canonical digest domain for `camera-supervision` operational intents.
pub const INTENT_CAMERA_SUPERVISION_DOMAIN: &str = "fss.ops_targets.intent_camera_supervision.v1";
/// Canonical digest domain for a proposed control request at an exact owner/anchor scope.
pub const CAMERA_CONTROL_REQUEST_DOMAIN: &str = "fss.ops_targets.camera_control_request.v1";

/// Closed set of operational intent variants admitted by `plan` and `commit`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpsIntentKind {
    /// Declare a durable per-sensor `PrivacyMaskPolicy`.
    PrivacyMask {
        /// Target camera sensor identity.
        sensor: SensorId,
        /// Declared decoded stream resolution `[width, height]`.
        resolution: [u32; 2],
        /// One to 32 axis-aligned `[x, y, width, height]` redaction rectangles.
        rectangles: Vec<[u32; 4]>,
    },
    /// Place, release, retain-until, or expire a durable legal `HoldRecord`.
    EvidenceHold {
        /// Hold action (`place`, `release`, `retain`, `expire`).
        action: String,
        /// Stable hold identifier.
        hold_id: String,
        /// Exact retained import SHA-256 identity.
        import_id: ContentDigest,
        /// Non-secret rationale.
        reason: String,
        /// Optional deadline timestamp (required for `retain` and `expire`).
        until_ns: Option<i128>,
        /// Optional explicit owner time assertion `(earliest_ns, latest_ns)` (for `expire`).
        attested_now_ns: Option<(i128, i128)>,
    },
    /// Adopt or update a durable per-sensor bounded `RetentionPolicyRecord`.
    RetentionPolicy {
        /// Target camera sensor identity.
        sensor: SensorId,
        /// Whether cleanup requests may use this policy generation.
        enabled: bool,
        /// Positive minimum retention age in nanoseconds.
        retain_for_ns: u64,
        /// Optional bounded retention ring source-byte budget.
        max_retained_source_bytes: Option<u64>,
        /// Optional predecessor policy digest (`None` for first adoption).
        expected_policy: Option<ContentDigest>,
        /// Explicit owner time assertion `(earliest_ns, latest_ns)` for impact preview.
        attested_now_ns: (i128, i128),
        /// Non-secret rationale.
        reason: String,
    },
    /// Dispatch a closed-enum bounded supervisor command over local `fss-ipc`.
    CameraSupervision {
        /// Closed bounded control operation (`BoundedControlOp`).
        op: BoundedControlOp,
        /// Target camera identifier (required for camera-scoped ops, absent for reload/scrub).
        camera_id: Option<String>,
        /// Optional explicit site identifier override.
        site_id: Option<String>,
        /// Stable key returned by preview. Required on commit and every retry;
        /// use a distinct key for a distinct intentional operation.
        idempotency_key: Option<ContentDigest>,
    },
}

/// Request parameters shared by operational `plan` (preview) and `commit` (execute).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpsIntentRequest {
    /// Existing deployment root directory.
    pub root: PathBuf,
    /// Audit principal label.
    pub principal: PrincipalId,
    /// Optional owning session identity.
    pub session_id: Option<SessionId>,
    /// Typed operational intent variant.
    pub intent: OpsIntentKind,
    /// Exact approval digest returned by `plan` (mandatory on `commit`, absent on `plan`).
    pub approval_digest: Option<ContentDigest>,
    /// Explicit launcher/CLI capability grants.
    pub granted_capabilities: BTreeSet<String>,
}

struct IntentCtx<'a> {
    root: &'a Path,
    site_lineage: &'a str,
    anchor: &'a LedgerAnchor,
    principal: &'a PrincipalId,
    approval: Option<ContentDigest>,
}

struct IntentOutcome {
    anchor: LedgerAnchor,
    payload_json: String,
    proof_pointers: Vec<String>,
    warnings: Vec<String>,
    fingerprint: ContentDigest,
    idempotency_key: String,
    completed_note: String,
    not_started: Vec<String>,
    possibly_occurred: Vec<String>,
}

/// Executes an operational `plan` preview (read-only, zero mutations) and renders an envelope.
pub(crate) fn execute_plan(
    req: &OpsIntentRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> (String, ExitIdentity) {
    match run_intent(req, false, cancelled) {
        Ok(params) => render_ok_envelope(&req.root, params),
        Err(err) => render_refusal_envelope(
            &req.root,
            "plan",
            &req.principal,
            req.session_id.as_ref(),
            OPS_PLAN_PAYLOAD_SCHEMA,
            &err,
        ),
    }
}

/// Executes an operational `commit` (approval-gated, capability-checked, idempotent).
pub(crate) fn execute_commit(
    req: &OpsIntentRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> (String, ExitIdentity) {
    match run_intent(req, true, cancelled) {
        Ok(params) => render_ok_envelope(&req.root, params),
        Err(err) => render_refusal_envelope(
            &req.root,
            "commit",
            &req.principal,
            req.session_id.as_ref(),
            OPS_COMMIT_PAYLOAD_SCHEMA,
            &err,
        ),
    }
}

fn run_intent<'a>(
    req: &'a OpsIntentRequest,
    is_commit: bool,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<OpsEnvelopeParams<'a>, OpsError> {
    if cancelled() {
        return Err(OpsError::Cancelled);
    }
    let effective = resolve_effective_capabilities(
        &req.root,
        &req.principal,
        req.session_id.as_ref(),
        &req.granted_capabilities,
    )?;
    let required_caps = required_caps_for(&req.intent, is_commit);
    require_capabilities(
        &effective,
        &required_caps,
        if is_commit {
            "operational commit intent"
        } else {
            "operational plan preview"
        },
    )?;
    let approval = if is_commit {
        let digest = req.approval_digest.ok_or_else(|| {
            OpsError::ApprovalRequired(
                "commit requires exact approval_digest from plan preview".into(),
            )
        })?;
        if !is_valid_sha256(digest) {
            return Err(OpsError::ApprovalMismatch(
                "approval_digest must be canonical nonzero SHA-256".into(),
            ));
        }
        Some(digest)
    } else {
        None
    };

    ensure_deployment_root(&req.root)?;
    let snapshot = read_deployment_cancellable(&req.root, &OrientLimits::default(), cancelled)
        .map_err(|err| OpsError::OperationFailed(format!("deployment snapshot failed: {err}")))?;
    let ctx = IntentCtx {
        root: &req.root,
        site_lineage: &snapshot.site_lineage,
        anchor: &snapshot.anchor,
        principal: &req.principal,
        approval,
    };
    let outcome = match &req.intent {
        OpsIntentKind::PrivacyMask {
            sensor,
            resolution,
            rectangles,
        } => run_privacy_mask(&ctx, sensor, *resolution, rectangles)?,
        OpsIntentKind::EvidenceHold {
            action,
            hold_id,
            import_id,
            reason,
            until_ns,
            attested_now_ns,
        } => run_evidence_hold(
            &ctx,
            action,
            hold_id,
            *import_id,
            reason,
            *until_ns,
            *attested_now_ns,
        )?,
        OpsIntentKind::RetentionPolicy {
            sensor,
            enabled,
            retain_for_ns,
            max_retained_source_bytes,
            expected_policy,
            attested_now_ns,
            reason,
        } => run_retention_policy(
            &ctx,
            sensor,
            *enabled,
            *retain_for_ns,
            *max_retained_source_bytes,
            *expected_policy,
            *attested_now_ns,
            reason,
        )?,
        OpsIntentKind::CameraSupervision {
            op,
            camera_id,
            site_id,
            idempotency_key,
        } => run_camera_supervision(
            &ctx,
            *op,
            camera_id.as_deref(),
            site_id.as_deref(),
            *idempotency_key,
        )?,
    };

    Ok(OpsEnvelopeParams {
        operation: if is_commit { "commit" } else { "plan" },
        principal: &req.principal,
        session_id: req.session_id.as_ref(),
        anchor: outcome.anchor,
        view: AgentView::Case,
        capabilities: required_caps.into_iter().map(str::to_owned).collect(),
        privacy_purpose: if is_commit {
            "approval-gated durable operational commit"
        } else {
            "read-only operational intent preview emitting exact approval digest"
        },
        allowed_domains: &["operational-intent-preview-and-commit-receipts"],
        redacted_domains: &["media-payloads", "raw-credentials"],
        payload_schema: if is_commit { OPS_COMMIT_PAYLOAD_SCHEMA } else { OPS_PLAN_PAYLOAD_SCHEMA },
        payload_json: outcome.payload_json,
        epistemic_state: KnowledgeState::Known,
        completeness: Completeness::Complete,
        warnings: outcome.warnings,
        proof_pointers: outcome.proof_pointers,
        decision_fingerprint: outcome.fingerprint,
        idempotency_key: Some(outcome.idempotency_key),
        safe_retry: ResponseSafeRetry::YesSameRequest,
        recovery_class: if is_commit {
            "reconciliation_required"
        } else {
            "operator_action_required"
        },
        boundary: ExecutionBoundary {
            completed: vec![outcome.completed_note],
            not_started: outcome.not_started,
            possibly_occurred: outcome.possibly_occurred,
            preserved_truth: vec![
                "Every mutating operational intent requires preview -> exact approval_digest -> capability-checked durable commit.".to_owned(),
            ],
            invalidated: Vec::new(),
        },
        created_at_ns: snapshot.latest_evidence_time.0,
    })
}

fn required_caps_for(intent: &OpsIntentKind, is_commit: bool) -> Vec<&'static str> {
    let base = if is_commit {
        CAP_AGENT_PLAN_COMMIT
    } else {
        CAP_AGENT_PLAN_PREPARE
    };
    match intent {
        OpsIntentKind::PrivacyMask { .. } => vec![base],
        OpsIntentKind::EvidenceHold { .. } | OpsIntentKind::RetentionPolicy { .. } => {
            vec![
                base,
                if is_commit {
                    CAP_RETENTION_COMMIT
                } else {
                    CAP_RETENTION_PREPARE
                },
            ]
        }
        OpsIntentKind::CameraSupervision { .. } => vec![base, CAP_OBSERVE_STATUS],
    }
}

fn build_write_context(
    ctx: &IntentCtx<'_>,
    extra_caps: &[&str],
) -> Result<(ContextAuthority, ReplayCx), OpsError> {
    let mut caps = vec![ADP_REPLAY_ROW_ID.to_owned()];
    caps.extend(extra_caps.iter().map(|s| (*s).to_owned()));
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:ops-intent-authority".to_owned(),
        operation_id: OperationId::parse("operation:ops-intent-authority")
            .map_err(|_| OpsError::OperationFailed("invalid authority operation id".into()))?,
        principal: ctx.principal.as_str().to_owned(),
        capabilities: caps,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(16 * 1024 * 1024)
            .storage_operations(16_384)
            .build()
            .map_err(|_| OpsError::BoundsExceeded("invalid write budget vector".into()))?,
        privacy_scope: "private:property".to_owned(),
        retention_scope: "retention:existing-deployment-policy".to_owned(),
        anchor_universe: ContentDigest::sha256(ctx.site_lineage.as_bytes()),
        generation: 1,
    })
    .map_err(|_| OpsError::OperationFailed("failed to construct write authority".into()))?;
    let cx =
        ReplayCx::from_context_authority(&authority, ctx.root.to_path_buf()).map_err(|_| {
            OpsError::OperationFailed("failed to construct write replay context".into())
        })?;
    Ok((authority, cx))
}

fn idempotency_digest(domain: &str, approval: ContentDigest, subject: &str) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text(domain);
    enc.text("idempotency");
    enc.digest(approval);
    enc.text(subject);
    ContentDigest::sha256(&enc.finish())
}

fn run_privacy_mask(
    ctx: &IntentCtx<'_>,
    sensor: &SensorId,
    resolution: [u32; 2],
    rectangles: &[[u32; 4]],
) -> Result<IntentOutcome, OpsError> {
    let policy = PrivacyMaskPolicy::new(sensor.clone(), resolution, rectangles)
        .map_err(|err| OpsError::InvalidRequest(format!("invalid privacy mask policy: {err}")))?;
    let (_, cx) = build_write_context(ctx, &[])?;
    let mut deployment = ReferenceDeployment::open(ctx.root, ctx.site_lineage, &cx)
        .map_err(|err| OpsError::OperationFailed(format!("failed to open deployment: {err}")))?;
    let decl = match ctx.approval {
        None => preview_mask(&deployment, &policy).map_err(|err| {
            OpsError::OperationFailed(format!("privacy mask preview failed: {err}"))
        })?,
        Some(digest) => {
            declare_mask(&mut deployment, &policy, digest, &cx).map_err(|err| match err {
                PrivacyMaskError::StaleApproval(_) => OpsError::ApprovalMismatch(err.to_string()),
                PrivacyMaskError::InvalidPolicy(_) => OpsError::InvalidRequest(err.to_string()),
                other => OpsError::OperationFailed(format!("privacy mask commit failed: {other}")),
            })?
        }
    };
    let anchor = deployment.current_anchor().clone();
    cx.drain_and_finalize();
    let idem = idempotency_digest(INTENT_PRIVACY_MASK_DOMAIN, decl.approval, sensor.as_str());
    let payload_json = object(&[
        ("intent", string("privacy-mask")),
        ("status", string(decl.status.as_str())),
        (
            "authorityChanged",
            (decl.status == MaskDeclarationStatus::Retained).to_string(),
        ),
        ("sensorId", string(sensor.as_str())),
        ("policyDigest", string(&decl.policy_digest.to_text())),
        ("approvalDigest", string(&decl.approval.to_text())),
        ("idempotencyKey", string(&idem.to_text())),
        (
            "generation",
            decl.generation
                .map_or_else(|| "null".to_owned(), |g| g.to_string()),
        ),
        (
            "replaces",
            decl.replaces
                .map_or_else(|| "null".to_owned(), |d| string(&d.to_text())),
        ),
    ]);
    let preview = ctx.approval.is_none();
    Ok(IntentOutcome {
        possibly_occurred: Vec::new(),
        anchor,
        payload_json,
        proof_pointers: vec![
            decl.policy_digest.to_text(),
            decl.approval.to_text(),
            idem.to_text(),
        ],
        warnings: if preview {
            vec![
                "Preview only; rerun commit with exact approvalDigest to retain this privacy mask."
                    .to_owned(),
            ]
        } else {
            Vec::new()
        },
        fingerprint: idem,
        idempotency_key: idem.to_text(),
        completed_note: if preview {
            format!("Previewed PrivacyMaskPolicy for {}.", sensor.as_str())
        } else {
            format!(
                "Committed PrivacyMaskPolicy for {} (status={}).",
                sensor.as_str(),
                decl.status.as_str()
            )
        },
        not_started: if preview {
            vec!["No privacy mask policy was committed during plan preview.".to_owned()]
        } else {
            Vec::new()
        },
    })
}

fn run_evidence_hold(
    ctx: &IntentCtx<'_>,
    action: &str,
    hold_id: &str,
    import_id: ContentDigest,
    reason: &str,
    until_ns: Option<i128>,
    attested_now_ns: Option<(i128, i128)>,
) -> Result<IntentOutcome, OpsError> {
    let state = match action {
        "place" => HoldState::Held,
        "release" => HoldState::Released,
        "retain" => HoldState::Until {
            not_before: TimestampNs(until_ns.ok_or_else(|| {
                OpsError::InvalidRequest("evidence-hold retain requires until_ns".into())
            })?),
        },
        "expire" => {
            let not_before = until_ns.ok_or_else(|| {
                OpsError::InvalidRequest("evidence-hold expire requires until_ns".into())
            })?;
            let (e, l) = attested_now_ns.ok_or_else(|| {
                OpsError::InvalidRequest("evidence-hold expire requires attested_now_ns".into())
            })?;
            let attested_now =
                CaptureInterval::new(TimestampNs(e), TimestampNs(l)).map_err(|_| {
                    OpsError::InvalidRequest("attested_now_ns requires earliest <= latest".into())
                })?;
            HoldState::Expired {
                not_before: TimestampNs(not_before),
                attested_now,
            }
        }
        other => {
            return Err(OpsError::InvalidRequest(format!(
                "unsupported evidence-hold action `{other}`"
            )));
        }
    };
    let request = HoldRequest {
        hold_id: hold_id.to_owned(),
        import_identity: import_id,
        state,
        reason: reason.to_owned(),
    };
    request
        .validate()
        .map_err(|err| OpsError::InvalidRequest(format!("invalid hold request: {err}")))?;
    let caps: &[&str] = if ctx.approval.is_some() {
        &[CAP_RETENTION_PREPARE, CAP_RETENTION_COMMIT]
    } else {
        &[CAP_RETENTION_PREPARE]
    };
    let (authority, cx) = build_write_context(ctx, caps)?;
    let mut deployment = ReferenceDeployment::open(ctx.root, ctx.site_lineage, &cx)
        .map_err(|err| OpsError::OperationFailed(format!("failed to open deployment: {err}")))?;
    let receipt = match ctx.approval {
        None => preview_hold(&deployment, &request, &authority, &cx).map_err(|err| {
            OpsError::OperationFailed(format!("evidence hold preview failed: {err}"))
        })?,
        Some(digest) => commit_hold(&mut deployment, &request, digest, &authority, &cx).map_err(
            |err| match err {
                HoldError::StaleApproval => {
                    OpsError::ApprovalMismatch("evidence hold approval digest mismatch".into())
                }
                HoldError::Unauthorized => OpsError::CapabilityDenied(err.to_string()),
                HoldError::InvalidRequest(_) => OpsError::InvalidRequest(err.to_string()),
                other => OpsError::OperationFailed(format!("evidence hold commit failed: {other}")),
            },
        )?,
    };
    let anchor = deployment.current_anchor().clone();
    cx.drain_and_finalize();
    let approval_out = receipt.record.approval();
    let idem = idempotency_digest(INTENT_EVIDENCE_HOLD_DOMAIN, approval_out, hold_id);
    let payload_json = object(&[
        ("intent", string("evidence-hold")),
        ("status", string(receipt.outcome.as_str())),
        (
            "authorityChanged",
            (receipt.outcome == HoldOutcome::Committed).to_string(),
        ),
        ("holdId", string(&receipt.record.request().hold_id)),
        (
            "importId",
            string(&receipt.record.request().import_identity.to_text()),
        ),
        ("holdState", string(receipt.record.request().state.as_str())),
        ("recordDigest", string(&receipt.record.digest().to_text())),
        ("approvalDigest", string(&approval_out.to_text())),
        ("idempotencyKey", string(&idem.to_text())),
        ("deletionPerformed", "false".to_owned()),
    ]);
    let preview = ctx.approval.is_none();
    Ok(IntentOutcome {
        possibly_occurred: Vec::new(),
        anchor,
        payload_json,
        proof_pointers: vec![
            receipt.record.digest().to_text(),
            approval_out.to_text(),
            idem.to_text(),
        ],
        warnings: if preview {
            vec!["Preview only; rerun commit with exact approvalDigest to persist this evidence hold.".to_owned()]
        } else {
            Vec::new()
        },
        fingerprint: idem,
        idempotency_key: idem.to_text(),
        completed_note: if preview {
            format!("Previewed evidence hold {hold_id} ({action}).")
        } else {
            format!(
                "Committed evidence hold {hold_id} (status={}).",
                receipt.outcome.as_str()
            )
        },
        not_started: vec![
            if preview {
                "No hold record was written during plan preview."
            } else {
                "No evidence bytes were deleted."
            }
            .to_owned(),
        ],
    })
}

#[allow(clippy::too_many_arguments)]
fn run_retention_policy(
    ctx: &IntentCtx<'_>,
    sensor: &SensorId,
    enabled: bool,
    retain_for_ns: u64,
    max_retained_source_bytes: Option<u64>,
    expected_policy: Option<ContentDigest>,
    attested_now_ns: (i128, i128),
    reason: &str,
) -> Result<IntentOutcome, OpsError> {
    let attested_now = CaptureInterval::new(
        TimestampNs(attested_now_ns.0),
        TimestampNs(attested_now_ns.1),
    )
    .map_err(|_| OpsError::InvalidRequest("attested_now_ns requires earliest <= latest".into()))?;
    let request = PolicyChangeRequest {
        sensor: sensor.clone(),
        enabled,
        retain_for_ns,
        max_retained_source_bytes,
        expected_policy,
        attested_now,
        reason: reason.to_owned(),
    };
    request
        .validate()
        .map_err(|err| OpsError::InvalidRequest(format!("invalid retention policy: {err}")))?;
    let caps: &[&str] = if ctx.approval.is_some() {
        &[CAP_RETENTION_PREPARE, CAP_RETENTION_COMMIT]
    } else {
        &[CAP_RETENTION_PREPARE]
    };
    let (authority, cx) = build_write_context(ctx, caps)?;
    let mut deployment = ReferenceDeployment::open(ctx.root, ctx.site_lineage, &cx)
        .map_err(|err| OpsError::OperationFailed(format!("failed to open deployment: {err}")))?;
    let receipt = match ctx.approval {
        None => preview_policy_change(&deployment, &request, &authority, &cx).map_err(|err| {
            OpsError::OperationFailed(format!("retention policy preview failed: {err}"))
        })?,
        Some(digest) => commit_policy_change(&mut deployment, &request, digest, &authority, &cx)
            .map_err(|err| match err {
                PolicyError::StaleApproval => {
                    OpsError::ApprovalMismatch("retention policy approval digest mismatch".into())
                }
                PolicyError::Unauthorized => OpsError::CapabilityDenied(err.to_string()),
                PolicyError::InvalidRequest => OpsError::InvalidRequest(err.to_string()),
                other => {
                    OpsError::OperationFailed(format!("retention policy commit failed: {other}"))
                }
            })?,
    };
    let anchor = deployment.current_anchor().clone();
    cx.drain_and_finalize();
    let approval_out = receipt.record.approval();
    let idem = idempotency_digest(
        INTENT_RETENTION_POLICY_DOMAIN,
        approval_out,
        sensor.as_str(),
    );
    let payload_json = object(&[
        ("intent", string("retention-policy")),
        ("status", string(receipt.outcome.as_str())),
        (
            "authorityChanged",
            (receipt.outcome == PolicyOutcome::Committed).to_string(),
        ),
        ("sensorId", string(sensor.as_str())),
        ("enabled", enabled.to_string()),
        ("generation", receipt.record.generation().to_string()),
        ("retainForNs", string(&retain_for_ns.to_string())),
        (
            "maxRetainedSourceBytes",
            max_retained_source_bytes.map_or_else(|| "null".to_owned(), |b| string(&b.to_string())),
        ),
        ("recordDigest", string(&receipt.record.digest().to_text())),
        ("approvalDigest", string(&approval_out.to_text())),
        ("idempotencyKey", string(&idem.to_text())),
        ("deletionPerformed", "false".to_owned()),
    ]);
    let preview = ctx.approval.is_none();
    Ok(IntentOutcome {
        possibly_occurred: Vec::new(),        anchor, payload_json,
        proof_pointers: vec![receipt.record.digest().to_text(), approval_out.to_text(), idem.to_text()],
        warnings: vec![if preview {
            "Preview only; rerun commit with exact approvalDigest to adopt this retention policy. Adoption never deletes bytes."
        } else {
            "Retention policy committed; no evidence bytes were deleted."
        }.to_owned()],
        fingerprint: idem, idempotency_key: idem.to_text(),
        completed_note: if preview {
            format!("Previewed retention policy for {}.", sensor.as_str())
        } else {
            format!("Committed retention policy generation {} for {} (status={}).", receipt.record.generation(), sensor.as_str(), receipt.outcome.as_str())
        },
        not_started: vec![if preview { "No retention policy was written during plan preview." } else { "No evidence cleanup or byte deletion was executed." }.to_owned()],
    })
}

fn camera_control_request_key(
    ctx: &IntentCtx<'_>,
    expected_approval: ContentDigest,
    supplied_key: Option<ContentDigest>,
) -> Result<ContentDigest, OpsError> {
    if let Some(key) = supplied_key {
        if !is_valid_sha256(key) || key.is_laboratory() {
            return Err(OpsError::InvalidRequest(
                "idempotency_key must be a canonical nonzero SHA-256 request identity".into(),
            ));
        }
        return Ok(key);
    }
    if ctx.approval.is_some() {
        return Err(OpsError::InvalidRequest(
            "camera-supervision commit requires the idempotency_key returned by plan; retain it for every retry".into(),
        ));
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CAMERA_CONTROL_REQUEST_DOMAIN);
    encoder.digest(deployment_root_digest(ctx.root));
    encoder.text(ctx.principal.as_str());
    ctx.anchor.encode_canonical(&mut encoder);
    encoder.digest(expected_approval);
    Ok(ContentDigest::sha256(&encoder.finish()))
}

fn run_camera_supervision(
    ctx: &IntentCtx<'_>,
    op: BoundedControlOp,
    camera_id: Option<&str>,
    site_id_override: Option<&str>,
    request_key: Option<ContentDigest>,
) -> Result<IntentOutcome, OpsError> {
    if op.requires_camera_id() && camera_id.is_none() {
        return Err(OpsError::InvalidRequest(format!(
            "camera-supervision op `{}` requires camera_id",
            op.as_str()
        )));
    }
    if matches!(
        op,
        BoundedControlOp::ReloadManifest | BoundedControlOp::TriggerScrub
    ) && camera_id.is_some()
    {
        return Err(OpsError::InvalidRequest(format!(
            "camera-supervision op `{}` is deployment-wide and does not accept camera_id",
            op.as_str()
        )));
    }
    let descriptor_res = DaemonRuntimeDescriptor::read_from_root(ctx.root);
    let deployment_id = site_id_override
        .map(str::to_owned)
        .or_else(|| descriptor_res.as_ref().ok().map(|d| d.site_id.clone()))
        .unwrap_or_else(|| ctx.site_lineage.to_owned());
    let reload_preview = if op == BoundedControlOp::ReloadManifest && ctx.approval.is_none() {
        let descriptor = descriptor_res.as_ref().map_err(|err| {
            OpsError::DaemonUnavailable(format!(
                "daemon_unavailable: exact reload preview requires the live manifest owner ({err})"
            ))
        })?;
        Some(request_manifest_reload_preview(
            ctx,
            &deployment_id,
            descriptor,
        )?)
    } else {
        None
    };
    let expected_approval = if op == BoundedControlOp::ReloadManifest {
        // A commit carries the original sealed approval. Fetching a fresh preview here would
        // replace its identity after file/active-generation drift and prevent exact replay.
        // The daemon first resolves the retained key, then validates fresh admission.
        reload_preview
            .map(|preview| preview.approval_digest)
            .or(ctx.approval)
            .ok_or_else(|| {
                OpsError::ApprovalRequired("reload preview approval is required".into())
            })?
    } else if op == BoundedControlOp::StopCamera && camera_id == Some(DAEMON_STOP_TARGET) {
        daemon_stop_approval_digest(&deployment_id, deployment_root_digest(ctx.root))
    } else {
        control_op_approval_digest(&deployment_id, op, camera_id)
    };
    if !is_valid_sha256(expected_approval) || expected_approval.is_laboratory() {
        return Err(OpsError::ApprovalMismatch(
            "control approval must be canonical nonzero SHA-256".into(),
        ));
    }
    let idem = camera_control_request_key(ctx, expected_approval, request_key)?;

    let Some(supplied_approval) = ctx.approval else {
        let daemon_live = descriptor_res.is_ok();
        let mut payload_fields = vec![
            ("intent", string("camera-supervision")),
            ("status", string("proposed")),
            ("authorityChanged", "false".to_owned()),
            ("deploymentId", string(&deployment_id)),
            ("op", string(op.as_str())),
            (
                "cameraId",
                camera_id.map_or_else(|| "null".to_owned(), string),
            ),
            ("daemonLive", daemon_live.to_string()),
            ("approvalDigest", string(&expected_approval.to_text())),
            ("idempotencyKey", string(&idem.to_text())),
            ("semanticCompletionProved", "false".to_owned()),
        ];
        let mut proof_pointers = vec![
            ctx.anchor.state_root.to_text(),
            expected_approval.to_text(),
            idem.to_text(),
        ];
        if let Some(preview) = reload_preview {
            payload_fields.push((
                "activeManifestDigest",
                string(&preview.active_manifest_digest.to_text()),
            ));
            payload_fields.push((
                "candidateManifestDigest",
                string(&preview.candidate_manifest_digest.to_text()),
            ));
            proof_pointers.push(preview.active_manifest_digest.to_text());
            proof_pointers.push(preview.candidate_manifest_digest.to_text());
        }
        return Ok(IntentOutcome {
            anchor: ctx.anchor.clone(),
            payload_json: object(&payload_fields),
            proof_pointers,
            warnings: vec![
                "Preview only; commit with the exact approvalDigest and idempotencyKey. Keep the key for retries; choose a new key for a distinct intended operation.".to_owned(),
                if reload_preview.is_some() {
                    "Reload approval binds the exact active and candidate manifest digests. Fresh admission and execution refuse drift; retries keep the original approval and key."
                } else if daemon_live {
                    "The descriptor is present; commit still requires a live daemon with durable keyed-control support."
                } else {
                    "The daemon is offline; commit refuses until a compatible daemon is started."
                }.to_owned(),
            ],
            fingerprint: idem,
            idempotency_key: idem.to_text(),
            completed_note: format!(
                "Previewed bounded camera supervision op `{}` without contacting the control queue.",
                op.as_str()
            ),
            not_started: vec!["No IPC control command was dispatched during plan preview.".to_owned()],
            possibly_occurred: Vec::new(),
        });
    };

    if supplied_approval != expected_approval {
        return Err(OpsError::ApprovalMismatch(format!(
            "camera-supervision approval digest mismatch for op `{}`",
            op.as_str()
        )));
    }
    let descriptor = descriptor_res.map_err(|err| {
        OpsError::DaemonUnavailable(format!("daemon_unavailable: fss-daemon is offline ({err}); start fss-daemon before committing camera-supervision"))
    })?;
    let mut client =
        connect_control_client(ctx, &deployment_id, &descriptor, CAP_AGENT_PLAN_COMMIT)?;

    let req_id = client.next_request_id();
    let response = client
        .submit_idempotent_control(
            req_id, idem, op, camera_id.map(str::to_owned), supplied_approval,
        )
        .map_err(|err| {
            control_outcome_uncertain(
                ctx, supplied_approval, idem,
                format!("fss-ipc submission has no conclusive receipt ({err}); retain the original idempotency_key"),
            )
        })?;
    camera_control_response(
        ctx,
        op,
        camera_id,
        &deployment_id,
        descriptor.descriptor_digest(),
        supplied_approval,
        idem,
        req_id,
        response,
    )
}

#[derive(Clone, Copy)]
struct ManifestReloadPreview {
    active_manifest_digest: ContentDigest,
    candidate_manifest_digest: ContentDigest,
    approval_digest: ContentDigest,
}

fn connect_control_client(
    ctx: &IntentCtx<'_>,
    deployment_id: &str,
    descriptor: &DaemonRuntimeDescriptor,
    capability: &str,
) -> Result<IpcClient, OpsError> {
    IpcClient::connect(IpcClientConfig {
        deployment_root: ctx.root.to_path_buf(),
        deployment_id: deployment_id.to_owned(),
        contract_basis_digest: descriptor.contract_basis_digest,
        principal: ctx.principal.clone(),
        capabilities: vec![CAP_OBSERVE_STATUS.to_owned(), capability.to_owned()],
        io_timeout: Duration::from_secs(5),
    })
    .map_err(|err| {
        OpsError::DaemonUnavailable(format!(
            "daemon_unavailable: fss-ipc connect failed ({err})"
        ))
    })
}

fn request_manifest_reload_preview(
    ctx: &IntentCtx<'_>,
    deployment_id: &str,
    descriptor: &DaemonRuntimeDescriptor,
) -> Result<ManifestReloadPreview, OpsError> {
    let mut client =
        connect_control_client(ctx, deployment_id, descriptor, CAP_AGENT_PLAN_PREPARE)?;
    let request_id = client.next_request_id();
    let response = client.preview_manifest_reload(request_id).map_err(|err| {
        OpsError::DaemonUnavailable(format!(
            "daemon_unavailable: exact manifest reload preview failed ({err})"
        ))
    })?;
    validate_manifest_reload_preview(ctx, deployment_id, request_id, response)
}

fn validate_manifest_reload_preview(
    ctx: &IntentCtx<'_>,
    deployment_id: &str,
    request_id: u64,
    response: IpcResponse,
) -> Result<ManifestReloadPreview, OpsError> {
    if response.request_id() != request_id {
        return Err(OpsError::OperationFailed(
            "manifest reload preview response does not match its request".into(),
        ));
    }
    match response {
        IpcResponse::ManifestReloadPreview {
            active_manifest_digest,
            candidate_manifest_digest,
            approval_digest,
            ..
        } => {
            if [
                active_manifest_digest,
                candidate_manifest_digest,
                approval_digest,
            ]
            .into_iter()
            .any(|digest| !is_valid_sha256(digest) || digest.is_laboratory())
                || approval_digest
                    != manifest_reload_approval_digest(
                        deployment_id,
                        deployment_root_digest(ctx.root),
                        active_manifest_digest,
                        candidate_manifest_digest,
                    )
            {
                return Err(OpsError::OperationFailed(
                    "manifest reload preview does not bind this deployment and exact active/candidate generations".into(),
                ));
            }
            Ok(ManifestReloadPreview {
                active_manifest_digest,
                candidate_manifest_digest,
                approval_digest,
            })
        }
        IpcResponse::Refused {
            error_id, reason, ..
        } => Err(OpsError::OperationFailed(format!(
            "daemon refused exact manifest reload preview ({error_id}): {reason}"
        ))),
        IpcResponse::Cancelled { .. } => Err(OpsError::Cancelled),
        _ => Err(OpsError::OperationFailed(
            "unexpected fss-ipc response to PreviewManifestReload".into(),
        )),
    }
}

fn control_outcome_uncertain(
    ctx: &IntentCtx<'_>,
    approval: ContentDigest,
    key: ContentDigest,
    detail: String,
) -> OpsError {
    // Keep the diagnostic bounded so the uncertainty envelope always retains its retry key.
    let detail: String = detail.chars().take(768).collect();
    OpsError::ControlOutcomeUncertain {
        detail,
        idempotency_key: key,
        approval_digest: approval,
        input_anchor: Box::new(ctx.anchor.clone()),
    }
}

#[allow(clippy::too_many_arguments)]
fn camera_control_response(
    ctx: &IntentCtx<'_>,
    op: BoundedControlOp,
    camera_id: Option<&str>,
    deployment_id: &str,
    descriptor_digest: ContentDigest,
    approval: ContentDigest,
    key: ContentDigest,
    request_id: u64,
    response: IpcResponse,
) -> Result<IntentOutcome, OpsError> {
    if response.request_id() != request_id {
        return Err(control_outcome_uncertain(
            ctx,
            approval,
            key,
            format!(
                "Control response correlation {} does not match submitted request {request_id}; no receipt is attributed to this key.",
                response.request_id()
            ),
        ));
    }
    let (operation_id, status, progress, recovered) = match response {
        IpcResponse::ControlAccepted { operation_id, state, .. } => {
            let status = match state {
                ControlOperationState::Queued => "queued",
                ControlOperationState::Accepted => "accepted",
                ControlOperationState::Executing => "executing",
                ControlOperationState::Completed => "completed",
            };
            (operation_id, status, None, false)
        }
        IpcResponse::ControlReplayed { operation_id, progress, recovered, .. } => {
            (operation_id, "replayed", Some(progress), recovered)
        }
        IpcResponse::Refused { error_id, reason, .. } => {
            let detail = format!("daemon refused bounded control ({error_id}): {reason}");
            return Err(if matches!(
                error_id.as_str(),
                fss_core::ERR_OP_RECONCILIATION_REQUIRED_001 | "ERR-DAEMON-SHUTDOWN-001"
            ) {
                control_outcome_uncertain(ctx, approval, key, detail)
            } else {
                OpsError::OperationFailed(detail)
            });
        }
        IpcResponse::Cancelled { .. } => return Err(control_outcome_uncertain(
            ctx, approval, key,
            "Control submission was cancelled; reconcile the original key before deciding whether its retained operation executed.".to_owned(),
        )),
        _ => return Err(control_outcome_uncertain(
            ctx, approval, key,
            "Unexpected fss-ipc response to SubmitIdempotentControl; the original submission outcome is unknown.".to_owned(),
        )),
    };
    let replayed = progress.is_some();
    let possibly_occurred = if matches!(
        progress,
        Some(RetainedControlProgress::DispatchStarted | RetainedControlProgress::SubsystemReturned)
    ) {
        vec!["The original command crossed its dispatch boundary; inspect subsystem evidence to establish its semantic outcome.".to_owned()]
    } else {
        Vec::new()
    };
    Ok(IntentOutcome {
        anchor: ctx.anchor.clone(),
        payload_json: object(&[
            ("intent", string("camera-supervision")),
            ("status", string(status)),
            ("authorityChanged", (!replayed).to_string()),
            ("deploymentId", string(deployment_id)),
            ("op", string(op.as_str())),
            ("cameraId", camera_id.map_or_else(|| "null".to_owned(), string)),
            ("operationId", string(operation_id.as_str())),
            ("daemonLive", "true".to_owned()),
            ("approvalDigest", string(&approval.to_text())),
            ("idempotencyKey", string(&key.to_text())),
            ("replayed", replayed.to_string()),
            ("progress", progress.map_or_else(|| "null".to_owned(), |p| string(p.as_str()))),
            ("recovered", recovered.to_string()),
            ("semanticCompletionProved", "false".to_owned()),
        ]),
        proof_pointers: vec![
            ctx.anchor.state_root.to_text(), descriptor_digest.to_text(),
            approval.to_text(), key.to_text(),
        ],
        warnings: vec![if recovered {
            "This retained command belongs to an earlier daemon owner and remains inert. Replaying its receipt does not authorize resumption or prove completion."
        } else {
            "Admission and retained progress record control ownership; the subsystem must separately prove its semantic outcome."
        }.to_owned()],
        fingerprint: key,
        idempotency_key: key.to_text(),
        completed_note: format!(
            "{} bounded control admission {} (state={status}).",
            if replayed { "Returned retained" } else { "Durably accepted" },
            operation_id.as_str(),
        ),
        not_started: vec![if replayed {
            "This retry did not enqueue or dispatch another control command."
        } else {
            "No semantic effect completion was inferred from admission."
        }.to_owned()],
        possibly_occurred,
    })
}
