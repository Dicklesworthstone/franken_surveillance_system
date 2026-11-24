#![forbid(unsafe_code)]
//! Registered `AgentResponseEnvelope` rendering for H2 analytic and H3 visual hydration.

use std::path::Path;

use fss_core::{
    AgentResponseEnvelope, AgentView, BudgetVector, CanonicalEncoder, Completeness, ContentDigest,
    ExecutionBoundary, KnowledgeState, LedgerAnchor, PrincipalId, ResponseOutcome,
    ResponseSafeRetry, ResponseTaskState, SessionId,
};

use super::h2::{H2HydrationAnswer, H2HydrationRequest};
use super::h3::{H3HydrationAnswer, H3HydrationRequest};
use super::{
    CAP_AGENT_HYDRATE_H2, CAP_AGENT_HYDRATE_H3, H2_PAYLOAD_SCHEMA, H2_RECEIPT_DOMAIN,
    H3_PAYLOAD_SCHEMA, H3_RECEIPT_DOMAIN, HydrationError, MAX_H2_OUTPUT_BYTES, MAX_H3_OUTPUT_BYTES,
    MAX_HYDRATION_READ_BYTES, MAX_HYDRATION_READ_OBJECTS,
};
use crate::agent_json;
use crate::error::ExitIdentity;
use crate::json_output::{object, string, strings};

pub(super) fn render_h2_envelope(
    req: &H2HydrationRequest,
    answer: &H2HydrationAnswer,
) -> (String, ExitIdentity) {
    let payload_json = answer.to_json();
    if payload_json.len() > MAX_H2_OUTPUT_BYTES {
        let error = HydrationError::BoundsExceeded(
            "H2 projection exceeds 256 KiB output bound; nothing was truncated".into(),
        );
        return render_refusal_envelope(
            &req.root,
            &req.principal,
            req.session_id.as_ref(),
            H2_PAYLOAD_SCHEMA,
            H2_RECEIPT_DOMAIN,
            &error,
        );
    }
    let privacy = privacy_projection_json(
        &answer.anchor,
        "capability-gated H2 structured analytic hydration",
        &[
            "retained-track-trajectories-and-boxes",
            "retained-model-receipt-metadata",
            "failure-domain-support-and-graph-neighborhood",
        ],
        &[
            "raw-media-bytes",
            "unredacted-frame-pixels",
            "operator-notes",
        ],
    );
    let requested = BudgetVector::builder()
        .tokens(req.budget_tokens.unwrap_or(answer.budget.vector.tokens))
        .bytes(MAX_HYDRATION_READ_BYTES as u64)
        .storage_operations(MAX_HYDRATION_READ_OBJECTS as u64)
        .build()
        .unwrap_or(answer.budget.vector);
    let rendered = build_envelope(EnvelopeParams {
        principal: &req.principal,
        session_id: req.session_id.as_ref(),
        anchor: answer.anchor.clone(),
        view: AgentView::Forensic,
        capabilities: vec![CAP_AGENT_HYDRATE_H2.to_owned()],
        privacy_json: privacy,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: H2_PAYLOAD_SCHEMA,
        payload_json,
        completeness: Completeness::Bounded,
        warnings: answer.warnings.clone(),
        budgets_json: agent_json::budget_summary(&requested, &answer.budget.vector),
        proof_pointers: answer.proof_pointers.clone(),
        decision_fingerprint: answer.receipt.receipt_digest,
        boundary: ExecutionBoundary {
            completed: vec![
                "Verified CAP-AGENT-HYDRATE-H2-001 and compiled anchor-pinned H2 analytic projection."
                    .to_owned(),
            ],
            not_started: vec![
                "No raw pixels were decoded, no deployment authority was modified, and no effect was executed."
                    .to_owned(),
            ],
            possibly_occurred: Vec::new(),
            preserved_truth: vec![
                "Uncalibrated scores remain explicitly uncalibrated; structural proximity never proves physical truth."
                    .to_owned(),
            ],
            invalidated: Vec::new(),
        },
        created_at_ns: answer.observed_at_ns,
    });
    match rendered {
        Ok(out) if out.len() <= MAX_H2_OUTPUT_BYTES => (out, ExitIdentity::SUCCESS),
        Ok(_) => render_refusal_envelope(
            &req.root,
            &req.principal,
            req.session_id.as_ref(),
            H2_PAYLOAD_SCHEMA,
            H2_RECEIPT_DOMAIN,
            &HydrationError::BoundsExceeded("H2 envelope exceeds 256 KiB ceiling".into()),
        ),
        Err(err) => render_refusal_envelope(
            &req.root,
            &req.principal,
            req.session_id.as_ref(),
            H2_PAYLOAD_SCHEMA,
            H2_RECEIPT_DOMAIN,
            &err,
        ),
    }
}

pub(super) fn render_h3_envelope(
    req: &H3HydrationRequest,
    answer: &H3HydrationAnswer,
) -> (String, ExitIdentity) {
    let payload_json = answer.to_json();
    if payload_json.len() > MAX_H3_OUTPUT_BYTES {
        let error = HydrationError::BoundsExceeded(
            "H3 visual response exceeds 1 MiB output ceiling; reduce max_h3_frames or max_dimension"
                .into(),
        );
        return render_refusal_envelope(
            &req.root,
            &req.principal,
            req.session_id.as_ref(),
            H3_PAYLOAD_SCHEMA,
            H3_RECEIPT_DOMAIN,
            &error,
        );
    }
    let privacy = privacy_projection_json(
        &answer.anchor,
        "dual-gated privacy-masked H3 visual keyframe hydration",
        &[
            "privacy-masked-jpeg-derivatives",
            "h3-frame-redaction-receipts",
        ],
        &["unmasked-source-pixels", "raw-retained-bitstreams"],
    );
    let requested = BudgetVector::builder()
        .tokens(req.budget_tokens.unwrap_or(answer.budget.vector.tokens))
        .bytes(req.limits.max_h3_bytes as u64)
        .storage_operations(MAX_HYDRATION_READ_OBJECTS as u64)
        .build()
        .unwrap_or(answer.budget.vector);
    let rendered = build_envelope(EnvelopeParams {
        principal: &req.principal,
        session_id: req.session_id.as_ref(),
        anchor: answer.anchor.clone(),
        view: AgentView::Forensic,
        capabilities: vec![CAP_AGENT_HYDRATE_H3.to_owned()],
        privacy_json: privacy,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: H3_PAYLOAD_SCHEMA,
        payload_json,
        completeness: Completeness::Bounded,
        warnings: answer.warnings.clone(),
        budgets_json: agent_json::budget_summary(&requested, &answer.budget.vector),
        proof_pointers: answer.proof_pointers.clone(),
        decision_fingerprint: answer.receipt_digest,
        boundary: ExecutionBoundary {
            completed: vec![
                "Verified dual H3 gates, enforced active sensor privacy masks BEFORE crop/downscale/encode, and produced bounded JPEG derivatives."
                    .to_owned(),
            ],
            not_started: vec![
                "No unmasked pixels were released, no deployment state was modified, and no external effect was executed."
                    .to_owned(),
            ],
            possibly_occurred: Vec::new(),
            preserved_truth: vec![
                "Lossy JPEG derivatives remain derived artifacts; unmasked access is permanently refused."
                    .to_owned(),
            ],
            invalidated: Vec::new(),
        },
        created_at_ns: answer.observed_at_ns,
    });
    match rendered {
        Ok(out) if out.len() <= MAX_H3_OUTPUT_BYTES => (out, ExitIdentity::SUCCESS),
        Ok(_) => render_refusal_envelope(
            &req.root,
            &req.principal,
            req.session_id.as_ref(),
            H3_PAYLOAD_SCHEMA,
            H3_RECEIPT_DOMAIN,
            &HydrationError::BoundsExceeded("H3 envelope exceeds 1 MiB ceiling".into()),
        ),
        Err(err) => render_refusal_envelope(
            &req.root,
            &req.principal,
            req.session_id.as_ref(),
            H3_PAYLOAD_SCHEMA,
            H3_RECEIPT_DOMAIN,
            &err,
        ),
    }
}

pub(super) fn render_refusal_envelope(
    root: &Path,
    principal: &PrincipalId,
    session_id: Option<&SessionId>,
    payload_schema: &'static str,
    domain: &'static str,
    error: &HydrationError,
) -> (String, ExitIdentity) {
    let mut enc = CanonicalEncoder::new();
    enc.text(domain);
    enc.text("refusal");
    enc.text(principal.as_str());
    enc.text(error.error_id());
    enc.text(&error.to_string());
    let fingerprint = ContentDigest::sha256(&enc.finish());
    let anchor = LedgerAnchor::genesis("site:hydration-refusal");
    let privacy = privacy_projection_json(
        &anchor,
        "payload-free fail-closed hydration refusal",
        &[],
        &["all-requested-hydration-data"],
    );
    let rendered = build_envelope(EnvelopeParams {
        principal,
        session_id,
        anchor,
        view: AgentView::Forensic,
        capabilities: Vec::new(),
        privacy_json: privacy,
        outcome: ResponseOutcome::Refused,
        error_id: Some(error.error_id()),
        payload_schema,
        payload_json: "null".to_owned(),
        completeness: Completeness::Partial,
        warnings: vec![error.to_string()],
        budgets_json: agent_json::budget_summary(&BudgetVector::ZERO, &BudgetVector::ZERO),
        proof_pointers: Vec::new(),
        decision_fingerprint: fingerprint,
        boundary: ExecutionBoundary {
            completed: vec![format!(
                "Hydration refused fail-closed ({}).",
                error.error_id()
            )],
            not_started: vec!["No unmasked or unauthorized data was disclosed.".to_owned()],
            possibly_occurred: Vec::new(),
            preserved_truth: vec!["Deployment root remained strictly read-only.".to_owned()],
            invalidated: Vec::new(),
        },
        created_at_ns: 0,
    });
    match rendered {
        Ok(out) => (out, ExitIdentity::AGENT_REFUSED),
        Err(_) => (
            crate::orient_cmd::execution_diagnostic(
                "query",
                root,
                error.error_id(),
                ExitIdentity::AGENT_REFUSED,
            ),
            ExitIdentity::AGENT_REFUSED,
        ),
    }
}

struct EnvelopeParams<'a> {
    principal: &'a PrincipalId,
    session_id: Option<&'a SessionId>,
    anchor: LedgerAnchor,
    view: AgentView,
    capabilities: Vec<String>,
    privacy_json: String,
    outcome: ResponseOutcome,
    error_id: Option<&'static str>,
    payload_schema: &'static str,
    payload_json: String,
    completeness: Completeness,
    warnings: Vec<String>,
    budgets_json: String,
    proof_pointers: Vec<String>,
    decision_fingerprint: ContentDigest,
    boundary: ExecutionBoundary,
    created_at_ns: i128,
}

fn build_envelope(params: EnvelopeParams<'_>) -> Result<String, HydrationError> {
    let payload_digest = ContentDigest::sha256(params.payload_json.as_bytes());
    let short = params.decision_fingerprint.to_text();
    let hex = short.strip_prefix("sha256:").unwrap_or(&short);
    let envelope = AgentResponseEnvelope::new(
        fss_core::reference_contract_basis(),
        "query",
        format!("request:query:{hex}"),
        1,
        params.principal.as_str(),
        params.session_id.map(|id| id.as_str().to_owned()),
        None,
        format!("trace:query:{hex}"),
        params.anchor,
        None,
        None,
        params.view,
        params.capabilities,
        params.privacy_json,
        params.outcome,
        None,
        Some(ResponseTaskState::None),
        params.error_id.map(ToOwned::to_owned),
        params.payload_schema,
        params.payload_json,
        payload_digest,
        KnowledgeState::Unknown,
        params.completeness,
        params.warnings,
        Vec::new(),
        vec![
            "Payload tokens are computed deterministically as ceil(serialized_bytes / 4)."
                .to_owned(),
        ],
        params.budgets_json,
        params.proof_pointers,
        Vec::new(),
        params.decision_fingerprint,
        None,
        None,
        None,
        None,
        if params.outcome == ResponseOutcome::Ok {
            "safe_read_retry"
        } else {
            "operator_action_required"
        },
        if params.outcome == ResponseOutcome::Ok {
            ResponseSafeRetry::YesSameRequest
        } else {
            ResponseSafeRetry::No
        },
        false,
        params.boundary,
        params.created_at_ns,
    )
    .map_err(|_| HydrationError::CustodyFailure("failed to construct response envelope".into()))?;
    envelope.validate().map_err(|_| {
        HydrationError::CustodyFailure("response envelope failed validation".into())
    })?;
    agent_json::response_envelope(&envelope, &[])
        .ok_or_else(|| HydrationError::CustodyFailure("failed to render response envelope".into()))
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
