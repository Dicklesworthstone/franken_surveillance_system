#![forbid(unsafe_code)]
//! `AOP-005 query --target holds` and `query --target privacy-masks` — read-only inspection of
//! active legal holds, retention policies, and per-sensor privacy mask bindings.
//!
//! Semantic plane: `"cognition"` (strictly read-only inspection; grants no mutation authority).

use std::collections::BTreeSet;
use std::path::PathBuf;

use fss_core::{
    AgentView, CanonicalEncode, CanonicalEncoder, CaptureInterval, Completeness, ContentDigest,
    ExecutionBoundary, KnowledgeState, PrincipalId, ResponseSafeRetry, SensorId, SessionId,
    TimestampNs,
};
use fss_reference::agent_orient::{OrientLimits, read_deployment_cancellable};
use fss_reference::deletion::holds::{HoldRecord, HoldState};
use fss_reference::deletion::inspection::{inspect_holds, inspect_policies, inspection_limits};
use fss_reference::deletion::retention::policy::RetentionPolicyRecord;
use fss_reference::ingest::privacy_mask::{MaskBinding, PrivacyMaskPolicy, current_mask};
use fss_reference::reference_deployment::FAMILY_PRIVACY_MASK_POLICY;
use fss_reference::retained_source::RetainedSource;

use super::{
    CAP_AGENT_QUERY, CAP_RETENTION_PREPARE, OpsEnvelopeParams, OpsError, build_readonly_context,
    ensure_deployment_root, open_readonly_source, render_ok_envelope, render_refusal_envelope,
    require_capabilities, resolve_effective_capabilities,
};
use crate::agent_json::evidence_anchor;
use crate::error::ExitIdentity;
use crate::json_output::{array, object, string};

/// Registered payload schema for `query --target holds`.
pub const HOLDS_PAYLOAD_SCHEMA: &str = "fss.agent_ops_holds.v1";
/// Canonical digest domain for `query --target holds`.
pub const HOLDS_DIGEST_DOMAIN: &str = "fss.ops_targets.holds.v1";
/// Registered payload schema for `query --target privacy-masks`.
pub const PRIVACY_MASKS_PAYLOAD_SCHEMA: &str = "fss.agent_ops_privacy_masks.v1";
/// Canonical digest domain for `query --target privacy-masks`.
pub const PRIVACY_MASKS_DIGEST_DOMAIN: &str = "fss.ops_targets.privacy_masks.v1";

/// Request parameters for read-only inspection of legal holds and retention policies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldsQueryRequest {
    /// Existing deployment root directory.
    pub root: PathBuf,
    /// Audit principal label.
    pub principal: PrincipalId,
    /// Optional owning session identity for capability resolution.
    pub session_id: Option<SessionId>,
    /// Optional sensor filter for retention policies.
    pub sensor: Option<SensorId>,
    /// Optional explicit owner time assertion `(earliest_ns, latest_ns)` for expiry readiness.
    pub attested_now_ns: Option<(i128, i128)>,
    /// Explicit launcher/CLI capability grants.
    pub granted_capabilities: BTreeSet<String>,
}

/// Request parameters for read-only inspection of per-sensor privacy mask policies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyMasksQueryRequest {
    /// Existing deployment root directory.
    pub root: PathBuf,
    /// Audit principal label.
    pub principal: PrincipalId,
    /// Optional owning session identity for capability resolution.
    pub session_id: Option<SessionId>,
    /// Optional sensor filter.
    pub sensor: Option<SensorId>,
    /// Explicit launcher/CLI capability grants.
    pub granted_capabilities: BTreeSet<String>,
}

/// Executes `query --target holds` and renders a registered `AgentResponseEnvelope`.
pub(crate) fn execute_holds(
    req: &HoldsQueryRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> (String, ExitIdentity) {
    match run_holds(req, cancelled) {
        Ok(params) => render_ok_envelope(&req.root, params),
        Err(err) => render_refusal_envelope(
            &req.root,
            "query",
            &req.principal,
            req.session_id.as_ref(),
            HOLDS_PAYLOAD_SCHEMA,
            &err,
        ),
    }
}

/// Executes `query --target privacy-masks` and renders a registered `AgentResponseEnvelope`.
pub(crate) fn execute_privacy_masks(
    req: &PrivacyMasksQueryRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> (String, ExitIdentity) {
    match run_privacy_masks(req, cancelled) {
        Ok(params) => render_ok_envelope(&req.root, params),
        Err(err) => render_refusal_envelope(
            &req.root,
            "query",
            &req.principal,
            req.session_id.as_ref(),
            PRIVACY_MASKS_PAYLOAD_SCHEMA,
            &err,
        ),
    }
}

fn run_holds<'a>(
    req: &'a HoldsQueryRequest,
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
    require_capabilities(
        &effective,
        &[CAP_AGENT_QUERY, CAP_RETENTION_PREPARE],
        "query --target holds",
    )?;
    ensure_deployment_root(&req.root)?;
    let snapshot = read_deployment_cancellable(&req.root, &OrientLimits::default(), cancelled)
        .map_err(|err| OpsError::OperationFailed(format!("deployment snapshot failed: {err}")))?;
    let attested_now = match req.attested_now_ns {
        Some((earliest, latest)) => Some(
            CaptureInterval::new(TimestampNs(earliest), TimestampNs(latest)).map_err(|_| {
                OpsError::InvalidRequest("attested_now_ns requires earliest <= latest".into())
            })?,
        ),
        None => None,
    };

    let (authority, cx) = build_readonly_context(
        &req.root,
        &snapshot.site_lineage,
        &req.principal,
        &[CAP_RETENTION_PREPARE],
    )?;
    let mut limits = inspection_limits();
    limits.max_read_bytes = limits.max_read_bytes.min(authority.budgets.bytes as usize);
    limits.max_read_objects = limits
        .max_read_objects
        .min(authority.budgets.storage_operations as usize);
    let holds_inspection = inspect_holds(cx.root_dir(), &authority, limits, &cx, cancelled)
        .map_err(|err| OpsError::OperationFailed(format!("hold inspection refused: {err}")))?;
    let policies_inspection = inspect_policies(cx.root_dir(), &authority, limits, &cx, cancelled)
        .map_err(|err| {
        OpsError::OperationFailed(format!("policy inspection refused: {err}"))
    })?;
    cx.drain_and_finalize();

    let active_holds = holds_inspection
        .records
        .iter()
        .filter(|r| r.request().state.is_active())
        .count();
    let mut hold_rows = Vec::with_capacity(holds_inspection.records.len());
    for rec in &holds_inspection.records {
        hold_rows.push(render_hold_record(rec, attested_now)?);
    }
    let filtered_policies: Vec<&RetentionPolicyRecord> = policies_inspection
        .records
        .iter()
        .filter(|rec| {
            req.sensor
                .as_ref()
                .is_none_or(|sensor| &rec.request().sensor == sensor)
        })
        .collect();
    let policy_rows: Vec<String> = filtered_policies
        .iter()
        .map(|rec| render_policy_record(rec))
        .collect();

    let mut fp_enc = CanonicalEncoder::new();
    fp_enc.text(HOLDS_DIGEST_DOMAIN);
    holds_inspection.anchor.encode_canonical(&mut fp_enc);
    fp_enc.u64(holds_inspection.records.len() as u64);
    for rec in &holds_inspection.records {
        fp_enc.digest(rec.digest());
    }
    fp_enc.u64(filtered_policies.len() as u64);
    for rec in &filtered_policies {
        fp_enc.digest(rec.digest());
    }
    let fingerprint = ContentDigest::sha256(&fp_enc.finish());

    let mut proof_pointers = vec![holds_inspection.anchor.state_root.to_text()];
    proof_pointers.extend(
        holds_inspection
            .records
            .iter()
            .take(16)
            .map(|r| r.digest().to_text()),
    );
    proof_pointers.extend(
        filtered_policies
            .iter()
            .take(16)
            .map(|r| r.digest().to_text()),
    );

    let payload_json = object(&[
        ("schema", string(HOLDS_PAYLOAD_SCHEMA)),
        ("siteLineage", string(&snapshot.site_lineage)),
        ("activeHoldCount", active_holds.to_string()),
        ("totalHoldCount", holds_inspection.records.len().to_string()),
        ("holds", array(&hold_rows)),
        ("retentionPolicyCount", filtered_policies.len().to_string()),
        ("retentionPolicies", array(&policy_rows)),
        ("deletionPerformed", "false".to_owned()),
        ("effectsAuthorized", "false".to_owned()),
    ]);

    Ok(OpsEnvelopeParams {
        operation: "query",
        principal: &req.principal,
        session_id: req.session_id.as_ref(),
        anchor: holds_inspection.anchor,
        view: AgentView::Case,
        capabilities: vec![CAP_AGENT_QUERY.to_owned(), CAP_RETENTION_PREPARE.to_owned()],
        privacy_purpose: "read-only inspection of legal holds and per-sensor retention policies",
        allowed_domains: &["retained-evidence-holds", "retained-retention-policies"],
        redacted_domains: &["media-payloads", "raw-credentials"],
        payload_schema: HOLDS_PAYLOAD_SCHEMA,
        payload_json,
        epistemic_state: KnowledgeState::Known,
        completeness: Completeness::Bounded,
        warnings: vec![
            "Read-only hold and retention policy inspection; never releases holds or deletes evidence."
                .to_owned(),
        ],
        proof_pointers,
        decision_fingerprint: fingerprint,
        idempotency_key: None,
        safe_retry: ResponseSafeRetry::YesSameRequest,
        recovery_class: "safe_read_retry",
        boundary: ExecutionBoundary {
            completed: vec![format!(
                "Verified {} hold record(s) and {} retention policy record(s) read-only.",
                holds_inspection.records.len(),
                filtered_policies.len()
            )],
            not_started: vec![
                "No hold was placed/released and no evidence was deleted.".to_owned(),
            ],
            possibly_occurred: Vec::new(),
            preserved_truth: vec![
                "Terminal hold records remain visible; eligibility never releases a hold."
                    .to_owned(),
            ],
            invalidated: Vec::new(),
        },
        created_at_ns: snapshot.latest_evidence_time.0,
    })
}

fn run_privacy_masks<'a>(
    req: &'a PrivacyMasksQueryRequest,
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
    require_capabilities(
        &effective,
        &[CAP_AGENT_QUERY],
        "query --target privacy-masks",
    )?;
    ensure_deployment_root(&req.root)?;
    let snapshot = read_deployment_cancellable(&req.root, &OrientLimits::default(), cancelled)
        .map_err(|err| OpsError::OperationFailed(format!("deployment snapshot failed: {err}")))?;
    let (_, cx) = build_readonly_context(&req.root, &snapshot.site_lineage, &req.principal, &[])?;
    let source = open_readonly_source(&req.root, &cx, cancelled)?;

    let mut sensors: BTreeSet<SensorId> = BTreeSet::new();
    if let Some(sensor) = &req.sensor {
        sensors.insert(sensor.clone());
    } else {
        for cov in &snapshot.coverage {
            if let Ok(sid) = SensorId::parse(cov.record.sensor_id.clone()) {
                sensors.insert(sid);
            }
        }
        for live in &snapshot.sensor_liveness {
            sensors.insert(live.record.enrollment().sensor().clone());
        }
        // Also discover every sensor that has a committed privacy_mask_policy delta.
        for batch in source.ledger().batches() {
            for delta in &batch.deltas {
                if delta.family == FAMILY_PRIVACY_MASK_POLICY
                    && let Ok(bytes) = source.read_object_bounded(
                        delta.payload_digest,
                        fss_reference::ingest::privacy_mask::MAX_MASK_POLICY_BYTES,
                    )
                    && let Ok(policy) = PrivacyMaskPolicy::from_bytes(&bytes, delta.payload_digest)
                {
                    sensors.insert(policy.sensor_id().clone());
                }
            }
        }
    }

    let mut rows = Vec::with_capacity(sensors.len());
    let mut fp_enc = CanonicalEncoder::new();
    fp_enc.text(PRIVACY_MASKS_DIGEST_DOMAIN);
    snapshot.anchor.encode_canonical(&mut fp_enc);
    fp_enc.u64(sensors.len() as u64);
    let mut proof_pointers = vec![snapshot.anchor.state_root.to_text()];

    for sensor in &sensors {
        let binding = current_mask(&source, sensor)
            .map_err(|err| OpsError::OperationFailed(format!("privacy mask read failed: {err}")))?;
        fp_enc.text(sensor.as_str());
        fp_enc.digest(binding.digest());
        if let Some(digest) = binding.policy_digest() {
            proof_pointers.push(digest.to_text());
        }
        rows.push(render_mask_entry(sensor, &binding));
    }
    cx.drain_and_finalize();

    let fingerprint = ContentDigest::sha256(&fp_enc.finish());
    let payload_json = object(&[
        ("schema", string(PRIVACY_MASKS_PAYLOAD_SCHEMA)),
        ("siteLineage", string(&snapshot.site_lineage)),
        ("sensorCount", sensors.len().to_string()),
        ("masks", array(&rows)),
        ("effectsAuthorized", "false".to_owned()),
    ]);

    Ok(OpsEnvelopeParams {
        operation: "query",
        principal: &req.principal,
        session_id: req.session_id.as_ref(),
        anchor: snapshot.anchor.clone(),
        view: AgentView::Case,
        capabilities: vec![CAP_AGENT_QUERY.to_owned()],
        privacy_purpose: "read-only inspection of active per-sensor privacy mask bindings",
        allowed_domains: &["retained-privacy-mask-policies"],
        redacted_domains: &["media-payloads", "unmasked-pixels"],
        payload_schema: PRIVACY_MASKS_PAYLOAD_SCHEMA,
        payload_json,
        epistemic_state: KnowledgeState::Known,
        completeness: Completeness::Bounded,
        warnings: vec![
            "Sensors with no_policy_declared carry an explicit marker; unmasked access to masked sensors is permanently refused.".to_owned(),
        ],
        proof_pointers,
        decision_fingerprint: fingerprint,
        idempotency_key: None,
        safe_retry: ResponseSafeRetry::YesSameRequest,
        recovery_class: "safe_read_retry",
        boundary: ExecutionBoundary {
            completed: vec![format!(
                "Verified active privacy mask bindings for {} sensor(s) read-only.",
                sensors.len()
            )],
            not_started: vec![
                "No pixels were decoded and no privacy mask policy was modified.".to_owned(),
            ],
            possibly_occurred: Vec::new(),
            preserved_truth: vec![
                "Privacy mask policies are immutable generations; damaged custody fails closed."
                    .to_owned(),
            ],
            invalidated: Vec::new(),
        },
        created_at_ns: snapshot.latest_evidence_time.0,
    })
}

fn render_hold_record(
    record: &HoldRecord,
    attested_now: Option<CaptureInterval>,
) -> Result<String, OpsError> {
    let state = record.request().state;
    let mut fields = vec![
        ("holdId", string(&record.request().hold_id)),
        (
            "importIdentity",
            string(&record.request().import_identity.to_text()),
        ),
        ("state", string(state.as_str())),
        ("active", state.is_active().to_string()),
        ("reason", string(&record.request().reason)),
        ("principal", string(record.principal())),
        ("site", string(record.site())),
        ("basis", evidence_anchor(record.basis())),
        ("recordDigest", string(&record.digest().to_text())),
    ];
    if let Some(not_before) = state.not_before() {
        fields.push(("notBeforeNs", string(&not_before.0.to_string())));
    }
    if let Some(now) = attested_now {
        let readiness = state.readiness(now).map_err(|err| {
            OpsError::InvalidRequest(format!("hold readiness evaluation failed: {err}"))
        })?;
        fields.push(("timeReadiness", string(readiness.as_str())));
    }
    if matches!(state, HoldState::Expired { .. }) {
        fields.push(("expired", "true".to_owned()));
    }
    Ok(object(&fields))
}

fn render_policy_record(record: &RetentionPolicyRecord) -> String {
    let req = record.request();
    object(&[
        ("sensor", string(req.sensor.as_str())),
        ("enabled", req.enabled.to_string()),
        ("generation", record.generation().to_string()),
        ("retainForNs", string(&req.retain_for_ns.to_string())),
        (
            "maxRetainedSourceBytes",
            req.max_retained_source_bytes
                .map_or_else(|| "null".to_owned(), |b| string(&b.to_string())),
        ),
        ("reason", string(&req.reason)),
        ("principal", string(record.principal())),
        ("basis", evidence_anchor(record.basis())),
        ("recordDigest", string(&record.digest().to_text())),
    ])
}

fn render_mask_entry(sensor: &SensorId, binding: &MaskBinding) -> String {
    object(&[
        ("sensorId", string(sensor.as_str())),
        ("mask", binding.to_json()),
    ])
}
