#![forbid(unsafe_code)]
//! `AOP-005 query --target fusion` — read-only `fss-fusion` milliban LLR interval evaluation and
//! simultaneous `--without-sensor` / `--without-domain` counterfactual ablation.
//!
//! Semantic plane: `"cognition"` (pure derived evidence fusion; grants no effect authority).

use std::collections::BTreeSet;
use std::path::PathBuf;

use fss_core::{
    AgentView, CanonicalEncode, CanonicalEncoder, Completeness, ContentDigest, EventId,
    ExecutionBoundary, KnowledgeState, PrincipalId, ResponseSafeRetry, SessionId,
};
use fss_fusion::{
    AblationTarget, Calibration, Coverage, Decision, EvidenceItem, FusionOutcome, FusionPolicy,
    FusionQuery, LlrInterval, Observability, Severity, ablate, fuse,
};
use fss_reference::agent_orient::{OrientLimits, read_deployment_cancellable};

use super::{
    CAP_AGENT_QUERY, OpsEnvelopeParams, OpsError, ensure_deployment_root, render_ok_envelope,
    render_refusal_envelope, require_capabilities, resolve_effective_capabilities,
};
use crate::error::ExitIdentity;
use crate::json_output::{array, object, string, strings};

/// Registered payload schema for `query --target fusion`.
pub const FUSION_PAYLOAD_SCHEMA: &str = "fss.agent_ops_fusion.v1";
/// Canonical digest domain for `query --target fusion`.
pub const FUSION_DIGEST_DOMAIN: &str = "fss.ops_targets.fusion.v1";

/// One candidate or retained evidence row submitted to read-only fusion evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FusionEvidenceInput {
    /// Stable evidence item identifier.
    pub id: String,
    /// Producing sensor identifier.
    pub sensor: String,
    /// Declared failure domains (sensor is always implicitly included by `fss-fusion`).
    pub failure_domains: BTreeSet<String>,
    /// Optional calibrated LLR interval `(lo_millibans, hi_millibans)`.
    pub llr: Option<(i64, i64)>,
    /// Explicit calibration generation label when `llr` is supplied.
    pub calibration_generation: Option<String>,
    /// Explicit reason when uncalibrated (`llr` is `None`).
    pub uncalibrated_reason: Option<String>,
    /// Observability spelling (`observed`, `redacted`, `stale`, or `not_observable`).
    pub observability: String,
}

/// Request parameters for read-only milliban LLR fusion and counterfactual ablation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FusionQueryRequest {
    /// Existing deployment root directory (pinned to current authority anchor).
    pub root: PathBuf,
    /// Audit principal label.
    pub principal: PrincipalId,
    /// Optional owning session identity for capability resolution.
    pub session_id: Option<SessionId>,
    /// Optional retained event identifier to hydrate evidence edges from the deployment.
    pub event_id: Option<EventId>,
    /// Optional explicit inline candidate evidence rows.
    pub evidence: Vec<FusionEvidenceInput>,
    /// Prior log-odds interval `(lo, hi)` in millibans (defaults to `(-500, -400)`).
    pub prior: (i64, i64),
    /// Coverage state (`complete`, `degraded`, or `gap`).
    pub coverage_state: String,
    /// Alert threshold in millibans (default `1000`).
    pub alert_threshold: i64,
    /// Retain threshold in millibans (default `0`).
    pub retain_threshold: i64,
    /// Reject threshold in millibans (default `-1000`).
    pub reject_threshold: i64,
    /// Minimum independent supporting clusters required to alert (default `2`).
    pub min_independent_support: u32,
    /// Sensors excluded simultaneously in counterfactual ablation (`--without-sensor`).
    pub without_sensors: Vec<String>,
    /// Failure domains excluded simultaneously in counterfactual ablation (`--without-domain`).
    pub without_domains: Vec<String>,
    /// Explicit launcher/CLI capability grants.
    pub granted_capabilities: BTreeSet<String>,
}

/// Executes `query --target fusion` and renders a registered `AgentResponseEnvelope`.
pub(crate) fn execute(
    req: &FusionQueryRequest,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> (String, ExitIdentity) {
    match run(req, cancelled) {
        Ok(params) => render_ok_envelope(&req.root, params),
        Err(err) => render_refusal_envelope(
            &req.root,
            "query",
            &req.principal,
            req.session_id.as_ref(),
            FUSION_PAYLOAD_SCHEMA,
            &err,
        ),
    }
}

fn run<'a>(
    req: &'a FusionQueryRequest,
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
    require_capabilities(&effective, &[CAP_AGENT_QUERY], "query --target fusion")?;
    ensure_deployment_root(&req.root)?;
    if cancelled() {
        return Err(OpsError::Cancelled);
    }
    let snapshot = read_deployment_cancellable(&req.root, &OrientLimits::default(), cancelled)
        .map_err(|err| OpsError::OperationFailed(format!("deployment snapshot failed: {err}")))?;

    let (hypothesis, kind, evidence_items) = build_evidence_items(req, &snapshot)?;
    let prior = LlrInterval::new(req.prior.0, req.prior.1)
        .map_err(|err| OpsError::InvalidRequest(format!("invalid prior interval: {err}")))?;
    let coverage = match req.coverage_state.as_str() {
        "complete" => Coverage::Complete,
        "degraded" => Coverage::Degraded {
            reason: "caller_declared_degraded_coverage".to_owned(),
        },
        "gap" => Coverage::Gap {
            reason: "caller_declared_coverage_gap".to_owned(),
        },
        other => {
            return Err(OpsError::InvalidRequest(format!(
                "unsupported coverage_state `{other}`; expected complete, degraded, or gap"
            )));
        }
    };
    let fusion_query = FusionQuery {
        hypothesis,
        kind,
        prior,
        evidence: evidence_items,
        coverage,
        opportunities: Vec::new(),
        probes: Vec::new(),
        severity: Severity {
            expected_harm: 1_000,
            false_alert_cost: 100,
            delay_cost_per_second: 10,
            reversible: true,
        },
        policy: FusionPolicy {
            generation: "policy:ops-fusion-query:v1".to_owned(),
            alert_threshold: req.alert_threshold,
            retain_threshold: req.retain_threshold,
            reject_threshold: req.reject_threshold,
            min_independent_support: req.min_independent_support,
            urgent_single_domain_threshold: None,
            max_wait_ns: 0,
            look_penalty_per_doubling: 0,
            operator_confirmation_available: true,
        },
        looks: 1,
        now_ns: u64::try_from(snapshot.latest_evidence_time.0.max(0)).unwrap_or(0),
    };

    let baseline = fuse(&fusion_query)
        .map_err(|err| OpsError::InvalidRequest(format!("fss-fusion evaluation refused: {err}")))?;

    let mut targets = Vec::new();
    for sensor in &req.without_sensors {
        targets.push(AblationTarget::Sensor(sensor.clone()));
    }
    for domain in &req.without_domains {
        targets.push(AblationTarget::FailureDomain(domain.clone()));
    }

    let ablation = if targets.is_empty() {
        None
    } else {
        Some(ablate(&fusion_query, &targets).map_err(|err| {
            OpsError::InvalidRequest(format!("fss-fusion ablation refused: {err}"))
        })?)
    };

    let mut fp_enc = CanonicalEncoder::new();
    fp_enc.text(FUSION_DIGEST_DOMAIN);
    snapshot.anchor.encode_canonical(&mut fp_enc);
    fp_enc.digest(baseline.query_digest);
    fp_enc.digest(baseline.decision_digest);
    if let Some(ab) = &ablation {
        fp_enc.bool(true);
        fp_enc.digest(ab.digest());
    } else {
        fp_enc.bool(false);
    }
    let fingerprint = ContentDigest::sha256(&fp_enc.finish());

    let mut proof_pointers = vec![
        snapshot.anchor.state_root.to_text(),
        baseline.query_digest.to_text(),
        baseline.decision_digest.to_text(),
    ];
    let ablation_json = match &ablation {
        None => "null".to_owned(),
        Some(ab) => {
            proof_pointers.push(ab.digest().to_text());
            let target_rows: Vec<String> = ab
                .targets()
                .iter()
                .map(|t| {
                    object(&[
                        ("kind", string(t.kind())),
                        ("identity", string(t.identity())),
                    ])
                })
                .collect();
            let decision_changed = baseline.decision != ab.outcome().decision;
            object(&[
                ("schema", string(fss_fusion::FUSION_ABLATION_SCHEMA)),
                (
                    "implementation",
                    string(fss_fusion::FUSION_ABLATION_IMPLEMENTATION),
                ),
                ("ablationDigest", string(&ab.digest().to_text())),
                ("decisionChanged", decision_changed.to_string()),
                ("targets", array(&target_rows)),
                ("unavailableEvidence", strings(ab.unavailable_evidence())),
                ("counterfactualOutcome", render_outcome(ab.outcome())),
            ])
        }
    };

    let payload_json = object(&[
        ("schema", string(FUSION_PAYLOAD_SCHEMA)),
        ("implementation", string(fss_fusion::IMPLEMENTATION_ID)),
        ("baseline", render_outcome(&baseline)),
        ("ablation", ablation_json),
        ("effectsAuthorized", "false".to_owned()),
    ]);

    Ok(OpsEnvelopeParams {
        operation: "query",
        principal: &req.principal,
        session_id: req.session_id.as_ref(),
        anchor: snapshot.anchor.clone(),
        view: AgentView::Case,
        capabilities: vec![CAP_AGENT_QUERY.to_owned()],
        privacy_purpose: "read-only fss-fusion milliban LLR evaluation and counterfactual ablation",
        allowed_domains: &["derived-fusion-milliban-llr", "counterfactual-ablation"],
        redacted_domains: &["media-payloads", "raw-credentials"],
        payload_schema: FUSION_PAYLOAD_SCHEMA,
        payload_json,
        epistemic_state: KnowledgeState::Estimated,
        completeness: Completeness::Bounded,
        warnings: vec![
            "Fusion evaluation is derived cognition over declared intervals; it never mutates policy or grants alert authority.".to_owned(),
        ],
        proof_pointers,
        decision_fingerprint: fingerprint,
        idempotency_key: None,
        safe_retry: ResponseSafeRetry::YesSameRequest,
        recovery_class: "safe_read_retry",
        boundary: ExecutionBoundary {
            completed: vec![
                "Evaluated fss-fusion exact integer milliban LLR intervals and optional counterfactual ablation."
                    .to_owned(),
            ],
            not_started: vec![
                "No event revision was published, no policy changed, and no alert was triggered."
                    .to_owned(),
            ],
            possibly_occurred: Vec::new(),
            preserved_truth: vec![
                "Shared failure domains collapse via hull contraction; uncalibrated evidence contributes zero belief."
                    .to_owned(),
            ],
            invalidated: Vec::new(),
        },
        created_at_ns: snapshot.latest_evidence_time.0,
    })
}

fn build_evidence_items(
    req: &FusionQueryRequest,
    snapshot: &fss_reference::agent_orient::DeploymentSnapshot,
) -> Result<(String, String, Vec<EvidenceItem>), OpsError> {
    if !req.evidence.is_empty() {
        let mut out = Vec::with_capacity(req.evidence.len());
        for row in &req.evidence {
            let calibration = match row.llr {
                Some((lo, hi)) => Calibration::Calibrated {
                    generation: row
                        .calibration_generation
                        .clone()
                        .unwrap_or_else(|| "cal:inline-caller-declared:v1".to_owned()),
                    llr: LlrInterval::new(lo, hi).map_err(|err| {
                        OpsError::InvalidRequest(format!("invalid LLR interval: {err}"))
                    })?,
                },
                None => Calibration::Uncalibrated {
                    reason: row
                        .uncalibrated_reason
                        .clone()
                        .unwrap_or_else(|| "uncalibrated_input".to_owned()),
                },
            };
            let observability = match row.observability.as_str() {
                "observed" => Observability::Observed,
                "redacted" => Observability::Redacted,
                "stale" => Observability::Stale,
                "not_observable" => Observability::NotObservable {
                    reason: "caller_declared_not_observable".to_owned(),
                },
                other => {
                    return Err(OpsError::InvalidRequest(format!(
                        "unsupported observability `{other}`"
                    )));
                }
            };
            out.push(EvidenceItem {
                id: row.id.clone(),
                sensor: row.sensor.clone(),
                failure_domains: row.failure_domains.clone(),
                calibration,
                observability,
            });
        }
        let hyp = req.event_id.as_ref().map_or_else(
            || "hypothesis:candidate".to_owned(),
            |id| id.as_str().to_owned(),
        );
        return Ok((hyp, "candidate_fusion".to_owned(), out));
    }

    let Some(event_id) = &req.event_id else {
        return Err(OpsError::InvalidRequest(
            "query --target fusion requires either event_id or non-empty evidence array".into(),
        ));
    };
    let retained = snapshot.event(event_id).ok_or_else(|| {
        OpsError::NotFound(format!(
            "event {} not found in deployment",
            event_id.as_str()
        ))
    })?;
    let mut items = Vec::with_capacity(retained.event.evidence.len());
    for (idx, edge) in retained.event.evidence.iter().enumerate() {
        let domain = if edge.failure_domain.is_empty() {
            format!("edge:{idx}")
        } else {
            edge.failure_domain.clone()
        };
        let mut domains = BTreeSet::new();
        domains.insert(domain.clone());
        items.push(EvidenceItem {
            id: format!("ev:{idx}:{}", edge.digest.to_text()),
            sensor: domain,
            failure_domains: domains,
            calibration: Calibration::Uncalibrated {
                reason: "retained_event_edge_without_bound_calibration".to_owned(),
            },
            observability: Observability::Observed,
        });
    }
    Ok((
        event_id.as_str().to_owned(),
        retained.event.kind.as_str().to_owned(),
        items,
    ))
}

fn render_decision(decision: &Decision) -> String {
    let mut fields = vec![("kind", string(decision.as_str()))];
    match decision {
        Decision::WaitForCorroboration {
            opportunity,
            deadline_ns,
            value_bound,
        } => {
            fields.push(("opportunity", string(opportunity)));
            fields.push(("deadlineNs", string(&deadline_ns.to_string())));
            fields.push(("valueBound", value_bound.to_string()));
        }
        Decision::RequestObservation { probe, value_bound } => {
            fields.push(("probe", string(probe)));
            fields.push(("valueBound", value_bound.to_string()));
        }
        _ => {}
    }
    object(&fields)
}

fn render_outcome(outcome: &FusionOutcome) -> String {
    let clusters: Vec<String> = outcome
        .clusters
        .iter()
        .map(|cluster| {
            object(&[
                ("label", cluster.label.to_string()),
                ("members", strings(&cluster.members)),
                ("failureDomains", strings(&cluster.failure_domains)),
                (
                    "llrMillibans",
                    format!("[{},{}]", cluster.llr.lo(), cluster.llr.hi()),
                ),
            ])
        })
        .collect();
    object(&[
        ("queryDigest", string(&outcome.query_digest.to_text())),
        ("decisionDigest", string(&outcome.decision_digest.to_text())),
        ("policyGeneration", string(&outcome.policy_generation)),
        ("decision", render_decision(&outcome.decision)),
        (
            "reasons",
            strings(outcome.reasons.iter().map(|r| r.as_str())),
        ),
        ("knowledgeState", string(outcome.knowledge_state)),
        ("provenanceClass", string("derived")),
        (
            "posteriorLogOddsMillibans",
            format!("[{},{}]", outcome.posterior.lo(), outcome.posterior.hi()),
        ),
        (
            "probabilityPpm",
            format!(
                "[{},{}]",
                outcome.probability_ppm.0, outcome.probability_ppm.1
            ),
        ),
        (
            "sequentialAlertThreshold",
            outcome.sequential_alert_threshold.to_string(),
        ),
        (
            "supportingClusters",
            outcome.supporting_clusters.to_string(),
        ),
        (
            "contradictingClusters",
            outcome.contradicting_clusters.to_string(),
        ),
        (
            "supportToAlert",
            outcome
                .support_to_alert
                .map_or_else(|| "null".to_owned(), |v| v.to_string()),
        ),
        (
            "reductionToRetain",
            outcome
                .reduction_to_retain
                .map_or_else(|| "null".to_owned(), |v| v.to_string()),
        ),
        ("clusters", array(&clusters)),
    ])
}
