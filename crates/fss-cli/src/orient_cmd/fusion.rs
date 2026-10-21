#![forbid(unsafe_code)]
//! Opt-in calibrated sequential evidence fusion (`fss-fusion`) and counterfactual minimal-flip
//! explanations inside AOP-011 (`fss explain`).
//!
//! When `--score-calibration <FILE>` is supplied to `fss explain`, the committed event's evidence
//! edges and failure domains are evaluated through [`fss_fusion::fuse`] under the verified
//! [`ScoreCalibration`] artifact. Exact integer-milliban LLR intervals, Fréchet-Hoeffding
//! common-cause failure-domain hulls, and minimal-flip counterfactual witnesses are surfaced as
//! derived propositions and invalidators in the `AgentCognitiveEnvelope` while keeping default
//! `fss explain` invocations (without `--score-calibration`) 100% byte-identical.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fss_core::{
    AgentCognitiveEnvelope, Completeness, ContentDigest, EnvelopeProposition,
    EvidenceEdgeRelation, ExplainQuestion, ExplainReceipt, KnowledgeState, ResponseOutcome,
    ResponseSafeRetry,
};
use fss_fusion::{
    Coverage, Decision, EvidenceItem, FusionOutcome, FusionPolicy, FusionQuery, Observability,
    Reason, ScoreCalibration, Severity, fuse,
};
use fss_reference::agent_orient::{DeploymentOrientation, EventExplanation};

use super::{ExplainArgs, ResponseParts, agent_json, evidence, read_only_boundary, take};
use crate::error::CliError;
use crate::json_input::{Value, read_document};

pub(super) const ERR_FUSION_INPUT_INVALID: &str = "ERR-FUSION-INPUT-INVALID-001";
const DEFAULT_POLICY_GENERATION: &str = "fss.explain.fusion_policy.v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FusionExplainError {
    InvalidCalibration(&'static str),
    ContextBound,
}

impl FusionExplainError {
    pub(super) fn error_id(&self) -> &'static str {
        match self {
            Self::InvalidCalibration(_) => ERR_FUSION_INPUT_INVALID,
            Self::ContextBound => super::ERR_AGENT_CONTEXT_INCOMPLETE,
        }
    }

    pub(super) fn reason(&self) -> &'static str {
        match self {
            Self::InvalidCalibration(why) => why,
            Self::ContextBound => {
                "The calibrated fusion and counterfactual explanation exceeded the admitted token allowance."
            }
        }
    }
}

pub(super) fn parse_policy(raw: &str) -> Result<FusionPolicy, &'static str> {
    let parts: Vec<&str> = raw.split(',').collect();
    if parts.len() != 3 {
        return Err(
            "fusion policy must be three comma-separated milliban integers: alert_mban,corroborate_mban,conflict_floor_mban",
        );
    }
    let alert_threshold = parts[0]
        .parse::<i64>()
        .map_err(|_| "alert_mban must be a signed integer")?;
    let retain_threshold = parts[1]
        .parse::<i64>()
        .map_err(|_| "corroborate_mban must be a signed integer")?;
    let reject_threshold = parts[2]
        .parse::<i64>()
        .map_err(|_| "conflict_floor_mban must be a signed integer")?;
    if !(reject_threshold < retain_threshold && retain_threshold <= alert_threshold) {
        return Err(
            "fusion policy thresholds must satisfy conflict_floor_mban < corroborate_mban <= alert_mban",
        );
    }
    Ok(FusionPolicy {
        generation: DEFAULT_POLICY_GENERATION.to_owned(),
        alert_threshold,
        retain_threshold,
        reject_threshold,
        min_independent_support: 2,
        urgent_single_domain_threshold: None,
        max_wait_ns: 0,
        look_penalty_per_doubling: 0,
        operator_confirmation_available: false,
    })
}

pub(super) fn default_policy() -> FusionPolicy {
    FusionPolicy {
        generation: DEFAULT_POLICY_GENERATION.to_owned(),
        alert_threshold: 1_000,
        retain_threshold: 0,
        reject_threshold: -1_000,
        min_independent_support: 2,
        urgent_single_domain_threshold: None,
        max_wait_ns: 0,
        look_penalty_per_doubling: 0,
        operator_confirmation_available: false,
    }
}

pub(super) fn parse(
    values: &[(String, String, usize)],
) -> Result<(Option<PathBuf>, Option<String>), CliError> {
    let score_calibration = take(values, "--score-calibration").map(|(_, v, _)| PathBuf::from(v));
    let fusion_policy = match take(values, "--fusion-policy") {
        None => None,
        Some((_, value, index)) => {
            if score_calibration.is_none() {
                return Err(CliError::MissingValue {
                    option: "--score-calibration".to_owned(),
                    command: Some("explain".to_owned()),
                    expected: "a score calibration file when `--fusion-policy` is supplied"
                        .to_owned(),
                });
            }
            if let Err(reason) = parse_policy(value) {
                return Err(CliError::MalformedValue {
                    option: "--fusion-policy".to_owned(),
                    value: value.clone(),
                    reason: reason.to_owned(),
                    command: Some("explain".to_owned()),
                    index: *index,
                });
            }
            Some(value.clone())
        }
    };
    Ok((score_calibration, fusion_policy))
}

struct LoadedCalibration {
    calibration: ScoreCalibration,
    domain_scores_ppm: BTreeMap<String, u32>,
}

fn field<'a>(
    map: &'a BTreeMap<String, Value>,
    key: &str,
) -> Result<&'a Value, FusionExplainError> {
    map.get(key)
        .ok_or(FusionExplainError::InvalidCalibration(
            "score calibration missing required field",
        ))
}

fn as_text<'a>(value: &'a Value) -> Result<&'a str, FusionExplainError> {
    value
        .text()
        .ok_or(FusionExplainError::InvalidCalibration(
            "score calibration expected string field",
        ))
}

fn as_u32(value: &Value) -> Result<u32, FusionExplainError> {
    value
        .integer()
        .and_then(|v| u32::try_from(v).ok())
        .ok_or(FusionExplainError::InvalidCalibration(
            "score calibration expected u32 integer",
        ))
}

fn as_u64(value: &Value) -> Result<u64, FusionExplainError> {
    value
        .integer()
        .and_then(|v| u64::try_from(v).ok())
        .ok_or(FusionExplainError::InvalidCalibration(
            "score calibration expected u64 integer",
        ))
}

fn load_score_calibration(path: &Path) -> Result<LoadedCalibration, FusionExplainError> {
    let path_str = path
        .to_str()
        .ok_or(FusionExplainError::InvalidCalibration(
            "score calibration path requires UTF-8",
        ))?;
    let document = read_document(path_str).map_err(|_| {
        FusionExplainError::InvalidCalibration(
            "score calibration file is unreadable or malformed JSON",
        )
    })?;
    let top = document
        .object()
        .ok_or(FusionExplainError::InvalidCalibration(
            "score calibration must be a JSON object",
        ))?;
    let cal_obj = match top.get("score_calibration") {
        Some(inner) => inner
            .object()
            .ok_or(FusionExplainError::InvalidCalibration(
                "score_calibration field must be a JSON object",
            ))?,
        None => top,
    };
    if cal_obj.get("schema").and_then(Value::text) != Some("fss.score_calibration.v1") {
        return Err(FusionExplainError::InvalidCalibration(
            "score calibration schema must be fss.score_calibration.v1",
        ));
    }
    let generation = as_text(field(cal_obj, "generation")?)?;
    let bins_val =
        field(cal_obj, "bins")?
            .array()
            .ok_or(FusionExplainError::InvalidCalibration(
                "score calibration bins must be an array",
            ))?;
    let mut edges = Vec::with_capacity(bins_val.len());
    let mut counts = Vec::with_capacity(bins_val.len());
    for bin_val in bins_val {
        let bin = bin_val
            .object()
            .ok_or(FusionExplainError::InvalidCalibration(
                "score calibration bin must be an object",
            ))?;
        edges.push(as_u32(field(bin, "lo_ppm")?)?);
        counts.push((
            as_u64(field(bin, "true_positives")?)?,
            as_u64(field(bin, "false_positives")?)?,
        ));
    }
    let calibration = ScoreCalibration::from_counts(generation, &edges, &counts).map_err(|_| {
        FusionExplainError::InvalidCalibration("score calibration counts failed validation")
    })?;
    let declared = as_text(field(cal_obj, "digest")?)?;
    if declared != calibration.digest.to_text() {
        return Err(FusionExplainError::InvalidCalibration(
            "score calibration digest does not match recomputed Wilson bins",
        ));
    }
    let mut domain_scores_ppm = BTreeMap::new();
    for map_key in ["domain_scores_ppm", "camera_scores_ppm"] {
        if let Some(scores_val) = top.get(map_key) {
            let scores_obj =
                scores_val
                    .object()
                    .ok_or(FusionExplainError::InvalidCalibration(
                        "scores_ppm map must be an object",
                    ))?;
            for (k, score_val) in scores_obj {
                let ppm = as_u32(score_val)?;
                if ppm > 1_000_000 {
                    return Err(FusionExplainError::InvalidCalibration(
                        "score_ppm entry exceeds 1000000 ppm",
                    ));
                }
                domain_scores_ppm.insert(k.clone(), ppm);
            }
        }
    }
    Ok(LoadedCalibration {
        calibration,
        domain_scores_ppm,
    })
}

fn disposition_label(outcome: &FusionOutcome) -> &'static str {
    if outcome.knowledge_state == "conflicted"
        || outcome.reasons.contains(&Reason::ConflictingEvidence)
    {
        "Conflicted"
    } else if matches!(
        outcome.decision,
        Decision::Alert | Decision::AlertDegradedCoverage
    ) {
        "AlertWarranted"
    } else if outcome.supporting_clusters == 1
        && outcome
            .reasons
            .contains(&Reason::InsufficientIndependentSupport)
    {
        "SingleSourceOnly"
    } else if matches!(outcome.decision, Decision::Reject | Decision::RetainSilently) {
        "NoActivity"
    } else {
        "AbstainCorroborate"
    }
}

fn add(left: u64, right: u64) -> Result<u64, FusionExplainError> {
    left.checked_add(right)
        .ok_or(FusionExplainError::ContextBound)
}

fn proposition_bytes(propositions: &[EnvelopeProposition]) -> Result<u64, FusionExplainError> {
    let mut bytes = 0;
    for p in propositions {
        for text in [&p.id, &p.statement, &p.provenance] {
            bytes = add(bytes, text.len() as u64)?;
        }
        bytes = add(bytes, p.state.as_str().len() as u64)?;
        for text in &p.evidence {
            bytes = add(bytes, text.len() as u64)?;
        }
    }
    Ok(bytes)
}

pub(super) fn augment(
    support: &mut evidence::SupportReview,
    explanation: &EventExplanation,
    args: &ExplainArgs,
) -> Result<(), FusionExplainError> {
    let Some(path) = &args.score_calibration else {
        return Ok(());
    };
    let loaded = load_score_calibration(path)?;
    let policy = match &args.fusion_policy {
        Some(raw) => parse_policy(raw).map_err(FusionExplainError::InvalidCalibration)?,
        None => default_policy(),
    };
    let event = &explanation.event.event;
    let target = explanation.event.revision_digest;
    let high_score = loaded
        .calibration
        .bins
        .last()
        .map_or(900_000, |b| b.lo_ppm.midpoint(b.hi_ppm));
    let low_score = loaded
        .calibration
        .bins
        .first()
        .map_or(100_000, |b| b.lo_ppm.midpoint(b.hi_ppm));
    let mut evidence_items = Vec::new();
    for (idx, edge) in event.evidence.iter().enumerate() {
        if !matches!(
            edge.relation,
            EvidenceEdgeRelation::Supports | EvidenceEdgeRelation::Contradicts
        ) {
            continue;
        }
        let domain = if edge.failure_domain.is_empty() {
            format!("edge-{idx}")
        } else {
            edge.failure_domain.clone()
        };
        let score_ppm = loaded
            .domain_scores_ppm
            .get(&domain)
            .or_else(|| loaded.domain_scores_ppm.get(&idx.to_string()))
            .copied()
            .unwrap_or(match edge.relation {
                EvidenceEdgeRelation::Supports => high_score,
                EvidenceEdgeRelation::Contradicts => low_score,
                _ => high_score,
            });
        evidence_items.push(EvidenceItem {
            id: format!("edge:{idx}:{}", edge.digest),
            sensor: domain.clone(),
            failure_domains: BTreeSet::from([domain]),
            calibration: loaded.calibration.calibrate(score_ppm),
            observability: Observability::Observed,
        });
    }
    let query = FusionQuery {
        hypothesis: event.event_id.as_str().to_owned(),
        kind: event.kind.as_str().to_owned(),
        prior: loaded.calibration.prior,
        evidence: evidence_items,
        coverage: Coverage::Complete,
        opportunities: Vec::new(),
        probes: Vec::new(),
        severity: Severity {
            expected_harm: 1_000,
            false_alert_cost: 100,
            delay_cost_per_second: 10,
            reversible: false,
        },
        policy,
        looks: 1,
        now_ns: 0,
    };
    let outcome = fuse(&query).map_err(|_| {
        FusionExplainError::InvalidCalibration("calibrated fusion query failed validation")
    })?;
    let receipt = ExplainReceipt::compile(
        ExplainQuestion::Why,
        target,
        vec![
            support.receipt.receipt_digest(),
            loaded.calibration.digest,
            outcome.query_digest,
            outcome.decision_digest,
        ],
        Vec::new(),
        0,
    )
    .map_err(|_| FusionExplainError::InvalidCalibration("explain receipt failed validation"))?;

    let reasons_str: Vec<&str> = outcome.reasons.iter().map(|r| r.as_str()).collect();
    let fusion_state = if outcome.knowledge_state == "conflicted" {
        KnowledgeState::Conflicted
    } else if matches!(
        outcome.decision,
        Decision::Alert | Decision::AlertDegradedCoverage
    ) {
        KnowledgeState::Estimated
    } else {
        KnowledgeState::Indeterminate
    };
    let mut new_propositions = vec![EnvelopeProposition {
        id: format!("claim:event-fusion:{target}:posterior-llr"),
        statement: format!(
            "Calibrated fusion assessment (generation {}, digest {}): posterior_llr_mban=[{}, {}], probability_ppm=[{}, {}], disposition={}, decision={}, supporting_clusters={}, contradicting_clusters={}, reasons=[{}].",
            loaded.calibration.generation,
            loaded.calibration.digest,
            outcome.posterior.lo(),
            outcome.posterior.hi(),
            outcome.probability_ppm.0,
            outcome.probability_ppm.1,
            disposition_label(&outcome),
            outcome.decision.as_str(),
            outcome.supporting_clusters,
            outcome.contradicting_clusters,
            reasons_str.join(","),
        ),
        state: fusion_state,
        provenance: "derived".to_owned(),
        evidence: vec![
            loaded.calibration.digest.to_text(),
            outcome.query_digest.to_text(),
            outcome.decision_digest.to_text(),
        ],
    }];

    for cluster in &outcome.clusters {
        let domains: Vec<&str> = cluster.failure_domains.iter().map(String::as_str).collect();
        new_propositions.push(EnvelopeProposition {
            id: format!("claim:event-fusion:{target}:cluster:{}", cluster.label),
            statement: format!(
                "Failure-domain hull cluster {} (direction={}, llr_mban=[{}, {}], domains=[{}], members=[{}]): Frechet-Hoeffding common-cause envelope counts shared domains once.",
                cluster.label,
                cluster.direction.as_str(),
                cluster.llr.lo(),
                cluster.llr.hi(),
                domains.join(","),
                cluster.members.join(","),
            ),
            state: KnowledgeState::Estimated,
            provenance: "derived".to_owned(),
            evidence: vec![outcome.decision_digest.to_text()],
        });
    }

    let mut new_invalidators = Vec::new();
    for cf in &outcome.counterfactuals {
        let removed_domains: Vec<&str> = outcome
            .clusters
            .iter()
            .find(|c| c.label == cf.removed_cluster)
            .map(|c| c.failure_domains.iter().map(String::as_str).collect())
            .unwrap_or_default();
        let flips = cf.decision != outcome.decision;
        new_propositions.push(EnvelopeProposition {
            id: format!(
                "claim:event-fusion:{target}:counterfactual:{}",
                cf.removed_cluster
            ),
            statement: format!(
                "Counterfactual minimal-flip witness (removed_cluster={}, removed_domains=[{}]): posterior_llr_mban=[{}, {}], decision={}, flips_decision={}.",
                cf.removed_cluster,
                removed_domains.join(","),
                cf.posterior.lo(),
                cf.posterior.hi(),
                cf.decision.as_str(),
                flips,
            ),
            state: KnowledgeState::Estimated,
            provenance: "derived".to_owned(),
            evidence: vec![outcome.decision_digest.to_text()],
        });
        if flips {
            new_invalidators.push(format!(
                "Removing failure-domain cluster {} ([{}]) flips the calibrated fusion decision from {} to {} (posterior_llr_mban=[{}, {}]).",
                cf.removed_cluster,
                removed_domains.join(","),
                outcome.decision.as_str(),
                cf.decision.as_str(),
                cf.posterior.lo(),
                cf.posterior.hi(),
            ));
        }
    }
    if let Some(needed) = outcome.support_to_alert {
        new_invalidators.push(format!(
            "Additional independent calibrated support of at least {needed} millibans across >= 2 disjoint failure domains is required to reach the alert threshold."
        ));
    }

    let pointers = [
        receipt.receipt_digest().to_text(),
        loaded.calibration.digest.to_text(),
        outcome.query_digest.to_text(),
        outcome.decision_digest.to_text(),
    ];
    let mut extra_bytes = proposition_bytes(&new_propositions)?;
    for text in new_invalidators
        .iter()
        .map(String::as_str)
        .chain(pointers.iter().map(String::as_str))
    {
        extra_bytes = add(extra_bytes, text.len() as u64)?;
    }
    let next_tokens = add(support.consumed.tokens, extra_bytes.div_ceil(4))?;
    if extra_bytes > 8 * 1024 || next_tokens > support.requested.tokens {
        return Err(FusionExplainError::ContextBound);
    }
    support.consumed.tokens = next_tokens;
    support.propositions.extend(new_propositions);
    support.invalidators.extend(new_invalidators);
    support.proof_pointers.extend(pointers);
    support.receipt = receipt;
    Ok(())
}

pub(super) fn refusal(
    orientation: &DeploymentOrientation,
    explanation: &EventExplanation,
    request_digest: ContentDigest,
    support: &evidence::SupportReview,
    error: &FusionExplainError,
) -> Result<String, Box<dyn std::error::Error>> {
    let capsule = orientation.capsule();
    super::build_response(ResponseParts {
        operation: "explain",
        request_digest,
        principal: capsule.principal_id.clone(),
        session_id: Some(capsule.session_id.as_str().to_owned()),
        mission_id: Some(capsule.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: support.view,
        capability: super::CAPABILITY_EXPLAIN,
        outcome: ResponseOutcome::Refused,
        error_id: Some(error.error_id()),
        payload_schema: AgentCognitiveEnvelope::SCHEMA,
        payload_json: "null".to_owned(),
        epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial,
        warnings: vec![error.reason().to_owned()],
        contradictions: orientation.contradictions.clone(),
        degradation: vec![
            "The calibrated fusion explanation was refused; no uncalibrated fallback or truncated counterfactual was substituted.".to_owned(),
        ],
        budgets_json: agent_json::budget_summary(&support.requested, &support.consumed),
        proof_pointers: vec![
            explanation.event.event_root.to_text(),
            explanation.event.revision_digest.to_text(),
        ],
        affordances: Vec::new(),
        affordance_objects: Vec::new(),
        decision_fingerprint: request_digest,
        compression_receipt_id: None,
        continuation: None,
        recovery_class: "operator_action_required",
        safe_retry: ResponseSafeRetry::No,
        boundary: read_only_boundary(
            "No calibrated fusion explanation was served; no event or effect was changed."
                .to_owned(),
        ),
        created_at_ns: capsule.created_at.0,
        workspace_revision: None,
        idempotency_key: None,
    })
}
