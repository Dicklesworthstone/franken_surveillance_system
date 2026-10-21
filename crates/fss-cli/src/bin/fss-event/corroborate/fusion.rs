#![forbid(unsafe_code)]
//! Calibrated sequential evidence fusion (`fss-fusion`) composed over recorded corroboration
//! candidates.
//!
//! When `--score-calibration` is supplied, each corroborated candidate's per-camera entry
//! observations and declared/intrinsic failure domains are evaluated through [`fss_fusion::fuse`]
//! under the verified [`ScoreCalibration`] artifact. Observations sharing any failure domain
//! collapse into a single dependency cluster via their Fréchet-Hoeffding interval hull; independent
//! clusters sum in exact integer millibans; and removing each cluster yields a counterfactual
//! minimal-flip witness.
//!
//! This assessment is derived cognition: it never mutates positive event proposals, rewrites
//! coverage records, or grants effect authority. When `--score-calibration` is omitted, no fusion
//! section is emitted and the report remains byte-identical.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fss_cli::agent_json::{array, object, string};
use fss_cli::json_input::{Value, read_document};
use fss_core::ContentDigest;
use fss_fusion::{
    Coverage, Decision, EvidenceItem, FusionOutcome, FusionPolicy, FusionQuery, LlrInterval,
    Observability, Reason, ScoreCalibration, Severity, fuse,
};
use fss_reference::ReplayCx;
use fss_reference::ingest::detector_cascade::EvidenceOutcome;
use fss_reference::ingest::recorded_corroboration::{CorroborationError, CorroborationReport};
use fss_reference::ingest::recorded_decode::RecordedDecodeError;

use super::{CorroborateAction, RunResult};

/// Default policy generation for corroborated zone-entry fusion when `--fusion-policy` is omitted.
pub(super) const DEFAULT_POLICY_GENERATION: &str = "fss.corroboration.fusion_policy.v1";

/// Parses `--fusion-policy <alert_mban,corroborate_mban,conflict_floor_mban>`.
pub(super) fn parse_policy(raw: &str) -> Result<FusionPolicy, String> {
    let parts: Vec<&str> = raw.split(',').collect();
    if parts.len() != 3 {
        return Err(
            "--fusion-policy requires three comma-separated milliban integers: alert_mban,corroborate_mban,conflict_floor_mban"
                .to_owned(),
        );
    }
    let parse_mban = |text: &str, name: &str| -> Result<i64, String> {
        text.parse::<i64>()
            .map_err(|_| format!("invalid integer for {name} in --fusion-policy"))
    };
    let alert_threshold = parse_mban(parts[0], "alert_mban")?;
    let retain_threshold = parse_mban(parts[1], "corroborate_mban")?;
    let reject_threshold = parse_mban(parts[2], "conflict_floor_mban")?;
    if !(reject_threshold < retain_threshold && retain_threshold <= alert_threshold) {
        return Err(
            "--fusion-policy thresholds must satisfy conflict_floor_mban < corroborate_mban <= alert_mban"
                .to_owned(),
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

fn field<'a>(map: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a Value, CorroborationError> {
    map.get(key)
        .ok_or(CorroborationError::InvalidPlan("score calibration missing required field"))
}

fn as_text<'a>(value: &'a Value) -> Result<&'a str, CorroborationError> {
    value
        .text()
        .ok_or(CorroborationError::InvalidPlan("score calibration expected string field"))
}

fn as_u32(value: &Value) -> Result<u32, CorroborationError> {
    value
        .integer()
        .and_then(|v| u32::try_from(v).ok())
        .ok_or(CorroborationError::InvalidPlan("score calibration expected u32 integer"))
}

fn as_u64(value: &Value) -> Result<u64, CorroborationError> {
    value
        .integer()
        .and_then(|v| u64::try_from(v).ok())
        .ok_or(CorroborationError::InvalidPlan("score calibration expected u64 integer"))
}

fn load_score_calibration(path: &Path) -> Result<LoadedCalibration, CorroborationError> {
    let path_str = path.to_str().ok_or(CorroborationError::InvalidPlan(
        "score calibration path requires UTF-8",
    ))?;
    let document = read_document(path_str).map_err(|_| {
        CorroborationError::InvalidPlan("score calibration file is unreadable or malformed JSON")
    })?;
    let top = document.object().ok_or(CorroborationError::InvalidPlan(
        "score calibration must be a JSON object",
    ))?;
    let cal_obj = match top.get("score_calibration") {
        Some(inner) => inner.object().ok_or(CorroborationError::InvalidPlan(
            "score_calibration field must be a JSON object",
        ))?,
        None => top,
    };
    if cal_obj.get("schema").and_then(Value::text) != Some("fss.score_calibration.v1") {
        return Err(CorroborationError::InvalidPlan(
            "score calibration schema must be fss.score_calibration.v1",
        ));
    }
    let generation = as_text(field(cal_obj, "generation")?)?;
    let bins_val = field(cal_obj, "bins")?.array().ok_or(
        CorroborationError::InvalidPlan("score calibration bins must be an array"),
    )?;
    let mut edges = Vec::with_capacity(bins_val.len());
    let mut counts = Vec::with_capacity(bins_val.len());
    for bin_val in bins_val {
        let bin = bin_val.object().ok_or(CorroborationError::InvalidPlan(
            "score calibration bin must be an object",
        ))?;
        edges.push(as_u32(field(bin, "lo_ppm")?)?);
        counts.push((
            as_u64(field(bin, "true_positives")?)?,
            as_u64(field(bin, "false_positives")?)?,
        ));
    }
    let calibration = ScoreCalibration::from_counts(generation, &edges, &counts).map_err(|_| {
        CorroborationError::InvalidPlan("score calibration counts failed validation")
    })?;
    let declared = as_text(field(cal_obj, "digest")?)?;
    if declared != calibration.digest.to_text() {
        return Err(CorroborationError::InvalidPlan(
            "score calibration digest does not match recomputed Wilson bins",
        ));
    }
    let mut camera_scores_ppm = BTreeMap::new();
    if let Some(scores_val) = top.get("camera_scores_ppm") {
        let scores_obj = scores_val.object().ok_or(CorroborationError::InvalidPlan(
            "camera_scores_ppm must be an object",
        ))?;
        for (camera, score_val) in scores_obj {
            let ppm = as_u32(score_val)?;
            if ppm > 1_000_000 {
                return Err(CorroborationError::InvalidPlan(
                    "camera_scores_ppm entry exceeds 1000000 ppm",
                ));
            }
            camera_scores_ppm.insert(camera.clone(), ppm);
        }
    }
    Ok(LoadedCalibration {
        calibration,
        camera_scores_ppm,
    })
}

pub(super) struct CandidateFusionAssessment {
    candidate_id: ContentDigest,
    event_id: String,
    outcome: FusionOutcome,
}

pub(super) struct CorroborationFusionReport {
    calibration_generation: String,
    calibration_digest: ContentDigest,
    prior: LlrInterval,
    policy: FusionPolicy,
    candidates: Vec<CandidateFusionAssessment>,
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

fn interval_json(interval: LlrInterval) -> String {
    format!("[{},{}]", interval.lo(), interval.hi())
}

impl CorroborationFusionReport {
    pub(super) fn to_json(&self) -> String {
        let candidates: Vec<String> = self
            .candidates
            .iter()
            .map(|item| {
                let outcome = &item.outcome;
                let reasons: Vec<String> = outcome
                    .reasons
                    .iter()
                    .map(|reason| string(reason.as_str()))
                    .collect();
                let clusters: Vec<String> = outcome
                    .clusters
                    .iter()
                    .map(|cluster| {
                        let members: Vec<String> =
                            cluster.members.iter().map(|m| string(m)).collect();
                        let domains: Vec<String> =
                            cluster.failure_domains.iter().map(|d| string(d)).collect();
                        object(&[
                            ("label", cluster.label.to_string()),
                            ("members", array(&members)),
                            ("failure_domains", array(&domains)),
                            ("llr_mban", interval_json(cluster.llr)),
                            ("direction", string(cluster.direction.as_str())),
                        ])
                    })
                    .collect();
                let counterfactuals: Vec<String> = outcome
                    .counterfactuals
                    .iter()
                    .map(|cf| {
                        let removed_domains: Vec<String> = outcome
                            .clusters
                            .iter()
                            .find(|c| c.label == cf.removed_cluster)
                            .map(|c| c.failure_domains.iter().map(|d| string(d)).collect())
                            .unwrap_or_default();
                        object(&[
                            ("removed_cluster", cf.removed_cluster.to_string()),
                            ("removed_domains", array(&removed_domains)),
                            ("posterior_llr_mban", interval_json(cf.posterior)),
                            ("decision", string(cf.decision.as_str())),
                            (
                                "flips_decision",
                                (cf.decision != outcome.decision).to_string(),
                            ),
                        ])
                    })
                    .collect();
                object(&[
                    ("candidate_id", string(&item.candidate_id.to_text())),
                    ("event_id", string(&item.event_id)),
                    ("query_digest", string(&outcome.query_digest.to_text())),
                    (
                        "decision_digest",
                        string(&outcome.decision_digest.to_text()),
                    ),
                    ("posterior_llr_mban", interval_json(outcome.posterior)),
                    (
                        "probability_ppm",
                        format!(
                            "[{},{}]",
                            outcome.probability_ppm.0, outcome.probability_ppm.1
                        ),
                    ),
                    ("decision", string(outcome.decision.as_str())),
                    ("disposition", string(disposition_label(outcome))),
                    ("knowledge_state", string(outcome.knowledge_state)),
                    (
                        "supporting_clusters",
                        outcome.supporting_clusters.to_string(),
                    ),
                    (
                        "contradicting_clusters",
                        outcome.contradicting_clusters.to_string(),
                    ),
                    ("reasons", array(&reasons)),
                    (
                        "support_to_alert_mban",
                        outcome
                            .support_to_alert
                            .map_or_else(|| "null".to_owned(), |v| v.to_string()),
                    ),
                    (
                        "reduction_to_retain_mban",
                        outcome
                            .reduction_to_retain
                            .map_or_else(|| "null".to_owned(), |v| v.to_string()),
                    ),
                    ("clusters", array(&clusters)),
                    ("counterfactuals", array(&counterfactuals)),
                ])
            })
            .collect();
        object(&[
            ("format", string("fss.corroboration_fusion_assessment.v1")),
            ("calibration_generation", string(&self.calibration_generation)),
            (
                "score_calibration_digest",
                string(&self.calibration_digest.to_text()),
            ),
            ("prior_llr_mban", interval_json(self.prior)),
            (
                "policy",
                object(&[
                    ("generation", string(&self.policy.generation)),
                    (
                        "alert_threshold_mban",
                        self.policy.alert_threshold.to_string(),
                    ),
                    (
                        "retain_threshold_mban",
                        self.policy.retain_threshold.to_string(),
                    ),
                    (
                        "reject_threshold_mban",
                        self.policy.reject_threshold.to_string(),
                    ),
                    (
                        "min_independent_support",
                        self.policy.min_independent_support.to_string(),
                    ),
                ]),
            ),
            ("candidates", array(&candidates)),
            ("effects_authorized", "false".to_owned()),
        ])
    }
}

pub(super) struct LoadedCalibration {
    calibration: ScoreCalibration,
    camera_scores_ppm: BTreeMap<String, u32>,
}

pub(super) fn load(
    action: &CorroborateAction,
    cx: &ReplayCx,
) -> RunResult<Option<LoadedCalibration>> {
    let Some(path) = &action.score_calibration else {
        return Ok(None);
    };
    cx.checkpoint("corroboration_fusion:load")
        .map_err(|_| RecordedDecodeError::Cancelled)?;
    Ok(Some(load_score_calibration(path)?))
}

pub(super) fn assess(
    loaded: Option<&LoadedCalibration>,
    action: &CorroborateAction,
    report: &CorroborationReport,
    cx: &ReplayCx,
) -> RunResult<Option<CorroborationFusionReport>> {
    let Some(loaded) = loaded else {
        return Ok(None);
    };
    cx.checkpoint("corroboration_fusion:assess")
        .map_err(|_| RecordedDecodeError::Cancelled)?;
    let policy = action
        .fusion_policy
        .clone()
        .unwrap_or_else(default_policy);
    let mut assessments = Vec::with_capacity(report.candidates().len());
    for candidate in report.candidates() {
        let mut evidence = Vec::with_capacity(candidate.entries.len());
        for &entry_idx in &candidate.entries {
            let entry = &report.entries()[entry_idx];
            let camera = &report.cameras()[entry.camera];
            let mut failure_domains: BTreeSet<String> = report
                .dependencies()
                .cameras()
                .iter()
                .find(|c| c.camera == camera.name)
                .map(|c| c.failure_domains.iter().cloned().collect())
                .unwrap_or_default();
            failure_domains.insert(camera.failure_domain.clone());
            let score_ppm = entry
                .class_evidence
                .iter()
                .find_map(|ce| match &ce.outcome {
                    EvidenceOutcome::Associated { detection, .. } => {
                        Some((detection.score * 1_000_000.0).round().clamp(0.0, 1_000_000.0) as u32)
                    }
                    _ => None,
                })
                .or_else(|| loaded.camera_scores_ppm.get(&camera.name).copied())
                .unwrap_or_else(|| {
                    (candidate.association_score * 1_000_000.0)
                        .round()
                        .clamp(0.0, 1_000_000.0) as u32
                });
            evidence.push(EvidenceItem {
                id: format!("obs:{}:{}", camera.name, entry.record_digest),
                sensor: camera.sensor_id.clone(),
                failure_domains,
                calibration: loaded.calibration.calibrate(score_ppm),
                observability: Observability::Observed,
            });
        }
        let query = FusionQuery {
            hypothesis: candidate.event().event_id.as_str().to_owned(),
            kind: candidate.event().kind.as_str().to_owned(),
            prior: loaded.calibration.prior,
            evidence,
            coverage: Coverage::Complete,
            opportunities: Vec::new(),
            probes: Vec::new(),
            severity: Severity {
                expected_harm: 1_000,
                false_alert_cost: 100,
                delay_cost_per_second: 10,
                reversible: false,
            },
            policy: policy.clone(),
            looks: 1,
            now_ns: 0,
        };
        let outcome = fuse(&query).map_err(|_| {
            CorroborationError::InvalidPlan("calibrated fusion query failed validation")
        })?;
        assessments.push(CandidateFusionAssessment {
            candidate_id: candidate.identity(),
            event_id: candidate.event().event_id.as_str().to_owned(),
            outcome,
        });
    }
    Ok(Some(CorroborationFusionReport {
        calibration_generation: loaded.calibration.generation.clone(),
        calibration_digest: loaded.calibration.digest,
        prior: loaded.calibration.prior,
        policy,
        candidates: assessments,
    }))
}
