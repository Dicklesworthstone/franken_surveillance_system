#![forbid(unsafe_code)]
//! Pure, deterministic projections for replayable numerical fusion and source-loss scenarios.

use fss_fusion::{
    Calibration, Coverage, Decision, FusionAblation, FusionOutcome, FusionQuery, LlrInterval,
    Observability,
};

fn text(s: &str) -> String {
    format!("\"{}\"", crate::escape_json_str(s))
}
fn array(rows: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", rows.into_iter().collect::<Vec<_>>().join(","))
}
fn object(rows: &[(&str, String)]) -> String {
    format!(
        "{{{}}}",
        rows.iter()
            .map(|(k, v)| format!("{}:{v}", text(k)))
            .collect::<Vec<_>>()
            .join(",")
    )
}
fn pair(llr: LlrInterval) -> String {
    format!("[{},{}]", llr.lo(), llr.hi())
}
fn optional<T: ToString>(v: Option<T>) -> String {
    v.map_or_else(|| "null".to_owned(), |v| v.to_string())
}
fn decision(d: &Decision) -> String {
    let mut fields = vec![("kind", text(d.as_str()))];
    match d {
        Decision::WaitForCorroboration {
            opportunity,
            deadline_ns,
            value_bound,
        } => {
            fields.extend([
                ("opportunity", text(opportunity)),
                ("deadline_ns", text(&deadline_ns.to_string())),
                ("value_bound", text(&value_bound.to_string())),
            ]);
        }
        Decision::RequestObservation { probe, value_bound } => fields.extend([
            ("probe", text(probe)),
            ("value_bound", text(&value_bound.to_string())),
        ]),
        _ => {}
    }
    object(&fields)
}
fn calibration(c: &Calibration) -> String {
    match c {
        Calibration::Calibrated { generation, llr } => {
            object(&[("generation", text(generation)), ("llr", pair(*llr))])
        }
        Calibration::Uncalibrated { reason } => object(&[("uncalibrated", text(reason))]),
    }
}
fn observability(o: &Observability) -> String {
    match o {
        Observability::Observed => text("observed"),
        Observability::Redacted => text("redacted"),
        Observability::Stale => text("stale"),
        Observability::NotObservable { reason } => object(&[("not_observable", text(reason))]),
    }
}
/// Render a complete numerical query that the ordinary fss-fuse parser can replay.
#[must_use]
pub fn fusion_query_json(q: &FusionQuery) -> String {
    let p = &q.policy;
    let s = q.severity;
    object(&[
        ("schema", text("fss.fusion_query.v2")),
        ("hypothesis", text(&q.hypothesis)),
        ("kind", text(&q.kind)),
        ("prior", pair(q.prior)),
        ("looks", q.looks.to_string()),
        ("now_ns", text(&q.now_ns.to_string())),
        (
            "coverage",
            match &q.coverage {
                Coverage::Complete => object(&[("state", text("complete"))]),
                Coverage::Degraded { reason } => {
                    object(&[("state", text("degraded")), ("reason", text(reason))])
                }
                Coverage::Gap { reason } => {
                    object(&[("state", text("gap")), ("reason", text(reason))])
                }
            },
        ),
        (
            "severity",
            object(&[
                ("expected_harm", text(&s.expected_harm.to_string())),
                ("false_alert_cost", text(&s.false_alert_cost.to_string())),
                (
                    "delay_cost_per_second",
                    text(&s.delay_cost_per_second.to_string()),
                ),
                ("reversible", s.reversible.to_string()),
            ]),
        ),
        (
            "policy",
            object(&[
                ("generation", text(&p.generation)),
                ("alert_threshold", p.alert_threshold.to_string()),
                ("retain_threshold", p.retain_threshold.to_string()),
                ("reject_threshold", p.reject_threshold.to_string()),
                (
                    "min_independent_support",
                    p.min_independent_support.to_string(),
                ),
                (
                    "urgent_single_domain_threshold",
                    optional(p.urgent_single_domain_threshold),
                ),
                ("max_wait_ns", text(&p.max_wait_ns.to_string())),
                (
                    "look_penalty_per_doubling",
                    p.look_penalty_per_doubling.to_string(),
                ),
                (
                    "operator_confirmation_available",
                    p.operator_confirmation_available.to_string(),
                ),
            ]),
        ),
        (
            "evidence",
            array(q.evidence.iter().map(|e| {
                object(&[
                    ("id", text(&e.id)),
                    ("sensor", text(&e.sensor)),
                    (
                        "failure_domains",
                        array(e.failure_domains.iter().map(|d| text(d))),
                    ),
                    ("observability", observability(&e.observability)),
                    ("calibration", calibration(&e.calibration)),
                ])
            })),
        ),
        (
            "opportunities",
            array(q.opportunities.iter().map(|o| {
                object(&[
                    ("id", text(&o.id)),
                    ("sensor", text(&o.sensor)),
                    (
                        "failure_domains",
                        array(o.failure_domains.iter().map(|d| text(d))),
                    ),
                    ("window_start_ns", text(&o.window_start.to_string())),
                    ("window_end_ns", text(&o.window_end.to_string())),
                    ("positive", pair(o.positive)),
                    ("negative", pair(o.negative)),
                ])
            })),
        ),
        (
            "probes",
            array(q.probes.iter().map(|p| {
                object(&[
                    ("id", text(&p.id)),
                    ("kind", text(&p.kind)),
                    (
                        "failure_domains",
                        array(p.failure_domains.iter().map(|d| text(d))),
                    ),
                    ("cost", text(&p.cost.to_string())),
                    ("latency_ns", text(&p.latency_ns.to_string())),
                    ("positive", pair(p.positive)),
                    ("negative", pair(p.negative)),
                ])
            })),
        ),
    ])
}
/// Render the core decision, including common-cause hulls, exclusions and counterfactuals.
/// Raw-score and source provenance belong in the enclosing owner-specific report.
#[must_use]
pub fn fusion_outcome_json(o: &FusionOutcome) -> String {
    object(&[
        ("schema", text("fss.fusion_outcome.v1")),
        ("implementation", text(fss_fusion::IMPLEMENTATION_ID)),
        ("query_digest", text(&o.query_digest.to_text())),
        ("decision_digest", text(&o.decision_digest.to_text())),
        ("policy_generation", text(&o.policy_generation)),
        ("decision", decision(&o.decision)),
        ("reasons", array(o.reasons.iter().map(|r| text(r.as_str())))),
        ("knowledge_state", text(o.knowledge_state)),
        ("provenance_class", text("derived")),
        ("posterior_log_odds_millibans", pair(o.posterior)),
        (
            "probability_ppm",
            format!("[{},{}]", o.probability_ppm.0, o.probability_ppm.1),
        ),
        (
            "sequential_alert_threshold",
            o.sequential_alert_threshold.to_string(),
        ),
        ("supporting_clusters", o.supporting_clusters.to_string()),
        (
            "contradicting_clusters",
            o.contradicting_clusters.to_string(),
        ),
        ("support_to_alert", optional(o.support_to_alert)),
        ("reduction_to_retain", optional(o.reduction_to_retain)),
        (
            "clusters",
            array(o.clusters.iter().map(|c| {
                object(&[
                    ("label", c.label.to_string()),
                    ("members", array(c.members.iter().map(|m| text(m)))),
                    (
                        "failure_domains",
                        array(c.failure_domains.iter().map(|d| text(d))),
                    ),
                    ("llr_millibans", pair(c.llr)),
                    ("direction", text(c.direction.as_str())),
                ])
            })),
        ),
        (
            "excluded",
            array(
                o.excluded
                    .iter()
                    .map(|(id, reason)| object(&[("id", text(id)), ("reason", text(reason))])),
            ),
        ),
        (
            "uncalibrated",
            array(o.uncalibrated.iter().map(|id| text(id))),
        ),
        (
            "counterfactuals",
            array(o.counterfactuals.iter().map(|c| {
                object(&[
                    ("removed_cluster", c.removed_cluster.to_string()),
                    ("posterior_log_odds_millibans", pair(c.posterior)),
                    ("decision", decision(&c.decision)),
                ])
            })),
        ),
        ("effect_authority", "false".to_owned()),
    ])
}

/// Complete output budget shared by the offline and native ablation wrappers.
/// Owners check the complete JSON before releasing it; no successful prefix is returned.
pub const MAX_ABLATION_REPORT_BYTES: usize = 16 * 1024 * 1024;

/// Render the complete immutable source-loss explanation. Numerical replay inputs retain
/// every row, including existing uncertainty; the original and projected decisions are separate.
/// Returns None unless both replay queries fit the ordinary parser's byte bound and the complete
/// report fits the ablation output bound. No successful prefix is returned.
#[must_use]
pub fn fusion_ablation_json(report: &FusionAblation) -> Option<String> {
    let original = fusion_query_json(report.original_query());
    let counterfactual = fusion_query_json(report.counterfactual_query());
    if original.len() > fss_core::json_input::MAX_INPUT_BYTES
        || counterfactual.len() > fss_core::json_input::MAX_INPUT_BYTES
    {
        return None;
    }
    let json = object(&[
        ("schema", text(fss_fusion::FUSION_ABLATION_SCHEMA)),
        (
            "implementation",
            text(fss_fusion::FUSION_ABLATION_IMPLEMENTATION),
        ),
        (
            "targets",
            array(report.targets().iter().map(|target| {
                object(&[
                    ("kind", text(target.kind())),
                    ("identity", text(target.identity())),
                ])
            })),
        ),
        (
            "baseline",
            object(&[
                ("query", original),
                ("outcome", fusion_outcome_json(report.baseline())),
            ]),
        ),
        (
            "counterfactual",
            object(&[
                ("query", counterfactual),
                ("outcome", fusion_outcome_json(report.outcome())),
            ]),
        ),
        (
            "unavailable_evidence",
            array(report.unavailable_evidence().iter().map(|id| text(id))),
        ),
        (
            "removed_opportunities",
            array(report.removed_opportunities().iter().map(|id| text(id))),
        ),
        (
            "removed_probes",
            array(report.removed_probes().iter().map(|id| text(id))),
        ),
        (
            "work",
            object(&[
                (
                    "selector_item_checks",
                    text(&report.work().selector_item_checks.to_string()),
                ),
                (
                    "fusion_evaluations",
                    report.work().fusion_evaluations.to_string(),
                ),
            ]),
        ),
        ("ablation_digest", text(&report.digest().to_text())),
        ("event_policy_changed", "false".to_owned()),
        ("effect_authority", "false".to_owned()),
    ]);
    (json.len().saturating_add(1) <= MAX_ABLATION_REPORT_BYTES).then_some(json)
}
