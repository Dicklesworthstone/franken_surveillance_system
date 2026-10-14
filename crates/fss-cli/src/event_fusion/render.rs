#![forbid(unsafe_code)]
//! Bounded-parent JSON projection. Engine queries are directly replayable by fss-fuse.
use super::*;
use fss_fusion::Decision;

pub(super) fn text(s: &str) -> String {
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
fn maybe_digest(v: Option<ContentDigest>) -> String {
    v.map_or_else(|| "null".to_owned(), |v| text(&v.to_text()))
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
fn query(q: &FusionQuery) -> String {
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
        ("opportunities", "[]".to_owned()),
        ("probes", "[]".to_owned()),
    ])
}
fn outcome(o: &FusionOutcome) -> String {
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
fn scores(rows: &[ScoreLink]) -> String {
    array(rows.iter().map(|r| {
        object(&[
            ("evidence_id", text(&r.evidence_id)),
            ("sensor", text(&r.sensor)),
            ("source_record", maybe_digest(r.source_record)),
            ("score_f32_bits", optional(r.score_bits)),
            (
                "score_ppm_outward",
                r.score_ppm
                    .map_or_else(|| "null".to_owned(), |[lo, hi]| format!("[{lo},{hi}]")),
            ),
            ("calibration_digest", maybe_digest(r.calibration)),
        ])
    }))
}
pub(super) fn count_calibration(c: &ScoreCalibration) -> String {
    object(&[
        ("schema", text("fss.score_calibration.v1")),
        ("generation", text(&c.generation)),
        ("digest", text(&c.digest.to_text())),
        ("prior_log_odds_millibans", pair(c.prior)),
        ("interval", text("wilson_z2_per_bin_not_simultaneous")),
        ("true_positives", c.positives.to_string()),
        ("false_positives", c.negatives.to_string()),
        (
            "bins",
            array(c.bins.iter().map(|b| {
                object(&[
                    ("lo_ppm", b.lo_ppm.to_string()),
                    ("hi_ppm", b.hi_ppm.to_string()),
                    ("true_positives", b.positives.to_string()),
                    ("false_positives", b.negatives.to_string()),
                    ("llr_millibans", pair(b.llr)),
                ])
            })),
        ),
    ])
}
pub(super) fn report(r: &EventFusionReport) -> String {
    object(&[
        ("schema", text("fss.event_class_fusion_report.v1")),
        ("recipe", text(RECIPE)),
        ("profile_digest", text(&r.profile.digest.to_text())),
        ("plan_digest", text(&r.profile.spec.plan_digest.to_text())),
        (
            "cascade_digest",
            text(&r.profile.spec.cascade_digest.to_text()),
        ),
        ("package_digest", text(&r.package.to_text())),
        ("class_index", r.profile.spec.class_index.to_string()),
        ("class_label", text(&r.label)),
        ("source_context_digest", text(&r.context.to_text())),
        (
            "authority_sequence",
            text(&r.basis.commit_sequence.to_string()),
        ),
        ("authority_state_root", text(&r.basis.state_root.to_text())),
        (
            "calibration_applicability",
            text("owner_asserted_for_exact_native_plan_not_deployment_qualification"),
        ),
        (
            "look_count_provenance",
            text("owner_declared_not_persistently_accounted"),
        ),
        (
            "calibrations",
            array(r.profile.spec.calibrations.iter().map(|b| {
                object(&[
                    ("sensor", text(&b.sensor)),
                    (
                        "failure_domains",
                        array(b.failure_domains.iter().map(|d| text(d))),
                    ),
                    ("calibration", count_calibration(&b.calibration)),
                ])
            })),
        ),
        (
            "candidates",
            array(r.results.iter().map(|c| {
                object(&[
                    ("candidate", text(&c.candidate.to_text())),
                    ("native_proposal", text(&c.native_proposal.to_text())),
                    (
                        "native_provenance_root",
                        text(&c.native_provenance.to_text()),
                    ),
                    ("binding_digest", text(&c.binding_digest.to_text())),
                    ("query", query(&c.query)),
                    ("scores", scores(&c.scores)),
                    ("outcome", outcome(&c.outcome)),
                ])
            })),
        ),
        ("report_digest", text(&r.digest.to_text())),
        ("complete_candidate_analysis", "true".to_owned()),
        ("class_absence_certified", "false".to_owned()),
        ("event_policy_changed", "false".to_owned()),
        ("published", "false".to_owned()),
        ("effect_authority", "false".to_owned()),
    ])
}
