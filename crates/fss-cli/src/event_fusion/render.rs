#![forbid(unsafe_code)]
//! Bounded-parent JSON projection. Engine queries are directly replayable by fss-fuse.
use super::*;

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
pub(crate) fn query(q: &FusionQuery) -> String {
    crate::fusion_json::fusion_query_json(q)
}
pub(crate) fn outcome(o: &FusionOutcome) -> String {
    crate::fusion_json::fusion_outcome_json(o)
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
pub(crate) fn count_calibration(c: &ScoreCalibration) -> String {
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
    let mut fields = vec![
        (
            "schema",
            text(match r.profile.whole_recording {
                Some(WholeRecordingScope::Watch(_)) => "fss.event_class_fusion_report.v2",
                Some(WholeRecordingScope::Corroboration(_)) => "fss.event_class_fusion_report.v3",
                Some(WholeRecordingScope::Dwell(_)) => "fss.event_class_fusion_report.v4",
                None => "fss.event_class_fusion_report.v1",
            }),
        ),
        ("recipe", text(RECIPE)),
        ("profile_digest", text(&r.profile.digest.to_text())),
        (
            "coverage_digests",
            array(
                r.profile
                    .spec
                    .coverage_digests
                    .iter()
                    .map(|d| text(&d.to_text())),
            ),
        ),
        // Always preserve the complete policy/prior/time, including zero-candidate reports.
        // This is an empty-input template, NOT an evaluated or observed hypothesis.
        (
            "profile_query_template",
            query(&super::query(&r.profile.spec, "profile", Vec::new())),
        ),
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
    ];
    if let Some(root) = r.profile.long_watch_analysis_root() {
        fields.extend([
            ("source_scope", text(streaming::SCOPE)),
            (
                "analysis_digest",
                text(&r.profile.spec.plan_digest.to_text()),
            ),
            ("analysis_root", text(&root.to_text())),
            (
                "detector_recipe_digest",
                text(&r.profile.spec.cascade_digest.to_text()),
            ),
            (
                "maximum_candidates",
                streaming::MAX_LONG_CANDIDATES.to_string(),
            ),
            ("maximum_total_evidence", MAX_TOTAL_EVIDENCE.to_string()),
            ("coverage_witness_supplied", "false".to_owned()),
        ]);
    }
    if let Some(roots) = r.profile.long_corroboration_analysis_roots() {
        fields.extend([
            ("source_scope", text(corroboration::SCOPE)),
            (
                "analysis_digest",
                text(&r.profile.spec.plan_digest.to_text()),
            ),
            (
                "long_corroboration_analysis_roots",
                array(roots.iter().map(|root| text(&root.to_text()))),
            ),
            (
                "detector_recipe_digest",
                text(&r.profile.spec.cascade_digest.to_text()),
            ),
            (
                "maximum_candidates",
                MAX_LONG_CORROBORATION_CANDIDATES.to_string(),
            ),
            ("maximum_total_evidence", MAX_TOTAL_EVIDENCE.to_string()),
            ("coverage_witness_supplied", "false".to_owned()),
        ]);
    }
    if let Some(root) = r.profile.long_dwell_analysis_root() {
        fields.extend([
            ("source_scope", text(dwell::SCOPE)),
            (
                "analysis_digest",
                text(&r.profile.spec.plan_digest.to_text()),
            ),
            ("analysis_root", text(&root.to_text())),
            (
                "detector_recipe_digest",
                text(&r.profile.spec.cascade_digest.to_text()),
            ),
            ("maximum_candidates", MAX_LONG_DWELL_CANDIDATES.to_string()),
            ("maximum_total_evidence", MAX_TOTAL_EVIDENCE.to_string()),
            (
                "temporal_claim",
                text("sampled_dwell_only_no_continuous_occupancy"),
            ),
            ("coverage_witness_supplied", "false".to_owned()),
            ("continuous_occupancy_certified", "false".to_owned()),
        ]);
    }
    object(&fields)
}
