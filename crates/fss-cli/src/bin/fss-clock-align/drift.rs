#![forbid(unsafe_code)]
//! Explicit affine-rate input and complete diagnostics; v1 offset bytes stay unchanged.

use fss_cli::agent_json::{object, string};
use fss_cli::json_input::Value;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_geometry::temporal_alignment::MAX_CLOCK_OFFSET_HYPOTHESES;
use fss_geometry::temporal_alignment::drift::{ClockDriftScan, ClockRateHypothesis, scan_clock_drift};
use fss_geometry::temporal_validation::{TemporalCompatibility, TemporalValidationOutcome};
use super::{MAX_REPORT_BYTES, Result, failure, input};

pub const SCHEMA: &str = "fss.clock_drift_query.v1";
struct Query {
    common: input::Query,
    target_anchor_ns: i128,
    hypotheses: Vec<ClockRateHypothesis>,
}

fn query(value: &Value) -> Result<Query> {
    let Some(original) = value.object() else { return Err(failure("input", "expected drift query object")); };
    let keys = ["schema", "world_basis", "association_evidence", "reference_camera", "target_camera",
        "target_anchor_ns", "hypotheses", "fit_options", "training", "validation"];
    if original.len() != keys.len() || keys.iter().any(|key| !original.contains_key(*key))
        || original.get("schema").and_then(Value::text) != Some(SCHEMA)
    {
        return Err(failure("input", "missing, unknown or unsupported drift query field"));
    }
    let target_anchor_ns = original.get("target_anchor_ns").and_then(Value::integer)
        .ok_or_else(|| failure("input", "target anchor must be an exact signed integer"))?;
    let rows = original.get("hypotheses").and_then(Value::array)
        .filter(|rows| !rows.is_empty() && rows.len() <= MAX_CLOCK_OFFSET_HYPOTHESES)
        .ok_or_else(|| failure("input", "expected one through 64 rate hypotheses"))?;
    let mut hypotheses = Vec::new();
    hypotheses.try_reserve_exact(rows.len()).map_err(|_| failure("limit", "hypothesis allocation refused"))?;
    for row in rows {
        let fields = row.object().filter(|f| f.len() == 2 && f.contains_key("offset_ns") && f.contains_key("skew_ppb"))
            .ok_or_else(|| failure("input", "rate hypothesis needs only offset_ns and skew_ppb"))?;
        let offset_ns = fields.get("offset_ns").and_then(Value::integer)
            .ok_or_else(|| failure("input", "offset must be an exact signed integer"))?;
        let skew_ppb = fields.get("skew_ppb").and_then(Value::integer).and_then(|v| i64::try_from(v).ok())
            .ok_or_else(|| failure("input", "skew must be an exact signed integer"))?;
        hypotheses.push(ClockRateHypothesis { offset_ns, skew_ppb });
    }
    // Reuse the exact camera/source/membership reader, not a second weaker schema.
    // This internal document is never hashed, retained or presented as user input.
    let mut shared = original.clone();
    shared.remove("target_anchor_ns");
    shared.remove("hypotheses");
    shared.insert("schema".into(), Value::Text(input::SCHEMA.into()));
    shared.insert("offsets_ns".into(), Value::Array(vec![Value::Number("0".into())]));
    let common = input::query(&Value::Object(shared))?;
    Ok(Query { common, target_anchor_ns, hypotheses })
}

pub fn analyze(value: &Value, digest: ContentDigest, work_limit: u64, input_bytes: usize) -> Result<(String, bool)> {
    let query = query(value)?;
    let mut work = WorkBudget::new(work_limit);
    let scan = scan_clock_drift(query.common.pair, query.target_anchor_ns,
        &query.common.training, &query.common.validation, &query.hypotheses,
        query.common.options, &mut work).map_err(|error| failure("scan", error.to_string()))?;
    let supported = scan.trials.iter().any(|trial| trial.consistent_for_all_capture_times());
    let report = render(&query, &scan, digest, work_limit, input_bytes);
    if report.len() >= MAX_REPORT_BYTES { return Err(failure("limit", "complete drift report exceeds output bound")); }
    Ok((report, supported))
}

fn array(values: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", values.into_iter().collect::<Vec<_>>().join(","))
}
fn times(values: [i128; 2]) -> String { array(values.map(|v| string(&v.to_string()))) }
fn floats(values: &[f64]) -> String { array(values.iter().map(|v| v.to_string())) }

fn render(query: &Query, scan: &ClockDriftScan, digest: ContentDigest, work_limit: u64, input_bytes: usize) -> String {
    let common = &query.common;
    let trials = array(scan.trials.iter().map(|trial| {
        let mut fields = vec![
            ("offset_ns", string(&trial.hypothesis.offset_ns.to_string())),
            ("skew_ppb", string(&trial.hypothesis.skew_ppb.to_string())),
            ("work_units", trial.work_units.to_string()),
            ("consistent_for_all_validation_times", trial.consistent_for_all_capture_times().to_string()),
            ("training_time_mappings", array(trial.training_mappings.iter().map(|m| object(&[
                ("camera", string(&m.camera.to_string())),
                ("original_local_capture_ns", string(&m.local_time_ns.to_string())),
                ("nominal_reference_capture_ns", string(&m.mapped.nominal_ns.to_string())),
                ("exact_mapping_enclosure_ns", times(m.mapped.enclosure_ns)),
            ])))),
        ];
        match &trial.result {
            Err(error) => {
                fields.push(("outcome", string("unresolved")));
                fields.push(("reason", string(&format!("{error:?}"))));
            }
            Ok(result) => {
                let fit = &result.fit;
                fields.push(("outcome", string("evaluated")));
                fields.push(("fit", object(&[
                    ("reference_time_ns", string(&fit.reference_time_ns.to_string())),
                    ("observed_time_range_ns", times(fit.observed_time_range_ns)),
                    ("position", floats(&fit.position)),
                    ("velocity_per_second", floats(&fit.velocity_per_second)),
                    ("conditional_pixel_noise_covariance", array(fit.pixel_noise_covariance.iter().map(|r| floats(r)))),
                    ("normalized_condition_number", fit.normalized_condition_number.to_string()),
                    ("rms_reprojection_pixels", fit.rms_reprojection_pixels.to_string()),
                    ("training_residuals", array(fit.residuals.iter().map(|r| object(&[
                        ("camera", string(&r.camera.to_string())),
                        ("nominal_reference_capture_ns", string(&r.capture_time_ns.to_string())),
                        ("pixels", r.pixels.to_string()),
                    ])))),
                ])));
                fields.push(("validation", array(result.checks.iter().map(|check| {
                    let mut row = vec![("camera", string(&check.camera.to_string())),
                        ("mapped_capture_interval_ns", times(check.capture_interval_ns))];
                    match check.outcome {
                        TemporalValidationOutcome::NotObservable(reason) => {
                            row.push(("outcome", string("not_observable")));
                            row.push(("reason", string(&format!("{reason:?}"))));
                        }
                        TemporalValidationOutcome::Observable { projected_endpoints, residual_bounds_pixels, compatibility } => {
                            row.push(("outcome", string(match compatibility {
                                TemporalCompatibility::ConsistentForAllTimes => "consistent_for_all_times",
                                TemporalCompatibility::TimingAmbiguous => "timing_ambiguous",
                                TemporalCompatibility::Inconsistent => "inconsistent",
                            })));
                            row.push(("projected_endpoints", array(projected_endpoints.iter().map(|v| floats(v)))));
                            row.push(("residual_bounds_pixels", floats(&residual_bounds_pixels)));
                        }
                    }
                    object(&row)
                }))));
            }
        }
        object(&fields)
    }));
    let report = object(&[
        ("schema", string("fss.clock_drift_report.v1")),
        ("input_digest", string(&digest.to_text())),
        ("input_bytes", input_bytes.to_string()),
        ("world_basis", string(&common.world.to_text())),
        ("association_evidence", string(&common.association.to_text())),
        ("reference_camera", string(&common.pair.reference_camera.to_string())),
        ("target_camera", string(&common.pair.target_camera.to_string())),
        ("reference_clock", string(&common.pair.reference_clock.to_string())),
        ("target_clock", string(&common.pair.target_clock.to_string())),
        ("target_anchor_ns", string(&scan.target_anchor_ns.to_string())),
        ("mapping", string("reference = target_anchor - offset + (target - target_anchor) * 1000000000 / (1000000000 + skew_ppb)")),
        ("training_rounding", string("nearest integer; half ties earlier; exact rational enclosure retained, not propagated into covariance")),
        ("validation_rounding", string("earliest floor, latest ceiling; no inward rounding")),
        ("cameras", array(common.cameras.iter().map(|c| object(&[
            ("camera", string(&c.id.to_string())), ("clock", string(&c.clock.to_string())),
            ("calibration_digest", string(&c.calibration.to_text())), ("image_domain", string(&c.image_domain.to_text())),
        ])))),
        ("sources", array(common.sources.iter().map(|s| object(&[
            ("camera", string(&s.camera.to_string())), ("clock", string(&s.clock.to_string())),
            ("role", string(if s.validation { "validation_search_constraint" } else { "nominal_training" })),
            ("original_local_capture_ns", times(s.capture)), ("exposure", string(&s.exposure)),
            ("source_digest", string(&s.source.to_text())), ("evidence_digest", string(&s.evidence.to_text())),
        ])))),
        ("hypotheses_complete", "true".into()),
        ("hypothesis_count", scan.trials.len().to_string()),
        ("all_times_supported_count", scan.trials.iter().filter(|t| t.consistent_for_all_capture_times()).count().to_string()),
        ("work_limit", work_limit.to_string()), ("work_consumed", scan.work_units.to_string()),
        ("work_remaining", (work_limit - scan.work_units).to_string()),
        ("clock_activated", "false".into()), ("continuous_rate_or_offset_certified", "false".into()),
        ("source_custody_verified", "false".into()), ("physical_calibration_verified", "false".into()),
        ("independent_clock_validation", "false".into()), ("coverage_or_effect_authority", "false".into()),
        ("model", string("affine clock mapping; constant-velocity feature; fixed pinhole cameras; nominal training times")),
        ("excluded_uncertainties", string("clock-rate variation, training timestamp and rounding uncertainty, camera calibration, association, rolling shutter, acceleration and shared-mode errors")),
        ("trials", trials),
    ]);
    object(&[("schema", string("fss.clock_drift_response.v1")),
        ("report_digest", string(&ContentDigest::sha256(report.as_bytes()).to_text())), ("report", report)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_cli::json_input::parse;
    const FIXTURE: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/clock-alignment/drifting_feature.json"));
    type Test = std::result::Result<(), String>;
    fn document() -> std::result::Result<Value, String> {
        parse(std::str::from_utf8(FIXTURE).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
    }
    #[test]
    fn explicit_rate_inventory_is_complete_and_reports_rounding_and_claim_limits() -> Test {
        let (text, supported) = super::super::analyze(FIXTURE, ContentDigest::sha256(FIXTURE), 100_000_000).map_err(|e| e.detail)?;
        assert!(supported);
        let document = parse(&text).map_err(|e| e.to_string())?;
        let body = document.object().and_then(|v| v.get("report")).and_then(Value::object).ok_or("report")?;
        assert_eq!(body.get("hypothesis_count").and_then(Value::integer), Some(3));
        assert_eq!(body.get("all_times_supported_count").and_then(Value::integer), Some(1));
        assert_eq!(body.get("sources").and_then(Value::array).map(|v| v.len()), Some(22));
        assert_eq!(body.get("independent_clock_validation").and_then(Value::boolean), Some(false));
        assert_eq!(body.get("clock_activated").and_then(Value::boolean), Some(false));
        let trials = body.get("trials").and_then(Value::array).ok_or("trials")?;
        for trial in trials {
            let mappings = trial.object().and_then(|v| v.get("training_time_mappings")).and_then(Value::array).ok_or("mappings")?;
            assert_eq!(mappings.len(), 12);
        }
        let start = text.rfind("\"report\":").ok_or("body boundary")? + "\"report\":".len();
        let hash = ContentDigest::sha256(text[start..text.len()-1].trim().as_bytes()).to_text();
        assert_eq!(document.object().and_then(|v| v.get("report_digest")).and_then(Value::text), Some(hash.as_str()));
        Ok(())
    }
    #[test]
    fn offset_only_field_cannot_be_silently_ignored_in_a_drift_query() -> Test {
        let Value::Object(mut fields) = document()? else { return Err("object".into()); };
        fields.insert("offsets_ns".into(), Value::Array(vec![Value::Number("0".into())]));
        assert!(query(&Value::Object(fields)).is_err());
        Ok(())
    }
    #[test]
    fn duplicate_and_out_of_range_rate_inventory_refuse_without_output() -> Test {
        for rows in [r#"[{"offset_ns":50000000,"skew_ppb":0},{"offset_ns":"50000000","skew_ppb":"0"}]"#,
            r#"[{"offset_ns":50000000,"skew_ppb":1000001}]"#]
        {
            let Value::Object(mut fields) = document()? else { return Err("object".into()); };
            fields.insert("hypotheses".into(), parse(rows).map_err(|e| e.to_string())?);
            assert!(analyze(&Value::Object(fields), ContentDigest::sha256(FIXTURE), 100_000_000, FIXTURE.len()).is_err());
        }
        Ok(())
    }
    #[test]
    fn input_pin_and_one_shared_work_limit_apply_before_successful_drift_output() {
        assert!(super::super::analyze(FIXTURE, ContentDigest::sha256(b"wrong"), 100_000_000).is_err());
        assert!(super::super::analyze(FIXTURE, ContentDigest::sha256(FIXTURE), 1).is_err());
    }
}
