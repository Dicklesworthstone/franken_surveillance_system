#![forbid(unsafe_code)]
//! Full finite-scan diagnostics; no score-based pruning or clock activation.

use fss_cli::agent_json::{object, string};
use fss_core::ContentDigest;
use fss_geometry::temporal_alignment::ClockAlignmentScan;
use fss_geometry::temporal_validation::{TemporalCompatibility, TemporalValidationOutcome};
use super::input::Query;

fn array(values: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", values.into_iter().collect::<Vec<_>>().join(","))
}
fn floats(values: &[f64]) -> String { array(values.iter().map(|v| v.to_string())) }
fn times(values: [i128; 2]) -> String { array(values.map(|v| string(&v.to_string()))) }

pub fn render(query: &Query, scan: &ClockAlignmentScan, input_digest: ContentDigest,
    work_limit: u64, input_bytes: usize) -> String
{
    let trials = array(scan.trials.iter().map(|trial| {
        let mut fields = vec![
            ("target_minus_reference_ns", string(&trial.target_minus_reference_ns.to_string())),
            ("work_units", trial.work_units.to_string()),
            ("consistent_for_all_validation_times", trial.consistent_for_all_capture_times().to_string()),
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
                        ("mapped_capture_ns", string(&r.capture_time_ns.to_string())),
                        ("pixels", r.pixels.to_string()),
                    ])))),
                ])));
                fields.push(("validation", array(result.checks.iter().map(|check| {
                    let mut row = vec![
                        ("camera", string(&check.camera.to_string())),
                        ("mapped_capture_interval_ns", times(check.capture_interval_ns)),
                    ];
                    match check.outcome {
                        TemporalValidationOutcome::NotObservable(reason) => {
                            row.push(("outcome", string("not_observable")));
                            row.push(("reason", string(&format!("{reason:?}"))));
                        }
                        TemporalValidationOutcome::Observable { projected_endpoints, residual_bounds_pixels, compatibility } => {
                            let status = match compatibility {
                                TemporalCompatibility::ConsistentForAllTimes => "consistent_for_all_times",
                                TemporalCompatibility::TimingAmbiguous => "timing_ambiguous",
                                TemporalCompatibility::Inconsistent => "inconsistent",
                            };
                            row.push(("outcome", string(status)));
                            row.push(("projected_endpoints", array(projected_endpoints.iter().map(|p| floats(p)))));
                            row.push(("residual_bounds_pixels", floats(&residual_bounds_pixels)));
                        }
                    }
                    object(&row)
                }))));
            }
        }
        object(&fields)
    }));
    let supported = scan.trials.iter().filter(|trial| trial.consistent_for_all_capture_times()).count();
    let report = object(&[
        ("schema", string("fss.clock_alignment_report.v1")),
        ("input_digest", string(&input_digest.to_text())),
        ("input_bytes", input_bytes.to_string()),
        ("world_basis", string(&query.world.to_text())),
        ("association_evidence", string(&query.association.to_text())),
        ("reference_camera", string(&query.pair.reference_camera.to_string())),
        ("target_camera", string(&query.pair.target_camera.to_string())),
        ("reference_clock", string(&query.pair.reference_clock.to_string())),
        ("target_clock", string(&query.pair.target_clock.to_string())),
        ("cameras", array(query.cameras.iter().map(|camera| object(&[
            ("camera", string(&camera.id.to_string())),
            ("clock", string(&camera.clock.to_string())),
            ("calibration_digest", string(&camera.calibration.to_text())),
            ("image_domain", string(&camera.image_domain.to_text())),
        ])))),
        ("sources", array(query.sources.iter().map(|source| object(&[
            ("camera", string(&source.camera.to_string())),
            ("clock", string(&source.clock.to_string())),
            ("role", string(if source.validation { "validation_search_constraint" } else { "nominal_training" })),
            ("original_local_capture_ns", times(source.capture)),
            ("exposure", string(&source.exposure)),
            ("source_digest", string(&source.source.to_text())),
            ("evidence_digest", string(&source.evidence.to_text())),
        ])))),
        ("hypotheses_complete", "true".into()),
        ("hypothesis_count", scan.trials.len().to_string()),
        ("all_times_supported_count", supported.to_string()),
        ("work_limit", work_limit.to_string()),
        ("work_consumed", scan.work_units.to_string()),
        ("work_remaining", (work_limit - scan.work_units).to_string()),
        ("clock_activated", "false".into()),
        ("continuous_offset_certified", "false".into()),
        ("source_custody_verified", "false".into()),
        ("physical_calibration_verified", "false".into()),
        ("independent_clock_validation", "false".into()),
        ("coverage_or_effect_authority", "false".into()),
        ("model", string("constant-offset; constant-velocity; fixed pinhole cameras; nominal training times")),
        ("excluded_uncertainties", string("clock drift, training timestamp uncertainty, camera calibration, association, rolling shutter, acceleration and shared-mode errors")),
        ("trials", trials),
    ]);
    // The schema is included in these exact bytes. This integrity receipt is not authority.
    object(&[
        ("schema", string("fss.clock_alignment_response.v1")),
        ("report_digest", string(&ContentDigest::sha256(report.as_bytes()).to_text())),
        ("report", report),
    ])
}
