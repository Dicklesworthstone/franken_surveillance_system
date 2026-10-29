#![forbid(unsafe_code)]
//! Complete deterministic projection; the receipt binds every field except itself.

use super::*;
use crate::agent_json::{array, object, string};
use crate::event_fusion::render as fusion;

fn list(values: impl IntoIterator<Item = String>) -> String {
    array(&values.into_iter().collect::<Vec<_>>())
}
fn digest(value: ContentDigest) -> String {
    string(&value.to_text())
}
fn optional(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_owned(), |n| n.to_string())
}
pub(super) fn camera(camera: &RetainedCameraSpec) -> String {
    object(&[
        ("camera_id", string(&camera.camera_id)),
        ("sensor_id", string(&camera.sensor_id)),
        ("package_digest", digest(camera.package_digest)),
        ("model_digest", digest(camera.model_digest)),
        ("contract_digest", digest(camera.contract_digest)),
        ("class_index", camera.class_index.to_string()),
        (
            "failure_domains",
            list(camera.failure_domains.iter().map(|v| string(v))),
        ),
        (
            "calibration",
            camera
                .calibration
                .as_ref()
                .map_or_else(|| "null".to_owned(), fusion::count_calibration),
        ),
    ])
}

pub(super) fn observation(o: &RetainedSupervisorObservation) -> String {
    let mut fields = vec![
        ("identity", digest(o.identity)),
        ("sensor_id", string(&o.sensor_id)),
        ("capsule_digest", digest(o.capsule_digest)),
        ("segment", o.segment.to_string()),
        (
            "capture_ns",
            list(o.capture_ns.iter().map(|n| string(&n.to_string()))),
        ),
        ("clock_basis", string(o.clock_basis.as_str())),
        ("capture_time_label", string(&o.capture_time_label)),
        ("package_digest", digest(o.package_digest)),
        ("model_digest", digest(o.model_digest)),
        ("model_id", string(&o.model_id)),
        ("generation", string(&o.generation)),
        ("contract_digest", digest(o.contract_digest)),
        ("class_index", o.class_index.to_string()),
        ("detection_row", o.detection_row.to_string()),
        ("score_f32_bits", o.score_bits.to_string()),
        (
            "score_ppm_outward",
            list(o.score_ppm.iter().map(u32::to_string)),
        ),
        ("bounds", list(o.bounds.iter().map(u32::to_string))),
        ("inference_identity", digest(o.inference_identity)),
        ("output_digest", digest(o.output_digest)),
        ("detection_report_digest", digest(o.detection_report_digest)),
        (
            "calibration_digest",
            o.calibration_digest
                .map_or_else(|| "null".to_owned(), digest),
        ),
    ];
    if let Some(health) = &o.health {
        fields.push(("historical_health", super::health::exposure_json(health)));
    }
    object(&fields)
}

fn selection(s: &SelectionLink) -> String {
    object(&[
        ("event_id", string(s.selector.event_id.as_str())),
        ("capsule_digest", digest(s.selector.capsule_digest)),
        ("segment", s.selector.segment.to_string()),
        ("detection_row", s.selector.detection_row.to_string()),
        ("observation_identity", digest(s.observation)),
        ("new_evidence", s.new_evidence.to_string()),
        ("event_root", digest(s.event_root)),
        ("track", digest(s.track)),
        ("analysis_digest", digest(s.analysis_digest)),
        ("detection_record", digest(s.detection_record)),
        ("detection_root", digest(s.detection_root)),
    ])
}

fn fields(r: &RetainedSupervisorReport) -> Vec<(&'static str, String)> {
    let spec = &r.plan.spec;
    vec![
        ("schema", string(RETAINED_SUPERVISOR_REPORT_SCHEMA)),
        (
            "observation_basis",
            string("verified_retained_native_detections"),
        ),
        ("plan_digest", digest(r.plan.digest)),
        ("site_lineage", string(&spec.site_lineage)),
        ("hypothesis_id", string(&spec.hypothesis_id)),
        ("label", string(&spec.label)),
        ("start_ns", string(&spec.start_ns.to_string())),
        (
            "authority_sequence",
            string(&r.basis.commit_sequence.to_string()),
        ),
        ("authority_state_root", digest(r.basis.state_root)),
        ("ledger_root", digest(r.ledger_root)),
        ("effect_root", digest(r.effect_root)),
        (
            "calibration_applicability",
            string("owner_asserted_for_exact_retained_plan_not_deployment_qualification"),
        ),
        (
            "look_count_provenance",
            string("bounded_plan_windows_not_persistent_exposure_accounting"),
        ),
        ("source_custody_verified", "true".to_owned()),
        ("cross_camera_actor_association", string("not_established")),
        ("clock_synchronization", string("not_established")),
        ("supports_absence_claim", "false".to_owned()),
        ("effects_authorized", "false".to_owned()),
        ("anytime_bound_verified", "false".to_owned()),
        ("cameras", list(spec.cameras.iter().map(camera))),
        (
            "events",
            list(spec.events.iter().map(|e| {
                object(&[
                    ("camera_id", string(&e.camera_id)),
                    ("event_id", string(e.event_id.as_str())),
                    ("expected_event_root", digest(e.expected_event_root)),
                ])
            })),
        ),
        ("observations", list(r.observations.iter().map(observation))),
        ("health_catalog", r.health_json.clone()),
        (
            "windows",
            list(r.windows.iter().map(|w| {
                object(&[
                    ("window_index", w.window_index.to_string()),
                    ("end_ns", string(&w.end_ns.to_string())),
                    ("new_observations", w.new_observations.to_string()),
                    ("unique_observations", w.unique_observations.to_string()),
                    (
                        "cameras_without_new_observations",
                        list(w.cameras_without_new_observations.iter().map(|c| string(c))),
                    ),
                    ("selections", list(w.selections.iter().map(selection))),
                    ("query", fusion::query(&w.query)),
                    ("outcome", fusion::outcome(&w.outcome)),
                ])
            })),
        ),
        (
            "read_usage",
            object(&[
                (
                    "accounting",
                    string("conservative_stored_envelope_reservations_including_eof_probe"),
                ),
                (
                    "reserved_bytes",
                    (r.read_after.used_bytes - r.read_before.used_bytes).to_string(),
                ),
                (
                    "read_attempts",
                    (r.read_after.used_read_attempts - r.read_before.used_read_attempts)
                        .to_string(),
                ),
                ("total_reserved_bytes", r.read_after.used_bytes.to_string()),
                (
                    "total_read_attempts",
                    r.read_after.used_read_attempts.to_string(),
                ),
                ("remaining_bytes", optional(r.read_after.remaining_bytes)),
                (
                    "remaining_read_attempts",
                    optional(r.read_after.remaining_read_attempts),
                ),
                ("journal_observations", "2".to_owned()),
                (
                    "open_recovery_and_filesystem_metadata_included",
                    "false".to_owned(),
                ),
            ]),
        ),
        (
            "limits",
            object(&[
                ("max_read_bytes", spec.limits.max_read_bytes.to_string()),
                (
                    "max_read_attempts",
                    spec.limits.max_read_attempts.to_string(),
                ),
                (
                    "max_journal_bytes",
                    spec.limits.max_journal_bytes.to_string(),
                ),
                ("max_report_bytes", spec.limits.max_report_bytes.to_string()),
            ]),
        ),
    ]
}

pub(super) fn seal(r: &RetainedSupervisorReport) -> Result<ContentDigest> {
    let unsigned = object(&fields(r));
    if unsigned.len() > r.plan.spec.limits.max_report_bytes {
        return Err(Error::Limit("complete report bytes"));
    }
    let mut e = CanonicalEncoder::new();
    e.text("fss.retained_supervisor_receipt.v1");
    e.bytes(unsigned.as_bytes());
    finish(e)
}

pub(super) fn report(r: &RetainedSupervisorReport) -> String {
    let mut fields = fields(r);
    fields.push(("receipt_digest", digest(r.digest)));
    object(&fields)
}
