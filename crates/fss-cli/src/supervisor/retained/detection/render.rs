#![forbid(unsafe_code)]
//! Complete direct-source projection with no fabricated event, track or continuity identity.

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::agent_json::{array, object, string};
use crate::event_fusion::render as fusion;

use super::super::render as retained;
use super::{
    Error, RETAINED_DETECTION_REPORT_SCHEMA, Result, RetainedDetectionReport,
    RetainedDetectionSource, Selection, finish,
};

fn list(values: impl IntoIterator<Item = String>) -> String {
    array(&values.into_iter().collect::<Vec<_>>())
}
fn digest(value: ContentDigest) -> String {
    string(&value.to_text())
}
fn optional(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_owned(), |n| n.to_string())
}

pub(super) fn source(source: &RetainedDetectionSource) -> String {
    object(&[
        ("report_digest", digest(source.report_digest)),
        ("record_digest", digest(source.record_digest)),
        ("detection_root", digest(source.detection_root)),
        ("source_verified", source.source_verified.to_string()),
        (
            "health_digest",
            source
                .health_digest
                .map_or_else(|| "null".to_owned(), digest),
        ),
    ])
}

fn selection(row: &Selection) -> String {
    object(&[
        ("report_digest", digest(row.source.report_digest)),
        ("record_digest", digest(row.source.record_digest)),
        ("detection_root", digest(row.source.detection_root)),
        ("capsule_digest", digest(row.capsule_digest)),
        ("segment", row.segment.to_string()),
        ("detection_row", row.detection_row.to_string()),
        ("observation_identity", digest(row.observation)),
        ("new_evidence", row.new_evidence.to_string()),
        (
            "health_digest",
            row.source
                .health_digest
                .map_or_else(|| "null".to_owned(), digest),
        ),
    ])
}

fn fields(report: &RetainedDetectionReport) -> Vec<(&'static str, String)> {
    let spec = report.request.template().spec();
    let work = &report.discovery;
    vec![
        ("schema", string(RETAINED_DETECTION_REPORT_SCHEMA)),
        ("request_digest", digest(report.request.digest())),
        (
            "observation_basis",
            string("verified_retained_native_detection_records"),
        ),
        ("site_lineage", string(&spec.site_lineage)),
        ("hypothesis_id", string(&spec.hypothesis_id)),
        ("label", string(&spec.label)),
        ("start_ns", string(&spec.start_ns.to_string())),
        (
            "authority_sequence",
            string(&report.basis.commit_sequence.to_string()),
        ),
        ("authority_state_root", digest(report.basis.state_root)),
        ("ledger_root", digest(report.ledger_root)),
        ("effect_root", digest(report.effect_root)),
        (
            "calibration_applicability",
            string("owner_asserted_for_exact_retained_plan_not_deployment_qualification"),
        ),
        (
            "look_count_provenance",
            string("bounded_plan_windows_not_persistent_exposure_accounting"),
        ),
        ("source_custody_verified", "true".to_owned()),
        ("tracking_association", string("not_established")),
        ("cross_camera_actor_association", string("not_established")),
        ("clock_synchronization", string("not_established")),
        ("supports_absence_claim", "false".to_owned()),
        ("effects_authorized", "false".to_owned()),
        ("anytime_bound_verified", "false".to_owned()),
        ("cameras", list(spec.cameras.iter().map(retained::camera))),
        ("source_inventory", list(report.sources.iter().map(source))),
        ("health_catalog", report.health_json.clone()),
        (
            "observations",
            list(report.observations.iter().map(retained::observation)),
        ),
        (
            "windows",
            list(report.windows.iter().map(|window| {
                object(&[
                    ("window_index", window.window_index.to_string()),
                    ("end_ns", string(&window.end_ns.to_string())),
                    ("new_observations", window.new_observations.to_string()),
                    (
                        "unique_observations",
                        window.unique_observations.to_string(),
                    ),
                    (
                        "cameras_without_new_observations",
                        list(
                            window
                                .cameras_without_new_observations
                                .iter()
                                .map(|s| string(s)),
                        ),
                    ),
                    ("selections", list(window.selections.iter().map(selection))),
                    ("query", fusion::query(&window.query)),
                    ("outcome", fusion::outcome(&window.outcome)),
                ])
            })),
        ),
        (
            "discovery",
            object(&[
                ("catalog_objects", work.catalog_objects.to_string()),
                ("catalog_reports", work.catalog_reports.to_string()),
                ("metadata_reads", work.metadata_reads.to_string()),
                (
                    "source_reports_opened",
                    work.source_reports_opened.to_string(),
                ),
                ("selected_reports", work.selected_reports.to_string()),
                (
                    "selected_observations",
                    work.selected_observations.to_string(),
                ),
                (
                    "non_detection_frames",
                    work.non_detection_frames.to_string(),
                ),
                ("history_scan_units", work.history_scan_units.to_string()),
                (
                    "no_detection_semantics",
                    string("no_selected_class_row_never_absence_or_complete_sampling"),
                ),
                (
                    "exclusions",
                    list(work.exclusions.iter().map(|entry| {
                        object(&[
                            ("report_digest", digest(entry.source.report_digest)),
                            ("record_digest", digest(entry.source.record_digest)),
                            ("detection_root", digest(entry.source.detection_root)),
                            ("source_verified", entry.source.source_verified.to_string()),
                            ("reason", string(entry.reason)),
                            (
                                "capsule_digest",
                                entry.row.map_or_else(|| "null".to_owned(), |r| digest(r.0)),
                            ),
                            (
                                "segment",
                                entry
                                    .row
                                    .map_or_else(|| "null".to_owned(), |r| r.1.to_string()),
                            ),
                            (
                                "detection_row",
                                entry
                                    .row
                                    .map_or_else(|| "null".to_owned(), |r| r.2.to_string()),
                            ),
                        ])
                    })),
                ),
            ]),
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
                    (report.read_after.used_bytes - report.read_before.used_bytes).to_string(),
                ),
                (
                    "read_attempts",
                    (report.read_after.used_read_attempts - report.read_before.used_read_attempts)
                        .to_string(),
                ),
                (
                    "total_reserved_bytes",
                    report.read_after.used_bytes.to_string(),
                ),
                (
                    "total_read_attempts",
                    report.read_after.used_read_attempts.to_string(),
                ),
                (
                    "remaining_bytes",
                    optional(report.read_after.remaining_bytes),
                ),
                (
                    "remaining_read_attempts",
                    optional(report.read_after.remaining_read_attempts),
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
                (
                    "maximum_catalog_reports",
                    report.request.maximum_catalog_reports().to_string(),
                ),
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

pub(super) fn seal(report: &RetainedDetectionReport) -> Result<ContentDigest> {
    let unsigned = object(&fields(report));
    if unsigned.len() > report.request.template().spec().limits.max_report_bytes {
        return Err(Error::Limit("complete detector discovery report bytes"));
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.retained_detection_discovery_receipt.v1");
    encoder.bytes(unsigned.as_bytes());
    finish(encoder)
}

pub(super) fn report(report: &RetainedDetectionReport) -> Result<String> {
    let mut fields = fields(report);
    fields.push(("receipt_digest", digest(report.digest)));
    let json = object(&fields);
    if json.len() > report.request.template().spec().limits.max_report_bytes {
        return Err(Error::Limit("complete detector discovery report bytes"));
    }
    Ok(json)
}
