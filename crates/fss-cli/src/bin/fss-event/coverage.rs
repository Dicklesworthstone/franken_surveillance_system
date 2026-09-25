#![forbid(unsafe_code)]
//! JSON rendering of proposed or retained coverage records (`fss.recorded_watch_coverage.v1`)
//! shared by `fss-event watch` and `fss-event corroborate`. Every witness is rendered as the
//! registered `fss.coverage_witness.v1` object; every uncovered interval keeps its typed reason.
//! A `decode_refused` interval also names its `error_id`, and a ground zone with geometric
//! visibility carries a `visibility` object (fraction, sampling, occlusion model and claim);
//! records without either render exactly as before.

use fss_cli::agent_json::{array, coverage_witness, object, optional_string, string};
use fss_core::{CaptureInterval, ContentDigest};
use fss_reference::ingest::ground_visibility::{NotVisibleCause, Occlusion, ZoneVisibility};
use fss_reference::ingest::recorded_coverage::{CoverageRecord, CoverageStatus, UncoveredReason};

fn interval(value: CaptureInterval) -> String {
    format!("[{},{}]", value.earliest.0, value.latest.0)
}

fn visibility(value: &ZoneVisibility) -> String {
    let (reason, mesh) = match value.occlusion {
        Occlusion::Unknown(reason) => (Some(reason.as_str()), None),
        Occlusion::MeshChecked(digest) => (None, Some(digest.to_text())),
    };
    let mut fields = vec![
        ("camera_model", string(value.camera_model.as_str())),
        ("sampling", string(&value.sampling_label())),
        ("samples", value.samples.to_string()),
        ("visible", value.visible.to_string()),
        ("outside_frustum", value.outside_frustum.to_string()),
        ("occluded", value.occluded.to_string()),
    ];
    // Only a masked assessment names the count, so unmasked visibility bytes are unchanged.
    if value.privacy_masked > 0 {
        fields.push(("privacy_masked", value.privacy_masked.to_string()));
    }
    fields.extend([
        (
            "visible_fraction_ppm",
            value.visible_fraction_ppm().to_string(),
        ),
        ("threshold_ppm", value.threshold_ppm.to_string()),
        (
            "state",
            string(if value.observable() {
                "observable"
            } else {
                "not_observable"
            }),
        ),
        (
            "cause",
            optional_string(value.cause().map(|cause| match cause {
                NotVisibleCause::Occluded => "occluded",
                NotVisibleCause::OutsideFrustum => "outside_frustum",
                NotVisibleCause::PrivacyMasked => "privacy_masked",
            })),
        ),
        ("occlusion", string(value.occlusion.as_str())),
        ("occlusion_unknown_reason", optional_string(reason)),
        ("scene_mesh_digest", optional_string(mesh.as_deref())),
        ("claim", string(value.claim())),
    ]);
    object(&fields)
}

fn record(value: &CoverageRecord) -> String {
    let zones: Vec<String> = value
        .zones
        .iter()
        .map(|zone| {
            let witnesses: Vec<String> = zone
                .witnesses
                .iter()
                .map(|witness| {
                    object(&[
                        ("first_segment", witness.first_segment.to_string()),
                        ("last_segment", witness.last_segment.to_string()),
                        ("frames", witness.frames.to_string()),
                        ("covered_ns", interval(witness.covered)),
                        ("outer_ns", interval(witness.outer)),
                        ("witness", coverage_witness(&witness.witness)),
                    ])
                })
                .collect();
            let uncovered: Vec<String> = zone
                .uncovered
                .iter()
                .map(|gap| {
                    let (candidate, event) = match &gap.reason {
                        UncoveredReason::ZoneEntry {
                            candidate,
                            event_id,
                        } => (Some(candidate.to_text()), event_id.as_deref()),
                        _ => (None, None),
                    };
                    let mut fields = vec![
                        ("reason", string(gap.reason.as_str())),
                        ("first_segment", gap.first_segment.to_string()),
                        ("last_segment", gap.last_segment.to_string()),
                        (
                            "capture_ns",
                            gap.capture.map_or_else(|| "null".to_owned(), interval),
                        ),
                        ("candidate_id", optional_string(candidate.as_deref())),
                        ("event_id", optional_string(event)),
                    ];
                    if let UncoveredReason::DecodeRefused { error_id } = &gap.reason {
                        fields.push(("error_id", string(error_id)));
                    }
                    object(&fields)
                })
                .collect();
            let mut fields = vec![
                ("scope", string(&zone.scope)),
                ("zone_id", string(&zone.zone_id)),
                ("geometry", string(&zone.geometry)),
                (
                    "pipeline_generation",
                    string(&zone.pipeline_generation.to_text()),
                ),
                ("witness_count", zone.witnesses.len().to_string()),
                ("witnesses", array(&witnesses)),
                ("uncovered", array(&uncovered)),
            ];
            if let Some(value) = &zone.visibility {
                fields.push(("visibility", visibility(value)));
            }
            object(&fields)
        })
        .collect();
    object(&[
        ("source", string(value.source.as_str())),
        ("record_digest", string(&value.digest().to_text())),
        ("identity", string(&value.identity().to_text())),
        ("import_identity", string(&value.import_identity.to_text())),
        ("sensor_id", string(&value.sensor_id)),
        ("capture_time_label", string(&value.capture_time_label)),
        ("basis_commit", value.basis.commit_sequence.to_string()),
        ("first_segment", value.first_segment.to_string()),
        ("last_segment", value.last_segment.to_string()),
        ("analysed_ns", interval(value.analysed)),
        ("zones", array(&zones)),
    ])
}

/// The report's `coverage` member: status, the exact approval and its rerun command, and every
/// record (one for watch, one per camera for corroborate).
pub(super) fn render(
    records: &[&CoverageRecord],
    status: CoverageStatus,
    approval: ContentDigest,
    rerun: &str,
) -> String {
    let witnesses: usize = records.iter().map(|r| r.witnesses().count()).sum();
    let command = match status {
        CoverageStatus::Proposed => string(&format!("{rerun} --retain-coverage {approval}")),
        CoverageStatus::Retained | CoverageStatus::AlreadyRetained => "null".to_owned(),
    };
    let rendered: Vec<String> = records.iter().map(|value| record(value)).collect();
    object(&[
        ("format", string("fss.recorded_watch_coverage.v1")),
        ("coverage_status", string(status.as_str())),
        ("approval_digest", string(&approval.to_text())),
        ("retain_command", command),
        ("witness_count", witnesses.to_string()),
        (
            "absence_certified_for_witness_domains",
            (status != CoverageStatus::Proposed && witnesses > 0).to_string(),
        ),
        ("records", array(&rendered)),
    ])
}
