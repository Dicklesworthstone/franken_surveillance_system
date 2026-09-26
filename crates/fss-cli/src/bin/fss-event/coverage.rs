#![forbid(unsafe_code)]
//! JSON rendering of proposed or retained coverage records (`fss.recorded_watch_coverage.v1`)
//! shared by `fss-event watch` and `fss-event corroborate`. Every witness is rendered as the
//! registered `fss.coverage_witness.v1` object; every uncovered interval keeps its typed reason.
//! A `decode_refused` interval also names its `error_id`, and a ground zone with geometric
//! visibility carries a `visibility` object (fraction, sampling, occlusion model and claim);
//! records without either render exactly as before. A record that binds its camera's pose
//! provenance (version 4) carries a `pose_provenance` object; a record whose visibility used a
//! calibrated pose without one predates provenance binding and says `unrecorded`.

use fss_cli::agent_json::{array, coverage_witness, object, optional_string, string};
use fss_core::{CaptureInterval, ContentDigest};
use fss_reference::ingest::ground_visibility::{
    CameraModel, NotVisibleCause, Occlusion, ZoneVisibility,
};
use fss_reference::ingest::recorded_coverage::{
    CoverageRecord, CoverageStatus, PoseProvenance, UncoveredReason,
};

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

/// `pose_provenance` of one record: the bound source, or `unrecorded` for a posed record that
/// predates provenance binding; `None` when no zone used a pose.
fn pose_provenance(value: &CoverageRecord) -> Option<String> {
    let Some(provenance) = &value.pose_provenance else {
        let posed = value.zones.iter().any(|zone| {
            zone.visibility
                .as_ref()
                .is_some_and(|visibility| visibility.camera_model == CameraModel::CalibratedPose)
        });
        return posed.then(|| {
            object(&[
                ("source", string("unrecorded")),
                ("claim", string("pose_source_not_bound_by_this_record")),
            ])
        });
    };
    let mut fields = vec![
        ("source", string(provenance.source())),
        ("provenance_digest", string(&provenance.digest().to_text())),
    ];
    if let PoseProvenance::SiteCalibration {
        calibration_digest,
        camera_handle,
        intrinsics_generation,
        extrinsics_generation,
        currency,
    } = provenance
    {
        fields.extend([
            ("calibration_digest", string(&calibration_digest.to_text())),
            ("camera_handle", camera_handle.to_string()),
            ("intrinsics_generation", intrinsics_generation.to_string()),
            ("extrinsics_generation", extrinsics_generation.to_string()),
            ("generation_currency", string(currency.as_str())),
        ]);
        // Only `adopted_current` names a receipt, so earlier renderings keep their bytes.
        if let Some(receipt) = currency.adoption_receipt() {
            fields.extend([
                ("adoption_receipt", string(&receipt.to_text())),
                (
                    "currency_claim",
                    string("retained_owner_adoption_not_a_physical_observation"),
                ),
            ]);
        }
    }
    fields.push(("claim", string(provenance.claim())));
    Some(object(&fields))
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
    let mut fields = vec![
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
    ];
    if let Some(provenance) = pose_provenance(value) {
        fields.push(("pose_provenance", provenance));
    }
    fields.push(("zones", array(&zones)));
    object(&fields)
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
