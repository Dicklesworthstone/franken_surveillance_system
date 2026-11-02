#![forbid(unsafe_code)]
//! Complete adopted-camera atlas provenance and exact-byte export envelopes.
//!
//! These pure serializers do not resolve authority, open sources or publish files. Their
//! JSON fragments must come from the established strict input and sealed-owner serializers.
//! The command revalidates every source and current adoption before releasing the final
//! report, and holds the deployment owner through publication. FSATLAS1 stays unchanged.

use fss_cli::json_output::{array, object, string};
use fss_cli::retained_continuity_query::{anchor_digest, authority_anchor_json};
use fss_core::{ContentDigest, DigestAlgorithm, LedgerAnchor};
use fss_geometry::{GeometryBasis, GeometryError, WorkBudget};
use fss_twin::PropertyTwin;
use fss_twin::atlas_archive::MAX_ATLAS_BYTES;
use fss_twin::reconstruction_atlas::AtlasBuildReceipt;

use super::atlas_report::{count, digest};
use super::{Result, atlas_report, fail, input_error};

pub(super) const MANIFEST_SCHEMA: &str = "fss.reconstruction_atlas_adopted_provenance.v1";
pub(super) const REPORT_SCHEMA: &str = "fss.reconstruction_atlas_adopted.v1";
const BODY_SCHEMA: &str = "fss.reconstruction_atlas_adopted_report.v1";
const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;
const MAX_COST_BYTES: usize = 4096;

/// Exact immutable declarations, native results and owner-produced current lineage.
pub(super) struct ManifestInput<'a> {
    pub twin: &'a PropertyTwin,
    pub geometry_basis: (u64, u64),
    pub rig_digest: ContentDigest,
    pub rig_semantic_digest: ContentDigest,
    pub rig_declarations: &'a str,
    pub query_digest: ContentDigest,
    pub query_declarations: &'a str,
    pub selection_digest: ContentDigest,
    pub selection_declarations: &'a str,
    pub entry_anchor: &'a LedgerAnchor,
    pub anchor: &'a LedgerAnchor,
    /// Complete `calibrated_report::calibration` output from the selected sealed owner.
    pub calibration: &'a str,
    /// All canonical `{camera,record_digest,record}` rows, including unused source views.
    /// Each record is exactly `report::calibrated_view_json`, without re-encoding its hash.
    pub source_records: &'a [String],
    /// Complete strict `calibrated_report::GeometryReport::json`, including all alternatives.
    pub geometry: &'a str,
    pub build: &'a AtlasBuildReceipt,
}

/// Exact bytes hashed by the unchanged atlas archive, with native result pins for finalization.
pub(super) struct Manifest {
    pub json: String,
    pub digest: ContentDigest,
    atlas_digest: [u8; 32],
    descriptor_digest: [u8; 32],
    landmarks: usize,
    references: usize,
    bindings: usize,
}

/// Actual archive result, never a request to replace its geometry or reference descriptors.
pub(super) struct ArchiveSummary {
    pub package_digest: ContentDigest,
    pub atlas_digest: [u8; 32],
    pub descriptor_digest: [u8; 32],
    pub bytes: usize,
    pub landmarks: usize,
    pub references: usize,
    pub bindings: usize,
}

fn work_error(error: GeometryError) -> super::super::Failure {
    fail(
        if error == GeometryError::Cancelled {
            "ERR-SCENE-FUSION-CANCELLED-001"
        } else {
            "ERR-SCENE-FUSION-LIMIT-001"
        },
        error.to_string(),
    )
}

fn pin(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256 && value.bytes() != [0; 32]
}

fn bounded_length(length: usize, maximum: usize, why: &'static str) -> Result<()> {
    if maximum == 0
        || maximum > MAX_REPORT_BYTES
        || length.checked_add(1).is_none_or(|value| value > maximum)
    {
        return Err(fail("ERR-SCENE-FUSION-LIMIT-001", why));
    }
    Ok(())
}

/// Keep the difference between current owner adoption, mathematical fitting and physical truth.
pub(super) fn assumptions() -> String {
    array(&[
        "atlas_is_a_derived_candidate_and_does_not_activate_calibration_or_change_the_twin",
        "current_adoption_is_owner_authority_not_an_independent_physical_calibration_measurement",
        "source_camera_poses_and_intrinsics_come_only_from_the_exact_current_adopted_candidate",
        "direct_pinhole_pixels_preserve_the_exact_original_calibration_image_domain_and_dimensions",
        "current_adoption_and_withdrawal_are_revalidated_at_the_report_anchor_before_publication",
        "all_original_source_ranges_and_current_privacy_are_revalidated_before_publication",
        "enduring_static_eligibility_and_twin_feature_assignments_are_explicit_owner_declarations",
        "physical_groups_are_declared_alias_groups_not_authenticated_object_identity",
        "all_selected_landmark_member_views_and_actual_native_descriptors_are_preserved",
        "all_unselected_candidates_and_geometric_refusals_remain_in_the_manifest",
        "capture_window_stationarity_does_not_establish_enduring_landmark_stability",
        "absolute_landmark_error_remains_unknown_and_is_not_derived_from_pixel_covariance",
        "reconstruction_pixel_covariance_excludes_shared_camera_map_lens_clock_and_correspondence_error",
        "local_calibration_covariance_is_conditional_and_has_no_cross_camera_covariance_blocks",
        "archive_checksums_do_not_grant_source_access_or_establish_future_source_privacy",
        "reference_exposures_are_not_independent_localization_validation_observations",
        "coordinates_remain_in_the_exact_twin_source_units_and_scale_basis",
    ].map(string))
}

/// Serialize the complete native admission and retained authority without a circular archive hash.
/// The returned digest covers the exact UTF-8 manifest, not a reparsed/reordered representation.
pub(super) fn manifest(
    input: &ManifestInput<'_>,
    maximum_bytes: usize,
    work: &mut WorkBudget<'_>,
) -> Result<Manifest> {
    work.charge(0).map_err(work_error)?;
    let (property, revision) = input.geometry_basis;
    if GeometryBasis::new(property, revision).ok() != Some(input.twin.basis())
        || input.build.twin_digest != input.twin.digest()
        || input.source_records.len() != input.build.sources.len()
        || !(2..=8).contains(&input.source_records.len())
        || !(1..=128).contains(&input.build.landmarks.len())
        || input.entry_anchor.site_lineage != input.anchor.site_lineage
        || input.entry_anchor.ledger_epoch != input.anchor.ledger_epoch
        || input.entry_anchor.commit_sequence > input.anchor.commit_sequence
        || [
            input.rig_digest,
            input.rig_semantic_digest,
            input.query_digest,
            input.selection_digest,
        ]
        .into_iter()
        .any(|value| !pin(value))
    {
        return Err(input_error(
            "adopted atlas manifest basis or complete inventory differs",
        ));
    }
    let descriptor_digest = input.build.sources[0].descriptor_domain;
    if descriptor_digest == [0; 32]
        || input
            .build
            .sources
            .iter()
            .any(|source| source.descriptor_domain != descriptor_digest)
    {
        return Err(input_error(
            "adopted atlas reference descriptor spaces differ",
        ));
    }
    let references = input
        .build
        .sources
        .iter()
        .filter(|source| source.included)
        .count();
    let bindings = input
        .build
        .landmarks
        .iter()
        .map(|point| point.members.len())
        .sum::<usize>();
    if !(2..=8).contains(&references) || !(2..=256).contains(&bindings) {
        return Err(input_error(
            "adopted atlas archive membership is outside its native bounds",
        ));
    }
    // Admission is independent of the caller's requested output allowance. Every complete
    // supplied fragment is charged before it is copied, even for a one-byte output request.
    let mut input_bytes = 0_usize;
    for part in [
        input.rig_declarations,
        input.query_declarations,
        input.selection_declarations,
        input.calibration,
        input.geometry,
    ]
    .into_iter()
    .chain(input.source_records.iter().map(String::as_str))
    {
        if part.is_empty() {
            return Err(input_error(
                "adopted atlas manifest contains an empty complete JSON fragment",
            ));
        }
        input_bytes = input_bytes
            .checked_add(part.len())
            .filter(|value| *value <= MAX_REPORT_BYTES)
            .ok_or_else(|| {
                fail(
                    "ERR-SCENE-FUSION-LIMIT-001",
                    "complete adopted atlas fragments exceed 32 MiB",
                )
            })?;
    }
    work.charge(131_072 + input_bytes as u64 * 8)
        .map_err(work_error)?;
    let receipt = atlas_report::receipt(input.build, work);
    // Preserve cancellation even when the older shared receipt serializer reports LIMIT.
    work.charge(0).map_err(work_error)?;
    let receipt = receipt?;
    work.charge(65_536 + receipt.len() as u64 * 8)
        .map_err(work_error)?;
    let json = object(&[
        ("schema", string(MANIFEST_SCHEMA)),
        ("authority", string("derived_cognition_no_effect_authority")),
        ("twin_digest", digest(input.twin.digest())),
        (
            "source_scene_digest",
            digest(input.twin.source_scene_digest()),
        ),
        (
            "geometry_basis",
            object(&[("property", count(property)), ("revision", count(revision))]),
        ),
        ("coordinate_frame", string("RH_Z_UP")),
        ("evaluation_scope", string(input.twin.evaluation_scope())),
        ("observation_epoch", string(input.twin.observation_epoch())),
        (
            "scale",
            super::super::matching::report::scale(input.twin.scale()),
        ),
        (
            "map_error",
            match input.twin.geometry_error() {
                Some(value) => {
                    object(&[("state", string("available")), ("value", value.to_string())])
                }
                None => object(&[
                    ("state", string("unavailable")),
                    ("reason", string("map_error_not_quantified")),
                ]),
            },
        ),
        ("camera_rig_digest", string(&input.rig_digest.to_text())),
        (
            "camera_rig_semantic_digest",
            string(&input.rig_semantic_digest.to_text()),
        ),
        ("rig_declarations", input.rig_declarations.to_owned()),
        ("query_digest", string(&input.query_digest.to_text())),
        ("query_declarations", input.query_declarations.to_owned()),
        (
            "selection_digest",
            string(&input.selection_digest.to_text()),
        ),
        ("selection", input.selection_declarations.to_owned()),
        (
            "entry_anchor_digest",
            string(&anchor_digest(input.entry_anchor).to_text()),
        ),
        ("entry_anchor", authority_anchor_json(input.entry_anchor)),
        (
            "anchor_digest",
            string(&anchor_digest(input.anchor).to_text()),
        ),
        ("anchor", authority_anchor_json(input.anchor)),
        ("calibration", input.calibration.to_owned()),
        ("source_records", array(input.source_records)),
        ("geometry", input.geometry.to_owned()),
        ("atlas_build", receipt),
        ("assumptions", assumptions()),
    ]);
    bounded_length(
        json.len(),
        maximum_bytes,
        "complete adopted atlas provenance exceeds its output allowance",
    )?;
    let digest = ContentDigest::sha256(json.as_bytes());
    work.charge(0).map_err(work_error)?;
    Ok(Manifest {
        json,
        digest,
        atlas_digest: input.build.atlas_digest,
        descriptor_digest,
        landmarks: input.build.landmarks.len(),
        references,
        bindings,
    })
}

/// Finish one report after source and calibration revalidation, without renewing any allowance.
/// `make_cost` receives the final charged geometry-work count; its complete JSON is <=4096 bytes.
pub(super) fn finish(
    manifest: Manifest,
    archive: ArchiveSummary,
    make_cost: impl FnOnce(u64) -> String,
    maximum_bytes: usize,
    work: &mut WorkBudget<'_>,
) -> Result<String> {
    work.charge(0).map_err(work_error)?;
    if !pin(archive.package_digest)
        || archive.atlas_digest != manifest.atlas_digest
        || archive.descriptor_digest != manifest.descriptor_digest
        || archive.landmarks != manifest.landmarks
        || archive.references != manifest.references
        || archive.bindings != manifest.bindings
        || !(188..=MAX_ATLAS_BYTES).contains(&archive.bytes)
    {
        return Err(input_error(
            "archive summary differs from the complete native atlas manifest",
        ));
    }
    // Worst-case JSON escaping is six output bytes per original byte. This reservation
    // covers the escaped string, both complete envelope copies and the body digest,
    // plus the bounded cost object. It does not shrink with the caller's output cap.
    work.charge(262_144 + manifest.json.len() as u64 * 32)
        .map_err(work_error)?;
    let cost = make_cost(work.used());
    work.charge(0).map_err(work_error)?;
    if cost.is_empty() || cost.len() > MAX_COST_BYTES {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete adopted atlas cost exceeds 4096 bytes",
        ));
    }
    let body = object(&[
        ("schema", string(BODY_SCHEMA)),
        ("outcome", string("candidate_export")),
        (
            "archive",
            object(&[
                ("format", string("FSATLAS1")),
                ("package_digest", string(&archive.package_digest.to_text())),
                ("provenance_digest", string(&manifest.digest.to_text())),
                ("atlas_digest", digest(archive.atlas_digest)),
                ("descriptor_digest", digest(archive.descriptor_digest)),
                ("bytes", archive.bytes.to_string()),
                ("landmarks", archive.landmarks.to_string()),
                ("references", archive.references.to_string()),
                ("bindings", archive.bindings.to_string()),
            ]),
        ),
        ("provenance_manifest_utf8", string(&manifest.json)),
        ("cost", cost),
    ]);
    let json = object(&[
        ("schema", string(REPORT_SCHEMA)),
        (
            "report_digest",
            string(&ContentDigest::sha256(body.as_bytes()).to_text()),
        ),
        ("report", body),
    ]);
    bounded_length(
        json.len(),
        maximum_bytes,
        "complete adopted atlas report exceeds its output allowance",
    )?;
    work.charge(0).map_err(work_error)?;
    Ok(json)
}

#[cfg(test)]
#[path = "calibrated_atlas_report_tests.rs"]
mod tests;
