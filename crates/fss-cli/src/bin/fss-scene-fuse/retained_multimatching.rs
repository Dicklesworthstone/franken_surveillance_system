#![forbid(unsafe_code)]
//! Joint native static-feature reconstruction across three through eight retained cameras.

#[path = "retained_multimatching/input.rs"]
pub(super) mod input;
#[path = "retained_multimatching/report.rs"]
pub(super) mod report;
#[cfg(test)]
#[path = "retained_multimatching/tests.rs"]
pub(super) mod tests;

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use fss_cli::json_output::{array, object, string};
use fss_cli::retained_continuity_query::{anchor_digest, authority_anchor_json};
use fss_cli::scene_rig::SceneRig;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_reference::ingest::recorded_decode::DecodeBudget;
use fss_reference::ingest::recorded_decode::video_budget::{
    RecordedVideoDecodeBudget, VIDEO_DECODE_SEPARATE_AXIS_POLICY, VIDEO_DECODE_WORK_MODEL,
};
use fss_reference::ingest::twin_localization::features::RecordedFeatureReadBudget;
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_twin::multiview_feature_association::associate_multiview_features;
use fss_twin::{ImportExpectation, ImportLimits, import_twin};

use super::super::matching::report::scale;
use super::{
    FeatureInput, MAX_JSON_BYTES, MAX_TWIN_BYTES, Options, Result, SOURCE_BYTES, authority,
    check_cancel, checkpoint, document, extract_features, fail, fusion_input, input_error,
    options_profile, preflight_views, prepare_images, read_input, resolved, retained_handoffs,
    write_report,
};

const DEFAULT_WORK: u64 = 8_000_000_000;
const MAX_WORK: u64 = 16_000_000_000;
const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;
const JPEG_WORK: u64 = 2_000_000_000;
const VIDEO_BYTES: u64 = 512 * 1024 * 1024;
const VIDEO_LUMA: u64 = 2_147_483_648;

const HELP: &str = "fss-scene-fuse retained-multimatch --root DEPLOYMENT --site SITE\n\
    --twin PROPERTY.fsstwin --rig CAMERAS.json --query QUERY.json\n\
    [--principal PRINCIPAL] [--expected-input sha256:HEX] [--expected-anchor sha256:HEX]\n\
    [--report-out REPORT.json] [--work-units N] [--timeout-ms N] [--max-report-bytes N]\n\n\
Automatically associate native features across 3-8 authenticated retained JPEG/AVC/HEVC\n\
camera frames and reconstruct one joint static point per fully supported component.\n\
Every camera pair retains its full appearance/epipolar decisions and geometric outcomes.\n\
Components require one feature per participating camera and complete direct pair support.\n\
Conflicting camera cycles, incomplete chains and native geometric refusals remain explicit;\n\
no greedy identity assignment, hidden outlier removal or partial inventory is performed.\n\n\
Query v1 keeps declared native pinhole grids. Query v2 adds explicit native Brown-Conrady,\n\
fisheye and pinhole crop/resize correction. Use views:[...] with the same exact source, rig,\n\
image and clock declarations as retained-match. Every image plan is admitted before decoding.\n\
Target intrinsics come from the rig and corrected domains come from native maps. Source capture,\n\
dimensions and current privacy come from the sealed retained owners. Every source revalidates\n\
after complete analysis. JPEG may publish its ordinary derivative; no calibration, identity,\n\
world revision, event or effect is activated. Entry/final anchors are both reported.\n\n\
The full capture hull is at most 1 second and must contain the requested scene time. For each\n\
pair/component, the native static solver uses the requested time clamped to that subset's\n\
capture hull; both original and derived times remain explicit. This depends on the declared\n\
static scene over the FULL hull and does not estimate clock synchronization or target motion.\n\n\
Bounds: 128 features/view, 256 actual features total, 28672 Cartesian pair rows, 64 coding\n\
segments/video range. Source reads share 4 GiB including final validation. Geometry/extraction/\n\
report work defaults to 8B units (maximum 16B), sufficient in allowance for full 1080p FAST grids\n\
across 8 views. Separate decoder caps: 2B JPEG work, 512 MiB video encoded bytes, 2147483648\n\
coded-luma admission units. Inputs have the same retained-match bounds. Complete report: 32 MiB.\n\
Default timeout: 30000 ms, maximum 3600000. Output is private/exclusive and identical to stdout.\n\
Exit 0: at least one joint point and no nontrivial unresolved/refused components; 3: no joint\n\
reconstruction or unresolved/refused components; 2: input/custody/privacy/resource/I/O failure.\n\
Isolated unmatched features are retained diagnostics; pair refusals rescued by joint geometry\n\
remain visible without forcing exit 3. See docs/RETAINED_MULTICAMERA_MATCHING.md and\n\
docs/RETAINED_LENS_MATCHING.md for the exact versioned inputs and corrected source lineage.\n";

fn options(args: &[OsString]) -> Result<Option<Options>> {
    options_profile(args, DEFAULT_WORK, MAX_WORK, MAX_REPORT_BYTES)
}

struct Report {
    json: String,
    reconstructed: bool,
}

fn digest(bytes: [u8; 32]) -> String {
    string(&ContentDigest::new(fss_core::DigestAlgorithm::Sha256, bytes).to_text())
}
fn count(value: u64) -> String {
    string(&value.to_string())
}

fn analyze(options: &Options, root: &Path, cx: &ReplayCx) -> Result<Report> {
    checkpoint(cx, "retained_scene_multimatch:begin")?;
    let started = Instant::now();
    let timeout = options.timeout;
    let cancelled = || cx.is_cancelled() || started.elapsed() >= timeout;
    check_cancel(cx, &cancelled)?;
    if let Some(path) = &options.report_out {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(fail(
                    "ERR-SCENE-FUSION-OUTPUT-001",
                    "report output already exists",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(fail(
                    "ERR-SCENE-FUSION-OUTPUT-001",
                    "report output cannot be inspected",
                ));
            }
        }
    }
    let query_bytes = read_input(&options.query, MAX_JSON_BYTES, cx)?;
    let query_digest = ContentDigest::sha256(&query_bytes);
    if options
        .expected_input
        .is_some_and(|pin| pin != query_digest)
    {
        return Err(input_error("query bytes differ from --expected-input"));
    }
    let rig_bytes = read_input(&options.rig, MAX_JSON_BYTES, cx)?;
    let rig_digest = ContentDigest::sha256(&rig_bytes);
    let rig_document = document(&rig_bytes)?;
    let query = input::parse(&query_bytes, rig_digest)?;
    let (package_sha256, source_scene_sha256, basis) =
        fusion_input::twin_expectation(&rig_document)?;
    let twin_bytes = read_input(&options.twin, MAX_TWIN_BYTES, cx)?;
    let mut work = WorkBudget::with_cancellation_probe(options.work, &cancelled);
    let twin = import_twin(
        &twin_bytes,
        ImportExpectation {
            package_sha256,
            source_scene_sha256,
            basis,
        },
        ImportLimits::default(),
        &mut work,
    )
    .map_err(|e| fail("ERR-SCENE-FUSION-TWIN-001", e.to_string()))?;
    let rig = SceneRig::from_document(&rig_document, &twin, &mut work)
        .map_err(|e| fail("ERR-SCENE-FUSION-RIG-001", e.to_string()))?;
    let mut deployment = ReferenceDeployment::reopen(root, &options.site, cx)
        .map_err(|e| fail("ERR-SCENE-FUSION-INPUT-001", e.to_string()))?;
    let entry_anchor = deployment.current_anchor().clone();
    if options
        .expected_anchor
        .is_some_and(|pin| pin != anchor_digest(&entry_anchor))
    {
        return Err(input_error("deployment differs from --expected-anchor"));
    }
    preflight_views(&deployment, &query.views, cx)?;
    let images = prepare_images(&query.views, &rig, &mut work)?;
    let reads = RecordedFeatureReadBudget::with_cancellation_probe(
        SOURCE_BYTES,
        Arc::new(move || started.elapsed() >= timeout),
    );
    let mut jpeg = DecodeBudget::with_cancellation_probe(JPEG_WORK, &cancelled);
    let mut video = RecordedVideoDecodeBudget::with_separate_limits(VIDEO_BYTES, VIDEO_LUMA)
        .map_err(|e| fail(e.stable_id(), e.to_string()))?;
    let mut owners = Vec::with_capacity(query.views.len());
    for (view, image) in query.views.iter().zip(&images) {
        check_cancel(cx, &cancelled)?;
        owners.push(extract_features(
            &mut deployment,
            FeatureInput {
                view,
                image,
                extraction: query.extraction,
            },
            &reads,
            &mut jpeg,
            &mut video,
            &mut work,
            cx,
        )?);
    }
    drop(images);
    let final_anchor = deployment.current_anchor().clone();
    let snapshots = owners.iter().map(resolved).collect::<Vec<_>>();
    let views = input::bind(&query, &snapshots, &rig)?;
    let association = associate_multiview_features(&twin, &views, query.matching, &mut work)
        .map_err(|e| fail("ERR-SCENE-FUSION-POINT-001", e.to_string()))?;
    let geometry = report::compute(&association, options.report_bytes, &mut work)?;
    let receipt_bytes = owners
        .iter()
        .map(|o| o.native_receipt().len() as u64)
        .sum::<u64>();
    let feature_count = views
        .iter()
        .map(|v| v.frame.features().len() as u64)
        .sum::<u64>();
    // Pair/component rendering reserves its own complete cost. This independent bound covers
    // every source view, original receipt, query, final envelope, and repeated immutable copies.
    work.charge(
        131_072
            + receipt_bytes * 8
            + feature_count * 1024
            + query.declarations.len() as u64 * 4
            + geometry.json.len() as u64 * 4,
    )
    .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
    if query.version == 2 {
        work.charge(super::image_report::VIEW_WORK * owners.len() as u64)
            .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
    }
    let mut source_views = Vec::with_capacity(owners.len());
    for view in association.views() {
        let index = query
            .views
            .iter()
            .position(|v| v.camera == view.camera.camera)
            .ok_or_else(|| input_error("multi-camera association has no matching source owner"))?;
        source_views.push(super::report::view_json(
            view,
            &owners[index],
            &rig,
            query.version,
        ));
    }
    let (property, revision) = rig.geometry_basis();
    let analysis = object(&[
        ("authority", string("derived_cognition_no_effect_authority")),
        (
            "source_provenance",
            string("verified_retained_native_frames"),
        ),
        ("physical_identity_established", "false".into()),
        ("query_digest", string(&query_digest.to_text())),
        (
            "entry_anchor_digest",
            string(&anchor_digest(&entry_anchor).to_text()),
        ),
        ("entry_anchor", authority_anchor_json(&entry_anchor)),
        (
            "anchor_digest",
            string(&anchor_digest(&final_anchor).to_text()),
        ),
        ("anchor", authority_anchor_json(&final_anchor)),
        ("clock", count(query.matching.clock)),
        ("clock_evidence", digest(query.matching.clock_evidence)),
        ("privacy_domain", count(query.matching.privacy_domain)),
        (
            "basis",
            object(&[
                ("twin_digest", digest(twin.digest())),
                ("source_scene_digest", digest(twin.source_scene_digest())),
                (
                    "camera_rig_digest",
                    digest(query.matching.camera_rig_digest),
                ),
                (
                    "camera_rig_semantic_digest",
                    string(&rig.digest().to_text()),
                ),
                (
                    "geometry_basis",
                    object(&[("property", count(property)), ("revision", count(revision))]),
                ),
                ("coordinate_frame", string("RH_Z_UP")),
                ("evaluation_scope", string(twin.evaluation_scope())),
                ("observation_epoch", string(twin.observation_epoch())),
                ("scale", scale(twin.scale())),
                (
                    "map_error",
                    match twin.geometry_error() {
                        Some(value) => {
                            object(&[("state", string("available")), ("value", value.to_string())])
                        }
                        None => object(&[
                            ("state", string("unavailable")),
                            ("reason", string("map_error_not_quantified")),
                        ]),
                    },
                ),
            ]),
        ),
        ("declarations", query.declarations.clone()),
        (
            "assumptions",
            if query.version == 2 {
                super::image_report::assumptions(true)
            } else {
                array(&[
            "source_to_rig_mapping_and_undistorted_pixel_domain_are_operator_declarations",
            "camera_rig_is_authored_nominal_not_activated_or_physically_validated",
            "additive_clock_alignment_is_declared_and_preserves_full_source_uncertainty",
            "common_scene_features_are_stationary_over_the_full_capture_hull",
            "appearance_and_epipolar_correspondences_are_hypotheses_not_physical_identity",
            "current_deployment_privacy_masks_exclude_full_descriptor_footprints",
            "subset_solve_time_is_requested_scene_time_clamped_to_subset_capture_hull",
            "complete_direct_pair_support_is_required_for_joint_components",
            "unresolved_components_preserve_pair_alternatives_without_identity_assignment",
            "all_participating_component_views_are_required_with_no_outlier_removal",
            "pixel_noise_covariance_excludes_camera_map_clock_motion_and_correspondence_error",
            "retained_custody_does_not_establish_live_coverage_or_calibration_quality",
        ].map(string))
            },
        ),
        ("views", array(&source_views)),
        ("geometry", geometry.json),
    ]);
    if analysis
        .len()
        .checked_add(1)
        .is_none_or(|n| n > options.report_bytes)
    {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete multi-camera analysis exceeds output allowance",
        ));
    }
    // Every original source range/current mask must remain valid after all geometry and
    // source-dependent serialization. No mutable source access follows this final pass.
    for owner in &owners {
        check_cancel(cx, &cancelled)?;
        owner
            .revalidate(&deployment, cx, &mut work)
            .map_err(|e| fail(e.stable_id(), e.to_string()))?;
    }
    if *deployment.current_anchor() != final_anchor {
        return Err(input_error(
            "authority anchor changed during multi-camera matching",
        ));
    }
    check_cancel(cx, &cancelled)?;
    let body = object(&[
        (
            "schema",
            string(&format!(
                "fss.scene_feature_multimatch_retained_report.v{}",
                query.version
            )),
        ),
        ("analysis", analysis),
        (
            "cost",
            object(&[
                (
                    "geometry_work",
                    object(&[
                        ("allowance", count(options.work)),
                        ("used", count(work.used())),
                    ]),
                ),
                (
                    "source_bytes",
                    object(&[
                        ("allowance", count(SOURCE_BYTES)),
                        ("used", count(reads.used())),
                        ("includes_final_revalidation", "true".into()),
                    ]),
                ),
                (
                    "jpeg_work",
                    object(&[
                        ("allowance", count(JPEG_WORK)),
                        ("used", count(jpeg.used())),
                    ]),
                ),
                (
                    "video_admission",
                    object(&[
                        ("model", string(VIDEO_DECODE_WORK_MODEL)),
                        ("axis_policy", string(VIDEO_DECODE_SEPARATE_AXIS_POLICY)),
                        ("encoded_bytes_allowance", count(VIDEO_BYTES)),
                        ("encoded_bytes_used", count(video.encoded_bytes())),
                        ("coded_luma_allowance", count(VIDEO_LUMA)),
                        ("coded_luma_used", count(video.coded_luma_capacity())),
                    ]),
                ),
                (
                    "unmeasured",
                    array(&["cpu_time", "energy", "peak_memory"].map(string)),
                ),
            ]),
        ),
    ]);
    let json = object(&[
        (
            "schema",
            string(&format!(
                "fss.scene_feature_multimatch_retained.v{}",
                query.version
            )),
        ),
        (
            "report_digest",
            string(&ContentDigest::sha256(body.as_bytes()).to_text()),
        ),
        ("report", body),
    ]);
    if json
        .len()
        .checked_add(1)
        .is_none_or(|n| n > options.report_bytes)
    {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete multi-camera report exceeds output allowance",
        ));
    }
    Ok(Report {
        json,
        reconstructed: geometry.reconstructed,
    })
}

fn execute(options: &Options, out: &mut impl Write) -> Result<bool> {
    let authority = authority(options)?;
    let root = retained_handoffs::preflight(&options.root, &options.site, &authority)?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())
        .map_err(|e| fail("ERR-SCENE-FUSION-AUTHORITY-001", e.to_string()))?;
    let result = (|| {
        let report = analyze(options, &root, &cx)?;
        if let Some(path) = &options.report_out {
            write_report(path, report.json.as_bytes(), &cx)?;
        } else {
            checkpoint(&cx, "retained_scene_multimatch:stdout")?;
        }
        writeln!(out, "{}", report.json).map_err(|_| {
            fail(
                "ERR-SCENE-FUSION-OUTPUT-001",
                "stdout failed; any completed report file remains available",
            )
        })?;
        Ok(report.reconstructed)
    })();
    cx.drain_and_finalize();
    result
}

pub(super) fn run(args: &[OsString], out: &mut impl Write) -> Result<bool> {
    match options(args)? {
        Some(options) => execute(&options, out),
        None => {
            out.write_all(HELP.as_bytes())
                .map_err(|_| fail("ERR-SCENE-FUSION-OUTPUT-001", "help output failed"))?;
            Ok(true)
        }
    }
}
