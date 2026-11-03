#![forbid(unsafe_code)]
//! Native reconstruction using exact, currently adopted camera calibrations.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use fss_cli::json_output::{array, object, string};
use fss_cli::retained_continuity_query::{anchor_digest, authority_anchor_json};
use fss_cli::scene_rig::{AdoptedSceneCameraBinding, SceneRig, SceneRigError};
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_geometry::{GeometryBasis, GeometryError, WorkBudget};
use fss_reference::ingest::recorded_decode::DecodeBudget;
use fss_reference::ingest::recorded_decode::video_budget::{
    RecordedVideoDecodeBudget, VIDEO_DECODE_SEPARATE_AXIS_POLICY, VIDEO_DECODE_WORK_MODEL,
};
use fss_reference::ingest::scene_calibration::{
    MAX_SCENE_CALIBRATION_AUTHORITY_BYTES, MAX_SCENE_CALIBRATION_INPUT_BYTES,
    RetainedSceneCalibration, SceneCalibrationBinding, SceneCalibrationRequest,
    resolve_scene_calibration, resolve_scene_calibration_for_rectification,
};
use fss_reference::ingest::site_calibration::{MAX_CALIBRATION_BYTES, MAX_OBSERVATION_BYTES};
use fss_reference::ingest::twin_localization::features::RecordedFeatureReadBudget;
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_twin::feature_association::FeatureView;
use fss_twin::{ImportExpectation, ImportLimits, PropertyTwin, import_twin};

use super::super::matching::report::scale;
use super::calibrated_clock;
use super::calibrated_input::{AdoptedRig, MatchingQuery};
use super::images::{ImageDeclaration, PreparedImage};
use super::input::{ResolvedFrame, Source};
use super::{
    FeatureInput, MAX_JSON_BYTES, MAX_TWIN_BYTES, Options, Result, SOURCE_BYTES,
    calibrated_input as input, calibrated_report as report, check_cancel, checkpoint,
    extract_features, fail, input_error, options_profile, prepare_images, read_input, resolved,
    retained_handoffs, write_report,
};

const DEFAULT_WORK: u64 = 8_000_000_000;
const MAX_WORK: u64 = 16_000_000_000;
const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;
pub(super) const JPEG_WORK: u64 = 2_000_000_000;
pub(super) const VIDEO_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const VIDEO_LUMA: u64 = 2_147_483_648;

const HELP: &str = "fss-scene-fuse retained-calibrated-match --root DEPLOYMENT --site SITE\n\
    --twin PROPERTY.fsstwin --rig ADOPTED-CAMERAS.json --query QUERY.json\n\
    [--principal PRINCIPAL] [--expected-input sha256:HEX] [--expected-anchor sha256:HEX]\n\
    [--report-out REPORT.json] [--work-units N] [--timeout-ms N] [--max-report-bytes N]\n\n\
Reconstruct static 3D points or moving trajectories with exact currently adopted camera\n\
calibrations. The rig schema fss.scene_camera_rig_adopted.v1 pins an FSSCAL01/02 file, each\n\
original camera input, each current adoption receipt and physical sensor. Intrinsics and\n\
poses come exclusively from that verified calibration. No caller geometry override is allowed.\n\n\
Use an existing retained-match v1/v2, retained-multimatch v1/v2 or retained-motion-match v1/v2\n\
query. All rig cameras must participate. Rig v1 requires the original calibrated pinhole\n\
domain. Rig fss.scene_camera_rig_adopted.v2 explicitly admits native radial rectification: the\n\
query source K/grid/domain, Brown[k1,k2,0]/zero tangential terms and semantic FSSCAL lens_basis\n\
must match adopted calibration exactly. Target K/grid remain the refined calibration values.\n\
Every map compiles before decoding. Direct images require zero radial terms. Camera clock,\n\
privacy, source-object mapping and use interval remain explicit owner declarations.\n\n\
Motion query v2 replays the exact original clock-validation query against the currently\n\
adopted calibration digest, sensor, pose, intrinsics and prepared image domain. Every\n\
declared clock hypothesis remains in the complete mapped exposure hull, including those\n\
without conditional support. It emits adopted report v3 without activating a clock or\n\
authenticating the clock query's declared observation sources. The 1MiB original clock\n\
query reserve comes from the existing 4GiB source-read allowance.\n\n\
Every original source and the current adoption/withdrawal history are revalidated after\n\
complete analysis. Missing, superseded, withdrawn or mismatched calibration refuses output.\n\
The report retains every correspondence alternative, conditional covariance and nominal\n\
visibility conflict. Adoption is owner authority, not a physical accuracy measurement.\n\n\
Bounds: 16 original exposures, 8 query cameras, 128 features/view, 256 actual features total\n\
(pair matching retains its existing two-view ceiling); calibration plus original inputs20MiB,\n\
authority reads64MiB, original camera reads4GiB, report32MiB. Work defaults8B, maximum16B.\n\
Timeout defaults30000ms, maximum3600000. Output is private/create-only and matches stdout.\n\
Exit0: at least one fit with no nontrivial unresolved or nominally occluded component;\n\
3: complete analysis with no fit or unresolved components;2: input/custody/currency/resource\n\
or publication failure. See docs/ADOPTED_CALIBRATION_RECONSTRUCTION.md.\n";

fn options(args: &[OsString]) -> Result<Option<Options>> {
    options_profile(args, DEFAULT_WORK, MAX_WORK, MAX_REPORT_BYTES)
}

struct Report {
    json: String,
    reconstructed: bool,
    started: Instant,
    // Retain the exclusive deployment guard through report file/stdout release.
    // Final currency checks must not be followed by a concurrent legitimate
    // adoption, withdrawal or privacy-policy publication before output completes.
    _deployment: ReferenceDeployment,
}

fn authority(options: &Options) -> Result<ContextAuthority> {
    ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-calibrated-match-cli".into(),
        operation_id: OperationId::parse("operation:retained-calibrated-match-cli")
            .map_err(|_| input_error("calibrated matching operation identity"))?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(
                SOURCE_BYTES
                    + MAX_SCENE_CALIBRATION_AUTHORITY_BYTES
                    + (MAX_TWIN_BYTES
                        + 2 * MAX_JSON_BYTES
                        + MAX_SCENE_CALIBRATION_INPUT_BYTES
                        + options.report_bytes) as u64,
            )
            .build()
            .map_err(|_| input_error("calibrated matching resource allowance"))?,
        privacy_scope: "privacy:local-authorized-retained-calibrated-matching".into(),
        retention_scope: "retention:operator-selected-report".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-AUTHORITY-001",
            "calibrated matching authority refused",
        )
    })
}

fn digest(bytes: [u8; 32]) -> String {
    string(&ContentDigest::new(fss_core::DigestAlgorithm::Sha256, bytes).to_text())
}
fn count(value: u64) -> String {
    string(&value.to_string())
}

pub(super) fn work_error(error: GeometryError) -> super::super::Failure {
    fail(
        if error == GeometryError::Cancelled {
            "ERR-SCENE-FUSION-CANCELLED-001"
        } else {
            "ERR-SCENE-FUSION-LIMIT-001"
        },
        error.to_string(),
    )
}

pub(super) fn rig_error(error: SceneRigError) -> super::super::Failure {
    match error {
        SceneRigError::Geometry(
            inner @ (GeometryError::Cancelled
            | GeometryError::BudgetExhausted
            | GeometryError::LimitExceeded),
        ) => work_error(inner),
        SceneRigError::Limit => fail("ERR-SCENE-FUSION-LIMIT-001", error.to_string()),
        _ => fail("ERR-SCENE-FUSION-RIG-001", error.to_string()),
    }
}

fn relative_to_rig(rig: &Path, file: &str) -> PathBuf {
    let file = Path::new(file);
    if file.is_absolute() {
        file.to_path_buf()
    } else {
        rig.parent().unwrap_or_else(|| Path::new(".")).join(file)
    }
}

pub(super) fn same_selected_sensors(query: &MatchingQuery, declaration: &AdoptedRig) -> Result<()> {
    let selected: BTreeSet<_> = query.views().iter().map(|v| v.camera).collect();
    if selected != declaration.cameras.iter().map(|v| v.camera).collect() {
        return Err(input_error(
            "query must use every adopted rig camera and no other camera",
        ));
    }
    for view in query.views() {
        let camera = declaration
            .cameras
            .iter()
            .find(|r| r.camera == view.camera)
            .ok_or_else(|| input_error("selected source has no adopted camera"))?;
        if view.source.pins().sensor_id != camera.sensor_id.as_str() {
            return Err(input_error(
                "selected source sensor differs from its adopted camera binding",
            ));
        }
    }
    Ok(())
}

pub(super) fn declared_modes(
    query: &MatchingQuery,
    calibration: &RetainedSceneCalibration,
) -> Result<()> {
    for view in query.views() {
        let camera = calibration
            .camera(view.camera)
            .ok_or_else(|| input_error("selected source has no verified calibration"))?;
        let basis = camera.image_basis();
        match view.image {
            ImageDeclaration::Pinhole(domain) => {
                if camera.record().distortion != [0.0, 0.0] {
                    return Err(input_error(
                        "nonzero adopted radial distortion requires explicit native rectification",
                    ));
                }
                if domain.bytes() != basis.image.image_domain {
                    return Err(input_error(
                        "source image domain differs from the exact original calibration input",
                    ));
                }
            }
            ImageDeclaration::Rectified(raw) => {
                let expected = calibration
                    .rectification_spec(view.camera, raw.maximum_radius, raw.luma_range)
                    .map_err(|e| fail(e.stable_id(), e.to_string()))?;
                if raw.spec(camera.intrinsics()) != expected {
                    return Err(input_error(
                        "source domain, refined intrinsics, radial model or lens basis differs from adopted calibration",
                    ));
                }
            }
        }
        if let (Some(expected), Source::Jpeg { interpretation, .. }) =
            (basis.interpretation, &view.source)
            && expected != *interpretation
        {
            return Err(input_error(
                "JPEG interpretation differs from the original calibration frame",
            ));
        }
    }
    Ok(())
}

/// Check the actual sealed source results against the exact plans compiled before decoding.
/// Pair/multi/temporal binding preserves query order; each source receipt is already checked
/// by images::bind, including raw pixels, privacy footprint, map and original exposure.
pub(super) fn actual_modes(
    views: &[FeatureView],
    calibration: &RetainedSceneCalibration,
    images: &[PreparedImage],
) -> Result<()> {
    if views.len() != images.len() {
        return Err(input_error(
            "calibrated image plan and source inventory differ",
        ));
    }
    for (view, image) in views.iter().zip(images) {
        let camera = calibration
            .camera(view.camera.camera)
            .ok_or_else(|| input_error("native source has no verified calibration"))?;
        let actual = view.frame.identity();
        if actual.image_domain != image.domain.bytes()
            || actual.dimensions != camera.intrinsics().dimensions()
        {
            return Err(input_error(
                "actual native feature image differs from the calibrated image mode",
            ));
        }
        if let Some(plan) = &image.rectifier {
            let spec = plan.spec();
            let expected = calibration
                .rectification_spec(view.camera.camera, spec.maximum_radius, spec.range)
                .map_err(|e| fail(e.stable_id(), e.to_string()))?;
            if spec != expected || actual.image_domain != plan.output_domain() {
                return Err(input_error(
                    "actual rectification plan differs from the exact adopted lens model",
                ));
            }
        } else if camera.record().distortion != [0.0, 0.0]
            || actual.image_domain != camera.image_basis().image.image_domain
        {
            return Err(input_error(
                "direct native feature image differs from the calibrated pinhole source",
            ));
        }
    }
    Ok(())
}

fn snapshot<'a>(v: &ResolvedFrame<'a>) -> ResolvedFrame<'a> {
    ResolvedFrame {
        capsule: v.capsule,
        import_identity: v.import_identity,
        segment: v.segment,
        dimensions: v.dimensions,
        exposure: v.exposure,
        luma: v.luma,
        frame: v.frame,
        allowed_mask_digest: v.allowed_mask_digest,
        codec: v.codec,
        range_start: v.range_start,
        range_count: v.range_count,
        rectification: v.rectification,
    }
}

pub(super) fn bind(
    query: &MatchingQuery,
    snapshots: &[ResolvedFrame<'_>],
    rig: &SceneRig,
) -> Result<Vec<FeatureView>> {
    bind_with_clock(query, snapshots, rig, None)
}

fn bind_with_clock(
    query: &MatchingQuery,
    snapshots: &[ResolvedFrame<'_>],
    rig: &SceneRig,
    clock: Option<&super::temporal_clock::Ready>,
) -> Result<Vec<FeatureView>> {
    if clock.is_some() && !matches!(query, MatchingQuery::Temporal(_)) {
        return Err(input_error(
            "clock replay requires the explicit temporal query profile",
        ));
    }
    match query {
        MatchingQuery::Pair(query) => {
            let [left, right] = snapshots else {
                return Err(input_error(
                    "static pair requires exactly two original sources",
                ));
            };
            super::input::bind(query, [snapshot(left), snapshot(right)], rig).map(Vec::from)
        }
        MatchingQuery::Multi(query) => super::multiview::input::bind(query, snapshots, rig),
        MatchingQuery::Temporal(query) => {
            super::temporal_input::bind_with_clock(query, snapshots, rig, clock)
        }
    }
}

pub(super) fn load_calibration(
    options: &Options,
    declaration: &AdoptedRig,
    deployment: &ReferenceDeployment,
    twin: &PropertyTwin,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RetainedSceneCalibration> {
    let bytes = read_input(
        &relative_to_rig(&options.rig, &declaration.calibration.path),
        MAX_CALIBRATION_BYTES,
        cx,
    )?;
    if ContentDigest::sha256(&bytes) != declaration.calibration.file_digest {
        return Err(input_error(
            "calibration whole-file SHA-256 differs from the adopted rig pin",
        ));
    }
    let mut total = bytes.len();
    let mut inputs = Vec::with_capacity(declaration.cameras.len());
    for camera in &declaration.cameras {
        // Every immutable input is individually bounded and the cumulative bound
        // is checked before retaining the next allocation or decoding the record.
        let bytes = read_input(
            &relative_to_rig(&options.rig, &camera.original_input.path),
            MAX_OBSERVATION_BYTES,
            cx,
        )?;
        total = total
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_SCENE_CALIBRATION_INPUT_BYTES)
            .ok_or_else(|| {
                fail(
                    "ERR-SCENE-CALIBRATION-LIMIT-001",
                    "complete calibration inputs exceed20MiB",
                )
            })?;
        if ContentDigest::sha256(&bytes) != camera.original_input.digest {
            return Err(input_error(
                "original calibration input differs from its exact file pin",
            ));
        }
        inputs.push(bytes);
    }
    let bindings = declaration
        .cameras
        .iter()
        .zip(&inputs)
        .map(|(camera, bytes)| SceneCalibrationBinding {
            camera_handle: camera.camera,
            sensor_id: camera.sensor_id.clone(),
            adoption_digest: camera.adoption_digest,
            camera_input: bytes.as_slice(),
        })
        .collect::<Vec<_>>();
    let resolve = if declaration.rectification {
        resolve_scene_calibration_for_rectification
    } else {
        resolve_scene_calibration
    };
    resolve(
        deployment,
        &SceneCalibrationRequest {
            calibration_bytes: &bytes,
            calibration_digest: declaration.calibration.digest,
            bindings: &bindings,
        },
        twin,
        work,
        cx,
    )
    .map_err(|e| fail(e.stable_id(), e.to_string()))
}

/// Select the exact typed projection for the explicitly declared image profile.
pub(super) fn project_rig(
    twin: &PropertyTwin,
    calibration: &RetainedSceneCalibration,
    declaration: &AdoptedRig,
    work: &mut WorkBudget<'_>,
) -> Result<SceneRig> {
    let declarations = declaration
        .cameras
        .iter()
        .map(|camera| AdoptedSceneCameraBinding {
            camera: camera.camera,
            source_object_id: camera.source_object_id.clone(),
            image_domain: camera.image_domain,
            clock: camera.clock,
            privacy_domain: camera.privacy_domain,
            validity: camera.validity,
        })
        .collect::<Vec<_>>();
    let project = if declaration.rectification {
        SceneRig::from_retained_rectified_calibration
    } else {
        SceneRig::from_retained_calibration
    };
    project(
        twin,
        calibration,
        declaration.geometry_basis,
        &declarations,
        work,
    )
    .map_err(rig_error)
}

fn analyze(options: &Options, root: &Path, cx: &ReplayCx) -> Result<Report> {
    checkpoint(cx, "retained_calibrated_match:begin")?;
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
    let declaration = input::parse_rig(&rig_bytes)?;
    let query = MatchingQuery::for_rig(&query_bytes, rig_digest, &declaration)?;
    same_selected_sensors(&query, &declaration)?;
    let twin_bytes = read_input(&options.twin, MAX_TWIN_BYTES, cx)?;
    let mut work = WorkBudget::with_cancellation_probe(options.work, &cancelled);
    let twin = import_twin(
        &twin_bytes,
        ImportExpectation {
            package_sha256: declaration.twin_digest.bytes(),
            source_scene_sha256: declaration.source_scene_digest.bytes(),
            basis: GeometryBasis::new(declaration.geometry_basis.0, declaration.geometry_basis.1)
                .map_err(|_| input_error("invalid property geometry basis"))?,
        },
        ImportLimits::default(),
        &mut work,
    )
    .map_err(|e| fail("ERR-SCENE-FUSION-TWIN-001", e.to_string()))?;
    if twin.evaluation_scope() != declaration.evaluation_scope {
        return Err(input_error(
            "calibrated rig evaluation scope differs from the exact twin",
        ));
    }
    let mut deployment = ReferenceDeployment::reopen(root, &options.site, cx)
        .map_err(|e| fail("ERR-SCENE-FUSION-INPUT-001", e.to_string()))?;
    let entry_anchor = deployment.current_anchor().clone();
    if options
        .expected_anchor
        .is_some_and(|pin| pin != anchor_digest(&entry_anchor))
    {
        return Err(input_error("deployment differs from --expected-anchor"));
    }
    // Original capsule/source pins authenticate every selected sensor before it
    // can become a calibration binding. No image decode has taken place yet.
    calibrated_clock::preflight_sources(&query, &deployment, cx)?;
    check_cancel(cx, &cancelled)?;
    let calibration = load_calibration(options, &declaration, &deployment, &twin, &mut work, cx)?;
    declared_modes(&query, &calibration)?;
    let rig = project_rig(&twin, &calibration, &declaration, &mut work)?;
    let images = prepare_images(query.views(), &rig, &mut work)?;
    let clock = calibrated_clock::replay(
        &query,
        &calibration,
        &rig,
        &images,
        &deployment,
        &mut work,
        cx,
    )?;
    let source_bytes = calibrated_clock::source_allowance(clock.is_some());
    let reads = RecordedFeatureReadBudget::with_cancellation_probe(
        source_bytes,
        Arc::new(move || started.elapsed() >= timeout),
    );
    let mut jpeg = DecodeBudget::with_cancellation_probe(JPEG_WORK, &cancelled);
    let mut video = RecordedVideoDecodeBudget::with_separate_limits(VIDEO_BYTES, VIDEO_LUMA)
        .map_err(|e| fail(e.stable_id(), e.to_string()))?;
    let mut owners = Vec::with_capacity(query.views().len());
    for (view, image) in query.views().iter().zip(&images) {
        check_cancel(cx, &cancelled)?;
        owners.push(extract_features(
            &mut deployment,
            FeatureInput {
                view,
                image,
                extraction: query.extraction(),
            },
            &reads,
            &mut jpeg,
            &mut video,
            &mut work,
            cx,
        )?);
    }
    let final_anchor = deployment.current_anchor().clone();
    let snapshots = owners.iter().map(resolved).collect::<Vec<_>>();
    let views = bind_with_clock(&query, &snapshots, &rig, clock.as_ref().map(|c| &c.ready))?;
    actual_modes(&views, &calibration, &images)?;
    drop(images);
    let geometry = report::geometry(&query, &twin, &views, options.report_bytes, &mut work)?;
    let clock_json = clock
        .as_ref()
        .map(|clock| clock.ready.render(query.views(), &snapshots, &mut work))
        .transpose()?;
    let calibration_json = report::calibration(&calibration, &mut work)?;
    let native_bytes = owners
        .iter()
        .map(|o| o.native_receipt().len() as u64)
        .sum::<u64>();
    if owners.iter().any(|o| o.native_receipt().len() > 16_384) {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete native source receipt exceeds its bound",
        ));
    }
    let features = views
        .iter()
        .map(|v| v.frame.features().len() as u64)
        .sum::<u64>();
    work.charge(
        131_072
            + native_bytes * 8
            + features * 1024
            + query.declarations().len() as u64 * 4
            + rig_bytes.len() as u64 * 4
            + calibration_json.len() as u64 * 4
            + geometry.json.len() as u64 * 4
            + super::image_report::VIEW_WORK * owners.len() as u64,
    )
    .map_err(work_error)?;
    let mut source_views = Vec::with_capacity(owners.len());
    for (index, view) in geometry.views.iter().enumerate() {
        let owner = owners
            .iter()
            .find(|owner| owner.frame().identity().exposure == view.frame.identity().exposure)
            .ok_or_else(|| {
                input_error("calibrated association has no exact original exposure owner")
            })?;
        source_views.push(object(&[
            ("index", index.to_string()),
            ("exposure", count(index as u64 + 1)),
            (
                "view",
                super::report::calibrated_view_json(view, owner, &rig),
            ),
        ]));
    }
    let (property, revision) = rig.geometry_basis();
    let mut analysis_fields = vec![
        ("kind", string(query.kind())),
        (
            "outcome",
            string(if geometry.solved == 0 {
                "no_reconstruction"
            } else if geometry.reconstructed {
                "reconstructed"
            } else {
                "reconstructed_with_refusals"
            }),
        ),
        ("authority", string("derived_cognition_no_effect_authority")),
        ("physical_identity_established", "false".into()),
        ("query_digest", string(&query_digest.to_text())),
        ("rig_digest", string(&rig_digest.to_text())),
        ("reference_time_ns", count(geometry.reference_time_ns)),
        ("capture_hull_ns", array(&geometry.capture_hull.map(count))),
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
        (
            "basis",
            object(&[
                ("twin_digest", digest(twin.digest())),
                ("source_scene_digest", digest(twin.source_scene_digest())),
                ("camera_rig_digest", string(&rig_digest.to_text())),
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
        ("calibration", calibration_json),
        ("declarations", query.declarations().to_owned()),
        (
            "rig_declarations",
            super::input::json(&super::document(&rig_bytes)?),
        ),
        (
            "assumptions",
            if clock.is_some() {
                report::clock_assumptions(declaration.rectification)
            } else if declaration.rectification {
                report::rectified_assumptions(query.kind())
            } else {
                report::assumptions(query.kind())
            },
        ),
        ("views", array(&source_views)),
        ("geometry", geometry.json),
        (
            "counts",
            object(&[
                ("solved", geometry.solved.to_string()),
                ("unresolved", geometry.unresolved.to_string()),
                (
                    "nominal_occlusion_conflicts",
                    geometry.occlusion_conflicts.to_string(),
                ),
            ]),
        ),
    ];
    if let Some(clock_json) = clock_json {
        analysis_fields.push(("clock_validation", clock_json));
    }
    let analysis = object(&analysis_fields);
    if analysis
        .len()
        .checked_add(1)
        .is_none_or(|n| n > options.report_bytes)
    {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete calibrated analysis exceeds output allowance",
        ));
    }
    // Source-dependent reporting is complete before either custody owner checks
    // current authority again. No source access follows this final pass.
    for owner in &owners {
        check_cancel(cx, &cancelled)?;
        owner
            .revalidate(&deployment, cx, &mut work)
            .map_err(|e| fail(e.stable_id(), e.to_string()))?;
    }
    calibration
        .revalidate(&deployment, cx, &mut work)
        .map_err(|e| fail(e.stable_id(), e.to_string()))?;
    if *deployment.current_anchor() != final_anchor {
        return Err(input_error(
            "authority anchor changed during calibrated scene reconstruction",
        ));
    }
    check_cancel(cx, &cancelled)?;
    let body = object(&[
        (
            "schema",
            string(if clock.is_some() {
                "fss.scene_feature_match_adopted_report.v3"
            } else if declaration.rectification {
                "fss.scene_feature_match_adopted_report.v2"
            } else {
                "fss.scene_feature_match_adopted_report.v1"
            }),
        ),
        ("analysis", analysis),
        ("cost", {
            let mut fields = vec![
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
                        ("allowance", count(source_bytes)),
                        ("used", count(reads.used())),
                        ("includes_final_revalidation", "true".into()),
                    ]),
                ),
                (
                    "calibration_input_bytes",
                    object(&[
                        ("allowance", count(MAX_SCENE_CALIBRATION_INPUT_BYTES as u64)),
                        ("used", count(calibration.input_bytes())),
                    ]),
                ),
                (
                    "calibration_authority_bytes",
                    object(&[
                        ("allowance", count(MAX_SCENE_CALIBRATION_AUTHORITY_BYTES)),
                        ("reserved", count(calibration.authority_reserved_bytes())),
                        ("verified", count(calibration.authority_read_bytes())),
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
            ];
            if let Some(clock) = &clock {
                fields.push((
                    "clock_query_bytes",
                    object(&[
                        (
                            "allowance",
                            count(fss_cli::clock_alignment::MAX_INPUT_BYTES as u64),
                        ),
                        ("used", count(clock.input_bytes as u64)),
                        ("reserved_from_source_bytes", "true".into()),
                    ]),
                ));
            }
            object(&fields)
        }),
    ]);
    let json = object(&[
        (
            "schema",
            string(if clock.is_some() {
                "fss.scene_feature_match_adopted.v3"
            } else if declaration.rectification {
                "fss.scene_feature_match_adopted.v2"
            } else {
                "fss.scene_feature_match_adopted.v1"
            }),
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
            "complete calibrated report exceeds output allowance",
        ));
    }
    check_cancel(cx, &cancelled)?;
    Ok(Report {
        json,
        reconstructed: geometry.reconstructed,
        started,
        _deployment: deployment,
    })
}

fn execute(options: &Options, out: &mut impl Write) -> Result<bool> {
    let authority = authority(options)?;
    let root = retained_handoffs::preflight(&options.root, &options.site, &authority)?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())
        .map_err(|e| fail("ERR-SCENE-FUSION-AUTHORITY-001", e.to_string()))?;
    let result = (|| {
        let report = analyze(options, &root, &cx)?;
        let cancelled = || cx.is_cancelled() || report.started.elapsed() >= options.timeout;
        check_cancel(&cx, &cancelled)?;
        if let Some(path) = &options.report_out {
            write_report(path, report.json.as_bytes(), &cx)?;
        } else {
            checkpoint(&cx, "retained_calibrated_match:stdout")?;
        }
        check_cancel(&cx, &cancelled)?;
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

#[cfg(test)]
#[path = "calibrated_tests.rs"]
pub(super) mod tests;
