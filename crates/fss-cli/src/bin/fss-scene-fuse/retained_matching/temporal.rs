#![forbid(unsafe_code)]
//! Reconstruct moving native features across repeated authenticated camera exposures.

use super::temporal_input as input;
use super::temporal_report as report;

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
use fss_geometry::{GeometryError, WorkBudget};
use fss_reference::ingest::recorded_decode::DecodeBudget;
use fss_reference::ingest::recorded_decode::video_budget::{
    RecordedVideoDecodeBudget, VIDEO_DECODE_SEPARATE_AXIS_POLICY, VIDEO_DECODE_WORK_MODEL,
};
use fss_reference::ingest::twin_localization::features::RecordedFeatureReadBudget;
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_twin::temporal_feature_association::{
    TemporalAssociationError, associate_temporal_features,
};
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

const HELP: &str = "fss-scene-fuse retained-motion-match --root DEPLOYMENT --site SITE\n\
    --twin PROPERTY.fsstwin --rig CAMERAS.json --query QUERY.json\n\
    [--principal PRINCIPAL] [--expected-input sha256:HEX] [--expected-anchor sha256:HEX]\n\
    [--report-out REPORT.json] [--work-units N] [--timeout-ms N] [--max-report-bytes N]\n\n\
Automatically match native features across 4-16 retained JPEG/AVC/HEVC exposures from 2-8\n\
fixed cameras, then estimate common-time 3D position and constant velocity. Repeated frames\n\
from one camera retain their exact source exposure and shared calibration. Every frame pair\n\
keeps complete descriptor decisions; ambiguous, conflicting, incomplete and refused motion\n\
hypotheses remain explicit. No static epipolar gate is applied to moving observations.\n\n\
Query schema: fss.scene_feature_motion_match_retained_query.v1. Use views:[...] with the\n\
existing retained v2 image declarations, including native lens correction. Motion must be\n\
constant_velocity_during_capture_hull. Declare the full capture-span/uncertainty limits and\n\
common scene time; a fitted component must bracket that time without extrapolation. Four\n\
observations, two cameras and complete direct pair support are required for each motion fit.\n\n\
All image plans are admitted before native decoding. Source capture times, dimensions and\n\
privacy masks come from sealed source owners and revalidate after complete analysis. JPEG\n\
may publish its ordinary retained derivative. Source mapping, clock alignment, constant\n\
velocity and pixel noise remain declarations; covariance excludes shared camera/map/clock\n\
error. No calibration, physical identity, persistent track merge or effect is activated.\n\n\
Bounds: 16 exposures, 8 cameras, 128 features/view, 256 actual features total, 30720 complete\n\
Cartesian rows, capture hull <=60 seconds. Shared source reads 4 GiB including revalidation;\n\
geometry/extraction/report work defaults to 8B units (maximum 16B). Decoder caps: 2B JPEG\n\
work, 512 MiB video bytes, 2147483648 coded-luma units. Complete report <=32 MiB. Timeout\n\
defaults to 30000 ms, maximum 3600000. File output is private/create-only and matches stdout.\n\
Exit 0: at least one motion fit and no nontrivial unresolved/refused/conflicted component;\n\
3: no reconstruction or unresolved components; 2: input/source/privacy/resource/I/O failure.\n\
See docs/RETAINED_TEMPORAL_MATCHING.md.\n";

fn options(args: &[OsString]) -> Result<Option<Options>> {
    options_profile(args, DEFAULT_WORK, MAX_WORK, MAX_REPORT_BYTES)
}

struct Report {
    json: String,
    reconstructed: bool,
    started: Instant,
}

fn digest(bytes: [u8; 32]) -> String {
    string(&ContentDigest::new(fss_core::DigestAlgorithm::Sha256, bytes).to_text())
}
fn count(value: u64) -> String {
    string(&value.to_string())
}

fn analyze(options: &Options, root: &Path, cx: &ReplayCx) -> Result<Report> {
    checkpoint(cx, "retained_scene_motion_match:begin")?;
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
    let association = associate_temporal_features(&twin, &views, query.matching, &mut work)
        .map_err(|error| {
            let code = match error {
                TemporalAssociationError::Geometry(GeometryError::Cancelled) => {
                    "ERR-SCENE-FUSION-CANCELLED-001"
                }
                TemporalAssociationError::Limit
                | TemporalAssociationError::Geometry(
                    GeometryError::BudgetExhausted | GeometryError::LimitExceeded,
                ) => "ERR-SCENE-FUSION-LIMIT-001",
                _ => "ERR-SCENE-FUSION-POINT-001",
            };
            fail(code, error.to_string())
        })?;
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
    work.charge(super::image_report::VIEW_WORK * owners.len() as u64)
        .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
    let mut source_views = Vec::with_capacity(owners.len());
    for (index, view) in association.views().iter().enumerate() {
        let owner = owners
            .iter()
            .find(|owner| owner.frame().identity().exposure == view.frame.identity().exposure)
            .ok_or_else(|| {
                input_error("temporal association has no exact source exposure owner")
            })?;
        source_views.push(object(&[
            ("index", index.to_string()),
            ("exposure", count(index as u64 + 1)),
            ("view", super::report::view_json(view, owner, &rig, 2)),
        ]));
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
        ("assumptions", report::assumptions()),
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
            "complete temporal feature analysis exceeds output allowance",
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
            "authority anchor changed during temporal feature matching",
        ));
    }
    check_cancel(cx, &cancelled)?;
    let body = object(&[
        (
            "schema",
            string("fss.scene_feature_motion_match_retained_report.v1"),
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
            string("fss.scene_feature_motion_match_retained.v1"),
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
            "complete temporal feature report exceeds output allowance",
        ));
    }
    check_cancel(cx, &cancelled)?;
    Ok(Report {
        json,
        reconstructed: geometry.reconstructed,
        started,
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
            checkpoint(&cx, "retained_scene_motion_match:stdout")?;
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
#[path = "temporal_tests.rs"]
pub(super) mod tests;
