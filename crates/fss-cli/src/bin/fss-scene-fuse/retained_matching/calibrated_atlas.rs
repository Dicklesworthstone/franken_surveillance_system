#![forbid(unsafe_code)]
//! Current adopted camera geometry to a portable, source-linked localization atlas.

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use fss_cli::json_output::{array, object, string};
use fss_cli::retained_continuity_query::anchor_digest;
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_geometry::{GeometryBasis, WorkBudget};
use fss_reference::ingest::recorded_decode::DecodeBudget;
use fss_reference::ingest::recorded_decode::video_budget::{
    RecordedVideoDecodeBudget, VIDEO_DECODE_SEPARATE_AXIS_POLICY, VIDEO_DECODE_WORK_MODEL,
};
use fss_reference::ingest::scene_calibration::{
    MAX_SCENE_CALIBRATION_AUTHORITY_BYTES, MAX_SCENE_CALIBRATION_INPUT_BYTES,
};
use fss_reference::ingest::twin_localization::features::RecordedFeatureReadBudget;
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_twin::atlas_archive::{ArchiveError, MAX_ATLAS_BYTES, encode_atlas};
use fss_twin::reconstruction_atlas::{
    AtlasBuildRequest, ReconstructionAtlasError, ReferenceSource, build_reconstruction_atlas,
};
use fss_twin::{ImportExpectation, ImportLimits, import_twin};

use super::atlas::{Options, atlas_error, options, preflight_output, write_archive};
use super::atlas_input::{MAX_SELECTION_BYTES, parse_selection, validate_twin};
use super::calibrated::{self, JPEG_WORK, VIDEO_BYTES, VIDEO_LUMA, work_error};
use super::calibrated_atlas_report::{self as report, ArchiveSummary, ManifestInput};
use super::calibrated_input::{MatchingQuery, parse_rig};
use super::{
    FeatureInput, MAX_JSON_BYTES, MAX_TWIN_BYTES, Result, SOURCE_BYTES, calibrated_report,
    check_cancel, document, extract_features, fail, input_error, preflight_views, prepare_images,
    read_input, resolved, retained_handoffs, write_report,
};

const HELP: &str = "fss-scene-fuse retained-calibrated-atlas --root DEPLOYMENT --site SITE\n\
    --twin PROPERTY.fsstwin --rig ADOPTED-CAMERAS.json --query MATCH_QUERY.json\n\
    --selection LANDMARKS.json --atlas-out PROPERTY.fsatlas\n\
    [--report-out REPORT.json] [--expected-selection sha256:HEX]\n\
    [--principal PRINCIPAL] [--expected-input sha256:HEX] [--expected-anchor sha256:HEX]\n\
    [--work-units N] [--timeout-ms N] [--max-report-bytes N]\n\n\
Export native static scene landmarks reconstructed using exact currently adopted camera\n\
calibrations. The unchanged FSATLAS1 archive can be consumed by fss-file localize.\n\
Rig schema fss.scene_camera_rig_adopted.v1 requires original calibrated pinhole images.\n\
Rig v2 explicitly admits the exact adopted Brown radial model through native rectification,\n\
with original source domain and refined source/target K/grid. Existing static pair/multiview\n\
v1/v2 queries are supported. Selected sensors, original calibration inputs and decoded grids\n\
must match current adopted geometry; all maps compile before decoding. Temporal queries refuse.\n\n\
First inspect retained-calibrated-match to choose exact native hypothesis/component pins\n\
from geometry.native_diagnostics. The selection schema fss.reconstruction_atlas_selection.v1\n\
pins the whole association. Every chosen point declares a unique landmark/physical-group\n\
ID, existing twin feature ordinal and enduring_static_basis. No coordinate, descriptor or\n\
error override is accepted. Refused, incomplete or nominally occluded points refuse export.\n\n\
Complete source records, adopted calibration/covariance provenance, selection, native\n\
alternatives and atlas admission are preserved in an exact-byte manifest. Original source,\n\
current privacy and calibration adoption/withdrawal custody revalidate after construction;\n\
the deployment owner stays locked through archive/report/stdout release. JPEG decoding may\n\
publish its ordinary retained derivative before a later analysis refusal.\n\n\
The atlas remains a candidate with unknown absolute landmark error. No camera calibration,\n\
world revision, physical identity, persistent track or effect is activated. The report\n\
provides the exact package/provenance/descriptor pins accepted by fss-file localize.\n\n\
Bounds: 128 selected landmarks; selection64KiB; archive8MiB; complete report32MiB. Shared\n\
original reads4GiB, calibration inputs20MiB, cumulative authority reads64MiB, all including\n\
their final revalidation where applicable. Geometry work defaults8B, maximum16B; JPEG\n\
work2B; video512MiB and2147483648 coded-luma units. Timeout defaults30000ms, maximum3600000.\n\
Outputs are private/create-only; the archive is synchronized before report/stdout. I/O\n\
failure can leave new files for inspection. Exit0: complete candidate export;2: refusal.\n\
See docs/ADOPTED_RECONSTRUCTION_ATLAS.md.\n";

fn count(value: u64) -> String {
    string(&value.to_string())
}

fn authority(options: &Options) -> Result<ContextAuthority> {
    ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-calibrated-atlas-cli".into(),
        operation_id: OperationId::parse("operation:retained-calibrated-atlas-cli")
            .map_err(|_| input_error("calibrated atlas operation identity"))?,
        principal: options.matching.principal.clone(),
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
                        + MAX_SELECTION_BYTES
                        + MAX_ATLAS_BYTES
                        + options.matching.report_bytes) as u64,
            )
            .build()
            .map_err(|_| input_error("calibrated atlas resource allowance"))?,
        privacy_scope: "privacy:local-authorized-retained-calibrated-atlas".into(),
        retention_scope: "retention:operator-selected-localization-atlas".into(),
        anchor_universe: ContentDigest::sha256(options.matching.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-AUTHORITY-001",
            "calibrated atlas authority refused",
        )
    })
}

struct Export {
    archive: Vec<u8>,
    json: String,
    started: Instant,
    // Final current-adoption/privacy checks remain protected until all output completes.
    _deployment: ReferenceDeployment,
}

fn analyze(options: &Options, root: &Path, cx: &ReplayCx) -> Result<Export> {
    let opts = &options.matching;
    let started = Instant::now();
    let timeout = opts.timeout;
    let cancelled = || cx.is_cancelled() || started.elapsed() >= timeout;
    check_cancel(cx, &cancelled)?;
    preflight_output(&options.atlas_out, cx)?;
    if let Some(path) = &opts.report_out {
        if *path == options.atlas_out {
            return Err(input_error(
                "atlas and report require distinct output paths",
            ));
        }
        preflight_output(path, cx)?;
    }
    let selection_bytes = read_input(&options.selection, MAX_SELECTION_BYTES, cx)?;
    let selection_digest = ContentDigest::sha256(&selection_bytes);
    if options
        .expected_selection
        .is_some_and(|pin| pin != selection_digest)
    {
        return Err(input_error(
            "selection bytes differ from --expected-selection",
        ));
    }
    let selection = parse_selection(&selection_bytes)?;
    let query_bytes = read_input(&opts.query, MAX_JSON_BYTES, cx)?;
    let query_digest = ContentDigest::sha256(&query_bytes);
    if opts.expected_input.is_some_and(|pin| pin != query_digest) {
        return Err(input_error("query bytes differ from --expected-input"));
    }
    let rig_bytes = read_input(&opts.rig, MAX_JSON_BYTES, cx)?;
    let rig_digest = ContentDigest::sha256(&rig_bytes);
    let declaration = parse_rig(&rig_bytes)?;
    let query = MatchingQuery::for_rig(&query_bytes, rig_digest, &declaration)?;
    if matches!(query, MatchingQuery::Temporal(_)) {
        return Err(input_error(
            "moving-feature reconstructions cannot become static atlas landmarks",
        ));
    }
    calibrated::same_selected_sensors(&query, &declaration)?;
    let twin_bytes = read_input(&opts.twin, MAX_TWIN_BYTES, cx)?;
    let mut work = WorkBudget::with_cancellation_probe(opts.work, &cancelled);
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
    validate_twin(&selection, &twin)?;
    let mut deployment = ReferenceDeployment::reopen(root, &opts.site, cx)
        .map_err(|e| fail("ERR-SCENE-FUSION-INPUT-001", e.to_string()))?;
    let entry_anchor = deployment.current_anchor().clone();
    if opts
        .expected_anchor
        .is_some_and(|pin| pin != anchor_digest(&entry_anchor))
    {
        return Err(input_error("deployment differs from --expected-anchor"));
    }
    preflight_views(&deployment, query.views(), cx)?;
    check_cancel(cx, &cancelled)?;
    let calibration =
        calibrated::load_calibration(opts, &declaration, &deployment, &twin, &mut work, cx)?;
    calibrated::declared_modes(&query, &calibration)?;
    let rig = calibrated::project_rig(&twin, &calibration, &declaration, &mut work)?;
    let images = prepare_images(query.views(), &rig, &mut work)?;
    let reads = RecordedFeatureReadBudget::with_cancellation_probe(
        SOURCE_BYTES,
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
    let views = calibrated::bind(&query, &snapshots, &rig)?;
    calibrated::actual_modes(&views, &calibration, &images)?;
    drop(images);
    let geometry =
        calibrated_report::geometry(&query, &twin, &views, opts.report_bytes, &mut work)?;
    let calibration_json = calibrated_report::calibration(&calibration, &mut work)?;
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
            + features * 8192
            + super::image_report::VIEW_WORK * owners.len() as u64,
    )
    .map_err(work_error)?;
    let mut sources = Vec::with_capacity(owners.len());
    let mut records = Vec::with_capacity(owners.len());
    for view in &geometry.views {
        let owner = owners
            .iter()
            .find(|owner| owner.frame().identity().exposure == view.frame.identity().exposure)
            .ok_or_else(|| {
                input_error("calibrated atlas view has no exact original exposure owner")
            })?;
        let record = super::report::calibrated_view_json(view, owner, &rig);
        let source_record = ContentDigest::sha256(record.as_bytes());
        sources.push(ReferenceSource {
            camera: view.camera.camera,
            source_record: source_record.bytes(),
        });
        records.push(object(&[
            ("camera", count(view.camera.camera)),
            ("record_digest", string(&source_record.to_text())),
            ("record", record),
        ]));
    }
    let built = build_reconstruction_atlas(
        &twin,
        &AtlasBuildRequest {
            association_evidence: selection.association_evidence,
            selections: &selection.landmarks,
            references: &sources,
        },
        geometry.static_reconstruction()?,
        &mut work,
    )
    .map_err(atlas_error)?;
    let rig_declarations = super::input::json(&document(&rig_bytes)?);
    let manifest = report::manifest(
        &ManifestInput {
            rectification: declaration.rectification,
            twin: &twin,
            geometry_basis: rig.geometry_basis(),
            rig_digest,
            rig_semantic_digest: rig.digest(),
            rig_declarations: &rig_declarations,
            query_digest,
            query_declarations: query.declarations(),
            selection_digest,
            selection_declarations: &selection.declarations,
            entry_anchor: &entry_anchor,
            anchor: &final_anchor,
            calibration: &calibration_json,
            source_records: &records,
            geometry: &geometry.json,
            build: built.receipt(),
        },
        opts.report_bytes,
        &mut work,
    )?;
    let archive = encode_atlas(
        built.atlas(),
        manifest.digest.bytes(),
        built.references(),
        &mut work,
    )
    .map_err(|e| match e {
        ArchiveError::Localization(inner) => {
            atlas_error(ReconstructionAtlasError::Localization(inner))
        }
        ArchiveError::Limit => fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()),
        _ => input_error(e.to_string()),
    })?;
    let summary = ArchiveSummary {
        package_digest: ContentDigest::sha256(&archive),
        atlas_digest: built.atlas().digest(),
        descriptor_digest: built
            .atlas()
            .references()
            .first()
            .ok_or_else(|| input_error("native atlas has no reference source"))?
            .frame
            .descriptor_domain(),
        bytes: archive.len(),
        landmarks: built.atlas().landmarks().len(),
        references: built.atlas().references().len(),
        bindings: built.atlas().bindings().len(),
    };
    // Every source-dependent manifest field and the complete archive already exist.
    // Original source/privacy and calibration authority revalidate together at this boundary.
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
            "authority anchor changed during calibrated atlas construction",
        ));
    }
    check_cancel(cx, &cancelled)?;
    let json = report::finish(
        manifest,
        summary,
        |used| {
            object(&[
                (
                    "geometry_work",
                    object(&[("allowance", count(opts.work)), ("used", count(used))]),
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
            ])
        },
        opts.report_bytes,
        &mut work,
    )?;
    check_cancel(cx, &cancelled)?;
    Ok(Export {
        archive,
        json,
        started,
        _deployment: deployment,
    })
}

fn execute(options: &Options, out: &mut impl Write) -> Result<bool> {
    let authority = authority(options)?;
    let root =
        retained_handoffs::preflight(&options.matching.root, &options.matching.site, &authority)?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())
        .map_err(|e| fail("ERR-SCENE-FUSION-AUTHORITY-001", e.to_string()))?;
    let result = (|| {
        let export = analyze(options, &root, &cx)?;
        let cancelled =
            || cx.is_cancelled() || export.started.elapsed() >= options.matching.timeout;
        write_archive(&options.atlas_out, &export.archive, &cx, &cancelled)?;
        check_cancel(&cx, &cancelled)?;
        if let Some(path) = &options.matching.report_out {
            write_report(path, export.json.as_bytes(), &cx)?;
        }
        check_cancel(&cx, &cancelled)?;
        writeln!(out, "{}", export.json).map_err(|_| {
            fail(
                "ERR-SCENE-FUSION-OUTPUT-001",
                "stdout failed; completed atlas/report files remain available",
            )
        })?;
        Ok(true)
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
#[path = "calibrated_atlas_tests.rs"]
mod tests;
