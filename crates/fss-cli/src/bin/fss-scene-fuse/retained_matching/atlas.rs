#![forbid(unsafe_code)]
//! Retained camera reconstruction to a portable, explicitly selected localization atlas.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use fss_cli::json_output::{array, object, string};
use fss_cli::retained_continuity_query::{anchor_digest, authority_anchor_json};
use fss_cli::scene_rig::SceneRig;
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_geometry::{GeometryError, WorkBudget};
use fss_reference::ingest::recorded_decode::DecodeBudget;
use fss_reference::ingest::recorded_decode::video_budget::{
    RecordedVideoDecodeBudget, VIDEO_DECODE_SEPARATE_AXIS_POLICY, VIDEO_DECODE_WORK_MODEL,
};
use fss_reference::ingest::twin_localization::features::RecordedFeatureReadBudget;
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_twin::atlas_archive::{ArchiveError, MAX_ATLAS_BYTES, encode_atlas};
use fss_twin::feature_association::{FeatureAssociation, FeatureView, associate_features};
use fss_twin::localization::LocalizationError;
use fss_twin::multiview_feature_association::{
    MultiFeatureAssociation, associate_multiview_features,
};
use fss_twin::reconstruction_atlas::{
    AtlasBuildRequest, Reconstruction, ReconstructionAtlasError, ReferenceSource,
    build_reconstruction_atlas,
};
use fss_twin::{ImportExpectation, ImportLimits, import_twin};

use super::atlas_input::{self as input, MAX_SELECTION_BYTES, MatchingQuery};
use super::atlas_report::{self as report, count, digest};
use super::{
    FeatureInput, MAX_JSON_BYTES, MAX_TWIN_BYTES, Options as MatchOptions, Result, SOURCE_BYTES,
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

const HELP: &str = "fss-scene-fuse retained-atlas --root DEPLOYMENT --site SITE\n\
    --twin PROPERTY.fsstwin --rig CAMERAS.json --query MATCH_QUERY.json\n\
    --selection LANDMARKS.json --atlas-out PROPERTY.fsatlas\n\
    [--report-out REPORT.json] [--expected-selection sha256:HEX]\n\
    [--principal PRINCIPAL] [--expected-input sha256:HEX] [--expected-anchor sha256:HEX]\n\
    [--work-units N] [--timeout-ms N] [--max-report-bytes N]\n\n\
Reconstruct the exact existing retained pair or 3-8 camera matching query (v1 or v2),\n\
then export explicitly selected native points and reference descriptors as FSATLAS1.\n\
First inspect retained-match or retained-multimatch to select exact hypothesis/component\n\
evidence. The selection schema is fss.reconstruction_atlas_selection.v1 and pins the whole\n\
association. Every selected point requires a distinct landmark/physical-group ID, existing\n\
twin feature ordinal and an enduring_static_basis declaration. Coordinates, descriptors\n\
and uncertainty bounds cannot be overridden. Unresolved, refused or nominally occluded\n\
points cannot become landmarks. All member-view bindings and alternatives are preserved.\n\n\
The atlas remains a candidate with unknown absolute landmark error. Export does not activate\n\
calibration, establish persistent physical identity or certify future landmark stability.\n\
Native JPEG/AVC/HEVC and v2 lens correction use the existing sealed source owners. Every\n\
original source and current privacy policy revalidates after complete archive/provenance\n\
serialization, before output creation. JPEG may publish its ordinary retained derivative.\n\n\
The report embeds exact provenance_manifest_utf8 bytes and the package/provenance/descriptor\n\
pins accepted by fss-file localize. --atlas-out is required and create-only; --report-out\n\
is private/create-only and identical to stdout. Incomplete I/O is an error and can leave\n\
new output files for inspection; existing files are never overwritten.\n\n\
Bounds: 128 selected landmarks; selection 64 KiB; archive 8 MiB; complete report 32 MiB.\n\
Shared original reads 4 GiB including final validation. Geometry work defaults to 8B units\n\
(maximum 16B). Separate decoder allowances: 2B JPEG work, 512 MiB video bytes, 2147483648\n\
coded-luma units. Timeout defaults to 30000 ms, maximum 3600000. Exit 0: complete candidate\n\
export; 2: input/source/privacy/budget/cancellation/publication failure.\n\
See docs/RECONSTRUCTED_LOCALIZATION_ATLAS.md.\n";

#[derive(Debug)]
pub(super) struct Options {
    pub(super) matching: MatchOptions,
    pub(super) selection: PathBuf,
    pub(super) atlas_out: PathBuf,
    pub(super) expected_selection: Option<ContentDigest>,
}

pub(super) fn options(args: &[OsString]) -> Result<Option<Options>> {
    if matches!(args, [flag] if matches!(flag.to_str(), Some("--help" | "-h"))) {
        return Ok(None);
    }
    if args.len() > 30
        || args.len() % 2 != 0
        || args.iter().any(|v| v.as_encoded_bytes().len() > 4096)
    {
        return Err(input_error(
            "expected bounded retained-atlas option/value pairs",
        ));
    }
    let mut remaining = Vec::new();
    let mut selection = None;
    let mut atlas_out = None;
    let mut expected_selection = None;
    for [key, value] in args.as_chunks::<2>().0 {
        if value.is_empty() || value.to_str().is_some_and(|v| v.starts_with("--")) {
            return Err(input_error("retained-atlas option has no value"));
        }
        match key.to_str() {
            Some("--selection") => {
                if selection.replace(PathBuf::from(value)).is_some() {
                    return Err(input_error("duplicate atlas selection"));
                }
            }
            Some("--atlas-out") => {
                if atlas_out.replace(PathBuf::from(value)).is_some() {
                    return Err(input_error("duplicate atlas output"));
                }
            }
            Some("--expected-selection") => {
                let pin = value
                    .to_str()
                    .and_then(|v| ContentDigest::parse(v).ok())
                    .filter(|v| super::input::is_pin(*v))
                    .ok_or_else(|| {
                        input_error("expected-selection requires a nonzero sha256:HEX")
                    })?;
                if expected_selection.replace(pin).is_some() {
                    return Err(input_error("duplicate selection pin"));
                }
            }
            _ => remaining.extend([key.clone(), value.clone()]),
        }
    }
    let matching = options_profile(&remaining, DEFAULT_WORK, MAX_WORK, MAX_REPORT_BYTES)?
        .ok_or_else(|| input_error("retained-atlas requires matching inputs"))?;
    Ok(Some(Options {
        matching,
        selection: selection.ok_or_else(|| input_error("--selection is required"))?,
        atlas_out: atlas_out.ok_or_else(|| input_error("--atlas-out is required"))?,
        expected_selection,
    }))
}

fn authority(options: &Options) -> Result<ContextAuthority> {
    ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-reconstruction-atlas-cli".into(),
        operation_id: OperationId::parse("operation:retained-reconstruction-atlas-cli")
            .map_err(|_| input_error("atlas operation identity"))?,
        principal: options.matching.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(
                SOURCE_BYTES
                    + (MAX_TWIN_BYTES
                        + 2 * MAX_JSON_BYTES
                        + MAX_SELECTION_BYTES
                        + MAX_ATLAS_BYTES
                        + options.matching.report_bytes) as u64,
            )
            .build()
            .map_err(|_| input_error("atlas resource allowance"))?,
        privacy_scope: "privacy:local-authorized-retained-atlas".into(),
        retention_scope: "retention:operator-selected-localization-atlas".into(),
        anchor_universe: ContentDigest::sha256(options.matching.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-AUTHORITY-001",
            "retained atlas authority refused",
        )
    })
}

pub(super) fn preflight_output(path: &Path, cx: &ReplayCx) -> Result<()> {
    checkpoint(cx, "retained_atlas:output_preflight")?;
    match fs::symlink_metadata(path) {
        Ok(_) => Err(fail(
            "ERR-SCENE-FUSION-OUTPUT-001",
            "atlas or report output already exists",
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(fail(
            "ERR-SCENE-FUSION-OUTPUT-001",
            "atlas or report output cannot be inspected",
        )),
    }
}

enum Association {
    Pair(Box<FeatureAssociation>),
    Multiview(Box<MultiFeatureAssociation>),
}
impl Association {
    fn reconstruction(&self) -> Reconstruction<'_> {
        match self {
            Self::Pair(v) => Reconstruction::Pair(v),
            Self::Multiview(v) => Reconstruction::Multiview(v),
        }
    }
    fn views(&self) -> &[FeatureView] {
        match self {
            Self::Pair(v) => v.views(),
            Self::Multiview(v) => v.views(),
        }
    }
}

pub(super) fn atlas_error(error: ReconstructionAtlasError) -> super::super::Failure {
    match error {
        ReconstructionAtlasError::Localization(LocalizationError::Geometry(
            GeometryError::Cancelled,
        )) => fail("ERR-SCENE-FUSION-CANCELLED-001", error.to_string()),
        ReconstructionAtlasError::Limit
        | ReconstructionAtlasError::Localization(LocalizationError::Limit)
        | ReconstructionAtlasError::Localization(LocalizationError::Geometry(
            GeometryError::BudgetExhausted | GeometryError::LimitExceeded,
        )) => fail("ERR-SCENE-FUSION-LIMIT-001", error.to_string()),
        _ => input_error(error.to_string()),
    }
}

struct Export {
    archive: Vec<u8>,
    json: String,
    started: Instant,
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
    let selection = input::parse_selection(&selection_bytes)?;
    let query_bytes = read_input(&opts.query, MAX_JSON_BYTES, cx)?;
    let query_digest = ContentDigest::sha256(&query_bytes);
    if opts.expected_input.is_some_and(|pin| pin != query_digest) {
        return Err(input_error("query bytes differ from --expected-input"));
    }
    let rig_bytes = read_input(&opts.rig, MAX_JSON_BYTES, cx)?;
    let rig_digest = ContentDigest::sha256(&rig_bytes);
    let rig_document = document(&rig_bytes)?;
    let query = input::parse_matching(&query_bytes, rig_digest)?;
    let (package_sha256, source_scene_sha256, basis) =
        fusion_input::twin_expectation(&rig_document)?;
    let twin_bytes = read_input(&opts.twin, MAX_TWIN_BYTES, cx)?;
    let mut work = WorkBudget::with_cancellation_probe(opts.work, &cancelled);
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
    input::validate_twin(&selection, &twin)?;
    let rig = SceneRig::from_document(&rig_document, &twin, &mut work)
        .map_err(|e| fail("ERR-SCENE-FUSION-RIG-001", e.to_string()))?;
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
    drop(images);
    let final_anchor = deployment.current_anchor().clone();
    let snapshots = owners.iter().map(resolved).collect::<Vec<_>>();
    let views = query.bind(&snapshots, &rig)?;
    let association = match &query {
        MatchingQuery::Pair(_) => {
            let [left, right] = views.as_slice() else {
                return Err(input_error("pair reconstruction has an invalid view count"));
            };
            Association::Pair(Box::new(
                associate_features(&twin, [left, right], query.matching(), &mut work)
                    .map_err(|e| fail("ERR-SCENE-FUSION-POINT-001", e.to_string()))?,
            ))
        }
        MatchingQuery::Multiview(_) => Association::Multiview(Box::new(
            associate_multiview_features(&twin, &views, query.matching(), &mut work)
                .map_err(|e| fail("ERR-SCENE-FUSION-POINT-001", e.to_string()))?,
        )),
    };
    let native_bytes = owners
        .iter()
        .map(|v| v.native_receipt().len() as u64)
        .sum::<u64>();
    let features = views
        .iter()
        .map(|v| v.frame.features().len() as u64)
        .sum::<u64>();
    work.charge(65_536 + native_bytes * 8 + features * 8192 + owners.len() as u64 * 131_072)
        .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
    let mut sources = Vec::with_capacity(owners.len());
    let mut records = Vec::with_capacity(owners.len());
    for view in association.views() {
        let index = query
            .views()
            .iter()
            .position(|v| v.camera == view.camera.camera)
            .ok_or_else(|| input_error("atlas source has no original owner"))?;
        // Always retain complete image processing, including v1 direct-pinhole sources.
        let record = super::report::view_json(view, &owners[index], &rig, 2);
        let source_record = ContentDigest::sha256(record.as_bytes()).bytes();
        sources.push(ReferenceSource {
            camera: view.camera.camera,
            source_record,
        });
        records.push(object(&[
            ("camera", count(view.camera.camera)),
            ("record_digest", digest(source_record)),
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
        association.reconstruction(),
        &mut work,
    )
    .map_err(atlas_error)?;
    let geometry = report::geometry(association.reconstruction(), opts.report_bytes, &mut work)?;
    let receipt = report::receipt(built.receipt(), &mut work)?;
    let manifest_parts = records.iter().map(|v| v.len() as u64).sum::<u64>()
        + geometry.len() as u64
        + receipt.len() as u64
        + query.declarations().len() as u64
        + selection.declarations.len() as u64;
    work.charge(manifest_parts * 4 + 65_536)
        .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
    let (property, revision) = rig.geometry_basis();
    let manifest = object(&[
        ("schema", string("fss.reconstruction_atlas_provenance.v1")),
        ("authority", string("derived_cognition_no_effect_authority")),
        ("twin_digest", digest(twin.digest())),
        ("source_scene_digest", digest(twin.source_scene_digest())),
        (
            "geometry_basis",
            object(&[("property", count(property)), ("revision", count(revision))]),
        ),
        ("coordinate_frame", string("RH_Z_UP")),
        ("evaluation_scope", string(twin.evaluation_scope())),
        ("observation_epoch", string(twin.observation_epoch())),
        ("scale", super::super::matching::report::scale(twin.scale())),
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
        ("camera_rig_digest", string(&rig_digest.to_text())),
        (
            "camera_rig_semantic_digest",
            string(&rig.digest().to_text()),
        ),
        ("query_digest", string(&query_digest.to_text())),
        ("query_declarations", query.declarations().to_owned()),
        ("selection_digest", string(&selection_digest.to_text())),
        ("selection", selection.declarations),
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
        ("source_records", array(&records)),
        ("geometry", geometry),
        ("atlas_build", receipt),
        ("assumptions", report::assumptions()),
    ]);
    if manifest
        .len()
        .checked_add(1)
        .is_none_or(|n| n > opts.report_bytes)
    {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete atlas provenance exceeds report allowance",
        ));
    }
    // Reserve exact-byte hash, string escaping and complete final-envelope copies before revalidation.
    work.charge(manifest.len() as u64 * 8 + 65_536)
        .map_err(|e| fail("ERR-SCENE-FUSION-LIMIT-001", e.to_string()))?;
    let provenance = ContentDigest::sha256(manifest.as_bytes());
    let archive = encode_atlas(
        built.atlas(),
        provenance.bytes(),
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
    let archive_digest = ContentDigest::sha256(&archive);
    let descriptor = built
        .atlas()
        .references()
        .first()
        .ok_or_else(|| input_error("native atlas has no reference source"))?
        .frame
        .descriptor_domain();
    check_cancel(cx, &cancelled)?;
    for owner in &owners {
        check_cancel(cx, &cancelled)?;
        owner
            .revalidate(&deployment, cx, &mut work)
            .map_err(|e| fail(e.stable_id(), e.to_string()))?;
    }
    if *deployment.current_anchor() != final_anchor {
        return Err(input_error(
            "authority anchor changed during atlas construction",
        ));
    }
    check_cancel(cx, &cancelled)?;
    let body = object(&[
        (
            "schema",
            string("fss.reconstruction_atlas_retained_report.v1"),
        ),
        ("outcome", string("candidate_export")),
        (
            "archive",
            object(&[
                ("format", string("FSATLAS1")),
                ("package_digest", string(&archive_digest.to_text())),
                ("provenance_digest", string(&provenance.to_text())),
                ("atlas_digest", digest(built.atlas().digest())),
                ("descriptor_digest", digest(descriptor)),
                ("bytes", archive.len().to_string()),
                ("landmarks", built.atlas().landmarks().len().to_string()),
                ("references", built.atlas().references().len().to_string()),
                ("bindings", built.atlas().bindings().len().to_string()),
            ]),
        ),
        ("provenance_manifest_utf8", string(&manifest)),
        (
            "cost",
            object(&[
                (
                    "geometry_work",
                    object(&[
                        ("allowance", count(opts.work)),
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
        ("schema", string("fss.reconstruction_atlas_retained.v1")),
        (
            "report_digest",
            string(&ContentDigest::sha256(body.as_bytes()).to_text()),
        ),
        ("report", body),
    ]);
    if json
        .len()
        .checked_add(1)
        .is_none_or(|n| n > opts.report_bytes)
    {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete atlas report exceeds output allowance",
        ));
    }
    check_cancel(cx, &cancelled)?;
    Ok(Export {
        archive,
        json,
        started,
    })
}

pub(super) fn write_archive(
    path: &Path,
    bytes: &[u8],
    cx: &ReplayCx,
    cancelled: &impl Fn() -> bool,
) -> Result<()> {
    check_cancel(cx, cancelled)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-OUTPUT-001",
            "new atlas file could not be created",
        )
    })?;
    for chunk in bytes.chunks(64 * 1024) {
        check_cancel(cx, cancelled)?;
        file.write_all(chunk).map_err(|_| {
            fail(
                "ERR-SCENE-FUSION-OUTPUT-001",
                "atlas write incomplete; inspect the new file before retrying",
            )
        })?;
    }
    file.sync_all().map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-OUTPUT-001",
            "atlas synchronization incomplete; inspect the new file before retrying",
        )
    })?;
    cx.checkpoint_post_commit("retained_atlas:archive_written");
    Ok(())
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
        // The report is the final root and follows the complete checksummed archive.
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
#[path = "atlas_tests.rs"]
mod tests;
