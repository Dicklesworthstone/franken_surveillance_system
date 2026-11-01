#![forbid(unsafe_code)]
//! Automatic scene correspondences from authenticated, privacy-screened retained frames.

#[path = "retained_matching/input.rs"]
mod input;
#[path = "retained_matching/report.rs"]
mod report;
#[cfg(test)]
#[path = "retained_matching/tests.rs"]
mod tests;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fss_cli::retained_continuity_query::anchor_digest;
use fss_cli::scene_rig::SceneRig;
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_geometry::WorkBudget;
use fss_reference::ingest::recorded_decode::h264::{
    DecoderLimits as H264Limits, RecordedH264Request,
};
use fss_reference::ingest::recorded_decode::h265::{
    DecoderLimits as H265Limits, RecordedH265Request,
};
use fss_reference::ingest::recorded_decode::video_budget::RecordedVideoDecodeBudget;
use fss_reference::ingest::recorded_decode::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeRequest,
    retained_source_capsule,
};
use fss_reference::ingest::twin_localization::RecordedLocalizationSource;
use fss_reference::ingest::twin_localization::features::{
    RecordedFeatureReadBudget, RecordedFeatureRequest, RecordedFeatures, extract_recorded_features,
};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_twin::feature_association::associate_features;
use fss_twin::{ImportExpectation, ImportLimits, import_twin};

use super::{
    MAX_JSON_BYTES, MAX_REPORT_BYTES, MAX_TWIN_BYTES, Result, checkpoint, document, fail,
    input as fusion_input, input_error, read_input, retained_handoffs, write_report,
};

const DEFAULT_WORK: u64 = 2_000_000_000;
const MAX_WORK: u64 = 5_000_000_000;
const SOURCE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const JPEG_WORK: u64 = 500_000_000;
const VIDEO_BYTES: u64 = 256 * 1024 * 1024;
const VIDEO_LUMA: u64 = 536_870_912;

const HELP: &str = "fss-scene-fuse retained-match --root DEPLOYMENT --site SITE\n\
    --twin PROPERTY.fsstwin --rig CAMERAS.json --query QUERY.json\n\
    [--principal PRINCIPAL] [--expected-input sha256:HEX] [--expected-anchor sha256:HEX]\n\
    [--report-out REPORT.json] [--work-units N] [--timeout-ms N] [--max-report-bytes N]\n\n\
Discover native image correspondences and reconstruct stationary scene points from two\n\
authenticated retained camera frames. No exported images or manual feature pixels are needed.\n\
Source import/capsule/encoded-byte/sensor/stream pins are checked before native decoding.\n\
JPEG, bounded IDR-starting AVC and IRAP-starting HEVC use their existing retained owners.\n\
Current deployment privacy masks exclude complete FAST/BRIEF descriptor footprints.\n\n\
The strict schema is fss.scene_feature_match_retained_query.v1. Camera mapping, undistorted\n\
image-domain applicability, additive clock alignment and a static common scene remain explicit\n\
assumptions. Source capture intervals, pixel dimensions and privacy cannot be overridden.\n\
Every descriptor pair, ambiguity, reconstructed point and geometric refusal is reported.\n\
All selected original ranges and current privacy are revalidated before releasing a report.\n\n\
An existing deployment is required. JPEG decoding may publish its ordinary retained derivative\n\
receipt, including before a later matching refusal; entry and final authority anchors are shown.\n\
No camera calibration, world revision, physical identity, event or effect is activated.\n\n\
Bounds: 128 features/view; 64 coding segments per video range; 4096 per image axis and\n\
4194304 pixels; 4 GiB cumulative original reads including final validation. --work-units\n\
bounds geometry/extraction/report work (default2000000000, maximum5000000000). Separately\n\
reported cumulative decoder allowances are 500000000 JPEG work units, 256 MiB video encoded\n\
bytes and 536870912 coded-luma admission units. These are different accounting axes.\n\
Timeout defaults to30000ms (maximum3600000). Complete report maximum8MiB including newline.\n\
--report-out exclusively creates a private new file identical to stdout. Exit0: at least one\n\
point and no selected geometric refusals;3: no reconstruction or selected refusals;2: input,\n\
custody, privacy, authority, cancellation, resource or output failure.\n\
See docs/RETAINED_SCENE_MATCHING.md for exact source selections and provenance.\n";

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    twin: PathBuf,
    rig: PathBuf,
    query: PathBuf,
    report_out: Option<PathBuf>,
    expected_input: Option<ContentDigest>,
    expected_anchor: Option<ContentDigest>,
    work: u64,
    timeout: Duration,
    report_bytes: usize,
}

fn options(args: &[OsString]) -> Result<Option<Options>> {
    if matches!(args, [flag] if matches!(flag.to_str(), Some("--help" | "-h"))) {
        return Ok(None);
    }
    if args.len() > 24
        || args.len() % 2 != 0
        || args.iter().any(|a| a.as_encoded_bytes().len() > 4096)
    {
        return Err(input_error(
            "expected bounded retained-match option/value pairs",
        ));
    }
    let mut fields = BTreeMap::new();
    for [key, value] in args.as_chunks::<2>().0 {
        let key = key
            .to_str()
            .ok_or_else(|| input_error("option must be UTF-8"))?;
        if ![
            "--root",
            "--site",
            "--principal",
            "--twin",
            "--rig",
            "--query",
            "--report-out",
            "--expected-input",
            "--expected-anchor",
            "--work-units",
            "--timeout-ms",
            "--max-report-bytes",
        ]
        .contains(&key)
            || value.is_empty()
            || value.to_str().is_some_and(|v| v.starts_with("--"))
            || fields.insert(key, value).is_some()
        {
            return Err(input_error(
                "unknown/duplicate retained-match option or missing value",
            ));
        }
    }
    let path = |key: &str| {
        fields
            .get(key)
            .map(PathBuf::from)
            .ok_or_else(|| input_error(format!("{key} is required")))
    };
    let name = |key: &str, default: Option<&str>| -> Result<String> {
        let value = fields
            .get(key)
            .map(|v| {
                v.to_str()
                    .ok_or_else(|| input_error("identity must be UTF-8"))
            })
            .transpose()?
            .or(default)
            .ok_or_else(|| input_error(format!("{key} is required")))?;
        if value.is_empty()
            || value.len() > 256
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":_.-".contains(&b))
        {
            return Err(input_error("identity is outside its bounded ASCII grammar"));
        }
        Ok(value.to_owned())
    };
    let pin = |key: &str| -> Result<Option<ContentDigest>> {
        fields
            .get(key)
            .map(|v| {
                let text = v.to_str().ok_or_else(|| input_error("pin must be UTF-8"))?;
                if !text.starts_with("sha256:") {
                    return Err(input_error("pin requires sha256:HEX"));
                }
                ContentDigest::parse(text).map_err(|_| input_error("invalid content pin"))
            })
            .transpose()
    };
    let integer = |key: &str, default: u64, min: u64, max: u64| -> Result<u64> {
        let Some(value) = fields.get(key) else {
            return Ok(default);
        };
        value
            .to_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| (min..=max).contains(n))
            .ok_or_else(|| input_error(format!("{key} is outside {min}..={max}")))
    };
    Ok(Some(Options {
        root: path("--root")?,
        site: name("--site", None)?,
        principal: name("--principal", Some("principal:local-operator"))?,
        twin: path("--twin")?,
        rig: path("--rig")?,
        query: path("--query")?,
        report_out: fields.get("--report-out").map(PathBuf::from),
        expected_input: pin("--expected-input")?,
        expected_anchor: pin("--expected-anchor")?,
        work: integer("--work-units", DEFAULT_WORK, 1, MAX_WORK)?,
        timeout: Duration::from_millis(integer("--timeout-ms", 30_000, 1, 3_600_000)?),
        report_bytes: integer(
            "--max-report-bytes",
            MAX_REPORT_BYTES as u64,
            1024,
            MAX_REPORT_BYTES as u64,
        )? as usize,
    }))
}

fn authority(options: &Options) -> Result<ContextAuthority> {
    ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-scene-matching-cli".into(),
        operation_id: OperationId::parse("operation:retained-scene-matching-cli")
            .map_err(|_| input_error("matching operation identity"))?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(SOURCE_BYTES + (MAX_TWIN_BYTES + 2 * MAX_JSON_BYTES + MAX_REPORT_BYTES) as u64)
            .build()
            .map_err(|_| input_error("matching resource allowance"))?,
        privacy_scope: "privacy:local-authorized-retained-scene-matching".into(),
        retention_scope: "retention:operator-selected-report".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-AUTHORITY-001",
            "retained matching authority refused",
        )
    })
}

fn check_cancel(cx: &ReplayCx, cancelled: &impl Fn() -> bool) -> Result<()> {
    if cancelled() {
        cx.request_cancellation();
        return Err(fail(
            "ERR-SCENE-FUSION-CANCELLED-001",
            "retained matching cancelled or deadline reached",
        ));
    }
    checkpoint(cx, "retained_scene_match:checkpoint")
}

fn source(view: &input::View) -> RecordedLocalizationSource {
    let limits = RetainedReadLimits::default();
    match &view.source {
        input::Source::Jpeg {
            pins,
            interpretation,
        } => RecordedLocalizationSource::Jpeg(RecordedDecodeRequest {
            import_identity: pins.import_identity,
            segment_index: pins.segment,
            interpretation: *interpretation,
            read_limits: limits,
            decode_limits: DecodeLimits::default(),
        }),
        input::Source::H264 {
            pins,
            first_segment,
            segment_count,
        } => RecordedLocalizationSource::H264 {
            segment: pins.segment,
            request: RecordedH264Request {
                import_identity: pins.import_identity,
                first_segment: *first_segment,
                segment_count: *segment_count,
                interpretation: ComponentInterpretation::YCbCr,
                read_limits: limits,
                decoder_limits: H264Limits {
                    max_width: 4096,
                    max_height: 4096,
                    max_macroblocks: 16_384,
                    max_pictures: *segment_count as u64,
                    max_nal_bytes: 16 * 1024 * 1024,
                    ..H264Limits::default()
                },
            },
        },
        input::Source::H265 {
            pins,
            first_segment,
            segment_count,
        } => RecordedLocalizationSource::H265 {
            segment: pins.segment,
            request: RecordedH265Request {
                import_identity: pins.import_identity,
                first_segment: *first_segment,
                segment_count: *segment_count,
                interpretation: ComponentInterpretation::YCbCr,
                read_limits: limits,
                decoder_limits: H265Limits {
                    max_width: 4096,
                    max_height: 4096,
                    max_luma_samples: 4_194_304,
                    max_pictures: *segment_count as u64,
                    max_nal_bytes: 16 * 1024 * 1024,
                    ..H265Limits::default()
                },
            },
        },
    }
}

fn preflight_sources(
    deployment: &ReferenceDeployment,
    query: &input::Query,
    cx: &ReplayCx,
) -> Result<()> {
    for view in &query.views {
        checkpoint(cx, "retained_scene_match:source_preflight")?;
        let pins = view.source.pins();
        let retained = RetainedFileImport::open(
            deployment,
            pins.import_identity,
            RetainedReadLimits::default(),
            cx,
        )
        .map_err(|e| fail("ERR-SCENE-FUSION-INPUT-001", e.to_string()))?;
        let capsule = retained_source_capsule(deployment, &retained, pins.segment)
            .map_err(|e| fail(e.stable_id(), e.to_string()))?;
        input::validate_capsule(view, &capsule)?;
        let admitted = match &view.source {
            input::Source::Jpeg { .. } => retained.manifest().format == "mjpeg",
            input::Source::H264 { .. } => matches!(
                retained.manifest().format.as_str(),
                "annexb" | "mp4avc" | "mkvavc"
            ),
            input::Source::H265 { .. } => matches!(
                retained.manifest().format.as_str(),
                "hevc" | "mp4hevc" | "mkvhevc"
            ),
        };
        if !admitted {
            return Err(input_error(
                "selected native codec differs from retained source format",
            ));
        }
    }
    Ok(())
}

fn resolved(owner: &RecordedFeatures) -> input::ResolvedFrame<'_> {
    let source = owner.source();
    input::ResolvedFrame {
        capsule: owner.capsule(),
        import_identity: source.import_identity,
        segment: source.segment,
        dimensions: source.dimensions,
        exposure: source.exposure,
        luma: source.luma,
        frame: owner.frame(),
        allowed_mask_digest: owner.selection().mask_digest,
        codec: source.codec,
        range_start: source.range_start,
        range_count: source.range_count,
    }
}

fn analyze(options: &Options, root: &Path, cx: &ReplayCx) -> Result<report::Report> {
    checkpoint(cx, "retained_scene_match:begin")?;
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
    let bytes = read_input(&options.query, MAX_JSON_BYTES, cx)?;
    let query_digest = ContentDigest::sha256(&bytes);
    if options
        .expected_input
        .is_some_and(|pin| pin != query_digest)
    {
        return Err(input_error("query bytes differ from --expected-input"));
    }
    let rig_bytes = read_input(&options.rig, MAX_JSON_BYTES, cx)?;
    let rig_document = document(&rig_bytes)?;
    let rig_digest = ContentDigest::sha256(&rig_bytes);
    let query = input::parse(&bytes, rig_digest)?;
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
    preflight_sources(&deployment, &query, cx)?;
    check_cancel(cx, &cancelled)?;
    let reads = RecordedFeatureReadBudget::with_cancellation_probe(
        SOURCE_BYTES,
        Arc::new(move || started.elapsed() >= timeout),
    );
    let mut jpeg = DecodeBudget::with_cancellation_probe(JPEG_WORK, &cancelled);
    let mut video = RecordedVideoDecodeBudget::with_separate_limits(VIDEO_BYTES, VIDEO_LUMA)
        .map_err(|e| fail(e.stable_id(), e.to_string()))?;
    let mut extract = |view: &input::View| -> Result<RecordedFeatures> {
        check_cancel(cx, &cancelled)?;
        extract_recorded_features(
            &mut deployment,
            &RecordedFeatureRequest {
                source: source(view),
                image_domain: view.image_domain_digest,
                extraction: query.extraction,
            },
            &reads,
            &mut jpeg,
            &mut video,
            &mut work,
            cx,
        )
        .map_err(|e| fail(e.stable_id(), e.to_string()))
    };
    let owners = [extract(&query.views[0])?, extract(&query.views[1])?];
    let final_anchor = deployment.current_anchor().clone();
    let views = input::bind(&query, [resolved(&owners[0]), resolved(&owners[1])], &rig)?;
    let association = associate_features(&twin, [&views[0], &views[1]], query.matching, &mut work)
        .map_err(|e| fail("ERR-SCENE-FUSION-POINT-001", e.to_string()))?;
    let draft = report::compute(
        report::ReportInput {
            twin: &twin,
            rig: &rig,
            query: &query,
            query_digest,
            association: &association,
            owners: &owners,
            entry_anchor: &entry_anchor,
            final_anchor: &final_anchor,
        },
        options.report_bytes,
        &mut work,
    )?;
    // The complete source-dependent report body exists before the owner reopens every
    // selected source range and current mask. Only bounded immutable cost/envelope wrapping
    // follows validation; no source-derived observation is recomputed afterward.
    for owner in &owners {
        check_cancel(cx, &cancelled)?;
        owner
            .revalidate(&deployment, cx, &mut work)
            .map_err(|e| fail(e.stable_id(), e.to_string()))?;
    }
    if *deployment.current_anchor() != final_anchor {
        return Err(input_error(
            "authority anchor changed during retained matching",
        ));
    }
    check_cancel(cx, &cancelled)?;
    report::finish(
        draft,
        &work,
        reads.used(),
        jpeg.used(),
        &video,
        options.report_bytes,
    )
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
            checkpoint(&cx, "retained_scene_match:stdout")?;
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
