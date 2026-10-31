#![forbid(unsafe_code)]
//! Local operator boundary for source-pinned native two-image reconstruction.

#[cfg(test)]
#[path = "matching/fixtures.rs"]
mod fixtures;
#[path = "matching/input.rs"]
mod input;
#[cfg(test)]
#[path = "matching/owner_tests.rs"]
mod owner_tests;
#[path = "matching/pipeline.rs"]
mod pipeline;
#[path = "matching/report.rs"]
mod report;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fss_cli::scene_rig::SceneRig;
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_geometry::WorkBudget;
use fss_reference::ReplayCx;
use fss_twin::{ImportExpectation, ImportLimits, import_twin};

use super::{
    MAX_JSON_BYTES, MAX_REPORT_BYTES, MAX_TWIN_BYTES, Result, checkpoint, document, fail,
    input as fusion_input, input_error, read_input, write_report,
};

const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_MASK_BYTES: usize = 4 * 1024 * 1024;
// Full-resolution extraction costs more work than supplied-point fusion.
// Two fully allowed 1080p grids need over 1.27 billion FAST work units alone.
const DEFAULT_MATCH_WORK: u64 = 2_000_000_000;
const MAX_MATCH_WORK: u64 = 5_000_000_000;
const HELP: &str = "fss-scene-fuse match --twin PROPERTY.fsstwin --rig CAMERAS.json --query QUERY.json\n\
    --left LEFT.jpg --right RIGHT.jpg [--left-mask LEFT.mask] [--right-mask RIGHT.mask]\n\
    [--report-out REPORT.json] [--work-units N] [--timeout-ms N] [--max-report-bytes N]\n\n\
Automatically extract native masked FAST/BRIEF features from two exact pinned JPEGs,\n\
match them with symmetric descriptor ambiguity checks and nominal epipolar gates, then\n\
reconstruct common static-feature hypotheses using the native property-twin geometry.\n\
No manual pixel correspondences are required. Every candidate pair, selected feature,\n\
native point estimate and geometric refusal is retained in the complete JSON report.\n\n\
The schema is fss.scene_feature_match_query.v1. It pins the rig, each original JPEG,\n\
image-domain mapping, privacy scope, clock and full capture intervals. Explicit masks\n\
are required: either all_allowed or a pinned row-major 0/1 byte file. Every descriptor's\n\
entire 33x33 footprint must be allowed. Maximum 128 features/view and 16384 pair rows.\n\
Both baseline and progressive Huffman JPEGs use the existing native luma decoder.\n\
Decoded dimensions must match the declared undistorted pinhole mode; lens correction,\n\
Exif orientation and colour transformations are never silently applied. This command\n\
does not establish physical identity, authenticate deployment custody or activate effects.\n\n\
Inputs are bounded regular files: twin 64 MiB, rig/query 1 MiB each, JPEG 16 MiB each, mask 4 MiB\n\
each. Complete report maximum 8 MiB including newline. Default shared work 2000000000 units\n\
(maximum 5000000000); default timeout 30000 ms (maximum 3600000). Decoding, extraction and\n\
geometry check the same owner cancellation/deadline. --report-out exclusively creates\n\
a private new file with the same bytes as stdout. Exit 0: one or more points and no selected\n\
geometry refusals; 3: no reconstruction or some selected refusals; 2: input/I/O/work failure.\n\
See docs/SCENE_FEATURE_MATCHING.md for assumptions, an example query and interpretation.\n";

#[derive(Debug)]
struct Options {
    twin: PathBuf,
    rig: PathBuf,
    query: PathBuf,
    images: [PathBuf; 2],
    masks: [Option<PathBuf>; 2],
    report_out: Option<PathBuf>,
    work: u64,
    timeout: Duration,
    report_bytes: usize,
}

fn options(args: &[OsString]) -> Result<Option<Options>> {
    if matches!(args, [flag] if matches!(flag.to_str(), Some("--help" | "-h"))) {
        return Ok(None);
    }
    if args.len() > 22
        || args.len() % 2 != 0
        || args.iter().any(|v| v.as_encoded_bytes().len() > 4096)
    {
        return Err(input_error("expected bounded match option/value pairs"));
    }
    let mut values = BTreeMap::new();
    for [key, value] in args.as_chunks::<2>().0 {
        let key = key
            .to_str()
            .ok_or_else(|| input_error("option must be UTF-8"))?;
        if ![
            "--twin",
            "--rig",
            "--query",
            "--left",
            "--right",
            "--left-mask",
            "--right-mask",
            "--report-out",
            "--work-units",
            "--timeout-ms",
            "--max-report-bytes",
        ]
        .contains(&key)
            || value.is_empty()
            || value.to_str().is_some_and(|s| s.starts_with("--"))
            || values.insert(key, value).is_some()
        {
            return Err(input_error(
                "unknown/duplicate matching option or missing value",
            ));
        }
    }
    let path = |key: &str| -> Result<PathBuf> {
        values
            .get(key)
            .map(PathBuf::from)
            .ok_or_else(|| input_error(format!("{key} is required")))
    };
    let integer = |key: &str, default: u64, min: u64, max: u64| -> Result<u64> {
        let Some(value) = values.get(key) else {
            return Ok(default);
        };
        let value = value
            .to_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| input_error("expected a decimal option"))?;
        value
            .parse::<u64>()
            .ok()
            .filter(|n| (min..=max).contains(n))
            .ok_or_else(|| input_error(format!("{key} is outside {min}..={max}")))
    };
    Ok(Some(Options {
        twin: path("--twin")?,
        rig: path("--rig")?,
        query: path("--query")?,
        images: [path("--left")?, path("--right")?],
        masks: [
            values.get("--left-mask").map(PathBuf::from),
            values.get("--right-mask").map(PathBuf::from),
        ],
        report_out: values.get("--report-out").map(PathBuf::from),
        work: integer("--work-units", DEFAULT_MATCH_WORK, 1, MAX_MATCH_WORK)?,
        timeout: Duration::from_millis(integer("--timeout-ms", 30_000, 1, 3_600_000)?),
        report_bytes: integer(
            "--max-report-bytes",
            MAX_REPORT_BYTES as u64,
            1024,
            MAX_REPORT_BYTES as u64,
        )? as usize,
    }))
}

fn authority() -> Result<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:scene-feature-match-cli".into(),
        operation_id: OperationId::parse("operation:scene-feature-match-cli")
            .map_err(|_| input_error("matching operation identity"))?,
        principal: "principal:local-operator".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(
                (MAX_TWIN_BYTES
                    + 2 * MAX_JSON_BYTES
                    + 2 * MAX_IMAGE_BYTES
                    + 2 * MAX_MASK_BYTES
                    + MAX_REPORT_BYTES) as u64,
            )
            .build()
            .map_err(|_| input_error("matching resource allowance"))?,
        privacy_scope: "privacy:local-authorized-image-matching".into(),
        retention_scope: "retention:operator-selected-report".into(),
        anchor_universe: ContentDigest::sha256(input::SCHEMA.as_bytes()),
        generation: 1,
    })
    .map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-AUTHORITY-001",
            "matching analysis authority refused",
        )
    })?;
    ReplayCx::from_context_authority(&authority, PathBuf::from(".")).map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-AUTHORITY-001",
            "matching file context refused",
        )
    })
}

fn check_cancel(cx: &ReplayCx, cancelled: &impl Fn() -> bool) -> Result<()> {
    if cancelled() {
        cx.request_cancellation();
        return Err(fail(
            "ERR-SCENE-FUSION-CANCELLED-001",
            "image matching cancelled or deadline reached",
        ));
    }
    checkpoint(cx, "scene_feature_match:checkpoint")
}

fn analyze(options: &Options, cx: &ReplayCx) -> Result<report::Report> {
    let started = Instant::now();
    let cancelled = || cx.is_cancelled() || started.elapsed() >= options.timeout;
    check_cancel(cx, &cancelled)?;
    if let Some(path) = &options.report_out {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(fail(
                    "ERR-SCENE-FUSION-OUTPUT-001",
                    "report output already exists",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(fail(
                    "ERR-SCENE-FUSION-OUTPUT-001",
                    "report output cannot be inspected",
                ));
            }
        }
    }
    let rig_bytes = read_input(&options.rig, MAX_JSON_BYTES, cx)?;
    let query_bytes = read_input(&options.query, MAX_JSON_BYTES, cx)?;
    let rig_document = document(&rig_bytes)?;
    let query = input::parse(&query_bytes, ContentDigest::sha256(&rig_bytes))?;
    for (view, mask) in query.views.iter().zip(&options.masks) {
        if !matches!(
            (view.mask, mask),
            (input::Mask::AllAllowed, None) | (input::Mask::File(_), Some(_))
        ) {
            return Err(input_error("mask file presence differs from query policy"));
        }
    }
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
    let left = read_input(&options.images[0], MAX_IMAGE_BYTES, cx)?;
    check_cancel(cx, &cancelled)?;
    let right = read_input(&options.images[1], MAX_IMAGE_BYTES, cx)?;
    let mut masks = [None, None];
    for (path, bytes) in options.masks.iter().zip(&mut masks) {
        check_cancel(cx, &cancelled)?;
        *bytes = path
            .as_ref()
            .map(|path| read_input(path, MAX_MASK_BYTES, cx))
            .transpose()?;
    }
    let analysis = pipeline::analyze(
        &twin,
        &rig,
        &query,
        [
            pipeline::Image {
                bytes: &left,
                mask: masks[0].as_deref(),
            },
            pipeline::Image {
                bytes: &right,
                mask: masks[1].as_deref(),
            },
        ],
        &cancelled,
        &mut work,
    )?;
    let report = report::compute(
        &twin,
        &rig,
        &query,
        ContentDigest::sha256(&query_bytes),
        &analysis,
        options.report_bytes,
        &mut work,
    )?;
    check_cancel(cx, &cancelled)?;
    Ok(report)
}

fn execute(options: &Options, out: &mut impl Write) -> Result<bool> {
    let cx = authority()?;
    let result = (|| {
        let report = analyze(options, &cx)?;
        if let Some(path) = &options.report_out {
            write_report(path, report.json.as_bytes(), &cx)?;
        }
        if options.report_out.is_none() {
            checkpoint(&cx, "scene_feature_match:stdout")?;
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
            write!(out, "{HELP}")
                .map_err(|_| fail("ERR-SCENE-FUSION-OUTPUT-001", "help output failed"))?;
            Ok(true)
        }
    }
}
