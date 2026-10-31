#![forbid(unsafe_code)]
//! Bounded, owner-local reconstruction of source-linked multi-camera scene hypotheses.
//!
//! This command composes the imported twin, camera-rig reader and native geometry solvers.
//! Its report is derived advice: input handles are retained, not authenticated source custody,
//! and authored camera placements do not become accepted physical calibration.

#[path = "fss-scene-fuse/handoffs.rs"]
mod handoffs;
#[path = "fss-scene-fuse/input.rs"]
mod input;
#[path = "fss-scene-fuse/report.rs"]
mod report;
#[path = "fss-scene-fuse/retained_handoffs.rs"]
mod retained_handoffs;
#[cfg(test)]
#[path = "fss-scene-fuse/tests.rs"]
mod tests;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_cli::agent_json::{object, string};
use fss_cli::json_input::{Value, parse};
use fss_cli::scene_rig::SceneRig;
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_geometry::WorkBudget;
use fss_reference::ReplayCx;
use fss_twin::{ImportExpectation, ImportLimits, import_twin};

const MAX_TWIN_BYTES: usize = 64 * 1024 * 1024;
const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_WORK: u64 = 100_000_000;
const MAX_WORK: u64 = 1_000_000_000;

const HELP: &str = "fss-scene-fuse --twin PROPERTY.fsstwin --rig CAMERAS.json --observations QUERY.json\n\
    [--report-out REPORT.json] [--work-units N]\n\n\
Reconstruct common points and constant-velocity trajectories in one property frame and at\n\
one declared scene time, using the native multi-camera geometry algorithms. Input files\n\
must be bounded regular files. The camera rig pins the exact twin and source-scene hashes;\n\
the query pins the exact camera-rig file hash. No camera streams, model downloads, scene\n\
activation, event publication or alerts are performed. Source handles are retained as\n\
caller assertions; this command does not fetch or authenticate their bytes.\n\n\
The query schema is fss.scene_fusion_query.v1. Supply a shared clock, clock_evidence,\n\
privacy_domain and reference_time_ns, then up to 64 explicit correspondence hypotheses.\n\
Each hypothesis chooses motion.kind static, linear (externally supplied velocity), or\n\
infer_linear (jointly infer position and velocity from staggered exposures). Every source\n\
observation supplies camera, track, exposure, image_domain, capture_ns, pixel_min/pixel_max,\n\
visible_contact, sigma_pixels, evidence_digest and source_digest. See docs/SCENE_FUSION.md.\n\n\
Every hypothesis is reported, including refusals. Exit 0: all solved; 3: some/all refused;\n\
2: invalid input, I/O, authority or report failure. --report-out exclusively creates a new\n\
private file after the complete report is computed; existing files are never overwritten.\n\
The stdout JSON is identical to that file. Default work allowance: 100000000 units.\n\n\
For automatic ordered anonymous tracklet association, use fss-scene-fuse handoffs --help.\n\
For authenticated retained package tracks, use fss-scene-fuse retained-handoffs --help.\n";

#[derive(Debug)]
struct Failure {
    code: &'static str,
    detail: String,
}
type Result<T> = std::result::Result<T, Failure>;
fn fail(code: &'static str, detail: impl Into<String>) -> Failure {
    Failure {
        code,
        detail: detail.into(),
    }
}
fn input_error(detail: impl Into<String>) -> Failure {
    fail("ERR-SCENE-FUSION-INPUT-001", detail)
}
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| fail("ERR-SCENE-FUSION-CANCELLED-001", "analysis cancelled"))
}

#[derive(Clone, Debug)]
struct Options {
    twin: PathBuf,
    rig: PathBuf,
    observations: PathBuf,
    report_out: Option<PathBuf>,
    work: u64,
}
fn options(args: impl IntoIterator<Item = OsString>) -> Result<Option<Options>> {
    let args: Vec<_> = args.into_iter().collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "-h")) {
        return Ok(None);
    }
    let mut fields = BTreeMap::new();
    let mut it = args.into_iter();
    while let Some(key) = it.next() {
        let key = key
            .to_str()
            .ok_or_else(|| input_error("option must be UTF-8"))?
            .to_owned();
        if ![
            "--twin",
            "--rig",
            "--observations",
            "--report-out",
            "--work-units",
        ]
        .contains(&key.as_str())
        {
            return Err(input_error("unknown option; use --help"));
        }
        let value = it
            .next()
            .ok_or_else(|| input_error("option requires a value"))?;
        if fields.insert(key, value).is_some() {
            return Err(input_error("duplicate option"));
        }
    }
    let required = |key: &str| -> Result<PathBuf> {
        fields
            .get(key)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| input_error(format!("missing {key}")))
    };
    let work = fields
        .get("--work-units")
        .map(|v| {
            v.to_str()
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|v| (1..=MAX_WORK).contains(v))
                .ok_or_else(|| input_error("work-units must be 1..=1000000000"))
        })
        .transpose()?
        .unwrap_or(DEFAULT_WORK);
    Ok(Some(Options {
        twin: required("--twin")?,
        rig: required("--rig")?,
        observations: required("--observations")?,
        report_out: fields.get("--report-out").map(PathBuf::from),
        work,
    }))
}

// The local process explicitly names the three inputs. No path is read from their contents.
// The borrowed context owns each I/O/checkpoint; neither a digest nor a camera ID is a grant.
fn read_input(path: &Path, limit: usize, cx: &ReplayCx) -> Result<Vec<u8>> {
    checkpoint(cx, "scene_fusion:before_read")?;
    let meta = fs::symlink_metadata(path)
        .map_err(|_| fail("ERR-SCENE-FUSION-IO-001", "input cannot be inspected"))?;
    if !meta.file_type().is_file() || meta.len() > limit as u64 {
        return Err(fail(
            "ERR-SCENE-FUSION-IO-001",
            "input must be a bounded regular file, not a symlink",
        ));
    }
    let file =
        File::open(path).map_err(|_| fail("ERR-SCENE-FUSION-IO-001", "input cannot be opened"))?;
    let opened = file.metadata().map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-IO-001",
            "opened input cannot be inspected",
        )
    })?;
    if !opened.is_file() || opened.len() > limit as u64 {
        return Err(fail(
            "ERR-SCENE-FUSION-IO-001",
            "opened input exceeds its regular-file bound",
        ));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(
            usize::try_from(opened.len()).map_err(|_| input_error("input size overflow"))?,
        )
        .map_err(|_| fail("ERR-SCENE-FUSION-LIMIT-001", "input allocation refused"))?;
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            fail(
                "ERR-SCENE-FUSION-IO-001",
                "input could not be read completely",
            )
        })?;
    checkpoint(cx, "scene_fusion:after_read")?;
    if bytes.len() > limit {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "input exceeds byte limit",
        ));
    }
    Ok(bytes)
}
fn document(bytes: &[u8]) -> Result<Value> {
    parse(std::str::from_utf8(bytes).map_err(|_| input_error("JSON input must be UTF-8"))?)
        .map_err(|e| input_error(e.to_string()))
}

fn analyze(options: &Options, cx: &ReplayCx) -> Result<report::Report> {
    // Preflight output before expensive geometry or any output creation.
    if let Some(path) = &options.report_out {
        checkpoint(cx, "scene_fusion:output_preflight")?;
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
    let rig_bytes = read_input(&options.rig, MAX_JSON_BYTES, cx)?;
    let rig_document = document(&rig_bytes)?;
    let query_bytes = read_input(&options.observations, MAX_JSON_BYTES, cx)?;
    let query_document = document(&query_bytes)?;
    let (package_sha256, source_scene_sha256, basis) = input::twin_expectation(&rig_document)?;
    let twin_bytes = read_input(&options.twin, MAX_TWIN_BYTES, cx)?;
    let mut work = WorkBudget::new(options.work);
    checkpoint(cx, "scene_fusion:import")?;
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
    let rig_digest = ContentDigest::sha256(&rig_bytes);
    let query = input::query(&query_document, rig_digest, &rig)?;
    checkpoint(cx, "scene_fusion:solve")?;
    let report = report::compute(
        &twin,
        &rig,
        &query,
        rig_digest,
        ContentDigest::sha256(&query_bytes),
        &mut work,
        cx,
    )?;
    if report.json.len() > MAX_REPORT_BYTES {
        return Err(fail(
            "ERR-SCENE-FUSION-LIMIT-001",
            "complete report exceeds output allowance",
        ));
    }
    checkpoint(cx, "scene_fusion:complete")?;
    Ok(report)
}

fn write_report(path: &Path, bytes: &[u8], cx: &ReplayCx) -> Result<()> {
    checkpoint(cx, "scene_fusion:before_output")?;
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
            "new report file could not be created",
        )
    })?;
    // An incomplete write is an explicit failure. Never claim the report is a published root.
    file.write_all(bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_| {
            fail(
                "ERR-SCENE-FUSION-OUTPUT-001",
                "report write incomplete; inspect the new output before retrying",
            )
        })?;
    cx.checkpoint_post_commit("scene_fusion:output_written");
    Ok(())
}

fn authority() -> Result<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:scene-fusion-cli".into(),
        operation_id: OperationId::parse("operation:scene-fusion-cli")
            .map_err(|_| input_error("operation identity"))?,
        principal: "principal:local-operator".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes((MAX_TWIN_BYTES + 2 * MAX_JSON_BYTES + MAX_REPORT_BYTES) as u64)
            .build()
            .map_err(|_| input_error("resource allowance"))?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:operator-selected-report".into(),
        anchor_universe: ContentDigest::sha256(b"fss.scene_fusion_query.v1"),
        generation: 1,
    })
    .map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-AUTHORITY-001",
            "local analysis authority refused",
        )
    })?;
    ReplayCx::from_context_authority(&authority, PathBuf::from(".")).map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-AUTHORITY-001",
            "local file context refused",
        )
    })
}

fn execute(options: &Options, out: &mut impl Write) -> Result<bool> {
    let cx = authority()?;
    let result = (|| {
        let report = analyze(options, &cx)?;
        if let Some(path) = &options.report_out {
            write_report(path, report.json.as_bytes(), &cx)?;
        }
        // A completed output file is reported even if cancellation arrives after its write.
        if options.report_out.is_none() {
            checkpoint(&cx, "scene_fusion:stdout")?;
        }
        writeln!(out, "{}", report.json).map_err(|_| {
            fail(
                "ERR-SCENE-FUSION-OUTPUT-001",
                "stdout failed; any completed report file remains available",
            )
        })?;
        Ok(report.all_solved)
    })();
    cx.drain_and_finalize();
    result
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = if args.first().and_then(|arg| arg.to_str()) == Some("handoffs") {
        handoffs::run(&args[1..], &mut io::stdout().lock())
    } else if args.first().and_then(|arg| arg.to_str()) == Some("retained-handoffs") {
        retained_handoffs::run(&args[1..], &mut io::stdout().lock())
    } else {
        options(args).and_then(|value| match value {
            None => {
                print!("{HELP}");
                Ok(true)
            }
            Some(options) => execute(&options, &mut io::stdout().lock()),
        })
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(3),
        Err(e) => {
            eprintln!(
                "{}",
                object(&[
                    ("schema", string("fss.scene_fusion_error.v1")),
                    ("outcome", string("refused")),
                    ("code", string(e.code)),
                    ("detail", string(&e.detail))
                ])
            );
            ExitCode::from(2)
        }
    }
}
