#![forbid(unsafe_code)]
//! Read-only, digest-pinned moving-feature clock hypothesis scans.

#[path = "fss-clock-align/input.rs"]
mod input;
#[path = "fss-clock-align/report.rs"]
mod report;
#[path = "fss-clock-align/drift.rs"]
mod drift;
#[cfg(test)]
#[path = "fss-clock-align/tests.rs"]
mod tests;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use fss_cli::agent_json::{object, string};
use fss_cli::json_input::parse;
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_geometry::{WorkBudget, temporal_alignment::scan_clock_offsets};
use fss_reference::ReplayCx;

const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_WORK: u64 = 100_000_000;
const MAX_WORK: u64 = 1_000_000_000;
const HELP: &str = "fss-clock-align --input QUERY.json --input-digest sha256:HEX [--work-units N]\n\nRead one explicitly pinned local query and report EVERY supplied clock hypothesis over\nnative moving-feature fits. fss.clock_alignment_query.v1 searches constant offsets;\nfss.clock_drift_query.v1 searches explicit offset/rate pairs at a declared target anchor.\nNo camera contact, source hydration, clock activation, coverage or effects. Source,\nassociation and calibration pins remain caller assertions. See docs/MOVING_TARGET_CLOCK_ALIGNMENT.md.\nExit 0: complete scan with at least one all-times-supported hypothesis (possibly ambiguous).\nExit 3: complete scan without an all-times-supported hypothesis. Exit 2: refused/incomplete.\n";

#[derive(Debug)]
struct Failure { code: &'static str, detail: String }
type Result<T> = std::result::Result<T, Failure>;
fn failure(code: &'static str, detail: impl Into<String>) -> Failure {
    let code = match code {
        "input" => "ERR-CLOCK-ALIGNMENT-INPUT-001",
        "io" => "ERR-CLOCK-ALIGNMENT-IO-001",
        "limit" => "ERR-CLOCK-ALIGNMENT-LIMIT-001",
        "scan" => "ERR-CLOCK-ALIGNMENT-SCAN-001",
        "output" => "ERR-CLOCK-ALIGNMENT-OUTPUT-001",
        _ => "ERR-CLOCK-ALIGNMENT-AUTHORITY-001",
    };
    Failure { code, detail: detail.into() }
}
#[derive(Debug)]
struct Options { input: PathBuf, digest: ContentDigest, work: u64 }
fn options(args: impl IntoIterator<Item = OsString>) -> Result<Option<Options>> {
    let args: Vec<_> = args.into_iter().collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "-h")) { return Ok(None); }
    let mut fields = BTreeMap::new();
    let mut it = args.into_iter();
    while let Some(key) = it.next() {
        let key = key.to_str().ok_or_else(|| failure("input", "option is not UTF-8"))?.to_owned();
        if !["--input", "--input-digest", "--work-units"].contains(&key.as_str()) {
            return Err(failure("input", "unknown option; use --help"));
        }
        let value = it.next().ok_or_else(|| failure("input", "option needs a value"))?;
        if fields.insert(key, value).is_some() { return Err(failure("input", "duplicate option")); }
    }
    let path = fields.get("--input").filter(|s| !s.is_empty())
        .map(PathBuf::from).ok_or_else(|| failure("input", "missing input file"))?;
    let digest = fields.get("--input-digest").and_then(|s| s.to_str())
        .ok_or_else(|| failure("input", "missing independent input digest"))?;
    let work = fields.get("--work-units").map(|s| {
        s.to_str().and_then(|s| s.parse::<u64>().ok()).filter(|v| (1..=MAX_WORK).contains(v))
            .ok_or_else(|| failure("input", "work-units must be 1..=1000000000"))
    }).transpose()?.unwrap_or(DEFAULT_WORK);
    Ok(Some(Options { input: path, digest: input::digest(digest)?, work }))
}
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage).map_err(|_| failure("authority", "local analysis admission refused"))
}
fn read_input(path: &Path, cx: &ReplayCx) -> Result<Vec<u8>> {
    checkpoint(cx, "clock_alignment:before_read")?;
    let metadata = fs::symlink_metadata(path).map_err(|_| failure("io", "input cannot be inspected"))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_INPUT_BYTES as u64 {
        return Err(failure("io", "input must be a bounded regular file, not a symlink"));
    }
    let file = File::open(path).map_err(|_| failure("io", "input cannot be opened"))?;
    let opened = file.metadata().map_err(|_| failure("io", "opened input cannot be inspected"))?;
    if !opened.is_file() || opened.len() > MAX_INPUT_BYTES as u64 {
        return Err(failure("io", "opened input exceeds regular-file bound"));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(opened.len() as usize).map_err(|_| failure("limit", "input allocation refused"))?;
    file.take(MAX_INPUT_BYTES as u64 + 1).read_to_end(&mut bytes)
        .map_err(|_| failure("io", "input read failed"))?;
    checkpoint(cx, "clock_alignment:after_read")?;
    if bytes.len() > MAX_INPUT_BYTES { return Err(failure("limit", "input exceeds byte limit")); }
    Ok(bytes)
}
fn analyze(bytes: &[u8], expected: ContentDigest, work_limit: u64) -> Result<(String, bool)> {
    if bytes.len() > MAX_INPUT_BYTES || ContentDigest::sha256(bytes) != expected {
        return Err(failure("input", "input size or independent digest mismatch"));
    }
    let value = parse(std::str::from_utf8(bytes).map_err(|_| failure("input", "input is not UTF-8"))?)
        .map_err(|_| failure("input", "invalid or oversized JSON"))?;
    if value.object().and_then(|fields| fields.get("schema")).and_then(|value| value.text()) == Some(drift::SCHEMA) {
        return drift::analyze(&value, expected, work_limit, bytes.len());
    }
    let query = input::query(&value)?;
    let mut budget = WorkBudget::new(work_limit);
    let scan = scan_clock_offsets(query.pair, &query.training, &query.validation, &query.offsets,
        query.options, &mut budget).map_err(|e| failure("scan", e.to_string()))?;
    let supported = scan.trials.iter().any(|trial| trial.consistent_for_all_capture_times());
    let report = report::render(&query, &scan, expected, work_limit, bytes.len());
    if report.len() >= MAX_REPORT_BYTES { return Err(failure("limit", "complete report exceeds output bound")); }
    Ok((report, supported))
}
fn execute(options: &Options, out: &mut impl Write) -> Result<bool> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:clock-alignment".into(),
        operation_id: OperationId::parse("operation:clock-alignment")
            .map_err(|_| failure("authority", "operation identity refused"))?,
        principal: "principal:local-operator".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes((MAX_INPUT_BYTES + MAX_REPORT_BYTES) as u64)
            .build().map_err(|_| failure("authority", "local resource allowance refused"))?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:no-publication".into(),
        anchor_universe: ContentDigest::sha256(input::SCHEMA.as_bytes()), generation: 1,
    }).map_err(|_| failure("authority", "local authority refused"))?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, PathBuf::from("."))
        .map_err(|_| failure("authority", "local file context refused"))?;
    let result = (|| {
        let bytes = read_input(&options.input, &cx)?;
        checkpoint(&cx, "clock_alignment:before_scan")?;
        let (report, supported) = analyze(&bytes, options.digest, options.work)?;
        checkpoint(&cx, "clock_alignment:before_output")?;
        out.write_all(report.as_bytes()).and_then(|_| out.write_all(b"\n")).and_then(|_| out.flush())
            .map_err(|_| failure("output", "report output or flush failed"))?;
        Ok(supported)
    })();
    cx.drain_and_finalize();
    result
}
fn main() -> ExitCode {
    let result = options(std::env::args_os().skip(1)).and_then(|options| match options {
        None => io::stdout().lock().write_all(HELP.as_bytes()).map(|_| true)
            .map_err(|_| failure("output", "help output failed")),
        Some(options) => execute(&options, &mut io::stdout().lock()),
    });
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(3),
        Err(error) => {
            eprintln!("{}", object(&[("schema", string("fss.clock_alignment_error.v1")),
                ("outcome", string("refused")), ("code", string(error.code)), ("detail", string(&error.detail))]));
            ExitCode::from(2)
        }
    }
}
