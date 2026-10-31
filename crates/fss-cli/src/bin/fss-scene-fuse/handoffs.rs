#![forbid(unsafe_code)]
//! Owner-local file boundary for the pure anonymous continuity query.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fss_cli::continuity_query::{
    self, MAX_OUTPUT_ENTRIES, MAX_REPORT_BYTES, MAX_WORK, QUERY_SCHEMA,
};
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_graph_algorithms::certified::Budget;
use fss_reference::ReplayCx;

use super::{Result, checkpoint, fail, input_error, read_input, write_report};

const HELP: &str = "fss-scene-fuse handoffs --observations QUERY.json\n\
    [--report-out REPORT.json] [--expected-input sha256:HEX]\n\
    [--work-units N] [--timeout-ms N] [--max-report-bytes N]\n\n\
Compute anonymous tracklet handoff paths across up to 32 cameras/tracklets using\n\
globally optimal assignment and explicit birth/end costs. QUERY.json uses\n\
fss.scene_handoffs_query.v1 and declares one property/session/privacy/clock scope,\n\
source and generation handles, capture intervals, and allowed transit/cost bases.\n\
Every directed pair is reported, including exclusions and unavailable source support.\n\n\
Each admitted transition must fit its transit window for ALL endpoint times.\n\
Overlapping exposures and merely possible transitions remain outside this profile.\n\
The displayed 1..32 ranked alternatives accompany the COMPLETE implicit family\n\
and explicit all-singleton explanation. A displayed prefix never erases alternatives.\n\
Costs are operator declarations, not probabilities; paths are hypotheses, not identity.\n\
Source handles are retained as assertions; their bytes are not fetched or authenticated.\n\n\
Input: bounded regular file, at most 1 MiB. Default work: 2000000, maximum 50000000;\n\
default timeout: 30000 ms, maximum 3600000. Complete report: at most 2 MiB.\n\
Exhaustion/cancellation refuses the entire answer. --expected-input pins exact JSON bytes.\n\
--report-out exclusively creates a private file after the complete result is ready.\n\
Exit 0 means the bounded query completed, including unresolved or all-singleton cases.\n\
No source acquisition, person identification, event publication or activation occurs.\n\
See docs/SCENE_HANDOFFS.md for the query, assumptions and complete-alternative semantics.\n";

#[derive(Debug)]
struct Options {
    observations: PathBuf,
    report_out: Option<PathBuf>,
    expected: Option<ContentDigest>,
    work: u64,
    timeout: Duration,
    report_bytes: usize,
}

fn options(args: &[OsString]) -> Result<Option<Options>> {
    if matches!(args, [flag] if matches!(flag.to_str(), Some("--help" | "-h"))) {
        return Ok(None);
    }
    if args.len() > 12
        || args.len() % 2 != 0
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(input_error(
            "expected bounded handoffs option/value pairs; use handoffs --help",
        ));
    }
    let mut values = BTreeMap::new();
    for [key, value] in args.as_chunks::<2>().0 {
        let key = key
            .to_str()
            .ok_or_else(|| input_error("option must be UTF-8"))?;
        if ![
            "--observations",
            "--report-out",
            "--expected-input",
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
                "unknown/duplicate handoff option or missing value",
            ));
        }
    }
    let integer = |key: &str, default: u64, minimum: u64, maximum: u64| -> Result<u64> {
        let Some(value) = values.get(key) else {
            return Ok(default);
        };
        let value = value
            .to_str()
            .ok_or_else(|| input_error("numeric option must be UTF-8"))?;
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(input_error("expected a nonnegative decimal option value"));
        }
        value
            .parse::<u64>()
            .ok()
            .filter(|n| (minimum..=maximum).contains(n))
            .ok_or_else(|| input_error(format!("{key} is outside {minimum}..={maximum}")))
    };
    let expected = values
        .get("--expected-input")
        .map(|v| {
            let text = v
                .to_str()
                .ok_or_else(|| input_error("input pin must be UTF-8"))?;
            if !text.starts_with("sha256:") {
                return Err(input_error("input pin must be sha256:HEX"));
            }
            ContentDigest::parse(text).map_err(|_| input_error("invalid input document pin"))
        })
        .transpose()?;
    Ok(Some(Options {
        observations: PathBuf::from(
            values
                .get("--observations")
                .ok_or_else(|| input_error("--observations is required"))?,
        ),
        report_out: values.get("--report-out").map(PathBuf::from),
        expected,
        work: integer("--work-units", 2_000_000, 1, MAX_WORK)?,
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
        trace_id: "trace:scene-handoffs-cli".into(),
        operation_id: OperationId::parse("operation:scene-handoffs-cli")
            .map_err(|_| input_error("operation identity"))?,
        principal: "principal:local-operator".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes((1024 * 1024 + MAX_REPORT_BYTES) as u64)
            .build()
            .map_err(|_| input_error("resource allowance"))?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:operator-selected-report".into(),
        anchor_universe: ContentDigest::sha256(QUERY_SCHEMA.as_bytes()),
        generation: 1,
    })
    .map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-AUTHORITY-001",
            "local handoff authority refused",
        )
    })?;
    ReplayCx::from_context_authority(&authority, PathBuf::from(".")).map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-AUTHORITY-001",
            "local handoff context refused",
        )
    })
}

fn analyze(options: &Options, cx: &ReplayCx) -> Result<String> {
    checkpoint(cx, "scene_handoffs:begin")?;
    let started = Instant::now();
    let cancelled = || cx.is_cancelled() || started.elapsed() >= options.timeout;
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
    if cancelled() {
        return Err(fail(
            "ERR-SCENE-FUSION-CANCELLED-001",
            "handoff deadline reached before input read",
        ));
    }
    let bytes = read_input(&options.observations, 1024 * 1024, cx)?;
    if options
        .expected
        .is_some_and(|pin| pin != ContentDigest::sha256(&bytes))
    {
        return Err(input_error("query bytes differ from --expected-input"));
    }
    let report = continuity_query::analyze(
        &bytes,
        Budget::new(options.work, MAX_OUTPUT_ENTRIES),
        options.report_bytes,
        &cancelled,
    )
    .map_err(|error| fail(error.code(), error.to_string()))?;
    if cancelled() {
        return Err(fail(
            "ERR-SCENE-FUSION-CANCELLED-001",
            "handoff deadline reached before output",
        ));
    }
    checkpoint(cx, "scene_handoffs:complete")?;
    Ok(report)
}

fn execute(options: &Options, out: &mut impl Write) -> Result<bool> {
    let cx = authority()?;
    let result = (|| {
        let report = analyze(options, &cx)?;
        if let Some(path) = &options.report_out {
            write_report(path, report.as_bytes(), &cx)?;
        } else {
            checkpoint(&cx, "scene_handoffs:stdout")?;
        }
        writeln!(out, "{report}").map_err(|_| {
            fail(
                "ERR-SCENE-FUSION-OUTPUT-001",
                "stdout failed; any completed report file remains available",
            )
        })?;
        Ok(true)
    })();
    cx.drain_and_finalize();
    result
}

pub(super) fn run(args: &[OsString], out: &mut impl Write) -> Result<bool> {
    match options(args)? {
        None => {
            out.write_all(HELP.as_bytes())
                .map_err(|_| fail("ERR-SCENE-FUSION-OUTPUT-001", "help output failed"))?;
            Ok(true)
        }
        Some(options) => execute(&options, out),
    }
}

#[cfg(test)]
#[path = "handoffs_tests.rs"]
mod tests;
