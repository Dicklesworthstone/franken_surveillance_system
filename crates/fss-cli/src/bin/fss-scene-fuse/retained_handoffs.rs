#![forbid(unsafe_code)]
//! Existing-deployment owner for authenticated package-track handoff projections.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fss_cli::continuity_query::{MAX_OUTPUT_ENTRIES, MAX_WORK};
use fss_cli::retained_continuity_query::{self as query, RetainedReportInput};
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_graph_algorithms::certified::Budget;
use fss_reference::ingest::package_handoffs::PackageHandoffProjection;
use fss_reference::{DeploymentLayout, ReferenceDeployment, ReplayCx};

use super::{Result, checkpoint, fail, input_error, read_input, write_report};

const HELP: &str = "fss-scene-fuse retained-handoffs --root DEPLOYMENT --site SITE --selection QUERY.json\n\
    [--principal PRINCIPAL] [--report-out REPORT.json]\n\
    [--expected-input sha256:HEX] [--expected-anchor sha256:HEX]\n\
    [--work-units N] [--timeout-ms N] [--max-report-bytes N]\n\n\
Build anonymous handoff hypotheses from existing, authenticated package detections.\n\
QUERY.json selects exact retained detector reports, tracking recipes and native track IDs;\n\
capture intervals, matched detections, sensors and model comparison keys come from custody.\n\
No detector is executed and no source/model file is reacquired. Missing, corrupt, deleted\n\
or privacy-stale custody refuses the query. No event publication or activation occurs.\n\n\
Selection schema: fss.scene_handoffs_retained_query.v1. Maximum 32 tracks from four\n\
distinct tracking recipes, each with at most 64 source frames. Clock alignment offsets,\n\
common-clock identity, calibration handles, transit bounds and costs remain explicit\n\
operator assumptions. Original clock basis and tentative observations remain visible.\n\
The full report contains source bindings, every selected observation, exact authority\n\
anchor, both solver certificates, ranked paths and the complete admitted alternative family.\n\
This does not establish physical identity, detector accuracy or authenticated calibration.\n\n\
Input is a bounded regular file of at most 1 MiB. Default work: 2000000; maximum: 50000000.\n\
Default timeout: 30000 ms; maximum: 3600000. Complete report: at most 4 MiB.\n\
All recipes and revalidation share one 4 GiB original-source read allowance. Deadline\n\
checks surround bounded source-owner calls. --expected-anchor pins SHA-256 of canonical\n\
full anchor bytes.\n\
Existing report destinations refuse. --report-out creates a private new file whose bytes\n\
including final newline equal stdout. Exit 0 means the selected query completed.\n\
See docs/RETAINED_HANDOFFS.md for provenance, assumptions and recovery boundaries.\n";

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    selection: PathBuf,
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
    if args.len() > 20
        || args.len() % 2 != 0
        || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096)
    {
        return Err(input_error(
            "expected bounded retained-handoffs option/value pairs",
        ));
    }
    let mut values = BTreeMap::new();
    for [key, value] in args.as_chunks::<2>().0 {
        let key = key
            .to_str()
            .ok_or_else(|| input_error("option must be UTF-8"))?;
        if ![
            "--root",
            "--site",
            "--principal",
            "--selection",
            "--report-out",
            "--expected-input",
            "--expected-anchor",
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
                "unknown/duplicate retained-handoff option or missing value",
            ));
        }
    }
    let path = |key: &str| -> Result<PathBuf> {
        values
            .get(key)
            .map(PathBuf::from)
            .ok_or_else(|| input_error(format!("{key} is required")))
    };
    let name = |key: &str, default: Option<&str>| -> Result<String> {
        let value = values
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
        values
            .get(key)
            .map(|v| {
                let value = v.to_str().ok_or_else(|| input_error("pin must be UTF-8"))?;
                if !value.starts_with("sha256:") {
                    return Err(input_error("pin must use sha256:HEX"));
                }
                ContentDigest::parse(value).map_err(|_| input_error("invalid content pin"))
            })
            .transpose()
    };
    let integer = |key: &str, default: u64, minimum: u64, maximum: u64| -> Result<u64> {
        let Some(value) = values.get(key) else {
            return Ok(default);
        };
        let value = value
            .to_str()
            .ok_or_else(|| input_error("numeric option must be UTF-8"))?;
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(input_error("expected decimal option value"));
        }
        value
            .parse::<u64>()
            .ok()
            .filter(|v| (minimum..=maximum).contains(v))
            .ok_or_else(|| input_error(format!("{key} is outside {minimum}..={maximum}")))
    };
    Ok(Some(Options {
        root: path("--root")?,
        site: name("--site", None)?,
        principal: name("--principal", Some("principal:local-operator"))?,
        selection: path("--selection")?,
        report_out: values.get("--report-out").map(PathBuf::from),
        expected_input: pin("--expected-input")?,
        expected_anchor: pin("--expected-anchor")?,
        work: integer("--work-units", 2_000_000, 1, MAX_WORK)?,
        timeout: Duration::from_millis(integer("--timeout-ms", 30_000, 1, 3_600_000)?),
        report_bytes: integer(
            "--max-report-bytes",
            query::MAX_REPORT_BYTES as u64,
            1024,
            query::MAX_REPORT_BYTES as u64,
        )? as usize,
    }))
}

fn authority(options: &Options) -> Result<ContextAuthority> {
    ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-handoffs-cli".into(),
        operation_id: OperationId::parse("operation:retained-handoffs-cli")
            .map_err(|_| input_error("operation identity"))?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        // One cumulative 4 GiB original-source allowance covers every recipe and
        // revalidation; the remaining allowance covers bounded context documents.
        budgets: BudgetVector::builder()
            .bytes(4 * 1024 * 1024 * 1024 + 8 * 1024 * 1024)
            .build()
            .map_err(|_| input_error("resource allowance"))?,
        privacy_scope: "privacy:local-authorized-retained-analysis".into(),
        retention_scope: "retention:operator-selected-report".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| {
        fail(
            "ERR-SCENE-FUSION-AUTHORITY-001",
            "retained analysis authority refused",
        )
    })
}

fn preflight(root: &Path, site: &str, authority: &ContextAuthority) -> Result<PathBuf> {
    authority
        .validate()
        .map_err(|_| fail("ERR-SCENE-FUSION-AUTHORITY-001", "invalid read authority"))?;
    if !authority.has_capability("ADP-REPLAY-001")
        || authority.anchor_universe != ContentDigest::sha256(site.as_bytes())
    {
        return Err(fail(
            "ERR-SCENE-FUSION-AUTHORITY-001",
            "deployment authority does not match site",
        ));
    }
    let check = || -> std::result::Result<PathBuf, Box<dyn std::error::Error>> {
        if !fs::symlink_metadata(root)?.file_type().is_dir() {
            return Err("existing non-symlink deployment directory required".into());
        }
        let root = fs::canonicalize(root)?;
        let path = root.join("LAYOUT");
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || metadata.len() > 4096 {
            return Err("regular bounded deployment layout required".into());
        }
        let mut bytes = Vec::new();
        File::open(path)?.take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err("layout exceeds bound".into());
        }
        let layout = DeploymentLayout::parse_canonical_text(std::str::from_utf8(&bytes)?)?;
        if layout.site_lineage != site {
            return Err("deployment site does not match".into());
        }
        for relative in [layout.ledger_relpath, layout.effects_relpath] {
            let metadata = fs::symlink_metadata(root.join(relative))?;
            if !metadata.file_type().is_file() || metadata.len() > 64 * 1024 * 1024 {
                return Err("regular existing journals at most 64 MiB required".into());
            }
        }
        Ok(root)
    };
    check().map_err(|e| fail("ERR-SCENE-FUSION-INPUT-001", e.to_string()))
}

fn analyze(options: &Options, root: &Path, cx: &ReplayCx) -> Result<String> {
    checkpoint(cx, "retained_handoffs:begin")?;
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
    let bytes = read_input(&options.selection, query::MAX_INPUT_BYTES, cx)?;
    let input_document = ContentDigest::sha256(&bytes);
    if options.expected_input.is_some_and(|p| p != input_document) {
        return Err(input_error("selection bytes differ from --expected-input"));
    }
    let request = query::parse_query(&bytes).map_err(input_error)?;
    if cancelled() {
        return Err(fail(
            "ERR-GRAPH-CANCELLED-001",
            "handoff deadline reached before deployment read",
        ));
    }
    let deployment = ReferenceDeployment::reopen(root, &options.site, cx)
        .map_err(|e| fail("ERR-SCENE-FUSION-INPUT-001", e.to_string()))?;
    if options
        .expected_anchor
        .is_some_and(|p| p != query::anchor_digest(deployment.current_anchor()))
    {
        return Err(input_error("deployment differs from --expected-anchor"));
    }
    let projection =
        PackageHandoffProjection::read_with_cancel(&deployment, &request, cx, &cancelled)
            .map_err(|e| fail(e.stable_id(), e.to_string()))?;
    let report = query::analyze(
        RetainedReportInput {
            input_document,
            projection_digest: projection.digest(),
            anchor: projection.anchor(),
            bindings: projection.bindings(),
            query: projection.query(),
        },
        Budget::new(options.work, MAX_OUTPUT_ENTRIES),
        options.report_bytes,
        &cancelled,
    )
    .map_err(|e| fail(e.code(), e.to_string()))?;
    projection
        .revalidate_with_cancel(&deployment, cx, &cancelled)
        .map_err(|e| fail(e.stable_id(), e.to_string()))?;
    if cancelled() {
        return Err(fail(
            "ERR-GRAPH-CANCELLED-001",
            "handoff deadline reached before output",
        ));
    }
    checkpoint(cx, "retained_handoffs:complete")?;
    Ok(report)
}

fn execute(options: &Options, out: &mut impl Write) -> Result<bool> {
    let authority = authority(options)?;
    // This check precedes ReplayCx construction, which may create its region directory.
    let root = preflight(&options.root, &options.site, &authority)?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())
        .map_err(|e| fail("ERR-SCENE-FUSION-AUTHORITY-001", e.to_string()))?;
    let result = (|| {
        let report = analyze(options, &root, &cx)?;
        if let Some(path) = &options.report_out {
            write_report(path, report.as_bytes(), &cx)?;
        } else {
            checkpoint(&cx, "retained_handoffs:stdout")?;
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
#[path = "retained_handoffs_tests.rs"]
mod tests;
