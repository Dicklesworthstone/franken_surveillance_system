#![forbid(unsafe_code)]
//! Independent retention, cold inspection and exact native replay of historical diagnostics.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_cli::agent_json::{evidence_anchor, object, string};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, DigestAlgorithm, LedgerAnchor, OperationId, PrincipalId,
};
use fss_reference::ingest::historical_health::{
    HistoricalHealthDiagnostic, HistoricalHealthReadLimits, HistoricalHealthReadReport,
    HistoricalHealthRetention, read_retained, verify_retained,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Run<T> = Result<T, Box<dyn Error>>;
const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_WATCH_REPORT_BYTES: usize = 1024 * 1024;
const HELP: &str = "fss-event health read --root EXISTING_DIR --site SITE\n\
  --diagnostic-digest sha256:RECORD\n\
fss-event health verify --root EXISTING_DIR --site SITE\n\
  --diagnostic-digest sha256:RECORD --expected-provenance-root sha256:ROOT\n\
  --execute-perception yes\n\
Read checks the retained historical receipt, committed source references and policy metadata.\n\
It does not read source media or trace payloads and does not certify their availability.\n\
Verify reruns the exact retained native scan and health policy on privacy-masked source\n\
pixels, comparing the complete receipt and trace. It needs neither a source path nor a\n\
trained model. It does not rerun detector classification or verify an event.\n\
Retain a diagnosis independently with fss-event watch --stream-watch (or --stream-dwell)\n\
  --sensor-health conservative-v1 --retain-health sha256:APPROVAL\n\
using the exact approval and rerun command from the preview's historical_health object.\n\
This works with no event candidates and with findings that block event publication.\n\
Common bounds: --max-metadata-bytes N (default 64 MiB, maximum 256 MiB)\n\
  --max-report-bytes N (default 1 MiB, maximum 16 MiB) [--principal ID]\n\
Execution ceilings (also accepted by read to bind its verification command):\n\
  --source-read-bytes N --pixel-budget N --assignment-work N --trace-bytes N\n\
  --decode-work N --max-dimension N --max-pixels N --max-segment-bytes N\n\
Ceilings can refuse replay; they never change or widen the retained recipe.\n\
Optional --report-out FILE exports the complete JSON create-only outside the deployment.\n\
Missing/deleted selected metadata, wrong pins and exhausted bounds refuse without success\n\
output. Native verification also refuses missing source/trace custody and changed privacy.\n\
Existing deployment open may perform its normal restart recovery; these\n\
commands publish no events, diagnostics or effects. A matched replay establishes historical\n\
reproducibility, not current camera health, tampering, physical absence or detector accuracy.\n";

const COMMON: &[&str] = &[
    "--root",
    "--site",
    "--principal",
    "--diagnostic-digest",
    "--max-metadata-bytes",
    "--max-report-bytes",
    "--source-read-bytes",
    "--pixel-budget",
    "--assignment-work",
    "--trace-bytes",
    "--decode-work",
    "--max-dimension",
    "--max-pixels",
    "--max-segment-bytes",
    "--report-out",
];
const VERIFY: &[&str] = &["--expected-provenance-root", "--execute-perception"];

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    diagnostic: ContentDigest,
    expected_root: Option<ContentDigest>,
    limits: HistoricalHealthReadLimits,
    dimension_override: Option<u32>,
    pixels_override: Option<usize>,
    maximum_report_bytes: usize,
    report_out: Option<PathBuf>,
}

fn text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .ok_or_else(|| format!("required option {key}"))?
        .to_str()
        .ok_or_else(|| format!("{key} requires UTF-8"))
}

fn number(
    values: &BTreeMap<String, OsString>,
    key: &str,
    default: u64,
    maximum: u64,
) -> Result<u64, String> {
    let value = if values.contains_key(key) {
        let value = text(values, key)?;
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("{key} requires unsigned decimal"));
        }
        value
            .parse()
            .map_err(|_| format!("{key} integer overflow"))?
    } else {
        default
    };
    if value == 0 || value > maximum {
        return Err(format!("{key} outside bounds"));
    }
    Ok(value)
}

fn digest(value: &str) -> Result<ContentDigest, String> {
    let digest = ContentDigest::parse(value).map_err(|_| "invalid content digest")?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err("nonzero SHA-256 required".into());
    }
    Ok(digest)
}

fn parse(args: &[OsString]) -> Result<Options, String> {
    if args.len() > 35 || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096) {
        return Err("argument bounds exceeded".into());
    }
    let verify = match args.first().and_then(|arg| arg.to_str()) {
        Some("read") => false,
        Some("verify") => true,
        _ => return Err("expected health read or verify".into()),
    };
    let mut values = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        if !COMMON.contains(&key) && !(verify && VERIFY.contains(&key)) {
            return Err(format!("unknown or inapplicable option {key}"));
        }
        let value = pair
            .get(1)
            .filter(|value| {
                !value.is_empty() && !value.to_str().is_some_and(|value| value.starts_with("--"))
            })
            .ok_or_else(|| format!("missing value for {key}"))?;
        if values.insert(key.to_owned(), value.clone()).is_some() {
            return Err(format!("duplicate {key}"));
        }
    }
    let root = PathBuf::from(values.get("--root").ok_or("required option --root")?);
    if !root.is_absolute() {
        return Err("--root must be absolute".into());
    }
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = values
        .get("--principal")
        .map_or(Ok("principal:local-operator"), |value| {
            value.to_str().ok_or("--principal requires UTF-8")
        })?
        .to_owned();
    if site.len() > 256 || principal.len() > 128 {
        return Err("site or principal exceeds bound".into());
    }
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let expected_root = if verify {
        if text(&values, "--execute-perception")? != "yes" {
            return Err("--execute-perception must be yes".into());
        }
        Some(digest(text(&values, "--expected-provenance-root")?)?)
    } else {
        None
    };
    let mut limits = HistoricalHealthReadLimits::default();
    // The default reader admits both native-library and watch-CLI producer profiles. Watch
    // stores 4096 for both dimensions even for an unused codec; native defaults retain larger
    // AVC macroblock / HEVC sample ceilings. This fixed admission profile does not replace
    // any retained limit. Explicit flags below may narrow it and refuse the original recipe.
    limits.execution.decode.h264_limits.max_width =
        limits.execution.decode.h264_limits.max_width.max(4096);
    limits.execution.decode.h264_limits.max_height =
        limits.execution.decode.h264_limits.max_height.max(4096);
    limits.execution.decode.h265_limits.max_width =
        limits.execution.decode.h265_limits.max_width.max(4096);
    limits.execution.decode.h265_limits.max_height =
        limits.execution.decode.h265_limits.max_height.max(4096);
    limits.maximum_metadata_bytes = number(
        &values,
        "--max-metadata-bytes",
        limits.maximum_metadata_bytes as u64,
        256 * 1024 * 1024,
    )? as usize;
    let execution = &mut limits.execution;
    execution.maximum_source_chunk_bytes = number(
        &values,
        "--source-read-bytes",
        execution.maximum_source_chunk_bytes,
        512 * 1024 * 1024,
    )?;
    execution.maximum_pixel_samples = number(
        &values,
        "--pixel-budget",
        execution.maximum_pixel_samples,
        64 * 1024 * 1024 * 1024,
    )?;
    execution.maximum_assignment_work = number(
        &values,
        "--assignment-work",
        execution.maximum_assignment_work,
        64 * 1024 * 1024 * 1024,
    )?;
    execution.maximum_trace_bytes = number(
        &values,
        "--trace-bytes",
        execution.maximum_trace_bytes as u64,
        8 * 1024 * 1024,
    )? as usize;
    execution.decode.jpeg_work_units = number(
        &values,
        "--decode-work",
        execution.decode.jpeg_work_units,
        1_000_000_000_000,
    )?;
    execution.decode.read_limits.max_segment_bytes = number(
        &values,
        "--max-segment-bytes",
        execution.decode.read_limits.max_segment_bytes,
        64 * 1024 * 1024,
    )?;
    // Preserve each codec owner's default when no cross-codec override was requested.
    // In particular, unused AVC/HEVC ceilings in a library-produced JPEG recipe must not
    // silently become smaller merely because the reader is the CLI.
    let dimension_override = if values.contains_key("--max-dimension") {
        let dimension = number(&values, "--max-dimension", 4096, 4096)? as u32;
        if dimension < 16 {
            return Err("--max-dimension must be 16..4096".into());
        }
        execution.decode.jpeg_limits.maximum_dimension = dimension;
        execution.decode.h264_limits.max_width = dimension;
        execution.decode.h264_limits.max_height = dimension;
        execution.decode.h265_limits.max_width = dimension;
        execution.decode.h265_limits.max_height = dimension;
        Some(dimension)
    } else {
        None
    };
    let pixels_override = if values.contains_key("--max-pixels") {
        let pixels = number(&values, "--max-pixels", 4_194_304, 4_194_304)? as usize;
        execution.decode.jpeg_limits.maximum_pixels = pixels;
        execution.decode.h264_limits.max_macroblocks =
            u32::try_from(pixels.div_ceil(256)).map_err(|_| "pixel bound")?;
        execution.decode.h265_limits.max_luma_samples = pixels as u64;
        Some(pixels)
    } else {
        None
    };
    limits.validate().map_err(|error| error.to_string())?;
    Ok(Options {
        root,
        site,
        principal,
        diagnostic: digest(text(&values, "--diagnostic-digest")?)?,
        expected_root,
        limits,
        dimension_override,
        pixels_override,
        maximum_report_bytes: number(
            &values,
            "--max-report-bytes",
            1024 * 1024,
            MAX_REPORT_BYTES as u64,
        )? as usize,
        report_out: values.get("--report-out").map(PathBuf::from),
    })
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn verification_command(
    options: &Options,
    root: &Path,
    provenance: ContentDigest,
) -> Option<String> {
    let limits = &options.limits.execution;
    Some(format!(
        concat!(
            "fss-event health verify --root {} --site {} --principal {} ",
            "--diagnostic-digest {} --expected-provenance-root {} --execute-perception yes ",
            "--max-metadata-bytes {} --max-report-bytes {} --source-read-bytes {} ",
            "--pixel-budget {} --assignment-work {} --trace-bytes {} --decode-work {} ",
            "--max-segment-bytes {}{}{}"
        ),
        quote(root.to_str()?),
        quote(&options.site),
        quote(&options.principal),
        options.diagnostic,
        provenance,
        options.limits.maximum_metadata_bytes,
        options.maximum_report_bytes,
        limits.maximum_source_chunk_bytes,
        limits.maximum_pixel_samples,
        limits.maximum_assignment_work,
        limits.maximum_trace_bytes,
        limits.decode.jpeg_work_units,
        limits.decode.read_limits.max_segment_bytes,
        options
            .dimension_override
            .map_or_else(String::new, |value| format!(" --max-dimension {value}")),
        options
            .pixels_override
            .map_or_else(String::new, |value| format!(" --max-pixels {value}")),
    ))
}

fn report(options: &Options, root: &Path, retained: &HistoricalHealthReadReport) -> Run<String> {
    let verified = retained.native_verified;
    if verified != options.expected_root.is_some()
        || retained.record.record_digest() != options.diagnostic
        || options
            .expected_root
            .is_some_and(|root| root != retained.provenance_root)
    {
        return Err("historical health response does not match the admitted operation".into());
    }
    let limits = &options.limits.execution;
    let text = object(&[
        (
            "operation",
            string(if verified {
                "verify_historical_health"
            } else {
                "read_historical_health"
            }),
        ),
        (
            "status",
            string(if verified {
                "native_replay_matched"
            } else {
                "inspected_not_replayed"
            }),
        ),
        ("record_digest", string(&options.diagnostic.to_text())),
        (
            "provenance_root",
            string(&retained.provenance_root.to_text()),
        ),
        ("anchor", evidence_anchor(&retained.ledger_anchor)),
        ("record", retained.record.to_json()),
        ("native_replayed", verified.to_string()),
        ("source_and_trace_verified", verified.to_string()),
        ("current_privacy_revalidated", verified.to_string()),
        (
            "frames_replayed",
            if verified {
                retained.frames_replayed.to_string()
            } else {
                "null".into()
            },
        ),
        (
            "source_chunk_bytes_read",
            if verified {
                retained.source_chunk_bytes_read.to_string()
            } else {
                "null".into()
            },
        ),
        ("current_health_proved", "false".into()),
        ("tamper_proved", "false".into()),
        ("absence_certifiable", "false".into()),
        ("event_verified", "false".into()),
        ("effects_authorized", "false".into()),
        (
            "bounds",
            object(&[
                (
                    "metadata_bytes",
                    options.limits.maximum_metadata_bytes.to_string(),
                ),
                ("report_bytes", options.maximum_report_bytes.to_string()),
                (
                    "source_chunk_bytes",
                    limits.maximum_source_chunk_bytes.to_string(),
                ),
                ("pixel_samples", limits.maximum_pixel_samples.to_string()),
                (
                    "assignment_work",
                    limits.maximum_assignment_work.to_string(),
                ),
                ("trace_bytes", limits.maximum_trace_bytes.to_string()),
                ("jpeg_work", limits.decode.jpeg_work_units.to_string()),
                (
                    "jpeg_max_dimension",
                    limits.decode.jpeg_limits.maximum_dimension.to_string(),
                ),
                (
                    "jpeg_max_pixels",
                    limits.decode.jpeg_limits.maximum_pixels.to_string(),
                ),
                (
                    "h264_max_width",
                    limits.decode.h264_limits.max_width.to_string(),
                ),
                (
                    "h264_max_height",
                    limits.decode.h264_limits.max_height.to_string(),
                ),
                (
                    "h264_max_macroblocks",
                    limits.decode.h264_limits.max_macroblocks.to_string(),
                ),
                (
                    "h265_max_width",
                    limits.decode.h265_limits.max_width.to_string(),
                ),
                (
                    "h265_max_height",
                    limits.decode.h265_limits.max_height.to_string(),
                ),
                (
                    "h265_max_luma_samples",
                    limits.decode.h265_limits.max_luma_samples.to_string(),
                ),
                (
                    "max_segment_bytes",
                    limits.decode.read_limits.max_segment_bytes.to_string(),
                ),
            ]),
        ),
        (
            "verification_command",
            verification_command(options, root, retained.provenance_root)
                .map_or_else(|| "null".into(), |value| string(&value)),
        ),
    ]);
    if text
        .len()
        .checked_add(1)
        .is_none_or(|n| n > options.maximum_report_bytes)
    {
        return Err("complete historical health report exceeds byte bound".into());
    }
    Ok(format!("{text}\n"))
}

fn run(options: Options) -> Run<String> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:historical-health-cli".into(),
        operation_id: OperationId::parse("operation:historical-health-cli")?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(128 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:current-deployment-policy".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    let root = super::replay::preflight(&options.root, &options.site, &authority)?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let result = (|| -> Run<String> {
        let deployment = ReferenceDeployment::open(&root, &options.site, &cx)?;
        let retained = match options.expected_root {
            None => read_retained(&deployment, options.diagnostic, &options.limits, &cx)?,
            Some(expected) => verify_retained(
                &deployment,
                options.diagnostic,
                expected,
                &options.limits,
                &cx,
            )?,
        };
        let output = report(&options, &root, &retained)?;
        if let Some(path) = &options.report_out {
            super::export(path, output.as_bytes(), &root, &cx)?;
        }
        Ok(output)
    })();
    cx.drain_and_finalize();
    result
}

/// Preserve the existing whole-recording JSON shape and add one explicit, independently
/// approved diagnostic. `None` leaves the old unscreened report bytes unchanged.
pub(super) fn preflight_watch_diagnostic(
    report: String,
    diagnostic: Option<&HistoricalHealthDiagnostic>,
    anchor: &LedgerAnchor,
    rerun: &str,
) -> Run<()> {
    // A later publication must not discover that its complete response cannot fit. Admit
    // the longest status and the full anchor with its longest sequence before any write.
    let maximal_retention = diagnostic.map(|diagnostic| {
        let mut ledger_anchor = anchor.clone();
        ledger_anchor.commit_sequence = u64::MAX;
        HistoricalHealthRetention {
            record_digest: diagnostic.record_digest(),
            provenance_root: diagnostic.provenance_root(),
            ledger_anchor,
            already_retained: true,
        }
    });
    with_watch_diagnostic(report, diagnostic, maximal_retention.as_ref(), rerun)?;
    Ok(())
}

pub(super) fn with_watch_diagnostic(
    report: String,
    diagnostic: Option<&HistoricalHealthDiagnostic>,
    retention: Option<&HistoricalHealthRetention>,
    rerun: &str,
) -> Run<String> {
    let Some(diagnostic) = diagnostic else {
        return Ok(report);
    };
    let status = match retention {
        Some(retention) if retention.already_retained => "already_retained",
        Some(_) => "retained",
        None if diagnostic.already_retained() => "already_retained",
        None => "prepared",
    };
    let health = object(&[
        (
            "record_digest",
            string(&diagnostic.record_digest().to_text()),
        ),
        (
            "approval_digest",
            string(&diagnostic.approval_digest().to_text()),
        ),
        (
            "provenance_root",
            string(&diagnostic.provenance_root().to_text()),
        ),
        ("status", string(status)),
        ("receipt", diagnostic.record().to_json()),
        (
            "retention_anchor",
            retention.map_or_else(
                || "null".into(),
                |value| evidence_anchor(&value.ledger_anchor),
            ),
        ),
        (
            "retain_command",
            string(&format!(
                "{rerun} --retain-health {}",
                diagnostic.approval_digest()
            )),
        ),
        ("event_approval_required", "false".into()),
        ("current_health_proved", "false".into()),
        ("absence_certifiable", "false".into()),
        ("effects_authorized", "false".into()),
    ]);
    let prefix = report
        .strip_suffix('}')
        .ok_or("invalid whole-recording report framing")?;
    let report = format!("{prefix},\"historical_health\":{health}}}");
    if report
        .len()
        .checked_add(1)
        .is_none_or(|n| n > MAX_WATCH_REPORT_BYTES)
    {
        return Err("complete watch and historical health report exceeds byte bound".into());
    }
    Ok(report)
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    if args.is_empty()
        || (args.len() == 1 && ["help", "--help", "-h"].iter().any(|arg| args[0] == *arg))
        || (args.len() == 2
            && ["read", "verify"].iter().any(|arg| args[0] == *arg)
            && ["help", "--help", "-h"].iter().any(|arg| args[1] == *arg))
    {
        return match super::replay::emit(&mut io::stdout().lock(), HELP.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(1),
        };
    }
    let options = match parse(args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {error}; use fss-event health --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match run(options).and_then(|output| {
        super::replay::emit(&mut io::stdout().lock(), output.as_bytes())?;
        Ok(())
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}
