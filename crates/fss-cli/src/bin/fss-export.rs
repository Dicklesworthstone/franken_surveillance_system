#![forbid(unsafe_code)]
//! Local operator adapter for approval-gated redacted P5 event exports.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{evidence_anchor, object, string};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, DigestAlgorithm, EventId, OperationId, PrincipalId, TimestampNs,
};
use fss_reference::agent_orient::OrientLimits;
use fss_reference::evidence_export::{
    CAP_EXPORT_COMMIT, CAP_EXPORT_PREPARE, EventExportPreview, EventExportRequest, ExportError,
    commit_export, preview_export, read_export,
};
use fss_reference::retained_source::{ImmutableRetainedReadLimits, ImmutableRetainedSource};
use fss_reference::{ReferenceDeployment, ReplayCx};

#[path = "fss-export/media.rs"]
mod media;
#[path = "fss-export/review.rs"]
mod review;
#[cfg(test)]
#[path = "fss-export/immutable_tests.rs"]
mod immutable_tests;

const DEFAULT_SHOW_READ_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SHOW_READ_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_SHOW_READ_OBJECTS: u64 = 65_536;
const MAX_SHOW_READ_OBJECTS: u64 = 1_000_000;
const MAX_SHOW_REPORT_BYTES: usize = 1024 * 1024;

const HELP: &str = "fss-export event --root DIR --site SITE --event-id ID \
  --expected-revision sha256:HEX --recipient ID --purpose TEXT --expires-at-ns I128 \
  [--principal ID] [--approve sha256:HEX]\n\
Without --approve this is a read-only preview. Review approval_digest, export_root and package.\n\
Preview works during capture without locking, recovery, publication or source-media reads.\n\
Preview-only --max-read-bytes, --max-read-objects and --timeout-ms use the show limits below.\n\
The complete response is withheld until final canonical metadata and custody checks pass.\n\
Repeat the exact request with --approve to publish the redacted export root and authority record.\n\
The fixed profile exports event state/class/time, evidence/model digests and decision fingerprints.\n\
It never exports raw media, source/device identities, zone/track IDs, failure-domain plaintext,\n\
model tensors, or the live archive namespace. There is no override or include-all option.\n\
expires-at-ns is retained policy metadata; this reference has no trusted wall clock or auto-delete.\n\
Publication is local only. No email/upload/provider dispatch occurs.\n\
fss-export show --root DIR --site SITE --export-root sha256:HEX [--principal ID]\n\
  [--max-read-bytes N] (default 64 MiB, max 1 GiB)\n\
  [--max-read-objects N] (default 65536, max 1000000)\n\
  [--timeout-ms N] (default 30000, max 600000).\n\
show verifies committed authority, the root manifest and the redacted record, including final\n\
custody revalidation under one nonrenewing read allowance and a cooperative deadline.\n\
It works during active ingest without locking, journal repair, deployment changes or raw media\n\
reads. Complete output is at most 1 MiB. Missing roots and incomplete journals are refused.\n";

type RunResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    request: EventExportRequest,
    approval: Option<ContentDigest>,
    read_limits: ImmutableRetainedReadLimits,
    timeout: Duration,
}

#[derive(Debug)]
struct ShowOptions {
    root: PathBuf,
    site: String,
    principal: String,
    export_root: ContentDigest,
    read_limits: ImmutableRetainedReadLimits,
    timeout: Duration,
}

fn text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .ok_or_else(|| format!("required option {key}"))?
        .to_str()
        .ok_or_else(|| format!("{key} requires UTF-8"))
}
fn digest(value: &str) -> Result<ContentDigest, String> {
    let digest = ContentDigest::parse(value).map_err(|_| "expected sha256:HEX".to_owned())?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err("nonzero SHA-256 required".into());
    }
    Ok(digest)
}
fn parse(args: &[OsString]) -> Result<Options, String> {
    if args.len() > 25 || args.first().and_then(|v| v.to_str()) != Some("event") {
        return Err("expected bounded 'event' export command".into());
    }
    let allowed = [
        "--root",
        "--site",
        "--principal",
        "--event-id",
        "--expected-revision",
        "--recipient",
        "--purpose",
        "--expires-at-ns",
        "--approve",
        "--max-read-bytes",
        "--max-read-objects",
        "--timeout-ms",
    ];
    let mut values = BTreeMap::new();
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        if !allowed.contains(&key) {
            return Err(format!("unknown option {key}"));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        if value.is_empty()
            || value.len() > 4096
            || value.to_str().is_some_and(|v| v.starts_with("--"))
        {
            return Err(format!("missing value for {key}"));
        }
        if values.insert(key.to_owned(), value.clone()).is_some() {
            return Err(format!("duplicate {key}"));
        }
        index += 2;
    }
    let root = PathBuf::from(values.get("--root").ok_or("required option --root")?);
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = values
        .get("--principal")
        .map(|_| text(&values, "--principal"))
        .transpose()?
        .unwrap_or("principal:local-operator")
        .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
    let event_id =
        EventId::parse(text(&values, "--event-id")?).map_err(|_| "invalid event identity")?;
    let expected_revision = digest(text(&values, "--expected-revision")?)?;
    let expires_at = text(&values, "--expires-at-ns")?
        .parse::<i128>()
        .map_err(|_| "--expires-at-ns requires signed decimal i128")?;
    let request = EventExportRequest {
        event_id,
        expected_revision,
        recipient: text(&values, "--recipient")?.to_owned(),
        purpose: text(&values, "--purpose")?.to_owned(),
        expires_at: TimestampNs(expires_at),
    };
    request.validate().map_err(|e| e.to_string())?;
    let approval = values
        .get("--approve")
        .map(|_| text(&values, "--approve").and_then(digest))
        .transpose()?;
    if approval.is_some()
        && ["--max-read-bytes", "--max-read-objects", "--timeout-ms"]
            .iter()
            .any(|key| values.contains_key(*key))
    {
        return Err("read allowances and timeout apply only to unapproved previews".into());
    }
    let (read_limits, timeout) = read_options(&values)?;
    Ok(Options {
        root,
        site,
        principal,
        request,
        approval,
        read_limits,
        timeout,
    })
}

fn parse_show(args: &[OsString]) -> Result<ShowOptions, String> {
    if args.len() > 15 || args.first().and_then(|v| v.to_str()) != Some("show") {
        return Err("expected bounded 'show' export command".into());
    }
    let allowed = [
        "--root",
        "--site",
        "--principal",
        "--export-root",
        "--max-read-bytes",
        "--max-read-objects",
        "--timeout-ms",
    ];
    let mut values = BTreeMap::new();
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        if !allowed.contains(&key) {
            return Err(format!("unknown option {key}"));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        if value.is_empty()
            || value.len() > 4096
            || value.to_str().is_some_and(|v| v.starts_with("--"))
        {
            return Err(format!("missing value for {key}"));
        }
        if values.insert(key.to_owned(), value.clone()).is_some() {
            return Err(format!("duplicate {key}"));
        }
        index += 2;
    }
    let root = PathBuf::from(values.get("--root").ok_or("required option --root")?);
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = values
        .get("--principal")
        .map(|_| text(&values, "--principal"))
        .transpose()?
        .unwrap_or("principal:local-operator")
        .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
    let (read_limits, timeout) = read_options(&values)?;
    Ok(ShowOptions {
        root,
        site,
        principal,
        export_root: digest(text(&values, "--export-root")?)?,
        read_limits,
        timeout,
    })
}

fn read_options(
    values: &BTreeMap<String, OsString>,
) -> Result<(ImmutableRetainedReadLimits, Duration), String> {
    let limit = |key: &str, default: u64, maximum: u64| -> Result<u64, String> {
        let Some(value) = values.get(key) else {
            return Ok(default);
        };
        let value = value.to_str().ok_or("read limits require decimal UTF-8")?;
        let parsed = value
            .parse::<u64>()
            .map_err(|_| "read limits require canonical positive decimal")?;
        if parsed == 0 || parsed > maximum || parsed.to_string() != value {
            return Err("read limits require bounded canonical positive decimal".into());
        }
        Ok(parsed)
    };
    Ok((
        ImmutableRetainedReadLimits {
            snapshot: OrientLimits::default(),
            max_read_bytes: usize::try_from(limit(
                "--max-read-bytes",
                DEFAULT_SHOW_READ_BYTES,
                MAX_SHOW_READ_BYTES,
            )?)
            .map_err(|_| "read byte allowance exceeds address range")?,
            max_read_objects: usize::try_from(limit(
                "--max-read-objects",
                DEFAULT_SHOW_READ_OBJECTS,
                MAX_SHOW_READ_OBJECTS,
            )?)
            .map_err(|_| "read attempt allowance exceeds address range")?,
        },
        Duration::from_millis(limit("--timeout-ms", 30_000, 600_000)?),
    ))
}

fn run_show(options: &ShowOptions) -> RunResult<String> {
    let start = Instant::now();
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?
            .file_type()
            .is_file()
    {
        return Err(io::Error::other("existing regular deployment and LAYOUT required").into());
    }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:export-show-cli".into(),
        operation_id: OperationId::parse("operation:export-show-cli")?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".to_owned(), CAP_EXPORT_PREPARE.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(options.read_limits.max_read_bytes as u64)
            .storage_operations(options.read_limits.max_read_objects as u64)
            .build()?,
        privacy_scope: "privacy:redacted-event-export-v1".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    let root = fs::canonicalize(&options.root)?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, root.clone())?;
    let result = (|| -> RunResult<String> {
        let stopped = || start.elapsed() >= options.timeout;
        let read_error = || {
            if stopped() {
                ExportError::Cancelled
            } else {
                ExportError::CustodyMismatch
            }
        };
        let deployment =
            ImmutableRetainedSource::open_cancellable(&root, options.read_limits, &cx, &stopped)
                .map_err(|_| read_error())?;
        if deployment.history().site_lineage() != options.site {
            return Err(ExportError::Unauthorized.into());
        }
        let (record, anchor) = read_export(&deployment, options.export_root, &authority, &cx)?;
        let package = record.to_redacted_json();
        deployment.revalidate().map_err(|_| read_error())?;
        let usage = deployment.usage();
        let report = object(&[
            ("format", string("fss.evidence_export_cli.v1")),
            ("site", string(&options.site)),
            ("status", string("verified_committed_export")),
            ("export_root", string(&options.export_root.to_text())),
            ("record_digest", string(&record.digest().to_text())),
            ("authority_anchor", evidence_anchor(&anchor)),
            ("package", package),
            ("deployment_mutated", "false".into()),
            ("payload_read_bytes", usage.read_bytes.to_string()),
            ("payload_read_attempts", usage.read_objects.to_string()),
            ("external_transport_performed", "false".into()),
            ("raw_media_read", "false".into()),
            ("qualification", string("implemented_not_qualified")),
        ]);
        if report.len() > MAX_SHOW_REPORT_BYTES {
            return Err(ExportError::Limit.into());
        }
        Ok(report)
    })();
    cx.drain_and_finalize();
    result
}

fn run(options: &Options) -> RunResult<String> {
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir()
        || !fs::symlink_metadata(options.root.join("LAYOUT"))?
            .file_type()
            .is_file()
    {
        return Err(io::Error::other("existing regular deployment and LAYOUT required").into());
    }
    let mut capabilities = vec!["ADP-REPLAY-001".to_owned(), CAP_EXPORT_PREPARE.to_owned()];
    if options.approval.is_some() {
        capabilities.push(CAP_EXPORT_COMMIT.to_owned());
    }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:export-cli".into(),
        operation_id: OperationId::parse("operation:export-cli")?,
        principal: options.principal.clone(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(options.read_limits.max_read_bytes as u64)
            .storage_operations(options.read_limits.max_read_objects as u64)
            .build()?,
        privacy_scope: "privacy:redacted-event-export-v1".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    let root = fs::canonicalize(&options.root)?;
    let cx = if options.approval.is_none() {
        ReplayCx::from_context_authority_read_only(&authority, root)?
    } else {
        ReplayCx::from_context_authority(&authority, root)?
    };
    let result = run_with(options, &authority, &cx);
    cx.drain_and_finalize();
    result
}
fn run_with(options: &Options, authority: &ContextAuthority, cx: &ReplayCx) -> RunResult<String> {
    let Some(approval) = options.approval else {
        let start = Instant::now();
        return run_preview_with(options, authority, cx, &|| {
            start.elapsed() >= options.timeout
        });
    };
    let mut deployment = ReferenceDeployment::open(cx.root_dir(), &options.site, cx)?;
    let receipt = commit_export(&mut deployment, &options.request, approval, authority, cx)?;
    event_report(
        options,
        &receipt.preview,
        receipt.published,
        &receipt.anchor,
    )
}

fn run_preview_with(
    options: &Options,
    authority: &ContextAuthority,
    cx: &ReplayCx,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> RunResult<String> {
    if options.approval.is_some() {
        return Err(ExportError::Unauthorized.into());
    }
    let read_error = |error: fss_reference::ingest::FileIngestError| match error {
        fss_reference::ingest::FileIngestError::CancellationRequested { .. } => {
            ExportError::Cancelled
        }
        _ => ExportError::CustodyMismatch,
    };
    let deployment = ImmutableRetainedSource::open_cancellable(
        cx.root_dir(),
        options.read_limits,
        cx,
        cancelled,
    )
    .map_err(read_error)?;
    if deployment.history().site_lineage() != options.site {
        return Err(ExportError::Unauthorized.into());
    }
    if !deployment.snapshot().effect_journal_present {
        return Err(ExportError::CustodyMismatch.into());
    }
    let preview = preview_export(&deployment, &options.request, authority, cx)?;
    let report = event_report(options, &preview, false, &deployment.snapshot().anchor)?;
    deployment
        .revalidate_snapshot_metadata()
        .map_err(read_error)?;
    deployment.revalidate().map_err(read_error)?;
    Ok(report)
}

fn event_report(
    options: &Options,
    preview: &EventExportPreview,
    published: bool,
    commit_anchor: &fss_core::LedgerAnchor,
) -> RunResult<String> {
    let status = if published {
        "published"
    } else if preview.already_committed() {
        "already_committed"
    } else {
        "proposed"
    };
    let report = object(&[
        ("format", string("fss.evidence_export_cli.v1")),
        ("site", string(&options.site)),
        ("status", string(status)),
        ("published", published.to_string()),
        ("approval_digest", string(&preview.approval().to_text())),
        ("export_root", string(&preview.root().to_text())),
        (
            "record_digest",
            string(&preview.record().digest().to_text()),
        ),
        ("authority_anchor", evidence_anchor(commit_anchor)),
        ("package", preview.record().to_redacted_json()),
        ("external_transport_performed", "false".into()),
        ("raw_media_read", "false".into()),
        (
            "expiry_enforcement",
            string("metadata_only_no_trusted_clock"),
        ),
        ("qualification", string("implemented_not_qualified")),
    ]);
    if report.len() > MAX_SHOW_REPORT_BYTES {
        return Err(ExportError::Limit.into());
    }
    Ok(report)
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        print!("{HELP}\n{}\n{}", media::HELP, review::HELP);
        return ExitCode::from(ExitIdentity::SUCCESS.code);
    }
    if matches!(
        args.first().and_then(|value| value.to_str()),
        Some("media" | "media-verify")
    ) {
        return media::main(&args);
    }
    if matches!(
        args.first().and_then(|value| value.to_str()),
        Some("review" | "review-show" | "review-read" | "review-revoke" | "review-delivery-show")
    ) {
        return review::main(&args);
    }
    if args.first().and_then(|v| v.to_str()) == Some("show") {
        let options = match parse_show(&args) {
            Ok(v) => v,
            Err(reason) => {
                eprintln!("{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-export --help");
                return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
            }
        };
        return match run_show(&options) {
            Ok(json) => match writeln!(io::stdout().lock(), "{json}") {
                Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
                Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
            },
            Err(error) => {
                let id = error
                    .downcast_ref::<ExportError>()
                    .map_or(ERR_CLI_RUNTIME_FAILURE, ExportError::stable_id);
                eprintln!("{id}: {error}");
                ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
            }
        };
    }
    let options = match parse(&args) {
        Ok(v) => v,
        Err(reason) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-export --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match run(&options) {
        Ok(json) => match writeln!(io::stdout().lock(), "{json}") {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            let id = error
                .downcast_ref::<ExportError>()
                .map_or(ERR_CLI_RUNTIME_FAILURE, ExportError::stable_id);
            eprintln!("{id}: {error}");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arguments() -> Vec<OsString> {
        [
            "event",
            "--root",
            "/existing",
            "--site",
            "site:export",
            "--event-id",
            "event:test",
            "--expected-revision",
            &ContentDigest::sha256(b"revision").to_text(),
            "--recipient",
            "recipient:insurer-case-7",
            "--purpose",
            "Owner incident review",
            "--expires-at-ns",
            "1000",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }
    #[test]
    fn exact_revision_recipient_purpose_and_expiry_are_required() -> Result<(), String> {
        let options = parse(&arguments())?;
        assert!(options.approval.is_none());
        assert_eq!(options.request.recipient, "recipient:insurer-case-7");
        for key in [
            "--expected-revision",
            "--recipient",
            "--purpose",
            "--expires-at-ns",
        ] {
            let mut args = arguments();
            let at = args.iter().position(|v| v == key).ok_or("key")?;
            args.drain(at..=at + 1);
            assert!(parse(&args).is_err(), "accepted missing {key}");
        }
        Ok(())
    }
    #[test]
    fn approval_is_separate_and_unknown_or_duplicate_options_fail() -> Result<(), String> {
        let approval = ContentDigest::sha256(b"approval");
        let mut args = arguments();
        args.extend(["--approve".into(), approval.to_text().into()]);
        assert_eq!(parse(&args)?.approval, Some(approval));
        let mut duplicate = arguments();
        duplicate.extend(["--purpose".into(), "other".into()]);
        assert!(parse(&duplicate).is_err());
        let mut unknown = arguments();
        unknown.extend(["--include-raw".into(), "yes".into()]);
        assert!(parse(&unknown).is_err());
        Ok(())
    }
    #[test]
    fn include_all_or_raw_media_escape_hatches_do_not_exist() {
        for key in [
            "--raw",
            "--include-all",
            "--include-media",
            "--include-identities",
            "--force",
        ] {
            let mut args = arguments();
            args.extend([key.into(), "yes".into()]);
            assert!(parse(&args).is_err(), "accepted {key}");
        }
    }
    #[test]
    fn show_requires_only_exact_export_root_and_read_scope() -> Result<(), String> {
        let root = ContentDigest::sha256(b"export");
        let args = [
            "show",
            "--root",
            "/existing",
            "--site",
            "site:export",
            "--export-root",
            &root.to_text(),
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        let options = parse_show(&args)?;
        assert_eq!(options.export_root, root);
        assert_eq!(
            options.read_limits.max_read_bytes as u64,
            DEFAULT_SHOW_READ_BYTES
        );
        assert_eq!(
            options.read_limits.max_read_objects as u64,
            DEFAULT_SHOW_READ_OBJECTS
        );
        assert_eq!(options.timeout, Duration::from_millis(30_000));
        let mut bad = args.clone();
        bad.extend(["--approve".into(), root.to_text().into()]);
        assert!(parse_show(&bad).is_err());
        for (key, value) in [
            ("--max-read-bytes", "0"),
            ("--max-read-bytes", "1073741825"),
            ("--max-read-bytes", "01"),
            ("--max-read-objects", "0"),
            ("--max-read-objects", "1000001"),
            ("--max-read-objects", "+1"),
            ("--timeout-ms", "0"),
            ("--timeout-ms", "600001"),
            ("--timeout-ms", "01"),
        ] {
            let mut bad = args.clone();
            bad.extend([key.into(), value.into()]);
            assert!(parse_show(&bad).is_err(), "accepted {key}={value}");
        }
        let mut narrow = args;
        narrow.extend([
            "--max-read-bytes".into(),
            "1".into(),
            "--max-read-objects".into(),
            "1".into(),
            "--timeout-ms".into(),
            "1".into(),
        ]);
        let bounded = parse_show(&narrow)?;
        assert_eq!(bounded.export_root, root);
        assert_eq!(bounded.read_limits.max_read_bytes, 1);
        assert_eq!(bounded.read_limits.max_read_objects, 1);
        assert_eq!(bounded.timeout, Duration::from_millis(1));
        Ok(())
    }
}
