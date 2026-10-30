#![forbid(unsafe_code)]
//! Explicitly approved, whole-source footage export and independent offline verification.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_cli::agent_json::{evidence_anchor, object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, EventId, OperationId, PrincipalId, TimestampNs,
};
use fss_reference::evidence_export::{CAP_EXPORT_COMMIT, CAP_EXPORT_PREPARE, EventExportRequest};
use fss_reference::original_media_export::{
    CAP_EXPORT_ORIGINAL_MEDIA, MAX_ORIGINAL_MEDIA_BYTES, OriginalMediaExportError,
    OriginalMediaExportPreview, OriginalMediaExportRequest, approve_original_media_export,
    preview_original_media_export, revalidate_original_media_export, verify_original_media_export,
};
use fss_reference::{DeploymentLayout, ReferenceDeployment, ReplayCx};

use super::{RunResult, digest, text};

#[path = "media/file.rs"]
mod file;

pub(super) const HELP: &str = "fss-export media --root DIR --site SITE --event-id ID\n\
  --expected-revision sha256:HEX --import-identity sha256:HEX\n\
  --expected-import-root sha256:HEX --recipient ID --purpose TEXT --expires-at-ns I128\n\
  --attested-now-ns EARLIEST:LATEST --whole-source yes --max-source-bytes U64 --out DIR\n\
  [--principal ID] [--approve sha256:HEX]\n\
Previews a separate original-footage profile. Repeat the exact request with its approval_digest\n\
to write verified source media, canonical custody record and manifest; COMPLETE.json appears last.\n\
The ENTIRE selected source recording is disclosed, including time outside the event. No trimming\n\
or masking is performed. Only verified video-only native RTSP MP4 and omission-free MJPEG sources\n\
are supported, including native detector-package candidates and verified operator-reviewed\n\
long or package events. A package event's native origin remains uncalibrated, unclassified and\n\
indeterminate; the current review state is an operator assertion. Verification reruns no inference.\n\
Review chains bind the\n\
current revision to the original native event; operator assertions are not new sensor evidence.\n\
Masked, deleted, unsupported, stale or unverified sources are refused. At most 64 MiB.\n\
Approval binds the current event, source root, actor, recipient, purpose, expiry, clock attestation,\n\
byte bound and actual destination parent. Preview creates no output. New directories are 0700 and\n\
files 0600. Destination parent must exist outside the deployment and forbid group/world writes.\n\
Publication requires Linux x86-64/aarch64 and /proc. Existing exact complete exports are verified\n\
on retry; conflicting or incomplete directories are never overwritten. An interrupted write can\n\
leave a private incomplete directory. No external transfer or delivery authority row is created.\n\
\n\
fss-export media-verify --input DIR --export-root sha256:TRUSTED_ROOT\n\
  --recipient ID --attested-now-ns EARLIEST:LATEST\n\
Verifies complete package bytes offline against a root supplied through an independent channel.\n\
It opens no deployment. Recipient is a label, not authentication. The caller attests current time;\n\
both interval bounds must precede exclusive expiry. No ambient clock or current privacy state is\n\
consulted offline. Copies are plaintext; expiry or later deletion cannot erase exported copies.\n";

const MAX_REPORT_BYTES: usize = 512 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;

struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    request: OriginalMediaExportRequest,
    output: PathBuf,
    approval: Option<ContentDigest>,
}

struct VerifyOptions {
    input: PathBuf,
    root: ContentDigest,
    recipient: String,
    now: CaptureInterval,
}

fn values(args: &[OsString], allowed: &[&str]) -> Result<BTreeMap<String, OsString>, String> {
    if args.len() > 1 + 2 * allowed.len() {
        return Err("command exceeds argument bound".into());
    }
    let mut values = BTreeMap::new();
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        if !allowed.contains(&key) {
            return Err(format!("unknown or inapplicable option {key}"));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        if value.is_empty() || value.to_str().is_some_and(|v| v.starts_with("--")) {
            return Err(format!("missing value for {key}"));
        }
        if value.as_encoded_bytes().len() > 4096 {
            return Err("argument exceeds byte bound".into());
        }
        if values.insert(key.to_owned(), value.clone()).is_some() {
            return Err(format!("duplicate {key}"));
        }
        index += 2;
    }
    Ok(values)
}

fn path(values: &BTreeMap<String, OsString>, key: &str) -> Result<PathBuf, String> {
    values
        .get(key)
        .map(PathBuf::from)
        .ok_or_else(|| format!("required option {key}"))
}

fn interval(value: &str) -> Result<CaptureInterval, String> {
    if value.len() > 81 {
        return Err("current-time interval exceeds bound".into());
    }
    let (earliest, latest) = value
        .split_once(':')
        .ok_or("current time requires EARLIEST:LATEST")?;
    let earliest = earliest
        .parse::<i128>()
        .map_err(|_| "invalid earliest current time")?;
    let latest = latest
        .parse::<i128>()
        .map_err(|_| "invalid latest current time")?;
    CaptureInterval::new(TimestampNs(earliest), TimestampNs(latest))
        .map_err(|_| "inverted current-time interval".into())
}

fn parse(args: &[OsString]) -> Result<Options, String> {
    let values = values(
        args,
        &[
            "--root",
            "--site",
            "--event-id",
            "--expected-revision",
            "--import-identity",
            "--expected-import-root",
            "--recipient",
            "--purpose",
            "--expires-at-ns",
            "--attested-now-ns",
            "--whole-source",
            "--max-source-bytes",
            "--out",
            "--principal",
            "--approve",
        ],
    )?;
    if text(&values, "--whole-source")? != "yes" {
        return Err(
            "--whole-source yes must explicitly authorize the entire selected recording".into(),
        );
    }
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site")?;
    let principal = values
        .get("--principal")
        .map(|_| text(&values, "--principal"))
        .transpose()?
        .unwrap_or("principal:local-operator")
        .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
    let request = OriginalMediaExportRequest {
        event: EventExportRequest {
            event_id: EventId::parse(text(&values, "--event-id")?).map_err(|_| "invalid event")?,
            expected_revision: digest(text(&values, "--expected-revision")?)?,
            recipient: text(&values, "--recipient")?.to_owned(),
            purpose: text(&values, "--purpose")?.to_owned(),
            expires_at: TimestampNs(
                text(&values, "--expires-at-ns")?
                    .parse::<i128>()
                    .map_err(|_| "expiry requires signed decimal i128")?,
            ),
        },
        import_identity: digest(text(&values, "--import-identity")?)?,
        expected_import_root: digest(text(&values, "--expected-import-root")?)?,
        whole_source_authorized: true,
        // Replaced with the held destination directory binding before core admission.
        destination_binding: ContentDigest::sha256(b"fss.original_media.unbound_cli_path.v1"),
        max_source_bytes: text(&values, "--max-source-bytes")?
            .parse::<u64>()
            .map_err(|_| "source byte bound requires unsigned decimal u64")?,
        attested_now: interval(text(&values, "--attested-now-ns")?)?,
    };
    request.validate().map_err(|e| e.to_string())?;
    let approval = values
        .get("--approve")
        .map(|_| text(&values, "--approve").and_then(digest))
        .transpose()?;
    Ok(Options {
        root: path(&values, "--root")?,
        site,
        principal,
        request,
        output: path(&values, "--out")?,
        approval,
    })
}

fn parse_verify(args: &[OsString]) -> Result<VerifyOptions, String> {
    let values = values(
        args,
        &[
            "--input",
            "--export-root",
            "--recipient",
            "--attested-now-ns",
        ],
    )?;
    Ok(VerifyOptions {
        input: path(&values, "--input")?,
        root: digest(text(&values, "--export-root")?)?,
        recipient: text(&values, "--recipient")?.to_owned(),
        now: interval(text(&values, "--attested-now-ns")?)?,
    })
}

fn preflight(root: &Path, site: &str) -> RunResult<PathBuf> {
    if !fs::symlink_metadata(root)?.file_type().is_dir() {
        return Err(io::Error::other("existing non-symlink deployment directory required").into());
    }
    let root = fs::canonicalize(root)?;
    let bytes = file::read_bounded(&root.join("LAYOUT"), 4096)?;
    let layout = DeploymentLayout::parse_canonical_text(std::str::from_utf8(&bytes)?)?;
    if layout.site_lineage != site {
        return Err(io::Error::other("deployment site mismatch").into());
    }
    for relative in [layout.ledger_relpath, layout.effects_relpath] {
        let metadata = fs::symlink_metadata(root.join(relative))?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_JOURNAL_BYTES {
            return Err(io::Error::other("regular bounded existing journal required").into());
        }
    }
    Ok(root)
}

fn bounded_report(report: String) -> RunResult<String> {
    if report.len() > MAX_REPORT_BYTES {
        return Err(io::Error::other("media export report exceeds byte bound").into());
    }
    Ok(report)
}

fn completion(root: ContentDigest, digest: ContentDigest, filename: &str, bytes: usize) -> String {
    object(&[
        ("format", string("fss.original_media_export_complete.v1")),
        ("export_root", string(&root.to_text())),
        ("media_digest", string(&digest.to_text())),
        ("media_filename", string(filename)),
        ("media_bytes", bytes.to_string()),
        ("whole_source_included", "true".into()),
    ])
}

fn report(
    preview: &OriginalMediaExportPreview,
    output: &Path,
    status: &str,
    published: bool,
) -> RunResult<String> {
    bounded_report(object(&[
        ("format", string("fss.original_media_export_cli.v1")),
        ("status", string(status)),
        ("profile", string(preview.profile())),
        ("published", published.to_string()),
        ("approval_digest", string(&preview.approval().to_text())),
        ("export_root", string(&preview.root().to_text())),
        ("media_digest", string(&preview.media_digest().to_text())),
        ("media_filename", string(preview.media_filename())),
        ("media_bytes", preview.media_bytes().len().to_string()),
        (
            "output",
            output.to_str().map_or_else(|| "null".into(), string),
        ),
        ("authority_anchor", evidence_anchor(preview.basis())),
        ("record", preview.record_json()),
        ("external_transport_performed", "false".into()),
        ("delivery_receipt_in_deployment", "false".into()),
        ("whole_source_included", "true".into()),
        ("clip_trimmed", "false".into()),
        ("qualification", string("implemented_not_qualified")),
    ]))
}

fn run(mut options: Options) -> RunResult<String> {
    let root = preflight(&options.root, &options.site)?;
    let target = file::Target::new(&options.output, &root)?;
    options.request.destination_binding = target.binding()?;
    let mut capabilities = vec![
        "ADP-REPLAY-001".into(),
        CAP_EXPORT_PREPARE.into(),
        CAP_EXPORT_ORIGINAL_MEDIA.into(),
    ];
    if options.approval.is_some() {
        capabilities.push(CAP_EXPORT_COMMIT.into());
    }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:original-media-export-cli".into(),
        operation_id: OperationId::parse("operation:original-media-export-cli")?,
        principal: options.principal,
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:approved-whole-original-media-v1".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let result = (|| -> RunResult<String> {
        let deployment = ReferenceDeployment::open(&root, &options.site, &cx)?;
        let Some(approval) = options.approval else {
            let preview =
                preview_original_media_export(&deployment, &options.request, &authority, &cx)?;
            return report(&preview, target.path(), "awaiting_approval", false);
        };
        let prepared = approve_original_media_export(
            &deployment,
            &options.request,
            approval,
            &authority,
            &cx,
        )?;
        let preview = prepared.preview();
        // Bound complete reports before any external output can become visible.
        let created = report(preview, target.path(), "exported_original_media", true)?;
        let existing = report(
            preview,
            target.path(),
            "already_exported_original_media",
            false,
        )?;
        let record_json = preview.record_json();
        let complete = completion(
            preview.root(),
            preview.media_digest(),
            preview.media_filename(),
            preview.media_bytes().len(),
        );
        let files = [
            (preview.media_filename(), preview.media_bytes()),
            ("record.canonical", preview.record_bytes()),
            ("manifest.canonical", preview.manifest_bytes()),
            ("record.json", record_json.as_bytes()),
        ];
        // The deployment owns its exclusive publisher/ledger lease for this entire operation.
        // Revalidate through that same owner immediately before completion: reopening while
        // still holding the lease would fail; dropping it would permit an avoidable privacy race.
        let receipt = file::publish(&target, &files, complete.as_bytes(), |stage| {
            cx.checkpoint(stage)?;
            if stage == "original_media:file_publish" {
                revalidate_original_media_export(&deployment, &prepared, &authority, &cx)?;
            }
            Ok(())
        })?;
        cx.checkpoint_post_commit("original_media:file_complete");
        Ok(if receipt.already_present {
            existing
        } else {
            created
        })
    })();
    cx.drain_and_finalize();
    result
}

fn run_verify(options: &VerifyOptions) -> RunResult<String> {
    let input = file::Input::open(&options.input)?;
    let manifest = input.read("manifest.canonical", MAX_REPORT_BYTES)?;
    let record_bytes = input.read("record.canonical", MAX_REPORT_BYTES)?;
    let complete = input.read("COMPLETE.json", MAX_REPORT_BYTES)?;
    let (name, media) = input.media(MAX_ORIGINAL_MEDIA_BYTES as usize)?;
    let record = verify_original_media_export(&manifest, &record_bytes, &media, options.root)?;
    if name != record.media_filename()
        || options.recipient != record.request().event.recipient
        || options.now.latest >= record.request().event.expires_at
    {
        return Err(
            io::Error::other("recipient, source profile or exclusive expiry mismatch").into(),
        );
    }
    let expected = completion(
        options.root,
        ContentDigest::sha256(&media),
        &name,
        media.len(),
    );
    if complete != expected.as_bytes()
        || input.read("record.json", MAX_REPORT_BYTES)? != record.to_json().as_bytes()
    {
        return Err(io::Error::other("export completion or display record mismatch").into());
    }
    input.check_current()?;
    bounded_report(object(&[
        ("format", string("fss.original_media_verification_cli.v1")),
        ("status", string("verified_original_media")),
        ("profile", string(record.profile())),
        ("export_root", string(&options.root.to_text())),
        (
            "media_digest",
            string(&ContentDigest::sha256(&media).to_text()),
        ),
        ("media_filename", string(&name)),
        ("media_bytes", media.len().to_string()),
        ("record", record.to_json()),
        ("root_trust", string("independently_supplied_by_caller")),
        ("current_deployment_state_checked", "false".into()),
        ("recipient_authenticated", "false".into()),
        ("delivery_proven", "false".into()),
        ("external_copies_auto_erased", "false".into()),
    ]))
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    let result = if args.first().and_then(|v| v.to_str()) == Some("media-verify") {
        match parse_verify(args) {
            Ok(options) => run_verify(&options),
            Err(error) => return malformed(&error),
        }
    } else {
        match parse(args) {
            Ok(options) => run(options),
            Err(error) => return malformed(&error),
        }
    };
    match result {
        Ok(report) => match writeln!(io::stdout().lock(), "{report}") {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => {
                eprintln!(
                    "ERR-EXPORT-STORAGE-001: report_output_failed_check_COMPLETE_before_retry"
                );
                ExitCode::from(1)
            }
        },
        Err(error) => {
            if let Some(error) = error.downcast_ref::<OriginalMediaExportError>() {
                eprintln!("{}: {error}", error.stable_id());
            } else if let Some(error) = error.downcast_ref::<file::FileError>() {
                eprintln!("ERR-EXPORT-STORAGE-001: {error}");
            } else {
                eprintln!("ERR-EXPORT-STORAGE-001: original_media_export_or_verification_refused");
            }
            ExitCode::from(1)
        }
    }
}

fn malformed(error: &str) -> ExitCode {
    eprintln!(
        "{}: {error}; use fss-export --help",
        fss_cli::ERR_CLI_MALFORMED_VALUE
    );
    ExitCode::from(2)
}
