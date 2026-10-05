#![forbid(unsafe_code)]
//! Portable redacted export handoff and offline, independently root-pinned verification.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_cli::agent_json::{object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, DigestAlgorithm, OperationId, PrincipalId,
    TimestampNs,
};
use fss_reference::evidence_export::{CAP_EXPORT_COMMIT, CAP_EXPORT_PREPARE, ExportError};
use fss_reference::export_package::{
    MAX_PACKAGE_BYTES, PackageError, PackageScope, VerifiedPackage, prepare_package, verify_package,
};
use fss_reference::{DeploymentLayout, ReferenceDeployment, ReplayCx};

#[path = "fss-export-package/file.rs"]
mod file;

const HELP: &str = "fss-export-package pack --root DIR --site SITE --export-root sha256:HEX\n\
  --recipient LABEL --attested-now-ns EARLIEST:LATEST --out FILE\n\
  [--principal ID] [--approve sha256:EXACT_FILE_APPROVAL]\n\
Packages an ALREADY COMMITTED fss-export event root, never an unapproved preview.\n\
Without --approve: reports the exact file approval; no output file is created.\n\
Approval binds the package, recipient, time bounds, actor and actual destination directory.\n\
Writes require Linux x86-64/aarch64, /proc, and an existing directory outside the deployment.\n\
The destination directory must not be group- or world-writable. New files use mode 0600.\n\
The final name is create-only; exact-byte retries are idempotent, conflicts never overwrite.\n\
Opening the existing deployment may perform its normal restart reconciliation.\n\
\n\
fss-export-package verify --input FILE --export-root sha256:TRUSTED_ROOT\n\
  --recipient LABEL --attested-now-ns EARLIEST:LATEST\n\
Offline verification opens no deployment and makes no network request. Supply the root through\n\
an independent trusted channel, not from the package being checked. Recipient is a label, not\n\
authentication. Both current-time bounds must precede exclusive expiry. No host clock is read.\n\
Packages contain redacted event METADATA ONLY, not playable footage or a general archive.\n\
Hash verification is not a signature, current-state proof, physical truth or delivery proof.\n\
The package is plaintext; expiry does not erase existing copies.\n";
const MAX_REPORT_BYTES: usize = 512 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
type RunResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct Pack {
    root: PathBuf,
    site: String,
    principal: String,
    export_root: ContentDigest,
    scope: PackageScope,
    output: PathBuf,
    approval: Option<ContentDigest>,
}
#[derive(Debug)]
enum Options {
    Pack(Pack),
    Verify {
        input: PathBuf,
        export_root: ContentDigest,
        scope: PackageScope,
    },
}

fn digest(value: &str) -> Result<ContentDigest, String> {
    if value.len() > 80 {
        return Err("digest exceeds bound".into());
    }
    let digest = ContentDigest::parse(value).map_err(|_| "expected sha256:HEX")?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err("nonzero SHA-256 root or approval required".into());
    }
    Ok(digest)
}
fn text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .ok_or_else(|| format!("required option {key}"))?
        .to_str()
        .ok_or_else(|| format!("{key} requires UTF-8"))
}
fn path(values: &BTreeMap<String, OsString>, key: &str) -> Result<PathBuf, String> {
    let value = values.get(key).ok_or_else(|| format!("required option {key}"))?;
    if value.as_encoded_bytes().len() > 4096 {
        return Err(format!("{key} exceeds path bound"));
    }
    Ok(PathBuf::from(value))
}
fn parse(args: &[OsString]) -> Result<Options, String> {
    let command = args.first().and_then(|v| v.to_str()).ok_or("pack or verify required")?;
    if !matches!(command, "pack" | "verify") || args.len() > 21 {
        return Err("expected bounded pack or verify command".into());
    }
    let mut values = BTreeMap::new();
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        let common = matches!(key, "--export-root" | "--recipient" | "--attested-now-ns");
        let allowed = common || match command {
            "pack" => matches!(key, "--root" | "--site" | "--principal" | "--out" | "--approve"),
            "verify" => key == "--input",
            _ => false,
        };
        if !allowed {
            return Err(format!("unknown or inapplicable option {key}"));
        }
        let value = args.get(index + 1).ok_or_else(|| format!("missing value for {key}"))?;
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
    let times = text(&values, "--attested-now-ns")?;
    if times.len() > 81 {
        return Err("current-time interval exceeds bound".into());
    }
    let (earliest, latest) = times.split_once(':').ok_or("current time requires EARLIEST:LATEST")?;
    let earliest = earliest.parse::<i128>().map_err(|_| "invalid earliest current time")?;
    let latest = latest.parse::<i128>().map_err(|_| "invalid latest current time")?;
    let scope = PackageScope {
        recipient: text(&values, "--recipient")?.to_owned(),
        attested_now: CaptureInterval::new(TimestampNs(earliest), TimestampNs(latest))
            .map_err(|_| "inverted current-time interval")?,
    };
    scope.validate().map_err(|e| e.to_string())?;
    let export_root = digest(text(&values, "--export-root")?)?;
    if command == "verify" {
        return Ok(Options::Verify { input: path(&values, "--input")?, export_root, scope });
    }
    let site = text(&values, "--site")?.to_owned();
    if site.len() > 256 {
        return Err("site exceeds bound".into());
    }
    fss_reference::reference_deployment::validate_site_lineage(&site).map_err(|_| "invalid site")?;
    let principal = if values.contains_key("--principal") {
        text(&values, "--principal")?
    } else {
        "principal:local-operator"
    }.to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
    let approval = if values.contains_key("--approve") {
        Some(digest(text(&values, "--approve")?)?)
    } else {
        None
    };
    Ok(Options::Pack(Pack {
        root: path(&values, "--root")?,
        site,
        principal,
        export_root,
        scope,
        output: path(&values, "--out")?,
        approval,
    }))
}

fn report(verified: &VerifiedPackage, scope: &PackageScope, status: &str) -> String {
    object(&[
        ("format", string("fss.export_package_report.v1")),
        ("status", string(status)),
        ("export_root", string(&verified.root().to_text())),
        ("package_digest", string(&verified.package_digest().to_text())),
        ("record_digest", string(&verified.record().digest().to_text())),
        ("recipient", string(&scope.recipient)),
        ("attested_now_earliest_ns", string(&scope.attested_now.earliest.0.to_string())),
        ("attested_now_latest_ns", string(&scope.attested_now.latest.0.to_string())),
        ("expiry_interpretation", string("exclusive_under_supplied_time_bounds_not_a_trusted_clock")),
        ("verification_claim", string("exact_record_and_manifest_match_independently_supplied_root")),
        ("signature_verified", "false".into()),
        ("current_ledger_state_verified_offline", "false".into()),
        ("recipient_authenticated", "false".into()),
        ("raw_media_included", "false".into()),
        ("network_transport_performed", "false".into()),
        ("encrypted", "false".into()),
        ("package", verified.record().to_redacted_json()),
        ("qualification", string("implemented_not_qualified")),
    ])
}
fn bounded_report(report: String) -> RunResult<String> {
    if report.len() > MAX_REPORT_BYTES {
        return Err(PackageError::Limit.into());
    }
    Ok(report)
}

fn preflight(root: &Path, site: &str) -> RunResult<PathBuf> {
    if !fs::symlink_metadata(root)?.file_type().is_dir() {
        return Err(io::Error::other("existing non-symlink deployment directory required").into());
    }
    let root = fs::canonicalize(root)?;
    let layout = file::read_bounded(&root.join("LAYOUT"), 4096)?;
    let layout = DeploymentLayout::parse_canonical_text(std::str::from_utf8(&layout)?)?;
    if layout.site_lineage != site {
        return Err(PackageError::Unauthorized.into());
    }
    for relative in [layout.ledger_relpath, layout.effects_relpath] {
        let metadata = fs::symlink_metadata(root.join(relative))?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_JOURNAL_BYTES {
            return Err(io::Error::other("regular bounded existing journal required").into());
        }
    }
    Ok(root)
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
fn approve_command(options: &Pack, root: &Path, output: &Path, approval: ContentDigest) -> Option<String> {
    Some(format!(
        "fss-export-package pack --root {} --site {} --principal {} --export-root {} --recipient {} --attested-now-ns {} --out {} --approve {}",
        quote(root.to_str()?), quote(&options.site), quote(&options.principal),
        options.export_root, quote(&options.scope.recipient),
        quote(&format!("{}:{}", options.scope.attested_now.earliest.0, options.scope.attested_now.latest.0)),
        quote(output.to_str()?), approval,
    ))
}

fn run_pack(options: &Pack) -> RunResult<String> {
    let root = preflight(&options.root, &options.site)?;
    let target = file::Target::new(&options.output, &root)?;
    // This explicitly invoked local-owner adapter is not remote authentication. It may read the
    // original owner's approved export; the new file effect additionally needs exact approval.
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:export-package-cli".into(),
        operation_id: OperationId::parse("operation:export-package-cli")?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into(), CAP_EXPORT_PREPARE.into(), CAP_EXPORT_COMMIT.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(128 * 1024 * 1024).storage_operations(65_536).build()?,
        privacy_scope: "privacy:redacted-event-export-v1".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let result = (|| -> RunResult<String> {
        let deployment = ReferenceDeployment::open(&root, &options.site, &cx)?;
        let package = prepare_package(&deployment, options.export_root, &options.scope, &authority, &cx)?;
        let approval = target.approval(&package, &options.scope, &options.principal, &options.site)?;
        let details = report(package.verified(), &options.scope, "verified_committed_export_for_copy");
        // Bound every complete report BEFORE the external output filename can become visible.
        let render = |status: &str, cleanup: bool| -> RunResult<String> {
            bounded_report(object(&[
                ("format", string("fss.export_package_file_report.v1")),
                ("status", string(status)),
                ("approval_digest", string(&approval.to_text())),
                ("approve_command", approve_command(options, &root, target.path(), approval)
                    .as_deref().map_or_else(|| "null".into(), string)),
                ("output", target.path().to_str().map_or_else(|| "null".into(), string)),
                ("package_bytes", package.bytes().len().to_string()),
                ("temporary_cleanup_pending", cleanup.to_string()),
                ("deployment_open_may_reconcile", "true".into()),
                ("copy_receipt_in_deployment", "false".into()),
                ("delivery_verified", "false".into()),
                ("details", details.clone()),
            ]))
        };
        let proposed = render("proposed", false)?;
        let created = render("created", false)?;
        let existing = render("already_present", false)?;
        let created_cleanup_pending = render("created", true)?;
        let existing_cleanup_pending = render("already_present", true)?;
        let Some(given) = options.approval else { return Ok(proposed); };
        if given != approval {
            return Err(ExportError::StaleApproval.into());
        }
        let receipt = file::publish(&target, package.bytes(), |stage| {
            cx.checkpoint(stage).map_err(|_| file::FileError::Cancelled)
        })?;
        cx.checkpoint_post_commit("export_package:file_complete");
        Ok(match (receipt.already_present, receipt.temporary_cleanup_pending) {
            (false, false) => created,
            (true, false) => existing,
            (false, true) => created_cleanup_pending,
            (true, true) => existing_cleanup_pending,
        })
    })();
    cx.drain_and_finalize();
    result
}

fn run(options: &Options) -> RunResult<String> {
    match options {
        Options::Pack(options) => run_pack(options),
        Options::Verify { input, export_root, scope } => {
            let bytes = file::read_bounded(input, MAX_PACKAGE_BYTES)?;
            let verified = verify_package(&bytes, *export_root, scope)?;
            bounded_report(report(&verified, scope, "verified_against_supplied_root"))
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }
    let options = match parse(&args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("refusal_id={}\nreason={error}", fss_cli::ERR_CLI_MALFORMED_VALUE);
            return ExitCode::from(2);
        }
    };
    match run(&options) {
        Ok(report) => {
            let mut output = io::stdout().lock();
            match writeln!(output, "{report}") {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => {
                    eprintln!("refusal_id=ERR-EXPORT-STORAGE-001\nreason=report_output_failed_check_output_file_before_retry");
                    ExitCode::from(1)
                }
            }
        }
        Err(error) => {
            if let Some(package) = error.downcast_ref::<PackageError>() {
                eprintln!("refusal_id={}\nreason={}", package.stable_id(), package.reason());
            } else if let Some(export) = error.downcast_ref::<ExportError>() {
                eprintln!("refusal_id={}\nreason={export}", export.stable_id());
            } else if let Some(file) = error.downcast_ref::<file::FileError>() {
                let id = if matches!(file, file::FileError::Cancelled) { "ERR-EXPORT-CANCELLED-001" }
                    else { "ERR-EXPORT-STORAGE-001" };
                eprintln!("refusal_id={id}\nreason={}", file.reason());
            } else {
                eprintln!("refusal_id=ERR-EXPORT-STORAGE-001\nreason=package_storage_or_deployment_refusal");
            }
            ExitCode::from(1)
        }
    }
}
