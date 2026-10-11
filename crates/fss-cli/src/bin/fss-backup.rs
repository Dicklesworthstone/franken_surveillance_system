#![forbid(unsafe_code)]
//! Operator-local current-format recovery, with separate explicit original custody authority.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_cli::ERR_CLI_MALFORMED_VALUE;
use fss_cli::agent_json::{evidence_anchor, object, string};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, DigestAlgorithm, OperationId, PrincipalId,
    RootAuthoritySpec,
};
use fss_reference::deployment_backup::{
    BACKUP_PROFILE, BackupAccess, BackupAuthority, BackupError, BackupLimits, BackupManifest,
    RestoreReceipt, create_backup, inspect_backup, prepare_backup, restore_backup,
};
use fss_reference::{ADP_REPLAY_ROW_ID, DeploymentLimits, ReplayCx};

const FORMAT: &str = "fss.deployment_backup_report.v1";
const MAX_ARGS: usize = 49;
const MAX_ARG_BYTES: usize = 4096;
const MAX_REPORT_BYTES: usize = 16 * 1024;
const RESTORE_REPORT_RESERVE: usize = 2048;
const HELP: &str = "fss-backup plan --root DEPLOYMENT --allow-originals [LIMITS]\n\
fss-backup create --root DEPLOYMENT --bundle NEW_BUNDLE --expect sha256:HEX --allow-originals [LIMITS]\n\
fss-backup inspect --bundle BUNDLE --expect sha256:HEX --allow-originals [BACKUP_LIMITS]\n\
fss-backup restore --bundle BUNDLE --root NEW_DEPLOYMENT --expect sha256:HEX --allow-originals [BACKUP_LIMITS]\n\
\n\
  Profile: reference-core-local-v1. Captures the exact current-format core journals,\n\
  objects, publication records, holds and deletion state. Unsupported populated\n\
  state, including independent agent journals, is refused, never silently omitted.\n\
  Source must be quiescent with no pending recovery. New destinations only.\n\
  Create/restore require Linux x86_64 or aarch64 with descriptor-pinned writes.\n\
  Bundles retain unredacted original evidence: --allow-originals explicitly grants\n\
  local original reads and the selected copy destination for this invocation.\n\
  A replay context alone never grants that access. There is no remote export.\n\
\n\
  Plan reports an independent manifest digest without changing the deployment.\n\
  Retain and verify that digest separately before create, inspect or restore.\n\
  Creation publishes MANIFEST last. Bundle payloads cannot be opened as live\n\
  deployments. Restore verifies the complete bundle, preserves the source history\n\
  prefix, and appends a permanent alert-effect fence before activating LAYOUT.\n\
  Restored alerts cannot be prepared, dispatched or falsely cancelled. There is\n\
  no automatic failover, schema migration, effect reconciliation or unfence here.\n\
\n\
  All commands emit a bounded metadata-only JSON report. Optional: --json,\n\
  --principal PRINCIPAL (default operator:local-backup). No object bytes are printed.\n\
  BACKUP_LIMITS: --max-files N --max-file-bytes N --max-total-bytes N\n\
                --max-manifest-bytes N --max-journal-bytes N\n\
  Additional plan/create LIMITS (must exactly match the deployment's LAYOUT):\n\
    --spool-object-max-bytes N --spool-total-max-bytes N --manifest-children-max N\n\
    --batch-entries-max N --journal-record-max-bytes N --max-roots N\n\
    --max-tombstones N --spool-max-objects N --scan-max-objects N\n\
  Absent deployment limits use the standard deployment limits. Inspect/restore\n\
  use the full limits committed in the pinned manifest and refuse overrides.\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    Plan,
    Create,
    Inspect,
    Restore,
}

#[derive(Debug)]
struct Request {
    action: Action,
    root: Option<PathBuf>,
    bundle: Option<PathBuf>,
    expected: Option<ContentDigest>,
    principal: String,
    deployment_limits: DeploymentLimits,
    limits: BackupLimits,
}

#[derive(Debug)]
enum Error {
    Usage(&'static str),
    Backup(BackupError),
    Context,
    Output,
}
impl From<BackupError> for Error {
    fn from(error: BackupError) -> Self {
        Self::Backup(error)
    }
}
fn text(value: &OsStr) -> Result<&str, Error> {
    value
        .to_str()
        .filter(|value| !value.is_empty())
        .ok_or(Error::Usage("a nonempty UTF-8 option value is required"))
}
fn number(value: &OsStr, maximum: u64) -> Result<u64, Error> {
    let value = text(value)?;
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Usage(
            "numeric limits require positive decimal integers",
        ));
    }
    let n = value
        .parse::<u64>()
        .map_err(|_| Error::Usage("numeric limit overflow"))?;
    if n == 0 || n > maximum {
        return Err(Error::Usage("numeric limit exceeds its bounds"));
    }
    Ok(n)
}
fn parse(args: &[OsString]) -> Result<Option<Request>, Error> {
    if args.len() > MAX_ARGS
        || args
            .iter()
            .any(|arg| arg.as_encoded_bytes().len() > MAX_ARG_BYTES)
    {
        return Err(Error::Usage("argument count or length exceeds its bound"));
    }
    if args.len() == 1 && matches!(args[0].to_str(), Some("help" | "--help" | "-h")) {
        return Ok(None);
    }
    let action = match args.first().and_then(|arg| arg.to_str()) {
        Some("plan") => Action::Plan,
        Some("create") => Action::Create,
        Some("inspect") => Action::Inspect,
        Some("restore") => Action::Restore,
        _ => return Err(Error::Usage("expected plan, create, inspect or restore")),
    };
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h")) {
        return Ok(None);
    }
    let (mut root, mut bundle, mut expected) = (None, None, None);
    let mut principal = "operator:local-backup".to_owned();
    let mut deployment_limits = DeploymentLimits::standard();
    let mut limits = BackupLimits::default();
    let mut seen = BTreeSet::new();
    let mut allowed = false;
    let mut at = 1;
    while at < args.len() {
        let key = text(&args[at])?;
        if !seen.insert(key) {
            return Err(Error::Usage("duplicate singleton option"));
        }
        at += 1;
        if key == "--allow-originals" {
            allowed = true;
            continue;
        }
        if key == "--json" {
            continue;
        }
        let value = args.get(at).ok_or(Error::Usage("missing option value"))?;
        if value.is_empty() || value.to_str().is_some_and(|s| s.starts_with("--")) {
            return Err(Error::Usage("missing option value"));
        }
        at += 1;
        match key {
            "--root" => root = Some(PathBuf::from(value)),
            "--bundle" => bundle = Some(PathBuf::from(value)),
            "--expect" => {
                let digest = ContentDigest::parse(text(value)?)
                    .map_err(|_| Error::Usage("invalid manifest digest"))?;
                if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
                    return Err(Error::Usage(
                        "manifest pin requires a nonzero SHA-256 digest",
                    ));
                }
                expected = Some(digest);
            }
            "--principal" => {
                let value = text(value)?;
                PrincipalId::parse(value).map_err(|_| Error::Usage("invalid principal"))?;
                principal = value.to_owned();
            }
            "--max-files" => limits.max_files = number(value, 262_144)? as usize,
            "--max-file-bytes" => limits.max_file_bytes = number(value, 256 * 1024 * 1024 + 52)?,
            "--max-total-bytes" => limits.max_total_bytes = number(value, 4 * 1024 * 1024 * 1024)?,
            "--max-manifest-bytes" => {
                limits.max_manifest_bytes = number(value, 64 * 1024 * 1024)? as usize
            }
            "--max-journal-bytes" => {
                limits.max_journal_bytes = number(value, 256 * 1024 * 1024)? as usize
            }
            "--spool-object-max-bytes"
            | "--spool-total-max-bytes"
            | "--manifest-children-max"
            | "--batch-entries-max"
            | "--journal-record-max-bytes"
            | "--max-roots"
            | "--max-tombstones"
            | "--spool-max-objects"
            | "--scan-max-objects" => {
                if !matches!(action, Action::Plan | Action::Create) {
                    return Err(Error::Usage(
                        "inspect and restore use retained deployment limits; overrides are refused",
                    ));
                }
                match key {
                    "--spool-object-max-bytes" => {
                        deployment_limits.spool_object_max_bytes = number(value, 256 * 1024 * 1024)?
                    }
                    "--spool-total-max-bytes" => {
                        deployment_limits.spool_total_max_bytes =
                            number(value, 4 * 1024 * 1024 * 1024)?
                    }
                    "--manifest-children-max" => {
                        deployment_limits.manifest_children_max = number(value, 16_384)? as usize
                    }
                    "--batch-entries-max" => {
                        deployment_limits.batch_entries_max = number(value, 16_384)? as usize
                    }
                    "--journal-record-max-bytes" => {
                        deployment_limits.journal_record_max_bytes =
                            number(value, 16 * 1024 * 1024)? as u32
                    }
                    "--max-roots" => deployment_limits.max_roots = number(value, 65_536)? as usize,
                    "--max-tombstones" => {
                        deployment_limits.max_tombstones = number(value, 65_536)? as usize
                    }
                    "--spool-max-objects" => {
                        deployment_limits.spool_max_objects = number(value, 65_536)? as usize
                    }
                    "--scan-max-objects" => {
                        deployment_limits.scan_max_objects = number(value, 262_144)? as usize
                    }
                    _ => return Err(Error::Usage("unknown deployment limit")),
                }
            }
            _ => return Err(Error::Usage("unknown option")),
        }
    }
    if !allowed {
        return Err(Error::Usage(
            "--allow-originals is required for explicit original-custody access",
        ));
    }
    match action {
        Action::Plan if root.is_none() || bundle.is_some() || expected.is_some() => {
            return Err(Error::Usage(
                "plan requires --root and refuses --bundle or --expect",
            ));
        }
        Action::Create | Action::Restore
            if root.is_none() || bundle.is_none() || expected.is_none() =>
        {
            return Err(Error::Usage(
                "create and restore require --root, --bundle and --expect",
            ));
        }
        Action::Inspect if bundle.is_none() || expected.is_none() || root.is_some() => {
            return Err(Error::Usage(
                "inspect requires --bundle and --expect and refuses --root",
            ));
        }
        _ => {}
    }
    deployment_limits
        .to_publication_limits()
        .validate()
        .map_err(|_| Error::Usage("inconsistent deployment limits"))?;
    Ok(Some(Request {
        action,
        root,
        bundle,
        expected,
        principal,
        deployment_limits,
        limits,
    }))
}

/// The parser only constructs Request after explicit --allow-originals. This immutable grant
/// is scoped to this action, these paths and this independent pin; ReplayCx is a separate gate.
struct LocalGrant<'a>(&'a Request);
impl BackupAuthority for LocalGrant<'_> {
    fn permit(&self, access: BackupAccess<'_>) -> bool {
        let r = self.0;
        match access {
            BackupAccess::ReadDeployment { source } => {
                matches!(r.action, Action::Plan | Action::Create)
                    && r.root.as_deref() == Some(source)
            }
            BackupAccess::WriteBundle {
                source,
                bundle,
                manifest,
            } => {
                r.action == Action::Create
                    && r.root.as_deref() == Some(source)
                    && r.bundle.as_deref() == Some(bundle)
                    && r.expected == Some(manifest)
            }
            BackupAccess::ReadBundle { bundle, manifest } => {
                matches!(r.action, Action::Inspect | Action::Restore)
                    && r.bundle.as_deref() == Some(bundle)
                    && r.expected == Some(manifest)
            }
            BackupAccess::RestoreDeployment {
                bundle,
                destination,
                manifest,
            } => {
                r.action == Action::Restore
                    && r.bundle.as_deref() == Some(bundle)
                    && r.root.as_deref() == Some(destination)
                    && r.expected == Some(manifest)
            }
        }
    }
}
fn backup_limits(l: BackupLimits) -> String {
    object(&[
        ("max_files", l.max_files.to_string()),
        ("max_file_bytes", l.max_file_bytes.to_string()),
        ("max_total_bytes", l.max_total_bytes.to_string()),
        ("max_manifest_bytes", l.max_manifest_bytes.to_string()),
        ("max_journal_bytes", l.max_journal_bytes.to_string()),
    ])
}
fn deployment_limits(l: &DeploymentLimits) -> String {
    object(&[
        (
            "spool_object_max_bytes",
            l.spool_object_max_bytes.to_string(),
        ),
        ("spool_total_max_bytes", l.spool_total_max_bytes.to_string()),
        ("manifest_children_max", l.manifest_children_max.to_string()),
        ("batch_entries_max", l.batch_entries_max.to_string()),
        (
            "journal_record_max_bytes",
            l.journal_record_max_bytes.to_string(),
        ),
        ("max_roots", l.max_roots.to_string()),
        ("max_tombstones", l.max_tombstones.to_string()),
        ("spool_max_objects", l.spool_max_objects.to_string()),
        ("scan_max_objects", l.scan_max_objects.to_string()),
    ])
}
fn report(
    r: &Request,
    status: &str,
    manifest: &BackupManifest,
    restored: Option<&RestoreReceipt>,
) -> String {
    object(&[
        ("format", string(FORMAT)),
        ("status", string(status)),
        ("profile", string(BACKUP_PROFILE)),
        ("manifest_digest", string(&manifest.digest().to_text())),
        ("site", string(manifest.site())),
        ("source_anchor", evidence_anchor(manifest.source_anchor())),
        (
            "source_ledger_root",
            string(&manifest.ledger_root().to_text()),
        ),
        (
            "source_effects_root",
            string(&manifest.effects_root().to_text()),
        ),
        ("file_count", manifest.file_count().to_string()),
        ("total_bytes", manifest.total_bytes().to_string()),
        (
            "deployment_limits",
            deployment_limits(manifest.deployment_limits()),
        ),
        ("backup_limits", backup_limits(r.limits)),
        (
            "restoration",
            restored.map_or_else(
                || "null".to_owned(),
                |receipt| {
                    object(&[
                        (
                            "destination_anchor",
                            evidence_anchor(receipt.destination_anchor()),
                        ),
                        (
                            "destination_ledger_root",
                            string(&receipt.destination_ledger_root().to_text()),
                        ),
                        ("fence_digest", string(&receipt.fence_digest().to_text())),
                        ("alert_effects_disabled", "true".to_owned()),
                        ("effect_reconciliation_performed", "false".to_owned()),
                    ])
                },
            ),
        ),
    ])
}
fn path<'a>(value: &'a Option<PathBuf>) -> Result<&'a Path, Error> {
    value
        .as_deref()
        .ok_or(Error::Usage("required path is absent"))
}
fn pin(r: &Request) -> Result<ContentDigest, Error> {
    r.expected
        .ok_or(Error::Usage("independent manifest digest is absent"))
}
fn preflight_report(r: &Request, manifest: &BackupManifest) -> Result<(), Error> {
    // Bound the complete eventual output BEFORE any publication. Anchor/digest encodings have
    // fixed bounds; the only restored strings are the already bounded site and canonical hashes.
    if report(r, "verified", manifest, None).len() + RESTORE_REPORT_RESERVE > MAX_REPORT_BYTES {
        return Err(Error::Output);
    }
    Ok(())
}
fn run_with(r: &Request, cx: &ReplayCx) -> Result<String, Error> {
    let grant = LocalGrant(r);
    match r.action {
        Action::Plan => {
            let manifest =
                prepare_backup(path(&r.root)?, r.deployment_limits, r.limits, &grant, cx)?;
            preflight_report(r, &manifest)?;
            Ok(report(r, "planned", &manifest, None))
        }
        Action::Create => {
            let manifest =
                prepare_backup(path(&r.root)?, r.deployment_limits, r.limits, &grant, cx)?;
            if manifest.digest() != pin(r)? {
                return Err(BackupError::Changed.into());
            }
            preflight_report(r, &manifest)?;
            let receipt = create_backup(
                path(&r.root)?,
                path(&r.bundle)?,
                pin(r)?,
                r.deployment_limits,
                r.limits,
                &grant,
                cx,
            )?;
            Ok(report(r, "created", receipt.manifest(), None))
        }
        Action::Inspect => {
            let manifest = inspect_backup(path(&r.bundle)?, pin(r)?, r.limits, &grant, cx)?;
            preflight_report(r, &manifest)?;
            Ok(report(r, "verified", &manifest, None))
        }
        Action::Restore => {
            let manifest = inspect_backup(path(&r.bundle)?, pin(r)?, r.limits, &grant, cx)?;
            preflight_report(r, &manifest)?;
            let receipt = restore_backup(
                path(&r.bundle)?,
                path(&r.root)?,
                pin(r)?,
                r.limits,
                &grant,
                cx,
            )?;
            Ok(report(r, "restored", receipt.manifest(), Some(&receipt)))
        }
    }
}
fn run(r: &Request) -> Result<String, Error> {
    // ReplayIoAuthority may create its scratch root. Use the existing working directory,
    // never a source or a fresh destination; all selected custody is authorized by LocalGrant.
    let context_root = std::env::current_dir().map_err(|_| Error::Context)?;
    // Mutating commands preflight the complete report and then perform a separately bounded
    // pinned transfer. Declare both semantic-read allowances in the execution context.
    let passes = if matches!(r.action, Action::Create | Action::Restore) {
        2
    } else {
        1
    };
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:backup-cli".into(),
        operation_id: OperationId::parse("operation:backup-cli").map_err(|_| Error::Context)?,
        principal: r.principal.clone(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(
                r.limits
                    .max_total_bytes
                    .saturating_mul(16)
                    .saturating_add(r.limits.max_manifest_bytes as u64 * 4)
                    .saturating_mul(passes),
            )
            .storage_operations((r.limits.max_files as u64 * 128 + 10_000) * passes)
            .build()
            .map_err(|_| Error::Context)?,
        privacy_scope: "privacy:local-explicit-originals".into(),
        retention_scope: "retention:local-explicit-backup-destination".into(),
        anchor_universe: r
            .expected
            .unwrap_or_else(|| ContentDigest::sha256(b"fss:backup-plan:unselected")),
        generation: 1,
    })
    .map_err(|_| Error::Context)?;
    let cx =
        ReplayCx::from_context_authority(&authority, context_root).map_err(|_| Error::Context)?;
    let result = run_with(r, &cx);
    cx.drain_and_finalize();
    result
}
fn error_code(error: &BackupError) -> &'static str {
    match error {
        BackupError::Unauthorized => "ERR-BACKUP-AUTHORITY-001",
        BackupError::Cancelled => "ERR-BACKUP-CANCELLED-001",
        BackupError::Locked => "ERR-BACKUP-LOCKED-001",
        BackupError::Limit(_) => "ERR-BACKUP-LIMIT-001",
        BackupError::Unsupported(_) => "ERR-BACKUP-PROFILE-001",
        BackupError::Corrupt(_) => "ERR-BACKUP-VERIFY-001",
        BackupError::RecoveryRequired(_) => "ERR-BACKUP-RECOVERY-001",
        BackupError::Changed => "ERR-BACKUP-PIN-001",
        BackupError::DestinationExists => "ERR-BACKUP-DESTINATION-001",
        BackupError::InvalidPath => "ERR-BACKUP-PATH-001",
        BackupError::Io(_) => "ERR-BACKUP-IO-001",
        BackupError::Indeterminate => "ERR-BACKUP-INDETERMINATE-001",
    }
}
fn failure(error: Error) -> (String, u8) {
    let status = if matches!(&error, Error::Backup(BackupError::Indeterminate)) {
        "indeterminate"
    } else {
        "refused"
    };
    let (code, reason, message, exit) = match &error {
        Error::Usage(message) => (ERR_CLI_MALFORMED_VALUE, "invalid_backup_request", (*message).to_owned(), 2),
        Error::Backup(BackupError::Indeterminate) => ("ERR-BACKUP-INDETERMINATE-001", "backup_activation_indeterminate",
            "activation may have completed; inspect the exact destination and retained manifest before retrying".to_owned(), 1),
        Error::Backup(error) => (error_code(error), error.reason(), error.to_string(), 1),
        Error::Context => ("ERR-BACKUP-AUTHORITY-001", "backup_context_refused", "local execution context unavailable".to_owned(), 1),
        Error::Output => ("ERR-BACKUP-LIMIT-001", "backup_report_bound", "complete report exceeds its output bound".to_owned(), 1),
    };
    (
        object(&[
            ("format", string(FORMAT)),
            ("status", string(status)),
            ("error_id", string(code)),
            ("reason", string(reason)),
            ("message", string(&message)),
        ]),
        exit,
    )
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(MAX_ARGS + 1).collect();
    let result = parse(&args).and_then(|request| match request {
        None => Ok(None),
        Some(r) => run(&r).map(Some),
    });
    let (output, exit) = match result {
        Ok(None) => (HELP.to_owned(), 0),
        Ok(Some(report)) => (format!("{report}\n"), 0),
        Err(error) => {
            let (report, exit) = failure(error);
            (format!("{report}\n"), exit)
        }
    };
    if io::stdout().lock().write_all(output.as_bytes()).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::from(exit)
}
