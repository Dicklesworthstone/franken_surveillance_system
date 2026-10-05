#![forbid(unsafe_code)]
//! Local alert status and exact-approved cancellation, without dispatch or provider access.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use fss_cli::agent_json::{array, evidence_anchor, object, string};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, DigestAlgorithm, EffectState,
    IndeterminateEffectReason, Obligation, OperationId, OperationReceipt, PrincipalId,
    RootAuthoritySpec, TimestampNs,
};
use fss_reference::agent_orient::{OrientLimits, obligation_state_str, read_deployment};
use fss_reference::alert_control::{
    AlertCancellationPlan, AlertControlError, CAP_ALERT_CANCEL, CAP_ALERT_STATUS,
    MAX_ALERT_OPERATIONS, MAX_CANCEL_PRINCIPAL_BYTES, MAX_CONTROL_JOURNAL_BYTES,
    cancel_prepared_alert, preview_alert_cancellation,
};
use fss_reference::{DeploymentLayout, ReferenceDeployment, ReplayCx};

const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;
const HELP: &str = "fss-alert status --root DIR --site SITE [--operation-id ID]\n\
  fss-alert cancel --root DIR --site SITE --operation-id ID\n\
    [--principal ID] [--approve sha256:APPROVAL]\n\
  status reads a bounded committed snapshot without creating, locking, repairing or\n\
  changing the deployment. It includes durable operation and obligation identities,\n\
  proof digests, and explicit uncommitted-tail warnings. An absent journal is UNKNOWN.\n\
  cancel previews an exact approval unless --approve is supplied. Only a prepared,\n\
  never-committed alert can be cancelled. The old event, source media and relay route\n\
  are not needed. Approval binds the full preparation, actor and physical journals.\n\
  A retained request precedes the terminal journal transition; exact cold retries\n\
  append nothing. A different cancellation is not this request's successful retry.\n\
  Cancellation uses the locked deployment open path, which may conservatively mark\n\
  crash-interrupted committed operations indeterminate during restart recovery.\n\
  No network access, resend, forced failure, acknowledgement or delivery certification.\n\
  Adapter acceptance is not human delivery. Indeterminate sends remain unresolved.\n\
  Requires an existing owner-authorized local deployment. --principal is an audit\n\
  identity, not remote authentication. This process supplies the local cancellation\n\
  capability; the library refuses finite-deadline delegation without a clock owner.\n\
  Limits: 4096 operations/obligations, 64 MiB per journal, 8 MiB complete JSON output.\n\
  Reference implementation, not production-qualified.\n";

type RunResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct Options {
    cancel: bool,
    root: PathBuf,
    site: String,
    principal: String,
    operation: Option<OperationId>,
    approval: Option<ContentDigest>,
}

fn parse(args: &[OsString]) -> Result<Options, String> {
    let command = args.first().and_then(|s| s.to_str()).ok_or("expected status or cancel")?;
    if !matches!(command, "status" | "cancel") || args.len() > 11 {
        return Err("expected bounded status or cancel arguments".into());
    }
    let cancel = command == "cancel";
    let mut values = BTreeMap::new();
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        if !matches!(key, "--root" | "--site" | "--operation-id")
            && !(cancel && matches!(key, "--principal" | "--approve"))
        {
            return Err(format!("unknown or inapplicable option {key}"));
        }
        let value = args.get(index + 1).ok_or_else(|| format!("missing value for {key}"))?;
        if value.is_empty() || value.to_str().is_some_and(|v| v.starts_with("--")) {
            return Err(format!("missing value for {key}"));
        }
        if values.insert(key, value).is_some() {
            return Err(format!("duplicate option {key}"));
        }
        index += 2;
    }
    let text = |key: &str| -> Result<&str, String> {
        values.get(key).ok_or_else(|| format!("required option {key}"))?
            .to_str().ok_or_else(|| format!("{key} requires UTF-8"))
    };
    let root = PathBuf::from(*values.get("--root").ok_or("required option --root")?);
    let site = text("--site")?.to_owned();
    if site.len() > 256 {
        return Err("site lineage exceeds 256 bytes".into());
    }
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = if values.contains_key("--principal") {
        text("--principal")?
    } else {
        "principal:local-operator"
    }.to_owned();
    if principal.len() > MAX_CANCEL_PRINCIPAL_BYTES
        || principal.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err("principal exceeds its bound or contains whitespace/controls".into());
    }
    PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
    let operation = if cancel || values.contains_key("--operation-id") {
        Some(OperationId::parse(text("--operation-id")?).map_err(|_| "invalid operation ID")?)
    } else { None };
    let approval = if values.contains_key("--approve") {
        let digest = ContentDigest::parse(text("--approve")?).map_err(|_| "invalid approval digest")?;
        if digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err("approval requires SHA-256".into());
        }
        Some(digest)
    } else { None };
    Ok(Options { cancel, root, site, principal, operation, approval })
}

fn optional_digest(value: Option<ContentDigest>) -> String {
    value.map_or_else(|| "null".into(), |v| string(&v.to_text()))
}

fn operation_json(op: &OperationReceipt, obligation: &Obligation, complete: bool) -> String {
    let reason = match &op.indeterminate_reason {
        None => object(&[("state", string("not_applicable"))]),
        Some(IndeterminateEffectReason::Unrecorded) => object(&[("state", string("unrecorded_unknown"))]),
        Some(IndeterminateEffectReason::Recorded(value)) => object(&[
            ("state", string("recorded")), ("value", string(value)),
        ]),
    };
    object(&[
        ("operation_id", string(op.intent.operation_id.as_str())),
        ("idempotency_key", string(op.intent.idempotency_key.as_str())),
        ("state", string(op.state.as_str())),
        ("receipt_digest", string(&op.receipt_digest().to_text())),
        ("request_digest", string(&op.intent.request_digest.to_text())),
        ("precondition_digest", string(&op.intent.precondition_digest.to_text())),
        ("prepared_at_ns", string(&op.prepared_at.0.to_string())),
        ("updated_at_ns", string(&op.updated_at.0.to_string())),
        ("committed_at_ns", op.committed_at.map_or_else(|| "null".into(), |t| string(&t.0.to_string()))),
        ("result_digest", optional_digest(op.result_digest)),
        ("recorded_reason", op.error_code.as_deref().map_or_else(|| "null".into(), string)),
        ("indeterminate_reason", reason),
        ("obligation", object(&[
            ("id", string(obligation.obligation_id.as_str())),
            ("state", string(obligation_state_str(obligation.state))),
            ("terminal_predicate", string(&obligation.terminal_predicate)),
            ("proof_digest", optional_digest(obligation.proof_digest)),
        ])),
        ("cancellation_candidate", (complete && op.state == EffectState::Prepared).to_string()),
        ("next_step", string(if !complete {
            "inspect_uncommitted_history_before_any_mutation"
        } else {
            match op.state {
                EffectState::Prepared => "preview_exact_cancellation_or_use_original_dispatch_workflow",
                EffectState::Cancelled => "terminal_local_cancellation_do_not_dispatch",
                EffectState::Verified | EffectState::Failed => "inspect_existing_terminal_proof_do_not_resend",
                _ => "obtain_independent_provider_evidence_do_not_resend_or_force_terminal_state",
            }
        })),
        ("dispatch_authorized", "false".into()),
        ("human_delivery", string("not_inferred_from_local_state")),
    ])
}

fn status(options: &Options) -> RunResult<String> {
    // Deliberately not ReferenceDeployment::open: status cannot trigger restart reclassification.
    // Like fss orient, this is an owner-local read boundary, not a remote authentication service.
    let snapshot = read_deployment(&options.root, &OrientLimits::default())?;
    if snapshot.site_lineage != options.site {
        return Err(io::Error::other("deployment site mismatch").into());
    }
    if snapshot.operations.len() > MAX_ALERT_OPERATIONS || snapshot.obligations.len() > MAX_ALERT_OPERATIONS {
        return Err(AlertControlError::Limit.into());
    }
    let complete = snapshot.effect_journal_present
        && !snapshot.effect_tail_uncommitted && !snapshot.ledger_tail_uncommitted;
    let mut obligations = BTreeMap::new();
    for obligation in &snapshot.obligations {
        if obligations.insert(obligation.operation_id.as_str(), obligation).is_some() {
            return Err(AlertControlError::Inconsistent.into());
        }
    }
    let mut rows = Vec::new();
    let mut bytes = 0;
    for op in &snapshot.operations {
        if op.intent.effect_class != "alert.dispatch"
            || options.operation.as_ref().is_some_and(|id| *id != op.intent.operation_id)
        { continue; }
        let obligation = obligations.get(op.intent.operation_id.as_str())
            .ok_or(AlertControlError::Inconsistent)?;
        let row = operation_json(op, obligation, complete);
        bytes += row.len();
        if bytes > MAX_REPORT_BYTES { return Err(AlertControlError::Limit.into()); }
        rows.push(row);
    }
    if options.operation.is_some() && rows.is_empty() {
        return Err(AlertControlError::NotAlert.into());
    }
    Ok(object(&[
        ("format", string("fss.alert_lifecycle_cli.v1")),
        ("action", string("status")),
        ("site", string(&snapshot.site_lineage)),
        ("anchor", evidence_anchor(&snapshot.anchor)),
        ("effect_journal_root", string(&snapshot.effect_journal_root.to_text())),
        ("effect_journal_present", snapshot.effect_journal_present.to_string()),
        ("ledger_tail_uncommitted", snapshot.ledger_tail_uncommitted.to_string()),
        ("effect_tail_uncommitted", snapshot.effect_tail_uncommitted.to_string()),
        ("inventory", string(if complete { "complete_committed_snapshot" } else { "unknown_beyond_committed_prefix" })),
        ("operation_count", rows.len().to_string()),
        ("operations", array(&rows)),
        ("read_capability", string(CAP_ALERT_STATUS)),
        ("writes", string("none")),
        ("network_access", "false".into()),
        ("qualification", string("implemented_not_qualified")),
    ]))
}

fn shell_arg(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn approval_command(options: &Options, plan: &AlertCancellationPlan) -> Option<String> {
    // Never silently replace OS-path bytes in an executable suggested command.
    Some(format!(
        "fss-alert cancel --root {} --site {} --operation-id {} --principal {} --approve {}",
        shell_arg(options.root.to_str()?), shell_arg(&options.site),
        shell_arg(plan.prepared().intent.operation_id.as_str()), shell_arg(plan.principal()),
        plan.approval_digest().to_text(),
    ))
}

fn plan_json(options: &Options, plan: &AlertCancellationPlan) -> String {
    object(&[
        ("operation_id", string(plan.prepared().intent.operation_id.as_str())),
        ("obligation_id", string(plan.prepared().obligation_id.as_str())),
        ("prepared_record_digest", string(&plan.prepared().prepared_record_digest().to_text())),
        ("principal", string(plan.principal())),
        ("evidence_digest", string(&plan.evidence_digest().to_text())),
        ("expected_cancellation_proof", string(&plan.proof_digest().to_text())),
        ("approval_digest", string(&plan.approval_digest().to_text())),
        ("approve_command", approval_command(options, plan).map_or_else(|| "null".into(), |s| string(&s))),
        ("command_encoding", string(if options.root.to_str().is_some() {
            "posix_shell_quoted"
        } else { "non_utf8_root_reuse_original_command_and_append_approval" })),
        ("approval_is_authority", "false".into()),
    ])
}

fn preflight(options: &Options) -> RunResult<()> {
    if !fs::symlink_metadata(&options.root)?.file_type().is_dir() {
        return Err(io::Error::other("existing regular deployment root required").into());
    }
    let layout = options.root.join("LAYOUT");
    let metadata = fs::symlink_metadata(&layout)?;
    if !metadata.file_type().is_file() || metadata.len() > 64 * 1024 {
        return Err(io::Error::other("regular bounded deployment LAYOUT required").into());
    }
    let mut layout_bytes = Vec::new();
    fs::File::open(layout)?.take(64 * 1024 + 1).read_to_end(&mut layout_bytes)?;
    if layout_bytes.len() > 64 * 1024 {
        return Err(AlertControlError::Limit.into());
    }
    let layout = DeploymentLayout::parse_canonical_text(std::str::from_utf8(&layout_bytes)?)?;
    if layout.site_lineage != options.site {
        return Err(io::Error::other("deployment site mismatch").into());
    }
    for name in ["ledger/journal.fssj", "effects/journal.fssj"] {
        let metadata = fs::symlink_metadata(options.root.join(name))?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_CONTROL_JOURNAL_BYTES {
            return Err(AlertControlError::Limit.into());
        }
    }
    Ok(())
}

fn cancel(options: &Options) -> RunResult<String> {
    let operation = options.operation.as_ref().ok_or(AlertControlError::NotAlert)?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:alert-control-cli".into(),
        operation_id: OperationId::parse("operation:alert-control-cli")?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into(), CAP_ALERT_CANCEL.into()],
        deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(MAX_REPORT_BYTES as u64).storage_operations(8192).build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()), generation: 1,
    })?;
    // ReplayCx may create its root; refuse nonexistent or foreign deployments before constructing it.
    preflight(options)?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())?;
    let result = (|| -> RunResult<String> {
        let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)?;
        let (plan, outcome, state) = match options.approval {
            None => {
                let plan = preview_alert_cancellation(&deployment, operation, &authority, &cx)?;
                let receipt = deployment.effects().operation(operation).ok_or(AlertControlError::NotAlert)?;
                let obligation = deployment.effects().obligation(&plan.prepared().obligation_id)
                    .ok_or(AlertControlError::Inconsistent)?;
                let state = operation_json(receipt, obligation, true);
                (plan, "proposed", state)
            }
            Some(approval) => {
                cx.checkpoint("alert_cancel:journal_time")?;
                let now = TimestampNs(i128::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?);
                let receipt = cancel_prepared_alert(&mut deployment, operation, approval, now, &authority, &cx)?;
                let state = operation_json(&receipt.operation, &receipt.obligation, true);
                (receipt.plan, receipt.outcome.as_str(), state)
            }
        };
        Ok(object(&[
            ("format", string("fss.alert_lifecycle_cli.v1")),
            ("action", string("cancel")),
            ("site", string(&options.site)),
            ("anchor", evidence_anchor(deployment.current_anchor())),
            ("effect_journal_root", string(&deployment.effects().last_root().to_text())),
            ("outcome", string(outcome)),
            ("plan", plan_json(options, &plan)),
            ("operation", state),
            ("new_cancellation_committed", (outcome == "cancelled").to_string()),
            ("deployment_open_may_perform_restart_recovery", "true".into()),
            ("network_access", "false".into()),
            ("qualification", string("implemented_not_qualified")),
        ]))
    })();
    cx.drain_and_finalize();
    result
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let help = matches!(args.as_slice(), [flag] if matches!(flag.to_str(), Some("--help" | "-h" | "help")))
        || matches!(args.as_slice(), [command, flag] if matches!(command.to_str(), Some("status" | "cancel")) && matches!(flag.to_str(), Some("--help" | "-h")));
    if help {
        return if io::stdout().lock().write_all(HELP.as_bytes()).is_ok() {
            ExitCode::from(ExitIdentity::SUCCESS.code)
        } else { ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code) };
    }
    let options = match parse(&args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {error}; use fss-alert --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let result = if options.cancel { cancel(&options) } else { status(&options) };
    match result {
        Ok(json) if json.len() <= MAX_REPORT_BYTES => {
            if writeln!(io::stdout().lock(), "{json}").is_ok() {
                ExitCode::from(ExitIdentity::SUCCESS.code)
            } else { ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code) }
        }
        Ok(_) => {
            eprintln!("{ERR_CLI_RUNTIME_FAILURE}: complete alert report exceeds output bound");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
        Err(error) => {
            eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
            if let Some(control) = error.downcast_ref::<AlertControlError>() {
                eprintln!("refusal_id={}", control.stable_id());
            }
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}
