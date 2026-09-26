#![forbid(unsafe_code)]
//! `fss-event delete`: graph-complete deletion closure of one retained import, or of every
//! retained import of one sensor or one event (FSS-037).
//!
//! `plan` is read-only (`CAP-DELETE-PREPARE-001`): exactly one of `--import-id`, `--sensor-id`
//! or `--event-id` names the scope; it prints the sealed, digest-bound deletion plan (the scope
//! kind and identity are inside the digest), its exact approval and the rerun command, and writes
//! nothing. `commit`
//! (`CAP-DELETE-COMMIT-001`) revalidates the plan against the current head (any change is a stale
//! plan), appends the deletion record first, unlinks, verifies and appends the completion record;
//! a rerun of the same commit resumes and completes exactly once. Removal is unlinking from the
//! local filesystem, never cryptographic erasure.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use fss_cli::escape_json_str;
use fss_core::region::ContextAuthority;
use fss_core::{ContentDigest, DigestAlgorithm, EventId, PrincipalId, SensorId};
use fss_reference::deletion::{
    CommitReceipt, DELETION_COMPLETION_DOMAIN, DELETION_MECHANISM, DELETION_OUT_OF_SCOPE,
    DELETION_SCOPE_COMPLETION_DOMAIN, DeletionPlan, DeletionScope, Finding, commit_deletion,
    plan_scope_deletion,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::RunResult;

/// Capability of `delete plan`.
pub(super) const CAP_DELETE_PREPARE: &str = "CAP-DELETE-PREPARE-001";
/// Capability of `delete commit`.
pub(super) const CAP_DELETE_COMMIT: &str = "CAP-DELETE-COMMIT-001";

/// What the command does.
#[derive(Debug)]
pub(super) enum Operation {
    /// Read-only plan of one scope (an import, a sensor or an event).
    Plan {
        /// What the plan deletes.
        scope: DeletionScope,
    },
    /// Execute (or resume) one sealed plan under its exact approval.
    Commit {
        /// Sealed plan digest.
        plan: ContentDigest,
        /// Exact approval digest.
        approve: ContentDigest,
    },
}

/// Fully parsed request.
#[derive(Debug)]
pub(super) struct DeleteAction {
    pub(super) root: PathBuf,
    pub(super) site: String,
    pub(super) principal: String,
    pub(super) operation: Operation,
}

fn sha256(value: &str, key: &str) -> Result<ContentDigest, String> {
    let digest = ContentDigest::parse(value).map_err(|_| format!("invalid digest for {key}"))?;
    if digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err(format!("{key} requires SHA-256"));
    }
    Ok(digest)
}

/// Parses the arguments after `delete`.
pub(super) fn parse(args: &[OsString]) -> Result<DeleteAction, String> {
    let operation = args
        .first()
        .and_then(|a| a.to_str())
        .ok_or("delete requires plan or commit")?;
    if !matches!(operation, "plan" | "commit") {
        return Err("delete requires plan or commit".to_owned());
    }
    let mut values: Vec<(String, String)> = Vec::new();
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        let argument = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {key}"))?
            .to_str()
            .ok_or_else(|| format!("{key} requires a UTF-8 value"))?;
        if argument.is_empty() || argument.starts_with("--") {
            return Err(format!("missing value for {key}"));
        }
        let allowed = matches!(key, "--root" | "--site" | "--principal")
            || (operation == "plan" && matches!(key, "--import-id" | "--sensor-id" | "--event-id"))
            || (operation == "commit" && matches!(key, "--plan" | "--approve"));
        if !allowed {
            return Err("unknown or inapplicable option".to_owned());
        }
        if values.iter().any(|(k, _)| k == key) {
            return Err(format!("duplicate {key}"));
        }
        values.push((key.to_owned(), argument.to_owned()));
        index += 2;
    }
    let text = |key: &str| -> Result<&str, String> {
        values
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .ok_or_else(|| format!("required option {key}"))
    };
    let site = text("--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal =
        text("--principal").map_or_else(|_| "principal:local-operator".to_owned(), str::to_owned);
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let operation = if operation == "plan" {
        let named: Vec<&str> = ["--import-id", "--sensor-id", "--event-id"]
            .into_iter()
            .filter(|key| values.iter().any(|(k, _)| k == key))
            .collect();
        let scope = match named.as_slice() {
            ["--import-id"] => DeletionScope::Import(sha256(text("--import-id")?, "--import-id")?),
            ["--sensor-id"] => DeletionScope::Sensor(
                SensorId::parse(text("--sensor-id")?).map_err(|_| "invalid sensor ID")?,
            ),
            ["--event-id"] => DeletionScope::Event(
                EventId::parse(text("--event-id")?).map_err(|_| "invalid event ID")?,
            ),
            [] => return Err("required option --import-id, --sensor-id or --event-id".to_owned()),
            _ => {
                return Err(
                    "--import-id, --sensor-id and --event-id are mutually exclusive".to_owned(),
                );
            }
        };
        Operation::Plan { scope }
    } else {
        Operation::Commit {
            plan: sha256(text("--plan")?, "--plan")?,
            approve: sha256(text("--approve")?, "--approve")?,
        }
    };
    Ok(DeleteAction {
        root: PathBuf::from(text("--root")?),
        site,
        principal,
        operation,
    })
}

fn quote(text: &str) -> String {
    format!("\"{}\"", escape_json_str(text))
}

fn findings(items: &[Finding]) -> String {
    let rendered: Vec<String> = items
        .iter()
        .map(|f| {
            format!(
                "{{\"kind\":{},\"subject\":{},\"detail\":{}}}",
                quote(&f.kind),
                quote(&f.subject),
                quote(&f.detail)
            )
        })
        .collect();
    format!("[{}]", rendered.join(","))
}

fn scope_json(scope: &DeletionScope, imports: &[ContentDigest]) -> String {
    let members: Vec<String> = imports.iter().map(|d| format!("\"{d}\"")).collect();
    format!(
        "\"scope\":{{\"kind\":\"{}\",\"id\":{},\"text\":{}}},\"import_identity\":{},\"imports\":[{}]",
        scope.kind(),
        quote(&scope.id()),
        quote(&scope.text()),
        match scope {
            DeletionScope::Import(import) => format!("\"{import}\""),
            DeletionScope::Sensor(_) | DeletionScope::Event(_) => "null".to_owned(),
        },
        members.join(",")
    )
}

fn out_of_scope() -> String {
    let items: Vec<String> = DELETION_OUT_OF_SCOPE.iter().map(|s| quote(s)).collect();
    format!("[{}]", items.join(","))
}

fn quote_arg(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:,./=@+".contains(&b))
    {
        argument.to_owned()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

fn plan_json(action: &DeleteAction, plan: &DeletionPlan) -> RunResult<String> {
    let digest = plan.digest()?;
    let approval = plan.approval_digest(&action.principal)?;
    let blocked = !plan.blockers.is_empty();
    let command = if blocked {
        "null".to_owned()
    } else {
        quote(&format!(
            "fss-event delete commit --root {} --site {} --principal {} --plan {digest} --approve {approval}",
            quote_arg(&action.root.to_string_lossy()),
            quote_arg(&action.site),
            quote_arg(&action.principal)
        ))
    };
    let units: Vec<String> = plan
        .units
        .iter()
        .map(|u| {
            format!(
                "{{\"id\":{},\"kind\":{},\"class\":{},\"via\":\"{}\"}}",
                quote(&u.id),
                quote(&u.kind),
                quote(&u.class),
                u.via
            )
        })
        .collect();
    let deletable: Vec<String> = plan
        .deletable
        .iter()
        .map(|o| format!("{{\"digest\":\"{}\",\"bytes\":{}}}", o.digest, o.bytes))
        .collect();
    let retained: Vec<String> = plan
        .retained
        .iter()
        .map(|o| {
            format!(
                "{{\"digest\":\"{}\",\"reason\":{}}}",
                o.digest,
                quote(&o.reason)
            )
        })
        .collect();
    let tombstones: Vec<String> = plan
        .tombstones
        .iter()
        .map(|t| {
            format!(
                "{{\"object_id\":{},\"prior_generation\":{},\"plane\":\"{}\"}}",
                quote(&t.object_id),
                t.prior_generation,
                t.plane.as_str()
            )
        })
        .collect();
    let retractions: Vec<String> = plan
        .retractions
        .iter()
        .map(|r| {
            format!(
                "{{\"slot\":{},\"root\":\"{}\",\"prior_generation\":{}}}",
                quote(&r.slot),
                r.root,
                r.prior_generation
                    .map_or_else(|| "null".to_owned(), |g| g.to_string())
            )
        })
        .collect();
    let events: Vec<String> = plan
        .events
        .iter()
        .map(|e| {
            format!(
                "{{\"object_id\":{},\"latest_revision\":{},\"history\":\"retained\",\"evidence_availability\":\"deleted\"}}",
                quote(&e.object_id),
                e.latest_revision
            )
        })
        .collect();
    Ok(format!(
        "{{\"format\":\"{}\",\"status\":\"{}\",\"site_lineage\":{},{},\"plan_digest\":\"{digest}\",\"approval_digest\":\"{approval}\",\"approve_command\":{command},\"basis\":{{\"authority_sequence\":{},\"state_root\":\"{}\",\"effect_journal_root\":\"{}\"}},\"scanned\":{{\"objects\":{},\"bytes\":{}}},\"counts\":{{\"units\":{},\"deletable_objects\":{},\"deletable_bytes\":{},\"retained_objects\":{},\"ledger_tombstones\":{},\"root_retractions\":{},\"events_retained\":{},\"blockers\":{},\"unknown_copies\":{}}},\"units\":[{}],\"deletable\":[{}],\"retained\":[{}],\"tombstone_batch\":{{\"batch_id\":{},\"deltas\":{},\"tombstones\":[{}],\"retractions\":[{}]}},\"events\":[{}],\"blockers\":{},\"unknown_copies\":{},\"unattributed\":{{\"staging_files\":{},\"staging_bytes\":{},\"objects\":{},\"object_bytes\":{},\"deleted_by_this_plan\":false}},\"hold_registry\":\"enforced_import_closure_v1\",\"mechanism\":\"{DELETION_MECHANISM}\",\"cryptographic_erasure\":false,\"out_of_scope\":{},\"writes\":\"none\"}}\n",
        plan.domain(),
        if blocked { "blocked" } else { "planned" },
        quote(&plan.site_lineage),
        scope_json(&plan.scope, &plan.imports),
        plan.basis_anchor.commit_sequence,
        plan.basis_anchor.state_root,
        plan.effect_journal_root,
        plan.scanned_objects,
        plan.scanned_bytes,
        plan.units.len(),
        plan.deletable.len(),
        plan.deletable_bytes(),
        plan.retained.len(),
        plan.tombstones.len(),
        plan.retractions.len(),
        plan.events.len(),
        plan.blockers.len(),
        plan.unknown_copies.len(),
        units.join(","),
        deletable.join(","),
        retained.join(","),
        quote(&DeletionPlan::record_batch_id(digest)),
        plan.tombstones.len() + plan.retractions.len() + 1,
        tombstones.join(","),
        retractions.join(","),
        events.join(","),
        findings(&plan.blockers),
        findings(&plan.unknown_copies),
        plan.unattributed.staging_files,
        plan.unattributed.staging_bytes,
        plan.unattributed.objects,
        plan.unattributed.object_bytes,
        out_of_scope(),
    ))
}

fn completion_json(receipt: &CommitReceipt) -> String {
    let c = &receipt.completion;
    format!(
        "{{\"format\":\"{}\",\"outcome\":\"{}\",{},\"plan_digest\":\"{}\",\"completion_digest\":\"{}\",\"record_batch\":{},\"completion_batch\":{},\"objects_unlinked\":{},\"bytes_unlinked\":{},\"removal_verified\":\"every_removed_name_absent_from_local_spool\",\"roots_retracted\":{},\"ledger_objects_tombstoned\":{},\"objects_retained\":{},\"events_with_deleted_evidence\":{},\"blocked\":{},\"not_proven\":{},\"mechanism\":\"{DELETION_MECHANISM}\",\"cryptographic_erasure\":false,\"out_of_scope\":{},\"authority_sequence\":{}}}\n",
        match c.scope {
            DeletionScope::Import(_) => DELETION_COMPLETION_DOMAIN,
            DeletionScope::Sensor(_) | DeletionScope::Event(_) => DELETION_SCOPE_COMPLETION_DOMAIN,
        },
        receipt.outcome.as_str(),
        scope_json(&c.scope, &c.imports),
        receipt.plan_digest,
        receipt.completion_digest,
        quote(&DeletionPlan::record_batch_id(receipt.plan_digest)),
        quote(&DeletionPlan::completion_batch_id(receipt.plan_digest)),
        c.objects_unlinked,
        c.bytes_unlinked,
        c.roots_retracted,
        c.ledger_objects_tombstoned,
        c.objects_retained,
        c.events_with_deleted_evidence,
        findings(&c.blocked),
        findings(&c.not_proven),
        out_of_scope(),
        receipt.authority_sequence
    )
}

/// Plans or commits, and prints the JSON report.
pub(super) fn run(
    action: &DeleteAction,
    deployment: &mut ReferenceDeployment,
    authority: &ContextAuthority,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let required = match action.operation {
        Operation::Plan { .. } => CAP_DELETE_PREPARE,
        Operation::Commit { .. } => CAP_DELETE_COMMIT,
    };
    if !authority.has_capability(required) {
        return Err(
            std::io::Error::other(format!("ERR-AUTH-DENIED-001: {required} not granted")).into(),
        );
    }
    let json = match &action.operation {
        Operation::Plan { scope } => {
            let plan = plan_scope_deletion(deployment, scope, cx)?;
            plan_json(action, &plan)?
        }
        Operation::Commit { plan, approve } => {
            let receipt = commit_deletion(deployment, *plan, *approve, &action.principal, cx)?;
            completion_json(&receipt)
        }
    };
    out.write_all(json.as_bytes())?;
    Ok(())
}
