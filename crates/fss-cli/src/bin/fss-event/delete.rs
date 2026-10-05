#![forbid(unsafe_code)]
//! `fss-event delete`: graph-complete, exactly approved local deletion.
//!
//! Legacy plan/commit retain their semantics. `retention-plan` and `retention-commit` additionally
//! require a sensor, a positive --retain-for-ns and --attested-now-ns EARLIEST:LATEST. They select
//! whole recordings by conservative capture bounds, then use one existing union deletion.
//! Source gaps and unknown time retain recordings; active holds block the whole cohort.
//! No standing policy changes, host clock reads, automatic hold releases or remote erasure.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use fss_cli::escape_json_str;
use fss_core::region::ContextAuthority;
use fss_core::{CaptureInterval, ContentDigest, DigestAlgorithm, EventId, PrincipalId, SensorId, TimestampNs};
use fss_reference::deletion::{
    CommitReceipt, DELETION_MECHANISM, DELETION_OUT_OF_SCOPE, DeletionError,
    DeletionPlan, DeletionScope, Finding, commit_deletion, plan_scope_deletion,
};
use fss_reference::deletion::retention::{
    RetentionRequest, RetentionSelection, commit_retention, plan_retention,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::RunResult;

/// Capability of `delete plan` and `delete retention-plan`.
pub(super) const CAP_DELETE_PREPARE: &str = "CAP-DELETE-PREPARE-001";
/// Capability of `delete commit` and `delete retention-commit`.
pub(super) const CAP_DELETE_COMMIT: &str = "CAP-DELETE-COMMIT-001";
const MAX_RETENTION_REPORT_BYTES: usize = 64 * 1024 * 1024;

/// What the command does. Retention uses the same preparation/commit capability split.
#[derive(Debug)]
pub(super) enum Operation {
    /// Read-only plan. For retention the action's request selects a subset of this sensor.
    Plan {
        /// Scope for legacy planning; never used to widen an age-based request.
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

/// Fully parsed request; no I/O occurs until all retention arguments are valid.
#[derive(Debug)]
pub(super) struct DeleteAction {
    pub(super) root: PathBuf,
    pub(super) site: String,
    pub(super) principal: String,
    pub(super) operation: Operation,
    retention: Option<RetentionRequest>,
}

fn sha256(value: &str, key: &str) -> Result<ContentDigest, String> {
    let digest = ContentDigest::parse(value).map_err(|_| format!("invalid digest for {key}"))?;
    if digest.algorithm() != DigestAlgorithm::Sha256 { return Err(format!("{key} requires SHA-256")); }
    Ok(digest)
}

/// Parses the arguments after `delete`.
pub(super) fn parse(args: &[OsString]) -> Result<DeleteAction, String> {
    let command = args.first().and_then(|a| a.to_str())
        .ok_or("delete requires plan, commit, retention-plan or retention-commit")?;
    if !matches!(command, "plan" | "commit" | "retention-plan" | "retention-commit") {
        return Err("delete requires plan, commit, retention-plan or retention-commit".to_owned());
    }
    let is_retention = matches!(command, "retention-plan" | "retention-commit");
    let is_plan = matches!(command, "plan" | "retention-plan");
    let mut values: Vec<(String, String)> = Vec::new();
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        let argument = args.get(index + 1).ok_or_else(|| format!("missing value for {key}"))?
            .to_str().ok_or_else(|| format!("{key} requires a UTF-8 value"))?;
        if argument.is_empty() || argument.starts_with("--") { return Err(format!("missing value for {key}")); }
        let allowed = matches!(key, "--root" | "--site" | "--principal")
            || (command == "plan" && matches!(key, "--import-id" | "--sensor-id" | "--event-id"))
            || (!is_plan && matches!(key, "--plan" | "--approve"))
            || (is_retention && matches!(key, "--sensor-id" | "--retain-for-ns" | "--attested-now-ns"));
        if !allowed { return Err("unknown or inapplicable option".to_owned()); }
        if values.iter().any(|(k, _)| k == key) { return Err(format!("duplicate {key}")); }
        values.push((key.to_owned(), argument.to_owned()));
        index += 2;
    }
    let text = |key: &str| -> Result<&str, String> {
        values.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
            .ok_or_else(|| format!("required option {key}"))
    };
    let site = text("--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site).map_err(|_| "invalid site lineage")?;
    let principal = text("--principal").map_or_else(|_| "principal:local-operator".to_owned(), str::to_owned);
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let retention = if is_retention {
        let sensor = SensorId::parse(text("--sensor-id")?).map_err(|_| "invalid sensor ID")?;
        let duration = text("--retain-for-ns")?.parse::<u64>()
            .map_err(|_| "--retain-for-ns requires positive integer nanoseconds")?;
        let (first, last) = text("--attested-now-ns")?.split_once(':')
            .ok_or("--attested-now-ns requires EARLIEST:LATEST signed nanoseconds")?;
        let first = first.parse::<i128>().map_err(|_| "invalid earliest attested time")?;
        let last = last.parse::<i128>().map_err(|_| "invalid latest attested time")?;
        let now = CaptureInterval::new(TimestampNs(first), TimestampNs(last))
            .map_err(|_| "attested current-time bounds are inverted")?;
        Some(RetentionRequest::new(sensor, duration, now)
            .map_err(|_| "retention duration must be positive and time bounds ordered")?)
    } else { None };
    let operation = if is_plan {
        let scope = if let Some(request) = &retention {
            // The run path uses the explicit retention request, never this entire-sensor scope.
            DeletionScope::Sensor(request.sensor().clone())
        } else {
            let named: Vec<&str> = ["--import-id", "--sensor-id", "--event-id"].into_iter()
                .filter(|key| values.iter().any(|(k, _)| k == key)).collect();
            match named.as_slice() {
                ["--import-id"] => DeletionScope::Import(sha256(text("--import-id")?, "--import-id")?),
                ["--sensor-id"] => DeletionScope::Sensor(SensorId::parse(text("--sensor-id")?).map_err(|_| "invalid sensor ID")?),
                ["--event-id"] => DeletionScope::Event(EventId::parse(text("--event-id")?).map_err(|_| "invalid event ID")?),
                [] => return Err("required option --import-id, --sensor-id or --event-id".to_owned()),
                _ => return Err("--import-id, --sensor-id and --event-id are mutually exclusive".to_owned()),
            }
        };
        Operation::Plan { scope }
    } else {
        Operation::Commit { plan: sha256(text("--plan")?, "--plan")?, approve: sha256(text("--approve")?, "--approve")? }
    };
    Ok(DeleteAction { root: PathBuf::from(text("--root")?), site, principal, operation, retention })
}

fn quote(text: &str) -> String { format!("\"{}\"", escape_json_str(text)) }

fn findings(items: &[Finding]) -> String {
    let rendered: Vec<String> = items.iter().map(|f| {
        format!("{{\"kind\":{},\"subject\":{},\"detail\":{}}}", quote(&f.kind), quote(&f.subject), quote(&f.detail))
    }).collect();
    format!("[{}]", rendered.join(","))
}

fn retention_json(selection: &RetentionSelection) -> String {
    let request = selection.request();
    let now = request.attested_now();
    let candidates: Vec<String> = selection.candidates().iter().map(|c| {
        let end = c.capture_end().map_or_else(|| "null".to_owned(), |end| {
            format!("{{\"earliest_ns\":\"{}\",\"latest_ns\":\"{}\"}}", end.earliest_ns, end.latest_ns)
        });
        format!("{{\"import_identity\":\"{}\",\"manifest_digest\":\"{}\",\"timing_digest\":\"{}\",\"capture_end\":{},\"disposition\":\"{}\"}}",
            c.import_identity(), c.manifest_digest(), c.timing_digest(), end, c.disposition().as_str())
    }).collect();
    format!("{{\"format\":\"fss.retention_selection.v1\",\"sensor_id\":{},\"retain_for_ns\":\"{}\",\"attested_now\":{{\"earliest_ns\":\"{}\",\"latest_ns\":\"{}\"}},\"time_provenance\":\"owner_assertions_not_observed_clock\",\"eligibility\":\"latest_capture_plus_retention_not_after_earliest_attested_now\",\"candidates\":[{}],\"standing_policy_changed\":false,\"holds_released\":false}}",
        quote(request.sensor().as_str()), request.retain_for_ns(), now.earliest.0, now.latest.0, candidates.join(","))
}

fn scope_json(scope: &DeletionScope, imports: &[ContentDigest]) -> String {
    let members: Vec<String> = imports.iter().map(|d| format!("\"{d}\"")).collect();
    let mut json = format!(
        "\"scope\":{{\"kind\":\"{}\",\"id\":{},\"text\":{}}},\"import_identity\":{},\"imports\":[{}]",
        scope.kind(), quote(&scope.id()), quote(&scope.text()),
        match scope { DeletionScope::Import(import) => format!("\"{import}\""), _ => "null".to_owned() },
        members.join(",")
    );
    if let DeletionScope::Retention(selection) = scope {
        json.push_str(&format!(",\"retention_selection\":{}", retention_json(selection)));
    }
    json
}

fn out_of_scope() -> String {
    let items: Vec<String> = DELETION_OUT_OF_SCOPE.iter().map(|s| quote(s)).collect();
    format!("[{}]", items.join(","))
}

fn quote_arg(argument: &str) -> String {
    if !argument.is_empty() && argument.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_:,./=@+".contains(&b)) {
        argument.to_owned()
    } else { format!("'{}'", argument.replace('\'', "'\\''")) }
}

fn plan_json(action: &DeleteAction, plan: &DeletionPlan) -> RunResult<String> {
    let digest = plan.digest()?;
    let approval = plan.approval_digest(&action.principal)?;
    let blocked = !plan.blockers.is_empty();
    let command = if blocked { "null".to_owned() } else {
        let (verb, parameters) = match &plan.scope {
            DeletionScope::Retention(selection) => {
                let request = selection.request();
                let now = request.attested_now();
                ("retention-commit", format!(" --sensor-id {} --retain-for-ns {} --attested-now-ns {}:{}",
                    quote_arg(request.sensor().as_str()), request.retain_for_ns(), now.earliest.0, now.latest.0))
            }
            _ => ("commit", String::new()),
        };
        quote(&format!(
            "fss-event delete {verb} --root {} --site {} --principal {}{parameters} --plan {digest} --approve {approval}",
            quote_arg(&action.root.to_string_lossy()), quote_arg(&action.site), quote_arg(&action.principal)
        ))
    };
    let units: Vec<String> = plan.units.iter().map(|u| {
        format!("{{\"id\":{},\"kind\":{},\"class\":{},\"via\":\"{}\"}}", quote(&u.id), quote(&u.kind), quote(&u.class), u.via)
    }).collect();
    let deletable: Vec<String> = plan.deletable.iter()
        .map(|o| format!("{{\"digest\":\"{}\",\"bytes\":{}}}", o.digest, o.bytes)).collect();
    let retained: Vec<String> = plan.retained.iter()
        .map(|o| format!("{{\"digest\":\"{}\",\"reason\":{}}}", o.digest, quote(&o.reason))).collect();
    let tombstones: Vec<String> = plan.tombstones.iter().map(|t| {
        format!("{{\"object_id\":{},\"prior_generation\":{},\"plane\":\"{}\"}}", quote(&t.object_id), t.prior_generation, t.plane.as_str())
    }).collect();
    let retractions: Vec<String> = plan.retractions.iter().map(|r| {
        format!("{{\"slot\":{},\"root\":\"{}\",\"prior_generation\":{}}}", quote(&r.slot), r.root,
            r.prior_generation.map_or_else(|| "null".to_owned(), |g| g.to_string()))
    }).collect();
    let events: Vec<String> = plan.events.iter().map(|e| {
        format!("{{\"object_id\":{},\"latest_revision\":{},\"history\":\"retained\",\"evidence_availability\":\"deleted\"}}",
            quote(&e.object_id), e.latest_revision)
    }).collect();
    Ok(format!(
        "{{\"format\":\"{}\",\"status\":\"{}\",\"site_lineage\":{},{},\"plan_digest\":\"{digest}\",\"approval_digest\":\"{approval}\",\"approve_command\":{command},\"basis\":{{\"authority_sequence\":{},\"state_root\":\"{}\",\"effect_journal_root\":\"{}\"}},\"scanned\":{{\"objects\":{},\"bytes\":{}}},\"counts\":{{\"units\":{},\"deletable_objects\":{},\"deletable_bytes\":{},\"retained_objects\":{},\"ledger_tombstones\":{},\"root_retractions\":{},\"events_retained\":{},\"blockers\":{},\"unknown_copies\":{}}},\"units\":[{}],\"deletable\":[{}],\"retained\":[{}],\"tombstone_batch\":{{\"batch_id\":{},\"deltas\":{},\"tombstones\":[{}],\"retractions\":[{}]}},\"events\":[{}],\"blockers\":{},\"unknown_copies\":{},\"unattributed\":{{\"staging_files\":{},\"staging_bytes\":{},\"objects\":{},\"object_bytes\":{},\"deleted_by_this_plan\":false}},\"hold_registry\":\"enforced_import_closure_v1\",\"mechanism\":\"{DELETION_MECHANISM}\",\"cryptographic_erasure\":false,\"out_of_scope\":{},\"writes\":\"none\"}}\n",
        plan.domain(), if blocked { "blocked" } else { "planned" }, quote(&plan.site_lineage),
        scope_json(&plan.scope, &plan.imports), plan.basis_anchor.commit_sequence, plan.basis_anchor.state_root,
        plan.effect_journal_root, plan.scanned_objects, plan.scanned_bytes, plan.units.len(), plan.deletable.len(),
        plan.deletable_bytes(), plan.retained.len(), plan.tombstones.len(), plan.retractions.len(), plan.events.len(),
        plan.blockers.len(), plan.unknown_copies.len(), units.join(","), deletable.join(","), retained.join(","),
        quote(&DeletionPlan::record_batch_id(digest)), plan.tombstones.len() + plan.retractions.len() + 1,
        tombstones.join(","), retractions.join(","), events.join(","), findings(&plan.blockers), findings(&plan.unknown_copies),
        plan.unattributed.staging_files, plan.unattributed.staging_bytes, plan.unattributed.objects,
        plan.unattributed.object_bytes, out_of_scope(),
    ))
}

fn completion_json(receipt: &CommitReceipt) -> String {
    let c = &receipt.completion;
    format!(
        "{{\"format\":\"{}\",\"outcome\":\"{}\",{},\"plan_digest\":\"{}\",\"completion_digest\":\"{}\",\"record_batch\":{},\"completion_batch\":{},\"objects_unlinked\":{},\"bytes_unlinked\":{},\"removal_verified\":\"every_removed_name_absent_from_local_spool\",\"roots_retracted\":{},\"ledger_objects_tombstoned\":{},\"objects_retained\":{},\"events_with_deleted_evidence\":{},\"blocked\":{},\"not_proven\":{},\"mechanism\":\"{DELETION_MECHANISM}\",\"cryptographic_erasure\":false,\"out_of_scope\":{},\"authority_sequence\":{}}}\n",
        c.domain(), receipt.outcome.as_str(), scope_json(&c.scope, &c.imports), receipt.plan_digest,
        receipt.completion_digest, quote(&DeletionPlan::record_batch_id(receipt.plan_digest)),
        quote(&DeletionPlan::completion_batch_id(receipt.plan_digest)), c.objects_unlinked, c.bytes_unlinked,
        c.roots_retracted, c.ledger_objects_tombstoned, c.objects_retained, c.events_with_deleted_evidence,
        findings(&c.blocked), findings(&c.not_proven), out_of_scope(), receipt.authority_sequence
    )
}

fn retention_preview(action: &DeleteAction, deployment: &ReferenceDeployment,
    request: &RetentionRequest, cx: &ReplayCx) -> RunResult<String>
{
    let preview = plan_retention(deployment, request, cx)?;
    let assessment = &preview.assessment;
    let status = match &preview.deletion {
        Some(plan) if !plan.blockers.is_empty() => "blocked",
        Some(_) => "planned",
        None => "nothing_eligible",
    };
    let plan = match &preview.deletion { Some(plan) => plan_json(action, plan)?, None => "null".to_owned() };
    let selection_passes = if preview.deletion.is_some() { 2_u64 } else { 1_u64 };
    Ok(format!("{{\"format\":\"fss.retention_cleanup_preview.v1\",\"status\":\"{status}\",\"selection\":{},\"selector_work\":{{\"passes\":{selection_passes},\"ledger_entries\":{},\"capsules\":{},\"metadata_bytes\":{}}},\"outside_sensor_imports\":{},\"incomplete_imports_not_selected\":{},\"deletion_plan\":{},\"writes\":\"none\",\"qualification\":\"implemented_not_qualified\"}}\n",
        retention_json(&assessment.selection), assessment.ledger_entries * selection_passes,
        assessment.capsules * selection_passes, assessment.metadata_bytes * selection_passes,
        assessment.outside_sensor, assessment.incomplete_imports, plan.trim()))
}

/// Plans or commits and buffers the complete JSON report before writing stdout.
pub(super) fn run(action: &DeleteAction, deployment: &mut ReferenceDeployment,
    authority: &ContextAuthority, cx: &ReplayCx, out: &mut impl Write) -> RunResult<()>
{
    let required = match action.operation {
        Operation::Plan { .. } => CAP_DELETE_PREPARE,
        Operation::Commit { .. } => CAP_DELETE_COMMIT,
    };
    if !authority.has_capability(required) {
        return Err(std::io::Error::other(format!("ERR-AUTH-DENIED-001: {required} not granted")).into());
    }
    let json = match (&action.operation, &action.retention) {
        (Operation::Plan { .. }, Some(request)) => retention_preview(action, deployment, request, cx)?,
        (Operation::Commit { plan, approve }, Some(request)) => {
            let receipt = commit_retention(deployment, request, *plan, *approve, &action.principal, cx)?;
            completion_json(&receipt)
        }
        (Operation::Plan { scope }, None) => {
            let plan = plan_scope_deletion(deployment, scope, cx)?;
            plan_json(action, &plan)?
        }
        (Operation::Commit { plan, approve }, None) => {
            let receipt = commit_deletion(deployment, *plan, *approve, &action.principal, cx)?;
            completion_json(&receipt)
        }
    };
    if action.retention.is_some() && json.len() > MAX_RETENTION_REPORT_BYTES {
        return Err(DeletionError::Bound { limit: "retention_report_bytes" }.into());
    }
    out.write_all(json.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arguments(command: &str) -> Vec<OsString> {
        [command, "--root", "not-opened", "--site", "site:test"].into_iter().map(Into::into).collect()
    }
    fn retention_arguments(command: &str) -> Vec<OsString> {
        let mut args = arguments(command);
        args.extend(["--sensor-id", "sensor:a", "--retain-for-ns", "10", "--attested-now-ns", "-10:20"].into_iter().map(OsString::from));
        args
    }
    #[test]
    fn retention_requires_explicit_complete_request_before_io() -> Result<(), String> {
        assert!(parse(&arguments("retention-plan")).is_err());
        let args = retention_arguments("retention-plan");
        let action = parse(&args)?;
        assert!(matches!(action.operation, Operation::Plan { .. }));
        let request = action.retention.ok_or("missing request")?;
        assert_eq!(request.sensor().as_str(), "sensor:a");
        assert_eq!(request.attested_now().earliest.0, -10);
        assert_eq!(request.attested_now().latest.0, 20);
        Ok(())
    }
    #[test]
    fn malformed_retention_time_duration_duplicates_and_other_scopes_refuse() {
        for (key, value) in [("--retain-for-ns", "0"), ("--retain-for-ns", "-1"),
            ("--attested-now-ns", "20:10"), ("--attested-now-ns", "0:1:2"), ("--attested-now-ns", "NaN:1")] {
            let mut args = retention_arguments("retention-plan");
            for index in 0..args.len() - 1 {
                if args[index] == key { args[index + 1] = value.into(); break; }
            }
            assert!(parse(&args).is_err());
        }
        for (key, value) in [("--sensor-id", "sensor:b"), ("--event-id", "event:a"), ("--approve", "bad")] {
            let mut args = retention_arguments("retention-plan");
            args.extend([key.into(), value.into()]);
            assert!(parse(&args).is_err());
        }
    }
    #[test]
    fn retention_commit_requires_both_exact_digests() -> Result<(), String> {
        let mut args = retention_arguments("retention-commit");
        assert!(parse(&args).is_err());
        let digest = ContentDigest::sha256(b"plan").to_text();
        args.extend(["--plan".into(), digest.clone().into()]);
        assert!(parse(&args).is_err());
        args.extend(["--approve".into(), digest.into()]);
        assert!(matches!(parse(&args)?.operation, Operation::Commit { .. }));
        Ok(())
    }
    #[test]
    fn legacy_commands_do_not_silently_accept_retention_semantics() -> Result<(), String> {
        let mut args = arguments("plan");
        args.extend(["--sensor-id".into(), "sensor:a".into()]);
        assert!(parse(&args)?.retention.is_none());
        args.extend(["--retain-for-ns".into(), "10".into()]);
        assert!(parse(&args).is_err());
        Ok(())
    }
}
