#![forbid(unsafe_code)]
//! `fss-event alert`: prepare, then commit and dispatch exactly one webhook for a corroborated
//! event, each step under its own exact approval.
//!
//! 1. Without `--approve`, the alert plan is computed against current authority in a scratch
//!    journal (nothing durable) and its plan digest is reported with the exact command to prepare.
//! 2. `--approve PLAN` durably prepares the intent in the deployment's effect journal (idempotency
//!    key, operation and terminal-proof obligation recorded) and reports the dispatch digest, which
//!    binds the prepared record, the relay route, the principal and the explicit deadline.
//! 3. `--approve PLAN --dispatch DISPATCH` commits the prepared operation durably BEFORE any network
//!    I/O and sends one request through `WebhookAttempt` under [`CliWebhookOwner`], a restrictive
//!    `WebhookAuthority`, then records the local observation. A complete 2xx head is recorded as
//!    `adapter_accepted`: relay acceptance only, never human delivery. A lost acknowledgement,
//!    timeout, refusal or malformed response is recorded as `indeterminate` and exits nonzero.
//!
//! A rerun after commit never resends: the journal holds the operation in a non-prepared state and
//! the command only reports it. The operation identity is derived from the exact event revision
//! and relay route, so the same request cannot be prepared twice under different identities.

use std::ffi::OsString;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use fss_cli::alert_effect::{
    AlertIdentities, alert_identities, dispatch_approval_digest, dispatch_prepared_alert,
    not_eligible, obligation_state, outcome_text, plan_approval_digest, wall_ns,
};
use fss_core::region::ContextAuthority;
use fss_core::{
    ContentDigest, DigestAlgorithm, EffectJournal, EffectState, EventId, ObligationState,
    OperationReceipt, PrincipalId, TimestampNs,
};
use fss_reference::webhook::{WebhookEndpoint, WebhookEvidence, WebhookOutcome};
use fss_reference::{
    PrepareAlertParams, ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision,
    ReplayCx, committed_reference_policy_action, prepare_reference_alert,
    rehydrate_reference_alert_plan,
};

use super::{RunResult, export};

/// Capability the alert command needs to prepare an intent (registries/CAPABILITIES.md).
pub(super) const CAP_ALERT_PREPARE: &str = fss_cli::alert_effect::CAP_ALERT_PREPARE;
/// Capability the alert command needs to commit an exact prepared plan.
pub(super) const CAP_ALERT_COMMIT: &str = fss_cli::alert_effect::CAP_ALERT_COMMIT;
const MAX_DEADLINE_MS: u64 = fss_cli::alert_effect::MAX_DEADLINE_MS;

const OPTIONS: &[&str] = &[
    "--root",
    "--site",
    "--principal",
    "--event-id",
    "--relay",
    "--path",
    "--plaintext-approval",
    "--deadline-ms",
    "--approve",
    "--dispatch",
    "--report-out",
];

/// Typed refusals of the alert command, with registered identities (the shared alert core's).
pub(super) use fss_cli::alert_effect::AlertEffectError as AlertCliError;

/// Fully parsed alert request; nothing here is authority until `run` validates it.
#[derive(Debug)]
pub(super) struct AlertAction {
    pub(super) root: PathBuf,
    pub(super) site: String,
    pub(super) principal: String,
    event_id: EventId,
    relay: SocketAddr,
    path: String,
    plaintext_approval: ContentDigest,
    deadline_ms: u64,
    approve: Option<ContentDigest>,
    pub(super) dispatch: Option<ContentDigest>,
    report_out: Option<PathBuf>,
}

fn digest(value: &str, key: &str) -> Result<ContentDigest, String> {
    let parsed = ContentDigest::parse(value).map_err(|_| format!("invalid digest for {key}"))?;
    if parsed.algorithm() != DigestAlgorithm::Sha256 {
        return Err(format!("{key} requires SHA-256"));
    }
    Ok(parsed)
}

/// Parses the arguments after `alert`. Every option takes one separate UTF-8 value once.
pub(super) fn parse(args: &[OsString]) -> Result<AlertAction, String> {
    let mut values: Vec<(String, String)> = Vec::new();
    let mut index = 0;
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
        if !OPTIONS.contains(&key) {
            return Err("unknown or inapplicable option".to_owned());
        }
        if values.iter().any(|(k, _)| k == key) {
            return Err(format!("duplicate {key}"));
        }
        values.push((key.to_owned(), argument.to_owned()));
        index += 2;
    }
    let find = |key: &str| {
        values
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let required = |key: &str| find(key).ok_or_else(|| format!("required option {key}"));
    let site = required("--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = find("--principal")
        .unwrap_or("principal:local-operator")
        .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let deadline_ms: u64 = required("--deadline-ms")?
        .parse()
        .map_err(|_| "invalid numeric value for --deadline-ms")?;
    if deadline_ms == 0 || deadline_ms > MAX_DEADLINE_MS {
        return Err("--deadline-ms must be 1..60000".to_owned());
    }
    let approve = find("--approve")
        .map(|v| digest(v, "--approve"))
        .transpose()?;
    let dispatch = find("--dispatch")
        .map(|v| digest(v, "--dispatch"))
        .transpose()?;
    if dispatch.is_some() && approve.is_none() {
        return Err("--dispatch also requires the exact --approve plan digest".to_owned());
    }
    Ok(AlertAction {
        root: PathBuf::from(required("--root")?),
        site,
        principal,
        event_id: EventId::parse(required("--event-id")?).map_err(|_| "invalid event ID")?,
        relay: required("--relay")?
            .parse()
            .map_err(|_| "--relay must be an exact IP:PORT socket address (no DNS)")?,
        path: required("--path")?.to_owned(),
        plaintext_approval: digest(required("--plaintext-approval")?, "--plaintext-approval")?,
        deadline_ms,
        approve,
        dispatch,
        report_out: find("--report-out").map(PathBuf::from),
    })
}

struct Report<'a> {
    stage: &'static str,
    action: &'a AlertAction,
    endpoint: &'a WebhookEndpoint,
    ids: &'a AlertIdentities,
    event_state: &'a str,
    policy_action: ReferencePolicyAction,
    plan: Option<ContentDigest>,
    dispatch: Option<ContentDigest>,
    operation: Option<&'a OperationReceipt>,
    obligation: Option<ObligationState>,
    evidence: Option<&'a WebhookEvidence>,
    next: Option<String>,
}

fn quote(argument: &str) -> String {
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

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn optional<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "null".to_owned(), |v| format!("\"{v}\""))
}

impl Report<'_> {
    fn command(&self, approve: ContentDigest, dispatch: Option<ContentDigest>) -> String {
        let a = self.action;
        let mut command = format!(
            "fss-event alert --root {} --site {} --principal {} --event-id {} --relay {} --path {} \
             --plaintext-approval {} --deadline-ms {} --approve {approve}",
            quote(&a.root.to_string_lossy()),
            quote(&a.site),
            quote(&a.principal),
            a.event_id,
            a.relay,
            quote(&a.path),
            a.plaintext_approval,
            a.deadline_ms,
        );
        if let Some(dispatch) = dispatch {
            command.push_str(&format!(" --dispatch {dispatch}"));
        }
        command
    }

    fn json(&self) -> String {
        let operation = self.operation;
        let state = operation.map(|o| o.state);
        let delivery = match state {
            Some(EffectState::AdapterAccepted) => "relay_acceptance_only",
            Some(EffectState::Indeterminate | EffectState::Committed) => "indeterminate",
            Some(EffectState::Verified) => "verified",
            Some(EffectState::Failed) => "failed",
            Some(EffectState::Cancelled) => "cancelled_not_sent",
            _ => "not_dispatched",
        };
        let evidence = self.evidence.map_or_else(
            || "null".to_owned(),
            |e| {
                format!(
                    concat!(
                        "{{\"outcome\":\"{}\",\"request_sha256\":\"{}\",\"request_bytes\":{},",
                        "\"sent_bytes\":{},\"response_prefix_bytes\":{},\"io_calls\":{},",
                        "\"observation_digest\":{},\"commitment_root\":\"{}\"}}"
                    ),
                    e.outcome()
                        .map_or_else(|| "unfinished".to_owned(), outcome_text),
                    ContentDigest::sha256(e.request()),
                    e.request().len(),
                    e.sent_bytes(),
                    e.response_prefix().len(),
                    e.io_calls(),
                    optional(e.digest().ok()),
                    e.commitment_root(),
                )
            },
        );
        format!(
            concat!(
                "{{\"format\":\"fss.alert_operation_report.v1\",\"stage\":\"{}\",",
                "\"event_id\":\"{}\",\"event_state\":\"{}\",\"policy_action\":\"{}\",",
                "\"route_digest\":\"{}\",\"channel\":\"{}\",\"transport\":\"explicit_plaintext_relay\",",
                "\"operation_id\":\"{}\",\"idempotency_key\":\"{}\",\"obligation_id\":\"{}\",",
                "\"plan_digest\":{},\"dispatch_digest\":{},\"effect_state\":{},",
                "\"obligation_state\":{},\"result_digest\":{},\"delivery_claim\":\"{}\",",
                "\"deadline_ms\":{},\"retries\":0,\"resend\":false,\"evidence\":{},",
                "\"next_command\":{}}}"
            ),
            self.stage,
            self.action.event_id,
            self.event_state,
            match self.policy_action {
                ReferencePolicyAction::PrepareAlert => "prepare_alert",
                ReferencePolicyAction::Hold => "hold",
            },
            self.endpoint.digest(),
            self.endpoint.channel(),
            self.ids.operation,
            self.ids.idempotency,
            self.ids.obligation,
            optional(self.plan),
            optional(self.dispatch),
            optional(state.map(EffectState::as_str)),
            optional(self.obligation.map(obligation_state)),
            optional(operation.and_then(|o| o.result_digest)),
            delivery,
            self.action.deadline_ms,
            evidence,
            self.next
                .as_deref()
                .map_or_else(|| "null".to_owned(), json_string),
        )
    }
}

fn emit(report: &Report<'_>, root: &Path, cx: &ReplayCx, out: &mut impl Write) -> RunResult<()> {
    let json = format!("{}\n", report.json());
    if let Some(path) = &report.action.report_out {
        export(path, json.as_bytes(), root, cx)?;
    }
    out.write_all(json.as_bytes())?;
    Ok(())
}

/// Runs one alert stage against the deployment. See the module documentation.
pub(super) fn run(
    action: &AlertAction,
    deployment: &mut ReferenceDeployment,
    root: &Path,
    authority: &ContextAuthority,
    cx: &ReplayCx,
    out: &mut impl Write,
) -> RunResult<()> {
    let endpoint = WebhookEndpoint::new(action.relay, &action.path, action.plaintext_approval)
        .map_err(|_| AlertCliError::Route)?;
    let (event, receipt) = deployment
        .current_event_authority(&action.event_id)
        .map_err(AlertCliError::Authority)?;
    let policy_action = committed_reference_policy_action(&event);
    let decision = ReferencePolicyDecision {
        event: event.clone(),
        action: policy_action,
    };
    let ids = alert_identities(receipt.event_revision_digest, endpoint.digest())?;
    let mut report = Report {
        stage: "proposed",
        action,
        endpoint: &endpoint,
        ids: &ids,
        event_state: event.state.as_str(),
        policy_action,
        plan: None,
        dispatch: None,
        operation: None,
        obligation: None,
        evidence: None,
        next: None,
    };
    let existing = deployment.effects().operation(&ids.operation).cloned();
    let Some(operation) = existing else {
        // Nothing durable yet: compute the exact plan in a scratch journal.
        if !authority.has_capability(CAP_ALERT_PREPARE) {
            return Err(AlertCliError::Dispatch("missing CAP-ALERT-PREPARE-001".to_owned()).into());
        }
        let now = TimestampNs(i128::from(wall_ns()?));
        let plan = prepare_reference_alert(
            PrepareAlertParams {
                decision: &decision,
                event_receipt: &receipt,
                authority: deployment.ledger(),
                operation_id: ids.operation.clone(),
                idempotency_key: ids.idempotency.clone(),
                obligation_id: ids.obligation.clone(),
                channel: endpoint.channel().to_owned(),
                now,
            },
            &mut EffectJournal::new(),
        )
        .map_err(not_eligible)?;
        let approval = plan_approval_digest(&plan, &endpoint, &action.principal);
        report.plan = Some(approval);
        if let Some(dispatch) = action.dispatch {
            // No prepared operation exists, so no dispatch approval can be current.
            return Err(AlertCliError::StaleApproval(dispatch).into());
        }
        match action.approve {
            None => {
                report.next = Some(report.command(approval, None));
                return emit(&report, root, cx, out);
            }
            Some(given) if given != approval => {
                return Err(AlertCliError::StaleApproval(given).into());
            }
            Some(_) => {}
        }
        let (journal, ledger) = deployment.effects_and_ledger();
        let prepared = journal
            .prepare_alert(PrepareAlertParams {
                decision: &decision,
                event_receipt: &receipt,
                authority: ledger,
                operation_id: ids.operation.clone(),
                idempotency_key: ids.idempotency.clone(),
                obligation_id: ids.obligation.clone(),
                channel: endpoint.channel().to_owned(),
                now,
            })
            .map_err(|e| AlertCliError::Dispatch(e.to_string()))?;
        if plan_approval_digest(&prepared, &endpoint, &action.principal) != approval {
            return Err(AlertCliError::StaleApproval(approval).into());
        }
        let operation = journal
            .operation(&ids.operation)
            .cloned()
            .ok_or_else(|| AlertCliError::Dispatch("prepared operation missing".to_owned()))?;
        let dispatch =
            dispatch_approval_digest(approval, &operation, action.deadline_ms, &action.principal);
        report.stage = "prepared";
        report.dispatch = Some(dispatch);
        report.obligation = journal.obligation(&ids.obligation).map(|o| o.state);
        report.operation = Some(&operation);
        report.next = Some(report.command(approval, Some(dispatch)));
        return emit(&report, root, cx, out);
    };
    report.obligation = deployment
        .effects()
        .obligation(&ids.obligation)
        .map(|o| o.state);
    if operation.state != EffectState::Prepared {
        // Committed, observed, cancelled or reconciled: report only. Never resend.
        report.stage = if operation.state == EffectState::Cancelled {
            "cancelled_before_dispatch"
        } else {
            "already_dispatched"
        };
        report.operation = Some(&operation);
        emit(&report, root, cx, out)?;
        return match operation.state {
            EffectState::Committed | EffectState::Indeterminate => {
                Err(AlertCliError::Indeterminate.into())
            }
            _ => Ok(()),
        };
    }
    let plan = rehydrate_reference_alert_plan(
        &operation,
        ids.obligation.clone(),
        &event,
        &receipt,
        deployment.ledger(),
        endpoint.channel(),
    )
    .map_err(AlertCliError::Authority)?;
    let approval = plan_approval_digest(&plan, &endpoint, &action.principal);
    let dispatch =
        dispatch_approval_digest(approval, &operation, action.deadline_ms, &action.principal);
    report.stage = "prepared";
    report.plan = Some(approval);
    report.dispatch = Some(dispatch);
    report.operation = Some(&operation);
    match action.approve {
        None => {
            report.next = Some(report.command(approval, Some(dispatch)));
            return emit(&report, root, cx, out);
        }
        Some(given) if given != approval => {
            return Err(AlertCliError::StaleApproval(given).into());
        }
        Some(_) => {}
    }
    match action.dispatch {
        None => {
            report.next = Some(report.command(approval, Some(dispatch)));
            return emit(&report, root, cx, out);
        }
        Some(given) if given != dispatch => {
            return Err(AlertCliError::StaleApproval(given).into());
        }
        Some(_) => {}
    }
    let dispatched = dispatch_prepared_alert(
        deployment,
        &plan,
        &endpoint,
        &operation,
        authority.has_capability(CAP_ALERT_COMMIT) && authority.principal == action.principal,
        action.deadline_ms,
        cx,
    )?;
    let outcome = dispatched.outcome;
    let recorded = dispatched.recorded;
    let evidence = dispatched.evidence;
    report.stage = "dispatched";
    report.operation = Some(&recorded);
    report.obligation = deployment
        .effects()
        .obligation(&ids.obligation)
        .map(|o| o.state);
    report.evidence = Some(&evidence);
    emit(&report, root, cx, out)?;
    match outcome {
        WebhookOutcome::ReceiverAccepted(_) if recorded.state == EffectState::AdapterAccepted => {
            Ok(())
        }
        _ => Err(AlertCliError::Indeterminate.into()),
    }
}
