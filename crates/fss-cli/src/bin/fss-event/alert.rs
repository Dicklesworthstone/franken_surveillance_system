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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fss_core::effect::EffectAuthority;
use fss_core::region::ContextAuthority;
use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, EffectIntent, EffectJournal,
    EffectState, EventId, IdempotencyKey, ObligationId, ObligationState, OperationId,
    OperationReceipt, PrincipalId, TimestampNs,
};
use fss_publication::LocalPublicationError;
use fss_reference::webhook::{
    WebhookAttempt, WebhookAuthority, WebhookBoundary, WebhookDenial, WebhookEndpoint,
    WebhookEvidence, WebhookInterruption, WebhookLimits, WebhookOutcome, WebhookProgress,
    WebhookScope,
};
use fss_reference::{
    PrepareAlertParams, ReferenceAlertPlan, ReferenceDeployment, ReferenceError,
    ReferencePolicyAction, ReferencePolicyDecision, ReplayCx, committed_reference_policy_action,
    prepare_reference_alert, rehydrate_reference_alert_plan,
};

use super::{RunResult, export};

/// Capability the alert command needs to prepare an intent (registries/CAPABILITIES.md).
pub(super) const CAP_ALERT_PREPARE: &str = "CAP-ALERT-PREPARE-001";
/// Capability the alert command needs to commit an exact prepared plan.
pub(super) const CAP_ALERT_COMMIT: &str = "CAP-ALERT-COMMIT-001";
const OPERATION_DOMAIN: &str = "fss.cli_alert_operation.v1";
const PLAN_APPROVAL_DOMAIN: &str = "fss.cli_alert_plan_approval.v1";
const DISPATCH_APPROVAL_DOMAIN: &str = "fss.cli_alert_dispatch_approval.v1";
const MAX_DEADLINE_MS: u64 = 60_000;

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

/// Typed refusals of the alert command, with registered identities.
#[derive(Debug)]
pub(super) enum AlertCliError {
    /// The relay route is not admissible (address, path or plaintext approval).
    Route,
    /// The event is absent, or its authority could not be read and verified.
    Authority(ReferenceError),
    /// Policy, corroboration or sensor-integrity gates refuse an alert for this event.
    NotEligible(ReferenceError),
    /// An approval digest does not match the current plan or prepared operation.
    StaleApproval(ContentDigest),
    /// The host admission clock is unavailable or moved behind the journal.
    Clock,
    /// Durable effect journal or webhook owner refusal before any network I/O.
    Dispatch(String),
    /// The dispatch outcome is unknown: no trustworthy acknowledgement was recorded.
    Indeterminate,
}

impl AlertCliError {
    /// Registered stable identity (registries/ERRORS.md).
    pub(super) fn stable_id(&self) -> &'static str {
        match self {
            Self::Route => "ERR-ALERT-ROUTE-INVALID-001",
            Self::Authority(_) => "ERR-ALERT-AUTHORITY-001",
            Self::NotEligible(_) => "ERR-ALERT-NOT-ELIGIBLE-001",
            Self::StaleApproval(_) => "ERR-ALERT-APPROVAL-STALE-001",
            Self::Clock => "ERR-ALERT-CLOCK-001",
            Self::Dispatch(_) => "ERR-ALERT-DISPATCH-001",
            Self::Indeterminate => "ERR-EFFECT-INDETERMINATE-001",
        }
    }
}

impl std::fmt::Display for AlertCliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Route => f.write_str("relay route refused (exact IP:PORT, plain absolute path, nonzero plaintext approval)"),
            Self::Authority(e) => write!(f, "event authority refused: {e}"),
            Self::NotEligible(e) => write!(f, "alert not eligible: {e}"),
            Self::StaleApproval(d) => write!(f, "approval {d} does not match the current alert plan or prepared operation"),
            Self::Clock => f.write_str("admission clock unavailable or behind the effect journal"),
            Self::Dispatch(why) => write!(f, "alert dispatch refused before any network I/O: {why}"),
            Self::Indeterminate => f.write_str("alert outcome is indeterminate; reconcile before any retry, never resend"),
        }
    }
}
impl std::error::Error for AlertCliError {}

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

fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Host wall clock read once at the CLI boundary as the journal admission time; deadlines are
/// measured separately on a monotonic clock.
fn wall_ns() -> Result<u64, AlertCliError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AlertCliError::Clock)?;
    u64::try_from(elapsed.as_nanos()).map_err(|_| AlertCliError::Clock)
}

struct Identities {
    operation: OperationId,
    idempotency: IdempotencyKey,
    obligation: ObligationId,
}

fn identities(event_revision: ContentDigest, route: ContentDigest) -> RunResult<Identities> {
    let mut e = CanonicalEncoder::new();
    e.text(OPERATION_DOMAIN);
    e.digest(event_revision);
    e.digest(route);
    let key = hex(ContentDigest::sha256(&e.finish()));
    Ok(Identities {
        operation: OperationId::parse(format!("operation:alert:{key}"))?,
        idempotency: IdempotencyKey::parse(format!("idempotency:alert:{key}"))?,
        obligation: ObligationId::parse(format!("obligation:alert:{key}"))?,
    })
}

/// Exact approval identity of a plan: its effect intent, obligation, channel, relay route and the
/// approving principal. Time-independent, so a dry run and the later preparation agree.
fn plan_digest(
    plan: &ReferenceAlertPlan,
    endpoint: &WebhookEndpoint,
    principal: &str,
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(PLAN_APPROVAL_DOMAIN);
    plan.intent.encode_canonical(&mut e);
    plan.obligation_id.encode_canonical(&mut e);
    e.text(&plan.channel);
    e.digest(plan.event_root);
    e.digest(plan.event_revision_digest);
    e.digest(endpoint.digest());
    e.text(principal);
    ContentDigest::sha256(&e.finish())
}

/// Exact approval identity of one dispatch: the plan approval, the durable prepared record, the
/// explicit deadline and the principal.
fn dispatch_digest(
    plan: ContentDigest,
    operation: &OperationReceipt,
    deadline_ms: u64,
    principal: &str,
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(DISPATCH_APPROVAL_DOMAIN);
    e.digest(plan);
    operation.intent.encode_canonical(&mut e);
    e.text(operation.state.as_str());
    e.i128(operation.prepared_at.0);
    e.text(&operation.authority.principal);
    e.text(&operation.authority.capability);
    e.u64(deadline_ms);
    e.text(principal);
    ContentDigest::sha256(&e.finish())
}

/// CLI-owned live authority for exactly one approved dispatch. Every check is independent of the
/// caller's admission time: the deadline is measured on a monotonic clock started at approval.
/// It admits only the approved route, journal file, intent and recorded effect authority; commit
/// only while the operation is still prepared (no second commit, no retry); network boundaries
/// only while it is committed and before the deadline; and recording of the observation (a local
/// cleanup boundary) only for this committed operation. Cancellation of the owning Cx denies.
struct CliWebhookOwner<'a> {
    route: ContentDigest,
    journal: PathBuf,
    intent: EffectIntent,
    authority: EffectAuthority,
    commit_granted: bool,
    started: Instant,
    deadline: Duration,
    cx: &'a ReplayCx,
}

impl WebhookAuthority for CliWebhookOwner<'_> {
    fn checkpoint(
        &self,
        scope: WebhookScope<'_>,
        boundary: WebhookBoundary,
        now_ns: u64,
        network_deadline_ns: u64,
    ) -> Result<(), WebhookDenial> {
        if !self.commit_granted
            || scope.endpoint.digest() != self.route
            || scope.effect_journal != self.journal.as_path()
            || scope.operation.intent != self.intent
            || scope.operation.intent.effect_class != "alert.dispatch"
            || scope.operation.authority != self.authority
        {
            return Err(WebhookDenial::Unauthorized);
        }
        if self.cx.is_cancelled() {
            return Err(WebhookDenial::Cancelled);
        }
        let state = scope.operation.state;
        match boundary {
            WebhookBoundary::Commit => {
                if state != EffectState::Prepared {
                    return Err(WebhookDenial::Unauthorized);
                }
            }
            WebhookBoundary::Record => {
                // Local cleanup only: the observation of this committed attempt, or an exact
                // repeat of its already-recorded outcome.
                if !matches!(
                    state,
                    EffectState::Committed
                        | EffectState::AdapterAccepted
                        | EffectState::Indeterminate
                ) {
                    return Err(WebhookDenial::Unauthorized);
                }
                return Ok(());
            }
            _ => {
                if state != EffectState::Committed {
                    return Err(WebhookDenial::Revoked);
                }
            }
        }
        if self.started.elapsed() >= self.deadline || now_ns >= network_deadline_ns {
            return Err(WebhookDenial::Deadline);
        }
        Ok(())
    }
}

fn obligation_state(state: ObligationState) -> &'static str {
    match state {
        ObligationState::Pending => "pending",
        ObligationState::Verified => "verified",
        ObligationState::Failed => "failed",
        ObligationState::Indeterminate => "indeterminate",
        ObligationState::Cancelled => "cancelled",
    }
}

fn outcome_text(outcome: WebhookOutcome) -> String {
    match outcome {
        WebhookOutcome::ReceiverAccepted(code) => format!("receiver_accepted_{code}"),
        WebhookOutcome::ReceiverStatus(code) => format!("receiver_status_{code}"),
        WebhookOutcome::Interrupted(reason) => format!(
            "interrupted_{}",
            match reason {
                WebhookInterruption::Deadline => "deadline",
                WebhookInterruption::ClockReversed => "clock_reversed",
                WebhookInterruption::Denied(_) => "denied",
                WebhookInterruption::EventAuthorityRefused => "event_authority_refused",
                WebhookInterruption::Limit => "limit",
                WebhookInterruption::Io => "io",
                WebhookInterruption::Disconnected => "disconnected",
                WebhookInterruption::InvalidResponse => "invalid_response",
                WebhookInterruption::Retired => "retired",
            }
        ),
    }
}

struct Report<'a> {
    stage: &'static str,
    action: &'a AlertAction,
    endpoint: &'a WebhookEndpoint,
    ids: &'a Identities,
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

fn not_eligible(error: ReferenceError) -> AlertCliError {
    match error {
        ReferenceError::InvalidSpec("alert_not_eligible")
        | ReferenceError::Contract(fss_core::ContractError::SensorIntegrityRisk) => {
            AlertCliError::NotEligible(error)
        }
        other => AlertCliError::Authority(other),
    }
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
    let ids = identities(receipt.event_revision_digest, endpoint.digest())?;
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
        let approval = plan_digest(&plan, &endpoint, &action.principal);
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
        if plan_digest(&prepared, &endpoint, &action.principal) != approval {
            return Err(AlertCliError::StaleApproval(approval).into());
        }
        let operation = journal
            .operation(&ids.operation)
            .cloned()
            .ok_or_else(|| AlertCliError::Dispatch("prepared operation missing".to_owned()))?;
        let dispatch = dispatch_digest(approval, &operation, action.deadline_ms, &action.principal);
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
    let approval = plan_digest(&plan, &endpoint, &action.principal);
    let dispatch = dispatch_digest(approval, &operation, action.deadline_ms, &action.principal);
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
    let (journal, ledger, publisher) = deployment.effect_dispatch_parts();
    let owner = CliWebhookOwner {
        route: endpoint.digest(),
        journal: journal.path().to_path_buf(),
        intent: plan.intent.clone(),
        authority: operation.authority.clone(),
        commit_granted: authority.has_capability(CAP_ALERT_COMMIT)
            && authority.principal == action.principal,
        started: Instant::now(),
        deadline: Duration::from_millis(action.deadline_ms),
        cx,
    };
    let base = wall_ns()?;
    if i128::from(base) < operation.updated_at.0 {
        return Err(AlertCliError::Clock.into());
    }
    let admission = || {
        u64::try_from(owner.started.elapsed().as_nanos())
            .ok()
            .and_then(|elapsed| base.checked_add(elapsed))
            .unwrap_or(u64::MAX)
    };
    let deadline_ns = base
        .checked_add(action.deadline_ms.saturating_mul(1_000_000))
        .ok_or(AlertCliError::Clock)?;
    let limits = WebhookLimits {
        io_calls: 4096,
        io_bytes: 4096,
        response_bytes: 16384,
        connect_timeout_ns: action
            .deadline_ms
            .saturating_mul(1_000_000)
            .min(5_000_000_000),
    };
    let read = |digest: ContentDigest| {
        publisher
            .spool()
            .read(digest)
            .map(|bytes| bytes.to_vec())
            .map_err(|error| ReferenceError::from(LocalPublicationError::Spool(error)))
    };
    let mut attempt = WebhookAttempt::begin(
        &plan,
        &endpoint,
        ledger,
        journal,
        limits,
        base,
        deadline_ns,
        &owner,
        read,
    )
    .map_err(|e| match e {
        fss_reference::webhook::WebhookError::Authority(error) => not_eligible(error),
        other => AlertCliError::Dispatch(other.to_string()),
    })?;
    // Commitment is durable. One bounded attempt follows: at most `io_calls` socket operations,
    // each pending poll paced by 1 ms, ending at the deadline. Nothing is ever retried.
    let outcome = loop {
        match attempt.poll(admission(), &owner, read) {
            WebhookProgress::ReadyToRecord(outcome) => break outcome,
            WebhookProgress::Pending => std::thread::sleep(Duration::from_millis(1)),
        }
    };
    let recorded = attempt
        .record(admission(), &owner)
        .cloned()
        .map_err(|e| AlertCliError::Dispatch(format!("observation not recorded: {e}")));
    let evidence = attempt.retire();
    let recorded = recorded?;
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
