#![forbid(unsafe_code)]
//! The one alert-effect core shared by `fss-event alert` and the canonical agent grammar
//! (`fss plan`, `fss commit`): operation identities, the exact plan and dispatch approval
//! digests, the restrictive webhook owner, and the single bounded dispatch attempt.
//!
//! Both surfaces derive the operation identity from the exact event revision and relay route, so
//! an alert prepared through one surface is the same operation (one idempotency key, one
//! obligation) through the other, and neither can prepare or send it twice.
//!
//! Commitment is durable before any network I/O. A complete 2xx head is recorded as
//! `adapter_accepted` after exact wire evidence reaches durable local custody (relay acceptance
//! only, never human delivery); a lost acknowledgement,
//! timeout, refusal, or malformed response is recorded as `indeterminate`. Nothing is retried.

use std::time::{SystemTime, UNIX_EPOCH};

use fss_core::{
    ContentDigest, ContextAuthority, ContractError, EffectState, EventHypothesis, ObligationState,
    OperationReceipt, TimestampNs,
};
use fss_publication::LocalPublicationError;
use fss_reference::webhook::retained::RetainedWebhookEvidence;
use fss_reference::webhook::{
    WebhookDenial, WebhookDisclosureProfile, WebhookEndpoint, WebhookEvidence, WebhookInterruption,
    WebhookOutcome, WebhookRequestPreview, preview_webhook_request,
};
use fss_reference::{
    MAX_ALERT_HEALTH_OBJECT_BYTES, ReferenceAlertPlan, ReferenceDeployment, ReferenceError,
    ReplayCx, check_alert_historical_health,
};

/// Metadata-only runtime presentation for both CLI surfaces.
pub mod report;
mod runtime;
pub use runtime::AlertRuntimeSummary;

/// Capability needed to prepare an alert intent (registries/CAPABILITIES.md).
pub const CAP_ALERT_PREPARE: &str = "CAP-ALERT-PREPARE-001";
/// Capability needed to commit an exact prepared alert plan.
pub const CAP_ALERT_COMMIT: &str = "CAP-ALERT-COMMIT-001";
/// Largest admitted dispatch deadline.
pub const MAX_DEADLINE_MS: u64 = 60_000;
/// Finite whole-attempt socket reservations, including blocked and failed calls.
pub const MAX_DISPATCH_NETWORK_BYTES: u64 = 4096 * 4096;
/// Local outcome-recording allowance; never extends the network deadline.
pub const DISPATCH_CLEANUP_MS: u64 = 5_000;
/// Source-read admissions and prepaid durable journal transitions and wire custody.
pub const MAX_DISPATCH_STORAGE_OPERATIONS: u64 = 8192;
mod identity;
pub use identity::{
    AlertIdentities, WIRE_RETENTION_POLICY, alert_identities, dispatch_approval_digest,
};

/// Typed refusals of an alert stage, with registered identities.
#[derive(Debug)]
pub enum AlertEffectError {
    /// The relay route is not admissible (address, path or plaintext approval).
    Route,
    /// The event is absent, or its authority could not be read and verified.
    Authority(ReferenceError),
    /// Policy, corroboration, sensor-integrity or retained source-health gates refuse the alert.
    NotEligible(ReferenceError),
    /// An approval digest does not match the current plan or prepared operation.
    StaleApproval(ContentDigest),
    /// The host admission clock is unavailable or moved behind the journal.
    Clock,
    /// Durable effect journal or webhook owner refusal; uncertain appends need recovery.
    Dispatch(String),
    /// The dispatch outcome is unknown: no trustworthy acknowledgement was recorded.
    Indeterminate,
}

impl AlertEffectError {
    /// Registered stable identity (registries/ERRORS.md).
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
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

impl std::fmt::Display for AlertEffectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Route => f.write_str("relay route refused (exact IP:PORT, plain absolute path, nonzero plaintext approval)"),
            Self::Authority(e) => write!(f, "event authority refused: {e}"),
            Self::NotEligible(e) => write!(f, "alert not eligible: {e}"),
            Self::StaleApproval(d) => write!(f, "approval {d} does not match the current alert plan or prepared operation"),
            Self::Clock => f.write_str("admission clock unavailable or behind the effect journal"),
            Self::Dispatch(why) => write!(f, "alert dispatch refused: {why}; inspect the durable operation before any retry"),
            Self::Indeterminate => f.write_str("alert outcome is indeterminate; reconcile before any retry, never resend"),
        }
    }
}

impl std::error::Error for AlertEffectError {}

/// Maps a preparation refusal: policy/integrity/source-health gates are `NotEligible`; other errors are an
/// authority refusal.
#[must_use]
pub fn not_eligible(error: ReferenceError) -> AlertEffectError {
    match error {
        ReferenceError::InvalidSpec("alert_not_eligible")
        | ReferenceError::Contract(ContractError::SensorIntegrityRisk)
        | ReferenceError::AlertSourceHealth(_) => AlertEffectError::NotEligible(error),
        other => AlertEffectError::Authority(other),
    }
}

/// Parse the same explicit disclosure selection for both CLI surfaces and MCP forwarding.
/// A separate metadata approval is mandatory for the rich profile and invalid for references.
pub fn parse_disclosure_profile(
    profile: Option<&str>,
    metadata_approval: Option<ContentDigest>,
) -> Result<WebhookDisclosureProfile, AlertEffectError> {
    let profile = profile
        .map(WebhookDisclosureProfile::parse)
        .transpose()
        .map_err(|_| AlertEffectError::Route)?
        .unwrap_or_default();
    profile
        .validate(metadata_approval)
        .map_err(|_| AlertEffectError::Route)?;
    Ok(profile)
}

/// Refuse a complete unrepresentable request before any durable preparation. Dispatch repeats
/// this same encoder after rebuilding the plan, while live event/effect authority stays separate.
pub fn check_alert_request(
    plan: &ReferenceAlertPlan,
    endpoint: &WebhookEndpoint,
) -> Result<WebhookRequestPreview, AlertEffectError> {
    preview_webhook_request(plan, endpoint)
        .map_err(|error| AlertEffectError::Dispatch(error.to_string()))
}

/// Checks retained diagnostic eligibility before proposing or durably preparing an alert.
///
/// Reads are bounded before allocation and pass the caller's explicit context checkpoint. The
/// reference owner shares aggregate metadata and matching bounds across the complete check.
/// Absence of a matching diagnostic remains unknown health and supplies no health certificate.
/// An existing non-prepared operation is inspected through its own historical receipt instead.
pub fn check_alert_source_health(
    deployment: &ReferenceDeployment,
    event: &EventHypothesis,
    cx: &ReplayCx,
) -> Result<(), AlertEffectError> {
    if cx.root_dir() != deployment.root() {
        return Err(AlertEffectError::Authority(ReferenceError::InvalidSpec(
            "alert_source_health_context",
        )));
    }
    cx.checkpoint("alert:source_health").map_err(|_| {
        AlertEffectError::Authority(ReferenceError::CancellationRequested {
            stage: "alert:source_health",
        })
    })?;
    check_alert_historical_health(deployment.ledger(), event, |digest| {
        cx.checkpoint("alert:source_health:read").map_err(|_| {
            ReferenceError::CancellationRequested {
                stage: "alert:source_health:read",
            }
        })?;
        deployment
            .publisher()
            .spool()
            .read_bounded(digest, MAX_ALERT_HEALTH_OBJECT_BYTES)
            .map_err(|error| ReferenceError::from(LocalPublicationError::Spool(error)))
    })
    .map_err(not_eligible)
}

/// Host wall clock read once at the CLI boundary as the journal admission time; deadlines are
/// measured separately on a monotonic clock.
pub fn wall_ns() -> Result<u64, AlertEffectError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AlertEffectError::Clock)?;
    u64::try_from(elapsed.as_nanos()).map_err(|_| AlertEffectError::Clock)
}

/// Exact approval identity of the plan, including its profile-bound route/channel.
/// The reference-profile encoding remains byte-identical to the previous implementation.
#[must_use]
pub fn plan_approval_digest(
    plan: &ReferenceAlertPlan,
    endpoint: &WebhookEndpoint,
    principal: &str,
) -> ContentDigest {
    identity::plan_approval_parts(
        &plan.intent,
        &plan.obligation_id,
        &plan.channel,
        plan.event_root,
        plan.event_revision_digest,
        endpoint.digest(),
        principal,
    )
}

/// Registered spelling of an obligation state.
#[must_use]
pub const fn obligation_state(state: ObligationState) -> &'static str {
    match state {
        ObligationState::Pending => "pending",
        ObligationState::Verified => "verified",
        ObligationState::Failed => "failed",
        ObligationState::Indeterminate => "indeterminate",
        ObligationState::Cancelled => "cancelled",
    }
}

/// Stable spelling of one webhook outcome.
#[must_use]
pub fn outcome_text(outcome: WebhookOutcome) -> String {
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

/// What one completed dispatch attempt recorded.
#[derive(Debug)]
pub struct AlertDispatch {
    /// The webhook outcome.
    pub outcome: WebhookOutcome,
    /// The operation receipt recorded after the attempt.
    pub recorded: OperationReceipt,
    /// The retired attempt's evidence (request bytes digest, I/O counts, observation).
    pub evidence: WebhookEvidence,
    /// Locally verified root-last custody of the exact retired observation, captured before
    /// appending its result. Its historical-record flag reflects that earlier snapshot; consult
    /// `recorded` for the later result. Missing custody requires recovery and never a resend.
    pub retained_evidence: Option<RetainedWebhookEvidence>,
    /// Resource reservations, terminal task receipt and honest subtree closure.
    pub runtime: AlertRuntimeSummary,
}

impl AlertDispatch {
    /// True only for a complete 2xx head retained locally and recorded as `adapter_accepted`.
    #[must_use]
    pub fn accepted(&self) -> bool {
        matches!(self.outcome, WebhookOutcome::ReceiverAccepted(_))
            && self.recorded.state == EffectState::AdapterAccepted
            && self.retained_evidence.is_some()
    }
}

/// Commits `operation` (which must still be prepared) durably, then sends exactly one webhook
/// request to `endpoint` under a restrictive owner, retains the exact wire observation
/// root-last, and only then records the local result in the effect journal.
///
/// `commit_granted` is the caller's verdict that the exact dispatch approval and the commit
/// capability are present; without it the owner refuses before any write or I/O.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_prepared_alert(
    deployment: &mut ReferenceDeployment,
    plan: &ReferenceAlertPlan,
    endpoint: &WebhookEndpoint,
    operation: &OperationReceipt,
    commit_granted: bool,
    deadline_ms: u64,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<AlertDispatch, AlertEffectError> {
    runtime::dispatch(
        deployment,
        plan,
        endpoint,
        operation,
        commit_granted,
        deadline_ms,
        authority,
        cx,
        None,
    )
}

/// An additional held-session restriction; never a substitute for native effect authority.
///
/// Live session expiry limits the network window. The callback resamples admission after
/// source reads and at the final commit/socket boundary. Neither restriction applies to
/// finite cleanup of an operation already committed.
pub(crate) struct AlertDispatchAdmission<'a> {
    pub deadline: Option<TimestampNs>,
    pub check: &'a dyn Fn() -> Result<(), WebhookDenial>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_prepared_alert_with_admission(
    deployment: &mut ReferenceDeployment,
    plan: &ReferenceAlertPlan,
    endpoint: &WebhookEndpoint,
    operation: &OperationReceipt,
    commit_granted: bool,
    deadline_ms: u64,
    authority: &ContextAuthority,
    cx: &ReplayCx,
    admission: &AlertDispatchAdmission<'_>,
) -> Result<AlertDispatch, AlertEffectError> {
    runtime::dispatch(
        deployment,
        plan,
        endpoint,
        operation,
        commit_granted,
        deadline_ms,
        authority,
        cx,
        Some(admission),
    )
}
