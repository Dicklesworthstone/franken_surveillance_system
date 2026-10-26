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
//! `adapter_accepted` (relay acceptance only, never human delivery); a lost acknowledgement,
//! timeout, refusal, or malformed response is recorded as `indeterminate`. Nothing is retried.

use std::time::{SystemTime, UNIX_EPOCH};

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContextAuthority, ContractError, EffectState,
    IdempotencyKey, ObligationId, ObligationState, OperationId, OperationReceipt,
};
use fss_reference::webhook::{
    WebhookEndpoint, WebhookEvidence, WebhookInterruption, WebhookOutcome,
};
use fss_reference::{ReferenceAlertPlan, ReferenceDeployment, ReferenceError, ReplayCx};

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
/// Source-read admissions and prepaid durable journal transitions.
pub const MAX_DISPATCH_STORAGE_OPERATIONS: u64 = 8192;
const OPERATION_DOMAIN: &str = "fss.cli_alert_operation.v1";
const PLAN_APPROVAL_DOMAIN: &str = "fss.cli_alert_plan_approval.v1";
const DISPATCH_APPROVAL_DOMAIN: &str = "fss.cli_alert_dispatch_approval.v1";

/// Typed refusals of an alert stage, with registered identities.
#[derive(Debug)]
pub enum AlertEffectError {
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

/// Maps a preparation refusal: policy/integrity gates are `NotEligible`, anything else is an
/// authority refusal.
#[must_use]
pub fn not_eligible(error: ReferenceError) -> AlertEffectError {
    match error {
        ReferenceError::InvalidSpec("alert_not_eligible")
        | ReferenceError::Contract(ContractError::SensorIntegrityRisk) => {
            AlertEffectError::NotEligible(error)
        }
        other => AlertEffectError::Authority(other),
    }
}

fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Host wall clock read once at the CLI boundary as the journal admission time; deadlines are
/// measured separately on a monotonic clock.
pub fn wall_ns() -> Result<u64, AlertEffectError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AlertEffectError::Clock)?;
    u64::try_from(elapsed.as_nanos()).map_err(|_| AlertEffectError::Clock)
}

/// The deterministic identities of one alert: one per (event revision, relay route).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertIdentities {
    /// Effect operation identity.
    pub operation: OperationId,
    /// Idempotency key.
    pub idempotency: IdempotencyKey,
    /// Terminal-proof obligation identity.
    pub obligation: ObligationId,
}

/// Derives the alert identities of `event_revision` sent over `route`.
pub fn alert_identities(
    event_revision: ContentDigest,
    route: ContentDigest,
) -> Result<AlertIdentities, ContractError> {
    let mut e = CanonicalEncoder::new();
    e.text(OPERATION_DOMAIN);
    e.digest(event_revision);
    e.digest(route);
    let key = hex(ContentDigest::sha256(&e.finish()));
    Ok(AlertIdentities {
        operation: OperationId::parse(format!("operation:alert:{key}"))?,
        idempotency: IdempotencyKey::parse(format!("idempotency:alert:{key}"))?,
        obligation: ObligationId::parse(format!("obligation:alert:{key}"))?,
    })
}

/// Exact approval identity of a plan: its effect intent, obligation, channel, relay route and the
/// approving principal. Time-independent, so a dry run and the later preparation agree.
#[must_use]
pub fn plan_approval_digest(
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
#[must_use]
pub fn dispatch_approval_digest(
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
    /// Resource reservations, terminal task receipt and honest subtree closure.
    pub runtime: AlertRuntimeSummary,
}

impl AlertDispatch {
    /// True only for a complete 2xx head recorded as `adapter_accepted`.
    #[must_use]
    pub fn accepted(&self) -> bool {
        matches!(self.outcome, WebhookOutcome::ReceiverAccepted(_))
            && self.recorded.state == EffectState::AdapterAccepted
    }
}

/// Commits `operation` (which must still be prepared) durably, then sends exactly one webhook
/// request to `endpoint` under a restrictive owner and records the local observation.
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
    )
}
