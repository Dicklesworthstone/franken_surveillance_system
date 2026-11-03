#![forbid(unsafe_code)]
//! Bounded, owner-authorized ONVIF PullPoint acquisition.
//!
//! A session creates one short-lived subscription, retains each complete response
//! through the caller's sink before the next poll, and explicitly unsubscribes.
//! The same literal peer, HTTP origin, generation and approved service subtree
//! govern every request and secret use. A response is vendor cognition, never
//! coverage or authenticated device identity. No retry recreates a subscription
//! after an ambiguous failure, and partial custody survives a later refusal.

use std::fmt;

use fss_core::ContentDigest;

use super::client::{ClientError, DigestConfig, OnvifContext};
use super::http::{
    HttpDenial, HttpExchange, HttpLimits, HttpOperation, HttpProgress, HttpResponse, HttpRoute,
    event_target_in_root,
};
use super::metadata::MetadataError;
use super::wire::{
    self, PullPointSubscription, SoapRequest, WireError, create_pull_point_request,
    parse_pull_messages_response, parse_pull_point_subscription, parse_renew_response,
    parse_unsubscribe_response, pull_messages_request, renew_pull_point_request,
    unsubscribe_pull_point_request, validate_relates_to,
};
use crate::rtsp::authentication::{DigestAuthorization, DigestChallenge};

/// Time reserved exclusively for explicit Unsubscribe after capture stops.
pub const CLEANUP_RESERVE_NS: u64 = 2_000_000_000;
/// Cooperative steps reserved exclusively for Unsubscribe after capture stops.
pub const CLEANUP_RESERVE_STEPS: u32 = 1024;
/// Maximum wall-monotonic duration of one owned acquisition session.
pub const MAX_SESSION_NS: u64 = 60_000_000_000;
/// Maximum complete source responses retained by one session.
pub const MAX_PULLS: u32 = 64;
/// Maximum explicitly approved finite renewals within one unchanged live session deadline.
pub const MAX_RENEWALS: u32 = 4;
const MAX_STEPS: u32 = 100_000;
const RESPONSE_MARGIN_NS: u64 = 500_000_000;

/// An independently approved bounded event lifecycle, never inferred from discovery.
#[derive(Clone)]
pub struct PullPointConfig {
    /// Exact owner-approved event-service route with event-lifecycle capability.
    pub events: HttpRoute,
    /// Independently approved path subtree for server-returned subscription EPRs.
    pub service_root: String,
    /// Explicit HTTP Digest configuration; no mechanism or policy fallback.
    pub auth: Option<DigestConfig>,
    /// Per-exchange byte, syscall and connection ceilings.
    pub limits: HttpLimits,
    /// Absolute monotonic deadline, at most sixty seconds from admission.
    pub deadline_ns: u64,
    /// Whole-session clock/poll progress ceiling, including cleanup reservation.
    pub max_steps: u32,
    /// Maximum retained PullMessages responses, 1..=64; empty responses count.
    pub max_pulls: u32,
    /// Explicit finite renewal ceiling, 0..=4. Zero preserves capture without renewal.
    pub max_renewals: u32,
    /// Maximum remote long-poll duration, 1..=30 seconds; shortened near a bound.
    pub pull_timeout_seconds: u32,
    /// Maximum notifications accepted in each response, 1..=128.
    pub message_limit: u16,
    /// Requested subscription duration, 1..=3600 seconds. This is not a remote guarantee.
    pub lifetime_seconds: u32,
}
impl fmt::Debug for PullPointConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PullPointConfig")
            .field("deadline_ns", &self.deadline_ns)
            .field("max_pulls", &self.max_pulls)
            .field("max_renewals", &self.max_renewals)
            .field("message_limit", &self.message_limit)
            .field("authenticated_lane", &self.auth.is_some())
            .finish_non_exhaustive()
    }
}

/// Complete source and explicit acquisition observations for one retention call.
/// These bytes can contain private vendor data and must not enter logs.
pub struct PullBatch<'a> {
    /// Complete transfer-decoded PullMessages SOAP, including unsupported fields.
    pub source: &'a [u8],
    /// Exact independently scoped subscription route.
    pub route: &'a HttpRoute,
    /// Original response position; no empty response or duplicate is coalesced.
    pub pull_index: u32,
    /// Monotonic start of the original request, before a possible Digest retry.
    pub started_ns: u64,
    /// Monotonic completion of the response, before parsing/retention.
    pub completed_ns: u64,
    /// Whether this particular response followed an HTTP Digest client proof.
    /// HTTP Digest does not authenticate the remote server to this client.
    pub authenticated: bool,
    /// Exact CreatePullPointSubscription response used to obtain this EPR.
    pub subscription_response: &'a [u8],
    /// Monotonic start of Create, before its possible Digest retry.
    pub subscription_started_ns: u64,
    /// Monotonic completion of Create.
    pub subscription_completed_ns: u64,
    /// Unique logical PullMessages request identity, distinct from every other operation.
    pub message_id: &'a str,
    /// Unique logical Create request identity used for the retained subscription response.
    pub subscription_message_id: &'a str,
}
impl fmt::Debug for PullBatch<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PullBatch")
            .field("pull_index", &self.pull_index)
            .field("source_bytes", &self.source.len())
            .field("authenticated", &self.authenticated)
            .finish_non_exhaustive()
    }
}

/// A sink returns only after this source's immutable publication is durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedBatch {
    /// Exact retained import identity, usable for independent cold verification.
    pub identity: ContentDigest,
    /// Exact durable publication root.
    pub root: ContentDigest,
}

/// A definitely durable receipt and an optional refusal of any further work.
/// A late storage denial must preserve the receipt while stopping the next poll.
#[derive(Debug)]
pub struct RetainedProgress {
    /// Exact source/control publication that completed.
    pub receipt: RetainedBatch,
    /// A post-commit owner refusal; cleanup may still use its independently live authority.
    pub stop: Option<PullPointError>,
}
impl From<RetainedBatch> for RetainedProgress {
    fn from(receipt: RetainedBatch) -> Self {
        Self {
            receipt,
            stop: None,
        }
    }
}

/// Control boundaries that must reach durable custody before further network work.
/// Bodies and route fields may contain private endpoint references; Debug omits them.
pub enum PullPointControl<'a> {
    /// Persist this exact logical request before any Create dispatch.
    CreateIntent {
        /// Independently approved event route.
        events: &'a HttpRoute,
        /// Independently approved subscription subtree.
        service_root: &'a str,
        /// Fresh logical Create identity, reused only for its explicit HTTP 401 retry.
        message_id: &'a str,
        /// Original monotonic admission point, before intent storage.
        started_ns: u64,
        /// Finite requested lease, not a remote guarantee.
        lifetime_seconds: u32,
    },
    /// Persist the complete scoped Create response before the first poll.
    Created {
        /// Complete transfer-decoded Create SOAP.
        source: &'a [u8],
        /// Original logical Create identity.
        message_id: &'a str,
        /// Original monotonic Create admission.
        started_ns: u64,
        /// Complete response observation time.
        completed_ns: u64,
        /// Whether this response followed a client Digest proof.
        authenticated: bool,
    },
    /// Persist the finite same-endpoint request before any Renew dispatch.
    RenewIntent {
        /// Original independently approved subscription route.
        route: &'a HttpRoute,
        /// Fresh logical request identity, reused only after explicit HTTP401.
        message_id: &'a str,
        /// Original monotonic admission before intent custody.
        started_ns: u64,
        /// Finite requested lease, bounded by the original capture approval.
        lifetime_seconds: u32,
        /// Zero-based bounded renewal attempt within this invocation.
        renewal_index: u32,
    },
    /// Persist a complete renewal response, including replies that cannot extend the lease.
    Renewed {
        /// Complete transfer-decoded body, potentially malformed or private.
        source: &'a [u8],
        /// Exact logical request identity belonging to the prior durable intent.
        message_id: &'a str,
        /// Complete response observation time, absent when the live clock refused.
        completed_ns: Option<u64>,
        /// Whether this response followed a client Digest proof.
        authenticated: bool,
        /// Complete final HTTP status, independent of SOAP parsing.
        http_status: u16,
        /// Whether the response declared application/soap+xml.
        soap_content_type: bool,
    },
    /// Persist the exact cleanup obligation before any Unsubscribe dispatch.
    UnsubscribeIntent {
        /// Independently current route, constrained to the original subscription EPR.
        route: &'a HttpRoute,
        /// Fresh logical cleanup identity, reused only for the explicit HTTP 401 retry.
        message_id: &'a str,
        /// Exact original Create identity, independently checked against retained custody.
        create_message_id: &'a str,
        /// SHA-256 of the exact request SOAP, including EPR parameters and fresh MessageID.
        request_digest: ContentDigest,
        /// Current owner's monotonic admission before intent custody.
        started_ns: u64,
    },
    /// Persist the complete cleanup response before interpreting success or refusal.
    UnsubscribeOutcome {
        /// Independently current route used for the cleanup request.
        route: &'a HttpRoute,
        /// Complete transfer-decoded response, including malformed or refused bodies.
        source: &'a [u8],
        /// Exact logical cleanup identity belonging to the prior durable intent.
        message_id: &'a str,
        /// Current owner's monotonic request admission.
        started_ns: u64,
        /// Transport-admitted completion time, preserved across later clock refusal.
        completed_ns: Option<u64>,
        /// Whether this response followed a client Digest proof.
        authenticated: bool,
        /// Complete final HTTP status, independent of SOAP parsing.
        http_status: u16,
        /// Whether the response declared application/soap+xml.
        soap_content_type: bool,
    },
    /// Persist the exact validated cleanup response as a terminal historical receipt.
    Unsubscribed {
        /// Independently current subscription route actually used.
        route: &'a HttpRoute,
        /// Complete Unsubscribe SOAP.
        source: &'a [u8],
        /// Fresh logical Unsubscribe request identity.
        message_id: &'a str,
        /// Current owner's monotonic request start.
        started_ns: u64,
        /// Current owner's monotonic complete response time.
        completed_ns: u64,
        /// Whether this response followed a client Digest proof.
        authenticated: bool,
    },
}
impl fmt::Debug for PullPointControl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateIntent { .. } => f.write_str("PullPointControl::CreateIntent([redacted])"),
            Self::Created { source, .. } => f
                .debug_struct("PullPointControl::Created")
                .field("source_bytes", &source.len())
                .finish_non_exhaustive(),
            Self::RenewIntent { .. } => f.write_str("PullPointControl::RenewIntent([redacted])"),
            Self::Renewed { source, .. } => f
                .debug_struct("PullPointControl::Renewed")
                .field("source_bytes", &source.len())
                .finish_non_exhaustive(),
            Self::UnsubscribeIntent { .. } => {
                f.write_str("PullPointControl::UnsubscribeIntent([redacted])")
            }
            Self::UnsubscribeOutcome { source, .. } => f
                .debug_struct("PullPointControl::UnsubscribeOutcome")
                .field("source_bytes", &source.len())
                .finish_non_exhaustive(),
            Self::Unsubscribed { source, .. } => f
                .debug_struct("PullPointControl::Unsubscribed")
                .field("source_bytes", &source.len())
                .finish_non_exhaustive(),
        }
    }
}

/// Observed subscription outcome, not proof of future device behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionState {
    /// No creation attempt was admitted.
    NotCreated,
    /// Creation may have reached the device but no usable scoped EPR was obtained.
    Indeterminate,
    /// A scoped creation response was observed; Unsubscribe remains unconfirmed.
    Active,
    /// A successful, validated UnsubscribeResponse was observed under live authority.
    Unsubscribed,
}

/// Explicit bounded stopping reason; none implies complete camera event coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureStop {
    /// An explicit cleanup-only operation performed no Create or PullMessages.
    CleanupOnly,
    /// The requested maximum number of complete responses was retained.
    PullLimit,
    /// Further polling would consume the cleanup time reservation.
    DeadlineReserve,
    /// Further polling would consume the cleanup progress reservation.
    StepReserve,
    /// Further polling would overlap the conservative subscription lease bound.
    LeaseReserve,
    /// A protocol, custody, cancellation or authority refusal stopped capture.
    Failure,
}

/// Partial durable results and remote cleanup state survive every later error.
#[derive(Clone)]
pub struct CaptureReport {
    /// Ordered durable sources, including empty batches and duplicate notifications.
    pub retained: Vec<RetainedBatch>,
    /// Definitely durable logical Create intent, written before dispatch.
    pub create_intent: Option<RetainedBatch>,
    /// Definitely durable complete Create response, written before any poll.
    pub created_subscription: Option<RetainedBatch>,
    /// Durable cleanup obligation retained before any Unsubscribe dispatch.
    pub unsubscribe_intent: Option<RetainedBatch>,
    /// Durable complete cleanup response, including refused or malformed outcomes.
    pub unsubscribe_outcome: Option<RetainedBatch>,
    /// Definitely durable terminal Unsubscribe observation, if its sink succeeded.
    pub unsubscribe_receipt: Option<RetainedBatch>,
    /// Durable pre-dispatch renewal obligations, including attempts with unknown outcomes.
    pub renewal_intents: Vec<RetainedBatch>,
    /// Durable complete renewal responses, including rejected/malformed bodies.
    pub renewal_outcomes: Vec<RetainedBatch>,
    /// Validated and durably observed successful renewal responses in this invocation.
    pub renewals: u32,
    /// Actual HTTP attempts, including authentication retries and cleanup.
    pub exchanges: u32,
    /// Complete responses successfully handed to durable custody.
    pub pulls: u32,
    /// Total notifications in those retained responses, without deduplication.
    pub notifications: u64,
    /// Explicit last observed remote subscription outcome.
    pub subscription_state: SubscriptionState,
    /// Why the acquisition stopped.
    pub stop: CaptureStop,
    /// Payload-free cleanup failure when Unsubscribe could not be confirmed.
    pub cleanup_error: Option<&'static str>,
    subscription_source: Option<Vec<u8>>,
    subscription_started_ns: Option<u64>,
    subscription_completed_ns: Option<u64>,
    subscription_message_id: Option<String>,
}
impl Default for CaptureReport {
    fn default() -> Self {
        Self {
            retained: Vec::new(),
            create_intent: None,
            created_subscription: None,
            unsubscribe_intent: None,
            unsubscribe_outcome: None,
            unsubscribe_receipt: None,
            renewal_intents: Vec::new(),
            renewal_outcomes: Vec::new(),
            renewals: 0,
            exchanges: 0,
            pulls: 0,
            notifications: 0,
            subscription_state: SubscriptionState::NotCreated,
            stop: CaptureStop::Failure,
            cleanup_error: None,
            subscription_source: None,
            subscription_started_ns: None,
            subscription_completed_ns: None,
            subscription_message_id: None,
        }
    }
}

impl CaptureReport {
    /// Complete Create response, even if no PullMessages batch reached custody.
    /// It may be malformed or have an unapproved EPR; retaining it grants no route authority.
    pub fn subscription_response(&self) -> Option<&[u8]> {
        self.subscription_source.as_deref()
    }

    /// Original Create admission time, before any authentication retry.
    pub const fn subscription_started_ns(&self) -> Option<u64> {
        self.subscription_started_ns
    }

    /// Time at which the complete Create response was observed.
    pub const fn subscription_completed_ns(&self) -> Option<u64> {
        self.subscription_completed_ns
    }

    /// Logical Create identity, useful when reconciling an indeterminate response.
    pub fn subscription_message_id(&self) -> Option<&str> {
        self.subscription_message_id.as_deref()
    }
}
impl fmt::Debug for CaptureReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaptureReport")
            .field("retained", &self.retained)
            .field("create_intent", &self.create_intent)
            .field("created_subscription", &self.created_subscription)
            .field("unsubscribe_intent", &self.unsubscribe_intent)
            .field("unsubscribe_outcome", &self.unsubscribe_outcome)
            .field("unsubscribe_receipt", &self.unsubscribe_receipt)
            .field("renewal_intents", &self.renewal_intents)
            .field("renewal_outcomes", &self.renewal_outcomes)
            .field("renewals", &self.renewals)
            .field("exchanges", &self.exchanges)
            .field("pulls", &self.pulls)
            .field("notifications", &self.notifications)
            .field("subscription_state", &self.subscription_state)
            .field("stop", &self.stop)
            .field("cleanup_error", &self.cleanup_error)
            .field(
                "subscription_source_bytes",
                &self.subscription_source.as_ref().map(Vec::len),
            )
            .finish_non_exhaustive()
    }
}

/// Payload-free failure cause; retained source identities live in CaptureFailure.report.
#[derive(Debug)]
pub enum PullPointError {
    /// Native transport, authentication, SOAP or context refusal.
    Client(ClientError),
    /// Canonical source custody failed.
    Retention(MetadataError),
    /// Invalid independent owner configuration, before any creation attempt.
    Configuration,
    /// Remote response has more notifications than the exact requested limit.
    MessageLimit,
    /// The reported lease cannot safely admit even one bounded poll and cleanup.
    Lease,
}
impl PullPointError {
    /// Stable diagnostic identity; no endpoints, values or credentials are reflected.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Client(error) => error.code(),
            Self::Retention(error) => error.code(),
            Self::Configuration => "ERR-ONVIF-PULLPOINT-CONFIG-001",
            Self::MessageLimit => "ERR-ONVIF-PULLPOINT-LIMIT-001",
            Self::Lease => "ERR-ONVIF-PULLPOINT-LEASE-001",
        }
    }
}
impl fmt::Display for PullPointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for PullPointError {}
impl From<ClientError> for PullPointError {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}
impl From<WireError> for PullPointError {
    fn from(error: WireError) -> Self {
        Self::Client(ClientError::Wire(error))
    }
}
impl From<MetadataError> for PullPointError {
    fn from(error: MetadataError) -> Self {
        Self::Retention(error)
    }
}

/// An error never discards prior durable batches or claims that remote cleanup succeeded.
#[derive(Debug)]
pub struct CaptureFailure {
    /// Complete ordered partial receipts and observed cleanup state.
    pub report: CaptureReport,
    /// Primary failure; a secondary cleanup refusal is also recorded in the report.
    pub error: PullPointError,
}
impl CaptureFailure {
    /// Stable primary failure identity.
    pub fn code(&self) -> &'static str {
        self.error.code()
    }
}
impl fmt::Display for CaptureFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for CaptureFailure {}

/// Whether an exact route lies inside an independently supplied service subtree.
/// Query tokens are checked by the route constructor and never become path authority.
pub fn route_in_service_root(route: &HttpRoute, service_root: &str) -> bool {
    route.is_event_subscription() && event_target_in_root(route.target(), service_root)
}

/// Acquire at most max_pulls complete responses and retain each before another poll.
///
/// The sink must publish the source, exact Create response, and acquisition binding
/// through the live-specific custody API. An empty response is retained exactly but
/// establishes no absence/coverage. Errors preserve already returned sink receipts.
/// No transport error recreates a subscription or repeats a PullMessages operation;
/// only an explicit HTTP 401 permits one same-request Digest retry.
///
/// Cleanup uses reserved time, steps and exchanges, but never overrides cancellation,
/// revocation or the absolute deadline. If cleanup cannot run, the report preserves
/// Active/Indeterminate and an error rather than claiming that the camera stopped.
pub fn capture(
    config: &PullPointConfig,
    cx: &impl OnvifContext,
    mut sink: impl FnMut(PullBatch<'_>) -> Result<RetainedBatch, MetadataError>,
) -> Result<CaptureReport, CaptureFailure> {
    // Renewal has mandatory pre-dispatch custody. The legacy batch-only API cannot provide it.
    if config.max_renewals != 0 {
        return Err(CaptureFailure {
            report: CaptureReport::default(),
            error: PullPointError::Configuration,
        });
    }
    capture_inner(
        config,
        cx,
        |_| Ok(None),
        |batch| sink(batch).map(Into::into),
    )
}

/// Capture with mandatory durable Create intent and response callbacks.
///
/// The intent callback completes before dispatch. The Created callback completes
/// before the first poll; if it refuses, cleanup is still attempted under the
/// original live authority. A cold intent without a response remains indeterminate
/// and never authorizes another Create. Earlier returned receipts survive refusal.
pub fn capture_with_control(
    config: &PullPointConfig,
    cx: &impl OnvifContext,
    mut control: impl FnMut(PullPointControl<'_>) -> Result<RetainedBatch, MetadataError>,
    mut sink: impl FnMut(PullBatch<'_>) -> Result<RetainedBatch, MetadataError>,
) -> Result<CaptureReport, CaptureFailure> {
    capture_with_progress(
        config,
        cx,
        |event| control(event).map(Into::into),
        |batch| sink(batch).map(Into::into),
    )
}

/// Capture while preserving a durable receipt alongside any post-commit refusal.
/// A storage-budget or storage-authority denial stops polling even when network
/// authority still permits the separately bounded Unsubscribe obligation.
pub fn capture_with_progress(
    config: &PullPointConfig,
    cx: &impl OnvifContext,
    mut control: impl FnMut(PullPointControl<'_>) -> Result<RetainedProgress, MetadataError>,
    sink: impl FnMut(PullBatch<'_>) -> Result<RetainedProgress, MetadataError>,
) -> Result<CaptureReport, CaptureFailure> {
    capture_inner(config, cx, |event| control(event).map(Some), sink)
}

fn capture_inner(
    config: &PullPointConfig,
    cx: &impl OnvifContext,
    mut control: impl FnMut(PullPointControl<'_>) -> Result<Option<RetainedProgress>, MetadataError>,
    mut sink: impl FnMut(PullBatch<'_>) -> Result<RetainedProgress, MetadataError>,
) -> Result<CaptureReport, CaptureFailure> {
    let mut report = CaptureReport::default();
    let mut budget = Budget::default();
    let active = begin(config, cx, &mut budget, &mut report, &mut control);
    let result = match active {
        Ok(active) => {
            let captured = control(PullPointControl::Created {
                source: &active.source,
                message_id: &active.message_id,
                started_ns: active.started_ns,
                completed_ns: active.completed_ns,
                authenticated: active.authenticated,
            })
            .map_err(PullPointError::Retention)
            .and_then(|progress| {
                if let Some(progress) = progress {
                    report.created_subscription = Some(progress.receipt);
                    if let Some(error) = progress.stop {
                        return Err(error);
                    }
                }
                poll(
                    config,
                    cx,
                    &mut budget,
                    &active,
                    &mut report,
                    &mut control,
                    &mut sink,
                )
            });
            let cleaned = finish_cleanup(
                config,
                cx,
                &mut budget,
                &active.subscription,
                &active.route,
                &active.message_id,
                &mut report,
                &mut control,
            );
            match cleaned {
                Ok(()) => report.subscription_state = SubscriptionState::Unsubscribed,
                Err(ref error) => report.cleanup_error = Some(error.code()),
            }
            match captured {
                Err(error) => Err(error),
                Ok(()) => cleaned,
            }
        }
        Err(error) => Err(error),
    };
    report.exchanges = budget.exchanges;
    match result {
        Ok(()) => Ok(report),
        Err(error) => {
            report.stop = CaptureStop::Failure;
            Err(CaptureFailure { report, error })
        }
    }
}

struct Active {
    subscription: PullPointSubscription,
    route: HttpRoute,
    source: Vec<u8>,
    started_ns: u64,
    completed_ns: u64,
    lease_deadline_ns: u64,
    message_id: String,
    authenticated: bool,
}

fn begin(
    config: &PullPointConfig,
    cx: &impl OnvifContext,
    budget: &mut Budget,
    report: &mut CaptureReport,
    control: &mut impl FnMut(PullPointControl<'_>) -> Result<Option<RetainedProgress>, MetadataError>,
) -> Result<Active, PullPointError> {
    validate_config(config)?;
    let first = budget.now(config.deadline_ns, config.max_steps, cx)?;
    let remaining = config
        .deadline_ns
        .checked_sub(first)
        .ok_or(ClientError::Deadline)?;
    if remaining > MAX_SESSION_NS || remaining <= CLEANUP_RESERVE_NS {
        return Err(PullPointError::Configuration);
    }
    let endpoint = format!(
        "http://{}{}",
        config.events.authority(),
        config.events.target()
    );
    let request = create_pull_point_request(&endpoint, config.lifetime_seconds)?;
    let started_ns = budget.now(work_deadline(config), work_steps(config), cx)?;
    cx.checkpoint(
        &config.events,
        HttpOperation::Write,
        started_ns,
        work_deadline(config),
    )
    .map_err(denial)?;
    let message_id = next_request_id(
        &config.events,
        work_deadline(config),
        work_steps(config),
        cx,
        budget,
    )?;
    let request = request.with_message_id(&message_id)?;
    report.subscription_started_ns = Some(started_ns);
    report.subscription_message_id = Some(message_id.clone());
    if let Some(progress) = control(PullPointControl::CreateIntent {
        events: &config.events,
        service_root: &config.service_root,
        message_id: &message_id,
        started_ns,
        lifetime_seconds: config.lifetime_seconds,
    })? {
        report.create_intent = Some(progress.receipt);
        if let Some(error) = progress.stop {
            return Err(error);
        }
    }
    // Dispatch can begin only after the intent sink acknowledges durable custody.
    // The next exchange independently rechecks time and live route authority.
    report.subscription_state = SubscriptionState::Indeterminate;
    let (response, authenticated) = exchange(
        config,
        &config.events,
        &request,
        work_deadline(config),
        work_steps(config),
        cx,
        budget,
    )?;
    report.subscription_source = Some(response.body().to_vec());
    let completed_ns = budget.now(work_deadline(config), work_steps(config), cx)?;
    report.subscription_completed_ns = Some(completed_ns);
    let source = soap_body(&response)?;
    wire::require_relates_to(source, &message_id)?;
    let subscription = parse_pull_point_subscription(source)?;
    let route = config
        .events
        .event_subscription(subscription.endpoint(), &config.service_root)
        .map_err(|_| ClientError::Scope)?;
    let lease_ns = u64::from(subscription.lease_seconds().min(config.lifetime_seconds))
        .checked_mul(1_000_000_000)
        .ok_or(PullPointError::Lease)?;
    let lease_deadline_ns = started_ns.saturating_add(lease_ns);
    report.subscription_state = SubscriptionState::Active;
    Ok(Active {
        subscription,
        route,
        source: response.into_body(),
        started_ns,
        completed_ns,
        lease_deadline_ns,
        message_id,
        authenticated,
    })
}

#[allow(clippy::too_many_arguments)]
fn poll(
    config: &PullPointConfig,
    cx: &impl OnvifContext,
    budget: &mut Budget,
    active: &Active,
    report: &mut CaptureReport,
    control: &mut impl FnMut(PullPointControl<'_>) -> Result<Option<RetainedProgress>, MetadataError>,
    sink: &mut impl FnMut(PullBatch<'_>) -> Result<RetainedProgress, MetadataError>,
) -> Result<(), PullPointError> {
    let mut lease_deadline_ns = active.lease_deadline_ns;
    let lease_work_deadline = lease_deadline_ns.saturating_sub(CLEANUP_RESERVE_NS);
    if lease_work_deadline
        <= active
            .completed_ns
            .saturating_add(1_000_000_000 + RESPONSE_MARGIN_NS)
        && config.max_renewals == 0
    {
        return Err(PullPointError::Lease);
    }
    for pull_index in 0..config.max_pulls {
        if budget.steps >= work_steps(config) {
            report.stop = CaptureStop::StepReserve;
            return Ok(());
        }
        let mut started_ns = budget.now(config.deadline_ns, work_steps(config), cx)?;
        let mut lease_work_deadline = lease_deadline_ns.saturating_sub(CLEANUP_RESERVE_NS);
        let wanted = u64::from(config.pull_timeout_seconds) * 1_000_000_000 + RESPONSE_MARGIN_NS;
        // Renew only when the lease would constrain the next requested poll and the unchanged
        // session has enough remaining work time. Never use the cleanup reservation for Renew.
        if report.renewals < config.max_renewals
            && lease_work_deadline < work_deadline(config)
            && lease_work_deadline.saturating_sub(started_ns) < wanted
            && work_deadline(config).saturating_sub(started_ns) > wanted + RESPONSE_MARGIN_NS
            && lease_work_deadline.saturating_sub(started_ns) > RESPONSE_MARGIN_NS
        {
            lease_deadline_ns = renew(
                config,
                cx,
                budget,
                active,
                report,
                control,
                lease_work_deadline,
            )?;
            started_ns = budget.now(config.deadline_ns, work_steps(config), cx)?;
            lease_work_deadline = lease_deadline_ns.saturating_sub(CLEANUP_RESERVE_NS);
        }
        let deadline = work_deadline(config).min(lease_work_deadline);
        let available_ns = deadline.saturating_sub(started_ns);
        let available_seconds = available_ns.saturating_sub(RESPONSE_MARGIN_NS) / 1_000_000_000;
        if available_seconds == 0 {
            report.stop = if lease_work_deadline < work_deadline(config) {
                CaptureStop::LeaseReserve
            } else {
                CaptureStop::DeadlineReserve
            };
            return Ok(());
        }
        let timeout_seconds = config
            .pull_timeout_seconds
            .min(u32::try_from(available_seconds).unwrap_or(u32::MAX));
        let request =
            pull_messages_request(&active.subscription, timeout_seconds, config.message_limit)?;
        let message_id = next_request_id(&active.route, deadline, work_steps(config), cx, budget)?;
        let request = request.with_message_id(&message_id)?;
        let (response, authenticated) = exchange(
            config,
            &active.route,
            &request,
            deadline,
            work_steps(config),
            cx,
            budget,
        )?;
        let completed_ns = budget.now(deadline, work_steps(config), cx)?;
        let source = soap_body(&response)?;
        validate_relates_to(source, &message_id)?;
        let document = parse_pull_messages_response(source)?;
        if document.notifications.len() > usize::from(config.message_limit) {
            return Err(PullPointError::MessageLimit);
        }
        let now = budget.now(deadline, work_steps(config), cx)?;
        cx.checkpoint(&active.route, HttpOperation::Release, now, deadline)
            .map_err(denial)?;
        let retained = sink(PullBatch {
            source,
            route: &active.route,
            pull_index,
            started_ns,
            completed_ns,
            authenticated,
            subscription_response: &active.source,
            subscription_started_ns: active.started_ns,
            subscription_completed_ns: active.completed_ns,
            message_id: &message_id,
            subscription_message_id: &active.message_id,
        })?;
        // A completed durable sink receipt is retained even if cancellation arrives
        // immediately afterwards. The next admission and cleanup will observe it.
        report.retained.push(retained.receipt);
        report.pulls += 1;
        report.notifications += document.notifications.len() as u64;
        if let Some(error) = retained.stop {
            return Err(error);
        }
    }
    report.stop = CaptureStop::PullLimit;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn renew(
    config: &PullPointConfig,
    cx: &impl OnvifContext,
    budget: &mut Budget,
    active: &Active,
    report: &mut CaptureReport,
    control: &mut impl FnMut(PullPointControl<'_>) -> Result<Option<RetainedProgress>, MetadataError>,
    old_work_deadline: u64,
) -> Result<u64, PullPointError> {
    let deadline = old_work_deadline.min(work_deadline(config));
    let started_ns = budget.now(deadline, work_steps(config), cx)?;
    let message_id = next_request_id(&active.route, deadline, work_steps(config), cx, budget)?;
    let request = renew_pull_point_request(&active.subscription, config.lifetime_seconds)?
        .with_message_id(&message_id)?;
    let progress = control(PullPointControl::RenewIntent {
        route: &active.route,
        message_id: &message_id,
        started_ns,
        lifetime_seconds: config.lifetime_seconds,
        renewal_index: report.renewals,
    })?
    .ok_or(MetadataError::Authority)?;
    report.renewal_intents.push(progress.receipt);
    if let Some(error) = progress.stop {
        return Err(error);
    }
    let (response, authenticated, response_error) =
        renew_exchange(config, &active.route, &request, deadline, cx, budget)?;
    let completed = budget.now(deadline, work_steps(config), cx);
    let completed_ns = completed.as_ref().ok().copied();
    let parsed = completed.and_then(|now| {
        if let Some(error) = response_error {
            return Err(error);
        }
        let source = soap_body(&response)?;
        wire::require_relates_to(source, &message_id)?;
        let lease = parse_renew_response(source)?;
        cx.checkpoint(&active.route, HttpOperation::Release, now, deadline)
            .map_err(denial)?;
        Ok(lease)
    });
    // A complete rejected/malformed response is still retained. No further poll can occur
    // until this callback succeeds and the independently validated result is usable.
    let progress = control(PullPointControl::Renewed {
        source: response.body(),
        message_id: &message_id,
        completed_ns,
        authenticated,
        http_status: response.status(),
        soap_content_type: is_soap_response(&response),
    })?
    .ok_or(MetadataError::Authority)?;
    report.renewal_outcomes.push(progress.receipt);
    if parsed.is_ok() {
        report.renewals += 1;
    }
    if let Some(error) = progress.stop {
        return Err(error);
    }
    let lease = parsed?;
    let lease_ns = u64::from(lease.lease_seconds().min(config.lifetime_seconds)) * 1_000_000_000;
    let renewed_deadline = started_ns
        .checked_add(lease_ns)
        .ok_or(PullPointError::Lease)?;
    if renewed_deadline.saturating_sub(CLEANUP_RESERVE_NS)
        <= completed_ns
            .ok_or(PullPointError::Lease)?
            .saturating_add(1_000_000_000 + RESPONSE_MARGIN_NS)
    {
        return Err(PullPointError::Lease);
    }
    Ok(renewed_deadline)
}

/// Preserve complete authentication refusals as renewal outcomes. A lost transport result
/// still has no complete body to retain and leaves the pre-dispatch intent unresolved.
fn renew_exchange(
    config: &PullPointConfig,
    route: &HttpRoute,
    request: &SoapRequest,
    deadline: u64,
    cx: &impl OnvifContext,
    budget: &mut Budget,
) -> Result<(HttpResponse, bool, Option<ClientError>), ClientError> {
    let (response, authenticated, _, refusal) = control_exchange(
        config,
        route,
        request,
        deadline,
        work_steps(config),
        cx,
        budget,
    )?;
    Ok((response, authenticated, refusal))
}

/// Retain the last complete control response even when authentication refuses it. A lost
/// transport response remains unresolved; the explicit 401 retry is the same logical request.
fn control_exchange(
    config: &PullPointConfig,
    route: &HttpRoute,
    request: &SoapRequest,
    deadline: u64,
    maximum_steps: u32,
    cx: &impl OnvifContext,
    budget: &mut Budget,
) -> Result<(HttpResponse, bool, u64, Option<ClientError>), ClientError> {
    let (first, completed_ns) = send_observed(
        config,
        route,
        request,
        None,
        deadline,
        maximum_steps,
        cx,
        budget,
    )?;
    if first.status() != 401 {
        return Ok((first, false, completed_ns, None));
    }
    let authorization = (|| {
        let auth = config
            .auth
            .as_ref()
            .ok_or(ClientError::AuthenticationRequired)?;
        let header = first
            .digest_challenge()
            .ok_or(ClientError::AuthenticationRefused)?;
        let challenge = DigestChallenge::parse(header, &auth.expected_realm, auth.policy)?;
        let now = budget.now(deadline, maximum_steps, cx)?;
        cx.checkpoint(route, HttpOperation::Write, now, deadline)
            .map_err(denial)?;
        cx.authorize(route, &challenge)
    })();
    let authorization = match authorization {
        Ok(value) => value,
        Err(error) => return Ok((first, false, completed_ns, Some(error))),
    };
    let (response, completed_ns) = send_observed(
        config,
        route,
        request,
        Some(&authorization),
        deadline,
        maximum_steps,
        cx,
        budget,
    )?;
    let error = (response.status() == 401).then_some(ClientError::AuthenticationRefused);
    Ok((response, true, completed_ns, error))
}

#[allow(clippy::too_many_arguments)]
fn finish_cleanup(
    config: &PullPointConfig,
    cx: &impl OnvifContext,
    budget: &mut Budget,
    subscription: &PullPointSubscription,
    route: &HttpRoute,
    create_message_id: &str,
    report: &mut CaptureReport,
    control: &mut impl FnMut(PullPointControl<'_>) -> Result<Option<RetainedProgress>, MetadataError>,
) -> Result<(), PullPointError> {
    let started_ns = budget.now(config.deadline_ns, config.max_steps, cx)?;
    let message_id = next_request_id(route, config.deadline_ns, config.max_steps, cx, budget)?;
    if message_id == create_message_id {
        return Err(ClientError::Entropy.into());
    }
    let request = unsubscribe_pull_point_request(subscription)?.with_message_id(&message_id)?;
    if let Some(progress) = control(PullPointControl::UnsubscribeIntent {
        route,
        message_id: &message_id,
        create_message_id,
        request_digest: ContentDigest::sha256(request.body()),
        started_ns,
    })? {
        report.unsubscribe_intent = Some(progress.receipt);
        if let Some(error) = progress.stop {
            return Err(error);
        }
    }
    // Recorded entrypoints always return Some above. Only the explicitly batch-only legacy
    // capture adapter can omit control custody; its existing cleanup behavior is unchanged.
    let (response, authenticated, completed_ns, response_error) = control_exchange(
        config,
        route,
        &request,
        config.deadline_ns,
        config.max_steps,
        cx,
        budget,
    )?;
    let outcome = control(PullPointControl::UnsubscribeOutcome {
        route,
        source: response.body(),
        message_id: &message_id,
        started_ns,
        completed_ns: Some(completed_ns),
        authenticated,
        http_status: response.status(),
        soap_content_type: is_soap_response(&response),
    });
    let custody_error = match outcome {
        Ok(Some(progress)) => {
            // A returned immutable receipt survives parsing, cancellation, or finalization.
            report.unsubscribe_outcome = Some(progress.receipt);
            progress.stop
        }
        Ok(None) => None,
        Err(error) => Some(error.into()),
    };
    let validated = (|| {
        if let Some(error) = response_error {
            return Err(error);
        }
        let source = soap_body(&response)?;
        wire::require_relates_to(source, &message_id)?;
        parse_unsubscribe_response(source)?;
        Ok::<_, ClientError>(())
    })();
    if validated.is_ok() {
        // The complete response was released under live authority. A later custody or clock
        // refusal cannot erase its validated remote outcome, or justify an automatic resend.
        report.subscription_state = SubscriptionState::Unsubscribed;
    }
    if let Some(error) = custody_error {
        return Err(error);
    }
    validated?;
    let now = budget.now(config.deadline_ns, config.max_steps, cx)?;
    cx.checkpoint(route, HttpOperation::Release, now, config.deadline_ns)
        .map_err(denial)?;
    if let Some(progress) = control(PullPointControl::Unsubscribed {
        route,
        source: response.body(),
        message_id: &message_id,
        started_ns,
        completed_ns,
        authenticated,
    })? {
        report.unsubscribe_receipt = Some(progress.receipt);
        if let Some(error) = progress.stop {
            return Err(error);
        }
    }
    Ok(())
}

/// Explicitly unsubscribe a previously verified endpoint under fresh live authority.
///
/// The caller independently checks its retained generation/route pins against
/// this new configuration. This function performs no Create or PullMessages and
/// never interprets a retained approval as a current grant. Its sink must retain a new,
/// current cleanup intent before dispatch, returning a stop with the receipt for replayed
/// or stale attempts. Complete responses reach custody before interpretation; a validated
/// success also retains the existing terminal receipt when current authority permits it.
pub fn unsubscribe_existing(
    config: &PullPointConfig,
    cx: &impl OnvifContext,
    subscription: &PullPointSubscription,
    create_message_id: &str,
    mut control: impl FnMut(PullPointControl<'_>) -> Result<RetainedProgress, MetadataError>,
) -> Result<CaptureReport, CaptureFailure> {
    let mut report = CaptureReport {
        // This is the last historical Create observation, not a fresh active-state proof.
        subscription_state: SubscriptionState::Active,
        stop: CaptureStop::CleanupOnly,
        ..CaptureReport::default()
    };
    let mut budget = Budget::default();
    let result = (|| {
        validate_config(config)?;
        let first = budget.now(config.deadline_ns, config.max_steps, cx)?;
        if config.deadline_ns.saturating_sub(first) > MAX_SESSION_NS {
            return Err(PullPointError::Configuration);
        }
        unsubscribe_pull_point_request(subscription)?.with_message_id(create_message_id)?;
        let route = config
            .events
            .event_subscription(subscription.endpoint(), &config.service_root)
            .map_err(|_| ClientError::Scope)?;
        finish_cleanup(
            config,
            cx,
            &mut budget,
            subscription,
            &route,
            create_message_id,
            &mut report,
            &mut |event| control(event).map(Some),
        )
    })();
    report.exchanges = budget.exchanges;
    match result {
        Ok(()) => Ok(report),
        Err(error) => {
            report.cleanup_error = Some(error.code());
            report.stop = CaptureStop::Failure;
            Err(CaptureFailure { report, error })
        }
    }
}

/// Validate all static owner bounds without reading a clock, credentials, disk or network.
pub fn validate_config(config: &PullPointConfig) -> Result<(), PullPointError> {
    config
        .limits
        .validate()
        .map_err(|_| PullPointError::Configuration)?;
    if !route_in_service_root(&config.events, &config.service_root)
        || config.deadline_ns <= CLEANUP_RESERVE_NS
        || config.max_steps <= CLEANUP_RESERVE_STEPS
        || config.max_steps > MAX_STEPS
        || !(1..=MAX_PULLS).contains(&config.max_pulls)
        || config.max_renewals > MAX_RENEWALS
        || !(1..=30).contains(&config.pull_timeout_seconds)
        || !(1..=128).contains(&config.message_limit)
        || !(1..=3600).contains(&config.lifetime_seconds)
        || config.limits.body_bytes > wire::MAX_SOAP_BYTES
    {
        return Err(PullPointError::Configuration);
    }
    if let Some(auth) = &config.auth {
        if auth.expected_realm.is_empty()
            || auth.expected_realm.len() > 512
            || !auth
                .expected_realm
                .bytes()
                .all(|byte| (32..127).contains(&byte))
            || auth.policy.allow_legacy_no_qop && !auth.policy.allow_legacy_md5
        {
            return Err(PullPointError::Configuration);
        }
    }
    Ok(())
}

const fn work_deadline(config: &PullPointConfig) -> u64 {
    config.deadline_ns.saturating_sub(CLEANUP_RESERVE_NS)
}
const fn work_steps(config: &PullPointConfig) -> u32 {
    config.max_steps.saturating_sub(CLEANUP_RESERVE_STEPS)
}

#[derive(Default)]
struct Budget {
    last_ns: Option<u64>,
    steps: u32,
    exchanges: u32,
    used_ids: Vec<[u8; 16]>,
}
impl Budget {
    fn now(
        &mut self,
        deadline: u64,
        maximum_steps: u32,
        cx: &impl OnvifContext,
    ) -> Result<u64, ClientError> {
        self.steps = self.steps.checked_add(1).ok_or(ClientError::Budget)?;
        if self.steps > maximum_steps {
            return Err(ClientError::Budget);
        }
        let now = cx.now_ns()?;
        if self.last_ns.is_some_and(|previous| now < previous) {
            return Err(ClientError::Clock);
        }
        self.last_ns = Some(now);
        if now >= deadline {
            return Err(ClientError::Deadline);
        }
        Ok(now)
    }
}

fn next_request_id(
    route: &HttpRoute,
    deadline: u64,
    maximum_steps: u32,
    cx: &impl OnvifContext,
    budget: &mut Budget,
) -> Result<String, ClientError> {
    let now = budget.now(deadline, maximum_steps, cx)?;
    cx.checkpoint(route, HttpOperation::Write, now, deadline)
        .map_err(denial)?;
    let nonce = cx.event_request_id()?;
    if nonce == [0; 16]
        || budget.used_ids.contains(&nonce)
        || budget.used_ids.len() >= (MAX_PULLS + MAX_RENEWALS + 2) as usize
    {
        return Err(ClientError::Entropy);
    }
    budget.used_ids.push(nonce);
    let mut id = String::from("urn:fss:onvif:");
    for byte in nonce {
        use std::fmt::Write as _;
        write!(&mut id, "{byte:02x}").map_err(|_| ClientError::Entropy)?;
    }
    Ok(id)
}

fn denial(error: HttpDenial) -> ClientError {
    match error {
        HttpDenial::Cancelled => ClientError::Cancelled,
        HttpDenial::Deadline => ClientError::Deadline,
        HttpDenial::Budget => ClientError::Budget,
        HttpDenial::Unauthorized | HttpDenial::Revoked => ClientError::Authority,
    }
}

fn exchange(
    config: &PullPointConfig,
    route: &HttpRoute,
    request: &SoapRequest,
    deadline: u64,
    maximum_steps: u32,
    cx: &impl OnvifContext,
    budget: &mut Budget,
) -> Result<(HttpResponse, bool), ClientError> {
    let first = send(
        config,
        route,
        request,
        None,
        deadline,
        maximum_steps,
        cx,
        budget,
    )?;
    if first.status() != 401 {
        return Ok((first, false));
    }
    let auth = config
        .auth
        .as_ref()
        .ok_or(ClientError::AuthenticationRequired)?;
    let header = first
        .digest_challenge()
        .ok_or(ClientError::AuthenticationRefused)?;
    let challenge = DigestChallenge::parse(header, &auth.expected_realm, auth.policy)?;
    let now = budget.now(deadline, maximum_steps, cx)?;
    cx.checkpoint(route, HttpOperation::Write, now, deadline)
        .map_err(denial)?;
    let authorization = cx.authorize(route, &challenge)?;
    let response = send(
        config,
        route,
        request,
        Some(&authorization),
        deadline,
        maximum_steps,
        cx,
        budget,
    )?;
    if response.status() == 401 {
        return Err(ClientError::AuthenticationRefused);
    }
    Ok((response, true))
}

#[allow(clippy::too_many_arguments)]
fn send(
    config: &PullPointConfig,
    route: &HttpRoute,
    request: &SoapRequest,
    authorization: Option<&DigestAuthorization>,
    deadline: u64,
    maximum_steps: u32,
    cx: &impl OnvifContext,
    budget: &mut Budget,
) -> Result<HttpResponse, ClientError> {
    send_observed(
        config,
        route,
        request,
        authorization,
        deadline,
        maximum_steps,
        cx,
        budget,
    )
    .map(|(response, _)| response)
}

#[allow(clippy::too_many_arguments)]
fn send_observed(
    config: &PullPointConfig,
    route: &HttpRoute,
    request: &SoapRequest,
    authorization: Option<&DigestAuthorization>,
    deadline: u64,
    maximum_steps: u32,
    cx: &impl OnvifContext,
    budget: &mut Budget,
) -> Result<(HttpResponse, u64), ClientError> {
    budget.exchanges = budget.exchanges.checked_add(1).ok_or(ClientError::Budget)?;
    let maximum_exchanges = config
        .max_pulls
        .saturating_add(config.max_renewals)
        .saturating_add(2)
        .saturating_mul(2);
    if budget.exchanges > maximum_exchanges {
        return Err(ClientError::Budget);
    }
    let now = budget.now(deadline, maximum_steps, cx)?;
    let mut exchange = HttpExchange::connect(
        route.clone(),
        request,
        authorization,
        config.limits,
        now,
        deadline,
        cx,
    )?;
    loop {
        let now = budget.now(deadline, maximum_steps, cx)?;
        match exchange.step(now, cx)? {
            HttpProgress::Complete => {
                let now = budget.now(deadline, maximum_steps, cx)?;
                return exchange
                    .take_response(now, cx)
                    .map(|response| (response, now))
                    .map_err(Into::into);
            }
            HttpProgress::Advanced => {}
            HttpProgress::Pending => cx.wait(deadline)?,
        }
    }
}

fn soap_body(response: &HttpResponse) -> Result<&[u8], ClientError> {
    let is_soap = is_soap_response(response);
    if response.status() != 200 {
        if is_soap && matches!(response.status(), 400 | 500) {
            return Err(match wire::parse_soap_fault(response.body()) {
                Ok(fault) => ClientError::Wire(WireError::SoapFault(fault)),
                Err(WireError::UnexpectedResponse) => ClientError::HttpStatus(response.status()),
                Err(error) => ClientError::Wire(error),
            });
        }
        return Err(ClientError::HttpStatus(response.status()));
    }
    if !is_soap {
        return Err(ClientError::Unsupported);
    }
    Ok(response.body())
}

fn is_soap_response(response: &HttpResponse) -> bool {
    response.content_type().is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/soap+xml"))
    })
}
