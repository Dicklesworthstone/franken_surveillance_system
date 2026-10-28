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
    parse_pull_messages_response, parse_pull_point_subscription, parse_unsubscribe_response,
    pull_messages_request, unsubscribe_pull_point_request, validate_relates_to,
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
    let mut report = CaptureReport::default();
    let mut budget = Budget::default();
    let active = begin(config, cx, &mut budget, &mut report);
    let result = match active {
        Ok(active) => {
            let captured = poll(config, cx, &mut budget, &active, &mut report, &mut sink);
            let cleaned = cleanup(config, cx, &mut budget, &active);
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
}

fn begin(
    config: &PullPointConfig,
    cx: &impl OnvifContext,
    budget: &mut Budget,
    report: &mut CaptureReport,
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
    report.subscription_state = SubscriptionState::Indeterminate;
    report.subscription_started_ns = Some(started_ns);
    report.subscription_message_id = Some(message_id.clone());
    let (response, _) = exchange(
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
    validate_relates_to(source, &message_id)?;
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
    })
}

fn poll(
    config: &PullPointConfig,
    cx: &impl OnvifContext,
    budget: &mut Budget,
    active: &Active,
    report: &mut CaptureReport,
    sink: &mut impl FnMut(PullBatch<'_>) -> Result<RetainedBatch, MetadataError>,
) -> Result<(), PullPointError> {
    let lease_work_deadline = active.lease_deadline_ns.saturating_sub(CLEANUP_RESERVE_NS);
    if lease_work_deadline
        <= active
            .completed_ns
            .saturating_add(1_000_000_000 + RESPONSE_MARGIN_NS)
    {
        return Err(PullPointError::Lease);
    }
    for pull_index in 0..config.max_pulls {
        if budget.steps >= work_steps(config) {
            report.stop = CaptureStop::StepReserve;
            return Ok(());
        }
        let started_ns = budget.now(config.deadline_ns, work_steps(config), cx)?;
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
        report.retained.push(retained);
        report.pulls += 1;
        report.notifications += document.notifications.len() as u64;
    }
    report.stop = CaptureStop::PullLimit;
    Ok(())
}

fn cleanup(
    config: &PullPointConfig,
    cx: &impl OnvifContext,
    budget: &mut Budget,
    active: &Active,
) -> Result<(), PullPointError> {
    let message_id = next_request_id(
        &active.route,
        config.deadline_ns,
        config.max_steps,
        cx,
        budget,
    )?;
    let request =
        unsubscribe_pull_point_request(&active.subscription)?.with_message_id(&message_id)?;
    let (response, _) = exchange(
        config,
        &active.route,
        &request,
        config.deadline_ns,
        config.max_steps,
        cx,
        budget,
    )?;
    let source = soap_body(&response)?;
    validate_relates_to(source, &message_id)?;
    parse_unsubscribe_response(source)?;
    let now = budget.now(config.deadline_ns, config.max_steps, cx)?;
    cx.checkpoint(
        &active.route,
        HttpOperation::Release,
        now,
        config.deadline_ns,
    )
    .map_err(denial)?;
    Ok(())
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
    if nonce == [0; 16] || budget.used_ids.contains(&nonce) || budget.used_ids.len() >= 66 {
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
    budget.exchanges = budget.exchanges.checked_add(1).ok_or(ClientError::Budget)?;
    let maximum_exchanges = config.max_pulls.saturating_add(2).saturating_mul(2);
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
                return exchange.take_response(now, cx).map_err(Into::into);
            }
            HttpProgress::Advanced => {}
            HttpProgress::Pending => cx.wait(deadline)?,
        }
    }
}

fn soap_body(response: &HttpResponse) -> Result<&[u8], ClientError> {
    let is_soap = response.content_type().is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/soap+xml"))
    });
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
