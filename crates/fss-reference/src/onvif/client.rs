#![forbid(unsafe_code)]
//! Read-only device → media profile → stream URI negotiation.
//!
//! Neither a discovery XAddr nor a response URI grants authority. Every advertised route
//! is checked against the independently approved literal peer, exact HTTP authority, and
//! service subtree before credentials or requests can reach it. RTSP has a separate scope.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use super::authentication::{UsernameToken, UtcDateTime};
use super::http::{
    HttpAuthority, HttpDenial, HttpError, HttpExchange, HttpLimits, HttpOperation, HttpProgress,
    HttpResponse, HttpRoute,
};
use super::wire::{
    self, Capabilities, Media2Service, Media2StreamUri, MediaProfile, MediaVersion, SoapRequest,
    StreamUri, WireError,
};
use crate::rtsp::authentication::{
    AuthenticationError, DigestAuthorization, DigestChallenge, DigestPolicy,
};
use crate::rtsp::client::validated_uri_parts;

const MAX_SESSION_NS: u64 = 60_000_000_000;
const MAX_STEPS: u32 = 100_000;

/// Exact realm and explicitly opted-in legacy HTTP Digest policy.
#[derive(Clone)]
pub struct DigestConfig {
    /// Independently configured realm; never inferred from a challenge.
    pub expected_realm: String,
    /// Exact algorithm and qop allowance; no automatic weakening.
    pub policy: DigestPolicy,
}

impl fmt::Debug for DigestConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DigestConfig")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Explicitly selected authentication mechanism. A challenge or SOAP fault never
/// switches mechanisms, acquires a new credential scope, or weakens this choice.
#[derive(Clone, Debug)]
pub enum AuthenticationConfig {
    /// Independently pinned realm and approved HTTP Digest algorithm policy.
    HttpDigest(DigestConfig),
    /// WS-Security PasswordDigest with fresh per-request nonce and camera UTC.
    /// The unsigned PRE_AUTH time read is required before any credential callback.
    UsernameTokenDigest,
}

/// Independent RTSP destination approval. No DNS lookup or URI-based peer substitution.
#[derive(Clone)]
pub struct RtspScope {
    /// Independently approved literal network destination.
    pub peer: SocketAddr,
    /// Exact authority spelling expected in the server's URI.
    pub authority: String,
}

impl fmt::Debug for RtspScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RtspScope([REDACTED])")
    }
}

/// One bounded onboarding session, supplied by an explicit owner.
#[derive(Clone)]
pub struct ClientConfig {
    /// Explicit service lane; no automatic Media1/Media2 fallback or downgrade.
    pub media_version: MediaVersion,
    /// Approved device-service route, including generation and plaintext consent.
    pub device: HttpRoute,
    /// Absolute HTTP path subtree, such as `/onvif`; never a discovered grant.
    pub service_root: String,
    /// Optional owner-selected HTTP Digest or UsernameToken PasswordDigest lane.
    pub auth: Option<AuthenticationConfig>,
    /// Required for selection, optional for profile inventory.
    pub rtsp: Option<RtspScope>,
    /// Per-exchange wire, allocation, I/O and connect ceilings.
    pub limits: HttpLimits,
    /// Absolute deadline in the context's monotonic clock domain; at most 60 seconds away.
    pub deadline_ns: u64,
    /// Includes clock/poll progress, not just successful socket calls.
    pub max_steps: u32,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("media_version", &self.media_version)
            .field("authenticated", &self.auth.is_some())
            .field("rtsp_scope", &self.rtsp.is_some())
            .field("deadline_ns", &self.deadline_ns)
            .field("max_steps", &self.max_steps)
            .finish_non_exhaustive()
    }
}

/// A negotiated observation, not a conformance, camera-identity, or retained-media claim.
pub struct Onboarding {
    /// Version-specific observed service advertisement, without inferred capabilities.
    pub discovery: MediaDiscovery,
    /// Complete bounded profile projection, without automatic selection.
    pub profiles: Vec<MediaProfile>,
    /// The exact requested profile's scoped URI, if selection was requested.
    pub selection: Option<SelectedStream>,
    /// Actual POST attempts, including authentication retries.
    pub exchanges: u32,
}

impl fmt::Debug for Onboarding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Onboarding")
            .field("media_version", &self.discovery.media_version())
            .field("profile_count", &self.profiles.len())
            .field("selected", &self.selection.is_some())
            .field("exchanges", &self.exchanges)
            .finish_non_exhaustive()
    }
}

/// Service discovery preserves which protocol observation supplied the endpoint.
/// Media2 GetServices does not report Media1 streaming capability flags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MediaDiscovery {
    /// Media1 GetCapabilities result, including unknown/false/true transport state.
    Media1(Capabilities),
    /// Exact Media2 namespace selected from the complete GetServices response.
    Media2(Media2Service),
}

impl MediaDiscovery {
    /// Exact negotiated service contract.
    #[must_use]
    pub const fn media_version(&self) -> MediaVersion {
        match self {
            Self::Media1(_) => MediaVersion::Media1,
            Self::Media2(_) => MediaVersion::Media2,
        }
    }

    fn media_uri(&self) -> Result<&str, ClientError> {
        match self {
            Self::Media1(capabilities) => capabilities
                .media_xaddr
                .as_deref()
                .ok_or(ClientError::Unsupported),
            Self::Media2(service) => Ok(&service.xaddr),
        }
    }
}

/// URI lifetime basis remains explicit across service versions and handoffs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamValidity {
    /// All mandatory validity fields actually observed in a Media1 response.
    Media1 {
        /// Device-reported connection invalidation flag.
        invalid_after_connect: bool,
        /// Device-reported reboot invalidation flag.
        invalid_after_reboot: bool,
        /// Device-reported bounded XML duration.
        timeout: String,
    },
    /// Media2 specifies a stable indefinitely valid URI and returns no lifetime fields.
    /// This records the protocol basis, not a separately measured device guarantee.
    Media2Indefinite,
}

/// Selected URI and its observed or protocol-defined validity basis. This is
/// negotiation metadata, not source continuity or ongoing device availability.
#[derive(Clone, Eq, PartialEq)]
pub struct NegotiatedStreamUri {
    /// Exact decoded URI, validated against the owner's independent RTSP scope.
    pub uri: String,
    /// Explicit lifetime basis; never synthesize Media1 flags for Media2.
    pub validity: StreamValidity,
}

impl NegotiatedStreamUri {
    /// Whether this lane supports reuse without a device-reported expiry.
    #[must_use]
    pub fn is_stable(&self) -> bool {
        match &self.validity {
            StreamValidity::Media1 {
                invalid_after_connect,
                invalid_after_reboot,
                timeout,
            } => wire::stable_lifetime(*invalid_after_connect, *invalid_after_reboot, timeout),
            StreamValidity::Media2Indefinite => true,
        }
    }
}

impl fmt::Debug for NegotiatedStreamUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NegotiatedStreamUri")
            .field("uri", &"[redacted]")
            .field("validity", &self.validity)
            .finish()
    }
}

impl From<StreamUri> for NegotiatedStreamUri {
    fn from(stream: StreamUri) -> Self {
        Self {
            uri: stream.uri,
            validity: StreamValidity::Media1 {
                invalid_after_connect: stream.invalid_after_connect,
                invalid_after_reboot: stream.invalid_after_reboot,
                timeout: stream.timeout,
            },
        }
    }
}

impl From<Media2StreamUri> for NegotiatedStreamUri {
    fn from(stream: Media2StreamUri) -> Self {
        Self {
            uri: stream.uri,
            validity: StreamValidity::Media2Indefinite,
        }
    }
}

/// Exact server-returned URI with independent route pins. Never log this object as raw data.
pub struct SelectedStream {
    /// Exact selected profile metadata, not a proof of received media properties.
    pub profile: MediaProfile,
    /// Server-reported presentation with explicit version-specific lifetime basis.
    pub stream: NegotiatedStreamUri,
    /// Independently approved RTSP destination.
    pub peer: SocketAddr,
    /// Independently approved RTSP authority, matching the URI exactly.
    pub authority: String,
}

impl fmt::Debug for SelectedStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SelectedStream([REDACTED])")
    }
}

/// Payload-free refusals. No remote XML, URI, realm, credential, or OS error is reflected.
#[derive(Debug)]
pub enum ClientError {
    /// Native route, socket, framing, or live-authority failure.
    Http(HttpError),
    /// SOAP/XML refusal or typed redacted remote fault.
    Wire(WireError),
    /// Pinned-realm or approved Digest-profile refusal.
    Authentication(AuthenticationError),
    /// The server challenged an owner without an approved credential configuration.
    AuthenticationRequired,
    /// Unsupported challenge or rejection after the single authenticated retry.
    AuthenticationRefused,
    /// HTTP status that cannot represent a successful operation.
    HttpStatus(u16),
    /// Route, URI or service subtree exceeds the independent owner scope.
    Scope,
    /// Invalid, absent or non-video profile selection.
    Profile,
    /// Service, transport, or MIME type is outside the implemented subset.
    Unsupported,
    /// The whole onboarding deadline was exceeded or invalid.
    Deadline,
    /// Caller cancellation, distinct from a remote protocol failure.
    Cancelled,
    /// Owner authority was denied or revoked before result release.
    Authority,
    /// The caller's monotonic clock regressed.
    Clock,
    /// A whole-session step or exchange ceiling was reached.
    Budget,
    /// Credential configuration or current lease was refused.
    Credentials,
    /// The owner could not provide fresh authentication entropy.
    Entropy,
}

impl ClientError {
    /// Stable payload-free diagnostic identity suitable for operator output.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Http(_) => "ERR-ONVIF-HTTP-001",
            Self::Wire(_) => "ERR-ONVIF-SOAP-001",
            Self::Authentication(_) | Self::AuthenticationRefused => "ERR-ONVIF-AUTH-001",
            Self::AuthenticationRequired => "ERR-ONVIF-CREDENTIALS-REQUIRED-001",
            Self::HttpStatus(_) => "ERR-ONVIF-STATUS-001",
            Self::Scope => "ERR-ONVIF-SCOPE-001",
            Self::Profile => "ERR-ONVIF-PROFILE-001",
            Self::Unsupported => "ERR-ONVIF-UNSUPPORTED-001",
            Self::Deadline => "ERR-ONVIF-DEADLINE-001",
            Self::Cancelled => "ERR-ONVIF-CANCELLED-001",
            Self::Authority => "ERR-ONVIF-AUTHORITY-001",
            Self::Clock => "ERR-ONVIF-CLOCK-001",
            Self::Budget => "ERR-ONVIF-BUDGET-001",
            Self::Credentials => "ERR-ONVIF-CREDENTIALS-001",
            Self::Entropy => "ERR-ONVIF-ENTROPY-001",
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for ClientError {}
impl From<HttpError> for ClientError {
    fn from(error: HttpError) -> Self {
        Self::Http(error)
    }
}
impl From<WireError> for ClientError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}
impl From<AuthenticationError> for ClientError {
    fn from(error: AuthenticationError) -> Self {
        Self::Authentication(error)
    }
}

/// The caller owns live cancellation, clock, wait budget, secrets, and entropy.
///
/// `authorize` is reached only after the exact configured realm and Digest policy pass.
/// It must revalidate the credential lease, obtain fresh unpredictable 128-bit entropy,
/// and sign `POST` with `route.target()` and nonce count 1. Each challenge is used once.
/// No credential or nonce is cached across requests, services, or onboarding sessions.
pub trait OnvifContext: HttpAuthority {
    /// Read a monotonic timestamp through live owner authority.
    fn now_ns(&self) -> Result<u64, ClientError>;
    /// Bounded cooperative wait; must check cancellation/deadline before and after waiting.
    fn wait(&self, deadline_ns: u64) -> Result<(), ClientError>;
    /// Borrow scoped credentials and fresh entropy, producing one exact POST authorization.
    fn authorize(
        &self,
        route: &HttpRoute,
        challenge: &DigestChallenge,
    ) -> Result<DigestAuthorization, ClientError>;

    /// Revalidate the exact route, operation, and current credential lease, then
    /// create one fresh UsernameToken using unpredictable 128-bit entropy and
    /// exactly `created`. The core supplies camera UTC advanced only by owned
    /// monotonic elapsed time. Default refusal preserves existing owner contracts.
    fn username_token(
        &self,
        _route: &HttpRoute,
        _request: &SoapRequest,
        _created: UtcDateTime,
    ) -> Result<UsernameToken, ClientError> {
        Err(ClientError::Credentials)
    }
}

/// Read services/capabilities and profiles in the explicitly selected media lane,
/// optionally obtaining one exact selected profile's URI.
///
/// At most three media operations and one same-route HTTP Digest retry per operation occur.
/// The explicit UsernameToken lane instead makes one unsigned time read and signs each
/// media request once, with no mechanism fallback and the same six-exchange ceiling.
/// There is no automatic profile choice, redirect, TLS downgrade, DNS resolution, retry of
/// authentication failure, PTZ/configuration effect, or stream acquisition in this function.
pub fn run(
    config: &ClientConfig,
    profile_token: Option<&str>,
    cx: &impl OnvifContext,
) -> Result<Onboarding, ClientError> {
    validate_config(config, profile_token)?;
    // Validate the owner's selection before any I/O; keep the exact escaped request.
    let selection_request = profile_token
        .map(|token| match config.media_version {
            MediaVersion::Media1 => wire::get_stream_uri_request(token),
            MediaVersion::Media2 => wire::get_media2_stream_uri_request(token),
        })
        .transpose()?;
    let mut budget = SessionBudget::default();
    let now = budget.now(config, cx)?;
    if config.deadline_ns.saturating_sub(now) > MAX_SESSION_NS {
        return Err(ClientError::Deadline);
    }

    if matches!(
        config.auth.as_ref(),
        Some(AuthenticationConfig::UsernameTokenDigest)
    ) {
        let request = wire::get_system_date_and_time_request();
        let response = send(config, &config.device, &request, None, cx, &mut budget)?;
        if response.status() == 401 {
            return Err(ClientError::AuthenticationRefused);
        }
        let observed_ns = budget.now(config, cx)?;
        let utc = wire::parse_system_date_and_time(soap_body(&response)?)?;
        let now = budget.now(config, cx)?;
        cx.checkpoint(
            &config.device,
            HttpOperation::Release,
            now,
            config.deadline_ns,
        )
        .map_err(wsse_checkpoint_error)?;
        budget.authentication_time = Some(AuthenticationTime { utc, observed_ns });
    }

    let discovery_request = match config.media_version {
        MediaVersion::Media1 => wire::get_capabilities_request(),
        MediaVersion::Media2 => wire::get_services_request(),
    };
    let response = exchange(config, &config.device, &discovery_request, cx, &mut budget)?;
    let discovery = match config.media_version {
        MediaVersion::Media1 => {
            MediaDiscovery::Media1(wire::parse_capabilities(soap_body(&response)?)?)
        }
        MediaVersion::Media2 => MediaDiscovery::Media2(
            wire::parse_media2_service(soap_body(&response)?)?.ok_or(ClientError::Unsupported)?,
        ),
    };
    let media_uri = discovery.media_uri()?;
    // No credential lookup or socket to an advertised endpoint until this scope check passes.
    let media = media_route(config, media_uri)?;
    let profiles_request = match config.media_version {
        MediaVersion::Media1 => wire::get_profiles_request(),
        MediaVersion::Media2 => wire::get_media2_profiles_request(),
    };
    let response = exchange(config, &media, &profiles_request, cx, &mut budget)?;
    let profiles = match config.media_version {
        MediaVersion::Media1 => wire::parse_profiles(soap_body(&response)?)?,
        MediaVersion::Media2 => wire::parse_media2_profiles(soap_body(&response)?)?,
    };

    let selection = if let Some(token) = profile_token {
        let profile = profiles
            .iter()
            .find(|p| p.token == token)
            .ok_or(ClientError::Profile)?;
        if profile.video.is_none() {
            return Err(ClientError::Profile);
        }
        if matches!(&discovery, MediaDiscovery::Media1(capabilities) if capabilities.rtp_rtsp_tcp == Some(false))
        {
            return Err(ClientError::Unsupported);
        }
        let response = exchange(
            config,
            &media,
            selection_request.as_ref().ok_or(ClientError::Profile)?,
            cx,
            &mut budget,
        )?;
        let stream: NegotiatedStreamUri = match config.media_version {
            MediaVersion::Media1 => wire::parse_stream_uri(soap_body(&response)?)?.into(),
            MediaVersion::Media2 => wire::parse_media2_stream_uri(soap_body(&response)?)?.into(),
        };
        let scope = config.rtsp.as_ref().ok_or(ClientError::Scope)?;
        validate_stream_uri(&stream.uri, scope)?;
        Some(SelectedStream {
            profile: profile.clone(),
            stream,
            peer: scope.peer,
            authority: scope.authority.clone(),
        })
    } else {
        None
    };
    // Parsing and allocation cannot turn a revoked or expired response into a released result.
    let now = budget.now(config, cx)?;
    cx.checkpoint(&media, HttpOperation::Release, now, config.deadline_ns)
        .map_err(|_| ClientError::Authority)?;
    Ok(Onboarding {
        discovery,
        profiles,
        selection,
        exchanges: budget.exchanges,
    })
}

#[derive(Default)]
struct SessionBudget {
    last_ns: u64,
    steps: u32,
    exchanges: u32,
    authentication_time: Option<AuthenticationTime>,
}

struct AuthenticationTime {
    utc: UtcDateTime,
    observed_ns: u64,
}

fn wsse_checkpoint_error(denial: HttpDenial) -> ClientError {
    match denial {
        HttpDenial::Cancelled => ClientError::Cancelled,
        HttpDenial::Deadline => ClientError::Deadline,
        HttpDenial::Budget => ClientError::Budget,
        HttpDenial::Unauthorized | HttpDenial::Revoked => ClientError::Authority,
    }
}

impl SessionBudget {
    fn now(&mut self, config: &ClientConfig, cx: &impl OnvifContext) -> Result<u64, ClientError> {
        self.steps = self.steps.checked_add(1).ok_or(ClientError::Budget)?;
        if self.steps > config.max_steps {
            return Err(ClientError::Budget);
        }
        let now = cx.now_ns()?;
        if now < self.last_ns {
            return Err(ClientError::Clock);
        }
        self.last_ns = now;
        if now >= config.deadline_ns {
            return Err(ClientError::Deadline);
        }
        Ok(now)
    }
}

fn exchange(
    config: &ClientConfig,
    route: &HttpRoute,
    request: &SoapRequest,
    cx: &impl OnvifContext,
    budget: &mut SessionBudget,
) -> Result<HttpResponse, ClientError> {
    if matches!(
        config.auth.as_ref(),
        Some(AuthenticationConfig::UsernameTokenDigest)
    ) {
        let now = budget.now(config, cx)?;
        cx.checkpoint(route, HttpOperation::Write, now, config.deadline_ns)
            .map_err(wsse_checkpoint_error)?;
        let time = budget
            .authentication_time
            .as_ref()
            .ok_or(ClientError::Clock)?;
        let elapsed_ns = now
            .checked_sub(time.observed_ns)
            .ok_or(ClientError::Clock)?;
        let created = time.utc.checked_add_seconds(elapsed_ns / 1_000_000_000)?;
        let token = cx.username_token(route, request, created)?;
        if token.created() != created {
            return Err(ClientError::Credentials);
        }
        let signed = request.clone().with_username_token(&token)?;
        let response = send(config, route, &signed, None, cx, budget)?;
        if response.status() == 401 {
            return Err(ClientError::AuthenticationRefused);
        }
        return Ok(response);
    }
    let first = send(config, route, request, None, cx, budget)?;
    if first.status() != 401 {
        return Ok(first);
    }
    let auth = match config.auth.as_ref() {
        Some(AuthenticationConfig::HttpDigest(auth)) => auth,
        Some(AuthenticationConfig::UsernameTokenDigest) => {
            return Err(ClientError::AuthenticationRefused);
        }
        None => return Err(ClientError::AuthenticationRequired),
    };
    let header = first
        .digest_challenge()
        .ok_or(ClientError::AuthenticationRefused)?;
    let challenge = DigestChallenge::parse(header, &auth.expected_realm, auth.policy)?;
    let now = budget.now(config, cx)?;
    cx.checkpoint(route, HttpOperation::Write, now, config.deadline_ns)
        .map_err(|_| ClientError::Authority)?;
    let authorization = cx.authorize(route, &challenge)?;
    let response = send(config, route, request, Some(&authorization), cx, budget)?;
    if response.status() == 401 {
        return Err(ClientError::AuthenticationRefused);
    }
    Ok(response)
}

fn send(
    config: &ClientConfig,
    route: &HttpRoute,
    request: &SoapRequest,
    authorization: Option<&DigestAuthorization>,
    cx: &impl OnvifContext,
    budget: &mut SessionBudget,
) -> Result<HttpResponse, ClientError> {
    budget.exchanges += 1;
    if budget.exchanges > 6 {
        return Err(ClientError::Budget);
    }
    let now = budget.now(config, cx)?;
    let mut exchange = HttpExchange::connect(
        route.clone(),
        request,
        authorization,
        config.limits,
        now,
        config.deadline_ns,
        cx,
    )?;
    loop {
        let now = budget.now(config, cx)?;
        match exchange.step(now, cx)? {
            HttpProgress::Complete => {
                let now = budget.now(config, cx)?;
                return Ok(exchange.take_response(now, cx)?);
            }
            HttpProgress::Advanced => {}
            HttpProgress::Pending => cx.wait(config.deadline_ns)?,
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
        // SOAP 1.2 faults use HTTP 400/500. Preserve their typed, redacted meaning,
        // but never turn a success-shaped body under an error status into success.
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

fn validate_config(config: &ClientConfig, token: Option<&str>) -> Result<(), ClientError> {
    if config.max_steps == 0 || config.max_steps > MAX_STEPS || config.deadline_ns == 0 {
        return Err(ClientError::Budget);
    }
    validate_authority(config.device.authority(), config.device.peer(), 80)?;
    validate_path(&config.service_root)?;
    if config.service_root.len() > 512 || config.service_root.contains('?') {
        return Err(ClientError::Scope);
    }
    validate_path(config.device.target())?;
    if !within_root(config.device.target(), &config.service_root) {
        return Err(ClientError::Scope);
    }
    if let Some(AuthenticationConfig::HttpDigest(auth)) = &config.auth {
        if auth.expected_realm.is_empty()
            || auth.expected_realm.len() > 512
            || !auth.expected_realm.bytes().all(|b| (32..127).contains(&b))
            || auth.policy.allow_legacy_no_qop && !auth.policy.allow_legacy_md5
        {
            return Err(ClientError::Credentials);
        }
    }
    if let Some(scope) = &config.rtsp {
        validate_authority(&scope.authority, scope.peer, 554)?;
    } else if token.is_some() {
        return Err(ClientError::Scope);
    }
    Ok(())
}

fn media_route(config: &ClientConfig, uri: &str) -> Result<HttpRoute, ClientError> {
    if uri.len() > 2_048 {
        return Err(ClientError::Scope);
    }
    let rest = uri.strip_prefix("http://").ok_or(ClientError::Scope)?;
    let slash = rest.find('/').ok_or(ClientError::Scope)?;
    let (authority, target) = rest.split_at(slash);
    if authority != config.device.authority() {
        return Err(ClientError::Scope);
    }
    validate_path(target)?;
    if !within_root(target, &config.service_root) {
        return Err(ClientError::Scope);
    }
    Ok(config.device.with_target(target)?)
}

/// Validate the exact returned URI against separately authorized RTSP routing.
pub fn validate_stream_uri(uri: &str, scope: &RtspScope) -> Result<(), ClientError> {
    validate_authority(&scope.authority, scope.peer, 554)?;
    let (authority, _) = validated_uri_parts(uri).map_err(|_| ClientError::Scope)?;
    if authority != scope.authority {
        return Err(ClientError::Scope);
    }
    Ok(())
}

fn validate_authority(
    authority: &str,
    peer: SocketAddr,
    default_port: u16,
) -> Result<(), ClientError> {
    if peer.port() == 0
        || peer.ip().is_unspecified()
        || peer.ip().is_multicast()
        || matches!(peer.ip(), IpAddr::V4(ip) if ip.is_broadcast())
        || authority.is_empty()
        || authority.len() > 512
    {
        return Err(ClientError::Scope);
    }
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or(ClientError::Scope)?;
        let ip = authority[1..end]
            .parse::<Ipv6Addr>()
            .map_err(|_| ClientError::Scope)?;
        if IpAddr::V6(ip) != peer.ip() {
            return Err(ClientError::Scope);
        }
        let tail = &authority[end + 1..];
        let port = if tail.is_empty() {
            default_port
        } else {
            parse_port(tail.strip_prefix(':').ok_or(ClientError::Scope)?)?
        };
        (&authority[..=end], port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, parse_port(port)?),
            None => (authority, default_port),
        };
        if host.is_empty()
            || host.len() > 253
            || !host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(ClientError::Scope);
        }
        if host.parse::<IpAddr>().is_ok_and(|ip| ip != peer.ip()) {
            return Err(ClientError::Scope);
        }
        (host, port)
    };
    if host.is_empty() || port != peer.port() {
        return Err(ClientError::Scope);
    }
    Ok(())
}

fn parse_port(text: &str) -> Result<u16, ClientError> {
    if text.is_empty()
        || text.len() > 5
        || text.starts_with('0')
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(ClientError::Scope);
    }
    let port = text.parse::<u16>().map_err(|_| ClientError::Scope)?;
    if port == 0 {
        return Err(ClientError::Scope);
    }
    Ok(port)
}

fn validate_path(path: &str) -> Result<(), ClientError> {
    if path.is_empty()
        || path.len() > 2_048
        || !path.starts_with('/')
        || path.starts_with("//")
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._~-".contains(&b))
    {
        return Err(ClientError::Scope);
    }
    let pathname = path.split('?').next().ok_or(ClientError::Scope)?;
    if pathname.split('/').any(|part| matches!(part, "." | "..")) {
        return Err(ClientError::Scope);
    }
    Ok(())
}

fn within_root(target: &str, root: &str) -> bool {
    let path = target.split('?').next().unwrap_or("");
    let root = root.trim_end_matches('/');
    root.is_empty()
        || path == root
        || path
            .strip_prefix(root)
            .is_some_and(|tail| tail.starts_with('/'))
}
