#![forbid(unsafe_code)]
//! Inert controller-address handoff planning; no socket or effect is dispatched.
//!
//! A plan binds a proposed `PUT` to a known prior address and caller-supplied
//! camera, peer-admission and lease claims. None authenticates the camera or
//! establishes current state. An address-only reverse request is not a complete
//! rollback plan. Dispatch requires a fresh registered management effect and a
//! separate owned transport; this module exposes no write-ready HTTP request.

use super::camera_api::{self, ControllerAddress, SettingsObservation};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use std::{fmt, net::Ipv4Addr};

/// Effect class used for controller-association changes.
pub const EFFECT_CLASS: &str = "EFFECT-CAMERA-MANAGEMENT-001";

/// HTTP body framing bound to the prepared management effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Framing {
    /// Send a fixed content length, preserving the original request identity.
    ContentLength,
    /// Send one HTTP/1.1 chunk followed by the terminating chunk.
    Chunked,
}

/// Caller-supplied preconditions; their authenticity and freshness are external.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Preconditions {
    /// Identity binding independently established by the owner.
    pub camera: ContentDigest,
    /// Current peer-admission decision binding.
    pub peer_admission: ContentDigest,
    /// Nonzero generation of the camera-local session.
    pub session_generation: u64,
    /// Current camera lease fence.
    pub lease_fence: u64,
    /// Address observation from the camera-local settings endpoint.
    pub settings: SettingsObservation,
}

/// Payload-free reason an inert handoff cannot be prepared or revalidated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A digest, peer, generation, lease or observation binding is invalid.
    Preconditions,
    /// The prior address is absent, unset, or not represented in this profile.
    PriorUnknown,
    /// The new address is not an eligible unicast destination or is unchanged.
    Destination,
    /// Current claims differ from the prepared plan.
    Stale,
    /// Bounded canonical encoding failed.
    Encoding,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi controller handoff refused: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Classification of an untrusted settings readback. Reported and unset
/// values carry a peer/session binding; missing and unsupported values do not.
/// None of these variants proves device identity, adoption or effect settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Readback {
    /// The camera reported the requested controller address.
    Requested,
    /// The camera reported the controller address observed before the change.
    Previous,
    /// A different IPv4 address was reported.
    Different,
    /// The address was explicitly unset.
    Unset,
    /// The address was absent.
    Missing,
    /// The address was present but unsupported by this profile.
    Unsupported,
}

/// Digest-bound, non-dispatchable plan. Debug omits network addresses.
pub struct Plan {
    peer: Ipv4Addr,
    generation: u64,
    destination: Ipv4Addr,
    prior: Ipv4Addr,
    camera: ContentDigest,
    fence: u64,
    request: ContentDigest,
    preconditions: ContentDigest,
    reverse_preview: ContentDigest,
    framing: Framing,
    controller_port: Option<u16>,
    route: Route,
}

enum Route {
    Settings,
    ManagementV12 { port: u16, token: ManagementToken },
}

struct ManagementToken([u8; 32]);
impl Drop for ManagementToken {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// An expected hello claim derived from an exact management request.
/// Matching this value is correlation only: it does not authenticate the
/// peer, establish dispatch, prevent replay, or settle a committed effect.
pub struct HelloBinding {
    request: ContentDigest,
    token_digest: ContentDigest,
}
impl fmt::Debug for HelloBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HelloBinding(<redacted>)")
    }
}
impl HelloBinding {
    /// The management request whose token is expected, not proof of dispatch.
    pub fn request_digest(&self) -> ContentDigest {
        self.request
    }

    pub(super) fn accepts(&self, value: &str) -> bool {
        use zeroize::Zeroizing;
        let text = value.as_bytes();
        if text.len() != 64 {
            return false;
        }
        let mut decoded = Zeroizing::new([0u8; 32]);
        for (dst, pair) in decoded.iter_mut().zip(text.as_chunks::<2>().0) {
            fn nibble(b: u8) -> Option<u8> {
                match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    _ => None,
                }
            }
            let (Some(high), Some(low)) = (nibble(pair[0]), nibble(pair[1])) else {
                return false;
            };
            *dst = (high << 4) | low;
        }
        ContentDigest::sha256(&decoded[..]) == self.token_digest
    }
}

/// A private request body; it is never exposed by `Debug` and is cleared on drop.
pub(super) struct Body(Vec<u8>);
impl Body {
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }
}
impl Drop for Body {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
impl fmt::Debug for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plan")
            .field("request", &self.request)
            .field("preconditions", &self.preconditions)
            .finish_non_exhaustive()
    }
}
impl Plan {
    /// Prepare an inert forward request and address-only reverse preview.
    /// A supported, reported prior address is mandatory; unset and unknown
    /// values cannot silently become a restoration promise.
    pub fn new(
        peer: Ipv4Addr,
        destination: Ipv4Addr,
        current: Preconditions,
    ) -> Result<Self, Error> {
        Self::new_with_framing(peer, destination, current, Framing::ContentLength)
    }
    /// Prepare a request using explicitly selected, digest-bound HTTP framing.
    pub fn new_with_framing(
        peer: Ipv4Addr,
        destination: Ipv4Addr,
        current: Preconditions,
        framing: Framing,
    ) -> Result<Self, Error> {
        let prior = match current.settings.controller {
            ControllerAddress::Reported(ip) => ip,
            _ => return Err(Error::PriorUnknown),
        };
        if !valid_peer(peer) || !valid_destination(destination) || destination == prior {
            return Err(Error::Destination);
        }
        let preconditions = preconditions_digest(peer, current)?;
        let request = request_digest(peer, current.session_generation, destination, framing)?;
        let reverse_preview = request_digest(peer, current.session_generation, prior, framing)?;
        Ok(Self {
            peer,
            generation: current.session_generation,
            destination,
            prior,
            camera: current.camera,
            fence: current.lease_fence,
            request,
            preconditions,
            reverse_preview,
            framing,
            controller_port: None,
            route: Route::Settings,
        })
    }
    /// Prepare the experimental 1.2 management route with a single WSS host.
    /// `token` must be freshly generated from an authorized cryptographic
    /// entropy source; nonzero bytes do not prove entropy. The camera protocol,
    /// acceptance, return path and restoration are not established by this plan.
    /// The existing reverse preview remains address-only and is not a rollback.
    pub fn new_management_v12(
        peer: Ipv4Addr,
        destination: Ipv4Addr,
        port: u16,
        token: [u8; 32],
        current: Preconditions,
    ) -> Result<Self, Error> {
        let token = ManagementToken(token);
        if port == 0 || token.0 == [0; 32] {
            return Err(Error::Destination);
        }
        let mut plan = Self::new(peer, destination, current)?;
        plan.request = management_request_digest(
            peer,
            current.session_generation,
            destination,
            port,
            &token.0,
        )?;
        plan.route = Route::ManagementV12 { port, token };
        Ok(plan)
    }
    /// Bind the reported listener port to this plan's effect preconditions.
    ///
    /// This records one caller-supplied status claim; it does not authenticate
    /// the camera or establish that its port remains unchanged.
    pub fn bind_reported_controller_port(
        mut self,
        status: camera_api::StatusShape,
        expected: u16,
    ) -> Result<Self, Error> {
        if expected == 0
            || self.controller_port.is_some()
            || status.controller_port != camera_api::ControllerPort::Reported(expected)
        {
            return Err(Error::Preconditions);
        }
        self.preconditions = listener_preconditions_digest(self.preconditions, expected)?;
        self.controller_port = Some(expected);
        Ok(self)
    }
    /// Exact semantic request digest for management-effect preparation.
    pub fn request_digest(&self) -> ContentDigest {
        self.request
    }
    /// Derive a claim check for this exact 1.2 request. This is not effect
    /// authority, a dispatch receipt, device identity, or adoption proof.
    pub fn hello_binding(&self) -> Option<HelloBinding> {
        match &self.route {
            Route::Settings => None,
            Route::ManagementV12 { token, .. } => Some(HelloBinding {
                request: self.request,
                token_digest: ContentDigest::sha256(&token.0),
            }),
        }
    }
    /// Bound caller-supplied preconditions for management-effect preparation.
    pub fn precondition_digest(&self) -> ContentDigest {
        self.preconditions
    }
    /// Address-only reverse request identity, not authority or proof of rollback.
    pub fn reverse_preview_digest(&self) -> ContentDigest {
        self.reverse_preview
    }
    /// Camera resource that must be covered by the live lease and grant.
    pub fn resource(&self) -> String {
        format!("camera:{}", self.camera.to_text())
    }
    /// Lease fence captured by this plan.
    pub fn fence(&self) -> u64 {
        self.fence
    }
    /// Refuse stale, mismatched or unrepresentable current claims before commit.
    pub fn check_current(&self, current: Preconditions) -> Result<(), Error> {
        let base = preconditions_digest(self.peer, current)?;
        let current_digest = match self.controller_port {
            Some(port) => listener_preconditions_digest(base, port)?,
            None => base,
        };
        if current_digest != self.preconditions
            || current.settings.controller != ControllerAddress::Reported(self.prior)
            || self.destination == self.prior
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Compare a settings claim; representable values must carry the binding
    /// for this plan's exact peer and session. Missing and unsupported values
    /// are not bound and cannot confirm any remote state. The caller must
    /// establish freshness and independently reconcile the journaled effect.
    pub fn classify_readback(&self, observation: SettingsObservation) -> Result<Readback, Error> {
        let expected =
            camera_api::controller_binding(observation.controller, self.peer, self.generation)
                .map_err(|_| Error::Preconditions)?;
        if observation.binding != expected {
            return Err(Error::Preconditions);
        }
        Ok(match observation.controller {
            ControllerAddress::Reported(ip) if ip == self.destination => Readback::Requested,
            ControllerAddress::Reported(ip) if ip == self.prior => Readback::Previous,
            ControllerAddress::Reported(_) => Readback::Different,
            ControllerAddress::Unset => Readback::Unset,
            ControllerAddress::Missing => Readback::Missing,
            ControllerAddress::Unsupported => Readback::Unsupported,
        })
    }
    pub(super) fn matches_session(&self, peer: Ipv4Addr, generation: u64) -> bool {
        self.peer == peer && self.generation == generation
    }
    /// A port-bound plan must still match the latest status observed by the
    /// same local session. This does not prove the camera has not changed
    /// after that observation.
    pub(super) fn matches_latest_status(&self, status: Option<camera_api::StatusShape>) -> bool {
        self.controller_port.is_none_or(|port| {
            status.is_some_and(|status| {
                status.controller_port == camera_api::ControllerPort::Reported(port)
            })
        })
    }
    pub(super) fn framing(&self) -> Framing {
        self.framing
    }
    pub(super) fn method_and_path(&self) -> (&'static str, &'static str) {
        match &self.route {
            Route::Settings => ("PUT", "/api/1.1/settings"),
            Route::ManagementV12 { .. } => ("POST", "/api/1.2/manage"),
        }
    }
    pub(super) fn body(&self) -> Result<Body, Error> {
        let (actual, body) = match &self.route {
            Route::Settings => (
                request_digest(self.peer, self.generation, self.destination, self.framing)?,
                Body(body(self.destination).into_bytes()),
            ),
            Route::ManagementV12 { port, token } => {
                let digest = management_request_digest(
                    self.peer,
                    self.generation,
                    self.destination,
                    *port,
                    &token.0,
                )?;
                let mut bytes = format!(
                    "{{\"mgmt\":{{\"protocol\":\"wss\",\"hosts\":[\"{}:{}\"],\"token\":\"",
                    self.destination, port
                )
                .into_bytes();
                const HEX: &[u8; 16] = b"0123456789abcdef";
                for &byte in &token.0 {
                    bytes.push(HEX[usize::from(byte >> 4)]);
                    bytes.push(HEX[usize::from(byte & 15)]);
                }
                bytes.extend_from_slice(b"\"}}");
                (digest, Body(bytes))
            }
        };
        if actual != self.request {
            return Err(Error::Stale);
        }
        Ok(body)
    }
}
fn listener_preconditions_digest(base: ContentDigest, port: u16) -> Result<ContentDigest, Error> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.unifi-direct.controller-handoff-listener-precondition.v1");
    e.digest(base);
    e.u64(u64::from(port));
    Ok(ContentDigest::sha256(
        &e.finish_checked().map_err(|_| Error::Encoding)?,
    ))
}

fn valid_peer(ip: Ipv4Addr) -> bool {
    (ip.is_private() || ip.is_loopback() || ip.is_link_local())
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
}
fn valid_destination(ip: Ipv4Addr) -> bool {
    (ip.is_private() || ip.is_link_local())
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
}
fn valid_digest(d: ContentDigest) -> bool {
    d.algorithm() == DigestAlgorithm::Sha256 && !d.is_laboratory() && d.bytes() != [0; 32]
}
fn preconditions_digest(peer: Ipv4Addr, current: Preconditions) -> Result<ContentDigest, Error> {
    if !valid_peer(peer)
        || !valid_digest(current.camera)
        || !valid_digest(current.peer_admission)
        || current.session_generation == 0
        || current.lease_fence == 0
    {
        return Err(Error::Preconditions);
    }
    let prior = match current.settings.controller {
        ControllerAddress::Reported(ip) => ip,
        _ => return Err(Error::PriorUnknown),
    };
    let expected = camera_api::controller_binding(
        ControllerAddress::Reported(prior),
        peer,
        current.session_generation,
    )
    .map_err(|_| Error::Preconditions)?
    .ok_or(Error::Preconditions)?;
    if current.settings.binding != Some(expected) {
        return Err(Error::Preconditions);
    }
    let mut e = CanonicalEncoder::new();
    e.text("fss.unifi-direct.controller-handoff-precondition.v1");
    e.text(EFFECT_CLASS);
    e.digest(current.camera);
    e.digest(current.peer_admission);
    e.u64(current.session_generation);
    e.u64(current.lease_fence);
    e.digest(expected);
    Ok(ContentDigest::sha256(
        &e.finish_checked().map_err(|_| Error::Encoding)?,
    ))
}
fn request_digest(
    peer: Ipv4Addr,
    generation: u64,
    address: Ipv4Addr,
    framing: Framing,
) -> Result<ContentDigest, Error> {
    let body = body(address);
    let mut e = CanonicalEncoder::new();
    match framing {
        Framing::ContentLength => e.text("fss.unifi-direct.controller-handoff-request.v1"),
        Framing::Chunked => {
            e.text("fss.unifi-direct.controller-handoff-request.v2");
            e.text("transfer-encoding:chunked");
        }
    }
    e.text("PUT");
    e.text("/api/1.1/settings");
    e.text(&peer.to_string());
    e.u64(generation);
    e.bytes(body.as_bytes());
    Ok(ContentDigest::sha256(
        &e.finish_checked().map_err(|_| Error::Encoding)?,
    ))
}
fn management_request_digest(
    peer: Ipv4Addr,
    generation: u64,
    destination: Ipv4Addr,
    port: u16,
    token: &[u8; 32],
) -> Result<ContentDigest, Error> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.unifi-direct.controller-management-v12-request.v1");
    e.text("POST");
    e.text("/api/1.2/manage");
    e.text(&peer.to_string());
    e.u64(generation);
    e.text("wss");
    e.text(&destination.to_string());
    e.u64(u64::from(port));
    e.digest(ContentDigest::sha256(token));
    Ok(ContentDigest::sha256(
        &e.finish_checked().map_err(|_| Error::Encoding)?,
    ))
}
fn body(address: Ipv4Addr) -> String {
    format!("{{\"controller\":{{\"addr\":\"{address}\"}}}}")
}
