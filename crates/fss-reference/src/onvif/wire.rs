#![forbid(unsafe_code)]
//! Bounded, namespace-aware SOAP 1.2 wire subset for read-only ONVIF Media1/Media2
//! onboarding. This module owns bytes, never network or credential authority.
//!
//! Contracts: `https://www.onvif.org/ver10/device/wsdl/devicemgmt.wsdl`,
//! `https://www.onvif.org/ver10/media/wsdl/media.wsdl`,
//! `https://www.onvif.org/ver20/media/wsdl/media.wsdl`, and
//! `https://www.onvif.org/ver10/schema/onvif.xsd`. These read-only operations do not
//! establish Profile T conformance, stream continuity, or device qualification.

use std::fmt;

#[path = "wire/analytics.rs"]
mod analytics;
#[path = "wire/events.rs"]
mod events;
#[path = "wire/media2.rs"]
mod media2;
#[path = "wire/pullpoint.rs"]
mod pullpoint;
#[path = "wire/time.rs"]
mod time;
#[path = "wire/xml.rs"]
mod xml;

pub use analytics::{
    AnalyticsAppearance, AnalyticsBoundingBox, AnalyticsClass, AnalyticsClassCandidate,
    AnalyticsClassFormat, AnalyticsFrame, AnalyticsNumber, AnalyticsObject, AnalyticsShape,
    AnalyticsTransformation, AnalyticsVector, MAX_ANALYTICS_CLASSES, MAX_ANALYTICS_COORDINATE,
    MAX_ANALYTICS_FRAMES, MAX_ANALYTICS_NUMBER_BYTES, MAX_ANALYTICS_OBJECTS,
    MAX_ANALYTICS_OBJECTS_PER_FRAME,
};
pub use events::{
    EventDocument, EventDocumentFormat, EventItems, EventNotification, EventTopic, MAX_EVENT_ITEMS,
    MAX_EVENT_NOTIFICATIONS, MAX_EVENT_VALUE_BYTES, PropertyOperation, SimpleItem,
    parse_event_document, parse_metadata_document,
};
pub use media2::{
    MAX_ONVIF_SERVICES, Media2Service, Media2StreamUri, ServiceVersion,
    get_media2_profiles_request, get_media2_stream_uri_request, get_services_request,
    parse_media2_profiles, parse_media2_service, parse_media2_stream_uri,
};
pub use pullpoint::{
    MAX_PULL_POINT_LIFETIME_SECONDS, MAX_PULL_TIMEOUT_SECONDS, MAX_REFERENCE_PARAMETERS,
    PullPointLease, PullPointSubscription, create_pull_point_request, parse_pull_messages_response,
    parse_pull_point_subscription, parse_renew_response, parse_unsubscribe_response,
    pull_messages_request, renew_pull_point_request, require_relates_to,
    unsubscribe_pull_point_request, validate_relates_to,
};
pub use time::{UtcDateTime, get_system_date_and_time_request, parse_system_date_and_time};

/// Maximum complete SOAP response size, including unrelated extensions.
pub const MAX_SOAP_BYTES: usize = 256 * 1024;
/// Maximum number of profiles accepted in one complete response.
pub const MAX_MEDIA_PROFILES: usize = 64;
/// Maximum size of a reported service or stream URI.
pub const MAX_URI_BYTES: usize = 4096;
/// Maximum encoder dimension admitted by this bounded wire subset.
pub const MAX_VIDEO_DIMENSION: u32 = 32_768;

const SOAP_NS: &str = "http://www.w3.org/2003/05/soap-envelope";
const DEVICE_NS: &str = "http://www.onvif.org/ver10/device/wsdl";
const MEDIA_NS: &str = "http://www.onvif.org/ver10/media/wsdl";
const MEDIA2_NS: &str = "http://www.onvif.org/ver20/media/wsdl";
const SCHEMA_NS: &str = "http://www.onvif.org/ver10/schema";
const ERROR_NS: &str = "http://www.onvif.org/ver10/error";
const MAX_REFERENCE_CHARS: usize = 64;

/// Explicit owner-selected media service contract. A failed lane never falls
/// back to another namespace or service without a new caller decision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MediaVersion {
    /// Original Media1 service, retained as the default lane.
    #[default]
    Media1,
    /// Media2 service, including advertised H.265 encoder configurations.
    Media2,
}

/// The complete operation set admitted by this module. Event-subscription
/// operations require separate explicit remote transient-state authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnvifOperation {
    /// Read camera UTC before authentication; this grants no recording-time authority.
    GetSystemDateAndTime,
    /// Find the Media1 service endpoint and advertised streaming capabilities.
    GetCapabilities,
    /// Enumerate existing media profiles without modifying the device.
    GetProfiles,
    /// Request the selected profile's unicast RTSP-over-TCP presentation URI.
    GetStreamUri,
    /// Request the selected profile's bounded JPEG snapshot URI.
    GetSnapshotUri,
    /// Enumerate device services without requesting their untyped capabilities.
    GetServices,
    /// Enumerate Media2 profiles including their existing video encoder configuration.
    GetMedia2Profiles,
    /// Request the selected Media2 profile's RTSP-over-TCP presentation URI.
    GetMedia2StreamUri,
    /// Create one finite transient event subscription, with explicit owner authority.
    CreatePullPointSubscription,
    /// Pull vendor event notifications from the exact acquired subscription.
    PullMessages,
    /// Renew only an explicitly owned transient event subscription.
    RenewPullPoint,
    /// Delete only an explicitly owned transient event subscription.
    UnsubscribePullPoint,
}

impl OnvifOperation {
    /// SOAP 1.2 HTTP action bound to this exact operation.
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::GetSystemDateAndTime => {
                "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime"
            }
            Self::GetCapabilities => "http://www.onvif.org/ver10/device/wsdl/GetCapabilities",
            Self::GetProfiles => "http://www.onvif.org/ver10/media/wsdl/GetProfiles",
            Self::GetStreamUri => "http://www.onvif.org/ver10/media/wsdl/GetStreamUri",
            Self::GetSnapshotUri => "http://www.onvif.org/ver10/media/wsdl/GetSnapshotUri",
            Self::GetServices => "http://www.onvif.org/ver10/device/wsdl/GetServices",
            Self::GetMedia2Profiles => "http://www.onvif.org/ver20/media/wsdl/GetProfiles",
            Self::GetMedia2StreamUri => "http://www.onvif.org/ver20/media/wsdl/GetStreamUri",
            Self::CreatePullPointSubscription => {
                "http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionRequest"
            }
            Self::PullMessages => {
                "http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessagesRequest"
            }
            Self::RenewPullPoint => {
                "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/RenewRequest"
            }
            Self::UnsubscribePullPoint => {
                "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeRequest"
            }
        }
    }
}

/// A complete request constructible only through operation-specific builders.
/// Debug output never includes a profile token or SOAP body.
#[derive(Clone, Eq, PartialEq)]
pub struct SoapRequest {
    action: &'static str,
    body: Vec<u8>,
    username_token: bool,
}

impl SoapRequest {
    /// The exact action for the enclosed immutable SOAP body.
    #[must_use]
    pub const fn action(&self) -> &'static str {
        self.action
    }

    /// Request bytes, for the scoped transport only; never log these bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Whether this exact body already carries a WS-Security UsernameToken.
    #[must_use]
    pub const fn has_username_token(&self) -> bool {
        self.username_token
    }

    /// Whether this operation requires explicit event-subscription authority.
    /// HTTP routes for ordinary read-only onboarding cannot authorize these bytes.
    #[must_use]
    pub fn is_event_subscription(&self) -> bool {
        [
            OnvifOperation::CreatePullPointSubscription,
            OnvifOperation::PullMessages,
            OnvifOperation::RenewPullPoint,
            OnvifOperation::UnsubscribePullPoint,
        ]
        .into_iter()
        .any(|operation| self.action == operation.action())
    }

    /// Bind one owner-supplied unique request identity to a PullPoint message.
    /// The live owner must prevent reuse across distinct logical requests; an
    /// authentication retry of the same message keeps the same identity.
    pub fn with_message_id(mut self, id: &str) -> Result<Self, WireError> {
        pullpoint::message_id(id)?;
        if !self.is_event_subscription() || self.message_id().is_some() || self.username_token {
            return Err(WireError::UnsupportedHeader);
        }
        let at = self
            .body
            .windows(b"<s:Header>".len())
            .position(|part| part == b"<s:Header>")
            .ok_or(WireError::UnexpectedEnvelope)?
            + b"<s:Header>".len();
        let addition = format!("<wsa:MessageID>{id}</wsa:MessageID>");
        let length = self
            .body
            .len()
            .checked_add(addition.len())
            .ok_or(WireError::InputTooLarge)?;
        if length > MAX_SOAP_BYTES {
            return Err(WireError::InputTooLarge);
        }
        let mut body = Vec::with_capacity(length);
        body.extend_from_slice(&self.body[..at]);
        body.extend_from_slice(addition.as_bytes());
        body.extend_from_slice(&self.body[at..]);
        self.body.fill(0);
        self.body = body;
        Ok(self)
    }

    /// Exact owner-supplied WS-Addressing identity, if this subscription request
    /// has been completed. The HTTP event lane refuses requests without one.
    #[must_use]
    pub fn message_id(&self) -> Option<&str> {
        let body = std::str::from_utf8(&self.body).ok()?;
        let (_, tail) = body.split_once("<wsa:MessageID>")?;
        tail.split_once("</wsa:MessageID>").map(|(id, _)| id)
    }

    pub(super) fn with_security_header(mut self, header: &[u8]) -> Result<Self, WireError> {
        if self.username_token || self.action == OnvifOperation::GetSystemDateAndTime.action() {
            return Err(WireError::UnsupportedHeader);
        }
        let body_at = self
            .body
            .windows(b"<s:Body>".len())
            .position(|part| part == b"<s:Body>")
            .ok_or(WireError::UnexpectedEnvelope)?;
        // PullPoint already carries WS-Addressing headers. Insert the typed
        // Security child into that Header rather than creating a second Header.
        let existing_header = self.body[..body_at]
            .windows(b"</s:Header>".len())
            .position(|part| part == b"</s:Header>");
        let (at, addition) = if let Some(at) = existing_header {
            let addition = header
                .strip_prefix(b"<s:Header>")
                .and_then(|value| value.strip_suffix(b"</s:Header>"))
                .ok_or(WireError::UnsupportedHeader)?;
            (at, addition)
        } else {
            (body_at, header)
        };
        let length = self
            .body
            .len()
            .checked_add(addition.len())
            .ok_or(WireError::InputTooLarge)?;
        if length > MAX_SOAP_BYTES {
            return Err(WireError::InputTooLarge);
        }
        let mut body = Vec::with_capacity(length);
        body.extend_from_slice(&self.body[..at]);
        body.extend_from_slice(addition);
        body.extend_from_slice(&self.body[at..]);
        self.body.fill(0);
        self.body = body;
        self.username_token = true;
        Ok(self)
    }
}

impl Drop for SoapRequest {
    fn drop(&mut self) {
        // Best-effort reduction of proof/token lifetime, not a secure-erasure guarantee.
        self.body.fill(0);
    }
}

impl fmt::Debug for SoapRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoapRequest")
            .field("action", &self.action)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Media1 service advertisement. An advertised URI confers no network authority.
#[derive(Clone, Eq, PartialEq)]
pub struct Capabilities {
    /// Untrusted service URI; the caller must validate its owner-authorized scope.
    pub media_xaddr: Option<String>,
    /// Explicit RTP/RTSP/TCP advertisement; missing means unknown, never false.
    pub rtp_rtsp_tcp: Option<bool>,
}

impl fmt::Debug for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Capabilities")
            .field("media_service_advertised", &self.media_xaddr.is_some())
            .field("rtp_rtsp_tcp", &self.rtp_rtsp_tcp)
            .finish()
    }
}

/// Advertised codec vocabulary; unknown/vendor extensions remain unsupported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoEncoding {
    /// H.264/AVC advertisement, independent of actual SPS/profile validation.
    H264,
    /// H.265/HEVC advertisement, admitted only through Media2's codec vocabulary.
    H265,
    /// JPEG video advertisement.
    Jpeg,
    /// MPEG-4 Part 2 advertisement.
    Mpeg4,
    /// Unknown or out-of-subset codec; no untrusted label is reflected.
    Unsupported,
}

/// Advertised video properties, not proof that a stream decodes or matches them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VideoEncoder {
    /// Advertised codec.
    pub encoding: VideoEncoding,
    /// Positive bounded advertised width.
    pub width: u32,
    /// Positive bounded advertised height.
    pub height: u32,
}

/// A complete media profile projection; text and tokens are untrusted metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct MediaProfile {
    /// Exact token used by `get_stream_uri_request`; never log it.
    pub token: String,
    /// Device-supplied display name; requires presentation sanitization.
    pub name: String,
    /// Missing video configuration is explicit, including audio-only profiles.
    pub video: Option<VideoEncoder>,
}

impl fmt::Debug for MediaProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MediaProfile")
            .field("token", &"[redacted]")
            .field("name", &"[untrusted metadata]")
            .field("video", &self.video)
            .finish()
    }
}

/// Reported URI and all mandatory validity fields, without fabricated defaults.
#[derive(Clone, Eq, PartialEq)]
pub struct StreamUri {
    /// Exact decoded URI; caller must validate its scope and credential policy.
    pub uri: String,
    /// Whether the device says connection establishment invalidates this URI.
    pub invalid_after_connect: bool,
    /// Whether the device says reboot invalidates this URI.
    pub invalid_after_reboot: bool,
    /// Bounded nonnegative XML duration. `PT0S` conventionally means indefinite.
    /// The caller must select its supported validity subset before persistence.
    pub timeout: String,
}

impl StreamUri {
    /// Whether the device reports a reusable URI with no expiry. Zero calendar
    /// components are recognized without inventing a month-to-seconds conversion.
    #[must_use]
    pub fn is_stable(&self) -> bool {
        stable_lifetime(
            self.invalid_after_connect,
            self.invalid_after_reboot,
            &self.timeout,
        )
    }
}

pub(super) fn stable_lifetime(connect: bool, reboot: bool, timeout: &str) -> bool {
    !connect
        && !reboot
        && duration(timeout).is_ok()
        && timeout
            .bytes()
            .filter(u8::is_ascii_digit)
            .all(|digit| digit == b'0')
}

impl fmt::Debug for StreamUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamUri")
            .field("uri", &"[redacted]")
            .field("invalid_after_connect", &self.invalid_after_connect)
            .field("invalid_after_reboot", &self.invalid_after_reboot)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Reported snapshot URI with its optional device-declared expiry, without
/// fabricated defaults. The caller must fetch it before expiry and validate scope.
#[derive(Clone, Eq, PartialEq)]
pub struct SnapshotUri {
    /// Exact decoded URI; caller must validate its scope and credential policy.
    pub uri: String,
    /// Device-declared absolute expiry (ISO-8601), when the device supplied one.
    pub valid_until: Option<String>,
}

impl fmt::Debug for SnapshotUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotUri")
            .field("uri", &"[redacted]")
            .field("valid_until", &self.valid_until)
            .finish()
    }
}

/// Namespace-resolved SOAP 1.2 fault class; raw device text is never retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoapFaultCode {
    /// Request-side fault.
    Sender,
    /// Device-side fault.
    Receiver,
    /// Unsupported SOAP envelope version.
    VersionMismatch,
    /// Required SOAP header was not understood.
    MustUnderstand,
    /// Unsupported SOAP encoding.
    DataEncodingUnknown,
    /// Unknown QName, preserved as an unsupported category.
    Unknown,
}

/// Selected ONVIF error subcodes; raw QNames and reasons are not diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoapFaultSubcode {
    /// The device refused authorization.
    NotAuthorized,
    /// The requested action is unavailable.
    ActionNotSupported,
    /// Invalid request argument.
    InvalidArgVal,
    /// The requested profile does not exist.
    NoProfile,
    /// No subcode was supplied.
    Absent,
    /// A supplied subcode is outside the admitted vocabulary.
    Unknown,
}

/// Payload-free fault summary safe to expose in diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SoapFault {
    /// SOAP-level category.
    pub code: SoapFaultCode,
    /// Most specific ONVIF subcode encountered in the bounded subcode chain.
    pub subcode: SoapFaultSubcode,
}

/// Payload-free parsing/building failure. No variant contains response text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    /// The complete response exceeds the fixed byte bound.
    InputTooLarge,
    /// Malformed XML, invalid namespace binding, or illegal XML character.
    MalformedXml,
    /// DTD, processing instruction, or unsupported XML declaration.
    UnsupportedXml,
    /// XML depth, element, attribute, name, or text bound exceeded.
    XmlLimitExceeded,
    /// Not one SOAP 1.2 envelope with exactly one body.
    UnexpectedEnvelope,
    /// Body does not contain exactly the requested response.
    UnexpectedResponse,
    /// Multiple values for a field or duplicate profile tokens.
    DuplicateField,
    /// A mandatory field was not supplied.
    MissingField,
    /// Invalid bounded scalar, token, boolean, dimension, URI text, or duration.
    InvalidField,
    /// More profiles were supplied than can be represented completely.
    ProfileLimitExceeded,
    /// More advertised services were supplied than can be checked completely.
    ServiceLimitExceeded,
    /// More event notifications were supplied than can be represented completely.
    EventLimitExceeded,
    /// More Source, Key, or Data items were supplied than this subset permits.
    ItemLimitExceeded,
    /// More analytics frames, objects, or class candidates than this subset permits.
    AnalyticsLimitExceeded,
    /// Event topic dialect or namespace use is outside the explicit subset.
    UnsupportedEventContent,
    /// A required header or SOAP encoding lies outside this wire subset.
    UnsupportedHeader,
    /// Typed SOAP fault, without reason text, detail, URLs, or credentials.
    SoapFault(SoapFault),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SoapFault(fault) => {
                write!(f, "ONVIF SOAP fault: {:?}/{:?}", fault.code, fault.subcode)
            }
            Self::InputTooLarge => f.write_str("ONVIF SOAP response exceeds byte limit"),
            Self::MalformedXml => f.write_str("malformed ONVIF XML or namespace"),
            Self::UnsupportedXml => f.write_str("unsupported ONVIF XML construct"),
            Self::XmlLimitExceeded => f.write_str("ONVIF XML resource limit exceeded"),
            Self::UnexpectedEnvelope => f.write_str("invalid ONVIF SOAP 1.2 envelope"),
            Self::UnexpectedResponse => f.write_str("unexpected ONVIF SOAP response"),
            Self::DuplicateField => f.write_str("duplicate ONVIF response field"),
            Self::MissingField => f.write_str("missing ONVIF response field"),
            Self::InvalidField => f.write_str("invalid ONVIF response field"),
            Self::ProfileLimitExceeded => f.write_str("ONVIF profile count exceeds limit"),
            Self::ServiceLimitExceeded => f.write_str("ONVIF service count exceeds limit"),
            Self::EventLimitExceeded => f.write_str("ONVIF event count exceeds limit"),
            Self::ItemLimitExceeded => f.write_str("ONVIF event item count exceeds limit"),
            Self::AnalyticsLimitExceeded => f.write_str("ONVIF analytics count exceeds limit"),
            Self::UnsupportedEventContent => f.write_str("unsupported ONVIF event content"),
            Self::UnsupportedHeader => {
                f.write_str("unsupported required ONVIF SOAP header or encoding")
            }
        }
    }
}

impl std::error::Error for WireError {}

fn request(operation: OnvifOperation, content: &str) -> SoapRequest {
    SoapRequest {
        action: operation.action(),
        username_token: false,
        body: format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"{SOAP_NS}\" xmlns:tds=\"{DEVICE_NS}\" xmlns:trt=\"{MEDIA_NS}\" xmlns:tt=\"{SCHEMA_NS}\"><s:Body>{content}</s:Body></s:Envelope>"
        )
        .into_bytes(),
    }
}

/// Request only the Media1 capability category; this never modifies the camera.
#[must_use]
pub fn get_capabilities_request() -> SoapRequest {
    request(
        OnvifOperation::GetCapabilities,
        "<tds:GetCapabilities><tds:Category>Media</tds:Category></tds:GetCapabilities>",
    )
}

/// Enumerate the device's existing Media1 profiles without creating a profile.
#[must_use]
pub fn get_profiles_request() -> SoapRequest {
    request(OnvifOperation::GetProfiles, "<trt:GetProfiles/>")
}

/// Request RTP unicast over RTSP/TCP for an exact bounded token. XML metacharacters
/// are escaped, so a token cannot alter the operation or introduce another body.
pub fn get_stream_uri_request(profile_token: &str) -> Result<SoapRequest, WireError> {
    let token = escaped_reference(profile_token)?;
    Ok(request(
        OnvifOperation::GetStreamUri,
        &format!(
            "<trt:GetStreamUri><trt:StreamSetup><tt:Stream>RTP_unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>{token}</trt:ProfileToken></trt:GetStreamUri>"
        ),
    ))
}

/// Request the selected profile's bounded JPEG snapshot URI for an exact bounded token.
pub fn get_snapshot_uri_request(profile_token: &str) -> Result<SoapRequest, WireError> {
    let token = escaped_reference(profile_token)?;
    Ok(request(
        OnvifOperation::GetSnapshotUri,
        &format!(
            "<trt:GetSnapshotUri><trt:ProfileToken>{token}</trt:ProfileToken></trt:GetSnapshotUri>"
        ),
    ))
}

fn escaped_reference(profile_token: &str) -> Result<String, WireError> {
    reference(profile_token)?;
    let mut token = String::with_capacity(profile_token.len());
    for ch in profile_token.chars() {
        match ch {
            '&' => token.push_str("&amp;"),
            '<' => token.push_str("&lt;"),
            '>' => token.push_str("&gt;"),
            '"' => token.push_str("&quot;"),
            '\'' => token.push_str("&apos;"),
            _ => token.push(ch),
        }
    }
    Ok(token)
}

/// Parse the exact Media1 capability projection. Unrelated extensions are bounded
/// and ignored; a same-local-name field in another namespace cannot supply data.
pub fn parse_capabilities(bytes: &[u8]) -> Result<Capabilities, WireError> {
    let (doc, response) = response(bytes, DEVICE_NS, "GetCapabilitiesResponse")?;
    let capabilities = required(&doc, response, DEVICE_NS, "Capabilities")?;
    let Some(media) = unique(&doc, capabilities, SCHEMA_NS, "Media")? else {
        return Ok(Capabilities {
            media_xaddr: None,
            rtp_rtsp_tcp: None,
        });
    };
    let endpoint = required(&doc, media, SCHEMA_NS, "XAddr")?;
    let media_xaddr = uri_text(&doc, endpoint)?.to_owned();
    let rtp_rtsp_tcp = unique(&doc, media, SCHEMA_NS, "StreamingCapabilities")?
        .map(|streaming| {
            unique(&doc, streaming, SCHEMA_NS, "RTP_RTSP_TCP")?
                .map(|flag| boolean(&doc, flag))
                .transpose()
        })
        .transpose()?
        .flatten();
    Ok(Capabilities {
        media_xaddr: Some(media_xaddr),
        rtp_rtsp_tcp,
    })
}

/// Parse the complete bounded profile list; duplicates or overflow refuse the
/// response rather than silently dropping profiles that could affect selection.
pub fn parse_profiles(bytes: &[u8]) -> Result<Vec<MediaProfile>, WireError> {
    let (doc, response) = response(bytes, MEDIA_NS, "GetProfilesResponse")?;
    let mut profiles: Vec<MediaProfile> = Vec::new();
    for id in doc.child_ids(response) {
        // GetProfilesResponse contains only Profiles in Media1's WSDL. Treating
        // a same-local-name foreign element as an empty inventory would turn an
        // unsupported/malformed reply into an unwitnessed absence claim.
        if !doc.named(id, MEDIA_NS, "Profiles") {
            return Err(WireError::UnexpectedResponse);
        }
        if profiles.len() == MAX_MEDIA_PROFILES {
            return Err(WireError::ProfileLimitExceeded);
        }
        let token = doc
            .attribute(id, "", "token")
            .ok_or(WireError::MissingField)?;
        reference(token)?;
        if profiles.iter().any(|profile| profile.token == token) {
            return Err(WireError::DuplicateField);
        }
        let name_id = required(&doc, id, SCHEMA_NS, "Name")?;
        let name = doc.leaf_text(name_id)?;
        if name.chars().count() > MAX_REFERENCE_CHARS || name.chars().any(char::is_control) {
            return Err(WireError::InvalidField);
        }
        if let Some(fixed) = doc.attribute(id, "", "fixed") {
            parse_boolean(fixed)?;
        }
        let video = unique(&doc, id, SCHEMA_NS, "VideoEncoderConfiguration")?
            .map(|encoder| {
                let encoding_id = required(&doc, encoder, SCHEMA_NS, "Encoding")?;
                let encoding = match scalar(&doc, encoding_id)? {
                    "H264" => VideoEncoding::H264,
                    "JPEG" => VideoEncoding::Jpeg,
                    "MPEG4" => VideoEncoding::Mpeg4,
                    value if value.is_empty() || value.len() > 64 => {
                        return Err(WireError::InvalidField);
                    }
                    _ => VideoEncoding::Unsupported,
                };
                let resolution = required(&doc, encoder, SCHEMA_NS, "Resolution")?;
                let width = dimension(&doc, required(&doc, resolution, SCHEMA_NS, "Width")?)?;
                let height = dimension(&doc, required(&doc, resolution, SCHEMA_NS, "Height")?)?;
                Ok(VideoEncoder {
                    encoding,
                    width,
                    height,
                })
            })
            .transpose()?;
        profiles.push(MediaProfile {
            token: token.to_owned(),
            name: name.to_owned(),
            video,
        });
    }
    Ok(profiles)
}

/// Parse a Media1 URI with all mandatory validity fields. URL authorization,
/// credentials, redirects, codec support, and actual capture belong to callers.
pub fn parse_stream_uri(bytes: &[u8]) -> Result<StreamUri, WireError> {
    let (doc, response) = response(bytes, MEDIA_NS, "GetStreamUriResponse")?;
    let media = required(&doc, response, MEDIA_NS, "MediaUri")?;
    let uri = uri_text(&doc, required(&doc, media, SCHEMA_NS, "Uri")?)?.to_owned();
    let invalid_after_connect = boolean(
        &doc,
        required(&doc, media, SCHEMA_NS, "InvalidAfterConnect")?,
    )?;
    let invalid_after_reboot = boolean(
        &doc,
        required(&doc, media, SCHEMA_NS, "InvalidAfterReboot")?,
    )?;
    let timeout = scalar(&doc, required(&doc, media, SCHEMA_NS, "Timeout")?)?;
    duration(timeout)?;
    Ok(StreamUri {
        uri,
        invalid_after_connect,
        invalid_after_reboot,
        timeout: timeout.to_owned(),
    })
}

/// Parse a Media1 snapshot URI with its optional device-declared expiry. Fetching,
/// byte bounds, and actual image custody belong to the caller.
pub fn parse_snapshot_uri(bytes: &[u8]) -> Result<SnapshotUri, WireError> {
    let (doc, response) = response(bytes, MEDIA_NS, "GetSnapshotUriResponse")?;
    let media = required(&doc, response, MEDIA_NS, "MediaUri")?;
    let uri = uri_text(&doc, required(&doc, media, SCHEMA_NS, "Uri")?)?.to_owned();
    let valid_until = unique(&doc, media, SCHEMA_NS, "ValidUntil")?
        .map(|id| scalar(&doc, id))
        .transpose()?
        .map(|s| s.to_owned());
    Ok(SnapshotUri { uri, valid_until })
}

/// Parse only a SOAP 1.2 fault, including the error body of HTTP 400/500 responses.
/// A success envelope is refused, so HTTP errors cannot become operation success.
pub fn parse_soap_fault(bytes: &[u8]) -> Result<SoapFault, WireError> {
    match response(bytes, SOAP_NS, "Fault") {
        Err(WireError::SoapFault(fault)) => Ok(fault),
        Err(error) => Err(error),
        Ok(_) => Err(WireError::UnexpectedResponse),
    }
}

fn response(
    bytes: &[u8],
    namespace: &str,
    local: &str,
) -> Result<(xml::Document, usize), WireError> {
    response_with_addressing(bytes, namespace, local, None)
}

fn response_with_addressing(
    bytes: &[u8],
    namespace: &str,
    local: &str,
    expected_action: Option<&str>,
) -> Result<(xml::Document, usize), WireError> {
    let doc = xml::Document::parse(bytes)?;
    let root = doc.root();
    if !doc.named(root, SOAP_NS, "Envelope") || !doc.only_whitespace(root) {
        return Err(WireError::UnexpectedEnvelope);
    }
    if doc.attribute(root, SOAP_NS, "encodingStyle").is_some() {
        return Err(WireError::UnsupportedHeader);
    }
    let mut body = None;
    let mut header_seen = false;
    let mut action = None;
    let mut to_seen = false;
    let mut relates_seen = false;
    for child in doc.child_ids(root) {
        if doc.named(child, SOAP_NS, "Header") && !header_seen && body.is_none() {
            header_seen = true;
            if !doc.only_whitespace(child) {
                return Err(WireError::UnexpectedEnvelope);
            }
            for field in doc.child_ids(child) {
                let understood = if expected_action.is_some()
                    && doc.named(field, pullpoint::ADDRESSING_NS, "Action")
                {
                    if action.is_some() {
                        return Err(WireError::DuplicateField);
                    }
                    action = Some(scalar(&doc, field)?);
                    true
                } else if expected_action.is_some()
                    && doc.named(field, pullpoint::ADDRESSING_NS, "To")
                {
                    if to_seen {
                        return Err(WireError::DuplicateField);
                    }
                    to_seen = true;
                    if scalar(&doc, field)? != pullpoint::ANONYMOUS {
                        return Err(WireError::UnsupportedHeader);
                    }
                    true
                } else if expected_action.is_some()
                    && doc.named(field, pullpoint::ADDRESSING_NS, "RelatesTo")
                {
                    if relates_seen {
                        return Err(WireError::DuplicateField);
                    }
                    relates_seen = true;
                    pullpoint::relates_to(&doc, field)?;
                    true
                } else {
                    false
                };
                if understood {
                    if doc.attribute(field, SOAP_NS, "role").is_some_and(|role| {
                        role != "http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver"
                    }) {
                        return Err(WireError::UnsupportedHeader);
                    }
                }
                if let Some(required) = doc.attribute(field, SOAP_NS, "mustUnderstand") {
                    if parse_boolean(required)? && !understood {
                        return Err(WireError::UnsupportedHeader);
                    }
                }
            }
        } else if doc.named(child, SOAP_NS, "Body") && body.is_none() {
            body = Some(child);
        } else {
            return Err(WireError::UnexpectedEnvelope);
        }
    }
    let body = body.ok_or(WireError::UnexpectedEnvelope)?;
    if !doc.only_whitespace(body) {
        return Err(WireError::UnexpectedEnvelope);
    }
    let response = {
        let mut children = doc.child_ids(body);
        let response = children.next().ok_or(WireError::UnexpectedResponse)?;
        if children.next().is_some() {
            return Err(WireError::UnexpectedResponse);
        }
        response
    };
    if doc.attribute(body, SOAP_NS, "encodingStyle").is_some()
        || doc.attribute(response, SOAP_NS, "encodingStyle").is_some()
    {
        return Err(WireError::UnsupportedHeader);
    }
    if doc.named(response, SOAP_NS, "Fault") {
        return Err(WireError::SoapFault(fault(&doc, response)?));
    }
    if !doc.named(response, namespace, local) || !doc.only_whitespace(response) {
        return Err(WireError::UnexpectedResponse);
    }
    if let (Some(expected), Some(observed)) = (expected_action, action) {
        if observed != expected {
            return Err(WireError::UnexpectedResponse);
        }
    }
    Ok((doc, response))
}

fn fault(doc: &xml::Document, fault: usize) -> Result<SoapFault, WireError> {
    let code = required(doc, fault, SOAP_NS, "Code")?;
    let value = required(doc, code, SOAP_NS, "Value")?;
    let (namespace, local) = doc.resolve_qname(value, scalar(doc, value)?)?;
    let code_kind = match (namespace, local) {
        (SOAP_NS, "Sender") => SoapFaultCode::Sender,
        (SOAP_NS, "Receiver") => SoapFaultCode::Receiver,
        (SOAP_NS, "VersionMismatch") => SoapFaultCode::VersionMismatch,
        (SOAP_NS, "MustUnderstand") => SoapFaultCode::MustUnderstand,
        (SOAP_NS, "DataEncodingUnknown") => SoapFaultCode::DataEncodingUnknown,
        _ => SoapFaultCode::Unknown,
    };
    // Reason is mandatory in SOAP 1.2 but its hostile prose is never reflected.
    let reason = required(doc, fault, SOAP_NS, "Reason")?;
    if doc.children(reason, SOAP_NS, "Text").next().is_none() {
        return Err(WireError::MissingField);
    }
    let mut parent = code;
    let mut subcode = SoapFaultSubcode::Absent;
    while let Some(nested) = unique(doc, parent, SOAP_NS, "Subcode")? {
        let value = required(doc, nested, SOAP_NS, "Value")?;
        let (namespace, local) = doc.resolve_qname(value, scalar(doc, value)?)?;
        subcode = match (namespace, local) {
            (ERROR_NS, "NotAuthorized") => SoapFaultSubcode::NotAuthorized,
            (ERROR_NS, "ActionNotSupported") => SoapFaultSubcode::ActionNotSupported,
            (ERROR_NS, "InvalidArgVal") => SoapFaultSubcode::InvalidArgVal,
            (ERROR_NS, "NoProfile") => SoapFaultSubcode::NoProfile,
            _ => SoapFaultSubcode::Unknown,
        };
        parent = nested;
    }
    Ok(SoapFault {
        code: code_kind,
        subcode,
    })
}

fn unique(
    doc: &xml::Document,
    parent: usize,
    namespace: &str,
    local: &str,
) -> Result<Option<usize>, WireError> {
    if !doc.only_whitespace(parent) {
        return Err(WireError::InvalidField);
    }
    let mut children = doc.children(parent, namespace, local);
    let result = children.next();
    if children.next().is_some() {
        return Err(WireError::DuplicateField);
    }
    Ok(result)
}

fn required(
    doc: &xml::Document,
    parent: usize,
    namespace: &str,
    local: &str,
) -> Result<usize, WireError> {
    unique(doc, parent, namespace, local)?.ok_or(WireError::MissingField)
}

fn scalar(doc: &xml::Document, id: usize) -> Result<&str, WireError> {
    Ok(doc.leaf_text(id)?.trim_matches(xml::whitespace))
}

fn uri_text(doc: &xml::Document, id: usize) -> Result<&str, WireError> {
    let text = scalar(doc, id)?;
    if text.is_empty()
        || text.len() > MAX_URI_BYTES
        || text.chars().any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(WireError::InvalidField);
    }
    Ok(text)
}

fn reference(value: &str) -> Result<(), WireError> {
    if value.is_empty()
        || value.chars().count() > MAX_REFERENCE_CHARS
        || value
            .chars()
            .any(|ch| ch.is_control() || !xml::valid_char(ch))
    {
        return Err(WireError::InvalidField);
    }
    Ok(())
}

fn parse_boolean(value: &str) -> Result<bool, WireError> {
    match value.trim_matches(xml::whitespace) {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(WireError::InvalidField),
    }
}

fn boolean(doc: &xml::Document, id: usize) -> Result<bool, WireError> {
    parse_boolean(doc.leaf_text(id)?)
}

fn dimension(doc: &xml::Document, id: usize) -> Result<u32, WireError> {
    let text = scalar(doc, id)?;
    let text = text.strip_prefix('+').unwrap_or(text);
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|ch| ch.is_ascii_digit()) {
        return Err(WireError::InvalidField);
    }
    let value = text.parse::<u32>().map_err(|_| WireError::InvalidField)?;
    if value == 0 || value > MAX_VIDEO_DIMENSION {
        return Err(WireError::InvalidField);
    }
    Ok(value)
}

fn duration(value: &str) -> Result<(), WireError> {
    // XML Schema duration lexical structure. Do not convert calendar months or
    // years into seconds; that interpretation belongs to the caller's policy.
    if value.len() > 128 || !value.starts_with('P') {
        return Err(WireError::InvalidField);
    }
    let bytes = value.as_bytes();
    let mut pos = 1;
    let mut in_time = false;
    let mut last = 0;
    let mut components = 0;
    let mut time_components = 0;
    while pos < bytes.len() {
        if bytes[pos] == b'T' {
            if in_time {
                return Err(WireError::InvalidField);
            }
            in_time = true;
            pos += 1;
            continue;
        }
        let start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == start {
            return Err(WireError::InvalidField);
        }
        let mut fraction = false;
        if pos < bytes.len() && bytes[pos] == b'.' {
            fraction = true;
            pos += 1;
            let start = pos;
            while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                pos += 1;
            }
            if start == pos {
                return Err(WireError::InvalidField);
            }
        }
        let unit = *bytes.get(pos).ok_or(WireError::InvalidField)?;
        let rank = match (in_time, unit, fraction) {
            (false, b'Y', false) => 1,
            (false, b'M', false) => 2,
            (false, b'D', false) => 3,
            (true, b'H', false) => 4,
            (true, b'M', false) => 5,
            (true, b'S', _) => 6,
            _ => return Err(WireError::InvalidField),
        };
        if rank <= last {
            return Err(WireError::InvalidField);
        }
        last = rank;
        components += 1;
        time_components += usize::from(in_time);
        pos += 1;
    }
    if components == 0 || (in_time && time_components == 0) {
        return Err(WireError::InvalidField);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNAPSHOT_URI_RESPONSE: &str = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"",
        " xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\"",
        " xmlns:tt=\"http://www.onvif.org/ver10/schema\">",
        "<s:Body>",
        "<trt:GetSnapshotUriResponse>",
        "<trt:MediaUri>",
        "<tt:Uri>http://192.168.5.211:8080/snap/image.jpg</tt:Uri>",
        "<tt:ValidUntil>2026-10-20T00:05:00Z</tt:ValidUntil>",
        "</trt:MediaUri>",
        "</trt:GetSnapshotUriResponse>",
        "</s:Body>",
        "</s:Envelope>"
    );

    #[test]
    fn parse_snapshot_uri_reads_uri_and_optional_expiry() -> Result<(), Box<dyn std::error::Error>>
    {
        let snap = parse_snapshot_uri(SNAPSHOT_URI_RESPONSE.as_bytes())?;
        assert_eq!(snap.uri, "http://192.168.5.211:8080/snap/image.jpg");
        assert_eq!(snap.valid_until.as_deref(), Some("2026-10-20T00:05:00Z"));
        Ok(())
    }

    #[test]
    fn parse_snapshot_uri_without_expiry_is_valid() -> Result<(), Box<dyn std::error::Error>> {
        let body = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"",
            " xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\"",
            " xmlns:tt=\"http://www.onvif.org/ver10/schema\">",
            "<s:Body>",
            "<trt:GetSnapshotUriResponse>",
            "<trt:MediaUri>",
            "<tt:Uri>http://192.168.5.211:8080/snap/image.jpg</tt:Uri>",
            "</trt:MediaUri>",
            "</trt:GetSnapshotUriResponse>",
            "</s:Body>",
            "</s:Envelope>"
        );
        let snap = parse_snapshot_uri(body.as_bytes())?;
        assert_eq!(snap.uri, "http://192.168.5.211:8080/snap/image.jpg");
        assert!(snap.valid_until.is_none());
        Ok(())
    }

    #[test]
    fn parse_snapshot_uri_refuses_missing_media_uri() -> Result<(), Box<dyn std::error::Error>> {
        let body = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"",
            " xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\">",
            "<s:Body>",
            "<trt:GetSnapshotUriResponse>",
            "</trt:GetSnapshotUriResponse>",
            "</s:Body>",
            "</s:Envelope>"
        );
        assert_eq!(
            parse_snapshot_uri(body.as_bytes()).err(),
            Some(WireError::MissingField)
        );
        Ok(())
    }

    #[test]
    fn get_snapshot_uri_request_binds_action_and_token() -> Result<(), Box<dyn std::error::Error>> {
        let req = get_snapshot_uri_request("Profile_1")?;
        assert_eq!(
            req.action(),
            "http://www.onvif.org/ver10/media/wsdl/GetSnapshotUri"
        );
        let body = std::str::from_utf8(req.body())?;
        assert!(body.contains("<trt:GetSnapshotUri>"));
        assert!(body.contains("<trt:ProfileToken>Profile_1</trt:ProfileToken>"));
        Ok(())
    }
}
