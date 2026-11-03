#![forbid(unsafe_code)]
//! Bounded, model-independent parsing of owner-supplied UniFi Protect camera/stream exports.
//!
//! This module performs no I/O, authenticates no console, enables no stream, and grants no
//! capture authority. Official `/v1/cameras` and `/v1/cameras/{id}/rtsps-stream` responses are
//! input metadata, not proof of current device health. Unknown vendor fields remain available
//! privately; no camera name implies a codec, frame rate, dimensions, PTZ, or audio permission.
//! Main and package views have distinct identities, while quality levels of the main camera
//! remain renditions of the same view. All stream URLs and raw metadata are private input.

mod endpoint;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::json_input::{self, JsonError, Value};

pub use endpoint::{StreamEndpoint, StreamScheme};

/// Absolute input bound; also bounded by the shared parser's depth/node/string limits.
pub const MAX_PROTECT_DOCUMENT_BYTES: usize = json_input::MAX_INPUT_BYTES;
/// Maximum cameras accepted from one complete inventory response (never truncated).
pub const MAX_PROTECT_CAMERAS: usize = 512;
/// Maximum encoded URI size before any parsing or allocation.
pub const MAX_STREAM_URI_BYTES: usize = 4096;
const MAX_ID_BYTES: usize = 128;
const MAX_LABEL_BYTES: usize = 512;

/// Explicit stream quality requested by the operator; there is no automatic fallback.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProtectQuality {
    /// Main camera's high-quality rendition.
    High,
    /// Main camera's medium-quality rendition.
    Medium,
    /// Main camera's low-quality rendition.
    Low,
    /// A distinct package-camera view, where explicitly supported.
    Package,
}

impl ProtectQuality {
    /// The exact official JSON field / quality spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Package => "package",
        }
    }

    /// Physical/logical view selected by this rendition.
    #[must_use]
    pub const fn view(self) -> ProtectView {
        match self {
            Self::Package => ProtectView::Package,
            Self::High | Self::Medium | Self::Low => ProtectView::Main,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::High => 0,
            Self::Medium => 1,
            Self::Low => 2,
            Self::Package => 3,
        }
    }
}

/// A view within a camera, independently of the chosen quality rendition.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProtectView {
    /// Main camera view.
    Main,
    /// Separate package camera view on supported doorbells/entry devices.
    Package,
}

impl ProtectView {
    /// Stable view spelling for local identity composition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Package => "package",
        }
    }
}

/// The state reported in an export; it is never proof of current live health.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CameraConnection {
    /// Vendor reported `CONNECTED`.
    Connected,
    /// Vendor reported `CONNECTING`.
    Connecting,
    /// Vendor reported `DISCONNECTED`.
    Disconnected,
    /// Missing/null/unrecognized value; the exact field remains in private vendor metadata.
    Unknown,
}

/// Pure parse/selection failure; variants never contain raw URLs, identifiers, or metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtectError {
    /// Document exceeds the input ceiling.
    InputLimit,
    /// Input is not UTF-8.
    InvalidUtf8,
    /// Strict JSON syntax, duplicate-key, depth, node, or string-bound refusal.
    InvalidJson(JsonError),
    /// A top-level JSON value is not the required array/object.
    InvalidShape,
    /// A required known field is missing.
    MissingField(&'static str),
    /// A known field has an invalid type or bounded value.
    InvalidField(&'static str),
    /// Owner handoff contains a field outside the fixed wrapper contract.
    UnknownSourceField,
    /// Inventory exceeds the camera ceiling.
    CameraLimit,
    /// Inventory contains an ambiguous duplicate camera identifier.
    DuplicateCamera,
    /// URI exceeds its size ceiling.
    UriLimit,
    /// URI is malformed or uses unsupported syntax/scheme.
    InvalidEndpoint,
    /// URL userinfo is forbidden; credentials require a separate authorized secret boundary.
    UserInfoForbidden,
    /// A secure endpoint cannot be sent through plaintext RTSP.
    SecureTransportRequired,
    /// Requested quality was omitted from the response; availability is unknown.
    MissingStream(ProtectQuality),
    /// Requested quality was explicitly null (no enabled stream URL).
    DisabledStream(ProtectQuality),
    /// Package view requires an explicit true `hasPackageCamera` capability.
    PackageUnavailable,
    /// Explicit operator RTSP choice has no separately supplied URL map.
    MissingOperatorRtsp,
    /// An entry in the explicit RTSP override map is not plaintext RTSP.
    NonRtspOverride,
}

impl fmt::Display for ProtectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputLimit => f.write_str("Protect input exceeds its byte bound"),
            Self::InvalidUtf8 => f.write_str("Protect input is not UTF-8"),
            Self::InvalidJson(error) => write!(f, "invalid Protect JSON: {error}"),
            Self::InvalidShape => f.write_str("unexpected Protect JSON shape"),
            Self::MissingField(field) => write!(f, "missing Protect field {field}"),
            Self::InvalidField(field) => write!(f, "invalid Protect field {field}"),
            Self::UnknownSourceField => f.write_str("unknown field in Protect source handoff"),
            Self::CameraLimit => f.write_str("Protect inventory exceeds its camera bound"),
            Self::DuplicateCamera => f.write_str("duplicate camera in Protect inventory"),
            Self::UriLimit => f.write_str("Protect stream URI exceeds its byte bound"),
            Self::InvalidEndpoint => f.write_str("invalid Protect stream endpoint"),
            Self::UserInfoForbidden => f.write_str("Protect stream URI must not contain userinfo"),
            Self::SecureTransportRequired => {
                f.write_str("RTSPS requires secure transport; automatic downgrade is forbidden")
            }
            Self::MissingStream(quality) => {
                write!(f, "{} stream availability is missing", quality.as_str())
            }
            Self::DisabledStream(quality) => {
                write!(f, "{} stream has no enabled URL", quality.as_str())
            }
            Self::PackageUnavailable => f.write_str("package view capability is absent or unknown"),
            Self::MissingOperatorRtsp => f.write_str("no explicit operator RTSP map was supplied"),
            Self::NonRtspOverride => f.write_str("operator RTSP override must use rtsp://"),
        }
    }
}

impl std::error::Error for ProtectError {}

/// A camera from Protect, including private fields unknown to this implementation.
#[derive(Clone, PartialEq)]
pub struct ProtectCamera {
    id: String,
    name: Option<String>,
    model: Option<String>,
    connection: CameraConnection,
    has_package_camera: Option<bool>,
    vendor_fields: BTreeMap<String, Value>,
}

impl fmt::Debug for ProtectCamera {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectCamera")
            .field("connection", &self.connection)
            .field("has_package_camera", &self.has_package_camera)
            .finish_non_exhaustive()
    }
}

impl ProtectCamera {
    /// Parse one official camera-details response, without performing any I/O.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtectError> {
        Self::from_value(parse_document(bytes)?)
    }

    fn from_value(value: Value) -> Result<Self, ProtectError> {
        let fields = object(value)?;
        let id =
            optional_text(&fields, "id", MAX_ID_BYTES)?.ok_or(ProtectError::MissingField("id"))?;
        if id.is_empty() {
            return Err(ProtectError::InvalidField("id"));
        }
        let name = optional_text(&fields, "name", MAX_LABEL_BYTES)?;
        let model = optional_text(&fields, "type", MAX_LABEL_BYTES)?;
        let state = optional_text(&fields, "state", 64)?;
        let connection = match state.as_deref() {
            Some("CONNECTED") => CameraConnection::Connected,
            Some("CONNECTING") => CameraConnection::Connecting,
            Some("DISCONNECTED") => CameraConnection::Disconnected,
            _ => CameraConnection::Unknown,
        };
        let has_package_camera = match fields.get("hasPackageCamera") {
            None | Some(Value::Null) => None,
            Some(Value::Bool(value)) => Some(*value),
            _ => return Err(ProtectError::InvalidField("hasPackageCamera")),
        };
        Ok(Self {
            id,
            name,
            model,
            connection,
            has_package_camera,
            vendor_fields: fields,
        })
    }

    /// Exact vendor ID within its console; caller must separately bind the console and FSS sensor.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Private, untrusted display name, if supplied; never an identity or instruction.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Private reported model name, including unknown future models; no media facts are inferred.
    #[must_use]
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    /// Vendor-reported export state, which can be stale at capture time.
    #[must_use]
    pub const fn connection_state(&self) -> CameraConnection {
        self.connection
    }

    /// Reported package camera capability; missing/null remain unknown.
    #[must_use]
    pub const fn has_package_camera(&self) -> Option<bool> {
        self.has_package_camera
    }

    /// Exact parsed fields, including unknown capabilities. Private data: never log wholesale.
    #[must_use]
    pub const fn vendor_fields(&self) -> &BTreeMap<String, Value> {
        &self.vendor_fields
    }

    /// Pair a camera ID with its view without merging the package feed into its main feed.
    /// This is scoped to the caller's console, not a globally unique FSS sensor identity.
    pub fn view_identity(
        &self,
        quality: ProtectQuality,
    ) -> Result<CameraViewIdentity<'_>, ProtectError> {
        if quality == ProtectQuality::Package && self.has_package_camera != Some(true) {
            return Err(ProtectError::PackageUnavailable);
        }
        Ok(CameraViewIdentity {
            camera_id: &self.id,
            view: quality.view(),
        })
    }
}

/// Camera and physical view identity within a caller-bound Protect console.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CameraViewIdentity<'a> {
    camera_id: &'a str,
    view: ProtectView,
}

impl fmt::Debug for CameraViewIdentity<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CameraViewIdentity")
            .field("view", &self.view)
            .finish_non_exhaustive()
    }
}

impl<'a> CameraViewIdentity<'a> {
    /// Exact private vendor camera ID.
    #[must_use]
    pub const fn camera_id(self) -> &'a str {
        self.camera_id
    }

    /// Main or separate package view.
    #[must_use]
    pub const fn view(self) -> ProtectView {
        self.view
    }
}

/// Complete bounded inventory; no missing, offline, or unfamiliar-model entry is silently dropped.
#[derive(Clone, Debug, PartialEq)]
pub struct ProtectCatalog {
    cameras: Vec<ProtectCamera>,
}

impl ProtectCatalog {
    /// Parse the JSON array returned by official `GET /v1/cameras`.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtectError> {
        let Value::Array(values) = parse_document(bytes)? else {
            return Err(ProtectError::InvalidShape);
        };
        if values.len() > MAX_PROTECT_CAMERAS {
            return Err(ProtectError::CameraLimit);
        }
        let mut ids = BTreeSet::new();
        let mut cameras = Vec::with_capacity(values.len());
        for value in values {
            let camera = ProtectCamera::from_value(value)?;
            if !ids.insert(camera.id.clone()) {
                return Err(ProtectError::DuplicateCamera);
            }
            cameras.push(camera);
        }
        Ok(Self { cameras })
    }

    /// Cameras in response order, including explicit disconnected/unknown states.
    #[must_use]
    pub fn cameras(&self) -> &[ProtectCamera] {
        &self.cameras
    }

    /// Exact, unambiguous camera lookup; no name matching or first-camera fallback.
    #[must_use]
    pub fn camera(&self, id: &str) -> Option<&ProtectCamera> {
        self.cameras.iter().find(|camera| camera.id == id)
    }
}

/// A quality's availability, preserving omitted versus explicitly disabled/null.
#[derive(Clone, Debug, PartialEq)]
pub enum StreamAvailability {
    /// The field was absent; no availability inference is possible.
    Missing,
    /// The field was null; no enabled URL was supplied.
    Disabled,
    /// A syntactically valid private URI; reachability/codec/TLS are not established.
    Available(StreamEndpoint),
}

/// Official stream response; known qualities are parsed and additive vendor fields retained.
#[derive(Clone, PartialEq)]
pub struct ProtectStreams {
    qualities: [StreamAvailability; 4],
    extensions: BTreeMap<String, Value>,
}

impl fmt::Debug for ProtectStreams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectStreams")
            .field("qualities", &self.qualities)
            .finish_non_exhaustive()
    }
}

impl ProtectStreams {
    /// Parse the nullable quality map returned by `GET /v1/cameras/{id}/rtsps-stream`.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtectError> {
        Self::from_value(parse_document(bytes)?)
    }

    fn from_value(value: Value) -> Result<Self, ProtectError> {
        let mut fields = object(value)?;
        let mut qualities = std::array::from_fn(|_| StreamAvailability::Missing);
        for quality in [
            ProtectQuality::High,
            ProtectQuality::Medium,
            ProtectQuality::Low,
            ProtectQuality::Package,
        ] {
            qualities[quality.index()] = match fields.remove(quality.as_str()) {
                None => StreamAvailability::Missing,
                Some(Value::Null) => StreamAvailability::Disabled,
                Some(Value::Text(uri)) => {
                    StreamAvailability::Available(StreamEndpoint::parse(&uri)?)
                }
                Some(_) => return Err(ProtectError::InvalidField(quality.as_str())),
            };
        }
        Ok(Self {
            qualities,
            extensions: fields,
        })
    }

    /// Availability for exactly one quality; this never falls back to another quality/view.
    #[must_use]
    pub fn availability(&self, quality: ProtectQuality) -> &StreamAvailability {
        &self.qualities[quality.index()]
    }

    /// Unknown/additive vendor fields retained privately for future interpretation.
    #[must_use]
    pub const fn extensions(&self) -> &BTreeMap<String, Value> {
        &self.extensions
    }

    /// Select a known view and exact quality. Exported connection state cannot prove live health.
    pub fn select(
        &self,
        camera: &ProtectCamera,
        quality: ProtectQuality,
    ) -> Result<&StreamEndpoint, ProtectError> {
        camera.view_identity(quality)?;
        match self.availability(quality) {
            StreamAvailability::Missing => Err(ProtectError::MissingStream(quality)),
            StreamAvailability::Disabled => Err(ProtectError::DisabledStream(quality)),
            StreamAvailability::Available(endpoint) => Ok(endpoint),
        }
    }
}

/// Explicit choice of URL source; no implicit RTSPS-to-RTSP rewrite exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportChoice {
    /// Use the exact URL in the official stream response, preserving its transport.
    Published,
    /// Use a separately operator-supplied plaintext RTSP URL for the exact quality/view.
    OperatorRtsp,
}

/// Private handoff of one camera and its stream response, plus optional explicit RTSP URLs.
#[derive(Clone, Debug, PartialEq)]
pub struct ProtectSource {
    camera: ProtectCamera,
    streams: ProtectStreams,
    rtsp: Option<ProtectStreams>,
}

impl ProtectSource {
    /// Parse `{ "camera": <details>, "streams": <quality map>, "rtsp": <optional map> }`.
    /// The wrapper is FSS-owned and rejects unknown keys; its vendor objects tolerate additions.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtectError> {
        let mut fields = object(parse_document(bytes)?)?;
        let camera = ProtectCamera::from_value(
            fields
                .remove("camera")
                .ok_or(ProtectError::MissingField("camera"))?,
        )?;
        let streams = ProtectStreams::from_value(
            fields
                .remove("streams")
                .ok_or(ProtectError::MissingField("streams"))?,
        )?;
        let rtsp = fields
            .remove("rtsp")
            .map(ProtectStreams::from_value)
            .transpose()?;
        if !fields.is_empty() {
            return Err(ProtectError::UnknownSourceField);
        }
        if let Some(overrides) = &rtsp {
            for availability in &overrides.qualities {
                if let StreamAvailability::Available(endpoint) = availability
                    && endpoint.requires_secure_transport()
                {
                    return Err(ProtectError::NonRtspOverride);
                }
            }
            // This operator-owned map has a fixed vocabulary, unlike vendor responses.
            if !overrides.extensions.is_empty() {
                return Err(ProtectError::UnknownSourceField);
            }
        }
        Ok(Self {
            camera,
            streams,
            rtsp,
        })
    }

    /// Private camera metadata with its explicit vendor-reported state/capabilities.
    #[must_use]
    pub const fn camera(&self) -> &ProtectCamera {
        &self.camera
    }

    /// Official reported qualities, without operator overrides.
    #[must_use]
    pub const fn streams(&self) -> &ProtectStreams {
        &self.streams
    }

    /// Select exactly the requested view, quality and transport source; no I/O or fallback.
    pub fn select(
        &self,
        quality: ProtectQuality,
        transport: TransportChoice,
    ) -> Result<SelectedStream<'_>, ProtectError> {
        let streams = match transport {
            TransportChoice::Published => &self.streams,
            TransportChoice::OperatorRtsp => self
                .rtsp
                .as_ref()
                .ok_or(ProtectError::MissingOperatorRtsp)?,
        };
        let endpoint = streams.select(&self.camera, quality)?;
        Ok(SelectedStream {
            camera: &self.camera,
            endpoint,
            quality,
        })
    }
}

/// Selected metadata and exact private endpoint; not a capture permission or health witness.
#[derive(Clone, Copy, Debug)]
pub struct SelectedStream<'a> {
    camera: &'a ProtectCamera,
    endpoint: &'a StreamEndpoint,
    quality: ProtectQuality,
}

impl<'a> SelectedStream<'a> {
    /// Camera from the same handoff as the stream.
    #[must_use]
    pub const fn camera(self) -> &'a ProtectCamera {
        self.camera
    }

    /// Exact private endpoint, without transport conversion.
    #[must_use]
    pub const fn endpoint(self) -> &'a StreamEndpoint {
        self.endpoint
    }

    /// Requested exact rendition quality.
    #[must_use]
    pub const fn quality(self) -> ProtectQuality {
        self.quality
    }

    /// Main or package view, kept independent from quality.
    #[must_use]
    pub const fn view(self) -> ProtectView {
        self.quality.view()
    }

    /// Camera/view pair within the caller's console identity.
    #[must_use]
    pub fn identity(self) -> CameraViewIdentity<'a> {
        CameraViewIdentity {
            camera_id: self.camera.id(),
            view: self.view(),
        }
    }
}

fn parse_document(bytes: &[u8]) -> Result<Value, ProtectError> {
    if bytes.len() > MAX_PROTECT_DOCUMENT_BYTES {
        return Err(ProtectError::InputLimit);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ProtectError::InvalidUtf8)?;
    json_input::parse(text).map_err(ProtectError::InvalidJson)
}

fn object(value: Value) -> Result<BTreeMap<String, Value>, ProtectError> {
    if let Value::Object(fields) = value {
        Ok(fields)
    } else {
        Err(ProtectError::InvalidShape)
    }
}

fn optional_text(
    fields: &BTreeMap<String, Value>,
    key: &'static str,
    limit: usize,
) -> Result<Option<String>, ProtectError> {
    match fields.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Text(text)) if text.len() <= limit && !text.chars().any(char::is_control) => {
            Ok(Some(text.clone()))
        }
        _ => Err(ProtectError::InvalidField(key)),
    }
}
