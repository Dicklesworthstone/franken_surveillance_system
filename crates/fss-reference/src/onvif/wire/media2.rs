#![forbid(unsafe_code)]
//! Read-only Media2 projection, sharing the bounded SOAP/XML owner with Media1.
//! Media2's URI stability comes from its protocol contract, not fabricated
//! Media1 `InvalidAfterConnect`, `InvalidAfterReboot`, or `Timeout` observations.

use std::fmt;

use super::{
    DEVICE_NS, MAX_MEDIA_PROFILES, MAX_REFERENCE_CHARS, MEDIA2_NS, MediaProfile, OnvifOperation,
    SCHEMA_NS, SOAP_NS, SoapRequest, VideoEncoder, VideoEncoding, WireError, dimension,
    escaped_reference, parse_boolean, reference, request, required, response, scalar, unique,
    uri_text, xml,
};

/// Maximum complete device-service inventory checked before choosing Media2.
pub const MAX_ONVIF_SERVICES: usize = 64;

/// Bounded nonnegative version reported by a service; not a conformance identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceVersion {
    /// Service version's reported major component.
    pub major: u16,
    /// Service version's reported minor component, without reinterpretation.
    pub minor: u16,
}

/// Exact Media2 advertisement from GetServices, with no implied route authority.
#[derive(Clone, Eq, PartialEq)]
pub struct Media2Service {
    /// Untrusted service address, to be checked against the independently approved scope.
    pub xaddr: String,
    /// Reported service version, not the device firmware or Profile T qualification.
    pub version: ServiceVersion,
}

impl fmt::Debug for Media2Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Media2Service")
            .field("xaddr", &"[redacted]")
            .field("version", &self.version)
            .finish()
    }
}

/// The Media2 response reports only a URI. Its indefinitely reusable lifetime
/// is the Media2 service contract, independent of the observed Media1 flags.
#[derive(Clone, Eq, PartialEq)]
pub struct Media2StreamUri {
    /// Exact decoded URI; caller must validate network and credential scope.
    pub uri: String,
}

impl fmt::Debug for Media2StreamUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Media2StreamUri([redacted])")
    }
}

/// Enumerate services without obtaining or interpreting untyped capabilities.
#[must_use]
pub fn get_services_request() -> SoapRequest {
    request(
        OnvifOperation::GetServices,
        "<tds:GetServices><tds:IncludeCapability>false</tds:IncludeCapability></tds:GetServices>",
    )
}

fn media2_request(operation: OnvifOperation, content: &str) -> SoapRequest {
    SoapRequest {
        action: operation.action(),
        username_token: false,
        body: format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"{SOAP_NS}\" xmlns:tr2=\"{MEDIA2_NS}\" xmlns:tt=\"{SCHEMA_NS}\"><s:Body>{content}</s:Body></s:Envelope>"
        )
        .into_bytes(),
    }
}

/// Request every existing profile with its video encoder configuration. Omitting
/// Type would request no configuration information in Media2, hiding the codec.
#[must_use]
pub fn get_media2_profiles_request() -> SoapRequest {
    media2_request(
        OnvifOperation::GetMedia2Profiles,
        "<tr2:GetProfiles><tr2:Type>VideoEncoder</tr2:Type></tr2:GetProfiles>",
    )
}

/// Select an existing profile using Media2's RTSP (RTP over TCP) transport enum.
/// Token escaping is identical to the Media1 boundary; no profile is created.
pub fn get_media2_stream_uri_request(profile_token: &str) -> Result<SoapRequest, WireError> {
    let token = escaped_reference(profile_token)?;
    Ok(media2_request(
        OnvifOperation::GetMedia2StreamUri,
        &format!(
            "<tr2:GetStreamUri><tr2:Protocol>RTSP</tr2:Protocol><tr2:ProfileToken>{token}</tr2:ProfileToken></tr2:GetStreamUri>"
        ),
    ))
}

/// Check a complete bounded service inventory and select only the exact Media2
/// namespace. Duplicate namespaces are ambiguous and refuse the entire response.
/// No match in a valid inventory is explicit `None`; an empty/malformed response
/// cannot be converted into an unsupported-service absence claim.
pub fn parse_media2_service(bytes: &[u8]) -> Result<Option<Media2Service>, WireError> {
    let (doc, root) = response(bytes, DEVICE_NS, "GetServicesResponse")?;
    let mut namespaces = Vec::new();
    let mut media2 = None;
    for id in doc.child_ids(root) {
        if !doc.named(id, DEVICE_NS, "Service") {
            return Err(WireError::UnexpectedResponse);
        }
        if namespaces.len() == MAX_ONVIF_SERVICES {
            return Err(WireError::ServiceLimitExceeded);
        }
        let namespace = uri_text(&doc, required(&doc, id, DEVICE_NS, "Namespace")?)?;
        if namespaces.contains(&namespace) {
            return Err(WireError::DuplicateField);
        }
        namespaces.push(namespace);
        let xaddr = uri_text(&doc, required(&doc, id, DEVICE_NS, "XAddr")?)?;
        let version = required(&doc, id, DEVICE_NS, "Version")?;
        let major = version_component(&doc, required(&doc, version, SCHEMA_NS, "Major")?)?;
        let minor = version_component(&doc, required(&doc, version, SCHEMA_NS, "Minor")?)?;
        // Capabilities are unrequested and never confer an interpretation or grant.
        // Check their cardinality even if a device includes this optional field.
        unique(&doc, id, DEVICE_NS, "Capabilities")?;
        if namespace == MEDIA2_NS {
            media2 = Some(Media2Service {
                xaddr: xaddr.to_owned(),
                version: ServiceVersion { major, minor },
            });
        }
    }
    if namespaces.is_empty() {
        return Err(WireError::MissingField);
    }
    Ok(media2)
}

fn version_component(doc: &xml::Document, id: usize) -> Result<u16, WireError> {
    let text = scalar(doc, id)?;
    let text = text.strip_prefix('+').unwrap_or(text);
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WireError::InvalidField);
    }
    text.parse().map_err(|_| WireError::InvalidField)
}

/// Parse Media2's own profile shape, including Configurations/VideoEncoder.
/// A missing video encoder remains `None`; an unsupported advertised codec remains
/// `Unsupported`. Neither can be inferred from a profile name or stream URI.
pub fn parse_media2_profiles(bytes: &[u8]) -> Result<Vec<MediaProfile>, WireError> {
    let (doc, root) = response(bytes, MEDIA2_NS, "GetProfilesResponse")?;
    let mut profiles: Vec<MediaProfile> = Vec::new();
    for id in doc.child_ids(root) {
        if !doc.named(id, MEDIA2_NS, "Profiles") {
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
        let name = doc.leaf_text(required(&doc, id, MEDIA2_NS, "Name")?)?;
        if name.chars().count() > MAX_REFERENCE_CHARS || name.chars().any(char::is_control) {
            return Err(WireError::InvalidField);
        }
        if let Some(fixed) = doc.attribute(id, "", "fixed") {
            parse_boolean(fixed)?;
        }
        let video = unique(&doc, id, MEDIA2_NS, "Configurations")?
            .map(|configs| {
                unique(&doc, configs, MEDIA2_NS, "VideoEncoder")?
                    .map(|encoder| video_encoder(&doc, encoder))
                    .transpose()
            })
            .transpose()?
            .flatten();
        profiles.push(MediaProfile {
            token: token.to_owned(),
            name: name.to_owned(),
            video,
        });
    }
    Ok(profiles)
}

fn video_encoder(doc: &xml::Document, encoder: usize) -> Result<VideoEncoder, WireError> {
    let encoding = match scalar(doc, required(doc, encoder, SCHEMA_NS, "Encoding")?)? {
        "H264" => VideoEncoding::H264,
        "H265" => VideoEncoding::H265,
        "JPEG" => VideoEncoding::Jpeg,
        "MPV4-ES" => VideoEncoding::Mpeg4,
        value if value.is_empty() || value.len() > 64 => return Err(WireError::InvalidField),
        _ => VideoEncoding::Unsupported,
    };
    let resolution = required(doc, encoder, SCHEMA_NS, "Resolution")?;
    let width = dimension(doc, required(doc, resolution, SCHEMA_NS, "Width")?)?;
    let height = dimension(doc, required(doc, resolution, SCHEMA_NS, "Height")?)?;
    Ok(VideoEncoder {
        encoding,
        width,
        height,
    })
}

/// Parse the exact Media2 Uri response. Media1 lifetime fields are not part of
/// this response contract and are never accepted as a substitute or defaulted.
pub fn parse_media2_stream_uri(bytes: &[u8]) -> Result<Media2StreamUri, WireError> {
    let (doc, root) = response(bytes, MEDIA2_NS, "GetStreamUriResponse")?;
    let uri = required(&doc, root, MEDIA2_NS, "Uri")?;
    if doc.child_ids(root).any(|id| id != uri) {
        return Err(WireError::UnexpectedResponse);
    }
    Ok(Media2StreamUri {
        uri: uri_text(&doc, uri)?.to_owned(),
    })
}
