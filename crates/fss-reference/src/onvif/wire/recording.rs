#![forbid(unsafe_code)]
//! Bounded read-only recording inventory, advertised times and replay URI projection.
//!
//! Contracts: ONVIF ver10/recording.wsdl, ver10/search.wsdl, ver10/replay.wsdl and
//! ver10/schema/onvif.xsd. A track can contain disconnected slices: advertised extrema
//! never prove continuous retention or delivery. No search session, recording job,
//! configuration mutation or URI-lifetime assertion is introduced here.

use super::{
    OnvifOperation, SCHEMA_NS, SOAP_NS, ServiceVersion, SoapRequest, WireError, duration,
    escaped_reference, parse_metadata_utc_nanoseconds, reference, required, response, scalar,
    unique, uri_text, xml,
};
use fss_core::ContentDigest;
use std::fmt;

#[path = "recording/canonical.rs"]
mod canonical;
#[path = "recording/range.rs"]
mod range;
pub use range::{AdvertisedRecordingRange, RecordingCheckError, RecordingRangeAssessment};

/// Complete inventory ceiling; excess entries refuse instead of silently truncating.
pub const MAX_RECORDINGS: usize = 64;
/// Complete track ceiling for each recording, including non-video tracks.
pub const MAX_RECORDING_TRACKS: usize = 32;
/// Bounded descriptive text; descriptions are observations, never routing authority.
pub const MAX_RECORDING_DESCRIPTION_BYTES: usize = 512;
/// Bound for the entire canonical information projection in a protected handoff.
pub const MAX_RECORDING_INFORMATION_BYTES: usize = 64 * 1024;
/// Canonical information projection, including the digest of its exact SOAP body.
pub const RECORDING_INFORMATION_DOMAIN: &str = "fss.onvif_recording_information.v1";
/// Canonical service projection, including the complete GetServices body identity.
pub const RECORDING_SERVICES_DOMAIN: &str = "fss.onvif_recording_services.v1";
/// Recording-control namespace; only its read-only GetRecordings operation is admitted.
pub const RECORDING_NS: &str = "http://www.onvif.org/ver10/recording/wsdl";
/// Recording-search namespace; this subset creates no remote search session.
pub const SEARCH_NS: &str = "http://www.onvif.org/ver10/search/wsdl";
/// Replay-control namespace; no replay configuration is written.
pub const REPLAY_NS: &str = "http://www.onvif.org/ver10/replay/wsdl";

/// Advertised endpoint, pending the independent owner's origin/subtree check.
#[derive(Clone, Eq, PartialEq)]
pub struct RecordingService {
    /// Untrusted exact address; never log or use it as an authorization grant.
    pub xaddr: String,
    /// Service-reported version, not firmware identity or conformance.
    pub version: ServiceVersion,
}
impl fmt::Debug for RecordingService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingService")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// Exact namespace selection from one complete bounded GetServices response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingServices {
    /// Optional Recording service; absence is distinct from malformed discovery.
    pub recording: Option<RecordingService>,
    /// Optional Search service, required for selected recording information.
    pub search: Option<RecordingService>,
    /// Optional Replay service, required for URI acquisition.
    pub replay: Option<RecordingService>,
    /// Identity of all received SOAP bytes, including unprojected extensions.
    pub response_body_digest: ContentDigest,
}

/// Descriptive source advertisement. These strings do not select a local sensor or peer.
#[derive(Clone, Eq, PartialEq)]
pub struct RecordingSource {
    /// Opaque source URI, distinct from a local evidence identity.
    pub source_id: String,
    /// Bounded descriptive source name.
    pub name: String,
    /// Bounded vendor-described physical location.
    pub location: String,
    /// Bounded source description.
    pub description: String,
    /// Vendor-described source URI, never followed by this client.
    pub address: String,
    /// Optional exact source token, without inferred profile association.
    pub video_source_token: Option<String>,
}
impl fmt::Debug for RecordingSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordingSource([redacted])")
    }
}

/// Track type advertised by ONVIF, independent of codec and SDP track selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordingTrackType {
    /// A video track; its codec remains independently selected and checked.
    Video,
    /// An audio track, outside this replay capture slice.
    Audio,
    /// A metadata track, not a substitute for video source coverage.
    Metadata,
    /// ONVIF's explicit future-extension track category.
    Extended,
}
impl RecordingTrackType {
    /// Stable spelling used in bounded operator projections.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Video => "Video",
            Self::Audio => "Audio",
            Self::Metadata => "Metadata",
            Self::Extended => "Extended",
        }
    }
}

/// One exact configured track from GetRecordings.
#[derive(Clone, Eq, PartialEq)]
pub struct RecordingTrack {
    /// Exact device recording-track token.
    pub token: String,
    /// Advertised track family, without codec inference.
    pub kind: RecordingTrackType,
    /// Bounded descriptive text.
    pub description: String,
}
impl fmt::Debug for RecordingTrack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingTrack")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// One complete bounded recording configuration projection.
#[derive(Clone, Eq, PartialEq)]
pub struct RecordingItem {
    /// Exact token used only by an explicit subsequent selection.
    pub token: String,
    /// Descriptive source; no implicit sensor mapping.
    pub source: RecordingSource,
    /// Bounded recording description.
    pub content: String,
    /// Maximum-retention configuration, never evidence of actual availability.
    pub maximum_retention_time: String,
    /// All advertised tracks in response order; never auto-selected by name.
    pub tracks: Vec<RecordingTrack>,
}
impl fmt::Debug for RecordingItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingItem")
            .field("tracks", &self.tracks.len())
            .finish_non_exhaustive()
    }
}

/// Complete bounded inventory and the digest of the original response body.
#[derive(Clone, Eq, PartialEq)]
pub struct RecordingList {
    /// All recording entries, including entries with no video or no tracks.
    pub recordings: Vec<RecordingItem>,
    /// Identity of original SOAP bytes, including unprojected extensions.
    pub response_body_digest: ContentDigest,
}
impl fmt::Debug for RecordingList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingList")
            .field("recordings", &self.recordings.len())
            .finish()
    }
}

/// Configured track plus its vendor-advertised oldest/newest data coordinates.
#[derive(Clone, Eq, PartialEq)]
pub struct RecordingTrackInformation {
    /// Exact recording-track identity, not an SDP control URI.
    pub token: String,
    /// Track family; video codec is deliberately absent.
    pub kind: RecordingTrackType,
    /// Bounded descriptive text.
    pub description: String,
    /// Missing times stay unknown; gaps inside the extrema are unobservable here.
    pub range: AdvertisedRecordingRange,
}
impl fmt::Debug for RecordingTrackInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingTrackInformation")
            .field("kind", &self.kind)
            .field("range", &self.range)
            .finish_non_exhaustive()
    }
}

/// Device-reported recording state, never a local source-custody decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordingStatus {
    /// Recording exists but capture has not begun.
    Initiated,
    /// Device reports ongoing recording.
    Recording,
    /// Device reports stopped recording.
    Stopped,
    /// Device reports removal in progress.
    Removing,
    /// Device reports removed recording.
    Removed,
    /// Device explicitly reports unknown state.
    Unknown,
}
impl RecordingStatus {
    /// Stable spelling of the actual advertised enum value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initiated => "Initiated",
            Self::Recording => "Recording",
            Self::Stopped => "Stopped",
            Self::Removing => "Removing",
            Self::Removed => "Removed",
            Self::Unknown => "Unknown",
        }
    }
}

/// Selected information; canonical bytes bind projection and original body digest.
#[derive(Clone, Eq, PartialEq)]
pub struct RecordingInformation {
    /// Exact response token, required to match the caller's selection.
    pub token: String,
    /// Descriptive source advertisement, without routing or sensor authority.
    pub source: RecordingSource,
    /// Bounded recording description.
    pub content: String,
    /// Optional recording-wide extrema; not continuous coverage.
    pub range: AdvertisedRecordingRange,
    /// Complete bounded track information, preserving response order.
    pub tracks: Vec<RecordingTrackInformation>,
    /// Actual reported recording state.
    pub status: RecordingStatus,
    /// Identity of the complete SOAP body, including unprojected extensions.
    pub response_body_digest: ContentDigest,
}
impl fmt::Debug for RecordingInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingInformation")
            .field("tracks", &self.tracks.len())
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// GetReplayUri supplies no URI lifetime fields or stable-reuse guarantee.
#[derive(Clone, Eq, PartialEq)]
pub struct ReplayUri {
    /// Exact decoded URI, pending independent RTSP scope validation.
    pub uri: String,
    /// Original SOAP-body identity; a digest does not retain the body itself.
    pub response_body_digest: ContentDigest,
}
impl fmt::Debug for ReplayUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplayUri([redacted; lifetime unknown])")
    }
}

fn recording_request(operation: OnvifOperation, content: &str) -> SoapRequest {
    SoapRequest {
        action: operation.action(),
        username_token: false,
        body: format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"{SOAP_NS}\" xmlns:trc=\"{RECORDING_NS}\" xmlns:tse=\"{SEARCH_NS}\" xmlns:trp=\"{REPLAY_NS}\" xmlns:tt=\"{SCHEMA_NS}\"><s:Body>{content}</s:Body></s:Envelope>"
        ).into_bytes(),
    }
}

/// Enumerate recordings without creating jobs, recordings or search sessions.
#[must_use]
pub fn get_recordings_request() -> SoapRequest {
    recording_request(OnvifOperation::GetRecordings, "<trc:GetRecordings/>")
}

/// Read one explicitly selected recording token; escaped before network I/O.
pub fn get_recording_information_request(token: &str) -> Result<SoapRequest, WireError> {
    let token = escaped_reference(token)?;
    Ok(recording_request(
        OnvifOperation::GetRecordingInformation,
        &format!(
            "<tse:GetRecordingInformation><tse:RecordingToken>{token}</tse:RecordingToken></tse:GetRecordingInformation>"
        ),
    ))
}

/// Request unicast RTSP/TCP replay for an exact token; playback is not started.
pub fn get_replay_uri_request(token: &str) -> Result<SoapRequest, WireError> {
    let token = escaped_reference(token)?;
    Ok(recording_request(
        OnvifOperation::GetReplayUri,
        &format!(
            "<trp:GetReplayUri><trp:StreamSetup><tt:Stream>RTP_unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trp:StreamSetup><trp:RecordingToken>{token}</trp:RecordingToken></trp:GetReplayUri>"
        ),
    ))
}

/// Select Recording/Search/Replay only after validating the entire bounded service inventory.
pub fn parse_recording_services(bytes: &[u8]) -> Result<RecordingServices, WireError> {
    let services = super::media2::parse_services(bytes)?;
    let mut result = RecordingServices {
        recording: None,
        search: None,
        replay: None,
        response_body_digest: ContentDigest::sha256(bytes),
    };
    for service in services {
        let selected = match service.namespace.as_str() {
            RECORDING_NS => &mut result.recording,
            SEARCH_NS => &mut result.search,
            REPLAY_NS => &mut result.replay,
            _ => continue,
        };
        *selected = Some(RecordingService {
            xaddr: service.xaddr,
            version: service.version,
        });
    }
    Ok(result)
}

fn text(doc: &xml::Document, parent: usize, local: &str) -> Result<String, WireError> {
    let value = scalar(doc, required(doc, parent, SCHEMA_NS, local)?)?;
    validate_text(value)?;
    Ok(value.to_owned())
}
fn validate_text(value: &str) -> Result<(), WireError> {
    if value.len() > MAX_RECORDING_DESCRIPTION_BYTES
        || value.chars().any(|c| c.is_control() || !xml::valid_char(c))
    {
        return Err(WireError::InvalidField);
    }
    Ok(())
}
fn token(doc: &xml::Document, parent: usize, local: &str) -> Result<String, WireError> {
    let value = doc.leaf_text(required(doc, parent, SCHEMA_NS, local)?)?;
    reference(value)?;
    Ok(value.to_owned())
}
fn source(doc: &xml::Document, parent: usize) -> Result<RecordingSource, WireError> {
    let source = required(doc, parent, SCHEMA_NS, "Source")?;
    Ok(RecordingSource {
        source_id: uri_text(doc, required(doc, source, SCHEMA_NS, "SourceId")?)?.to_owned(),
        name: text(doc, source, "Name")?,
        location: text(doc, source, "Location")?,
        description: text(doc, source, "Description")?,
        address: uri_text(doc, required(doc, source, SCHEMA_NS, "Address")?)?.to_owned(),
        video_source_token: unique(doc, source, SCHEMA_NS, "VideoSourceToken")?
            .map(|id| {
                let value = doc.leaf_text(id)?;
                reference(value)?;
                Ok(value.to_owned())
            })
            .transpose()?,
    })
}
fn track_type(value: &str) -> Result<RecordingTrackType, WireError> {
    match value {
        "Video" => Ok(RecordingTrackType::Video),
        "Audio" => Ok(RecordingTrackType::Audio),
        "Metadata" => Ok(RecordingTrackType::Metadata),
        "Extended" => Ok(RecordingTrackType::Extended),
        _ => Err(WireError::InvalidField),
    }
}
fn status(value: &str) -> Result<RecordingStatus, WireError> {
    match value {
        "Initiated" => Ok(RecordingStatus::Initiated),
        "Recording" => Ok(RecordingStatus::Recording),
        "Stopped" => Ok(RecordingStatus::Stopped),
        "Removing" => Ok(RecordingStatus::Removing),
        "Removed" => Ok(RecordingStatus::Removed),
        "Unknown" => Ok(RecordingStatus::Unknown),
        _ => Err(WireError::InvalidField),
    }
}
fn advertised_range(
    doc: &xml::Document,
    parent: usize,
    first: &str,
    last: &str,
) -> Result<AdvertisedRecordingRange, WireError> {
    let read = |name| {
        unique(doc, parent, SCHEMA_NS, name)?
            .map(|id| parse_metadata_utc_nanoseconds(scalar(doc, id)?))
            .transpose()
    };
    Ok(AdvertisedRecordingRange {
        earliest_ns: read(first)?,
        latest_ns: read(last)?,
    })
}

/// Complete recording/track inventory. Empty is a valid observed inventory.
pub fn parse_recordings(bytes: &[u8]) -> Result<RecordingList, WireError> {
    let (doc, root) = response(bytes, RECORDING_NS, "GetRecordingsResponse")?;
    let mut recordings: Vec<RecordingItem> = Vec::new();
    for id in doc.child_ids(root) {
        if !doc.named(id, RECORDING_NS, "RecordingItem") {
            return Err(WireError::UnexpectedResponse);
        }
        if recordings.len() == MAX_RECORDINGS {
            return Err(WireError::RecordingLimitExceeded);
        }
        let recording_token = token(&doc, id, "RecordingToken")?;
        if recordings.iter().any(|item| item.token == recording_token) {
            return Err(WireError::DuplicateField);
        }
        let config = required(&doc, id, SCHEMA_NS, "Configuration")?;
        let retention = scalar(
            &doc,
            required(&doc, config, SCHEMA_NS, "MaximumRetentionTime")?,
        )?;
        duration(retention)?;
        let mut tracks: Vec<RecordingTrack> = Vec::new();
        let list = required(&doc, id, SCHEMA_NS, "Tracks")?;
        for track in doc.child_ids(list) {
            if !doc.named(track, SCHEMA_NS, "Track") {
                return Err(WireError::UnexpectedResponse);
            }
            if tracks.len() == MAX_RECORDING_TRACKS {
                return Err(WireError::RecordingLimitExceeded);
            }
            let track_token = token(&doc, track, "TrackToken")?;
            if tracks.iter().any(|item| item.token == track_token) {
                return Err(WireError::DuplicateField);
            }
            let config = required(&doc, track, SCHEMA_NS, "Configuration")?;
            tracks.push(RecordingTrack {
                token: track_token,
                kind: track_type(scalar(
                    &doc,
                    required(&doc, config, SCHEMA_NS, "TrackType")?,
                )?)?,
                description: text(&doc, config, "Description")?,
            });
        }
        recordings.push(RecordingItem {
            token: recording_token,
            source: source(&doc, config)?,
            content: text(&doc, config, "Content")?,
            maximum_retention_time: retention.to_owned(),
            tracks,
        });
    }
    Ok(RecordingList {
        recordings,
        response_body_digest: ContentDigest::sha256(bytes),
    })
}

/// Read selected information. Missing dates stay unknown; contradictions remain represented
/// and fail range validation instead of being normalized or clipped.
pub fn parse_recording_information(bytes: &[u8]) -> Result<RecordingInformation, WireError> {
    let (doc, root) = response(bytes, SEARCH_NS, "GetRecordingInformationResponse")?;
    let info = required(&doc, root, SEARCH_NS, "RecordingInformation")?;
    if doc.child_ids(root).any(|id| id != info) {
        return Err(WireError::UnexpectedResponse);
    }
    let mut tracks: Vec<RecordingTrackInformation> = Vec::new();
    for track in doc.children(info, SCHEMA_NS, "Track") {
        if tracks.len() == MAX_RECORDING_TRACKS {
            return Err(WireError::RecordingLimitExceeded);
        }
        let token = token(&doc, track, "TrackToken")?;
        if tracks.iter().any(|item| item.token == token) {
            return Err(WireError::DuplicateField);
        }
        tracks.push(RecordingTrackInformation {
            token,
            kind: track_type(scalar(
                &doc,
                required(&doc, track, SCHEMA_NS, "TrackType")?,
            )?)?,
            description: text(&doc, track, "Description")?,
            range: advertised_range(&doc, track, "DataFrom", "DataTo")?,
        });
    }
    let result = RecordingInformation {
        token: token(&doc, info, "RecordingToken")?,
        source: source(&doc, info)?,
        content: text(&doc, info, "Content")?,
        range: advertised_range(&doc, info, "EarliestRecording", "LatestRecording")?,
        tracks,
        status: status(scalar(
            &doc,
            required(&doc, info, SCHEMA_NS, "RecordingStatus")?,
        )?)?,
        response_body_digest: ContentDigest::sha256(bytes),
    };
    result.canonical_bytes()?;
    Ok(result)
}

/// Exact URI-only response. Media1 lifetime flags cannot supply a fabricated validity basis.
pub fn parse_replay_uri(bytes: &[u8]) -> Result<ReplayUri, WireError> {
    let (doc, root) = response(bytes, REPLAY_NS, "GetReplayUriResponse")?;
    let uri = required(&doc, root, REPLAY_NS, "Uri")?;
    if doc.child_ids(root).any(|id| id != uri) {
        return Err(WireError::UnexpectedResponse);
    }
    Ok(ReplayUri {
        uri: uri_text(&doc, uri)?.to_owned(),
        response_body_digest: ContentDigest::sha256(bytes),
    })
}
