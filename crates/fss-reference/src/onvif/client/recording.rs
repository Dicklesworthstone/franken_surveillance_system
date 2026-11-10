#![forbid(unsafe_code)]
//! Finite read-only recording discovery through the existing HTTP/auth/session owner.
//!
//! Inventory is GetServices -> GetRecordings. Explicit selection is GetServices ->
//! GetRecordingInformation -> GetReplayUri. No FindRecordings session, automatic token choice,
//! configuration write, retry beyond one Digest challenge, or RTSP acquisition occurs here.

use std::fmt;
use std::net::SocketAddr;

use fss_core::ContentDigest;

use super::{
    ClientConfig, ClientError, HttpOperation, HttpRoute, OnvifContext, SessionBudget, exchange,
    media_route, soap_body, start_session, validate_config, validate_stream_uri,
    wsse_checkpoint_error,
};
use crate::onvif::wire::{
    self, RecordingCheckError, RecordingInformation, RecordingItem, RecordingRangeAssessment,
    RecordingServices,
};
use crate::rtsp::client::replay::ReplayWindow;

/// Complete bounded inventory; source/recording names are private metadata, not diagnostics.
pub struct RecordingInventory {
    /// Exact selected namespaces and original GetServices body identity.
    pub services: RecordingServices,
    /// Every advertised recording configuration, including non-video recordings.
    pub recordings: Vec<RecordingItem>,
    /// Original GetRecordings SOAP body identity, including discarded extensions.
    pub response_body_digest: ContentDigest,
    /// Actual HTTP attempts including the bounded authentication retry.
    pub exchanges: u32,
}
impl fmt::Debug for RecordingInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingInventory")
            .field("recordings", &self.recordings.len())
            .field("exchanges", &self.exchanges).finish_non_exhaustive()
    }
}

/// A scoped URI and exact device observation, ready for a separately approved private handoff.
/// No URI stability, recorder coverage, source custody, or Profile G conformance is asserted.
pub struct RecordingReplay {
    /// Exact observed service advertisements and their original body identity.
    pub services: RecordingServices,
    /// Bounded information for exactly the selected recording token.
    pub information: RecordingInformation,
    /// Exact RTSP URI after independent authority validation; lifetime is unknown.
    pub uri: String,
    /// Original GetReplayUri SOAP body identity.
    pub uri_response_digest: ContentDigest,
    /// Independently approved literal RTSP destination.
    pub peer: SocketAddr,
    /// Independently approved exact RTSP authority spelling.
    pub authority: String,
    /// Actual HTTP attempts, including authentication retries.
    pub exchanges: u32,
}
impl fmt::Debug for RecordingReplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingReplay").field("exchanges", &self.exchanges).finish_non_exhaustive()
    }
}

impl RecordingInformation {
    /// Compare the exact native closed replay request without changing either endpoint.
    /// Successful comparison remains an advertised-extrema observation, never continuous coverage.
    pub fn validate_requested_window(&self, window: ReplayWindow) -> Result<RecordingRangeAssessment, RecordingCheckError> {
        let start = i128::try_from(window.start().unix_nanoseconds())
            .map_err(|_| RecordingCheckError::InvalidRequestedBounds)?;
        let end = i128::try_from(window.end().unix_nanoseconds())
            .map_err(|_| RecordingCheckError::InvalidRequestedBounds)?;
        self.validate_requested_bounds(start, end)
    }
}

fn discover(config: &ClientConfig, cx: &impl OnvifContext, budget: &mut SessionBudget) -> Result<RecordingServices, ClientError> {
    let response = exchange(config, &config.device, &wire::get_services_request(), cx, budget)?;
    Ok(wire::parse_recording_services(soap_body(&response)?)?)
}

fn release(config: &ClientConfig, route: &HttpRoute, cx: &impl OnvifContext, budget: &mut SessionBudget) -> Result<(), ClientError> {
    let now = budget.now(config, cx)?;
    cx.checkpoint(route, HttpOperation::Release, now, config.deadline_ns).map_err(wsse_checkpoint_error)
}

/// Inventory existing recordings with at most two logical operations. Media version is
/// irrelevant only in this explicitly selected recording lane; the live-media API is unchanged.
pub fn inventory(config: &ClientConfig, cx: &impl OnvifContext) -> Result<RecordingInventory, ClientError> {
    validate_config(config, None)?;
    let mut budget = start_session(config, cx)?;
    let services = discover(config, cx, &mut budget)?;
    let recording = services.recording.as_ref().ok_or(ClientError::Unsupported)?;
    let route = media_route(config, &recording.xaddr)?;
    let response = exchange(config, &route, &wire::get_recordings_request(), cx, &mut budget)?;
    let list = wire::parse_recordings(soap_body(&response)?)?;
    release(config, &config.device, cx, &mut budget)?;
    release(config, &route, cx, &mut budget)?;
    Ok(RecordingInventory {
        services, recordings: list.recordings,
        response_body_digest: list.response_body_digest, exchanges: budget.exchanges,
    })
}

/// Resolve one exact recording and one unchanged closed request. Bad tokens fail before I/O;
/// ambiguous/contradictory/outside-range observations fail before acquiring a replay URI.
/// Unknown extrema remain explicit in the information record and never cause clipping.
pub fn select(config: &ClientConfig, recording_token: &str, window: ReplayWindow, cx: &impl OnvifContext) -> Result<RecordingReplay, ClientError> {
    validate_config(config, Some(recording_token))?;
    let information_request = wire::get_recording_information_request(recording_token)?;
    let uri_request = wire::get_replay_uri_request(recording_token)?;
    let mut budget = start_session(config, cx)?;
    let services = discover(config, cx, &mut budget)?;
    let search = services.search.as_ref().ok_or(ClientError::Unsupported)?;
    let replay = services.replay.as_ref().ok_or(ClientError::Unsupported)?;
    // Validate both advertised destinations before a follow-up or credential callback.
    let search_route = media_route(config, &search.xaddr)?;
    let replay_route = media_route(config, &replay.xaddr)?;
    let response = exchange(config, &search_route, &information_request, cx, &mut budget)?;
    let information = wire::parse_recording_information(soap_body(&response)?)?;
    if information.token != recording_token {
        return Err(RecordingCheckError::TokenMismatch.into());
    }
    information.validate_requested_window(window)?;
    let response = exchange(config, &replay_route, &uri_request, cx, &mut budget)?;
    let uri = wire::parse_replay_uri(soap_body(&response)?)?;
    let scope = config.rtsp.as_ref().ok_or(ClientError::Scope)?;
    validate_stream_uri(&uri.uri, scope)?;
    for route in [&config.device, &search_route, &replay_route] {
        release(config, route, cx, &mut budget)?;
    }
    Ok(RecordingReplay {
        services, information, uri: uri.uri, uri_response_digest: uri.response_body_digest,
        peer: scope.peer, authority: scope.authority.clone(), exchanges: budget.exchanges,
    })
}
