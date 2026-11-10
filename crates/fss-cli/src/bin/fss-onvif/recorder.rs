#![forbid(unsafe_code)]
//! Explicit historical-recording operations over the existing scoped SOAP owner.

use std::collections::BTreeMap;

use fss_cli::agent_json::{array, object, string};
use fss_cli::onvif_replay_plan::ReplayHandoff;
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_reference::onvif::client::{ClientConfig, ClientError, OnvifContext, recording};
use fss_reference::onvif::http::HttpRoute;
use fss_reference::onvif::wire::{self, SoapRequest};
use fss_reference::rtsp::client::replay::ReplayWindow;
use fss_reference::rtsp::recording_replay::ReplayCodec;

use super::plan::{OnvifAuthPlan, Plan};

const ARGUMENT: &str = "ERR-ONVIF-ARGUMENT-001";
pub(super) const HTTP_POLICY: &str = "read-only-recording-inventory-and-exact-replay:\
same-pinned-http-origin:explicit-service-subtree:bounded-complete-getservices-getrecordings:\
exact-getrecordinginformation-getreplayuri:single-video-track:known-bounds-never-clipped:\
one-scoped-digest-retry:no-basic-no-wsse-no-tls:private-create-only-metadata:\
independently-pinned-rtsp:explicit-native-avc-hevc:unknown-uri-lifetime:\
no-remote-search-session-no-capture-authority-no-retention-or-capture-time-claim:v1";
pub(super) const USERNAME_TOKEN_POLICY: &str = "read-only-recording-inventory-and-exact-replay:\
same-pinned-http-origin:explicit-service-subtree:bounded-complete-getservices-getrecordings:\
exact-getrecordinginformation-getreplayuri:single-video-track:known-bounds-never-clipped:\
username-token-passworddigest-sha1:one-unsigned-getsystemdatetime:\
camera-utc-plus-owned-monotonic:token-freshness-only:fresh-128bit-nonce-per-request:\
no-http-auth-fallback-no-basic-no-tls:private-create-only-metadata:\
independently-pinned-rtsp:explicit-native-avc-hevc:unknown-uri-lifetime:\
no-remote-search-session-no-capture-authority-no-retention-or-capture-time-claim:v1";

pub(super) enum RecorderRequest {
    Inventory,
    Replay {
        token: String,
        window: ReplayWindow,
        codec: ReplayCodec,
    },
}

impl RecorderRequest {
    pub(super) fn parse(
        command: Option<&str>,
        values: &BTreeMap<&str, &str>,
    ) -> Result<Option<Self>, &'static str> {
        const REPLAY: &[&str] = &["--recording-token", "--replay-start", "--replay-end", "--codec"];
        let Some(command) = command else {
            if REPLAY.iter().any(|key| values.contains_key(key)) {
                return Err(ARGUMENT);
            }
            return Ok(None);
        };
        if values.contains_key("--profile") || values.contains_key("--media-version") {
            return Err(ARGUMENT);
        }
        match command {
            "recordings" => {
                if REPLAY.iter().any(|key| values.contains_key(key))
                    || values.contains_key("--rtsp-peer")
                    || values.contains_key("--rtsp-authority")
                {
                    return Err(ARGUMENT);
                }
                Ok(Some(Self::Inventory))
            }
            "replay" => {
                let required = |key| values.get(key).copied().ok_or(ARGUMENT);
                let token = required("--recording-token")?.to_owned();
                wire::recording::get_recording_information_request(&token).map_err(|_| ARGUMENT)?;
                let window = ReplayWindow::from_timestamps(
                    required("--replay-start")?,
                    required("--replay-end")?,
                ).map_err(|_| ARGUMENT)?;
                let codec = match required("--codec")? {
                    "avc" => ReplayCodec::Avc,
                    "hevc" => ReplayCodec::Hevc,
                    _ => return Err(ARGUMENT),
                };
                Ok(Some(Self::Replay { token, window, codec }))
            }
            _ => Err(ARGUMENT),
        }
    }

    pub(super) fn is_replay(&self) -> bool {
        matches!(self, Self::Replay { .. })
    }

    pub(super) fn operation(&self) -> &'static str {
        match self {
            Self::Inventory => "recordings",
            Self::Replay { .. } => "replay",
        }
    }

    pub(super) fn encode(&self, out: &mut CanonicalEncoder) {
        match self {
            Self::Inventory => out.u8(0),
            Self::Replay { token, window, codec } => {
                out.u8(1);
                out.text(token);
                out.text(&window.to_string());
                out.text(codec.as_str());
            }
        }
    }

    /// A scoped secret owner never becomes a signer for arbitrary SOAP bodies.
    pub(super) fn username_request_matches(
        &self,
        device_path: &str,
        route: &HttpRoute,
        request: &SoapRequest,
    ) -> bool {
        if request == &wire::get_services_request() {
            return route.target() == device_path;
        }
        match self {
            Self::Inventory => request == &wire::recording::get_recordings_request(),
            Self::Replay { token, .. } => [
                wire::recording::get_recording_information_request(token),
                wire::recording::get_replay_uri_request(token),
            ].into_iter().any(|expected| expected.is_ok_and(|expected| request == &expected)),
        }
    }

    fn selection_json(&self) -> String {
        match self {
            Self::Inventory => "null".into(),
            Self::Replay { token, window, codec } => object(&[
                ("recording_token_digest", string(&ContentDigest::sha256(token.as_bytes()).to_text())),
                ("requested_range", string(&window.to_string())),
                ("codec", string(codec.as_str())),
                ("recording_availability", string("not_observed")),
                ("uri_lifetime", string("unknown")),
            ]),
        }
    }
}

pub(super) fn preview(plan: &Plan) -> Result<String, &'static str> {
    let request = plan.recording.as_ref().ok_or(ARGUMENT)?;
    Ok(object(&[
        ("schema", string(plan.schema())),
        ("phase", string("planned")),
        ("operation", string(request.operation())),
        ("approval", string(&plan.digest()?.to_text())),
        ("policy", string(plan.policy())),
        ("peer", string(&plan.peer.to_string())),
        ("authority", string(&plan.authority)),
        ("device_path", string(&plan.device_path)),
        ("service_root", string(&plan.service_root)),
        ("generation", plan.generation.to_string()),
        ("output", string(plan.output.to_str().ok_or(ARGUMENT)?)),
        ("selection", request.selection_json()),
        ("rtsp_peer", plan.rtsp.as_ref().map_or_else(|| "null".into(), |s| string(&s.peer.to_string()))),
        ("rtsp_authority", plan.rtsp.as_ref().map_or_else(|| "null".into(), |s| string(&s.authority))),
        ("authentication", plan.auth.as_ref().map_or_else(|| string("challenge-refused"), OnvifAuthPlan::preview)),
        ("timeout_ns", plan.timeout_ns.to_string()),
        ("max_steps", plan.max_steps.to_string()),
        ("max_response_bytes", plan.limits.body_bytes.to_string()),
        ("max_http_exchanges", plan.max_http_exchanges().to_string()),
        ("credentials_read", "false".into()),
        ("device_contacted", "false".into()),
        ("capture_authorized", "false".into()),
        ("profile_g_conformance", string("not-established")),
        ("effects", string("none-until-exact-approval")),
    ]) + "\n")
}

pub(super) struct RecorderObservation {
    pub(super) bytes: String,
    operation: &'static str,
    recordings: usize,
    tracks: usize,
    exchanges: u32,
    selection: Option<String>,
}

impl RecorderObservation {
    pub(super) fn result(&self, approval: ContentDigest, file_digest: ContentDigest) -> String {
        object(&[
            ("schema", string("fss.onvif_recording_operator_result.v1")),
            ("phase", string("completed")),
            ("operation", string(self.operation)),
            ("approval", string(&approval.to_text())),
            ("output_digest", string(&file_digest.to_text())),
            ("output_bytes", self.bytes.len().to_string()),
            ("recordings", self.recordings.to_string()),
            ("tracks", self.tracks.to_string()),
            ("http_exchanges", self.exchanges.to_string()),
            ("handoff_ready", self.selection.is_some().to_string()),
            ("selection", self.selection.clone().unwrap_or_else(|| "null".into())),
            ("native_resources_quiescent", "true".into()),
            ("capture_authorized", "false".into()),
            ("source_evidence", "false".into()),
            ("continuous_coverage_verified", "false".into()),
            ("profile_g_conformance", string("not-established")),
        ]) + "\n"
    }
}

fn source_json(source: &wire::RecordingSource) -> String {
    object(&[
        ("source_id", string(&source.source_id)),
        ("name", string(&source.name)),
        ("location", string(&source.location)),
        ("description", string(&source.description)),
        ("address", string(&source.address)),
        ("video_source_token", source.video_source_token.as_deref().map_or_else(|| "null".into(), string)),
    ])
}

fn service_json(service: Option<&wire::RecordingService>) -> String {
    service.map_or_else(|| "null".into(), |service| object(&[
        ("xaddr", string(&service.xaddr)),
        ("major", service.version.major.to_string()),
        ("minor", service.version.minor.to_string()),
    ]))
}

fn inventory_json(report: &recording::RecordingInventory, approval: ContentDigest) -> Result<String, &'static str> {
    let services = &report.services;
    let recordings: Vec<_> = report.recordings.iter().map(|recording| {
        let tracks: Vec<_> = recording.tracks.iter().map(|track| object(&[
            ("token", string(&track.token)),
            ("type", string(track.kind.as_str())),
            ("description", string(&track.description)),
        ])).collect();
        object(&[
            ("token", string(&recording.token)),
            ("token_digest", string(&ContentDigest::sha256(recording.token.as_bytes()).to_text())),
            ("source", source_json(&recording.source)),
            ("content", string(&recording.content)),
            ("maximum_retention_time", string(&recording.maximum_retention_time)),
            ("tracks", array(&tracks)),
            ("advertisement_basis", string("device-configuration-observation")),
            ("retained_media_verified", "false".into()),
        ])
    }).collect();
    Ok(object(&[
        ("schema", string("fss.onvif_recording_inventory.v1")),
        ("onboarding_plan", string(&approval.to_text())),
        ("services", object(&[
            ("recording", service_json(services.recording.as_ref())),
            ("search", service_json(services.search.as_ref())),
            ("replay", service_json(services.replay.as_ref())),
            ("observation_digest", string(&services.digest().map_err(|error| ClientError::Wire(error).code())?.to_text())),
            ("response_body_digest", string(&services.response_body_digest.to_text())),
        ])),
        ("response_body_digest", string(&report.response_body_digest.to_text())),
        ("recordings", array(&recordings)),
        ("capture_authorized", "false".into()),
        ("source_evidence", "false".into()),
        ("continuous_coverage_verified", "false".into()),
        ("profile_g_conformance", string("not-established")),
    ]) + "\n")
}

pub(super) fn observe(
    request: &RecorderRequest,
    config: &ClientConfig,
    owner: &impl OnvifContext,
    approval: ContentDigest,
) -> Result<RecorderObservation, &'static str> {
    let observation = match request {
        RecorderRequest::Inventory => {
            let report = recording::inventory(config, owner).map_err(|error| error.code())?;
            RecorderObservation {
                bytes: inventory_json(&report, approval)?,
                operation: request.operation(),
                recordings: report.recordings.len(),
                tracks: report.recordings.iter().map(|recording| recording.tracks.len()).sum(),
                exchanges: report.exchanges,
                selection: None,
            }
        }
        RecorderRequest::Replay { token, window, codec } => {
            let report = recording::select(config, token, *window, owner).map_err(|error| error.code())?;
            let handoff = ReplayHandoff::from_selected(&report, approval, *window, *codec)?;
            let selection = object(&[
                ("recording_token_digest", string(&handoff.recording_token_digest().to_text())),
                ("information_digest", string(&handoff.information_digest()?.to_text())),
                ("services_digest", string(&report.services.digest().map_err(|error| ClientError::Wire(error).code())?.to_text())),
                ("uri_response_digest", string(&report.uri_response_digest.to_text())),
                ("requested_range", string(&handoff.window().to_string())),
                ("codec", string(handoff.codec().as_str())),
                ("advertised_range_assessment", string(handoff.range_assessment()?)),
                ("uri_lifetime", string("unknown")),
            ]);
            RecorderObservation {
                bytes: handoff.render()?,
                operation: request.operation(),
                recordings: 1,
                tracks: report.information.tracks.len(),
                exchanges: report.exchanges,
                selection: Some(selection),
            }
        }
    };
    if observation.bytes.len() > super::private_file::MAX_FILE_BYTES {
        return Err("ERR-ONVIF-BUDGET-001");
    }
    Ok(observation)
}

#[cfg(test)]
#[path = "recorder_tests.rs"]
mod tests;
