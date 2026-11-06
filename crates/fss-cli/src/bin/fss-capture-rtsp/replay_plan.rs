#![forbid(unsafe_code)]
//! Pure, approval-bound selection of one explicitly supplied recorder replay URI.

use std::collections::BTreeMap;
use std::ffi::OsString;

use fss_cli::agent_json::{object, string};
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_reference::rtsp::client::ClientConfig;
use fss_reference::rtsp::client::replay::{MAX_REPLAY_DURATION_SECONDS, ReplayWindow};
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording_replay::ReplayRequest;
use fss_reference::rtsp::tcp::{SsrcPolicy, TcpBinding};

pub(super) const POLICY: &str = "recorder-replay:avc:explicit-uri:closed-clock-range:require-onvif-replay:rate-control-no:durable-request-acknowledgement:received-prefix-only:v1";

pub(crate) fn reject_wrapped(args: &[OsString]) -> Result<(), &'static str> {
    if args
        .chunks_exact(2)
        .any(|pair| pair[0] == "--replay-start" || pair[0] == "--replay-end")
    {
        return Err("recorder replay requires direct single AVC capture with an explicit replay URI");
    }
    Ok(())
}

pub(super) fn parse(
    values: &BTreeMap<&str, &str>,
    binding: &TcpBinding,
    protocol: &ClientConfig,
    scope: &RecordingScope,
    payload_type: u8,
    hevc: bool,
    base_decode_clock: ContentDigest,
) -> Result<Option<ReplayRequest>, &'static str> {
    let (start, end) = match (values.get("--replay-start"), values.get("--replay-end")) {
        (None, None) => return Ok(None),
        (Some(start), Some(end)) => (*start, *end),
        _ => return Err("recorder replay requires both --replay-start and --replay-end"),
    };
    if hevc || binding.ssrc_policy() != SsrcPolicy::Pinned {
        return Err("recorder replay currently requires AVC and an explicitly pinned SSRC");
    }
    let window = ReplayWindow::from_timestamps(start, end)
        .map_err(|_| "invalid closed recorder replay interval; use compact UTC within seven days")?;
    let mut route = CanonicalEncoder::new();
    route.text("fss.rtsp_recorder_replay_route.v1");
    route.text(&binding.peer().to_string());
    route.text(binding.authority());
    route.text(&protocol.presentation_uri);
    route.text(&protocol.control_root_uri);
    route.bytes(&binding.key().ingress.to_be_bytes());
    route.u64(binding.key().generation);
    route.u32(binding.key().ssrc);
    route.u64(protocol.media_index as u64);
    route.u32(u32::from(protocol.channels.0));
    route.u32(u32::from(protocol.channels.1));
    route.u32(u32::from(payload_type));
    let route = ContentDigest::sha256(
        &route
            .finish_checked()
            .map_err(|_| "replay route encoding refused")?,
    );
    ReplayRequest::new(scope.clone(), route, window, base_decode_clock)
        .map(Some)
        .map_err(|_| "recorder replay request refused")
}

pub(super) fn preview(request: &ReplayRequest) -> String {
    object(&[
        ("source", string("recorder_replay")),
        ("request_identity", string(&request.digest().to_text())),
        ("requested_range", string(&request.window().to_string())),
        ("maximum_range_seconds", MAX_REPLAY_DURATION_SECONDS.to_string()),
        ("require", string("onvif-replay")),
        ("rate_control", string("no")),
        ("acknowledgement", string("one-closed-contained-clock-range-required")),
        ("receipt", string("root-last-after-original-window-verification")),
        ("historical_frame_time", string("unknown")),
        ("complete_interval_retrieval", "false".into()),
        ("upstream_retention_known", "false".into()),
        ("automatic_live_fallback", "false".into()),
    ])
}
