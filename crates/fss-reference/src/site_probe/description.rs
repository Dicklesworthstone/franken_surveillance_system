#![forbid(unsafe_code)]
//! Strict whole-response observation through the native framing and SDP owners.

use fss_core::ContentDigest;

use crate::rtsp::client::observed::{ObservedVideoDescription, observe_video_description};
use crate::rtsp::client::{ClientCodec, ClientConfig};
use crate::rtsp::framed::{MAX_WIRE_CHUNK, RtspWireIntake};
use crate::rtsp::{RtspEvent, RtspResponse};
use crate::site::{ProbeCodec, SiteSource};

use super::{ProbeSelection, SiteProbeError};

pub(super) struct Description {
    pub(super) media: ObservedVideoDescription,
    pub(super) sdp_digest: ContentDigest,
    pub(super) server_header_digest: Option<ContentDigest>,
}

pub(super) fn inspect(
    source: &SiteSource,
    selection: &ProbeSelection,
    bytes: &[u8],
) -> Result<Description, SiteProbeError> {
    let mut intake = RtspWireIntake::new();
    let mut response = None;
    for chunk in bytes.chunks(MAX_WIRE_CHUNK) {
        // Zero is a deterministic local processing coordinate, not a source timestamp.
        intake
            .ingest(chunk, 0)
            .map_err(|_| SiteProbeError::Description)?;
        drain(&mut intake, &mut response)?;
    }
    intake.finish();
    drain(&mut intake, &mut response)?;
    if !intake.is_ended() {
        return Err(SiteProbeError::Description);
    }
    let response = response.ok_or(SiteProbeError::Description)?;
    let mut server = response
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("Server"));
    let server_header_digest = match server.next() {
        Some(header) if !header.value.is_empty() => {
            Some(ContentDigest::sha256(header.value.as_bytes()))
        }
        Some(_) => return Err(SiteProbeError::ServerHeader),
        None => None,
    };
    if server.next().is_some() {
        return Err(SiteProbeError::ServerHeader);
    }
    let config = ClientConfig {
        presentation_uri: format!(
            "rtsp://{}{}",
            source.authority,
            source
                .presentation
                .as_deref()
                .ok_or(SiteProbeError::Manifest)?
        ),
        control_root_uri: format!(
            "rtsp://{}{}",
            source.authority,
            source
                .control_root
                .as_deref()
                .ok_or(SiteProbeError::Manifest)?
        ),
        media_index: selection.media_index,
        channels: (selection.rtp_channel, selection.rtp_channel + 1),
        response_timeout_ns: 1,
        default_session_timeout_seconds: 1,
    };
    let codec = match selection.codec {
        ProbeCodec::Avc => ClientCodec::H264,
        ProbeCodec::Hevc => ClientCodec::H265,
        ProbeCodec::Jpeg => ClientCodec::Jpeg,
    };
    let media = observe_video_description(&config, &response, codec, None)
        .map_err(|_| SiteProbeError::Description)?;
    Ok(Description {
        media,
        sdp_digest: ContentDigest::sha256(&response.body),
        server_header_digest,
    })
}

fn drain(
    intake: &mut RtspWireIntake,
    response: &mut Option<RtspResponse>,
) -> Result<(), SiteProbeError> {
    while let Some(frame) = intake.poll(0).map_err(|_| SiteProbeError::Description)? {
        let (event, _, _) = frame.into_parts();
        let RtspEvent::Response(parsed) = event else {
            return Err(SiteProbeError::Description);
        };
        if response.replace(parsed).is_some() {
            return Err(SiteProbeError::Description);
        }
    }
    Ok(())
}
