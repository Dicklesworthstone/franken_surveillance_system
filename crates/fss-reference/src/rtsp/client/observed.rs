#![forbid(unsafe_code)]
//! Reuse the live client's exact SDP and control-URI admission for supplied evidence.
//!
//! This validates syntax and the caller's declared scope. There is no request/response
//! correlation, authenticated server, connection, observed SETUP, or live authority.

use super::{
    ClientCodec, ClientConfig, ClientError, ClientMedia, NegotiatedMedia, RtspClientSession,
    RtspResponse, bounded_response, decimal, description, hevc::HevcClientMedia, singleton,
};

/// Admitted video signaling, not a decoded or currently reachable source.
#[derive(Debug)]
pub enum ObservedVideoDescription {
    /// Existing bounded AVC signaling, including exact SPS and PPS bytes.
    Avc(ClientMedia),
    /// Existing no-DON single-layer HEVC signaling; configuration remains separately checked.
    Hevc(HevcClientMedia),
}

/// Apply the same video-description function used by a matching live DESCRIBE response.
///
/// The supplied CSeq must be syntactically valid but is not correlated to a request.
/// No RTSP message is synthesized, transmitted, rewritten, or treated as authenticated.
/// Parameter bytes and private routing data never appear in errors or Debug output.
pub fn observe_video_description(
    config: &ClientConfig,
    response: &RtspResponse,
    codec: ClientCodec,
    payload_type: Option<u8>,
) -> Result<ObservedVideoDescription, ClientError> {
    if !matches!(codec, ClientCodec::H264 | ClientCodec::H265)
        || payload_type.is_some_and(|pt| !(96..=127).contains(&pt))
    {
        return Err(ClientError::Configuration);
    }
    // An inert constructor owns the exact URI/configuration rules; it creates no request.
    let _scope = RtspClientSession::new_for_codec(config.clone(), codec)?;
    bounded_response(response)?;
    if response.version != "RTSP/1.0"
        || response.status_code != 200
        || response.auth_challenge.is_some()
        || decimal(singleton(&response.headers, "CSeq")?.ok_or(ClientError::Response)?)?
            > u64::from(u32::MAX)
    {
        return Err(ClientError::Response);
    }
    // This is deliberately the live client's one semantic owner, not a parallel parser.
    match description(config, response, codec, payload_type)?.0 {
        NegotiatedMedia::H264(media) => Ok(ObservedVideoDescription::Avc(media)),
        NegotiatedMedia::H265(media) => Ok(ObservedVideoDescription::Hevc(media)),
        _ => Err(ClientError::Description),
    }
}
