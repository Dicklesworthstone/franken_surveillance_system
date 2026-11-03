#![forbid(unsafe_code)]
//! Immutable RFC 2435 JPEG/90000 signaling on the existing RTSP session.

use super::ClientError;
use crate::rtsp::SdpMedia;

/// Exact selected JPEG transport. Packet headers and the decoder validate each image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JpegClientMedia {
    payload_type: u8,
    reduced_rtcp: bool,
}
impl JpegClientMedia {
    /// Static JPEG payload 26 or the exact owner-selected dynamic payload.
    pub fn payload_type(&self) -> u8 {
        self.payload_type
    }
    /// Explicit SDP reduced-size RTCP signaling, never inferred from incoming bytes.
    pub fn reduced_rtcp(&self) -> bool {
        self.reduced_rtcp
    }
}
pub(super) fn negotiate(media: &SdpMedia) -> Result<JpegClientMedia, ClientError> {
    if media.media_type != "video"
        || !matches!(media.proto.as_str(), "RTP/AVP" | "RTP/AVP/TCP")
        || !matches!(media.payload_type, 26 | 96..=127)
        || media.encoding_name.as_deref() != Some("JPEG")
        || media.clock_rate != Some(90_000)
        || media.packetization_mode.is_some()
        || media.profile_level_id.is_some()
        || !media.sprop_parameter_sets.is_empty()
        || media.sps.is_some()
        || media.pps.is_some()
    {
        return Err(ClientError::Description);
    }
    Ok(JpegClientMedia {
        payload_type: media.payload_type,
        reduced_rtcp: media.rtcp_reduced_size,
    })
}
