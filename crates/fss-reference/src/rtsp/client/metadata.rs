#![forbid(unsafe_code)]
//! The selected uncompressed ONVIF application transport, independent of XML meaning.

use super::ClientError;
use crate::rtsp::SdpMedia;

/// Immutable exact SDP selection. This grants no network or observation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataClientMedia {
    payload_type: u8,
    reduced_rtcp: bool,
}

impl MetadataClientMedia {
    /// Explicitly selected dynamic RTP payload type.
    pub fn payload_type(&self) -> u8 {
        self.payload_type
    }

    /// Explicit SDP reduced-size RTCP signaling, never inferred from incoming bytes.
    pub fn reduced_rtcp(&self) -> bool {
        self.reduced_rtcp
    }
}

pub(super) fn negotiate(media: &SdpMedia) -> Result<MetadataClientMedia, ClientError> {
    if media.media_type != "application"
        || !matches!(media.proto.as_str(), "RTP/AVP" | "RTP/AVP/TCP")
        || !(96..=127).contains(&media.payload_type)
        || media.encoding_name.as_deref() != Some("vnd.onvif.metadata")
        || media.clock_rate != Some(90_000)
        || media.packetization_mode.is_some()
        || media.profile_level_id.is_some()
        || !media.sprop_parameter_sets.is_empty()
        || media.sps.is_some()
        || media.pps.is_some()
    {
        return Err(ClientError::Description);
    }
    Ok(MetadataClientMedia {
        payload_type: media.payload_type,
        reduced_rtcp: media.rtcp_reduced_size,
    })
}
