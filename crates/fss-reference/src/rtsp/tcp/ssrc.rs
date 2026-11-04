#![forbid(unsafe_code)]
//! Constructor-selected sender binding. An SSRC is stream identity, not authentication.

use fss_packet::{PacketLimits, RtpPacket, StreamKey};

/// How one connection selects its RTP synchronization-source identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SsrcPolicy {
    /// Require the owner's exact SSRC, including zero, throughout this connection.
    Pinned,
    /// Bind once to SETUP's SSRC, or the first valid selected-channel RTP packet.
    /// The route, payload, ingress and generation remain independently pinned.
    LearnOnce,
}

/// Private, allocation-free state shared by the AVC and HEVC protocol owners.
/// No public API can reset or replace a sender in a running connection.
#[derive(Clone, Debug)]
pub(in crate::rtsp) struct SenderBinding {
    template: StreamKey,
    selected: Option<StreamKey>,
}
impl SenderBinding {
    pub(in crate::rtsp) fn new(key: StreamKey, policy: SsrcPolicy) -> Self {
        Self {
            template: key,
            selected: (policy == SsrcPolicy::Pinned).then_some(key),
        }
    }

    pub(in crate::rtsp) fn key(&self) -> Option<StreamKey> {
        self.selected
    }

    pub(in crate::rtsp) fn setup(&mut self, advertised: Option<u32>) -> Result<(), ()> {
        if let Some(ssrc) = advertised {
            self.select(ssrc)?;
        }
        Ok(())
    }

    /// Call only after the session has admitted the selected RTP channel.
    /// Validate CSRC, extension, padding, version, size, payload type and nonempty
    /// media before allowing any packet to establish the source identifier.
    pub(in crate::rtsp) fn packet(
        &mut self,
        bytes: &[u8],
        payload_type: u8,
        limits: PacketLimits,
    ) -> Result<(), ()> {
        let packet = RtpPacket::parse(bytes, limits).map_err(|_| ())?;
        if packet.payload_type() != payload_type || packet.payload().is_empty() {
            return Err(());
        }
        self.select(packet.ssrc())
    }

    fn select(&mut self, ssrc: u32) -> Result<(), ()> {
        if let Some(selected) = self.selected {
            if selected.ssrc != ssrc {
                return Err(());
            }
        } else {
            self.selected = Some(StreamKey {
                ssrc,
                ..self.template
            });
        }
        Ok(())
    }
}
