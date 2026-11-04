#![forbid(unsafe_code)]
//! Native syntax-grouped RTP observations for a session-owned RTSP site probe.
//!
//! Callers own approved network effects, authentication, liveness and TEARDOWN.
//! Picture boundaries are measured by the same codec owners as recorded probes;
//! they do not certify complete decoded pixels or authenticate a camera. A live
//! caller may explicitly freeze a confirmed prefix and account for its excluded
//! unfinished tail. Raw SDP and media never survive into a receipt.

use fss_core::ContentDigest;
use fss_packet::{PacketLimits, RtpPacket, StreamKey};

use super::probe_route::ProbeRoute;
use super::{ProbeCodec, SiteManifest, SiteProbeReceipt};
use crate::rtsp::client::observed::ObservedVideoDescription;
use crate::rtsp::client::{hevc, jpeg};
use crate::rtsp::selection::{
    MAX_SELECTION_BYTES, select_h264_description, select_h265_description, select_jpeg_description,
};
use crate::site_probe::media::{MediaObserver, PreparedMedia};
use crate::site_probe::{Cadence, SiteProbeError};

/// Maximum datagrams in one strictly bounded observation.
pub const MAX_PROBE_RTP_PACKETS: u32 = 4096;
/// Maximum aggregate RTP bytes in one observation.
pub const MAX_PROBE_RTP_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum native syntax-grouped picture observations in one sample.
pub const MAX_PROBE_PICTURES: u32 = 64;

/// Payload-free refusal states; no camera address, secret or source data is rendered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationError {
    /// Source kind, identity, declaration or selected index is invalid.
    Scope,
    /// SDP, native codec syntax or immutable parameter sets cannot be admitted.
    Negotiation,
    /// An input or cumulative work limit was exceeded.
    Limit,
    /// A malformed RTP packet or foreign channel or payload arrived.
    Packet,
    /// Sender, sequence or native picture-start continuity was lost.
    Continuity,
    /// Native picture-boundary timestamps do not follow one fixed 90 kHz cadence.
    Cadence,
    /// Too few witnessed groups, or an unfinished strict sample or prefix operation.
    Incomplete,
    /// The emitted receipt fails the canonical schema contract.
    Receipt,
}
impl ObservationError {
    /// Stable, non-disclosing diagnostic identity.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Scope => "ERR-SITE-PROBE-SCOPE-001",
            Self::Negotiation => "ERR-SITE-PROBE-NEGOTIATION-001",
            Self::Limit => "ERR-SITE-PROBE-LIMIT-001",
            Self::Packet => "ERR-SITE-PROBE-PACKET-001",
            Self::Continuity => "ERR-SITE-PROBE-CONTINUITY-001",
            Self::Cadence => "ERR-SITE-PROBE-CADENCE-001",
            Self::Incomplete => "ERR-SITE-PROBE-INCOMPLETE-001",
            Self::Receipt => "ERR-SITE-PROBE-RECEIPT-001",
        }
    }
}
impl std::fmt::Display for ObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for ObservationError {}

/// One media selection already negotiated by the session-owned native RTSP client.
/// All inputs must come from the same DESCRIBE/SETUP session; this API cannot prove it.
pub struct NegotiatedProbe<'a> {
    /// Original DESCRIBE body, never written to the observation receipt.
    pub sdp: &'a [u8],
    /// Original SDP video media ordinal.
    pub media_index: usize,
    /// Selected even RTP interleaved channel, followed by RTCP.
    pub rtp_channel: u8,
    /// Selected codec.
    pub codec: ProbeCodec,
    /// Exact dynamic RTP payload type, or static payload 26 for JPEG.
    pub payload_type: u8,
    /// Decoded selected NALs (AVC SPS/PPS or HEVC VPS/SPS/PPS); empty for JPEG.
    pub parameter_sets: &'a [&'a [u8]],
    /// Opaque bounded identity provided by the owning client.
    pub server_identity: &'a str,
}

/// Derivative bytes explicitly excluded at a live sample cut. These counts do
/// not represent extra original-wire bytes, omitted frames, or durable custody.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProbeTail {
    /// Complete reconstructed NAL bytes in a group with no witnessed boundary.
    pub unverified_nal_bytes_excluded: u64,
    /// Reconstructed bytes of an unfinished fragmentation unit.
    pub unfinished_fragment_bytes_excluded: u64,
}

/// Bounded transient native reconstruction. Only digests, counters and RTP
/// coordinates survive successful finalization; no media is retained in a receipt.
pub struct RtspProbeObserver<'a> {
    manifest: &'a SiteManifest,
    source_index: usize,
    route: ProbeRoute,
    media_index: usize,
    rtp_channel: u8,
    codec: ProbeCodec,
    payload_type: u8,
    sdp_digest: ContentDigest,
    parameter_digests: Vec<ContentDigest>,
    server_identity: String,
    prepared: Option<PreparedMedia>,
    media: Option<MediaObserver>,
    ssrc: Option<u32>,
    sequence: Option<u64>,
    last_ns: Option<u64>,
    cadence: Cadence,
    packets: u32,
    bytes: u64,
    invalidated: bool,
    frozen: Option<ProbeTail>,
}
impl std::fmt::Debug for RtspProbeObserver<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtspProbeObserver")
            .field("source_index", &self.source_index)
            .field("confirmed_pictures", &self.cadence.frames())
            .field("packets", &self.packets)
            .field("frozen", &self.frozen.is_some())
            .finish_non_exhaustive()
    }
}
impl<'a> RtspProbeObserver<'a> {
    /// Begin from an exact validated source and SDP selection. The shared native
    /// configuration owner checks full SPS syntax, including field-mode refusal.
    pub fn new(
        manifest: &'a SiteManifest,
        source_index: usize,
        negotiated: NegotiatedProbe<'_>,
    ) -> Result<Self, ObservationError> {
        let route =
            ProbeRoute::direct(manifest, source_index).map_err(|_| ObservationError::Scope)?;
        Self::new_with_route(manifest, source_index, route, negotiated)
    }

    /// Begin with an exact direct or protected UniFi/ONVIF route under the original manifest.
    /// The route is consistency evidence only; the caller still owns network authority and
    /// must supply codec/session observations rather than infer them from an export.
    pub fn new_with_route(
        manifest: &'a SiteManifest,
        source_index: usize,
        route: ProbeRoute,
        negotiated: NegotiatedProbe<'_>,
    ) -> Result<Self, ObservationError> {
        route
            .validate_for(manifest, source_index)
            .map_err(|_| ObservationError::Scope)?;
        route
            .validate_codec(manifest, negotiated.codec)
            .map_err(|_| ObservationError::Negotiation)?;
        if negotiated.sdp.is_empty() || negotiated.sdp.len() > MAX_SELECTION_BYTES {
            return Err(ObservationError::Limit);
        }
        if negotiated.media_index > 63
            || negotiated.rtp_channel % 2 != 0
            || (!(96..=127).contains(&negotiated.payload_type)
                && !(negotiated.codec == ProbeCodec::Jpeg && negotiated.payload_type == 26))
            || negotiated.server_identity.is_empty()
            || negotiated.server_identity.len() > 256
            || !negotiated
                .server_identity
                .bytes()
                .all(|b| (32..=126).contains(&b))
        {
            return Err(ObservationError::Negotiation);
        }
        let prepared = match negotiated.codec {
            ProbeCodec::Avc => {
                let session = select_h264_description(
                    negotiated.sdp,
                    negotiated.media_index,
                    Some(negotiated.payload_type),
                )
                .map_err(|_| ObservationError::Negotiation)?;
                let media = session
                    .media
                    .get(negotiated.media_index)
                    .ok_or(ObservationError::Negotiation)?;
                if media.media_type != "video"
                    || media.encoding_name.as_deref() != Some("H264")
                    || media.payload_type != negotiated.payload_type
                    || media.clock_rate != Some(90_000)
                {
                    return Err(ObservationError::Negotiation);
                }
                PreparedMedia::avc(
                    media.sps.as_deref().ok_or(ObservationError::Negotiation)?,
                    media.pps.as_deref().ok_or(ObservationError::Negotiation)?,
                    media.packetization_mode.unwrap_or(0),
                    media.payload_type,
                    media.rtcp_reduced_size,
                )
                .map_err(measurement_error)?
            }
            ProbeCodec::Hevc => {
                let (session, projected) = select_h265_description(
                    negotiated.sdp,
                    negotiated.media_index,
                    Some(negotiated.payload_type),
                )
                .map_err(|_| ObservationError::Negotiation)?;
                let media = session
                    .media
                    .get(negotiated.media_index)
                    .ok_or(ObservationError::Negotiation)?;
                // Reuse the session's no-DON/profile/parameter negotiation; there
                // is no independent fmtp parser or guessed parameter fallback.
                let selected = hevc::negotiate(&projected, negotiated.media_index, media)
                    .map_err(|_| ObservationError::Negotiation)?;
                PreparedMedia::new(ObservedVideoDescription::Hevc(selected))
                    .map_err(measurement_error)?
            }
            ProbeCodec::Jpeg => {
                let session = select_jpeg_description(
                    negotiated.sdp,
                    negotiated.media_index,
                    Some(negotiated.payload_type),
                )
                .map_err(|_| ObservationError::Negotiation)?;
                let media = session
                    .media
                    .get(negotiated.media_index)
                    .ok_or(ObservationError::Negotiation)?;
                let selected = jpeg::negotiate(media).map_err(|_| ObservationError::Negotiation)?;
                PreparedMedia::new(ObservedVideoDescription::Jpeg(selected))
                    .map_err(measurement_error)?
            }
        };
        let parameter_digests = prepared.parameter_set_digests();
        if prepared.payload_type() != negotiated.payload_type
            || parameter_digests.len() != negotiated.parameter_sets.len()
            || parameter_digests
                .iter()
                .zip(negotiated.parameter_sets)
                .any(|(digest, supplied)| {
                    supplied.is_empty()
                        || supplied.len() > 16_384
                        || *digest != ContentDigest::sha256(supplied)
                })
        {
            return Err(ObservationError::Negotiation);
        }
        Ok(Self {
            manifest,
            source_index,
            route,
            media_index: negotiated.media_index,
            rtp_channel: negotiated.rtp_channel,
            codec: negotiated.codec,
            payload_type: negotiated.payload_type,
            sdp_digest: ContentDigest::sha256(negotiated.sdp),
            parameter_digests,
            server_identity: negotiated.server_identity.to_owned(),
            prepared: Some(prepared),
            media: None,
            ssrc: None,
            sequence: None,
            last_ns: None,
            cadence: Cadence::default(),
            packets: 0,
            bytes: 0,
            invalidated: false,
            frozen: None,
        })
    }

    /// Admit supplied evidence with a local work coordinate, not an arrival-time
    /// claim. Live owners use `observe_rtp_at` with their actual monotonic clock.
    pub fn observe_rtp(&mut self, channel: u8, bytes: &[u8]) -> Result<(), ObservationError> {
        let Some(step) = self.last_ns.unwrap_or(0).checked_add(1) else {
            self.invalidated = true;
            return Err(ObservationError::Limit);
        };
        self.observe_rtp_at(channel, bytes, step)
    }

    /// Admit one RTP datagram through native depacketization and picture grouping
    /// at the owning connection's monotonic time. Native fragment/group lifetime
    /// checks see that same time; a refusal permanently invalidates the sample.
    pub fn observe_rtp_at(
        &mut self,
        channel: u8,
        bytes: &[u8],
        now_ns: u64,
    ) -> Result<(), ObservationError> {
        if self.invalidated || self.frozen.is_some() || self.last_ns.is_some_and(|old| now_ns < old)
        {
            self.invalidated = true;
            return Err(ObservationError::Continuity);
        }
        let result = self.observe_packet(channel, bytes, now_ns);
        if result.is_err() {
            self.invalidated = true;
        } else {
            self.last_ns = Some(now_ns);
        }
        result
    }

    fn observe_packet(
        &mut self,
        channel: u8,
        bytes: &[u8],
        now_ns: u64,
    ) -> Result<(), ObservationError> {
        if self.packets >= MAX_PROBE_RTP_PACKETS {
            return Err(ObservationError::Limit);
        }
        let total = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or(ObservationError::Limit)?;
        if total > MAX_PROBE_RTP_BYTES {
            return Err(ObservationError::Limit);
        }
        let packet = RtpPacket::parse(bytes, PacketLimits::default())
            .map_err(|_| ObservationError::Packet)?;
        if channel != self.rtp_channel
            || packet.payload_type() != self.payload_type
            || packet.payload().is_empty()
        {
            return Err(ObservationError::Packet);
        }
        if self.ssrc.is_some_and(|old| old != packet.ssrc()) {
            return Err(ObservationError::Continuity);
        }
        let extended = if let Some(previous) = self.sequence {
            let next = previous.checked_add(1).ok_or(ObservationError::Limit)?;
            if packet.sequence() != next as u16 {
                return Err(ObservationError::Continuity);
            }
            next
        } else {
            u64::from(packet.sequence())
        };
        if self.media.is_none() {
            // This private, observer-local slot is not a capture epoch or an
            // externally reusable stream identity. The receipt binds the source.
            let key = StreamKey {
                ingress: self.source_index as u128 + 1,
                generation: self.manifest.sources[self.source_index].generation,
                ssrc: packet.ssrc(),
            };
            self.media = Some(
                self.prepared
                    .take()
                    .ok_or(ObservationError::Negotiation)?
                    .start(key)
                    .map_err(measurement_error)?,
            );
        }
        self.ssrc = Some(packet.ssrc());
        self.sequence = Some(extended);
        self.media
            .as_mut()
            .ok_or(ObservationError::Incomplete)?
            .push(extended, packet, now_ns, &mut self.cadence)
            .map_err(measurement_error)?;
        if self.cadence.frames() > MAX_PROBE_PICTURES {
            return Err(ObservationError::Limit);
        }
        self.packets += 1;
        self.bytes = total;
        Ok(())
    }

    /// Witnessed native groups so far. Markers, incomplete fragments, pending
    /// pictures and unverified EOF tails do not independently increment this count.
    pub fn confirmed_pictures(&self) -> u32 {
        self.cadence.frames()
    }

    /// Freeze a confirmed live prefix, explicitly omitting any unfinished next
    /// group/fragment. This performs local cancellation, never fabricated EOS/EOF.
    /// A whole datagram is processed before a cut, so it may confirm several groups.
    pub fn freeze_prefix(&mut self) -> Result<ProbeTail, ObservationError> {
        if self.invalidated {
            return Err(ObservationError::Continuity);
        }
        if self.frozen.is_some() || self.cadence.frames() < 3 {
            return Err(ObservationError::Incomplete);
        }
        let pending = self
            .media
            .as_mut()
            .ok_or(ObservationError::Incomplete)?
            .discard_pending();
        let tail = ProbeTail {
            unverified_nal_bytes_excluded: pending.nal_bytes,
            unfinished_fragment_bytes_excluded: pending.fragment_bytes,
        };
        self.frozen = Some(tail);
        Ok(tail)
    }

    /// Finalize only an explicitly frozen live prefix. The caller must separately
    /// witness matching TEARDOWN; this pure API grants no network or capture rights.
    pub fn finish_prefix(self) -> Result<SiteProbeReceipt, ObservationError> {
        if self.invalidated {
            return Err(ObservationError::Continuity);
        }
        if self.frozen.is_none() {
            return Err(ObservationError::Incomplete);
        }
        self.receipt()
    }

    /// Strict finalization of all supplied evidence. Unfinished fragments and
    /// pictures refuse the whole sample; use the explicit live-prefix API to cut.
    pub fn finish(mut self) -> Result<SiteProbeReceipt, ObservationError> {
        if self.invalidated {
            return Err(ObservationError::Continuity);
        }
        if self.frozen.is_some() {
            return Err(ObservationError::Incomplete);
        }
        self.media
            .as_mut()
            .ok_or(ObservationError::Incomplete)?
            .finish(self.last_ns.unwrap_or(0), &mut self.cadence)
            .map_err(measurement_error)?;
        if self.cadence.frames() > MAX_PROBE_PICTURES {
            return Err(ObservationError::Limit);
        }
        self.receipt()
    }

    fn receipt(self) -> Result<SiteProbeReceipt, ObservationError> {
        let (observed_frames, first_rtp_timestamp, last_rtp_timestamp, frame_duration_ticks) =
            self.cadence.finish().map_err(measurement_error)?;
        let source = &self.manifest.sources[self.source_index];
        let receipt = SiteProbeReceipt {
            site_id: self.manifest.site_id.clone(),
            source_id: source.source_id.clone(),
            manifest_digest: self.route.manifest_digest(),
            source_generation: source.generation,
            peer: self.route.peer(),
            authority: self.route.authority().to_owned(),
            presentation: self.route.presentation().to_owned(),
            control_root: self.route.control_root().to_owned(),
            media_index: self.media_index,
            rtp_channel: self.rtp_channel,
            rtcp_channel: self.rtp_channel + 1,
            sdp_digest: self.sdp_digest,
            codec: self.codec,
            payload_type: self.payload_type,
            ssrc: self.ssrc.ok_or(ObservationError::Incomplete)?,
            frame_duration_ticks,
            clock_rate_hz: 90_000,
            observed_frames,
            first_rtp_timestamp,
            last_rtp_timestamp,
            parameter_set_digests: self.parameter_digests,
            server_identity: self.server_identity,
            // VIT-019 adds the schema field; wiring a real wall-clock sample into
            // the live observer is a separate follow-up, tracked on that bead.
            clock_evidence: None,
        };
        self.route
            .validate_receipt(self.manifest, &receipt)
            .map_err(|_| ObservationError::Receipt)?;
        Ok(receipt)
    }
}

fn measurement_error(error: SiteProbeError) -> ObservationError {
    match error {
        SiteProbeError::Limit => ObservationError::Limit,
        SiteProbeError::Manifest | SiteProbeError::Source | SiteProbeError::SourceKind => {
            ObservationError::Scope
        }
        SiteProbeError::Selection
        | SiteProbeError::Description
        | SiteProbeError::ServerHeader
        | SiteProbeError::Codec
        | SiteProbeError::ParameterChange => ObservationError::Negotiation,
        SiteProbeError::RtpDump | SiteProbeError::Packet => ObservationError::Packet,
        SiteProbeError::Sequence | SiteProbeError::StreamChanged | SiteProbeError::Picture => {
            ObservationError::Continuity
        }
        SiteProbeError::IncompletePicture | SiteProbeError::InsufficientPictures => {
            ObservationError::Incomplete
        }
        SiteProbeError::Cadence => ObservationError::Cadence,
        SiteProbeError::Encoding => ObservationError::Receipt,
    }
}

#[cfg(test)]
#[path = "probe_observation_tests.rs"]
mod tests;
