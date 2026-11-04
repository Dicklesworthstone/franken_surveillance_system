#![forbid(unsafe_code)]
//! Pure RTP observations for a native, session-owned RTSP site probe (VIT-003).
//!
//! Callers own approved network effects, authentication, liveness and TEARDOWN.
//! These observations cannot authenticate a camera or certify a complete picture.
//! Raw SDP and packet bytes never survive into a receipt.

use fss_core::ContentDigest;
use fss_packet::{PacketLimits, RtpPacket};
use super::{ProbeCodec, SiteManifest, SiteProbeReceipt, SourceKind};
use crate::rtsp::sdp::decode_base64;
use crate::rtsp::selection::{MAX_SELECTION_BYTES, select_h264_description, select_h265_description};

/// Maximum datagrams in one strictly bounded observation.
pub const MAX_PROBE_RTP_PACKETS: u32 = 4096;
/// Maximum aggregate bytes in one observation.
pub const MAX_PROBE_RTP_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum marked candidate pictures in one observation.
pub const MAX_PROBE_PICTURES: u32 = 64;

/// Payload-free refusal states; no camera address, secret or source data is rendered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationError {
    /// Source kind, identity, declaration or selected index is invalid.
    Scope,
    /// The chosen SDP media and codec parameter sets do not match exactly.
    Negotiation,
    /// An input or cumulative work limit was exceeded.
    Limit,
    /// A malformed RTP packet or foreign channel or payload arrived.
    Packet,
    /// Sender, sequence or picture-boundary continuity was lost.
    Continuity,
    /// RTP picture-boundary timestamps do not follow one fixed 90 kHz cadence.
    Cadence,
    /// The sample contains fewer than three complete marked boundaries.
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
    /// Exact dynamic RTP payload type.
    pub payload_type: u8,
    /// Decoded selected NALs (AVC SPS/PPS or HEVC VPS/SPS/PPS).
    pub parameter_sets: &'a [&'a [u8]],
    /// Opaque bounded identity provided by the owning client.
    pub server_identity: &'a str,
}

/// Fixed-memory observer. Only digests, counters and RTP header coordinates survive.
pub struct RtspProbeObserver<'a> {
    manifest: &'a SiteManifest,
    source_index: usize,
    media_index: usize,
    rtp_channel: u8,
    codec: ProbeCodec,
    payload_type: u8,
    sdp_digest: ContentDigest,
    parameter_digests: Vec<ContentDigest>,
    server_identity: String,
    ssrc: Option<u32>,
    sequence: Option<u16>,
    active_timestamp: Option<u32>,
    active_marked: bool,
    first_timestamp: Option<u32>,
    last_timestamp: Option<u32>,
    cadence: Option<u32>,
    pictures: u32,
    packets: u32,
    bytes: u64,
    invalidated: bool,
}
impl std::fmt::Debug for RtspProbeObserver<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtspProbeObserver")
            .field("source_index", &self.source_index)
            .field("pictures", &self.pictures)
            .field("packets", &self.packets)
            .finish_non_exhaustive()
    }
}
impl<'a> RtspProbeObserver<'a> {
    /// Begin observation from an exact validated manifest source and SDP selection.
    pub fn new(
        manifest: &'a SiteManifest,
        source_index: usize,
        negotiated: NegotiatedProbe<'_>,
    ) -> Result<Self, ObservationError> {
        manifest.validate().map_err(|_| ObservationError::Scope)?;
        let source = manifest.sources.get(source_index).ok_or(ObservationError::Scope)?;
        if !matches!(source.kind, SourceKind::Rtsp | SourceKind::NvrChannel)
            || !source.owner_authorized || !source.plaintext
        {
            return Err(ObservationError::Scope);
        }
        if negotiated.sdp.is_empty() || negotiated.sdp.len() > MAX_SELECTION_BYTES {
            return Err(ObservationError::Limit);
        }
        if negotiated.media_index > 63 || negotiated.rtp_channel % 2 != 0
            || !(96..=127).contains(&negotiated.payload_type)
            || negotiated.server_identity.is_empty() || negotiated.server_identity.len() > 256
            || !negotiated.server_identity.bytes().all(|b| (32..=126).contains(&b))
        {
            return Err(ObservationError::Negotiation);
        }
        let (session, projected_hevc) = match negotiated.codec {
            ProbeCodec::Avc => (
                select_h264_description(negotiated.sdp, negotiated.media_index, Some(negotiated.payload_type))
                    .map_err(|_| ObservationError::Negotiation)?,
                None,
            ),
            ProbeCodec::Hevc => {
                let (session, projected) = select_h265_description(
                    negotiated.sdp, negotiated.media_index, Some(negotiated.payload_type),
                ).map_err(|_| ObservationError::Negotiation)?;
                (session, Some(projected))
            }
            ProbeCodec::Jpeg => return Err(ObservationError::Negotiation),
        };
        let media = session.media.get(negotiated.media_index).ok_or(ObservationError::Negotiation)?;
        if media.media_type != "video" || media.payload_type != negotiated.payload_type
            || media.clock_rate != Some(90_000)
        {
            return Err(ObservationError::Negotiation);
        }
        let decoded = match negotiated.codec {
            ProbeCodec::Avc => vec![
                media.sps.clone().ok_or(ObservationError::Negotiation)?,
                media.pps.clone().ok_or(ObservationError::Negotiation)?,
            ],
            ProbeCodec::Hevc => hevc_sets(
                projected_hevc.as_deref().ok_or(ObservationError::Negotiation)?,
                negotiated.media_index, negotiated.payload_type,
            )?,
            ProbeCodec::Jpeg => return Err(ObservationError::Negotiation),
        };
        if decoded.len() != negotiated.parameter_sets.len() {
            return Err(ObservationError::Negotiation);
        }
        let mut parameter_digests = Vec::with_capacity(decoded.len());
        for (index, (actual, supplied)) in decoded.iter().zip(negotiated.parameter_sets).enumerate() {
            let header_ok = match negotiated.codec {
                ProbeCodec::Avc => actual.first().is_some_and(|b| b & 0x1f == 7 + index as u8),
                ProbeCodec::Hevc => actual.len() >= 2 && (actual[0] >> 1) & 0x3f == 32 + index as u8,
                ProbeCodec::Jpeg => false,
            };
            if actual.as_slice() != *supplied || actual.is_empty() || actual.len() > 16_384 || !header_ok {
                return Err(ObservationError::Negotiation);
            }
            let digest = ContentDigest::sha256(actual);
            if parameter_digests.contains(&digest) {
                return Err(ObservationError::Negotiation);
            }
            parameter_digests.push(digest);
        }
        Ok(Self {
            manifest, source_index,
            media_index: negotiated.media_index,
            rtp_channel: negotiated.rtp_channel,
            codec: negotiated.codec,
            payload_type: negotiated.payload_type,
            sdp_digest: ContentDigest::sha256(negotiated.sdp),
            parameter_digests, server_identity: negotiated.server_identity.to_owned(),
            ssrc: None, sequence: None, active_timestamp: None, active_marked: false,
            first_timestamp: None, last_timestamp: None, cadence: None,
            pictures: 0, packets: 0, bytes: 0, invalidated: false,
        })
    }

    /// Admit one interleaved RTP packet (not RTCP), without retaining its bytes.
    pub fn observe_rtp(&mut self, channel: u8, bytes: &[u8]) -> Result<(), ObservationError> {
        if self.invalidated {
            return Err(ObservationError::Continuity);
        }
        let result = self.observe_packet(channel, bytes);
        if result.is_err() {
            self.invalidated = true;
        }
        result
    }

    fn observe_packet(&mut self, channel: u8, bytes: &[u8]) -> Result<(), ObservationError> {
        if self.packets >= MAX_PROBE_RTP_PACKETS {
            return Err(ObservationError::Limit);
        }
        let total = self.bytes.checked_add(bytes.len() as u64).ok_or(ObservationError::Limit)?;
        if total > MAX_PROBE_RTP_BYTES {
            return Err(ObservationError::Limit);
        }
        let packet = RtpPacket::parse(bytes, PacketLimits::default())
            .map_err(|_| ObservationError::Packet)?;
        if channel != self.rtp_channel || packet.payload_type() != self.payload_type
            || packet.payload().is_empty()
        {
            return Err(ObservationError::Packet);
        }
        if self.ssrc.is_some_and(|old| old != packet.ssrc())
            || self.sequence.is_some_and(|old| old.wrapping_add(1) != packet.sequence())
        {
            return Err(ObservationError::Continuity);
        }
        let ts = packet.timestamp();
        if let Some(active) = self.active_timestamp {
            if ts != active {
                if !self.active_marked {
                    return Err(ObservationError::Continuity);
                }
                self.active_marked = false;
            } else if self.active_marked {
                return Err(ObservationError::Continuity);
            }
        }
        self.active_timestamp = Some(ts);
        if packet.marker() {
            if self.pictures >= MAX_PROBE_PICTURES {
                return Err(ObservationError::Limit);
            }
            if let Some(last) = self.last_timestamp {
                let delta = ts.wrapping_sub(last);
                if !(1..=90_000).contains(&delta)
                    || self.cadence.is_some_and(|old| old != delta)
                {
                    return Err(ObservationError::Cadence);
                }
                self.cadence = Some(delta);
            } else {
                self.first_timestamp = Some(ts);
            }
            self.last_timestamp = Some(ts);
            self.active_marked = true;
            self.pictures += 1;
        }
        self.packets += 1;
        self.bytes = total;
        self.sequence = Some(packet.sequence());
        self.ssrc = Some(packet.ssrc());
        Ok(())
    }

    /// Return a canonical v1 receipt only for a fully marked, steady source sample.
    ///
    /// The caller must independently observe successful RTSP TEARDOWN; returning a
    /// receipt cannot prove remote close, caller identity, freshness or camera liveness.
    pub fn finish(self) -> Result<SiteProbeReceipt, ObservationError> {
        if self.invalidated {
            return Err(ObservationError::Continuity);
        }
        if !self.active_marked || self.pictures < 3 {
            return Err(ObservationError::Incomplete);
        }
        let source = &self.manifest.sources[self.source_index];
        let receipt = SiteProbeReceipt {
            site_id: self.manifest.site_id.clone(), source_id: source.source_id.clone(),
            manifest_digest: self.manifest.digest().map_err(|_| ObservationError::Receipt)?,
            source_generation: source.generation, peer: source.peer,
            authority: source.authority.clone(),
            presentation: source.presentation.clone().ok_or(ObservationError::Receipt)?,
            control_root: source.control_root.clone().ok_or(ObservationError::Receipt)?,
            media_index: self.media_index, rtp_channel: self.rtp_channel,
            rtcp_channel: self.rtp_channel + 1, sdp_digest: self.sdp_digest,
            codec: self.codec, payload_type: self.payload_type,
            ssrc: self.ssrc.ok_or(ObservationError::Incomplete)?,
            frame_duration_ticks: self.cadence.ok_or(ObservationError::Incomplete)?,
            clock_rate_hz: 90_000, observed_frames: self.pictures,
            first_rtp_timestamp: self.first_timestamp.ok_or(ObservationError::Incomplete)?,
            last_rtp_timestamp: self.last_timestamp.ok_or(ObservationError::Incomplete)?,
            parameter_set_digests: self.parameter_digests,
            server_identity: self.server_identity,
        };
        receipt.validate_for(self.manifest).map_err(|_| ObservationError::Receipt)?;
        Ok(receipt)
    }
}

// Strict single-value HEVC subset: a selected native representation with multiple
// parameter NAL alternatives is ambiguous for the v1 receipt's one-digest slots.
fn hevc_sets(projected: &str, media_index: usize, payload: u8) -> Result<Vec<Vec<u8>>, ObservationError> {
    let mut section = None;
    let mut found = false;
    let mut result: [Option<Vec<u8>>; 3] = [None, None, None];
    for line in projected.lines().map(str::trim) {
        if line.starts_with("m=") {
            section = Some(section.map_or(0usize, |n| n + 1));
        }
        if section != Some(media_index) {
            continue;
        }
        let Some(rest) = line.strip_prefix("a=fmtp:") else { continue };
        let Some((number, fields)) = rest.split_once(' ') else {
            return Err(ObservationError::Negotiation);
        };
        if number.parse::<u8>().ok() != Some(payload) {
            continue;
        }
        if found {
            return Err(ObservationError::Negotiation);
        }
        found = true;
        for field in fields.split(';').map(str::trim) {
            let Some((key, raw)) = field.split_once('=') else { continue };
            let index = if key.eq_ignore_ascii_case("sprop-vps") { Some(0) }
                else if key.eq_ignore_ascii_case("sprop-sps") { Some(1) }
                else if key.eq_ignore_ascii_case("sprop-pps") { Some(2) }
                else { None };
            if let Some(index) = index {
                if result[index].is_some() || raw.contains(',') {
                    return Err(ObservationError::Negotiation);
                }
                result[index] = Some(decode_base64(raw).map_err(|_| ObservationError::Negotiation)?);
            }
        }
    }
    if !found { return Err(ObservationError::Negotiation) }
    result.into_iter().map(|value| value.ok_or(ObservationError::Negotiation)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    const MANIFEST: &str = include_str!("../../../../fixtures/site/manifest.v1.json");
    const SDP: &str = concat!(
        "v=0\r\n", "o=- 1 1 IN IP4 127.0.0.1\r\n", "s=probe-fixture\r\n",
        "t=0 0\r\n", "a=control:*\r\n", "m=video 0 RTP/AVP 96\r\n",
        "a=control:trackID=1\r\n", "a=rtpmap:96 H264/90000\r\n",
        "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0IAHw==,aAA=\r\n",
    );
    const SPS: &[u8] = &[0x67, 0x42, 0x00, 0x1f];
    const PPS: &[u8] = &[0x68, 0x00];

    fn probe<'a>(manifest: &'a SiteManifest) -> Result<RtspProbeObserver<'a>, ObservationError> {
        let parameters = [SPS, PPS];
        RtspProbeObserver::new(manifest, 0, NegotiatedProbe {
            sdp: SDP.as_bytes(), media_index: 0, rtp_channel: 0, codec: ProbeCodec::Avc,
            payload_type: 96, parameter_sets: &parameters, server_identity: "fixture",
        })
    }
    fn packet(seq: u16, ts: u32, ssrc: u32, marker: bool) -> Vec<u8> {
        let mut bytes = vec![0x80, if marker { 0xe0 } else { 0x60 }];
        bytes.extend_from_slice(&seq.to_be_bytes());
        bytes.extend_from_slice(&ts.to_be_bytes());
        bytes.extend_from_slice(&ssrc.to_be_bytes());
        bytes.extend_from_slice(&[0x65, 0x00]);
        bytes
    }
    #[test]
    fn sequence_and_timestamp_wrap_yield_exact_receipt() -> Result<(), Box<dyn std::error::Error>> {
        let manifest = SiteManifest::parse(MANIFEST)?;
        let mut observer = probe(&manifest)?;
        let stamps = [0xffff_f000_u32, 0xffff_fe10, 0x0000_0c20, 0x0000_1a30];
        for (i, stamp) in stamps.into_iter().enumerate() {
            observer.observe_rtp(0, &packet((u16::MAX - 1).wrapping_add(i as u16), stamp, 0, true))?;
        }
        let receipt = observer.finish()?;
        assert_eq!(receipt.observed_frames, 4);
        assert_eq!(receipt.ssrc, 0);
        assert_eq!(receipt.frame_duration_ticks, 3600);
        assert_eq!(receipt.last_rtp_timestamp, stamps[3]);
        assert_eq!(receipt.parameter_set_digests, vec![ContentDigest::sha256(SPS), ContentDigest::sha256(PPS)]);
        receipt.validate_for(&manifest)?;
        Ok(())
    }
    #[test]
    fn gaps_foreign_sender_and_channels_refuse() -> Result<(), Box<dyn std::error::Error>> {
        let manifest = SiteManifest::parse(MANIFEST)?;
        let mut gap = probe(&manifest)?;
        gap.observe_rtp(0, &packet(1, 100, 7, true))?;
        assert_eq!(gap.observe_rtp(0, &packet(3, 3700, 7, true)), Err(ObservationError::Continuity));
        // A caller cannot ignore the error and resume to manufacture a valid receipt.
        assert_eq!(gap.observe_rtp(0, &packet(2, 3700, 7, true)), Err(ObservationError::Continuity));
        assert!(matches!(gap.finish(), Err(ObservationError::Continuity)));
        let mut switch = probe(&manifest)?;
        switch.observe_rtp(0, &packet(1, 100, 7, true))?;
        assert_eq!(switch.observe_rtp(0, &packet(2, 3700, 8, true)), Err(ObservationError::Continuity));
        assert_eq!(probe(&manifest)?.observe_rtp(2, &packet(1, 100, 7, true)), Err(ObservationError::Packet));
        Ok(())
    }
    #[test]
    fn drift_and_missing_markers_refuse() -> Result<(), Box<dyn std::error::Error>> {
        let manifest = SiteManifest::parse(MANIFEST)?;
        let mut incomplete = probe(&manifest)?;
        incomplete.observe_rtp(0, &packet(1, 100, 7, false))?;
        assert_eq!(incomplete.observe_rtp(0, &packet(2, 3700, 7, true)), Err(ObservationError::Continuity));
        assert!(matches!(incomplete.finish(), Err(ObservationError::Continuity)));
        let mut drift = probe(&manifest)?;
        drift.observe_rtp(0, &packet(1, 100, 7, true))?;
        drift.observe_rtp(0, &packet(2, 3700, 7, true))?;
        assert_eq!(drift.observe_rtp(0, &packet(3, 7500, 7, true)), Err(ObservationError::Cadence));
        Ok(())
    }
    #[test]
    fn nominated_sdp_parameter_bytes_are_checked() -> Result<(), Box<dyn std::error::Error>> {
        let manifest = SiteManifest::parse(MANIFEST)?;
        let bad = [0x67, 0x42, 0, 0x20];
        let params: [&[u8]; 2] = [&bad, PPS];
        assert!(matches!(RtspProbeObserver::new(&manifest, 0, NegotiatedProbe {
            sdp: SDP.as_bytes(), media_index: 0, rtp_channel: 0,
            codec: ProbeCodec::Avc, payload_type: 96,
            parameter_sets: &params, server_identity: "fixture",
        }), Err(ObservationError::Negotiation)));
        assert!(matches!(probe(&manifest)?.finish(), Err(ObservationError::Incomplete)));
        Ok(())
    }
}
