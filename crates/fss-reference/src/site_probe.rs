#![forbid(unsafe_code)]
//! Measured, bounded site probe receipts from supplied DESCRIBE and RTP evidence.
//!
//! This module performs no I/O. It reuses the native RTSP, rtpdump, RTP, codec
//! reconstruction and picture-boundary validators. An accepted receipt reports
//! observations in supplied bytes, not decoded completeness, a live camera,
//! authenticated origin, camera capture time, or source-custody certification.
//! The manifest's route and the interleaved channels are operator selections:
//! rtpdump does not contain a SETUP transaction or interleaved channel numbers.

mod description;
mod media;

#[cfg(test)]
mod tests;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_packet::{PacketLimits, RtcpCompound, RtpPacket, StreamKey};

use crate::ingest::rtpdump::{RtpDumpKind, RtpDumpLimits, RtpDumpReader};
use crate::site::{ProbeCodec, SiteManifest, SiteProbeReceipt, SourceKind};

/// Complete strict RTSP response ceiling, including headers and SDP body.
pub const MAX_DESCRIBE_RESPONSE_BYTES: usize = 128 * 1024;
/// Complete supplied rtptools file ceiling.
pub const MAX_PROBE_RTPDUMP_BYTES: usize = 8 * 1024 * 1024;
/// Maximum complete RTP/RTCP records examined, including discarded RTCP metadata.
pub const MAX_PROBE_RECORDS: usize = 32_768;
/// Maximum syntax-grouped picture timestamps in one measurement.
pub const MAX_MEASURED_PROBE_FRAMES: u32 = 4096;
/// Two equal consecutive deltas require at least three observed pictures.
pub const MIN_MEASURED_PROBE_FRAMES: u32 = 3;

const POLICY: &str = "offline-measured-site-probe:v1:native-describe-and-picture-owners:\
strict-contiguous-single-stream:constant-rtp-cadence:all-bytes-or-refuse:\
operator-route-and-channels:no-origin-authentication:no-liveness:no-custody:\
no-decoded-completeness:no-clock-trust";
const JPEG_POLICY: &str = "offline-measured-site-probe-jpeg:v1:native-describe-and-rfc2435-owner:\
complete-transport-images:strict-contiguous-single-stream:constant-rtp-cadence:\
all-bytes-or-refuse:operator-route-and-channels:no-origin-authentication:\
no-liveness:no-custody:no-entropy-validation:no-decoded-completeness:no-clock-trust";

/// Explicit media choice; the payload is selected only if the native SDP owner finds one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeSelection {
    /// AVC, HEVC or RFC 2435 JPEG, using the existing native picture/reconstruction owners.
    pub codec: ProbeCodec,
    /// Exact source SDP media section, from 0 through 63.
    pub media_index: usize,
    /// Proposed even RTP channel. Not measured from the supplied rtpdump.
    pub rtp_channel: u8,
}

/// Payload-free, path-free refusal. A valid prefix never produces a partial receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiteProbeError {
    /// Input bytes, records, pictures or another hard bound were exceeded.
    Limit,
    /// A public typed manifest failed its canonical validation.
    Manifest,
    /// The selected source does not exist.
    Source,
    /// The selected source requires a separate ONVIF or UniFi route acquisition.
    SourceKind,
    /// Unsupported codec, media index, or interleaved channel selection.
    Selection,
    /// Strict response framing, native SDP negotiation or URI scope failed.
    Description,
    /// Server header was duplicated or empty; no first/last-wins identity is admitted.
    ServerHeader,
    /// rtpdump framing was malformed, truncated or captured only a datagram prefix.
    RtpDump,
    /// RTP or RTCP framing was malformed.
    Packet,
    /// Packet sequence was lost, duplicated, reordered, or restarted.
    Sequence,
    /// More than one SSRC or payload type occurred in the selected evidence.
    StreamChanged,
    /// Codec syntax or reconstruction could not be admitted by its native owner.
    Codec,
    /// A parameter set changed or a picture referenced a different configuration.
    ParameterChange,
    /// A native syntax-grouped picture lacked its required first slice or had a discontinuity.
    Picture,
    /// An unfinished fragment or picture lacked a trustworthy syntax boundary at EOF.
    IncompletePicture,
    /// Picture timestamps were repeated, reversed, variable or outside the admitted cadence.
    Cadence,
    /// The evidence had too few syntax-grouped pictures to measure two equal deltas.
    InsufficientPictures,
    /// A canonical evidence identity could not be constructed.
    Encoding,
}

impl SiteProbeError {
    /// Stable machine identity without untrusted values.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Limit => "ERR-SITE-PROBE-LIMIT-001",
            Self::Manifest | Self::Source | Self::SourceKind | Self::Selection => {
                "ERR-SITE-PROBE-SELECTION-001"
            }
            Self::Description | Self::ServerHeader => "ERR-SITE-PROBE-DESCRIPTION-001",
            Self::RtpDump | Self::Packet => "ERR-SITE-PROBE-PACKET-001",
            Self::Sequence | Self::StreamChanged => "ERR-SITE-PROBE-CONTINUITY-001",
            Self::Codec | Self::ParameterChange | Self::Picture | Self::IncompletePicture => {
                "ERR-SITE-PROBE-PICTURE-001"
            }
            Self::Cadence | Self::InsufficientPictures => "ERR-SITE-PROBE-CADENCE-001",
            Self::Encoding => "ERR-SITE-PROBE-ENCODING-001",
        }
    }

    /// Static explanation safe to show without exposing media, tokens or paths.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Limit => "bounded probe evidence limit exceeded",
            Self::Manifest => "manifest validation failed",
            Self::Source => "selected source is absent from the manifest",
            Self::SourceKind => "only explicit RTSP and NVR channel sources are supported",
            Self::Selection => "unsupported or invalid explicit media selection",
            Self::Description => "DESCRIBE evidence failed native framing, SDP or route admission",
            Self::ServerHeader => "server identity header is ambiguous or empty",
            Self::RtpDump => "rtpdump evidence is malformed, truncated or capture-limited",
            Self::Packet => "RTP or RTCP evidence failed native packet validation",
            Self::Sequence => "RTP packet sequence is not exactly consecutive",
            Self::StreamChanged => "RTP sender or selected payload changed",
            Self::Codec => "codec evidence failed native reconstruction or syntax admission",
            Self::ParameterChange => "media configuration changed within the probe evidence",
            Self::Picture => "picture lacks its first slice or has a known discontinuity",
            Self::IncompletePicture => {
                "evidence ends with an unfinished fragment or unverified picture"
            }
            Self::Cadence => {
                "consecutive picture timestamps do not have one positive fixed cadence"
            }
            Self::InsufficientPictures => "at least three syntax-grouped pictures are required",
            Self::Encoding => "canonical probe evidence encoding failed",
        }
    }
}

impl std::fmt::Display for SiteProbeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.reason())
    }
}
impl std::error::Error for SiteProbeError {}

/// Immutable measurements with a companion identity binding every supplied source byte.
#[derive(Clone, Eq, PartialEq)]
pub struct MeasuredProbe {
    receipt: SiteProbeReceipt,
    evidence_digest: ContentDigest,
    describe_digest: ContentDigest,
    rtp_dump_digest: ContentDigest,
    server_header_digest: Option<ContentDigest>,
    rtp_packets: u32,
    rtcp_packets: u32,
}

impl std::fmt::Debug for MeasuredProbe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MeasuredProbe")
            .field("evidence_digest", &self.evidence_digest)
            .field("codec", &self.receipt.codec)
            .field("observed_frames", &self.receipt.observed_frames)
            .field("rtp_packets", &self.rtp_packets)
            .field("rtcp_packets", &self.rtcp_packets)
            .finish_non_exhaustive()
    }
}

impl MeasuredProbe {
    /// Canonical site receipt; provenance limitations remain those documented by this module.
    #[must_use]
    pub fn receipt(&self) -> &SiteProbeReceipt {
        &self.receipt
    }
    /// Domain-separated binding of raw inputs, selection, manifest, policy and measurements.
    #[must_use]
    pub const fn evidence_digest(&self) -> ContentDigest {
        self.evidence_digest
    }
    /// SHA-256 of the complete supplied response, including every original header byte.
    #[must_use]
    pub const fn describe_digest(&self) -> ContentDigest {
        self.describe_digest
    }
    /// SHA-256 of the complete supplied rtpdump, including its untrusted recording metadata.
    #[must_use]
    pub const fn rtp_dump_digest(&self) -> ContentDigest {
        self.rtp_dump_digest
    }
    /// SHA-256 of the parsed, trimmed Server header value, if supplied; never authentication.
    #[must_use]
    pub const fn server_header_digest(&self) -> Option<ContentDigest> {
        self.server_header_digest
    }
    /// Number of complete validated RTP datagrams, including codec metadata packets.
    #[must_use]
    pub const fn rtp_packets(&self) -> u32 {
        self.rtp_packets
    }
    /// Number of validated RTCP datagrams; no clock assertions are admitted from them.
    #[must_use]
    pub const fn rtcp_packets(&self) -> u32 {
        self.rtcp_packets
    }
}

/// Measure one manifest source from exact supplied response and rtptools file bytes.
///
/// No file, credential, network target, ambient clock or external state is accessed.
/// Every packet is checked; a bad suffix invalidates the whole result. Native
/// codec syntax establishes picture groups before RTP timestamps are compared.
/// RTP marker bits alone never become picture observations or completeness claims.
pub fn measure_probe(
    manifest: &SiteManifest,
    source_id: &str,
    selection: &ProbeSelection,
    describe_response: &[u8],
    rtp_dump: &[u8],
) -> Result<MeasuredProbe, SiteProbeError> {
    if describe_response.is_empty()
        || describe_response.len() > MAX_DESCRIBE_RESPONSE_BYTES
        || rtp_dump.is_empty()
        || rtp_dump.len() > MAX_PROBE_RTPDUMP_BYTES
    {
        return Err(SiteProbeError::Limit);
    }
    let manifest_digest = manifest.digest().map_err(|_| SiteProbeError::Manifest)?;
    let source = manifest
        .sources
        .iter()
        .find(|source| source.source_id == source_id)
        .ok_or(SiteProbeError::Source)?;
    if !matches!(source.kind, SourceKind::Rtsp | SourceKind::NvrChannel) {
        return Err(SiteProbeError::SourceKind);
    }
    if selection.media_index > 63
        || selection.rtp_channel % 2 != 0
        || selection.rtp_channel.checked_add(1).is_none()
    {
        return Err(SiteProbeError::Selection);
    }
    let description = description::inspect(source, selection, describe_response)?;
    let prepared = media::PreparedMedia::new(description.media)?;
    let parameter_set_digests = prepared.parameter_set_digests();
    let payload_type = prepared.payload_type();
    let rtcp_mode = prepared.rtcp_mode();
    let mut prepared = Some(prepared);
    let describe_digest = ContentDigest::sha256(describe_response);
    let rtp_dump_digest = ContentDigest::sha256(rtp_dump);
    let mut stream_encoding = CanonicalEncoder::new();
    stream_encoding.text("fss.site_probe_stream.v1");
    stream_encoding.digest(manifest_digest);
    stream_encoding.text(source_id);
    stream_encoding.digest(describe_digest);
    stream_encoding.digest(rtp_dump_digest);
    let stream_digest = encoded_digest(stream_encoding)?;
    let mut ingress_bytes = [0; 16];
    ingress_bytes.copy_from_slice(&stream_digest.bytes()[..16]);
    let ingress = u128::from_be_bytes(ingress_bytes);
    if ingress == 0 {
        return Err(SiteProbeError::Encoding);
    }

    let mut reader = RtpDumpReader::new(
        rtp_dump,
        RtpDumpLimits {
            max_input_bytes: MAX_PROBE_RTPDUMP_BYTES,
            max_records: MAX_PROBE_RECORDS,
            max_packet_bytes: 65_527,
        },
    )
    .map_err(|_| SiteProbeError::RtpDump)?;
    let mut observer: Option<media::MediaObserver> = None;
    let mut key = None;
    let mut sequence = None;
    let mut cadence = Cadence::default();
    let mut rtp_packets = 0u32;
    let mut rtcp_packets = 0u32;
    // This is a bounded local work counter, not recorded or camera time. File offset
    // metadata never changes fragment deadlines or becomes an inferred clock basis.
    let mut step = 0u64;
    while let Some(record) = reader.next_record().map_err(|_| SiteProbeError::RtpDump)? {
        step += 1;
        match record.kind() {
            RtpDumpKind::CapturedPrefix => return Err(SiteProbeError::RtpDump),
            RtpDumpKind::Rtcp => {
                RtcpCompound::parse(record.packet(), PacketLimits::default(), rtcp_mode)
                    .map_err(|_| SiteProbeError::Packet)?;
                rtcp_packets += 1;
            }
            RtpDumpKind::Rtp => {
                let packet = RtpPacket::parse(record.packet(), PacketLimits::default())
                    .map_err(|_| SiteProbeError::Packet)?;
                if packet.payload_type() != payload_type
                    || key.is_some_and(|key: StreamKey| key.ssrc != packet.ssrc())
                {
                    return Err(SiteProbeError::StreamChanged);
                }
                let extended = if let Some(prior) = sequence {
                    let next = prior + 1;
                    if packet.sequence() != next as u16 {
                        return Err(SiteProbeError::Sequence);
                    }
                    next
                } else {
                    u64::from(packet.sequence())
                };
                sequence = Some(extended);
                if observer.is_none() {
                    let observed_key = StreamKey {
                        ingress,
                        generation: source.generation,
                        ssrc: packet.ssrc(),
                    };
                    observer = Some(
                        prepared
                            .take()
                            .ok_or(SiteProbeError::Codec)?
                            .start(observed_key)?,
                    );
                    key = Some(observed_key);
                }
                observer.as_mut().ok_or(SiteProbeError::Codec)?.push(
                    extended,
                    packet,
                    step,
                    &mut cadence,
                )?;
                rtp_packets += 1;
            }
        }
    }
    observer
        .as_mut()
        .ok_or(SiteProbeError::InsufficientPictures)?
        .finish(step, &mut cadence)?;
    let (observed_frames, first_rtp_timestamp, last_rtp_timestamp, frame_duration_ticks) =
        cadence.finish()?;
    let server_identity = description.server_header_digest.map_or_else(
        || "unknown:server-not-reported".to_string(),
        |digest| format!("server-header:{digest}"),
    );
    let receipt = SiteProbeReceipt {
        site_id: manifest.site_id.clone(),
        source_id: source.source_id.clone(),
        manifest_digest,
        source_generation: source.generation,
        peer: source.peer,
        authority: source.authority.clone(),
        presentation: source
            .presentation
            .clone()
            .ok_or(SiteProbeError::Manifest)?,
        control_root: source
            .control_root
            .clone()
            .ok_or(SiteProbeError::Manifest)?,
        media_index: selection.media_index,
        rtp_channel: selection.rtp_channel,
        rtcp_channel: selection.rtp_channel + 1,
        sdp_digest: description.sdp_digest,
        codec: selection.codec,
        payload_type,
        ssrc: key.ok_or(SiteProbeError::InsufficientPictures)?.ssrc,
        frame_duration_ticks,
        clock_rate_hz: 90_000,
        observed_frames,
        first_rtp_timestamp,
        last_rtp_timestamp,
        parameter_set_digests,
        server_identity,
    };
    receipt
        .validate_for(manifest)
        .map_err(|_| SiteProbeError::Encoding)?;
    let mut evidence = CanonicalEncoder::new();
    evidence.text("fss.site_measured_probe.v1");
    evidence.text(if selection.codec == ProbeCodec::Jpeg {
        JPEG_POLICY
    } else {
        POLICY
    });
    evidence.digest(manifest_digest);
    evidence.text(source_id);
    evidence.digest(describe_digest);
    evidence.digest(rtp_dump_digest);
    evidence.text(selection.codec.as_str());
    evidence.u64(selection.media_index as u64);
    evidence.u8(selection.rtp_channel);
    evidence.digest(receipt.digest().map_err(|_| SiteProbeError::Encoding)?);
    evidence.bool(description.server_header_digest.is_some());
    if let Some(digest) = description.server_header_digest {
        evidence.digest(digest);
    }
    evidence.u32(rtp_packets);
    evidence.u32(rtcp_packets);
    evidence.u64(MAX_DESCRIBE_RESPONSE_BYTES as u64);
    evidence.u64(MAX_PROBE_RTPDUMP_BYTES as u64);
    evidence.u64(MAX_PROBE_RECORDS as u64);
    evidence.u32(MAX_MEASURED_PROBE_FRAMES);
    evidence.u32(MIN_MEASURED_PROBE_FRAMES);
    if selection.codec == ProbeCodec::Jpeg {
        // Preserve all existing AVC/HEVC identities while binding this newly
        // admitted reconstruction contract and every native per-image bound.
        let limits = fss_packet::jpeg::JpegLimits::default();
        evidence.text(fss_packet::jpeg::JPEG_RECONSTRUCTION_PROFILE);
        evidence.u64(limits.max_frame_bytes as u64);
        evidence.u64(limits.max_fragment_packets as u64);
        evidence.u64(limits.max_pending_age_ns);
        evidence.u64(limits.max_cached_quantizers as u64);
        evidence.u32(u32::from(limits.max_dimension));
    }
    Ok(MeasuredProbe {
        receipt,
        evidence_digest: encoded_digest(evidence)?,
        describe_digest,
        rtp_dump_digest,
        server_header_digest: description.server_header_digest,
        rtp_packets,
        rtcp_packets,
    })
}

fn encoded_digest(encoding: CanonicalEncoder) -> Result<ContentDigest, SiteProbeError> {
    encoding
        .finish_checked()
        .map(|bytes| ContentDigest::sha256(&bytes))
        .map_err(|_| SiteProbeError::Encoding)
}

#[derive(Default)]
struct Cadence {
    frames: u32,
    first: Option<u32>,
    last: Option<u32>,
    ticks: Option<u32>,
}

impl Cadence {
    fn observe(&mut self, timestamp: u32) -> Result<(), SiteProbeError> {
        if self.frames == MAX_MEASURED_PROBE_FRAMES {
            return Err(SiteProbeError::Limit);
        }
        if let Some(previous) = self.last {
            let delta = timestamp.wrapping_sub(previous);
            if !(1..=90_000).contains(&delta) || self.ticks.is_some_and(|ticks| ticks != delta) {
                return Err(SiteProbeError::Cadence);
            }
            self.ticks = Some(delta);
        }
        self.first = self.first.or(Some(timestamp));
        self.last = Some(timestamp);
        self.frames += 1;
        Ok(())
    }

    fn finish(self) -> Result<(u32, u32, u32, u32), SiteProbeError> {
        if self.frames < MIN_MEASURED_PROBE_FRAMES {
            return Err(SiteProbeError::InsufficientPictures);
        }
        Ok((
            self.frames,
            self.first.ok_or(SiteProbeError::InsufficientPictures)?,
            self.last.ok_or(SiteProbeError::InsufficientPictures)?,
            self.ticks.ok_or(SiteProbeError::InsufficientPictures)?,
        ))
    }
}
