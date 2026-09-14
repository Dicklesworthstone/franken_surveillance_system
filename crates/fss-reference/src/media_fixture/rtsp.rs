#![forbid(unsafe_code)]
//! Deterministic synthetic RTSP/1.0 interleaved-TCP session transcript generator.
//!
//! Generates recorded client/server exchange transcripts in a documented container
//! format for testing sans-IO RTSP parsers and session drivers without sockets.
//!
//! Container format:
//! - Magic header: `#!fss-rtsp-transcript v1\n`
//! - Records:
//!   - `direction`: `u8` (0 = Client-to-Server / C2S, 1 = Server-to-Client / S2C)
//!   - `offset_ms`: `u32` (big-endian)
//!   - `len`: `u32` (big-endian)
//!   - `bytes`: raw payload of length `len`
//!
//! Variants:
//! - `clean`: standard complete exchange (OPTIONS, DESCRIBE with SDP, SETUP, PLAY,
//!   interleaved RTP/RTCP on channels 0 and 1, TEARDOWN)
//! - `auth_required`: server answers 401 with WWW-Authenticate challenge; transcript ends
//! - `interleave_split`: an interleaved media frame split across consecutive S2C records
//! - `bad_content_length`: DESCRIBE response carries non-numeric Content-Length
//! - `session_timeout_header`: SETUP response carries `timeout=30` in Session header
//! - `rtcp_rsize`: SDP advertises `a=rtcp-rsize`, and channel 1 carries reduced-size SRs
//! - `sr_absent`: no RTCP SRs are sent on channel 1
//! - `get_parameter_keepalive`: includes C2S GET_PARAMETER keepalive exchange

use std::fmt;

use super::{
    ExpectedSequenceClass, MEDIA_FIXTURE_NOTE, MediaFixtureError, h264::H264AnnexBStream,
    rtpdump::RtpdumpPacketDesc,
};
use fss_core::ContentDigest;

/// Header line required for RTSP transcript container format.
pub const RTSP_TRANSCRIPT_MAGIC_HEADER: &[u8] = b"#!fss-rtsp-transcript v1\n";

/// Canonical default RTSP stream URI (using RFC 2606 .invalid TLD, zero credentials).
pub const DEFAULT_RTSP_STREAM_URI: &str = "rtsp://fixture.invalid/stream";

/// Default synthetic RTSP session identifier.
pub const DEFAULT_RTSP_SESSION_ID: &str = "12345678";

/// Synthetic RTCP SDES CNAME (RFC 2606 domain; no personal or network identity).
pub const DEFAULT_RTCP_CNAME: &str = "fss-fixture@fixture.invalid";

/// Default synthetic SSRC (matching rtpdump fixtures).
pub const DEFAULT_RTSP_SSRC: u32 = 0x1122_3344;

/// Default H.264 dynamic payload type.
pub const DEFAULT_RTSP_PAYLOAD_TYPE: u8 = 96;

/// Default RTP video clock rate in Hertz.
pub const DEFAULT_RTSP_CLOCK_RATE_HZ: u32 = 90_000;

/// Default initial RTP sequence number (65534 to test sequence wrap).
pub const DEFAULT_RTSP_INITIAL_SEQUENCE: u16 = 65_534;

/// Default maximum transmission unit for RTP packets.
pub const DEFAULT_RTSP_MTU: usize = 1200;

/// Direction of traffic in an RTSP transcript record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TranscriptDirection {
    /// Client-to-Server message.
    ClientToServer,
    /// Server-to-Client message or interleaved frame.
    ServerToClient,
}

impl TranscriptDirection {
    /// Wire byte representation (0 for C2S, 1 for S2C).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::ClientToServer => 0,
            Self::ServerToClient => 1,
        }
    }

    /// Canonical string identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientToServer => "C2S",
            Self::ServerToClient => "S2C",
        }
    }

    /// Parses wire byte back into direction variant.
    #[must_use]
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::ClientToServer),
            1 => Some(Self::ServerToClient),
            _ => None,
        }
    }
}

/// A single recorded record within an RTSP transcript container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptRecord {
    /// Traffic direction.
    pub direction: TranscriptDirection,
    /// Milliseconds offset from start of session.
    pub offset_ms: u32,
    /// Raw payload bytes of the record.
    pub bytes: Vec<u8>,
}

/// Parameters governing RTSP transcript synthesis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtspTranscriptParams {
    /// Negotiated synchronization source identifier (SSRC).
    pub ssrc: u32,
    /// Dynamic payload type number (96 for H.264).
    pub payload_type: u8,
    /// RTP clock rate in Hertz (90,000 for video).
    pub clock_rate_hz: u32,
    /// Seeded initial sequence number.
    pub initial_sequence: u16,
    /// Synthetic session identifier string.
    pub session_id: &'static str,
    /// Synthetic stream URI.
    pub stream_uri: &'static str,
    /// Maximum transmission unit size in bytes.
    pub mtu: usize,
    /// RTCP SDES canonical end-point identifier (CNAME).
    pub cname: &'static str,
}

impl Default for RtspTranscriptParams {
    fn default() -> Self {
        Self {
            ssrc: DEFAULT_RTSP_SSRC,
            payload_type: DEFAULT_RTSP_PAYLOAD_TYPE,
            clock_rate_hz: DEFAULT_RTSP_CLOCK_RATE_HZ,
            initial_sequence: DEFAULT_RTSP_INITIAL_SEQUENCE,
            session_id: DEFAULT_RTSP_SESSION_ID,
            stream_uri: DEFAULT_RTSP_STREAM_URI,
            mtu: DEFAULT_RTSP_MTU,
            cname: DEFAULT_RTCP_CNAME,
        }
    }
}

/// Metadata descriptor for an RTCP Sender Report within a transcript fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtspSenderReportDesc {
    /// Milliseconds offset from start of session.
    pub offset_ms: u32,
    /// Interleaved channel index (typically 1).
    pub channel: u8,
    /// Claimed synchronization source identifier.
    pub ssrc: u32,
    /// NTP timestamp integer seconds.
    pub ntp_seconds: u32,
    /// NTP timestamp fractional seconds.
    pub ntp_fraction: u32,
    /// Corresponding media-clock timestamp.
    pub rtp_timestamp: u32,
    /// Sender packet counter.
    pub packet_count: u32,
    /// Sender payload-octet counter.
    pub octet_count: u32,
    /// True if packet is a compound SR+SDES packet.
    pub is_compound: bool,
    /// CNAME item if present.
    pub cname: Option<String>,
}

/// Complete synthesized RTSP transcript fixture with raw bytes and verified manifest metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtspTranscriptFixture {
    /// Canonical variant name ("clean", "auth_required", etc.).
    pub variant_name: &'static str,
    /// Filename without path (e.g. "clean.transcript").
    pub filename: String,
    /// Complete raw file bytes including magic header and all records.
    pub bytes: Vec<u8>,
    /// Deserialized individual records.
    pub records: Vec<TranscriptRecord>,
    /// Metadata descriptors for each interleaved RTP packet.
    pub packets: Vec<RtpdumpPacketDesc>,
    /// Metadata descriptors for each interleaved RTCP sender report.
    pub sender_reports: Vec<RtspSenderReportDesc>,
    /// Hex-encoded SHA-256 digest of the complete file bytes.
    pub sha256: String,
}

/// Serializes transcript records into standard container bytes.
#[must_use]
pub fn serialize_transcript(records: &[TranscriptRecord]) -> Vec<u8> {
    let mut total_len = RTSP_TRANSCRIPT_MAGIC_HEADER.len();
    for r in records {
        total_len += 1 + 4 + 4 + r.bytes.len();
    }
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(RTSP_TRANSCRIPT_MAGIC_HEADER);
    for r in records {
        out.push(r.direction.as_u8());
        out.extend_from_slice(&r.offset_ms.to_be_bytes());
        out.extend_from_slice(&(r.bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&r.bytes);
    }
    out
}

/// Parses raw container bytes into typed transcript records.
pub fn parse_transcript(data: &[u8]) -> Result<Vec<TranscriptRecord>, MediaFixtureError> {
    if data.len() < RTSP_TRANSCRIPT_MAGIC_HEADER.len()
        || &data[..RTSP_TRANSCRIPT_MAGIC_HEADER.len()] != RTSP_TRANSCRIPT_MAGIC_HEADER
    {
        return Err(MediaFixtureError::InvalidParam(
            "invalid or missing transcript magic header",
        ));
    }
    let mut pos = RTSP_TRANSCRIPT_MAGIC_HEADER.len();
    let mut records = Vec::new();

    while pos < data.len() {
        if pos + 9 > data.len() {
            return Err(MediaFixtureError::TruncatedData);
        }
        let dir_byte = data[pos];
        let direction = TranscriptDirection::from_u8(dir_byte).ok_or(
            MediaFixtureError::InvalidParam("unknown transcript direction byte"),
        )?;
        let offset_ms =
            u32::from_be_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]]);
        let len = u32::from_be_bytes([data[pos + 5], data[pos + 6], data[pos + 7], data[pos + 8]])
            as usize;
        pos += 9;

        if pos + len > data.len() {
            return Err(MediaFixtureError::TruncatedData);
        }
        let bytes = data[pos..pos + len].to_vec();
        pos += len;

        records.push(TranscriptRecord {
            direction,
            offset_ms,
            bytes,
        });
    }

    Ok(records)
}

/// Encapsulates a payload into an RTSP interleaved binary frame (`$` prefix).
#[must_use]
pub fn encode_interleaved_frame(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.push(b'$');
    frame.push(channel);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Serializes an RFC 3550 RTCP Sender Report (SR) packet with zero report blocks (28 bytes).
#[must_use]
pub fn build_rtcp_sender_report(
    ssrc: u32,
    ntp_seconds: u32,
    ntp_fraction: u32,
    rtp_timestamp: u32,
    packet_count: u32,
    octet_count: u32,
) -> Vec<u8> {
    let mut sr = Vec::with_capacity(28);
    // Byte 0: V=2, P=0, RC=0 -> 0x80
    sr.push(0x80);
    // Byte 1: PT=200 (SR)
    sr.push(200);
    // Bytes 2..4: length in 32-bit words minus 1 = 7 - 1 = 6
    sr.extend_from_slice(&6u16.to_be_bytes());
    // Bytes 4..8: SSRC
    sr.extend_from_slice(&ssrc.to_be_bytes());
    // Bytes 8..12: NTP seconds
    sr.extend_from_slice(&ntp_seconds.to_be_bytes());
    // Bytes 12..16: NTP fraction
    sr.extend_from_slice(&ntp_fraction.to_be_bytes());
    // Bytes 16..20: RTP timestamp
    sr.extend_from_slice(&rtp_timestamp.to_be_bytes());
    // Bytes 20..24: sender's packet count
    sr.extend_from_slice(&packet_count.to_be_bytes());
    // Bytes 24..28: sender's octet count
    sr.extend_from_slice(&octet_count.to_be_bytes());
    sr
}

/// Serializes an RFC 3550 RTCP SDES packet containing a single chunk with a CNAME item.
#[must_use]
pub fn build_rtcp_sdes_cname(ssrc: u32, cname: &str) -> Vec<u8> {
    let cname_bytes = cname.as_bytes();
    let unpadded_len = 4 + 1 + 1 + cname_bytes.len() + 1;
    let padded_len = (unpadded_len + 3) & !3;
    let pad_count = padded_len - unpadded_len;

    let mut body = Vec::with_capacity(padded_len);
    body.extend_from_slice(&ssrc.to_be_bytes());
    body.push(1); // CNAME item type
    body.push(cname_bytes.len() as u8);
    body.extend_from_slice(cname_bytes);
    body.push(0); // null item terminator
    for _ in 0..pad_count {
        body.push(0);
    }

    let mut sdes = Vec::with_capacity(4 + body.len());
    // Byte 0: V=2, P=0, SC=1 (1 chunk) -> 0x81
    sdes.push(0x81);
    // Byte 1: PT=202 (SDES)
    sdes.push(202);
    // Bytes 2..4: length in 32-bit words minus 1 = (4 + body.len()) / 4 - 1 = body.len() / 4
    let word_len = (body.len() / 4) as u16;
    sdes.extend_from_slice(&word_len.to_be_bytes());
    sdes.extend_from_slice(&body);
    sdes
}

/// Serializes a compound RTCP packet (SR followed by SDES CNAME).
#[must_use]
pub fn build_compound_rtcp_sr(
    ssrc: u32,
    ntp_seconds: u32,
    ntp_fraction: u32,
    rtp_timestamp: u32,
    packet_count: u32,
    octet_count: u32,
    cname: &str,
) -> Vec<u8> {
    let mut compound = build_rtcp_sender_report(
        ssrc,
        ntp_seconds,
        ntp_fraction,
        rtp_timestamp,
        packet_count,
        octet_count,
    );
    let sdes = build_rtcp_sdes_cname(ssrc, cname);
    compound.extend_from_slice(&sdes);
    compound
}

/// First-party deterministic standard Base64 encoder for SDP sprop parameter sets.
#[must_use]
pub fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Builds an SDP body matching the synthetic session parameters.
fn build_sdp(params: &RtspTranscriptParams, sps_b64: &str, pps_b64: &str, rsize: bool) -> String {
    let mut sdp = String::new();
    sdp.push_str("v=0\r\n");
    sdp.push_str("o=- 0 0 IN IP4 fixture.invalid\r\n");
    sdp.push_str("s=FSS Synthetic RTSP Session\r\n");
    sdp.push_str("c=IN IP4 fixture.invalid\r\n");
    sdp.push_str("t=0 0\r\n");
    sdp.push_str(&format!("m=video 0 RTP/AVP {}\r\n", params.payload_type));
    sdp.push_str(&format!(
        "a=rtpmap:{} H264/{}\r\n",
        params.payload_type, params.clock_rate_hz
    ));
    sdp.push_str(&format!(
        "a=fmtp:{} packetization-mode=1;sprop-parameter-sets={},{}\r\n",
        params.payload_type, sps_b64, pps_b64
    ));
    sdp.push_str("a=control:trackID=1\r\n");
    if rsize {
        sdp.push_str("a=rtcp-rsize\r\n");
    }
    sdp
}

/// Helper to extract raw RTP wire datagrams and descriptors from clean rtpdump fixture.
fn extract_clean_rtp_packets(
    annexb: &H264AnnexBStream,
    params: &RtspTranscriptParams,
) -> Result<Vec<(Vec<u8>, RtpdumpPacketDesc)>, MediaFixtureError> {
    use super::rtpdump::{
        RD_HDR_LEN, RD_PKT_HDR_LEN, RTPDUMP_MAGIC_HEADER, RtpdumpParams, generate_rtpdump_clean,
    };

    let rtp_params = RtpdumpParams {
        ssrc: params.ssrc,
        payload_type: params.payload_type,
        clock_rate_hz: params.clock_rate_hz,
        initial_sequence: params.initial_sequence,
        mtu: params.mtu,
    };
    let clean = generate_rtpdump_clean(annexb, &rtp_params)?;

    let mut offset = RTPDUMP_MAGIC_HEADER.len() + RD_HDR_LEN;
    let mut packets = Vec::with_capacity(clean.packets.len());

    for desc in clean.packets {
        if offset + RD_PKT_HDR_LEN > clean.bytes.len() {
            return Err(MediaFixtureError::TruncatedData);
        }
        let record_len =
            u16::from_be_bytes([clean.bytes[offset], clean.bytes[offset + 1]]) as usize;
        let plen = u16::from_be_bytes([clean.bytes[offset + 2], clean.bytes[offset + 3]]) as usize;
        let wire_start = offset + RD_PKT_HDR_LEN;
        let wire_end = wire_start + plen;
        if wire_end > clean.bytes.len() {
            return Err(MediaFixtureError::TruncatedData);
        }
        let wire_bytes = clean.bytes[wire_start..wire_end].to_vec();
        packets.push((wire_bytes, desc));
        offset += record_len;
    }

    Ok(packets)
}

/// Extracts SPS and PPS Base64 strings from Annex-B stream.
fn extract_sps_pps_b64(annexb: &H264AnnexBStream) -> Result<(String, String), MediaFixtureError> {
    let sps = annexb
        .nals
        .iter()
        .find(|n| n.nal_unit_type == 7)
        .ok_or(MediaFixtureError::InvalidParam("Annex-B missing SPS"))?;
    let pps = annexb
        .nals
        .iter()
        .find(|n| n.nal_unit_type == 8)
        .ok_or(MediaFixtureError::InvalidParam("Annex-B missing PPS"))?;
    Ok((
        encode_base64(&sps.wire_bytes),
        encode_base64(&pps.wire_bytes),
    ))
}

/// Finalizes a fixture by serializing records, computing digest, and packing metadata.
fn finalize_fixture(
    variant_name: &'static str,
    records: Vec<TranscriptRecord>,
    packets: Vec<RtpdumpPacketDesc>,
    sender_reports: Vec<RtspSenderReportDesc>,
) -> RtspTranscriptFixture {
    let bytes = serialize_transcript(&records);
    let digest = ContentDigest::sha256(&bytes);
    let mut sha256 = String::with_capacity(64);
    for b in digest.bytes() {
        use std::fmt::Write;
        let _ = write!(sha256, "{:02x}", b);
    }

    RtspTranscriptFixture {
        variant_name,
        filename: format!("{variant_name}.transcript"),
        bytes,
        records,
        packets,
        sender_reports,
        sha256,
    }
}

/// Generates the standard `clean.transcript` fixture.
pub fn generate_transcript_clean(
    annexb: &H264AnnexBStream,
    params: &RtspTranscriptParams,
) -> Result<RtspTranscriptFixture, MediaFixtureError> {
    let (sps_b64, pps_b64) = extract_sps_pps_b64(annexb)?;
    let sdp = build_sdp(params, &sps_b64, &pps_b64, false);
    let rtp_packets = extract_clean_rtp_packets(annexb, params)?;

    let mut records = Vec::new();
    let uri = params.stream_uri;
    let sid = params.session_id;

    // 1. OPTIONS exchange
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ClientToServer,
        offset_ms: 0,
        bytes: format!("OPTIONS {uri} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: FSS-Reference\r\n\r\n")
            .into_bytes(),
    });
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 0,
        bytes: b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n"
            .to_vec(),
    });

    // 2. DESCRIBE exchange
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ClientToServer,
        offset_ms: 0,
        bytes: format!("DESCRIBE {uri} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n")
            .into_bytes(),
    });
    let sdp_len = sdp.len();
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 0,
        bytes: format!(
            "RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\nContent-Base: {uri}/\r\nContent-Length: {sdp_len}\r\n\r\n{sdp}"
        )
        .into_bytes(),
    });

    // 3. SETUP exchange
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ClientToServer,
        offset_ms: 0,
        bytes: format!(
            "SETUP {uri}/trackID=1 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n"
        )
        .into_bytes(),
    });
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 0,
        bytes: format!(
            "RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: {sid};timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n"
        )
        .into_bytes(),
    });

    // 4. PLAY exchange
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ClientToServer,
        offset_ms: 0,
        bytes: format!("PLAY {uri} RTSP/1.0\r\nCSeq: 4\r\nSession: {sid}\r\nRange: npt=0-\r\n\r\n")
            .into_bytes(),
    });
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 0,
        bytes: format!(
            "RTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: {sid}\r\nRTP-Info: url={uri}/trackID=1;seq={};rtptime={}\r\n\r\n",
            params.initial_sequence, 90_000
        )
        .into_bytes(),
    });

    // 5. Interleaved media frames (channel 0 RTP, channel 1 RTCP)
    let mut sender_reports = Vec::new();
    let mut packet_descs = Vec::with_capacity(rtp_packets.len());

    // SR 0 at offset 0 ms
    let sr0_bytes =
        build_compound_rtcp_sr(params.ssrc, 3_900_000_000, 0, 90_000, 0, 0, params.cname);
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 0,
        bytes: encode_interleaved_frame(1, &sr0_bytes),
    });
    sender_reports.push(RtspSenderReportDesc {
        offset_ms: 0,
        channel: 1,
        ssrc: params.ssrc,
        ntp_seconds: 3_900_000_000,
        ntp_fraction: 0,
        rtp_timestamp: 90_000,
        packet_count: 0,
        octet_count: 0,
        is_compound: true,
        cname: Some(params.cname.to_string()),
    });

    for (idx, (wire, desc)) in rtp_packets.into_iter().enumerate() {
        // Send SR 1 at offset 66 ms (before AU2 / packet index 9)
        if idx == 9 {
            let sr1_bytes = build_compound_rtcp_sr(
                params.ssrc,
                3_900_000_000,
                283_467_841,
                96_000,
                9,
                2199,
                params.cname,
            );
            records.push(TranscriptRecord {
                direction: TranscriptDirection::ServerToClient,
                offset_ms: 66,
                bytes: encode_interleaved_frame(1, &sr1_bytes),
            });
            sender_reports.push(RtspSenderReportDesc {
                offset_ms: 66,
                channel: 1,
                ssrc: params.ssrc,
                ntp_seconds: 3_900_000_000,
                ntp_fraction: 283_467_841,
                rtp_timestamp: 96_000,
                packet_count: 9,
                octet_count: 2199,
                is_compound: true,
                cname: Some(params.cname.to_string()),
            });
        }

        records.push(TranscriptRecord {
            direction: TranscriptDirection::ServerToClient,
            offset_ms: desc.offset_ms,
            bytes: encode_interleaved_frame(0, &wire),
        });
        packet_descs.push(desc);
    }

    // SR 2 at offset 132 ms (after final AU4 packets)
    let sr2_bytes = build_compound_rtcp_sr(
        params.ssrc,
        3_900_000_000,
        566_935_683,
        102_000,
        15,
        3504,
        params.cname,
    );
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 132,
        bytes: encode_interleaved_frame(1, &sr2_bytes),
    });
    sender_reports.push(RtspSenderReportDesc {
        offset_ms: 132,
        channel: 1,
        ssrc: params.ssrc,
        ntp_seconds: 3_900_000_000,
        ntp_fraction: 566_935_683,
        rtp_timestamp: 102_000,
        packet_count: 15,
        octet_count: 3504,
        is_compound: true,
        cname: Some(params.cname.to_string()),
    });

    // 6. TEARDOWN exchange
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ClientToServer,
        offset_ms: 150,
        bytes: format!("TEARDOWN {uri} RTSP/1.0\r\nCSeq: 5\r\nSession: {sid}\r\n\r\n").into_bytes(),
    });
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 150,
        bytes: format!("RTSP/1.0 200 OK\r\nCSeq: 5\r\nSession: {sid}\r\n\r\n").into_bytes(),
    });

    Ok(finalize_fixture(
        "clean",
        records,
        packet_descs,
        sender_reports,
    ))
}

/// Generates the `auth_required.transcript` fixture.
pub fn generate_transcript_auth_required(
    params: &RtspTranscriptParams,
) -> Result<RtspTranscriptFixture, MediaFixtureError> {
    let uri = params.stream_uri;
    let mut records = Vec::new();

    records.push(TranscriptRecord {
        direction: TranscriptDirection::ClientToServer,
        offset_ms: 0,
        bytes: format!("OPTIONS {uri} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: FSS-Reference\r\n\r\n")
            .into_bytes(),
    });
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 0,
        bytes: b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"fixture.invalid\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"\r\n\r\n".to_vec(),
    });

    Ok(finalize_fixture(
        "auth_required",
        records,
        Vec::new(),
        Vec::new(),
    ))
}

/// Generates the `interleave_split.transcript` fixture where a large frame is split across records.
pub fn generate_transcript_interleave_split(
    annexb: &H264AnnexBStream,
    params: &RtspTranscriptParams,
) -> Result<RtspTranscriptFixture, MediaFixtureError> {
    let clean = generate_transcript_clean(annexb, params)?;
    let mut split_records = Vec::with_capacity(clean.records.len() + 1);

    for r in clean.records {
        // Target packet 4 (the 1200-byte FU-A frame with total 1204 bytes on channel 0)
        if r.direction == TranscriptDirection::ServerToClient
            && r.bytes.len() == 1204
            && r.bytes.starts_with(b"$\x00")
        {
            let split_pos = 600;
            split_records.push(TranscriptRecord {
                direction: TranscriptDirection::ServerToClient,
                offset_ms: r.offset_ms,
                bytes: r.bytes[..split_pos].to_vec(),
            });
            split_records.push(TranscriptRecord {
                direction: TranscriptDirection::ServerToClient,
                offset_ms: r.offset_ms,
                bytes: r.bytes[split_pos..].to_vec(),
            });
        } else {
            split_records.push(r);
        }
    }

    Ok(finalize_fixture(
        "interleave_split",
        split_records,
        clean.packets,
        clean.sender_reports,
    ))
}

/// Generates the `bad_content_length.transcript` fixture.
pub fn generate_transcript_bad_content_length(
    annexb: &H264AnnexBStream,
    params: &RtspTranscriptParams,
) -> Result<RtspTranscriptFixture, MediaFixtureError> {
    let (sps_b64, pps_b64) = extract_sps_pps_b64(annexb)?;
    let sdp = build_sdp(params, &sps_b64, &pps_b64, false);
    let uri = params.stream_uri;

    let mut records = Vec::new();
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ClientToServer,
        offset_ms: 0,
        bytes: format!("OPTIONS {uri} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: FSS-Reference\r\n\r\n")
            .into_bytes(),
    });
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 0,
        bytes: b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n"
            .to_vec(),
    });
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ClientToServer,
        offset_ms: 0,
        bytes: format!("DESCRIBE {uri} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n")
            .into_bytes(),
    });
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 0,
        bytes: format!(
            "RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\nContent-Base: {uri}/\r\nContent-Length: not-a-number\r\n\r\n{sdp}"
        )
        .into_bytes(),
    });

    Ok(finalize_fixture(
        "bad_content_length",
        records,
        Vec::new(),
        Vec::new(),
    ))
}

/// Generates the `session_timeout_header.transcript` fixture.
pub fn generate_transcript_session_timeout(
    annexb: &H264AnnexBStream,
    params: &RtspTranscriptParams,
) -> Result<RtspTranscriptFixture, MediaFixtureError> {
    let clean = generate_transcript_clean(annexb, params)?;
    let sid = params.session_id;

    let modified_records = clean
        .records
        .into_iter()
        .map(|mut r| {
            if r.direction == TranscriptDirection::ServerToClient
                && r.bytes.windows(11).any(|w| w == b";timeout=60")
            {
                let text = String::from_utf8_lossy(&r.bytes);
                let replaced = text.replace(
                    &format!("Session: {sid};timeout=60"),
                    &format!("Session: {sid};timeout=30"),
                );
                r.bytes = replaced.into_bytes();
            }
            r
        })
        .collect();

    Ok(finalize_fixture(
        "session_timeout_header",
        modified_records,
        clean.packets,
        clean.sender_reports,
    ))
}

/// Generates the `rtcp_rsize.transcript` fixture with `a=rtcp-rsize` and reduced-size SRs.
pub fn generate_transcript_rtcp_rsize(
    annexb: &H264AnnexBStream,
    params: &RtspTranscriptParams,
) -> Result<RtspTranscriptFixture, MediaFixtureError> {
    let (sps_b64, pps_b64) = extract_sps_pps_b64(annexb)?;
    let sdp = build_sdp(params, &sps_b64, &pps_b64, true);
    let rtp_packets = extract_clean_rtp_packets(annexb, params)?;

    let mut records = Vec::new();
    let uri = params.stream_uri;
    let sid = params.session_id;

    // 1. OPTIONS exchange
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ClientToServer,
        offset_ms: 0,
        bytes: format!("OPTIONS {uri} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: FSS-Reference\r\n\r\n")
            .into_bytes(),
    });
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 0,
        bytes: b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n"
            .to_vec(),
    });

    // 2. DESCRIBE exchange
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ClientToServer,
        offset_ms: 0,
        bytes: format!("DESCRIBE {uri} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n")
            .into_bytes(),
    });
    let sdp_len = sdp.len();
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 0,
        bytes: format!(
            "RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\nContent-Base: {uri}/\r\nContent-Length: {sdp_len}\r\n\r\n{sdp}"
        )
        .into_bytes(),
    });

    // 3. SETUP exchange
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ClientToServer,
        offset_ms: 0,
        bytes: format!(
            "SETUP {uri}/trackID=1 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n"
        )
        .into_bytes(),
    });
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 0,
        bytes: format!(
            "RTSP/1.0 200 OK\r\nCSeq: 3\r\nSession: {sid};timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n"
        )
        .into_bytes(),
    });

    // 4. PLAY exchange
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ClientToServer,
        offset_ms: 0,
        bytes: format!("PLAY {uri} RTSP/1.0\r\nCSeq: 4\r\nSession: {sid}\r\nRange: npt=0-\r\n\r\n")
            .into_bytes(),
    });
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 0,
        bytes: format!(
            "RTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: {sid}\r\nRTP-Info: url={uri}/trackID=1;seq={};rtptime={}\r\n\r\n",
            params.initial_sequence, 90_000
        )
        .into_bytes(),
    });

    // 5. Interleaved media frames with ReducedSize SRs
    let mut sender_reports = Vec::new();
    let mut packet_descs = Vec::with_capacity(rtp_packets.len());

    // SR 0 at offset 0 ms
    let sr0_bytes = build_rtcp_sender_report(params.ssrc, 3_900_000_000, 0, 90_000, 0, 0);
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 0,
        bytes: encode_interleaved_frame(1, &sr0_bytes),
    });
    sender_reports.push(RtspSenderReportDesc {
        offset_ms: 0,
        channel: 1,
        ssrc: params.ssrc,
        ntp_seconds: 3_900_000_000,
        ntp_fraction: 0,
        rtp_timestamp: 90_000,
        packet_count: 0,
        octet_count: 0,
        is_compound: false,
        cname: None,
    });

    for (idx, (wire, desc)) in rtp_packets.into_iter().enumerate() {
        if idx == 9 {
            let sr1_bytes =
                build_rtcp_sender_report(params.ssrc, 3_900_000_000, 283_467_841, 96_000, 9, 2199);
            records.push(TranscriptRecord {
                direction: TranscriptDirection::ServerToClient,
                offset_ms: 66,
                bytes: encode_interleaved_frame(1, &sr1_bytes),
            });
            sender_reports.push(RtspSenderReportDesc {
                offset_ms: 66,
                channel: 1,
                ssrc: params.ssrc,
                ntp_seconds: 3_900_000_000,
                ntp_fraction: 283_467_841,
                rtp_timestamp: 96_000,
                packet_count: 9,
                octet_count: 2199,
                is_compound: false,
                cname: None,
            });
        }

        records.push(TranscriptRecord {
            direction: TranscriptDirection::ServerToClient,
            offset_ms: desc.offset_ms,
            bytes: encode_interleaved_frame(0, &wire),
        });
        packet_descs.push(desc);
    }

    // SR 2 at offset 132 ms
    let sr2_bytes =
        build_rtcp_sender_report(params.ssrc, 3_900_000_000, 566_935_683, 102_000, 15, 3504);
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 132,
        bytes: encode_interleaved_frame(1, &sr2_bytes),
    });
    sender_reports.push(RtspSenderReportDesc {
        offset_ms: 132,
        channel: 1,
        ssrc: params.ssrc,
        ntp_seconds: 3_900_000_000,
        ntp_fraction: 566_935_683,
        rtp_timestamp: 102_000,
        packet_count: 15,
        octet_count: 3504,
        is_compound: false,
        cname: None,
    });

    // 6. TEARDOWN exchange
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ClientToServer,
        offset_ms: 150,
        bytes: format!("TEARDOWN {uri} RTSP/1.0\r\nCSeq: 5\r\nSession: {sid}\r\n\r\n").into_bytes(),
    });
    records.push(TranscriptRecord {
        direction: TranscriptDirection::ServerToClient,
        offset_ms: 150,
        bytes: format!("RTSP/1.0 200 OK\r\nCSeq: 5\r\nSession: {sid}\r\n\r\n").into_bytes(),
    });

    Ok(finalize_fixture(
        "rtcp_rsize",
        records,
        packet_descs,
        sender_reports,
    ))
}

/// Generates the `sr_absent.transcript` fixture with no channel 1 RTCP reports.
pub fn generate_transcript_sr_absent(
    annexb: &H264AnnexBStream,
    params: &RtspTranscriptParams,
) -> Result<RtspTranscriptFixture, MediaFixtureError> {
    let clean = generate_transcript_clean(annexb, params)?;
    let records_without_sr = clean
        .records
        .into_iter()
        .filter(|r| {
            !(r.direction == TranscriptDirection::ServerToClient && r.bytes.starts_with(b"$\x01"))
        })
        .collect();

    Ok(finalize_fixture(
        "sr_absent",
        records_without_sr,
        clean.packets,
        Vec::new(),
    ))
}

/// Generates the `get_parameter_keepalive.transcript` fixture with GET_PARAMETER.
pub fn generate_transcript_get_parameter_keepalive(
    annexb: &H264AnnexBStream,
    params: &RtspTranscriptParams,
) -> Result<RtspTranscriptFixture, MediaFixtureError> {
    let clean = generate_transcript_clean(annexb, params)?;
    let uri = params.stream_uri;
    let sid = params.session_id;

    let mut records = Vec::with_capacity(clean.records.len() + 2);
    for r in clean.records {
        if r.direction == TranscriptDirection::ClientToServer && r.bytes.starts_with(b"TEARDOWN ") {
            // Insert GET_PARAMETER keepalive before TEARDOWN
            records.push(TranscriptRecord {
                direction: TranscriptDirection::ClientToServer,
                offset_ms: 140,
                bytes: format!("GET_PARAMETER {uri} RTSP/1.0\r\nCSeq: 5\r\nSession: {sid}\r\n\r\n")
                    .into_bytes(),
            });
            records.push(TranscriptRecord {
                direction: TranscriptDirection::ServerToClient,
                offset_ms: 140,
                bytes: format!("RTSP/1.0 200 OK\r\nCSeq: 5\r\nSession: {sid}\r\n\r\n").into_bytes(),
            });

            // Update TEARDOWN CSeq to 6
            records.push(TranscriptRecord {
                direction: TranscriptDirection::ClientToServer,
                offset_ms: 150,
                bytes: format!("TEARDOWN {uri} RTSP/1.0\r\nCSeq: 6\r\nSession: {sid}\r\n\r\n")
                    .into_bytes(),
            });
        } else if r.direction == TranscriptDirection::ServerToClient
            && r.offset_ms == 150
            && r.bytes.starts_with(b"RTSP/1.0 200 OK\r\nCSeq: 5")
        {
            // Update TEARDOWN response CSeq to 6
            records.push(TranscriptRecord {
                direction: TranscriptDirection::ServerToClient,
                offset_ms: 150,
                bytes: format!("RTSP/1.0 200 OK\r\nCSeq: 6\r\nSession: {sid}\r\n\r\n").into_bytes(),
            });
        } else {
            records.push(r);
        }
    }

    Ok(finalize_fixture(
        "get_parameter_keepalive",
        records,
        clean.packets,
        clean.sender_reports,
    ))
}

/// Builds JSON manifest for all RTSP transcript fixtures.
#[must_use]
pub fn build_rtsp_manifest_json(
    fixtures: &[RtspTranscriptFixture],
    params: &RtspTranscriptParams,
) -> String {
    let mut out = String::with_capacity(32 * 1024);
    out.push_str("{\n");
    out.push_str("  \"schema\": \"fss.media_fixture.manifest.v1\",\n");
    out.push_str("  \"family\": \"rtsp\",\n");
    out.push_str(&format!("  \"note\": \"{MEDIA_FIXTURE_NOTE}\",\n"));
    out.push_str("  \"generator\": \"fss-reference::media_fixture::rtsp\",\n");
    out.push_str("  \"generator_version\": \"1.0.0\",\n");
    out.push_str("  \"fixtures\": [\n");

    for (f_idx, fix) in fixtures.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"name\": \"{}\",\n", fix.filename));
        out.push_str("      \"format\": \"rtsp-transcript\",\n");
        out.push_str(&format!("      \"variant\": \"{}\",\n", fix.variant_name));
        out.push_str(&format!("      \"sha256\": \"{}\",\n", fix.sha256));
        out.push_str(&format!("      \"byte_len\": {},\n", fix.bytes.len()));
        out.push_str(&format!("      \"note\": \"{MEDIA_FIXTURE_NOTE}\",\n"));
        out.push_str("      \"source_annexb_fixture\": \"clean.264\",\n");
        out.push_str("      \"params\": {\n");
        out.push_str(&format!("        \"ssrc\": {},\n", params.ssrc));
        out.push_str(&format!(
            "        \"payload_type\": {},\n",
            params.payload_type
        ));
        out.push_str(&format!(
            "        \"clock_rate_hz\": {},\n",
            params.clock_rate_hz
        ));
        out.push_str(&format!(
            "        \"initial_sequence\": {},\n",
            params.initial_sequence
        ));
        out.push_str(&format!(
            "        \"session_id\": \"{}\",\n",
            params.session_id
        ));
        out.push_str(&format!(
            "        \"stream_uri\": \"{}\",\n",
            params.stream_uri
        ));
        out.push_str(&format!("        \"mtu\": {}\n", params.mtu));
        out.push_str("      },\n");

        out.push_str(&format!("      \"record_count\": {},\n", fix.records.len()));
        out.push_str(&format!(
            "      \"rtp_packet_count\": {},\n",
            fix.packets.len()
        ));
        out.push_str(&format!(
            "      \"rtcp_report_count\": {},\n",
            fix.sender_reports.len()
        ));

        out.push_str("      \"expected_packets\": [\n");
        for (p_idx, pkt) in fix.packets.iter().enumerate() {
            out.push_str("        {\n");
            out.push_str(&format!("          \"index\": {},\n", pkt.index));
            out.push_str(&format!("          \"offset_ms\": {},\n", pkt.offset_ms));
            out.push_str(&format!("          \"sequence\": {},\n", pkt.sequence));
            out.push_str(&format!("          \"timestamp\": {},\n", pkt.timestamp));
            out.push_str(&format!("          \"ssrc\": {},\n", pkt.ssrc));
            out.push_str(&format!("          \"marker\": {},\n", pkt.marker));
            out.push_str(&format!(
                "          \"payload_type\": {},\n",
                pkt.payload_type
            ));
            out.push_str(&format!("          \"packet_len\": {},\n", pkt.packet_len));
            out.push_str(&format!(
                "          \"expected_sequence_class\": \"{}\",\n",
                pkt.expected_sequence_class.as_str()
            ));
            out.push_str(&format!(
                "          \"is_sacrificial\": {},\n",
                pkt.is_sacrificial
            ));
            out.push_str(&format!(
                "          \"expected_delivered\": {},\n",
                pkt.expected_delivered
            ));
            out.push_str(&format!(
                "          \"packetization\": \"{}\",\n",
                pkt.packetization
            ));
            out.push_str("          \"nal_types\": [");
            for (nt_idx, nt) in pkt.nal_types.iter().enumerate() {
                if nt_idx > 0 {
                    out.push_str(", ");
                }
                out.push_str(&format!("{nt}"));
            }
            out.push_str("]\n");

            if p_idx + 1 == fix.packets.len() {
                out.push_str("        }\n");
            } else {
                out.push_str("        },\n");
            }
        }
        out.push_str("      ],\n");

        out.push_str("      \"sender_reports\": [\n");
        for (sr_idx, sr) in fix.sender_reports.iter().enumerate() {
            out.push_str("        {\n");
            out.push_str(&format!("          \"offset_ms\": {},\n", sr.offset_ms));
            out.push_str(&format!("          \"channel\": {},\n", sr.channel));
            out.push_str(&format!("          \"ssrc\": {},\n", sr.ssrc));
            out.push_str(&format!("          \"ntp_seconds\": {},\n", sr.ntp_seconds));
            out.push_str(&format!(
                "          \"ntp_fraction\": {},\n",
                sr.ntp_fraction
            ));
            out.push_str(&format!(
                "          \"rtp_timestamp\": {},\n",
                sr.rtp_timestamp
            ));
            out.push_str(&format!(
                "          \"packet_count\": {},\n",
                sr.packet_count
            ));
            out.push_str(&format!("          \"octet_count\": {},\n", sr.octet_count));
            out.push_str(&format!("          \"is_compound\": {},\n", sr.is_compound));
            if let Some(ref c) = sr.cname {
                out.push_str(&format!("          \"cname\": \"{c}\"\n"));
            } else {
                out.push_str("          \"cname\": null\n");
            }

            if sr_idx + 1 == fix.sender_reports.len() {
                out.push_str("        }\n");
            } else {
                out.push_str("        },\n");
            }
        }
        out.push_str("      ]\n");

        if f_idx + 1 == fixtures.len() {
            out.push_str("    }\n");
        } else {
            out.push_str("    },\n");
        }
    }

    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}
