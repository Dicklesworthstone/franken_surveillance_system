#![forbid(unsafe_code)]
//! Deterministic synthetic rtpdump (RFC 3550 / RFC 6184) bitstream generator.
//!
//! Generates rtptools-compatible rtpdump files containing RFC 6184 packetized
//! H.264 streams (Single NAL, STAP-A, FU-A) across 7 canonical continuity variants:
//! `clean`, `loss`, `reorder`, `duplicate`, `ssrc_reset`, `truncated_last_record`,
//! and `large_gap`.
//!
//! Note on media decodability: all generated payloads have structurally valid
//! NAL syntax, slice headers, and packet framing; pictures are not decodable.

use super::{ExpectedSequenceClass, MEDIA_FIXTURE_NOTE, MediaFixtureError, h264::H264AnnexBStream};
use fss_core::ContentDigest;

/// Header line required for rtptools rtpdump format with zero IP address.
pub const RTPDUMP_MAGIC_HEADER: &[u8] = b"#!rtpplay1.0 0.0.0.0/0\n";

/// Fixed 16-byte RD_hdr_t preamble for rtpdump format.
pub const RD_HDR_LEN: usize = 16;

/// Fixed 8-byte RD_packet_t record prefix for rtpdump format.
pub const RD_PKT_HDR_LEN: usize = 8;

/// RTP fixed header size in bytes.
pub const RTP_FIXED_HDR_LEN: usize = 12;

/// Parameters governing rtpdump synthesis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpdumpParams {
    /// Negotiated synchronization source identifier (SSRC).
    pub ssrc: u32,
    /// Dynamic payload type number (typically 96 for H.264).
    pub payload_type: u8,
    /// RTP clock rate in Hertz (90,000 for video).
    pub clock_rate_hz: u32,
    /// Seeded initial sequence number (65534 enables immediate 65535 -> 0 wrap).
    pub initial_sequence: u16,
    /// Maximum transmission unit size in bytes for packet framing.
    pub mtu: usize,
}

impl Default for RtpdumpParams {
    fn default() -> Self {
        Self {
            ssrc: 0x1122_3344,
            payload_type: 96,
            clock_rate_hz: 90_000,
            initial_sequence: 65_534,
            mtu: 1200,
        }
    }
}

/// Metadata descriptor for a single packet within an rtpdump fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpdumpPacketDesc {
    /// 0-based sequential packet index in the rtpdump stream.
    pub index: usize,
    /// Milliseconds offset from start of session.
    pub offset_ms: u32,
    /// 16-bit wire sequence number.
    pub sequence: u16,
    /// 32-bit wire timestamp.
    pub timestamp: u32,
    /// 32-bit wire synchronization source identifier.
    pub ssrc: u32,
    /// Marker bit set on final packet of access unit.
    pub marker: bool,
    /// 7-bit wire payload type.
    pub payload_type: u8,
    /// Complete wire packet length (12-byte header + payload).
    pub packet_len: usize,
    /// Expected SequenceClass under RFC 3550 A.1 continuity rules.
    pub expected_sequence_class: ExpectedSequenceClass,
    /// True if this is an unadmitted sacrificial packet (e.g. leading Probation packet).
    pub is_sacrificial: bool,
    /// True if packet is expected to be delivered to the depacketizer/decoder.
    pub expected_delivered: bool,
    /// RFC 6184 packetization type string: "STAP-A", "SingleNal", or "FU-A".
    pub packetization: &'static str,
    /// Contained NAL unit types.
    pub nal_types: Vec<u8>,
}

/// Complete synthesized rtpdump fixture with raw bytes and verified manifest metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpdumpFixture {
    /// Canonical variant name ("clean", "loss", "reorder", "duplicate", etc.).
    pub variant_name: &'static str,
    /// Filename without path (e.g. "clean.rtp").
    pub filename: String,
    /// Complete raw file bytes including rtpdump header and all packet records.
    pub bytes: Vec<u8>,
    /// Descriptors for each packet in the stream.
    pub packets: Vec<RtpdumpPacketDesc>,
    /// Explicitly dropped sequence numbers for loss variants.
    pub missing_sequences: Vec<u16>,
    /// Hex-encoded SHA-256 digest of the complete file bytes.
    pub sha256: String,
    /// True if the last record was intentionally truncated.
    pub is_truncated: bool,
}

/// Serializes an in-memory packet into a complete 12-byte RTP wire datagram.
fn build_rtp_packet_bytes(
    marker: bool,
    payload_type: u8,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(RTP_FIXED_HDR_LEN + payload.len());
    // Byte 0: V=2, P=0, X=0, CC=0 -> 0x80
    packet.push(0x80);
    // Byte 1: M (1 bit) | PT (7 bits)
    let m_bit = if marker { 0x80 } else { 0x00 };
    packet.push(m_bit | (payload_type & 0x7f));
    // Bytes 2..4: Sequence number (big endian)
    packet.extend_from_slice(&sequence.to_be_bytes());
    // Bytes 4..8: Timestamp (big endian)
    packet.extend_from_slice(&timestamp.to_be_bytes());
    // Bytes 8..12: SSRC (big endian)
    packet.extend_from_slice(&ssrc.to_be_bytes());
    // Payload
    packet.extend_from_slice(payload);
    packet
}

/// Internal representation of a packet before rtpdump serialization.
struct ProtoPacket {
    offset_ms: u32,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
    marker: bool,
    payload_type: u8,
    payload: Vec<u8>,
    expected_sequence_class: ExpectedSequenceClass,
    is_sacrificial: bool,
    expected_delivered: bool,
    packetization: &'static str,
    nal_types: Vec<u8>,
}

/// Packetizes Annex-B NAL units into proto-packets per RFC 6184.
fn packetize_nals_for_stream(
    annexb: &H264AnnexBStream,
    params: &RtpdumpParams,
) -> Result<Vec<ProtoPacket>, MediaFixtureError> {
    let mut packets = Vec::new();
    let mut seq = params.initial_sequence;

    // Find AU0 AUD NAL
    let au0_aud = annexb
        .nals
        .iter()
        .find(|n| n.access_unit_index == 0 && n.nal_unit_type == 9)
        .ok_or(MediaFixtureError::InvalidParam(
            "Annex-B stream missing AU0 AUD",
        ))?;

    // Find SPS and PPS NALs for STAP-A aggregation
    let sps_nal = annexb.nals.iter().find(|n| n.nal_unit_type == 7).ok_or(
        MediaFixtureError::InvalidParam("Annex-B stream missing SPS"),
    )?;
    let pps_nal = annexb.nals.iter().find(|n| n.nal_unit_type == 8).ok_or(
        MediaFixtureError::InvalidParam("Annex-B stream missing PPS"),
    )?;

    // Build STAP-A payload: NRI=3, type=24 -> 0x78
    let mut stap_payload = Vec::new();
    stap_payload.push(0x78);
    stap_payload.extend_from_slice(&(sps_nal.wire_bytes.len() as u16).to_be_bytes());
    stap_payload.extend_from_slice(&sps_nal.wire_bytes);
    stap_payload.extend_from_slice(&(pps_nal.wire_bytes.len() as u16).to_be_bytes());
    stap_payload.extend_from_slice(&pps_nal.wire_bytes);

    let base_timestamp = 90_000u32;
    let ssrc = params.ssrc;
    let pt = params.payload_type;

    // 1. Sacrificial packet (Probation): AU0 AUD
    packets.push(ProtoPacket {
        offset_ms: 0,
        sequence: seq,
        timestamp: base_timestamp,
        ssrc,
        marker: false,
        payload_type: pt,
        payload: au0_aud.wire_bytes.clone(),
        expected_sequence_class: ExpectedSequenceClass::Probation,
        is_sacrificial: true,
        expected_delivered: false,
        packetization: "SingleNal",
        nal_types: vec![9],
    });
    seq = seq.wrapping_add(1);

    // 2. Baseline packet: AU0 AUD (Baseline)
    packets.push(ProtoPacket {
        offset_ms: 0,
        sequence: seq,
        timestamp: base_timestamp,
        ssrc,
        marker: false,
        payload_type: pt,
        payload: au0_aud.wire_bytes.clone(),
        expected_sequence_class: ExpectedSequenceClass::Baseline,
        is_sacrificial: false,
        expected_delivered: true,
        packetization: "SingleNal",
        nal_types: vec![9],
    });
    seq = seq.wrapping_add(1);

    // 3. Advanced packet: SPS+PPS STAP-A (Advanced)
    packets.push(ProtoPacket {
        offset_ms: 0,
        sequence: seq,
        timestamp: base_timestamp,
        ssrc,
        marker: false,
        payload_type: pt,
        payload: stap_payload,
        expected_sequence_class: ExpectedSequenceClass::Advanced,
        is_sacrificial: false,
        expected_delivered: true,
        packetization: "STAP-A",
        nal_types: vec![7, 8],
    });
    seq = seq.wrapping_add(1);

    // 4. Process remaining NALs (for AU0: exclude AUD, SPS, PPS; for AU > 0: exclude SPS, PPS)
    for au_idx in 0..annexb.access_unit_count {
        let au_nals: Vec<&super::h264::SyntheticNal> = annexb
            .nals
            .iter()
            .filter(|n| {
                if au_idx == 0 {
                    n.access_unit_index == 0
                        && n.nal_unit_type != 7
                        && n.nal_unit_type != 8
                        && n.nal_unit_type != 9
                } else {
                    n.access_unit_index == au_idx && n.nal_unit_type != 7 && n.nal_unit_type != 8
                }
            })
            .collect();

        let au_timestamp = base_timestamp.wrapping_add((au_idx as u32).wrapping_mul(3_000));
        let au_offset_ms = (au_idx as u32).wrapping_mul(33);

        for (nal_in_au_idx, nal) in au_nals.iter().enumerate() {
            let is_last_nal_in_au = nal_in_au_idx + 1 == au_nals.len();
            let nal_bytes = &nal.wire_bytes;

            if nal_bytes.len() + RTP_FIXED_HDR_LEN <= params.mtu {
                // Single NAL unit packet
                let marker = is_last_nal_in_au;
                packets.push(ProtoPacket {
                    offset_ms: au_offset_ms,
                    sequence: seq,
                    timestamp: au_timestamp,
                    ssrc,
                    marker,
                    payload_type: pt,
                    payload: nal_bytes.clone(),
                    expected_sequence_class: ExpectedSequenceClass::Advanced,
                    is_sacrificial: false,
                    expected_delivered: true,
                    packetization: "SingleNal",
                    nal_types: vec![nal.nal_unit_type],
                });
                seq = seq.wrapping_add(1);
            } else {
                // Fragmented Unit A (FU-A) packetization
                let nal_header = nal_bytes[0];
                let nal_payload = &nal_bytes[1..];
                let nri = nal_header & 0x60;
                let original_type = nal_header & 0x1f;
                let fu_indicator = nri | 28; // FU-A indicator (type 28)

                let max_frag_payload = params.mtu.saturating_sub(RTP_FIXED_HDR_LEN + 2);
                if max_frag_payload == 0 {
                    return Err(MediaFixtureError::InvalidParam("MTU too small for FU-A"));
                }

                let total_frags = nal_payload.len().div_ceil(max_frag_payload);
                for frag_idx in 0..total_frags {
                    let start = frag_idx * max_frag_payload;
                    let end = (start + max_frag_payload).min(nal_payload.len());
                    let frag_chunk = &nal_payload[start..end];

                    let is_start = frag_idx == 0;
                    let is_end = frag_idx + 1 == total_frags;

                    let mut fu_header = original_type;
                    if is_start {
                        fu_header |= 0x80; // S bit
                    }
                    if is_end {
                        fu_header |= 0x40; // E bit
                    }

                    let mut fu_payload = Vec::with_capacity(2 + frag_chunk.len());
                    fu_payload.push(fu_indicator);
                    fu_payload.push(fu_header);
                    fu_payload.extend_from_slice(frag_chunk);

                    let marker = is_end && is_last_nal_in_au;

                    packets.push(ProtoPacket {
                        offset_ms: au_offset_ms,
                        sequence: seq,
                        timestamp: au_timestamp,
                        ssrc,
                        marker,
                        payload_type: pt,
                        payload: fu_payload,
                        expected_sequence_class: ExpectedSequenceClass::Advanced,
                        is_sacrificial: false,
                        expected_delivered: true,
                        packetization: "FU-A",
                        nal_types: vec![nal.nal_unit_type],
                    });
                    seq = seq.wrapping_add(1);
                }
            }
        }
    }

    Ok(packets)
}

/// Serializes proto-packets into the standard rtpdump file format.
fn serialize_rtpdump(
    variant_name: &'static str,
    filename: String,
    proto_packets: Vec<ProtoPacket>,
    missing_sequences: Vec<u16>,
    truncate_last_record: bool,
) -> RtpdumpFixture {
    let mut bytes = Vec::new();
    // 1. Text header line: #!rtpplay1.0 0.0.0.0/0\n
    bytes.extend_from_slice(RTPDUMP_MAGIC_HEADER);

    // 2. 16-byte RD_hdr_t: all zeros for deterministic synthetic capture
    bytes.extend_from_slice(&0u32.to_be_bytes()); // start sec
    bytes.extend_from_slice(&0u32.to_be_bytes()); // start usec
    bytes.extend_from_slice(&0u32.to_be_bytes()); // source IP 0.0.0.0
    bytes.extend_from_slice(&0u16.to_be_bytes()); // port 0
    bytes.extend_from_slice(&0u16.to_be_bytes()); // padding 0

    let mut descriptors = Vec::with_capacity(proto_packets.len());

    let num_packets = proto_packets.len();
    for (idx, p) in proto_packets.into_iter().enumerate() {
        let is_last = idx + 1 == num_packets;
        let rtp_wire = build_rtp_packet_bytes(
            p.marker,
            p.payload_type,
            p.sequence,
            p.timestamp,
            p.ssrc,
            &p.payload,
        );

        let packet_len = rtp_wire.len();
        let record_length = (RD_PKT_HDR_LEN + packet_len) as u16;
        let plen = packet_len as u16;

        if truncate_last_record && is_last {
            // Write partial 4 bytes of the 8-byte RD_packet_t header to simulate truncated record
            bytes.extend_from_slice(&record_length.to_be_bytes());
            bytes.extend_from_slice(&plen.to_be_bytes());
            // Intentionally omit offset_ms and packet payload; truncated record is excluded from descriptors
            break;
        }

        descriptors.push(RtpdumpPacketDesc {
            index: idx,
            offset_ms: p.offset_ms,
            sequence: p.sequence,
            timestamp: p.timestamp,
            ssrc: p.ssrc,
            marker: p.marker,
            payload_type: p.payload_type,
            packet_len,
            expected_sequence_class: p.expected_sequence_class,
            is_sacrificial: p.is_sacrificial,
            expected_delivered: p.expected_delivered,
            packetization: p.packetization,
            nal_types: p.nal_types,
        });

        // 8-byte RD_packet_t
        bytes.extend_from_slice(&record_length.to_be_bytes());
        bytes.extend_from_slice(&plen.to_be_bytes());
        bytes.extend_from_slice(&p.offset_ms.to_be_bytes());
        // Packet payload
        bytes.extend_from_slice(&rtp_wire);
    }

    let digest = ContentDigest::sha256(&bytes);
    let mut sha256 = String::with_capacity(64);
    for b in digest.bytes() {
        use std::fmt::Write;
        let _ = write!(sha256, "{:02x}", b);
    }

    RtpdumpFixture {
        variant_name,
        filename,
        bytes,
        packets: descriptors,
        missing_sequences,
        sha256,
        is_truncated: truncate_last_record,
    }
}

/// Generates the canonical `clean` rtpdump fixture.
pub fn generate_rtpdump_clean(
    annexb: &H264AnnexBStream,
    params: &RtpdumpParams,
) -> Result<RtpdumpFixture, MediaFixtureError> {
    let proto = packetize_nals_for_stream(annexb, params)?;
    Ok(serialize_rtpdump(
        "clean",
        "clean.rtp".to_string(),
        proto,
        Vec::new(),
        false,
    ))
}

/// Generates the `loss` rtpdump fixture with sequence 1 dropped.
pub fn generate_rtpdump_loss(
    annexb: &H264AnnexBStream,
    params: &RtpdumpParams,
) -> Result<RtpdumpFixture, MediaFixtureError> {
    let mut proto = packetize_nals_for_stream(annexb, params)?;
    let drop_seq = 1u16; // SEI packet
    proto.retain(|p| p.sequence != drop_seq);
    Ok(serialize_rtpdump(
        "loss",
        "loss.rtp".to_string(),
        proto,
        vec![drop_seq],
        false,
    ))
}

/// Generates the `reorder` rtpdump fixture with packets at seq 0 and seq 1 swapped.
pub fn generate_rtpdump_reorder(
    annexb: &H264AnnexBStream,
    params: &RtpdumpParams,
) -> Result<RtpdumpFixture, MediaFixtureError> {
    let mut proto = packetize_nals_for_stream(annexb, params)?;
    if proto.len() > 3 {
        // Swap packet at index 2 (seq 0) and index 3 (seq 1)
        proto.swap(2, 3);
        // Index 2 is now seq 1 (Advanced)
        // Index 3 is now seq 0 (Reordered under 128-window rules; depacketizer ignores non-increasing)
        proto[3].expected_sequence_class = ExpectedSequenceClass::Reordered;
        proto[3].expected_delivered = false;
    }
    Ok(serialize_rtpdump(
        "reorder",
        "reorder.rtp".to_string(),
        proto,
        Vec::new(),
        false,
    ))
}

/// Generates the `duplicate` rtpdump fixture with packet at seq 0 repeated.
pub fn generate_rtpdump_duplicate(
    annexb: &H264AnnexBStream,
    params: &RtpdumpParams,
) -> Result<RtpdumpFixture, MediaFixtureError> {
    let proto = packetize_nals_for_stream(annexb, params)?;
    let mut dup_proto = Vec::with_capacity(proto.len() + 1);
    for (idx, p) in proto.into_iter().enumerate() {
        dup_proto.push(ProtoPacket {
            offset_ms: p.offset_ms,
            sequence: p.sequence,
            timestamp: p.timestamp,
            ssrc: p.ssrc,
            marker: p.marker,
            payload_type: p.payload_type,
            payload: p.payload.clone(),
            expected_sequence_class: p.expected_sequence_class,
            is_sacrificial: p.is_sacrificial,
            expected_delivered: p.expected_delivered,
            packetization: p.packetization,
            nal_types: p.nal_types.clone(),
        });
        if idx == 2 {
            // Duplicate packet at index 2 (seq 0)
            dup_proto.push(ProtoPacket {
                offset_ms: p.offset_ms.wrapping_add(1),
                sequence: p.sequence,
                timestamp: p.timestamp,
                ssrc: p.ssrc,
                marker: p.marker,
                payload_type: p.payload_type,
                payload: p.payload,
                expected_sequence_class: ExpectedSequenceClass::Duplicate,
                is_sacrificial: false,
                expected_delivered: false,
                packetization: p.packetization,
                nal_types: p.nal_types,
            });
        }
    }
    Ok(serialize_rtpdump(
        "duplicate",
        "duplicate.rtp".to_string(),
        dup_proto,
        Vec::new(),
        false,
    ))
}

/// Generates the `ssrc_reset` rtpdump fixture with a mid-stream SSRC switch.
pub fn generate_rtpdump_ssrc_reset(
    annexb: &H264AnnexBStream,
    params: &RtpdumpParams,
) -> Result<RtpdumpFixture, MediaFixtureError> {
    let proto = packetize_nals_for_stream(annexb, params)?;
    let mut reset_proto = Vec::new();

    // Generation 1: first 4 packets under SSRC1
    for p in proto.iter().take(4) {
        reset_proto.push(ProtoPacket {
            offset_ms: p.offset_ms,
            sequence: p.sequence,
            timestamp: p.timestamp,
            ssrc: params.ssrc,
            marker: p.marker,
            payload_type: p.payload_type,
            payload: p.payload.clone(),
            expected_sequence_class: p.expected_sequence_class,
            is_sacrificial: p.is_sacrificial,
            expected_delivered: p.expected_delivered,
            packetization: p.packetization,
            nal_types: p.nal_types.clone(),
        });
    }

    // Generation 2: new SSRC (0x55667788), leading sacrificial AUD, baseline AUD, then slice
    let ssrc2 = 0x5566_7788u32;
    let mut seq2 = 1_000u16;
    let ts2 = 180_000u32;
    let offset2 = 132u32;

    // Sacrificial AUD for generation 2
    let aud_payload = &proto[0].payload;
    reset_proto.push(ProtoPacket {
        offset_ms: offset2,
        sequence: seq2,
        timestamp: ts2,
        ssrc: ssrc2,
        marker: false,
        payload_type: params.payload_type,
        payload: aud_payload.clone(),
        expected_sequence_class: ExpectedSequenceClass::Probation,
        is_sacrificial: true,
        expected_delivered: false,
        packetization: "SingleNal",
        nal_types: vec![9],
    });
    seq2 = seq2.wrapping_add(1);

    // Baseline AUD for generation 2
    reset_proto.push(ProtoPacket {
        offset_ms: offset2,
        sequence: seq2,
        timestamp: ts2,
        ssrc: ssrc2,
        marker: false,
        payload_type: params.payload_type,
        payload: aud_payload.clone(),
        expected_sequence_class: ExpectedSequenceClass::Baseline,
        is_sacrificial: false,
        expected_delivered: true,
        packetization: "SingleNal",
        nal_types: vec![9],
    });
    seq2 = seq2.wrapping_add(1);

    // Slice for generation 2 (SingleNal slice with marker = true)
    let slice_pkt = proto
        .iter()
        .find(|p| p.packetization == "SingleNal" && p.nal_types == vec![5])
        .ok_or(MediaFixtureError::InvalidParam(
            "missing slice packet in proto",
        ))?;
    reset_proto.push(ProtoPacket {
        offset_ms: offset2,
        sequence: seq2,
        timestamp: ts2,
        ssrc: ssrc2,
        marker: true,
        payload_type: params.payload_type,
        payload: slice_pkt.payload.clone(),
        expected_sequence_class: ExpectedSequenceClass::Advanced,
        is_sacrificial: false,
        expected_delivered: true,
        packetization: "SingleNal",
        nal_types: vec![5],
    });

    Ok(serialize_rtpdump(
        "ssrc_reset",
        "ssrc_reset.rtp".to_string(),
        reset_proto,
        Vec::new(),
        false,
    ))
}

/// Generates the `truncated_last_record` rtpdump fixture.
pub fn generate_rtpdump_truncated_last_record(
    annexb: &H264AnnexBStream,
    params: &RtpdumpParams,
) -> Result<RtpdumpFixture, MediaFixtureError> {
    let proto = packetize_nals_for_stream(annexb, params)?;
    Ok(serialize_rtpdump(
        "truncated_last_record",
        "truncated_last_record.rtp".to_string(),
        proto,
        Vec::new(),
        true, // Truncate last record
    ))
}

/// Generates the `large_gap` rtpdump fixture (>3,000 packet jump causing DiscontinuitySuspected and RestartRequired).
pub fn generate_rtpdump_large_gap(
    annexb: &H264AnnexBStream,
    params: &RtpdumpParams,
) -> Result<RtpdumpFixture, MediaFixtureError> {
    let proto = packetize_nals_for_stream(annexb, params)?;
    let mut gap_proto = Vec::new();

    // Take first 4 packets (Probation, Baseline, seq 0, seq 1)
    for p in proto.into_iter().take(4) {
        gap_proto.push(p);
    }

    // Forward jump of 3500 (> 3000 forward dropout threshold)
    let jump_seq = 1u16.wrapping_add(3_500); // 3501
    let ts = 90_000u32;
    let offset = 66u32;

    // Packet 4: First discontinuous packet -> DiscontinuitySuspected
    gap_proto.push(ProtoPacket {
        offset_ms: offset,
        sequence: jump_seq,
        timestamp: ts,
        ssrc: params.ssrc,
        marker: false,
        payload_type: params.payload_type,
        payload: vec![0x61, 0x10, 0x20], // Dummy non-IDR slice
        expected_sequence_class: ExpectedSequenceClass::DiscontinuitySuspected,
        is_sacrificial: false,
        expected_delivered: false,
        packetization: "SingleNal",
        nal_types: vec![1],
    });

    // Packet 5: Consecutive discontinuous packet matching bad_next -> RestartRequired
    gap_proto.push(ProtoPacket {
        offset_ms: offset.wrapping_add(10),
        sequence: jump_seq.wrapping_add(1),
        timestamp: ts,
        ssrc: params.ssrc,
        marker: false,
        payload_type: params.payload_type,
        payload: vec![0x61, 0x10, 0x21],
        expected_sequence_class: ExpectedSequenceClass::RestartRequired,
        is_sacrificial: false,
        expected_delivered: false,
        packetization: "SingleNal",
        nal_types: vec![1],
    });

    // Packet 6: Subsequent arrival while restart_required is latched -> RestartRequired
    gap_proto.push(ProtoPacket {
        offset_ms: offset.wrapping_add(20),
        sequence: jump_seq.wrapping_add(2),
        timestamp: ts,
        ssrc: params.ssrc,
        marker: false,
        payload_type: params.payload_type,
        payload: vec![0x61, 0x10, 0x22],
        expected_sequence_class: ExpectedSequenceClass::RestartRequired,
        is_sacrificial: false,
        expected_delivered: false,
        packetization: "SingleNal",
        nal_types: vec![1],
    });

    Ok(serialize_rtpdump(
        "large_gap",
        "large_gap.rtp".to_string(),
        gap_proto,
        Vec::new(),
        false,
    ))
}

/// Formats the per-family JSON manifest string for rtpdump fixtures.
#[must_use]
pub fn build_rtp_manifest_json(fixtures: &[RtpdumpFixture], params: &RtpdumpParams) -> String {
    let mut out = String::with_capacity(8192);
    out.push_str("{\n");
    out.push_str("  \"schema\": \"fss.media_fixture.manifest.v1\",\n");
    out.push_str("  \"family\": \"rtp\",\n");
    out.push_str(&format!("  \"note\": \"{MEDIA_FIXTURE_NOTE}\",\n"));
    out.push_str("  \"generator\": \"fss-reference::media_fixture::rtpdump\",\n");
    out.push_str("  \"generator_version\": \"1.0.0\",\n");
    out.push_str("  \"fixtures\": [\n");

    for (f_idx, fix) in fixtures.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"name\": \"{}\",\n", fix.filename));
        out.push_str("      \"format\": \"rtpdump\",\n");
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
        out.push_str(&format!("        \"mtu\": {}\n", params.mtu));
        out.push_str("      },\n");

        if !fix.missing_sequences.is_empty() {
            out.push_str("      \"missing_sequences\": [");
            for (m_idx, s) in fix.missing_sequences.iter().enumerate() {
                if m_idx > 0 {
                    out.push_str(", ");
                }
                out.push_str(&format!("{s}"));
            }
            out.push_str("],\n");
        }

        if fix.is_truncated {
            out.push_str("      \"is_truncated\": true,\n");
        }

        out.push_str(&format!(
            "      \"expected_packet_count\": {},\n",
            fix.packets.len()
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
