#![forbid(unsafe_code)]
//! Wire-layout, bounded-work, and hostile-input contracts for the packet kernel.

use fss_packet::{PacketError, PacketLimits, RtcpCompound, RtcpMode, RtpPacket};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn rtp(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 0xe0, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xf0, 0, 0, 0, 7];
    bytes.extend_from_slice(payload);
    bytes
}

fn rr(ssrc: u32) -> Vec<u8> {
    let mut bytes = vec![0x80, 201, 0, 1];
    bytes.extend_from_slice(&ssrc.to_be_bytes());
    bytes
}

fn sdes(ssrc: u32) -> Vec<u8> {
    let mut bytes = vec![0x81, 202, 0, 3];
    bytes.extend_from_slice(&ssrc.to_be_bytes());
    bytes.extend_from_slice(&[1, 3, b'c', b'a', b'm', 0, 0, 0]);
    bytes
}

#[test]
fn rtp_borrows_exact_source_and_does_not_invent_codec_or_time() -> TestResult {
    let bytes = rtp(&[0x65, 1, 2, 3]);
    let packet = RtpPacket::parse(&bytes, PacketLimits::default())?;
    assert_eq!(packet.wire_bytes(), bytes);
    assert_eq!(packet.sequence(), 65_534);
    assert_eq!(packet.timestamp(), 0xffff_fff0);
    assert_eq!(packet.ssrc(), 7);
    assert_eq!(packet.payload_type(), 96);
    assert!(packet.marker());
    assert_eq!(packet.payload(), [0x65, 1, 2, 3]);
    assert_eq!(packet.payload_range(), 12..16);
    assert_eq!(packet.csrcs().len(), 0);
    Ok(())
}

#[test]
fn csrc_extension_and_padding_ranges_are_independent() -> TestResult {
    let mut bytes = rtp(&[]);
    bytes[0] = 0xb2;
    bytes.extend_from_slice(&[0, 0, 0, 11, 0, 0, 0, 12]);
    bytes.extend_from_slice(&[0xbe, 0xde, 0, 1, 10, 20, 30, 40]);
    bytes.extend_from_slice(&[0x65, 42, 0, 0, 0, 4]);
    let packet = RtpPacket::parse(&bytes, PacketLimits::default())?;
    assert_eq!(packet.csrcs().collect::<Vec<_>>(), [11, 12]);
    let extension = packet.extension().ok_or("missing extension")?;
    assert_eq!(extension.profile, 0xbede);
    assert_eq!(extension.bytes, [10, 20, 30, 40]);
    assert_eq!(packet.payload(), [0x65, 42]);
    assert_eq!(packet.payload_range(), 28..30);
    assert_eq!(packet.padding_len(), 4);
    for length in 0..28 {
        assert!(RtpPacket::parse(&bytes[..length], PacketLimits::default()).is_err());
    }
    Ok(())
}

#[test]
fn empty_payload_and_zero_word_extension_are_valid() -> TestResult {
    let mut bytes = rtp(&[0xab, 0xcd, 0, 0]);
    bytes[0] = 0x90;
    let packet = RtpPacket::parse(&bytes, PacketLimits::default())?;
    assert!(packet.payload().is_empty());
    assert_eq!(
        packet.extension().ok_or("missing extension")?.bytes.len(),
        0
    );
    Ok(())
}

#[test]
fn padding_cannot_consume_header_or_extension() {
    for padding in [0, 2, 255] {
        let mut bytes = rtp(&[padding]);
        bytes[0] |= 0x20;
        assert_eq!(
            RtpPacket::parse(&bytes, PacketLimits::default()),
            Err(PacketError::Padding)
        );
    }
}

#[test]
fn fixed_header_and_extension_limits_fail_closed() {
    for length in 0..12 {
        assert_eq!(
            RtpPacket::parse(&[0; 12][..length], PacketLimits::default()),
            Err(PacketError::Truncated)
        );
    }
    let mut bytes = rtp(&[]);
    bytes[0] = 0x40;
    assert_eq!(
        RtpPacket::parse(&bytes, PacketLimits::default()),
        Err(PacketError::Version)
    );
    bytes[0] = 0x90;
    bytes.extend_from_slice(&[0, 0, 0xff, 0xff]);
    assert_eq!(
        RtpPacket::parse(&bytes, PacketLimits::default()),
        Err(PacketError::ExtensionLimit)
    );
    let limits = PacketLimits {
        max_packet_bytes: 12,
        ..PacketLimits::default()
    };
    assert_eq!(
        RtpPacket::parse(&bytes, limits),
        Err(PacketError::ByteLimit)
    );
    let limits = PacketLimits {
        max_rtcp_packets: 0,
        ..PacketLimits::default()
    };
    assert_eq!(
        RtpPacket::parse(&bytes, limits),
        Err(PacketError::InvalidLimits)
    );
}

#[test]
fn conventional_rtcp_requires_matching_cname() -> TestResult {
    let mut bytes = rr(7);
    assert_eq!(
        RtcpCompound::parse(&bytes, PacketLimits::default(), RtcpMode::Compound),
        Err(PacketError::Compound)
    );
    assert!(RtcpCompound::parse(&bytes, PacketLimits::default(), RtcpMode::ReducedSize).is_ok());
    bytes.extend_from_slice(&sdes(8));
    assert_eq!(
        RtcpCompound::parse(&bytes, PacketLimits::default(), RtcpMode::Compound),
        Err(PacketError::Compound)
    );
    bytes.extend_from_slice(&sdes(7));
    let compound = RtcpCompound::parse(&bytes, PacketLimits::default(), RtcpMode::Compound)?;
    assert_eq!(compound.packet_count(), 3);
    assert_eq!(compound.packets().len(), 3);
    assert_eq!(
        compound
            .packets()
            .map(|p| p.packet_type())
            .collect::<Vec<_>>(),
        [201, 202, 202]
    );
    Ok(())
}

#[test]
fn sender_report_preserves_mapping_and_counter_wrap() -> TestResult {
    let mut bytes = vec![0x80, 200, 0, 6];
    for word in [
        7_u32,
        0xffff_ffff,
        0x8000_1234,
        0xffff_fff0,
        0xffff_fffe,
        1234,
    ] {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    let compound = RtcpCompound::parse(&bytes, PacketLimits::default(), RtcpMode::ReducedSize)?;
    let packet = compound.packets().next().ok_or("missing packet")?;
    let sender = packet.sender_report().ok_or("missing sender report")?;
    assert_eq!(sender.ssrc, 7);
    assert_eq!(sender.ntp.middle_32(), 0xffff_8000);
    assert_eq!(sender.rtp_timestamp, 0xffff_fff0);
    assert_eq!(sender.packet_count, 0xffff_fffe);
    assert_eq!(sender.octet_count, 1234);
    assert_eq!(packet.report_blocks().len(), 0);
    Ok(())
}

#[test]
fn reception_report_sign_extends_loss_and_preserves_extensions() -> TestResult {
    for (wire, expected) in [
        (0x00_0001_u32, 1),
        (0x7f_ffff, 8_388_607),
        (0x80_0000, -8_388_608),
        (0xff_ffff, -1),
    ] {
        let mut bytes = vec![0x81, 201, 0, 8];
        bytes.extend_from_slice(&7_u32.to_be_bytes());
        bytes.extend_from_slice(&99_u32.to_be_bytes());
        bytes.push(128);
        bytes.extend_from_slice(&wire.to_be_bytes()[1..]);
        for value in [65_537_u32, 50, 0x1234_5678, 65_536] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&[9, 8, 7, 6]);
        let compound = RtcpCompound::parse(&bytes, PacketLimits::default(), RtcpMode::ReducedSize)?;
        let packet = compound.packets().next().ok_or("missing packet")?;
        let report = packet.report_blocks().next().ok_or("missing report")?;
        assert_eq!(report.ssrc, 99);
        assert_eq!(report.fraction_lost, 128);
        assert_eq!(report.cumulative_lost, expected);
        assert_eq!(report.extended_highest_sequence, 65_537);
        assert_eq!(report.jitter, 50);
        assert_eq!(report.last_sender_report, 0x1234_5678);
        assert_eq!(report.delay_since_last_sender_report, 65_536);
        assert_eq!(packet.report_extension(), Some([9, 8, 7, 6].as_slice()));
    }
    Ok(())
}

#[test]
fn malformed_suffix_never_returns_a_valid_report_prefix() {
    let mut bytes = rr(7);
    bytes.extend_from_slice(&[0x80, 200, 0, 6]);
    assert_eq!(
        RtcpCompound::parse(&bytes, PacketLimits::default(), RtcpMode::ReducedSize),
        Err(PacketError::Truncated)
    );
    bytes = rr(7);
    bytes[0] |= 1;
    assert_eq!(
        RtcpCompound::parse(&bytes, PacketLimits::default(), RtcpMode::ReducedSize),
        Err(PacketError::Report)
    );
}

#[test]
fn rtcp_padding_only_belongs_to_last_packet() -> TestResult {
    let mut padded = rr(7);
    padded[0] |= 0x20;
    padded[3] = 2;
    padded.extend_from_slice(&[0, 0, 0, 4]);
    let parsed = RtcpCompound::parse(&padded, PacketLimits::default(), RtcpMode::ReducedSize)?;
    assert_eq!(
        parsed.packets().next().ok_or("missing packet")?.body(),
        7_u32.to_be_bytes()
    );
    let mut bytes = padded.clone();
    bytes.extend_from_slice(&rr(8));
    assert_eq!(
        RtcpCompound::parse(&bytes, PacketLimits::default(), RtcpMode::ReducedSize),
        Err(PacketError::Padding)
    );
    for padding in [0, 1, 3, 12] {
        padded[11] = padding;
        assert_eq!(
            RtcpCompound::parse(&padded, PacketLimits::default(), RtcpMode::ReducedSize),
            Err(PacketError::Padding)
        );
    }
    Ok(())
}

#[test]
fn source_description_must_terminate_and_match_chunk_count() {
    for (index, value) in [(0, 0x82), (9, 200), (13, 2), (15, 1)] {
        let mut bytes = sdes(7);
        bytes[index] = value;
        assert!(
            RtcpCompound::parse(&bytes, PacketLimits::default(), RtcpMode::ReducedSize).is_err()
        );
    }
}

#[test]
fn goodbye_reason_and_application_minima_are_checked() -> TestResult {
    let bytes = [0x81, 203, 0, 2, 0, 0, 0, 7, 2, b'o', b'k', 0];
    assert!(RtcpCompound::parse(&bytes, PacketLimits::default(), RtcpMode::ReducedSize).is_ok());
    let mut bad = bytes;
    bad[8] = 4;
    assert_eq!(
        RtcpCompound::parse(&bad, PacketLimits::default(), RtcpMode::ReducedSize),
        Err(PacketError::Goodbye)
    );
    let mut app = rr(7);
    app[1] = 204;
    assert_eq!(
        RtcpCompound::parse(&app, PacketLimits::default(), RtcpMode::ReducedSize),
        Err(PacketError::Application)
    );
    app[3] = 2;
    app.extend_from_slice(b"FSS1");
    assert!(RtcpCompound::parse(&app, PacketLimits::default(), RtcpMode::ReducedSize).is_ok());
    Ok(())
}

#[test]
fn unknown_types_stay_opaque_and_counts_are_bounded() -> TestResult {
    let bytes = [0x80, 210, 0, 1, 1, 2, 3, 4];
    let compound = RtcpCompound::parse(&bytes, PacketLimits::default(), RtcpMode::ReducedSize)?;
    let packet = compound.packets().next().ok_or("missing packet")?;
    assert!(packet.sender_report().is_none());
    assert_eq!(packet.report_blocks().len(), 0);
    assert_eq!(packet.body(), [1, 2, 3, 4]);
    let mut doubled = bytes.to_vec();
    doubled.extend_from_slice(&bytes);
    let limits = PacketLimits {
        max_rtcp_packets: 1,
        ..PacketLimits::default()
    };
    assert_eq!(
        RtcpCompound::parse(&doubled, limits, RtcpMode::ReducedSize),
        Err(PacketError::PacketCount)
    );
    Ok(())
}

#[test]
fn debug_output_never_includes_source_or_sdes_text() -> TestResult {
    let bytes = rtp(b"private-media-secret");
    let packet = RtpPacket::parse(&bytes, PacketLimits::default())?;
    assert!(!format!("{packet:?}").contains("private"));
    let mut bytes = rr(7);
    bytes.extend_from_slice(&sdes(7));
    let compound = RtcpCompound::parse(&bytes, PacketLimits::default(), RtcpMode::Compound)?;
    assert!(!format!("{compound:?}").contains("cam"));
    for packet in compound.packets() {
        assert!(!format!("{packet:?}").contains("cam"));
    }
    Ok(())
}

#[test]
fn deterministic_hostile_corpus_never_panics_or_exposes_out_of_bounds_spans() {
    let mut seed = 0x4f53_5321_u64;
    for length in 0..512 {
        for _ in 0..16 {
            let mut bytes = vec![0; length];
            for byte in &mut bytes {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *byte = (seed >> 32) as u8;
            }
            if let Ok(packet) = RtpPacket::parse(&bytes, PacketLimits::default()) {
                let range = packet.payload_range();
                assert!(range.start <= range.end && range.end <= bytes.len());
                assert_eq!(packet.payload(), &bytes[range]);
                assert_eq!(packet.csrcs().count(), usize::from(bytes[0] & 15));
            }
            for mode in [RtcpMode::Compound, RtcpMode::ReducedSize] {
                if let Ok(compound) = RtcpCompound::parse(&bytes, PacketLimits::default(), mode) {
                    assert_eq!(compound.packets().count(), compound.packet_count());
                    assert_eq!(
                        compound
                            .packets()
                            .map(|p| p.wire_bytes().len())
                            .sum::<usize>(),
                        bytes.len()
                    );
                    for packet in compound.packets() {
                        let _ = packet.sender_report();
                        let _ = packet.report_blocks().collect::<Vec<_>>();
                    }
                }
            }
        }
    }
}
