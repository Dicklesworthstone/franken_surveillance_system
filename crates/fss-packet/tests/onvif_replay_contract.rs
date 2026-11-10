#![forbid(unsafe_code)]
//! Wire and numeric boundary contracts for historical recorder assertions.

use fss_packet::onvif_replay::{
    MAX_RECORDED_UTC_NS, REPLAY_EXTENSION_BYTES, REPLAY_EXTENSION_PROFILE, RecordedUtcInterval,
    ReplayExtensionError as Error, ReplayHeaderExtension, parse_replay_extension,
};
use fss_packet::{HeaderExtension, NtpTimestamp, PacketLimits, RtpPacket};

const UNIX_EPOCH_NTP_SECONDS: u32 = 2_208_988_800;
type Test = Result<(), Box<dyn std::error::Error>>;

fn extension(seconds: u32, fraction: u32, flags: u8, cseq: u8) -> [u8; 12] {
    let mut bytes = [0_u8; 12];
    bytes[..4].copy_from_slice(&seconds.to_be_bytes());
    bytes[4..8].copy_from_slice(&fraction.to_be_bytes());
    bytes[8] = flags;
    bytes[9] = cseq;
    bytes
}

fn parse(bytes: &[u8]) -> Result<ReplayHeaderExtension, Error> {
    parse_replay_extension(HeaderExtension {
        profile: REPLAY_EXTENSION_PROFILE,
        bytes,
    })?
    .ok_or(Error::Length)
}

fn observed(seconds: u32, fraction: u32) -> ReplayHeaderExtension {
    parse(&extension(seconds, fraction, 0, 7)).expect("fixed valid fixture")
}

#[test]
fn known_extension_preserves_exact_network_order_fields() -> Test {
    let value = parse(&extension(0xA1B2_C3D4, 0xE5F6_0718, 0xF0, 0x91))?;
    assert_eq!(REPLAY_EXTENSION_PROFILE, 0xABAC);
    assert_eq!(REPLAY_EXTENSION_BYTES, 12);
    assert_eq!(
        value.ntp,
        NtpTimestamp {
            seconds: 0xA1B2_C3D4,
            fraction: 0xE5F6_0718,
        }
    );
    assert!(value.clean_point);
    assert!(value.end_of_contiguous_section);
    assert!(value.discontinuity);
    assert!(value.terminal);
    assert_eq!(value.cseq_low, 0x91);
    Ok(())
}

#[test]
fn each_replay_flag_is_independent_and_never_relabels_its_neighbour() -> Test {
    for bits in 0_u8..16 {
        let flags = bits << 4;
        let value = parse(&extension(UNIX_EPOCH_NTP_SECONDS, 1, flags, 0))?;
        assert_eq!(value.clean_point, flags & 0x80 != 0);
        assert_eq!(value.end_of_contiguous_section, flags & 0x40 != 0);
        assert_eq!(value.discontinuity, flags & 0x20 != 0);
        assert_eq!(value.terminal, flags & 0x10 != 0);
        assert_eq!(value.ntp.fraction, 1);
    }
    Ok(())
}

#[test]
fn all_reserved_flag_patterns_refuse_even_with_valid_time() {
    for reserved in 1_u8..16 {
        assert_eq!(
            parse(&extension(UNIX_EPOCH_NTP_SECONDS, 0, 0xF0 | reserved, 7)),
            Err(Error::ReservedBits)
        );
    }
}

#[test]
fn known_profile_requires_the_exact_avc_hevc_length_including_no_jpeg_tail() {
    for length in 0..=64 {
        let bytes = vec![0; length];
        if length == REPLAY_EXTENSION_BYTES {
            assert!(parse(&bytes).is_ok());
        } else {
            assert_eq!(parse(&bytes), Err(Error::Length));
        }
    }
    let mut combined = extension(UNIX_EPOCH_NTP_SECONDS, 0, 0, 7).to_vec();
    combined.extend_from_slice(&[0xFF, 0xD8, 0, 0]);
    assert_eq!(parse(&combined), Err(Error::Length));
}

#[test]
fn a_foreign_extension_never_becomes_a_malformed_or_guessed_replay_header() -> Test {
    for profile in [0, 0xABAB, 0xABAD, 0xBEDE, 0x1000, 0xFFD8, 0xFFFF] {
        for bytes in [&[][..], &[0xFF][..], &[0xFF; 12][..], &[0xFF; 64][..]] {
            assert_eq!(
                parse_replay_extension(HeaderExtension { profile, bytes })?,
                None
            );
        }
    }
    assert_eq!(
        parse_replay_extension(HeaderExtension {
            profile: REPLAY_EXTENSION_PROFILE,
            bytes: &[0xFF],
        }),
        Err(Error::Length)
    );
    Ok(())
}

#[test]
fn padding_does_not_change_the_semantic_assertion_or_invent_reserved_bits() -> Test {
    let plain = extension(UNIX_EPOCH_NTP_SECONDS, 0x8000_0000, 0xA0, 7);
    let expected = parse(&plain)?;
    for padding in [[0, 0], [0xFF, 0xFF], [0xCA, 0xFE], [0, 1]] {
        let mut bytes = plain;
        bytes[10..12].copy_from_slice(&padding);
        assert_eq!(parse(&bytes)?, expected);
        assert_eq!(&bytes[10..12], &padding);
    }
    Ok(())
}

#[test]
fn real_rtp_csrc_extension_and_padding_spans_preserve_the_original_payload() -> Test {
    let mut wire = vec![0xB2, 0xE0, 0, 42];
    wire.extend_from_slice(&90_000_u32.to_be_bytes());
    wire.extend_from_slice(&7_u32.to_be_bytes());
    wire.extend_from_slice(&9_u32.to_be_bytes());
    wire.extend_from_slice(&10_u32.to_be_bytes());
    wire.extend_from_slice(&REPLAY_EXTENSION_PROFILE.to_be_bytes());
    wire.extend_from_slice(&3_u16.to_be_bytes());
    let mut content = extension(UNIX_EPOCH_NTP_SECONDS, 0x8000_0000, 0x80, 7);
    content[10..12].copy_from_slice(&[0xCA, 0xFE]);
    wire.extend_from_slice(&content);
    let payload = [0x65, 0x88, 0x84];
    wire.extend_from_slice(&payload);
    wire.extend_from_slice(&[0, 0, 0, 4]);
    let before = wire.clone();

    let packet = RtpPacket::parse(&wire, PacketLimits::default())?;
    assert_eq!(packet.csrcs().collect::<Vec<_>>(), vec![9, 10]);
    assert_eq!(packet.sequence(), 42);
    assert_eq!(packet.timestamp(), 90_000);
    assert_eq!(packet.ssrc(), 7);
    assert_eq!(packet.payload_type(), 96);
    assert!(packet.marker());
    assert_eq!(packet.padding_len(), 4);
    assert_eq!(packet.payload(), payload);
    let parsed = parse_replay_extension(packet.extension().ok_or("extension")?)?
        .ok_or("recorded profile")?;
    assert_eq!(
        parsed.utc_for_era(0)?,
        RecordedUtcInterval {
            earliest_ns: 500_000_000,
            latest_ns: 500_000_000,
        }
    );
    assert!(parsed.clean_point);
    assert_eq!(packet.wire_bytes(), before);
    assert_eq!(wire, before);
    Ok(())
}

#[test]
fn rtp_framing_failure_remains_distinct_from_a_known_extension_content_failure() -> Test {
    let mut wire = vec![0x90, 96, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7];
    wire.extend_from_slice(&REPLAY_EXTENSION_PROFILE.to_be_bytes());
    wire.extend_from_slice(&3_u16.to_be_bytes());
    wire.extend_from_slice(&[0; 11]);
    assert!(RtpPacket::parse(&wire, PacketLimits::default()).is_err());

    wire[14..16].copy_from_slice(&2_u16.to_be_bytes());
    let packet = RtpPacket::parse(&wire, PacketLimits::default())?;
    assert_eq!(packet.payload(), &[0, 0, 0]);
    assert_eq!(
        parse_replay_extension(packet.extension().ok_or("extension")?),
        Err(Error::Length)
    );
    Ok(())
}

#[test]
fn absent_header_is_not_repaired_from_payload_timestamp_marker_or_ssrc() -> Test {
    let wire = [
        0x80, 0xE0, 0, 1, 0xAB, 0xAC, 0, 3, 0, 0, 0, 7, 0xAB, 0xAC, 0, 3,
    ];
    let packet = RtpPacket::parse(&wire, PacketLimits::default())?;
    assert!(packet.marker());
    assert!(packet.extension().is_none());
    assert_eq!(packet.payload(), &[0xAB, 0xAC, 0, 3]);
    Ok(())
}

#[test]
fn play_correlation_checks_only_low_bits_and_exposes_the_256_sequence_ambiguity() -> Test {
    let value = observed(UNIX_EPOCH_NTP_SECONDS, 0);
    value.correlate_play(7)?;
    value.correlate_play(263)?;
    value.correlate_play(0xFFFF_FF07)?;
    assert_eq!(value.correlate_play(8), Err(Error::PlayCseqMismatch));
    assert_eq!(value.correlate_play(0), Err(Error::InvalidPlayCseq));
    let zero = parse(&extension(UNIX_EPOCH_NTP_SECONDS, 0, 0, 0))?;
    zero.correlate_play(256)?;
    assert_eq!(zero.correlate_play(0), Err(Error::InvalidPlayCseq));
    let maximum = parse(&extension(UNIX_EPOCH_NTP_SECONDS, 0, 0, 255))?;
    maximum.correlate_play(u32::MAX)?;
    Ok(())
}

#[test]
fn utc_conversion_preserves_exact_whole_half_and_binary_fractional_seconds() -> Test {
    for (fraction, nanos) in [
        (0, 0),
        (0x8000_0000, 500_000_000),
        (0x4000_0000, 250_000_000),
        (0x0100_0000, 3_906_250),
        (0x0080_0000, 1_953_125),
    ] {
        assert_eq!(
            observed(UNIX_EPOCH_NTP_SECONDS + 12, fraction).utc_for_era(0)?,
            RecordedUtcInterval {
                earliest_ns: 12_000_000_000 + nanos,
                latest_ns: 12_000_000_000 + nanos,
            }
        );
    }
    Ok(())
}

#[test]
fn sub_nanosecond_fractions_round_outward_including_the_next_second() -> Test {
    for (fraction, earliest_ns, latest_ns) in [
        (1, 0, 1),
        (4, 0, 1),
        (5, 1, 2),
        (0x007F_FFFF, 1_953_124, 1_953_125),
        (u32::MAX, 999_999_999, 1_000_000_000),
    ] {
        assert_eq!(
            observed(UNIX_EPOCH_NTP_SECONDS, fraction).utc_for_era(0)?,
            RecordedUtcInterval {
                earliest_ns,
                latest_ns,
            }
        );
    }
    Ok(())
}

#[test]
fn explicit_era_changes_numeric_time_without_using_a_replay_or_host_clock_hint() -> Test {
    let value = observed(UNIX_EPOCH_NTP_SECONDS, 1);
    let era_zero = value.utc_for_era(0)?;
    let era_one = value.utc_for_era(1)?;
    assert_eq!(era_zero.earliest_ns, 0);
    assert_eq!(era_zero.latest_ns, 1);
    assert_eq!(era_one.earliest_ns - era_zero.earliest_ns, 4_294_967_296_000_000_000);
    assert_eq!(era_one.latest_ns - era_zero.latest_ns, 4_294_967_296_000_000_000);
    assert_eq!(value.ntp.seconds, UNIX_EPOCH_NTP_SECONDS);
    assert_eq!(value.ntp.fraction, 1);
    Ok(())
}

#[test]
fn era_rollover_requires_explicit_bases_and_never_turns_zero_into_a_valid_date() -> Test {
    let before = observed(u32::MAX, u32::MAX).utc_for_era(0)?;
    let after = observed(0, 1).utc_for_era(1)?;
    assert_eq!(before.earliest_ns, 2_085_978_495_999_999_999);
    assert_eq!(before.latest_ns, 2_085_978_496_000_000_000);
    assert_eq!(after.earliest_ns, 2_085_978_496_000_000_000);
    assert_eq!(after.latest_ns, 2_085_978_496_000_000_001);
    assert_eq!(observed(0, 1).utc_for_era(0), Err(Error::UtcRange));
    assert_eq!(observed(0, 0).utc_for_era(1), Err(Error::UnknownTimestamp));
    Ok(())
}

#[test]
fn unknown_time_preserves_flags_and_correlation_without_creating_epoch_evidence() -> Test {
    let value = parse(&extension(0, 0, 0x70, 7))?;
    assert!(value.end_of_contiguous_section);
    assert!(value.discontinuity);
    assert!(value.terminal);
    value.correlate_play(7)?;
    for era in [0, 1, 59, u32::MAX] {
        assert_eq!(value.utc_for_era(era), Err(Error::UnknownTimestamp));
    }
    Ok(())
}

#[test]
fn unsupported_utc_and_maximum_era_values_refuse_without_overflow_or_clamping() -> Test {
    assert_eq!(
        observed(UNIX_EPOCH_NTP_SECONDS - 1, u32::MAX).utc_for_era(0),
        Err(Error::UtcRange)
    );
    assert_eq!(observed(u32::MAX, u32::MAX).utc_for_era(u32::MAX), Err(Error::UtcRange));

    let last_ntp_second = 255_611_289_599_u64;
    let era = (last_ntp_second >> 32) as u32;
    let seconds = last_ntp_second as u32;
    assert_eq!(era, 59);
    assert_eq!(
        observed(seconds, 0).utc_for_era(era)?,
        RecordedUtcInterval {
            earliest_ns: 253_402_300_799_000_000_000,
            latest_ns: 253_402_300_799_000_000_000,
        }
    );
    // The final fraction rounds its upper endpoint into year 10000. This
    // bounded profile refuses instead of clipping away that uncertainty.
    assert_eq!(observed(seconds, u32::MAX).utc_for_era(era), Err(Error::UtcRange));
    assert_eq!(observed(seconds + 1, 0).utc_for_era(era), Err(Error::UtcRange));
    assert_eq!(MAX_RECORDED_UTC_NS, 253_402_300_799_999_999_999);
    Ok(())
}

#[test]
fn integer_interval_encloses_the_exact_rational_value_without_float_or_wrap() -> Test {
    let fractions = [
        0, 1, 2, 3, 4, 5, 0x007F_FFFF, 0x0080_0000, 0x1234_5678,
        0x4000_0000, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFE, u32::MAX,
    ];
    let scale = 1_i128 << 32;
    for era in [0_u32, 1, 2, 58] {
        for fraction in fractions {
            let value = observed(UNIX_EPOCH_NTP_SECONDS, fraction);
            let result = value.utc_for_era(era)?;
            let exact_numerator =
                i128::from(era) * scale * 1_000_000_000 * scale
                    + i128::from(fraction) * 1_000_000_000;
            assert!(result.earliest_ns * scale <= exact_numerator);
            assert!(result.latest_ns * scale >= exact_numerator);
            assert!((0..=1).contains(&(result.latest_ns - result.earliest_ns)));
        }
    }
    Ok(())
}

#[test]
fn refusal_codes_are_stable_payload_free_and_distinguish_unknown_from_invalid() {
    let reasons = [
        (Error::Length, "ERR-RTP-REPLAY-EXTENSION-LENGTH-001"),
        (Error::ReservedBits, "ERR-RTP-REPLAY-RESERVED-001"),
        (Error::UnknownTimestamp, "ERR-RTP-REPLAY-TIME-UNKNOWN-001"),
        (Error::UtcRange, "ERR-RTP-REPLAY-UTC-RANGE-001"),
        (Error::InvalidPlayCseq, "ERR-RTP-REPLAY-CSEQ-INVALID-001"),
        (Error::PlayCseqMismatch, "ERR-RTP-REPLAY-CSEQ-MISMATCH-001"),
    ];
    for (reason, expected) in reasons {
        assert_eq!(reason.code(), expected);
        assert_eq!(reason.to_string(), expected);
        assert!(reason.code().len() <= 64);
        assert!(!format!("{reason:?}").contains("private"));
    }
}
