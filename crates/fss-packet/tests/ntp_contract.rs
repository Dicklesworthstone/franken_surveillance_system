#![forbid(unsafe_code)]
//! Deterministic RFC 5905 basic-mode wire and conservative-interval contracts.
//!
//! No test contacts a time server, reads a clock or changes host time. The reply
//! fields are explicit server assertions, not UTC accuracy qualification.

use fss_packet::NtpTimestamp;
use fss_packet::ntp::{
    DurationInterval, LocalExchange, MAX_EXCHANGE_NS, MAX_OFFSET_NS, MAX_UNCERTAINTY_NS,
    OffsetInterval, PACKET_BYTES, SntpError, SntpLimits, SntpObservation, SntpRequest,
    UnixTimeInterval,
};

type Test = Result<(), Box<dyn std::error::Error>>;
const BASE: u64 = 1_700_000_000_000_000_000;
const SECOND: u64 = 1_000_000_000;

fn limits() -> SntpLimits {
    SntpLimits {
        max_exchange_ns: MAX_EXCHANGE_NS,
        max_offset_ns: MAX_OFFSET_NS,
        max_uncertainty_ns: MAX_UNCERTAINTY_NS,
    }
}

fn interval(earliest_ns: u64, latest_ns: u64) -> UnixTimeInterval {
    UnixTimeInterval {
        earliest_ns,
        latest_ns,
    }
}

fn times(start: u64, end: u64) -> LocalExchange {
    LocalExchange {
        sent: interval(start, start),
        received: interval(end, end),
    }
}

// Independent fixture encoder. It does not call the request constructor or the
// production timestamp helpers, and tests below separately lock known wire bytes.
fn put_time(reply: &mut [u8; PACKET_BYTES], at: usize, unix_ns: u64) {
    let total = u128::from(unix_ns);
    let seconds = ((total / 1_000_000_000 + 2_208_988_800) & 0xffff_ffff) as u32;
    let fraction = ((total % 1_000_000_000) * 0x1_0000_0000_u128 / 1_000_000_000) as u32;
    reply[at..at + 4].copy_from_slice(&seconds.to_be_bytes());
    reply[at + 4..at + 8].copy_from_slice(&fraction.to_be_bytes());
}

fn reply(request: &SntpRequest, receive: u64, transmit: u64) -> [u8; PACKET_BYTES] {
    let mut packet = [0_u8; PACKET_BYTES];
    packet[0] = (4 << 3) | 4;
    packet[1] = 2;
    packet[2] = 6;
    packet[3] = (-20_i8) as u8;
    packet[12..16].copy_from_slice(&[127, 0, 0, 1]);
    put_time(&mut packet, 16, receive.saturating_sub(SECOND));
    packet[24..32].copy_from_slice(&request.wire_bytes()[40..48]);
    put_time(&mut packet, 32, receive);
    put_time(&mut packet, 40, transmit);
    packet
}

fn ordinary() -> Result<(SntpRequest, [u8; PACKET_BYTES], LocalExchange), SntpError> {
    let request = SntpRequest::new(BASE)?;
    let packet = reply(&request, BASE + 375_000_000, BASE + 500_000_000);
    Ok((request, packet, times(BASE, BASE + 250_000_000)))
}

fn contains(observation: SntpObservation, value: i64) -> bool {
    observation.offset_interval_ns.lower_ns <= value
        && value <= observation.offset_interval_ns.upper_ns
        && i128::from(observation.offset_ns) - i128::from(observation.uncertainty_ns)
            <= i128::from(value)
        && i128::from(value)
            <= i128::from(observation.offset_ns) + i128::from(observation.uncertainty_ns)
}

#[test]
fn request_is_exact_basic_mode_with_known_epoch_and_fraction_bytes() -> Test {
    let request = SntpRequest::new(500_000_000)?;
    let mut expected = [0_u8; 48];
    expected[0] = 0x23;
    expected[40..48].copy_from_slice(&[0x83, 0xaa, 0x7e, 0x80, 0x80, 0, 0, 0]);
    assert_eq!(request.wire_bytes(), &expected);
    assert_eq!(
        request.transmit_timestamp(),
        NtpTimestamp {
            seconds: 2_208_988_800,
            fraction: 0x8000_0000,
        }
    );
    assert_eq!(SntpRequest::new(500_000_000)?, request);
    assert!(SntpRequest::new(0).is_ok());
    Ok(())
}

#[test]
fn four_timestamp_arithmetic_preserves_measured_asymmetric_delay_interval() -> Test {
    let (request, packet, local) = ordinary()?;
    let measured = request.evaluate_reply(&packet, local, limits())?;
    assert_eq!(
        measured.local_elapsed_ns,
        DurationInterval {
            lower_ns: 250_000_000,
            upper_ns: 250_000_000,
        }
    );
    assert_eq!(
        measured.server_processing_ns,
        DurationInterval {
            lower_ns: 125_000_000,
            upper_ns: 125_000_000,
        }
    );
    assert_eq!(
        measured.server_processing_ns,
        measured.network_round_trip_ns
    );
    assert_eq!(measured.offset_ns, 312_500_000);
    assert_eq!(measured.server_precision_ns, 954);
    assert_eq!(measured.frequency_tolerance_ns, 3750);
    assert_eq!(measured.uncertainty_ns, 62_504_704);
    assert_eq!(
        measured.offset_interval_ns,
        OffsetInterval {
            lower_ns: 249_995_296,
            upper_ns: 375_004_704,
        }
    );
    assert_eq!(measured.stratum, 2);
    assert_eq!(measured.poll_log2, 6);
    assert_eq!(measured.precision_log2, -20);
    assert_eq!(measured.reference_id, [127, 0, 0, 1]);
    assert_eq!(measured.leap_indicator, 0);
    assert_eq!(measured.root_delay_ns, 0);
    assert_eq!(measured.root_dispersion_ns, 0);
    Ok(())
}

#[test]
fn negative_offsets_and_half_nanosecond_midpoints_round_outward() -> Test {
    let (request, _, local) = ordinary()?;
    let packet = reply(&request, BASE - 125_000_000, BASE);
    let negative = request.evaluate_reply(&packet, local, limits())?;
    assert_eq!(negative.offset_ns, -187_500_000);
    assert!(contains(negative, -250_000_000));
    assert!(contains(negative, -125_000_000));
    let mut fractional = reply(&request, BASE, BASE);
    fractional[3] = (-128_i8) as u8;
    // A single NTP fraction tick is less than one nanosecond. The interval must
    // still cover it, including when converted to signed negative bounds.
    fractional[39] = 1;
    fractional[47] = 1;
    let measured = request.evaluate_reply(&fractional, times(BASE, BASE + 1), limits())?;
    assert_eq!(measured.offset_interval_ns.lower_ns, -3);
    assert_eq!(measured.offset_interval_ns.upper_ns, 3);
    assert_eq!(measured.offset_ns, 0);
    assert_eq!(measured.uncertainty_ns, 3);
    Ok(())
}

#[test]
fn root_delay_dispersion_and_precision_can_only_widen_the_result() -> Test {
    let (request, packet, local) = ordinary()?;
    let original = request.evaluate_reply(&packet, local, limits())?;
    let mut coarse = packet;
    coarse[4..8].copy_from_slice(&1_u32.to_be_bytes());
    coarse[8..12].copy_from_slice(&1_u32.to_be_bytes());
    let widened = request.evaluate_reply(&coarse, local, limits())?;
    assert_eq!(widened.root_delay_ns, 15_259);
    assert_eq!(widened.root_dispersion_ns, 15_259);
    assert_eq!(widened.offset_ns, original.offset_ns);
    assert_eq!(widened.uncertainty_ns, original.uncertainty_ns + 22_889);
    assert!(widened.offset_interval_ns.lower_ns < original.offset_interval_ns.lower_ns);
    assert!(widened.offset_interval_ns.upper_ns > original.offset_interval_ns.upper_ns);
    coarse[3] = (-10_i8) as u8;
    let less_precise = request.evaluate_reply(&coarse, local, limits())?;
    assert_eq!(less_precise.server_precision_ns, 976_563);
    assert!(less_precise.uncertainty_ns > widened.uncertainty_ns);
    Ok(())
}

#[test]
fn wider_local_sampling_brackets_never_narrow_an_accepted_interval() -> Test {
    let (request, packet, local) = ordinary()?;
    let exact = request.evaluate_reply(&packet, local, limits())?;
    for send_radius in [1, 101, 100_000] {
        for receive_radius in [1, 303, 1_000_000] {
            let mut wider = local;
            wider.sent = interval(BASE - send_radius, BASE + send_radius);
            wider.received = interval(
                local.received.earliest_ns - receive_radius,
                local.received.latest_ns + receive_radius,
            );
            let measured = request.evaluate_reply(&packet, wider, limits())?;
            assert!(measured.offset_interval_ns.lower_ns <= exact.offset_interval_ns.lower_ns);
            assert!(measured.offset_interval_ns.upper_ns >= exact.offset_interval_ns.upper_ns);
            assert!(
                measured.network_round_trip_ns.lower_ns <= exact.network_round_trip_ns.lower_ns
            );
            assert!(
                measured.network_round_trip_ns.upper_ns >= exact.network_round_trip_ns.upper_ns
            );
        }
    }
    Ok(())
}

#[test]
fn unequal_forward_and_reverse_delays_preserve_the_actual_declared_offset() -> Test {
    let request = SntpRequest::new(BASE)?;
    for offset in [-750_000_001_i64, -1, 0, 1, 1_500_000_001] {
        for forward in [0_u64, 1, 10_001, 100_000_000] {
            for reverse in [0_u64, 1, 20_003, 300_000_000] {
                for process in [0_u64, 1_000_000, 250_000_000] {
                    let receive =
                        (i128::from(BASE) + i128::from(forward) + i128::from(offset)) as u64;
                    let transmit = receive + process;
                    let packet = reply(&request, receive, transmit);
                    let end = BASE + forward + process + reverse;
                    // Independent fixed-point truncation of the two server
                    // timestamps can lengthen their difference by <1 ns. Keep
                    // zero-path cases, but supply the explicit local quantization
                    // bracket instead of asserting an impossible exact duration.
                    let local = LocalExchange {
                        sent: interval(BASE, BASE),
                        received: interval(end, end + 1),
                    };
                    let observation = request.evaluate_reply(&packet, local, limits())?;
                    assert!(contains(observation, offset));
                    assert!(observation.network_round_trip_ns.lower_ns <= forward + reverse);
                    assert!(forward + reverse <= observation.network_round_trip_ns.upper_ns);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn exact_origin_fraction_is_required_and_repeated_evaluation_is_deterministic() -> Test {
    let (request, packet, local) = ordinary()?;
    let accepted = request.evaluate_reply(&packet, local, limits())?;
    assert_eq!(request.evaluate_reply(&packet, local, limits())?, accepted);
    for index in 24..32 {
        let mut altered = packet;
        altered[index] ^= 1;
        assert_eq!(
            request.evaluate_reply(&altered, local, limits()),
            Err(SntpError::Origin)
        );
    }
    let other = SntpRequest::new(BASE + 1)?;
    assert_eq!(
        other.evaluate_reply(&packet, times(BASE, BASE + 250_000_000), limits()),
        Err(SntpError::LocalTime)
    );
    let other_local = LocalExchange {
        sent: interval(BASE, BASE + 1),
        received: local.received,
    };
    assert_eq!(
        other.evaluate_reply(&packet, other_local, limits()),
        Err(SntpError::Origin)
    );
    Ok(())
}

#[test]
fn every_truncation_and_unsupported_trailer_refuses_without_a_prefix() -> Test {
    let (request, packet, local) = ordinary()?;
    for length in 0..PACKET_BYTES {
        assert_eq!(
            request.evaluate_reply(&packet[..length], local, limits()),
            Err(SntpError::Length)
        );
    }
    for extra in [1, 4, 16, 20, 24, 48, 1024] {
        let mut bytes = packet.to_vec();
        bytes.resize(PACKET_BYTES + extra, 0);
        assert_eq!(
            request.evaluate_reply(&bytes, local, limits()),
            Err(SntpError::Length)
        );
    }
    Ok(())
}

#[test]
fn only_version_four_server_mode_and_synchronized_strata_are_admitted() -> Test {
    let (request, packet, local) = ordinary()?;
    for version in 0_u8..8 {
        let mut changed = packet;
        changed[0] = (version << 3) | 4;
        assert_eq!(
            request.evaluate_reply(&changed, local, limits()).is_ok(),
            version == 4
        );
    }
    for mode in 0_u8..8 {
        let mut changed = packet;
        changed[0] = (4 << 3) | mode;
        assert_eq!(
            request.evaluate_reply(&changed, local, limits()).is_ok(),
            mode == 4
        );
    }
    for stratum in 0_u8..=255 {
        let mut changed = packet;
        changed[1] = stratum;
        match stratum {
            0 => assert_eq!(
                request.evaluate_reply(&changed, local, limits()),
                Err(SntpError::KissOfDeath)
            ),
            1..=15 => assert_eq!(
                request.evaluate_reply(&changed, local, limits())?.stratum,
                stratum
            ),
            _ => assert_eq!(
                request.evaluate_reply(&changed, local, limits()),
                Err(SntpError::Unsynchronized)
            ),
        }
    }
    for leap in 0_u8..4 {
        let mut changed = packet;
        changed[0] |= leap << 6;
        if leap == 3 {
            assert_eq!(
                request.evaluate_reply(&changed, local, limits()),
                Err(SntpError::Unsynchronized)
            );
        } else {
            assert_eq!(
                request
                    .evaluate_reply(&changed, local, limits())?
                    .leap_indicator,
                leap
            );
        }
    }
    Ok(())
}

#[test]
fn kiss_codes_and_zero_remote_timestamps_are_never_measurements() -> Test {
    let (request, packet, local) = ordinary()?;
    for code in [*b"RATE", *b"DENY", *b"RSTR", [0xff; 4], [0; 4]] {
        let mut kod = packet;
        kod[1] = 0;
        kod[12..16].copy_from_slice(&code);
        assert_eq!(
            request.evaluate_reply(&kod, local, limits()),
            Err(SntpError::KissOfDeath)
        );
        assert!(!SntpError::KissOfDeath.to_string().contains("RATE"));
    }
    for at in [16, 32, 40] {
        let mut zero = packet;
        zero[at..at + 8].fill(0);
        assert_eq!(
            request.evaluate_reply(&zero, local, limits()),
            Err(SntpError::ZeroTimestamp)
        );
    }
    Ok(())
}

#[test]
fn remote_processing_and_reference_order_use_exact_fixed_point_values() -> Test {
    let (request, packet, local) = ordinary()?;
    let reversed = reply(&request, BASE + 500_000_000, BASE + 375_000_000);
    assert_eq!(
        request.evaluate_reply(&reversed, local, limits()),
        Err(SntpError::Timing)
    );
    let too_long = reply(&request, BASE, BASE + 500_000_000);
    assert_eq!(
        request.evaluate_reply(&too_long, local, limits()),
        Err(SntpError::Timing)
    );
    let mut future_reference = packet;
    put_time(&mut future_reference, 16, BASE + SECOND);
    assert_eq!(
        request.evaluate_reply(&future_reference, local, limits()),
        Err(SntpError::Timing)
    );
    let mut tiny = reply(&request, BASE, BASE);
    tiny[47] = 1;
    // Exact server processing is 2^-32 s > zero, even though ns flooring gives 0.
    assert_eq!(
        request.evaluate_reply(&tiny, times(BASE, BASE), limits()),
        Err(SntpError::Timing)
    );
    tiny[39] = 2;
    assert_eq!(
        request.evaluate_reply(&tiny, times(BASE, BASE + 1), limits()),
        Err(SntpError::Timing)
    );
    Ok(())
}

#[test]
fn malformed_local_brackets_and_expired_exchange_refuse() -> Test {
    let (request, packet, local) = ordinary()?;
    for malformed in [
        LocalExchange {
            sent: interval(BASE + 1, BASE + 2),
            ..local
        },
        LocalExchange {
            sent: interval(BASE - 2, BASE - 1),
            ..local
        },
        LocalExchange {
            sent: interval(BASE + 1, BASE),
            ..local
        },
        LocalExchange {
            received: interval(BASE + 2, BASE + 1),
            ..local
        },
        LocalExchange {
            sent: interval(BASE, BASE + 10),
            received: interval(BASE + 9, BASE + 20),
        },
        LocalExchange {
            received: interval(BASE - 2, BASE - 1),
            ..local
        },
    ] {
        assert_eq!(
            request.evaluate_reply(&packet, malformed, limits()),
            Err(SntpError::LocalTime)
        );
    }
    let mut expired = local;
    expired.received = interval(BASE + SECOND + 1, BASE + SECOND + 1);
    assert_eq!(
        request.evaluate_reply(&packet, expired, limits()),
        Err(SntpError::ExchangeLimit)
    );
    let mut narrow = limits();
    narrow.max_exchange_ns = 250_000_000;
    assert!(request.evaluate_reply(&packet, local, narrow).is_ok());
    narrow.max_exchange_ns -= 1;
    assert_eq!(
        request.evaluate_reply(&packet, local, narrow),
        Err(SntpError::ExchangeLimit)
    );
    Ok(())
}

#[test]
fn malicious_precisions_root_distance_and_explicit_limits_cannot_wrap() -> Test {
    let (request, packet, local) = ordinary()?;
    for exponent in i8::MIN..=i8::MAX {
        let mut changed = packet;
        changed[3] = exponent as u8;
        if exponent <= 3 {
            assert!(
                request
                    .evaluate_reply(&changed, local, limits())?
                    .server_precision_ns
                    >= 1
            );
        } else {
            assert_eq!(
                request.evaluate_reply(&changed, local, limits()),
                Err(SntpError::Uncertainty)
            );
        }
    }
    for signed in [0x8000_0000_u32, 0xffff_ffff] {
        let mut changed = packet;
        changed[4..8].copy_from_slice(&signed.to_be_bytes());
        assert_eq!(
            request.evaluate_reply(&changed, local, limits()),
            Err(SntpError::RootDelay)
        );
    }
    for at in [4, 8] {
        let mut changed = packet;
        changed[at..at + 4].copy_from_slice(&0x7fff_ffff_u32.to_be_bytes());
        assert_eq!(
            request.evaluate_reply(&changed, local, limits()),
            Err(SntpError::Uncertainty)
        );
    }
    for bad in [
        SntpLimits {
            max_exchange_ns: 0,
            ..limits()
        },
        SntpLimits {
            max_exchange_ns: MAX_EXCHANGE_NS + 1,
            ..limits()
        },
        SntpLimits {
            max_offset_ns: 0,
            ..limits()
        },
        SntpLimits {
            max_offset_ns: u64::MAX,
            ..limits()
        },
        SntpLimits {
            max_uncertainty_ns: 0,
            ..limits()
        },
        SntpLimits {
            max_uncertainty_ns: u64::MAX,
            ..limits()
        },
    ] {
        assert_eq!(
            request.evaluate_reply(&packet, local, bad),
            Err(SntpError::Limits)
        );
    }
    let narrow = SntpLimits {
        max_uncertainty_ns: 100,
        ..limits()
    };
    assert_eq!(
        request.evaluate_reply(&packet, local, narrow),
        Err(SntpError::Uncertainty)
    );
    let small_offset = SntpLimits {
        max_offset_ns: 100,
        ..limits()
    };
    assert_eq!(
        request.evaluate_reply(&packet, local, small_offset),
        Err(SntpError::Offset)
    );
    for shift in [-11_i128, 11] {
        let shifted = reply(
            &request,
            (i128::from(BASE) + shift * i128::from(SECOND)) as u64,
            (i128::from(BASE) + shift * i128::from(SECOND)) as u64,
        );
        assert_eq!(
            request.evaluate_reply(&shifted, times(BASE, BASE), limits()),
            Err(SntpError::Offset)
        );
    }
    Ok(())
}

#[test]
fn era_rollover_is_unfolded_from_the_same_explicit_local_hint() -> Test {
    for era in [1_u64, 2, 3, 4] {
        let rollover = (era * 0x1_0000_0000 - 2_208_988_800) * SECOND;
        assert_eq!(SntpRequest::new(rollover), Err(SntpError::ZeroTimestamp));
        let local_start = rollover - 125_000_000;
        let request = SntpRequest::new(local_start)?;
        let packet = reply(&request, rollover + 125_000_000, rollover + 250_000_000);
        let measured = request.evaluate_reply(
            &packet,
            times(local_start, local_start + 250_000_000),
            limits(),
        )?;
        assert_eq!(request.transmit_timestamp().seconds, u32::MAX);
        assert_eq!(measured.receive_timestamp.seconds, 0);
        assert_eq!(measured.transmit_timestamp.seconds, 0);
        assert_eq!(
            measured.receive_unix_ns,
            interval(rollover + 125_000_000, rollover + 125_000_000)
        );
        assert_eq!(
            measured.transmit_unix_ns,
            interval(rollover + 250_000_000, rollover + 250_000_000)
        );
        assert_eq!(measured.offset_ns, 187_500_000);
    }
    Ok(())
}

#[test]
fn ambiguous_half_era_and_out_of_range_unix_instants_refuse() -> Test {
    let (request, mut packet, local) = ordinary()?;
    let half_era = (1_u64 << 31) * SECOND;
    put_time(&mut packet, 32, BASE + half_era);
    put_time(&mut packet, 40, BASE + half_era);
    assert_eq!(
        request.evaluate_reply(&packet, local, limits()),
        Err(SntpError::Era)
    );
    let ancient = SntpRequest::new(0)?;
    let mut before_epoch = reply(&ancient, 1, 2);
    // One NTP second before Unix epoch, represented without fixture underflow.
    before_epoch[16..20].copy_from_slice(&2_208_988_799_u32.to_be_bytes());
    before_epoch[20..24].fill(0);
    assert_eq!(
        ancient.evaluate_reply(&before_epoch, times(0, 10), limits()),
        Err(SntpError::Era)
    );
    let final_request = SntpRequest::new(u64::MAX)?;
    let final_packet = reply(&final_request, u64::MAX, u64::MAX);
    let final_observation =
        final_request.evaluate_reply(&final_packet, times(u64::MAX, u64::MAX), limits())?;
    assert!(contains(final_observation, 0));
    Ok(())
}
