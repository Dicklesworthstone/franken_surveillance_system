#![forbid(unsafe_code)]
//! TEST-TIME-001: offset/drift/jitter/reconnect interval correctness.
//!
//! Properties over the sender-clock stack in `fss-packet::timing`:
//! conservative offset intervals (drift included by construction), owner
//! binding across reconnects, ambiguity/distance refusals, jitter
//! determinism and ordering, exact tick conversion, and report-delay
//! semantics. Each property emits one JSONL verdict line citing the
//! family id.

use fss_packet::{
    JitterEstimator, NtpTimestamp, SenderReport, SenderReportClock, StreamKey, arrival_ticks,
};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"TEST-TIME-001\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

fn key(ingress: u128, generation: u64) -> StreamKey {
    StreamKey {
        ingress,
        generation,
        ssrc: 0xDEAD_BEEF,
    }
}

fn report(rtp_ts: u32) -> SenderReport {
    SenderReport {
        ssrc: 0xDEAD_BEEF,
        ntp: NtpTimestamp {
            seconds: 3_700_000,
            fraction: 1 << 31,
        },
        rtp_timestamp: rtp_ts,
        packet_count: 1,
        octet_count: 0,
    }
}

fn clock(uncertainty_ns: u64, max_distance: u32) -> Result<SenderReportClock, fss_packet::ContinuityError> {
    SenderReportClock::new(
        key(7, 1),
        90_000,
        report(1_000_000),
        10_000_000_000,
        uncertainty_ns,
        max_distance,
    )
}

fn report_ntp_ns(rep: &SenderReport) -> i128 {
    i128::from(rep.ntp.seconds) * 1_000_000_000
        + i128::from(rep.ntp.fraction) * 1_000_000_000 / (1_i128 << 32)
}

/// P1 OFFSET CONSERVATISM (drift included by construction): the estimated
/// interval always contains the true sender instant for every (rate,
/// delta, uncertainty) on the grid, and is widened by at least the full
/// uncertainty on both ends.
#[test]
fn p1_offset_intervals_are_conservative() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    for &rate in &[90_000u32, 48_000, 8_000, 1] {
        for &delta_ticks in &[-90_000i64, -1, 0, 1, 45_000, 90_000] {
            for &uncertainty in &[0u64, 50_000_000] {
                let clock = SenderReportClock::new(
                    key(7, 1),
                    rate,
                    report(1_000_000),
                    10_000_000_000,
                    uncertainty,
                    200_000,
                )?;
                let ts = (1_000_000i64 + delta_ticks) as u32;
                let est = clock.estimate(key(7, 1), ts)?;
                let rep = report(1_000_000);
                let ntp_ns = report_ntp_ns(&rep);
                // True sender instant under exact rational arithmetic.
                let true_ns = ntp_ns + i128::from(delta_ticks) * 1_000_000_000 / i128::from(rate);
                assert!(
                    est.earliest_ntp_ns <= true_ns && true_ns <= est.latest_ntp_ns,
                    "rate {rate} delta {delta_ticks}: true {true_ns} outside [{}, {}]",
                    est.earliest_ntp_ns,
                    est.latest_ntp_ns
                );
                assert!(
                    est.latest_ntp_ns - est.earliest_ntp_ns >= 2 * i128::from(uncertainty),
                    "interval must carry the full uncertainty on both ends"
                );
                cases += 1;
            }
        }
    }
    emit("offset-conservatism", cases);
    Ok(())
}

/// P2 OWNER BINDING (reconnect safety): estimates are bound to the exact
/// owner epoch; a different ingress or generation — a reconnect or source
/// reset — is refused, never silently reused.
#[test]
fn p2_owner_binding_survives_reconnects() -> Result<(), Box<dyn std::error::Error>> {
    let clock = clock(0, 200_000)?;
    let est = clock.estimate(key(7, 1), 1_090_000)?;
    assert_eq!(est.key, key(7, 1));
    assert!(clock.estimate(key(8, 1), 1_090_000).is_err());
    assert!(clock.estimate(key(7, 2), 1_090_000).is_err());
    emit("owner-binding", 3);
    Ok(())
}

/// P3 AMBIGUITY/DISTANCE/CONFIGURATION REFUSALS: the half-range timestamp
/// is ambiguous, beyond-max-distance extrapolation is refused, and the
/// constructor refuses degenerate clocks and mismatched reports.
#[test]
fn p3_ambiguity_and_configuration_refusals() -> Result<(), Box<dyn std::error::Error>> {
    let clock = clock(0, 90_000)?;
    // Exactly the ambiguous half-point from the report timestamp.
    assert!(
        clock
            .estimate(key(7, 1), 1_000_000u32.wrapping_add(0x8000_0000))
            .is_err()
    );
    // Beyond the distance ceiling.
    assert!(clock.estimate(key(7, 1), 1_000_000 + 90_001).is_err());
    // Constructor refusals.
    assert!(SenderReportClock::new(key(0, 1), 90_000, report(1), 0, 0, 100).is_err());
    assert!(SenderReportClock::new(key(7, 0), 90_000, report(1), 0, 0, 100).is_err());
    assert!(SenderReportClock::new(key(7, 1), 0, report(1), 0, 0, 100).is_err());
    let zero_ntp = SenderReport {
        ssrc: 0xDEAD_BEEF,
        ntp: NtpTimestamp {
            seconds: 0,
            fraction: 0,
        },
        rtp_timestamp: 1,
        packet_count: 0,
        octet_count: 0,
    };
    assert!(SenderReportClock::new(key(7, 1), 90_000, zero_ntp, 0, 0, 100).is_err());
    let wrong_ssrc = SenderReport {
        ssrc: 0x1111_1111,
        ..report(1)
    };
    assert!(SenderReportClock::new(key(7, 1), 90_000, wrong_ssrc, 0, 0, 100).is_err());
    emit("ambiguity-refusals", 8);
    Ok(())
}

/// P4 JITTER: the estimator is deterministic, converges small under
/// constant spacing, grows under bursty alternation, and refuses reversed
/// arrival clocks.
#[test]
fn p4_jitter_determinism_and_ordering() -> Result<(), Box<dyn std::error::Error>> {
    let spaced = |est: &mut JitterEstimator| -> Result<Vec<u32>, fss_packet::ContinuityError> {
        let mut out = Vec::new();
        // Constant 3000-tick spacing with matching timestamps: zero
        // variation.
        for i in 0..50u64 {
            out.push(est.observe(i * 3000, (i * 3000) as u32)?);
        }
        Ok(out)
    };
    let mut a = JitterEstimator::default();
    let mut b = JitterEstimator::default();
    assert_eq!(spaced(&mut a)?, spaced(&mut b)?, "deterministic");
    let steady = a.ticks();
    // Bursty: arrivals constant but timestamps alternate ±1500 → variation.
    let mut bursty = JitterEstimator::default();
    for i in 0..50u64 {
        let ts = if i % 2 == 0 { 0u32 } else { 3000 };
        bursty.observe(i * 3000, ts)?;
    }
    assert!(
        bursty.ticks() > steady,
        "bursty spacing must accumulate more jitter than constant ({} > {})",
        bursty.ticks(),
        steady
    );
    // Reversed arrival clock refused.
    let mut reversed = JitterEstimator::default();
    reversed.observe(10_000, 10_000)?;
    assert!(reversed.observe(9_000, 10_000).is_err());
    emit("jitter-determinism-ordering", 3);
    Ok(())
}

/// P5 TICK CONVERSION: exact at known points, monotone, and rate-bounds
/// are refused.
#[test]
fn p5_arrival_tick_conversion() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(arrival_ticks(1_000_000_000, 90_000)?, 90_000);
    assert_eq!(arrival_ticks(2_000_000_000, 90_000)?, 180_000);
    assert_eq!(arrival_ticks(0, 90_000)?, 0);
    assert!(arrival_ticks(1, 90_000)? <= arrival_ticks(2, 90_000)?);
    assert!(arrival_ticks(1_000, 0).is_err());
    assert!(arrival_ticks(1_000, 1_000_000_001).is_err());
    emit("tick-conversion", 6);
    Ok(())
}

/// P6 REPORT DELAY (reconnect interval arithmetic): LSR/DLSR derive from
/// the bound report with monotone delay, and a clock that went backwards
/// is refused.
#[test]
fn p6_report_delay_semantics() -> Result<(), Box<dyn std::error::Error>> {
    let clock = clock(0, 200_000)?;
    let (lsr, d0) = clock.report_delay(10_000_000_000)?;
    assert_eq!(lsr, report(1_000_000).ntp.middle_32());
    assert_eq!(d0, 0, "zero elapsed at the received instant");
    let (_, d1) = clock.report_delay(10_001_000_000)?;
    assert!(d1 >= d0, "delay is monotone in elapsed time");
    assert!(clock.report_delay(9_999_999_999).is_err());
    emit("report-delay", 3);
    Ok(())
}
