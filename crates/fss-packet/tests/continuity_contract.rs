#![forbid(unsafe_code)]
//! Sequence, generation, loss, and conservative clock contracts.

use fss_packet::{
    ContinuityError, JitterEstimator, NtpTimestamp, PacketLimits, RtpPacket,
    SenderReport, SenderReportClock, SequenceClass, SequenceObservation, SequenceTracker,
    StreamKey, arrival_ticks,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey { ingress: 1, generation: 1, ssrc: 7 };

fn observe(tracker: &mut SequenceTracker, sequence: u16) -> Result<SequenceObservation, Box<dyn std::error::Error>> {
    let [hi, lo] = sequence.to_be_bytes();
    let bytes = [0x80, 96, hi, lo, 0, 0, 0, 0, 0, 0, 0, 7];
    Ok(tracker.observe(KEY, RtpPacket::parse(&bytes, PacketLimits::default())?)?)
}

#[test]
fn probation_cannot_publish_continuity_or_decode_admission() -> TestResult {
    let mut tracker = SequenceTracker::new(KEY, 96)?;
    for sequence in [99, 500, 500, 999] {
        let observation = observe(&mut tracker, sequence)?;
        assert_eq!(observation.class, SequenceClass::Probation);
        assert!(!observation.is_unique());
        assert_eq!(observation.extended_sequence, None);
        assert_eq!(observation.stats.expected, 0);
    }
    let observation = observe(&mut tracker, 1_000)?;
    assert_eq!(observation.class, SequenceClass::Baseline);
    assert!(observation.is_unique());
    assert_eq!(observation.stats.unique, 1);
    Ok(())
}

#[test]
fn wrap_reorder_and_duplicates_do_not_fabricate_recovered_loss() -> TestResult {
    let mut tracker = SequenceTracker::new(KEY, 96)?;
    observe(&mut tracker, 65_533)?;
    observe(&mut tracker, 65_534)?;
    let advanced = observe(&mut tracker, 1)?;
    assert_eq!(advanced.extended_sequence, Some(65_537));
    assert_eq!(advanced.stats.missing, 2);
    let late = observe(&mut tracker, 65_535)?;
    assert_eq!(late.class, SequenceClass::Reordered);
    assert_eq!(late.extended_sequence, Some(65_535));
    assert_eq!(late.stats.missing, 1);
    let duplicate = observe(&mut tracker, 65_535)?;
    assert_eq!(duplicate.class, SequenceClass::Duplicate);
    assert!(!duplicate.is_unique());
    assert_eq!(duplicate.stats.unique, 3);
    assert_eq!(duplicate.stats.received, 4);
    assert_eq!(duplicate.stats.missing, 1);
    let late = observe(&mut tracker, 0)?;
    assert_eq!(late.stats.missing, 0);
    assert_eq!(observe(&mut tracker, 65_533)?.class, SequenceClass::BeforeBaseline);
    Ok(())
}

#[test]
fn reordering_bitmap_never_aliases_a_new_cycle_or_old_position() -> TestResult {
    let mut tracker = SequenceTracker::new(KEY, 96)?;
    observe(&mut tracker, 0)?;
    observe(&mut tracker, 1)?;
    observe(&mut tracker, 200)?;
    assert_eq!(observe(&mut tracker, 73)?.class, SequenceClass::Reordered);
    assert_eq!(observe(&mut tracker, 73)?.class, SequenceClass::Duplicate);
    assert_eq!(observe(&mut tracker, 72)?.class, SequenceClass::DiscontinuitySuspected);
    assert_eq!(observe(&mut tracker, 201)?.class, SequenceClass::Advanced);
    for extended in 202..=150_000_u64 {
        let observation = observe(&mut tracker, extended as u16)?;
        assert_eq!(observation.extended_sequence, Some(extended));
    }
    assert_eq!(tracker.stats().expected, 150_000);
    assert_eq!(tracker.stats().missing, 197);
    Ok(())
}

#[test]
fn source_restart_requires_new_epoch_and_never_resets_old_statistics() -> TestResult {
    let mut tracker = SequenceTracker::new(KEY, 96)?;
    observe(&mut tracker, 10)?;
    observe(&mut tracker, 11)?;
    let stats = tracker.stats();
    assert_eq!(observe(&mut tracker, 20_000)?.class, SequenceClass::DiscontinuitySuspected);
    assert_eq!(observe(&mut tracker, 20_001)?.class, SequenceClass::RestartRequired);
    assert_eq!(observe(&mut tracker, 12)?.class, SequenceClass::RestartRequired);
    assert_eq!(tracker.stats(), stats);
    assert_eq!(tracker.restart(KEY, 96), Err(ContinuityError::GenerationRequired));
    let new_key = StreamKey { generation: 2, ..KEY };
    let fresh = tracker.restart(new_key, 96)?;
    assert_eq!(fresh.stats().received, 0);
    Ok(())
}

#[test]
fn generation_ssrc_and_payload_mismatch_leave_state_unchanged() -> TestResult {
    let mut tracker = SequenceTracker::new(KEY, 96)?;
    let before = tracker.clone();
    let mut bytes = [0x80, 96, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7];
    let packet = RtpPacket::parse(&bytes, PacketLimits::default())?;
    let other = StreamKey { generation: 2, ..KEY };
    assert_eq!(tracker.observe(other, packet), Err(ContinuityError::StreamMismatch));
    bytes[11] = 8;
    let packet = RtpPacket::parse(&bytes, PacketLimits::default())?;
    assert_eq!(tracker.observe(KEY, packet), Err(ContinuityError::StreamMismatch));
    bytes[11] = 7;
    bytes[1] = 97;
    let packet = RtpPacket::parse(&bytes, PacketLimits::default())?;
    assert_eq!(tracker.observe(KEY, packet), Err(ContinuityError::PayloadType));
    assert_eq!(tracker, before);
    Ok(())
}

#[test]
fn jitter_matches_integer_oracle_across_timestamp_wrap() -> TestResult {
    let mut jitter = JitterEstimator::default();
    assert_eq!(jitter.observe(0, 0xffff_fff0)?, 0);
    assert_eq!(jitter.observe(32, 16)?, 0);
    assert_eq!(jitter.observe(64, 32)?, 1);
    assert_eq!(jitter.observe(80, 48)?, 0);
    let mut scaled = 15_u64;
    for step in 1..=1_000_u64 {
        let arrival = 80 + step * 16;
        let timestamp = 48 + step as u32 * 15;
        scaled = scaled + 1 - ((scaled + 8) >> 4);
        assert_eq!(jitter.observe(arrival, timestamp)?, (scaled >> 4) as u32);
    }
    assert_eq!(arrival_ticks(u64::MAX, 1_000_000_000)?, u64::MAX);
    assert_eq!(arrival_ticks(1_000_000_000, 90_000)?, 90_000);
    assert_eq!(arrival_ticks(1, 0), Err(ContinuityError::Configuration));
    Ok(())
}

#[test]
fn ambiguous_or_reversed_clocks_refuse_atomically() -> TestResult {
    let mut jitter = JitterEstimator::default();
    jitter.observe(100, 20)?;
    let before = jitter;
    assert_eq!(jitter.observe(99, 21), Err(ContinuityError::ClockReversed));
    assert_eq!(jitter.observe(101, 0x8000_0014), Err(ContinuityError::ClockAmbiguous));
    assert_eq!(jitter.observe(100 + 0x8000_0000, 21), Err(ContinuityError::ClockAmbiguous));
    assert_eq!(jitter, before);
    Ok(())
}

fn report() -> SenderReport {
    SenderReport {
        ssrc: 7,
        ntp: NtpTimestamp { seconds: 100, fraction: 0 },
        rtp_timestamp: 0xffff_fff0,
        packet_count: 2,
        octet_count: 10,
    }
}

#[test]
fn sender_clock_mapping_is_conservative_bidirectional_and_epoch_bound() -> TestResult {
    let clock = SenderReportClock::new(KEY, 90_000, report(), 1_000_000_000, 10, 90_000)?;
    let future = clock.estimate(KEY, 16)?;
    assert_eq!(future.earliest_ntp_ns, 100_000_355_545);
    assert_eq!(future.latest_ntp_ns, 100_000_355_567);
    let past = clock.estimate(KEY, 0xffff_ffef)?;
    assert_eq!(past.earliest_ntp_ns, 99_999_988_878);
    assert_eq!(past.latest_ntp_ns, 99_999_988_900);
    assert_eq!(clock.report_delay(2_000_000_000)?, (100 << 16, 65_536));
    assert_eq!(clock.report_delay(0), Err(ContinuityError::ClockReversed));
    assert_eq!(clock.report_delay(u64::MAX), Err(ContinuityError::ClockAmbiguous));
    let other = StreamKey { generation: 2, ..KEY };
    assert_eq!(clock.estimate(other, 16), Err(ContinuityError::StreamMismatch));
    assert_eq!(clock.estimate(KEY, 0x7fff_fff0), Err(ContinuityError::ClockAmbiguous));
    assert_eq!(clock.estimate(KEY, 100_000), Err(ContinuityError::ClockAmbiguous));
    Ok(())
}

#[test]
fn increasing_uncertainty_only_widens_the_sender_assertion() -> TestResult {
    let narrow = SenderReportClock::new(KEY, 90_000, report(), 0, 0, 90_000)?;
    let wide = SenderReportClock::new(KEY, 90_000, report(), 0, 100_000, 90_000)?;
    for delta in -90_000_i32..=90_000 {
        let timestamp = report().rtp_timestamp.wrapping_add(delta as u32);
        let a = narrow.estimate(KEY, timestamp)?;
        let b = wide.estimate(KEY, timestamp)?;
        assert!(b.earliest_ntp_ns <= a.earliest_ntp_ns);
        assert!(b.latest_ntp_ns >= a.latest_ntp_ns);
    }
    Ok(())
}
