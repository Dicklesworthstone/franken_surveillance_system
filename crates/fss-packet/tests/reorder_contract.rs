#![forbid(unsafe_code)]
//! Ordered delivery, resource refusal, and source-custody regression contracts.

use fss_packet::{
    ContinuityError, PacketError, PacketLimits, QueueDiscardReason, ReorderDisposition,
    ReorderError, ReorderGapReason, ReorderLimits, ReorderPoll, RtpReorderBuffer, SequenceClass,
    StreamKey,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn key() -> StreamKey {
    StreamKey {
        ingress: 1,
        generation: 1,
        ssrc: 7,
    }
}

fn limits() -> ReorderLimits {
    ReorderLimits {
        packet: PacketLimits::default(),
        max_packets: 8,
        max_bytes: 1_024,
        max_delay_ns: 10,
    }
}

fn wire(sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 96];
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&1234_u32.to_be_bytes());
    bytes.extend_from_slice(&7_u32.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn packet(buffer: &mut RtpReorderBuffer, now: u64, expected: u64) -> TestResult<Vec<u8>> {
    let ReorderPoll::Packet(packet) = buffer.poll(now)? else {
        return Err("expected one ordered packet".into());
    };
    assert_eq!(packet.key(), key());
    assert_eq!(packet.sequence(), expected);
    assert_eq!(packet.packet()?.sequence(), expected as u16);
    Ok(packet.bytes().to_vec())
}

fn gap(
    buffer: &mut RtpReorderBuffer,
    now: u64,
    first: u64,
    last: u64,
    reason: ReorderGapReason,
) -> TestResult {
    let ReorderPoll::Gap(gap) = buffer.poll(now)? else {
        return Err("expected a delivery gap".into());
    };
    assert_eq!(gap.key, key());
    assert_eq!((gap.first_sequence, gap.last_sequence), (first, last));
    assert_eq!(gap.reason, reason);
    Ok(())
}

fn open(config: ReorderLimits) -> TestResult<RtpReorderBuffer> {
    let mut buffer = RtpReorderBuffer::new(key(), 96, config)?;
    let first = buffer.ingest(key(), &wire(9, &[0x65]), 0)?;
    assert_eq!(first.sequence.class, SequenceClass::Probation);
    assert_eq!(first.disposition, ReorderDisposition::NotAdmitted);
    assert_eq!(buffer.queued_packets(), 0);
    let baseline = buffer.ingest(key(), &wire(10, &[0x65]), 0)?;
    assert_eq!(baseline.sequence.class, SequenceClass::Baseline);
    assert_eq!(baseline.disposition, ReorderDisposition::Buffered);
    packet(&mut buffer, 0, 10)?;
    Ok(buffer)
}

#[test]
fn configuration_is_bounded_and_owner_bound() -> TestResult {
    for config in [
        ReorderLimits {
            max_packets: 0,
            ..limits()
        },
        ReorderLimits {
            max_packets: 129,
            ..limits()
        },
        ReorderLimits {
            max_bytes: 11,
            ..limits()
        },
        ReorderLimits {
            max_bytes: 16 * 1_024 * 1_024 + 1,
            ..limits()
        },
        ReorderLimits {
            max_delay_ns: 0,
            ..limits()
        },
        ReorderLimits {
            max_delay_ns: 60_000_000_001,
            ..limits()
        },
    ] {
        assert_eq!(
            RtpReorderBuffer::new(key(), 96, config)
                .err()
                .ok_or("expected refusal")?,
            ReorderError::Configuration
        );
    }
    assert_eq!(
        RtpReorderBuffer::new(
            StreamKey {
                ingress: 0,
                ..key()
            },
            96,
            limits()
        )
        .err()
        .ok_or("expected refusal")?,
        ReorderError::Continuity(ContinuityError::Configuration)
    );
    assert_eq!(
        RtpReorderBuffer::new(key(), 128, limits())
            .err()
            .ok_or("expected refusal")?,
        ReorderError::Continuity(ContinuityError::Configuration)
    );
    let mut invalid = limits();
    invalid.packet.max_packet_bytes = 11;
    assert_eq!(
        RtpReorderBuffer::new(key(), 96, invalid)
            .err()
            .ok_or("expected refusal")?,
        ReorderError::Packet(PacketError::InvalidLimits)
    );
    Ok(())
}

#[test]
fn out_of_order_packets_recover_without_publishing_a_gap() -> TestResult {
    let mut buffer = open(limits())?;
    buffer.ingest(key(), &wire(12, &[2]), 1)?;
    assert_eq!(
        buffer.poll(1)?,
        ReorderPoll::Pending {
            wake_at_ns: Some(11)
        }
    );
    let recovered = buffer.ingest(key(), &wire(11, &[1]), 2)?;
    assert_eq!(recovered.sequence.class, SequenceClass::Reordered);
    assert_eq!(buffer.next_wake_ns(), Some(2));
    assert_eq!(packet(&mut buffer, 2, 11)?, wire(11, &[1]));
    assert_eq!(packet(&mut buffer, 2, 12)?, wire(12, &[2]));
    assert_eq!(buffer.stats().missing, 0);
    assert_eq!(buffer.queued_bytes(), 0);
    assert_eq!(buffer.next_wake_ns(), None);
    Ok(())
}

#[test]
fn sequence_wrap_is_reordered_in_extended_space() -> TestResult {
    let mut buffer = RtpReorderBuffer::new(key(), 96, limits())?;
    buffer.ingest(key(), &wire(65534, &[1]), 0)?;
    buffer.ingest(key(), &wire(65535, &[2]), 0)?;
    packet(&mut buffer, 0, 65535)?;
    buffer.ingest(key(), &wire(1, &[4]), 1)?;
    buffer.ingest(key(), &wire(0, &[3]), 2)?;
    packet(&mut buffer, 2, 65536)?;
    packet(&mut buffer, 2, 65537)?;
    assert_eq!(buffer.stats().missing, 0);
    Ok(())
}

#[test]
fn oldest_witness_fixes_deadline_despite_duplicates_and_lower_recoveries() -> TestResult {
    let mut buffer = open(limits())?;
    buffer.ingest(key(), &wire(14, &[4]), 1)?;
    buffer.ingest(key(), &wire(12, &[2]), 5)?;
    buffer.ingest(key(), &wire(13, &[3]), 8)?;
    let duplicate = buffer.ingest(key(), &wire(14, &[4]), 10)?;
    assert_eq!(duplicate.disposition, ReorderDisposition::Duplicate);
    assert_eq!(buffer.next_wake_ns(), Some(11));
    assert_eq!(
        buffer.poll(10)?,
        ReorderPoll::Pending {
            wake_at_ns: Some(11)
        }
    );
    gap(&mut buffer, 11, 11, 11, ReorderGapReason::Deadline)?;
    for expected in 12..=14 {
        packet(&mut buffer, 11, expected)?;
    }
    assert_eq!(buffer.stats().missing, 1);
    Ok(())
}

#[test]
fn time_alone_can_retire_a_hole_and_late_recovery_cannot_resurrect_it() -> TestResult {
    let mut buffer = open(limits())?;
    buffer.ingest(key(), &wire(12, &[2]), 1)?;
    gap(&mut buffer, 11, 11, 11, ReorderGapReason::Deadline)?;
    packet(&mut buffer, 11, 12)?;
    let late = buffer.ingest(key(), &wire(11, &[1]), 12)?;
    assert_eq!(late.disposition, ReorderDisposition::TooLate);
    assert_eq!(late.sequence.class, SequenceClass::Reordered);
    assert_eq!(late.sequence.stats.missing, 0);
    assert_eq!(buffer.poll(12)?, ReorderPoll::Pending { wake_at_ns: None });
    Ok(())
}

#[test]
fn full_packet_queue_does_not_consume_refused_sequence() -> TestResult {
    let mut buffer = open(ReorderLimits {
        max_packets: 2,
        ..limits()
    })?;
    buffer.ingest(key(), &wire(11, &[1]), 1)?;
    buffer.ingest(key(), &wire(12, &[2]), 2)?;
    let before = buffer.stats();
    assert_eq!(
        buffer.ingest(key(), &wire(13, &[3]), 3),
        Err(ReorderError::PacketCapacity)
    );
    assert_eq!(buffer.stats(), before);
    assert_eq!(buffer.queued_packets(), 2);
    packet(&mut buffer, 3, 11)?;
    let retry = buffer.ingest(key(), &wire(13, &[3]), 3)?;
    assert_eq!(retry.disposition, ReorderDisposition::Buffered);
    assert_eq!(retry.sequence.class, SequenceClass::Advanced);
    packet(&mut buffer, 3, 12)?;
    packet(&mut buffer, 3, 13)?;
    Ok(())
}

#[test]
fn byte_budget_is_independent_and_refusal_is_retryable() -> TestResult {
    let mut buffer = open(ReorderLimits {
        max_bytes: 26,
        ..limits()
    })?;
    buffer.ingest(key(), &wire(11, &[1]), 1)?;
    buffer.ingest(key(), &wire(12, &[2]), 2)?;
    let before = buffer.stats();
    assert_eq!(
        buffer.ingest(key(), &wire(13, &[3]), 3),
        Err(ReorderError::ByteCapacity)
    );
    assert_eq!(buffer.stats(), before);
    assert_eq!(buffer.queued_bytes(), 26);
    packet(&mut buffer, 3, 11)?;
    assert_eq!(
        buffer.ingest(key(), &wire(13, &[3]), 3)?.disposition,
        ReorderDisposition::Buffered
    );
    Ok(())
}

#[test]
fn refused_baseline_does_not_end_probation() -> TestResult {
    let mut buffer = RtpReorderBuffer::new(
        key(),
        96,
        ReorderLimits {
            max_bytes: 12,
            ..limits()
        },
    )?;
    buffer.ingest(key(), &wire(9, &[]), 0)?;
    assert_eq!(
        buffer.ingest(key(), &wire(10, &[1]), 1),
        Err(ReorderError::ByteCapacity)
    );
    assert_eq!(buffer.stats().received, 0);
    assert_eq!(
        buffer.ingest(key(), &wire(10, &[]), 1)?.sequence.class,
        SequenceClass::Baseline
    );
    Ok(())
}

#[test]
fn wrong_stream_payload_malformed_input_and_clock_do_not_mutate() -> TestResult {
    let mut buffer = open(limits())?;
    buffer.ingest(key(), &wire(12, &[2]), 1)?;
    let before = buffer.stats();
    let mut bad_version = wire(11, &[1]);
    bad_version[0] = 0;
    assert_eq!(
        buffer.ingest(key(), &bad_version, 2),
        Err(ReorderError::Packet(PacketError::Version))
    );
    let mut bad_payload = wire(11, &[1]);
    bad_payload[1] = 97;
    assert_eq!(
        buffer.ingest(key(), &bad_payload, 2),
        Err(ReorderError::Continuity(ContinuityError::PayloadType))
    );
    assert_eq!(
        buffer.ingest(
            StreamKey {
                generation: 2,
                ..key()
            },
            &wire(11, &[1]),
            2
        ),
        Err(ReorderError::Continuity(ContinuityError::StreamMismatch))
    );
    let mut bad_ssrc = wire(11, &[1]);
    bad_ssrc[11] = 8;
    assert_eq!(
        buffer.ingest(key(), &bad_ssrc, 2),
        Err(ReorderError::Continuity(ContinuityError::StreamMismatch))
    );
    assert_eq!(
        buffer.ingest(key(), &wire(11, &[1]), 0),
        Err(ReorderError::Continuity(ContinuityError::ClockReversed))
    );
    assert_eq!(
        buffer.poll(0).err().ok_or("expected refusal")?,
        ReorderError::Continuity(ContinuityError::ClockReversed)
    );
    assert_eq!(buffer.stats(), before);
    assert_eq!(buffer.queued_packets(), 1);
    buffer.ingest(key(), &wire(11, &[1]), 1)?;
    packet(&mut buffer, 1, 11)?;
    packet(&mut buffer, 1, 12)?;
    Ok(())
}

#[test]
fn confirmed_restart_retires_old_queue_and_requires_new_epoch() -> TestResult {
    let mut buffer = open(limits())?;
    buffer.ingest(key(), &wire(12, &[2]), 1)?;
    let suspect = buffer.ingest(key(), &wire(20000, &[3]), 2)?;
    assert_eq!(
        suspect.sequence.class,
        SequenceClass::DiscontinuitySuspected
    );
    assert_eq!(buffer.queued_packets(), 1);
    let restart = buffer.ingest(key(), &wire(20001, &[4]), 3)?;
    assert_eq!(restart.disposition, ReorderDisposition::RestartRequired);
    let retired = restart.discarded.ok_or("expected retirement receipt")?;
    assert_eq!(retired.reason, QueueDiscardReason::RestartRequired);
    assert_eq!((retired.packets, retired.bytes), (1, 13));
    assert_eq!(
        (retired.first_sequence, retired.last_sequence),
        (Some(12), Some(12))
    );
    assert_eq!(buffer.queued_bytes(), 0);
    assert_eq!(buffer.poll(3)?, ReorderPoll::Ended);
    assert_eq!(
        buffer.ingest(key(), &wire(13, &[3]), 3),
        Err(ReorderError::Closed)
    );
    assert_eq!(
        buffer
            .restart(key(), 96, limits())
            .err()
            .ok_or("expected refusal")?,
        ReorderError::Continuity(ContinuityError::GenerationRequired)
    );
    assert_eq!(
        buffer
            .restart(
                StreamKey {
                    ingress: 2,
                    generation: 2,
                    ..key()
                },
                96,
                limits()
            )
            .err()
            .ok_or("expected refusal")?,
        ReorderError::Continuity(ContinuityError::StreamMismatch)
    );
    let new_key = StreamKey {
        generation: 2,
        ..key()
    };
    let mut reopened = buffer.restart(new_key, 96, limits())?;
    assert_eq!(
        reopened.ingest(new_key, &wire(20, &[1]), 0)?.sequence.class,
        SequenceClass::Probation
    );
    Ok(())
}

#[test]
fn eof_drains_packets_with_gaps_but_never_invents_a_missing_tail() -> TestResult {
    let mut buffer = open(limits())?;
    buffer.ingest(key(), &wire(12, &[2]), 1)?;
    buffer.ingest(key(), &wire(14, &[4]), 2)?;
    buffer.finish();
    assert_eq!(
        buffer.ingest(key(), &wire(11, &[1]), 2),
        Err(ReorderError::Closed)
    );
    gap(&mut buffer, 2, 11, 11, ReorderGapReason::EndOfInput)?;
    packet(&mut buffer, 2, 12)?;
    gap(&mut buffer, 2, 13, 13, ReorderGapReason::EndOfInput)?;
    packet(&mut buffer, 2, 14)?;
    assert_eq!(buffer.poll(2)?, ReorderPoll::Ended);
    assert_eq!(buffer.poll(2)?, ReorderPoll::Ended);
    Ok(())
}

#[test]
fn eof_during_probation_has_no_invented_baseline_or_gap() -> TestResult {
    let mut buffer = RtpReorderBuffer::new(key(), 96, limits())?;
    buffer.ingest(key(), &wire(9, &[1]), 0)?;
    buffer.finish();
    assert_eq!(buffer.poll(0)?, ReorderPoll::Ended);
    Ok(())
}

#[test]
fn cancellation_retires_queue_without_releasing_packets() -> TestResult {
    let mut buffer = open(limits())?;
    buffer.ingest(key(), &wire(12, &[2]), 1)?;
    buffer.ingest(key(), &wire(14, &[4]), 2)?;
    let retired = buffer.cancel();
    assert_eq!(retired.reason, QueueDiscardReason::Cancelled);
    assert_eq!((retired.packets, retired.bytes), (2, 26));
    assert_eq!(
        (retired.first_sequence, retired.last_sequence),
        (Some(12), Some(14))
    );
    assert_eq!(buffer.poll(2)?, ReorderPoll::Ended);
    assert_eq!(buffer.cancel().packets, 0);
    buffer.finish();
    assert_eq!(
        buffer.ingest(key(), &wire(15, &[5]), 3),
        Err(ReorderError::Closed)
    );
    Ok(())
}

#[test]
fn source_bytes_arrival_time_and_nondefault_limits_survive_delivery() -> TestResult {
    let mut config = limits();
    config.packet.max_packet_bytes = 100_000;
    config.max_bytes = 100_000;
    let mut buffer = open(config)?;
    let original = wire(11, &vec![0x65; 70_000]);
    let mut supplied = original.clone();
    buffer.ingest(key(), &supplied, 1)?;
    supplied.fill(0);
    let ReorderPoll::Packet(delivered) = buffer.poll(2)? else {
        return Err("expected packet".into());
    };
    assert_eq!(delivered.received_ns(), 1);
    assert_eq!(delivered.bytes(), original);
    assert_eq!(delivered.packet()?.payload().len(), 70_000);
    Ok(())
}

#[test]
fn conflicting_queued_duplicate_is_not_silently_accepted() -> TestResult {
    let mut buffer = open(limits())?;
    buffer.ingest(key(), &wire(11, &[1]), 1)?;
    let before = buffer.stats();
    assert_eq!(
        buffer.ingest(key(), &wire(11, &[99]), 2),
        Err(ReorderError::ConflictingDuplicate)
    );
    assert_eq!(buffer.stats(), before);
    assert_eq!(packet(&mut buffer, 1, 11)?, wire(11, &[1]));
    Ok(())
}

#[test]
fn duplicate_and_before_baseline_input_never_reenter_delivery() -> TestResult {
    let mut buffer = open(limits())?;
    assert_eq!(
        buffer.ingest(key(), &wire(10, &[0x65]), 1)?.disposition,
        ReorderDisposition::Duplicate
    );
    let old = buffer.ingest(key(), &wire(9, &[0x65]), 1)?;
    assert_eq!(old.sequence.class, SequenceClass::BeforeBaseline);
    assert_eq!(old.disposition, ReorderDisposition::NotAdmitted);
    assert_eq!(buffer.poll(1)?, ReorderPoll::Pending { wake_at_ns: None });
    Ok(())
}

#[test]
fn unrepresentable_deadline_is_refused_without_clock_or_sequence_mutation() -> TestResult {
    let mut buffer = open(limits())?;
    let before = buffer.stats();
    assert_eq!(
        buffer.ingest(key(), &wire(11, &[1]), u64::MAX - 5),
        Err(ReorderError::Continuity(ContinuityError::Exhausted))
    );
    assert_eq!(buffer.stats(), before);
    assert_eq!(
        buffer.ingest(key(), &wire(11, &[1]), 1)?.disposition,
        ReorderDisposition::Buffered
    );
    Ok(())
}

#[test]
fn debug_does_not_disclose_original_media() -> TestResult {
    let mut buffer = open(limits())?;
    let secret = b"PRIVATE-MEDIA-CANARY";
    buffer.ingest(key(), &wire(11, secret), 1)?;
    let state = format!("{buffer:?}");
    let output = format!("{:?}", buffer.poll(1)?);
    for text in [state, output] {
        assert!(!text.contains("PRIVATE-MEDIA-CANARY"));
        assert!(!text.contains(&format!("{secret:?}")));
    }
    Ok(())
}

fn permutations(
    values: &mut [u16],
    start: usize,
    visit: &mut impl FnMut(&[u16]) -> TestResult,
) -> TestResult {
    if start == values.len() {
        return visit(values);
    }
    for index in start..values.len() {
        values.swap(start, index);
        permutations(values, start + 1, visit)?;
        values.swap(start, index);
    }
    Ok(())
}

#[test]
fn every_six_packet_permutation_has_identical_ordered_output() -> TestResult {
    let mut cases = 0;
    permutations(&mut [11, 12, 13, 14, 15, 16], 0, &mut |order| {
        let mut buffer = open(limits())?;
        for sequence in order {
            buffer.ingest(key(), &wire(*sequence, &sequence.to_be_bytes()), 1)?;
        }
        for expected in 11..=16 {
            assert_eq!(
                packet(&mut buffer, 1, expected)?,
                wire(expected as u16, &(expected as u16).to_be_bytes())
            );
        }
        assert_eq!(buffer.stats().missing, 0);
        assert_eq!(buffer.queued_bytes(), 0);
        cases += 1;
        Ok(())
    })?;
    assert_eq!(cases, 720);
    Ok(())
}

#[test]
fn every_missing_position_yields_exactly_one_gap_and_preserves_other_packets() -> TestResult {
    for missing in 11..=15 {
        let mut buffer = open(limits())?;
        for sequence in (11..=16).rev().filter(|sequence| *sequence != missing) {
            buffer.ingest(key(), &wire(sequence, &[1]), 1)?;
        }
        buffer.finish();
        for sequence in 11..=16 {
            if sequence == missing {
                gap(
                    &mut buffer,
                    1,
                    u64::from(sequence),
                    u64::from(sequence),
                    ReorderGapReason::EndOfInput,
                )?;
            } else {
                packet(&mut buffer, 1, u64::from(sequence))?;
            }
        }
        assert_eq!(buffer.poll(1)?, ReorderPoll::Ended);
    }
    Ok(())
}
