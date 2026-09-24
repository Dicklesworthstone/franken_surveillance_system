#![forbid(unsafe_code)]
//! End-to-end ordered HEVC reception with original datagrams and retirement receipts.

use fss_packet::{
    ContinuityError, H265Error, H265Limits, H265Output, H265ReceiveError, H265ReceivePoll,
    H265Receiver, H265Status, OrderedRtpPacket, QueueDiscardReason, ReorderDisposition,
    ReorderError, ReorderGapReason, ReorderLimits, StreamKey,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type PacketStep = (OrderedRtpPacket, Result<H265Output, H265ReceiveError>);
const KEY: StreamKey = StreamKey {
    ingress: 1,
    generation: 1,
    ssrc: 7,
};

fn packet(sequence: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x80, 96 | if marker { 128 } else { 0 }];
    wire.extend_from_slice(&sequence.to_be_bytes());
    wire.extend_from_slice(&90_000_u32.to_be_bytes());
    wire.extend_from_slice(&KEY.ssrc.to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

fn packet_step(
    receiver: &mut H265Receiver,
    now: u64,
) -> Result<PacketStep, Box<dyn std::error::Error>> {
    match receiver.poll(now)? {
        H265ReceivePoll::Packet {
            source,
            reconstruction,
        } => Ok((source, reconstruction)),
        _ => Err("expected one original packet and its reconstruction result".into()),
    }
}

fn prime(receiver: &mut H265Receiver, key: StreamKey) -> TestResult {
    // Establish the shared RTP sequence tracker's probation baseline before FU input.
    for seq in 0..4 {
        receiver.ingest(key, &packet(seq, true, &[0x40, 1, 1]), u64::from(seq))?;
        loop {
            match receiver.poll(u64::from(seq))? {
                H265ReceivePoll::Packet { reconstruction, .. } => {
                    reconstruction?;
                }
                H265ReceivePoll::Pending { .. } => break,
                _ => return Err("unexpected baseline transition".into()),
            }
        }
    }
    assert_eq!(receiver.queued_packets(), 0);
    assert_eq!(receiver.pending_nal_bytes(), 0);
    Ok(())
}

fn open(
    reorder: ReorderLimits,
    codec: H265Limits,
) -> Result<H265Receiver, Box<dyn std::error::Error>> {
    let mut receiver = H265Receiver::new(KEY, 96, 0, reorder, codec)?;
    prime(&mut receiver, KEY)?;
    Ok(receiver)
}

#[test]
fn out_of_order_fragments_reconstruct_with_exact_original_datagrams() -> TestResult {
    let mut receiver = open(ReorderLimits::default(), H265Limits::default())?;
    let start = packet(4, false, &[0x62, 1, 0x93, 1]);
    let middle = packet(5, false, &[0x62, 1, 0x13, 2]);
    let end = packet(6, true, &[0x62, 1, 0x53, 3]);
    receiver.ingest(KEY, &start, 4)?;
    let (source, output) = packet_step(&mut receiver, 4)?;
    assert_eq!(source.bytes(), start);
    assert_eq!(output?.status, H265Status::FragmentPending);
    receiver.ingest(KEY, &end, 5)?;
    assert!(matches!(receiver.poll(5)?, H265ReceivePoll::Pending { .. }));
    receiver.ingest(KEY, &middle, 6)?;
    let (source, output) = packet_step(&mut receiver, 6)?;
    assert_eq!(source.bytes(), middle);
    assert_eq!(source.received_ns(), 6);
    assert_eq!(output?.status, H265Status::FragmentPending);
    let (source, output) = packet_step(&mut receiver, 6)?;
    assert_eq!(source.bytes(), end);
    assert_eq!(source.received_ns(), 5);
    let output = output?;
    assert_eq!(output.nals[0].bytes(), [0x26, 1, 1, 2, 3]);
    for (index, wire) in [&start, &middle, &end].into_iter().enumerate() {
        let span = &output.nals[0].sources()[index];
        assert_eq!(span.sequence, index as u64 + 4);
        assert_eq!(
            &wire[span.wire_range.clone()],
            &output.nals[0].bytes()[span.nal_range.clone()]
        );
    }
    assert_eq!(receiver.queued_bytes(), 0);
    assert_eq!(receiver.pending_nal_bytes(), 0);
    Ok(())
}

#[test]
fn malformed_codec_output_still_returns_its_original_source() -> TestResult {
    let mut receiver = open(ReorderLimits::default(), H265Limits::default())?;
    let malformed = packet(4, true, &[0x62, 1, 0xd3, 99]);
    receiver.ingest(KEY, &malformed, 4)?;
    let (source, reconstruction) = packet_step(&mut receiver, 4)?;
    assert_eq!(source.bytes(), malformed);
    let error = reconstruction.err().ok_or("malformed FU accepted")?;
    assert!(
        matches!(error, H265ReceiveError::Codec(failure) if failure.reason == H265Error::Malformed)
    );
    assert_eq!(receiver.queued_packets(), 0);
    receiver.ingest(KEY, &packet(5, true, &[0x26, 1, 3]), 5)?;
    assert_eq!(
        packet_step(&mut receiver, 5)?.1?.nals[0].bytes(),
        [0x26, 1, 3]
    );
    Ok(())
}

#[test]
fn delivery_deadline_retires_chain_before_returning_orphaned_end_packet() -> TestResult {
    let reorder = ReorderLimits {
        max_delay_ns: 10,
        ..ReorderLimits::default()
    };
    let codec = H265Limits {
        max_pending_age_ns: 100,
        ..H265Limits::default()
    };
    let mut receiver = open(reorder, codec)?;
    receiver.ingest(KEY, &packet(4, false, &[0x62, 1, 0x93, 1]), 4)?;
    packet_step(&mut receiver, 4)?.1?;
    let end = packet(6, true, &[0x62, 1, 0x53, 3]);
    receiver.ingest(KEY, &end, 5)?;
    assert_eq!(receiver.next_wake_ns(), Some(15));
    assert!(matches!(
        receiver.poll(14)?,
        H265ReceivePoll::Pending {
            wake_at_ns: Some(15)
        }
    ));
    let H265ReceivePoll::Gap { gap, discarded } = receiver.poll(15)? else {
        return Err("gap missing at its exact deadline".into());
    };
    assert_eq!(gap.first_sequence, 5);
    assert_eq!(gap.last_sequence, 5);
    assert_eq!(gap.reason, ReorderGapReason::Deadline);
    assert_eq!(
        discarded.ok_or("pending FU was not retired")?.reason,
        H265Error::Gap
    );
    let (source, reconstruction) = packet_step(&mut receiver, 15)?;
    assert_eq!(source.bytes(), end);
    assert!(
        matches!(reconstruction, Err(H265ReceiveError::Codec(failure))
        if failure.reason == H265Error::MissingStart && failure.discarded.is_none())
    );
    let late = receiver.ingest(KEY, &packet(5, false, &[0x62, 1, 0x13, 2]), 16)?;
    assert_eq!(late.transport.disposition, ReorderDisposition::TooLate);
    assert_eq!(receiver.pending_nal_bytes(), 0);
    assert_eq!(receiver.next_wake_ns(), None);
    Ok(())
}

#[test]
fn fragment_timer_runs_without_packets_and_does_not_lose_queued_source() -> TestResult {
    let codec = H265Limits {
        max_pending_age_ns: 10,
        ..H265Limits::default()
    };
    let mut receiver = open(ReorderLimits::default(), codec)?;
    receiver.ingest(KEY, &packet(4, false, &[0x62, 1, 0x93, 1]), 4)?;
    packet_step(&mut receiver, 4)?.1?;
    assert_eq!(receiver.next_wake_ns(), Some(14));
    assert!(matches!(
        receiver.poll(13)?,
        H265ReceivePoll::Pending {
            wake_at_ns: Some(14)
        }
    ));
    let clean = packet(5, true, &[0x26, 1, 9]);
    receiver.ingest(KEY, &clean, 14)?;
    assert!(
        matches!(receiver.poll(14)?, H265ReceivePoll::FragmentDiscarded(discard)
        if discard.reason == H265Error::Deadline && discard.first_sequence == 4)
    );
    assert_eq!(receiver.queued_packets(), 1);
    let (source, reconstruction) = packet_step(&mut receiver, 14)?;
    assert_eq!(source.bytes(), clean);
    assert_eq!(reconstruction?.nals[0].bytes(), [0x26, 1, 9]);
    assert_eq!(receiver.next_wake_ns(), None);
    Ok(())
}

#[test]
fn queue_backpressure_does_not_consume_the_refused_sequence() -> TestResult {
    let reorder = ReorderLimits {
        max_packets: 1,
        ..ReorderLimits::default()
    };
    let mut receiver = open(reorder, H265Limits::default())?;
    receiver.ingest(KEY, &packet(4, false, &[0x62, 1, 0x93, 1]), 4)?;
    let end = packet(5, true, &[0x62, 1, 0x53, 2]);
    let before = receiver.stats();
    assert_eq!(
        receiver
            .ingest(KEY, &end, 5)
            .err()
            .ok_or("capacity was not enforced")?,
        H265ReceiveError::Transport(ReorderError::PacketCapacity)
    );
    assert_eq!(receiver.stats(), before);
    packet_step(&mut receiver, 4)?.1?;
    let admission = receiver.ingest(KEY, &end, 5)?;
    assert_eq!(
        admission.transport.disposition,
        ReorderDisposition::Buffered
    );
    assert_eq!(
        packet_step(&mut receiver, 5)?.1?.nals[0].bytes(),
        [0x26, 1, 1, 2]
    );
    Ok(())
}

#[test]
fn finish_drains_accepted_fragments_before_finalizing_the_codec() -> TestResult {
    let mut receiver = open(ReorderLimits::default(), H265Limits::default())?;
    receiver.ingest(KEY, &packet(4, false, &[0x62, 1, 0x93, 1]), 4)?;
    receiver.ingest(KEY, &packet(5, true, &[0x62, 1, 0x53, 2]), 5)?;
    receiver.finish();
    assert_eq!(
        packet_step(&mut receiver, 5)?.1?.status,
        H265Status::FragmentPending
    );
    assert_eq!(
        packet_step(&mut receiver, 5)?.1?.nals[0].bytes(),
        [0x26, 1, 1, 2]
    );
    assert!(matches!(
        receiver.poll(5)?,
        H265ReceivePoll::Ended { discarded: None }
    ));
    assert!(matches!(
        receiver.poll(6)?,
        H265ReceivePoll::Ended { discarded: None }
    ));
    assert_eq!(receiver.next_wake_ns(), None);
    assert!(
        receiver
            .ingest(KEY, &packet(6, true, &[0x26, 1, 3]), 6)
            .is_err()
    );
    Ok(())
}

#[test]
fn finish_emits_intervening_gap_and_incomplete_eof_retirement_once() -> TestResult {
    let mut receiver = open(ReorderLimits::default(), H265Limits::default())?;
    receiver.ingest(KEY, &packet(5, false, &[0x62, 1, 0x93, 1]), 4)?;
    receiver.finish();
    assert!(
        matches!(receiver.poll(4)?, H265ReceivePoll::Gap { gap, discarded: None }
        if gap.first_sequence == 4 && gap.last_sequence == 4 && gap.reason == ReorderGapReason::EndOfInput)
    );
    packet_step(&mut receiver, 4)?.1?;
    assert!(
        matches!(receiver.poll(4)?, H265ReceivePoll::Ended { discarded: Some(discard) }
        if discard.reason == H265Error::EndOfInput && discard.first_sequence == 5)
    );
    assert!(matches!(
        receiver.poll(4)?,
        H265ReceivePoll::Ended { discarded: None }
    ));
    Ok(())
}

#[test]
fn cancellation_accounts_for_queue_and_codec_without_publishing_either() -> TestResult {
    let mut receiver = open(ReorderLimits::default(), H265Limits::default())?;
    receiver.ingest(KEY, &packet(4, false, &[0x62, 1, 0x93, 1]), 4)?;
    packet_step(&mut receiver, 4)?.1?;
    let end = packet(6, true, &[0x62, 1, 0x53, 3]);
    receiver.ingest(KEY, &end, 5)?;
    let cancelled = receiver.cancel();
    assert_eq!(cancelled.queue.reason, QueueDiscardReason::Cancelled);
    assert_eq!(cancelled.queue.packets, 1);
    assert_eq!(cancelled.queue.bytes, end.len());
    assert_eq!(
        cancelled.fragment.ok_or("missing FU cancellation")?.reason,
        H265Error::Cancelled
    );
    assert_eq!(receiver.queued_bytes(), 0);
    assert_eq!(receiver.pending_nal_bytes(), 0);
    assert!(matches!(
        receiver.poll(5)?,
        H265ReceivePoll::Ended { discarded: None }
    ));
    let again = receiver.cancel();
    assert_eq!(again.queue.packets, 0);
    assert!(again.fragment.is_none());
    Ok(())
}

#[test]
fn confirmed_source_restart_fences_both_layers_and_requires_new_generation() -> TestResult {
    let mut receiver = open(ReorderLimits::default(), H265Limits::default())?;
    receiver.ingest(KEY, &packet(4, false, &[0x62, 1, 0x93, 1]), 4)?;
    packet_step(&mut receiver, 4)?.1?;
    receiver.ingest(KEY, &packet(6, true, &[0x26, 1, 3]), 5)?;
    let suspect = receiver.ingest(KEY, &packet(40_000, true, &[0x26, 1, 4]), 6)?;
    assert_eq!(
        suspect.transport.disposition,
        ReorderDisposition::NotAdmitted
    );
    let restart = receiver.ingest(KEY, &packet(40_001, true, &[0x26, 1, 5]), 7)?;
    assert_eq!(
        restart.transport.disposition,
        ReorderDisposition::RestartRequired
    );
    let queue = restart
        .transport
        .discarded
        .ok_or("missing queue retirement")?;
    assert_eq!(queue.reason, QueueDiscardReason::RestartRequired);
    assert_eq!(queue.packets, 1);
    assert_eq!(
        restart.discarded.ok_or("missing codec retirement")?.reason,
        H265Error::Gap
    );
    assert!(matches!(
        receiver.poll(7)?,
        H265ReceivePoll::Ended { discarded: None }
    ));
    assert!(
        receiver
            .restart(KEY, 96, 0, ReorderLimits::default(), H265Limits::default())
            .is_err()
    );
    let new_key = StreamKey {
        generation: 2,
        ..KEY
    };
    let mut next = receiver.restart(
        new_key,
        96,
        0,
        ReorderLimits::default(),
        H265Limits::default(),
    )?;
    prime(&mut next, new_key)?;
    next.ingest(new_key, &packet(4, true, &[0x62, 1, 0x53, 2]), 4)?;
    assert!(
        matches!(packet_step(&mut next, 4)?.1, Err(H265ReceiveError::Codec(failure))
        if failure.reason == H265Error::MissingStart)
    );
    assert!(
        next.ingest(KEY, &packet(5, true, &[0x26, 1, 3]), 5)
            .is_err()
    );
    Ok(())
}

#[test]
fn speculative_restart_does_not_discard_old_owner_work() -> TestResult {
    let mut receiver = open(ReorderLimits::default(), H265Limits::default())?;
    receiver.ingest(KEY, &packet(4, false, &[0x62, 1, 0x93, 1]), 4)?;
    packet_step(&mut receiver, 4)?.1?;
    let next = receiver.restart(
        StreamKey {
            generation: 2,
            ..KEY
        },
        96,
        0,
        ReorderLimits::default(),
        H265Limits::default(),
    )?;
    assert_eq!(next.pending_nal_bytes(), 0);
    assert_eq!(receiver.pending_nal_bytes(), 3);
    receiver.ingest(KEY, &packet(5, true, &[0x62, 1, 0x53, 2]), 5)?;
    assert_eq!(
        packet_step(&mut receiver, 5)?.1?.nals[0].bytes(),
        [0x26, 1, 1, 2]
    );
    Ok(())
}

#[test]
fn reversed_time_and_conflicting_duplicate_refusals_preserve_pending_work() -> TestResult {
    let mut receiver = open(ReorderLimits::default(), H265Limits::default())?;
    receiver.ingest(KEY, &packet(4, false, &[0x62, 1, 0x93, 1]), 4)?;
    packet_step(&mut receiver, 4)?.1?;
    let original = packet(5, true, &[0x62, 1, 0x53, 2]);
    receiver.ingest(KEY, &original, 5)?;
    let before = receiver.stats();
    assert_eq!(
        receiver.poll(4).err().ok_or("reversed clock accepted")?,
        H265ReceiveError::Transport(ReorderError::Continuity(ContinuityError::ClockReversed))
    );
    assert_eq!(
        receiver
            .ingest(KEY, &packet(5, true, &[0x62, 1, 0x53, 9]), 6)
            .err()
            .ok_or("conflicting bytes accepted")?,
        H265ReceiveError::Transport(ReorderError::ConflictingDuplicate)
    );
    assert_eq!(receiver.stats(), before);
    let (source, reconstruction) = packet_step(&mut receiver, 5)?;
    assert_eq!(source.bytes(), original);
    assert_eq!(reconstruction?.nals[0].bytes(), [0x26, 1, 1, 2]);
    Ok(())
}

#[test]
fn unsupported_don_and_resource_configuration_fail_before_admission() -> TestResult {
    let error = H265Receiver::new(KEY, 96, 1, ReorderLimits::default(), H265Limits::default())
        .err()
        .ok_or("unsupported DON silently admitted")?;
    assert!(
        matches!(error, H265ReceiveError::Codec(failure) if failure.reason == H265Error::Unsupported)
    );
    let error = H265Receiver::new(
        KEY,
        96,
        0,
        ReorderLimits {
            max_packets: 0,
            ..ReorderLimits::default()
        },
        H265Limits::default(),
    )
    .err()
    .ok_or("unbounded queue configuration admitted")?;
    assert_eq!(
        error,
        H265ReceiveError::Transport(ReorderError::Configuration)
    );
    Ok(())
}
