#![forbid(unsafe_code)]
//! End-to-end ordered wire delivery and H.264 reconstruction lifecycle contracts.

use fss_packet::{
    ContinuityError, H264Depacketizer, H264Error, H264Limits, H264Mode, H264Output,
    H264ReceiveError, H264ReceivePoll, H264Receiver, H264Status, OrderedRtpPacket,
    PacketLimits, QueueDiscardReason, ReorderDisposition, ReorderError, ReorderGapReason,
    ReorderLimits, RtpPacket, StreamKey,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey {
    ingress: 1,
    generation: 1,
    ssrc: 7,
};

fn limits() -> ReorderLimits {
    ReorderLimits {
        max_packets: 8,
        max_bytes: 1_024,
        max_delay_ns: 10,
        ..ReorderLimits::default()
    }
}

fn codec_limits() -> H264Limits {
    H264Limits {
        max_nal_bytes: 128,
        max_pending_age_ns: 100,
        ..H264Limits::default()
    }
}

fn wire(sequence: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 96 | if marker { 128 } else { 0 }];
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&9000_u32.to_be_bytes());
    bytes.extend_from_slice(&KEY.ssrc.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn delivered(
    receiver: &mut H264Receiver,
    now: u64,
    sequence: u64,
) -> TestResult<(OrderedRtpPacket, Result<H264Output, H264ReceiveError>)> {
    let H264ReceivePoll::Packet {
        source,
        reconstruction,
    } = receiver.poll(now)?
    else {
        return Err("expected an original datagram and reconstruction result".into());
    };
    assert_eq!(source.sequence(), sequence);
    Ok((source, reconstruction))
}

fn open(reorder: ReorderLimits, codec: H264Limits) -> TestResult<H264Receiver> {
    let mut receiver = H264Receiver::new(KEY, 96, H264Mode::NonInterleaved, reorder, codec)?;
    receiver.ingest(KEY, &wire(9, true, &[0x61, 0]), 0)?;
    receiver.ingest(KEY, &wire(10, true, &[0x61, 0]), 0)?;
    let (_, output) = delivered(&mut receiver, 0, 10)?;
    assert_eq!(output?.status, H264Status::Complete);
    Ok(receiver)
}

#[test]
fn reordered_fu_reconstructs_exact_nal_and_retains_each_original_timestamp() -> TestResult {
    let mut receiver = open(limits(), codec_limits())?;
    let start = wire(11, false, &[0x7c, 0x85, b'a']);
    let middle = wire(12, false, &[0x7c, 0x05, b'b']);
    let end = wire(13, true, &[0x7c, 0x45, b'c']);
    receiver.ingest(KEY, &start, 1)?;
    receiver.ingest(KEY, &end, 2)?;
    receiver.ingest(KEY, &middle, 3)?;
    let (source, pending) = delivered(&mut receiver, 3, 11)?;
    assert_eq!(source.bytes(), start);
    assert_eq!(source.received_ns(), 1);
    assert_eq!(pending?.status, H264Status::FragmentPending);
    let (source, pending) = delivered(&mut receiver, 3, 12)?;
    assert_eq!(source.bytes(), middle);
    assert_eq!(source.received_ns(), 3);
    assert_eq!(pending?.status, H264Status::FragmentPending);
    let (source, completed) = delivered(&mut receiver, 3, 13)?;
    assert_eq!(source.bytes(), end);
    assert_eq!(source.received_ns(), 2);
    let output = completed?;
    assert_eq!(output.status, H264Status::Complete);
    assert!(!output.gap_before);
    assert!(output.discarded.is_none());
    assert_eq!(output.nals.len(), 1);
    let nal = &output.nals[0];
    assert_eq!(nal.bytes(), &[0x65, b'a', b'b', b'c']);
    assert_eq!(nal.key(), KEY);
    assert_eq!(nal.timestamp(), 9000);
    assert!(nal.marker());
    assert_eq!(nal.sources().len(), 3);
    for (index, span) in nal.sources().iter().enumerate() {
        assert_eq!(span.sequence, 11 + index as u64);
        assert_eq!(span.wire_range, 14..15);
        assert_eq!(span.fragment_header_range, Some(12..14));
        assert_eq!(span.nal_range, index + 1..index + 2);
    }
    assert_eq!(receiver.pending_nal_bytes(), 0);
    assert_eq!(receiver.queued_bytes(), 0);
    assert_eq!(receiver.next_wake_ns(), None);
    Ok(())
}

#[test]
fn missing_fragment_retires_chain_before_next_packet_and_preserves_refused_source() -> TestResult {
    let mut receiver = open(limits(), codec_limits())?;
    receiver.ingest(KEY, &wire(11, false, &[0x7c, 0x85, 1]), 1)?;
    delivered(&mut receiver, 1, 11)?.1?;
    let end = wire(13, true, &[0x7c, 0x45, 3]);
    receiver.ingest(KEY, &end, 2)?;
    assert_eq!(receiver.next_wake_ns(), Some(12));
    let H264ReceivePoll::Gap { gap, discarded } = receiver.poll(12)? else {
        return Err("expected gap before packet delivery".into());
    };
    assert_eq!((gap.first_sequence, gap.last_sequence), (12, 12));
    assert_eq!(gap.reason, ReorderGapReason::Deadline);
    let retired = discarded.ok_or("missing fragment retirement receipt")?;
    assert_eq!(retired.reason, H264Error::Gap);
    assert_eq!(retired.first_sequence, 11);
    assert_eq!(retired.byte_len, 2);
    assert_eq!(receiver.pending_nal_bytes(), 0);
    let (source, refusal) = delivered(&mut receiver, 12, 13)?;
    assert_eq!(source.bytes(), end);
    let H264ReceiveError::Codec(failure) = refusal.err().ok_or("expected codec refusal")? else {
        return Err("wrong refusal layer".into());
    };
    assert_eq!(failure.reason, H264Error::MissingStart);
    assert!(failure.discarded.is_none());
    let late = receiver.ingest(KEY, &wire(12, false, &[0x7c, 0x05, 2]), 13)?;
    assert_eq!(late.transport.disposition, ReorderDisposition::TooLate);
    assert_eq!(receiver.pending_nal_bytes(), 0);
    Ok(())
}

#[test]
fn codec_deadline_wakes_without_network_and_duplicates_cannot_extend_it() -> TestResult {
    let mut receiver = open(limits(), codec_limits())?;
    let start = wire(11, false, &[0x7c, 0x85, 1]);
    receiver.ingest(KEY, &start, 1)?;
    delivered(&mut receiver, 1, 11)?.1?;
    assert_eq!(receiver.next_wake_ns(), Some(101));
    receiver.ingest(KEY, &start, 100)?;
    assert_eq!(receiver.next_wake_ns(), Some(101));
    assert_eq!(
        receiver.poll(100)?,
        H264ReceivePoll::Pending { wake_at_ns: Some(101) }
    );
    let H264ReceivePoll::FragmentDiscarded(retired) = receiver.poll(101)? else {
        return Err("expected timer-only fragment retirement".into());
    };
    assert_eq!(retired.reason, H264Error::Deadline);
    assert_eq!(receiver.pending_nal_bytes(), 0);
    assert_eq!(receiver.next_wake_ns(), None);
    assert_eq!(receiver.poll(101)?, H264ReceivePoll::Pending { wake_at_ns: None });
    Ok(())
}

#[test]
fn codec_timeout_precedes_later_transport_deadline_without_consuming_queued_source() -> TestResult {
    let mut receiver = open(
        ReorderLimits { max_delay_ns: 100, ..limits() },
        H264Limits { max_pending_age_ns: 5, ..codec_limits() },
    )?;
    receiver.ingest(KEY, &wire(11, false, &[0x7c, 0x85, 1]), 1)?;
    delivered(&mut receiver, 1, 11)?.1?;
    receiver.ingest(KEY, &wire(13, true, &[0x65, 3]), 2)?;
    assert_eq!(receiver.next_wake_ns(), Some(6));
    assert!(matches!(receiver.poll(6)?, H264ReceivePoll::FragmentDiscarded(_)));
    assert_eq!(receiver.queued_packets(), 1);
    assert_eq!(receiver.next_wake_ns(), Some(102));
    let H264ReceivePoll::Gap { discarded, .. } = receiver.poll(102)? else {
        return Err("expected later transport gap".into());
    };
    assert!(discarded.is_none());
    let (_, output) = delivered(&mut receiver, 102, 13)?;
    assert!(output?.gap_before);
    Ok(())
}

#[test]
fn malformed_stap_and_codec_byte_limit_keep_original_datagrams() -> TestResult {
    let mut receiver = open(limits(), H264Limits { max_nal_bytes: 3, ..codec_limits() })?;
    for (sequence, payload, expected) in [
        (11, vec![0x78, 0, 2, 0x65, 1, 0], H264Error::Malformed),
        (12, vec![0x65, 1, 2, 3], H264Error::Limit),
        (13, vec![0xe5, 1], H264Error::Corrupt),
    ] {
        let original = wire(sequence, true, &payload);
        receiver.ingest(KEY, &original, 1)?;
        let (source, refusal) = delivered(&mut receiver, 1, u64::from(sequence))?;
        assert_eq!(source.bytes(), original);
        let H264ReceiveError::Codec(failure) = refusal.err().ok_or("expected refusal")? else {
            return Err("wrong refusal layer".into());
        };
        assert_eq!(failure.reason, expected);
        assert_eq!(receiver.pending_nal_bytes(), 0);
    }
    receiver.ingest(KEY, &wire(14, true, &[0x65, 1]), 2)?;
    assert_eq!(delivered(&mut receiver, 2, 14)?.1?.nals.len(), 1);
    Ok(())
}

#[test]
fn eof_drains_complete_queued_fu_before_finalizing_codec() -> TestResult {
    let mut receiver = open(limits(), codec_limits())?;
    receiver.ingest(KEY, &wire(12, true, &[0x7c, 0x45, 2]), 1)?;
    receiver.ingest(KEY, &wire(11, false, &[0x7c, 0x85, 1]), 2)?;
    receiver.finish();
    assert_eq!(delivered(&mut receiver, 2, 11)?.1?.status, H264Status::FragmentPending);
    let output = delivered(&mut receiver, 2, 12)?.1?;
    assert_eq!(output.nals[0].bytes(), &[0x65, 1, 2]);
    assert_eq!(receiver.poll(2)?, H264ReceivePoll::Ended { discarded: None });
    assert_eq!(receiver.next_wake_ns(), None);
    assert_eq!(receiver.poll(2)?, H264ReceivePoll::Ended { discarded: None });
    Ok(())
}

#[test]
fn eof_reports_unfinished_fragment_once_without_fabricating_complete_output() -> TestResult {
    let mut receiver = open(limits(), codec_limits())?;
    receiver.ingest(KEY, &wire(11, false, &[0x7c, 0x85, 1]), 1)?;
    delivered(&mut receiver, 1, 11)?.1?;
    receiver.finish();
    let H264ReceivePoll::Ended { discarded } = receiver.poll(1)? else {
        return Err("expected EOF".into());
    };
    assert_eq!(discarded.ok_or("expected retirement")?.reason, H264Error::EndOfInput);
    assert_eq!(receiver.poll(1)?, H264ReceivePoll::Ended { discarded: None });
    assert_eq!(receiver.pending_nal_bytes(), 0);
    assert_eq!(receiver.next_wake_ns(), None);
    assert_eq!(
        receiver.ingest(KEY, &wire(12, true, &[0x65]), 2).err(),
        Some(H264ReceiveError::Transport(ReorderError::Closed))
    );
    Ok(())
}

#[test]
fn cancellation_accounts_for_both_queues_and_is_idempotent() -> TestResult {
    let mut receiver = open(limits(), codec_limits())?;
    receiver.ingest(KEY, &wire(11, false, &[0x7c, 0x85, 1]), 1)?;
    delivered(&mut receiver, 1, 11)?.1?;
    receiver.ingest(KEY, &wire(13, true, &[0x7c, 0x45, 3]), 2)?;
    let receipt = receiver.cancel();
    assert_eq!(receipt.queue.reason, QueueDiscardReason::Cancelled);
    assert_eq!(receipt.queue.packets, 1);
    assert_eq!(receipt.queue.bytes, 15);
    assert_eq!(receipt.fragment.ok_or("expected fragment receipt")?.reason, H264Error::Cancelled);
    assert_eq!(receiver.queued_bytes(), 0);
    assert_eq!(receiver.pending_nal_bytes(), 0);
    assert_eq!(receiver.next_wake_ns(), None);
    let second = receiver.cancel();
    assert_eq!(second.queue.packets, 0);
    assert!(second.fragment.is_none());
    assert_eq!(receiver.poll(2)?, H264ReceivePoll::Ended { discarded: None });
    Ok(())
}

#[test]
fn restart_retires_both_layers_and_cannot_reuse_old_generation() -> TestResult {
    let mut receiver = open(limits(), codec_limits())?;
    receiver.ingest(KEY, &wire(11, false, &[0x7c, 0x85, 1]), 1)?;
    delivered(&mut receiver, 1, 11)?.1?;
    receiver.ingest(KEY, &wire(13, true, &[0x7c, 0x45, 3]), 2)?;
    receiver.ingest(KEY, &wire(20000, true, &[0x65]), 3)?;
    let restart = receiver.ingest(KEY, &wire(20001, true, &[0x65]), 4)?;
    assert_eq!(restart.transport.disposition, ReorderDisposition::RestartRequired);
    assert_eq!(restart.transport.discarded.ok_or("expected queue receipt")?.packets, 1);
    assert_eq!(restart.discarded.ok_or("expected codec receipt")?.reason, H264Error::Gap);
    assert_eq!(receiver.next_wake_ns(), None);
    assert_eq!(receiver.poll(4)?, H264ReceivePoll::Ended { discarded: None });
    assert_eq!(
        receiver.restart(KEY, 96, H264Mode::NonInterleaved, limits(), codec_limits()).err(),
        Some(H264ReceiveError::Transport(ReorderError::Continuity(
            ContinuityError::GenerationRequired
        )))
    );
    let newer = StreamKey { generation: 2, ..KEY };
    let mut fresh = receiver.restart(newer, 96, H264Mode::NonInterleaved, limits(), codec_limits())?;
    fresh.ingest(newer, &wire(1, true, &[0x65]), 0)?;
    fresh.ingest(newer, &wire(2, true, &[0x65]), 0)?;
    let (source, output) = delivered(&mut fresh, 0, 2)?;
    assert_eq!(source.key(), newer);
    assert_eq!(output?.nals[0].key(), newer);
    Ok(())
}

#[test]
fn shared_clock_guards_ingest_and_poll_without_consuming_queued_data() -> TestResult {
    let mut receiver = open(limits(), codec_limits())?;
    receiver.ingest(KEY, &wire(11, true, &[0x65]), 5)?;
    let before = receiver.stats();
    let clock_error = H264ReceiveError::Transport(ReorderError::Continuity(
        ContinuityError::ClockReversed,
    ));
    assert_eq!(receiver.poll(4).err(), Some(clock_error.clone()));
    assert_eq!(receiver.ingest(KEY, &wire(12, true, &[0x65]), 4).err(), Some(clock_error));
    assert_eq!(receiver.stats(), before);
    assert_eq!(receiver.queued_packets(), 1);
    delivered(&mut receiver, 5, 11)?.1?;
    assert_eq!(receiver.poll(7)?, H264ReceivePoll::Pending { wake_at_ns: None });
    assert!(receiver.ingest(KEY, &wire(12, true, &[0x65]), 6).is_err());
    receiver.ingest(KEY, &wire(12, true, &[0x65]), 7)?;
    delivered(&mut receiver, 7, 12)?.1?;
    Ok(())
}

#[test]
fn capacity_refusal_then_retry_does_not_break_fragment_reconstruction() -> TestResult {
    let mut receiver = open(ReorderLimits { max_packets: 1, ..limits() }, codec_limits())?;
    receiver.ingest(KEY, &wire(11, false, &[0x7c, 0x85, 1]), 1)?;
    let end = wire(12, true, &[0x7c, 0x45, 2]);
    let before = receiver.stats();
    assert_eq!(
        receiver.ingest(KEY, &end, 2).err(),
        Some(H264ReceiveError::Transport(ReorderError::PacketCapacity))
    );
    assert_eq!(receiver.stats(), before);
    delivered(&mut receiver, 2, 11)?.1?;
    receiver.ingest(KEY, &end, 2)?;
    let output = delivered(&mut receiver, 2, 12)?.1?;
    assert_eq!(output.nals[0].bytes(), &[0x65, 1, 2]);
    Ok(())
}

#[test]
fn receiver_debug_and_codec_failure_do_not_print_private_media() -> TestResult {
    let mut receiver = open(limits(), codec_limits())?;
    let mut payload = vec![0x80];
    payload.extend_from_slice(b"PRIVATE-RECEIVER-MEDIA");
    receiver.ingest(KEY, &wire(11, true, &payload), 1)?;
    let before = format!("{receiver:?}");
    let after = format!("{:?}", receiver.poll(1)?);
    for text in [before, after] {
        assert!(!text.contains("PRIVATE-RECEIVER-MEDIA"));
        assert!(!text.contains(&format!("{payload:?}")));
    }
    Ok(())
}

#[test]
fn no_traffic_and_eof_during_probation_do_not_create_a_nal_or_gap() -> TestResult {
    let mut receiver = H264Receiver::new(KEY, 96, H264Mode::NonInterleaved, limits(), codec_limits())?;
    assert_eq!(receiver.next_wake_ns(), None);
    assert_eq!(receiver.poll(0)?, H264ReceivePoll::Pending { wake_at_ns: None });
    receiver.ingest(KEY, &wire(9, true, &[0x65]), 0)?;
    receiver.finish();
    assert_eq!(receiver.poll(0)?, H264ReceivePoll::Ended { discarded: None });
    Ok(())
}

#[test]
fn standalone_fragment_timer_and_gap_hooks_do_not_change_packet_admission() -> TestResult {
    let mut depacketizer = H264Depacketizer::new(KEY, 96, H264Mode::NonInterleaved, codec_limits())?;
    let start = wire(11, false, &[0x7c, 0x85, 1]);
    depacketizer.push(KEY, 11, RtpPacket::parse(&start, PacketLimits::default())?, 1)?;
    assert_eq!(depacketizer.next_deadline_ns(), Some(101));
    assert_eq!(depacketizer.discard_gap().ok_or("expected gap receipt")?.reason, H264Error::Gap);
    assert_eq!(depacketizer.next_deadline_ns(), None);
    assert!(depacketizer.discard_gap().is_none());
    let next = wire(13, true, &[0x65, 2]);
    let output = depacketizer.push(KEY, 13, RtpPacket::parse(&next, PacketLimits::default())?, 2)?;
    assert!(output.gap_before);
    assert_eq!(output.nals[0].bytes(), &[0x65, 2]);
    Ok(())
}

#[test]
fn unrepresentable_fu_deadline_is_refused_but_boundary_deadline_expires() -> TestResult {
    let config = H264Limits { max_pending_age_ns: 10, ..codec_limits() };
    let start = wire(11, false, &[0x7c, 0x85, 1]);
    let packet = RtpPacket::parse(&start, PacketLimits::default())?;
    let mut depacketizer = H264Depacketizer::new(KEY, 96, H264Mode::NonInterleaved, config)?;
    let error = depacketizer.push(KEY, 11, packet, u64::MAX - 9).err().ok_or("expected refusal")?;
    assert_eq!(error.reason, H264Error::Limit);
    assert_eq!(depacketizer.pending_bytes(), 0);
    assert_eq!(depacketizer.next_deadline_ns(), None);
    let mut boundary = H264Depacketizer::new(KEY, 96, H264Mode::NonInterleaved, config)?;
    boundary.push(KEY, 11, packet, u64::MAX - 10)?;
    assert_eq!(boundary.next_deadline_ns(), Some(u64::MAX));
    assert!(boundary.expire(u64::MAX - 1)?.is_none());
    assert_eq!(boundary.expire(u64::MAX)?.ok_or("expected expiry")?.reason, H264Error::Deadline);
    Ok(())
}

#[test]
fn receiver_returns_source_when_delivery_clock_cannot_represent_a_fu_deadline() -> TestResult {
    let mut receiver = open(limits(), codec_limits())?;
    let start = wire(11, false, &[0x7c, 0x85, 1]);
    receiver.ingest(KEY, &start, 1)?;
    let (source, refusal) = delivered(&mut receiver, u64::MAX - 50, 11)?;
    assert_eq!(source.bytes(), start);
    let H264ReceiveError::Codec(failure) = refusal.err().ok_or("expected refusal")? else {
        return Err("wrong refusal layer".into());
    };
    assert_eq!(failure.reason, H264Error::Limit);
    assert_eq!(receiver.pending_nal_bytes(), 0);
    assert_eq!(receiver.next_wake_ns(), None);
    Ok(())
}
