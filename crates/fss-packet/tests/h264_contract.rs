#![forbid(unsafe_code)]
//! Actual RTP payload reconstruction and failure/cancellation contracts.

use fss_packet::{
    H264Depacketizer, H264Error, H264Limits, H264Mode, H264Output, H264Status,
    PacketLimits, RtpPacket, SequenceTracker, StreamKey,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey { ingress: 1, generation: 1, ssrc: 7 };

fn packet(sequence: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 96 | if marker { 128 } else { 0 }];
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&KEY.ssrc.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn receiver(limits: H264Limits) -> Result<H264Depacketizer, Box<dyn std::error::Error>> {
    Ok(H264Depacketizer::new(KEY, 96, H264Mode::NonInterleaved, limits)?)
}

fn push(receiver: &mut H264Depacketizer, seq: u64, timestamp: u32, marker: bool, payload: &[u8], now: u64) -> Result<H264Output, Box<dyn std::error::Error>> {
    let bytes = packet(seq as u16, timestamp, marker, payload);
    Ok(receiver.push(KEY, seq, RtpPacket::parse(&bytes, PacketLimits::default())?, now)?)
}

#[test]
fn single_nal_preserves_byte_spans_without_annex_b_or_keyframe_claims() -> TestResult {
    let mut receiver = receiver(H264Limits::default())?;
    let output = push(&mut receiver, 1, 123, true, &[0x65, 1, 2], 0)?;
    assert_eq!(output.status, H264Status::Complete);
    let nal = &output.nals[0];
    assert_eq!(nal.bytes(), [0x65, 1, 2]);
    assert_eq!(nal.nal_type(), 5);
    assert_eq!(nal.key(), KEY);
    assert_eq!(nal.timestamp(), 123);
    assert!(nal.marker());
    assert_eq!(nal.sources()[0].wire_range, 12..15);
    assert_eq!(nal.sources()[0].nal_range, 0..3);
    assert_eq!(nal.sources()[0].fragment_header_range, None);
    assert_eq!(receiver.pending_bytes(), 0);
    Ok(())
}

#[test]
fn stap_a_preserves_order_and_only_last_nal_inherits_marker() -> TestResult {
    let mut receiver = receiver(H264Limits::default())?;
    let output = push(&mut receiver, 1, 123, true, &[0x78, 0, 2, 0x67, 10, 0, 2, 0x68, 20], 0)?;
    assert_eq!(output.nals.len(), 2);
    assert_eq!(output.nals[0].bytes(), [0x67, 10]);
    assert_eq!(output.nals[1].bytes(), [0x68, 20]);
    assert!(!output.nals[0].marker());
    assert!(output.nals[1].marker());
    assert_eq!(output.nals[0].sources()[0].wire_range, 15..17);
    assert_eq!(output.nals[1].sources()[0].wire_range, 19..21);
    Ok(())
}

#[test]
fn malformed_stap_suffix_never_publishes_valid_prefix() -> TestResult {
    for payload in [
        vec![0x78, 0, 2, 0x67, 10, 0, 2, 0x68],
        vec![0x78, 0, 2, 0x67, 10, 0, 0],
        vec![0x78, 0, 2, 0x67, 10, 0, 1, 0x78],
        vec![0x18, 0, 1, 0x67],
    ] {
        let mut receiver = receiver(H264Limits::default())?;
        let bytes = packet(1, 0, false, &payload);
        let failure = receiver.push(KEY, 1, RtpPacket::parse(&bytes, PacketLimits::default())?, 0);
        assert!(failure.is_err());
        assert_eq!(receiver.pending_bytes(), 0);
    }
    Ok(())
}

#[test]
fn fu_a_reassembles_exactly_across_sequence_wrap_and_empty_fragments() -> TestResult {
    let mut receiver = receiver(H264Limits::default())?;
    let start = push(&mut receiver, 65_535, 90_000, false, &[0x7c, 0xa5, 1, 2], 0)?;
    assert_eq!(start.status, H264Status::FragmentPending);
    assert!(start.nals.is_empty());
    let middle = push(&mut receiver, 65_536, 90_000, false, &[0x7c, 0x25], 1)?;
    assert!(middle.nals.is_empty());
    let end = push(&mut receiver, 65_537, 90_000, true, &[0x7c, 0x65, 3, 4], 2)?;
    let nal = &end.nals[0];
    assert_eq!(nal.bytes(), [0x65, 1, 2, 3, 4]);
    assert_eq!(nal.sources().len(), 3);
    assert_eq!(nal.sources()[0].fragment_header_range, Some(12..14));
    assert_eq!(nal.sources()[0].nal_range, 1..3);
    assert_eq!(nal.sources()[1].wire_range, 14..14);
    assert_eq!(nal.sources()[1].nal_range, 3..3);
    assert_eq!(nal.sources()[2].nal_range, 3..5);
    assert_eq!(receiver.pending_bytes(), 0);
    Ok(())
}

#[test]
fn a_gap_retires_partial_media_and_late_repair_cannot_resurrect_it() -> TestResult {
    let mut receiver = receiver(H264Limits::default())?;
    push(&mut receiver, 1, 0, false, &[0x7c, 0x85, 1], 0)?;
    let bytes = packet(3, 0, true, &[0x7c, 0x45, 3]);
    let failure = receiver.push(KEY, 3, RtpPacket::parse(&bytes, PacketLimits::default())?, 2).err().ok_or("gap was accepted")?;
    assert_eq!(failure.reason, H264Error::MissingStart);
    let discarded = failure.discarded.ok_or("missing discard receipt")?;
    assert_eq!(discarded.reason, H264Error::Gap);
    assert_eq!(discarded.byte_len, 2);
    assert_eq!(discarded.first_sequence, 1);
    assert_eq!(discarded.last_sequence, 1);
    let late = push(&mut receiver, 2, 0, false, &[0x7c, 5, 2], 3)?;
    assert_eq!(late.status, H264Status::IgnoredNonIncreasing);
    assert!(late.nals.is_empty());
    assert_eq!(receiver.pending_bytes(), 0);
    assert_eq!(push(&mut receiver, 4, 1, true, &[0x61, 8], 4)?.nals[0].bytes(), [0x61, 8]);
    Ok(())
}

#[test]
fn missing_start_timestamp_header_and_marker_corruption_refuse() -> TestResult {
    for (timestamp, marker, payload, reason) in [
        (1, true, vec![0x7c, 0x45, 2], H264Error::FragmentMismatch),
        (0, true, vec![0x5c, 0x45, 2], H264Error::FragmentMismatch),
        (0, false, vec![0x7c, 0xc5, 2], H264Error::Malformed),
        (0, true, vec![0x7c, 0x05, 2], H264Error::Malformed),
        (0, true, vec![0xfc, 0x45, 2], H264Error::Corrupt),
    ] {
        let mut receiver = receiver(H264Limits::default())?;
        push(&mut receiver, 1, 0, false, &[0x7c, 0x85, 1], 0)?;
        let bytes = packet(2, timestamp, marker, &payload);
        let failure = receiver.push(KEY, 2, RtpPacket::parse(&bytes, PacketLimits::default())?, 1).err().ok_or("bad fragment was accepted")?;
        assert_eq!(failure.reason, reason);
        assert!(failure.discarded.is_some());
        assert_eq!(receiver.pending_bytes(), 0);
    }
    Ok(())
}

#[test]
fn bounded_bytes_fragments_and_aggregation_fail_without_partial_publication() -> TestResult {
    let limits = H264Limits { max_nal_bytes: 3, max_fragment_packets: 2, max_packet_nals: 1, ..H264Limits::default() };
    let mut receiver = receiver(limits)?;
    push(&mut receiver, 1, 0, false, &[0x7c, 0x85, 1, 2], 0)?;
    let bytes = packet(2, 0, true, &[0x7c, 0x45, 3]);
    let failure = receiver.push(KEY, 2, RtpPacket::parse(&bytes, PacketLimits::default())?, 1).err().ok_or("byte limit ignored")?;
    assert_eq!(failure.reason, H264Error::Limit);
    assert_eq!(failure.discarded.ok_or("missing discard")?.byte_len, 3);
    push(&mut receiver, 3, 0, false, &[0x7c, 0x85], 2)?;
    push(&mut receiver, 4, 0, false, &[0x7c, 0x05], 3)?;
    let bytes = packet(5, 0, true, &[0x7c, 0x45]);
    let failure = receiver.push(KEY, 5, RtpPacket::parse(&bytes, PacketLimits::default())?, 4).err().ok_or("fragment limit ignored")?;
    assert_eq!(failure.reason, H264Error::Limit);
    assert_eq!(failure.discarded.ok_or("missing discard")?.fragments, 2);
    assert!(push(&mut receiver, 6, 0, true, &[0x78, 0, 1, 0x67, 0, 1, 0x68], 5).is_err());
    Ok(())
}

#[test]
fn cancellation_deadline_duplicate_traffic_and_eof_never_flush_partial_nals() -> TestResult {
    let limits = H264Limits { max_pending_age_ns: 10, ..H264Limits::default() };
    let mut receiver = receiver(limits)?;
    push(&mut receiver, 1, 0, false, &[0x7c, 0x85, 1], 0)?;
    let duplicate = push(&mut receiver, 1, 0, false, &[0x7c, 0x85, 1], 10)?;
    assert_eq!(duplicate.status, H264Status::IgnoredNonIncreasing);
    assert_eq!(duplicate.discarded.ok_or("duplicate traffic prevented expiry")?.reason, H264Error::Deadline);
    push(&mut receiver, 2, 0, false, &[0x7c, 0x85, 2], 11)?;
    assert_eq!(receiver.expire(21)?.ok_or("missing expiry")?.reason, H264Error::Deadline);
    push(&mut receiver, 3, 0, false, &[0x7c, 0x85, 3], 22)?;
    assert_eq!(receiver.finish().ok_or("missing EOF")?.reason, H264Error::EndOfInput);
    assert!(push(&mut receiver, 4, 0, true, &[0x65, 4], 23).is_err());
    assert!(receiver.finish().is_none());
    let mut receiver = H264Depacketizer::new(KEY, 96, H264Mode::NonInterleaved, limits)?;
    push(&mut receiver, 1, 0, false, &[0x7c, 0x85, 1], 0)?;
    assert_eq!(receiver.cancel().ok_or("missing cancel")?.reason, H264Error::Cancelled);
    assert_eq!(receiver.pending_bytes(), 0);
    assert!(receiver.cancel().is_none());
    Ok(())
}

#[test]
fn wrong_epoch_ssrc_payload_sequence_or_clock_cannot_clear_pending_state() -> TestResult {
    let mut receiver = receiver(H264Limits::default())?;
    push(&mut receiver, 1, 0, false, &[0x7c, 0x85, 1], 10)?;
    let bytes = packet(2, 0, true, &[0x7c, 0x45, 2]);
    let parsed = RtpPacket::parse(&bytes, PacketLimits::default())?;
    let other = StreamKey { generation: 2, ..KEY };
    assert_eq!(receiver.push(other, 2, parsed, 11).err().ok_or("epoch accepted")?.reason, H264Error::StreamMismatch);
    assert_eq!(receiver.push(KEY, 3, parsed, 11).err().ok_or("sequence accepted")?.reason, H264Error::StreamMismatch);
    assert_eq!(receiver.push(KEY, 2, parsed, 9).err().ok_or("clock accepted")?.reason, H264Error::ClockReversed);
    let mut wrong_ssrc = bytes.clone();
    wrong_ssrc[11] = 8;
    let wrong = RtpPacket::parse(&wrong_ssrc, PacketLimits::default())?;
    assert_eq!(receiver.push(KEY, 2, wrong, 11).err().ok_or("SSRC accepted")?.reason, H264Error::StreamMismatch);
    let mut wrong_payload = bytes.clone();
    wrong_payload[1] = 97;
    let wrong = RtpPacket::parse(&wrong_payload, PacketLimits::default())?;
    assert_eq!(receiver.push(KEY, 2, wrong, 11).err().ok_or("payload type accepted")?.reason, H264Error::StreamMismatch);
    assert_eq!(receiver.pending_bytes(), 2);
    assert_eq!(receiver.push(KEY, 2, parsed, 11)?.nals[0].bytes(), [0x65, 1, 2]);
    Ok(())
}

#[test]
fn mode_zero_and_interleaved_packets_never_silently_fallback() -> TestResult {
    let mut mode_zero = H264Depacketizer::new(KEY, 96, H264Mode::SingleNal, H264Limits::default())?;
    assert!(push(&mut mode_zero, 1, 0, true, &[0x65, 1], 0).is_ok());
    assert!(push(&mut mode_zero, 2, 0, false, &[0x7c, 0x85, 1], 1).is_err());
    for kind in [0, 25, 26, 27, 29, 30, 31] {
        let mut receiver = receiver(H264Limits::default())?;
        assert!(push(&mut receiver, 1, 0, false, &[0x60 | kind, 0, 1], 0).is_err());
    }
    Ok(())
}

#[test]
fn reconstructed_spans_match_retained_source_bytes_for_many_fragmentations() -> TestResult {
    for chunk_size in 1..=32 {
        let original: Vec<u8> = (0..127).collect();
        let chunks: Vec<&[u8]> = original.chunks(chunk_size).collect();
        let mut receiver = receiver(H264Limits::default())?;
        let mut retained = Vec::new();
        for (index, chunk) in chunks.iter().enumerate() {
            let end = index + 1 == chunks.len();
            let flags = (if index == 0 { 0x80 } else { 0 }) | (if end { 0x40 } else { 0 });
            let mut payload = vec![0x7c, 5 | flags];
            payload.extend_from_slice(chunk);
            let bytes = packet(index as u16, 0, end, &payload);
            retained.push(bytes.clone());
            let output = receiver.push(KEY, index as u64, RtpPacket::parse(&bytes, PacketLimits::default())?, index as u64)?;
            if end {
                let nal = &output.nals[0];
                assert_eq!(&nal.bytes()[1..], original);
                for source in nal.sources() {
                    assert_eq!(&retained[source.sequence as usize][source.wire_range.clone()], &nal.bytes()[source.nal_range.clone()]);
                }
            } else {
                assert!(output.nals.is_empty());
            }
        }
    }
    Ok(())
}

#[test]
fn sequence_receiver_to_reconstruction_is_a_real_wire_vertical_slice() -> TestResult {
    let mut sequence = SequenceTracker::new(KEY, 96)?;
    let mut decoder = receiver(H264Limits::default())?;
    let mut emitted = Vec::new();
    for (ordinal, (seq, marker, payload)) in [
        (65_533, false, vec![0x67, 0]),
        (65_534, false, vec![0x67, 1]),
        (65_535, false, vec![0x7c, 0x85, 10]),
        (65_535, false, vec![0x7c, 0x85, 10]),
        (0, true, vec![0x7c, 0x45, 20]),
    ].into_iter().enumerate() {
        let bytes = packet(seq, 90_000, marker, &payload);
        let parsed = RtpPacket::parse(&bytes, PacketLimits::default())?;
        let observation = sequence.observe(KEY, parsed)?;
        if observation.is_unique() {
            let extended = observation.extended_sequence.ok_or("unique packet without sequence")?;
            emitted.extend(decoder.push(KEY, extended, parsed, ordinal as u64)?.nals);
        }
    }
    assert_eq!(emitted.len(), 2);
    assert_eq!(emitted[0].bytes(), [0x67, 1]);
    assert_eq!(emitted[1].bytes(), [0x65, 10, 20]);
    assert_eq!(sequence.stats().missing, 0);
    assert!(decoder.finish().is_none());
    Ok(())
}
