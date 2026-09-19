#![forbid(unsafe_code)]
//! RFC 7798 wire reconstruction, provenance, and explicit failure contracts.

use fss_packet::{
    H265Depacketizer, H265Error, H265Failure, H265Limits, H265Output, H265Status,
    PacketLimits, RtpPacket, StreamKey,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey {
    ingress: 1,
    generation: 1,
    ssrc: 7,
};

fn packet(sequence: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 96 | if marker { 128 } else { 0 }];
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&KEY.ssrc.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn receiver(limits: H265Limits) -> Result<H265Depacketizer, H265Failure> {
    H265Depacketizer::new(KEY, 96, 0, limits)
}

fn feed(
    receiver: &mut H265Depacketizer,
    seq: u64,
    timestamp: u32,
    marker: bool,
    payload: &[u8],
    now: u64,
) -> Result<Result<H265Output, H265Failure>, Box<dyn std::error::Error>> {
    let bytes = packet(seq as u16, timestamp, marker, payload);
    Ok(receiver.push(
        KEY,
        seq,
        RtpPacket::parse(&bytes, PacketLimits::default())?,
        now,
    ))
}

fn header(kind: u8, layer: u8, tid: u8) -> [u8; 2] {
    [(kind << 1) | (layer >> 5), ((layer & 31) << 3) | tid]
}

fn aggregate(nals: &[Vec<u8>], layer: u8, tid: u8) -> Vec<u8> {
    let mut payload = header(48, layer, tid).to_vec();
    for nal in nals {
        payload.extend_from_slice(&(nal.len() as u16).to_be_bytes());
        payload.extend_from_slice(nal);
    }
    payload
}

#[test]
fn single_nal_preserves_layer_temporal_identity_and_original_byte_ranges() -> TestResult {
    let mut receiver = receiver(H265Limits::default())?;
    let mut payload = header(19, 37, 3).to_vec();
    payload.extend_from_slice(&[1, 2, 3]);
    let output = feed(&mut receiver, 1, 123, true, &payload, 0)??;
    assert_eq!(output.status, H265Status::Complete);
    let nal = &output.nals[0];
    assert_eq!(nal.bytes(), payload);
    assert_eq!(nal.nal_type(), 19);
    assert_eq!(nal.layer_id(), 37);
    assert_eq!(nal.temporal_id_plus_one(), 3);
    assert_eq!(nal.key(), KEY);
    assert_eq!(nal.timestamp(), 123);
    assert!(nal.marker());
    assert_eq!(nal.sources()[0].wire_range, 12..17);
    assert_eq!(nal.sources()[0].nal_range, 0..5);
    assert_eq!(nal.sources()[0].fragment_header_range, None);
    assert_eq!(receiver.pending_bytes(), 0);
    Ok(())
}

#[test]
fn aggregation_preserves_all_members_order_and_last_marker() -> TestResult {
    let mut receiver = receiver(H265Limits::default())?;
    let nals = vec![vec![0x40, 1, 10], vec![0x42, 1, 20], vec![0x44, 1, 30]];
    let payload = aggregate(&nals, 0, 1);
    let output = feed(&mut receiver, 1, 900, true, &payload, 0)??;
    assert_eq!(output.nals.len(), 3);
    for (index, nal) in output.nals.iter().enumerate() {
        assert_eq!(nal.bytes(), nals[index]);
        assert_eq!(nal.sources()[0].sequence, 1);
        assert_eq!(nal.sources()[0].wire_range, 16 + index * 5..19 + index * 5);
        assert_eq!(nal.marker(), index == 2);
    }
    Ok(())
}

#[test]
fn aggregate_header_uses_independent_minimum_layer_and_temporal_fields() -> TestResult {
    let nals = vec![header(32, 2, 7).to_vec(), header(33, 33, 2).to_vec()];
    let mut receiver = receiver(H265Limits::default())?;
    assert_eq!(
        feed(&mut receiver, 1, 0, false, &aggregate(&nals, 2, 2), 0)??.nals.len(),
        2
    );
    for (seq, layer, tid) in [(2, 33, 2), (3, 2, 7), (4, 0, 1)] {
        let error = feed(&mut receiver, seq, 0, false, &aggregate(&nals, layer, tid), seq)?
            .err()
            .ok_or("invalid AP identity was accepted")?;
        assert_eq!(error.reason, H265Error::Malformed);
    }
    Ok(())
}

#[test]
fn malformed_aggregation_never_publishes_a_valid_prefix() -> TestResult {
    let valid = aggregate(&[vec![0x40, 1, 10], vec![0x42, 1, 20]], 0, 1);
    let mut truncated = valid.clone();
    truncated.pop();
    let mut trailing_byte = valid;
    trailing_byte.push(0);
    for payload in [
        truncated,
        trailing_byte,
        aggregate(&[vec![0x40, 1, 10]], 0, 1),
        aggregate(&[], 0, 1),
        aggregate(&[vec![0x40, 1], vec![]], 0, 1),
        aggregate(&[vec![0x40, 1], vec![0x42]], 0, 1),
        aggregate(&[vec![0x40, 1], vec![0x60, 1]], 0, 1),
        aggregate(&[vec![0x40, 1], vec![0x62, 1]], 0, 1),
        aggregate(&[vec![0x40, 1], vec![0x64, 1]], 0, 1),
        aggregate(&[vec![0x40, 1], vec![0x42, 0]], 0, 1),
    ] {
        let mut receiver = receiver(H265Limits::default())?;
        assert!(feed(&mut receiver, 1, 0, true, &payload, 0)?.is_err());
        assert_eq!(receiver.pending_bytes(), 0);
    }
    Ok(())
}

#[test]
fn forbidden_bit_zero_temporal_id_and_unsupported_packet_types_are_explicit() -> TestResult {
    for (payload, expected) in [
        (vec![], H265Error::Malformed),
        (vec![0x26], H265Error::Malformed),
        (vec![0x26, 0], H265Error::Malformed),
        (vec![0xa6, 1], H265Error::Corrupt),
        (vec![0x64, 1], H265Error::Unsupported),
        (vec![0x7e, 1], H265Error::Unsupported),
        (aggregate(&[vec![0x40, 1], vec![0xc2, 1]], 0, 1), H265Error::Corrupt),
    ] {
        let mut receiver = receiver(H265Limits::default())?;
        let error = feed(&mut receiver, 1, 0, false, &payload, 0)?
            .err()
            .ok_or("invalid header accepted")?;
        assert_eq!(error.reason, expected);
    }
    Ok(())
}

#[test]
fn fragmented_nal_wraps_sequence_and_preserves_two_byte_header_provenance() -> TestResult {
    let mut receiver = receiver(H265Limits::default())?;
    let start = feed(&mut receiver, 65_535, 90_000, false, &[0x63, 0x2b, 0x93, 1, 2], 0)??;
    assert_eq!(start.status, H265Status::FragmentPending);
    assert!(start.nals.is_empty());
    feed(&mut receiver, 65_536, 90_000, false, &[0x63, 0x2b, 0x13, 3], 1)??;
    let output = feed(&mut receiver, 65_537, 90_000, true, &[0x63, 0x2b, 0x53, 4, 5], 2)??;
    let nal = &output.nals[0];
    assert_eq!(nal.bytes(), [0x27, 0x2b, 1, 2, 3, 4, 5]);
    assert_eq!(nal.layer_id(), 37);
    assert_eq!(nal.temporal_id_plus_one(), 3);
    assert_eq!(nal.sources().len(), 3);
    assert_eq!(nal.sources()[0].fragment_header_range, Some(12..15));
    assert_eq!(nal.sources()[0].wire_range, 15..17);
    assert_eq!(nal.sources()[0].nal_range, 2..4);
    assert_eq!(nal.sources()[1].nal_range, 4..5);
    assert_eq!(nal.sources()[2].nal_range, 5..7);
    assert_eq!(nal.sources()[2].sequence, 65_537);
    assert!(nal.marker());
    assert_eq!(receiver.pending_bytes(), 0);
    Ok(())
}

#[test]
fn every_fragment_split_preserves_all_layer_and_temporal_header_bits() -> TestResult {
    for layer in 0..=63 {
        for tid in 1..=7 {
            for split in 1..7 {
                let mut receiver = receiver(H265Limits::default())?;
                let body = [10, 20, 30, 40, 50, 60, 70];
                let mut start = header(49, layer, tid).to_vec();
                start.push(0x80 | 21);
                start.extend_from_slice(&body[..split]);
                let mut end = header(49, layer, tid).to_vec();
                end.push(0x40 | 21);
                end.extend_from_slice(&body[split..]);
                feed(&mut receiver, 1, 0, false, &start, 0)??;
                let output = feed(&mut receiver, 2, 0, true, &end, 1)??;
                let mut expected = header(21, layer, tid).to_vec();
                expected.extend_from_slice(&body);
                assert_eq!(output.nals[0].bytes(), expected);
                assert_eq!(output.nals[0].layer_id(), layer);
                assert_eq!(output.nals[0].temporal_id_plus_one(), tid);
            }
        }
    }
    Ok(())
}

#[test]
fn empty_illegal_combined_or_nested_fragment_headers_are_refused() -> TestResult {
    for payload in [
        vec![0x62, 1],
        vec![0x62, 1, 0x93],
        vec![0x62, 1, 0xd3, 1],
        vec![0x62, 1, 0xb0, 1],
        vec![0x62, 1, 0xb1, 1],
        vec![0x62, 1, 0xbf, 1],
    ] {
        let mut receiver = receiver(H265Limits::default())?;
        let error = feed(&mut receiver, 1, 0, false, &payload, 0)?
            .err()
            .ok_or("malformed FU accepted")?;
        assert_eq!(error.reason, H265Error::Malformed);
        assert_eq!(receiver.pending_bytes(), 0);
    }
    Ok(())
}

#[test]
fn timestamp_layer_temporal_type_and_marker_changes_retire_pending_chain() -> TestResult {
    for (timestamp, marker, payload, expected) in [
        (1, true, vec![0x62, 1, 0x53, 2], H265Error::FragmentMismatch),
        (0, true, vec![0x63, 1, 0x53, 2], H265Error::FragmentMismatch),
        (0, true, vec![0x62, 9, 0x53, 2], H265Error::FragmentMismatch),
        (0, true, vec![0x62, 2, 0x53, 2], H265Error::FragmentMismatch),
        (0, true, vec![0x62, 1, 0x54, 2], H265Error::FragmentMismatch),
        (0, true, vec![0x62, 1, 0x13, 2], H265Error::Malformed),
        (0, false, vec![0x62, 1, 0x13], H265Error::Malformed),
    ] {
        let mut receiver = receiver(H265Limits::default())?;
        feed(&mut receiver, 1, 0, false, &[0x62, 1, 0x93, 1], 0)??;
        let error = feed(&mut receiver, 2, timestamp, marker, &payload, 1)?
            .err()
            .ok_or("invalid FU continuation accepted")?;
        assert_eq!(error.reason, expected);
        assert_eq!(error.discarded.ok_or("missing discard")?.reason, expected);
        assert_eq!(receiver.pending_bytes(), 0);
    }
    Ok(())
}

#[test]
fn missing_start_and_loss_never_publish_or_resurrect_partial_media() -> TestResult {
    let mut receiver = receiver(H265Limits::default())?;
    let error = feed(&mut receiver, 1, 0, true, &[0x62, 1, 0x53, 1], 0)?
        .err().ok_or("missing start accepted")?;
    assert_eq!(error.reason, H265Error::MissingStart);
    feed(&mut receiver, 2, 0, false, &[0x62, 1, 0x93, 2], 1)??;
    let error = feed(&mut receiver, 4, 0, true, &[0x62, 1, 0x53, 4], 2)?
        .err().ok_or("gap was accepted")?;
    assert_eq!(error.reason, H265Error::MissingStart);
    let discarded = error.discarded.ok_or("missing gap receipt")?;
    assert_eq!(discarded.reason, H265Error::Gap);
    assert_eq!(discarded.first_sequence, 2);
    assert_eq!(discarded.last_sequence, 2);
    assert_eq!(discarded.byte_len, 3);
    let late = feed(&mut receiver, 3, 0, false, &[0x62, 1, 0x13, 3], 3)??;
    assert_eq!(late.status, H265Status::IgnoredNonIncreasing);
    assert!(late.nals.is_empty());
    assert_eq!(receiver.pending_bytes(), 0);
    let clean = feed(&mut receiver, 6, 1, true, &[0x26, 1, 8], 4)??;
    assert!(clean.gap_before);
    assert_eq!(clean.nals[0].bytes(), [0x26, 1, 8]);
    Ok(())
}

#[test]
fn interrupted_and_owner_declared_gap_receipts_are_reported_once() -> TestResult {
    let mut receiver = receiver(H265Limits::default())?;
    feed(&mut receiver, 1, 0, false, &[0x62, 1, 0x93, 1], 0)??;
    let fresh = feed(&mut receiver, 2, 1, false, &[0x62, 1, 0x94, 2], 1)??;
    assert_eq!(fresh.discarded.ok_or("missing interruption")?.reason, H265Error::Interrupted);
    let single = feed(&mut receiver, 3, 2, true, &[0x26, 1, 3], 2)??;
    assert_eq!(single.discarded.ok_or("missing single interruption")?.first_sequence, 2);
    feed(&mut receiver, 4, 3, false, &[0x62, 1, 0x93, 4], 3)??;
    assert_eq!(receiver.discard_gap().ok_or("missing declared gap")?.reason, H265Error::Gap);
    assert!(receiver.discard_gap().is_none());
    Ok(())
}

#[test]
fn deadlines_fire_without_network_and_duplicate_traffic_cannot_extend_them() -> TestResult {
    let limits = H265Limits { max_pending_age_ns: 10, ..H265Limits::default() };
    let mut receiver = receiver(limits)?;
    feed(&mut receiver, 1, 0, false, &[0x62, 1, 0x93, 1], 2)??;
    assert_eq!(receiver.next_deadline_ns(), Some(12));
    let duplicate = feed(&mut receiver, 1, 0, false, &[0x62, 1, 0x93, 1], 11)??;
    assert_eq!(duplicate.status, H265Status::IgnoredNonIncreasing);
    assert_eq!(receiver.next_deadline_ns(), Some(12));
    assert_eq!(receiver.expire(12)?.ok_or("expiry missing")?.reason, H265Error::Deadline);
    assert!(receiver.expire(13)?.is_none());
    assert_eq!(receiver.next_deadline_ns(), None);
    let error = feed(&mut receiver, 2, 0, true, &[0x62, 1, 0x53, 2], 14)?
        .err().ok_or("expired chain resurrected")?;
    assert_eq!(error.reason, H265Error::MissingStart);
    Ok(())
}

#[test]
fn wrong_epoch_ssrc_payload_sequence_and_reversed_clock_do_not_mutate_state() -> TestResult {
    let mut receiver = receiver(H265Limits::default())?;
    feed(&mut receiver, 1, 0, false, &[0x62, 1, 0x93, 1], 10)??;
    let end = packet(2, 0, true, &[0x62, 1, 0x53, 2]);
    let parsed = RtpPacket::parse(&end, PacketLimits::default())?;
    for key in [StreamKey { generation: 2, ..KEY }, StreamKey { ssrc: 9, ..KEY }] {
        let error = receiver.push(key, 2, parsed, 20).err().ok_or("wrong key accepted")?;
        assert_eq!(error.reason, H265Error::StreamMismatch);
        assert!(error.discarded.is_none());
    }
    let error = receiver.push(KEY, 3, parsed, 20).err().ok_or("sequence alias accepted")?;
    assert_eq!(error.reason, H265Error::StreamMismatch);
    let mut wrong_payload_type = end.clone();
    wrong_payload_type[1] = 97 | 128;
    let parsed_wrong = RtpPacket::parse(&wrong_payload_type, PacketLimits::default())?;
    assert_eq!(receiver.push(KEY, 2, parsed_wrong, 20).err().ok_or("wrong PT accepted")?.reason,
        H265Error::StreamMismatch);
    assert_eq!(receiver.push(KEY, 2, parsed, 9).err().ok_or("clock reversal accepted")?.reason,
        H265Error::ClockReversed);
    assert_eq!(receiver.pending_bytes(), 3);
    // Refusals at time 20 did not advance the valid owner's clock or sequence.
    assert_eq!(receiver.push(KEY, 2, parsed, 11)?.nals[0].bytes(), [0x26, 1, 1, 2]);
    Ok(())
}

#[test]
fn nal_aggregate_and_fragment_count_budgets_fail_closed() -> TestResult {
    let mut small = receiver(H265Limits { max_nal_bytes: 4, ..H265Limits::default() })?;
    let aggregate = aggregate(&[vec![0x40, 1, 1], vec![0x42, 1, 2]], 0, 1);
    assert_eq!(feed(&mut small, 1, 0, true, &aggregate, 0)?.err().ok_or("AP budget bypass")?.reason,
        H265Error::Limit);
    assert_eq!(feed(&mut small, 2, 0, true, &[0x26, 1, 1, 2, 3], 1)?.err()
        .ok_or("single budget bypass")?.reason, H265Error::Limit);
    feed(&mut small, 3, 0, false, &[0x62, 1, 0x93, 1, 2], 2)??;
    let error = feed(&mut small, 4, 0, true, &[0x62, 1, 0x53, 3], 3)?.err()
        .ok_or("FU byte budget bypass")?;
    assert_eq!(error.reason, H265Error::Limit);
    assert_eq!(error.discarded.ok_or("budget retirement missing")?.byte_len, 4);
    let mut count = receiver(H265Limits { max_fragment_packets: 2, ..H265Limits::default() })?;
    feed(&mut count, 1, 0, false, &[0x62, 1, 0x93, 1], 0)??;
    feed(&mut count, 2, 0, false, &[0x62, 1, 0x13, 2], 1)??;
    assert_eq!(feed(&mut count, 3, 0, true, &[0x62, 1, 0x53, 3], 2)?.err()
        .ok_or("FU count bypass")?.reason, H265Error::Limit);
    let mut ap_count = receiver(H265Limits { max_packet_nals: 1, ..H265Limits::default() })?;
    assert_eq!(feed(&mut ap_count, 1, 0, true, &aggregate, 0)?.err()
        .ok_or("AP count bypass")?.reason, H265Error::Limit);
    Ok(())
}

#[test]
fn unrepresentable_deadline_is_not_retained_forever() -> TestResult {
    let mut receiver = receiver(H265Limits::default())?;
    let error = feed(&mut receiver, 1, 0, false, &[0x62, 1, 0x93, 1], u64::MAX)?
        .err().ok_or("overflowing deadline accepted")?;
    assert_eq!(error.reason, H265Error::Limit);
    assert_eq!(receiver.pending_bytes(), 0);
    assert_eq!(receiver.next_deadline_ns(), None);
    Ok(())
}

#[test]
fn cancellation_and_eof_never_flush_incomplete_nals() -> TestResult {
    for cancelled in [false, true] {
        let mut receiver = receiver(H265Limits::default())?;
        feed(&mut receiver, 1, 0, false, &[0x62, 1, 0x93, 1], 0)??;
        let discarded = if cancelled { receiver.cancel() } else { receiver.finish() }
            .ok_or("terminal receipt missing")?;
        assert_eq!(discarded.reason, if cancelled { H265Error::Cancelled } else { H265Error::EndOfInput });
        assert!(receiver.cancel().is_none());
        assert!(receiver.finish().is_none());
        assert_eq!(receiver.pending_bytes(), 0);
        assert_eq!(feed(&mut receiver, 2, 0, true, &[0x26, 1, 2], 1)?.err()
            .ok_or("closed receiver admitted media")?.reason, H265Error::Closed);
    }
    Ok(())
}

#[test]
fn source_ranges_exclude_csrc_extension_and_rtp_padding() -> TestResult {
    let mut receiver = receiver(H265Limits::default())?;
    let mut wire = packet(1, 0, true, &[]);
    wire[0] = 0xb1; // Padding, extension, one CSRC.
    wire.extend_from_slice(&[0, 0, 0, 9]);
    wire.extend_from_slice(&[0xbe, 0xde, 0, 1, 0x10, 0x11, 0, 0]);
    wire.extend_from_slice(&[0x26, 1, 99]);
    wire.extend_from_slice(&[0, 0, 0, 4]);
    let output = receiver.push(KEY, 1, RtpPacket::parse(&wire, PacketLimits::default())?, 0)?;
    assert_eq!(output.nals[0].bytes(), [0x26, 1, 99]);
    assert_eq!(output.nals[0].sources()[0].wire_range, 24..27);
    Ok(())
}

#[test]
fn explicit_negotiation_and_configuration_cannot_be_silently_widened() -> TestResult {
    for don in [1, 32_767] {
        assert_eq!(H265Depacketizer::new(KEY, 96, don, H265Limits::default()).err()
            .ok_or("DON negotiation ignored")?.reason, H265Error::Unsupported);
    }
    assert_eq!(H265Depacketizer::new(KEY, 96, 32_768, H265Limits::default()).err()
        .ok_or("invalid SDP integer accepted")?.reason, H265Error::Configuration);
    for limits in [
        H265Limits { max_nal_bytes: 1, ..H265Limits::default() },
        H265Limits { max_nal_bytes: 16 * 1_024 * 1_024 + 1, ..H265Limits::default() },
        H265Limits { max_packet_nals: 0, ..H265Limits::default() },
        H265Limits { max_packet_nals: 257, ..H265Limits::default() },
        H265Limits { max_fragment_packets: 1, ..H265Limits::default() },
        H265Limits { max_fragment_packets: 4_097, ..H265Limits::default() },
        H265Limits { max_pending_age_ns: 0, ..H265Limits::default() },
        H265Limits { max_pending_age_ns: 60_000_000_001, ..H265Limits::default() },
    ] {
        assert_eq!(receiver(limits).err().ok_or("bad limits accepted")?.reason, H265Error::Configuration);
    }
    assert!(H265Depacketizer::new(StreamKey { generation: 0, ..KEY }, 96, 0, H265Limits::default()).is_err());
    assert!(H265Depacketizer::new(KEY, 128, 0, H265Limits::default()).is_err());
    Ok(())
}

#[test]
fn replay_is_deterministic_and_debug_does_not_disclose_media() -> TestResult {
    let mut left = receiver(H265Limits::default())?;
    let mut right = receiver(H265Limits::default())?;
    let payload = [0x26, 1, 83, 69, 67, 82, 69, 84];
    let a = feed(&mut left, 1, 0, true, &payload, 0)??;
    let b = feed(&mut right, 1, 0, true, &payload, 0)??;
    assert_eq!(a, b);
    let debug = format!("{a:?}");
    assert!(!debug.contains("SECRET"));
    assert!(!debug.contains(&format!("{payload:?}")));
    assert!(debug.contains("source_spans"));
    Ok(())
}
