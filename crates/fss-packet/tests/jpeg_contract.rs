#![forbid(unsafe_code)]
//! RFC 2435 transport, reconstruction provenance, cache and bounded retirement contracts.

use fss_packet::jpeg::{
    JpegDepacketizer, JpegError, JpegFrame, JpegLimits, JpegOutput, JpegReceiveError,
    JpegReceivePoll, JpegReceiver, JpegStatus,
};
use fss_packet::{PacketLimits, ReorderLimits, RtpPacket, StreamKey};
use std::collections::BTreeMap;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey {
    ingress: 7,
    generation: 3,
    ssrc: 17,
};

fn wire(sequence: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80, 26 | if marker { 0x80 } else { 0 }];
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&KEY.ssrc.to_be_bytes());
    out.extend_from_slice(payload);
    out
}
fn payload(kind: u8, q: u8, offset: usize, tables: Option<&[u8]>, scan: &[u8]) -> Vec<u8> {
    let mut out = vec![
        0,
        (offset >> 16) as u8,
        (offset >> 8) as u8,
        offset as u8,
        kind,
        q,
        2,
        2,
    ];
    if kind >= 64 {
        out.extend_from_slice(&[0, 1, 0xff, 0xff]);
    }
    if q >= 128 && offset == 0 {
        let tables = tables.unwrap_or(&[]);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&(tables.len() as u16).to_be_bytes());
        out.extend_from_slice(tables);
    }
    out.extend_from_slice(scan);
    out
}
fn owner(limits: JpegLimits) -> Test<JpegDepacketizer> {
    Ok(JpegDepacketizer::new(KEY, 26, limits)?)
}
fn push(owner: &mut JpegDepacketizer, sequence: u64, wire: &[u8], now: u64) -> Test<JpegOutput> {
    Ok(owner.push(
        KEY,
        sequence,
        RtpPacket::parse(wire, PacketLimits::default())?,
        now,
    )?)
}
fn image(output: JpegOutput) -> Test<JpegFrame> {
    assert_eq!(output.status, JpegStatus::Complete);
    Ok(*output.frame.ok_or("missing complete JPEG")?)
}
fn mapping(frame: &JpegFrame, packets: &BTreeMap<u64, Vec<u8>>) -> Test {
    let mut covered = vec![false; frame.bytes().len()];
    for source in frame.source_spans() {
        let packet = packets
            .get(&source.sequence)
            .ok_or("missing source dependency")?;
        assert_eq!(
            packet.get(source.wire_range.clone()),
            frame.bytes().get(source.jpeg_range.clone())
        );
        assert_eq!(source.wire_range.len(), source.jpeg_range.len());
        for byte in covered
            .get_mut(source.jpeg_range.clone())
            .ok_or("bad copy span")?
        {
            assert!(!*byte);
            *byte = true;
        }
    }
    for range in frame.generated_ranges() {
        for byte in covered.get_mut(range.clone()).ok_or("bad generated span")? {
            assert!(!*byte);
            *byte = true;
        }
    }
    assert!(covered.iter().all(|b| *b));
    for header in frame.header_sources() {
        let packet = packets
            .get(&header.sequence)
            .ok_or("missing header dependency")?;
        assert!(packet.get(header.wire_range.clone()).is_some());
    }
    Ok(())
}

#[test]
fn reconstructs_all_four_types_with_exact_generated_and_copied_byte_partition() -> Test {
    for kind in [0, 1, 64, 65] {
        let mut owner = owner(JpegLimits::default())?;
        let scan: &[u8] = if kind >= 64 {
            &[1, 0xff, 0xd0, 2, 0xff, 0xd9]
        } else {
            &[1, 0xff, 0, 2]
        };
        let packet = wire(11, 9000, true, &payload(kind, 50, 0, None, scan));
        let frame = image(push(&mut owner, 11, &packet, 1)?)?;
        assert_eq!(frame.dimensions(), [16, 16]);
        assert_eq!(frame.jpeg_type(), kind);
        assert_eq!(frame.quality(), 50);
        assert_eq!(frame.key(), KEY);
        assert_eq!(frame.timestamp(), 9000);
        assert_eq!(frame.sequence_interval(), [11, 11]);
        assert_eq!(frame.fragments(), 1);
        assert_eq!(frame.restart_interval(), (kind >= 64).then_some(1));
        assert!(frame.bytes().starts_with(&[0xff, 0xd8]));
        assert!(frame.bytes().ends_with(&[0xff, 0xd9]));
        mapping(&frame, &BTreeMap::from([(11, packet)]))?;
        assert_eq!(owner.pending_bytes(), 0);
        assert_eq!(owner.next_deadline_ns(), None);
    }
    Ok(())
}

#[test]
fn split_every_entropy_boundary_matches_one_packet_and_never_publishes_a_prefix() -> Test {
    let scan = [7, 0xff, 0, 8, 9, 0xff, 0xd9];
    let packet = wire(40, 91, true, &payload(1, 99, 0, None, &scan));
    let expected = image(push(&mut owner(JpegLimits::default())?, 40, &packet, 0)?)?;
    for split in 1..scan.len() {
        let mut owner = owner(JpegLimits::default())?;
        let a = wire(40, 91, false, &payload(1, 99, 0, None, &scan[..split]));
        let b = wire(41, 91, true, &payload(1, 99, split, None, &scan[split..]));
        let pending = push(&mut owner, 40, &a, 0)?;
        assert_eq!(pending.status, JpegStatus::FragmentPending);
        assert!(pending.frame.is_none());
        let complete = image(push(&mut owner, 41, &b, 1)?)?;
        assert_eq!(complete.bytes(), expected.bytes());
        mapping(&complete, &BTreeMap::from([(40, a), (41, b)]))?;
    }
    Ok(())
}

#[test]
fn cached_quantizers_keep_the_original_packet_dependency_and_reject_redefinition() -> Test {
    let mut owner = owner(JpegLimits::default())?;
    let tables = [9; 128];
    let first = wire(1, 1, true, &payload(1, 128, 0, Some(&tables), &[1]));
    let second = wire(2, 2, true, &payload(1, 128, 0, None, &[2]));
    image(push(&mut owner, 1, &first, 0)?)?;
    let cached = image(push(&mut owner, 2, &second, 1)?)?;
    assert_eq!(owner.cached_quantizers(), 1);
    assert_eq!(cached.source_spans()[0].sequence, 1);
    assert_eq!(cached.source_spans()[1].sequence, 1);
    assert_eq!(cached.header_sources()[0].sequence, 1);
    assert_eq!(cached.header_sources()[0].wire_range, 12..152);
    mapping(&cached, &BTreeMap::from([(1, first), (2, second)]))?;
    let changed = wire(3, 3, true, &payload(1, 128, 0, Some(&[8; 128]), &[3]));
    let error = owner
        .push(
            KEY,
            3,
            RtpPacket::parse(&changed, PacketLimits::default())?,
            2,
        )
        .err()
        .ok_or("changed static table accepted")?;
    assert_eq!(error.reason, JpegError::QuantizerConflict);
    assert_eq!(owner.cached_quantizers(), 1);
    Ok(())
}

#[test]
fn dynamic_q255_requires_fresh_tables_and_never_enters_static_cache() -> Test {
    let mut owner = owner(JpegLimits::default())?;
    let mut outputs = Vec::new();
    for (sequence, value) in [(1, 7), (2, 11)] {
        let packet = wire(
            sequence,
            u32::from(sequence),
            true,
            &payload(0, 255, 0, Some(&[value; 128]), &[1]),
        );
        outputs.push(image(push(
            &mut owner,
            u64::from(sequence),
            &packet,
            u64::from(sequence),
        )?)?);
    }
    assert_ne!(outputs[0].bytes(), outputs[1].bytes());
    assert_eq!(owner.cached_quantizers(), 0);
    let packet = wire(3, 3, true, &payload(0, 255, 0, None, &[1]));
    let error = owner
        .push(
            KEY,
            3,
            RtpPacket::parse(&packet, PacketLimits::default())?,
            3,
        )
        .err()
        .ok_or("missing Q255 tables accepted")?;
    assert_eq!(error.reason, JpegError::MissingQuantizers);
    Ok(())
}

#[test]
fn unknown_cached_table_and_cache_capacity_refuse_without_implicit_eviction() -> Test {
    let mut owner = owner(JpegLimits {
        max_cached_quantizers: 1,
        ..JpegLimits::default()
    })?;
    let missing = wire(1, 1, true, &payload(1, 128, 0, None, &[1]));
    assert_eq!(
        owner
            .push(
                KEY,
                1,
                RtpPacket::parse(&missing, PacketLimits::default())?,
                1
            )
            .err()
            .ok_or("unknown table accepted")?
            .reason,
        JpegError::MissingQuantizers
    );
    for (sequence, q) in [(2, 128), (3, 129)] {
        let packet = wire(
            sequence,
            u32::from(sequence),
            true,
            &payload(1, q, 0, Some(&[7; 128]), &[1]),
        );
        let result = owner.push(
            KEY,
            u64::from(sequence),
            RtpPacket::parse(&packet, PacketLimits::default())?,
            u64::from(sequence),
        );
        if q == 128 {
            image(result?)?;
        } else {
            assert_eq!(
                result.err().ok_or("cache bound ignored")?.reason,
                JpegError::Limit
            );
        }
    }
    assert_eq!(owner.cached_quantizers(), 1);
    Ok(())
}

#[test]
fn confirmed_gap_retires_incomplete_frame_and_late_recovery_cannot_resurrect_it() -> Test {
    let mut owner = owner(JpegLimits::default())?;
    let first = wire(10, 1, false, &payload(1, 50, 0, None, &[1]));
    push(&mut owner, 10, &first, 0)?;
    let end = wire(12, 1, true, &payload(1, 50, 2, None, &[3]));
    let error = owner
        .push(KEY, 12, RtpPacket::parse(&end, PacketLimits::default())?, 1)
        .err()
        .ok_or("gapped image accepted")?;
    assert_eq!(error.reason, JpegError::MissingStart);
    assert_eq!(
        error.discarded.ok_or("missing retirement")?.reason,
        JpegError::Gap
    );
    let late = wire(11, 1, false, &payload(1, 50, 1, None, &[2]));
    assert_eq!(
        push(&mut owner, 11, &late, 2)?.status,
        JpegStatus::IgnoredNonIncreasing
    );
    assert_eq!(owner.pending_bytes(), 0);
    let next = wire(13, 2, true, &payload(0, 50, 0, None, &[4]));
    image(push(&mut owner, 13, &next, 3)?)?;
    Ok(())
}

#[test]
fn overlapping_or_missing_scan_offsets_and_header_drift_refuse_the_whole_frame() -> Test {
    for mutation in 0..6 {
        let mut owner = owner(JpegLimits::default())?;
        let first = wire(1, 100, false, &payload(1, 50, 0, None, &[1, 2]));
        push(&mut owner, 1, &first, 0)?;
        let mut tail = payload(1, 50, 2, None, &[3]);
        match mutation {
            0 => tail[3] = 1,
            1 => tail[3] = 3,
            2 => tail[4] = 0,
            3 => tail[5] = 51,
            4 => tail[6] = 3,
            _ => {}
        }
        let packet = wire(2, if mutation == 5 { 101 } else { 100 }, true, &tail);
        let error = owner
            .push(
                KEY,
                2,
                RtpPacket::parse(&packet, PacketLimits::default())?,
                1,
            )
            .err()
            .ok_or("inconsistent image accepted")?;
        assert!(matches!(
            error.reason,
            JpegError::Malformed | JpegError::FragmentMismatch
        ));
        assert!(error.discarded.is_some());
        assert_eq!(owner.pending_bytes(), 0);
    }
    Ok(())
}

#[test]
fn dimensions_and_quality_can_change_only_at_a_new_complete_frame() -> Test {
    let mut owner = owner(JpegLimits::default())?;
    for sequence in 1..=3 {
        let mut body = payload((sequence & 1) as u8, (sequence * 30) as u8, 0, None, &[1]);
        body[6] = sequence as u8;
        let packet = wire(sequence as u16, sequence, true, &body);
        let frame = image(push(
            &mut owner,
            u64::from(sequence),
            &packet,
            u64::from(sequence),
        )?)?;
        assert_eq!(frame.dimensions(), [(sequence * 8) as u16, 16]);
    }
    Ok(())
}

#[test]
fn missing_marker_never_flushes_an_image_and_new_start_returns_retirement() -> Test {
    let mut owner = owner(JpegLimits::default())?;
    let first = wire(1, 1, false, &payload(1, 50, 0, None, &[1, 0xff, 0xd9]));
    push(&mut owner, 1, &first, 0)?;
    let next = wire(2, 2, true, &payload(1, 50, 0, None, &[1]));
    let output = push(&mut owner, 2, &next, 1)?;
    assert_eq!(
        output
            .discarded
            .as_ref()
            .ok_or("missing interrupted image")?
            .reason,
        JpegError::Interrupted
    );
    image(output)?;
    let tail = wire(3, 3, false, &payload(1, 50, 0, None, &[1]));
    push(&mut owner, 3, &tail, 2)?;
    assert_eq!(
        owner.finish().ok_or("missing EOF retirement")?.reason,
        JpegError::EndOfInput
    );
    assert!(owner.finish().is_none());
    assert_eq!(owner.pending_bytes(), 0);
    Ok(())
}

#[test]
fn absolute_frame_deadline_is_not_renewed_by_duplicate_traffic() -> Test {
    let mut owner = owner(JpegLimits {
        max_pending_age_ns: 10,
        ..JpegLimits::default()
    })?;
    let first = wire(1, 1, false, &payload(1, 50, 0, None, &[1]));
    push(&mut owner, 1, &first, 5)?;
    assert_eq!(owner.next_deadline_ns(), Some(15));
    assert_eq!(
        push(&mut owner, 1, &first, 14)?.status,
        JpegStatus::IgnoredNonIncreasing
    );
    assert_eq!(owner.next_deadline_ns(), Some(15));
    let retired = owner.expire(15)?.ok_or("expired frame retained")?;
    assert_eq!(retired.reason, JpegError::Deadline);
    assert_eq!(retired.fragments, 1);
    assert!(owner.expire(15)?.is_none());
    assert_eq!(
        owner
            .expire(14)
            .err()
            .ok_or("time reversal accepted")?
            .reason,
        JpegError::ClockReversed
    );
    Ok(())
}

#[test]
fn cancellation_releases_frame_and_parameter_cache_without_output() -> Test {
    let mut owner = owner(JpegLimits::default())?;
    let packet = wire(1, 1, false, &payload(1, 128, 0, Some(&[8; 128]), &[1]));
    push(&mut owner, 1, &packet, 0)?;
    assert_eq!(owner.cached_quantizers(), 1);
    assert_eq!(
        owner.cancel().ok_or("missing cancellation")?.reason,
        JpegError::Cancelled
    );
    assert_eq!(owner.cached_quantizers(), 0);
    assert_eq!(owner.pending_bytes(), 0);
    assert!(owner.cancel().is_none());
    assert_eq!(
        owner
            .push(
                KEY,
                1,
                RtpPacket::parse(&packet, PacketLimits::default())?,
                1
            )
            .err()
            .ok_or("cancelled receiver resumed")?
            .reason,
        JpegError::Closed
    );
    Ok(())
}

#[test]
fn exact_whole_image_byte_and_fragment_limits_include_generated_headers() -> Test {
    let packet = wire(1, 1, true, &payload(1, 50, 0, None, &[1, 2, 3]));
    let size = image(push(&mut owner(JpegLimits::default())?, 1, &packet, 0)?)?
        .bytes()
        .len();
    for maximum in [size - 1, size] {
        let mut owner = owner(JpegLimits {
            max_frame_bytes: maximum,
            ..JpegLimits::default()
        })?;
        let output = owner.push(
            KEY,
            1,
            RtpPacket::parse(&packet, PacketLimits::default())?,
            0,
        );
        assert_eq!(output.is_ok(), maximum == size);
        assert_eq!(owner.pending_bytes(), 0);
    }
    let mut owner = owner(JpegLimits {
        max_fragment_packets: 1,
        ..JpegLimits::default()
    })?;
    let first = wire(1, 1, false, &payload(1, 50, 0, None, &[1]));
    let second = wire(2, 1, true, &payload(1, 50, 1, None, &[2]));
    push(&mut owner, 1, &first, 0)?;
    assert_eq!(
        owner
            .push(
                KEY,
                2,
                RtpPacket::parse(&second, PacketLimits::default())?,
                1
            )
            .err()
            .ok_or("fragment limit ignored")?
            .reason,
        JpegError::Limit
    );
    assert_eq!(owner.pending_bytes(), 0);
    Ok(())
}

#[test]
fn unused_quantizer_precision_bits_do_not_change_tables_or_source_maps() -> Test {
    for high_bits in [0x04, 0x80, 0xfc] {
        let mut receiver = owner(JpegLimits::default())?;
        let mut body = payload(1, 128, 0, Some(&[9; 128]), &[1]);
        body[9] = high_bits;
        let original = wire(1, 1, true, &body);
        let frame = image(push(&mut receiver, 1, &original, 0)?)?;
        assert_eq!(frame.header_sources()[0].wire_range, 12..152);
        mapping(&frame, &BTreeMap::from([(1, original)]))?;
        assert_eq!(receiver.cached_quantizers(), 1);
    }
    Ok(())
}

#[test]
fn unsupported_types_interlace_reserved_quality_and_table_shapes_are_explicit() -> Test {
    let mut cases = Vec::new();
    for kind in [2, 63, 66, 127, 128, 255] {
        cases.push(payload(kind, 50, 0, None, &[1]));
    }
    for q in [0, 100, 127] {
        cases.push(payload(1, q, 0, None, &[1]));
    }
    let mut fields = payload(1, 50, 0, None, &[1]);
    fields[0] = 1;
    cases.push(fields);
    let mut precision = payload(1, 128, 0, Some(&[1; 128]), &[1]);
    precision[9] = 1;
    cases.push(precision);
    cases.push(payload(1, 128, 0, Some(&[1; 64]), &[1]));
    for body in cases {
        let mut owner = owner(JpegLimits::default())?;
        let packet = wire(1, 1, true, &body);
        assert_eq!(
            owner
                .push(
                    KEY,
                    1,
                    RtpPacket::parse(&packet, PacketLimits::default())?,
                    0
                )
                .err()
                .ok_or("unsupported payload accepted")?
                .reason,
            JpegError::Unsupported
        );
        assert_eq!(owner.pending_bytes(), 0);
    }
    Ok(())
}

#[test]
fn invalid_scan_markers_zero_quantizers_and_truncated_headers_never_publish() -> Test {
    let mut cases = Vec::new();
    for scan in [
        &[0xff][..],
        &[0xff, 0xd8],
        &[0xff, 0xd0],
        &[0xff, 0xd9, 1],
        &[0xff, 0xff, 0],
        &[],
    ] {
        cases.push(payload(1, 50, 0, None, scan));
    }
    cases.push(payload(1, 128, 0, Some(&[0; 128]), &[1]));
    let complete = payload(65, 128, 0, Some(&[1; 128]), &[1]);
    for cut in 0..complete.len() {
        cases.push(complete[..cut].to_vec());
    }
    for body in cases {
        let mut owner = owner(JpegLimits::default())?;
        let packet = wire(1, 1, true, &body);
        assert!(
            owner
                .push(
                    KEY,
                    1,
                    RtpPacket::parse(&packet, PacketLimits::default())?,
                    0
                )
                .is_err()
        );
        assert_eq!(owner.pending_bytes(), 0);
    }
    Ok(())
}

#[test]
fn stream_and_extended_sequence_mismatches_do_not_mutate_the_existing_owner() -> Test {
    let mut owner = owner(JpegLimits::default())?;
    let packet = wire(1, 1, false, &payload(1, 50, 0, None, &[1]));
    push(&mut owner, 1, &packet, 0)?;
    let retained = owner.pending_bytes();
    let next = wire(2, 1, true, &payload(1, 50, 1, None, &[2]));
    for key in [
        StreamKey {
            generation: 4,
            ..KEY
        },
        StreamKey { ssrc: 18, ..KEY },
    ] {
        assert_eq!(
            owner
                .push(key, 2, RtpPacket::parse(&next, PacketLimits::default())?, 1)
                .err()
                .ok_or("wrong owner accepted")?
                .reason,
            JpegError::StreamMismatch
        );
        assert_eq!(owner.pending_bytes(), retained);
    }
    assert_eq!(
        owner
            .push(KEY, 3, RtpPacket::parse(&next, PacketLimits::default())?, 1)
            .err()
            .ok_or("wrong sequence accepted")?
            .reason,
        JpegError::StreamMismatch
    );
    image(push(&mut owner, 2, &next, 1)?)?;
    Ok(())
}

#[test]
fn packet_header_extensions_and_padding_are_excluded_from_copied_image_spans() -> Test {
    let body = payload(1, 255, 0, Some(&[3; 128]), &[1, 2]);
    let mut packet = wire(1, 1, true, &[]);
    packet[0] = 0xb1;
    packet.extend_from_slice(&[0, 0, 0, 9]); // one CSRC
    packet.extend_from_slice(&[0xbe, 0xde, 0, 1, 4, 5, 6, 7]);
    packet.extend_from_slice(&body);
    packet.extend_from_slice(&[0, 0, 0, 4]);
    let frame = image(push(&mut owner(JpegLimits::default())?, 1, &packet, 0)?)?;
    assert!(
        frame
            .source_spans()
            .iter()
            .all(|s| s.wire_range.start >= 24 && s.wire_range.end <= packet.len() - 4)
    );
    mapping(&frame, &BTreeMap::from([(1, packet)]))?;
    Ok(())
}

#[test]
fn reordered_packets_preserve_original_receive_times_and_correct_frame_spans() -> Test {
    let mut receiver = JpegReceiver::new(
        KEY,
        26,
        ReorderLimits {
            max_delay_ns: 10,
            ..ReorderLimits::default()
        },
        JpegLimits::default(),
    )?;
    let probation = wire(9, 0, true, &payload(1, 50, 0, None, &[0]));
    let a = wire(10, 1, false, &payload(1, 50, 0, None, &[1]));
    let b = wire(11, 1, false, &payload(1, 50, 1, None, &[2]));
    let c = wire(12, 1, true, &payload(1, 50, 2, None, &[3]));
    receiver.ingest(KEY, &probation, 0)?;
    receiver.ingest(KEY, &a, 1)?;
    receiver.ingest(KEY, &c, 2)?;
    receiver.ingest(KEY, &b, 3)?;
    let mut complete = None;
    for (sequence, received) in [(10, 1), (11, 3), (12, 2)] {
        let JpegReceivePoll::Packet {
            source,
            reconstruction,
        } = receiver.poll(3)?
        else {
            return Err("expected ordered original packet".into());
        };
        assert_eq!(source.sequence(), sequence);
        assert_eq!(source.received_ns(), received);
        let output = reconstruction?;
        if sequence < 12 {
            assert!(output.frame.is_none());
        } else {
            complete = output.frame;
        }
    }
    mapping(
        &*complete.ok_or("missing reordered frame")?,
        &BTreeMap::from([(10, a), (11, b), (12, c)]),
    )?;
    assert_eq!(receiver.pending_frame_bytes(), 0);
    assert_eq!(receiver.queued_bytes(), 0);
    receiver.finish();
    assert!(matches!(
        receiver.poll(4)?,
        JpegReceivePoll::Ended { discarded: None }
    ));
    Ok(())
}

#[test]
fn receiver_loss_retires_partial_image_before_returning_the_original_refused_tail() -> Test {
    let mut receiver = JpegReceiver::new(
        KEY,
        26,
        ReorderLimits {
            max_delay_ns: 10,
            ..ReorderLimits::default()
        },
        JpegLimits::default(),
    )?;
    receiver.ingest(KEY, &wire(9, 0, true, &payload(1, 50, 0, None, &[0])), 0)?;
    receiver.ingest(KEY, &wire(10, 1, false, &payload(1, 50, 0, None, &[1])), 1)?;
    let JpegReceivePoll::Packet { reconstruction, .. } = receiver.poll(1)? else {
        return Err("missing first packet".into());
    };
    reconstruction?;
    let tail = wire(12, 1, true, &payload(1, 50, 2, None, &[3]));
    receiver.ingest(KEY, &tail, 2)?;
    let JpegReceivePoll::Gap { discarded, .. } = receiver.poll(12)? else {
        return Err("missing delivery gap".into());
    };
    assert_eq!(
        discarded.ok_or("missing partial retirement")?.reason,
        JpegError::Gap
    );
    let JpegReceivePoll::Packet {
        source,
        reconstruction,
    } = receiver.poll(12)?
    else {
        return Err("lost original tail".into());
    };
    assert_eq!(source.bytes(), tail);
    assert!(
        matches!(reconstruction, Err(JpegReceiveError::Codec(error)) if error.reason == JpegError::MissingStart)
    );
    assert_eq!(receiver.pending_frame_bytes(), 0);
    Ok(())
}

#[test]
fn bounded_header_mutations_never_escape_source_and_output_ranges() -> Test {
    let seed = payload(1, 255, 0, Some(&[8; 128]), &[3, 0xff, 0, 4]);
    for at in 0..seed.len() {
        for value in [0, 1, 127, 128, 255] {
            let mut payload = seed.clone();
            payload[at] = value;
            let packet = wire(1, 1, true, &payload);
            let mut owner = owner(JpegLimits {
                max_frame_bytes: 2048,
                max_fragment_packets: 2,
                ..JpegLimits::default()
            })?;
            if let Ok(output) = owner.push(
                KEY,
                1,
                RtpPacket::parse(&packet, PacketLimits::default())?,
                0,
            ) {
                let frame = image(output)?;
                assert!(frame.bytes().len() <= 2048);
                mapping(&frame, &BTreeMap::from([(1, packet)]))?;
            }
            assert_eq!(owner.pending_bytes(), 0);
        }
    }
    Ok(())
}
