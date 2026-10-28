#![forbid(unsafe_code)]
//! Exact-source ONVIF RTP metadata reconstruction and bounded failure contracts.

use std::collections::BTreeMap;

use fss_packet::{
    ContinuityError, OnvifMetadataDiscardReason, OnvifMetadataDocument, OnvifMetadataError,
    OnvifMetadataFailure, OnvifMetadataLimits, OnvifMetadataOutput, OnvifMetadataReceiveError,
    OnvifMetadataReceivePoll, OnvifMetadataReceiver, OnvifMetadataStatus, OrderedRtpPacket,
    ReorderDisposition, ReorderError, ReorderGapReason, ReorderLimits, StreamKey,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey {
    ingress: 41,
    generation: 3,
    ssrc: 0x12345678,
};

fn reorder_limits() -> ReorderLimits {
    ReorderLimits {
        max_packets: 8,
        max_bytes: 8192,
        max_delay_ns: 10,
        ..ReorderLimits::default()
    }
}
fn metadata_limits() -> OnvifMetadataLimits {
    OnvifMetadataLimits {
        max_document_bytes: 1024,
        max_fragment_packets: 16,
        max_pending_age_ns: 100,
    }
}
fn wire(sequence: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 96 | if marker { 0x80 } else { 0 }];
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&KEY.ssrc.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
fn packet(
    receiver: &mut OnvifMetadataReceiver,
    now: u64,
) -> Test<(
    OrderedRtpPacket,
    Result<OnvifMetadataOutput, OnvifMetadataFailure>,
)> {
    match receiver.poll(now)? {
        OnvifMetadataReceivePoll::Packet {
            source,
            reconstruction,
        } => Ok((source, reconstruction)),
        _ => Err("expected exactly one original packet".into()),
    }
}
fn complete(output: OnvifMetadataOutput) -> Test<OnvifMetadataDocument> {
    assert_eq!(output.status, OnvifMetadataStatus::Complete);
    output
        .document
        .ok_or_else(|| "completed transport document missing".into())
}
fn open(limits: OnvifMetadataLimits) -> Test<OnvifMetadataReceiver> {
    let mut receiver = OnvifMetadataReceiver::new(KEY, 96, reorder_limits(), limits)?;
    assert_eq!(
        receiver
            .ingest(KEY, &wire(9, 900, false, b"unknown"), 0)?
            .transport
            .disposition,
        ReorderDisposition::NotAdmitted
    );
    receiver.ingest(KEY, &wire(10, 901, true, b"partial-initial-tail"), 0)?;
    let output = packet(&mut receiver, 0)?.1?;
    assert_eq!(output.status, OnvifMetadataStatus::BoundaryObserved);
    assert!(output.document.is_none());
    Ok(receiver)
}

#[test]
fn changing_timestamps_reordered_fragments_preserve_exact_wire_and_receive_provenance() -> Test {
    let mut receiver = open(metadata_limits())?;
    let document = "<MetadataStream><Object>café</Object></MetadataStream>".as_bytes();
    let fragments = [&document[..27], &document[27..28], &document[28..]];
    let first = wire(11, 1, false, fragments[0]);
    let middle = wire(12, u32::MAX, false, fragments[1]);
    let last = wire(13, 0, true, fragments[2]);
    receiver.ingest(KEY, &first, 1)?;
    receiver.ingest(KEY, &last, 2)?;
    receiver.ingest_received(KEY, &middle, 0, 3)?;
    assert_eq!(
        receiver.ingest(KEY, &middle, 3)?.transport.disposition,
        ReorderDisposition::Duplicate
    );
    let (source, output) = packet(&mut receiver, 3)?;
    assert_eq!(source.bytes(), first);
    assert_eq!(output?.status, OnvifMetadataStatus::FragmentPending);
    let (source, output) = packet(&mut receiver, 3)?;
    assert_eq!(source.bytes(), middle);
    assert_eq!(output?.status, OnvifMetadataStatus::FragmentPending);
    let (source, output) = packet(&mut receiver, 3)?;
    assert_eq!(source.bytes(), last);
    let built = complete(output?)?;
    assert_eq!(built.bytes(), document);
    assert_eq!(built.key(), KEY);
    assert_eq!(built.boundary().sequence, 10);
    assert_eq!(built.boundary().timestamp, 901);
    assert_eq!(built.boundary().received_ns, 0);
    assert_eq!((built.first_sequence(), built.last_sequence()), (11, 13));
    assert_eq!((built.started_ns(), built.completed_ns()), (3, 3));
    let originals = BTreeMap::from([(11, first), (12, middle), (13, last)]);
    for (index, span) in built.sources().iter().enumerate() {
        let original = originals
            .get(&span.sequence)
            .ok_or("source packet missing")?;
        assert_eq!(
            &original[span.wire_range.clone()],
            &built.bytes()[span.document_range.clone()]
        );
        assert_eq!(span.timestamp, [1, u32::MAX, 0][index]);
        assert_eq!(span.received_ns, [1, 0, 2][index]);
    }
    assert_eq!(receiver.pending_document_bytes(), 0);
    assert_eq!(receiver.queued_bytes(), 0);
    assert_eq!(receiver.next_wake_ns(), None);
    let private = format!("{receiver:?} {built:?}");
    assert!(!private.contains("café"));
    assert!(!private.contains("MetadataStream>"));
    Ok(())
}

#[test]
fn startup_requires_delivered_boundary_and_never_claims_a_partial_first_document() -> Test {
    let mut receiver = OnvifMetadataReceiver::new(KEY, 96, reorder_limits(), metadata_limits())?;
    receiver.ingest(KEY, &wire(1, 1, true, b"<complete-but-unadmitted/>"), 0)?;
    receiver.ingest(KEY, &wire(2, 2, false, b"tail"), 1)?;
    assert_eq!(
        packet(&mut receiver, 1)?.1?.status,
        OnvifMetadataStatus::SeekingBoundary
    );
    receiver.ingest(KEY, &wire(3, 3, true, b"</unknown>"), 2)?;
    assert_eq!(
        packet(&mut receiver, 2)?.1?.status,
        OnvifMetadataStatus::BoundaryObserved
    );
    receiver.ingest(KEY, &wire(4, 4, true, b"<intact/>"), 3)?;
    assert_eq!(
        complete(packet(&mut receiver, 3)?.1?)?.bytes(),
        b"<intact/>"
    );
    Ok(())
}

#[test]
fn finalized_gap_discards_document_and_next_marker_resynchronizes_without_concatenation() -> Test {
    let mut receiver = open(metadata_limits())?;
    receiver.ingest(KEY, &wire(11, 0, false, b"<damaged>"), 1)?;
    packet(&mut receiver, 1)?.1?;
    receiver.ingest(KEY, &wire(13, 1, true, b"</damaged>"), 2)?;
    let OnvifMetadataReceivePoll::Gap { gap, discarded } = receiver.poll(12)? else {
        return Err("missing explicit gap".into());
    };
    assert_eq!((gap.first_sequence, gap.last_sequence), (12, 12));
    assert_eq!(gap.reason, ReorderGapReason::Deadline);
    let discarded = discarded.ok_or("partial document retirement missing")?;
    assert_eq!(discarded.reason, OnvifMetadataDiscardReason::Gap);
    assert_eq!(
        (discarded.first_sequence, discarded.last_sequence),
        (11, 11)
    );
    assert_eq!(discarded.byte_len, 9);
    assert_eq!(
        packet(&mut receiver, 12)?.1?.status,
        OnvifMetadataStatus::BoundaryObserved
    );
    assert_eq!(
        receiver
            .ingest(KEY, &wire(12, 2, false, b"late"), 13)?
            .transport
            .disposition,
        ReorderDisposition::TooLate
    );
    receiver.ingest(KEY, &wire(14, 3, true, b"<next/>"), 14)?;
    let next = complete(packet(&mut receiver, 14)?.1?)?;
    assert_eq!(next.bytes(), b"<next/>");
    assert_eq!(next.boundary().sequence, 13);
    Ok(())
}

#[test]
fn original_headers_extensions_and_padding_are_retained_but_not_copied_to_xml() -> Test {
    let mut receiver = open(metadata_limits())?;
    let mut source = wire(11, 987, true, &[]);
    source[0] = 0xb1; // padding, extension, one CSRC
    source.extend_from_slice(&99_u32.to_be_bytes());
    source.extend_from_slice(&[0x12, 0x34, 0, 1, 8, 7, 6, 5]);
    source.extend_from_slice(b"<only-payload/>");
    source.extend_from_slice(&[0, 0, 0, 4]);
    receiver.ingest(KEY, &source, 1)?;
    let (retained, output) = packet(&mut receiver, 1)?;
    assert_eq!(retained.bytes(), source);
    let built = complete(output?)?;
    assert_eq!(built.bytes(), b"<only-payload/>");
    assert_eq!(built.sources()[0].wire_range, 24..39);
    assert_eq!(built.sources()[0].document_range, 0..15);
    Ok(())
}

#[test]
fn sequence_wrap_preserves_one_document_and_source_epoch() -> Test {
    let mut receiver = OnvifMetadataReceiver::new(KEY, 96, reorder_limits(), metadata_limits())?;
    receiver.ingest(KEY, &wire(65533, 1, false, b"ignored"), 0)?;
    receiver.ingest(KEY, &wire(65534, 2, true, b"boundary"), 1)?;
    packet(&mut receiver, 1)?.1?;
    receiver.ingest(KEY, &wire(65535, 3, false, b"<wrap>"), 2)?;
    receiver.ingest(KEY, &wire(0, 4, true, b"</wrap>"), 3)?;
    packet(&mut receiver, 3)?.1?;
    let document = complete(packet(&mut receiver, 3)?.1?)?;
    assert_eq!(
        (document.first_sequence(), document.last_sequence()),
        (65535, 65536)
    );
    assert_eq!(document.bytes(), b"<wrap></wrap>");
    Ok(())
}

#[test]
fn fixed_age_expires_without_traffic_and_duplicates_never_extend_it() -> Test {
    let mut receiver = open(OnvifMetadataLimits {
        max_pending_age_ns: 10,
        ..metadata_limits()
    })?;
    let start = wire(11, 1, false, b"<late>");
    receiver.ingest(KEY, &start, 1)?;
    packet(&mut receiver, 1)?.1?;
    assert_eq!(receiver.next_wake_ns(), Some(11));
    assert_eq!(
        receiver.ingest(KEY, &start, 9)?.transport.disposition,
        ReorderDisposition::Duplicate
    );
    assert_eq!(receiver.next_wake_ns(), Some(11));
    let OnvifMetadataReceivePoll::DocumentDiscarded(retired) = receiver.poll(11)? else {
        return Err("missing fixed deadline retirement".into());
    };
    assert_eq!(retired.reason, OnvifMetadataDiscardReason::Deadline);
    assert_eq!(retired.byte_len, 6);
    assert_eq!(receiver.next_wake_ns(), None);
    receiver.ingest(KEY, &wire(12, 2, true, b"</late>"), 12)?;
    assert_eq!(
        packet(&mut receiver, 12)?.1?.status,
        OnvifMetadataStatus::BoundaryObserved
    );
    receiver.ingest(KEY, &wire(13, 3, true, b"<new/>"), 13)?;
    assert_eq!(complete(packet(&mut receiver, 13)?.1?)?.bytes(), b"<new/>");
    Ok(())
}

#[test]
fn empty_fragments_count_and_size_or_count_refusal_retires_only_the_original_candidate() -> Test {
    for count_limit in [false, true] {
        let limits = if count_limit {
            OnvifMetadataLimits {
                max_fragment_packets: 2,
                ..metadata_limits()
            }
        } else {
            OnvifMetadataLimits {
                max_document_bytes: 4,
                ..metadata_limits()
            }
        };
        let mut receiver = open(limits)?;
        receiver.ingest(KEY, &wire(11, 1, false, b"<a"), 1)?;
        packet(&mut receiver, 1)?.1?;
        receiver.ingest(KEY, &wire(12, 2, false, b""), 2)?;
        packet(&mut receiver, 2)?.1?;
        receiver.ingest(KEY, &wire(13, 3, true, b"x/>"), 3)?;
        let failure = packet(&mut receiver, 3)?
            .1
            .err()
            .ok_or("limit was accepted")?;
        assert_eq!(
            failure.reason,
            if count_limit {
                OnvifMetadataError::FragmentLimit
            } else {
                OnvifMetadataError::ByteLimit
            }
        );
        let retired = failure.discarded.ok_or("candidate retirement missing")?;
        assert_eq!(retired.byte_len, 2);
        assert_eq!(retired.fragments, 2);
        assert_eq!(retired.last_sequence, 12);
        receiver.ingest(KEY, &wire(14, 4, true, b"<b/>"), 4)?;
        assert_eq!(complete(packet(&mut receiver, 4)?.1?)?.bytes(), b"<b/>");
    }
    Ok(())
}

#[test]
fn oversized_first_payload_and_empty_closed_document_never_emit_empty_or_partial_xml() -> Test {
    let mut receiver = open(OnvifMetadataLimits {
        max_document_bytes: 4,
        ..metadata_limits()
    })?;
    receiver.ingest(KEY, &wire(11, 1, true, b"oversized"), 1)?;
    let error = packet(&mut receiver, 1)?
        .1
        .err()
        .ok_or("oversized payload accepted")?;
    assert_eq!(error.reason, OnvifMetadataError::ByteLimit);
    assert!(error.discarded.is_none());
    receiver.ingest(KEY, &wire(12, 2, true, b""), 2)?;
    let error = packet(&mut receiver, 2)?
        .1
        .err()
        .ok_or("empty XML accepted")?;
    assert_eq!(error.reason, OnvifMetadataError::EmptyDocument);
    assert_eq!(
        error
            .discarded
            .ok_or("empty fragment accounting absent")?
            .fragments,
        1
    );
    receiver.ingest(KEY, &wire(13, 3, true, b"<a/>"), 3)?;
    complete(packet(&mut receiver, 3)?.1?)?;
    Ok(())
}

#[test]
fn eof_drains_complete_packets_but_reports_incomplete_tail_only_once() -> Test {
    let mut receiver = open(metadata_limits())?;
    receiver.ingest(KEY, &wire(11, 1, true, b"<complete/>"), 1)?;
    receiver.ingest(KEY, &wire(12, 2, false, b"<unfinished>"), 2)?;
    receiver.finish();
    assert_eq!(
        complete(packet(&mut receiver, 2)?.1?)?.bytes(),
        b"<complete/>"
    );
    assert_eq!(
        packet(&mut receiver, 2)?.1?.status,
        OnvifMetadataStatus::FragmentPending
    );
    let OnvifMetadataReceivePoll::Ended {
        discarded: Some(retired),
    } = receiver.poll(2)?
    else {
        return Err("EOF retirement missing".into());
    };
    assert_eq!(retired.reason, OnvifMetadataDiscardReason::EndOfInput);
    assert_eq!(retired.first_sequence, 12);
    assert_eq!(
        receiver.poll(2)?,
        OnvifMetadataReceivePoll::Ended { discarded: None }
    );
    assert_eq!(receiver.next_wake_ns(), None);
    assert!(matches!(
        receiver.ingest(KEY, &wire(13, 3, true, b"</unfinished>"), 3),
        Err(OnvifMetadataReceiveError::Transport(ReorderError::Closed))
    ));
    Ok(())
}

#[test]
fn cancellation_and_truncated_source_retire_both_layers_without_publishing_bytes() -> Test {
    for reason in [
        OnvifMetadataDiscardReason::Cancelled,
        OnvifMetadataDiscardReason::TruncatedSource,
    ] {
        let mut receiver = open(metadata_limits())?;
        receiver.ingest(KEY, &wire(11, 1, false, b"<pending>"), 1)?;
        packet(&mut receiver, 1)?.1?;
        receiver.ingest(KEY, &wire(12, 2, true, b"</pending>"), 2)?;
        let retired = receiver.invalidate(reason);
        assert_eq!(retired.reason, reason);
        assert_eq!(retired.queue.packets, 1);
        assert_eq!(
            retired.document.ok_or("pending bytes absent")?.reason,
            reason
        );
        assert_eq!(
            receiver.poll(2)?,
            OnvifMetadataReceivePoll::Ended { discarded: None }
        );
        assert_eq!(receiver.pending_document_bytes(), 0);
        assert_eq!(receiver.queued_bytes(), 0);
    }
    Ok(())
}

#[test]
fn malformed_wire_and_conflicting_queued_duplicate_close_the_receiver_explicitly() -> Test {
    for conflict in [false, true] {
        let mut receiver = open(metadata_limits())?;
        receiver.ingest(KEY, &wire(11, 1, false, b"<pending>"), 1)?;
        packet(&mut receiver, 1)?.1?;
        receiver.ingest(KEY, &wire(12, 2, true, b"original"), 2)?;
        let invalid = if conflict {
            wire(12, 2, true, b"different")
        } else {
            vec![0x80, 96, 0]
        };
        let error = receiver
            .ingest(KEY, &invalid, 3)
            .err()
            .ok_or("invalid packet accepted")?;
        let OnvifMetadataReceiveError::Invalidated { retired, .. } = error else {
            return Err("retirement receipt absent".into());
        };
        assert_eq!(retired.queue.packets, 1);
        assert_eq!(
            retired.reason,
            if conflict {
                OnvifMetadataDiscardReason::ConflictingPacket
            } else {
                OnvifMetadataDiscardReason::InvalidPacket
            }
        );
        assert!(retired.document.is_some());
        assert_eq!(
            receiver.poll(3)?,
            OnvifMetadataReceivePoll::Ended { discarded: None }
        );
    }
    Ok(())
}

#[test]
fn scope_time_capacity_and_restart_refusals_preserve_or_retire_state_at_their_exact_boundary()
-> Test {
    let mut receiver = open(metadata_limits())?;
    receiver.ingest(KEY, &wire(11, 1, false, b"<pending>"), 1)?;
    packet(&mut receiver, 1)?.1?;
    let before = receiver.stats();
    let mut foreign_ssrc = wire(12, 2, true, b"foreign");
    foreign_ssrc[8..12].copy_from_slice(&5_u32.to_be_bytes());
    let mut foreign_pt = wire(12, 2, true, b"foreign");
    foreign_pt[1] = 97 | 0x80;
    for bad in [foreign_ssrc, foreign_pt] {
        assert!(matches!(
            receiver.ingest(KEY, &bad, 2),
            Err(OnvifMetadataReceiveError::Transport(
                ReorderError::Continuity(_)
            ))
        ));
        assert_eq!(receiver.stats(), before);
        assert_eq!(receiver.pending_document_bytes(), 9);
    }
    assert!(matches!(
        receiver.poll(0),
        Err(OnvifMetadataReceiveError::Transport(
            ReorderError::Continuity(ContinuityError::ClockReversed)
        ))
    ));
    assert!(
        receiver
            .restart(KEY, 96, reorder_limits(), metadata_limits())
            .is_err()
    );
    receiver.ingest(KEY, &wire(50000, 2, false, b"jump"), 2)?;
    let restart = receiver.ingest(KEY, &wire(50001, 3, true, b"restart"), 3)?;
    assert_eq!(
        restart.transport.disposition,
        ReorderDisposition::RestartRequired
    );
    assert_eq!(
        restart.discarded.ok_or("restart retirement absent")?.reason,
        OnvifMetadataDiscardReason::RestartRequired
    );
    assert_eq!(
        receiver.poll(3)?,
        OnvifMetadataReceivePoll::Ended { discarded: None }
    );
    let mut reopened = receiver.restart(
        StreamKey {
            generation: 4,
            ..KEY
        },
        96,
        reorder_limits(),
        metadata_limits(),
    )?;
    assert_eq!(reopened.pending_document_bytes(), 0);
    assert_eq!(
        reopened.poll(0)?,
        OnvifMetadataReceivePoll::Pending { wake_at_ns: None }
    );
    Ok(())
}

#[test]
fn invalid_dynamic_payload_or_document_bounds_refuse_before_any_packet_state() {
    for payload in [0, 95, 128, 255] {
        assert!(
            OnvifMetadataReceiver::new(KEY, payload, reorder_limits(), metadata_limits()).is_err()
        );
    }
    for limits in [
        OnvifMetadataLimits {
            max_document_bytes: 0,
            ..metadata_limits()
        },
        OnvifMetadataLimits {
            max_document_bytes: 256 * 1024 + 1,
            ..metadata_limits()
        },
        OnvifMetadataLimits {
            max_fragment_packets: 0,
            ..metadata_limits()
        },
        OnvifMetadataLimits {
            max_fragment_packets: 4097,
            ..metadata_limits()
        },
        OnvifMetadataLimits {
            max_pending_age_ns: 0,
            ..metadata_limits()
        },
        OnvifMetadataLimits {
            max_pending_age_ns: 60_000_000_001,
            ..metadata_limits()
        },
    ] {
        assert_eq!(limits.validate(), Err(OnvifMetadataError::Configuration));
        assert!(OnvifMetadataReceiver::new(KEY, 96, reorder_limits(), limits).is_err());
    }
}

#[test]
fn queue_backpressure_does_not_consume_the_refused_fragment_or_extend_document_time() -> Test {
    let mut receiver = OnvifMetadataReceiver::new(
        KEY,
        96,
        ReorderLimits {
            max_packets: 1,
            ..reorder_limits()
        },
        metadata_limits(),
    )?;
    receiver.ingest(KEY, &wire(9, 0, false, b"unknown"), 0)?;
    receiver.ingest(KEY, &wire(10, 1, true, b"boundary"), 0)?;
    packet(&mut receiver, 0)?.1?;
    receiver.ingest(KEY, &wire(11, 2, false, b"<x>"), 1)?;
    packet(&mut receiver, 1)?.1?;
    receiver.ingest(KEY, &wire(12, 3, false, b"a"), 2)?;
    let before = receiver.stats();
    let final_packet = wire(13, 4, true, b"</x>");
    assert!(matches!(
        receiver.ingest(KEY, &final_packet, 3),
        Err(OnvifMetadataReceiveError::Transport(
            ReorderError::PacketCapacity
        ))
    ));
    assert_eq!(receiver.stats(), before);
    assert_eq!(receiver.pending_document_bytes(), 3);
    packet(&mut receiver, 3)?.1?;
    assert_eq!(
        receiver
            .ingest_received(KEY, &final_packet, 3, 4)?
            .transport
            .disposition,
        ReorderDisposition::Buffered
    );
    let document = complete(packet(&mut receiver, 4)?.1?)?;
    assert_eq!(document.bytes(), b"<x>a</x>");
    assert_eq!(document.started_ns(), 1);
    assert_eq!(document.sources()[2].received_ns, 3);
    Ok(())
}
