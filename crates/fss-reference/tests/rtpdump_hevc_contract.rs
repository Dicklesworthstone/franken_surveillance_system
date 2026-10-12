#![forbid(unsafe_code)]
//! Real RFC 7798 receiver contracts over synthetic wire probes, not picture-decode claims.
mod rtpdump_support;

use fss_packet::{
    H265Error, H265Limits, H265ReceiveError, H265ReceivePoll, H265Receiver, ReorderLimits,
};
use fss_reference::ingest::rtpdump::hevc::*;
use rtpdump_support::*;

fn settings() -> HevcDumpConfig {
    let c = config();
    HevcDumpConfig {
        key: c.key,
        payload_type: c.payload_type,
        sprop_max_don_diff: 0,
        dump: c.dump,
        reorder: ReorderLimits::default(),
        reconstruction: H265Limits::default(),
        rtcp: c.rtcp,
    }
}

// Legal transport NALs. No RBSP validity, parameter availability, or pixels are inferred.
const AUD: &[u8] = &[70, 1, 0x80];
const SINGLE: &[u8] = &[2, 1, 0x80, 0xab, 0xcd];
const SECOND: &[u8] = &[4, 1, 0x80, 0xef];
const MULTILAYER: &[u8] = &[3, 0x39, 0x80, 0xde, 0xad, 0xbe, 0xef];

fn fragments(nal: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mid = 2 + (nal.len() - 2) / 2;
    let indicator = (nal[0] & 0x81) | (49 << 1);
    let kind = (nal[0] >> 1) & 63;
    let mut start = vec![indicator, nal[1], 0x80 | kind];
    start.extend_from_slice(&nal[2..mid]);
    let mut end = vec![indicator, nal[1], 0x40 | kind];
    end.extend_from_slice(&nal[mid..]);
    (start, end)
}

fn aggregate(nals: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![48 << 1, 1];
    for n in nals {
        out.extend_from_slice(&(n.len() as u16).to_be_bytes());
        out.extend_from_slice(n);
    }
    out
}

fn wrapped_packet(seq: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    let original = rtp(seq, marker, payload);
    let mut wire = original[..12].to_vec();
    wire[0] |= 0x31; // One CSRC, an extension, and padding: none may enter a NAL.
    wire.extend_from_slice(&123_u32.to_be_bytes());
    wire.extend_from_slice(&[0xbe, 0xde, 0, 1, 0x10, 0xaa, 0, 0]);
    wire.extend_from_slice(payload);
    wire.extend_from_slice(&[0, 0, 0, 4]);
    wire
}

#[derive(Default)]
struct Seen {
    records: usize,
    nals: Vec<Vec<u8>>,
    markers: Vec<bool>,
    reversed: usize,
}

fn clean(bytes: &[u8], expected_header_bytes: usize) -> Result<Seen, Error> {
    let cx = cx()?;
    let mut replay = RecordedHevcReplay::new(bytes, settings())?;
    let mut other_config = settings();
    other_config.key.generation += 1;
    let other_epoch = RecordedHevcReplay::new(bytes, other_config)?;
    let mut seen = Seen::default();
    let mut ended = false;
    let mut first_sources = std::collections::BTreeMap::new();
    for _ in 0..512 {
        match replay.step(&cx) {
            HevcDumpStep::Record {
                source,
                offset_reversed,
                admission: HevcDumpAdmission::Rtp(receipt),
            } => {
                assert_eq!(source.packet(), &bytes[source.packet_span()]);
                if let Some(sequence) = receipt.transport.sequence.extended_sequence {
                    if let Some(retained) = replay.source_record(sequence) {
                        let first = first_sources.entry(sequence).or_insert(source.index());
                        assert_eq!(retained.index(), *first);
                    }
                }
                seen.records += 1;
                seen.reversed += usize::from(offset_reversed);
            }
            HevcDumpStep::Progress(H265ReceivePoll::Packet { source, reconstruction }) => {
                let original = replay.source_record(source.sequence()).ok_or("missing source")?;
                assert_eq!(source.bytes(), original.packet());
                let output = reconstruction?;
                assert!(!output.gap_before);
                assert!(output.discarded.is_none());
                for nal in output.nals {
                    let spans = replay.map_nal(&nal)?;
                    assert!(!spans.is_empty());
                    assert_eq!(spans.len(), nal.sources().len());
                    for (span, kernel) in spans.into_iter().zip(nal.sources()) {
                        assert_eq!(&bytes[span.wire.clone()], &nal.bytes()[span.nal]);
                        let packet = replay.source_record(kernel.sequence).ok_or("source record")?;
                        assert_eq!(span.record, packet.index());
                        assert!(
                            span.wire.start >= packet.packet_span().start + expected_header_bytes
                        );
                        assert!(span.wire.end <= packet.packet_span().end);
                        if let Some(header) = span.fragment_header {
                            assert_eq!(header.len(), 3);
                            let h = &bytes[header];
                            assert_eq!(
                                &nal.bytes()[..2],
                                &[(h[0] & 0x81) | ((h[2] & 63) << 1), h[1]]
                            );
                        }
                    }
                    assert!(matches!(other_epoch.map_nal(&nal), Err(HevcDumpError::SourceMap)));
                    seen.markers.push(nal.marker());
                    seen.nals.push(nal.bytes().to_vec());
                }
            }
            HevcDumpStep::Progress(H265ReceivePoll::Ended { discarded: None }) => ended = true,
            HevcDumpStep::InputEnded => {}
            HevcDumpStep::Exhausted => {
                assert!(ended);
                assert_eq!(replay.retained_nal_bytes(), 0);
                assert!(matches!(replay.step(&cx), HevcDumpStep::Exhausted));
                return Ok(seen);
            }
            other => return Err(format!("unexpected clean replay event: {other:?}").into()),
        }
    }
    Err("recorded HEVC did not reach bounded quiescence".into())
}

#[test]
fn single_ap_and_fu_preserve_extensions_padding_sequence_wrap_and_first_original() -> TestResult {
    let ap = aggregate(&[SINGLE, SECOND]);
    let (start, end) = fragments(MULTILAYER);
    let mut bytes = header();
    for (seq, marker, payload) in [
        (65534, false, AUD),
        (65535, true, SINGLE),
        (0, true, ap.as_slice()),
        (1, false, start.as_slice()),
        (2, true, end.as_slice()),
        (2, true, end.as_slice()),
    ] {
        let wire = wrapped_packet(seq, marker, payload);
        record(&mut bytes, &wire, wire.len() as u16, 0);
    }
    let seen = clean(&bytes, 24)?;
    assert_eq!(seen.records, 6);
    assert_eq!(
        seen.nals,
        vec![SINGLE.to_vec(), SINGLE.to_vec(), SECOND.to_vec(), MULTILAYER.to_vec()]
    );
    assert_eq!(seen.markers, [true, false, true, true]);
    assert_eq!(seen.reversed, 0);
    Ok(())
}

#[test]
fn bounded_reordering_recovers_fu_without_rewriting_reversed_original_offsets() -> TestResult {
    let (start, end) = fragments(SINGLE);
    let bytes = dump(&[
        (10, false, AUD, 0),
        (11, false, AUD, 0),
        (13, true, &end, 2),
        (12, false, &start, 1),
    ]);
    let seen = clean(&bytes, 12)?;
    assert_eq!(seen.records, 4);
    assert_eq!(seen.nals, vec![AUD.to_vec(), SINGLE.to_vec()]);
    assert_eq!(seen.reversed, 1);
    Ok(())
}

fn sparse(tail_ms: u32) -> Vec<u8> {
    let (start, end) = fragments(SINGLE);
    dump(&[
        (10, false, AUD, 0),
        (11, false, AUD, 0),
        (13, false, &start, 1),
        (14, true, &end, tail_ms),
    ])
}
fn deadlines() -> HevcDumpConfig {
    let mut config = settings();
    config.reorder.max_delay_ns = 10_000_000;
    config.reconstruction.max_pending_age_ns = 20_000_000;
    config
}

#[test]
fn sparse_arrivals_cannot_grant_an_expired_fu_a_new_lifetime() -> TestResult {
    for (tail_ms, expired) in [(30, false), (31, true), (100, true), (u32::MAX, true)] {
        let bytes = sparse(tail_ms);
        let cx = cx()?;
        let mut replay = RecordedHevcReplay::new(&bytes, deadlines())?;
        let (mut records, mut gaps, mut retirements, mut completed, mut refused) = (0, 0, 0, 0, 0);
        let mut exhausted = false;
        for _ in 0..128 {
            match replay.step(&cx) {
                HevcDumpStep::Record { admission: HevcDumpAdmission::Rtp(_), .. } => {
                    records += 1;
                    if records == 4 {
                        assert_eq!(retirements > 0, expired, "arrival at {tail_ms} ms");
                    }
                }
                HevcDumpStep::Progress(H265ReceivePoll::Gap { .. }) => gaps += 1,
                HevcDumpStep::Progress(H265ReceivePoll::FragmentDiscarded(fragment)) => {
                    assert_eq!(fragment.reason, H265Error::Deadline);
                    assert_eq!(fragment.first_sequence, 13);
                    assert_eq!(fragment.last_sequence, 13);
                    assert_eq!(records, 3);
                    retirements += 1;
                }
                HevcDumpStep::Progress(H265ReceivePoll::Packet { reconstruction, .. }) => {
                    match reconstruction {
                        Ok(output) => {
                            for nal in output.nals {
                                if nal.nal_type() == 1 {
                                    assert_eq!(nal.bytes(), SINGLE);
                                    assert_eq!(replay.map_nal(&nal)?.len(), 2);
                                    completed += 1;
                                }
                            }
                        }
                        Err(H265ReceiveError::Codec(error)) => {
                            assert_eq!(error.reason, H265Error::MissingStart);
                            refused += 1;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                HevcDumpStep::Progress(H265ReceivePoll::Ended { discarded: None })
                | HevcDumpStep::InputEnded => {}
                HevcDumpStep::Exhausted => {
                    exhausted = true;
                    break;
                }
                other => return Err(format!("unexpected deadline event: {other:?}").into()),
            }
        }
        assert!(exhausted);
        assert_eq!((records, gaps), (4, 1));
        assert_eq!(retirements, usize::from(expired));
        assert_eq!(refused, usize::from(expired));
        assert_eq!(completed, usize::from(!expired));
        assert_eq!(replay.retained_nal_bytes(), 0);
    }
    Ok(())
}

#[test]
fn cancellation_between_deadline_events_never_admits_the_pending_tail() -> TestResult {
    let bytes = sparse(100);
    let cx = cx()?;
    let mut replay = RecordedHevcReplay::new(&bytes, deadlines())?;
    for _ in 0..128 {
        if matches!(replay.step(&cx), HevcDumpStep::Progress(H265ReceivePoll::Gap { .. })) {
            cx.request_cancellation();
            assert!(matches!(replay.step(&cx), HevcDumpStep::Cancelled(_)));
            assert!(replay.source_record(13).is_some());
            assert!(replay.source_record(14).is_none());
            assert_eq!(replay.retained_nal_bytes(), 0);
            assert!(matches!(replay.step(&cx), HevcDumpStep::Exhausted));
            assert!(cx.is_drain_completed());
            return Ok(());
        }
    }
    Err("missing deadline before cancellation".into())
}

#[test]
fn truncated_capture_fences_derivatives_but_keeps_all_following_originals() -> TestResult {
    let (start, end) = fragments(SINGLE);
    let mut bytes = dump(&[(10, false, AUD, 0), (11, false, &start, 0)]);
    let prefix = rtp(12, true, &end);
    record(&mut bytes, &prefix, prefix.len() as u16 + 1, 1);
    let later = rtp(13, true, SECOND);
    record(&mut bytes, &later, later.len() as u16, 2);
    let cx = cx()?;
    let mut replay = RecordedHevcReplay::new(&bytes, settings())?;
    let (mut records, mut prefix_seen, mut fenced) = (0, false, 0);
    for _ in 0..128 {
        match replay.step(&cx) {
            HevcDumpStep::Record { source, admission, .. } => {
                assert_eq!(source.packet(), &bytes[source.packet_span()]);
                records += 1;
                match admission {
                    HevcDumpAdmission::CapturedPrefix(retired) => {
                        assert!(retired.fragment.is_some());
                        prefix_seen = true;
                    }
                    HevcDumpAdmission::Fenced => {
                        assert!(prefix_seen);
                        fenced += 1;
                    }
                    HevcDumpAdmission::Rtp(_) => assert!(!prefix_seen),
                    other => return Err(format!("unexpected admission: {other:?}").into()),
                }
            }
            HevcDumpStep::Progress(H265ReceivePoll::Packet { reconstruction, .. }) => {
                assert!(!prefix_seen);
                assert!(reconstruction?.nals.is_empty());
            }
            HevcDumpStep::InputEnded => {}
            HevcDumpStep::Exhausted => {
                assert_eq!((records, fenced), (4, 1));
                assert_eq!(replay.retained_nal_bytes(), 0);
                return Ok(());
            }
            other => return Err(format!("unexpected prefix event: {other:?}").into()),
        }
    }
    Err("fenced originals did not drain".into())
}

#[test]
fn malformed_rtcp_and_ap_keep_exact_sources_without_destroying_independent_nals() -> TestResult {
    let mut bytes = dump(&[(10, false, AUD, 0), (11, true, SINGLE, 0)]);
    record(&mut bytes, &[0, 0, 0, 0], 0, 0); // Invalid RTCP, not an inferred RTP packet.
    let mut broken_ap = aggregate(&[SINGLE, SECOND]);
    broken_ap.pop(); // A valid AP prefix must never escape as a complete NAL.
    let bad = rtp(12, true, &broken_ap);
    record(&mut bytes, &bad, bad.len() as u16, 0);
    let good = rtp(13, true, SECOND);
    record(&mut bytes, &good, good.len() as u16, 0);
    let cx = cx()?;
    let mut replay = RecordedHevcReplay::new(&bytes, settings())?;
    let (mut records, mut rtcp_errors, mut codec_errors) = (0, 0, 0);
    let mut nals = Vec::new();
    for _ in 0..128 {
        match replay.step(&cx) {
            HevcDumpStep::Record { source, admission, .. } => {
                assert_eq!(source.packet(), &bytes[source.packet_span()]);
                records += 1;
                match admission {
                    HevcDumpAdmission::Rtcp(Err(_)) => rtcp_errors += 1,
                    HevcDumpAdmission::Rtp(_) => {}
                    other => {
                        return Err(format!("unexpected malformed admission: {other:?}").into());
                    }
                }
            }
            HevcDumpStep::Progress(H265ReceivePoll::Packet { source, reconstruction }) => {
                match reconstruction {
                    Ok(output) => nals.extend(output.nals.into_iter().map(|n| n.bytes().to_vec())),
                    Err(H265ReceiveError::Codec(error)) => {
                        assert_eq!(source.bytes(), bad.as_slice());
                        assert_eq!(error.reason, H265Error::Malformed);
                        codec_errors += 1;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            HevcDumpStep::Progress(H265ReceivePoll::Ended { discarded: None })
            | HevcDumpStep::InputEnded => {}
            HevcDumpStep::Exhausted => {
                assert_eq!((records, rtcp_errors, codec_errors), (5, 1, 1));
                assert_eq!(nals, vec![SINGLE.to_vec(), SECOND.to_vec()]);
                return Ok(());
            }
            other => return Err(format!("unexpected malformed event: {other:?}").into()),
        }
    }
    Err("malformed probes did not drain".into())
}

#[test]
fn incomplete_eof_retires_fu_and_malformed_framing_never_becomes_clean_eof() -> TestResult {
    let (start, _) = fragments(SINGLE);
    for malformed in [false, true] {
        let mut bytes = dump(&[(10, false, AUD, 0), (11, false, &start, 0)]);
        if malformed {
            bytes.extend_from_slice(&[0, 20, 0, 12]);
        }
        let cx = cx()?;
        let mut replay = RecordedHevcReplay::new(&bytes, settings())?;
        let mut retired = false;
        for _ in 0..128 {
            match replay.step(&cx) {
                HevcDumpStep::Progress(H265ReceivePoll::Ended { discarded: Some(fragment) }) => {
                    assert!(!malformed);
                    assert_eq!(fragment.reason, H265Error::EndOfInput);
                    retired = true;
                }
                HevcDumpStep::FramingRefused { cancelled, .. } => {
                    assert!(malformed);
                    assert!(cancelled.fragment.is_some());
                    retired = true;
                }
                HevcDumpStep::InputEnded => assert!(!malformed),
                HevcDumpStep::Progress(H265ReceivePoll::Packet { reconstruction, .. }) => {
                    assert!(reconstruction?.nals.is_empty());
                }
                HevcDumpStep::Record { .. } => {}
                HevcDumpStep::Exhausted => break,
                other => return Err(format!("unexpected terminal event: {other:?}").into()),
            }
        }
        assert!(retired);
        assert_eq!(replay.retained_nal_bytes(), 0);
        assert!(matches!(replay.step(&cx), HevcDumpStep::Exhausted));
    }
    Ok(())
}

#[test]
fn explicit_negotiation_and_container_ceilings_are_never_silently_broadened() -> TestResult {
    let bytes = dump(&[(10, false, AUD, 0), (11, true, SINGLE, 0)]);
    let mut c = settings();
    c.sprop_max_don_diff = 1;
    assert!(matches!(
        RecordedHevcReplay::new(&bytes, c),
        Err(HevcDumpError::Receiver(H265ReceiveError::Codec(error)))
            if error.reason == H265Error::Unsupported
    ));
    c = settings();
    c.reconstruction.max_nal_bytes = 1;
    assert!(RecordedHevcReplay::new(&bytes, c).is_err());
    c = settings();
    c.dump.max_records = 1;
    let cx = cx()?;
    let mut replay = RecordedHevcReplay::new(&bytes, c)?;
    assert!(matches!(replay.step(&cx), HevcDumpStep::Record { .. }));
    assert!(matches!(replay.step(&cx), HevcDumpStep::FramingRefused { .. }));
    assert!(matches!(replay.step(&cx), HevcDumpStep::Exhausted));
    Ok(())
}

#[test]
fn a_foreign_ssrc_fences_derivatives_without_hiding_refused_or_later_originals() -> TestResult {
    let (start, end) = fragments(SINGLE);
    let mut bytes = dump(&[(10, false, AUD, 0), (11, false, &start, 0)]);
    let mut wrong = rtp(12, true, SECOND);
    wrong[8..12].copy_from_slice(&8_u32.to_be_bytes());
    record(&mut bytes, &wrong, wrong.len() as u16, 1);
    let later = rtp(12, true, &end);
    record(&mut bytes, &later, later.len() as u16, 2);
    let cx = cx()?;
    let mut replay = RecordedHevcReplay::new(&bytes, settings())?;
    let (mut records, mut refused, mut fenced) = (0, false, false);
    for _ in 0..128 {
        match replay.step(&cx) {
            HevcDumpStep::Record { source, admission, .. } => {
                records += 1;
                assert_eq!(source.packet(), &bytes[source.packet_span()]);
                match admission {
                    HevcDumpAdmission::Refused { error: HevcDumpError::Receiver(_), cancelled } => {
                        assert_eq!(source.packet(), wrong.as_slice());
                        assert!(cancelled.fragment.is_some());
                        refused = true;
                    }
                    HevcDumpAdmission::Fenced => {
                        assert!(refused);
                        assert_eq!(source.packet(), later.as_slice());
                        fenced = true;
                    }
                    HevcDumpAdmission::Rtp(_) => assert!(!refused),
                    other => return Err(format!("unexpected owner admission: {other:?}").into()),
                }
            }
            HevcDumpStep::Progress(H265ReceivePoll::Packet { reconstruction, .. }) => {
                assert!(!refused);
                assert!(reconstruction?.nals.is_empty());
            }
            HevcDumpStep::InputEnded => {}
            HevcDumpStep::Exhausted => {
                assert_eq!(records, 4);
                assert!(refused && fenced);
                assert_eq!(replay.retained_nal_bytes(), 0);
                return Ok(());
            }
            other => return Err(format!("unexpected owner event: {other:?}").into()),
        }
    }
    Err("fenced owner probes did not drain".into())
}

#[test]
fn identical_payload_at_a_different_media_timestamp_is_not_a_valid_source_mapping() -> TestResult {
    let c = settings();
    let mut donor = H265Receiver::new(
        c.key,
        c.payload_type,
        c.sprop_max_don_diff,
        c.reorder,
        c.reconstruction,
    )?;
    donor.ingest(c.key, &rtp(10, false, AUD), 0)?;
    let mut changed = rtp(11, true, SINGLE);
    changed[4..8].copy_from_slice(&90_001_u32.to_be_bytes());
    donor.ingest(c.key, &changed, 0)?;
    let candidate = match donor.poll(0)? {
        H265ReceivePoll::Packet { reconstruction, .. } => {
            reconstruction?.nals.into_iter().next().ok_or("donor NAL")?
        }
        other => return Err(format!("unexpected donor event: {other:?}").into()),
    };
    let bytes = dump(&[(10, false, AUD, 0), (11, true, SINGLE, 0)]);
    let cx = cx()?;
    let mut replay = RecordedHevcReplay::new(&bytes, c)?;
    for _ in 0..32 {
        if let HevcDumpStep::Progress(H265ReceivePoll::Packet { reconstruction, .. }) =
            replay.step(&cx)
        {
            let nal = reconstruction?.nals.into_iter().next().ok_or("original NAL")?;
            assert_eq!(nal.bytes(), candidate.bytes());
            assert_eq!(nal.key(), candidate.key());
            assert_ne!(nal.timestamp(), candidate.timestamp());
            assert!(!replay.map_nal(&nal)?.is_empty());
            assert!(matches!(replay.map_nal(&candidate), Err(HevcDumpError::SourceMap)));
            return Ok(());
        }
    }
    Err("original NAL did not arrive".into())
}
