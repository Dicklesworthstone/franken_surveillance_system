#![forbid(unsafe_code)]
//! rtpdump RTP replay into exact NAL units across probation, reordering, wrap and missing fragments.
mod rtpdump_support;
use fss_packet::{H264Error, H264Status, RtcpMode, SequenceClass};
use fss_reference::ingest::rtpdump::{RtpDumpFault, replay::*};
use rtpdump_support::*;

fn records<'a>(
    replay: &mut RtpDumpReplay<'a>,
    cx: &fss_reference::ReplayCx,
) -> Result<Vec<ReplayedRecord<'a>>, Error> {
    let mut out = Vec::new();
    for _ in 0..100 {
        match replay.step(cx)? {
            RtpReplayStep::Record(record) => out.push(*record),
            RtpReplayStep::Ended {
                discarded: None, ..
            } => return Ok(out),
            other => return Err(format!("unexpected replay {other:?}").into()),
        }
    }
    Err("bounded fixture did not finish".into())
}
#[test]
fn real_baseline_single_and_fragmented_packets_reconstruct_exact_nals() -> TestResult {
    for fragmented in [false, true] {
        let b = real_dump(fragmented);
        let cx = cx()?;
        let mut replay = RtpDumpReplay::new(&b, config())?;
        let out = records(&mut replay, &cx)?;
        let mut decoded = Vec::new();
        assert!(
            matches!(&out[0].outcome,RtpRecordOutcome::SequenceOnly(o) if o.class == SequenceClass::Probation)
        );
        for event in out {
            assert_eq!(event.source.packet(), &b[event.source.packet_span()]);
            if let RtpRecordOutcome::H264 { nals, .. } = event.outcome {
                for n in nals {
                    for s in &n.sources {
                        assert_eq!(&b[s.wire.clone()], &n.nal.bytes()[s.nal.clone()]);
                    }
                    decoded.push(n.nal.bytes().to_vec());
                }
            }
        }
        assert_eq!(
            decoded,
            nals().iter().map(|n| n.to_vec()).collect::<Vec<_>>()
        );
        assert_eq!(replay.stats().missing, 0);
        assert_eq!(replay.pending_bytes(), 0);
        assert!(matches!(replay.step(&cx)?, RtpReplayStep::Exhausted));
    }
    Ok(())
}
#[test]
fn probation_duplicate_reorder_and_wrap_remain_distinct() -> TestResult {
    let b = dump(&[
        (65534, false, &[9, 0xf0], 0),
        (65535, true, &[0x65, 0xaa], 0),
        (1, true, &[0x61, 0xbb], 1),
        (0, true, &[0x61, 0xcc], 2),
        (1, true, &[0x61, 0xbb], 3),
    ]);
    let cx = cx()?;
    let mut replay = RtpDumpReplay::new(&b, config())?;
    let out = records(&mut replay, &cx)?;
    assert!(
        matches!(&out[1].outcome,RtpRecordOutcome::H264{observation,..} if observation.class==SequenceClass::Baseline)
    );
    assert!(matches!(
        &out[2].outcome,
        RtpRecordOutcome::H264 {
            gap_before: true,
            ..
        }
    ));
    assert!(
        matches!(&out[3].outcome,RtpRecordOutcome::H264{observation,status:H264Status::IgnoredNonIncreasing,nals,..}
        if observation.class==SequenceClass::Reordered && nals.is_empty())
    );
    assert!(
        matches!(&out[4].outcome,RtpRecordOutcome::SequenceOnly(o) if o.class==SequenceClass::Duplicate)
    );
    assert_eq!(replay.stats().unique, 3);
    assert_eq!(replay.stats().missing, 0);
    Ok(())
}
#[test]
fn missing_fragment_never_becomes_a_complete_nal() -> TestResult {
    let b = dump(&[
        (0, false, &[9, 0xf0], 0),
        (1, false, &[0x7c, 0x85, 0xaa], 0),
        (3, true, &[0x7c, 0x45, 0xbb], 1),
    ]);
    let cx = cx()?;
    let mut replay = RtpDumpReplay::new(&b, config())?;
    let out = records(&mut replay, &cx)?;
    assert!(
        matches!(&out[2].outcome,RtpRecordOutcome::CodecRefused{failure,..} if failure.reason==H264Error::MissingStart)
    );
    assert_eq!(
        out[2].discarded.as_ref().ok_or("discard")?.reason,
        H264Error::Gap
    );
    assert_eq!(replay.stats().missing, 1);
    Ok(())
}
#[test]
fn late_fu_completion_does_not_clear_expired_fragment_deadline() -> TestResult {
    let b = dump(&[
        (0, false, &[9, 0xf0], 0),
        (1, false, &[0x7c, 0x85, 0xaa], 0),
        (2, true, &[0x7c, 0x45, 0xbb], 2000),
    ]);
    let cx = cx()?;
    let mut replay = RtpDumpReplay::new(&b, config())?;
    let out = records(&mut replay, &cx)?;
    assert_eq!(
        out[2].expired.as_ref().ok_or("expiry")?.reason,
        H264Error::Deadline
    );
    assert!(
        matches!(&out[2].outcome,RtpRecordOutcome::CodecRefused{failure,..} if failure.reason==H264Error::MissingStart)
    );
    Ok(())
}
#[test]
fn decreasing_record_offsets_are_visible_without_reversing_replay_timer() -> TestResult {
    let b = dump(&[(0, false, &[9, 0xf0], 10), (1, true, &[0x65, 0xaa], 5)]);
    let cx = cx()?;
    let mut replay = RtpDumpReplay::new(&b, config())?;
    let out = records(&mut replay, &cx)?;
    assert!(out[1].offset_reversed);
    assert_eq!(out[1].source.offset_ms(), 5);
    Ok(())
}
#[test]
fn rtcp_mode_is_explicit_and_bad_rtcp_does_not_rebind_rtp() -> TestResult {
    for reduced in [false, true] {
        let mut b = header();
        record(&mut b, &[0x80, 201, 0, 1, 0, 0, 0, 7], 0, 0);
        let mut cfg = config();
        if reduced {
            cfg.rtcp = RtcpMode::ReducedSize;
        }
        let cx = cx()?;
        let mut r = RtpDumpReplay::new(&b, cfg)?;
        let out = records(&mut r, &cx)?;
        assert_eq!(matches!(out[0].outcome, RtpRecordOutcome::Rtcp), reduced);
        assert_eq!(r.stats().unique, 0);
    }
    Ok(())
}
#[test]
fn wrong_ssrc_is_refused_without_automatic_generation_change() -> TestResult {
    let mut b = header();
    let mut wrong = rtp(0, false, &[9, 0xf0]);
    wrong[11] = 8;
    record(&mut b, &wrong, wrong.len() as u16, 0);
    let cx = cx()?;
    let mut r = RtpDumpReplay::new(&b, config())?;
    let out = records(&mut r, &cx)?;
    assert!(matches!(out[0].outcome, RtpRecordOutcome::StreamRefused(_)));
    assert_eq!(r.stats().unique, 0);
    Ok(())
}
#[test]
fn malformed_stap_retains_source_without_leaking_a_valid_prefix() -> TestResult {
    let b = dump(&[
        (0, false, &[9, 0xf0], 0),
        (1, true, &[0x78, 0, 2, 0x65, 0xaa, 0, 5, 0x61], 0),
    ]);
    let cx = cx()?;
    let mut r = RtpDumpReplay::new(&b, config())?;
    let out = records(&mut r, &cx)?;
    assert!(matches!(
        out[1].outcome,
        RtpRecordOutcome::CodecRefused { .. }
    ));
    assert_eq!(out[1].source.packet(), &b[out[1].source.packet_span()]);
    Ok(())
}
#[test]
fn truncated_final_record_is_not_reported_as_clean_eof() -> TestResult {
    let mut b = dump(&[
        (0, false, &[9, 0xf0], 0),
        (1, false, &[0x7c, 0x85, 0xaa], 0),
    ]);
    b.extend_from_slice(&[0, 20, 0, 12]);
    let cx = cx()?;
    let mut r = RtpDumpReplay::new(&b, config())?;
    let _ = r.step(&cx)?;
    let _ = r.step(&cx)?;
    match r.step(&cx)? {
        RtpReplayStep::FramingRefused { error, discarded } => {
            assert_eq!(error.fault, RtpDumpFault::TruncatedRecordHeader);
            assert!(discarded.is_some());
            assert_eq!(error.span.end, b.len());
        }
        other => return Err(format!("{other:?}").into()),
    }
    assert!(matches!(r.step(&cx)?, RtpReplayStep::Exhausted));
    Ok(())
}
#[test]
fn cancellation_returns_fragment_receipt_and_leaves_original_input_intact() -> TestResult {
    let b = dump(&[
        (0, false, &[9, 0xf0], 0),
        (1, false, &[0x7c, 0x85, 0xaa], 0),
    ]);
    let original = b.clone();
    let cx = cx()?;
    let mut r = RtpDumpReplay::new(&b, config())?;
    let _ = r.step(&cx)?;
    let _ = r.step(&cx)?;
    cx.request_cancellation();
    assert!(matches!(
        r.step(&cx)?,
        RtpReplayStep::Cancelled { discarded: Some(_) }
    ));
    assert_eq!(b, original);
    assert_eq!(r.pending_bytes(), 0);
    assert!(cx.is_drain_completed());
    Ok(())
}
#[test]
fn clean_eof_reports_unfinished_fu_instead_of_emitting_it() -> TestResult {
    let b = dump(&[
        (0, false, &[9, 0xf0], 0),
        (1, false, &[0x7c, 0x85, 0xaa], 0),
    ]);
    let cx = cx()?;
    let mut r = RtpDumpReplay::new(&b, config())?;
    let _ = r.step(&cx)?;
    let _ = r.step(&cx)?;
    assert!(
        matches!(r.step(&cx)?,RtpReplayStep::Ended{discarded:Some(d),..} if d.reason==H264Error::EndOfInput)
    );
    Ok(())
}
#[test]
fn invalid_owner_or_parser_policy_refuses_before_consuming_input() -> TestResult {
    let b = header();
    let mut cfg = config();
    cfg.key.ingress = 0;
    assert!(RtpDumpReplay::new(&b, cfg).is_err());
    cfg = config();
    cfg.packet.max_packet_bytes = 0;
    assert!(RtpDumpReplay::new(&b, cfg).is_err());
    Ok(())
}
