#![forbid(unsafe_code)]
//! rtpdump RTP replay into exact NAL units across probation, reordering, wrap and missing fragments.
mod rtpdump_support;
use fss_packet::{ContinuityError, H264Error, H264Status, RtcpMode, SequenceClass};
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
/// Before the bound generation admits its baseline, a foreign SSRC is refused (never adopted).
/// After the baseline, an SSRC change opens generation + 1 with a fresh sequence epoch and keeps
/// ingesting: the second SSRC's packets are admitted, not refused.
/// Planted negative: the pre-fix replay (one fixed key) refuses every second-SSRC packet.
#[test]
fn wrong_first_ssrc_is_refused_but_a_later_ssrc_change_opens_a_new_generation() -> TestResult {
    let mut b = header();
    let mut wrong = rtp(0, false, &[9, 0xf0]);
    wrong[11] = 8;
    record(&mut b, &wrong, wrong.len() as u16, 0);
    let cx = cx()?;
    let mut r = RtpDumpReplay::new(&b, config())?;
    let out = records(&mut r, &cx)?;
    assert!(matches!(out[0].outcome, RtpRecordOutcome::StreamRefused(_)));
    assert!(out[0].restart.is_none());
    assert_eq!(r.stats().unique, 0);
    assert_eq!(r.key().generation, 1);

    let mut b = header();
    for (seq, ssrc, ts, payload) in [
        (10_u16, 7_u32, 3_000_u32, &[9_u8, 0xf0][..]),
        (11, 7, 3_000, &[0x65, 0xaa][..]),
        (12, 7, 6_000, &[0x61, 0xbb][..]),
        (500, 8, 9_000, &[9, 0xf0][..]),
        (501, 8, 9_000, &[0x65, 0xcc][..]),
        (502, 8, 12_000, &[0x61, 0xdd][..]),
    ] {
        let wire = rtp_full(seq, true, ts, ssrc, payload);
        record(&mut b, &wire, wire.len() as u16, u32::from(seq));
    }
    let mut r = RtpDumpReplay::new(&b, config())?;
    let out = records(&mut r, &cx)?;
    assert!(
        out[..3]
            .iter()
            .all(|o| o.key.generation == 1 && o.restart.is_none())
    );
    let restart = out[3].restart.ok_or("no restart at the SSRC change")?;
    assert_eq!(restart.cause, RestartCause::SsrcChange);
    assert_eq!((restart.previous.generation, restart.previous.ssrc), (1, 7));
    assert_eq!((out[3].key.generation, out[3].key.ssrc), (2, 8));
    assert!(
        matches!(&out[3].outcome, RtpRecordOutcome::SequenceOnly(o) if o.class == SequenceClass::Probation)
    );
    assert!(
        matches!(&out[4].outcome, RtpRecordOutcome::H264 { observation, nals, .. }
            if observation.class == SequenceClass::Baseline && nals.len() == 1)
    );
    assert!(
        matches!(&out[5].outcome, RtpRecordOutcome::H264 { observation, gap_before: false, nals, .. }
            if observation.class == SequenceClass::Advanced && nals.len() == 1)
    );
    assert_eq!(out[5].timestamp, Some(12_000));
    assert!(
        out.iter()
            .all(|o| !matches!(o.outcome, RtpRecordOutcome::StreamRefused(_)))
    );
    assert_eq!((r.key().generation, r.key().ssrc), (2, 8));
    Ok(())
}
/// fss-2h5zq.29 review D2: a foreign-SSRC packet after the baseline opens a generation only when
/// the next record is the same SSRC's next sequence (two-packet validation). Strays are refused
/// (`StreamRefused(StreamMismatch)`) without a restart and without retiring the bound stream's
/// pending fragment: one lands inside an FU-A, two more have a non-consecutive or bound-SSRC
/// follower. The bound stream keeps ingesting and the FU completes as one exact NAL.
/// Planted negatives: switching generation on the first foreign packet (pre-fix replay);
/// retiring the pending fragment on a stray.
#[test]
fn stray_foreign_ssrc_packets_are_refused_without_a_restart() -> TestResult {
    let mut b = header();
    for (i, (seq, ssrc, ts, marker, payload)) in [
        (10_u16, 7_u32, 3_000_u32, true, &[9_u8, 0xf0][..]),
        (11, 7, 3_000, true, &[0x65, 0xaa][..]),
        (12, 7, 6_000, false, &[0x7c, 0x85, 0xbb][..]),
        (500, 8, 9_000, true, &[9, 0xf0][..]),
        (13, 7, 6_000, true, &[0x7c, 0x45, 0xcc][..]),
        (600, 8, 9_000, true, &[9, 0xf0][..]),
        (602, 8, 9_000, true, &[9, 0xf0][..]),
        (14, 7, 9_000, true, &[0x61, 0xdd][..]),
    ]
    .into_iter()
    .enumerate()
    {
        let wire = rtp_full(seq, marker, ts, ssrc, payload);
        record(&mut b, &wire, wire.len() as u16, i as u32);
    }
    let cx = cx()?;
    let mut r = RtpDumpReplay::new(&b, config())?;
    let out = records(&mut r, &cx)?;
    assert_eq!(out.len(), 8);
    assert!(
        out.iter()
            .all(|o| o.restart.is_none() && (o.key.generation, o.key.ssrc) == (1, 7))
    );
    for stray in [3, 5, 6] {
        assert!(
            matches!(
                out[stray].outcome,
                RtpRecordOutcome::StreamRefused(ContinuityError::StreamMismatch)
            ),
            "record {stray}: {:?}",
            out[stray].outcome
        );
        assert!(out[stray].discarded.is_none());
    }
    match &out[4].outcome {
        RtpRecordOutcome::H264 {
            nals, gap_before, ..
        } => {
            assert!(!gap_before);
            assert_eq!(nals.len(), 1);
            assert_eq!(nals[0].nal.bytes(), &[0x65, 0xbb, 0xcc][..]);
        }
        other => return Err(format!("FU end not delivered: {other:?}").into()),
    }
    assert!(out[4].discarded.is_none());
    assert!(
        matches!(&out[7].outcome, RtpRecordOutcome::H264 { observation, gap_before: false, nals, .. }
            if observation.class == SequenceClass::Advanced && nals.len() == 1)
    );
    assert_eq!((r.key().generation, r.key().ssrc), (1, 7));
    Ok(())
}
/// A sequence jump: one suspected discontinuity, then the kernel's `RestartRequired` opens
/// generation + 1 on the same SSRC; the triggering packet starts probation and the stream keeps
/// ingesting.
/// Planted negative: the pre-fix replay leaves every later packet `RestartRequired`.
#[test]
fn restart_required_opens_a_new_generation_and_keeps_ingesting() -> TestResult {
    let mut b = header();
    for (seq, ts) in [
        (1_u16, 3_000_u32),
        (2, 6_000),
        (9_000, 9_000),
        (9_001, 12_000),
        (9_002, 15_000),
    ] {
        let wire = rtp_full(seq, true, ts, 7, &[0x61, seq as u8]);
        record(&mut b, &wire, wire.len() as u16, u32::from(seq));
    }
    let cx = cx()?;
    let mut r = RtpDumpReplay::new(&b, config())?;
    let out = records(&mut r, &cx)?;
    assert!(
        matches!(&out[2].outcome, RtpRecordOutcome::SequenceOnly(o) if o.class == SequenceClass::DiscontinuitySuspected)
    );
    let restart = out[3].restart.ok_or("no restart")?;
    assert_eq!(restart.cause, RestartCause::SequenceRestart);
    assert_eq!(out[3].key.generation, 2);
    assert!(
        matches!(&out[3].outcome, RtpRecordOutcome::SequenceOnly(o) if o.class == SequenceClass::Probation)
    );
    assert!(
        matches!(&out[4].outcome, RtpRecordOutcome::H264 { observation, .. } if observation.class == SequenceClass::Baseline)
    );
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
