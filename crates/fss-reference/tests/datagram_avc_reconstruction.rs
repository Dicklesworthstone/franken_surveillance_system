#![forbid(unsafe_code)]
//! Real stored AVC/RTCP originals, cold reconstruction, and native receiver comparison.
mod datagram_reconstruction_support;
use datagram_reconstruction_support::*;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_packet::avc::{
    AvcAssemblyStep, AvcPictureGroup, AvcReceivePoll, AvcReceiver, parse_pps, parse_sps,
};
use fss_publication::{NeverCancel, PublishCancellation, PublishCutPoint};
use fss_reference::rtsp::datagram_archive::DatagramArchiveError;
use fss_reference::rtsp::datagram_reconstruction::{
    AvcReplayError, AvcReplayStep, DatagramAvcReplay,
};

fn pictures(event: AvcReceivePoll, out: &mut Vec<AvcPictureGroup>) {
    match event {
        AvcReceivePoll::Picture(p) => out.push(p),
        AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(result)) => {
            if let Some(p) = result.picture {
                out.push(p);
            }
        }
        _ => {}
    }
}
fn run(
    p: &fss_publication::LocalRootPublisher,
    a: &fss_reference::rtsp::datagram_archive::DatagramArchive,
    now: u64,
) -> Test<(Vec<AvcPictureGroup>, Vec<Vec<u8>>)> {
    let mut replay = DatagramAvcReplay::new(a, spec()?, bounds(), now)?;
    let mut images = Vec::new();
    let mut originals = Vec::new();
    for _ in 0..4096 {
        match replay.step(p, now, &NeverCancel, &mut work())? {
            AvcReplayStep::Rtp {
                source,
                retired: None,
                ..
            } => originals.push(source.payload().to_vec()),
            AvcReplayStep::Media { event, .. } => pictures(event, &mut images),
            AvcReplayStep::ClockAdvanced { .. } => {}
            AvcReplayStep::PrefixExhausted { source, .. } => {
                assert_eq!(source, a.pin());
                assert!(matches!(
                    replay.step(p, now, &NeverCancel, &mut work())?,
                    AvcReplayStep::Ended
                ));
                return Ok((images, originals));
            }
            other => return Err(format!("unexpected clean replay step: {other:?}").into()),
        }
    }
    Err("replay did not reach its finite prefix".into())
}
#[test]
fn cold_original_reconstruction_matches_native_receiver_without_original_objects() -> Test {
    let path = fresh("native")?;
    let input = observations(true)?;
    let pin = save(&path, &input)?;
    let s = spec()?;
    let sps = parse_sps(s.sps, s.limits.syntax)?;
    let pps = parse_pps(s.pps, &sps, s.limits.syntax)?;
    let mut receiver = AvcReceiver::new(source::KEY, s.payload_type, s.mode, s.limits, (sps, pps))?;
    let mut expected = Vec::new();
    for (_, now, bytes) in &input {
        receiver.ingest(source::KEY, bytes, *now)?;
        let mut yielded = false;
        for _ in 0..1024 {
            match receiver.poll(*now)? {
                AvcReceivePoll::Pending { .. } => {
                    yielded = true;
                    break;
                }
                event => pictures(event, &mut expected),
            }
        }
        assert!(yielded);
    }
    assert_eq!(expected.len(), 1);
    let (p, a) = reopen(&path, pin)?;
    let (actual, originals) = run(&p, &a, 1_000_000_000_000)?;
    assert_eq!(actual, expected);
    assert_eq!(
        originals,
        input.into_iter().map(|(_, _, b)| b).collect::<Vec<_>>()
    );
    Ok(())
}
#[test]
fn current_storage_time_never_changes_historical_picture_or_interpretation() -> Test {
    let path = fresh("clocks")?;
    let pin = save(&path, &observations(false)?)?;
    let (p, a) = reopen(&path, pin)?;
    assert_eq!(run(&p, &a, 0)?, run(&p, &a, 8_000_000_000_000)?);
    assert_eq!(
        DatagramAvcReplay::new(&a, spec()?, bounds(), 0)?.interpretation(),
        DatagramAvcReplay::new(&a, spec()?, bounds(), 8_000_000_000_000)?.interpretation()
    );
    Ok(())
}
#[test]
fn truncated_fu_prefix_has_no_picture_no_future_timeout_and_no_codec_eof() -> Test {
    let path = fresh("partial")?;
    let mut input = observations(true)?;
    let _ = input.pop();
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let mut replay = DatagramAvcReplay::new(&a, spec()?, bounds(), 0)?;
    for _ in 0..128 {
        match replay.step(&p, 0, &NeverCancel, &mut work())? {
            AvcReplayStep::Media { event, .. } => {
                let mut out = Vec::new();
                pictures(event, &mut out);
                assert!(out.is_empty());
            }
            AvcReplayStep::PrefixExhausted {
                replay_ns, retired, ..
            } => {
                assert_eq!(replay_ns, 11);
                let s = spec()?;
                let sps = parse_sps(s.sps, s.limits.syntax)?;
                let pps = parse_pps(s.pps, &sps, s.limits.syntax)?;
                let mut empty =
                    AvcReceiver::new(source::KEY, s.payload_type, s.mode, s.limits, (sps, pps))?;
                assert_ne!(
                    retired,
                    empty.cancel(),
                    "incomplete transport state must remain explicit"
                );
                return Ok(());
            }
            AvcReplayStep::Rtp { .. } => {}
            other => return Err(format!("invented prefix progress: {other:?}").into()),
        }
    }
    Err("incomplete prefix did not stop".into())
}
#[test]
fn duplicate_rtp_observations_are_not_coalesced_by_receiver_deduplication() -> Test {
    let path = fresh("duplicates")?;
    let mut input = observations(false)?;
    input.push(input.last().ok_or("missing observation")?.clone());
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let (pictures, originals) = run(&p, &a, 0)?;
    assert_eq!(originals.len(), 3);
    assert_eq!(originals[1], originals[2]);
    assert_eq!(pictures.len(), 1);
    Ok(())
}
#[test]
fn invalid_rtcp_is_preserved_without_failing_independent_video_reconstruction() -> Test {
    let path = fresh("rtcp")?;
    let mut input = observations(false)?;
    input.insert(1, (1, 10, vec![0, 0, 0]));
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let mut replay = DatagramAvcReplay::new(&a, spec()?, bounds(), 0)?;
    let mut invalid = 0;
    let mut images = Vec::new();
    for _ in 0..128 {
        match replay.step(&p, 0, &NeverCancel, &mut work())? {
            AvcReplayStep::Rtcp { source, validation } => {
                assert_eq!(source.payload(), &[0, 0, 0]);
                assert!(validation.is_err());
                invalid += 1;
            }
            AvcReplayStep::Media { event, .. } => pictures(event, &mut images),
            AvcReplayStep::Rtp { .. } => {}
            AvcReplayStep::PrefixExhausted { .. } => {
                assert_eq!(invalid, 1);
                assert_eq!(images.len(), 1);
                return Ok(());
            }
            other => return Err(format!("unexpected RTCP progress: {other:?}").into()),
        }
    }
    Err("RTCP fixture did not drain".into())
}
#[test]
fn malformed_rtp_returns_exact_refused_source_and_fences_reconstruction() -> Test {
    let path = fresh("malformed")?;
    let pin = save(&path, &[(0, 10, vec![0])])?;
    let (p, a) = reopen(&path, pin)?;
    let mut replay = DatagramAvcReplay::new(&a, spec()?, bounds(), 0)?;
    match replay.step(&p, 0, &NeverCancel, &mut work())? {
        AvcReplayStep::InputRefused { source, .. } => assert_eq!(source.payload(), &[0]),
        other => return Err(format!("malformed RTP accepted: {other:?}").into()),
    }
    assert!(matches!(
        replay.step(&p, 0, &NeverCancel, &mut work())?,
        AvcReplayStep::Ended
    ));
    Ok(())
}
#[test]
fn missing_configuration_and_changed_policies_cannot_reuse_an_interpretation() -> Test {
    let path = fresh("config")?;
    let pin = save(&path, &observations(false)?)?;
    let (_, a) = reopen(&path, pin)?;
    let original = DatagramAvcReplay::new(&a, spec()?, bounds(), 0)?.interpretation();
    let mut changed = spec()?;
    changed.reduced_rtcp = true;
    assert_ne!(
        DatagramAvcReplay::new(&a, changed, bounds(), 0)?.interpretation(),
        original
    );
    changed = spec()?;
    changed.configuration_evidence = ContentDigest::sha256(b"different accepted config");
    assert_ne!(
        DatagramAvcReplay::new(&a, changed, bounds(), 0)?.interpretation(),
        original
    );
    changed = spec()?;
    changed.limits.reorder.max_delay_ns += 1;
    assert_ne!(
        DatagramAvcReplay::new(&a, changed, bounds(), 0)?.interpretation(),
        original
    );
    changed = spec()?;
    changed.sps = &[];
    assert!(DatagramAvcReplay::new(&a, changed, bounds(), 0).is_err());
    assert!(
        DatagramAvcReplay::new(
            &a,
            spec()?,
            fss_reference::rtsp::datagram_reconstruction::AvcReplayBounds {
                max_source_bytes: 0,
                ..bounds()
            },
            0
        )
        .is_err()
    );
    Ok(())
}
struct Stop;
impl PublishCancellation for Stop {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}
#[test]
fn current_clock_regression_is_safe_but_cancellation_and_budget_errors_fence() -> Test {
    let path = fresh("admission")?;
    let pin = save(&path, &observations(false)?)?;
    let (p, a) = reopen(&path, pin)?;
    let mut replay = DatagramAvcReplay::new(&a, spec()?, bounds(), 100)?;
    let error = replay
        .step(&p, 99, &NeverCancel, &mut work())
        .err()
        .ok_or("regression accepted")?;
    assert!(matches!(error.reason, AvcReplayError::ClockReversed));
    assert!(error.retirement.is_none());
    assert!(matches!(
        replay.step(&p, 100, &NeverCancel, &mut work())?,
        AvcReplayStep::Rtp { .. }
    ));
    let error = replay
        .step(&p, 100, &Stop, &mut work())
        .err()
        .ok_or("cancel ignored")?;
    assert_eq!(
        error.retirement.ok_or("lost retirement")?.observations_read,
        1
    );
    let mut replay = DatagramAvcReplay::new(&a, spec()?, bounds(), 100)?;
    let error = replay
        .step(&p, 100, &NeverCancel, &mut WorkBudget::new(1))
        .err()
        .ok_or("budget ignored")?;
    assert!(matches!(
        error.reason,
        AvcReplayError::Source(DatagramArchiveError::Work(_))
    ));
    assert_eq!(
        error.retirement.ok_or("lost retirement")?.observations_read,
        0
    );
    Ok(())
}
#[test]
fn source_corruption_is_not_reported_as_an_exhausted_prefix() -> Test {
    let path = fresh("corrupt")?;
    let pin = save(&path, &observations(false)?)?;
    let (p, a) = reopen(&path, pin)?;
    let hex = a.records()[0]
        .payload_digest
        .to_text()
        .strip_prefix("sha256:")
        .ok_or("digest")?
        .to_owned();
    std::fs::write(
        p.root_dir().join("spool/objects").join(hex),
        b"corrupted source",
    )?;
    let mut replay = DatagramAvcReplay::new(&a, spec()?, bounds(), 0)?;
    assert!(replay.step(&p, 0, &NeverCancel, &mut work()).is_err());
    assert!(matches!(
        replay.step(&p, 0, &NeverCancel, &mut work())?,
        AvcReplayStep::Ended
    ));
    Ok(())
}
#[test]
fn empty_inventory_has_no_invented_source_or_picture() -> Test {
    let path = fresh("empty")?;
    let pin = save(&path, &[])?;
    let (p, a) = reopen(&path, pin)?;
    assert_eq!(run(&p, &a, 0)?, (vec![], vec![]));
    Ok(())
}
#[test]
fn finite_progress_and_absolute_deadline_cannot_be_renewed_by_polling() -> Test {
    let path = fresh("finite")?;
    let pin = save(&path, &observations(false)?)?;
    let (p, a) = reopen(&path, pin)?;
    let mut b = bounds();
    b.max_steps = 1;
    let mut replay = DatagramAvcReplay::new(&a, spec()?, b, 0)?;
    let _ = replay.step(&p, 0, &NeverCancel, &mut work())?;
    assert!(replay.step(&p, 0, &NeverCancel, &mut work()).is_err());
    b = bounds();
    b.deadline_ns = 10;
    let mut replay = DatagramAvcReplay::new(&a, spec()?, b, 0)?;
    let error = replay
        .step(&p, 10, &NeverCancel, &mut work())
        .err()
        .ok_or("deadline renewed")?;
    assert!(matches!(
        error.reason,
        AvcReplayError::Source(DatagramArchiveError::Deadline)
    ));
    Ok(())
}

#[test]
fn timer_advances_are_bounded_by_the_next_retained_arrival() -> Test {
    let path = fresh("timer")?;
    let s = spec()?;
    let input = vec![
        (0, 10, raw(1, 9000, false, s.sps)),
        (0, 11, raw(2, 9000, false, s.sps)),
        (0, 12, raw(4, 9000, false, s.sps)),
        (0, 200_000_020, raw(5, 9000, false, s.sps)),
    ];
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let mut replay = DatagramAvcReplay::new(&a, s, bounds(), 0)?;
    let mut wakes = 0;
    for _ in 0..256 {
        match replay.step(&p, 0, &NeverCancel, &mut work())? {
            AvcReplayStep::ClockAdvanced { replay_ns } => {
                assert!(replay_ns < input[3].1);
                assert_eq!(replay.observations_read(), 3);
                wakes += 1;
            }
            AvcReplayStep::PrefixExhausted { replay_ns, .. } => {
                assert_eq!(replay_ns, input[3].1);
                assert!(wakes > 0);
                return Ok(());
            }
            AvcReplayStep::Rtp { .. } | AvcReplayStep::Media { .. } => {}
            other => return Err(format!("unexpected timer result: {other:?}").into()),
        }
    }
    Err("timer replay did not terminate".into())
}
struct CountingStop {
    calls: std::cell::Cell<usize>,
    fail_at: usize,
}
impl PublishCancellation for CountingStop {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        let n = self.calls.get() + 1;
        self.calls.set(n);
        n >= self.fail_at
    }
}
#[test]
fn post_read_revocation_returns_the_withheld_original_not_a_successful_event() -> Test {
    let path = fresh("postcheck")?;
    let pin = save(&path, &observations(false)?)?;
    let (p, a) = reopen(&path, pin)?;
    let count = CountingStop {
        calls: std::cell::Cell::new(0),
        fail_at: usize::MAX,
    };
    let mut replay = DatagramAvcReplay::new(&a, spec()?, bounds(), 0)?;
    assert!(matches!(
        replay.step(&p, 0, &count, &mut work())?,
        AvcReplayStep::Rtp { .. }
    ));
    let revoke = CountingStop {
        calls: std::cell::Cell::new(0),
        fail_at: count.calls.get(),
    };
    let mut replay = DatagramAvcReplay::new(&a, spec()?, bounds(), 0)?;
    let failure = replay
        .step(&p, 0, &revoke, &mut work())
        .err()
        .ok_or("postcheck accepted")?;
    let retained = failure.retirement.ok_or("retirement missing")?;
    assert_eq!(retained.observations_read, 1);
    match *retained.withheld.ok_or("original lost")? {
        AvcReplayStep::Rtp { source, .. } => {
            assert_eq!(source.payload(), &observations(false)?[0].2)
        }
        other => return Err(format!("wrong withheld output: {other:?}").into()),
    }
    Ok(())
}
