#![forbid(unsafe_code)]
//! Actual cold HEVC source custody, native transport oracle and failure fencing.
mod hevc_datagram_support;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_packet::{H265ReceivePoll, H265Receiver};
use fss_publication::{NeverCancel, PublishCancellation, PublishCutPoint};
use fss_reference::rtsp::datagram_archive::DatagramArchiveError;
use fss_reference::rtsp::datagram_reconstruction::hevc::{
    DatagramHevcReplay, HevcReplayBounds, HevcReplayError, HevcReplayStep,
};
use hevc_datagram_support::*;

type ReplayResult = (Vec<H265ReceivePoll>, Vec<Vec<u8>>);
fn run(
    p: &fss_publication::LocalRootPublisher,
    a: &fss_reference::rtsp::datagram_archive::DatagramArchive,
    now: u64,
) -> Test<ReplayResult> {
    let mut replay = DatagramHevcReplay::new(a, spec(), bounds(), now)?;
    let mut events = Vec::new();
    let mut originals = Vec::new();
    let mut budget = work();
    for _ in 0..4096 {
        match replay.step(p, now, &NeverCancel, &mut budget)? {
            HevcReplayStep::Rtp {
                source,
                retired: None,
                ..
            } => originals.push(source.payload().to_vec()),
            HevcReplayStep::Media { event, .. } => events.push(event),
            HevcReplayStep::ClockAdvanced { .. } => {}
            HevcReplayStep::PrefixExhausted { source, .. } => {
                assert_eq!(source, a.pin());
                assert!(matches!(
                    replay.step(p, now, &NeverCancel, &mut budget)?,
                    HevcReplayStep::Ended
                ));
                return Ok((events, originals));
            }
            other => return Err(format!("unexpected clean step: {other:?}").into()),
        }
    }
    Err("replay bound".into())
}
#[test]
fn cold_replay_matches_native_receiver_including_fragmented_nal_provenance() -> Test {
    for fragmented in [false, true] {
        let path = fresh(if fragmented {
            "native-fu"
        } else {
            "native-single"
        })?;
        let input = observations(fragmented)?;
        let pin = save(&path, &input)?;
        let s = spec();
        let mut receiver = H265Receiver::new(
            KEY,
            s.payload_type,
            s.sprop_max_don_diff,
            s.reorder,
            s.reconstruction,
        )?;
        let mut expected = Vec::new();
        for (_, now, bytes) in &input {
            receiver.ingest(KEY, bytes, *now)?;
            let mut drained = false;
            for _ in 0..1024 {
                match receiver.poll(*now)? {
                    H265ReceivePoll::Pending { .. } => {
                        drained = true;
                        break;
                    }
                    event => expected.push(event),
                }
            }
            assert!(drained);
        }
        let nals: usize = expected
            .iter()
            .map(|e| match e {
                H265ReceivePoll::Packet {
                    reconstruction: Ok(out),
                    ..
                } => out.nals.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(nals, 1);
        drop(receiver);
        let (p, a) = reopen(&path, pin)?;
        let (actual, originals) = run(&p, &a, 1_000_000_000_000)?;
        assert_eq!(actual, expected);
        assert_eq!(
            originals,
            input.into_iter().map(|(_, _, b)| b).collect::<Vec<_>>()
        );
        assert_eq!(run(&p, &a, 0)?.0, actual);
        assert_eq!(
            DatagramHevcReplay::new(&a, s, bounds(), 0)?.interpretation(),
            DatagramHevcReplay::new(&a, s, bounds(), 1_000_000_000_000)?.interpretation()
        );
    }
    Ok(())
}
#[test]
fn truncated_fragment_prefix_is_not_finished_or_expired_into_a_complete_nal() -> Test {
    let path = fresh("partial-fu")?;
    let mut input = observations(true)?;
    input.pop();
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let mut replay = DatagramHevcReplay::new(&a, spec(), bounds(), 0)?;
    for _ in 0..128 {
        match replay.step(&p, 0, &NeverCancel, &mut work())? {
            HevcReplayStep::Media {
                event:
                    H265ReceivePoll::Packet {
                        reconstruction: Ok(out),
                        ..
                    },
                ..
            } => assert!(out.nals.is_empty()),
            HevcReplayStep::Rtp { .. } => {}
            HevcReplayStep::PrefixExhausted {
                replay_ns, retired, ..
            } => {
                assert_eq!(replay_ns, 11);
                assert!(retired.fragment.is_some());
                return Ok(());
            }
            other => return Err(format!("fabricated progress: {other:?}").into()),
        }
    }
    Err("prefix bound".into())
}
#[test]
fn duplicate_and_invalid_rtcp_originals_are_retained_without_weakening_video_parsing() -> Test {
    let path = fresh("rtcp-duplicate")?;
    let mut input = observations(false)?;
    input.insert(1, (1, 10, vec![0, 0, 0]));
    input.push(input.last().ok_or("source")?.clone());
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let mut replay = DatagramHevcReplay::new(&a, spec(), bounds(), 0)?;
    let mut rtp = Vec::new();
    let mut invalid = 0;
    let mut nals = 0;
    for _ in 0..128 {
        match replay.step(&p, 0, &NeverCancel, &mut work())? {
            HevcReplayStep::Rtcp { source, validation } => {
                assert_eq!(source.payload(), &[0, 0, 0]);
                assert!(validation.is_err());
                invalid += 1;
            }
            HevcReplayStep::Rtp { source, .. } => rtp.push(source.payload().to_vec()),
            HevcReplayStep::Media {
                event:
                    H265ReceivePoll::Packet {
                        reconstruction: Ok(out),
                        ..
                    },
                ..
            } => nals += out.nals.len(),
            HevcReplayStep::PrefixExhausted { .. } => {
                assert_eq!((rtp.len(), invalid, nals), (3, 1, 1));
                assert_eq!(rtp[1], rtp[2]);
                return Ok(());
            }
            other => return Err(format!("unexpected: {other:?}").into()),
        }
    }
    Err("RTCP bound".into())
}
#[test]
fn malformed_rtp_fences_without_losing_the_original_or_consuming_the_successor() -> Test {
    let path = fresh("malformed")?;
    let mut input = observations(false)?;
    input.insert(0, (0, 9, vec![0]));
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let mut replay = DatagramHevcReplay::new(&a, spec(), bounds(), 0)?;
    assert!(
        matches!(replay.step(&p, 0, &NeverCancel, &mut work())?, HevcReplayStep::InputRefused { source, .. } if source.payload() == [0])
    );
    assert_eq!(replay.observations_read(), 1);
    assert!(matches!(
        replay.step(&p, 0, &NeverCancel, &mut work())?,
        HevcReplayStep::Ended
    ));
    Ok(())
}
#[test]
fn transport_interpretation_binds_all_native_limits_and_never_downgrades_don() -> Test {
    let path = fresh("interpretation")?;
    let pin = save(&path, &observations(false)?)?;
    let (_, a) = reopen(&path, pin)?;
    let base = DatagramHevcReplay::new(&a, spec(), bounds(), 0)?.interpretation();
    let mut variants = Vec::new();
    macro_rules! changed { ($($field:ident).+,$value:expr) => {{ let mut s=spec(); s$(.$field)+ = $value; variants.push(s); }}; }
    changed!(payload_type, 99);
    changed!(reduced_rtcp, true);
    changed!(
        configuration_evidence,
        ContentDigest::sha256(b"other evidence")
    );
    changed!(reorder.packet.max_packet_bytes, 32768);
    changed!(reorder.packet.max_extension_bytes, 1024);
    changed!(reorder.packet.max_rtcp_packets, 16);
    changed!(reorder.max_packets, 32);
    changed!(reorder.max_bytes, 1_000_000);
    changed!(reorder.max_delay_ns, 100_000);
    changed!(reconstruction.max_nal_bytes, 1_000_000);
    changed!(reconstruction.max_packet_nals, 8);
    changed!(reconstruction.max_fragment_packets, 64);
    changed!(reconstruction.max_pending_age_ns, 100_000);
    for s in variants {
        assert_ne!(
            DatagramHevcReplay::new(&a, s, bounds(), 0)?.interpretation(),
            base
        );
    }
    let mut s = spec();
    s.sprop_max_don_diff = 1;
    assert!(DatagramHevcReplay::new(&a, s, bounds(), 0).is_err());
    s = spec();
    s.configuration_evidence = ContentDigest::sha256(b"nonzero");
    assert!(
        DatagramHevcReplay::new(
            &a,
            s,
            HevcReplayBounds {
                max_steps: 0,
                ..bounds()
            },
            0
        )
        .is_err()
    );
    assert!(
        DatagramHevcReplay::new(
            &a,
            s,
            HevcReplayBounds {
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
    let mut replay = DatagramHevcReplay::new(&a, spec(), bounds(), 100)?;
    let error = replay
        .step(&p, 99, &NeverCancel, &mut work())
        .err()
        .ok_or("regression accepted")?;
    assert!(matches!(error.reason, HevcReplayError::ClockReversed));
    assert!(error.retirement.is_none());
    assert!(matches!(
        replay.step(&p, 100, &NeverCancel, &mut work())?,
        HevcReplayStep::Rtp { .. }
    ));
    let error = replay
        .step(&p, 100, &Stop, &mut work())
        .err()
        .ok_or("cancel ignored")?;
    assert_eq!(
        error.retirement.ok_or("lost retirement")?.observations_read,
        1
    );
    let mut replay = DatagramHevcReplay::new(&a, spec(), bounds(), 100)?;
    let error = replay
        .step(&p, 100, &NeverCancel, &mut WorkBudget::new(1))
        .err()
        .ok_or("budget ignored")?;
    assert!(matches!(
        error.reason,
        HevcReplayError::Source(DatagramArchiveError::Work(_))
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
    let mut replay = DatagramHevcReplay::new(&a, spec(), bounds(), 0)?;
    assert!(replay.step(&p, 0, &NeverCancel, &mut work()).is_err());
    assert!(matches!(
        replay.step(&p, 0, &NeverCancel, &mut work())?,
        HevcReplayStep::Ended
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
    let mut replay = DatagramHevcReplay::new(&a, spec(), b, 0)?;
    let _ = replay.step(&p, 0, &NeverCancel, &mut work())?;
    assert!(replay.step(&p, 0, &NeverCancel, &mut work()).is_err());
    b = bounds();
    b.deadline_ns = 10;
    let mut replay = DatagramHevcReplay::new(&a, spec(), b, 0)?;
    let error = replay
        .step(&p, 10, &NeverCancel, &mut work())
        .err()
        .ok_or("deadline renewed")?;
    assert!(matches!(
        error.reason,
        HevcReplayError::Source(DatagramArchiveError::Deadline)
    ));
    Ok(())
}

#[test]
fn timer_advances_are_bounded_by_the_next_retained_arrival() -> Test {
    let path = fresh("timer")?;
    let s = spec();
    let input = vec![
        (0, 10, raw(1, 9000, false, &[0x40, 1, 0x80])),
        (0, 11, raw(2, 9000, false, &[0x40, 1, 0x80])),
        (0, 12, raw(4, 9000, false, &[0x40, 1, 0x80])),
        (0, 200_000_020, raw(5, 9000, false, &[0x40, 1, 0x80])),
    ];
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let mut replay = DatagramHevcReplay::new(&a, s, bounds(), 0)?;
    let mut wakes = 0;
    for _ in 0..256 {
        match replay.step(&p, 0, &NeverCancel, &mut work())? {
            HevcReplayStep::ClockAdvanced { replay_ns } => {
                assert!(replay_ns < input[3].1);
                assert_eq!(replay.observations_read(), 3);
                wakes += 1;
            }
            HevcReplayStep::PrefixExhausted { replay_ns, .. } => {
                assert_eq!(replay_ns, input[3].1);
                assert!(wakes > 0);
                return Ok(());
            }
            HevcReplayStep::Rtp { .. } | HevcReplayStep::Media { .. } => {}
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
    let mut replay = DatagramHevcReplay::new(&a, spec(), bounds(), 0)?;
    assert!(matches!(
        replay.step(&p, 0, &count, &mut work())?,
        HevcReplayStep::Rtp { .. }
    ));
    let revoke = CountingStop {
        calls: std::cell::Cell::new(0),
        fail_at: count.calls.get(),
    };
    let mut replay = DatagramHevcReplay::new(&a, spec(), bounds(), 0)?;
    let failure = replay
        .step(&p, 0, &revoke, &mut work())
        .err()
        .ok_or("postcheck accepted")?;
    let retained = failure.retirement.ok_or("retirement missing")?;
    assert_eq!(retained.observations_read, 1);
    match *retained.withheld.ok_or("original lost")? {
        HevcReplayStep::Rtp { source, .. } => {
            assert_eq!(source.payload(), &observations(false)?[0].2)
        }
        other => return Err(format!("wrong withheld output: {other:?}").into()),
    }
    Ok(())
}
