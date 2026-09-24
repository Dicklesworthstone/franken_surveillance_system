#![forbid(unsafe_code)]
//! Cold exact source -> explicit timing -> native recording -> same-owner publication.
mod datagram_reconstruction_support;
use datagram_reconstruction_support::*;
use fss_container::TimedAvcPicture;
use fss_core::{ContentDigest, SensorId, StreamId};
use fss_packet::avc::{AvcAssemblyStep, AvcReceivePoll, AvcReceiver, parse_pps, parse_sps};
use fss_publication::{LocalRootPublisher, NeverCancel, PublishCancellation, PublishCutPoint, SlotName};
use fss_reference::rtsp::datagram_archive::DatagramArchive;
use fss_reference::rtsp::datagram_reconstruction::{AvcReplayError, AvcReplayStep};
use fss_reference::rtsp::datagram_reconstruction::recording::{DatagramRecordingReplay,
    RecordingReplayError, RecordingReplaySpec, RecordingReplayStep, RecordingReplayStop};
use fss_reference::rtsp::recording::{PreparedRecording, RecordingPacket, RecordingScope, prepare_recording};
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication, load_recording};
use fss_reference::rtsp::recording_capture::{CapturePoll, PictureTimingRequest, TimedCapture};
use fss_reference::rtsp::recording_collector::{CollectorLimits, RecordingTiming};

fn recording_spec() -> Test<RecordingReplaySpec> {
    Ok(RecordingReplaySpec { scope: RecordingScope {
        sensor: SensorId::parse("sensor:reconstruction")?, stream: StreamId::parse("video:reconstruction")?,
        generation: source::KEY.generation, anchor: ContentDigest::sha256(b"accepted authority/history anchor"),
        receive_clock: scope()?.receive_clock,
    }, time_scale: 90_000, limits: CollectorLimits::default(),
        timing_evidence: ContentDigest::sha256(b"owner accepted explicit decode-clock decisions") })
}
fn timing() -> RecordingTiming { RecordingTiming { decode_time: 700, duration: 3600, composition_offset: 0 } }
fn await_timing(r: &mut DatagramRecordingReplay<'_>, p: &LocalRootPublisher, now: u64) -> Test<PictureTimingRequest> {
    for _ in 0..256 {
        match r.step(p, now, &NeverCancel, &mut work())? {
            RecordingReplayStep::Capture(event) => match *event {
                CapturePoll::TimingRequired(request) => return Ok(request),
                CapturePoll::Receiver(_) => {},
                other => return Err(format!("unexpected pre-timing output: {:?}",
                    RecordingReplayStep::Capture(Box::new(other))).into()),
            },
            RecordingReplayStep::Source(_) | RecordingReplayStep::MediaQueued => {},
            other => return Err(format!("unexpected pre-timing output: {other:?}").into()),
        }
    }
    Err("picture timing request did not arrive".into())
}
fn completed(p: &LocalRootPublisher, a: &DatagramArchive, now: u64) -> Test<PreparedRecording> {
    let mut r = DatagramRecordingReplay::new(a, spec()?, recording_spec()?, bounds(), now)?;
    let mut output = None;
    for _ in 0..256 {
        match r.step(p, now, &NeverCancel, &mut work())? {
            RecordingReplayStep::Capture(event) => match *event {
                CapturePoll::TimingRequired(_) => {
                    assert!(matches!(r.supply_timing(timing(), now, &NeverCancel, &mut work())?, TimedCapture::Collected { .. }));
                }
                CapturePoll::Window(window) => { assert!(output.is_none()); output = Some(window); },
                CapturePoll::Receiver(_) => {},
                other => return Err(format!("unexpected reconstruction output: {:?}",
                    RecordingReplayStep::Capture(Box::new(other))).into()),
            },
            RecordingReplayStep::PrefixReady { .. } => r.finish_prefix(now, &NeverCancel, &mut work())?,
            RecordingReplayStep::FinishedPrefix { retained } => {
                assert!(matches!(retained.prefix.as_deref(), Some(AvcReplayStep::PrefixExhausted { .. })));
                assert!(matches!(r.step(p, now, &NeverCancel, &mut work())?, RecordingReplayStep::Ended));
                return output.ok_or_else(|| "completed picture was not prepared".into());
            }
            RecordingReplayStep::Source(_) | RecordingReplayStep::MediaQueued => {},
            other => return Err(format!("unexpected reconstruction output: {other:?}").into()),
        }
    }
    Err("recording did not complete bounded prefix drain".into())
}
fn direct_expected(input: &[(u8, u64, Vec<u8>)]) -> Test<PreparedRecording> {
    let s = spec()?; let sps = parse_sps(s.sps, s.limits.syntax)?;
    let pps = parse_pps(s.pps, &sps, s.limits.syntax)?;
    let mut receiver = AvcReceiver::new(source::KEY, s.payload_type, s.mode, s.limits, (sps, pps))?;
    let mut pictures = Vec::new();
    for (_, now, bytes) in input {
        let _ = receiver.ingest(source::KEY, bytes, *now)?;
        let mut yielded = false;
        for _ in 0..1024 {
            match receiver.poll(*now)? {
                AvcReceivePoll::Picture(p) => pictures.push(p),
                AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(out)) => {
                    if let Some(p) = out.picture { pictures.push(p); }
                }
                AvcReceivePoll::Pending { .. } => { yielded = true; break; },
                _ => {},
            }
        }
        assert!(yielded);
    }
    assert_eq!(pictures.len(), 1);
    let t = timing();
    let timed = [TimedAvcPicture { picture: &pictures[0], decode_time: t.decode_time,
        duration: t.duration, composition_offset: t.composition_offset }];
    // Sequence one was probation; the exact completed picture uses sequences two onward.
    let packets: Vec<_> = input.iter().enumerate().skip(1).map(|(i, (_, now, bytes))| RecordingPacket {
        sequence: i as u64 + 1, received_ns: *now, bytes,
    }).collect();
    let s = recording_spec()?;
    Ok(prepare_recording(s.scope, s.time_scale, &timed, &packets)?)
}

#[test]
fn cold_datagrams_become_identical_canonical_media_and_publish_with_the_same_owner() -> Test {
    let path = fresh("recording_cold")?; let input = observations(true)?;
    let pin = save(&path, &input)?;
    let expected = direct_expected(&input)?;
    let root = {
        let (mut p, a) = reopen(&path, pin)?;
        let window = completed(&p, &a, 1_000_000_000_000)?;
        assert_eq!(window.manifest(), expected.manifest());
        assert_eq!(window.objects().source, expected.objects().source);
        assert_eq!(window.objects().media, expected.objects().media);
        assert_eq!(window.objects().index, expected.objects().index);
        let root = window.manifest().root();
        let mut job = RecordingPublication::new(&window, &mut p, SlotName::parse("reconstructed-window")?,
            window.byte_len(), u64::MAX)?;
        let mut published = false;
        for _ in 0..5 {
            if let RecordingProgress::Published(receipt) = job.step(1_000_000_000_001, &NeverCancel)? {
                assert_eq!(receipt.root, root);
                assert_eq!(receipt.claims.local, fss_publication::LocalPublicationState::Durable);
                published = true; break;
            }
        }
        assert!(published); root
    };
    let p = LocalRootPublisher::open(&path, storage())?;
    let loaded = load_recording(&p, &SlotName::parse("reconstructed-window")?, root,
        &recording_spec()?.scope, &NeverCancel)?;
    assert_eq!(loaded.objects().media, expected.objects().media);
    assert_eq!(loaded.objects().source, expected.objects().source); Ok(())
}
#[test]
fn storage_admission_time_does_not_change_reconstructed_media_identity() -> Test {
    let path = fresh("recording_clocks")?; let pin = save(&path, &observations(false)?)?;
    let (p, a) = reopen(&path, pin)?;
    assert_eq!(completed(&p, &a, 1000)?.manifest().root(), completed(&p, &a, 9_000_000_000_000)?.manifest().root());
    Ok(())
}
#[test]
fn missing_timing_blocks_the_next_original_read_and_preserves_the_same_request() -> Test {
    let path = fresh("recording_wait")?; let mut input = observations(false)?;
    input.push((1, 12, vec![0, 0, 0]));
    let pin = save(&path, &input)?; let (p, a) = reopen(&path, pin)?;
    let mut r = DatagramRecordingReplay::new(&a, spec()?, recording_spec()?, bounds(), 1000)?;
    let request = await_timing(&mut r, &p, 1000)?;
    assert_eq!(r.observations_read(), 2);
    for _ in 0..8 {
        match r.step(&p, 1000, &NeverCancel, &mut work())? {
            RecordingReplayStep::Capture(event) if matches!(*event, CapturePoll::TimingRequired(_)) => {
                let CapturePoll::TimingRequired(same) = *event else { return Err("timing request lost".into()); };
                assert_eq!(same, request);
            }
            other => return Err(format!("read-ahead while timing pending: {other:?}").into()),
        }
        assert_eq!(r.observations_read(), 2);
    }
    let _ = r.supply_timing(timing(), 1000, &NeverCancel, &mut work())?;
    for _ in 0..32 {
        let _ = r.step(&p, 1000, &NeverCancel, &mut work())?;
        if r.observations_read() == 3 { return Ok(()); }
    }
    Err("corrected timing did not release pressure".into())
}
#[test]
fn invalid_timing_is_correctable_without_losing_or_replacing_the_picture() -> Test {
    let path = fresh("recording_timing")?; let pin = save(&path, &observations(false)?)?;
    let (p, a) = reopen(&path, pin)?;
    let mut r = DatagramRecordingReplay::new(&a, spec()?, recording_spec()?, bounds(), 1000)?;
    let request = await_timing(&mut r, &p, 1000)?;
    let error = r.supply_timing(RecordingTiming { duration: 0, ..timing() }, 1000,
        &NeverCancel, &mut work()).err().ok_or("invalid timing accepted")?;
    assert!(error.retirement.is_none());
    assert_eq!(await_timing(&mut r, &p, 1000)?, request);
    let _ = r.supply_timing(timing(), 1000, &NeverCancel, &mut work())?;
    assert!(r.seal(1000, &NeverCancel, &mut work())?);
    match r.step(&p, 1000, &NeverCancel, &mut work())? {
        RecordingReplayStep::Capture(event) if matches!(*event, CapturePoll::Window(_)) => {
            let CapturePoll::Window(window) = *event else { return Err("corrected window unavailable".into()); };
            assert_eq!(window.manifest().root(), completed(&p, &a, 1000)?.manifest().root());
        }
        other => return Err(format!("corrected window unavailable: {other:?}").into()),
    }
    Ok(())
}
#[test]
fn incomplete_fragment_finishes_only_the_selected_prefix_not_a_recording() -> Test {
    let path = fresh("recording_partial")?; let mut input = observations(true)?; let _ = input.pop();
    let pin = save(&path, &input)?; let (p, a) = reopen(&path, pin)?;
    let mut r = DatagramRecordingReplay::new(&a, spec()?, recording_spec()?, bounds(), 1000)?;
    for _ in 0..128 {
        match r.step(&p, 1000, &NeverCancel, &mut work())? {
            RecordingReplayStep::PrefixReady { .. } => r.finish_prefix(1000, &NeverCancel, &mut work())?,
            RecordingReplayStep::FinishedPrefix { retained } => {
                let c = retained.capture.ok_or("capture retirement lost")?;
                assert!(c.collection.ready.is_none()); assert!(c.collection.pending.pictures.is_empty());
                assert_eq!(c.collection.pending.sources.len(), 1);
                assert!(matches!(retained.prefix.as_deref(), Some(AvcReplayStep::PrefixExhausted { replay_ns: 11, .. })));
                return Ok(());
            }
            RecordingReplayStep::Source(_) | RecordingReplayStep::MediaQueued => {},
            RecordingReplayStep::Capture(event) if matches!(*event, CapturePoll::Receiver(_)) => {},
            other => return Err(format!("partial fragment became recording output: {other:?}").into()),
        }
    }
    Err("incomplete recording prefix did not terminate".into())
}
#[test]
fn unmarked_final_picture_is_retired_not_finished_into_an_invented_window() -> Test {
    let path = fresh("recording_unmarked")?; let mut input = observations(false)?; input[1].2[1] &= 127;
    let pin = save(&path, &input)?; let (p, a) = reopen(&path, pin)?;
    let mut r = DatagramRecordingReplay::new(&a, spec()?, recording_spec()?, bounds(), 1000)?;
    for _ in 0..128 {
        match r.step(&p, 1000, &NeverCancel, &mut work())? {
            RecordingReplayStep::PrefixReady { .. } => r.finish_prefix(1000, &NeverCancel, &mut work())?,
            RecordingReplayStep::FinishedPrefix { retained } => {
                match *retained.prefix.ok_or("prefix lost")? {
                    AvcReplayStep::PrefixExhausted { retired, .. } => assert!(retired.picture.is_some()),
                    other => return Err(format!("wrong prefix ending: {other:?}").into()),
                }
                assert!(retained.capture.ok_or("capture")?.collection.ready.is_none()); return Ok(());
            }
            RecordingReplayStep::Source(_) | RecordingReplayStep::MediaQueued => {},
            RecordingReplayStep::Capture(event) if matches!(*event, CapturePoll::Receiver(_)) => {},
            other => return Err(format!("unmarked tail became completed picture: {other:?}").into()),
        }
    }
    Err("unmarked prefix did not terminate".into())
}
#[test]
fn an_observed_gap_stops_collection_and_returns_prior_unsealed_work() -> Test {
    let path = fresh("recording_gap")?; let mut input = observations(false)?; let s = spec()?;
    input.extend([(0, 12, raw(4, 18000, false, s.sps)), (0, 200_000_020, raw(5, 18000, false, s.sps))]);
    let pin = save(&path, &input)?; let (p, a) = reopen(&path, pin)?;
    let mut r = DatagramRecordingReplay::new(&a, s, recording_spec()?, bounds(), 1000)?;
    for _ in 0..256 {
        match r.step(&p, 1000, &NeverCancel, &mut work())? {
            RecordingReplayStep::Capture(event) if matches!(*event, CapturePoll::TimingRequired(_)) => {
                let _ = r.supply_timing(timing(), 1000, &NeverCancel, &mut work())?;
            },
            RecordingReplayStep::Stopped { trigger: RecordingReplayStop::Collection(event), retained } => {
                assert!(retained.replay.is_some());
                match *event {
                    CapturePoll::Stopped { retained, .. } => {
                        assert_eq!(retained.collection.pending.pictures.len(), 1);
                        assert!(retained.collection.ready.is_none()); return Ok(());
                    }
                    _ => return Err("missing original collection stop".into()),
                }
            }
            RecordingReplayStep::Source(_) | RecordingReplayStep::MediaQueued => {},
            RecordingReplayStep::Capture(event) if matches!(*event, CapturePoll::Receiver(_)) => {},
            other => return Err(format!("gap silently finalized a window: {other:?}").into()),
        }
    }
    Err("gap was not surfaced".into())
}
#[test]
fn collection_pressure_retains_the_unconsumed_source_and_blocks_read_ahead() -> Test {
    let path = fresh("recording_pressure")?; let pin = save(&path, &observations(false)?)?;
    let (p, a) = reopen(&path, pin)?; let mut rs = recording_spec()?; rs.limits.max_source_bytes = 12;
    let mut r = DatagramRecordingReplay::new(&a, spec()?, rs, bounds(), 1000)?;
    for _ in 0..128 {
        match r.step(&p, 1000, &NeverCancel, &mut work())? {
            RecordingReplayStep::Capture(event) if matches!(*event, CapturePoll::Backpressure(_)) => {
                let read = r.observations_read();
                assert!(matches!(r.step(&p, 1000, &NeverCancel, &mut work())?,
                    RecordingReplayStep::Capture(event) if matches!(*event, CapturePoll::Backpressure(_))));
                assert_eq!(r.observations_read(), read);
                assert!(r.cancel().ok_or("retirement")?.capture.ok_or("capture")?.event.is_some()); return Ok(());
            }
            RecordingReplayStep::Source(_) | RecordingReplayStep::MediaQueued => {},
            other => return Err(format!("unexpected pressure output: {other:?}").into()),
        }
    }
    Err("small collector did not report pressure".into())
}
struct StopAt(std::cell::Cell<usize>);
impl PublishCancellation for StopAt {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        let n = self.0.get(); self.0.set(n.saturating_sub(1)); n <= 1
    }
}
#[test]
fn cancellation_after_window_extraction_keeps_the_entire_prepared_recording() -> Test {
    let path = fresh("recording_withheld")?; let pin = save(&path, &observations(false)?)?;
    let (p, a) = reopen(&path, pin)?;
    let mut r = DatagramRecordingReplay::new(&a, spec()?, recording_spec()?, bounds(), 1000)?;
    await_timing(&mut r, &p, 1000)?;
    let _ = r.supply_timing(timing(), 1000, &NeverCancel, &mut work())?;
    assert!(r.seal(1000, &NeverCancel, &mut work())?);
    let failure = r.step(&p, 1000, &StopAt(std::cell::Cell::new(2)), &mut work())
        .err().ok_or("post-window cancellation ignored")?;
    let retired = failure.retirement.ok_or("retirement missing")?;
    match *retired.withheld.ok_or("prepared recording lost")? {
        RecordingReplayStep::Capture(event) if matches!(*event, CapturePoll::Window(_)) => {
            let CapturePoll::Window(window) = *event else { return Err("wrong withheld result".into()); };
            assert_eq!(window.manifest().root(), completed(&p, &a, 1000)?.manifest().root());
        }
        other => return Err(format!("wrong withheld result: {other:?}").into()),
    }
    Ok(())
}
#[test]
fn cancellation_after_timing_admission_keeps_its_outcome_and_completed_picture() -> Test {
    let path = fresh("recording_timing_cancel")?; let pin = save(&path, &observations(false)?)?;
    let (p, a) = reopen(&path, pin)?;
    let mut r = DatagramRecordingReplay::new(&a, spec()?, recording_spec()?, bounds(), 1000)?;
    await_timing(&mut r, &p, 1000)?;
    let failure = r.supply_timing(timing(), 1000, &StopAt(std::cell::Cell::new(2)), &mut work())
        .err().ok_or("timing cancellation ignored")?;
    let retired = failure.retirement.ok_or("retirement")?;
    assert!(retired.withheld_timing.is_some());
    assert_eq!(retired.capture.ok_or("capture")?.collection.pending.pictures.len(), 1); Ok(())
}
#[test]
fn prefix_finish_cannot_bypass_unread_input_or_renew_expired_timing() -> Test {
    let path = fresh("recording_lease")?; let pin = save(&path, &observations(false)?)?;
    let (p, a) = reopen(&path, pin)?; let mut b = bounds(); b.deadline_ns = 2000;
    let mut r = DatagramRecordingReplay::new(&a, spec()?, recording_spec()?, b, 1000)?;
    let failure = r.finish_prefix(1000, &NeverCancel, &mut work()).err().ok_or("early finish accepted")?;
    assert!(matches!(failure.reason, RecordingReplayError::PrefixNotReady)); assert!(failure.retirement.is_none());
    await_timing(&mut r, &p, 1000)?;
    let failure = r.supply_timing(timing(), 2000, &NeverCancel, &mut work()).err().ok_or("lease renewed")?;
    assert!(failure.retirement.ok_or("retirement")?.capture.ok_or("capture")?.picture.is_some()); Ok(())
}
#[test]
fn recording_scope_and_timing_policy_are_bound_before_reconstruction() -> Test {
    let path = fresh("recording_scope")?; let pin = save(&path, &observations(false)?)?;
    let (_, a) = reopen(&path, pin)?;
    let original = DatagramRecordingReplay::new(&a, spec()?, recording_spec()?, bounds(), 1000)?.interpretation();
    let mut rs = recording_spec()?; rs.timing_evidence = ContentDigest::sha256(b"different media-clock evidence");
    assert_ne!(DatagramRecordingReplay::new(&a, spec()?, rs, bounds(), 1000)?.interpretation(), original);
    let mut rs = recording_spec()?; rs.limits.max_samples -= 1;
    assert_ne!(DatagramRecordingReplay::new(&a, spec()?, rs, bounds(), 1000)?.interpretation(), original);
    let mut rs = recording_spec()?; rs.scope.receive_clock = ContentDigest::sha256(b"wrong receive clock");
    assert!(DatagramRecordingReplay::new(&a, spec()?, rs, bounds(), 1000).is_err());
    let mut rs = recording_spec()?; rs.scope.generation += 1;
    assert!(DatagramRecordingReplay::new(&a, spec()?, rs, bounds(), 1000).is_err()); Ok(())
}
#[test]
fn clock_regression_preserves_pending_timing_for_a_corrected_call() -> Test {
    let path = fresh("recording_clock_refusal")?; let pin = save(&path, &observations(false)?)?;
    let (p, a) = reopen(&path, pin)?;
    let mut r = DatagramRecordingReplay::new(&a, spec()?, recording_spec()?, bounds(), 1000)?;
    let request = await_timing(&mut r, &p, 1000)?;
    let failure = r.supply_timing(timing(), 999, &NeverCancel, &mut work()).err().ok_or("backwards clock accepted")?;
    assert!(matches!(failure.reason, RecordingReplayError::Replay(AvcReplayError::ClockReversed)));
    assert!(failure.retirement.is_none()); assert_eq!(await_timing(&mut r, &p, 1000)?, request); Ok(())
}
