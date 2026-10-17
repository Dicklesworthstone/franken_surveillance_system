#![forbid(unsafe_code)]
//! Cold retained HEVC -> real boundary grouping -> explicit timing -> original-source proof.
mod hevc_datagram_support;
use fss_core::ContentDigest;
use fss_packet::hevc::HevcAssemblyLimits;
use fss_publication::{
    LocalRootPublisher, NeverCancel, PublishCancellation, PublishCutPoint, SlotName,
};
use fss_reference::rtsp::datagram_archive::DatagramArchive;
use fss_reference::rtsp::datagram_reconstruction::hevc::recording::*;
use fss_reference::rtsp::datagram_reconstruction::hevc::{HevcReplayError, HevcReplayStep};
use fss_reference::rtsp::hevc_recording_capture::{HevcCapturePoll, HevcPictureTimingRequest};
use fss_reference::rtsp::hevc_recording_collector::HevcCollectionAdmission;
use fss_reference::rtsp::recording::hevc::{
    HevcRecordingTiming, PreparedHevcRecording, local::load_hevc_recording, prepare_hevc_recording,
};
use fss_reference::rtsp::recording::{
    RecordingPacket,
    local::{RecordingProgress, RecordingPublication},
};
use fss_reference::rtsp::recording_collector::CollectorLimits;
use hevc_datagram_support::*;

fn recording() -> Test<HevcRecordingReplaySpec> {
    Ok(HevcRecordingReplaySpec {
        scope: media::scope()?,
        configuration: media::configuration()?,
        time_scale: 90_000,
        limits: CollectorLimits::default(),
        assembly: HevcAssemblyLimits::default(),
        timing_evidence: ContentDigest::sha256(b"independent per-picture decode clock evidence"),
    })
}
fn timing(i: u64) -> HevcRecordingTiming {
    HevcRecordingTiming {
        decode_time: i * 18_000,
        duration: 18_000,
        composition_offset: 0,
    }
}
fn input(fragmented: bool) -> Test<Vec<Observation>> {
    let mut input = observations(fragmented)?;
    let n = media::nals()?;
    let idr = n
        .iter()
        .find(|n| matches!((n[0] >> 1) & 63, 19 | 20))
        .ok_or("IDR")?;
    let seq = input.len() as u64 + 1;
    input.push((0, 10 + seq - 1, raw(seq, 27_000, true, idr)));
    Ok(input)
}
fn await_timing(
    r: &mut DatagramHevcRecordingReplay<'_>,
    p: &LocalRootPublisher,
    now: u64,
) -> Test<HevcPictureTimingRequest> {
    for _ in 0..512 {
        match r.step(p, now, &NeverCancel, &mut work())? {
            HevcRecordingReplayStep::Capture(event) => match *event {
                HevcCapturePoll::TimingRequired(request) => return Ok(request),
                HevcCapturePoll::Receiver(_) => {}
                other => return Err(format!("unexpected before timing: {other:?}").into()),
            },
            HevcRecordingReplayStep::Source(_) | HevcRecordingReplayStep::MediaQueued => {}
            other => return Err(format!("timing not observed: {other:?}").into()),
        }
    }
    Err("timing bound".into())
}
fn complete(
    p: &LocalRootPublisher,
    a: &DatagramArchive,
    now: u64,
) -> Test<(Vec<PreparedHevcRecording>, HevcRecordingReplayRetirement)> {
    let mut r = DatagramHevcRecordingReplay::new(a, spec(), recording()?, bounds(), now)?;
    let mut windows = Vec::new();
    let mut count = 0;
    let mut budget = work();
    for _ in 0..1024 {
        match r.step(p, now, &NeverCancel, &mut budget)? {
            HevcRecordingReplayStep::Capture(event) => match *event {
                HevcCapturePoll::TimingRequired(_) => {
                    let timed = r.supply_timing(timing(count), now, &NeverCancel, &mut budget)?;
                    assert!(matches!(
                        timed.admission,
                        HevcCollectionAdmission::Accepted { .. }
                    ));
                    count += 1;
                }
                HevcCapturePoll::Window(window) => windows.push(*window),
                HevcCapturePoll::Receiver(_) => {}
                other => return Err(format!("unexpected capture: {other:?}").into()),
            },
            HevcRecordingReplayStep::PrefixReady { .. } => {
                let _ = r.finish_prefix(now, &NeverCancel, &mut budget)?;
            }
            HevcRecordingReplayStep::FinishedPrefix { retained } => {
                assert_eq!(
                    windows.iter().map(|w| w.samples().len()).sum::<usize>(),
                    count as usize
                );
                assert!(matches!(
                    r.step(p, now, &NeverCancel, &mut budget)?,
                    HevcRecordingReplayStep::Ended
                ));
                assert!(r.cancel().is_none());
                return Ok((windows, *retained));
            }
            HevcRecordingReplayStep::Source(_) | HevcRecordingReplayStep::MediaQueued => {}
            other => return Err(format!("unexpected replay: {other:?}").into()),
        }
    }
    Err("completion bound".into())
}
#[test]
fn cold_hevc_prefix_reproduces_native_recording_and_publishes_with_source_owner() -> Test {
    for fragmented in [false, true] {
        let path = fresh(if fragmented {
            "recording-cold-fu"
        } else {
            "recording-cold-single"
        })?;
        let input = input(fragmented)?;
        let pin = save(&path, &input)?;
        let packets: Vec<_> = input
            .iter()
            .enumerate()
            .skip(1)
            .map(|(i, (_, time, bytes))| RecordingPacket {
                sequence: i as u64 + 1,
                received_ns: *time,
                bytes,
            })
            .collect();
        let expected = prepare_hevc_recording(
            media::scope()?,
            &media::configuration()?,
            90_000,
            &[timing(0)],
            &packets,
        )?;
        let root = {
            let (mut p, a) = reopen(&path, pin)?;
            let (mut windows, retired) = complete(&p, &a, 1_000_000_000_000)?;
            assert_eq!(windows.len(), 1);
            let window = windows.pop().ok_or("window")?;
            assert_eq!(window.manifest(), expected.manifest());
            assert_eq!(window.objects().source, expected.objects().source);
            assert_eq!(window.objects().media, expected.objects().media);
            assert_eq!(window.objects().index, expected.objects().index);
            assert_eq!(window.source_only_nals(), 1);
            assert!(
                retired.assembly.is_some(),
                "the witness belongs to an incomplete next group"
            );
            assert_eq!(retired.boundary, Some(HevcReplayBoundary::RetainedPrefix));
            assert!(matches!(
                retired.held_source.as_deref(),
                Some(HevcReplayStep::PrefixExhausted { .. })
            ));
            let root = window.manifest().root();
            let mut job = RecordingPublication::new(
                window.publication_plan(),
                &mut p,
                SlotName::parse("cold-hevc-window")?,
                window.byte_len(),
                u64::MAX,
            )?;
            let mut published = false;
            for _ in 0..8 {
                if let RecordingProgress::Published(receipt) =
                    job.step(1_000_000_000_001, &NeverCancel)?
                {
                    assert_eq!(receipt.root, root);
                    published = true;
                    break;
                }
            }
            assert!(published);
            root
        };
        let p = LocalRootPublisher::open(&path, storage())?;
        let loaded = load_hevc_recording(
            &p,
            &SlotName::parse("cold-hevc-window")?,
            root,
            &media::scope()?,
            &NeverCancel,
        )?;
        assert_eq!(loaded.objects().source, expected.objects().source);
        assert_eq!(loaded.objects().media, expected.objects().media);
        assert_eq!(
            complete(
                &p,
                &DatagramArchive::recover(
                    &p,
                    scope()?,
                    limits(),
                    Some(pin),
                    &NeverCancel,
                    &mut work()
                )?,
                0
            )?
            .0[0]
                .manifest()
                .root(),
            root
        );
    }
    Ok(())
}
#[test]
fn untimed_picture_blocks_reads_and_invalid_timing_keeps_the_same_request() -> Test {
    let path = fresh("recording-timing")?;
    let mut input = input(false)?;
    input.push((1, 13, vec![0, 0, 0]));
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let mut r = DatagramHevcRecordingReplay::new(&a, spec(), recording()?, bounds(), 100)?;
    let request = await_timing(&mut r, &p, 100)?;
    let read = r.observations_read();
    assert_eq!(read, 3);
    for _ in 0..5 {
        match r.step(&p, 100, &NeverCancel, &mut work())? {
            HevcRecordingReplayStep::Capture(event) => {
                assert!(matches!(*event,HevcCapturePoll::TimingRequired(same) if same==request))
            }
            other => return Err(format!("read-ahead: {other:?}").into()),
        }
    }
    let error = r
        .supply_timing(
            HevcRecordingTiming {
                duration: 0,
                ..timing(0)
            },
            100,
            &NeverCancel,
            &mut work(),
        )
        .err()
        .ok_or("bad timing")?;
    assert!(error.retirement.is_none());
    assert_eq!(r.observations_read(), read);
    let _ = r.supply_timing(timing(0), 100, &NeverCancel, &mut work())?;
    let retired = r.cancel().ok_or("cancel")?;
    assert_eq!(
        retired.capture.ok_or("capture")?.collection.pictures.len(),
        1
    );
    Ok(())
}
#[test]
fn incomplete_hevc_fragment_does_not_become_a_picture_or_eof() -> Test {
    let path = fresh("recording-incomplete")?;
    let mut input = observations(true)?;
    input.pop();
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let (windows, retired) = complete(&p, &a, 0)?;
    assert!(windows.is_empty());
    match *retired.held_source.ok_or("source retirement")? {
        HevcReplayStep::PrefixExhausted {
            retired, replay_ns, ..
        } => {
            assert_eq!(replay_ns, 11);
            assert!(retired.fragment.is_some());
        }
        other => return Err(format!("fake boundary: {other:?}").into()),
    }
    assert_eq!(
        retired.capture.ok_or("capture")?.collection.sources.len(),
        1
    );
    Ok(())
}
#[test]
fn explicit_eob_preserves_completed_pictures_without_reading_later_observations() -> Test {
    let path = fresh("recording-eob")?;
    let mut input = input(false)?;
    input.push((0, 13, raw(4, 27_000, true, &[0x4a, 1, 0x80])));
    input.push((1, 14, vec![0, 0, 0]));
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let (windows, retired) = complete(&p, &a, 0)?;
    assert_eq!(windows.iter().map(|w| w.samples().len()).sum::<usize>(), 2);
    assert_eq!(retired.boundary, Some(HevcReplayBoundary::EndOfBitstream));
    assert_eq!(retired.observations_read, 4);
    assert_eq!(retired.source.datagrams, 5);
    assert!(retired.replay.is_some());
    Ok(())
}
#[test]
fn historical_group_expiry_fences_before_new_picture_and_retains_original_admission() -> Test {
    let path = fresh("recording-expire")?;
    let mut input = input(false)?;
    input[2].1 = 100;
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let mut policy = recording()?;
    policy.assembly.max_age_ns = 2;
    let mut r = DatagramHevcRecordingReplay::new(&a, spec(), policy, bounds(), 0)?;
    for _ in 0..128 {
        match r.step(&p, 0, &NeverCancel, &mut work())? {
            HevcRecordingReplayStep::Stopped { trigger, retained } => {
                assert!(matches!(trigger, HevcRecordingReplayStop::Collection(_)));
                assert!(matches!(
                    retained.held_source.as_deref(),
                    Some(HevcReplayStep::Rtp { .. })
                ));
                return Ok(());
            }
            HevcRecordingReplayStep::Capture(event) => assert!(!matches!(
                *event,
                HevcCapturePoll::TimingRequired(_) | HevcCapturePoll::Window(_)
            )),
            HevcRecordingReplayStep::Source(_) | HevcRecordingReplayStep::MediaQueued => {}
            other => return Err(format!("expiry bypass: {other:?}").into()),
        }
    }
    Err("expiry bound".into())
}
#[test]
fn source_generation_clock_and_timing_evidence_are_validated_before_reads() -> Test {
    let path = fresh("recording-scope")?;
    let pin = save(&path, &input(false)?)?;
    let (_, a) = reopen(&path, pin)?;
    let mut s = recording()?;
    s.scope.generation += 1;
    assert!(DatagramHevcRecordingReplay::new(&a, spec(), s, bounds(), 0).is_err());
    let mut s = recording()?;
    s.scope.receive_clock = ContentDigest::sha256(b"other clock");
    assert!(DatagramHevcRecordingReplay::new(&a, spec(), s, bounds(), 0).is_err());
    let mut s = recording()?;
    s.time_scale = 0;
    assert!(DatagramHevcRecordingReplay::new(&a, spec(), s, bounds(), 0).is_err());
    let base =
        DatagramHevcRecordingReplay::new(&a, spec(), recording()?, bounds(), 0)?.interpretation();
    let mut s = recording()?;
    s.timing_evidence = ContentDigest::sha256(b"other timing");
    assert_ne!(
        DatagramHevcRecordingReplay::new(&a, spec(), s, bounds(), 0)?.interpretation(),
        base
    );
    let mut s = recording()?;
    s.assembly.max_age_ns += 1;
    assert_ne!(
        DatagramHevcRecordingReplay::new(&a, spec(), s, bounds(), 0)?.interpretation(),
        base
    );
    let mut s = recording()?;
    s.limits.max_age_ns += 1;
    assert_ne!(
        DatagramHevcRecordingReplay::new(&a, spec(), s, bounds(), 0)?.interpretation(),
        base
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
fn clock_refusal_is_safe_and_cancelled_timing_returns_original_picture_once() -> Test {
    let path = fresh("recording-cancel")?;
    let pin = save(&path, &input(false)?)?;
    let (p, a) = reopen(&path, pin)?;
    let mut r = DatagramHevcRecordingReplay::new(&a, spec(), recording()?, bounds(), 100)?;
    let error = r
        .step(&p, 99, &NeverCancel, &mut work())
        .err()
        .ok_or("clock")?;
    assert!(matches!(
        error.reason,
        HevcRecordingReplayError::Replay(HevcReplayError::ClockReversed)
    ));
    assert!(error.retirement.is_none());
    let _ = await_timing(&mut r, &p, 100)?;
    let error = r
        .supply_timing(timing(0), 100, &Stop, &mut work())
        .err()
        .ok_or("cancel")?;
    let retired = error.retirement.ok_or("retirement")?;
    assert!(retired.capture.ok_or("capture")?.event.is_some());
    assert!(r.cancel().is_none());
    Ok(())
}
#[test]
fn finalization_is_explicit_and_original_work_and_deadline_remain_finite() -> Test {
    let path = fresh("recording-finite")?;
    let pin = save(&path, &input(false)?)?;
    let (p, a) = reopen(&path, pin)?;
    let mut b = bounds();
    b.max_steps = 2;
    let mut r = DatagramHevcRecordingReplay::new(&a, spec(), recording()?, b, 0)?;
    let error = r
        .finish_prefix(0, &NeverCancel, &mut work())
        .err()
        .ok_or("premature finish")?;
    assert!(matches!(
        error.reason,
        HevcRecordingReplayError::PrefixNotReady
    ));
    assert!(error.retirement.is_none());
    let _ = r.step(&p, 0, &NeverCancel, &mut work())?;
    assert!(
        r.step(&p, 0, &NeverCancel, &mut work())
            .err()
            .ok_or("work")?
            .retirement
            .is_some()
    );
    let mut b = bounds();
    b.deadline_ns = 10;
    let mut r = DatagramHevcRecordingReplay::new(&a, spec(), recording()?, b, 0)?;
    assert!(r.step(&p, 10, &NeverCancel, &mut work()).is_err());
    Ok(())
}
struct Counting {
    calls: std::cell::Cell<usize>,
    stop: usize,
}
impl PublishCancellation for Counting {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        let n = self.calls.get() + 1;
        self.calls.set(n);
        n >= self.stop
    }
}
#[test]
fn post_timing_revocation_preserves_both_admitted_timing_and_original_event() -> Test {
    let path = fresh("recording-post-timing")?;
    let pin = save(&path, &input(false)?)?;
    let (p, a) = reopen(&path, pin)?;
    let count = Counting {
        calls: std::cell::Cell::new(0),
        stop: usize::MAX,
    };
    let mut r = DatagramHevcRecordingReplay::new(&a, spec(), recording()?, bounds(), 0)?;
    let _ = await_timing(&mut r, &p, 0)?;
    let _ = r.supply_timing(timing(0), 0, &count, &mut work())?;
    let stop = Counting {
        calls: std::cell::Cell::new(0),
        stop: count.calls.get(),
    };
    let mut r = DatagramHevcRecordingReplay::new(&a, spec(), recording()?, bounds(), 0)?;
    let _ = await_timing(&mut r, &p, 0)?;
    let retired = r
        .supply_timing(timing(0), 0, &stop, &mut work())
        .err()
        .ok_or("post-cancel")?
        .retirement
        .ok_or("retirement")?;
    assert!(retired.withheld_timing.is_some());
    assert_eq!(
        retired.capture.ok_or("capture")?.collection.pictures.len(),
        1
    );
    Ok(())
}

fn decode_pixels(window: &PreparedHevcRecording) -> Test<Vec<ContentDigest>> {
    use fss_codec_h265::{Decoder, DecoderLimits};
    use fss_container::demux::{AvcMp4, DemuxLimits, VideoCodec};
    let mut bytes = window.objects().initialization.to_vec();
    bytes.extend_from_slice(window.objects().media);
    let parsed = AvcMp4::parse(&bytes, None, DemuxLimits::default())?;
    assert_eq!(parsed.codec(), VideoCodec::Hevc);
    let elementary = parsed.annex_b(0, parsed.samples().len())?;
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut pictures = decoder.decode_annex_b(elementary.bytes())?;
    pictures.extend(decoder.finish()?);
    assert_eq!(pictures.len(), window.samples().len());
    let mut digests = Vec::new();
    for picture in pictures {
        assert!(picture.width() > 0 && picture.height() > 0);
        assert_eq!(
            picture.luma().len(),
            picture.width() as usize * picture.height() as usize
        );
        // Main8 fixture samples are native u8 surfaces; no derived preview is used.
        digests.push(ContentDigest::sha256(picture.luma()));
    }
    Ok(digests)
}
#[test]
fn cold_window_decodes_after_original_datagram_store_is_offline() -> Test {
    let source_path = fresh("recording-independent-source")?;
    let output_path = fresh("recording-independent-output")?;
    let offline = fresh("recording-independent-offline")?;
    let pin = save(&source_path, &input(true)?)?;
    let (root, expected) = {
        let (p, a) = reopen(&source_path, pin)?;
        let (mut windows, _) = complete(&p, &a, 0)?;
        let window = windows.pop().ok_or("window")?;
        let expected = decode_pixels(&window)?;
        let root = window.manifest().root();
        let mut output = LocalRootPublisher::open(&output_path, storage())?;
        let mut job = RecordingPublication::new(
            window.publication_plan(),
            &mut output,
            SlotName::parse("offline-hevc")?,
            window.byte_len(),
            u64::MAX,
        )?;
        let mut done = false;
        for _ in 0..8 {
            if matches!(job.step(0, &NeverCancel)?, RecordingProgress::Published(_)) {
                done = true;
                break;
            }
        }
        assert!(done);
        (root, expected)
    };
    std::fs::rename(&source_path, &offline)?;
    let output = LocalRootPublisher::open(&output_path, storage())?;
    let loaded = load_hevc_recording(
        &output,
        &SlotName::parse("offline-hevc")?,
        root,
        &media::scope()?,
        &NeverCancel,
    )?;
    assert_eq!(decode_pixels(&loaded)?, expected);
    Ok(())
}
#[test]
fn post_seal_revocation_keeps_ready_window_and_exact_released_source() -> Test {
    let path = fresh("recording-post-seal")?;
    let input = input(true)?;
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let count = Counting {
        calls: std::cell::Cell::new(0),
        stop: usize::MAX,
    };
    let mut r = DatagramHevcRecordingReplay::new(&a, spec(), recording()?, bounds(), 0)?;
    let _ = await_timing(&mut r, &p, 0)?;
    let _ = r.supply_timing(timing(0), 0, &NeverCancel, &mut work())?;
    let expected = r.seal(0, &count, &mut work())?;
    let stop = Counting {
        calls: std::cell::Cell::new(0),
        stop: count.calls.get(),
    };
    let mut r = DatagramHevcRecordingReplay::new(&a, spec(), recording()?, bounds(), 0)?;
    let _ = await_timing(&mut r, &p, 0)?;
    let _ = r.supply_timing(timing(0), 0, &NeverCancel, &mut work())?;
    let retired = r
        .seal(0, &stop, &mut work())
        .err()
        .ok_or("post-seal accepted")?
        .retirement
        .ok_or("lost retirement")?;
    let seal = retired.withheld_seal.ok_or("released originals lost")?;
    assert!(seal.window_ready);
    assert_eq!(seal.released, expected.released);
    let window = retired
        .capture
        .ok_or("capture")?
        .collection
        .ready
        .ok_or("window lost")?;
    assert_eq!(window.samples().len(), 1);
    assert!(!seal.released.is_empty());
    assert_eq!(seal.released[0].bytes(), input[1].2);
    Ok(())
}
#[test]
fn source_gap_fences_without_joining_pictures_across_missing_packets() -> Test {
    let path = fresh("recording-gap")?;
    let mut input = input(false)?;
    input[2].2[2..4].copy_from_slice(&4u16.to_be_bytes());
    input.push((0, 200_000_020, raw(5, 45_000, true, &[0x26, 1, 0x80])));
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let mut r = DatagramHevcRecordingReplay::new(&a, spec(), recording()?, bounds(), 0)?;
    for _ in 0..128 {
        match r.step(&p, 0, &NeverCancel, &mut work())? {
            HevcRecordingReplayStep::Stopped { trigger, .. } => {
                assert!(matches!(trigger, HevcRecordingReplayStop::Collection(_)));
                return Ok(());
            }
            HevcRecordingReplayStep::Capture(event) => assert!(!matches!(
                *event,
                HevcCapturePoll::Window(_) | HevcCapturePoll::TimingRequired(_)
            )),
            HevcRecordingReplayStep::Source(_) | HevcRecordingReplayStep::MediaQueued => {}
            other => return Err(format!("gap hidden: {other:?}").into()),
        }
    }
    Err("gap bound".into())
}
#[test]
fn eob_in_aggregate_retains_later_nals_instead_of_assembling_past_the_boundary() -> Test {
    let path = fresh("recording-eob-queue")?;
    let n = media::nals()?;
    let idr = n
        .iter()
        .find(|n| matches!((n[0] >> 1) & 63, 19 | 20))
        .ok_or("idr")?
        .clone();
    let tail = n[2].clone();
    let input = vec![
        (0, 10, raw(1, 9000, false, &n[0])),
        (
            0,
            11,
            raw(
                2,
                9000,
                false,
                &media::aggregate(&[idr, vec![0x4a, 1, 0x80], tail.clone()]),
            ),
        ),
    ];
    let pin = save(&path, &input)?;
    let (p, a) = reopen(&path, pin)?;
    let mut r = DatagramHevcRecordingReplay::new(&a, spec(), recording()?, bounds(), 0)?;
    for _ in 0..128 {
        match r.step(&p, 0, &NeverCancel, &mut work())? {
            HevcRecordingReplayStep::Capture(event) => match *event {
                HevcCapturePoll::TimingRequired(_) => {
                    let _ = r.supply_timing(timing(0), 0, &NeverCancel, &mut work())?;
                }
                HevcCapturePoll::Receiver(_) => {}
                other => return Err(format!("unexpected: {other:?}").into()),
            },
            HevcRecordingReplayStep::PrefixReady { boundary, .. } => {
                assert_eq!(boundary, HevcReplayBoundary::EndOfBitstream);
                let retired = r.cancel().ok_or("retirement")?;
                let queued: Vec<_> = retired.queued_nals.collect();
                assert_eq!(queued.len(), 1);
                assert_eq!(queued[0].bytes(), tail);
                return Ok(());
            }
            HevcRecordingReplayStep::Source(_) | HevcRecordingReplayStep::MediaQueued => {}
            other => return Err(format!("eob advanced: {other:?}").into()),
        }
    }
    Err("eob bound".into())
}
#[test]
fn empty_cold_source_can_finalize_without_a_fabricated_recording() -> Test {
    let path = fresh("recording-empty")?;
    let pin = save(&path, &[])?;
    let (p, a) = reopen(&path, pin)?;
    let (windows, retired) = complete(&p, &a, 0)?;
    assert!(windows.is_empty());
    assert_eq!(retired.observations_read, 0);
    assert!(retired.assembly.is_none());
    Ok(())
}
