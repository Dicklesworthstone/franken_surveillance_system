#![forbid(unsafe_code)]
//! Receiver-to-recording capture: byte-identical originals, explicit timing, and owned expiry.

mod collector_support;
use collector_support::*;
use fss_packet::avc::{
    AvcAssemblyRetirement, AvcBoundary, AvcReceivePoll, AvcReceiver, AvcRetirementReason,
};
use fss_reference::rtsp::recording::{PreparedRecording, verify_recording};
use fss_reference::rtsp::recording_capture::{
    CaptureError, CapturePoll, MAX_PENDING_EVENT_AGE_NS, RecordingCapture, TimedCapture,
};
use fss_reference::rtsp::recording_collector::{CollectionStop, CollectorError, CollectorLimits};

fn capture() -> Result<RecordingCapture, Error> {
    Ok(RecordingCapture::new(
        collector(CollectorLimits::default())?,
    ))
}
fn idr() -> Result<&'static [u8], Error> {
    nals()
        .into_iter()
        .find(|n| n[0] & 31 == 5)
        .ok_or_else(|| "IDR missing".into())
}
fn p_slice() -> Result<&'static [u8], Error> {
    nals()
        .into_iter()
        .find(|n| n[0] & 31 == 1)
        .ok_or_else(|| "P missing".into())
}

/// Deterministic fixture timing is explicit here; the production bridge never derives it.
fn advance(
    r: &mut AvcReceiver,
    c: &mut RecordingCapture,
    now: u64,
    dts: &mut u64,
    windows: &mut Vec<PreparedRecording>,
) -> TestResult {
    for _ in 0..1024 {
        let event = r.poll(now)?;
        if matches!(event, AvcReceivePoll::Pending { .. }) {
            return Ok(());
        }
        c.offer(event, now)?;
        for _ in 0..16 {
            match c.poll(now)? {
                CapturePoll::Receiver(_) => break,
                CapturePoll::TimingRequired(_) => {
                    match c.supply_timing(timing(*dts), now)? {
                        TimedCapture::Collected { unselected, .. } if unselected.is_empty() => {}
                        other => return Err(format!("unexpected selection {other:?}").into()),
                    }
                    *dts += 3600;
                }
                CapturePoll::Window(window) => windows.push(window),
                CapturePoll::Pending { .. } => break,
                other => return Err(format!("unexpected fixture capture {other:?}").into()),
            }
        }
    }
    Err("fixture exceeded receiver progress bound".into())
}
fn prime(r: &mut AvcReceiver) -> TestResult {
    r.ingest(key(), &packet(0, 90_000, false, nals()[0]), 0)?;
    Ok(())
}
fn first_sample(r: &mut AvcReceiver, c: &mut RecordingCapture) -> TestResult {
    prime(r)?;
    r.ingest(key(), &packet(1, 90_000, true, idr()?), 1)?;
    advance(r, c, 1, &mut 0, &mut Vec::new())?;
    assert_eq!(c.collector().retained_samples(), 1);
    Ok(())
}

#[test]
fn continuous_receiver_events_produce_independent_reverified_windows() -> TestResult {
    let mut r = receiver()?;
    let mut c = capture()?;
    prime(&mut r)?;
    let mut dts = 0;
    let mut windows = Vec::new();
    for (sequence, nal) in [(1, idr()?), (2, p_slice()?), (3, idr()?)] {
        r.ingest(
            key(),
            &packet(sequence, 90_000 + (sequence as u32 - 1) * 3600, true, nal),
            sequence,
        )?;
        advance(&mut r, &mut c, sequence, &mut dts, &mut windows)?;
    }
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].summary().samples, 2);
    c.seal(4)?;
    match c.poll(4)? {
        CapturePoll::Window(w) => windows.push(w),
        other => return Err(format!("{other:?}").into()),
    }
    assert_eq!(windows[1].summary().samples, 1);
    for window in windows {
        verify_recording(window.manifest(), window.objects(), &scope()?)?;
    }
    Ok(())
}

#[test]
fn original_source_event_is_forwarded_byte_identically_after_collection_copy() -> TestResult {
    let mut r = receiver()?;
    let mut c = capture()?;
    prime(&mut r)?;
    let wire = packet(1, 90_000, true, idr()?);
    r.ingest(key(), &wire, 5)?;
    c.offer(r.poll(5)?, 5)?;
    match c.poll(5)? {
        CapturePoll::Receiver(AvcReceivePoll::Source { source, .. }) => {
            assert_eq!(source.bytes(), wire);
            assert_eq!(source.received_ns(), 5);
            assert_eq!(c.collector().retained_source_bytes(), wire.len());
        }
        other => return Err(format!("{other:?}").into()),
    }
    let retired = c.cancel();
    assert_eq!(retired.collection.pending.sources[0].bytes(), wire);
    Ok(())
}

#[test]
fn held_picture_requires_explicit_timing_and_wrong_timing_is_retryable() -> TestResult {
    let mut r = receiver()?;
    let mut c = capture()?;
    prime(&mut r)?;
    r.ingest(key(), &packet(1, 90_000, true, idr()?), 1)?;
    c.offer(r.poll(1)?, 1)?;
    let _source = c.poll(1)?;
    c.offer(r.poll(1)?, 1)?;
    let request = match c.poll(1)? {
        CapturePoll::TimingRequired(p) => p,
        other => return Err(format!("{other:?}").into()),
    };
    assert_eq!(request.rtp_timestamp, 90_000);
    assert_eq!(c.collector().retained_samples(), 0);
    let rejected = c
        .offer(
            AvcReceivePoll::Pending {
                wake_at_ns: Some(99),
            },
            2,
        )
        .err()
        .ok_or("must backpressure")?;
    assert_eq!(rejected.reason, CaptureError::Backpressure);
    assert!(matches!(
        *rejected.event,
        AvcReceivePoll::Pending {
            wake_at_ns: Some(99)
        }
    ));
    let mut invalid = timing(0);
    invalid.duration = 0;
    assert!(matches!(
        c.supply_timing(invalid, 2),
        Err(CaptureError::Collection(CollectorError::Timeline))
    ));
    assert!(matches!(c.poll(2)?, CapturePoll::TimingRequired(p) if p == request));
    assert!(matches!(
        c.supply_timing(timing(0), 2)?,
        TimedCapture::Collected { .. }
    ));
    assert_eq!(c.collector().retained_samples(), 1);
    Ok(())
}

#[test]
fn missing_timing_expires_with_owned_picture_and_originals() -> TestResult {
    let mut r = receiver()?;
    let mut c = capture()?;
    prime(&mut r)?;
    r.ingest(key(), &packet(1, 90_000, true, idr()?), 1)?;
    c.offer(r.poll(1)?, 1)?;
    let _ = c.poll(1)?;
    c.offer(r.poll(1)?, 2)?;
    assert!(matches!(c.poll(2)?, CapturePoll::TimingRequired(_)));
    let deadline = 2 + MAX_PENDING_EVENT_AGE_NS;
    assert_eq!(c.next_wake_ns(), Some(deadline));
    assert!(matches!(
        c.supply_timing(timing(0), deadline),
        Err(CaptureError::Collection(CollectorError::Deadline))
    ));
    match c.poll(deadline)? {
        CapturePoll::Stopped {
            reason: CollectionStop::Deadline,
            retained,
            ..
        } => {
            assert!(retained.picture.is_some());
            assert_eq!(retained.collection.pending.sources.len(), 1);
            assert!(retained.collection.ready.is_none());
        }
        other => return Err(format!("{other:?}").into()),
    }
    assert!(matches!(
        c.poll(deadline)?,
        CapturePoll::Ended { trailing: None }
    ));
    Ok(())
}

#[test]
fn unprocessed_event_has_a_deadline_even_before_source_collection() -> TestResult {
    let mut r = receiver()?;
    let mut c = capture()?;
    prime(&mut r)?;
    let wire = packet(1, 90_000, true, idr()?);
    r.ingest(key(), &wire, 1)?;
    c.offer(r.poll(1)?, 1)?;
    match c.poll(1 + MAX_PENDING_EVENT_AGE_NS)? {
        CapturePoll::Stopped {
            retained,
            reason: CollectionStop::Deadline,
            ..
        } => {
            assert!(retained.collection.pending.sources.is_empty());
            assert!(
                matches!(retained.event, Some(AvcReceivePoll::Source { source, .. }) if source.bytes() == wire)
            );
        }
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

#[test]
fn missing_packet_automatically_fences_completed_but_unsealed_gop() -> TestResult {
    let mut r = receiver()?;
    let mut c = capture()?;
    first_sample(&mut r, &mut c)?;
    r.ingest(key(), &packet(3, 97_200, true, p_slice()?), 2)?;
    assert!(matches!(r.poll(2)?, AvcReceivePoll::Pending { .. }));
    let now = 100_000_002;
    c.offer(r.poll(now)?, now)?;
    assert!(matches!(c.seal(now), Err(CaptureError::Backpressure)));
    match c.poll(now)? {
        CapturePoll::Stopped {
            reason: CollectionStop::InputDiscontinuity,
            retained,
            ..
        } => {
            assert_eq!(retained.collection.pending.pictures.len(), 1);
            assert_eq!(retained.collection.pending.sources.len(), 1);
            assert!(matches!(retained.event, Some(AvcReceivePoll::Gap { .. })));
            assert!(retained.collection.ready.is_none());
        }
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

#[test]
fn malformed_codec_payload_retains_failing_original_and_prior_gop() -> TestResult {
    let mut r = receiver()?;
    let mut c = capture()?;
    first_sample(&mut r, &mut c)?;
    let wire = packet(2, 93_600, true, &[0x78, 0, 2, 0x61]);
    r.ingest(key(), &wire, 2)?;
    c.offer(r.poll(2)?, 2)?;
    match c.poll(2)? {
        CapturePoll::Stopped { retained, .. } => {
            assert_eq!(retained.collection.pending.pictures.len(), 1);
            assert!(
                matches!(retained.event, Some(AvcReceivePoll::CodecRefused { source, .. }) if source.bytes() == wire)
            );
        }
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

#[test]
fn fragment_timeout_automatically_fences_collection_without_network_input() -> TestResult {
    let mut r = receiver()?;
    let mut c = capture()?;
    first_sample(&mut r, &mut c)?;
    r.ingest(key(), &packet(2, 93_600, false, &[0x5c, 0x81, 0x80]), 2)?;
    c.offer(r.poll(2)?, 2)?;
    assert!(matches!(c.poll(2)?, CapturePoll::Receiver(_)));
    let now = 2_000_000_002;
    c.offer(r.poll(now)?, now)?;
    match c.poll(now)? {
        CapturePoll::Stopped { retained, .. } => {
            assert_eq!(retained.collection.pending.sources.len(), 2);
            assert_eq!(retained.collection.pending.pictures.len(), 1);
            assert!(matches!(
                retained.event,
                Some(AvcReceivePoll::FragmentRetired { .. })
            ));
        }
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

#[test]
fn bounded_source_pressure_retains_original_event_until_prefix_is_sealed() -> TestResult {
    let mut r = receiver()?;
    let mut c = RecordingCapture::new(collector(CollectorLimits {
        max_packets: 1,
        ..CollectorLimits::default()
    })?);
    first_sample(&mut r, &mut c)?;
    let wire = packet(2, 93_600, true, idr()?);
    r.ingest(key(), &wire, 2)?;
    c.offer(r.poll(2)?, 2)?;
    assert!(matches!(
        c.poll(2)?,
        CapturePoll::Backpressure(CollectorError::Capacity)
    ));
    assert!(
        c.offer(AvcReceivePoll::Pending { wake_at_ns: None }, 2)
            .is_err()
    );
    assert!(c.seal(3)?);
    assert!(matches!(c.poll(3)?, CapturePoll::Window(_)));
    match c.poll(3)? {
        CapturePoll::Receiver(AvcReceivePoll::Source { source, .. }) => {
            assert_eq!(source.bytes(), wire);
            assert_eq!(source.received_ns(), 2);
        }
        other => return Err(format!("{other:?}").into()),
    }
    c.offer(r.poll(3)?, 3)?;
    assert!(matches!(c.poll(3)?, CapturePoll::TimingRequired(_)));
    c.supply_timing(timing(3600), 3)?;
    assert_eq!(c.collector().retained_packets(), 1);
    Ok(())
}

#[test]
fn eof_returns_unverified_tail_but_seals_prior_complete_prefix() -> TestResult {
    let mut r = receiver()?;
    let mut c = capture()?;
    first_sample(&mut r, &mut c)?;
    let tail = packet(2, 93_600, false, p_slice()?);
    r.ingest(key(), &tail, 2)?;
    advance(&mut r, &mut c, 2, &mut 3600, &mut Vec::new())?;
    r.finish();
    c.offer(r.poll(3)?, 3)?;
    match c.poll(3)? {
        CapturePoll::Tail(out) => assert_eq!(
            out.picture.ok_or("tail")?.boundary(),
            AvcBoundary::EndOfInputUnverified
        ),
        other => return Err(format!("{other:?}").into()),
    }
    match c.poll(3)? {
        CapturePoll::Window(w) => {
            assert_eq!(w.summary().samples, 1);
            assert_eq!(w.summary().packets, 1);
        }
        other => return Err(format!("{other:?}").into()),
    }
    match c.poll(3)? {
        CapturePoll::Ended {
            trailing: Some(out),
        } => {
            assert_eq!(out.sources.len(), 1);
            assert_eq!(out.sources[0].bytes(), tail);
        }
        other => return Err(format!("{other:?}").into()),
    }
    assert!(matches!(c.poll(3)?, CapturePoll::Ended { trailing: None }));
    Ok(())
}

#[test]
fn cancellation_preserves_held_event_or_timing_picture() -> TestResult {
    let mut r = receiver()?;
    let mut c = capture()?;
    prime(&mut r)?;
    r.ingest(key(), &packet(1, 90_000, true, idr()?), 1)?;
    c.offer(r.poll(1)?, 1)?;
    let cancelled = c.cancel();
    assert!(cancelled.event.is_some());
    assert!(cancelled.collection.pending.sources.is_empty());
    let mut c = capture()?;
    let a = sample(1, 90_000, true, false)?;
    c.offer(AvcReceivePoll::Picture(a.picture), 2)?;
    let _ = c.poll(2)?;
    let cancelled = c.cancel();
    assert!(cancelled.picture.is_some());
    assert!(c.cancel().picture.is_none());
    Ok(())
}

#[test]
fn pending_failure_cannot_be_bypassed_with_explicit_seal() -> TestResult {
    let mut r = receiver()?;
    let mut c = capture()?;
    first_sample(&mut r, &mut c)?;
    let retired = AvcAssemblyRetirement {
        key: key(),
        reason: AvcRetirementReason::InvalidInput,
        nals: 0,
        bytes: 0,
        first_sequence: None,
        last_sequence: None,
    };
    c.offer(AvcReceivePoll::PictureRetired(retired), 2)?;
    assert!(matches!(c.seal(2), Err(CaptureError::Backpressure)));
    assert!(matches!(c.poll(2)?, CapturePoll::Stopped { .. }));
    Ok(())
}

#[test]
fn collection_expiry_preserves_ready_plan_without_upgrading_new_work() -> TestResult {
    let mut collector = collector(CollectorLimits {
        max_age_ns: 10,
        ..CollectorLimits::default()
    })?;
    let a = sample(1, 90_000, true, false)?;
    let b = sample(2, 93_600, true, false)?;
    a.source(&mut collector, 1)?;
    b.source(&mut collector, 1)?;
    accepted(collector.push_picture(a.timed(0), 1))?;
    accepted(collector.push_picture(b.timed(3600), 1))?;
    let mut c = RecordingCapture::new(collector);
    match c.poll(11)? {
        CapturePoll::Stopped {
            retained,
            reason: CollectionStop::Deadline,
            ..
        } => {
            assert!(retained.collection.ready.is_some());
            assert_eq!(retained.collection.pending.pictures.len(), 1);
        }
        other => return Err(format!("{other:?}").into()),
    }
    Ok(())
}

#[test]
fn clock_reversal_does_not_drop_accepted_event() -> TestResult {
    let mut c = capture()?;
    c.offer(
        AvcReceivePoll::Pending {
            wake_at_ns: Some(12),
        },
        5,
    )?;
    assert!(matches!(
        c.poll(4),
        Err(CaptureError::Collection(CollectorError::ClockReversed))
    ));
    assert!(matches!(
        c.poll(5)?,
        CapturePoll::Receiver(AvcReceivePoll::Pending {
            wake_at_ns: Some(12)
        })
    ));
    Ok(())
}

#[test]
fn capture_windows_publish_root_last_and_reopen_with_original_provenance() -> TestResult {
    use fss_object::SpoolLimits;
    use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
    use fss_reference::rtsp::recording::local::{
        RecordingProgress, RecordingPublication, load_recording,
    };
    let root = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("recording_capture_contract")
        .join("publish_reopen");
    match std::fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let limits = LocalPublicationLimits::new(
        8,
        16,
        8,
        64,
        SpoolLimits::new(64, 4 * 1024 * 1024, 1024 * 1024, 64),
    );
    let mut r = receiver()?;
    let mut c = capture()?;
    first_sample(&mut r, &mut c)?;
    c.seal(2)?;
    let plan = match c.poll(2)? {
        CapturePoll::Window(w) => w,
        other => return Err(format!("{other:?}").into()),
    };
    let slot = SlotName::parse("captured-gop-1")?;
    let mut publisher = LocalRootPublisher::open(&root, limits)?;
    {
        let mut job =
            RecordingPublication::new(&plan, &mut publisher, slot.clone(), plan.byte_len(), 100)?;
        for now in 0..4 {
            assert!(matches!(
                job.step(now, &NeverCancel)?,
                RecordingProgress::ChildStaged { .. }
            ));
        }
        assert!(matches!(
            job.step(4, &NeverCancel)?,
            RecordingProgress::Published(_)
        ));
    }
    drop(publisher);
    let reopened = LocalRootPublisher::open(&root, limits)?;
    let loaded = load_recording(
        &reopened,
        &slot,
        plan.manifest().root(),
        &scope()?,
        &NeverCancel,
    )?;
    assert_eq!(loaded.objects().source, plan.objects().source);
    assert_eq!(loaded.objects().media, plan.objects().media);
    Ok(())
}
