#![forbid(unsafe_code)]
//! Recording collector window sealing, backpressure and mid-GOP joins that preserve originals.

mod collector_support;
use collector_support::*;
use fss_reference::rtsp::recording::{RecordingPacket, verify_recording};
use fss_reference::rtsp::recording_collector::{
    CollectedPicture, CollectionStop, CollectorAdmission, CollectorError, CollectorLimits,
    RecordingCollector,
};

#[test]
fn next_idr_seals_previous_window_and_preserves_lookahead() -> TestResult {
    let mut c = collector(CollectorLimits::default())?;
    let a = sample(10, 90_000, true, false)?;
    let b = sample(11, 93_600, false, false)?;
    let next = sample(12, 97_200, true, false)?;
    a.source(&mut c, 1)?;
    b.source(&mut c, 2)?;
    next.source(&mut c, 3)?;
    assert!(!accepted(c.push_picture(a.timed(0), 3))?);
    assert!(!accepted(c.push_picture(b.timed(3600), 3))?);
    assert!(accepted(c.push_picture(next.timed(7200), 3))?);
    assert_eq!(c.retained_samples(), 1);
    assert_eq!(c.retained_packets(), 1);
    let ready = c.take_ready().ok_or("missing first window")?;
    assert_eq!(ready.summary().samples, 2);
    assert_eq!(ready.summary().packets, 2);
    assert_eq!(ready.summary().decode_interval, 0..7200);
    assert_eq!(
        verify_recording(ready.manifest(), ready.objects(), &scope()?)?,
        *ready.summary()
    );
    assert!(c.seal(4)?);
    let next = c.take_ready().ok_or("missing second window")?;
    assert_eq!(next.summary().decode_interval, 7200..10800);
    assert_eq!(next.summary().packets, 1);
    Ok(())
}

#[test]
fn output_backpressure_preserves_original_input_and_clock_for_retry() -> TestResult {
    let mut c = collector(CollectorLimits::default())?;
    let a = sample(1, 90_000, true, false)?;
    a.source(&mut c, 1)?;
    accepted(c.push_picture(a.timed(0), 1))?;
    c.seal(2)?;
    let b = sample(2, 93_600, true, false)?;
    let (seq, bytes) = &b.packets[0];
    let original = bytes.clone();
    assert_eq!(
        c.push_source(
            key(),
            RecordingPacket {
                sequence: *seq,
                received_ns: 2,
                bytes
            },
            100
        ),
        Err(CollectorError::Backpressure)
    );
    assert_eq!(bytes, &original);
    assert_eq!(c.retained_packets(), 0);
    let _ready = c.take_ready().ok_or("missing ready")?;
    b.source(&mut c, 3)?; // failed admission at 100 did not consume clock/sequence
    accepted(c.push_picture(b.timed(3600), 3))?;
    Ok(())
}

#[test]
fn picture_backpressure_returns_picture_intact() -> TestResult {
    let mut c = collector(CollectorLimits::default())?;
    let a = sample(1, 90_000, true, false)?;
    let b = sample(2, 93_600, true, false)?;
    a.source(&mut c, 1)?;
    b.source(&mut c, 1)?;
    accepted(c.push_picture(a.timed(0), 1))?;
    c.seal(1)?;
    let input = b.timed(3600);
    let bytes = input.picture.byte_len();
    match c.push_picture(input, 2) {
        CollectorAdmission::Refused {
            reason: CollectorError::Backpressure,
            picture,
        } => {
            assert_eq!(picture.picture.byte_len(), bytes);
            let _ = c.take_ready().ok_or("ready missing")?;
            accepted(c.push_picture(picture, 2))?;
        }
        other => return Err(format!("unexpected {other:?}").into()),
    }
    Ok(())
}

#[test]
fn joining_mid_gop_returns_skipped_picture_and_originals() -> TestResult {
    let mut c = collector(CollectorLimits::default())?;
    let p = sample(10, 90_000, false, true)?;
    let expected = p.packets[0].1.clone();
    p.source(&mut c, 1)?;
    match c.push_picture(p.timed(0), 1) {
        CollectorAdmission::AwaitingIdr {
            picture,
            unselected,
        } => {
            assert!(picture.picture.identity().idr_pic_id().is_none());
            assert_eq!(unselected.len(), 1);
            assert_eq!(unselected[0].bytes(), expected);
        }
        other => return Err(format!("unexpected {other:?}").into()),
    }
    assert_eq!(c.retained_packets(), 1);
    let idr = sample(12, 93_600, true, false)?;
    idr.source(&mut c, 2)?;
    match c.push_picture(idr.timed(3600), 2) {
        CollectorAdmission::Accepted {
            window_ready: false,
            unselected,
        } => {
            assert_eq!(unselected.len(), 1);
            assert_eq!(unselected[0].sequence(), 11);
        }
        other => return Err(format!("unexpected {other:?}").into()),
    }
    c.seal(3)?;
    assert_eq!(c.take_ready().ok_or("ready")?.summary().samples, 1);
    Ok(())
}

#[test]
fn packet_disjoint_cut_is_required_for_shared_stap_idr() -> TestResult {
    let raw = nals();
    let idr = raw.iter().find(|n| n[0] & 31 == 5).ok_or("IDR")?;
    let p = raw.iter().find(|n| n[0] & 31 == 1).ok_or("P")?;
    let mut r = receiver()?;
    r.ingest(key(), &packet(0, 90_000, false, raw[0]), 0)?;
    let first = packet(1, 90_000, true, idr);
    r.ingest(key(), &first, 1)?;
    let mut pictures = drain(&mut r, 1)?;
    let mut stap = vec![0x78];
    for nal in [*p, *idr] {
        stap.extend_from_slice(&(nal.len() as u16).to_be_bytes());
        stap.extend_from_slice(nal);
    }
    let shared = packet(2, 93_600, true, &stap);
    r.ingest(key(), &shared, 2)?;
    pictures.extend(drain(&mut r, 2)?);
    assert_eq!(pictures.len(), 3);
    let mut c = collector(CollectorLimits::default())?;
    for (seq, bytes) in [(1, &first), (2, &shared)] {
        c.push_source(
            key(),
            RecordingPacket {
                sequence: seq,
                received_ns: seq,
                bytes,
            },
            2,
        )?;
    }
    for (i, picture) in pictures.into_iter().enumerate() {
        assert!(!accepted(c.push_picture(
            CollectedPicture {
                picture,
                timing: timing(i as u64 * 3600)
            },
            2
        ))?);
    }
    assert_eq!(c.retained_samples(), 3);
    let next = sample(3, 97_200, true, false)?;
    next.source(&mut c, 3)?;
    assert!(accepted(c.push_picture(next.timed(10800), 3))?);
    let ready = c.take_ready().ok_or("shared packet window missing")?;
    assert_eq!(ready.summary().packets, 2);
    assert_eq!(ready.summary().samples, 3);
    Ok(())
}

#[test]
fn explicit_seal_refuses_an_unconsumed_stap_suffix_without_changing_state() -> TestResult {
    let raw = nals();
    let idr = raw.iter().find(|n| n[0] & 31 == 5).ok_or("IDR")?;
    let p = raw.iter().find(|n| n[0] & 31 == 1).ok_or("P")?;
    let mut payload = vec![0x78];
    for nal in [*idr, *p] {
        payload.extend_from_slice(&(nal.len() as u16).to_be_bytes());
        payload.extend_from_slice(nal);
    }
    let wire = packet(1, 90_000, true, &payload);
    let mut r = receiver()?;
    r.ingest(key(), &packet(0, 90_000, false, raw[0]), 0)?;
    r.ingest(key(), &wire, 1)?;
    let mut pictures = drain(&mut r, 1)?;
    assert_eq!(pictures.len(), 2);
    let mut c = collector(CollectorLimits::default())?;
    c.push_source(
        key(),
        RecordingPacket {
            sequence: 1,
            received_ns: 1,
            bytes: &wire,
        },
        1,
    )?;
    accepted(c.push_picture(
        CollectedPicture {
            picture: pictures.remove(0),
            timing: timing(0),
        },
        1,
    ))?;
    assert!(matches!(c.seal(2), Err(CollectorError::Recording(_))));
    assert!(!c.has_ready());
    assert_eq!(c.retained_packets(), 1);
    assert_eq!(c.retained_samples(), 1);
    accepted(c.push_picture(
        CollectedPicture {
            picture: pictures.remove(0),
            timing: timing(3600),
        },
        2,
    ))?;
    assert!(c.seal(2)?);
    assert_eq!(c.take_ready().ok_or("ready")?.summary().samples, 2);
    Ok(())
}

#[test]
fn timer_expiry_returns_all_sources_and_never_creates_a_window() -> TestResult {
    let mut c = collector(CollectorLimits {
        max_age_ns: 10,
        ..CollectorLimits::default()
    })?;
    let a = sample(1, 90_000, true, true)?;
    let original = a.packets[0].1.clone();
    a.source(&mut c, 5)?;
    accepted(c.push_picture(a.timed(0), 6))?;
    assert_eq!(c.next_wake_ns(), Some(15));
    assert!(c.poll(14)?.is_none());
    let expired = c.poll(15)?.ok_or("expiry absent")?;
    assert_eq!(expired.reason, CollectionStop::Deadline);
    assert_eq!(expired.sources[0].bytes(), original);
    assert_eq!(expired.pictures.len(), 1);
    assert_eq!(c.retained_packets(), 0);
    assert!(!c.has_ready());
    assert!(c.poll(15)?.is_none());
    Ok(())
}

#[test]
fn late_picture_cannot_escape_deadline() -> TestResult {
    let mut c = collector(CollectorLimits {
        max_age_ns: 10,
        ..CollectorLimits::default()
    })?;
    let a = sample(1, 90_000, true, false)?;
    a.source(&mut c, 0)?;
    assert!(matches!(
        c.push_picture(a.timed(0), 10),
        CollectorAdmission::Refused {
            reason: CollectorError::Deadline,
            ..
        }
    ));
    assert_eq!(c.retained_packets(), 1);
    assert_eq!(c.retained_samples(), 0);
    assert!(c.poll(10)?.is_some());
    Ok(())
}

#[test]
fn rollover_deadline_uses_lookahead_admission_not_picture_completion() -> TestResult {
    let mut c = collector(CollectorLimits {
        max_age_ns: 100,
        ..CollectorLimits::default()
    })?;
    let a = sample(1, 90_000, true, false)?;
    let b = sample(2, 93_600, true, false)?;
    a.source(&mut c, 0)?;
    b.source(&mut c, 10)?;
    accepted(c.push_picture(a.timed(0), 80))?;
    assert!(accepted(c.push_picture(b.timed(3600), 90))?);
    assert_eq!(c.next_wake_ns(), Some(110));
    let retired = c.poll(110)?.ok_or("lookahead must expire")?;
    assert_eq!(retired.sources.len(), 1);
    assert!(c.has_ready());
    Ok(())
}

#[test]
fn source_capacity_refusal_does_not_consume_sequence_or_time() -> TestResult {
    let mut c = collector(CollectorLimits {
        max_packets: 1,
        ..CollectorLimits::default()
    })?;
    let a = sample(1, 90_000, true, false)?;
    a.source(&mut c, 1)?;
    let b = sample(2, 93_600, true, false)?;
    assert!(b.source(&mut c, 100).is_err());
    accepted(c.push_picture(a.timed(0), 2))?;
    c.seal(2)?;
    let _ = c.take_ready().ok_or("ready")?;
    b.source(&mut c, 3)?;
    accepted(c.push_picture(b.timed(3600), 3))?;
    Ok(())
}

#[test]
fn window_sample_limit_is_enforced_but_safe_idr_can_roll_at_limit() -> TestResult {
    let mut c = collector(CollectorLimits {
        max_samples: 1,
        ..CollectorLimits::default()
    })?;
    let a = sample(1, 90_000, true, false)?;
    let p = sample(2, 93_600, false, false)?;
    a.source(&mut c, 1)?;
    p.source(&mut c, 2)?;
    accepted(c.push_picture(a.timed(0), 2))?;
    assert!(matches!(
        c.push_picture(p.timed(3600), 2),
        CollectorAdmission::Refused {
            reason: CollectorError::Capacity,
            ..
        }
    ));
    assert_eq!(c.retained_samples(), 1);
    assert_eq!(c.retained_packets(), 2);
    // Explicitly abandoning the unmatched P retains its original as an unselected prefix.
    c.seal(2)?;
    let _ = c.take_ready().ok_or("ready")?;
    let idr = sample(3, 97_200, true, false)?;
    idr.source(&mut c, 3)?;
    match c.push_picture(idr.timed(7200), 3) {
        CollectorAdmission::Accepted { unselected, .. } => assert_eq!(unselected.len(), 1),
        other => return Err(format!("unexpected {other:?}").into()),
    }
    let next = sample(4, 100_800, true, false)?;
    next.source(&mut c, 4)?;
    assert!(accepted(c.push_picture(next.timed(10800), 4))?);
    Ok(())
}

#[test]
fn missing_original_refuses_picture_without_consumption() -> TestResult {
    let mut c = collector(CollectorLimits::default())?;
    let a = sample(1, 90_000, true, false)?;
    let packets = a.packets.clone();
    match c.push_picture(a.timed(0), 1) {
        CollectorAdmission::Refused {
            reason: CollectorError::MissingSource,
            picture,
        } => {
            for (sequence, bytes) in &packets {
                c.push_source(
                    key(),
                    RecordingPacket {
                        sequence: *sequence,
                        received_ns: 0,
                        bytes,
                    },
                    1,
                )?;
            }
            accepted(c.push_picture(picture, 1))?;
        }
        other => return Err(format!("unexpected {other:?}").into()),
    }
    Ok(())
}

#[test]
fn received_time_is_preserved_even_when_it_reverses_in_sequence_order() -> TestResult {
    let mut c = collector(CollectorLimits::default())?;
    let a = sample(1, 90_000, true, true)?;
    for (i, (sequence, bytes)) in a.packets.iter().enumerate() {
        c.push_source(
            key(),
            RecordingPacket {
                sequence: *sequence,
                received_ns: 100 - i as u64,
                bytes,
            },
            200,
        )?;
    }
    let returned = c.cancel().pending;
    assert_eq!(returned.sources[0].received_ns(), 100);
    assert_eq!(returned.sources[1].received_ns(), 99);
    Ok(())
}

#[test]
fn cancellation_keeps_ready_window_separate_from_unsealed_lookahead() -> TestResult {
    let mut c = collector(CollectorLimits::default())?;
    let a = sample(1, 90_000, true, false)?;
    let b = sample(2, 93_600, true, false)?;
    a.source(&mut c, 1)?;
    b.source(&mut c, 1)?;
    accepted(c.push_picture(a.timed(0), 1))?;
    accepted(c.push_picture(b.timed(3600), 1))?;
    let result = c.cancel();
    assert!(result.ready.is_some());
    assert_eq!(result.pending.sources.len(), 1);
    assert_eq!(result.pending.pictures.len(), 1);
    let again = c.cancel();
    assert!(again.ready.is_none());
    assert!(again.pending.sources.is_empty());
    assert!(matches!(c.seal(1), Err(CollectorError::Closed)));
    Ok(())
}

#[test]
fn eof_seals_only_completed_pictures_and_returns_extra_originals() -> TestResult {
    let mut c = collector(CollectorLimits::default())?;
    let a = sample(1, 90_000, true, false)?;
    let b = sample(2, 93_600, false, true)?;
    a.source(&mut c, 1)?;
    b.source(&mut c, 2)?;
    accepted(c.push_picture(a.timed(0), 2))?;
    let tail = c.finish(3)?;
    assert_eq!(tail.reason, CollectionStop::EndOfInput);
    assert_eq!(tail.sources.len(), 2);
    assert!(tail.pictures.is_empty());
    assert_eq!(c.take_ready().ok_or("ready")?.summary().samples, 1);
    Ok(())
}

#[test]
fn gap_invalidation_returns_every_retained_byte_and_keeps_replay_high_water_mark() -> TestResult {
    let mut c = collector(CollectorLimits::default())?;
    let a = sample(1, 90_000, true, false)?;
    let wire = a.packets[0].1.clone();
    a.source(&mut c, 1)?;
    accepted(c.push_picture(a.timed(0), 1))?;
    let interrupted = c.interrupt(2, CollectionStop::InputDiscontinuity)?;
    assert_eq!(interrupted.sources[0].bytes(), wire);
    assert_eq!(interrupted.pictures.len(), 1);
    assert_eq!(
        c.push_source(
            key(),
            RecordingPacket {
                sequence: 1,
                received_ns: 1,
                bytes: &wire
            },
            2
        ),
        Err(CollectorError::SourceOrder)
    );
    let next = sample(3, 97_200, true, false)?;
    next.source(&mut c, 3)?;
    accepted(c.push_picture(next.timed(7200), 3))?;
    c.seal(3)?;
    Ok(())
}

#[test]
fn invalid_timing_refuses_intact_and_valid_retry_succeeds() -> TestResult {
    let mut c = collector(CollectorLimits::default())?;
    let a = sample(1, 90_000, true, false)?;
    a.source(&mut c, 1)?;
    let mut input = a.timed(0);
    input.timing.composition_offset = -1;
    match c.push_picture(input, 1) {
        CollectorAdmission::Refused {
            reason: CollectorError::Timeline,
            mut picture,
        } => {
            picture.timing.composition_offset = 0;
            accepted(c.push_picture(picture, 1))?;
        }
        other => return Err(format!("unexpected {other:?}").into()),
    }
    Ok(())
}

#[test]
fn duplicate_picture_is_not_recorded_twice() -> TestResult {
    let mut c = collector(CollectorLimits::default())?;
    let a = sample(1, 90_000, true, false)?;
    a.source(&mut c, 1)?;
    accepted(c.push_picture(a.timed(0), 1))?;
    let same = sample(1, 90_000, true, false)?;
    assert!(matches!(
        c.push_picture(same.timed(3600), 1),
        CollectorAdmission::Refused {
            reason: CollectorError::SourceOrder,
            ..
        }
    ));
    assert_eq!(c.retained_samples(), 1);
    Ok(())
}

#[test]
fn source_binding_raw_sequence_and_clock_are_checked_before_mutation() -> TestResult {
    let mut c = collector(CollectorLimits::default())?;
    let a = sample(1, 90_000, true, false)?;
    let wire = &a.packets[0].1;
    let p = RecordingPacket {
        sequence: 1,
        received_ns: 1,
        bytes: wire,
    };
    let mut wrong = key();
    wrong.generation = 2;
    assert_eq!(
        c.push_source(wrong, p, 5),
        Err(CollectorError::StreamMismatch)
    );
    assert_eq!(
        c.push_source(key(), RecordingPacket { sequence: 2, ..p }, 5),
        Err(CollectorError::Source)
    );
    c.push_source(key(), p, 1)?;
    assert!(matches!(
        c.push_picture(a.timed(0), 0),
        CollectorAdmission::Refused {
            reason: CollectorError::ClockReversed,
            ..
        }
    ));
    assert_eq!(c.retained_samples(), 0);
    assert_eq!(c.retained_packets(), 1);
    Ok(())
}

#[test]
fn invalid_configuration_and_unrepresentable_deadline_are_refused() -> TestResult {
    assert!(
        collector(CollectorLimits {
            max_packets: 0,
            ..CollectorLimits::default()
        })
        .is_err()
    );
    assert!(RecordingCollector::new(scope()?, key(), 96, 0, CollectorLimits::default()).is_err());
    let mut c = collector(CollectorLimits::default())?;
    let a = sample(1, 90_000, true, false)?;
    assert!(a.source(&mut c, u64::MAX).is_err());
    assert_eq!(c.retained_packets(), 0);
    a.source(&mut c, 0)?;
    Ok(())
}
