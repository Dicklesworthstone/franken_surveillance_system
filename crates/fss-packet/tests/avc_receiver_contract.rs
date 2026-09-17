#![forbid(unsafe_code)]
//! The composed public receiver must propagate loss without caller-side glue.

mod avc_support;

use avc_support::{Error, KEY, parameters, slice, split, wire};
use fss_packet::avc::{
    AvcAssemblyError, AvcAssemblyStep, AvcBoundary, AvcPictureGroup, AvcReceiveError,
    AvcReceiveLimits, AvcReceivePoll, AvcReceiver, AvcRetirementReason, parse_pps, parse_sps,
};
use fss_packet::{H264Error, H264Mode, ReorderDisposition, StreamKey};

type TestResult = Result<(), Error>;

fn limits() -> AvcReceiveLimits {
    let mut limits = AvcReceiveLimits::default();
    limits.reorder.max_delay_ns = 10;
    limits.reconstruction.max_pending_age_ns = 30;
    limits.assembly.max_age_ns = 100;
    limits
}

fn receiver(limits: AvcReceiveLimits) -> Result<AvcReceiver, Error> {
    let (sps, pps) = parameters()?;
    let first = wire(KEY, 0, 90, false, sps.nal_bytes());
    let mut receiver = AvcReceiver::new(KEY, 96, H264Mode::NonInterleaved, limits, (sps, pps))?;
    let admission = receiver.ingest(KEY, &first, 0)?;
    assert_eq!(
        admission.transport.transport.disposition,
        ReorderDisposition::NotAdmitted
    );
    Ok(receiver)
}

fn drain_clean(r: &mut AvcReceiver, now: u64) -> Result<Vec<AvcPictureGroup>, Error> {
    let mut pictures = Vec::new();
    // This ceiling is part of the test: no accidental infinite progress loop.
    for _ in 0..1_024 {
        match r.poll(now)? {
            AvcReceivePoll::Source {
                picture,
                fragment,
                gap_before,
                ..
            } => {
                assert!(picture.is_none() && fragment.is_none() && !gap_before);
            }
            AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(output)) => {
                assert!(output.retired.is_none());
                if let Some(picture) = output.picture {
                    pictures.push(picture);
                }
            }
            AvcReceivePoll::Picture(picture) => pictures.push(picture),
            AvcReceivePoll::Pending { .. } => return Ok(pictures),
            other => return Err(format!("unexpected clean receiver result: {other:?}").into()),
        }
    }
    Err("receiver failed to reach bounded quiescence".into())
}

fn pending_picture(r: &mut AvcReceiver) -> TestResult {
    r.ingest(KEY, &wire(KEY, 1, 90, false, &slice(0, 1)), 1)?;
    assert!(drain_clean(r, 1)?.is_empty());
    Ok(())
}

fn fragment_start() -> Vec<u8> {
    let data = slice(20, 1);
    let mut payload = vec![(data[0] & 0x60) | 28, 0x80 | (data[0] & 31)];
    payload.extend_from_slice(&data[1..]);
    payload
}

#[test]
fn real_source_is_exposed_before_owned_picture_admission() -> TestResult {
    let mut r = receiver(limits())?;
    let source = wire(KEY, 1, 90, true, &slice(0, 1));
    r.ingest(KEY, &source, 1)?;
    match r.poll(1)? {
        AvcReceivePoll::Source {
            source: saved,
            queued_nals,
            ..
        } => {
            assert_eq!(saved.bytes(), source);
            assert_eq!(queued_nals, 1);
        }
        _ => return Err("source was not emitted first".into()),
    }
    assert_eq!(r.next_wake_ns(), Some(1));
    let pictures = drain_clean(&mut r, 1)?;
    assert_eq!(pictures.len(), 1);
    assert_eq!(pictures[0].nals()[0].sources()[0].sequence, 1);
    assert_eq!(r.retained_nal_bytes(), 0);
    Ok(())
}

#[test]
fn gap_automatically_retires_picture_and_fragment_before_later_nals() -> TestResult {
    let mut r = receiver(limits())?;
    pending_picture(&mut r)?;
    r.ingest(KEY, &wire(KEY, 2, 90, false, &fragment_start()), 2)?;
    drain_clean(&mut r, 2)?;
    // Sequence 3 never arrives. A timer must report the gap without more traffic.
    r.ingest(KEY, &wire(KEY, 4, 90, true, &[0x5c, 0x41]), 3)?;
    assert!(matches!(
        r.poll(3)?,
        AvcReceivePoll::Pending {
            wake_at_ns: Some(13)
        }
    ));
    match r.poll(13)? {
        AvcReceivePoll::Gap {
            fragment, picture, ..
        } => {
            assert_eq!(
                fragment.ok_or("incomplete FU receipt")?.reason,
                H264Error::Gap
            );
            assert_eq!(
                picture.ok_or("picture receipt")?.reason,
                AvcRetirementReason::InputDiscontinuity
            );
        }
        _ => return Err("loss was not automatically propagated".into()),
    }
    assert!(matches!(
        r.poll(13)?,
        AvcReceivePoll::CodecRefused { picture: None, .. }
    ));
    assert!(matches!(r.poll(13)?, AvcReceivePoll::Pending { .. }));
    r.ingest(KEY, &wire(KEY, 5, 100, true, &slice(0, 2)), 14)?;
    let pictures = drain_clean(&mut r, 14)?;
    assert_eq!(pictures.len(), 1);
    assert!(pictures[0].discontinuity_before());
    assert_eq!(pictures[0].nals().len(), 1);
    Ok(())
}

#[test]
fn malformed_stap_keeps_original_and_invalidates_pending_picture() -> TestResult {
    let mut r = receiver(limits())?;
    pending_picture(&mut r)?;
    let source = wire(KEY, 2, 90, true, &[0x78, 0, 2, 0x61]);
    r.ingest(KEY, &source, 2)?;
    match r.poll(2)? {
        AvcReceivePoll::CodecRefused {
            source: saved,
            picture,
            ..
        } => {
            assert_eq!(saved.bytes(), source);
            assert_eq!(picture.ok_or("old picture retirement")?.nals, 1);
        }
        _ => return Err("malformed STAP did not retain original failure evidence".into()),
    }
    assert_eq!(r.retained_nal_bytes(), 0);
    r.ingest(KEY, &wire(KEY, 3, 100, true, &slice(0, 2)), 3)?;
    assert!(drain_clean(&mut r, 3)?[0].discontinuity_before());
    Ok(())
}

#[test]
fn fragment_timeout_automatically_invalidates_picture_without_new_packets() -> TestResult {
    let mut r = receiver(limits())?;
    pending_picture(&mut r)?;
    r.ingest(KEY, &wire(KEY, 2, 90, false, &fragment_start()), 2)?;
    drain_clean(&mut r, 2)?;
    assert_eq!(r.next_wake_ns(), Some(32));
    match r.poll(32)? {
        AvcReceivePoll::FragmentRetired { fragment, picture } => {
            assert_eq!(fragment.reason, H264Error::Deadline);
            assert_eq!(picture.ok_or("timeout picture retirement")?.nals, 1);
        }
        _ => return Err("fragment timeout did not reach picture layer".into()),
    }
    assert_eq!(r.retained_nal_bytes(), 0);
    assert!(matches!(
        r.poll(32)?,
        AvcReceivePoll::Pending { wake_at_ns: None }
    ));
    Ok(())
}

#[test]
fn picture_deadline_precedes_later_complete_nal_admission() -> TestResult {
    let mut policy = limits();
    policy.assembly.max_age_ns = 10;
    let mut r = receiver(policy)?;
    pending_picture(&mut r)?;
    r.ingest(KEY, &wire(KEY, 2, 100, false, &slice(0, 2)), 2)?;
    assert!(matches!(
        r.poll(2)?,
        AvcReceivePoll::Source { queued_nals: 1, .. }
    ));
    match r.poll(11)? {
        AvcReceivePoll::PictureRetired(retired) => {
            assert_eq!(retired.reason, AvcRetirementReason::Deadline)
        }
        _ => return Err("picture deadline bypassed by a queued NAL".into()),
    }
    assert_eq!(r.queued_nals(), 1);
    drain_clean(&mut r, 11)?;
    r.finish();
    match r.poll(11)? {
        AvcReceivePoll::Ended {
            tail: Some(tail), ..
        } => {
            let picture = tail.picture.ok_or("unverified surviving tail")?;
            assert!(picture.discontinuity_before());
            assert_eq!(picture.identity().frame_num(), 2);
            assert_eq!(picture.boundary(), AvcBoundary::EndOfInputUnverified);
        }
        _ => return Err("queued NAL was lost on timeout".into()),
    }
    Ok(())
}

#[test]
fn eof_with_incomplete_fu_retires_picture_instead_of_publishing_tail() -> TestResult {
    let mut r = receiver(limits())?;
    pending_picture(&mut r)?;
    r.ingest(KEY, &wire(KEY, 2, 90, false, &fragment_start()), 2)?;
    drain_clean(&mut r, 2)?;
    r.finish();
    assert_eq!(r.next_wake_ns(), Some(2));
    match r.poll(3)? {
        AvcReceivePoll::Ended {
            fragment,
            interrupted_picture,
            tail: Some(tail),
        } => {
            assert_eq!(
                fragment.ok_or("EOF fragment")?.reason,
                H264Error::EndOfInput
            );
            assert_eq!(interrupted_picture.ok_or("interrupted picture")?.nals, 1);
            assert!(tail.picture.is_none());
        }
        _ => return Err("interrupted EOF became a complete-looking tail".into()),
    }
    assert!(matches!(
        r.poll(3)?,
        AvcReceivePoll::Ended {
            fragment: None,
            interrupted_picture: None,
            tail: None
        }
    ));
    assert_eq!(r.next_wake_ns(), None);
    Ok(())
}

#[test]
fn cancellation_accounts_for_packet_queue_complete_nal_queue_and_picture() -> TestResult {
    let mut r = receiver(limits())?;
    pending_picture(&mut r)?;
    r.ingest(KEY, &wire(KEY, 2, 90, false, &slice(20, 1)), 2)?;
    assert!(matches!(
        r.poll(2)?,
        AvcReceivePoll::Source { queued_nals: 1, .. }
    ));
    r.ingest(KEY, &wire(KEY, 3, 100, true, &slice(0, 2)), 3)?;
    assert_eq!(r.queued_packets(), 1);
    let receipt = r.cancel();
    assert_eq!(receipt.queued_nals.nals, 1);
    assert_eq!(receipt.queued_nals.first_sequence, Some(2));
    assert_eq!(
        receipt.picture.ok_or("pending picture cancellation")?.nals,
        1
    );
    assert_eq!(r.queued_packets(), 0);
    assert_eq!(r.retained_nal_bytes(), 0);
    let again = r.cancel();
    assert_eq!(again.queued_nals.nals, 0);
    assert!(again.picture.is_none() && again.transport.fragment.is_none());
    assert!(
        r.ingest(KEY, &wire(KEY, 4, 110, true, &slice(0, 3)), 4)
            .is_err()
    );
    Ok(())
}

#[test]
fn confirmed_source_restart_retires_every_old_epoch_layer() -> TestResult {
    let mut r = receiver(limits())?;
    pending_picture(&mut r)?;
    r.ingest(KEY, &wire(KEY, 2, 90, false, &slice(20, 1)), 2)?;
    r.poll(2)?;
    r.ingest(KEY, &wire(KEY, 3, 100, true, &slice(0, 2)), 3)?;
    let suspected = r.ingest(KEY, &wire(KEY, 10_000, 90, false, &slice(0, 1)), 4)?;
    assert!(suspected.picture.is_none());
    let confirmed = r.ingest(KEY, &wire(KEY, 10_001, 90, false, &slice(0, 1)), 5)?;
    assert_eq!(
        confirmed.transport.transport.disposition,
        ReorderDisposition::RestartRequired
    );
    assert_eq!(confirmed.queued_nals.ok_or("restart NAL queue")?.nals, 1);
    assert_eq!(confirmed.picture.ok_or("restart picture")?.nals, 1);
    assert_eq!(r.retained_nal_bytes(), 0);
    assert!(matches!(
        r.poll(5)?,
        AvcReceivePoll::Ended { tail: None, .. }
    ));
    Ok(())
}

#[test]
fn refused_restart_or_clock_change_preserves_queued_and_pending_work() -> TestResult {
    let mut r = receiver(limits())?;
    pending_picture(&mut r)?;
    let retained = r.retained_nal_bytes();
    let stats = r.stats();
    assert!(matches!(
        r.restart(KEY, 96, H264Mode::NonInterleaved, limits(), parameters()?),
        Err(AvcReceiveError::Assembly(
            AvcAssemblyError::GenerationRequired
        ))
    ));
    assert!(matches!(
        r.poll(0),
        Err(AvcReceiveError::Assembly(AvcAssemblyError::ClockReversed))
    ));
    assert!(
        r.ingest(
            StreamKey { ingress: 99, ..KEY },
            &wire(KEY, 2, 90, false, &slice(20, 1)),
            2
        )
        .is_err()
    );
    assert_eq!(r.retained_nal_bytes(), retained);
    assert_eq!(r.stats(), stats);
    let key = StreamKey {
        generation: 2,
        ..KEY
    };
    let (mut next, receipt) =
        r.restart(key, 96, H264Mode::NonInterleaved, limits(), parameters()?)?;
    assert_eq!(receipt.picture.ok_or("successful restart receipt")?.nals, 1);
    next.ingest(key, &wire(key, 0, 90, false, &slice(0, 1)), 0)?;
    next.ingest(key, &wire(key, 1, 90, true, &slice(0, 1)), 1)?;
    let pictures = drain_clean(&mut next, 1)?;
    assert_eq!(pictures[0].key(), key);
    Ok(())
}

#[test]
fn exact_configuration_change_stops_transport_admission_without_laundering_picture() -> TestResult {
    let mut r = receiver(limits())?;
    pending_picture(&mut r)?;
    let (sps, _) = parameters()?;
    let mut changed = sps.nal_bytes().to_vec();
    changed[0] = 0x27; // Same bitstream id but different exact original parameter bytes.
    r.ingest(KEY, &wire(KEY, 2, 90, false, &changed), 2)?;
    r.poll(2)?;
    match r.poll(2)? {
        AvcReceivePoll::Assembly(AvcAssemblyStep::Refused(refusal)) => {
            assert_eq!(refusal.reason, AvcAssemblyError::ConfigurationChanged);
            assert_eq!(refusal.nal.bytes(), changed);
            assert!(refusal.retired.is_some());
        }
        _ => return Err("changed parameter set did not fence receiver".into()),
    }
    assert!(
        r.ingest(KEY, &wire(KEY, 3, 100, true, &slice(0, 2)), 3)
            .is_err()
    );
    assert!(matches!(r.poll(3)?, AvcReceivePoll::Ended { .. }));
    assert_eq!(r.retained_nal_bytes(), 0);
    Ok(())
}

#[test]
fn transport_backpressure_does_not_consume_sequence_or_picture() -> TestResult {
    let mut policy = limits();
    policy.reorder.max_packets = 1;
    let mut r = receiver(policy)?;
    let one = wire(KEY, 1, 90, false, &slice(0, 1));
    let two = wire(KEY, 2, 90, true, &slice(20, 1));
    r.ingest(KEY, &one, 1)?;
    let stats = r.stats();
    assert!(r.ingest(KEY, &two, 2).is_err());
    assert_eq!(r.stats(), stats);
    drain_clean(&mut r, 2)?;
    let retry = r.ingest(KEY, &two, 2)?;
    assert_eq!(
        retry.transport.transport.disposition,
        ReorderDisposition::Buffered
    );
    let pictures = drain_clean(&mut r, 2)?;
    assert_eq!(pictures.len(), 1);
    assert_eq!(pictures[0].nals().len(), 2);
    assert!(!pictures[0].discontinuity_before());
    Ok(())
}

#[test]
fn syntax_refusal_returns_owned_nal_before_clean_recovery() -> TestResult {
    let mut r = receiver(limits())?;
    pending_picture(&mut r)?;
    r.ingest(KEY, &wire(KEY, 2, 90, true, &[0x41, 0]), 2)?;
    assert!(matches!(r.poll(2)?, AvcReceivePoll::Source { .. }));
    match r.poll(2)? {
        AvcReceivePoll::Assembly(AvcAssemblyStep::Refused(refusal)) => {
            assert_eq!(refusal.nal.bytes(), &[0x41, 0]);
            assert_eq!(
                refusal.retired.ok_or("malformed prefix retirement")?.nals,
                1
            );
        }
        _ => return Err("syntax refusal lost its owned NAL".into()),
    }
    r.ingest(KEY, &wire(KEY, 3, 100, true, &slice(0, 2)), 3)?;
    assert!(drain_clean(&mut r, 3)?[0].discontinuity_before());
    Ok(())
}

#[test]
fn debug_never_prints_queued_media() -> TestResult {
    let mut r = receiver(limits())?;
    let secret = b"DO-NOT-PRINT-PRIVATE-MEDIA";
    let mut sei = vec![6];
    sei.extend_from_slice(secret);
    r.ingest(KEY, &wire(KEY, 1, 90, false, &sei), 1)?;
    let event = r.poll(1)?;
    for value in [format!("{r:?}"), format!("{event:?}")] {
        assert!(!value.contains("DO-NOT-PRINT-PRIVATE-MEDIA"));
        assert!(!value.contains("68, 79, 45, 78, 79, 84"));
    }
    Ok(())
}

fn fixture(bytes: &[u8], times: &[u32], dimensions: (u32, u32)) -> TestResult {
    let nals = split(bytes);
    let policy = AvcReceiveLimits::default();
    let sps = parse_sps(nals[0], policy.syntax)?;
    let pps = parse_pps(nals[1], &sps, policy.syntax)?;
    let mut r = AvcReceiver::new(KEY, 96, H264Mode::NonInterleaved, policy, (sps, pps))?;
    r.ingest(KEY, &wire(KEY, 0, times[0], false, nals[0]), 0)?;
    let mut pictures = Vec::new();
    let mut frame = 0;
    let mut sources = 0;
    for (index, nal) in nals.iter().enumerate() {
        let now = index as u64 + 1;
        let source = wire(KEY, now, times[frame.min(times.len() - 1)], false, nal);
        r.ingest(KEY, &source, now)?;
        match r.poll(now)? {
            AvcReceivePoll::Source {
                source: saved,
                picture,
                fragment,
                ..
            } => {
                assert_eq!(saved.bytes(), source);
                assert!(picture.is_none() && fragment.is_none());
                sources += 1;
            }
            _ => return Err("clean source event missing".into()),
        }
        pictures.extend(drain_clean(&mut r, now)?);
        if matches!(nal[0] & 31, 1 | 5) {
            frame += 1;
        }
    }
    r.finish();
    match r.poll(100)? {
        AvcReceivePoll::Ended {
            fragment: None,
            interrupted_picture: None,
            tail: Some(tail),
        } => {
            assert!(tail.retired.is_none());
            if let Some(picture) = tail.picture {
                pictures.push(picture);
            }
        }
        _ => return Err("clean EOF did not produce classified tail".into()),
    }
    assert_eq!(sources, nals.len());
    assert_eq!(pictures.len(), times.len());
    assert_eq!(
        pictures.iter().map(|p| p.timestamp()).collect::<Vec<_>>(),
        times
    );
    assert!(
        pictures
            .iter()
            .all(|p| p.sps().display_dimensions() == dimensions)
    );
    assert!(
        pictures
            .iter()
            .all(|p| p.saw_first_macroblock() && !p.discontinuity_before())
    );
    assert_eq!(
        pictures.last().ok_or("no final picture")?.boundary(),
        AvcBoundary::EndOfInputUnverified
    );
    assert_eq!(r.retained_nal_bytes(), 0);
    Ok(())
}

#[test]
fn real_baseline_fixture_reaches_picture_groups_through_one_receiver() -> TestResult {
    fixture(
        include_bytes!("fixtures/avc/baseline.264"),
        &[90_000, 93_600, 97_200, 100_800],
        (160, 128),
    )
}

#[test]
fn real_high_b_picture_fixture_preserves_nonmonotonic_media_timestamps() -> TestResult {
    fixture(
        include_bytes!("fixtures/avc/high_cropped.264"),
        &[90_000, 100_800, 93_600, 97_200, 108_000, 104_400],
        (64, 36),
    )
}
