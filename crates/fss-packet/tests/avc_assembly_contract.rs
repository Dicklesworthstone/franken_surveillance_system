#![forbid(unsafe_code)]
//! Real RTP-to-picture integration and adverse lifecycle/ownership contracts.

mod avc_support;

use avc_support::{Error, KEY, accept, nal, parameters, slice, split, wire};
use fss_packet::{H264Depacketizer, H264Limits, H264Mode, H264ReceivePoll, H264Receiver,
    PacketLimits, ReorderLimits, RtpPacket, StreamKey};
use fss_packet::avc::{AvcAssembler, AvcAssemblyError, AvcAssemblyLimits, AvcAssemblyPoll,
    AvcAssemblyStep, AvcBoundary, AvcRetirementReason, AvcSyntaxLimits, parse_pps, parse_sps};

type TestResult = Result<(), Error>;

fn assembler(limits: AvcAssemblyLimits) -> Result<AvcAssembler, Error> {
    let (sps, pps) = parameters()?;
    Ok(AvcAssembler::new(KEY, sps, pps, AvcSyntaxLimits::default(), limits)?)
}

#[test]
fn aud_less_multi_slice_group_is_not_split_by_first_macroblock_zero() -> TestResult {
    let mut a = assembler(AvcAssemblyLimits::default())?;
    assert!(accept(a.push(nal(KEY, 1, 90, false, &slice(20, 1))?, 0))?.picture.is_none());
    assert!(accept(a.push(nal(KEY, 2, 90, false, &slice(0, 1))?, 1))?.picture.is_none());
    let output = accept(a.push(nal(KEY, 3, 100, false, &slice(20, 2))?, 2))?;
    let first = output.picture.ok_or("expected preceding picture")?;
    assert_eq!(first.nals().len(), 2);
    assert!(first.saw_first_macroblock());
    assert_eq!(first.boundary(), AvcBoundary::NextPrimaryPicture);
    let tail = a.finish(3)?.picture.ok_or("expected unverified tail")?;
    assert!(!tail.saw_first_macroblock());
    assert_eq!(tail.boundary(), AvcBoundary::EndOfInputUnverified);
    Ok(())
}

#[test]
fn one_push_can_close_previous_picture_and_queue_marked_next_picture() -> TestResult {
    let mut a = assembler(AvcAssemblyLimits::default())?;
    accept(a.push(nal(KEY, 1, 90, false, &slice(0, 1))?, 0))?;
    let output = accept(a.push(nal(KEY, 2, 100, true, &slice(0, 2))?, 1))?;
    assert_eq!(output.picture.ok_or("prior picture")?.identity().frame_num(), 1);
    assert_eq!(a.next_wake_ns(), Some(1));
    let refused = match a.push(nal(KEY, 3, 110, true, &slice(0, 3))?, 2) {
        AvcAssemblyStep::Refused(r) => r,
        _ => return Err("must drain ready output before more input".into()),
    };
    assert_eq!(refused.reason, AvcAssemblyError::OutputPending);
    assert!(refused.retired.is_none());
    match a.poll(2)? {
        AvcAssemblyPoll::Picture(p) => {
            assert_eq!(p.identity().frame_num(), 2);
            assert_eq!(p.boundary(), AvcBoundary::RtpMarker);
        }
        _ => return Err("ready picture not drained".into()),
    }
    let last = accept(a.push(refused.nal, 2))?.picture.ok_or("retry picture")?;
    assert_eq!(last.identity().frame_num(), 3);
    assert_eq!(a.pending_bytes(), 0);
    Ok(())
}

#[test]
fn delayed_ready_drain_preserves_marker_on_finish() -> TestResult {
    let mut a = assembler(AvcAssemblyLimits::default())?;
    accept(a.push(nal(KEY, 1, 90, false, &slice(0, 1))?, 0))?;
    accept(a.push(nal(KEY, 2, 100, true, &slice(0, 2))?, 1))?;
    let p = a.finish(2)?.picture.ok_or("marked tail")?;
    assert_eq!(p.boundary(), AvcBoundary::RtpMarker);
    assert!(a.finish(2)?.picture.is_none());
    assert!(matches!(a.poll(2)?, AvcAssemblyPoll::Ended));
    Ok(())
}

#[test]
fn false_marker_cannot_create_duplicate_picture_groups() -> TestResult {
    let mut a = assembler(AvcAssemblyLimits::default())?;
    let first = accept(a.push(nal(KEY, 1, 90, true, &slice(0, 1))?, 0))?;
    assert!(first.picture.is_some());
    match a.push(nal(KEY, 2, 90, true, &slice(20, 1))?, 1) {
        AvcAssemblyStep::Refused(r) => assert_eq!(r.reason, AvcAssemblyError::PictureAlreadyEmitted),
        _ => return Err("false marker duplicated an already emitted picture".into()),
    }
    Ok(())
}

#[test]
fn wrong_epoch_and_reversed_time_cannot_retire_another_pending_picture() -> TestResult {
    let mut a = assembler(AvcAssemblyLimits::default())?;
    accept(a.push(nal(KEY, 1, 90, false, &slice(0, 1))?, 100))?;
    let retained = a.pending_bytes();
    let other = StreamKey { ingress: 99, ..KEY };
    for (key, now, expected) in [(other, 101, AvcAssemblyError::StreamMismatch), (KEY, 99, AvcAssemblyError::ClockReversed)] {
        match a.push(nal(key, 2, 90, true, &slice(20, 1))?, now) {
            AvcAssemblyStep::Refused(r) => { assert_eq!(r.reason, expected); assert!(r.retired.is_none()); }
            _ => return Err("invalid binding/time admitted".into()),
        }
        assert_eq!(a.pending_bytes(), retained);
    }
    assert_eq!(a.discontinuity(other, 101), Err(AvcAssemblyError::StreamMismatch));
    assert_eq!(a.pending_bytes(), retained);
    Ok(())
}

#[test]
fn overlapping_source_spans_are_refused_without_extending_deadline() -> TestResult {
    let mut a = assembler(AvcAssemblyLimits { max_age_ns: 10, ..AvcAssemblyLimits::default() })?;
    accept(a.push(nal(KEY, 1, 90, false, &slice(0, 1))?, 0))?;
    match a.push(nal(KEY, 1, 90, false, &slice(20, 1))?, 9) {
        AvcAssemblyStep::Refused(r) => assert_eq!(r.reason, AvcAssemblyError::SourceOrder),
        _ => return Err("overlapping original source accepted".into()),
    }
    assert_eq!(a.next_wake_ns(), Some(10));
    match a.poll(10)? {
        AvcAssemblyPoll::Retired(r) => assert_eq!(r.reason, AvcRetirementReason::Deadline),
        _ => return Err("timer did not retire pending picture".into()),
    }
    assert!(matches!(a.poll(10)?, AvcAssemblyPoll::Pending { wake_at_ns: None }));
    Ok(())
}

#[test]
fn distinct_stap_nal_spans_in_one_datagram_are_admitted_in_order() -> TestResult {
    let (sps, pps) = parameters()?;
    let first = slice(0, 1); let second = slice(20, 1);
    let mut payload = vec![0x78];
    for bytes in [sps.nal_bytes(), pps.nal_bytes(), first.as_slice(), second.as_slice()] {
        payload.extend_from_slice(&(bytes.len() as u16).to_be_bytes()); payload.extend_from_slice(bytes);
    }
    let bytes = wire(KEY, 1, 90, true, &payload);
    let mut d = H264Depacketizer::new(KEY, 96, H264Mode::NonInterleaved, H264Limits::default())?;
    let reconstructed = d.push(KEY, 1, RtpPacket::parse(&bytes, PacketLimits::default())?, 0)?;
    let mut a = AvcAssembler::new(KEY, sps, pps, AvcSyntaxLimits::default(), AvcAssemblyLimits::default())?;
    let mut group = None;
    for nal in reconstructed.nals {
        let output = accept(a.push(nal, 0))?;
        if output.picture.is_some() { group = output.picture; }
    }
    let picture = group.ok_or("no assembled STAP picture")?;
    assert_eq!(picture.nals().len(), 4);
    assert!(picture.nals().iter().all(|n| n.sources()[0].sequence == 1));
    assert_eq!(picture.boundary(), AvcBoundary::RtpMarker);
    Ok(())
}

#[test]
fn exact_parameter_change_fences_epoch_and_requires_explicit_restart() -> TestResult {
    let (sps, pps) = parameters()?;
    let mut changed = sps.nal_bytes().to_vec(); changed[3] += 1;
    let new_sps = parse_sps(&changed, AvcSyntaxLimits::default())?;
    let new_pps = parse_pps(pps.nal_bytes(), &new_sps, AvcSyntaxLimits::default())?;
    let mut a = assembler(AvcAssemblyLimits::default())?;
    accept(a.push(nal(KEY, 1, 90, false, &slice(0, 1))?, 0))?;
    match a.push(nal(KEY, 2, 100, false, &changed)?, 1) {
        AvcAssemblyStep::Refused(r) => {
            assert_eq!(r.reason, AvcAssemblyError::ConfigurationChanged);
            assert_eq!(r.nal.bytes(), changed);
            assert_eq!(r.retired.ok_or("missing old-generation retirement")?.reason, AvcRetirementReason::ConfigurationChanged);
        }
        _ => return Err("silent parameter replacement".into()),
    }
    assert!(matches!(a.push(nal(KEY, 3, 100, true, &slice(0, 2))?, 2), AvcAssemblyStep::Refused(_)));
    assert!(matches!(a.restart(KEY, new_sps.clone(), new_pps.clone()), Err(AvcAssemblyError::GenerationRequired)));
    let next_key = StreamKey { generation: 2, ..KEY };
    let (mut next, old) = a.restart(next_key, new_sps, new_pps)?;
    assert!(old.is_none());
    let p = accept(next.push(nal(next_key, 1, 100, true, &slice(0, 2))?, 0))?.picture.ok_or("new epoch")?;
    assert_eq!(p.sps().nal_bytes(), changed);
    assert_eq!(p.key(), next_key);
    Ok(())
}

#[test]
fn repeated_identical_parameter_bytes_do_not_change_configuration() -> TestResult {
    let (sps, pps) = parameters()?; let mut a = assembler(AvcAssemblyLimits::default())?;
    accept(a.push(nal(KEY, 1, 0, false, sps.nal_bytes())?, 0))?;
    accept(a.push(nal(KEY, 2, 0, false, pps.nal_bytes())?, 1))?;
    let p = accept(a.push(nal(KEY, 3, 90, true, &slice(0, 1))?, 2))?.picture.ok_or("picture")?;
    assert_eq!(p.sps().nal_bytes(), sps.nal_bytes());
    assert_eq!(p.pps().nal_bytes(), pps.nal_bytes());
    assert_eq!(p.nals().len(), 3);
    Ok(())
}

#[test]
fn gaps_retire_partial_group_and_preserve_discontinuity_on_recovery() -> TestResult {
    let mut a = assembler(AvcAssemblyLimits::default())?;
    accept(a.push(nal(KEY, 1, 90, false, &slice(0, 1))?, 0))?;
    let retired = a.discontinuity(KEY, 1)?.ok_or("gap retirement")?;
    assert_eq!(retired.reason, AvcRetirementReason::InputDiscontinuity);
    assert_eq!((retired.first_sequence, retired.last_sequence), (Some(1), Some(1)));
    assert!(a.discontinuity(KEY, 1)?.is_none());
    let p = accept(a.push(nal(KEY, 4, 90, true, &slice(20, 1))?, 2))?.picture.ok_or("recovered partial group")?;
    assert!(p.discontinuity_before());
    assert!(!p.saw_first_macroblock());
    assert_eq!(p.nals().len(), 1);
    Ok(())
}

#[test]
fn timestamp_conflict_cannot_publish_mixed_sampling_instants() -> TestResult {
    let mut a = assembler(AvcAssemblyLimits::default())?;
    accept(a.push(nal(KEY, 1, 90, false, &slice(0, 1))?, 0))?;
    match a.push(nal(KEY, 2, 91, true, &slice(20, 1))?, 1) {
        AvcAssemblyStep::Refused(r) => {
            assert_eq!(r.reason, AvcAssemblyError::TimestampMismatch);
            assert_eq!(r.retired.ok_or("retirement")?.nals, 1);
        }
        _ => return Err("mixed timestamps admitted".into()),
    }
    assert_eq!(a.pending_nals(), 0);
    Ok(())
}

#[test]
fn metadata_prefix_after_vcl_ends_previous_group_without_fabricating_a_frame() -> TestResult {
    let mut a = assembler(AvcAssemblyLimits::default())?;
    accept(a.push(nal(KEY, 1, 90, false, &slice(0, 1))?, 0))?;
    let output = accept(a.push(nal(KEY, 2, 100, false, &[9, 0x10])?, 1))?;
    assert_eq!(output.picture.ok_or("previous group")?.boundary(), AvcBoundary::NextAccessUnitPrefix);
    let end = a.finish(2)?;
    assert!(end.picture.is_none());
    assert_eq!(end.retired.ok_or("metadata-only retirement")?.reason, AvcRetirementReason::NoPrimaryPicture);
    Ok(())
}

#[test]
fn malformed_codec_input_returns_its_original_nal_and_retires_pending_group() -> TestResult {
    let mut a = assembler(AvcAssemblyLimits::default())?;
    accept(a.push(nal(KEY, 1, 90, false, &slice(0, 1))?, 0))?;
    match a.push(nal(KEY, 2, 90, true, &[0x41, 0])?, 1) {
        AvcAssemblyStep::Refused(r) => {
            assert!(matches!(r.reason, AvcAssemblyError::Syntax(_)));
            assert_eq!(r.nal.bytes(), &[0x41, 0]);
            assert_eq!(r.nal.sources()[0].sequence, 2);
            assert_eq!(r.retired.ok_or("old grouping retirement")?.reason, AvcRetirementReason::InvalidInput);
        }
        _ => return Err("malformed slice accepted".into()),
    }
    Ok(())
}

#[test]
fn nal_and_byte_capacity_retire_derivative_without_losing_rejected_source() -> TestResult {
    for limits in [
        AvcAssemblyLimits { max_nals: 1, ..AvcAssemblyLimits::default() },
        AvcAssemblyLimits { max_bytes: slice(0, 1).len(), ..AvcAssemblyLimits::default() },
    ] {
        let mut a = assembler(limits)?;
        accept(a.push(nal(KEY, 1, 90, false, &slice(0, 1))?, 0))?;
        let input = slice(20, 1);
        match a.push(nal(KEY, 2, 90, true, &input)?, 1) {
            AvcAssemblyStep::Refused(r) => {
                assert_eq!(r.reason, AvcAssemblyError::Limit);
                assert_eq!(r.nal.bytes(), input);
                assert_eq!(r.retired.ok_or("retired old derivative")?.nals, 1);
            }
            _ => return Err("assembly exceeded its resource ceiling".into()),
        }
        assert_eq!(a.pending_bytes(), 0);
        let recovered = accept(a.push(nal(KEY, 3, 100, true, &slice(0, 2))?, 2))?.picture.ok_or("recovered group")?;
        assert!(recovered.discontinuity_before());
    }
    Ok(())
}

#[test]
fn no_pending_picture_can_have_an_unrepresentable_deadline() -> TestResult {
    let mut a = assembler(AvcAssemblyLimits { max_age_ns: 10, ..AvcAssemblyLimits::default() })?;
    match a.push(nal(KEY, 1, 90, false, &slice(0, 1))?, u64::MAX - 5) {
        AvcAssemblyStep::Refused(r) => assert_eq!(r.reason, AvcAssemblyError::Limit),
        _ => return Err("stranded unrepresentable deadline".into()),
    }
    assert_eq!(a.pending_bytes(), 0);
    assert_eq!(a.next_wake_ns(), None);
    Ok(())
}

#[test]
fn cancellation_and_restart_have_exactly_once_retirement() -> TestResult {
    let (sps, pps) = parameters()?; let mut a = assembler(AvcAssemblyLimits::default())?;
    accept(a.push(nal(KEY, 1, 90, false, &slice(0, 1))?, 0))?;
    assert!(matches!(a.restart(KEY, sps.clone(), pps.clone()), Err(AvcAssemblyError::GenerationRequired)));
    assert_eq!(a.pending_nals(), 1);
    let (mut next, old) = a.restart(StreamKey { generation: 2, ..KEY }, sps, pps)?;
    assert_eq!(old.ok_or("restart retirement")?.reason, AvcRetirementReason::Restarted);
    assert!(a.cancel().is_none());
    let key = StreamKey { generation: 2, ..KEY };
    accept(next.push(nal(key, 1, 90, false, &slice(0, 1))?, 0))?;
    assert_eq!(next.cancel().ok_or("cancel retirement")?.reason, AvcRetirementReason::Cancelled);
    assert!(next.cancel().is_none());
    assert!(matches!(next.poll(1)?, AvcAssemblyPoll::Ended));
    Ok(())
}

#[test]
fn explicit_stream_end_is_not_relabelled_as_an_unverified_tail() -> TestResult {
    let mut a = assembler(AvcAssemblyLimits::default())?;
    accept(a.push(nal(KEY, 1, 90, false, &slice(0, 1))?, 0))?;
    let p = accept(a.push(nal(KEY, 2, 90, false, &[11, 0x80])?, 1))?.picture.ok_or("stream-end group")?;
    assert_eq!(p.boundary(), AvcBoundary::EndOfStream);
    assert_eq!(p.nals().len(), 2);
    assert!(matches!(a.poll(1)?, AvcAssemblyPoll::Ended));
    Ok(())
}

fn receiver_fixture(bytes: &[u8], times: &[u32], dimensions: (u32, u32)) -> TestResult {
    let l = AvcSyntaxLimits::default(); let nals = split(bytes);
    let sps = parse_sps(nals[0], l)?; let pps = parse_pps(nals[1], &sps, l)?;
    let mut assembler = AvcAssembler::new(KEY, sps, pps, l, AvcAssemblyLimits::default())?;
    let mut receiver = H264Receiver::new(KEY, 96, H264Mode::NonInterleaved, ReorderLimits::default(), H264Limits::default())?;
    receiver.ingest(KEY, &wire(KEY, 0, times[0], false, nals[0]), 0)?;
    let mut groups = Vec::new(); let mut frame = 0;
    for (index, bytes) in nals.iter().enumerate() {
        let timestamp = times[frame.min(times.len() - 1)];
        let wire = wire(KEY, index as u64 + 1, timestamp, false, bytes);
        let now = index as u64 + 1;
        receiver.ingest(KEY, &wire, now)?;
        loop {
            match receiver.poll(now)? {
                H264ReceivePoll::Packet { source, reconstruction } => {
                    assert_eq!(source.packet()?.wire_bytes(), wire);
                    let output = reconstruction?;
                    assert!(!output.gap_before && output.discarded.is_none());
                    for nal in output.nals {
                        let step = accept(assembler.push(nal, now))?;
                        assert!(step.retired.is_none());
                        if let Some(picture) = step.picture { groups.push(picture); }
                        while let AvcAssemblyPoll::Picture(picture) = assembler.poll(now)? { groups.push(picture); }
                    }
                }
                H264ReceivePoll::Pending { .. } => break,
                _ => return Err("unexpected fault in clean real-bitstream replay".into()),
            }
        }
        if matches!(bytes[0] & 31, 1 | 5) { frame += 1; }
    }
    receiver.finish();
    assert!(matches!(receiver.poll(100)?, H264ReceivePoll::Ended { discarded: None }));
    if let Some(picture) = assembler.finish(100)?.picture { groups.push(picture); }
    assert_eq!(groups.len(), times.len());
    assert_eq!(groups.iter().map(|g| g.timestamp()).collect::<Vec<_>>(), times);
    assert!(groups.iter().all(|g| g.sps().display_dimensions() == dimensions));
    assert!(groups.iter().all(|g| g.saw_first_macroblock() && !g.discontinuity_before()));
    assert_eq!(groups.last().ok_or("no pictures")?.boundary(), AvcBoundary::EndOfInputUnverified);
    Ok(())
}

#[test]
fn baseline_rtp_to_nal_to_parameter_bound_picture_replay() -> TestResult {
    receiver_fixture(include_bytes!("fixtures/avc/baseline.264"), &[90_000, 93_600, 97_200, 100_800], (160, 128))
}

#[test]
fn high_rtp_replay_preserves_b_picture_timestamp_order_and_cropping() -> TestResult {
    receiver_fixture(include_bytes!("fixtures/avc/high_cropped.264"), &[90_000, 100_800, 93_600, 97_200, 108_000, 104_400], (64, 36))
}
