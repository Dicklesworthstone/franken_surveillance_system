#![forbid(unsafe_code)]
//! Native packet/assembly/replay contracts for continuous HEVC window collection.
mod hevc_recording_support;
use hevc_recording_support::*;
use fss_packet::{H265Depacketizer, H265Limits, PacketLimits, RtpPacket, StreamKey};
use fss_packet::hevc::{HevcAssembler, HevcAssemblyLimits, HevcAssemblyStep, HevcPictureGroup};
use fss_reference::rtsp::hevc_recording_collector::{HevcRecordingCollector, HevcCollectionAdmission};
use fss_reference::rtsp::recording::hevc::{PreparedHevcRecording, verify_hevc_recording};
use fss_reference::rtsp::recording_collector::{CollectionStop, CollectorError as E, CollectorLimits};

type TestResult = Result<(), Error>;
const KEY: StreamKey = StreamKey { ingress: 1, generation: 1, ssrc: SSRC };
fn collector(limits: CollectorLimits) -> Result<HevcRecordingCollector, Error> {
    Ok(HevcRecordingCollector::new(scope()?, KEY, PT, configuration()?, 90_000, limits)?)
}
fn observations(packets: &[Packet]) -> Result<Vec<(u64, HevcPictureGroup)>, Error> {
    let mut dep = H265Depacketizer::new(KEY, PT, 0, H265Limits::default())?;
    let mut a = HevcAssembler::new(KEY, HevcAssemblyLimits::default())?;
    let mut pictures = Vec::new();
    for p in packets {
        let output = dep.push(KEY, p.sequence, RtpPacket::parse(&p.bytes, PacketLimits::default())?, 0)?;
        assert!(!output.gap_before); assert!(output.discarded.is_none());
        for nal in output.nals {
            match a.push(nal, 0) {
                HevcAssemblyStep::Accepted(output) => {
                    assert!(output.retired.is_none()); assert!(output.standalone.is_none());
                    if let Some(picture) = output.picture { pictures.push((p.sequence, picture)); }
                }
                HevcAssemblyStep::Refused(r) => return Err(r.reason.into()),
            }
        }
    }
    assert!(dep.finish().is_none());
    // No assembler EOF flush: only actual source boundaries produce observations.
    Ok(pictures)
}
fn push(c: &mut HevcRecordingCollector, p: &Packet, now: u64) -> Result<(), Error> {
    c.push_source(KEY, borrowed(std::slice::from_ref(p))[0], now)?; Ok(())
}
fn drive(c: &mut HevcRecordingCollector, packets: &[Packet], take: bool)
    -> Result<Vec<PreparedHevcRecording>, Error>
{
    let groups = observations(packets)?;
    let timing = timings(groups.len());
    let mut windows = Vec::new();
    for (i, p) in packets.iter().enumerate() {
        push(c, p, i as u64)?;
        for (index, (_, picture)) in groups.iter().enumerate().filter(|(_, (seq, _))| *seq == p.sequence) {
            c.push_picture(picture, timing[index], i as u64)?;
            if take && let Some(window) = c.take_ready() { windows.push(window); }
        }
    }
    Ok(windows)
}
fn resequence(packets: &mut [Packet]) {
    for (i, p) in packets.iter_mut().enumerate() {
        p.sequence = 65_533 + i as u64;
        p.bytes[2..4].copy_from_slice(&(p.sequence as u16).to_be_bytes());
    }
}

#[test]
fn continuous_fixture_yields_two_replay_verified_idr_windows_with_exact_shared_witness() -> TestResult {
    let packets = packets()?;
    let mut c = collector(CollectorLimits::default())?;
    let mut windows = drive(&mut c, &packets, true)?;
    assert!(c.finish(20)?.window_ready);
    windows.push(c.take_ready().ok_or("final window")?);
    assert_eq!(windows.len(), 2);
    assert_eq!(windows[0].summary().decode_interval, 0..36_000);
    assert_eq!(windows[1].summary().decode_interval, 36_000..72_000);
    assert_eq!(windows[0].source_only_nals(), 1);
    assert_eq!(windows[1].source_only_nals(), 0);
    let left = windows[0].packets()?; let right = windows[1].packets()?;
    assert_eq!(left.last().ok_or("left witness")?.bytes, packets[5].bytes);
    assert_eq!(right.first().ok_or("right witness")?.bytes, packets[5].bytes);
    for window in &windows { verify_hevc_recording(window.manifest(), window.objects(), &scope()?)?; }
    let trailing = c.cancel();
    assert_eq!(trailing.reason, CollectionStop::EndOfInput);
    assert!(trailing.pictures.is_empty()); assert!(trailing.ready.is_none());
    assert_eq!(trailing.sources.last().ok_or("trailing EOS")?.bytes(), packets[10].bytes);
    Ok(())
}

#[test]
fn aggregation_starting_a_new_idr_is_cut_without_splitting_or_losing_parameters() -> TestResult {
    let original = packets()?; let n = nals()?;
    let mut input = original[..5].to_vec();
    input.push(packet(0, 36_000, true, &aggregate(&n[5..9])));
    input.extend_from_slice(&original[9..]); resequence(&mut input);
    let mut c = collector(CollectorLimits::default())?;
    let mut windows = drive(&mut c, &input, true)?;
    c.finish(20)?; windows.push(c.take_ready().ok_or("final root")?);
    assert_eq!(windows.len(), 2);
    assert_eq!(windows[0].source_only_nals(), 4);
    assert_eq!(windows[0].packets()?.last().ok_or("AP witness")?.bytes,
        windows[1].packets()?.first().ok_or("AP start")?.bytes);
    for w in windows { verify_hevc_recording(w.manifest(), w.objects(), &scope()?)?; }
    Ok(())
}

#[test]
fn same_packet_closes_previous_picture_and_next_idr_so_the_cut_is_deferred() -> TestResult {
    let n = nals()?;
    let mut input = vec![packet(1, 0, true, &aggregate(&n[..4]))];
    input.push(packet(2, 18_000, true, &n[4]));
    // The old picture's prefix boundary and the new IDR's EOS share one
    // packet. An old-only replay would also close the IDR, so the cut defers.
    let mut group = n[5..9].to_vec(); group.push(vec![0x48, 1, 0x80]);
    input.push(packet(3, 36_000, true, &aggregate(&group)));
    let mut c = collector(CollectorLimits::default())?;
    let mut windows = drive(&mut c, &input, true)?;
    assert!(windows.is_empty());
    c.finish(20)?; windows.push(c.take_ready().ok_or("deferred root")?);
    assert_eq!(windows[0].summary().samples, 3);
    assert_eq!(windows[0].packets()?.len(), 3);
    verify_hevc_recording(windows[0].manifest(), windows[0].objects(), &scope()?)?;
    Ok(())
}

#[test]
fn fragmented_boundary_parameter_keeps_every_fu_in_both_source_roots() -> TestResult {
    let original = packets()?; let n = nals()?; let vps = &n[5];
    let mut input = original[..5].to_vec();
    let split = 2 + (vps.len() - 2) / 2;
    for (flags, body) in [(0x80, &vps[2..split]), (0x40, &vps[split..])] {
        let mut fu = vec![0x62, 1, flags | 32]; fu.extend_from_slice(body);
        input.push(packet(0, 36_000, flags == 0x40, &fu));
    }
    input.extend_from_slice(&original[6..]); resequence(&mut input);
    let mut c = collector(CollectorLimits::default())?;
    let mut windows = drive(&mut c, &input, true)?;
    c.finish(20)?; windows.push(c.take_ready().ok_or("final")?);
    let left = windows[0].packets()?; let right = windows[1].packets()?;
    assert_eq!(left[left.len() - 2].bytes, right[0].bytes);
    assert_eq!(left[left.len() - 1].bytes, right[1].bytes);
    assert_eq!(windows[0].source_only_nals(), 1);
    assert_eq!(windows[1].mappings()[0].sources.len(), 2);
    Ok(())
}

#[test]
fn ready_output_backpressures_sources_and_retries_without_advancing_sequence() -> TestResult {
    let packets = packets()?;
    let mut c = collector(CollectorLimits::default())?;
    drive(&mut c, &packets[..10], false)?;
    assert!(c.has_ready()); let before = c.retained_packets();
    assert_eq!(c.push_source(KEY, borrowed(&packets[10..])[0], 10), Err(E::Backpressure));
    assert_eq!(c.retained_packets(), before);
    let ready = c.take_ready().ok_or("ready root")?;
    push(&mut c, &packets[10], 10)?;
    assert_eq!(ready.summary().samples, 2);
    assert_eq!(c.retained_packets(), before + 1);
    Ok(())
}

#[test]
fn corrected_timing_retries_same_borrowed_picture_and_preserves_source() -> TestResult {
    let input = packets()?; let groups = observations(&input)?;
    let mut c = collector(CollectorLimits::default())?;
    for (i, p) in input[..5].iter().enumerate() { push(&mut c, p, i as u64)?; }
    let mut t = timings(1)[0]; t.duration = 0;
    assert_eq!(c.push_picture(&groups[0].1, t, 4).err(), Some(E::Timeline));
    assert_eq!(c.retained_samples(), 0); assert_eq!(c.retained_packets(), 5);
    assert!(matches!(c.push_picture(&groups[0].1, timings(1)[0], 4)?, HevcCollectionAdmission::Accepted { .. }));
    assert_eq!(c.retained_samples(), 1);
    assert_eq!(c.push_picture(&groups[0].1, timings(2)[1], 4).err(), Some(E::SourceOrder));
    Ok(())
}

#[test]
fn wrong_owner_missing_source_and_reversed_clock_leave_collection_unchanged() -> TestResult {
    let input = packets()?; let groups = observations(&input)?;
    let mut c = collector(CollectorLimits::default())?;
    assert_eq!(c.push_picture(&groups[0].1, timings(1)[0], 0).err(), Some(E::MissingSource));
    push(&mut c, &input[0], 10)?;
    let wrong = StreamKey { generation: 2, ..KEY };
    assert_eq!(c.push_source(wrong, borrowed(&input[1..2])[0], 11), Err(E::StreamMismatch));
    assert_eq!(c.push_source(KEY, borrowed(&input[1..2])[0], 9), Err(E::ClockReversed));
    assert_eq!(c.push_source(KEY, borrowed(&input[2..3])[0], 11), Err(E::SourceOrder));
    assert_eq!(c.retained_packets(), 1);
    push(&mut c, &input[1], 10)?;
    assert_eq!(c.retained_packets(), 2);
    Ok(())
}

#[test]
fn rotation_preserves_original_lookahead_age_and_expiry_returns_all_ownership() -> TestResult {
    let input = packets()?;
    let limits = CollectorLimits { max_age_ns: 100, ..CollectorLimits::default() };
    let mut c = collector(limits)?;
    drive(&mut c, &input[..10], false)?;
    assert_eq!(c.next_wake_ns(), Some(105));
    assert!(c.expire(104)?.is_none());
    let stopped = c.expire(105)?.ok_or("expiry missing")?;
    assert_eq!(stopped.reason, CollectionStop::Deadline);
    assert_eq!(stopped.ready.ok_or("prepared root lost")?.summary().samples, 2);
    assert_eq!(stopped.sources.first().ok_or("lookahead lost")?.sequence(), input[5].sequence);
    assert_eq!(stopped.pictures.len(), 1);
    assert_eq!(c.retained_source_bytes(), 0); assert_eq!(c.next_wake_ns(), None);
    assert!(c.expire(106)?.is_none());
    assert_eq!(c.cancel().reason, CollectionStop::Deadline);
    Ok(())
}

#[test]
fn startup_predicted_picture_is_returned_to_owner_selection_not_fabricated_as_idr() -> TestResult {
    let n = nals()?;
    let input = vec![packet(1, 0, true, &n[4]), packet(2, 18_000, true, &n[3]),
        packet(3, 18_000, true, &[0x48, 1, 0x80])];
    let mut c = collector(CollectorLimits::default())?;
    let mut windows = drive(&mut c, &input, true)?;
    assert!(windows.is_empty());
    c.finish(10)?; windows.push(c.take_ready().ok_or("IDR root")?);
    assert_eq!(windows[0].summary().samples, 1);
    assert_eq!(windows[0].summary().decode_interval, 18_000..36_000);
    assert_eq!(windows[0].packets()?.first().ok_or("source")?.sequence, 2);
    Ok(())
}

#[test]
fn explicit_seal_preserves_real_witness_and_unclosed_eof_tail_is_not_recorded() -> TestResult {
    let input = packets()?;
    let mut c = collector(CollectorLimits::default())?;
    let mut windows = drive(&mut c, &input[..10], true)?;
    c.finish(20)?; windows.push(c.take_ready().ok_or("closed prefix")?);
    assert_eq!(windows.iter().map(|w| w.summary().samples).sum::<usize>(), 3);
    assert_eq!(windows[1].source_only_nals(), 1);
    assert_eq!(windows[1].summary().decode_interval, 36_000..54_000);
    let tail = c.cancel();
    assert!(tail.sources.iter().any(|p| p.bytes() == input[9].bytes));
    Ok(())
}

#[test]
fn source_and_sample_capacity_refusals_preserve_exact_retryable_inputs() -> TestResult {
    let input = packets()?; let groups = observations(&input)?;
    let mut c = collector(CollectorLimits { max_packets: 1, ..CollectorLimits::default() })?;
    push(&mut c, &input[0], 0)?;
    assert_eq!(c.push_source(KEY, borrowed(&input[1..2])[0], 1), Err(E::Capacity));
    assert_eq!(c.cancel().sources[0].bytes(), input[0].bytes);
    let mut c = collector(CollectorLimits { max_samples: 1, ..CollectorLimits::default() })?;
    for (i, p) in input[..6].iter().enumerate() { push(&mut c, p, i as u64)?; }
    c.push_picture(&groups[0].1, timings(2)[0], 5)?;
    assert_eq!(c.push_picture(&groups[1].1, timings(2)[1], 5).err(), Some(E::Capacity));
    assert_eq!(c.retained_samples(), 1); assert_eq!(c.retained_packets(), 6);
    Ok(())
}

#[test]
fn deterministic_roots_keep_receive_times_and_reject_rebound_source_bytes() -> TestResult {
    let mut input = packets()?;
    for (i, p) in input.iter_mut().enumerate() { p.received_ns = 1000 - i as u64; }
    let mut left = collector(CollectorLimits::default())?;
    let mut right = collector(CollectorLimits::default())?;
    let a = drive(&mut left, &input, true)?; let b = drive(&mut right, &input, true)?;
    assert_eq!(a[0].manifest(), b[0].manifest());
    assert_eq!(a[0].packets()?[0].received_ns, 1000);
    assert_eq!(a[0].packets()?[1].received_ns, 999);
    let groups = observations(&input)?;
    let mut c = collector(CollectorLimits::default())?;
    input[3].bytes[14] ^= 1;
    for (i, p) in input[..5].iter().enumerate() { push(&mut c, p, i as u64)?; }
    assert_eq!(c.push_picture(&groups[0].1, timings(1)[0], 4).err(), Some(E::Source));
    assert_eq!(c.retained_samples(), 0);
    Ok(())
}
