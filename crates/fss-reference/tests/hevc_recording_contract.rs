#![forbid(unsafe_code)]
//! Immutable HEVC recording contracts, from real RTP reconstruction through exact byte replay.
mod hevc_recording_support;
use hevc_recording_support::*;
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_object::ObjectManifest;
use fss_packet::hevc::HevcBoundary;
use fss_reference::rtsp::recording::{RecordingError as E, RecordingObjects, verify_recording};
use fss_reference::rtsp::recording::hevc::{
    HEVC_RECORDING_KIND, PreparedHevcRecording, prepare_hevc_recording, verify_hevc_recording,
};
type TestResult = Result<(), Error>;

fn boundary(b: HevcBoundary) -> u64 {
    match b {
        HevcBoundary::NextFirstSlice => 1, HevcBoundary::NextAccessUnitPrefix => 2,
        HevcBoundary::AccessUnitDelimiter => 3, HevcBoundary::EndOfSequence => 4,
        HevcBoundary::EndOfBitstream => 5, HevcBoundary::EndOfInputUnverified => 6,
    }
}
fn range(e: &mut CanonicalEncoder, r: &std::ops::Range<usize>) { e.u64(r.start as u64); e.u64(r.end as u64); }
// Write the documented v1 layout independently, including deliberately rehashed
// mutations. A new root alone must not make false byte relationships valid.
fn index(plan: &PreparedHevcRecording, source: &[u8], init: &[u8], media: &[u8], mutation: u8)
    -> Result<Vec<u8>, Error>
{
    let s = &plan.summary().scope;
    let mut e = CanonicalEncoder::new();
    e.text("fss.hevc_recording_window.index.v1"); e.text(s.sensor.as_str()); e.text(s.stream.as_str());
    e.u64(s.generation); e.digest(s.anchor); e.digest(s.receive_clock);
    e.u32(SSRC); e.u32(u32::from(PT)); e.u32(plan.summary().time_scale);
    e.digest(ContentDigest::sha256(source)); e.digest(ContentDigest::sha256(init)); e.digest(ContentDigest::sha256(media));
    for (i, r) in plan.parameter_ranges().iter().enumerate() {
        if mutation == 6 && i == 0 { range(&mut e, &(r.start + 1..r.end)); } else { range(&mut e, r); }
    }
    e.u64((plan.source_only_nals() + usize::from(mutation == 5)) as u64);
    e.u64(plan.samples().len() as u64);
    for (i, sample) in plan.samples().iter().enumerate() {
        range(&mut e, &sample.range); e.u64(sample.decode_time); e.u64(sample.presentation_time);
        e.u32(sample.duration); e.u32(sample.rtp_timestamp + u32::from(mutation == 2 && i == 0));
        e.bool(if mutation == 3 && i == 0 { !sample.idr } else { sample.idr });
        e.u64(if mutation == 1 && i == 0 { 4 } else { boundary(sample.boundary) });
        range(&mut e, &sample.mappings);
    }
    e.u64(plan.mappings().len() as u64);
    for (i, m) in plan.mappings().iter().enumerate() {
        e.u64((m.sample + usize::from(mutation == 7 && i == 0)) as u64);
        e.u64(m.nal as u64); range(&mut e, &m.range); e.u64(m.sources.len() as u64);
        for span in &m.sources {
            e.u64(span.sequence);
            if mutation == 4 && i == 0 { range(&mut e, &(span.wire_range.start + 1..span.wire_range.end)); }
            else { range(&mut e, &span.wire_range); }
            range(&mut e, &span.nal_range); e.bool(span.fragment_header_range.is_some());
            if let Some(r) = &span.fragment_header_range { range(&mut e, r); }
        }
    }
    Ok(e.finish_checked()?)
}
fn manifest(objects: RecordingObjects<'_>) -> Result<ObjectManifest, Error> {
    Ok(ObjectManifest::new(HEVC_RECORDING_KIND, [ContentDigest::sha256(objects.source),
        ContentDigest::sha256(objects.initialization), ContentDigest::sha256(objects.media)],
        Some(ContentDigest::sha256(objects.index)))?)
}

#[test]
fn real_recording_retains_all_originals_and_replays_identical_media_and_maps() -> TestResult {
    let originals = packets()?;
    let plan = prepare(&originals, &timings(4))?;
    assert_eq!(plan.manifest().kind(), HEVC_RECORDING_KIND);
    assert_eq!(plan.manifest().children().len(), 4);
    assert_eq!(plan.summary().packets, 11);
    assert_eq!(plan.summary().samples, 4);
    assert_eq!(plan.summary().nals, 11);
    assert_eq!(plan.summary().decode_interval, 0..72_000);
    assert_eq!(plan.source_only_nals(), 0);
    assert_eq!(plan.objects().source, pack(&originals)?);
    assert_eq!(plan.objects().index, index(&plan, plan.objects().source, plan.objects().initialization, plan.objects().media, 0)?);
    let verified = verify_hevc_recording(plan.manifest(), plan.objects(), &scope()?)?;
    assert_eq!(&verified.recording, plan.summary()); assert_eq!(verified.source_only_nals, 0);
    for (original, reopened) in originals.iter().zip(plan.packets()?) {
        assert_eq!(original.sequence, reopened.sequence);
        assert_eq!(original.received_ns, reopened.received_ns);
        assert_eq!(original.bytes, reopened.bytes);
    }
    for mapping in plan.mappings() {
        for span in &mapping.sources {
            let packet = originals.iter().find(|p| p.sequence == span.sequence).ok_or("missing original")?;
            assert_eq!(&packet.bytes[span.wire_range.clone()],
                &plan.objects().media[mapping.range.start + span.nal_range.start..mapping.range.start + span.nal_range.end]);
        }
    }
    assert!(!format!("{plan:?}").contains(FIXTURE.lines().next().ok_or("fixture empty")?));
    Ok(())
}

#[test]
fn boundary_witness_remains_in_source_instead_of_becoming_a_media_sample() -> TestResult {
    let originals = packets()?;
    // The next VPS proves the end of the second picture; all three next
    // parameter NALs stay source-only, not part of the two remuxed samples.
    let plan = prepare(&originals[..8], &timings(2))?;
    assert_eq!(plan.summary().packets, 8); assert_eq!(plan.summary().samples, 2);
    assert_eq!(plan.source_only_nals(), 3);
    assert_eq!(plan.summary().nals, 5);
    assert_eq!(plan.samples()[1].boundary, HevcBoundary::NextAccessUnitPrefix);
    assert_eq!(plan.objects().source, pack(&originals[..8])?);
    let verified = verify_hevc_recording(plan.manifest(), plan.objects(), &scope()?)?;
    assert_eq!(verified.source_only_nals, 3);
    assert!(prepare(&originals[..5], &timings(2)).is_err()); // no closing witness
    Ok(())
}

#[test]
fn a_marked_eof_tail_never_becomes_a_verified_recording_picture() -> TestResult {
    let originals = packets()?;
    assert!(prepare(&originals[..10], &timings(4)).is_err());
    assert!(prepare(&originals[..4], &timings(1)).is_err());
    assert!(prepare(&originals, &timings(5)).is_err());
    assert!(prepare(&originals, &timings(3)).is_err()); // no silent truncation of a complete group
    Ok(())
}

#[test]
fn aggregation_and_fragmentation_retain_exact_source_and_header_synthesis() -> TestResult {
    let n = nals()?;
    let split = 2 + (n[3].len() - 2) / 2;
    let kind = (n[3][0] >> 1) & 63;
    let mut start = vec![0x62, 1, 0x80 | kind]; start.extend_from_slice(&n[3][2..split]);
    let mut end = vec![0x62, 1, 0x40 | kind]; end.extend_from_slice(&n[3][split..]);
    let source = vec![packet(65_534, 0, false, &aggregate(&n[..3])),
        packet(65_535, 0, false, &start), packet(65_536, 0, true, &end),
        packet(65_537, 0, true, &[0x48, 1, 0x80])];
    let plan = prepare(&source, &timings(1))?;
    assert_eq!(plan.summary().packets, 4); assert_eq!(plan.summary().nals, 5);
    let mapping = &plan.mappings()[3];
    assert_eq!(mapping.sources.len(), 2);
    assert_eq!(mapping.sources[0].fragment_header_range, Some(12..15));
    assert_eq!(mapping.sources[1].sequence, 65_536);
    assert_eq!(&plan.objects().media[mapping.range.clone()], n[3]);
    verify_hevc_recording(plan.manifest(), plan.objects(), &scope()?)?;
    assert!(prepare(&source[..2], &timings(1)).is_err());
    Ok(())
}

#[test]
fn gaps_duplicates_reordering_wrong_payload_and_wrong_ssrc_are_not_sealable() -> TestResult {
    for case in 0..6 {
        let mut source = packets()?;
        match case {
            0 => { source.remove(4); }
            1 => { source.insert(4, source[3].clone()); }
            2 => source.swap(3, 4),
            3 => source[3].bytes[1] ^= 1,
            4 => source[3].bytes[11] ^= 1,
            _ => source[3].sequence += 65_536,
        }
        assert!(prepare(&source, &timings(4)).is_err(), "source case {case}");
    }
    Ok(())
}

#[test]
fn saved_arrival_order_is_not_a_decode_clock_and_changes_only_the_bound_source_root() -> TestResult {
    let source = packets()?;
    let a = prepare(&source, &timings(4))?;
    let mut reordered_arrivals = source.clone();
    reordered_arrivals[4].received_ns = 1;
    let b = prepare(&reordered_arrivals, &timings(4))?;
    assert_eq!(a.objects().media, b.objects().media);
    assert_ne!(a.objects().source, b.objects().source);
    assert_ne!(a.manifest().root(), b.manifest().root());
    verify_hevc_recording(b.manifest(), b.objects(), &scope()?)?;
    assert_eq!(b.packets()?[4].received_ns, 1);
    let again = prepare(&source, &timings(4))?;
    assert_eq!(a.manifest(), again.manifest()); assert_eq!(a.objects().index, again.objects().index);
    Ok(())
}

#[test]
fn explicit_signed_timing_and_invalid_timeline_checks_survive_readback() -> TestResult {
    let source = packets()?;
    let mut t = timings(4); let base = u64::from(u32::MAX) + 17;
    for value in &mut t { value.decode_time += base; }
    t[0].composition_offset = 9_000; t[1].composition_offset = -9_000;
    let plan = prepare(&source, &t)?;
    assert_eq!(plan.samples()[0].presentation_time, base + 9_000);
    assert_eq!(plan.samples()[1].presentation_time, base + 9_000);
    verify_hevc_recording(plan.manifest(), plan.objects(), &scope()?)?;
    for case in 0..4 {
        let mut t = timings(4);
        match case {
            0 => t[0].duration = 0,
            1 => t[1].decode_time += 1,
            2 => t[0].composition_offset = -1,
            _ => t[0].decode_time = u64::MAX,
        }
        assert!(prepare(&source, &t).is_err());
    }
    Ok(())
}

#[test]
fn every_scope_coordinate_is_externally_pinned_and_avc_reader_stays_separate() -> TestResult {
    let plan = fixture()?;
    for case in 0..5 {
        let mut expected = scope()?;
        match case {
            0 => expected.sensor = fss_core::SensorId::parse("sensor-other")?,
            1 => expected.stream = fss_core::StreamId::parse("stream-other")?,
            2 => expected.generation += 1,
            3 => expected.anchor = ContentDigest::sha256(b"other-anchor"),
            _ => expected.receive_clock = ContentDigest::sha256(b"other-clock"),
        }
        assert_eq!(verify_hevc_recording(plan.manifest(), plan.objects(), &expected).err(), Some(E::Scope));
    }
    assert!(verify_recording(plan.manifest(), plan.objects(), &scope()?).is_err());
    Ok(())
}

#[test]
fn rehashing_forged_boundaries_timestamps_idr_flags_maps_or_lookahead_does_not_validate_them() -> TestResult {
    let plan = fixture()?; let original = plan.objects();
    for mutation in 1..=7 {
        let encoded = index(&plan, original.source, original.initialization, original.media, mutation)?;
        let objects = RecordingObjects { index: &encoded, ..original };
        let root = manifest(objects)?;
        assert_ne!(root.root(), plan.manifest().root());
        assert!(verify_hevc_recording(&root, objects, &scope()?).is_err(), "rehash mutation {mutation}");
    }
    Ok(())
}

#[test]
fn rehashed_media_and_source_payload_changes_still_have_to_agree_with_replay() -> TestResult {
    let plan = fixture()?; let original = plan.objects();
    let mut changed_media = original.media.to_vec();
    *changed_media.last_mut().ok_or("empty media")? ^= 1;
    let encoded = index(&plan, original.source, original.initialization, &changed_media, 0)?;
    let objects = RecordingObjects { media: &changed_media, index: &encoded, ..original };
    assert!(verify_hevc_recording(&manifest(objects)?, objects, &scope()?).is_err());
    let mut changed = packets()?;
    *changed[3].bytes.last_mut().ok_or("empty source")? ^= 1;
    let changed_source = pack(&changed)?;
    let encoded = index(&plan, &changed_source, original.initialization, original.media, 0)?;
    let objects = RecordingObjects { source: &changed_source, index: &encoded, ..original };
    assert!(verify_hevc_recording(&manifest(objects)?, objects, &scope()?).is_err());
    Ok(())
}

#[test]
fn malformed_canonical_suffix_and_wrong_manifest_role_are_never_accepted() -> TestResult {
    let plan = fixture()?; let original = plan.objects();
    let mut appended = original.index.to_vec(); appended.push(0);
    let objects = RecordingObjects { index: &appended, ..original };
    assert!(verify_hevc_recording(&manifest(objects)?, objects, &scope()?).is_err());
    let wrong = ObjectManifest::new("avc_recording_window_v1",
        [ContentDigest::sha256(original.source), ContentDigest::sha256(original.initialization), ContentDigest::sha256(original.media)],
        plan.manifest().metadata_digest())?;
    assert!(verify_hevc_recording(&wrong, original, &scope()?).is_err());
    let mut truncated = original.source.to_vec(); truncated.pop();
    let encoded = index(&plan, &truncated, original.initialization, original.media, 0)?;
    let objects = RecordingObjects { source: &truncated, index: &encoded, ..original };
    assert!(verify_hevc_recording(&manifest(objects)?, objects, &scope()?).is_err());
    Ok(())
}

#[test]
fn fixed_work_and_combined_object_limits_fail_before_unbounded_replay() -> TestResult {
    let source = packets()?; let config = configuration()?;
    assert_eq!(prepare_hevc_recording(scope()?, &config, 90_000, &timings(257), &borrowed(&source)).err(), Some(E::Limit));
    assert!(prepare_hevc_recording(scope()?, &config, 0, &timings(4), &borrowed(&source)).is_err());
    let too_many: Vec<_> = (0..4097).map(|i| packet(i, 0, true, &[0x26, 1, 0xa0])).collect();
    assert_eq!(prepare_hevc_recording(scope()?, &config, 90_000, &timings(1), &borrowed(&too_many)).err(), Some(E::Limit));
    let plan = fixture()?;
    let huge = vec![0; fss_reference::rtsp::recording::MAX_RECORDING_BYTES + 1];
    assert_eq!(verify_hevc_recording(plan.manifest(), RecordingObjects { source: &huge, ..plan.objects() }, &scope()?).err(), Some(E::Limit));
    Ok(())
}
