#![forbid(unsafe_code)]
//! Recording bytes and provenance, not a live-camera or decoder qualification.
mod recording_support;
use recording_support::*;
use fss_core::{ContentDigest, StreamId};
use fss_container::TimedAvcPicture;
use fss_reference::rtsp::recording::{RecordingError, RecordingObjects, RecordingPacket, prepare_recording, verify_recording};

type TestResult = Result<(), Error>;

#[test]
fn real_idr_window_retains_original_packets_and_exact_media() -> TestResult {
    let f = fixture(1, false)?; let p = f.prepare()?;
    let summary = verify_recording(p.manifest(), p.objects(), &scope()?)?;
    assert_eq!(summary, *p.summary()); assert_eq!(summary.samples, 1);
    assert_eq!(summary.packets, f.packets.len()); assert_eq!(summary.decode_interval, 0..3600);
    assert_eq!(p.manifest().children().len(), 4);
    for (_, digest, bytes) in p.children() { assert_eq!(digest, ContentDigest::sha256(bytes)); }
    Ok(())
}
#[test]
fn fragmented_idr_reconstructs_synthesized_header_and_all_source_spans() -> TestResult {
    let f = fixture(1, true)?; let p = f.prepare()?;
    assert_eq!(verify_recording(p.manifest(), p.objects(), &scope()?)?.packets, f.packets.len());
    assert!(p.summary().packets > p.summary().nals); Ok(())
}
#[test]
fn process_local_ingress_does_not_change_durable_recording_identity() -> TestResult {
    assert_eq!(fixture(1, false)?.prepare()?.manifest(), fixture(999, false)?.prepare()?.manifest()); Ok(())
}
#[test]
fn identical_preparation_is_deterministic_without_consuming_source() -> TestResult {
    let f = fixture(1, true)?; let a = f.prepare()?; let b = f.prepare()?;
    assert_eq!(a.manifest(), b.manifest()); assert_eq!(a.objects().source, b.objects().source);
    assert_eq!(a.objects().index, b.objects().index); assert_eq!(a.objects().media, b.objects().media); Ok(())
}
#[test]
fn wrong_expected_stream_and_clock_fail_closed() -> TestResult {
    let p = fixture(1, false)?.prepare()?;
    let mut wrong = scope()?; wrong.stream = StreamId::parse("other-stream")?;
    assert_eq!(verify_recording(p.manifest(), p.objects(), &wrong), Err(RecordingError::Scope));
    let mut wrong = scope()?; wrong.receive_clock = ContentDigest::sha256(b"different-clock-epoch");
    assert_eq!(verify_recording(p.manifest(), p.objects(), &wrong), Err(RecordingError::Scope)); Ok(())
}
#[test]
fn packet_body_tampering_cannot_keep_the_old_root() -> TestResult {
    let p = fixture(1, false)?.prepare()?; let mut source = p.objects().source.to_vec();
    let last = source.last_mut().ok_or("empty source")?; *last ^= 1;
    assert!(verify_recording(p.manifest(), RecordingObjects { source: &source, ..p.objects() }, &scope()?).is_err()); Ok(())
}
#[test]
fn wrong_original_bytes_are_refused_before_any_io() -> TestResult {
    let mut f = fixture(1, true)?;
    let bytes = &mut f.packets.last_mut().ok_or("no packet")?.2;
    let last = bytes.last_mut().ok_or("empty packet")?; *last ^= 1;
    assert!(f.prepare().is_err()); Ok(())
}
#[test]
fn missing_middle_fu_packet_is_not_a_recording() -> TestResult {
    let mut f = fixture(1, true)?; f.packets.remove(f.packets.len() - 2);
    assert!(f.prepare().is_err()); Ok(())
}
#[test]
fn duplicate_extended_sequence_is_not_deduplicated_silently() -> TestResult {
    let mut f = fixture(1, false)?; let p = f.packets[0].clone(); f.packets.insert(1, p);
    assert!(f.prepare().is_err()); Ok(())
}
#[test]
fn unused_source_packet_is_refused_instead_of_overcollecting() -> TestResult {
    let mut f = fixture(1, false)?; let seq = f.packets.last().ok_or("no packet")?.0 + 1;
    f.packets.push((seq, seq, packet(seq as u16, false, &[0x09, 0x10])));
    assert!(f.prepare().is_err()); Ok(())
}
#[test]
fn altered_receive_time_changes_root_but_is_not_a_capture_time_claim() -> TestResult {
    let mut f = fixture(1, false)?; let a = f.prepare()?;
    f.packets[0].1 = 999;
    let b = f.prepare()?; assert_ne!(a.manifest(), b.manifest());
    assert_eq!(a.summary().decode_interval, b.summary().decode_interval); Ok(())
}
#[test]
fn every_truncated_index_is_refused_without_a_valid_prefix_result() -> TestResult {
    let p = fixture(1, true)?.prepare()?;
    for length in 0..p.objects().index.len() {
        assert!(verify_recording(p.manifest(), RecordingObjects { index: &p.objects().index[..length], ..p.objects() }, &scope()?).is_err());
    }
    Ok(())
}
#[test]
fn index_suffix_and_unknown_version_are_refused() -> TestResult {
    let p = fixture(1, false)?.prepare()?; let mut index = p.objects().index.to_vec(); index.push(0);
    assert!(verify_recording(p.manifest(), RecordingObjects { index: &index, ..p.objects() }, &scope()?).is_err());
    index[8] ^= 1;
    assert!(verify_recording(p.manifest(), RecordingObjects { index: &index, ..p.objects() }, &scope()?).is_err()); Ok(())
}
#[test]
fn initialization_and_media_cannot_be_substituted_or_extended() -> TestResult {
    let p = fixture(1, false)?.prepare()?; let mut init = p.objects().initialization.to_vec(); init[0] ^= 1;
    assert!(verify_recording(p.manifest(), RecordingObjects { initialization: &init, ..p.objects() }, &scope()?).is_err());
    let mut media = p.objects().media.to_vec(); media.push(0);
    assert!(verify_recording(p.manifest(), RecordingObjects { media: &media, ..p.objects() }, &scope()?).is_err()); Ok(())
}
#[test]
fn scope_epoch_and_empty_window_are_refused() -> TestResult {
    assert!(prepare_recording(scope()?, 90_000, &[], &[]).is_err());
    let f = fixture(1, false)?;
    let pictures = [TimedAvcPicture { picture: &f.pictures[0], decode_time: 0, duration: 3600, composition_offset: 0 }];
    let packets: Vec<_> = f.packets.iter().map(|(s, t, b)| RecordingPacket { sequence: *s, received_ns: *t, bytes: b }).collect();
    let mut wrong = scope()?; wrong.generation = 2;
    assert!(prepare_recording(wrong, 90_000, &pictures, &packets).is_err()); Ok(())
}
#[test]
fn debug_excludes_encoded_media_and_original_datagrams() -> TestResult {
    let f = fixture(1, false)?; let p = f.prepare()?;
    let text = format!("{p:?} {:?}", p.objects());
    assert!(!text.contains("wire_range")); assert!(!text.contains("source: ["));
    assert!(!text.contains("initialization: [")); Ok(())
}
