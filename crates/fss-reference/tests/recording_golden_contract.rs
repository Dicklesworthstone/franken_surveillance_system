#![forbid(unsafe_code)]
//! Independent golden hashes plus self-consistent-hash adversaries.
mod recording_support;
use recording_support::*;
use fss_core::ContentDigest;
use fss_object::ObjectManifest;
use fss_reference::rtsp::recording::{PreparedRecording, RecordingObjects, RECORDING_KIND, verify_recording};

type TestResult = Result<(), Error>;

fn golden(fragmented: bool, expected: [&str; 5]) -> TestResult {
    let plan = fixture(1, fragmented)?.prepare()?;
    for ((_, actual, _), expected) in plan.children().into_iter().zip(expected[..4].iter()) {
        assert_eq!(actual.to_text(), format!("sha256:{expected}"));
    }
    assert_eq!(plan.manifest().root().to_text(), format!("sha256:{}", expected[4]));
    Ok(())
}
#[test]
fn single_nal_window_matches_independent_canonical_and_mp4_oracle() -> TestResult {
    golden(false, [
        "6c7ab24afcf580339a20c274fcb34eae9b7837e73cc4cea494744429adc85873",
        "54eef4d4f38d2b8bbc741704f763bdc59880b125d4b0fd6973d84464786b8e63",
        "e5c2af1967289aa99068873075a0405237a7034ce48d478631dd16ee11fed87b",
        "1d07965b1bac7190f44e2d9e17acfe5a54a638036a4b6e478c03f43e5aa4530d",
        "5d298d49154b05f7addc97d82ee75b2160763fd5e415371a251df9408c6889e9",
    ])
}
#[test]
fn fu_window_matches_independent_canonical_and_mp4_oracle() -> TestResult {
    golden(true, [
        "f706f8ac66839f53add73f0d6fa51deffd6b28b8924d137b45e8c281c80df7fd",
        "54eef4d4f38d2b8bbc741704f763bdc59880b125d4b0fd6973d84464786b8e63",
        "e5c2af1967289aa99068873075a0405237a7034ce48d478631dd16ee11fed87b",
        "691feef63eb70d3314db6b6b36c4b95a9eebcabaec2694c75995d1203706566a",
        "12b60714aac3fe08589f0c3329e46cab0fd93a934e0f05e855cf81042617af31",
    ])
}
fn rehash(objects: RecordingObjects<'_>) -> Result<ObjectManifest, Error> {
    Ok(ObjectManifest::new(RECORDING_KIND, [ContentDigest::sha256(objects.source),
        ContentDigest::sha256(objects.initialization), ContentDigest::sha256(objects.media)],
        Some(ContentDigest::sha256(objects.index)))?)
}
fn replace_digest(index: &mut [u8], before: &[u8], after: &[u8]) -> TestResult {
    let old_digest = ContentDigest::sha256(before); let new_digest = ContentDigest::sha256(after);
    let old = old_digest.bytes(); let new = new_digest.bytes();
    let positions: Vec<_> = index.windows(old.len()).enumerate()
        .filter_map(|(i, b)| (b == old.as_ref()).then_some(i)).collect();
    if positions.len() != 1 { return Err("fixture index must contain exactly one child reference".into()); }
    let at = positions[0]; index[at..at + new.len()].copy_from_slice(new.as_ref()); Ok(())
}
#[test]
fn changed_original_packet_is_rejected_even_after_all_hashes_are_recomputed() -> TestResult {
    let plan = fixture(1, true)?.prepare()?;
    let mut source = plan.objects().source.to_vec();
    *source.last_mut().ok_or("empty source")? ^= 1;
    let mut index = plan.objects().index.to_vec();
    replace_digest(&mut index, plan.objects().source, &source)?;
    let objects = RecordingObjects { source: &source, index: &index, ..plan.objects() };
    assert!(verify_recording(&rehash(objects)?, objects, &scope()?).is_err()); Ok(())
}
#[test]
fn changed_media_is_rejected_even_after_all_hashes_are_recomputed() -> TestResult {
    let plan = fixture(1, true)?.prepare()?;
    let mut media = plan.objects().media.to_vec();
    *media.last_mut().ok_or("empty media")? ^= 1;
    let mut index = plan.objects().index.to_vec();
    replace_digest(&mut index, plan.objects().media, &media)?;
    let objects = RecordingObjects { media: &media, index: &index, ..plan.objects() };
    assert!(verify_recording(&rehash(objects)?, objects, &scope()?).is_err()); Ok(())
}
#[test]
fn forged_fu_header_source_range_is_rejected_with_a_self_consistent_root() -> TestResult {
    let plan = fixture(1, true)?.prepare()?;
    let mut index = plan.objects().index.to_vec();
    // Last source span ends in fragment_header_range's exclusive endpoint (14).
    let end = index.last_mut().ok_or("empty index")?;
    assert_eq!(*end, 14); *end = 15;
    let objects = RecordingObjects { index: &index, ..plan.objects() };
    assert!(verify_recording(&rehash(objects)?, objects, &scope()?).is_err()); Ok(())
}
#[test]
fn unused_object_cannot_be_smuggled_into_the_recording_root() -> TestResult {
    let plan: PreparedRecording = fixture(1, false)?.prepare()?;
    let children = [ContentDigest::sha256(plan.objects().source), ContentDigest::sha256(plan.objects().initialization),
        ContentDigest::sha256(plan.objects().media), ContentDigest::sha256(b"unrequested-object")];
    let manifest = ObjectManifest::new(RECORDING_KIND, children, Some(ContentDigest::sha256(plan.objects().index)))?;
    assert!(verify_recording(&manifest, plan.objects(), &scope()?).is_err()); Ok(())
}
