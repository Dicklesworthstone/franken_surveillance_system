#![forbid(unsafe_code)]

use std::ffi::OsString;

use fss_core::ContentDigest;

use super::{driver, plan::Options};

fn args() -> Vec<OsString> {
    let digest = ContentDigest::sha256(b"rtsp-import-operator-fixture").to_text();
    [
        "--archive", "/absent-rtsp-import-fixture/source",
        "--root", "/absent-rtsp-import-fixture/destination",
        "--site", "site:test",
        "--window-slot", "recording-test",
        "--window-root", &digest,
        "--codec", "avc",
        "--sensor-id", "sensor:test",
        "--stream-id", "stream:test",
        "--generation", "1",
        "--anchor", &digest,
        "--receive-clock", &digest,
        "--receive-time-ns", "2000000000",
        "--owner-authorized", "yes",
        "--read-originals", "yes",
        "--retain-originals", "yes",
    ].into_iter().map(OsString::from).collect()
}

fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(position) = args.iter().position(|argument| argument == key) {
        args[position + 1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}

#[test]
fn preview_is_pure_and_names_original_custody_and_native_timing() -> Result<(), &'static str> {
    let options = Options::parse(&args())?;
    let preview = options.preview()?;
    for expected in [
        "\"kind\":\"plan\"",
        "\"writes\":\"none\"",
        "\"network\":\"none\"",
        "\"capture_time_label\":\"unknown\"",
        "\"sample_timing\":\"retained_mp4_presentation_timestamps\"",
        "\"maximum_original_bytes\":33554432",
        "\"maximum_media_bytes\":33554432",
        "\"maximum_frames\":256",
    ] {
        assert!(preview.contains(expected), "{expected}");
    }
    assert!(preview.contains(&options.approval()?.to_text()));
    Ok(())
}

#[test]
fn exact_approval_binds_every_source_destination_and_work_choice() -> Result<(), &'static str> {
    let approved = Options::parse(&args())?.approval()?;
    let other = ContentDigest::sha256(b"other").to_text();
    for (key, value) in [
        ("--archive", "/absent-rtsp-import-fixture/other-source"),
        ("--root", "/absent-rtsp-import-fixture/other-destination"),
        ("--site", "site:other"),
        ("--principal", "principal:other"),
        ("--window-slot", "other-recording"),
        ("--window-root", other.as_str()),
        ("--codec", "hevc"),
        ("--sensor-id", "sensor:other"),
        ("--stream-id", "stream:other"),
        ("--generation", "2"),
        ("--anchor", other.as_str()),
        ("--receive-clock", other.as_str()),
        ("--receive-time-ns", "3000000000"),
        ("--max-frames", "32"),
        ("--max-original-bytes", "1048576"),
        ("--max-media-bytes", "2097152"),
        ("--max-work", "100000"),
        ("--timeout-ms", "1000"),
    ] {
        let mut changed = args();
        set(&mut changed, key, value);
        let mut options = Options::parse(&changed)?;
        assert_ne!(options.approval()?, approved, "{key}");
        options.approve = Some(approved);
        assert_eq!(driver::execute(&options).err(), Some("ERR-RTSP-IMPORT-APPROVAL-001"), "{key}");
    }
    Ok(())
}

#[test]
fn original_read_and_retention_are_independently_explicit() {
    for key in ["--owner-authorized", "--read-originals", "--retain-originals"] {
        let mut input = args();
        set(&mut input, key, "no");
        assert!(Options::parse(&input).is_err(), "{key}");
        let position = input.iter().position(|argument| argument == key).expect("fixture");
        input.drain(position..position + 2);
        assert!(Options::parse(&input).is_err(), "{key}");
    }
}

#[test]
fn timestamps_preserve_nonnegative_i128_and_capture_origin_is_complete() -> Result<(), &'static str> {
    let mut input = args();
    set(&mut input, "--receive-time-ns", "184467440737095516160");
    let unhinted = Options::parse(&input)?;
    assert_eq!(unhinted.request.receive_time.0, 184467440737095516160);
    set(&mut input, "--capture-start-ns", "184467440736095516160");
    assert!(Options::parse(&input).is_err());
    set(&mut input, "--capture-uncertainty-ns", "1000");
    let hinted = Options::parse(&input)?;
    assert_ne!(hinted.approval()?, unhinted.approval()?);
    assert!(hinted.preview()?.contains("\"capture_time_label\":\"operator_assumption\""));
    for (key, value) in [
        ("--receive-time-ns", "-1"),
        ("--receive-time-ns", "170141183460469231731687303715884105728"),
        ("--capture-start-ns", "-1"),
        ("--capture-uncertainty-ns", "-1"),
    ] {
        let mut malformed = input.clone();
        set(&mut malformed, key, value);
        assert!(Options::parse(&malformed).is_err(), "{key}={value}");
    }
    Ok(())
}

#[test]
fn malformed_and_out_of_scope_inputs_refuse_before_io() {
    for (key, value) in [
        ("--codec", "auto"),
        ("--fps", "30"),
        ("--generation", "0"),
        ("--max-frames", "257"),
        ("--max-original-bytes", "33554433"),
        ("--max-media-bytes", "0"),
        ("--max-work", "0"),
        ("--timeout-ms", "600001"),
        ("--root", "/"),
        ("--root", "/absent-rtsp-import-fixture/source/nested"),
        ("--root", "/absent-rtsp-import-fixture/source"),
        ("--root", "/absent-rtsp-import-fixture/./destination"),
        ("--root", "relative"),
        ("--window-slot", "../escape"),
    ] {
        let mut input = args();
        set(&mut input, key, value);
        assert!(Options::parse(&input).is_err(), "{key}={value}");
    }
    let mut duplicate = args();
    duplicate.extend([OsString::from("--codec"), OsString::from("hevc")]);
    assert!(Options::parse(&duplicate).is_err());
    let mut unknown = args();
    unknown.extend([OsString::from("--url"), OsString::from("rtsp://example.invalid")]);
    assert!(Options::parse(&unknown).is_err());
}
