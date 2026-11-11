#![forbid(unsafe_code)]
//! Exact approval and no-I/O admission for historical recorder custody.

use std::ffi::OsString;

use fss_core::ContentDigest;

use super::{driver, plan::Options};

fn args() -> Vec<OsString> {
    let digest = ContentDigest::sha256(b"replay-import-operator-fixture").to_text();
    [
        "--archive",
        "/absent-replay-import-fixture/source",
        "--root",
        "/absent-replay-import-fixture/destination",
        "--site",
        "site:test",
        "--expected-replay-root",
        &digest,
        "--expected-replay-request",
        &digest,
        "--codec",
        "avc",
        "--sensor-id",
        "sensor:test",
        "--stream-id",
        "stream:test",
        "--generation",
        "1",
        "--anchor",
        &digest,
        "--receive-clock",
        &digest,
        "--decode-clock",
        &digest,
        "--time-scale",
        "90000",
        "--receive-time-ns",
        "2000000000",
        "--owner-authorized",
        "yes",
        "--read-originals",
        "yes",
        "--retain-originals",
        "yes",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(position) = args.iter().position(|arg| arg == key) {
        args[position + 1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}

#[test]
fn pure_preview_binds_whole_replay_without_promoting_historical_time() -> Result<(), &'static str> {
    let options = Options::parse(&args())?;
    let preview = options.preview()?;
    for expected in [
        "\"kind\":\"plan\"",
        "\"selection\":\"complete_replay_receipt\"",
        "\"retention\":\"complete_replay_receipt_and_every_original_window\"",
        "\"capture_time_label\":\"unknown\"",
        "\"decode_gaps\":\"reject\"",
        "\"maximum_windows\":64",
        "\"maximum_frames\":16384",
        "\"maximum_original_bytes\":134217728",
        "\"maximum_media_bytes\":67108864",
        "\"writes\":\"none\"",
        "\"network\":\"none\"",
        "\"continuity_certified\":false",
        "\"absence_certifiable\":false",
        "\"historical_utc_calibrated\":false",
    ] {
        assert!(preview.contains(expected), "{expected}");
    }
    assert!(preview.contains(&options.approval()?.to_text()));
    Ok(())
}

#[test]
fn replay_approval_rejects_changed_pins_scope_destination_interpretation_or_bounds_before_io()
-> Result<(), &'static str> {
    let approved = Options::parse(&args())?.approval()?;
    let other = ContentDigest::sha256(b"other-replay").to_text();
    for (key, value) in [
        ("--archive", "/absent-replay-import-fixture/other-source"),
        ("--root", "/absent-replay-import-fixture/other-target"),
        ("--site", "site:other"),
        ("--principal", "principal:other"),
        ("--expected-replay-root", other.as_str()),
        ("--expected-replay-request", other.as_str()),
        ("--codec", "hevc"),
        ("--sensor-id", "sensor:other"),
        ("--stream-id", "stream:other"),
        ("--generation", "2"),
        ("--anchor", other.as_str()),
        ("--receive-clock", other.as_str()),
        ("--decode-clock", other.as_str()),
        ("--time-scale", "1000"),
        ("--receive-time-ns", "3000000000"),
        ("--decode-gaps", "preserve"),
        ("--max-windows", "1"),
        ("--max-frames", "32"),
        ("--max-original-bytes", "1048576"),
        ("--max-media-bytes", "2097152"),
        ("--max-work", "1000"),
        ("--timeout-ms", "1000"),
    ] {
        let mut changed = args();
        set(&mut changed, key, value);
        let mut options = Options::parse(&changed)?;
        assert_ne!(options.approval()?, approved, "{key}");
        options.approve = Some(approved);
        assert_eq!(
            driver::execute(&options).err(),
            Some("ERR-RTSP-IMPORT-APPROVAL-001"),
            "{key}"
        );
    }
    Ok(())
}

#[test]
fn replay_import_requires_all_original_read_and_retention_acknowledgements() {
    for key in [
        "--owner-authorized",
        "--read-originals",
        "--retain-originals",
    ] {
        let mut input = args();
        set(&mut input, key, "no");
        assert!(Options::parse(&input).is_err(), "{key}");
        if let Some(position) = input.iter().position(|arg| arg == key) {
            input.drain(position..position + 2);
        }
        assert!(Options::parse(&input).is_err(), "{key}");
    }
}

#[test]
fn replay_time_assumption_is_separate_complete_and_approval_bound() -> Result<(), &'static str> {
    let mut input = args();
    set(&mut input, "--receive-time-ns", "184467440737095516160");
    let unhinted = Options::parse(&input)?;
    assert_eq!(unhinted.request.receive_time.0, 184467440737095516160);
    set(&mut input, "--capture-start-ns", "184467440736095516160");
    assert!(Options::parse(&input).is_err());
    set(&mut input, "--capture-uncertainty-ns", "1000");
    let hinted = Options::parse(&input)?;
    assert_ne!(hinted.approval()?, unhinted.approval()?);
    assert!(
        hinted
            .preview()?
            .contains("\"capture_time_label\":\"operator_assumption\"")
    );
    assert!(
        hinted
            .preview()?
            .contains("\"historical_utc_calibrated\":false")
    );
    set(&mut input, "--capture-uncertainty-ns", "0");
    let exact_assumption = Options::parse(&input)?;
    assert_ne!(exact_assumption.approval()?, hinted.approval()?);
    Ok(())
}

#[test]
fn replay_admission_refuses_ambiguous_selection_and_resource_overflow() {
    let zero = format!("sha256:{}", "0".repeat(64));
    for (key, value) in [
        ("--codec", "auto"),
        ("--expected-replay-root", zero.as_str()),
        ("--expected-replay-request", zero.as_str()),
        ("--generation", "0"),
        ("--time-scale", "0"),
        ("--time-scale", "4294967296"),
        ("--max-windows", "65"),
        ("--max-frames", "16385"),
        ("--max-original-bytes", "134217729"),
        ("--max-media-bytes", "67108865"),
        ("--max-work", "0"),
        ("--timeout-ms", "600001"),
        ("--receive-time-ns", "-1"),
        (
            "--receive-time-ns",
            "170141183460469231731687303715884105728",
        ),
        ("--decode-gaps", "ignore"),
        ("--window-slot", "one-window"),
        ("--catalog-root", "latest"),
        ("--root", "/"),
        ("--root", "relative"),
        ("--root", "/absent-replay-import-fixture/source"),
        ("--root", "/absent-replay-import-fixture/source/nested"),
        ("--root", "/absent-replay-import-fixture/./target"),
        ("--url", "rtsp://example.invalid"),
    ] {
        let mut input = args();
        set(&mut input, key, value);
        assert!(Options::parse(&input).is_err(), "{key}={value}");
    }
    let mut input = args();
    input.extend(["--codec".into(), "hevc".into()]);
    assert!(Options::parse(&input).is_err());
    let mut input = args();
    set(&mut input, "--principal", &"p".repeat(4097));
    assert!(Options::parse(&input).is_err());
}
