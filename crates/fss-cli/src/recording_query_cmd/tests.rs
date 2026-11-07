#![forbid(unsafe_code)]
//! The recording target has a closed, exactly pinned native decode-clock grammar.

use std::ffi::OsString;

use super::*;
use crate::{FssCommand, parse_fss_args};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn pins() -> Vec<(String, String)> {
    [
        ("--target", "recordings".to_owned()),
        ("--root", "/owner/deployment".to_owned()),
        ("--archive-root", "/owner/archive".to_owned()),
        ("--codec", "avc".to_owned()),
        ("--catalog-slot", "recordings-one".to_owned()),
        ("--catalog-root", ContentDigest::sha256(b"catalog").to_text()),
        ("--sensor", "sensor:front-door".to_owned()),
        ("--stream", "stream:primary".to_owned()),
        ("--generation", "1".to_owned()),
        (
            "--source-anchor",
            ContentDigest::sha256(b"historical-source-anchor").to_text(),
        ),
        (
            "--receive-clock",
            ContentDigest::sha256(b"receive-clock").to_text(),
        ),
        (
            "--decode-clock",
            ContentDigest::sha256(b"decode-clock").to_text(),
        ),
        ("--time-scale", "90000".to_owned()),
        ("--start-tick", "0".to_owned()),
        ("--end-tick", u64::MAX.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}
fn parse(values: &[(String, String)], equals: bool) -> Result<FssCommand, CliError> {
    let mut args = vec![OsString::from("query"), OsString::from("--json")];
    for (key, value) in values {
        if equals {
            args.push(format!("{key}={value}").into());
        } else {
            args.extend([key.into(), value.into()]);
        }
    }
    parse_fss_args(args)
}
fn changed(name: &str, value: &str) -> Vec<(String, String)> {
    let mut values = pins();
    if let Some(existing) = values.iter_mut().find(|(key, _)| key == name) {
        existing.1 = value.to_owned();
    } else {
        values.push((name.to_owned(), value.to_owned()));
    }
    values
}

#[test]
fn recordings_dispatch_keeps_all_pins_separate_from_current_deployment_context() -> TestResult {
    let values = pins();
    let space = parse(&values, false)?;
    assert_eq!(space, parse(&values, true)?);
    let FssCommand::RecordingQuery(args) = space else {
        return Err("recordings target dispatched to another command".into());
    };
    assert_eq!(args.root, PathBuf::from("/owner/deployment"));
    assert_eq!(args.archive_root, PathBuf::from("/owner/archive"));
    let request = args.request.recording;
    assert_eq!(request.codec, RecordingQueryCodec::Avc);
    assert_eq!(request.catalog_slot.as_str(), "recordings-one");
    assert_eq!(request.catalog_root, ContentDigest::sha256(b"catalog"));
    assert_eq!(request.scope.recording.sensor.as_str(), "sensor:front-door");
    assert_eq!(request.scope.recording.stream.as_str(), "stream:primary");
    assert_eq!(request.scope.recording.generation, 1);
    assert_eq!(
        request.scope.recording.anchor,
        ContentDigest::sha256(b"historical-source-anchor")
    );
    assert_eq!(
        request.scope.recording.receive_clock,
        ContentDigest::sha256(b"receive-clock")
    );
    assert_eq!(
        request.scope.decode_clock,
        ContentDigest::sha256(b"decode-clock")
    );
    assert_eq!(request.scope.time_scale, 90_000);
    assert_eq!(request.interval, 0..u64::MAX);
    assert_eq!(request.max_windows, 32);
    assert!(args.request.expected_anchor.is_none());
    assert!(matches!(
        parse(&changed("--codec", "hevc"), false)?,
        FssCommand::RecordingQuery(_)
    ));
    Ok(())
}

#[test]
fn every_source_and_catalog_pin_and_both_roots_are_required() {
    let values = pins();
    for missing in values.iter().map(|(key, _)| key) {
        let reduced: Vec<_> = values
            .iter()
            .filter(|(key, _)| key != missing)
            .cloned()
            .collect();
        assert!(parse(&reduced, false).is_err(), "accepted missing {missing}");
    }
}

#[test]
fn noncanonical_or_out_of_range_numeric_spellings_are_rejected() {
    for option in [
        "--generation",
        "--time-scale",
        "--start-tick",
        "--end-tick",
        "--max-windows",
        "--max-hydration-bytes",
    ] {
        for value in ["+1", "01", "-0", "-1", "1e3", " 1", "1.0", "18446744073709551616"] {
            assert!(
                parse(&changed(option, value), false).is_err(),
                "accepted {option}={value}"
            );
        }
    }
    for (option, value) in [
        ("--generation", "0"),
        ("--time-scale", "0"),
        ("--time-scale", "4294967296"),
        ("--end-tick", "0"),
        ("--max-windows", "0"),
        ("--max-windows", "33"),
        ("--max-hydration-bytes", "0"),
        ("--max-hydration-bytes", "2147483649"),
    ] {
        assert!(
            parse(&changed(option, value), false).is_err(),
            "accepted {option}={value}"
        );
    }
}

#[test]
fn foreign_targets_predicates_unpinned_clocks_and_effect_options_do_not_fall_through() -> TestResult {
    for (option, value) in [
        ("--target", "events"),
        ("--target", "footage"),
        ("--target", "media"),
        ("--codec", "h264"),
        ("--codec", "auto"),
        ("--catalog-slot", "../catalog"),
        ("--catalog-root", "latest"),
        ("--source-anchor", "latest"),
        ("--decode-clock", "rtp"),
        ("--sensor", "bad\nidentity"),
        ("--anchor", "latest"),
        ("--from-ns", "0"),
        ("--through-ns", "10"),
        ("--continuation", "anything"),
        ("--at", "latest"),
        ("--event-id", "event:one"),
        ("--kind", "unknown_presence"),
        ("--zone", "door"),
        ("--state", "hypothesized"),
        ("--max-entries", "32"),
        ("--hydrate", "H1"),
        ("--approve", "yes"),
    ] {
        assert!(
            parse(&changed(option, value), false).is_err(),
            "accepted {option}={value}"
        );
    }
    let zero = format!("sha256:{}", "0".repeat(64));
    for option in ["--catalog-root", "--source-anchor", "--receive-clock", "--decode-clock"] {
        assert!(parse(&changed(option, &zero), false).is_err());
    }
    for duplicate in ["--target", "--catalog-slot", "--catalog-root", "--archive-root"] {
        let mut values = pins();
        values.push(
            values
                .iter()
                .find(|(key, _)| key == duplicate)
                .ok_or("fixture pin")?
                .clone(),
        );
        assert!(parse(&values, false).is_err(), "accepted repeated {duplicate}");
    }
    Ok(())
}
