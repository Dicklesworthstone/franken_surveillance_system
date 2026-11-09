#![forbid(unsafe_code)]
//! The recording target has a closed, exactly pinned native decode-clock grammar.

use std::ffi::OsString;

use super::*;
use crate::{FssCommand, parse_fss_args};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn discovery_pins() -> Vec<(String, String)> {
    let mut values = pins();
    values.retain(|(key, _)| key != "--catalog-slot" && key != "--catalog-root");
    values.push(("--discover-catalogs".to_owned(), "yes".to_owned()));
    values
}

#[test]
fn discovery_grammar_preserves_exact_source_and_decode_clock_scope() -> TestResult {
    for codec in ["avc", "hevc"] {
        let mut values = discovery_pins();
        values
            .iter_mut()
            .find(|(key, _)| key == "--codec")
            .ok_or("codec fixture")?
            .1 = codec.to_owned();
        let command = parse(&values, false)?;
        assert_eq!(command, parse(&values, true)?);
        let FssCommand::RecordingDiscoveryQuery(args) = command else {
            return Err("discovery routed to another recording owner".into());
        };
        assert_eq!(args.request.recording.codec.as_str(), codec);
        assert_eq!(args.request.recording.interval, 0..u64::MAX);
        assert_eq!(args.request.recording.scope.time_scale, 90_000);
        assert_eq!(args.request.recording.max_windows, 32);
        assert_eq!(args.archive_root, PathBuf::from("/owner/archive"));
    }
    Ok(())
}

#[test]
fn discovery_grammar_refuses_mixed_modes_and_implicit_scope() -> TestResult {
    let valid = discovery_pins();
    for (name, value) in [
        ("--catalogs", "catalog=sha256:bad"),
        ("--catalog-slot", "catalog"),
        ("--catalog-root", "sha256:bad"),
        ("--clock-slot", "clock"),
        ("--clock-root", "sha256:bad"),
        ("--start-utc-ns", "0"),
        ("--end-utc-ns", "1"),
        ("--from-ns", "0"),
        ("--at", "latest"),
        ("--hydrate", "H3"),
    ] {
        let mut values = valid.clone();
        values.push((name.to_owned(), value.to_owned()));
        assert!(parse(&values, false).is_err(), "accepted {name}");
    }
    for value in ["", "no", "true", "1", "YES"] {
        let mut values = valid.clone();
        values
            .iter_mut()
            .find(|(key, _)| key == "--discover-catalogs")
            .ok_or("discovery fixture")?
            .1 = value.to_owned();
        assert!(parse(&values, false).is_err(), "accepted discovery {value}");
    }
    for missing in valid.iter().map(|(key, _)| key) {
        let values = valid
            .iter()
            .filter(|(key, _)| key != missing)
            .cloned()
            .collect::<Vec<_>>();
        assert!(parse(&values, false).is_err(), "accepted missing {missing}");
    }
    Ok(())
}

fn set_pins() -> Vec<(String, String)> {
    let mut values = pins();
    values.retain(|(key, _)| key != "--catalog-slot" && key != "--catalog-root");
    values.push((
        "--catalogs".to_owned(),
        format!(
            "catalog-b={},catalog-a={}",
            ContentDigest::sha256(b"catalog b"),
            ContentDigest::sha256(b"catalog a"),
        ),
    ));
    values
}

#[test]
fn catalog_set_grammar_preserves_source_scope_and_exact_integers() -> TestResult {
    let values = set_pins();
    let command = parse(&values, false)?;
    assert_eq!(command, parse(&values, true)?);
    let FssCommand::RecordingSetQuery(args) = command else {
        return Err("catalog set dispatched to a singleton or UTC owner".into());
    };
    assert_eq!(args.request.recording.catalogs.len(), 2);
    assert_eq!(
        args.request.recording.catalogs[0].slot.as_str(),
        "catalog-b"
    );
    assert_eq!(
        args.request.recording.catalogs[1].root,
        ContentDigest::sha256(b"catalog a")
    );
    assert_eq!(args.request.recording.interval, 0..u64::MAX);
    assert_eq!(args.request.recording.scope.time_scale, 90_000);
    assert_eq!(args.request.recording.max_windows, 32);
    assert_eq!(args.archive_root, PathBuf::from("/owner/archive"));
    Ok(())
}

#[test]
fn catalog_set_rejects_ambiguous_pins_mixed_clocks_and_unbounded_inputs() -> TestResult {
    let valid = set_pins();
    for (name, value) in [
        ("--catalog-slot", "single"),
        ("--catalog-root", "sha256:bad"),
        ("--clock-slot", "clock"),
        ("--clock-root", "sha256:bad"),
        ("--start-utc-ns", "0"),
        ("--end-utc-ns", "1"),
        ("--from-ns", "0"),
        ("--at", "latest"),
        ("--hydrate", "H3"),
    ] {
        let mut values = valid.clone();
        values.push((name.to_owned(), value.to_owned()));
        assert!(parse(&values, false).is_err(), "accepted {name}");
    }
    let digest = ContentDigest::sha256(b"same").to_text();
    let different = ContentDigest::sha256(b"different").to_text();
    for value in [
        String::new(),
        "catalog".to_owned(),
        format!("catalog={digest},"),
        format!("../catalog={digest}"),
        format!("catalog={digest},catalog={different}"),
        format!("first={digest},second={digest}"),
        format!("catalog = {digest}"),
        (0..9)
            .map(|i| format!("catalog-{i}={}", ContentDigest::sha256(&[i])))
            .collect::<Vec<_>>()
            .join(","),
        "x".repeat(2000),
    ] {
        let mut values = valid.clone();
        values
            .iter_mut()
            .find(|(name, _)| name == "--catalogs")
            .ok_or("missing test catalogs")?
            .1 = value;
        assert!(parse(&values, false).is_err());
    }
    for missing in valid.iter().map(|(name, _)| name) {
        let values = valid
            .iter()
            .filter(|(name, _)| name != missing)
            .cloned()
            .collect::<Vec<_>>();
        assert!(parse(&values, false).is_err(), "accepted missing {missing}");
    }
    Ok(())
}

fn pins() -> Vec<(String, String)> {
    [
        ("--target", "recordings".to_owned()),
        ("--root", "/owner/deployment".to_owned()),
        ("--archive-root", "/owner/archive".to_owned()),
        ("--codec", "avc".to_owned()),
        ("--catalog-slot", "recordings-one".to_owned()),
        (
            "--catalog-root",
            ContentDigest::sha256(b"catalog").to_text(),
        ),
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

fn utc_pins(codec: &str) -> TestResult<Vec<(String, String)>> {
    use fss_reference::rtsp::recording_clock::{RecordingClockCodec, clock_slot};

    let mut values = changed("--codec", codec);
    let FssCommand::RecordingQuery(base) = parse(&values, false)? else {
        return Err("expected legacy request for source pins".into());
    };
    let clock_codec = match codec {
        "avc" => RecordingClockCodec::Avc,
        "hevc" => RecordingClockCodec::Hevc,
        _ => return Err("fixture codec".into()),
    };
    let slot = clock_slot(clock_codec, &base.request.recording.scope)?;
    values.retain(|(key, _)| key != "--start-tick" && key != "--end-tick");
    values.extend([
        ("--clock-slot".to_owned(), slot.as_str().to_owned()),
        (
            "--clock-root".to_owned(),
            ContentDigest::sha256(b"clock companion").to_text(),
        ),
        ("--start-utc-ns".to_owned(), "9007199254740993".to_owned()),
        ("--end-utc-ns".to_owned(), u64::MAX.to_string()),
    ]);
    Ok(values)
}

fn utc_discovery_pins(codec: &str) -> TestResult<Vec<(String, String)>> {
    let mut values = utc_pins(codec)?;
    values.retain(|(key, _)| key != "--catalog-slot" && key != "--catalog-root");
    values.push(("--discover-catalogs".to_owned(), "yes".to_owned()));
    Ok(values)
}

#[test]
fn utc_discovery_dispatch_preserves_exact_clock_source_and_output_pins() -> TestResult {
    for codec in ["avc", "hevc"] {
        let values = utc_discovery_pins(codec)?;
        let command = parse(&values, false)?;
        assert_eq!(command, parse(&values, true)?);
        assert!(command.is_json());
        let FssCommand::RecordingUtcDiscoveryQuery(args) = command else {
            return Err("UTC discovery dispatched through another query mode".into());
        };
        assert_eq!(args.request.recording.codec.as_str(), codec);
        assert_eq!(
            args.request.recording.clock_root,
            ContentDigest::sha256(b"clock companion")
        );
        assert_eq!(
            args.request.recording.interval,
            9_007_199_254_740_993..u64::MAX
        );
        assert_eq!(args.request.recording.scope.time_scale, 90_000);
        assert_eq!(args.request.recording.scope.recording.generation, 1);
        assert_eq!(args.request.recording.max_windows, 32);
        assert_eq!(args.root, PathBuf::from("/owner/deployment"));
        assert_eq!(args.archive_root, PathBuf::from("/owner/archive"));
    }
    Ok(())
}

#[test]
fn utc_discovery_requires_explicit_complete_scope_without_manual_catalog_or_tick_modes()
-> TestResult {
    let valid = utc_discovery_pins("avc")?;
    for missing in valid.iter().map(|(key, _)| key) {
        let reduced = valid
            .iter()
            .filter(|(key, _)| key != missing)
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            parse(&reduced, false).is_err(),
            "accepted missing {missing}"
        );
    }
    for (key, value) in [
        ("--catalog-slot", "catalog"),
        ("--catalog-root", "sha256:bad"),
        ("--catalogs", "catalog=sha256:bad"),
        ("--start-tick", "0"),
        ("--end-tick", "1"),
        ("--from-ns", "0"),
        ("--through-ns", "1"),
        ("--at", "latest"),
        ("--hydrate", "H3"),
        ("--continuation", "cursor"),
    ] {
        let mut mixed = valid.clone();
        mixed.push((key.to_owned(), value.to_owned()));
        assert!(parse(&mixed, false).is_err(), "accepted mixed {key}");
    }
    for key in [
        "--discover-catalogs",
        "--clock-slot",
        "--clock-root",
        "--start-utc-ns",
        "--end-utc-ns",
    ] {
        let mut duplicate = valid.clone();
        duplicate.push(
            valid
                .iter()
                .find(|(name, _)| name == key)
                .ok_or("fixture pin")?
                .clone(),
        );
        assert!(parse(&duplicate, true).is_err(), "accepted duplicate {key}");
    }
    for (key, value) in [
        ("--discover-catalogs", "true"),
        ("--discover-catalogs", "no"),
        ("--discover-catalogs", "1"),
        ("--clock-slot", "foreign-clock"),
        ("--generation", "2"),
        ("--start-utc-ns", "9007199254740993.0"),
        ("--end-utc-ns", "18446744073709551616"),
    ] {
        let mut changed = valid.clone();
        changed
            .iter_mut()
            .find(|(name, _)| name == key)
            .ok_or("fixture pin")?
            .1 = value.to_owned();
        assert!(
            parse(&changed, false).is_err(),
            "accepted invalid {key}={value}"
        );
    }
    Ok(())
}

fn utc_set_pins(codec: &str) -> TestResult<Vec<(String, String)>> {
    let mut values = utc_pins(codec)?;
    values.retain(|(key, _)| key != "--catalog-slot" && key != "--catalog-root");
    let catalogs = set_pins()
        .into_iter()
        .find(|(key, _)| key == "--catalogs")
        .ok_or("catalog set fixture")?;
    values.push(catalogs);
    Ok(values)
}

#[test]
fn utc_set_dispatch_preserves_explicit_pages_clock_pins_and_exact_integers() -> TestResult {
    for codec in ["avc", "hevc"] {
        let values = utc_set_pins(codec)?;
        let command = parse(&values, false)?;
        assert_eq!(command, parse(&values, true)?);
        let FssCommand::RecordingUtcSetQuery(args) = command else {
            return Err("UTC catalog set dispatched through another query owner".into());
        };
        assert_eq!(args.request.recording.codec.as_str(), codec);
        assert_eq!(args.request.recording.catalogs.len(), 2);
        assert_eq!(
            args.request.recording.catalogs[0].slot.as_str(),
            "catalog-b"
        );
        assert_eq!(
            args.request.recording.catalogs[1].root,
            ContentDigest::sha256(b"catalog a")
        );
        assert_eq!(
            args.request.recording.clock_root,
            ContentDigest::sha256(b"clock companion")
        );
        assert_eq!(
            args.request.recording.interval,
            9_007_199_254_740_993..u64::MAX
        );
        assert_eq!(args.request.recording.scope.time_scale, 90_000);
        assert_eq!(args.request.recording.max_windows, 32);
        assert_eq!(args.archive_root, PathBuf::from("/owner/archive"));
    }
    Ok(())
}

#[test]
fn utc_set_requires_complete_pins_and_refuses_mixed_modes_or_implicit_discovery() -> TestResult {
    let valid = utc_set_pins("avc")?;
    for missing in valid.iter().map(|(key, _)| key) {
        let reduced = valid
            .iter()
            .filter(|(key, _)| key != missing)
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            parse(&reduced, false).is_err(),
            "accepted missing {missing}"
        );
    }
    for (key, value) in [
        ("--catalog-slot", "catalog"),
        ("--catalog-root", "sha256:bad"),
        ("--start-tick", "0"),
        ("--end-tick", "1"),
        ("--discover-catalogs", "yes"),
        ("--from-ns", "0"),
        ("--at", "latest"),
        ("--hydrate", "H3"),
        ("--continuation", "cursor"),
    ] {
        let mut mixed = valid.clone();
        mixed.push((key.to_owned(), value.to_owned()));
        assert!(parse(&mixed, false).is_err(), "accepted mixed {key}");
    }
    for key in [
        "--catalogs",
        "--clock-slot",
        "--clock-root",
        "--start-utc-ns",
        "--end-utc-ns",
    ] {
        let mut duplicate = valid.clone();
        duplicate.push(
            valid
                .iter()
                .find(|(name, _)| name == key)
                .ok_or("fixture pin")?
                .clone(),
        );
        assert!(parse(&duplicate, true).is_err(), "accepted duplicate {key}");
    }
    for (key, value) in [
        ("--clock-slot", "foreign-clock".to_owned()),
        ("--generation", "2".to_owned()),
        ("--start-utc-ns", "9007199254740993.0".to_owned()),
        ("--end-utc-ns", "18446744073709551616".to_owned()),
        (
            "--catalogs",
            format!(
                "a={},b={}",
                ContentDigest::sha256(b"same"),
                ContentDigest::sha256(b"same")
            ),
        ),
        (
            "--catalogs",
            (0..9)
                .map(|i| format!("page-{i}={}", ContentDigest::sha256(&[i])))
                .collect::<Vec<_>>()
                .join(","),
        ),
    ] {
        let mut changed = valid.clone();
        changed
            .iter_mut()
            .find(|(name, _)| name == key)
            .ok_or("fixture pin")?
            .1 = value;
        assert!(parse(&changed, false).is_err(), "accepted invalid {key}");
    }
    Ok(())
}

#[test]
fn utc_dispatch_preserves_exact_integers_and_never_fabricates_a_tick_query() -> TestResult {
    for codec in ["avc", "hevc"] {
        let values = utc_pins(codec)?;
        let space = parse(&values, false)?;
        assert_eq!(space, parse(&values, true)?);
        let FssCommand::RecordingUtcQuery(args) = space else {
            return Err("UTC request dispatched through another clock mode".into());
        };
        assert_eq!(args.root, PathBuf::from("/owner/deployment"));
        assert_eq!(args.archive_root, PathBuf::from("/owner/archive"));
        assert_eq!(args.request.recording.codec.as_str(), codec);
        assert_eq!(
            args.request.recording.interval,
            9_007_199_254_740_993..u64::MAX
        );
        assert_eq!(
            args.request.recording.clock_root,
            ContentDigest::sha256(b"clock companion")
        );
        assert_eq!(
            args.request.recording.catalog_root,
            ContentDigest::sha256(b"catalog")
        );
        assert_eq!(args.request.recording.scope.time_scale, 90_000);
        assert_eq!(args.request.recording.max_windows, 32);
        assert!(args.request.expected_anchor.is_none());
    }
    Ok(())
}

#[test]
fn utc_requires_every_pin_and_rejects_mixed_time_predicates_before_io() -> TestResult {
    let values = utc_pins("avc")?;
    for missing in values.iter().map(|(key, _)| key) {
        let reduced: Vec<_> = values
            .iter()
            .filter(|(key, _)| key != missing)
            .cloned()
            .collect();
        assert!(
            parse(&reduced, false).is_err(),
            "accepted missing {missing}"
        );
    }
    for (option, value) in [
        ("--start-tick", "0"),
        ("--end-tick", "1"),
        ("--from-ns", "0"),
        ("--through-ns", "1"),
        ("--at", "latest"),
        ("--continuation", "cursor"),
        ("--hydrate", "H1"),
        ("--approve", "yes"),
    ] {
        let mut mixed = values.clone();
        mixed.push((option.to_owned(), value.to_owned()));
        assert!(parse(&mixed, false).is_err(), "accepted {option}");
    }
    for option in [
        "--clock-slot",
        "--clock-root",
        "--start-utc-ns",
        "--end-utc-ns",
    ] {
        let mut duplicate = values.clone();
        duplicate.push(
            values
                .iter()
                .find(|(key, _)| key == option)
                .ok_or("fixture option")?
                .clone(),
        );
        assert!(
            parse(&duplicate, true).is_err(),
            "accepted duplicate {option}"
        );
    }
    Ok(())
}

#[test]
fn utc_refuses_noncanonical_numbers_and_foreign_clock_namespaces() -> TestResult {
    let values = utc_pins("avc")?;
    for option in ["--start-utc-ns", "--end-utc-ns"] {
        for value in [
            "+1",
            "01",
            "-0",
            "-1",
            "1e9",
            " 1",
            "1.0",
            "18446744073709551616",
        ] {
            let mut bad = values.clone();
            bad.iter_mut()
                .find(|(key, _)| key == option)
                .ok_or("fixture option")?
                .1 = value.to_owned();
            assert!(parse(&bad, false).is_err(), "accepted {option}={value}");
        }
    }
    for (option, value) in [
        ("--start-utc-ns", u64::MAX.to_string()),
        ("--end-utc-ns", "9007199254740993".to_owned()),
        ("--clock-slot", "arbitrary-clock-alias".to_owned()),
        ("--clock-root", format!("sha256:{}", "0".repeat(64))),
        ("--generation", "2".to_owned()),
        (
            "--receive-clock",
            ContentDigest::sha256(b"foreign-receive-clock").to_text(),
        ),
        (
            "--decode-clock",
            ContentDigest::sha256(b"foreign-decode-clock").to_text(),
        ),
        ("--codec", "hevc".to_owned()),
        ("--time-scale", "1000".to_owned()),
        ("--target", "events".to_owned()),
        ("--target", "footage".to_owned()),
    ] {
        let mut bad = values.clone();
        bad.iter_mut()
            .find(|(key, _)| key == option)
            .ok_or("fixture option")?
            .1 = value;
        assert!(
            parse(&bad, false).is_err(),
            "accepted incompatible {option}"
        );
    }
    Ok(())
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
        assert!(
            parse(&reduced, false).is_err(),
            "accepted missing {missing}"
        );
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
        for value in [
            "+1",
            "01",
            "-0",
            "-1",
            "1e3",
            " 1",
            "1.0",
            "18446744073709551616",
        ] {
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
fn foreign_targets_predicates_unpinned_clocks_and_effect_options_do_not_fall_through() -> TestResult
{
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
    for option in [
        "--catalog-root",
        "--source-anchor",
        "--receive-clock",
        "--decode-clock",
    ] {
        assert!(parse(&changed(option, &zero), false).is_err());
    }
    for duplicate in [
        "--target",
        "--catalog-slot",
        "--catalog-root",
        "--archive-root",
    ] {
        let mut values = pins();
        values.push(
            values
                .iter()
                .find(|(key, _)| key == duplicate)
                .ok_or("fixture pin")?
                .clone(),
        );
        assert!(
            parse(&values, false).is_err(),
            "accepted repeated {duplicate}"
        );
    }
    Ok(())
}

fn utc_session_json_fields(
    pin: &fss_reference::agent_recordings::utc_sessions::RecordingUtcSessionPin,
) -> std::collections::BTreeMap<&'static str, String> {
    let quote = |value: &str| format!("\"{}\"", crate::escape_json_str(value));
    [
        ("codec", quote(pin.codec.as_str())),
        ("sensor", quote(pin.scope.recording.sensor.as_str())),
        ("stream", quote(pin.scope.recording.stream.as_str())),
        (
            "generation",
            quote(&pin.scope.recording.generation.to_string()),
        ),
        (
            "source_anchor",
            quote(&pin.scope.recording.anchor.to_text()),
        ),
        (
            "receive_clock",
            quote(&pin.scope.recording.receive_clock.to_text()),
        ),
        ("decode_clock", quote(&pin.scope.decode_clock.to_text())),
        ("time_scale", pin.scope.time_scale.to_string()),
        (
            "catalogs",
            format!(
                "[{}]",
                pin.catalogs
                    .iter()
                    .map(|catalog| {
                        format!(
                            "{{\"slot\":{},\"root\":{}}}",
                            quote(catalog.slot.as_str()),
                            quote(&catalog.root.to_text())
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ),
        ("clock_slot", quote(pin.clock_slot.as_str())),
        ("clock_root", quote(&pin.clock_root.to_text())),
    ]
    .into_iter()
    .collect()
}

fn utc_session_json(fields: &std::collections::BTreeMap<&str, String>) -> String {
    format!(
        "{{{}}}",
        fields
            .iter()
            .map(|(key, value)| format!("\"{key}\":{value}"))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn utc_sessions_pins(
    codec: &str,
) -> TestResult<(
    Vec<(String, String)>,
    Vec<fss_reference::agent_recordings::utc_sessions::RecordingUtcSessionPin>,
)> {
    use fss_reference::agent_recordings::set::RecordingCatalogPin;
    use fss_reference::agent_recordings::utc_sessions::RecordingUtcSessionPin;
    use fss_reference::rtsp::recording_clock::{RecordingClockCodec, clock_slot};
    let mut values = utc_pins(codec)?;
    let FssCommand::RecordingUtcQuery(base) = parse(&values, false)? else {
        return Err("UTC source fixture".into());
    };
    let r = base.request.recording;
    let first = RecordingUtcSessionPin {
        codec: r.codec,
        scope: r.scope,
        clock_slot: r.clock_slot,
        clock_root: r.clock_root,
        catalogs: vec![RecordingCatalogPin {
            slot: r.catalog_slot,
            root: r.catalog_root,
        }],
    };
    let mut second = first.clone();
    second.codec = match first.codec {
        RecordingQueryCodec::Avc => RecordingQueryCodec::Hevc,
        RecordingQueryCodec::Hevc => RecordingQueryCodec::Avc,
    };
    second.scope.recording.generation = 9_007_199_254_740_993;
    second.scope.recording.anchor = ContentDigest::sha256(b"second retained source anchor");
    second.scope.recording.receive_clock = ContentDigest::sha256(b"second receive epoch");
    second.scope.decode_clock = ContentDigest::sha256(b"second decode epoch");
    second.scope.time_scale = u32::MAX;
    second.catalogs = vec![RecordingCatalogPin {
        slot: SlotName::parse("session-two-page")?,
        root: ContentDigest::sha256(b"second session catalog"),
    }];
    second.clock_slot = clock_slot(
        match second.codec {
            RecordingQueryCodec::Avc => RecordingClockCodec::Avc,
            RecordingQueryCodec::Hevc => RecordingClockCodec::Hevc,
        },
        &second.scope,
    )?;
    second.clock_root = ContentDigest::sha256(b"second session clock");
    let sessions = vec![first, second];
    values.retain(|(key, _)| {
        matches!(
            key.as_str(),
            "--target"
                | "--root"
                | "--archive-root"
                | "--principal"
                | "--anchor"
                | "--start-utc-ns"
                | "--end-utc-ns"
                | "--max-windows"
                | "--max-hydration-bytes"
        )
    });
    values.push((
        "--sessions".to_owned(),
        format!(
            "[{}]",
            sessions
                .iter()
                .map(|pin| utc_session_json(&utc_session_json_fields(pin)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    ));
    Ok((values, sessions))
}

#[test]
fn utc_sessions_grammar_preserves_distinct_capture_clocks_generations_and_codecs() -> TestResult {
    for codec in ["avc", "hevc"] {
        let (values, expected) = utc_sessions_pins(codec)?;
        let command = parse(&values, false)?;
        assert!(command.is_json());
        assert_eq!(command, parse(&values, true)?);
        let FssCommand::RecordingUtcSessionsQuery(args) = command else {
            return Err("session set routed to a different recording owner".into());
        };
        assert_eq!(args.request.recording.sessions.len(), 2);
        for pin in &expected {
            assert!(args.request.recording.sessions.contains(pin));
        }
        assert_eq!(
            args.request.recording.interval,
            9_007_199_254_740_993..u64::MAX
        );
        assert_eq!(args.request.recording.max_windows, 32);
        assert_eq!(args.root, PathBuf::from("/owner/deployment"));
        assert_eq!(args.archive_root, PathBuf::from("/owner/archive"));
        let mut reversed = values.clone();
        reversed
            .iter_mut()
            .find(|(key, _)| key == "--sessions")
            .ok_or("sessions")?
            .1 = format!(
            "[{}]",
            expected
                .iter()
                .rev()
                .map(|pin| utc_session_json(&utc_session_json_fields(pin)))
                .collect::<Vec<_>>()
                .join(",")
        );
        let FssCommand::RecordingUtcSessionsQuery(reversed) = parse(&reversed, false)? else {
            return Err("reversed sessions changed owner".into());
        };
        let limits =
            fss_reference::agent_recordings::utc_sessions::RecordingUtcSessionsLimits::default();
        assert_eq!(
            args.request.recording.request_digest(limits)?,
            reversed.request.recording.request_digest(limits)?
        );
    }
    Ok(())
}

#[test]
fn utc_sessions_grammar_refuses_implicit_mixed_scope_and_noncanonical_session_json() -> TestResult {
    let (valid, pins) = utc_sessions_pins("avc")?;
    let first = utc_session_json_fields(&pins[0]);
    let second = utc_session_json(&utc_session_json_fields(&pins[1]));
    let with_sessions = |body: String| {
        let mut values = valid.clone();
        values
            .iter_mut()
            .find(|(key, _)| key == "--sessions")
            .expect("fixture sessions")
            .1 = body;
        values
    };
    for missing in valid.iter().map(|(key, _)| key) {
        let values = valid
            .iter()
            .filter(|(key, _)| key != missing)
            .cloned()
            .collect::<Vec<_>>();
        assert!(parse(&values, false).is_err(), "missing {missing}");
    }
    for target in ["events", "footage"] {
        let mut values = valid.clone();
        values
            .iter_mut()
            .find(|(key, _)| key == "--target")
            .ok_or("target")?
            .1 = target.to_owned();
        assert!(
            parse(&values, false).is_err(),
            "session selector escaped into {target}"
        );
    }
    for missing in first.keys() {
        let mut fields = first.clone();
        fields.remove(missing);
        assert!(
            parse(
                &with_sessions(format!("[{},{}]", utc_session_json(&fields), second)),
                false
            )
            .is_err(),
            "missing session field {missing}"
        );
    }
    for (field, value) in [
        ("codec", "\"vp9\""),
        ("sensor", "\"sensor:other\""),
        ("stream", "\"stream:other\""),
        ("generation", "9007199254740993"),
        ("generation", "\"01\""),
        ("generation", "\"+1\""),
        ("generation", "\"0\""),
        ("generation", "\"18446744073709551616\""),
        ("time_scale", "\"90000\""),
        ("time_scale", "0"),
        ("time_scale", "4294967296"),
        ("time_scale", "9e4"),
        ("source_anchor", "null"),
        ("receive_clock", "\"sha256:bad\""),
        ("decode_clock", "\"sha256:bad\""),
        ("clock_slot", "\"unbound-clock\""),
        ("clock_root", "\"sha256:bad\""),
        ("catalogs", "[]"),
        ("catalogs", "{}"),
        ("unknown", "true"),
        ("root", "\"/other/archive\""),
    ] {
        let mut fields = first.clone();
        fields.insert(field, value.to_owned());
        assert!(
            parse(
                &with_sessions(format!("[{},{}]", utc_session_json(&fields), second)),
                false
            )
            .is_err(),
            "accepted {field}={value}"
        );
    }
    let item = utc_session_json(&first);
    for body in [
        "[]".to_owned(),
        "{}".to_owned(),
        "null".to_owned(),
        format!("[\"{item}\"]"),
        format!("[{item},{item}]"),
        format!("[{}]", vec![item.clone(); 9].join(",")),
        format!("[{{\"generation\":\"1\",{}}}]", &item[1..item.len() - 1]),
        format!("[{item}] trailing"),
        format!("[{}]", " ".repeat(65_536)),
    ] {
        assert!(parse(&with_sessions(body), false).is_err());
    }
    for (key, value) in [
        ("--codec", "avc"),
        ("--sensor", "sensor:front-door"),
        ("--stream", "stream:primary"),
        ("--generation", "1"),
        ("--source-anchor", "sha256:bad"),
        ("--receive-clock", "sha256:bad"),
        ("--decode-clock", "sha256:bad"),
        ("--time-scale", "90000"),
        ("--clock-slot", "clock"),
        ("--clock-root", "sha256:bad"),
        ("--catalogs", "catalog=sha256:bad"),
        ("--catalog-slot", "catalog"),
        ("--catalog-root", "sha256:bad"),
        ("--discover-catalogs", "yes"),
        ("--start-tick", "0"),
        ("--end-tick", "1"),
        ("--from-ns", "0"),
        ("--continuation", "cursor"),
        ("--hydrate", "H1"),
        ("--sessions", "[]"),
        ("--max-windows", "33"),
    ] {
        let mut mixed = valid.clone();
        mixed.push((key.to_owned(), value.to_owned()));
        assert!(parse(&mixed, false).is_err(), "accepted mixed {key}");
    }
    Ok(())
}
