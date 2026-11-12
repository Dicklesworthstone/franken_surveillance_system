#![forbid(unsafe_code)]
//! Closed recorder UTC grammar, lossless integer transport and explicit source-read admission.

use std::ffi::OsString;

use super::*;
use crate::{FssCommand, parse_fss_args};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn pins(codec: &str) -> Vec<(String, String)> {
    [
        ("--target", "recordings".to_owned()),
        ("--root", "/owner/deployment".to_owned()),
        ("--archive-root", "/owner/archive with spaces".to_owned()),
        ("--codec", codec.to_owned()),
        ("--sensor", "sensor:camera".to_owned()),
        ("--stream", "stream:main".to_owned()),
        ("--generation", u64::MAX.to_string()),
        (
            "--source-anchor",
            ContentDigest::sha256(b"source").to_text(),
        ),
        (
            "--receive-clock",
            ContentDigest::sha256(b"receive").to_text(),
        ),
        ("--decode-clock", ContentDigest::sha256(b"decode").to_text()),
        ("--time-scale", "90000".to_owned()),
        ("--replay-root", ContentDigest::sha256(b"receipt").to_text()),
        (
            "--replay-request",
            ContentDigest::sha256(b"request").to_text(),
        ),
        ("--ntp-era", "0".to_owned()),
        ("--utc-start-ns", "18446744073709551616".to_owned()),
        ("--utc-end-ns", "18446744073709551617".to_owned()),
        ("--verify-replay-source", "yes".to_owned()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}

fn parse(values: &[(String, String)], inline: bool) -> Result<FssCommand, CliError> {
    let mut args = vec![OsString::from("query"), OsString::from("--json")];
    for (key, value) in values {
        if inline {
            args.push(format!("{key}={value}").into());
        } else {
            args.extend([key.into(), value.into()]);
        }
    }
    parse_fss_args(args)
}

fn replace(values: &mut [(String, String)], key: &str, value: &str) -> Test {
    values
        .iter_mut()
        .find(|(name, _)| name == key)
        .ok_or("missing fixture option")?
        .1 = value.to_owned();
    Ok(())
}

#[test]
fn recorder_utc_uses_its_own_pins_and_preserves_i128_intervals_and_native_defaults() -> Test {
    for codec in ["avc", "hevc"] {
        let values = pins(codec);
        let command = parse(&values, false)?;
        assert_eq!(command, parse(&values, true)?);
        assert!(command.is_json());
        let FssCommand::RecordingReplayQuery(args) = command else {
            return Err("recorder UTC dispatched to a metadata-only owner".into());
        };
        assert!(args.verify_replay_source);
        assert_eq!(
            args.archive_root,
            PathBuf::from("/owner/archive with spaces")
        );
        assert_eq!(args.request.replay.codec.as_str(), codec);
        assert_eq!(args.request.replay.scope.recording.generation, u64::MAX);
        assert_eq!(args.request.replay.ntp_era, 0);
        assert_eq!(
            args.request.replay.start_ns,
            18_446_744_073_709_551_616_i128
        );
        assert_eq!(args.request.replay.end_ns, 18_446_744_073_709_551_617_i128);
        assert_eq!(
            args.request.replay.limits,
            ReplayTimeLimits {
                max_results: DEFAULT_REPLAY_QUERY_RESULTS,
                ..ReplayTimeLimits::default()
            }
        );
        assert_eq!(
            args.limits.replay.metadata.max_read_bytes
                + args.limits.replay.originals.max_read_bytes,
            1024 * 1024 * 1024
        );
        assert_eq!(
            args.limits.replay.metadata.max_io_calls + args.limits.replay.originals.max_io_calls,
            1_000_000
        );
    }
    Ok(())
}

#[test]
fn recorder_utc_requires_every_exact_pin_and_explicit_local_consent() {
    let valid = pins("avc");
    for missing in valid.iter().map(|(name, _)| name) {
        let values = valid
            .iter()
            .filter(|(name, _)| name != missing)
            .cloned()
            .collect::<Vec<_>>();
        assert!(parse(&values, false).is_err(), "accepted missing {missing}");
    }
    for (option, value) in &valid {
        let mut duplicate = valid.clone();
        duplicate.push((option.clone(), value.clone()));
        assert!(
            parse(&duplicate, true).is_err(),
            "accepted duplicate {option}"
        );
    }
}

#[test]
fn recorder_utc_refuses_mixed_modes_and_implicit_interpretations() -> Test {
    let valid = pins("hevc");
    for (key, value) in [
        ("--catalog-slot", "catalog"),
        ("--catalog-root", "sha256:bad"),
        ("--catalogs", "catalog=sha256:bad"),
        ("--discover-catalogs", "yes"),
        ("--sessions", "[]"),
        ("--clock-slot", "clock"),
        ("--clock-root", "sha256:bad"),
        ("--start-tick", "0"),
        ("--end-tick", "1"),
        ("--start-utc-ns", "0"),
        ("--end-utc-ns", "1"),
        ("--max-windows", "1"),
        ("--max-hydration-bytes", "1"),
        ("--from-ns", "0"),
        ("--at", "latest"),
        ("--continuation", "next"),
        ("--analysis", "tracks"),
        ("--sources", "[]"),
        ("--hydrate", "H3"),
    ] {
        let mut values = valid.clone();
        values.push((key.to_owned(), value.to_owned()));
        assert!(parse(&values, true).is_err(), "accepted mixed {key}");
    }
    for target in ["events", "footage", "onvif"] {
        let mut values = valid.clone();
        replace(&mut values, "--target", target)?;
        assert!(
            parse(&values, false).is_err(),
            "accepted replay fields for {target}"
        );
    }
    for consent in ["", "true", "1", "YES", "no"] {
        let mut values = valid.clone();
        replace(&mut values, "--verify-replay-source", consent)?;
        assert!(
            parse(&values, true).is_err(),
            "accepted implicit consent {consent}"
        );
    }
    Ok(())
}

#[test]
fn recorder_utc_refuses_noncanonical_numbers_zero_pins_and_unbounded_rows() -> Test {
    for (key, value) in [
        ("--generation", "01"),
        ("--time-scale", "0"),
        ("--time-scale", "4294967296"),
        ("--ntp-era", "-1"),
        ("--ntp-era", "00"),
        ("--ntp-era", "4294967296"),
        ("--utc-start-ns", "+1"),
        ("--utc-start-ns", "-1"),
        ("--utc-start-ns", "01"),
        ("--utc-start-ns", "1e9"),
        ("--utc-start-ns", "18446744073709551617"),
        ("--utc-end-ns", "253402300800000000001"),
        ("--utc-end-ns", "170141183460469231731687303715884105728"),
    ] {
        let mut values = pins("avc");
        replace(&mut values, key, value)?;
        assert!(parse(&values, true).is_err(), "accepted {key}={value}");
    }
    for key in [
        "--source-anchor",
        "--receive-clock",
        "--decode-clock",
        "--replay-root",
        "--replay-request",
    ] {
        let mut values = pins("avc");
        replace(&mut values, key, &format!("sha256:{}", "0".repeat(64)))?;
        assert!(parse(&values, true).is_err(), "accepted zero {key}");
    }
    for (key, value) in [
        ("--max-query-windows", "65"),
        ("--max-query-samples", "16385"),
        ("--max-query-packets", "262145"),
        ("--max-query-source-bytes", "2147483649"),
        ("--max-query-results", "0"),
        ("--max-query-results", "129"),
        ("--max-query-results", "01"),
        ("--max-query-read-bytes", "0"),
        ("--max-query-read-bytes", "4294967297"),
        ("--max-query-io-calls", "0"),
        ("--max-query-io-calls", "4000001"),
    ] {
        let mut values = pins("avc");
        values.push((key.to_owned(), value.to_owned()));
        assert!(parse(&values, true).is_err(), "accepted {key}={value}");
    }
    Ok(())
}

#[test]
fn typed_recorder_query_without_source_consent_refuses_before_deployment_io() -> Test {
    let FssCommand::RecordingReplayQuery(mut args) = parse(&pins("avc"), false)? else {
        return Err("wrong command fixture".into());
    };
    args.verify_replay_source = false;
    args.root = PathBuf::from("/missing/fss-no-source-grant/deployment");
    args.archive_root = PathBuf::from("/missing/fss-no-source-grant/archive");
    let (output, exit) = execute_recording_replay_query(&args);
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert!(output.contains(ERR_AGENT_CONTEXT_INCOMPLETE));
    assert!(!output.contains(crate::error::ERR_DOCTOR_NOT_A_DEPLOYMENT));
    Ok(())
}
