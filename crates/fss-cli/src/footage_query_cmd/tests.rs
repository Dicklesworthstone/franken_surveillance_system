#![forbid(unsafe_code)]
//! Grammar and projection contracts for the canonical footage query target.

use std::error::Error;
use std::ffi::OsString;

use super::*;
use crate::token::tokenize_os_args;

type TestResult = Result<(), Box<dyn Error>>;

fn parse(extra: &[&str]) -> Result<FssCommand, CliError> {
    let args = ["query", "--json", "--root", "/owner/deployment"]
        .into_iter()
        .chain(extra.iter().copied())
        .map(OsString::from);
    parse_query_command(&tokenize_os_args(args)?)
}

#[test]
fn default_and_explicit_events_keep_the_original_command() -> TestResult {
    let default = parse(&["--kind", "unknown_presence"])?;
    let explicit = parse(&["--target", "events", "--kind", "unknown_presence"])?;
    assert!(matches!(default, FssCommand::Query(_)));
    assert_eq!(default, explicit);
    Ok(())
}

#[test]
fn footage_target_retains_exact_identities_and_full_width_endpoints() -> TestResult {
    let lower = i128::MIN.to_string();
    let upper = i128::MAX.to_string();
    let command = parse(&[
        "--target=footage",
        "--sensor",
        "sensor:loading-dock",
        "--stream=stream:recording:1",
        "--from-ns",
        &lower,
        "--through-ns",
        &upper,
        "--max-entries=1",
        "--principal",
        "principal:footage-test",
    ])?;
    let FssCommand::FootageQuery(args) = command else {
        return Err("footage target dispatched to another command".into());
    };
    assert_eq!(
        args.request.filter.sensor.as_ref().map(SensorId::as_str),
        Some("sensor:loading-dock")
    );
    assert_eq!(
        args.request.filter.stream.as_ref().map(StreamId::as_str),
        Some("stream:recording:1")
    );
    assert_eq!(args.request.filter.from_ns, Some(i128::MIN));
    assert_eq!(args.request.filter.through_ns, Some(i128::MAX));
    assert_eq!(args.request.max_entries, 1);
    assert_eq!(args.request.principal.as_str(), "principal:footage-test");
    Ok(())
}

#[test]
fn footage_grammar_refuses_wrong_targets_cross_target_options_and_ambiguous_numbers() {
    for extra in [
        vec!["--target", "media"],
        vec!["--target", "footage", "--target", "events"],
        vec!["--target", "footage", "--target=footage"],
        vec!["--target", "footage", "--event-id", "event:1"],
        vec!["--target", "footage", "--kind", "unknown_presence"],
        vec!["--target", "footage", "--state", "hypothesized"],
        vec!["--target", "footage", "--zone", "door"],
        vec!["--target", "footage", "--at", "latest"],
        vec!["--target", "events", "--sensor", "sensor:1"],
        vec!["--stream", "stream:1"],
        vec![
            "--target",
            "footage",
            "--sensor",
            "sensor:1",
            "--sensor=sensor:2",
        ],
        vec!["--target", "footage", "--sensor", "bad\nidentity"],
        vec!["--target", "footage", "--from-ns", "2", "--through-ns", "1"],
        vec!["--target", "footage", "--from-ns", "-0"],
        vec!["--target", "footage", "--from-ns", "+1"],
        vec!["--target", "footage", "--through-ns", "1e3"],
        vec!["--target", "footage", "--max-entries", "0"],
        vec!["--target", "footage", "--max-entries", "33"],
        vec!["--target", "footage", "--max-entries", "01"],
        vec!["--target", "footage", "--anchor", "latest"],
        vec!["--target", "footage", "--continuation", "latest"],
        vec!["--target", "footage", "--hydrate", "yes"],
        vec!["--target", "footage", "--approve", "yes"],
        vec!["--target", "footage", "--certify-absence"],
    ] {
        assert!(parse(&extra).is_err(), "accepted {extra:?}");
    }
}

#[test]
fn footage_does_not_require_both_interval_endpoints() -> TestResult {
    for extra in [
        vec!["--target", "footage", "--from-ns", "-1"],
        vec!["--target", "footage", "--through-ns", "1"],
    ] {
        assert!(matches!(parse(&extra)?, FssCommand::FootageQuery(_)));
    }
    Ok(())
}
