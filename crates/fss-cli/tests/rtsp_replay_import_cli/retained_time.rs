#![forbid(unsafe_code)]
//! Cold retained recorder-time queries through real native import and command processes.

use std::ffi::OsString;
use std::fs;
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_reference::ingest::rtsp_import::RtspImportCodec;

use super::support::{Fixture, SITE, Test, approve, field, good, run, serial, set};

fn item<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    Ok(value
        .object()
        .and_then(|object| object.get(key))
        .ok_or("missing recorder-time report field")?)
}

fn query_args(fixture: &Fixture, identity: Option<&str>) -> Vec<OsString> {
    let scope = fixture.receipt.scope();
    let mut args = vec![
        "query-replay-utc".into(),
        "--root".into(),
        if identity.is_some() {
            fixture.target().into_os_string()
        } else {
            fixture.archive().into_os_string()
        },
    ];
    if let Some(identity) = identity {
        args.extend([
            "--site".into(),
            SITE.into(),
            "--import-id".into(),
            identity.into(),
            // Recorder-time projection reads native packets, never derived media segments.
            "--max-segment-bytes".into(),
            "1".into(),
        ]);
    }
    let window = fixture.receipt.request().window();
    for (key, value) in [
        (
            "--codec",
            fixture.receipt.request().codec().as_str().to_owned(),
        ),
        ("--sensor", scope.recording.sensor.as_str().to_owned()),
        ("--stream", scope.recording.stream.as_str().to_owned()),
        ("--generation", scope.recording.generation.to_string()),
        ("--anchor", scope.recording.anchor.to_text()),
        ("--receive-clock", scope.recording.receive_clock.to_text()),
        ("--decode-clock", scope.decode_clock.to_text()),
        ("--time-scale", scope.time_scale.to_string()),
        ("--expected-replay-root", fixture.receipt.root().to_text()),
        (
            "--expected-replay-request",
            fixture.receipt.request().digest().to_text(),
        ),
        ("--ntp-era", "0".to_owned()),
        (
            "--max-query-windows",
            fixture.receipt.windows().len().to_string(),
        ),
        ("--max-query-samples", fixture.frames.to_string()),
        ("--max-query-packets", "512".to_owned()),
        ("--max-query-source-bytes", "67108864".to_owned()),
        ("--max-query-results", "64".to_owned()),
        (
            "--utc-start-ns",
            window.start().unix_nanoseconds().to_string(),
        ),
        ("--utc-end-ns", window.end().unix_nanoseconds().to_string()),
        ("--timeout-ms", "600000".to_owned()),
    ] {
        args.extend([key.into(), value.into()]);
    }
    args
}

fn retained_query(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .args(args)
        .output()?)
}

fn import(fixture: &Fixture) -> Test<String> {
    let mut args = fixture.args()?;
    approve(&mut args)?;
    let imported = parse(&good(run(&args)?)?)?;
    Ok(field(&imported, "import_identity")?.to_owned())
}

#[test]
fn retained_queries_match_archive_reports_for_both_codecs_with_the_archive_offline() -> Test {
    let _serial = serial();
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let fixture = Fixture::new(codec, 2, 0)?;
        let archived = parse(&good(
            Command::new(env!("CARGO_BIN_EXE_fss-archive"))
                .args(query_args(&fixture, None))
                .output()?,
        )?)?;
        // The requested range contains the query, but native packets carry no ONVIF
        // timestamp. Neither the protocol range nor ingestion time may fill that gap.
        assert_eq!(item(&archived, "matched_samples")?.integer(), Some(0));
        assert_eq!(
            item(&archived, "unknown_samples")?.integer(),
            Some(fixture.frames as i128)
        );
        assert_eq!(field(&archived, "calibrated_capture_time")?, "unknown");
        assert_eq!(field(&archived, "coverage_claim")?, "not_claimed");
        assert_eq!(field(&archived, "absence_claim")?, "not_claimed");

        let identity = import(&fixture)?;
        let args = query_args(&fixture, Some(&identity));
        let journals = fixture.journals()?;
        let online = parse(&good(retained_query(&args)?)?)?;
        assert_eq!(
            field(&online, "schema")?,
            "fss.retained_replay_time_operator_report.v1"
        );
        assert_eq!(field(&online, "command")?, "query-replay-utc");
        assert_eq!(field(&online, "import_identity")?, identity);
        assert_eq!(
            item(&online, "source_archive_required")?.boolean(),
            Some(false)
        );
        assert_eq!(field(&online, "network")?, "none");
        ContentDigest::parse(field(&online, "import_root")?)?;
        assert_eq!(item(&online, "report")?, &archived);

        fs::rename(
            fixture.archive(),
            fixture.directory.0.join("archive offline"),
        )?;
        let cold = parse(&good(retained_query(&args)?)?)?;
        assert_eq!(
            cold, online,
            "cold query changed the native report or its retained binding"
        );
        assert_eq!(
            fixture.journals()?,
            journals,
            "read-only query appended custody or effects"
        );
        assert!(
            !fixture.archive().exists(),
            "retained query recreated the source archive"
        );
    }
    Ok(())
}

#[test]
fn retained_query_pins_and_bounds_refuse_without_partial_output_or_authority_changes() -> Test {
    let _serial = serial();
    let fixture = Fixture::new(RtspImportCodec::Hevc, 2, 0)?;
    let identity = import(&fixture)?;
    let args = query_args(&fixture, Some(&identity));
    good(retained_query(&args)?)?;
    let journals = fixture.journals()?;
    let foreign = ContentDigest::sha256(b"foreign retained replay-time pin").to_text();
    for (key, value) in [
        ("--import-id", foreign.as_str()),
        ("--expected-replay-root", foreign.as_str()),
        ("--expected-replay-request", foreign.as_str()),
        ("--decode-clock", foreign.as_str()),
        ("--receive-clock", foreign.as_str()),
        ("--codec", "avc"),
        ("--time-scale", "90001"),
        ("--max-query-windows", "1"),
        ("--max-query-samples", "1"),
        ("--max-query-packets", "1"),
        ("--max-query-source-bytes", "1"),
        ("--max-query-results", "1"),
        ("--max-source-bytes", "1"),
    ] {
        let mut wrong = args.clone();
        set(&mut wrong, key, value);
        let output = retained_query(&wrong)?;
        assert!(!output.status.success(), "invalid {key} was admitted");
        assert!(
            output.stdout.is_empty(),
            "invalid {key} emitted a partial report"
        );
        assert_eq!(
            fixture.journals()?,
            journals,
            "invalid {key} changed authority or effects"
        );
    }

    let missing = fixture.directory.0.join("missing retained root");
    let mut absent = args;
    set(
        &mut absent,
        "--root",
        missing.to_str().ok_or("UTF-8 fixture path")?,
    );
    let output = retained_query(&absent)?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!missing.exists(), "read-only query created a deployment");
    set(&mut absent, "--utc-start-ns", "PRIVATE_TIME_INPUT");
    let output = retained_query(&absent)?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_TIME_INPUT"));
    assert!(!missing.exists(), "malformed query created a deployment");
    Ok(())
}

#[test]
fn committed_deletion_prevents_later_retained_recorder_time_queries() -> Test {
    let _serial = serial();
    let fixture = Fixture::new(RtspImportCodec::Avc, 2, 0)?;
    let identity = import(&fixture)?;
    fs::rename(
        fixture.archive(),
        fixture.directory.0.join("archive offline"),
    )?;
    let args = query_args(&fixture, Some(&identity));
    good(retained_query(&args)?)?;

    let plan = parse(&good(
        Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["delete", "plan", "--root"])
            .arg(fixture.target())
            .args(["--site", SITE, "--import-id", &identity])
            .output()?,
    )?)?;
    let committed = parse(&good(
        Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["delete", "commit", "--root"])
            .arg(fixture.target())
            .args([
                "--site",
                SITE,
                "--plan",
                field(&plan, "plan_digest")?,
                "--approve",
                field(&plan, "approval_digest")?,
            ])
            .output()?,
    )?)?;
    assert!(
        item(&committed, "objects_unlinked")?
            .integer()
            .is_some_and(|count| count > 0)
    );
    let journals = fixture.journals()?;
    let refused = retained_query(&args)?;
    assert!(!refused.status.success());
    assert!(
        refused.stdout.is_empty(),
        "deleted replay emitted historical time rows"
    );
    assert_eq!(fixture.journals()?, journals);
    assert!(!fixture.archive().exists());
    Ok(())
}
