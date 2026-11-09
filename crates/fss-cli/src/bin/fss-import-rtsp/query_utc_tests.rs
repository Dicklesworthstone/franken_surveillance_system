#![forbid(unsafe_code)]

use super::*;
use fss_cli::agent_json::{array, object, string};
use fss_core::{SensorId, StreamId};
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_clock::{RecordingClockCodec, clock_slot};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn scope(index: u64) -> Test<CatalogScope> {
    Ok(CatalogScope {
        recording: RecordingScope {
            sensor: SensorId::parse("sensor:utc-import-parser")?,
            stream: StreamId::parse("stream:utc-import-parser")?,
            generation: 9_007_199_254_740_993 + index,
            anchor: ContentDigest::sha256(format!("source-{index}").as_bytes()),
            receive_clock: ContentDigest::sha256(format!("receive-{index}").as_bytes()),
        },
        decode_clock: ContentDigest::sha256(format!("decode-{index}").as_bytes()),
        time_scale: 90_000,
    })
}

fn base() -> Vec<OsString> {
    [
        "--archive",
        "/absent-utc-query-import-parser/archive",
        "--root",
        "/absent-utc-query-import-parser/deployment",
        "--site",
        "site:utc-import-parser",
        "--start-utc-ns",
        "1800000000000000000",
        "--end-utc-ns",
        "1800000000000000001",
        "--receive-time-ns",
        "1800000000000000010",
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

fn session(index: u64, count: usize) -> Test<String> {
    let scope = scope(index)?;
    let codec = if index.is_multiple_of(2) {
        RecordingClockCodec::Avc
    } else {
        RecordingClockCodec::Hevc
    };
    let catalogs = (0..count)
        .map(|page| {
            object(&[
                ("slot", string(&format!("session-{index}-catalog-{page}"))),
                (
                    "root",
                    string(
                        &ContentDigest::sha256(
                            format!("session-{index}-catalog-{page}").as_bytes(),
                        )
                        .to_text(),
                    ),
                ),
            ])
        })
        .collect::<Vec<_>>();
    Ok(object(&[
        ("codec", string(codec.as_str())),
        ("sensor", string(scope.recording.sensor.as_str())),
        ("stream", string(scope.recording.stream.as_str())),
        (
            "generation",
            string(&scope.recording.generation.to_string()),
        ),
        ("source_anchor", string(&scope.recording.anchor.to_text())),
        (
            "receive_clock",
            string(&scope.recording.receive_clock.to_text()),
        ),
        ("decode_clock", string(&scope.decode_clock.to_text())),
        ("time_scale", scope.time_scale.to_string()),
        ("catalogs", array(&catalogs)),
        ("clock_slot", string(clock_slot(codec, &scope)?.as_str())),
        (
            "clock_root",
            string(&ContentDigest::sha256(format!("clock-{index}").as_bytes()).to_text()),
        ),
    ]))
}

fn sessions(count: usize, catalogs: usize) -> Test<Vec<OsString>> {
    let mut args = base();
    args.extend([
        "--sessions".into(),
        array(
            &(0..count)
                .map(|index| session(index as u64, catalogs))
                .collect::<Test<Vec<_>>>()?,
        )
        .into(),
    ]);
    Ok(args)
}

fn discovery() -> Test<Vec<OsString>> {
    let scope = scope(0)?;
    let mut args = base();
    for (key, value) in [
        ("--discover-catalogs", "yes".to_owned()),
        ("--codec", "avc".to_owned()),
        ("--sensor-id", scope.recording.sensor.as_str().to_owned()),
        ("--stream-id", scope.recording.stream.as_str().to_owned()),
        ("--generation", scope.recording.generation.to_string()),
        ("--anchor", scope.recording.anchor.to_text()),
        ("--receive-clock", scope.recording.receive_clock.to_text()),
        ("--decode-clock", scope.decode_clock.to_text()),
        ("--time-scale", scope.time_scale.to_string()),
        (
            "--clock-slot",
            clock_slot(RecordingClockCodec::Avc, &scope)?
                .as_str()
                .to_owned(),
        ),
        ("--clock-root", ContentDigest::sha256(b"clock-0").to_text()),
    ] {
        args.extend([key.into(), value.into()]);
    }
    Ok(args)
}

fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = args.iter().position(|arg| arg == key) {
        args[index + 1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}

#[test]
fn utc_parser_reuses_exact_session_grammar_and_keeps_large_integers_lossless() -> Test {
    let options = UtcOptions::parse(&sessions(8, 8)?)?;
    let RtspUtcQueryImportInput::Sessions { request, limits } = &options.input else {
        return Err("sessions variant".into());
    };
    assert_eq!(request.recording.sessions.len(), 8);
    assert_eq!(
        request.recording.sessions[7].scope.recording.generation,
        9_007_199_254_741_000
    );
    assert_eq!(
        request.recording.interval,
        1_800_000_000_000_000_000..1_800_000_000_000_000_001
    );
    assert_eq!(request.recording.max_windows, 32);
    assert_eq!(
        request.recording.max_hydration_bytes,
        catalog::MAX_ORIGINAL_BYTES
    );
    assert_eq!(request.principal.as_str(), options.principal);
    assert!(request.recording.request_digest(limits.recording).is_ok());
    assert!(sessions(8, 8)?.last().ok_or("selector")?.len() > 4096);
    assert_eq!(options.settings.receive_time.0, 1_800_000_000_000_000_010);
    assert!(options.approve.is_none());
    assert!(!options.root.exists());
    assert!(!options.archive.exists());
    Ok(())
}

#[test]
fn utc_discovery_keeps_source_anchor_distinct_from_optional_deployment_anchor() -> Test {
    let options = UtcOptions::parse(&discovery()?)?;
    let RtspUtcQueryImportInput::Discovery { request, limits } = &options.input else {
        return Err("discovery variant".into());
    };
    assert_eq!(request.recording.scope, scope(0)?);
    assert!(request.expected_anchor.is_none());
    assert!(request.recording.request_digest(limits.recording).is_ok());
    assert_eq!(
        request.recording.clock_slot,
        clock_slot(RecordingClockCodec::Avc, &scope(0)?)?
    );
    Ok(())
}

#[test]
fn utc_parser_refuses_ambiguous_or_incomplete_time_sources_and_unapproved_retention() -> Test {
    for (key, value) in [
        ("--capture-start-ns", "1"),
        ("--capture-uncertainty-ns", "1"),
        ("--decode-start", "1"),
        ("--decode-end", "2"),
        ("--window-slot", "window"),
        ("--catalog-slot", "catalog"),
        ("--decode-gaps", "preserve"),
        ("--discover-catalogs", "no"),
        ("--clock-slot", "wrong-clock-scope"),
        ("--max-windows", "33"),
        ("--start-utc-ns", "1800000000000000001"),
        ("--end-utc-ns", "01800000000000000001"),
        ("--start-utc-ns", "-1"),
        ("--end-utc-ns", "18446744073709551616"),
        ("--owner-authorized", "no"),
        ("--read-originals", "no"),
        ("--retain-originals", "no"),
        ("--max-hydration-bytes", "134217729"),
        ("--max-work", "00"),
        ("--deployment-anchor", "forged"),
        ("--root", "/absent-utc-query-import-parser/archive/nested"),
        ("--archive", "relative/archive"),
        ("--approve", "sha256:00"),
    ] {
        let mut args = discovery()?;
        set(&mut args, key, value);
        assert!(UtcOptions::parse(&args).is_err(), "{key}={value}");
    }
    for key in [
        "--clock-root",
        "--clock-slot",
        "--start-utc-ns",
        "--receive-time-ns",
        "--owner-authorized",
    ] {
        let mut args = discovery()?;
        let index = args
            .iter()
            .position(|arg| arg == key)
            .ok_or("fixture option")?;
        args.drain(index..index + 2);
        assert!(UtcOptions::parse(&args).is_err(), "missing {key}");
    }
    let mut mixed = sessions(1, 1)?;
    set(&mut mixed, "--discover-catalogs", "yes");
    assert!(UtcOptions::parse(&mixed).is_err());
    let mut repeated = sessions(1, 1)?;
    repeated.extend(["--start-utc-ns".into(), "1800000000000000000".into()]);
    assert!(UtcOptions::parse(&repeated).is_err());
    Ok(())
}

#[test]
fn utc_session_selectors_are_literal_closed_and_bounded() -> Test {
    for text in [
        "[]".to_owned(),
        "{}".to_owned(),
        "/tmp/session-pins.json".to_owned(),
        format!("[{},{}]", session(0, 1)?, session(0, 1)?),
        format!(
            "[{}]",
            session(0, 1)?.replacen(
                "\"generation\":\"9007199254740993\"",
                "\"generation\":9007199254740993",
                1
            )
        ),
        format!(
            "[{}]",
            session(0, 1)?.replacen("{", "{\"unrecognized\":true,", 1)
        ),
        format!(
            "[{}]",
            session(0, 1)?.replacen("{", "{\"codec\":\"avc\",", 1)
        ),
        " ".repeat(MAX_SESSIONS_JSON_BYTES + 1),
    ] {
        let mut args = base();
        args.extend(["--sessions".into(), text.into()]);
        assert!(UtcOptions::parse(&args).is_err());
    }
    assert!(UtcOptions::parse(&sessions(9, 1)?).is_err());
    Ok(())
}

#[test]
fn utc_approval_binds_the_protected_plan_and_cooperative_deadline() -> Test {
    let options = UtcOptions::parse(&sessions(1, 1)?)?;
    let plan = ContentDigest::sha256(b"complete-current-context-and-settings");
    let approval = options.approval(plan)?;
    assert_ne!(
        approval,
        options.approval(ContentDigest::sha256(
            b"changed-source-clock-query-settings-or-context"
        ))?
    );
    let mut changed = sessions(1, 1)?;
    set(&mut changed, "--timeout-ms", "1000");
    assert_ne!(approval, UtcOptions::parse(&changed)?.approval(plan)?);
    assert!(options.approval(ContentDigest::sha256(b"other")).is_ok());
    assert!(
        options
            .approval(ContentDigest::parse(&format!("sha256:{}", "0".repeat(64)))?)
            .is_err()
    );
    Ok(())
}

#[test]
fn missing_utc_deployment_preview_does_not_create_either_store() -> Test {
    let options = UtcOptions::parse(&sessions(1, 1)?)?;
    assert!(!options.root.exists());
    assert!(!options.archive.exists());
    assert!(driver::run(&options).is_err());
    assert!(!options.root.exists());
    assert!(!options.archive.exists());
    Ok(())
}
