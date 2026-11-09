#![forbid(unsafe_code)]

use super::*;

fn args() -> Vec<OsString> {
    let digest = ContentDigest::sha256(b"query-import-parser-fixture").to_text();
    [
        "--archive",
        "/absent-query-import-fixture/archive",
        "--root",
        "/absent-query-import-fixture/deployment",
        "--site",
        "site:query-import-fixture",
        "--catalog-slot",
        "catalog-fixture",
        "--catalog-root",
        &digest,
        "--codec",
        "hevc",
        "--sensor-id",
        "sensor:query-fixture",
        "--stream-id",
        "stream:query-fixture",
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
        "--decode-start",
        "0",
        "--decode-end",
        "180000",
        "--receive-time-ns",
        "5000000000",
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
    if let Some(index) = args.iter().position(|arg| arg == key) {
        args[index + 1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}

#[test]
fn query_parser_preserves_exact_scope_and_keeps_capture_unknown() -> Result<(), &'static str> {
    let options = QueryOptions::parse(&args())?;
    assert_eq!(options.context.recording.interval, 0..180000);
    assert_eq!(options.context.recording.max_windows, 32);
    assert_eq!(options.context.recording.max_hydration_bytes, 134217728);
    assert_eq!(options.common.request.capture_origin, None);
    assert_eq!(options.common.request.receive_time.0, 5000000000);
    assert_eq!(
        options.context.recording.scope,
        options.common.catalog.as_ref().ok_or("catalog")?.scope
    );
    assert!(options.common.approve.is_none());
    Ok(())
}

#[test]
fn query_approval_binds_the_interval_quote_context_plan_and_owner_choices()
-> Result<(), &'static str> {
    let plan = ContentDigest::sha256(b"verified-plan");
    let options = QueryOptions::parse(&args())?;
    let approved = options.approval(plan)?;
    assert_ne!(approved, options.common.approval()?);
    assert_ne!(
        approved,
        options.approval(ContentDigest::sha256(b"other-plan"))?
    );
    let other = ContentDigest::sha256(b"other-scope").to_text();
    for (key, value) in [
        ("--decode-start", "1"),
        ("--decode-end", "180001"),
        ("--max-hydration-bytes", "67108864"),
        ("--max-windows", "2"),
        ("--max-frames", "10"),
        ("--max-original-bytes", "67108864"),
        ("--max-media-bytes", "33554432"),
        ("--max-work", "10000"),
        ("--timeout-ms", "1000"),
        ("--archive", "/absent-query-import-fixture/other-archive"),
        ("--root", "/absent-query-import-fixture/other-deployment"),
        ("--site", "site:other"),
        ("--principal", "principal:other"),
        ("--catalog-slot", "other-catalog"),
        ("--catalog-root", other.as_str()),
        ("--decode-clock", other.as_str()),
        ("--receive-time-ns", "6000000000"),
    ] {
        let mut changed = args();
        set(&mut changed, key, value);
        assert_ne!(
            QueryOptions::parse(&changed)?.approval(plan)?,
            approved,
            "{key}"
        );
    }
    Ok(())
}

#[test]
fn query_selection_never_reinterprets_capture_hints_pages_or_gap_modes() {
    for (key, value) in [
        ("--capture-start-ns", "1"),
        ("--capture-uncertainty-ns", "0"),
        ("--decode-gaps", "preserve"),
        ("--decode-gaps", "reject"),
        ("--catalog-pages", "catalog@sha256:00"),
        ("--max-pages", "1"),
        ("--window-slot", "window"),
        ("--window-root", "sha256:00"),
        ("--decode-start", "180000"),
        ("--decode-end", "0"),
        ("--decode-start", "-1"),
        ("--decode-start", "00"),
        ("--decode-end", "18446744073709551616"),
        ("--max-hydration-bytes", "0"),
        ("--max-hydration-bytes", "134217729"),
        ("--max-windows", "33"),
        ("--deployment-anchor", "forged"),
        ("--read-originals", "no"),
        ("--retain-originals", "no"),
        ("--owner-authorized", "no"),
        ("--root", "/absent-query-import-fixture/archive/nested"),
    ] {
        let mut malformed = args();
        set(&mut malformed, key, value);
        assert!(QueryOptions::parse(&malformed).is_err(), "{key}={value}");
    }
    for key in [
        "--decode-start",
        "--decode-end",
        "--catalog-slot",
        "--catalog-root",
    ] {
        let mut missing = args();
        let index = missing
            .iter()
            .position(|arg| arg == key)
            .expect("fixture option");
        missing.drain(index..index + 2);
        assert!(QueryOptions::parse(&missing).is_err(), "{key}");
    }
    let mut repeated = args();
    repeated.extend(["--decode-start".into(), "1".into()]);
    assert!(QueryOptions::parse(&repeated).is_err());
}

#[test]
fn missing_deployment_preview_cannot_create_source_or_destination() -> Result<(), &'static str> {
    let options = QueryOptions::parse(&args())?;
    assert!(!options.common.archive.exists());
    assert!(!options.common.root.exists());
    assert!(driver::run(&options).is_err());
    assert!(!options.common.archive.exists());
    assert!(!options.common.root.exists());
    Ok(())
}
