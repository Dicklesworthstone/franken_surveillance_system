#![forbid(unsafe_code)]

use super::*;

fn args() -> Vec<OsString> {
    let pin = ContentDigest::sha256(b"retained-query-fixture").to_text();
    [
        "--root",
        "/absent-retained-query-fixture/root",
        "--site",
        "site:test",
        "--import-id",
        &pin,
        "--codec",
        "avc",
        "--sensor",
        "sensor:test",
        "--stream",
        "stream:test",
        "--generation",
        "1",
        "--anchor",
        &pin,
        "--receive-clock",
        &pin,
        "--decode-clock",
        &pin,
        "--time-scale",
        "90000",
        "--expected-replay-root",
        &pin,
        "--expected-replay-request",
        &pin,
        "--ntp-era",
        "0",
        "--utc-start-ns",
        "1000000000",
        "--utc-end-ns",
        "2000000000",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = args.iter().position(|argument| argument == key) {
        args[index + 1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}

#[test]
fn retained_query_admits_explicit_era_and_independent_pins_without_io() -> Result<()> {
    let options = parse(&args())?;
    assert_eq!(options.query.ntp_era, 0);
    assert_eq!(options.query.limits, ReplayTimeLimits::default());
    assert_eq!(options.retained_limits.max_source_bytes, 64 * 1024 * 1024);
    assert!(options.query.digest().is_ok());
    for key in [
        "--import-id",
        "--codec",
        "--sensor",
        "--stream",
        "--generation",
        "--anchor",
        "--receive-clock",
        "--decode-clock",
        "--time-scale",
        "--expected-replay-root",
        "--expected-replay-request",
        "--ntp-era",
        "--utc-start-ns",
        "--utc-end-ns",
    ] {
        let mut input = args();
        let index = input
            .iter()
            .position(|argument| argument == key)
            .ok_or_else(|| malformed("missing fixture key"))?;
        input.drain(index..index + 2);
        assert!(parse(&input).is_err(), "{key}");
    }
    Ok(())
}

#[test]
fn retained_query_refuses_ambiguous_effectful_and_unbounded_options() {
    for (key, value) in [
        ("--codec", "auto"),
        ("--ntp-era", "4294967296"),
        ("--ntp-era", "-1"),
        ("--utc-start-ns", "-1"),
        ("--utc-end-ns", "1000000000"),
        ("--utc-end-ns", "253402300800000000001"),
        ("--time-scale", "0"),
        ("--generation", "0"),
        ("--max-query-windows", "65"),
        ("--max-query-samples", "16385"),
        ("--max-query-packets", "262145"),
        ("--max-query-source-bytes", "2147483649"),
        ("--max-query-results", "32769"),
        ("--max-source-bytes", "67108865"),
        ("--chunk-bytes", "0"),
        ("--max-segment-bytes", "67108865"),
        ("--timeout-ms", "600001"),
        ("--expected-replay-root", "sha256:bad"),
        ("--root", "/"),
        ("--root", "/some/../root"),
        ("--root", "relative/root"),
        ("--output", "/some/export"),
        ("--approve", "sha256:bad"),
        ("--url", "rtsp://example.invalid"),
        ("--manifest-out", "/some/manifest"),
        ("--capture-start-ns", "0"),
    ] {
        let mut input = args();
        set(&mut input, key, value);
        assert!(parse(&input).is_err(), "{key}={value}");
    }
    let mut duplicate = args();
    duplicate.extend(["--ntp-era".into(), "0".into()]);
    assert!(parse(&duplicate).is_err());
    let mut oversized = args();
    set(&mut oversized, "--site", &"a".repeat(4097));
    assert!(parse(&oversized).is_err());
}
