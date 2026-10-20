#![forbid(unsafe_code)]
//! Short-dwell admission must reach the native adapter, not bypass temporal or authority gates.

use super::*;

type Test = Result<(), Box<dyn std::error::Error>>;

fn args(extra: &[&str]) -> Vec<OsString> {
    let pin = ContentDigest::sha256(b"admission-only fixture").to_text();
    let mut values: Vec<OsString> = [
        "--root",
        "deliberately-unopened-deployment",
        "--site",
        "site:dwell-fusion",
        "--import-id",
        &pin,
        "--interpretation",
        "gray",
        "--zone",
        "yard:0,0,96,48",
        "--detector-package",
        "deliberately-unread-model.fmpk",
        "--detector-digest",
        &pin,
        "--detector-max-inferences",
        "1",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    values.extend(extra.iter().map(|arg| OsString::from(*arg)));
    values
}

fn with_profile(mut values: Vec<OsString>) -> Vec<OsString> {
    values.extend([
        OsString::from("--fusion-profile"),
        OsString::from("deliberately-unread-profile.json"),
        OsString::from("--fusion-digest"),
        OsString::from(ContentDigest::sha256(b"profile fixture").to_text()),
    ]);
    values
}

const DWELL: &[&str] = &[
    "--dwell-for-ns",
    "200000000",
    "--dwell-max-gap-ns",
    "100000000",
    "--dwell-min-observations",
    "3",
];

#[test]
fn short_dwell_admits_fusion_without_changing_native_rerun_or_rule() -> Test {
    let plain = parse(&args(DWELL))?;
    let fused = parse(&with_profile(args(DWELL)))?;
    assert_eq!(plain.rerun, fused.rerun);
    assert!(fused.rerun.contains("--dwell-for-ns 200000000"));
    assert!(!fused.rerun.contains("--fusion-"));
    assert_eq!(
        fused.dwell.ok_or("missing dwell rule")?.minimum_duration_ns,
        200_000_000
    );
    assert!(fused.stream_watch.is_none());
    assert!(fused.stream_dwell.is_none());
    assert!(fused.approvals.is_empty());
    assert!(fused.retain_coverage.is_none());
    assert!(fused.retain_health.is_none());
    Ok(())
}

#[test]
fn dwell_fusion_keeps_temporal_health_and_range_admission() {
    for extra in [
        vec!["--dwell-for-ns", "200000000"],
        vec!["--dwell-max-gap-ns", "100000000"],
        vec!["--dwell-for-ns", "0", "--dwell-max-gap-ns", "100000000"],
        vec!["--dwell-for-ns", "200000000", "--dwell-max-gap-ns", "0"],
        vec![
            "--dwell-for-ns",
            "200000000",
            "--dwell-max-gap-ns",
            "100000000",
            "--dwell-min-observations",
            "1",
        ],
        vec![
            "--dwell-for-ns",
            "200000000",
            "--dwell-max-gap-ns",
            "100000000",
            "--sensor-health",
            "conservative-v1",
        ],
        vec![
            "--dwell-for-ns",
            "200000000",
            "--dwell-max-gap-ns",
            "100000000",
            "--segment-count",
            "129",
        ],
        vec![
            "--dwell-for-ns",
            "200000000",
            "--dwell-max-gap-ns",
            "100000000",
            "--dwell-trace-bytes",
            "4096",
        ],
    ] {
        assert!(
            parse(&with_profile(args(&extra))).is_err(),
            "admitted {extra:?}"
        );
    }
}

#[test]
fn dwell_fusion_cannot_publish_retain_or_replace_the_requested_temporal_owner() -> Test {
    let pin = ContentDigest::sha256(b"unusable authority approval").to_text();
    for flag in ["--approve", "--retain-coverage", "--retain-health"] {
        let mut values = with_profile(args(DWELL));
        values.extend([OsString::from(flag), OsString::from(&pin)]);
        let error = parse(&values).err().ok_or("fusion must remain read-only")?;
        assert!(error.contains("calibrated fusion is read-only"), "{error}");
    }
    // A complete dwell scan now has its own fusion scope. It cannot enter the entry owner
    // or publish an incremental checkpoint in a read-only advice invocation.
    for (flag, reason) in [
        (
            "--stream-watch",
            "--stream-watch cannot be combined with --stream-dwell or dwell options",
        ),
    ] {
        let mut values = with_profile(args(DWELL));
        values.push(OsString::from(flag));
        let error = parse(&values).err().ok_or("streaming must not drop requested dwell semantics")?;
        assert!(error.contains(reason), "{error}");
    }
    let mut whole = with_profile(args(DWELL));
    whole.push(OsString::from("--stream-dwell"));
    assert!(parse(&whole)?.stream_dwell.is_some());
    for flag in ["--approve", "--retain-coverage", "--retain-health"] {
        let mut values = whole.clone();
        values.extend([OsString::from(flag), OsString::from(&pin)]);
        let error = parse(&values)
            .err()
            .ok_or("complete dwell advice remains read-only")?;
        assert!(error.contains("calibrated fusion is read-only"), "{error}");
    }
    whole.extend(["--dwell-step-frames".into(), "128".into()]);
    assert!(parse(&whole).is_err());
    // Absence of a fusion request must preserve the original command's admission.
    let plain = parse(&args(DWELL))?;
    assert!(
        super::super::detector::check_watch_fusion_mode(plain.cascade.as_ref(), false, true,)
            .is_ok()
    );
    Ok(())
}
