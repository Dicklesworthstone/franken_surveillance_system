#![forbid(unsafe_code)]
//! Pure approval admission and native operator handoff contracts.

use std::ffi::OsString;

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;

use super::plan::Options;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn hash(label: &str) -> String {
    ContentDigest::sha256(label.as_bytes()).to_text()
}

fn args() -> Vec<OsString> {
    [
        ("--archive", "/missing/http-sentinel-source".into()),
        ("--root", "/missing/http-sentinel-destination".into()),
        ("--site", "site:http-sentinel-cli".into()),
        ("--history-session", hash("history-session")),
        ("--history-root", hash("history-root")),
        ("--history-connections", "2".into()),
        (
            "--binding",
            "10,sensor:porch,stream:porch,50000000000,0,0,10".into(),
        ),
        (
            "--binding",
            "20,sensor:porch,stream:porch,50000000000,20000000000,0,10".into(),
        ),
        ("--interpretation", "gray".into()),
        ("--package", "/missing/http-sentinel-model.fmpk".into()),
        ("--package-digest", hash("native-package")),
        ("--sentinel-every-frames", "2".into()),
        ("--sentinel-burst-frames", "1".into()),
        ("--sentinel-max-inferences", "4".into()),
        ("--retain-analysis", "yes".into()),
        ("--owner-authorized", "yes".into()),
        ("--read-originals", "yes".into()),
        ("--retain-originals", "yes".into()),
        ("--read-model", "yes".into()),
    ]
    .into_iter()
    .flat_map(|(k, v): (&str, String)| [k.into(), v.into()])
    .collect()
}

fn set(args: &mut [OsString], key: &str, value: &str) {
    let index = args.iter().position(|v| v == key).expect("test option") + 1;
    args[index] = value.into();
}

fn member<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|o| o.get(key))
        .ok_or("missing field".into())
}

#[test]
fn missing_source_and_model_paths_still_produce_pure_complete_preview() -> Test {
    let options = Options::parse(&args())?;
    let value = parse(&options.preview()?)?;
    assert_eq!(
        member(&value, "format")?.text(),
        Some("fss.http_history_sentinel_operator.v1")
    );
    assert_eq!(member(&value, "writes")?.text(), Some("none"));
    assert_eq!(member(&value, "network")?.text(), Some("none"));
    assert_eq!(member(&value, "interpretation")?.text(), Some("gray"));
    assert_eq!(
        member(&value, "backend_generation")?.text(),
        Some(options.plan.backend.generation().to_text().as_str())
    );
    assert_eq!(
        member(&value, "event_publication_authorized")?.boolean(),
        Some(false)
    );
    assert_eq!(
        member(member(&value, "sampling")?, "motion_independent")?.boolean(),
        Some(true)
    );
    assert_eq!(
        member(member(&value, "reserved_whole_history")?, "connections")?.integer(),
        Some(2)
    );
    assert_eq!(
        member(member(&value, "reserved_whole_history")?, "inferences")?.integer(),
        Some(4)
    );
    assert_eq!(
        member(&value, "bindings")?.array().map(|a| a.len()),
        Some(2)
    );
    assert!(options.approve.is_none());
    Ok(())
}

#[test]
fn approval_binds_originals_model_destination_actor_sampling_retention_and_limits() -> Test {
    let baseline = Options::parse(&args())?.approval()?;
    for (key, value) in [
        ("--archive", "/missing/other-http-source"),
        ("--root", "/missing/other-destination"),
        ("--site", "site:other"),
        ("--package", "/missing/other-model.fmpk"),
        ("--interpretation", "ycbcr"),
        ("--sentinel-every-frames", "3"),
        ("--sentinel-burst-frames", "2"),
        ("--sentinel-max-inferences", "3"),
        ("--retain-analysis", "no"),
        (
            "--binding",
            "10,sensor:other,stream:porch,50000000000,0,0,10",
        ),
    ] {
        let mut changed = args();
        set(&mut changed, key, value);
        assert_ne!(Options::parse(&changed)?.approval()?, baseline, "{key}");
    }
    for key in ["--history-session", "--history-root", "--package-digest"] {
        let mut changed = args();
        set(&mut changed, key, &hash("changed"));
        assert_ne!(Options::parse(&changed)?.approval()?, baseline, "{key}");
    }
    for (key, value) in [
        ("--principal", "principal:other"),
        ("--threads", "2"),
        ("--kernels", "scalar-reference"),
        ("--minimum-score-ppm", "500000"),
        ("--max-frame-pixels", "1536"),
        ("--max-work", "1000000"),
        ("--max-framing-work", "1000000"),
        ("--archive-read-bytes", "1048576"),
        ("--timeout-ms", "25000"),
        ("--stream-read-bytes", "1048576"),
        ("--stream-pixel-budget", "1048576"),
        ("--max-macs", "1000000"),
        ("--max-tensor-bytes", "1048576"),
        ("--max-output-bytes", "1024"),
        ("--max-history-reads", "128"),
    ] {
        let mut changed = args();
        changed.extend([key.into(), value.into()]);
        assert_ne!(Options::parse(&changed)?.approval()?, baseline, "{key}");
    }
    Ok(())
}

#[test]
fn approval_is_order_independent_except_for_connection_order() -> Test {
    let original = args();
    let baseline = Options::parse(&original)?.approval()?;
    let mut pairs = original
        .chunks_exact(2)
        .filter(|p| p[0] != "--binding")
        .map(<[OsString]>::to_vec)
        .collect::<Vec<_>>();
    pairs.reverse();
    let mut reordered = pairs.into_iter().flatten().collect::<Vec<_>>();
    for pair in original.chunks_exact(2).filter(|p| p[0] == "--binding") {
        reordered.extend_from_slice(pair);
    }
    assert_eq!(Options::parse(&reordered)?.approval()?, baseline);
    let binding_indices = reordered
        .iter()
        .enumerate()
        .filter(|(_, v)| *v == "--binding")
        .map(|(i, _)| i + 1)
        .collect::<Vec<_>>();
    reordered.swap(binding_indices[0], binding_indices[1]);
    assert!(Options::parse(&reordered).is_err());
    Ok(())
}

#[test]
fn missing_consent_unknown_modes_and_invalid_sampling_refuse_before_io() {
    for key in [
        "--owner-authorized",
        "--read-originals",
        "--retain-originals",
        "--read-model",
        "--retain-analysis",
    ] {
        let mut changed = args();
        let index = changed
            .iter()
            .position(|v| v == key)
            .expect("required option");
        changed.drain(index..index + 2);
        assert!(Options::parse(&changed).is_err(), "{key}");
    }
    for (key, value) in [
        ("--archive", "relative"),
        ("--root", "/missing/http-sentinel-source/nested"),
        ("--package", "/missing/http-sentinel-destination/model.fmpk"),
        ("--sentinel-every-frames", "0"),
        ("--sentinel-burst-frames", "3"),
        ("--sentinel-max-inferences", "2049"),
        ("--history-connections", "3"),
        ("--read-model", "no"),
        ("--interpretation", "auto"),
        ("--retain-analysis", "true"),
        (
            "--binding",
            "10,sensor:porch,stream:porch,50000000000,0,0,NaN",
        ),
    ] {
        let mut changed = args();
        set(&mut changed, key, value);
        assert!(Options::parse(&changed).is_err(), "{key} {value}");
    }
    for (key, value) in [
        ("--zone", "porch:0,0,48,32"),
        ("--screened", "yes"),
        ("--tolerate-decode-refusals", "yes"),
        ("--site", "site:duplicate"),
    ] {
        let mut changed = args();
        changed.extend([key.into(), value.into()]);
        assert!(Options::parse(&changed).is_err(), "{key}");
    }
}

#[test]
fn absent_or_wrong_approval_refuses_before_source_or_model_access() -> Test {
    let mut options = Options::parse(&args())?;
    assert_eq!(
        super::driver::execute(&options).err(),
        Some("ERR-HTTP-HISTORY-SENTINEL-AUTHORITY-001")
    );
    options.approve = Some(ContentDigest::sha256(b"wrong approval"));
    assert_eq!(
        super::driver::execute(&options).err(),
        Some("ERR-HTTP-HISTORY-SENTINEL-AUTHORITY-001")
    );
    Ok(())
}

#[test]
fn narrowed_frame_capacity_matches_native_cold_replay_for_every_codec() -> Test {
    let mut narrowed = args();
    narrowed.extend(["--max-frame-pixels".into(), "511".into()]);
    let options = Options::parse(&narrowed)?;
    let package = &options.limits.sentinel.package;
    assert_eq!(package.jpeg.frame.maximum_pixels, 511);
    assert_eq!(package.h264.max_macroblocks, 1);
    assert_eq!(package.h265.max_luma_samples, 511);
    let preview = parse(&options.preview()?)?;
    assert_eq!(member(&preview, "frame_pixels")?.integer(), Some(511));
    let limits = member(&preview, "limits")?;
    assert_eq!(member(limits, "jpeg_frame_pixels")?.integer(), Some(511));
    assert_eq!(member(limits, "avc_macroblocks")?.integer(), Some(1));
    assert_eq!(member(limits, "hevc_luma_samples")?.integer(), Some(511));
    for invalid in ["0", "255", "9437185"] {
        set(&mut narrowed, "--max-frame-pixels", invalid);
        assert!(Options::parse(&narrowed).is_err(), "{invalid}");
    }
    Ok(())
}

#[test]
fn native_resource_overflow_and_oversized_output_reservations_refuse() {
    for extra in [
        vec!["--max-macs", "18446744073709551615"],
        vec!["--max-work", "18446744073709551616"],
        vec!["--threads", "0"],
        vec!["--max-history-bytes", "0"],
        vec!["--max-report-bytes", "1023"],
    ] {
        let mut changed = args();
        changed.extend(extra.into_iter().map(OsString::from));
        assert!(Options::parse(&changed).is_err());
    }
    let mut changed = args();
    set(&mut changed, "--sentinel-max-inferences", "2048");
    changed.extend(["--max-output-bytes".into(), "16777216".into()]);
    assert!(Options::parse(&changed).is_err());
}
