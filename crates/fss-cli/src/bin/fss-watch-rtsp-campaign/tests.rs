#![forbid(unsafe_code)]
//! Pure exact approval and full campaign admission; process tests own native custody behavior.

use std::ffi::OsString;

use fss_cli::agent_json::{array, object, string};
use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;

use super::{driver, plan};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ROOT: &str = "/missing/fss-campaign-watch-destination";
const SITE: &str = "site:campaign-watch-test";
const PRINCIPAL: &str = "principal:local-operator";

fn hash(label: &str) -> String {
    ContentDigest::sha256(label.as_bytes()).to_text()
}

fn child(ordinal: u32) -> Vec<String> {
    [
        (
            "--archive",
            format!("/missing/fss-campaign-watch-source-{ordinal}"),
        ),
        ("--root", ROOT.into()),
        ("--site", SITE.into()),
        ("--principal", PRINCIPAL.into()),
        ("--codec", "avc".into()),
        ("--catalog-slot", format!("catalog-{ordinal}")),
        ("--catalog-root", hash(&format!("catalog-root-{ordinal}"))),
        ("--decode-clock", hash(&format!("decode-clock-{ordinal}"))),
        ("--time-scale", "90000".into()),
        ("--sensor-id", "sensor:campaign-watch-test".into()),
        ("--stream-id", "stream:campaign-watch-test".into()),
        ("--generation", ordinal.to_string()),
        ("--anchor", hash("source-authority")),
        ("--receive-clock", hash(&format!("receive-clock-{ordinal}"))),
        ("--receive-time-ns", "5000000000".into()),
        ("--capture-start-ns", "0".into()),
        ("--capture-uncertainty-ns", "1000".into()),
        ("--max-frames", "3".into()),
        ("--owner-authorized", "yes".into()),
        ("--read-originals", "yes".into()),
        ("--retain-originals", "yes".into()),
    ]
    .into_iter()
    .flat_map(|(key, value)| [key.to_owned(), value])
    .collect()
}

fn args(children: &[Option<Vec<String>>]) -> Vec<OsString> {
    let rows = children
        .iter()
        .enumerate()
        .map(|(index, child)| {
            object(&[
                ("ordinal", (index + 1).to_string()),
                (
                    "request",
                    child.as_ref().map_or_else(
                        || "null".into(),
                        |child| array(&child.iter().map(|value| string(value)).collect::<Vec<_>>()),
                    ),
                ),
            ])
        })
        .collect::<Vec<_>>();
    [
        ("--root", ROOT.into()),
        ("--site", SITE.into()),
        ("--principal", PRINCIPAL.into()),
        (
            "--history-root",
            "/missing/fss-campaign-watch-history".into(),
        ),
        ("--history-approval", hash("history-approval")),
        ("--history-plan", hash("history-plan")),
        ("--history-root-digest", hash("history-root")),
        ("--history-records", "5".into()),
        ("--requests", array(&rows)),
        ("--interpretation", "ycbcr".into()),
        ("--zone", "entry:0,0,16,16".into()),
        ("--owner-authorized", "yes".into()),
        ("--read-originals", "yes".into()),
        ("--retain-originals", "yes".into()),
    ]
    .into_iter()
    .flat_map(|(key, value): (&str, String)| [OsString::from(key), OsString::from(value)])
    .collect()
}

fn set(input: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = input.iter().position(|part| part == key) {
        input[index + 1] = value.into();
    } else {
        input.extend([key.into(), value.into()]);
    }
}
fn child_set(input: &mut [String], key: &str, value: &str) {
    let index = input
        .iter()
        .position(|part| part == key)
        .expect("fixture key");
    input[index + 1] = value.into();
}
fn field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    Ok(value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or("missing fixture field")?)
}

#[test]
fn all_null_and_mixed_campaign_previews_are_pure_and_wrong_approval_has_no_io() -> Test {
    for children in [vec![None], vec![Some(child(1)), None, Some(child(3))]] {
        let mut options = plan::Options::parse(&args(&children))?;
        let report = parse(&options.preview()?)?;
        assert_eq!(field(&report, "kind")?.text(), Some("plan"));
        assert_eq!(
            field(&report, "writes")?.text(),
            Some("none_until_exact_outer_approval")
        );
        assert_eq!(field(&report, "network")?.text(), Some("none"));
        assert_eq!(field(&report, "event_publication")?.boolean(), Some(false));
        assert_eq!(
            field(&report, "absence_certifiable")?.boolean(),
            Some(false)
        );
        assert_eq!(
            field(&report, "attempts")?.array().ok_or("attempts")?.len(),
            children.len()
        );
        let reservation = field(&report, "reserved_whole_campaign")?;
        assert_eq!(
            field(reservation, "selected_recordings")?.integer(),
            Some(children.iter().filter(|row| row.is_some()).count() as i128)
        );
        assert_eq!(
            driver::execute(&options),
            Err("ERR-RTSP-CAMPAIGN-WATCH-AUTHORITY-001")
        );
        options.approve = Some(ContentDigest::sha256(b"incorrect exact outer approval"));
        assert_eq!(
            driver::execute(&options),
            Err("ERR-RTSP-CAMPAIGN-WATCH-AUTHORITY-001")
        );
    }
    Ok(())
}

#[test]
fn approval_binds_exact_prefix_and_every_owner_or_execution_allowance() -> Test {
    let input = args(&[Some(child(1)), None]);
    let original = plan::Options::parse(&input)?.approval()?;
    for (key, value) in [
        ("--history-approval", hash("other-approval")),
        ("--history-plan", hash("other-plan")),
        ("--history-root-digest", hash("other-root")),
        ("--history-records", "4".into()),
        ("--history-root", "/missing/other-history".into()),
        ("--history-max-records", "32".into()),
        ("--history-object-bytes", "131072".into()),
        ("--history-max-scan-entries", "2048".into()),
        ("--history-metadata-bytes", "8388608".into()),
        ("--history-storage-bytes", "16777216".into()),
        ("--archive-read-bytes", "999999999".into()),
        ("--max-work", "999999999999".into()),
        ("--timeout-ms", "60000".into()),
        ("--max-report-bytes", "1048576".into()),
        ("--screened", "yes".into()),
        ("--tolerate-decode-refusals", "yes".into()),
        ("--max-pixels", "20481".into()),
    ] {
        let mut changed = input.clone();
        set(&mut changed, key, &value);
        assert_ne!(
            plan::Options::parse(&changed)?.approval()?,
            original,
            "{key}"
        );
    }
    for (key, value) in [
        ("--archive", "/missing/another-source".into()),
        ("--catalog-root", hash("other-catalog")),
        ("--decode-clock", hash("other-decode-clock")),
        ("--receive-clock", hash("other-receive-clock")),
        ("--anchor", hash("other-source-authority")),
        ("--capture-start-ns", "1000000000".into()),
        ("--capture-uncertainty-ns", "2000".into()),
        ("--time-scale", "45000".into()),
        ("--max-frames", "4".into()),
    ] {
        let mut selected = child(1);
        child_set(&mut selected, key, &value);
        assert_ne!(
            plan::Options::parse(&args(&[Some(selected), None]))?.approval()?,
            original,
            "{key}"
        );
    }
    Ok(())
}

#[test]
fn missing_consent_partial_selectors_owner_drift_and_child_budget_refills_refuse() {
    for key in [
        "--owner-authorized",
        "--read-originals",
        "--retain-originals",
    ] {
        let mut input = args(&[None]);
        set(&mut input, key, "no");
        assert!(plan::Options::parse(&input).is_err(), "{key}");
        let mut selected = child(1);
        child_set(&mut selected, key, "no");
        assert!(
            plan::Options::parse(&args(&[Some(selected)])).is_err(),
            "child {key}"
        );
    }
    for (key, value) in [
        ("--root", "/missing/other-root"),
        ("--site", "site:other"),
        ("--principal", "principal:other"),
    ] {
        let mut selected = child(1);
        child_set(&mut selected, key, value);
        assert!(
            plan::Options::parse(&args(&[Some(selected)])).is_err(),
            "{key}"
        );
    }
    for (key, value) in [
        ("--approve", hash("child-approval")),
        ("--max-work", "1".into()),
        ("--timeout-ms", "1".into()),
    ] {
        let mut selected = child(1);
        selected.extend([key.into(), value]);
        assert!(
            plan::Options::parse(&args(&[Some(selected)])).is_err(),
            "{key}"
        );
    }
    let mut window = child(1);
    for key in ["--decode-clock", "--time-scale"] {
        let index = window.iter().position(|part| part == key).unwrap();
        window.drain(index..index + 2);
    }
    for (key, replacement) in [
        ("--catalog-slot", "--window-slot"),
        ("--catalog-root", "--window-root"),
    ] {
        let index = window.iter().position(|part| part == key).unwrap();
        window[index] = replacement.into();
    }
    assert!(plan::Options::parse(&args(&[Some(window)])).is_err());
}

#[test]
fn ordered_attempt_inventory_and_aggregate_overflow_are_rejected_purely() {
    for invalid in [
        "[]",
        "[{\"ordinal\":2,\"request\":null}]",
        "[{\"ordinal\":1}]",
        "[{\"ordinal\":1,\"request\":null,\"skip\":true}]",
        "[{\"ordinal\":1,\"request\":null},{\"ordinal\":1,\"request\":null}]",
    ] {
        let mut input = args(&[None]);
        set(&mut input, "--requests", invalid);
        assert!(plan::Options::parse(&input).is_err(), "{invalid}");
    }
    assert!(plan::Options::parse(&args(&vec![None; 17])).is_err());
    let mut input = args(&[Some(child(1)), Some(child(2))]);
    set(&mut input, "--stream-pixel-budget", &u64::MAX.to_string());
    assert!(plan::Options::parse(&input).is_err());
}
