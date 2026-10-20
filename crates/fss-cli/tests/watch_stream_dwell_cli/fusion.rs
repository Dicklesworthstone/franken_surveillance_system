#![forbid(unsafe_code)]
//! Real 300-frame retained scans and the pinned trained package through public processes.
//! Synthetic footage/counts exercise composition and never qualify detector or field calibration.

use super::*;
use fss_cli::event_fusion::{ClassFusionSpec, EventFusionProfile, SensorCalibration};
use fss_cli::json_input::{Value, parse};
use fss_fusion::{FusionPolicy, LlrInterval, ScoreCalibration, Severity};
use std::collections::BTreeSet;

const PACKAGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../models/yolox-nano/yolox_nano.fmpk"
));

fn member<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(key))
        .ok_or_else(|| format!("missing {key}").into())
}
fn text<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    member(value, key)?.text().ok_or("expected string".into())
}
fn items<'a>(value: &'a Value, key: &str) -> Test<&'a [Value]> {
    member(value, key)?.array().ok_or("expected array".into())
}
fn integer(value: &Value, key: &str) -> Test<i128> {
    member(value, key)?
        .integer()
        .ok_or("expected integer".into())
}
fn pin(value: &Value, key: &str) -> Test<ContentDigest> {
    Ok(ContentDigest::parse(text(value, key)?)?)
}
fn trained(fixture: &Fixture) -> Test<Vec<OsString>> {
    let path = fixture.directory.0.join("pinned detector.fmpk");
    fs::write(&path, PACKAGE)?;
    let mut args = fixture.args();
    args.extend([
        "--detector-package".into(),
        path.into_os_string(),
        "--detector-digest".into(),
        ContentDigest::sha256(PACKAGE).to_text().into(),
        "--detector-max-inferences".into(),
        "1".into(),
        "--detector-frames-per-track".into(),
        "3".into(),
    ]);
    Ok(args)
}
fn profile(native: &Value) -> Test<EventFusionProfile> {
    Ok(EventFusionProfile::for_long_dwell(
        ClassFusionSpec {
            plan_digest: pin(native, "analysis_digest")?,
            cascade_digest: pin(member(native, "detector_cascade")?, "recipe_digest")?,
            coverage_digests: BTreeSet::new(),
            class_index: 0,
            prior: LlrInterval::point(-500)?,
            policy: FusionPolicy {
                generation: "policy:dwell-fusion-fixture".into(),
                alert_threshold: 1000,
                retain_threshold: -500,
                reject_threshold: -1500,
                min_independent_support: 2,
                urgent_single_domain_threshold: None,
                max_wait_ns: 10,
                look_penalty_per_doubling: 301,
                operator_confirmation_available: true,
            },
            severity: Severity {
                expected_harm: 1000,
                false_alert_cost: 10,
                delay_cost_per_second: 0,
                reversible: false,
            },
            looks: 1,
            now_ns: 10,
            calibrations: vec![SensorCalibration {
                sensor: "sensor:stream-dwell".into(),
                failure_domains: BTreeSet::new(),
                calibration: ScoreCalibration::from_counts(
                    "fixture-only-not-deployment-calibration",
                    &[0, 500_000],
                    &[(100, 9900), (9900, 100)],
                )?,
            }],
        },
        pin(native, "analysis_root")?,
    )?)
}
fn with_profile(
    f: &Fixture,
    args: &[OsString],
    profile: &EventFusionProfile,
    name: &str,
) -> Test<Vec<OsString>> {
    let path = f.directory.0.join(format!("{name}.json"));
    let bytes = profile.to_json()?;
    fs::write(&path, &bytes)?;
    let mut args = args.to_vec();
    args.extend([
        "--fusion-profile".into(),
        path.into_os_string(),
        "--fusion-digest".into(),
        ContentDigest::sha256(bytes.as_bytes()).to_text().into(),
    ]);
    Ok(args)
}
fn read_only(report: &Value) -> Test {
    for flag in [
        "class_absence_certified",
        "event_policy_changed",
        "published",
        "effect_authority",
        "coverage_witness_supplied",
    ] {
        assert_eq!(member(report, flag)?.boolean(), Some(false), "{flag}");
    }
    assert_eq!(text(report, "schema")?, "fss.event_class_fusion_report.v4");
    assert_eq!(
        text(report, "temporal_claim")?,
        "sampled_dwell_only_no_continuous_occupancy"
    );
    assert!(items(report, "coverage_digests")?.is_empty());
    Ok(())
}

#[test]
fn calibrated_complete_dwell_preserves_native_episode_and_all_budget_omissions() -> Test {
    let f = Fixture::new("fusion-complete", true, true)?;
    let args = trained(&f)?;
    let before = f.snapshot()?;
    let native = parse(&good(run(&args)?)?)?;
    let profile = profile(&native)?;
    let mut fused_args = with_profile(&f, &args, &profile, "complete-dwell")?;
    let output_path = f.directory.0.join("complete advice.json");
    fused_args.extend(["--report-out".into(), output_path.clone().into_os_string()]);
    let output = good(run(&fused_args)?)?;
    assert_eq!(fs::read_to_string(&output_path)?, output);
    let fused = parse(&output)?;
    for key in [
        "analysis_digest",
        "analysis_root",
        "source_chunk_bytes_read",
        "frames_decoded",
        "pixel_samples_processed",
        "assignment_work_admitted",
        "detector_cascade",
        "candidates",
    ] {
        assert_eq!(
            member(&fused, key)?,
            member(&native, key)?,
            "changed native {key}"
        );
    }
    assert_eq!(integer(&fused, "frames_decoded")?, 300);
    let episode = items(&fused, "candidates")?
        .first()
        .ok_or("dwell episode")?;
    assert_eq!(integer(episode, "trigger_segment")?, 205);
    assert_eq!(items(episode, "class_evidence")?.len(), 3);
    let advice = member(&fused, "calibrated_class_advice")?;
    read_only(advice)?;
    let derived = items(advice, "candidates")?
        .first()
        .ok_or("episode class advice")?;
    assert_eq!(
        text(derived, "native_proposal")?,
        text(episode, "proposal_digest")?
    );
    assert_eq!(
        text(derived, "native_provenance_root")?,
        text(episode, "provenance_root")?
    );
    let scores = items(derived, "scores")?;
    assert_eq!(scores.len(), 3);
    assert!(
        scores
            .iter()
            .filter(|row| member(row, "score_f32_bits").ok() == Some(&Value::Null))
            .count()
            >= 2
    );
    assert!(scores.iter().all(|row| {
        member(row, "source_record")
            .ok()
            .is_some_and(|value| value != &Value::Null)
    }));
    assert_eq!(f.snapshot()?, before);
    // Repeat from retained source after the original import file was removed by the fixture.
    let replay_args = with_profile(&f, &args, &profile, "repeat-dwell")?;
    let repeated = parse(&good(run(&replay_args)?)?)?;
    assert_eq!(member(&repeated, "calibrated_class_advice")?, advice);
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn no_dwell_episode_is_an_empty_inventory_without_a_class_absence_claim() -> Test {
    let f = Fixture::new("fusion-empty", true, false)?;
    let args = trained(&f)?;
    let before = f.snapshot()?;
    let native = parse(&good(run(&args)?)?)?;
    assert!(items(&native, "candidates")?.is_empty());
    let fused_args = with_profile(&f, &args, &profile(&native)?, "empty-dwell")?;
    let fused = parse(&good(run(&fused_args)?)?)?;
    let advice = member(&fused, "calibrated_class_advice")?;
    read_only(advice)?;
    assert!(items(advice, "candidates")?.is_empty());
    assert_eq!(
        member(&fused, "detector_cascade")?,
        member(&native, "detector_cascade")?
    );
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn changed_rule_wrong_scope_and_authority_writes_cannot_reuse_dwell_profile() -> Test {
    let f = Fixture::new("fusion-scope", true, true)?;
    let args = trained(&f)?;
    let before = f.snapshot()?;
    let native = parse(&good(run(&args)?)?)?;
    let profile = profile(&native)?;
    let mut changed = with_profile(&f, &args, &profile, "wrong-rule")?;
    set(&mut changed, "--dwell-for-ns", "20100000000")?;
    let output = f.directory.0.join("refused advice.json");
    changed.extend(["--report-out".into(), output.clone().into_os_string()]);
    refuses(run(&changed)?, "ERR-EVENT-FUSION-SCOPE-001");
    assert!(!output.exists());
    // Wrong-scope input is refused before a deliberately absent detector is read.
    let watch =
        EventFusionProfile::for_long_watch(profile.spec().clone(), pin(&native, "analysis_root")?)?;
    let mut wrong_scope = with_profile(&f, &args, &watch, "entry-profile")?;
    set(
        &mut wrong_scope,
        "--detector-package",
        "/nonexistent/fss-dwell-model",
    )?;
    refuses(run(&wrong_scope)?, "ERR-EVENT-FUSION-SCOPE-001");
    for flag in ["--approve", "--retain-coverage", "--retain-health"] {
        let mut requested = with_profile(&f, &args, &profile, "read-only")?;
        requested.extend([
            OsString::from(flag),
            ContentDigest::sha256(b"no effect authority")
                .to_text()
                .into(),
        ]);
        refuses(run(&requested)?, "calibrated fusion is read-only");
    }
    let mut partial = with_profile(&f, &args, &profile, "partial")?;
    partial.extend(["--dwell-step-frames".into(), "128".into()]);
    refuses(run(&partial)?, "incremental dwell");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}
