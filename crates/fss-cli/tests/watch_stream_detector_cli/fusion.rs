#![forbid(unsafe_code)]
//! Actual 170-frame import, native trained scan and versioned class advice; no synthetic
//! report is substituted for a scan. The model fixture does not qualify detector quality.
use super::*;
use fss_cli::event_fusion::{ClassFusionSpec, EventFusionProfile, SensorCalibration};
use fss_fusion::{FusionPolicy, LlrInterval, ScoreCalibration, Severity};
use std::collections::BTreeSet;

fn pinned(report: &Value, key: &str) -> Test<ContentDigest> {
    Ok(ContentDigest::parse(&text(report, key)?)?)
}
fn profile(native: &Value) -> Test<EventFusionProfile> {
    Ok(EventFusionProfile::for_long_watch(ClassFusionSpec {
        // NOT native.plan_digest: complete trace and trained-stage results must be bound.
        plan_digest: pinned(native, "analysis_digest")?,
        cascade_digest: pinned(member(native, "detector_cascade")?, "recipe_digest")?,
        coverage_digests: BTreeSet::new(), class_index: 0,
        prior: LlrInterval::point(-500)?,
        policy: FusionPolicy {
            generation: "policy:long-watch-fusion-fixture".into(),
            alert_threshold: 1000, retain_threshold: -500, reject_threshold: -1500,
            min_independent_support: 2, urgent_single_domain_threshold: None,
            max_wait_ns: 10, look_penalty_per_doubling: 301,
            operator_confirmation_available: true,
        },
        severity: Severity {
            expected_harm: 1000, false_alert_cost: 10, delay_cost_per_second: 0, reversible: false,
        },
        looks: 1, now_ns: 10,
        calibrations: vec![SensorCalibration {
            sensor: "sensor:stream-detector".into(), failure_domains: BTreeSet::new(),
            calibration: ScoreCalibration::from_counts(
                "long-watch-fixture-only", &[0, 500_000], &[(100, 9_900), (9_900, 100)],
            )?,
        }],
    }, pinned(native, "analysis_root")?)?)
}
fn with_profile(f: &Fixture, args: &[OsString], p: &EventFusionProfile, suffix: &str) -> Test<Vec<OsString>> {
    let path = f.directory.0.join(format!("fusion-{suffix}.json"));
    let json = p.to_json()?;
    fs::write(&path, &json)?;
    let mut args = args.to_vec();
    args.extend([
        "--fusion-profile".into(), path.into_os_string(),
        "--fusion-digest".into(), ContentDigest::sha256(json.as_bytes()).to_text().into(),
    ]);
    Ok(args)
}
fn advice(report: &Value) -> Test<&Value> { member(report, "calibrated_class_advice") }
fn read_only(advice: &Value) -> Test {
    for key in ["class_absence_certified", "event_policy_changed", "published", "effect_authority", "coverage_witness_supplied"] {
        assert_eq!(member(advice, key)?, &Value::Bool(false), "{key}");
    }
    assert!(array(advice, "coverage_digests")?.is_empty());
    assert_eq!(text(member(member(advice, "profile_query_template")?, "coverage")?, "state")?, "gap");
    Ok(())
}

#[test]
fn complete_late_entry_advice_preserves_native_work_proposals_and_custody() -> Test {
    let f = Fixture::mjpeg("fusion-late", true)?;
    let before = f.snapshot()?;
    let native = good(run(&f.detected())?)?;
    let p = profile(&native)?;
    let args = with_profile(&f, &f.detected(), &p, "late")?;
    let fused = good(run(&args)?)?;
    let derived = advice(&fused)?;
    assert_eq!(text(derived, "schema")?, "fss.event_class_fusion_report.v2");
    assert_eq!(text(derived, "analysis_root")?, text(&native, "analysis_root")?);
    assert_eq!(text(derived, "analysis_digest")?, text(&native, "analysis_digest")?);
    assert_eq!(text(derived, "detector_recipe_digest")?, text(member(&native, "detector_cascade")?, "recipe_digest")?);
    assert_eq!(text(derived, "profile_digest")?, p.digest().to_text());
    for key in ["frames_decoded", "source_chunk_bytes_read", "pixel_samples_processed", "analysis_digest", "analysis_root", "detector_cascade"] {
        assert_eq!(member(&fused, key)?, member(&native, key)?, "native {key} changed");
    }
    assert_eq!(count(&fused, "frames_decoded")?, FRAMES as i128);
    let entry = candidate(&fused)?;
    assert!(count(entry, "entry_position")? >= APPEARANCE as i128);
    let fused_entry = candidate(derived)?;
    assert_eq!(text(fused_entry, "native_proposal")?, text(entry, "proposal_digest")?);
    assert_eq!(text(fused_entry, "native_provenance_root")?, text(entry, "provenance_root")?);
    assert_eq!(text(entry, "proposal_digest")?, text(candidate(&native)?, "proposal_digest")?);
    unchanged_authority(&fused)?;
    read_only(derived)?;
    assert_eq!(f.snapshot()?, before);
    let repeated = good(run(&args)?)?;
    assert_eq!(advice(&repeated)?, derived);
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn zero_candidates_remain_an_explicit_empty_inventory_not_class_absence() -> Test {
    let f = Fixture::mjpeg("fusion-empty", false)?;
    let before = f.snapshot()?;
    let native = good(run(&f.detected())?)?;
    assert!(array(&native, "candidates")?.is_empty());
    let args = with_profile(&f, &f.detected(), &profile(&native)?, "empty")?;
    let fused = good(run(&args)?)?;
    assert!(array(advice(&fused)?, "candidates")?.is_empty());
    assert_eq!(count(&fused, "frames_decoded")?, FRAMES as i128);
    read_only(advice(&fused)?)?;
    unchanged_authority(&fused)?;
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn skipped_native_inferences_remain_in_the_complete_fusion_inventory() -> Test {
    let f = Fixture::mjpeg("fusion-skipped", true)?;
    let before = f.snapshot()?;
    let mut args = f.detected();
    args.extend(["--detector-frames-per-track".into(), "3".into()]);
    let native = good(run(&args)?)?;
    let args = with_profile(&f, &args, &profile(&native)?, "skipped")?;
    let fused = good(run(&args)?)?;
    let cascade = member(&fused, "detector_cascade")?;
    assert_eq!(count(cascade, "inference_count")?, 1);
    assert_eq!(array(cascade, "budget_skipped_segments")?.len(), 2);
    assert_eq!(member(candidate(&fused)?, "class_evidence")?, member(candidate(&native)?, "class_evidence")?);
    let derived = candidate(advice(&fused)?)?;
    let scores = array(derived, "scores")?;
    assert_eq!(scores.len(), 3);
    assert!(scores.iter().filter(|score| member(score, "score_f32_bits").ok() == Some(&Value::Null)).count() >= 2);
    for score in scores { assert_ne!(member(score, "source_record")?, &Value::Null); }
    read_only(advice(&fused)?)?;
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn wrong_complete_scope_and_stale_profile_bytes_refuse_without_a_report_prefix() -> Test {
    let f = Fixture::mjpeg("fusion-scope", true)?;
    let native = good(run(&f.detected())?)?;
    let base = profile(&native)?;
    let before = f.snapshot()?;
    for changed in 0..4 {
        let mut spec = base.spec().clone();
        let mut root = base.long_watch_analysis_root().ok_or("missing root")?;
        match changed {
            0 => root = ContentDigest::sha256(b"other root"),
            1 => spec.plan_digest = ContentDigest::sha256(b"other analysis"),
            2 => spec.cascade_digest = ContentDigest::sha256(b"other recipe"),
            _ => spec.calibrations[0].sensor = "sensor:other".into(),
        }
        let p = EventFusionProfile::for_long_watch(spec, root)?;
        let mut args = with_profile(&f, &f.detected(), &p, &format!("scope-{changed}"))?;
        let export = f.directory.0.join(format!("must-not-exist-{changed}.json"));
        args.extend(["--report-out".into(), export.clone().into_os_string()]);
        refuses(run(&args)?, "ERR-EVENT-FUSION-SCOPE-001");
        assert!(!export.exists());
        assert_eq!(f.snapshot()?, before);
    }
    let mut stale = with_profile(&f, &f.detected(), &base, "bad-hash")?;
    set(&mut stale, "--fusion-digest", &ContentDigest::sha256(b"not the profile").to_text())?;
    refuses(run(&stale)?, "ERR-EVENT-FUSION-PROFILE-001");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn derived_advice_cannot_publish_or_retain_authority_and_old_profiles_do_not_cross_scopes() -> Test {
    let f = Fixture::mjpeg("fusion-write", true)?;
    let native = good(run(&f.detected())?)?;
    let p = profile(&native)?;
    let before = f.snapshot()?;
    for flag in ["--approve", "--retain-health"] {
        let mut args = with_profile(&f, &f.detected(), &p, flag.trim_start_matches('-'))?;
        args.extend([flag.into(), text(candidate(&native)?, "proposal_digest")?.into()]);
        refuses(run(&args)?, "calibrated fusion is read-only");
        assert_eq!(f.snapshot()?, before);
    }
    let mut old = p.spec().clone();
    old.coverage_digests.insert(ContentDigest::sha256(b"short coverage"));
    let old = EventFusionProfile::new(old)?;
    let mut args = with_profile(&f, &f.detected(), &old, "short")?;
    let missing = f.directory.0.join("missing-model.fmpk");
    set(&mut args, "--detector-package", missing.to_str().ok_or("UTF-8 fixture path")?)?;
    refuses(run(&args)?, "ERR-EVENT-FUSION-SCOPE-001");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn requested_whole_scan_health_gate_still_fences_calibrated_advice() -> Test {
    let f = Fixture::mjpeg("fusion-health", true)?;
    let mut args = f.detected();
    args.extend(["--sensor-health".into(), "conservative-v1".into()]);
    let native = good(run(&args)?)?;
    assert_eq!(member(&native, "publication_blocked")?, &Value::Bool(true));
    let before = f.snapshot()?;
    let mut fused = with_profile(&f, &args, &profile(&native)?, "health")?;
    let export = f.directory.0.join("blocked-advice.json");
    fused.extend(["--report-out".into(), export.clone().into_os_string()]);
    refuses(run(&fused)?, "ERR-EVENT-FUSION-EVIDENCE-001");
    assert!(!export.exists());
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn avc_and_hevc_advice_consume_the_same_native_display_order_analysis() -> Test {
    let avc = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../fss-reference/tests/fixtures/long_dwell_h264/square_300.mp4")).as_slice();
    let hevc = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../fss-reference/tests/fixtures/hevc_ingest/watch_96x48_moving.mp4")).as_slice();
    for (name, bytes, frames, zone) in [
        ("fusion-avc", avc, 300, "porch:0,0,48,32"),
        ("fusion-hevc", hevc, 14, "porch:0,0,96,48"),
    ] {
        let f = Fixture::import(name, bytes, "mp4", frames)?;
        let before = f.snapshot()?;
        let mut args = f.detected();
        set(&mut args, "--interpretation", "ycbcr")?;
        set(&mut args, "--zone", zone)?;
        let native = good(run(&args)?)?;
        assert_eq!(count(&native, "frames_decoded")?, frames as i128);
        let args = with_profile(&f, &args, &profile(&native)?, name)?;
        let fused = good(run(&args)?)?;
        for key in ["analysis_digest", "analysis_root", "frames_decoded", "detector_cascade"] {
            assert_eq!(member(&fused, key)?, member(&native, key)?, "{key}");
        }
        assert_eq!(text(candidate(advice(&fused)?)?, "native_proposal")?,
            text(candidate(&native)?, "proposal_digest")?);
        read_only(advice(&fused)?)?;
        unchanged_authority(&fused)?;
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}
