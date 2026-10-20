#![forbid(unsafe_code)]
//! Complete late dwell episodes use exact native class observations, across real CLI processes.
//! The trained-package fixture establishes wiring and custody, not detector quality.

use super::*;

fn dwell_args(f: &Fixture) -> Vec<OsString> {
    let mut args = f.detected();
    args.retain(|arg| arg != "--stream-watch");
    args.extend(
        [
            "--stream-dwell",
            "--dwell-for-ns",
            "200000000",
            "--dwell-max-gap-ns",
            "100000000",
            "--dwell-min-observations",
            "3",
        ]
        .map(OsString::from),
    );
    args
}

fn dwell_profile(native: &Value) -> Test<EventFusionProfile> {
    let template = profile(native)?;
    Ok(EventFusionProfile::for_long_dwell(
        template.spec().clone(),
        pinned(native, "analysis_root")?,
    )?)
}

#[test]
fn late_complete_dwell_advice_preserves_native_episode_work_and_exact_approvals() -> Test {
    let f = Fixture::mjpeg("dwell-fusion-late", true)?;
    let before = f.snapshot()?;
    let base = dwell_args(&f);
    let native = good(run(&base)?)?;
    assert_eq!(count(&native, "frames_decoded")?, FRAMES as i128);
    assert!(count(candidate(&native)?, "first_segment")? >= APPEARANCE as i128);
    assert!(count(candidate(&native)?, "trigger_segment")? > 128);
    let p = dwell_profile(&native)?;
    let args = with_profile(&f, &base, &p, "dwell-late")?;
    let mut exported = args.clone();
    let output = f.directory.0.join("complete dwell advice.json");
    exported.extend(["--report-out".into(), output.clone().into_os_string()]);
    let fused = good(run(&exported)?)?;
    assert_eq!(parse(&fs::read_to_string(output)?)?, fused);
    let derived = advice(&fused)?;
    assert_eq!(text(derived, "schema")?, "fss.event_class_fusion_report.v4");
    assert_eq!(
        text(derived, "analysis_digest")?,
        text(&native, "analysis_digest")?
    );
    assert_eq!(
        text(derived, "analysis_root")?,
        text(&native, "analysis_root")?
    );
    assert_eq!(text(derived, "profile_digest")?, p.digest().to_text());
    assert_eq!(
        text(derived, "detector_recipe_digest")?,
        text(member(&native, "detector_cascade")?, "recipe_digest")?
    );
    for key in [
        "analysis_digest",
        "analysis_root",
        "frames_decoded",
        "source_chunk_bytes_read",
        "pixel_samples_processed",
        "jpeg_work_units",
        "detector_cascade",
        "candidates",
    ] {
        assert_eq!(member(&fused, key)?, member(&native, key)?, "{key}");
    }
    assert_eq!(
        text(candidate(derived)?, "native_proposal")?,
        text(candidate(&native)?, "proposal_digest")?
    );
    assert_eq!(
        text(candidate(derived)?, "native_provenance_root")?,
        text(candidate(&native)?, "provenance_root")?
    );
    assert!(!text(candidate(&fused)?, "publish_command")?.contains("--fusion-"));
    unchanged_authority(&fused)?;
    read_only(derived)?;
    assert_eq!(f.snapshot()?, before);
    assert_eq!(advice(&good(run(&args)?)?)?, derived);
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn dwell_fusion_preserves_skipped_episode_observations_and_quiet_inventory() -> Test {
    for active in [false, true] {
        let f = Fixture::mjpeg(
            if active {
                "dwell-fusion-skipped"
            } else {
                "dwell-fusion-empty"
            },
            active,
        )?;
        let before = f.snapshot()?;
        let mut args = dwell_args(&f);
        args.extend(["--detector-frames-per-track".into(), "3".into()]);
        let native = good(run(&args)?)?;
        let args = with_profile(&f, &args, &dwell_profile(&native)?, "dwell-inventory")?;
        let fused = good(run(&args)?)?;
        let derived = advice(&fused)?;
        if active {
            let cascade = member(&fused, "detector_cascade")?;
            assert_eq!(count(cascade, "inference_count")?, 1);
            assert_eq!(array(cascade, "budget_skipped_segments")?.len(), 2);
            let scores = array(candidate(derived)?, "scores")?;
            assert_eq!(scores.len(), 3);
            assert!(
                scores
                    .iter()
                    .filter(|score| { member(score, "score_f32_bits").ok() == Some(&Value::Null) })
                    .count()
                    >= 2
            );
            for score in scores {
                assert_ne!(member(score, "source_record")?, &Value::Null);
            }
        } else {
            assert!(array(&native, "candidates")?.is_empty());
            assert!(array(derived, "candidates")?.is_empty());
            assert_eq!(
                count(member(&fused, "detector_cascade")?, "inference_count")?,
                0
            );
        }
        assert_eq!(
            member(&fused, "candidates")?,
            member(&native, "candidates")?
        );
        read_only(derived)?;
        unchanged_authority(&fused)?;
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn dwell_fusion_requires_exact_temporal_source_recipe_and_scope_before_delivery() -> Test {
    let f = Fixture::mjpeg("dwell-fusion-scope", true)?;
    let base = dwell_args(&f);
    let native = good(run(&base)?)?;
    let p = dwell_profile(&native)?;
    let before = f.snapshot()?;
    for changed in 0..4 {
        let mut spec = p.spec().clone();
        let mut root = pinned(&native, "analysis_root")?;
        match changed {
            0 => root = ContentDigest::sha256(b"wrong dwell analysis root"),
            1 => spec.plan_digest = ContentDigest::sha256(b"wrong complete dwell trace"),
            2 => spec.cascade_digest = ContentDigest::sha256(b"wrong dwell detector recipe"),
            _ => spec.calibrations[0].sensor = "sensor:other".into(),
        }
        let wrong = EventFusionProfile::for_long_dwell(spec, root)?;
        let mut args = with_profile(&f, &base, &wrong, &format!("dwell-scope-{changed}"))?;
        let export = f
            .directory
            .0
            .join(format!("no-dwell-advice-{changed}.json"));
        args.extend(["--report-out".into(), export.clone().into_os_string()]);
        refuses(run(&args)?, "ERR-EVENT-FUSION-SCOPE-001");
        assert!(!export.exists());
        assert_eq!(f.snapshot()?, before);
    }
    let mut changed_rule = with_profile(&f, &base, &p, "changed-dwell-rule")?;
    set(&mut changed_rule, "--dwell-for-ns", "300000000")?;
    refuses(run(&changed_rule)?, "ERR-EVENT-FUSION-SCOPE-001");
    assert_eq!(f.snapshot()?, before);

    // An entry profile using the same digests is still not a dwell profile. Its rejection
    // precedes opening even a nonexistent detector package or retained source.
    let watch = profile(&native)?;
    let mut wrong_mode = with_profile(&f, &base, &watch, "entry-is-not-dwell")?;
    let missing = f.directory.0.join("unavailable-model.fmpk");
    set(
        &mut wrong_mode,
        "--detector-package",
        missing.to_str().ok_or("UTF-8 path")?,
    )?;
    refuses(run(&wrong_mode)?, "ERR-EVENT-FUSION-SCOPE-001");
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn dwell_advice_cannot_write_authority_or_bypass_health_and_native_budgets() -> Test {
    let f = Fixture::mjpeg("dwell-fusion-gates", true)?;
    let base = dwell_args(&f);
    let native = good(run(&base)?)?;
    let p = dwell_profile(&native)?;
    let before = f.snapshot()?;
    for flag in ["--approve", "--retain-health", "--retain-coverage"] {
        let mut args = with_profile(&f, &base, &p, flag.trim_start_matches('-'))?;
        args.extend([
            flag.into(),
            text(candidate(&native)?, "proposal_digest")?.into(),
        ]);
        refuses(run(&args)?, "calibrated fusion is read-only");
        assert_eq!(f.snapshot()?, before);
    }
    let mut partial = with_profile(&f, &base, &p, "partial")?;
    partial.extend(["--dwell-step-frames".into(), "64".into()]);
    refuses(run(&partial)?, "excludes incremental dwell");
    assert_eq!(f.snapshot()?, before);
    let mut exhausted = with_profile(&f, &base, &p, "budget")?;
    exhausted.extend(["--dwell-pixel-budget".into(), "1".into()]);
    refuses(run(&exhausted)?, "ERR-WATCH-LIMIT-001");
    assert_eq!(f.snapshot()?, before);

    let mut screened = base;
    screened.extend(["--sensor-health".into(), "conservative-v1".into()]);
    let native = good(run(&screened)?)?;
    assert_eq!(member(&native, "publication_blocked")?, &Value::Bool(true));
    let p = dwell_profile(&native)?;
    let mut args = with_profile(&f, &screened, &p, "screened")?;
    let export = f.directory.0.join("blocked-dwell-advice.json");
    args.extend(["--report-out".into(), export.clone().into_os_string()]);
    refuses(run(&args)?, "ERR-EVENT-FUSION-EVIDENCE-001");
    assert!(!export.exists());
    assert_eq!(f.snapshot()?, before);
    Ok(())
}

#[test]
fn avc_and_hevc_dwell_advice_preserve_native_display_order_and_episode_inventory() -> Test {
    let avc = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fss-reference/tests/fixtures/long_dwell_h264/square_300.mp4"
    ))
    .as_slice();
    let hevc = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fss-reference/tests/fixtures/hevc_ingest/watch_96x48_moving.mp4"
    ))
    .as_slice();
    for (name, bytes, frames, zone, duration, gap, freeze_background) in [
        (
            "dwell-fusion-avc",
            avc,
            300,
            "porch:0,0,48,32",
            "20000000000",
            "100000000",
            false,
        ),
        (
            "dwell-fusion-hevc",
            hevc,
            14,
            "porch:0,0,96,48",
            "1",
            "1000000000",
            true,
        ),
    ] {
        let f = Fixture::import(name, bytes, "mp4", frames)?;
        let before = f.snapshot()?;
        let mut args = dwell_args(&f);
        set(&mut args, "--interpretation", "ycbcr")?;
        set(&mut args, "--zone", zone)?;
        set(&mut args, "--dwell-for-ns", duration)?;
        set(&mut args, "--dwell-max-gap-ns", gap)?;
        if freeze_background {
            args.extend(["--learning-rate-num".into(), "0".into()]);
        }
        let native = good(run(&args)?)?;
        assert_eq!(count(&native, "frames_decoded")?, frames as i128);
        let native_candidates = array(&native, "candidates")?;
        assert!(
            !native_candidates.is_empty(),
            "verified dwell fixture must qualify"
        );
        let args = with_profile(&f, &args, &dwell_profile(&native)?, name)?;
        let fused = good(run(&args)?)?;
        for key in [
            "analysis_digest",
            "analysis_root",
            "frames_decoded",
            "detector_cascade",
            "candidates",
        ] {
            assert_eq!(member(&fused, key)?, member(&native, key)?, "{key}");
        }
        let proposals = native_candidates
            .iter()
            .map(|candidate| text(candidate, "proposal_digest"))
            .collect::<Test<BTreeSet<_>>>()?;
        let advice = advice(&fused)?;
        let derived_candidates = array(advice, "candidates")?;
        assert_eq!(derived_candidates.len(), native_candidates.len());
        for derived in derived_candidates {
            assert!(proposals.contains(&text(derived, "native_proposal")?));
        }
        read_only(advice)?;
        unchanged_authority(&fused)?;
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}
