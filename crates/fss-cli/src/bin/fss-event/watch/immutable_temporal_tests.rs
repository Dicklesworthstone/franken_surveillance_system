#![forbid(unsafe_code)]
//! The temporal pipeline uses the same read owner and complete-delivery contract as short entry.

use super::*;

#[derive(Clone, Copy, Debug)]
enum Mode {
    ShortDwell,
    LongWatch,
    LongDwell,
}

fn temporal_args(
    root: &Path,
    import: ContentDigest,
    interpretation: &str,
    zone: &str,
    mode: Mode,
) -> Vec<OsString> {
    let mut args = request_args(root, import, interpretation, zone);
    match mode {
        Mode::ShortDwell => {}
        Mode::LongWatch => args.push("--stream-watch".into()),
        Mode::LongDwell => args.push("--stream-dwell".into()),
    }
    if !matches!(mode, Mode::LongWatch) {
        args.extend([
            "--dwell-for-ns".into(),
            "100000000".into(),
            "--dwell-max-gap-ns".into(),
            "300000000".into(),
        ]);
    }
    args
}

fn temporal_scene(frames: usize, motion_start: Option<usize>) -> Test<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut bytes = Vec::new();
    for index in 0..frames {
        let mut pixels = vec![0; 96 * 48];
        if let Some(start) = motion_start.filter(|start| index >= *start) {
            let left = ((index - start) * 8).min(80);
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * 96 + x] = 220;
                }
            }
        }
        bytes.extend(encode_jpeg(96, 48, &pixels, &config)?);
    }
    Ok(bytes)
}

fn invoke(args: &[OsString], output: &mut Vec<u8>) -> Test {
    let mut args = args.to_vec();
    args.insert(0, "watch".into());
    let options = crate::parse(&args)?.ok_or("watch unexpectedly parsed as help")?;
    crate::run(options, output)
}

#[test]
fn active_writer_temporal_previews_preserve_native_reports_and_cross_the_old_frame_boundary() -> Test {
    let mut fixture = Fixture::new("immutable-temporal-native")?;
    let short = fixture.ingest(
        "sensor:temporal-short", &scene()?, FileFormatHint::JpegStream, Some(0),
    )?;
    let long = fixture.ingest(
        "sensor:temporal-long", &temporal_scene(150, Some(126))?,
        FileFormatHint::JpegStream, Some(0),
    )?;
    let avc = fixture.ingest("sensor:temporal-avc", AVC, FileFormatHint::AnnexB, Some(0))?;
    let hevc = fixture.ingest("sensor:temporal-hevc", HEVC, FileFormatHint::Hevc, Some(0))?;
    let root = fixture.deployment.root().to_path_buf();
    let before = tree(&root)?;
    for (import, interpretation, zone, mode) in [
        (short, "gray", "door:64,0,32,32", Mode::ShortDwell),
        (long, "gray", "door:64,0,32,32", Mode::LongWatch),
        (long, "gray", "door:64,0,32,32", Mode::LongDwell),
        (avc, "ycbcr", "scene:0,0,176,144", Mode::LongWatch),
        (avc, "ycbcr", "scene:0,0,176,144", Mode::LongDwell),
        (hevc, "ycbcr", "door:64,0,32,32", Mode::LongWatch),
        (hevc, "ycbcr", "door:64,0,32,32", Mode::LongDwell),
    ] {
        let args = temporal_args(&root, import, interpretation, zone, mode);
        let action = crate::watch::parse(&args)?;
        assert!(action.is_immutable_preview());
        let mut native = Vec::new();
        crate::watch::run(
            &action, &mut fixture.deployment, &root, &fixture.cx, &mut native,
        )?;
        let mut preview = Vec::new();
        invoke(&args, &mut preview)?;
        assert_eq!(preview, native, "{mode:?}, {interpretation}");
        if import == long {
            let text = std::str::from_utf8(&preview)?;
            assert!(text.contains("\"frames_decoded\":150"));
            assert!(!text.contains("\"candidate_count\":0"), "{mode:?} lost the late event");
        }
        assert_eq!(tree(&root)?, before);
        let mut approved = args;
        approved.extend([
            "--approve".into(),
            ContentDigest::sha256(b"explicit temporal approval").to_text().into(),
        ]);
        let mut output = Vec::new();
        let error = invoke(&approved, &mut output).expect_err("approval bypassed active publisher");
        assert!(matches!(
            error.downcast_ref::<fss_reference::ReferenceError>(),
            Some(fss_reference::ReferenceError::DeploymentLocked { .. })
        ));
        assert!(output.is_empty());
    }
    let mut step = temporal_args(&root, long, "gray", "door:64,0,32,32", Mode::LongDwell);
    step.extend(["--dwell-step-frames".into(), "4".into()]);
    let mut output = Vec::new();
    let error = invoke(&step, &mut output).expect_err("checkpoint bypassed active publisher");
    assert!(matches!(
        error.downcast_ref::<fss_reference::ReferenceError>(),
        Some(fss_reference::ReferenceError::DeploymentLocked { .. })
    ));
    assert!(output.is_empty());
    assert_eq!(tree(&root)?, before);
    fixture.cx.drain_and_finalize();
    Ok(())
}

#[test]
fn degraded_whole_recording_diagnostics_remain_readable_without_publication() -> Test {
    let mut fixture = Fixture::new("immutable-temporal-health")?;
    let import = fixture.ingest(
        "sensor:temporal-dark", &temporal_scene(14, None)?,
        FileFormatHint::JpegStream, Some(0),
    )?;
    let root = fixture.deployment.root().to_path_buf();
    let before = tree(&root)?;
    for mode in [Mode::LongWatch, Mode::LongDwell] {
        let mut args = temporal_args(&root, import, "gray", "door:64,0,32,32", mode);
        args.extend(["--sensor-health".into(), "conservative-v1".into()]);
        let action = crate::watch::parse(&args)?;
        let mut native = Vec::new();
        crate::watch::run(
            &action, &mut fixture.deployment, &root, &fixture.cx, &mut native,
        )?;
        let mut preview = Vec::new();
        invoke(&args, &mut preview)?;
        assert_eq!(preview, native, "{mode:?}");
        let text = std::str::from_utf8(&preview)?;
        assert!(text.contains("\"publication_blocked\":true"), "health fixture was not degraded");
        assert!(text.contains("\"candidate_count\":0"));
        assert!(text.contains("historical_health"));
        assert_eq!(tree(&root)?, before);
    }
    fixture.cx.drain_and_finalize();
    Ok(())
}

#[test]
fn quiet_temporal_reports_share_exact_final_read_limits_and_cancel_without_output() -> Test {
    let mut fixture = Fixture::new("immutable-temporal-allowance")?;
    let import = fixture.ingest(
        "sensor:temporal-quiet", &temporal_scene(14, None)?,
        FileFormatHint::JpegStream, Some(0),
    )?;
    let root = fixture.deployment.root();
    let before = tree(root)?;
    let cx = read_context(root)?;
    let scalar = ScalarExecCx::new();
    for mode in [Mode::ShortDwell, Mode::LongWatch, Mode::LongDwell] {
        let args = temporal_args(root, import, "gray", "door:64,0,32,32", mode);
        let mut action = crate::watch::parse(&args)?;
        let calls = AtomicUsize::new(0);
        let count = || {
            calls.fetch_add(1, Ordering::SeqCst);
            false
        };
        let mut expected = Vec::new();
        let total = run_with(&action, root, &cx, &scalar, &count, &mut expected)?;
        let last = calls.load(Ordering::SeqCst);
        assert!(last > 1);
        assert!(std::str::from_utf8(&expected)?.contains("\"candidate_count\":0"));
        action.read_limits.max_read_bytes = usize::try_from(total.read_bytes)?;
        action.read_limits.max_read_objects = usize::try_from(total.read_objects)?;
        let exact = action.read_limits;
        let mut output = Vec::new();
        assert_eq!(
            run_with(&action, root, &cx, &scalar, &|| false, &mut output)?, total,
        );
        assert_eq!(output, expected);
        let report = fixture.directory.0.join(format!("refused-{mode:?}.json"));
        action.report_out = Some(report.clone());
        for bytes in [true, false] {
            action.read_limits = exact;
            if bytes {
                action.read_limits.max_read_bytes -= 1;
            } else {
                action.read_limits.max_read_objects -= 1;
            }
            let mut refused = Vec::new();
            assert!(run_with(&action, root, &cx, &scalar, &|| false, &mut refused).is_err());
            assert!(refused.is_empty());
            assert!(!report.exists());
            assert_eq!(tree(root)?, before);
        }
        action.read_limits = exact;
        calls.store(0, Ordering::SeqCst);
        let cancel_last = || calls.fetch_add(1, Ordering::SeqCst) + 1 >= last;
        let mut refused = Vec::new();
        assert!(run_with(&action, root, &cx, &scalar, &cancel_last, &mut refused).is_err());
        assert!(calls.load(Ordering::SeqCst) >= last);
        assert!(refused.is_empty());
        assert!(!report.exists());
        assert_eq!(tree(root)?, before);
    }
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    fixture.cx.drain_and_finalize();
    Ok(())
}

#[test]
fn quiet_whole_recording_final_validation_detects_late_capsule_and_source_damage() -> Test {
    for mode in [Mode::LongWatch, Mode::LongDwell] {
        for capsule in [true, false] {
            let mut fixture = Fixture::new(&format!("immutable-temporal-damage-{mode:?}-{capsule}"))?;
            let import = fixture.ingest(
                "sensor:temporal-damage", &temporal_scene(14, None)?,
                FileFormatHint::JpegStream, Some(0),
            )?;
            let root = fixture.deployment.root();
            let args = temporal_args(root, import, "gray", "door:64,0,32,32", mode);
            let mut action = crate::watch::parse(&args)?;
            action.options.tolerate_decode_refusals = !capsule;
            let retained = RetainedFileImport::open(
                &fixture.deployment, import, action.limits.read_limits, &fixture.cx,
            )?;
            let digest = if capsule {
                let object = format!("object:capsule:{}", retained.manifest().capsule_ids[0].as_str());
                fixture.deployment.ledger().batches().iter()
                    .flat_map(|batch| &batch.deltas)
                    .find(|delta| delta.object_id.as_str() == object)
                    .ok_or("missing quiet capsule")?
                    .payload_digest
            } else {
                retained.manifest().ordered_chunks[0]
            };
            let path = fixture.deployment.publisher().spool().object_path(digest);
            let mut damaged = fs::read(&path)?;
            *damaged.last_mut().ok_or("empty retained object")? ^= 1;
            let mut permissions = fs::metadata(&path)?.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            fs::set_permissions(&path, permissions)?;
            let scalar = ScalarExecCx::new();
            let calibration = read_context(root)?;
            calibration.set_cancel_at_checkpoint("watch_preview:delivery");
            let calls = AtomicUsize::new(0);
            let count = || {
                calls.fetch_add(1, Ordering::SeqCst);
                false
            };
            assert!(run_with(&action, root, &calibration, &scalar, &count, &mut Vec::new()).is_err());
            let before_delivery = calls.load(Ordering::SeqCst);
            calibration.drain_and_finalize();
            calls.store(0, Ordering::SeqCst);
            let fired = AtomicBool::new(false);
            let mutate = || {
                if calls.fetch_add(1, Ordering::SeqCst) == before_delivery {
                    fired.store(fs::write(&path, &damaged).is_ok(), Ordering::SeqCst);
                }
                false
            };
            let report = fixture.directory.0.join("damaged-temporal.json");
            action.report_out = Some(report.clone());
            let cx = read_context(root)?;
            let mut output = Vec::new();
            assert!(run_with(&action, root, &cx, &scalar, &mutate, &mut output).is_err());
            assert!(fired.load(Ordering::SeqCst), "late fault was not injected");
            assert!(output.is_empty());
            assert!(!report.exists());
            assert_eq!(fs::read(&path)?, damaged, "preview repaired source custody");
            scalar.drain_and_finalize();
            cx.drain_and_finalize();
            fixture.cx.drain_and_finalize();
        }
    }
    Ok(())
}
