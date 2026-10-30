#![forbid(unsafe_code)]
//! Real native video -> incremental temporal owner -> exact one-shot report and event oracle.

use super::*;

const HEVC_MP4: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/hevc_ingest/watch_96x48_moving.mp4"
));
const HEVC_OPEN_GOP_MP4: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fss-container/tests/fixtures/hevc_av.mp4"
));

fn hevc(label: &str) -> Test<Fixture> {
    let mut f = inter_fixture(label, HEVC_MP4)?;
    f.plan.segment_count = 14;
    f.plan.zones[0].width = 96;
    f.plan.zones[0].height = 48;
    Ok(f)
}

#[test]
fn avc_hot_slices_preserve_native_display_order_and_exact_one_shot_bytes() -> Test {
    let f = inter_fixture("incremental-avc-hot", SQUARE_MP4)?;
    let expected = f.analyze(rule())?;
    let before = f.snapshot();
    for chunk in [1, 17, 128, 299] {
        let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
        assert!(prepared.is_inter_coded());
        let mut running = prepared.start()?;
        let mut displayed = 0;
        while !running.complete() {
            let work = running.advance(&f.deployment, chunk, &f.cx)?;
            assert_eq!(work.frames_decoded, (displayed + chunk).min(FRAMES));
            assert!(work.source_positions >= work.frames_decoded);
            assert!(work.source_positions <= FRAMES);
            let video = running.video_progress().ok_or("video progress")?;
            assert_eq!(video.codec, "h264");
            assert_eq!(video.display_frames_processed, work.frames_decoded);
            assert_eq!(video.source_segments_consumed, work.source_positions);
            assert!(video.skipped_rasl_segments.is_empty());
            assert_eq!(video.decoder_drained, running.complete());
            assert_eq!(work.jpeg_work, 0);
            displayed = work.frames_decoded;
        }
        same_report(&running.finish(&f.deployment, &f.cx)?, &expected);
    }
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn coding_eof_is_not_completion_and_cold_resume_preserves_delayed_picture() -> Test {
    let mut f = inter_fixture("incremental-avc-cold", SQUARE_MP4)?;
    let expected = f.analyze(rule())?;
    let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
    let mut running = prepared.start()?;
    let prefix = running.advance(&f.deployment, FRAMES - 1, &f.cx)?;
    // The remaining picture is delayed native output. Every input was read, but the scan is
    // incomplete. This is the exact boundary where a source-counter-only gate would lie.
    assert_eq!(prefix.source_positions, FRAMES);
    assert_eq!(prefix.frames_decoded, FRAMES - 1);
    assert!(!running.complete());
    let video = running.video_progress().ok_or("video progress")?;
    assert!(!video.decoder_drained);
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    assert_eq!(running.retain(&mut f.deployment, &f.cx)?, pin);
    let retained = RetainedFileImport::open(
        &f.deployment,
        f.plan.import_identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    let (first, _) = source_capsule(&f.deployment, &retained, 0)?;
    let mut hull = first.capture;
    for segment in 1..prefix.source_positions {
        let (capsule, _) = source_capsule(&f.deployment, &retained, segment)?;
        hull.earliest = hull.earliest.min(capsule.capture.earliest);
        hull.latest = hull.latest.max(capsule.capture.latest);
    }
    let (last, _) = source_capsule(&f.deployment, &retained, prefix.source_positions - 1)?;
    // The final coding sample precedes another already consumed picture in presentation
    // time. The checkpoint must retain the complete capture hull, not just its endpoints.
    assert!(hull.latest > last.capture.latest);
    let revision = f
        .deployment
        .ledger()
        .current()
        .objects
        .values()
        .find(|object| {
            object.family == fss_publication::ROOT_REACHABILITY_FAMILY
                && object.payload_digest == pin.provenance_root
        })
        .ok_or("checkpoint authority revision")?;
    assert_eq!(revision.validity, hull);
    let root = f.deployment.root().to_path_buf();
    drop(running);
    drop(prepared);
    drop(f.deployment);
    let cx = context(&root, "principal:long-dwell-test")?;
    let mut deployment = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let saved = RetainedDwellCheckpoint::open(&deployment, pin, &restore_limits(), &cx)?;
    assert!(!saved.complete());
    assert_eq!(saved.video_progress(), Some(&video));
    let mut resumed = saved.resume(&deployment, &restore_limits(), &cx)?;
    assert_eq!(resumed.work(), prefix);
    assert_eq!(resumed.restoration_work(), prefix);
    assert!(!resumed.complete());
    let finished = resumed.advance(&deployment, 1, &cx)?;
    assert_eq!(finished.source_positions, prefix.source_positions);
    assert_eq!(finished.frames_decoded, FRAMES);
    assert!(resumed.complete());
    let complete = resumed.retain(&mut deployment, &cx)?;
    let mut report = resumed.finish(&deployment, &cx)?;
    same_report(&report, &expected);
    let approvals = BTreeSet::from([expected.candidates()[0].proposal_digest()]);
    assert_eq!(report.publish(&mut deployment, &approvals, &cx)?, 1);
    let saved = RetainedDwellCheckpoint::open(&deployment, complete, &restore_limits(), &cx)?;
    assert!(saved.complete());
    let mut retry = saved
        .resume(&deployment, &restore_limits(), &cx)?
        .finish(&deployment, &cx)?;
    assert_eq!(retry.publish(&mut deployment, &approvals, &cx)?, 0);
    Ok(())
}

#[test]
fn video_restore_and_hot_advance_keep_original_allowances() -> Test {
    let mut f = inter_fixture("incremental-avc-budget", SQUARE_MP4)?;
    let limits = LongDwellLimits {
        maximum_pixel_samples: u64::from(WIDTH * HEIGHT) * 100,
        ..LongDwellLimits::default()
    };
    let prepared = prepare(&f, limits, WatchOptions::default())?;
    let mut running = prepared.start()?;
    let prefix = running.advance(&f.deployment, 64, &f.cx)?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let after = f.snapshot();
    assert!(matches!(
        running.advance(&f.deployment, 64, &f.cx),
        Err(WatchError::Limit)
    ));
    assert!(!running.complete());
    assert!(running.advance(&f.deployment, 1, &f.cx).is_err());
    assert!(running.retain(&mut f.deployment, &f.cx).is_err());
    let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
    let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
    assert_eq!(resumed.work(), prefix);
    assert!(matches!(
        resumed.advance(&f.deployment, 64, &f.cx),
        Err(WatchError::Limit)
    ));
    assert_eq!(f.snapshot(), after);
    let mut denied = restore_limits();
    denied.maximum_prefix_frames = prefix.source_positions - 1;
    assert!(RetainedDwellCheckpoint::open(&f.deployment, pin, &denied, &f.cx).is_err());
    Ok(())
}

#[test]
fn video_cancellation_poisoning_and_regressed_capture_do_not_create_checkpoints() -> Test {
    let f = inter_fixture("incremental-avc-cancel", SQUARE_MP4)?;
    let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
    let mut running = prepared.start()?;
    let denied = context(f.deployment.root(), "principal:long-dwell-test")?;
    denied.set_cancel_at_checkpoint_occurrence("recorded_h264:segment", 3);
    let before = f.snapshot();
    assert!(running.advance(&f.deployment, 20, &denied).is_err());
    assert!(running.advance(&f.deployment, 1, &f.cx).is_err());
    assert!(!running.complete());
    assert_eq!(f.snapshot(), before);
    let f = inter_fixture("incremental-avc-clock", SQUARE_ANNEXB)?;
    let prepared = prepare(&f, LongDwellLimits::default(), WatchOptions::default())?;
    let mut running = prepared.start()?;
    assert!(matches!(
        running.advance(&f.deployment, FRAMES, &f.cx),
        Err(WatchError::InvalidPlan(
            "capture clock regressed during long dwell"
        ))
    ));
    assert!(!running.complete());
    Ok(())
}

#[test]
fn hevc_hot_and_cold_continuation_match_the_actual_native_owner() -> Test {
    let mut f = hevc("incremental-hevc")?;
    let rule = DwellPolicy {
        minimum_duration_ns: 1,
        maximum_sample_gap_ns: 1_000_000_000,
        minimum_observations: 3,
    };
    let expected = f.analyze(rule)?;
    let prepared = PreparedIncrementalDwell::new(
        &f.deployment,
        f.plan.clone(),
        rule,
        WatchOptions::default(),
        LongDwellLimits::default(),
        &f.cx,
    )?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 5, &f.cx)?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
    let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
    while !resumed.complete() {
        resumed.advance(&f.deployment, 1, &f.cx)?;
    }
    assert_eq!(
        resumed.video_progress().ok_or("video progress")?.codec,
        "h265"
    );
    same_report(&resumed.finish(&f.deployment, &f.cx)?, &expected);
    Ok(())
}

#[test]
fn hevc_cra_prefix_preserves_explicit_rasl_omissions_through_cold_completion() -> Test {
    for count in [3, 7] {
        let mut f = inter_fixture("incremental-hevc-cra", HEVC_OPEN_GOP_MP4)?;
        f.plan.first_segment = 3;
        f.plan.segment_count = count;
        f.plan.zones[0].width = 64;
        f.plan.zones[0].height = 48;
        let rule = DwellPolicy {
            minimum_duration_ns: 1,
            maximum_sample_gap_ns: 1_000_000_000,
            minimum_observations: 3,
        };
        let expected = f.analyze(rule)?;
        let prepared = PreparedIncrementalDwell::new(
            &f.deployment,
            f.plan.clone(),
            rule,
            WatchOptions::default(),
            LongDwellLimits::default(),
            &f.cx,
        )?;
        let mut running = prepared.start()?;
        running.advance(&f.deployment, 1, &f.cx)?;
        let prefix = running.work();
        let pin = running.retain(&mut f.deployment, &f.cx)?;
        let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
        let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
        assert_eq!(resumed.work(), prefix);
        while !resumed.complete() {
            resumed.advance(&f.deployment, 1, &f.cx)?;
        }
        let video = resumed.video_progress().ok_or("video progress")?;
        assert_eq!(video.source_segments_consumed, count);
        assert_eq!(video.display_frames_processed, count - 2);
        assert_eq!(video.skipped_rasl_segments, [4, 5]);
        assert!(video.decoder_drained);
        let complete = resumed.retain(&mut f.deployment, &f.cx)?;
        same_report(&resumed.finish(&f.deployment, &f.cx)?, &expected);
        let saved =
            RetainedDwellCheckpoint::open(&f.deployment, complete, &restore_limits(), &f.cx)?;
        assert!(saved.complete());
        let restored = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
        assert_eq!(restored.video_progress(), Some(video));
        same_report(&restored.finish(&f.deployment, &f.cx)?, &expected);
    }
    Ok(())
}

#[test]
fn screened_video_keeps_health_owner_and_complete_native_checkpoint() -> Test {
    let mut f = hevc("incremental-hevc-screened")?;
    let rule = DwellPolicy {
        minimum_duration_ns: 1,
        maximum_sample_gap_ns: 1_000_000_000,
        minimum_observations: 3,
    };
    let expected = LongDwellReport::analyze_screened(
        &f.deployment,
        &f.plan,
        rule,
        WatchOptions::default(),
        &LongDwellLimits::default(),
        &f.cx,
    )?;
    let prepared = PreparedIncrementalDwell::new_screened(
        &f.deployment,
        f.plan.clone(),
        rule,
        WatchOptions::default(),
        LongDwellLimits::default(),
        &f.cx,
    )?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 7, &f.cx)?;
    let original_health = running.health_work();
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
    let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
    assert_eq!(resumed.health_work(), original_health);
    assert_eq!(resumed.restoration_health_work(), original_health);
    resumed.advance(&f.deployment, 7, &f.cx)?;
    assert!(resumed.complete());
    let actual = resumed.finish(&f.deployment, &f.cx)?;
    same_report(&actual, &expected);
    assert_eq!(actual.health_summary(), expected.health_summary());
    Ok(())
}
