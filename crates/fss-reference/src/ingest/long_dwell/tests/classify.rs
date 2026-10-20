#![forbid(unsafe_code)]
//! A complete retained temporal scan enters the real trained stage without rescanning its
//! foreground/tracker prefix. Synthetic footage tests wiring and custody, not model quality.

use super::*;
use crate::ScalarExecCx;
use crate::ingest::detector_cascade::{CascadeConfig, EvidenceOutcome};
use crate::ingest::long_dwell::incremental::{
    DwellRestoreLimits, PreparedIncrementalDwell, RetainedDwellCheckpoint,
};
use crate::ingest::long_dwell_replay::{DwellReplayLimits, inspect_dwell, replay_dwell};
use crate::ingest::package_detect::PackageDetectLimits;
use crate::ingest::rgb_package::RgbDetectorPackage;

const PACKAGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../models/yolox-nano/yolox_nano.fmpk"
));
const PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

fn package(cx: &ReplayCx, scalar: &ScalarExecCx) -> Test<RgbDetectorPackage> {
    Ok(RgbDetectorPackage::load(
        PACKAGE,
        ContentDigest::parse(PACKAGE_DIGEST)?,
        1 << 36,
        cx,
        scalar,
    )?)
}
fn classifier<'a>(
    package: &'a RgbDetectorPackage,
    scalar: &'a ScalarExecCx,
) -> Test<LongDwellDetector<'a>> {
    Ok(LongDwellDetector::new(
        package,
        PACKAGE,
        CascadeConfig {
            frames_per_track: 3,
            max_inferences: 1,
            ..CascadeConfig::default()
        },
        PackageDetectLimits::default(),
        scalar,
    )?)
}
fn complete(f: &Fixture, limits: LongDwellLimits) -> Test<LongDwellReport> {
    let prepared = PreparedIncrementalDwell::new(
        &f.deployment,
        f.plan.clone(),
        rule(),
        WatchOptions::default(),
        limits,
        &f.cx,
    )?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 127, &f.cx)?;
    running.advance(&f.deployment, FRAMES, &f.cx)?;
    Ok(running.finish(&f.deployment, &f.cx)?)
}

#[test]
fn cold_temporal_continuation_classifies_once_and_publishes_the_existing_replay_closure() -> Test {
    let mut f = Fixture::new("terminal-cold", &scene(true, None, None, false)?, true)?;
    let prepared = PreparedIncrementalDwell::new(
        &f.deployment,
        f.plan.clone(),
        rule(),
        WatchOptions::default(),
        LongDwellLimits::default(),
        &f.cx,
    )?;
    let mut running = prepared.start()?;
    let prefix = running.advance(&f.deployment, 127, &f.cx)?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    drop(running);
    drop(prepared);
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);

    let cx = context(&root, "principal:long-dwell-test")?;
    let mut deployment = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let restore = DwellRestoreLimits {
        maximum_prefix_frames: FRAMES,
        execution: LongDwellLimits::default(),
    };
    let saved = RetainedDwellCheckpoint::open(&deployment, pin, &restore, &cx)?;
    let mut resumed = saved.resume(&deployment, &restore, &cx)?;
    assert_eq!(resumed.restoration_work(), prefix);
    resumed.advance(&deployment, FRAMES, &cx)?;
    let work = resumed.work();
    resumed.retain(&mut deployment, &cx)?;
    let mut actual = resumed.finish(&deployment, &cx)?;
    assert_eq!(actual.frames_decoded(), FRAMES);
    assert!(actual.detector_recipe().is_none());
    let untrained_approval = actual.candidates()[0].proposal_digest();

    let scalar = ScalarExecCx::new();
    let package = package(&cx, &scalar)?;
    let detector = classifier(&package, &scalar)?;
    let expected = LongDwellReport::analyze_with_detector(
        &deployment,
        &f.plan,
        rule(),
        WatchOptions::default(),
        &LongDwellLimits::default(),
        &detector,
        false,
        &cx,
    )?;
    let before = (
        deployment.current_anchor().clone(),
        deployment.effects().last_root(),
        deployment.publisher().spool().digests().count(),
    );
    // The foreground/tracker decoder checkpoint must never be visited by this terminal stage.
    let terminal = context(&root, "principal:long-dwell-test")?;
    terminal.set_cancel_at_checkpoint("long_dwell:decoded");
    actual.classify_with_detector(&deployment, &detector, &terminal)?;
    assert!(!terminal.is_cancelled());
    assert_eq!(
        actual.to_json(before.0.commit_sequence, None)?,
        expected.to_json(before.0.commit_sequence, None)?
    );
    assert_eq!(actual.frames_decoded(), work.frames_decoded);
    assert_eq!(actual.assignment_work, work.assignment_work);
    let outcome = actual.detector_cascade().ok_or("trained outcome")?;
    assert_eq!(outcome.inferred_segments(), [5]);
    assert_eq!(outcome.budget_skipped_segments(), [6, 7]);
    assert_eq!(
        actual.candidates()[0]
            .class_evidence()
            .iter()
            .filter(|e| matches!(&e.outcome, EvidenceOutcome::BudgetExhausted))
            .count(),
        2
    );
    assert_ne!(actual.candidates()[0].proposal_digest(), untrained_approval);
    assert_eq!(deployment.current_anchor(), &before.0);
    assert_eq!(deployment.effects().last_root(), before.1);
    assert_eq!(deployment.publisher().spool().digests().count(), before.2);
    assert!(
        actual
            .publish(&mut deployment, &BTreeSet::from([untrained_approval]), &cx)
            .is_err()
    );
    assert_eq!(deployment.current_anchor(), &before.0);

    let approvals = BTreeSet::from([actual.candidates()[0].proposal_digest()]);
    let event = actual.candidates()[0].event().event_id.clone();
    assert_eq!(actual.publish(&mut deployment, &approvals, &cx)?, 1);
    assert_eq!(actual.publish(&mut deployment, &approvals, &cx)?, 0);
    assert_eq!(
        deployment
            .publisher()
            .spool()
            .read(ContentDigest::parse(PACKAGE_DIGEST)?)?,
        PACKAGE
    );
    let replay_limits = DwellReplayLimits::default();
    let inspection = inspect_dwell(&deployment, &event, &replay_limits, &cx)?;
    assert_eq!(
        inspection.recipe().detector_package_digest(),
        Some(ContentDigest::parse(PACKAGE_DIGEST)?)
    );
    let replay_pin = inspection.pins();
    let after = deployment.current_anchor().clone();
    drop(detector);
    drop(package);
    scalar.drain_and_finalize();
    drop(actual);
    drop(expected);
    drop(deployment);

    let cold_cx = context(&root, "principal:long-dwell-test")?;
    let cold = ReferenceDeployment::reopen(&root, SITE, &cold_cx)?;
    let replay = replay_dwell(&cold, &event, replay_pin, &replay_limits, &cold_cx)?;
    assert_eq!(replay.frames_replayed(), FRAMES);
    assert_eq!(replay.inspection().pins(), replay_pin);
    assert_eq!(cold.current_anchor(), &after);
    // A repository copy is not a substitute for the published model archive's custody.
    let archive = cold
        .publisher()
        .spool()
        .object_path(ContentDigest::parse(PACKAGE_DIGEST)?);
    fs::remove_file(&archive)?;
    assert!(replay_dwell(&cold, &event, replay_pin, &replay_limits, &cold_cx).is_err());
    assert!(!archive.exists());
    assert_eq!(cold.current_anchor(), &after);
    Ok(())
}

#[test]
fn original_limits_and_late_cancellation_leave_the_complete_report_usable() -> Test {
    let f = Fixture::new("terminal-budget", &scene(true, None, None, false)?, true)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f.cx, &scalar)?;
    let detector = classifier(&package, &scalar)?;
    let base = f.analyze(rule())?;
    let before = f.snapshot();
    for limits in [
        LongDwellLimits {
            maximum_source_chunk_bytes: base.source_bytes,
            ..LongDwellLimits::default()
        },
        LongDwellLimits {
            maximum_pixel_samples: base.pixel_samples,
            ..LongDwellLimits::default()
        },
    ] {
        let mut report = complete(&f, limits)?;
        let original = report.to_json(before.0.commit_sequence, None)?;
        assert!(matches!(
            report.classify_with_detector(&f.deployment, &detector, &f.cx),
            Err(WatchError::Limit)
        ));
        assert_eq!(report.to_json(before.0.commit_sequence, None)?, original);
        assert!(report.detector_recipe().is_none());
        report.revalidate_derived_source(&f.deployment, &f.cx)?;
        assert_eq!(f.snapshot(), before);
    }

    let mut report = complete(&f, LongDwellLimits::default())?;
    let original = report.to_json(before.0.commit_sequence, None)?;
    let interrupted = context(f.deployment.root(), "principal:long-dwell-test")?;
    interrupted.set_cancel_at_checkpoint("long_dwell:classified");
    assert!(
        report
            .classify_with_detector(&f.deployment, &detector, &interrupted)
            .is_err()
    );
    assert!(interrupted.is_drain_completed());
    assert_eq!(report.to_json(before.0.commit_sequence, None)?, original);
    assert!(report.detector_recipe().is_none());
    assert_eq!(f.snapshot(), before);
    // This explicit new terminal attempt owns its classifier cost separately. The failed
    // attempt did not change the reusable temporal scan's original counters or reservation.
    report.classify_with_detector(&f.deployment, &detector, &f.cx)?;
    let trained = report.to_json(before.0.commit_sequence, None)?;
    let repeated = context(f.deployment.root(), "principal:long-dwell-test")?;
    repeated.set_cancel_at_checkpoint("long_watch_detector:admit");
    assert!(
        report
            .classify_with_detector(&f.deployment, &detector, &repeated)
            .is_err()
    );
    assert!(
        !repeated.is_cancelled(),
        "a trained report cannot renew model work"
    );
    assert_eq!(report.to_json(before.0.commit_sequence, None)?, trained);
    assert_eq!(f.snapshot(), before);
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn empty_and_positive_reports_keep_exact_actor_privacy_and_source_fences() -> Test {
    for active in [false, true] {
        let mut f = Fixture::new(
            if active {
                "terminal-positive"
            } else {
                "terminal-empty"
            },
            &scene(active, None, None, false)?,
            true,
        )?;
        let scalar = ScalarExecCx::new();
        let package = package(&f.cx, &scalar)?;
        let detector = classifier(&package, &scalar)?;
        let mut report = complete(&f, LongDwellLimits::default())?;
        assert_eq!(report.candidates().is_empty(), !active);
        let before = f.snapshot();
        let original = report.to_json(before.0.commit_sequence, None)?;
        let foreign = context(f.deployment.root(), "principal:another-actor")?;
        assert!(matches!(
            report.classify_with_detector(&f.deployment, &detector, &foreign),
            Err(WatchError::Conflict)
        ));
        assert_eq!(report.to_json(before.0.commit_sequence, None)?, original);
        assert_eq!(f.snapshot(), before);

        let policy = PrivacyMaskPolicy::new(
            SensorId::parse("sensor:long-dwell")?,
            [WIDTH, HEIGHT],
            &[[40, 0, 4, 4]],
        )?;
        let approval = preview_mask(&f.deployment, &policy)?.approval;
        declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
        let after = f.snapshot();
        assert!(matches!(
            report.classify_with_detector(&f.deployment, &detector, &f.cx),
            Err(WatchError::Conflict)
        ));
        assert_eq!(report.to_json(before.0.commit_sequence, None)?, original);
        assert_eq!(f.snapshot(), after);

        let mut current = complete(&f, LongDwellLimits::default())?;
        let current_json = current.to_json(after.0.commit_sequence, None)?;
        let retained = RetainedFileImport::open(
            &f.deployment,
            f.plan.import_identity,
            RetainedReadLimits::default(),
            &f.cx,
        )?;
        let source = retained.manifest().ordered_chunks[0];
        let path = f.deployment.publisher().spool().object_path(source);
        fs::remove_file(&path)?;
        let missing = f.snapshot();
        assert!(
            current
                .classify_with_detector(&f.deployment, &detector, &f.cx)
                .is_err()
        );
        assert!(!path.exists());
        assert_eq!(
            current.to_json(after.0.commit_sequence, None)?,
            current_json
        );
        assert_eq!(f.snapshot(), missing);
        scalar.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn zero_episodes_execute_no_inference_and_requested_health_still_blocks_the_stage() -> Test {
    let f = Fixture::new("terminal-health", &scene(false, None, None, false)?, true)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f.cx, &scalar)?;
    let detector = classifier(&package, &scalar)?;
    let before = f.snapshot();
    let mut report = complete(&f, LongDwellLimits::default())?;
    let terminal = context(f.deployment.root(), "principal:long-dwell-test")?;
    terminal.set_cancel_at_checkpoint("long_watch_detector:frame");
    report.classify_with_detector(&f.deployment, &detector, &terminal)?;
    assert!(!terminal.is_cancelled());
    assert!(report.candidates().is_empty());
    assert!(
        report
            .detector_cascade()
            .ok_or("empty trained inventory")?
            .inferred_segments()
            .is_empty()
    );
    assert_eq!(f.snapshot(), before);

    let mut screened = LongDwellReport::analyze_screened(
        &f.deployment,
        &f.plan,
        rule(),
        WatchOptions::default(),
        &LongDwellLimits::default(),
        &f.cx,
    )?;
    assert!(screened.publication_blocked());
    let original = screened.to_json(before.0.commit_sequence, None)?;
    let diagnostic = screened
        .health_diagnostic()
        .ok_or("health diagnostic")?
        .approval_digest();
    let denied = context(f.deployment.root(), "principal:long-dwell-test")?;
    denied.set_cancel_at_checkpoint("long_watch_detector:admit");
    assert!(matches!(
        screened.classify_with_detector(&f.deployment, &detector, &denied),
        Err(WatchError::InvalidPlan(HEALTH_PUBLICATION_BLOCKED))
    ));
    assert!(!denied.is_cancelled());
    assert_eq!(screened.to_json(before.0.commit_sequence, None)?, original);
    assert_eq!(
        screened
            .health_diagnostic()
            .ok_or("preserved health diagnostic")?
            .approval_digest(),
        diagnostic
    );
    assert_eq!(f.snapshot(), before);
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn completed_avc_scan_uses_the_same_display_order_selection_and_native_recipe() -> Test {
    let f = inter_fixture("terminal-avc", SQUARE_MP4)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f.cx, &scalar)?;
    let detector = classifier(&package, &scalar)?;
    let before = f.snapshot();
    let mut report = f.analyze(rule())?;
    let expected = LongDwellReport::analyze_with_detector(
        &f.deployment,
        &f.plan,
        rule(),
        WatchOptions::default(),
        &LongDwellLimits::default(),
        &detector,
        false,
        &f.cx,
    )?;
    report.classify_with_detector(&f.deployment, &detector, &f.cx)?;
    assert_eq!(
        report.to_json(before.0.commit_sequence, None)?,
        expected.to_json(before.0.commit_sequence, None)?
    );
    assert_eq!(report.frames_decoded(), FRAMES);
    assert_eq!(report.candidates().len(), 1);
    assert_eq!(f.snapshot(), before);
    scalar.drain_and_finalize();
    Ok(())
}
