#![forbid(unsafe_code)]
//! Whole-recording temporal eligibility, one classifier allowance and native cold replay.

use super::*;
use crate::ScalarExecCx;
use crate::ingest::detector_cascade::{CascadeConfig, EvidenceOutcome, SelectionReason};
use crate::ingest::long_dwell_replay::{DwellReplayLimits, inspect_dwell, replay_dwell};
use crate::ingest::package_detect::PackageDetectLimits;
use crate::ingest::rgb_package::RgbDetectorPackage;

const PACKAGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../models/yolox-nano/yolox_nano.fmpk"
));
const PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

fn package(f: &Fixture, scalar: &ScalarExecCx) -> Test<RgbDetectorPackage> {
    Ok(RgbDetectorPackage::load(
        PACKAGE,
        ContentDigest::parse(PACKAGE_DIGEST)?,
        1 << 36,
        &f.cx,
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

#[test]
fn trained_long_dwell_retains_exact_model_and_replays_after_cold_reopen() -> Test {
    let mut f = Fixture::new("trained-cold", &scene(true, None, None, false)?, true)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let detector = classifier(&package, &scalar)?;
    let before = f.snapshot();
    let mut report = LongDwellReport::analyze_with_detector(
        &f.deployment,
        &f.plan,
        rule(),
        WatchOptions::default(),
        &LongDwellLimits::default(),
        &detector,
        false,
        &f.cx,
    )?;
    assert_eq!(
        f.snapshot(),
        before,
        "analysis cannot grant event or effect authority"
    );
    assert_eq!(report.frames_decoded(), FRAMES);
    let outcome = report.detector_cascade().ok_or("trained outcome")?;
    assert_eq!(outcome.inferred_segments(), [5]);
    assert_eq!(outcome.budget_skipped_segments(), [6, 7]);
    assert_eq!(outcome.cascade_skipped.len(), FRAMES - 3);
    assert!(report.source_chunk_bytes_read() > f.input_bytes);
    let candidate = &report.candidates()[0];
    assert_eq!(candidate.span().trigger.position, 205);
    assert_eq!(candidate.class_evidence().len(), 3);
    assert_eq!(
        candidate.class_evidence()[0].reason,
        SelectionReason::DwellStart
    );
    assert!(matches!(
        candidate.class_evidence()[1].outcome,
        EvidenceOutcome::BudgetExhausted
    ));
    assert_eq!(candidate.event().kind, EventKind::Unclassified);
    assert_eq!(candidate.event().state, EventState::Indeterminate);
    assert!(candidate.event().decision_path.abstained);
    assert!(candidate.event().model_receipts.is_empty());
    assert!(candidate.event().evidence.iter().all(|item| !item.supports));
    assert!(
        candidate
            .event()
            .evidence
            .iter()
            .all(|item| item.relation == EvidenceEdgeRelation::DerivedFrom)
    );
    let classes = candidate.class_evidence().to_vec();
    let event = candidate.event().event_id.clone();
    let approvals = BTreeSet::from([candidate.proposal_digest()]);
    assert_eq!(report.publish(&mut f.deployment, &approvals, &f.cx)?, 1);
    assert_eq!(report.publish(&mut f.deployment, &approvals, &f.cx)?, 0);
    assert_eq!(
        f.deployment
            .publisher()
            .spool()
            .read(ContentDigest::parse(PACKAGE_DIGEST)?)?,
        PACKAGE
    );
    for class in &classes {
        assert_eq!(
            f.deployment.publisher().spool().read(class.digest)?,
            class.record
        );
    }
    let json = report.to_json(f.deployment.current_anchor().commit_sequence, None)?;
    assert!(json.contains("\"model_invoked\":true"));
    assert!(json.contains("qualifying_dwell_episode_first_actual_matches_only"));
    assert!(json.contains("\"alert_authorized\":false"));
    let inspected = inspect_dwell(&f.deployment, &event, &DwellReplayLimits::default(), &f.cx)?;
    assert_eq!(
        inspected.recipe().detector_package_digest(),
        Some(ContentDigest::parse(PACKAGE_DIGEST)?)
    );
    let pins = inspected.pins();
    let expected = f.snapshot();
    let root = f.deployment.root().to_path_buf();
    drop(report);
    drop(package);
    scalar.drain_and_finalize();
    drop(f.deployment);
    let reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
    let replay = replay_dwell(
        &reopened,
        &event,
        pins,
        &DwellReplayLimits::default(),
        &f.cx,
    )?;
    assert_eq!(replay.frames_replayed(), FRAMES);
    assert_eq!(replay.inspection().pins(), pins);
    assert_eq!(*reopened.current_anchor(), expected.0);
    assert_eq!(reopened.effects().last_root(), expected.1);
    assert_eq!(reopened.publisher().spool().digests().count(), expected.2);
    let current_limits = DwellReplayLimits {
        execution: LongDwellLimits {
            maximum_pixel_samples: LongDwellLimits::default().maximum_pixel_samples - 1,
            ..LongDwellLimits::default()
        },
        ..DwellReplayLimits::default()
    };
    assert!(
        replay_dwell(&reopened, &event, pins, &current_limits, &f.cx).is_err(),
        "replay must not execute a retained reservation beyond the current safety ceiling"
    );
    // A loose repository package may still exist, but replay must require selected custody.
    fs::remove_file(
        reopened
            .publisher()
            .spool()
            .object_path(ContentDigest::parse(PACKAGE_DIGEST)?),
    )?;
    assert!(
        replay_dwell(
            &reopened,
            &event,
            pins,
            &DwellReplayLimits::default(),
            &f.cx
        )
        .is_err()
    );
    assert_eq!(*reopened.current_anchor(), expected.0);
    assert_eq!(reopened.effects().last_root(), expected.1);
    Ok(())
}

#[test]
fn dwell_classifier_cannot_borrow_samples_or_renew_allowance_across_episodes() -> Test {
    let f = Fixture::new(
        "trained-episodes",
        &scene(true, Some(150), None, false)?,
        true,
    )?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let detector = classifier(&package, &scalar)?;
    let before = f.snapshot();
    let report = LongDwellReport::analyze_with_detector(
        &f.deployment,
        &f.plan,
        DwellPolicy {
            minimum_duration_ns: 5 * PERIOD,
            ..rule()
        },
        WatchOptions::default(),
        &LongDwellLimits::default(),
        &detector,
        false,
        &f.cx,
    )?;
    assert_eq!(f.snapshot(), before);
    assert_eq!(report.candidates().len(), 2);
    let first = &report.candidates()[0];
    let second = &report.candidates()[1];
    assert_eq!(first.episode.track, second.episode.track);
    assert_eq!(first.episode.epoch, second.episode.epoch);
    assert!(first.span().last.position < second.span().first.position);
    for candidate in report.candidates() {
        assert_eq!(candidate.class_evidence().len(), 3);
        assert_eq!(
            candidate.class_evidence()[0].segment,
            candidate.span().first.position
        );
        assert_eq!(
            candidate.class_evidence()[0].reason,
            SelectionReason::DwellStart
        );
        for class in candidate.class_evidence() {
            assert!(
                (candidate.span().first.position..=candidate.span().last.position)
                    .contains(&class.segment)
            );
        }
    }
    assert_eq!(
        report
            .detector_cascade()
            .ok_or("outcome")?
            .inferred_segments(),
        [5]
    );
    assert!(
        second
            .class_evidence()
            .iter()
            .all(|item| matches!(item.outcome, EvidenceOutcome::BudgetExhausted))
    );
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn trained_dwell_shares_source_and_pixel_allowances_with_temporal_scan() -> Test {
    let f = Fixture::new("trained-work", &scene(true, None, None, false)?, true)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let detector = classifier(&package, &scalar)?;
    let before = f.snapshot();
    let base = f.analyze(rule())?;
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
        assert!(matches!(
            LongDwellReport::analyze_with_detector(
                &f.deployment,
                &f.plan,
                rule(),
                WatchOptions::default(),
                &limits,
                &detector,
                false,
                &f.cx,
            ),
            Err(WatchError::Limit)
        ));
        assert_eq!(f.snapshot(), before);
    }
    f.cx.set_cancel_at_checkpoint("long_dwell_detector:select");
    assert!(
        LongDwellReport::analyze_with_detector(
            &f.deployment,
            &f.plan,
            rule(),
            WatchOptions::default(),
            &LongDwellLimits::default(),
            &detector,
            false,
            &f.cx,
        )
        .is_err()
    );
    assert!(f.cx.is_drain_completed());
    assert_eq!(f.snapshot(), before);
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn trained_mp4_dwell_selects_display_samples_but_classifies_their_native_coding_segments() -> Test {
    let f = inter_fixture("trained-mp4", SQUARE_MP4)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let detector = classifier(&package, &scalar)?;
    let before = f.snapshot();
    let report = LongDwellReport::analyze_with_detector(
        &f.deployment,
        &f.plan,
        rule(),
        WatchOptions::default(),
        &LongDwellLimits::default(),
        &detector,
        false,
        &f.cx,
    )?;
    assert_eq!(f.snapshot(), before);
    assert_eq!(report.frames_decoded(), FRAMES);
    assert_eq!(report.candidates().len(), 1);
    let completed = report.detector.as_ref().ok_or("detector")?;
    assert_eq!(completed.outcome.inferred_segments().len(), 1);
    assert_eq!(completed.entries.len(), 1);
    let selected = &completed.entries[0];
    let candidate = &report.candidates()[0];
    assert_eq!(selected.entry.position, candidate.span().first.position);
    assert_eq!(Some(selected.entry.capture), candidate.span().first.capture);
    for (class, frame) in candidate.class_evidence().iter().zip(&selected.frames) {
        assert_eq!(class.segment, frame.item.segment);
        assert!(
            (candidate.span().first.position..=candidate.span().last.position)
                .contains(&frame.position)
        );
    }
    assert!(
        report
            .to_json(0, None)?
            .contains("\"media_format\":\"mp4avc\"")
    );
    // A decoder read must be admitted before it happens. The sentinel would cancel if the
    // first frame reached perception, detecting any post-scan-only source limit check.
    f.cx.set_cancel_at_checkpoint("long_dwell:frame");
    let limits = LongDwellLimits {
        maximum_source_chunk_bytes: 1,
        ..LongDwellLimits::default()
    };
    for tolerate_decode_refusals in [false, true] {
        let options = WatchOptions {
            tolerate_decode_refusals,
        };
        assert!(matches!(
            LongDwellReport::analyze(&f.deployment, &f.plan, rule(), options, &limits, &f.cx,),
            Err(WatchError::Limit)
        ));
        assert!(matches!(
            LongDwellReport::analyze_with_detector(
                &f.deployment,
                &f.plan,
                rule(),
                options,
                &limits,
                &detector,
                false,
                &f.cx,
            ),
            Err(WatchError::Limit)
        ));
        assert!(
            !f.cx.is_drain_completed(),
            "source ceiling must refuse before the first decoded frame"
        );
        assert_eq!(f.snapshot(), before);
    }
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn nonqualifying_and_privacy_excluded_dwell_spend_no_inference_slots() -> Test {
    let mut f = Fixture::new("trained-ineligible", &scene(true, None, None, false)?, true)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let detector = classifier(&package, &scalar)?;
    let before = f.snapshot();
    let report = LongDwellReport::analyze_with_detector(
        &f.deployment,
        &f.plan,
        DwellPolicy {
            minimum_duration_ns: FRAMES as u64 * PERIOD,
            ..rule()
        },
        WatchOptions::default(),
        &LongDwellLimits::default(),
        &detector,
        false,
        &f.cx,
    )?;
    assert_eq!(f.snapshot(), before);
    assert!(report.candidates().is_empty());
    assert!(
        report
            .detector_cascade()
            .ok_or("outcome")?
            .frames
            .is_empty()
    );
    assert_eq!(report.source_chunk_bytes_read(), f.input_bytes);
    assert!(report.to_json(0, None)?.contains("\"model_invoked\":false"));
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:long-dwell")?,
        [WIDTH, HEIGHT],
        &[[0, 0, WIDTH, HEIGHT]],
    )?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let after_mask = f.snapshot();
    let report = LongDwellReport::analyze_with_detector(
        &f.deployment,
        &f.plan,
        rule(),
        WatchOptions::default(),
        &LongDwellLimits::default(),
        &detector,
        false,
        &f.cx,
    )?;
    assert_eq!(f.snapshot(), after_mask);
    assert!(report.candidates().is_empty());
    assert!(
        report
            .detector_cascade()
            .ok_or("outcome")?
            .frames
            .is_empty()
    );
    assert_eq!(report.masked_zones, 1);
    scalar.drain_and_finalize();
    Ok(())
}
