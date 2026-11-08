#![forbid(unsafe_code)]
//! Real source-custody integration. Pure extraction tests do not substitute for this target.

mod package_evaluation_support;

use std::fs;

use fss_core::{ClockBasis, ContentDigest, SensorId};
use fss_reference::ReferenceDeployment;
use fss_reference::ingest::package_evaluation::{
    MAX_PACKAGE_EVALUATION_SOURCE_BYTES, PackageEvaluationRequest, RetainedPackageEvaluation,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use package_evaluation_support::{
    DURATION, Directory, Fixture, ORIGIN, PRINCIPAL, SENSOR, SITE, STREAM, Test, context, labels,
    policy, tracking,
};

fn evaluate(fixture: &Fixture, positive: bool) -> Test<RetainedPackageEvaluation> {
    let cx = context(&fixture.root)?;
    let result = RetainedPackageEvaluation::open(
        &fixture.root,
        SITE,
        &fixture.request(),
        &labels(positive),
        &policy(),
        MAX_PACKAGE_EVALUATION_SOURCE_BYTES,
        &cx,
    );
    cx.drain_and_finalize();
    Ok(result?)
}

#[test]
fn cold_native_tracks_use_first_confirmation_and_reproduce_without_loose_inputs() -> Test {
    let fixture = Fixture::new("cold", [160, 160, 192], Some(0))?;
    assert!(!fixture.directory.0.join("source.mjpeg").exists());
    let before = fixture.journals()?;
    let first = evaluate(&fixture, true)?;
    let repeated = evaluate(&fixture, true)?;
    assert_eq!(first.digest(), repeated.digest());
    assert_eq!(first.projection(), repeated.projection());
    assert_eq!(first.report().counts.true_positives, 1);
    assert_eq!(first.report().counts.false_positives, 0);
    assert_eq!(first.report().durations.observed_ns, u128::from(DURATION));
    assert_eq!(first.projection().candidates.candidates.len(), 1);
    assert_eq!(
        first.projection().candidates.candidates[0].detect_ns,
        100_000_000
    );
    let first_confirmation = first
        .projection()
        .provenance
        .tracks
        .iter()
        .find_map(|track| track.first_confirmation.as_ref())
        .ok_or("first confirmation")?;
    assert_eq!(
        Some(first_confirmation.score_bits),
        fixture.first_confirmation_score_bits
    );
    assert_eq!(first_confirmation.observation_index, 1);
    assert_eq!(first_confirmation.capture_ns, ORIGIN + 100_000_000);
    assert_eq!(first.projection().provenance.source.frames.len(), 3);
    assert_eq!(first.projection().provenance.source.site_lineage, SITE);
    assert_eq!(first.projection().provenance.source.principal, PRINCIPAL);
    assert_eq!(
        first.projection().provenance.import_identity,
        fixture.import
    );
    assert_eq!(first.projection().provenance.request.stream_id, STREAM);
    assert!(first.source_bytes_read() >= fixture.source_bytes * 2);
    assert_eq!(fixture.journals()?, before);
    Ok(())
}

#[test]
fn a_negative_clip_with_zero_native_tracks_retains_its_declared_denominator() -> Test {
    let fixture = Fixture::new("negative", [0, 0, 0], Some(0))?;
    let before = fixture.journals()?;
    let result = evaluate(&fixture, false)?;
    assert!(result.projection().provenance.tracks.is_empty());
    assert!(result.projection().candidates.candidates.is_empty());
    assert_eq!(result.report().counts.truth_events, 0);
    assert_eq!(result.report().counts.candidates, 0);
    assert_eq!(result.report().durations.observed_ns, u128::from(DURATION));
    assert_eq!(fixture.journals()?, before);
    Ok(())
}

#[test]
fn final_revalidation_cannot_renew_the_original_source_allowance() -> Test {
    let fixture = Fixture::new("source-budget", [160, 160, 192], Some(0))?;
    let full = evaluate(&fixture, true)?.source_bytes_read();
    assert!(full >= fixture.source_bytes * 2);
    let before = fixture.journals()?;
    let cx = context(&fixture.root)?;
    assert!(
        RetainedPackageEvaluation::open(
            &fixture.root,
            SITE,
            &fixture.request(),
            &labels(true),
            &policy(),
            full - 1,
            &cx,
        )
        .is_err()
    );
    cx.drain_and_finalize();
    let cx = context(&fixture.root)?;
    let exact = RetainedPackageEvaluation::open(
        &fixture.root,
        SITE,
        &fixture.request(),
        &labels(true),
        &policy(),
        full,
        &cx,
    )?;
    assert_eq!(exact.source_bytes_read(), full);
    assert_eq!(fixture.journals()?, before);
    Ok(())
}

#[test]
fn unknown_uncertain_outside_and_foreign_clock_mappings_never_produce_scores() -> Test {
    for (name, uncertainty) in [("unknown-time", None), ("uncertain-time", Some(1))] {
        let fixture = Fixture::new(name, [160, 160, 192], uncertainty)?;
        let before = fixture.journals()?;
        assert!(evaluate(&fixture, true).is_err());
        assert_eq!(fixture.journals()?, before);
    }
    let fixture = Fixture::new("mapping", [160, 160, 192], Some(0))?;
    let mut request = fixture.request();
    request.clip_origin_ns -= 1;
    let cx = context(&fixture.root)?;
    assert!(
        RetainedPackageEvaluation::open(
            &fixture.root,
            SITE,
            &request,
            &labels(true),
            &policy(),
            MAX_PACKAGE_EVALUATION_SOURCE_BYTES,
            &cx,
        )
        .is_err()
    );
    request = fixture.request();
    request.clock_basis = ClockBasis::UtcDisciplined;
    assert!(
        RetainedPackageEvaluation::open(
            &fixture.root,
            SITE,
            &request,
            &labels(true),
            &policy(),
            MAX_PACKAGE_EVALUATION_SOURCE_BYTES,
            &cx,
        )
        .is_err()
    );
    let mut wrong_labels = labels(true);
    wrong_labels.events[0].zone = Some("yard".into());
    assert!(
        RetainedPackageEvaluation::open(
            &fixture.root,
            SITE,
            &fixture.request(),
            &wrong_labels,
            &policy(),
            MAX_PACKAGE_EVALUATION_SOURCE_BYTES,
            &cx,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn source_corruption_and_current_privacy_withdrawals_refuse_without_repair() -> Test {
    let fixture = Fixture::new("withdrawal", [160, 160, 192], Some(0))?;
    let before = fixture.journals()?;
    let bytes = fs::read(&fixture.chunk)?;
    let mut damaged = bytes.clone();
    *damaged.last_mut().ok_or("source object")? ^= 1;
    fs::write(&fixture.chunk, &damaged)?;
    assert!(evaluate(&fixture, true).is_err());
    assert_eq!(fs::read(&fixture.chunk)?, damaged);
    assert_eq!(fixture.journals()?, before);
    fs::write(&fixture.chunk, &bytes)?;
    let cx = context(&fixture.root)?;
    let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
    let mask = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [32, 16], &[[0, 0, 32, 16]])?;
    let approval = preview_mask(&deployment, &mask)?.approval;
    declare_mask(&mut deployment, &mask, approval, &cx)?;
    drop(deployment);
    cx.drain_and_finalize();
    let after_mask = fixture.journals()?;
    assert!(evaluate(&fixture, true).is_err());
    assert_eq!(fixture.journals()?, after_mask);
    Ok(())
}

#[test]
fn cancellation_before_open_and_inside_the_second_source_pass_returns_no_result() -> Test {
    let fixture = Fixture::new("cancel", [160, 160, 192], Some(0))?;
    let before = fixture.journals()?;
    for (stage, occurrence) in [
        ("package_evaluation:open", 1),
        ("package_event:verify_source_frame", 4),
    ] {
        let cx = context(&fixture.root)?;
        cx.set_cancel_at_checkpoint_occurrence(stage, occurrence);
        let result = RetainedPackageEvaluation::open(
            &fixture.root,
            SITE,
            &fixture.request(),
            &labels(true),
            &policy(),
            MAX_PACKAGE_EVALUATION_SOURCE_BYTES,
            &cx,
        );
        assert!(matches!(result, Err(error) if error.code() == "evaluation.cancelled"));
        assert!(cx.is_drain_completed());
    }
    assert_eq!(fixture.journals()?, before);
    Ok(())
}

#[test]
fn missing_deployment_is_never_created_by_context_or_evaluation() -> Test {
    let directory = Directory::new("missing")?;
    let root = directory.0.join("absent");
    let cx = context(&root)?;
    assert!(!root.exists());
    let request = PackageEvaluationRequest {
        report_digest: ContentDigest::sha256(b"absent report"),
        label: "numeric-a".into(),
        tracking: tracking(),
        clip_id: "clip".into(),
        clip_origin_ns: ORIGIN,
        stream_id: STREAM.into(),
        clock_basis: ClockBasis::Estimated,
    };
    assert!(
        RetainedPackageEvaluation::open(
            &root,
            SITE,
            &request,
            &labels(true),
            &policy(),
            MAX_PACKAGE_EVALUATION_SOURCE_BYTES,
            &cx,
        )
        .is_err()
    );
    assert!(!root.exists());
    Ok(())
}
