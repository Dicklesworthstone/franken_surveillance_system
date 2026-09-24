#![forbid(unsafe_code)]
//! Public activity-gate regression contracts: pixels, resets, skips, and replay.
use std::error::Error;

use fss_core::{ContentDigest, Generation, SourceId, StreamGeneration};
use fss_reference::activity::{
    ActivityBasis, ActivityConfig, ActivityDecision, ActivityFrame, ActivityGate, ActivityReset,
    ActivitySkip, MAX_ACTIVITY_SAMPLES,
};
use fss_reference::preprocess::ImageBytes;
use fss_reference::{ExecBudget, ExecError, ScalarExecCx};

type TestResult = Result<(), Box<dyn Error>>;

fn basis() -> Result<ActivityBasis, Box<dyn Error>> {
    Ok(ActivityBasis {
        source: SourceId::parse("src:yard")?,
        stream_generation: StreamGeneration::parse("stream:yard:v1")?,
        decoder_generation: Generation::GENESIS,
        policy_digest: ContentDigest::sha256(b"owner-policy-v1"),
        projection_digest: ContentDigest::sha256(b"privacy-view-v1"),
    })
}

fn frame<'a>(basis: &'a ActivityBasis, sequence: u64, bytes: &'a [u8]) -> ActivityFrame<'a> {
    ActivityFrame {
        image: ImageBytes {
            bytes,
            height: 2,
            width: 2,
            channels: 1,
            generation: basis.decoder_generation,
        },
        basis,
        sequence,
    }
}

fn gate() -> Result<ActivityGate, ExecError> {
    Ok(ActivityGate::new(ActivityConfig::new(2, 2, 20, 2_500)?))
}

#[test]
fn first_frame_is_not_quiet_and_stationary_pixels_never_certify_absence() -> TestResult {
    let basis = basis()?;
    let mut gate = gate()?;
    let cx = ScalarExecCx::new();
    let first = gate.observe(frame(&basis, 1, &[30; 4]), ExecBudget::unlimited(), &cx)?;
    assert_eq!(
        first.decision(),
        ActivityDecision::BaselineOnly(ActivityReset::FirstFrame)
    );
    assert_eq!(first.measurement(), None);
    let next = gate.observe(frame(&basis, 2, &[30; 4]), ExecBudget::unlimited(), &cx)?;
    assert_eq!(next.decision(), ActivityDecision::BelowThreshold);
    assert!(!next.supports_absence_claim());
    let m = next.measurement().ok_or("missing measured statistics")?;
    assert_eq!(
        (
            m.changed_samples,
            m.absolute_delta_sum,
            m.changed_basis_points
        ),
        (0, 0, 0)
    );
    assert_eq!(m.changed_sample_box, None);
    assert_eq!(next.previous_input_digest(), first.input_digest());
    assert_ne!(first.input_digest(), next.input_digest()); // sequence is part of identity
    assert_eq!(gate.retained_samples(), 4);
    Ok(())
}

#[test]
fn pixel_and_fraction_thresholds_are_inclusive() -> TestResult {
    let basis = basis()?;
    let mut gate = gate()?;
    let cx = ScalarExecCx::new();
    gate.observe(frame(&basis, 1, &[0; 4]), ExecBudget::unlimited(), &cx)?;
    let result = gate.observe(
        frame(&basis, 2, &[0, 20, 0, 0]),
        ExecBudget::unlimited(),
        &cx,
    )?;
    assert_eq!(result.decision(), ActivityDecision::Changed);
    let m = result.measurement().ok_or("missing change measurement")?;
    assert_eq!(m.changed_samples, 1);
    assert_eq!(m.absolute_delta_sum, 20);
    assert_eq!(m.changed_basis_points, 2_500);
    assert_eq!(m.changed_sample_box, Some([1, 0, 2, 1]));
    assert!(!result.supports_absence_claim());
    Ok(())
}

#[test]
fn threshold_decisions_use_exact_fractions_not_rounded_display_scores() -> TestResult {
    let basis = basis()?;
    let cx = ScalarExecCx::new();
    for (threshold, expected) in [
        (3_333, ActivityDecision::Changed),
        (3_334, ActivityDecision::BelowThreshold),
    ] {
        let mut gate = ActivityGate::new(ActivityConfig::new(3, 1, 1, threshold)?);
        for (sequence, bytes) in [(1, [0, 0, 0]), (2, [1, 0, 0])] {
            let mut input = frame(&basis, sequence, &bytes);
            input.image.height = 1;
            input.image.width = 3;
            let result = gate.observe(input, ExecBudget::unlimited(), &cx)?;
            if sequence == 2 {
                assert_eq!(result.decision(), expected);
                assert_eq!(
                    result
                        .measurement()
                        .ok_or("missing fraction")?
                        .changed_basis_points,
                    3_333
                );
            }
        }
    }
    Ok(())
}

#[test]
fn rgb_conversion_is_integer_and_grid_does_not_duplicate_small_sources() -> TestResult {
    let basis = basis()?;
    let cx = ScalarExecCx::new();
    let mut gate = ActivityGate::new(ActivityConfig::new(256, 256, 30, 7_500)?);
    let mut before = frame(&basis, 1, &[0; 12]);
    before.image.channels = 3;
    gate.observe(before, ExecBudget::unlimited(), &cx)?;
    let mut after = frame(&basis, 2, &[255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255]);
    after.image.channels = 3;
    let result = gate.observe(after, ExecBudget::unlimited(), &cx)?;
    let m = result.measurement().ok_or("missing RGB measurement")?;
    assert_eq!((m.sample_width, m.sample_height), (2, 2));
    assert_eq!(m.changed_samples, 3); // luma is [77, 149, 29, 255]
    assert_eq!(m.absolute_delta_sum, 510);
    assert_eq!(result.decision(), ActivityDecision::Changed);
    assert_eq!(gate.retained_samples(), 4);
    assert!(gate.retained_samples() <= MAX_ACTIVITY_SAMPLES);
    Ok(())
}

#[test]
fn every_source_or_interpretation_change_requires_a_new_baseline() -> TestResult {
    let original = basis()?;
    let mut variants = Vec::new();
    let mut source = original.clone();
    source.source = SourceId::parse("src:other")?;
    variants.push(source);
    let mut stream = original.clone();
    stream.stream_generation = StreamGeneration::parse("stream:yard:v2")?;
    variants.push(stream);
    let mut decoder = original.clone();
    decoder.decoder_generation = Generation::GENESIS.next()?;
    variants.push(decoder);
    let mut policy = original.clone();
    policy.policy_digest = ContentDigest::sha256(b"policy-v2");
    variants.push(policy);
    let mut view = original.clone();
    view.projection_digest = ContentDigest::sha256(b"view-v2");
    variants.push(view);
    for changed in variants {
        let mut gate = gate()?;
        let cx = ScalarExecCx::new();
        let first = gate.observe(frame(&original, 1, &[0; 4]), ExecBudget::unlimited(), &cx)?;
        let reset = gate.observe(frame(&changed, 2, &[0; 4]), ExecBudget::unlimited(), &cx)?;
        assert_eq!(
            reset.decision(),
            ActivityDecision::BaselineOnly(ActivityReset::BasisChanged)
        );
        assert_eq!(reset.previous_input_digest(), None);
        assert_ne!(first.basis_digest(), reset.basis_digest());
    }
    Ok(())
}

#[test]
fn sequence_and_shape_gaps_cannot_produce_low_activity() -> TestResult {
    let basis = basis()?;
    let mut gate = gate()?;
    let cx = ScalarExecCx::new();
    gate.observe(frame(&basis, 1, &[0; 4]), ExecBudget::unlimited(), &cx)?;
    let gap = gate.observe(frame(&basis, 3, &[0; 4]), ExecBudget::unlimited(), &cx)?;
    assert_eq!(
        gap.decision(),
        ActivityDecision::BaselineOnly(ActivityReset::SequenceGap)
    );
    let mut reshaped = frame(&basis, 4, &[0; 4]);
    reshaped.image.height = 1;
    reshaped.image.width = 4;
    let shape = gate.observe(reshaped, ExecBudget::unlimited(), &cx)?;
    assert_eq!(
        shape.decision(),
        ActivityDecision::BaselineOnly(ActivityReset::ShapeChanged)
    );
    assert!(
        gate.observe(reshaped, ExecBudget::unlimited(), &cx)
            .is_err()
    );
    assert_eq!(gate.retained_samples(), 0);
    reshaped.sequence = 5;
    let after_error = gate.observe(reshaped, ExecBudget::unlimited(), &cx)?;
    assert_eq!(
        after_error.decision(),
        ActivityDecision::BaselineOnly(ActivityReset::ObservationGap)
    );
    Ok(())
}

#[test]
fn denied_obscured_and_unobserved_are_distinct_pixel_free_skips() -> TestResult {
    let basis = basis()?;
    let cx = ScalarExecCx::new();
    let mut digests = Vec::new();
    for reason in [
        ActivitySkip::Denied,
        ActivitySkip::Obscured,
        ActivitySkip::Unobserved,
        ActivitySkip::Budget,
    ] {
        let mut gate = gate()?;
        gate.observe(frame(&basis, 1, &[0; 4]), ExecBudget::unlimited(), &cx)?;
        let receipt = gate.skip(&basis, 2, reason)?;
        assert_eq!(receipt.decision(), ActivityDecision::NotEvaluated(reason));
        assert_eq!(receipt.input_digest(), None);
        assert_eq!(receipt.previous_input_digest(), None);
        assert_eq!(receipt.measurement(), None);
        assert_eq!(receipt.admitted_work(), 0);
        assert_eq!(gate.retained_samples(), 0);
        assert!(!receipt.supports_absence_claim());
        digests.push(receipt.digest());
        let resumed = gate.observe(frame(&basis, 3, &[0; 4]), ExecBudget::unlimited(), &cx)?;
        assert_eq!(
            resumed.decision(),
            ActivityDecision::BaselineOnly(ActivityReset::ObservationGap)
        );
    }
    digests.sort();
    digests.dedup();
    assert_eq!(digests.len(), 4);
    Ok(())
}

#[test]
fn budget_refusal_drops_stale_baseline_and_has_no_pixel_identity() -> TestResult {
    let basis = basis()?;
    let mut gate = gate()?;
    let cx = ScalarExecCx::new();
    let first = gate.observe(frame(&basis, 1, &[0; 4]), ExecBudget::unlimited(), &cx)?;
    assert_eq!(first.admitted_work(), 4 + 4 * 32);
    assert_eq!(first.pixel_buffer_bytes(), 8);
    let second_budget = ExecBudget::new(first.admitted_work(), first.pixel_buffer_bytes() + 4);
    let exact = gate.observe(frame(&basis, 2, &[0; 4]), second_budget, &cx)?;
    assert_eq!(exact.decision(), ActivityDecision::BelowThreshold);
    let skipped = gate.observe(
        frame(&basis, 3, &[0; 4]),
        ExecBudget::new(second_budget.max_macs - 1, second_budget.max_bytes),
        &cx,
    )?;
    assert_eq!(
        skipped.decision(),
        ActivityDecision::NotEvaluated(ActivitySkip::Budget)
    );
    assert_eq!(skipped.input_digest(), None);
    assert_eq!(gate.retained_samples(), 0);
    let resumed = gate.observe(frame(&basis, 4, &[0; 4]), ExecBudget::unlimited(), &cx)?;
    assert_eq!(
        resumed.decision(),
        ActivityDecision::BaselineOnly(ActivityReset::ObservationGap)
    );
    let memory_skip = gate.observe(
        frame(&basis, 5, &[0; 4]),
        ExecBudget::new(u64::MAX, 11),
        &cx,
    )?;
    assert_eq!(
        memory_skip.decision(),
        ActivityDecision::NotEvaluated(ActivitySkip::Budget)
    );
    Ok(())
}

#[test]
fn cancellation_invalidates_comparison_without_advancing_sequence() -> TestResult {
    let basis = basis()?;
    let mut gate = gate()?;
    gate.observe(
        frame(&basis, 1, &[0; 4]),
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    let cancelled = ScalarExecCx::new();
    cancelled.request_cancellation();
    assert!(matches!(
        gate.observe(
            frame(&basis, 2, &[0; 4]),
            ExecBudget::unlimited(),
            &cancelled
        ),
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cancelled.is_drain_completed());
    assert_eq!(gate.retained_samples(), 0);
    let retry = gate.observe(
        frame(&basis, 2, &[0; 4]),
        ExecBudget::unlimited(),
        &ScalarExecCx::new(),
    )?;
    assert_eq!(
        retry.decision(),
        ActivityDecision::BaselineOnly(ActivityReset::ObservationGap)
    );
    Ok(())
}

#[test]
fn bad_metadata_and_generation_cannot_reuse_an_old_baseline() -> TestResult {
    let basis = basis()?;
    let mut gate = gate()?;
    let cx = ScalarExecCx::new();
    gate.observe(frame(&basis, 1, &[0; 4]), ExecBudget::unlimited(), &cx)?;
    let mut bad = frame(&basis, 2, &[0; 4]);
    bad.image.generation = Generation::GENESIS.next()?;
    assert!(matches!(
        gate.observe(bad, ExecBudget::unlimited(), &cx),
        Err(ExecError::GenerationMismatch { .. })
    ));
    assert_eq!(gate.retained_samples(), 0);
    assert!(
        gate.observe(frame(&basis, 2, &[0]), ExecBudget::unlimited(), &cx)
            .is_err()
    );
    let mut overflow = frame(&basis, 2, &[]);
    overflow.image.height = usize::MAX;
    assert!(
        gate.observe(overflow, ExecBudget::unlimited(), &cx)
            .is_err()
    );
    assert!(gate.skip(&basis, 0, ActivitySkip::Unobserved).is_err());
    Ok(())
}

#[test]
fn replay_receipts_are_deterministic_and_configuration_bound() -> TestResult {
    let basis = basis()?;
    let cx = ScalarExecCx::new();
    let mut left = gate()?;
    let mut right = gate()?;
    for (sequence, bytes) in [(1, [0; 4]), (2, [100; 4]), (3, [100; 4])] {
        let a = left.observe(
            frame(&basis, sequence, &bytes),
            ExecBudget::unlimited(),
            &cx,
        )?;
        let b = right.observe(
            frame(&basis, sequence, &bytes),
            ExecBudget::unlimited(),
            &cx,
        )?;
        assert_eq!(a, b);
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.sequence(), sequence);
    }
    assert_ne!(
        ActivityConfig::new(2, 2, 20, 2_500)?.digest(),
        ActivityConfig::new(2, 2, 21, 2_500)?.digest()
    );
    Ok(())
}

#[test]
fn invalid_configurations_are_rejected_without_allocating_a_grid() {
    for params in [
        (0, 1, 1, 1),
        (1, 0, 1, 1),
        (1, 1, 0, 1),
        (1, 1, 1, 0),
        (1, 1, 1, 10_001),
        (257, 256, 1, 1),
        (usize::MAX, 2, 1, 1),
    ] {
        assert!(ActivityConfig::new(params.0, params.1, params.2, params.3).is_err());
    }
}
