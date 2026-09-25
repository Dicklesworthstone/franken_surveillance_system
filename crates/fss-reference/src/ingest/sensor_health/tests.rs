#![forbid(unsafe_code)]
//! Synthetic screening regressions; not camera-health or detection-quality qualification.

use super::*;
use fss_core::TimestampNs;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn frame<'a>(
    segment: u64,
    pixels: &'a [u8],
    dimensions: [u32; 2],
) -> Result<HealthFrame<'a>, Box<dyn std::error::Error>> {
    Ok(HealthFrame {
        source_generation: ContentDigest::sha256(b"source-a"),
        segment,
        capsule_digest: ContentDigest::sha256(&segment.to_le_bytes()),
        capture: CaptureInterval::new(
            TimestampNs(i128::from(segment)),
            TimestampNs(i128::from(segment)),
        )?,
        dimensions,
        gap_before: false,
        pixels,
    })
}

fn push(
    screen: &mut HealthScreen,
    frame: HealthFrame<'_>,
) -> Result<HealthObservation, HealthError> {
    screen.observe_with(frame, || Ok(()))
}

#[test]
fn clipping_requires_exact_fraction_and_three_distinct_frames() -> TestResult {
    for (value, finding) in [
        (20, HealthFinding::PersistentDarkField),
        (235, HealthFinding::PersistentBrightField),
    ] {
        // Exactly 995 of 1000 pixels meet the threshold; one fewer must not pass it.
        let mut pixels = vec![value; 1000];
        pixels[995..].fill(128);
        let mut gate = HealthScreen::new(8000);
        for segment in 0..3 {
            let observed = push(&mut gate, frame(segment, &pixels, [100, 10])?)?;
            assert_eq!(observed.findings.contains(&finding), segment == 2);
        }
        pixels[994] = 128;
        let mut below = HealthScreen::new(8000);
        for segment in 0..3 {
            let observed = push(&mut below, frame(segment, &pixels, [100, 10])?)?;
            assert!(!observed.findings.contains(&finding));
        }
    }
    Ok(())
}

#[test]
fn exact_retries_do_not_accumulate_repetition_or_clipping() -> TestResult {
    let pixels = [0_u8; 16];
    let mut gate = HealthScreen::new(400);
    let input = frame(0, &pixels, [4, 4])?;
    let original = push(&mut gate, input)?;
    for _ in 0..10 {
        assert_eq!(push(&mut gate, input)?, original);
    }
    assert_eq!(original.repeated_frames, 1);
    assert!(original.findings.is_empty());
    assert_eq!(gate.samples_used(), 176);
    Ok(())
}

#[test]
fn eight_distinct_identical_frames_are_suspect_not_proven_tamper() -> TestResult {
    let pixels = [80_u8; 16];
    let mut gate = HealthScreen::new(200);
    for segment in 0..8 {
        let observed = push(&mut gate, frame(segment, &pixels, [4, 4])?)?;
        assert_eq!(observed.repeated_frames, segment as u32 + 1);
        assert_eq!(
            observed.findings,
            if segment == 7 {
                vec![HealthFinding::ExactFrameRepetition]
            } else {
                Vec::new()
            }
        );
    }
    Ok(())
}

#[test]
fn gaps_source_changes_and_geometry_changes_reset_temporal_evidence() -> TestResult {
    for reset in 0..3 {
        let pixels = [80_u8; 16];
        let mut gate = HealthScreen::new(256);
        for segment in 0..7 {
            let _ = push(&mut gate, frame(segment, &pixels, [4, 4])?)?;
        }
        let mut input = frame(7, &pixels, [4, 4])?;
        match reset {
            0 => input.gap_before = true,
            1 => input.source_generation = ContentDigest::sha256(b"source-b"),
            _ => input.dimensions = [8, 2],
        }
        let observed = push(&mut gate, input)?;
        assert!(observed.baseline_reset);
        assert_eq!(observed.repeated_frames, 1);
        assert!(observed.findings.is_empty());
    }
    Ok(())
}

#[test]
fn contrast_loss_requires_a_textured_predecessor_and_persists() -> TestResult {
    let mut textured = [20_u8; 100];
    textured[50..].fill(180);
    let blank = [100_u8; 100];
    let mut gate = HealthScreen::new(800);
    assert_eq!(
        push(&mut gate, frame(0, &textured, [10, 10])?)?.contrast_span,
        160
    );
    for segment in 1..=3 {
        let observed = push(&mut gate, frame(segment, &blank, [10, 10])?)?;
        assert_eq!(
            observed.findings.contains(&HealthFinding::ContrastCollapse),
            segment == 3
        );
    }
    let mut initially_blank = HealthScreen::new(400);
    for segment in 0..3 {
        assert!(
            push(&mut initially_blank, frame(segment, &blank, [10, 10])?)?
                .findings
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn cancellation_charges_completed_rows_without_advancing_the_baseline() -> TestResult {
    let pixels = [80_u8; 16];
    let mut gate = HealthScreen::new(100);
    let original = push(&mut gate, frame(0, &pixels, [4, 4])?)?;
    let mut checkpoints = 0;
    let failed = gate.observe_with(frame(1, &pixels, [4, 4])?, || {
        checkpoints += 1;
        if checkpoints == 4 {
            Err(HealthError::Cancelled)
        } else {
            Ok(())
        }
    });
    assert_eq!(failed, Err(HealthError::Cancelled));
    assert_eq!(gate.samples_used(), 24);
    assert_eq!(push(&mut gate, frame(0, &pixels, [4, 4])?)?, original);
    let next = push(&mut gate, frame(1, &pixels, [4, 4])?)?;
    assert_eq!(next.repeated_frames, 2);
    Ok(())
}

#[test]
fn substituted_or_old_positions_fail_but_display_order_is_not_decode_order() -> TestResult {
    let pixels = [80_u8; 16];
    let changed = [81_u8; 16];
    let mut gate = HealthScreen::new(200);
    let _ = push(&mut gate, frame(0, &pixels, [4, 4])?)?;
    assert_eq!(
        push(&mut gate, frame(0, &changed, [4, 4])?),
        Err(HealthError::ReplayedSource)
    );
    // B pictures may be output in an order unlike their source segment indices.
    let _ = push(&mut gate, frame(2, &pixels, [4, 4])?)?;
    let _ = push(&mut gate, frame(1, &pixels, [4, 4])?)?;
    assert_eq!(
        push(&mut gate, frame(0, &pixels, [4, 4])?),
        Err(HealthError::ReplayedSource)
    );
    Ok(())
}

#[test]
fn budgets_and_image_bounds_are_checked_before_allocation_or_history_updates() -> TestResult {
    let pixels = [80_u8; 16];
    let mut gate = HealthScreen::new(16);
    let _ = push(&mut gate, frame(0, &pixels, [4, 4])?)?;
    assert_eq!(
        push(&mut gate, frame(1, &pixels, [4, 4])?),
        Err(HealthError::Limit)
    );
    assert_eq!(gate.samples_used(), 16);
    let mut gate = HealthScreen::new(100);
    assert_eq!(
        push(&mut gate, frame(0, &pixels, [0, 4])?),
        Err(HealthError::InvalidImage)
    );
    assert_eq!(
        push(&mut gate, frame(0, &pixels, [4097, 1])?),
        Err(HealthError::InvalidImage)
    );
    assert_eq!(
        push(&mut gate, frame(0, &pixels, [4, 5])?),
        Err(HealthError::InvalidImage)
    );
    assert_eq!(gate.samples_used(), 0);
    Ok(())
}

#[test]
fn frame_capacity_is_exact_and_digests_bind_source_and_findings() -> TestResult {
    let pixel = [80_u8];
    let mut gate = HealthScreen::new(1000);
    for segment in 0..MAX_HEALTH_FRAMES as u64 {
        let _ = push(&mut gate, frame(segment, &pixel, [1, 1])?)?;
    }
    assert_eq!(
        push(&mut gate, frame(128, &pixel, [1, 1])?),
        Err(HealthError::Limit)
    );
    let mut a = HealthScreen::new(16);
    let original = push(&mut a, frame(0, &pixel, [1, 1])?)?;
    let mut altered = original.clone();
    altered.findings.push(HealthFinding::ExactFrameRepetition);
    assert_ne!(original.digest(), altered.digest());
    altered = original.clone();
    altered.capsule_digest = ContentDigest::sha256(b"other-capsule");
    assert_ne!(original.digest(), altered.digest());
    Ok(())
}
