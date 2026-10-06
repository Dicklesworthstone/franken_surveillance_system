#![forbid(unsafe_code)]
//! Long-screen compatibility, cumulative-budget and continuity regressions.

use super::*;
use fss_core::TimestampNs;

type Test = Result<(), Box<dyn std::error::Error>>;

fn frame(segment: u64, pixels: &[u8]) -> HealthFrame<'_> {
    HealthFrame {
        source_generation: ContentDigest::sha256(b"long-health-source"),
        segment,
        capsule_digest: ContentDigest::sha256(&segment.to_be_bytes()),
        capture: CaptureInterval::point(TimestampNs(i128::from(segment))),
        dimensions: [4, 4],
        gap_before: false,
        pixels,
    }
}

#[test]
fn larger_admission_preserves_every_compatibility_observation() -> Test {
    let mut original = HealthScreen::new(8192);
    let mut long = HealthScreen::with_frame_limit(8192, 300)?;
    for segment in 0..128 {
        let pixels = [40 + (segment % 32) as u8; 16];
        let expected = original.observe_with(frame(segment, &pixels), || Ok(()))?;
        let actual = long.observe_with(frame(segment, &pixels), || Ok(()))?;
        assert_eq!(actual, expected);
        assert_eq!(actual.digest(), expected.digest());
        assert_eq!(
            actual.digest(),
            ContentDigest::sha256(&actual.canonical_bytes())
        );
    }
    let pixels = [90; 16];
    assert_eq!(
        original.observe_with(frame(128, &pixels), || Ok(())),
        Err(HealthError::Limit)
    );
    for segment in 128..300 {
        long.observe_with(frame(segment, &pixels), || Ok(()))?;
    }
    assert_eq!(long.samples_used(), 300 * 16);
    assert_eq!(ContentDigest::sha256(policy_bytes()), policy_digest());
    Ok(())
}

#[test]
fn frame_ceiling_is_explicit_and_exact_retry_is_not_an_extra_frame() -> Test {
    assert!(matches!(
        HealthScreen::with_frame_limit(64, 0),
        Err(HealthError::Limit)
    ));
    assert!(matches!(
        HealthScreen::with_frame_limit(64, MAX_LONG_HEALTH_FRAMES + 1),
        Err(HealthError::Limit)
    ));
    let mut screen = HealthScreen::with_frame_limit(64, 1)?;
    let pixels = [90; 16];
    let first = screen.observe_with(frame(0, &pixels), || Ok(()))?;
    assert_eq!(
        screen.observe_with(frame(1, &pixels), || Ok(())),
        Err(HealthError::Limit)
    );
    assert_eq!(screen.samples_used(), 16);
    assert_eq!(screen.observe_with(frame(0, &pixels), || Ok(()))?, first);
    assert_eq!(screen.samples_used(), 32);
    let changed = [91; 16];
    assert_eq!(
        screen.observe_with(frame(0, &changed), || Ok(())),
        Err(HealthError::ReplayedSource)
    );
    assert_eq!(screen.samples_used(), 48);
    Ok(())
}

#[test]
fn repetition_beyond_the_old_window_is_not_lost_at_frame_128() -> Test {
    let mut screen = HealthScreen::with_frame_limit(16 * 140, 140)?;
    for segment in 0..138 {
        let value = if segment < 130 {
            40 + (segment % 128) as u8
        } else {
            200
        };
        let pixels = [value; 16];
        let observation = screen.observe_with(frame(segment, &pixels), || Ok(()))?;
        assert_eq!(
            observation
                .findings
                .contains(&HealthFinding::ExactFrameRepetition),
            segment == 137,
        );
    }
    Ok(())
}

#[test]
fn a_gap_resets_streaks_but_never_the_budget_or_replay_set() -> Test {
    let pixels = [100; 16];
    let mut screen = HealthScreen::with_frame_limit(16 * 16, 32)?;
    for segment in 0..16 {
        let mut input = frame(segment, &pixels);
        input.gap_before = segment == 8;
        let observation = screen.observe_with(input, || Ok(()))?;
        assert_eq!(observation.repeated_frames, (segment % 8 + 1) as u32);
        assert_eq!(observation.baseline_reset, segment == 0 || segment == 8);
    }
    assert_eq!(screen.samples_used(), 256);
    assert_eq!(
        screen.observe_with(frame(16, &pixels), || Ok(())),
        Err(HealthError::Limit)
    );

    let mut replay = HealthScreen::with_frame_limit(1024, 32)?;
    replay.observe_with(frame(0, &pixels), || Ok(()))?;
    let mut after_gap = frame(1, &pixels);
    after_gap.gap_before = true;
    replay.observe_with(after_gap, || Ok(()))?;
    assert_eq!(
        replay.observe_with(frame(0, &pixels), || Ok(())),
        Err(HealthError::ReplayedSource)
    );
    Ok(())
}

#[test]
fn a_cancelled_row_keeps_its_cost_but_cannot_advance_history() -> Test {
    let pixels = [100; 16];
    let mut screen = HealthScreen::with_frame_limit(64, 300)?;
    let mut calls = 0;
    let result = screen.observe_with(frame(0, &pixels), || {
        calls += 1;
        if calls == 3 {
            Err(HealthError::Cancelled)
        } else {
            Ok(())
        }
    });
    assert_eq!(result, Err(HealthError::Cancelled));
    assert_eq!(screen.samples_used(), 4);
    let first = screen.observe_with(frame(0, &pixels), || Ok(()))?;
    assert!(first.baseline_reset);
    assert_eq!(first.repeated_frames, 1);
    assert_eq!(screen.samples_used(), 20);
    Ok(())
}

#[test]
fn the_hard_frame_ceiling_does_not_overflow_streak_counters() -> Test {
    let pixels = [100; 16];
    let mut screen = HealthScreen::with_frame_limit(
        (MAX_LONG_HEALTH_FRAMES as u64 + 1) * 16,
        MAX_LONG_HEALTH_FRAMES,
    )?;
    let mut last = None;
    for segment in 0..MAX_LONG_HEALTH_FRAMES as u64 {
        last = Some(screen.observe_with(frame(segment, &pixels), || Ok(()))?);
    }
    let last = last.ok_or("missing final observation")?;
    assert_eq!(last.repeated_frames, MAX_LONG_HEALTH_FRAMES as u32);
    assert_eq!(
        screen.observe_with(frame(MAX_LONG_HEALTH_FRAMES as u64, &pixels), || Ok(())),
        Err(HealthError::Limit)
    );
    assert_eq!(screen.samples_used(), MAX_LONG_HEALTH_FRAMES as u64 * 16);
    Ok(())
}
