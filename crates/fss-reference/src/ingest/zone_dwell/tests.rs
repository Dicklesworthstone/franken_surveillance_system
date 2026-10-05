#![forbid(unsafe_code)]
use super::*;
use fss_core::TimestampNs;

type Test = Result<(), Box<dyn std::error::Error>>;
fn sample(position: usize, earliest: i128, latest: i128) -> DwellSample {
    DwellSample {
        position,
        capture: Some(CaptureInterval { earliest: TimestampNs(earliest), latest: TimestampNs(latest) }),
        matched_inside: true,
        discontinuity: false,
    }
}
fn policy() -> DwellPolicy {
    DwellPolicy { minimum_duration_ns: 20, maximum_sample_gap_ns: 15, minimum_observations: 2 }
}
fn sequence(times: &[i128]) -> Vec<DwellSample> {
    times.iter().enumerate().map(|(i, &t)| sample(i, t, t)).collect()
}

#[test]
fn one_episode_keeps_first_crossing_and_final_extent() -> Test {
    let input = sequence(&[0, 10, 20, 30, 40]);
    let spans = dwell_spans(&input, policy())?;
    assert_eq!(spans, vec![DwellSpan {
        first: 0, triggered: 2, last: 4, observations: 5,
        trigger_minimum_ns: 20, minimum_duration_ns: 40,
    }]);
    assert_eq!(dwell_spans(&input, policy())?, spans);
    Ok(())
}

#[test]
fn duration_and_observation_count_are_both_required() -> Test {
    let input = sequence(&[0, 10, 20, 30]);
    let mut p = policy();
    p.minimum_observations = 4;
    assert!(dwell_spans(&input[..3], p)?.is_empty());
    assert_eq!(dwell_spans(&input, p)?[0].triggered, 3);
    assert!(dwell_spans(&input[..2], policy())?.is_empty());
    Ok(())
}

#[test]
fn uncertain_endpoints_never_use_midpoints_for_duration() -> Test {
    let mut p = policy();
    p.maximum_sample_gap_ns = 100;
    let input = [sample(0, 0, 8), sample(1, 20, 28), sample(2, 27, 35), sample(3, 28, 36)];
    assert!(dwell_spans(&input[..3], p)?.is_empty());
    let result = dwell_spans(&input, p)?;
    assert_eq!(result[0].triggered, 3);
    assert_eq!(result[0].trigger_minimum_ns, 20);
    Ok(())
}

#[test]
fn worst_case_sampling_gap_and_exact_boundary() -> Test {
    let p = DwellPolicy { minimum_duration_ns: 5, maximum_sample_gap_ns: 15, minimum_observations: 2 };
    let exact = [sample(0, 0, 5), sample(1, 10, 15)];
    assert_eq!(dwell_spans(&exact, p)?[0].minimum_duration_ns, 5);
    let too_wide = [sample(0, 0, 5), sample(1, 10, 16)];
    assert!(dwell_spans(&too_wide, p)?.is_empty());
    // Each short interval alone looks precise, but the unobserved gap cannot become dwell.
    assert!(dwell_spans(&sequence(&[0, 100, 110]), policy())?.is_empty());
    Ok(())
}

#[test]
fn missing_match_unknown_time_and_discontinuity_each_break_a_run() -> Test {
    for kind in 0..4 {
        let mut input = sequence(&[0, 10, 20, 30]);
        match kind {
            0 => input[2].matched_inside = false,
            1 => input[2].capture = None,
            2 => input[2].discontinuity = true,
            _ => { input[2].position += 1; input[3].position += 1; }
        }
        assert!(dwell_spans(&input, policy())?.is_empty(), "break kind {kind}");
    }
    Ok(())
}

#[test]
fn leaving_and_reentering_yields_separate_episodes() -> Test {
    let mut input = sequence(&[0, 10, 20, 30, 40, 50, 60, 70]);
    input[3].matched_inside = false;
    let spans = dwell_spans(&input, policy())?;
    assert_eq!(spans.len(), 2);
    assert_eq!((spans[0].first, spans[0].triggered, spans[0].last), (0, 2, 2));
    assert_eq!((spans[1].first, spans[1].triggered, spans[1].last), (4, 6, 7));
    Ok(())
}

#[test]
fn repeated_capture_times_cannot_accumulate_duration() -> Test {
    assert!(dwell_spans(&sequence(&[10; 20]), policy())?.is_empty());
    let overlapping = [sample(0, 0, 100), sample(1, 10, 110), sample(2, 20, 120)];
    let mut p = policy();
    p.maximum_sample_gap_ns = 200;
    assert!(dwell_spans(&overlapping, p)?.is_empty());
    Ok(())
}

#[test]
fn signed_extremes_and_unsigned_position_end_are_exact() -> Test {
    for origin in [i128::MIN, -20, i128::MAX - 20] {
        let input = [sample(usize::MAX - 2, origin, origin),
                     sample(usize::MAX - 1, origin + 10, origin + 10),
                     sample(usize::MAX, origin + 20, origin + 20)];
        assert_eq!(dwell_spans(&input, policy())?[0].minimum_duration_ns, 20);
    }
    // A full signed-range separation is representable as u128 but exceeds every admitted gap.
    let input = [sample(0, i128::MIN, i128::MIN), sample(1, i128::MAX, i128::MAX)];
    assert!(dwell_spans(&input, policy())?.is_empty());
    Ok(())
}

#[test]
fn regression_and_malformed_input_refuse_the_complete_result() -> Test {
    assert_eq!(dwell_spans(&sequence(&[0, 10, 20, 19]), policy()), Err(DwellError::ClockReversed));
    assert_eq!(dwell_spans(&[sample(0, 10, 9)], policy()), Err(DwellError::InvalidSamples));
    assert_eq!(dwell_spans(&[sample(1, 0, 0), sample(1, 10, 10)], policy()), Err(DwellError::InvalidSamples));
    let mut p = policy();
    p.minimum_observations = 1;
    assert_eq!(dwell_spans(&[], p), Err(DwellError::InvalidPolicy));
    p = policy();
    p.minimum_duration_ns = 0;
    assert_eq!(dwell_spans(&[], p), Err(DwellError::InvalidPolicy));
    p = policy();
    p.maximum_sample_gap_ns = MAX_DWELL_NS + 1;
    assert_eq!(dwell_spans(&[], p), Err(DwellError::InvalidPolicy));
    Ok(())
}

#[test]
fn complete_output_and_input_limits_never_truncate() -> Test {
    let p = DwellPolicy { minimum_duration_ns: 1, maximum_sample_gap_ns: 1, minimum_observations: 2 };
    let input: Vec<_> = (0..99).map(|i| {
        let mut s = sample(i, i as i128, i as i128);
        s.matched_inside = i % 3 != 2;
        s
    }).collect();
    assert_eq!(dwell_spans(&input[..96], p)?.len(), MAX_DWELL_EPISODES);
    assert_eq!(dwell_spans(&input, p), Err(DwellError::Limit));
    assert_eq!(dwell_spans(&vec![sample(0, 0, 0); MAX_DWELL_SAMPLES + 1], p), Err(DwellError::Limit));
    Ok(())
}

#[test]
fn empty_and_wholly_unobserved_sequences_prove_nothing() -> Test {
    assert!(dwell_spans(&[], policy())?.is_empty());
    let mut input = sequence(&[0, 10, 20, 30]);
    for s in &mut input { s.capture = None; }
    assert!(dwell_spans(&input, policy())?.is_empty());
    Ok(())
}
