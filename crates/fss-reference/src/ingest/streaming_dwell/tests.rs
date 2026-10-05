#![forbid(unsafe_code)]

use super::*;
use crate::ingest::zone_dwell::dwell_spans;
use fss_core::TimestampNs;

type Test = Result<(), Box<dyn std::error::Error>>;

fn policy() -> DwellPolicy {
    DwellPolicy { minimum_duration_ns: 20, maximum_sample_gap_ns: 12, minimum_observations: 3 }
}
fn sample(position: usize, matched: bool) -> DwellSample {
    DwellSample {
        position,
        capture: Some(CaptureInterval::point(TimestampNs(position as i128 * 10))),
        matched_inside: matched,
        discontinuity: false,
    }
}
fn collect(samples: &[DwellSample], policy: DwellPolicy, chunk: usize)
    -> Result<Vec<StreamDwellSpan>, DwellError>
{
    let mut state = DwellAccumulator::new(policy, samples.len().max(1))?;
    let mut out = Vec::new();
    for batch in samples.chunks(chunk) {
        for sample in batch {
            if let Some(span) = state.push(*sample)? { out.push(span); }
        }
    }
    if let Some(span) = state.finish()? { out.push(span); }
    Ok(out)
}

#[test]
fn every_small_sequence_matches_the_existing_batch_reference() -> Test {
    // Ternary alphabet: actual match, miss, and unknown time. Each case is independently
    // partitioned by the batch owner and the streaming owner; no expected span is hand-built.
    for code in 0..3_u32.pow(8) {
        let mut digits = code;
        let mut samples = Vec::new();
        for position in 0..8 {
            let kind = digits % 3;
            digits /= 3;
            let mut s = sample(position, kind != 1);
            if kind == 2 { s.capture = None; }
            samples.push(s);
        }
        let batch = dwell_spans(&samples, policy())?;
        let online = collect(&samples, policy(), 3)?;
        assert_eq!(batch.len(), online.len(), "case {code}");
        for (a, b) in batch.iter().zip(&online) {
            assert_eq!(samples[a.first], b.first);
            assert_eq!(samples[a.triggered], b.trigger);
            assert_eq!(samples[a.last], b.last);
            assert_eq!(a.observations, b.observations);
            assert_eq!(a.trigger_minimum_ns, b.trigger_minimum_ns);
            assert_eq!(a.minimum_duration_ns, b.minimum_duration_ns);
        }
    }
    Ok(())
}

#[test]
fn long_episode_crosses_every_artificial_chunk_boundary_once() -> Test {
    let samples: Vec<_> = (0..4096).map(|p| sample(p, true)).collect();
    let rule = DwellPolicy { minimum_duration_ns: 30_000, ..policy() };
    let expected = collect(&samples, rule, 4096)?;
    assert_eq!(expected.len(), 1);
    assert_eq!(expected[0].first.position, 0);
    assert_eq!(expected[0].trigger.position, 3000);
    assert_eq!(expected[0].last.position, 4095);
    assert_eq!(expected[0].observations, 4096);
    for chunk in [1, 7, 127, 128, 129, 256, 1023] {
        assert_eq!(collect(&samples, rule, chunk)?, expected);
    }
    Ok(())
}

#[test]
fn rejected_clock_or_position_does_not_consume_or_close_state() -> Test {
    let mut state = DwellAccumulator::new(policy(), 10)?;
    for p in 0..3 { assert!(state.push(sample(p, true))?.is_none()); }
    let before = state;
    assert_eq!(state.push(sample(2, true)), Err(DwellError::InvalidSamples));
    assert_eq!(state, before);
    let mut reversed = sample(3, true);
    reversed.capture = Some(CaptureInterval::point(TimestampNs(0)));
    assert_eq!(state.push(reversed), Err(DwellError::ClockReversed));
    assert_eq!(state, before);
    assert!(state.push(sample(3, true))?.is_none());
    assert_eq!(state.finish()?.ok_or("missing span")?.observations, 4);
    Ok(())
}

#[test]
fn source_discontinuity_and_missing_positions_split_episodes() -> Test {
    let mut samples: Vec<_> = (0..9).map(|p| sample(p, true)).collect();
    samples[3].discontinuity = true;
    for s in &mut samples[6..] { s.position += 1; }
    let spans = collect(&samples, policy(), 4)?;
    assert_eq!(spans.iter().map(|s| s.first.position).collect::<Vec<_>>(), vec![0, 3, 7]);
    assert!(spans.iter().all(|s| s.observations == 3));
    Ok(())
}

#[test]
fn uncertainty_uses_conservative_endpoints_not_midpoints() -> Test {
    let samples: Vec<_> = (0..4).map(|p| DwellSample {
        capture: Some(CaptureInterval { earliest: TimestampNs(p * 10 - 4), latest: TimestampNs(p * 10 + 4) }),
        ..sample(p as usize, true)
    }).collect();
    let rule = DwellPolicy { maximum_sample_gap_ns: 18, ..policy() };
    let spans = collect(&samples, rule, 2)?;
    assert_eq!(spans[0].trigger.position, 3);
    assert_eq!(spans[0].minimum_duration_ns, 22);
    assert!(collect(&samples, DwellPolicy { maximum_sample_gap_ns: 17, ..rule }, 2)?.is_empty());
    Ok(())
}

#[test]
fn declared_budget_applies_across_batches_and_refusal_is_atomic() -> Test {
    let mut state = DwellAccumulator::new(policy(), 3)?;
    for p in 0..3 { let _ = state.push(sample(p, true))?; }
    let before = state;
    assert_eq!(state.push(sample(3, false)), Err(DwellError::Limit));
    assert_eq!(state, before);
    assert_eq!(state.consumed(), 3);
    assert_eq!(state.finish()?.ok_or("missing span")?.last.position, 2);
    Ok(())
}

#[test]
fn output_capacity_does_not_silently_drop_a_qualifying_episode() -> Test {
    let mut state = DwellAccumulator::new(policy(), 200)?;
    for p in 0..128 { let _ = state.push(sample(p, p % 4 != 3))?; }
    for p in 128..131 { let _ = state.push(sample(p, true))?; }
    let before = state;
    assert_eq!(state.push(sample(131, false)), Err(DwellError::Limit));
    assert_eq!(state, before);
    assert_eq!(state.finish(), Err(DwellError::Limit));
    Ok(())
}

#[test]
fn signed_extremes_and_inverted_intervals_never_wrap() -> Test {
    let mut state = DwellAccumulator::new(policy(), 4)?;
    let mut first = sample(0, true);
    first.capture = Some(CaptureInterval::point(TimestampNs(i128::MIN)));
    let _ = state.push(first)?;
    let mut last = sample(1, true);
    last.capture = Some(CaptureInterval::point(TimestampNs(i128::MAX)));
    assert!(state.push(last)?.is_none()); // A huge gap starts a new, unqualified episode.
    let before = state;
    let mut inverted = sample(2, true);
    inverted.capture = Some(CaptureInterval { earliest: TimestampNs(1), latest: TimestampNs(0) });
    assert_eq!(state.push(inverted), Err(DwellError::InvalidSamples));
    assert_eq!(state, before);
    assert!(state.finish()?.is_none());
    Ok(())
