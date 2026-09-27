#![forbid(unsafe_code)]
//! Temporal coverage versus an independent point-by-point observer oracle.

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{CaptureInterval, TimestampNs};
use fss_graph_algorithms::coverage_timeline::{
    CoverageTimelineError, MAX_TIMELINE_FACTS, MAX_TIMELINE_OPERATIONS,
    MAX_TIMELINE_OUTPUT_ENTRIES, MAX_TIMELINE_SEGMENTS, MAX_TIMELINE_WITNESSES,
    TimedCoverageObservation, analyse_coverage_timeline,
};
use fss_graph_algorithms::{GraphBudget, GraphError, ZoneState};

fn window(first: i128, last: i128) -> CaptureInterval {
    CaptureInterval { earliest: TimestampNs(first), latest: TimestampNs(last) }
}

fn fact(sensor: &str, intervals: &[(i128, i128)]) -> TimedCoverageObservation {
    TimedCoverageObservation {
        sensor_id: sensor.to_owned(),
        zone_scope: "ground-zone:door".to_owned(),
        covered: intervals.iter().map(|&(first, last)| window(first, last)).collect(),
    }
}

fn budget() -> GraphBudget {
    GraphBudget {
        max_operations: MAX_TIMELINE_OPERATIONS,
        max_output_entries: MAX_TIMELINE_OUTPUT_ENTRIES,
    }
}

#[test]
fn disjoint_history_exposes_both_handover_and_gaps() -> Result<(), Box<dyn Error>> {
    let input = [fact("a", &[(0, 4)]), fact("b", &[(6, 10)]), fact("c", &[])];
    let result = analyse_coverage_timeline("site:test", &input, window(0, 20), budget())?;
    let expected = [(0, 4, vec!["a"]), (5, 5, vec![]), (6, 10, vec!["b"]), (11, 20, vec![])];
    assert_eq!(result.segments.len(), expected.len());
    for (segment, (first, last, observers)) in result.segments.iter().zip(expected) {
        assert_eq!(segment.window, window(first, last));
        assert_eq!(segment.answer.zones.len(), 1);
        assert_eq!(segment.answer.zones[0].observers, observers);
        assert_eq!(segment.answer.zones[0].single_points_of_failure, observers);
        assert_eq!(segment.answer.sensors.len(), 3);
        assert_eq!(segment.answer.zones[0].state,
            if observers.is_empty() { ZoneState::NotObservable } else { ZoneState::SingleObserver });
    }
    Ok(())
}

#[test]
fn adjacent_witnesses_have_no_invented_gap_or_simultaneous_observer() -> Result<(), Box<dyn Error>> {
    let result = analyse_coverage_timeline("s", &[fact("a", &[(0, 4)]), fact("b", &[(5, 10)])], window(0, 10), budget())?;
    assert_eq!(result.segments.len(), 2);
    assert_eq!(result.segments[0].window, window(0, 4));
    assert_eq!(result.segments[1].window, window(5, 10));
    for segment in result.segments {
        assert_eq!(segment.answer.zones[0].state, ZoneState::SingleObserver);
    }
    Ok(())
}

#[test]
fn inclusive_endpoint_overlap_is_a_distinct_one_instant_segment() -> Result<(), Box<dyn Error>> {
    let result = analyse_coverage_timeline("s", &[fact("a", &[(0, 5)]), fact("b", &[(5, 10)])], window(0, 10), budget())?;
    assert_eq!(result.segments.len(), 3);
    assert_eq!(result.segments[1].window, window(5, 5));
    assert_eq!(result.segments[1].answer.zones[0].observers, ["a", "b"]);
    assert_eq!(result.segments[1].answer.zones[0].state, ZoneState::MultipleObservers);
    assert!(result.segments[1].answer.zones[0].single_points_of_failure.is_empty());
    Ok(())
}

#[test]
fn no_evidence_and_outside_evidence_keep_the_entire_query_explicit() -> Result<(), Box<dyn Error>> {
    let empty = analyse_coverage_timeline("s", &[], window(-9, 9), budget())?;
    assert_eq!(empty.segments.len(), 1);
    assert_eq!(empty.segments[0].window, window(-9, 9));
    assert!(empty.segments[0].answer.zones.is_empty());
    let outside = analyse_coverage_timeline("s", &[fact("a", &[(-20, -10), (10, 20)])], window(-9, 9), budget())?;
    assert_eq!(outside.segments.len(), 1);
    assert_eq!(outside.segments[0].answer.zones[0].state, ZoneState::NotObservable);
    Ok(())
}

#[test]
fn full_i128_range_and_extreme_point_queries_never_overflow() -> Result<(), Box<dyn Error>> {
    let input = [fact("a", &[(i128::MIN, i128::MIN)]), fact("b", &[(i128::MAX, i128::MAX)])];
    let result = analyse_coverage_timeline("s", &input, window(i128::MIN, i128::MAX), budget())?;
    assert_eq!(result.segments.len(), 3);
    assert_eq!(result.segments[0].window, window(i128::MIN, i128::MIN));
    assert_eq!(result.segments[1].window, window(i128::MIN + 1, i128::MAX - 1));
    assert_eq!(result.segments[1].answer.zones[0].state, ZoneState::NotObservable);
    assert_eq!(result.segments[2].window, window(i128::MAX, i128::MAX));
    for time in [i128::MIN, i128::MAX] {
        let point = analyse_coverage_timeline("s", &input, window(time, time), budget())?;
        assert_eq!(point.segments.len(), 1);
        assert_eq!(point.segments[0].answer.zones[0].state, ZoneState::SingleObserver);
    }
    Ok(())
}

#[test]
fn duplicate_rows_and_input_order_do_not_invent_observers() -> Result<(), Box<dyn Error>> {
    let input = vec![fact("a", &[(4, 9), (0, 5)]), fact("a", &[(0, 5)]), fact("b", &[])];
    let mut reordered = input.clone();
    reordered.reverse();
    for row in &mut reordered { row.covered.reverse(); }
    let original = analyse_coverage_timeline("s", &input, window(0, 9), budget())?;
    assert_eq!(original, analyse_coverage_timeline("s", &reordered, window(0, 9), budget())?);
    for segment in original.segments {
        assert_eq!(segment.answer.zones[0].observers, ["a"]);
        assert_eq!(segment.answer.zones[0].state, ZoneState::SingleObserver);
    }
    Ok(())
}

#[test]
fn inverted_source_intervals_are_refused_even_outside_the_query() {
    for (input, query) in [(vec![], window(2, 1)), (vec![fact("a", &[(30, 20)])], window(0, 10))] {
        assert!(matches!(analyse_coverage_timeline("s", &input, query, budget()), Err(CoverageTimelineError::Contract(_))));
    }
}

#[test]
fn malformed_identity_and_hard_input_limits_fail_closed() {
    for sensor in ["".to_owned(), "a\nb".to_owned(), "x".repeat(513)] {
        assert!(matches!(analyse_coverage_timeline("s", &[fact(&sensor, &[])], window(0, 1), budget()),
            Err(CoverageTimelineError::Graph(GraphError::InvalidNodeId(_)))));
    }
    assert!(analyse_coverage_timeline("", &[], window(0, 1), budget()).is_err());
    let input = vec![fact("a", &[]); MAX_TIMELINE_FACTS + 1];
    assert!(matches!(analyse_coverage_timeline("s", &input, window(0, 1), budget()), Err(CoverageTimelineError::Graph(GraphError::TooLarge))));
    let input = [fact("a", &vec![(0, 1); MAX_TIMELINE_WITNESSES + 1])];
    assert!(matches!(analyse_coverage_timeline("s", &input, window(0, 1), budget()), Err(CoverageTimelineError::Graph(GraphError::TooLarge))));
}

#[test]
fn segment_limit_never_returns_a_truncated_prefix() {
    let intervals: Vec<_> = (0..MAX_TIMELINE_SEGMENTS).map(|n| (2 * n as i128, 2 * n as i128)).collect();
    let result = analyse_coverage_timeline("s", &[fact("a", &intervals)], window(0, 1000), budget());
    assert!(matches!(result, Err(CoverageTimelineError::Graph(GraphError::BudgetExhausted { dimension: "timeline_segments", .. }))));
}

#[test]
fn aggregate_budgets_are_not_reset_for_each_graph() -> Result<(), Box<dyn Error>> {
    let input = [fact("a", &[(0, 4), (8, 9)]), fact("b", &[(3, 6)])];
    let full = analyse_coverage_timeline("s", &input, window(0, 10), budget())?;
    assert!(full.segments.len() > 1);
    let exact = GraphBudget { max_operations: full.operations, max_output_entries: full.output_entries };
    assert_eq!(full, analyse_coverage_timeline("s", &input, window(0, 10), exact)?);
    for limited in [GraphBudget { max_operations: full.operations - 1, ..exact }, GraphBudget { max_output_entries: full.output_entries - 1, ..exact }] {
        assert!(matches!(analyse_coverage_timeline("s", &input, window(0, 10), limited), Err(CoverageTimelineError::Graph(GraphError::BudgetExhausted { .. }))));
    }
    Ok(())
}

#[test]
fn seeded_timelines_match_independent_pointwise_observer_oracle() -> Result<(), Box<dyn Error>> {
    let mut seed = 0x4f535354494d45_u64;
    for _ in 0..256 {
        let mut input = Vec::new();
        for sensor in ["a", "b", "c", "d"] {
            let mut intervals = Vec::new();
            for _ in 0..3 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let a = (seed % 33) as i128 - 16;
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let b = (seed % 33) as i128 - 16;
                intervals.push((a.min(b), a.max(b)));
            }
            input.push(fact(sensor, &intervals));
        }
        let result = analyse_coverage_timeline("s", &input, window(-12, 12), budget())?;
        for time in -12..=12 {
            let covering: Vec<_> = result.segments.iter().filter(|segment| segment.window.earliest.0 <= time && time <= segment.window.latest.0).collect();
            assert_eq!(covering.len(), 1, "partition hole or overlap at {time}");
            let expected: BTreeSet<String> = input.iter().filter(|row| row.covered.iter().any(|covered| covered.earliest.0 <= time && time <= covered.latest.0)).map(|row| row.sensor_id.clone()).collect();
            let expected: Vec<_> = expected.into_iter().collect();
            let zone = &covering[0].answer.zones[0];
            assert_eq!(zone.observers, expected);
            assert_eq!(zone.single_points_of_failure, if expected.len() == 1 { expected.clone() } else { vec![] });
            assert_eq!(zone.state, match expected.len() { 0 => ZoneState::NotObservable, 1 => ZoneState::SingleObserver, _ => ZoneState::MultipleObservers });
        }
    }
    Ok(())
}
