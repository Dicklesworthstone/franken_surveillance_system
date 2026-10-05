#![forbid(unsafe_code)]
//! Joint failures at every certain-coverage boundary, under one aggregate request budget.

use fss_graph_algorithms::coverage::PROJECTION_KIND;
use fss_graph_algorithms::coverage_timeline::{MAX_TIMELINE_SEGMENTS, TIMELINE_POLICY};
use fss_reference::coverage_timeline::{CoverageTimelineReport, read_coverage_timeline};

use super::{
    GraphBudget, MAX_REPORT_BYTES, Request, admitted_count, array, budget, capture_window,
    combinations, evidence_anchor, object, string,
};

// Refuse malformed public report fields before accepting a complete-partition claim. No
// checked_add is performed after the final endpoint, so i128::MAX remains a valid endpoint.
fn validate(value: &CoverageTimelineReport, request: &Request) -> Result<(), String> {
    if value.site != request.site
        || value.window != request.window
        || value.segments.is_empty()
        || value.segments.len() > MAX_TIMELINE_SEGMENTS
    {
        return Err(
            "ERR-GRAPH-INPUT-INVALID-001: timeline does not match the requested site/window".into(),
        );
    }
    let mut expected = value.window.earliest;
    for (index, segment) in value.segments.iter().enumerate() {
        if segment.window.earliest != expected
            || segment.window.latest.0 < segment.window.earliest.0
            || segment.window.latest.0 > value.window.latest.0
            || segment.report.anchor != value.anchor
            || segment.report.site != value.site
        {
            return Err(
                "ERR-GRAPH-INPUT-INVALID-001: timeline is not one complete pinned partition".into(),
            );
        }
        let identity = format!(
            "{PROJECTION_KIND}@t1:{}:{}:{}:{}:{}",
            value.anchor.commit_sequence,
            value.window.earliest.0,
            value.window.latest.0,
            segment.window.earliest.0,
            segment.window.latest.0,
        );
        if segment.report.projection_id != identity {
            return Err(
                "ERR-GRAPH-INPUT-INVALID-001: timeline witness does not bind query and segment"
                    .into(),
            );
        }
        if index + 1 == value.segments.len() {
            if segment.window.latest != value.window.latest {
                return Err("ERR-GRAPH-INPUT-INVALID-001: timeline ends before the request".into());
            }
        } else {
            expected = super::TimestampNs(
                segment
                    .window
                    .latest
                    .0
                    .checked_add(1)
                    .ok_or("ERR-GRAPH-INPUT-INVALID-001: timeline endpoint overflow")?,
            );
        }
    }
    Ok(())
}

fn render(
    value: &CoverageTimelineReport,
    request: &Request,
    limit: GraphBudget,
    max_bytes: usize,
) -> Result<String, String> {
    validate(value, request)?;
    let limit = GraphBudget {
        max_operations: limit.max_operations.min(budget().max_operations),
        max_output_entries: limit.max_output_entries.min(budget().max_output_entries),
    };
    let max_bytes = max_bytes.min(MAX_REPORT_BYTES);
    let mut operations = value.operations;
    let mut output_entries = value.output_entries;
    if operations > limit.max_operations || output_entries > limit.max_output_entries {
        return Err(
            "ERR-GRAPH-BUDGET-EXHAUSTED-001: timeline source exceeds aggregate budget".into(),
        );
    }
    let per_segment = admitted_count(request.domains.len(), request.maximum)?;
    let mut rows = Vec::with_capacity(value.segments.len());
    let mut bytes = 0_usize;
    for (index, segment) in value.segments.iter().enumerate() {
        let result = combinations(
            &segment.report,
            &request.domains,
            request.maximum,
            GraphBudget {
                max_operations: limit.max_operations - operations,
                max_output_entries: limit.max_output_entries - output_entries,
            },
            max_bytes.saturating_sub(bytes),
        )?;
        operations += result.operations;
        output_entries += result.output_entries;
        let row = object(&[
            ("index", index.to_string()),
            ("capture_window", capture_window(segment.window)),
            ("result", result.json),
        ]);
        bytes = bytes
            .checked_add(row.len() + 1)
            .ok_or("timeline report size overflow")?;
        if bytes > max_bytes {
            return Err(
                "ERR-GRAPH-BUDGET-EXHAUSTED-001: failure-cut timeline exceeds byte limit".into(),
            );
        }
        rows.push(row);
    }
    let json = object(&[
        ("format", string("fss.coverage_failure_cut_timeline.v1")),
        ("site", string(&value.site)),
        ("anchor", evidence_anchor(&value.anchor)),
        ("capture_window", capture_window(value.window)),
        ("selection", string(TIMELINE_POLICY)),
        ("clock_alignment", string("operator_hints_not_calibration")),
        ("max_failed_domains", request.maximum.to_string()),
        ("segment_count", rows.len().to_string()),
        ("scenarios_per_segment", per_segment.to_string()),
        ("total_scenarios", (per_segment * rows.len()).to_string()),
        ("segments", array(&rows)),
        ("operations", operations.to_string()),
        ("output_entries", output_entries.to_string()),
        ("interval_checks", value.interval_checks.to_string()),
        ("completion", string("complete_within_declared_bound")),
        ("authority", string("derived_cognition_no_effect_authority")),
        ("qualification", string("implemented_not_qualified")),
        (
            "claim",
            string(
                "joint loss of retained qualifying witnesses at each certain boundary; unwitnessed intervals may contain observed activity or excluded analysis and prove neither sensor failure nor absence; no current availability, calibrated clock alignment or independence claim",
            ),
        ),
    ]);
    if json.len() > max_bytes {
        return Err("ERR-GRAPH-BUDGET-EXHAUSTED-001: complete timeline exceeds byte limit".into());
    }
    Ok(json)
}

pub(super) fn run(request: &Request) -> Result<String, String> {
    let value = read_coverage_timeline(&request.root, &request.site, request.window, budget())
        .map_err(|error| {
            format!(
                "{}: {error}",
                error.stable_id().unwrap_or(super::ERR_CLI_RUNTIME_FAILURE)
            )
        })?;
    render(&value, request, budget(), MAX_REPORT_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::{CaptureInterval, LedgerAnchor, TimestampNs};
    use fss_graph_algorithms::coverage_timeline::{
        TimedCoverageObservation, analyse_coverage_timeline,
    };
    use fss_reference::coverage_graph::CoverageGraphReport;
    use fss_reference::coverage_timeline::CoverageTimelineReportSegment;

    fn interval(first: i128, last: i128) -> CaptureInterval {
        CaptureInterval {
            earliest: TimestampNs(first),
            latest: TimestampNs(last),
        }
    }

    fn sample(
        window: CaptureInterval,
    ) -> Result<(CoverageTimelineReport, Request), Box<dyn std::error::Error>> {
        let facts = [
            TimedCoverageObservation {
                sensor_id: "a".into(),
                zone_scope: "door".into(),
                covered: vec![interval(-2, 0)],
            },
            TimedCoverageObservation {
                sensor_id: "b".into(),
                zone_scope: "door".into(),
                covered: vec![interval(0, 2)],
            },
        ];
        let base = analyse_coverage_timeline("site:test", &facts, window, budget())?;
        let anchor = LedgerAnchor::genesis("site:test");
        let mut segments = Vec::new();
        for segment in base.segments {
            let projection_id = format!(
                "{PROJECTION_KIND}@t1:0:{}:{}:{}:{}",
                window.earliest.0,
                window.latest.0,
                segment.window.earliest.0,
                segment.window.latest.0
            );
            let witness = segment
                .answer
                .analysis
                .witness(&projection_id, anchor.clone())?;
            segments.push(CoverageTimelineReportSegment {
                window: segment.window,
                report: CoverageGraphReport {
                    site: "site:test".into(),
                    anchor: anchor.clone(),
                    projection_id,
                    records: 2,
                    projection: segment.projection,
                    answer: segment.answer,
                    witness,
                },
            });
        }
        let value = CoverageTimelineReport {
            site: "site:test".into(),
            anchor,
            window,
            segments,
            operations: base.operations,
            output_entries: base.output_entries,
            interval_checks: base.interval_checks,
        };
        let request = Request {
            root: "not-opened".into(),
            site: "site:test".into(),
            window,
            maximum: 2,
            domains: vec![
                super::super::domain("power:left=a")?,
                super::super::domain("network:right=b")?,
            ],
            timeline: true,
        };
        Ok((value, request))
    }

    #[test]
    fn handover_overlap_and_unwitnessed_tail_keep_distinct_cuts()
    -> Result<(), Box<dyn std::error::Error>> {
        let (value, request) = sample(interval(-2, 3))?;
        let json = render(&value, &request, budget(), MAX_REPORT_BYTES)?;
        assert!(json.contains("\"segment_count\":4"));
        assert!(json.contains("\"total_scenarios\":12"));
        assert_eq!(json.matches("\"minimum_failed_domains\":1").count(), 2);
        assert_eq!(json.matches("\"minimum_failed_domains\":2").count(), 1);
        assert_eq!(
            json.matches("\"state\":\"initially_unwitnessed\"").count(),
            1
        );
        for segment in &value.segments {
            assert!(json.contains(&segment.report.witness.digest().to_text()));
        }
        assert_eq!(json, render(&value, &request, budget(), MAX_REPORT_BYTES)?);
        Ok(())
    }

    #[test]
    fn the_last_segment_cannot_reset_the_operation_output_or_byte_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let (value, request) = sample(interval(-2, 3))?;
        let mut exact = GraphBudget {
            max_operations: value.operations,
            max_output_entries: value.output_entries,
        };
        for segment in &value.segments {
            let result = combinations(
                &segment.report,
                &request.domains,
                2,
                budget(),
                MAX_REPORT_BYTES,
            )?;
            exact.max_operations += result.operations;
            exact.max_output_entries += result.output_entries;
        }
        let json = render(&value, &request, exact, MAX_REPORT_BYTES)?;
        for reduced in [
            GraphBudget {
                max_operations: exact.max_operations - 1,
                ..exact
            },
            GraphBudget {
                max_output_entries: exact.max_output_entries - 1,
                ..exact
            },
        ] {
            assert!(render(&value, &request, reduced, MAX_REPORT_BYTES).is_err());
        }
        assert_eq!(json, render(&value, &request, exact, json.len())?);
        assert!(render(&value, &request, exact, json.len() - 1).is_err());
        Ok(())
    }

    #[test]
    fn mixed_anchors_holes_and_relabelled_intervals_are_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        let (value, request) = sample(interval(-2, 3))?;
        let mut mixed = value.clone();
        mixed.segments[1].report.anchor.commit_sequence += 1;
        assert!(render(&mixed, &request, budget(), MAX_REPORT_BYTES).is_err());
        let mut hole = value.clone();
        hole.segments.remove(1);
        assert!(render(&hole, &request, budget(), MAX_REPORT_BYTES).is_err());
        let mut truncated = value.clone();
        truncated.segments.pop();
        assert!(render(&truncated, &request, budget(), MAX_REPORT_BYTES).is_err());
        let mut relabelled = value;
        relabelled.segments[0].report.projection_id = "another-window".into();
        assert!(render(&relabelled, &request, budget(), MAX_REPORT_BYTES).is_err());
        Ok(())
    }

    #[test]
    fn signed_extreme_point_windows_do_not_overflow() -> Result<(), Box<dyn std::error::Error>> {
        for point in [i128::MIN, i128::MAX] {
            let (value, request) = sample(interval(point, point))?;
            let json = render(&value, &request, budget(), MAX_REPORT_BYTES)?;
            assert!(json.contains(&format!("\"start_ns\":\"{point}\"")));
            assert!(json.contains("\"state\":\"initially_unwitnessed\""));
        }
        Ok(())
    }
}
