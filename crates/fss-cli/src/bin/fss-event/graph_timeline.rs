#![forbid(unsafe_code)]
//! Complete, buffered temporal coverage reports; no output prefix survives a refused segment.

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use fss_cli::agent_json::{array, evidence_anchor, object, string};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::CaptureInterval;
use fss_graph_algorithms::GraphBudget;
use fss_graph_algorithms::coverage_timeline::{
    MAX_TIMELINE_OPERATIONS, MAX_TIMELINE_OUTPUT_ENTRIES, MAX_TIMELINE_SEGMENTS, TIMELINE_POLICY,
};
use fss_graph_algorithms::failure_domains::FailureDomain;
use fss_reference::coverage_timeline::{CoverageTimelineReport, read_coverage_timeline};

use super::shared_failures;

const FORMAT: &str = "fss.coverage_timeline.v1";
const HELP: &str = "fss-event graph timeline --root DIR --site SITE --during START_NS:END_NS\n\
  [--failure-domain KIND:ID=SENSOR[,SENSOR...]] (repeatable)\n\
  Reads one committed snapshot. No mutation, repair, effect or absence authority.\n\
  Inclusive signed 128-bit capture nanoseconds; a point window is allowed.\n\
  Splits at certain witness boundaries, preserving handovers, overlaps and unwitnessed\n\
  intervals. Uncertainty hulls never create coverage; timestamps are operator hints,\n\
  not calibrated clock alignment. A witness gap may contain observed activity or\n\
  excluded analysis: it is NOT a sensor-failure or no-activity determination.\n\
  Each segment includes its zones, sensor single points and ALG-BRIDGE-001 witness,\n\
  binding the entire request, the segment and the same committed authority anchor.\n\
  Shared network/power/clock/host failures use the single-points declaration syntax;\n\
  each domain is tested independently in every segment, not jointly with other domains.\n\
  Topology declarations are owner assertions; undeclared dependencies remain unknown.\n\
  Hard limits: 4096 records and sensor/zone rows, 8192 certain intervals, 256 segments,\n\
  2000000 aggregate source/selection/traversal operations, 100000 output entries, 8 MiB.\n\
  Budgets include all segments and shared scenarios. Exhaustion refuses the whole report;\n\
  no sampling, truncation, partial stdout or reset of the budget for each segment.\n";

fn budget() -> GraphBudget {
    GraphBudget {
        max_operations: MAX_TIMELINE_OPERATIONS,
        max_output_entries: MAX_TIMELINE_OUTPUT_ENTRIES,
    }
}

fn parse(args: &[OsString]) -> Result<super::Request, String> {
    if args.first().and_then(|arg| arg.to_str()) != Some("timeline") {
        return Err("expected graph timeline".to_owned());
    }
    // Reuse the existing strict option and failure-domain parser without changing historical
    // request semantics, duplicate handling or signed timestamp precision.
    let mut translated = args.to_vec();
    translated[0] = "single-points".into();
    let request = super::parse(&translated)?;
    if request.window.is_none() {
        return Err("graph timeline requires --during START_NS:END_NS".to_owned());
    }
    Ok(request)
}

fn window_json(window: CaptureInterval) -> String {
    object(&[
        ("start_ns", string(&window.earliest.0.to_string())),
        ("end_ns", string(&window.latest.0.to_string())),
        ("endpoints", string("inclusive")),
    ])
}

fn render(
    value: &CoverageTimelineReport,
    domains: &[FailureDomain],
    limit: GraphBudget,
    max_bytes: usize,
) -> Result<String, String> {
    let limit = GraphBudget {
        max_operations: limit.max_operations.min(MAX_TIMELINE_OPERATIONS),
        max_output_entries: limit.max_output_entries.min(MAX_TIMELINE_OUTPUT_ENTRIES),
    };
    let max_bytes = max_bytes.min(shared_failures::MAX_REPORT_BYTES);
    let mut operations = value.operations;
    let mut output_entries = value.output_entries;
    if operations > limit.max_operations || output_entries > limit.max_output_entries {
        return Err(
            "ERR-GRAPH-BUDGET-EXHAUSTED-001: timeline base exceeds aggregate budget".to_owned(),
        );
    }
    let mut rows = Vec::with_capacity(value.segments.len());
    let mut bytes = 0_usize;
    for segment in &value.segments {
        let report = if domains.is_empty() {
            super::report(&segment.report, Some(segment.window))
        } else {
            let shared = shared_failures::render_with_budget(
                &segment.report,
                domains,
                GraphBudget {
                    max_operations: limit.max_operations - operations,
                    max_output_entries: limit.max_output_entries - output_entries,
                },
            )?;
            operations += shared.operations;
            output_entries += shared.output_entries;
            super::report_with_failures(&segment.report, Some(segment.window), Some(shared.json))
        };
        let row = object(&[
            ("capture_window", window_json(segment.window)),
            ("result", report),
        ]);
        bytes = bytes
            .checked_add(row.len() + 1)
            .ok_or("ERR-GRAPH-BUDGET-EXHAUSTED-001: timeline report size overflow")?;
        if bytes > max_bytes {
            return Err(
                "ERR-GRAPH-BUDGET-EXHAUSTED-001: timeline report exceeds byte budget".to_owned(),
            );
        }
        rows.push(row);
    }
    let rendered = object(&[
        ("format", string(FORMAT)),
        ("site", string(&value.site)),
        ("anchor", evidence_anchor(&value.anchor)),
        ("capture_window", window_json(value.window)),
        ("selection", string(TIMELINE_POLICY)),
        ("clock_alignment", string("operator_hints_not_calibration")),
        ("segment_count", rows.len().to_string()),
        ("segments", array(&rows)),
        (
            "budget",
            object(&[
                ("operations", operations.to_string()),
                ("output_entries", output_entries.to_string()),
                ("interval_checks", value.interval_checks.to_string()),
                ("max_operations", limit.max_operations.to_string()),
                ("max_output_entries", limit.max_output_entries.to_string()),
                ("max_segments", MAX_TIMELINE_SEGMENTS.to_string()),
                ("max_report_bytes", max_bytes.to_string()),
            ]),
        ),
        ("completion", string("complete")),
        ("authority", string("derived_cognition_no_effect_authority")),
        ("qualification", string("implemented_not_qualified")),
        (
            "claim",
            string(
                "exact partition of retained certain coverage witnesses at one anchor, conditional on operator capture hints; a witness gap may contain observed activity or excluded analysis and proves neither sensor failure nor absence; not current availability, calibrated clock alignment or an independence certificate",
            ),
        ),
    ]);
    if rendered.len() > max_bytes {
        return Err(
            "ERR-GRAPH-BUDGET-EXHAUSTED-001: timeline report exceeds byte budget".to_owned(),
        );
    }
    Ok(rendered)
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    if matches!(args, [command, flag] if command.to_str() == Some("timeline") && matches!(flag.to_str(), Some("--help" | "-h")))
    {
        return match io::stdout().lock().write_all(HELP.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        };
    }
    let request = match parse(args) {
        Ok(request) => request,
        Err(reason) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-event graph timeline --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let Some(window) = request.window else {
        eprintln!("{ERR_CLI_MALFORMED_VALUE}: graph timeline requires --during");
        return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
    };
    let value = match read_coverage_timeline(&request.root, &request.site, window, budget()) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
            if let Some(id) = error.stable_id() {
                eprintln!("refusal_id={id}");
            }
            return ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code);
        }
    };
    match render(
        &value,
        &request.domains,
        budget(),
        shared_failures::MAX_REPORT_BYTES,
    ) {
        Ok(rendered) => match writeln!(io::stdout().lock(), "{rendered}") {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::{LedgerAnchor, TimestampNs};
    use fss_graph_algorithms::coverage_timeline::{
        TimedCoverageObservation, analyse_coverage_timeline,
    };
    use fss_reference::coverage_graph::CoverageGraphReport;
    use fss_reference::coverage_timeline::CoverageTimelineReportSegment;

    fn sample() -> Result<CoverageTimelineReport, Box<dyn std::error::Error>> {
        let window = CaptureInterval::new(TimestampNs(-10), TimestampNs(10))?;
        let facts = vec![
            TimedCoverageObservation {
                sensor_id: "sensor:a".into(),
                zone_scope: "zone:door".into(),
                covered: vec![CaptureInterval::new(TimestampNs(-10), TimestampNs(0))?],
            },
            TimedCoverageObservation {
                sensor_id: "sensor:b".into(),
                zone_scope: "zone:door".into(),
                covered: vec![CaptureInterval::new(TimestampNs(0), TimestampNs(10))?],
            },
        ];
        let timeline = analyse_coverage_timeline("site:test", &facts, window, budget())?;
        let anchor = LedgerAnchor::genesis("site:test");
        let mut segments = Vec::new();
        for segment in timeline.segments {
            let projection_id = format!(
                "SensorCoverageGraph@t1:0:-10:10:{}:{}",
                segment.window.earliest.0, segment.window.latest.0
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
        Ok(CoverageTimelineReport {
            site: "site:test".into(),
            anchor,
            window,
            segments,
            operations: timeline.operations,
            output_entries: timeline.output_entries,
            interval_checks: timeline.interval_checks,
        })
    }

    #[test]
    fn timeline_requires_window_and_reuses_strict_parser() -> Result<(), String> {
        let base: Vec<OsString> = ["timeline", "--root", "not-opened", "--site", "site:test"]
            .into_iter()
            .map(Into::into)
            .collect();
        assert!(parse(&base).is_err());
        let mut valid = base.clone();
        valid.extend(["--during".into(), "-10:10".into()]);
        assert!(parse(&valid)?.window.is_some());
        valid.extend(["--during".into(), "0:1".into()]);
        assert!(parse(&valid).is_err());
        for text in ["10:0", "NaN:1", "1:2:3"] {
            let mut invalid = base.clone();
            invalid.extend(["--during".into(), text.into()]);
            assert!(parse(&invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn rendered_segments_keep_exact_bounds_and_witnesses() -> Result<(), Box<dyn std::error::Error>>
    {
        let value = sample()?;
        let json = render(&value, &[], budget(), shared_failures::MAX_REPORT_BYTES)?;
        assert!(json.contains("\"format\":\"fss.coverage_timeline.v1\""));
        assert!(json.contains("\"segment_count\":3"));
        assert!(json.contains("certain-boundary-partition-v1"));
        assert!(json.contains("\"start_ns\":\"-10\""));
        assert!(json.contains("\"end_ns\":\"10\""));
        assert!(json.contains("observed activity or excluded analysis"));
        for segment in &value.segments {
            assert!(json.contains(&segment.report.witness.digest().to_text()));
        }
        assert_eq!(
            json,
            render(&value, &[], budget(), shared_failures::MAX_REPORT_BYTES)?
        );
        assert!(render(&value, &[], budget(), json.len() - 1).is_err());
        Ok(())
    }

    #[test]
    fn shared_scenarios_consume_one_budget_across_all_segments()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = sample()?;
        let domains = [shared_failures::parse_domain(
            "network:lan=sensor:a,sensor:b",
        )?];
        let mut operations = value.operations;
        let mut output_entries = value.output_entries;
        for segment in &value.segments {
            let shared = shared_failures::render_with_budget(&segment.report, &domains, budget())?;
            operations += shared.operations;
            output_entries += shared.output_entries;
        }
        let exact = GraphBudget {
            max_operations: operations,
            max_output_entries: output_entries,
        };
        let json = render(&value, &domains, exact, shared_failures::MAX_REPORT_BYTES)?;
        assert_eq!(
            json.matches("\"shared_failure_scenarios\"").count(),
            value.segments.len()
        );
        assert!(json.contains("\"lost_zones\":[\"zone:door\"]"));
        assert!(
            render(
                &value,
                &domains,
                GraphBudget {
                    max_operations: operations - 1,
                    ..exact
                },
                shared_failures::MAX_REPORT_BYTES
            )
            .is_err()
        );
        assert!(
            render(
                &value,
                &domains,
                GraphBudget {
                    max_output_entries: output_entries - 1,
                    ..exact
                },
                shared_failures::MAX_REPORT_BYTES
            )
            .is_err()
        );
        Ok(())
    }
}
