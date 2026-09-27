#![forbid(unsafe_code)]
//! Read-only temporal coverage over one verified committed deployment snapshot.
//!
//! Certain retained witness bounds, not uncertainty hulls, drive the partition. Every segment
//! carries an existing `ALG-BRIDGE-001` witness binding the full request, segment and anchor.
//! A gap means no qualifying retained coverage witness; it may contain observed activity or
//! excluded analysis and must not be promoted to sensor failure, quietness or physical absence.

use std::path::Path;

use fss_core::{CaptureInterval, LedgerAnchor};
use fss_graph_algorithms::coverage::PROJECTION_KIND;
use fss_graph_algorithms::coverage_timeline::{
    CoverageTimelineError, MAX_TIMELINE_FACTS, MAX_TIMELINE_OPERATIONS,
    MAX_TIMELINE_OUTPUT_ENTRIES, MAX_TIMELINE_WITNESSES, TimedCoverageObservation,
    analyse_coverage_timeline,
};
use fss_graph_algorithms::{GraphBudget, GraphError};

use crate::agent_orient::{DeploymentSnapshot, OrientLimits, read_deployment};
use crate::coverage_graph::{CoverageGraphError, CoverageGraphReport};
use crate::ingest::recorded_coverage::CoverageRecord;

/// One fully witnessed, inclusive segment of the requested timeline.
#[derive(Clone, Debug, PartialEq)]
pub struct CoverageTimelineReportSegment {
    /// Certain capture-time bounds of this segment.
    pub window: CaptureInterval,
    /// Reuses the existing single-points answer and witness contract.
    pub report: CoverageGraphReport,
}

/// Complete timeline over one pinned authority anchor; never a truncated prefix.
#[derive(Clone, Debug, PartialEq)]
pub struct CoverageTimelineReport {
    /// Requested and verified site lineage.
    pub site: String,
    /// One committed anchor for every segment and optional failure scenario.
    pub anchor: LedgerAnchor,
    /// Full inclusive query, not just the witnessed portion.
    pub window: CaptureInterval,
    /// Chronological, non-overlapping segments that exactly cover `window`.
    pub segments: Vec<CoverageTimelineReportSegment>,
    /// Source extraction, input/selection inspections and graph traversal operations.
    pub operations: u64,
    /// Segment headers, sensor/zone rows and registered graph emitted identities.
    pub output_entries: u64,
    /// Certain-interval comparisons, already included in `operations`.
    pub interval_checks: u64,
}

fn graph_error(error: CoverageTimelineError) -> CoverageGraphError {
    match error {
        CoverageTimelineError::Graph(error) => CoverageGraphError::Graph(error),
        CoverageTimelineError::Contract(error) => CoverageGraphError::Contract(error),
    }
}

fn charge_source(used: &mut u64, amount: u64, limit: u64) -> Result<(), CoverageGraphError> {
    if amount > limit.saturating_sub(*used) {
        return Err(CoverageGraphError::Graph(GraphError::BudgetExhausted {
            dimension: "timeline_source_inspections",
            limit,
        }));
    }
    *used += amount;
    Ok(())
}

fn projection_identity(
    anchor: &LedgerAnchor,
    query: CaptureInterval,
    segment: CaptureInterval,
) -> String {
    // Compact, unambiguous decimal encoding fits the witness's 256-byte ID ceiling even
    // for four signed i128 extremes and the largest u64 commit sequence. t1 binds the
    // certain-boundary-partition-v1 compiler, independently of whole-witness-v1 queries.
    format!(
        "{PROJECTION_KIND}@t1:{}:{}:{}:{}:{}",
        anchor.commit_sequence,
        query.earliest.0,
        query.latest.0,
        segment.earliest.0,
        segment.latest.0
    )
}

fn analyse_records<'a>(
    site: &str,
    anchor: &LedgerAnchor,
    records: impl Iterator<Item = &'a CoverageRecord>,
    window: CaptureInterval,
    budget: GraphBudget,
) -> Result<CoverageTimelineReport, CoverageGraphError> {
    let window = CaptureInterval::new(window.earliest, window.latest)
        .map_err(CoverageGraphError::Contract)?;
    let budget = GraphBudget {
        max_operations: budget.max_operations.min(MAX_TIMELINE_OPERATIONS),
        max_output_entries: budget.max_output_entries.min(MAX_TIMELINE_OUTPUT_ENTRIES),
    };
    let mut observations = Vec::new();
    let mut record_count = 0;
    let mut witness_count = 0_usize;
    let mut source_operations = 0;
    for record in records {
        charge_source(&mut source_operations, 1, budget.max_operations)?;
        record_count += 1;
        if record_count > MAX_TIMELINE_FACTS {
            return Err(CoverageGraphError::Graph(GraphError::TooLarge));
        }
        for zone in &record.zones {
            if observations.len() == MAX_TIMELINE_FACTS {
                return Err(CoverageGraphError::Graph(GraphError::TooLarge));
            }
            witness_count = witness_count
                .checked_add(zone.witnesses.len())
                .ok_or(CoverageGraphError::Graph(GraphError::TooLarge))?;
            if witness_count > MAX_TIMELINE_WITNESSES {
                return Err(CoverageGraphError::Graph(GraphError::TooLarge));
            }
            charge_source(
                &mut source_operations,
                1 + zone.witnesses.len() as u64,
                budget.max_operations,
            )?;
            // Bounds precede allocation. Outer hulls and unobservable ranges never supply edges.
            observations.push(TimedCoverageObservation {
                sensor_id: record.sensor_id.clone(),
                zone_scope: zone.scope.clone(),
                covered: zone.witnesses.iter().map(|witness| witness.covered).collect(),
            });
        }
    }
    let timeline = analyse_coverage_timeline(
        site,
        &observations,
        window,
        GraphBudget {
            max_operations: budget.max_operations - source_operations,
            max_output_entries: budget.max_output_entries,
        },
    )
    .map_err(graph_error)?;
    let mut segments = Vec::with_capacity(timeline.segments.len());
    for segment in timeline.segments {
        let projection_id = projection_identity(anchor, window, segment.window);
        let witness = segment.answer.analysis.witness(&projection_id, anchor.clone())
            .map_err(CoverageGraphError::Contract)?;
        fss_graph_algorithms::bridges::check_witness_bound(&witness)
            .map_err(CoverageGraphError::Graph)?;
        segments.push(CoverageTimelineReportSegment {
            window: segment.window,
            report: CoverageGraphReport {
                site: site.to_owned(),
                anchor: anchor.clone(),
                projection_id,
                records: record_count,
                projection: segment.projection,
                answer: segment.answer,
                witness,
            },
        });
    }
    Ok(CoverageTimelineReport {
        site: site.to_owned(),
        anchor: anchor.clone(),
        window,
        segments,
        operations: source_operations + timeline.operations,
        output_entries: timeline.output_entries,
        interval_checks: timeline.interval_checks,
    })
}

/// Derive a complete, budgeted timeline from an already authorized committed snapshot.
///
/// # Errors
/// Invalid time bounds, oversized projections, any aggregate budget or witness failure.
pub fn coverage_timeline(
    snapshot: &DeploymentSnapshot,
    window: CaptureInterval,
    budget: GraphBudget,
) -> Result<CoverageTimelineReport, CoverageGraphError> {
    analyse_records(
        &snapshot.site_lineage,
        &snapshot.anchor,
        snapshot.coverage.iter().map(|retained| &retained.record),
        window,
        budget,
    )
}

/// Read and rehash one committed deployment, verify its site, then derive the entire timeline.
/// Nothing is written, repaired, locked or authorized. Invalid windows fail before any I/O.
///
/// # Errors
/// Every [`coverage_timeline`] failure, an unreadable deployment or a mismatching site lineage.
pub fn read_coverage_timeline(
    root: &Path,
    site: &str,
    window: CaptureInterval,
    budget: GraphBudget,
) -> Result<CoverageTimelineReport, CoverageGraphError> {
    let window = CaptureInterval::new(window.earliest, window.latest)
        .map_err(CoverageGraphError::Contract)?;
    let snapshot = read_deployment(root, &OrientLimits::default())
        .map_err(CoverageGraphError::Read)?;
    if snapshot.site_lineage != site {
        return Err(CoverageGraphError::SiteMismatch {
            expected: site.to_owned(),
            actual: snapshot.site_lineage,
        });
    }
    coverage_timeline(&snapshot, window, budget)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::recorded_coverage::{
        CoverageEntry, CoverageFrame, CoverageInput, CoverageSource, CoverageZoneInput,
        OPERATOR_TIME_LABEL, build_coverage,
    };
    use fss_core::{ContentDigest, TimestampNs};
    use fss_graph_algorithms::ZoneState;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn window(first: i128, last: i128) -> CaptureInterval {
        CaptureInterval { earliest: TimestampNs(first), latest: TimestampNs(last) }
    }

    fn budget() -> GraphBudget {
        GraphBudget { max_operations: MAX_TIMELINE_OPERATIONS, max_output_entries: MAX_TIMELINE_OUTPUT_ENTRIES }
    }

    fn record(sensor: &str, start: i128, entry: Option<usize>) -> Result<CoverageRecord, Box<dyn std::error::Error>> {
        let frames: Vec<_> = (0..20).map(|segment| {
            let time = start + segment as i128 * 10;
            CoverageFrame { segment, capture: window(time - 1, time + 1) }
        }).collect();
        let digest = ContentDigest::sha256(sensor.as_bytes());
        Ok(build_coverage(&CoverageInput {
            source: CoverageSource::Corroborate,
            import_identity: digest,
            import_root: digest,
            sensor_id: sensor,
            analysis_digest: digest,
            basis: LedgerAnchor::genesis("site:timeline-tests"),
            capture_time_label: OPERATOR_TIME_LABEL,
            segment_gaps: &[false; 20],
            first_segment: 0,
            last_segment: 19,
            frames: &frames,
            confirmation_hits: 1,
            zones: vec![CoverageZoneInput {
                zone_id: "door".to_owned(),
                pipeline_generation: digest,
                geometry: "0,0,10,10".to_owned(),
                inside_frame: true,
                entries: entry.map(|segment| CoverageEntry { segment, candidate: digest, event_id: None }).into_iter().collect(),
            }],
        })?)
    }

    #[test]
    fn recorded_history_yields_witnessed_handover_and_explicit_gap() -> TestResult {
        let records = [record("a", 0, None)?, record("b", 1000, None)?];
        let anchor = LedgerAnchor::genesis("site:timeline-tests");
        let result = analyse_records("site:timeline-tests", &anchor, records.iter(), window(0, 1200), budget())?;
        assert!(result.segments.iter().any(|s| s.report.answer.zones[0].observers == ["a"]));
        assert!(result.segments.iter().any(|s| s.report.answer.zones[0].observers == ["b"]));
        assert!(result.segments.iter().any(|s| s.report.answer.zones[0].state == ZoneState::NotObservable));
        assert!(result.segments.iter().all(|s| s.report.answer.zones[0].observers.len() <= 1));
        for segment in result.segments {
            assert_eq!(segment.report.witness.anchor(), &anchor);
            assert_eq!(segment.report.witness.projection_id(), projection_identity(&anchor, result.window, segment.window));
            fss_graph_algorithms::bridges::check_witness_bound(&segment.report.witness)?;
        }
        Ok(())
    }

    #[test]
    fn observed_entry_and_uncertain_hulls_do_not_bridge_certain_witness_gaps() -> TestResult {
        let record = record("a", 0, Some(10))?;
        assert_eq!(record.zones[0].witnesses.len(), 2);
        let anchor = LedgerAnchor::genesis("site:timeline-tests");
        let result = analyse_records("site:timeline-tests", &anchor, [&record].into_iter(), window(-1, 191), budget())?;
        for time in -1..=191 {
            let segments: Vec<_> = result.segments.iter().filter(|s| s.window.earliest.0 <= time && time <= s.window.latest.0).collect();
            assert_eq!(segments.len(), 1);
            let expected = record.zones[0].witnesses.iter().any(|w| w.covered.earliest.0 <= time && time <= w.covered.latest.0);
            assert_eq!(!segments[0].report.answer.zones[0].observers.is_empty(), expected);
        }
        Ok(())
    }

    #[test]
    fn identities_bind_full_query_segment_and_anchor_within_256_bytes() -> TestResult {
        let anchor = LedgerAnchor::genesis("site:timeline-tests");
        let records = [record("a", 0, None)?];
        let a = analyse_records("site:timeline-tests", &anchor, records.iter(), window(60, 120), budget())?;
        let b = analyse_records("site:timeline-tests", &anchor, records.iter(), window(70, 110), budget())?;
        assert_eq!(a.segments[0].report.answer.analysis.input_digest, b.segments[0].report.answer.analysis.input_digest);
        assert_ne!(a.segments[0].report.witness.digest(), b.segments[0].report.witness.digest());
        let extreme = window(i128::MIN, i128::MAX);
        let id = projection_identity(&anchor, extreme, extreme);
        assert!(id.len() < 256);
        let _ = a.segments[0].report.answer.analysis.witness(&id, anchor.clone())?;
        assert_ne!(projection_identity(&anchor, window(0, 20), window(0, 10)), projection_identity(&anchor, window(0, 30), window(0, 10)));
        assert_ne!(projection_identity(&anchor, window(0, 20), window(0, 10)), projection_identity(&anchor, window(0, 20), window(1, 10)));
        let mut newer = anchor.clone();
        newer.commit_sequence += 1;
        assert_ne!(projection_identity(&anchor, extreme, extreme), projection_identity(&newer, extreme, extreme));
        Ok(())
    }

    #[test]
    fn invalid_window_refused_before_opening_deployment() {
        assert!(matches!(read_coverage_timeline(Path::new("not-opened"), "s", window(2, 1), budget()), Err(CoverageGraphError::Contract(_))));
    }

    #[test]
    fn source_copying_is_charged_and_full_result_is_order_independent() -> TestResult {
        let records = [record("a", 0, None)?, record("b", 1000, None)?];
        let anchor = LedgerAnchor::genesis("site:timeline-tests");
        let result = analyse_records("site:timeline-tests", &anchor, records.iter(), window(0, 1200), budget())?;
        assert_eq!(result, analyse_records("site:timeline-tests", &anchor, records.iter().rev(), window(0, 1200), budget())?);
        let exact = GraphBudget { max_operations: result.operations, max_output_entries: result.output_entries };
        assert_eq!(result, analyse_records("site:timeline-tests", &anchor, records.iter(), window(0, 1200), exact)?);
        assert!(analyse_records("site:timeline-tests", &anchor, records.iter(), window(0, 1200), GraphBudget { max_operations: result.operations - 1, ..exact }).is_err());
        Ok(())
    }
}
