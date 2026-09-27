#![forbid(unsafe_code)]
//! Exact, bounded temporal partitions of retained sensor coverage.
//!
//! Unlike a historical union or a whole-query containment filter, this compiler splits an
//! inclusive capture window at every certain witness start and end. Each resulting segment
//! has a constant set of witnesses and runs the existing `ALG-BRIDGE-001` projection. Gaps,
//! zero-witness zones, sensor handovers and single-instant overlaps remain explicit.
//!
//! Callers must supply an already authorized projection of retained evidence. Capture bounds
//! are assertions in one declared time coordinate system, not calibrated clock alignment,
//! present availability, independent failure domains, or evidence of absence. No effect is
//! authorized. Publication must bind the requested window, each segment and authority anchor.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{CaptureInterval, ContractError, TimestampNs};

use crate::coverage::{PLANE_PREFIX, SENSOR_PREFIX, ZONE_PREFIX};
use crate::{
    CoverageObservation, CoverageSinglePoints, GraphBudget, GraphError, SensorCoverageProjection,
};

/// Selection identity; separate from the unchanged historical and whole-witness policies.
pub const TIMELINE_POLICY: &str = "certain-boundary-partition-v1";
/// Maximum input sensor/zone rows, before canonical merging.
pub const MAX_TIMELINE_FACTS: usize = 4096;
/// Maximum input certain intervals across all rows, including duplicates and out-of-window rows.
pub const MAX_TIMELINE_WITNESSES: usize = 8192;
/// Maximum temporal segments, including gaps. Excess is refused, never truncated.
pub const MAX_TIMELINE_SEGMENTS: usize = 256;
/// Maximum aggregate input/selection inspections plus registered graph traversal operations.
pub const MAX_TIMELINE_OPERATIONS: u64 = 2_000_000;
/// Maximum aggregate segments, projected sensor/zone rows and registered graph emitted identities.
pub const MAX_TIMELINE_OUTPUT_ENTRIES: u64 = 100_000;

/// One known sensor/zone pair and the certain bounds of its retained coverage witnesses.
#[derive(Clone, Debug, PartialEq)]
pub struct TimedCoverageObservation {
    /// Recording sensor; identities remain opaque.
    pub sensor_id: String,
    /// Image or ground zone scope, as recorded by the owner.
    pub zone_scope: String,
    /// Certain bounds only, never uncertainty hulls. Empty means named but unwitnessed.
    pub covered: Vec<CaptureInterval>,
}

/// One inclusive segment with a constant witness set and its exact sensor-loss analysis.
#[derive(Clone, Debug, PartialEq)]
pub struct CoverageTimelineSegment {
    /// Inclusive segment; all segments together exactly partition the requested window.
    pub window: CaptureInterval,
    /// Projection retained for independently declared shared-failure analysis.
    pub projection: SensorCoverageProjection,
    /// Existing bridge algorithm and cross-checked per-zone/per-sensor answers.
    pub answer: CoverageSinglePoints,
}

/// Complete temporal answer. No partial timeline is returned on any error.
#[derive(Clone, Debug, PartialEq)]
pub struct CoverageTimeline {
    /// Exact inclusive request, including any unwitnessed leading or trailing interval.
    pub window: CaptureInterval,
    /// Chronological segments; even an empty input produces one explicit segment.
    pub segments: Vec<CoverageTimelineSegment>,
    /// Input fact/interval inspections, selection inspections and graph traversal operations.
    pub operations: u64,
    /// Segments, projected sensor/zone rows and registered graph emitted identities.
    pub output_entries: u64,
    /// Certain interval containment comparisons, included in `operations`.
    pub interval_checks: u64,
}

/// Invalid public time bounds or a refused graph/input/resource limit.
#[derive(Clone, Debug, PartialEq)]
pub enum CoverageTimelineError {
    /// A query or source interval was inverted, including an out-of-window source interval.
    Contract(ContractError),
    /// Input, aggregate budget, or graph correctness refusal.
    Graph(GraphError),
}

impl fmt::Display for CoverageTimelineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "coverage interval rejected: {error:?}"),
            Self::Graph(error) => write!(formatter, "coverage timeline rejected: {error}"),
        }
    }
}

impl std::error::Error for CoverageTimelineError {}

impl From<GraphError> for CoverageTimelineError {
    fn from(error: GraphError) -> Self {
        Self::Graph(error)
    }
}

impl From<ContractError> for CoverageTimelineError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl CoverageTimelineError {
    /// Registered graph refusal identity, when applicable.
    #[must_use]
    pub const fn stable_id(&self) -> Option<&'static str> {
        match self {
            Self::Graph(error) => Some(error.stable_id()),
            Self::Contract(_) => None,
        }
    }
}

fn consume(
    used: &mut u64,
    amount: u64,
    limit: u64,
    dimension: &'static str,
) -> Result<(), GraphError> {
    if amount > limit.saturating_sub(*used) {
        return Err(GraphError::BudgetExhausted { dimension, limit });
    }
    *used += amount;
    Ok(())
}

fn validate_identity(prefix: &str, id: &str) -> Result<(), GraphError> {
    if id.is_empty()
        || id.len() > crate::graph::MAX_NODE_ID_LEN - prefix.len()
        || id.chars().any(char::is_control)
    {
        // Do not clone an oversized or control-bearing input into the error path.
        return Err(GraphError::InvalidNodeId(prefix.to_owned()));
    }
    Ok(())
}

/// Partition `window` and analyze the exact coverage graph of every segment.
///
/// Duplicate rows merge canonically; duplicate witnesses retain their counts but never create
/// additional observers. Every source interval is validated, even outside the query. Both
/// endpoint extremes of signed 128-bit nanoseconds are supported: successors are computed only
/// below the query's upper bound, and no duration subtraction is performed.
///
/// The dominant selection cost is O(S * (F + W)); graph work is the sum of registered runs.
/// Here S <= 256, F <= 4096 and W <= 8192. Ordered maps/sets additionally take O((F + W) log(F + W))
/// construction work. Input inspections, segment selections and graph traversals share one
/// caller budget, clamped to hard ceilings. Output accounting includes otherwise-unbounded
/// repeated zero-witness facts, not just bridge separations.
///
/// # Errors
/// Inverted intervals, invalid identities, hard input/segment limits, any graph refusal or
/// aggregate budget exhaustion. No prefix, sampled substitute or absence claim is returned.
pub fn analyse_coverage_timeline(
    site: &str,
    observations: &[TimedCoverageObservation],
    window: CaptureInterval,
    budget: GraphBudget,
) -> Result<CoverageTimeline, CoverageTimelineError> {
    let window = CaptureInterval::new(window.earliest, window.latest)?;
    validate_identity(PLANE_PREFIX, site)?;
    if observations.len() > MAX_TIMELINE_FACTS {
        return Err(GraphError::TooLarge.into());
    }
    let ceiling = GraphBudget {
        max_operations: budget.max_operations.min(MAX_TIMELINE_OPERATIONS),
        max_output_entries: budget.max_output_entries.min(MAX_TIMELINE_OUTPUT_ENTRIES),
    };
    let mut operations = 0;
    let mut witness_count = 0_usize;
    let mut facts: BTreeMap<(String, String), Vec<CaptureInterval>> = BTreeMap::new();
    let mut starts = BTreeSet::from([window.earliest.0]);
    for observation in observations {
        consume(&mut operations, 1, ceiling.max_operations, "timeline_operations")?;
        validate_identity(SENSOR_PREFIX, &observation.sensor_id)?;
        validate_identity(ZONE_PREFIX, &observation.zone_scope)?;
        witness_count = witness_count
            .checked_add(observation.covered.len())
            .ok_or(GraphError::TooLarge)?;
        if witness_count > MAX_TIMELINE_WITNESSES {
            return Err(GraphError::TooLarge.into());
        }
        let intervals = facts
            .entry((observation.sensor_id.clone(), observation.zone_scope.clone()))
            .or_default();
        for covered in &observation.covered {
            consume(&mut operations, 1, ceiling.max_operations, "timeline_operations")?;
            let covered = CaptureInterval::new(covered.earliest, covered.latest)?;
            intervals.push(covered);
            let first = covered.earliest.0.max(window.earliest.0);
            let last = covered.latest.0.min(window.latest.0);
            if first <= last {
                starts.insert(first);
                if last < window.latest.0 {
                    // last < query end <= i128::MAX makes this addition representable.
                    starts.insert(last + 1);
                }
                if starts.len() > MAX_TIMELINE_SEGMENTS {
                    return Err(GraphError::BudgetExhausted {
                        dimension: "timeline_segments",
                        limit: MAX_TIMELINE_SEGMENTS as u64,
                    }
                    .into());
                }
            }
        }
    }
    for intervals in facts.values_mut() {
        intervals.sort_unstable_by_key(|interval| (interval.earliest.0, interval.latest.0));
    }
    let starts: Vec<i128> = starts.into_iter().collect();
    let mut result = CoverageTimeline {
        window,
        segments: Vec::with_capacity(starts.len()),
        operations,
        output_entries: 0,
        interval_checks: 0,
    };
    for (index, first) in starts.iter().copied().enumerate() {
        // Sorted distinct starts ensure the successor is strictly above i128::MIN.
        let last = starts.get(index + 1).map_or(window.latest.0, |next| next - 1);
        let segment_window = CaptureInterval::new(TimestampNs(first), TimestampNs(last))?;
        consume(
            &mut result.output_entries,
            1 + facts.len() as u64,
            ceiling.max_output_entries,
            "timeline_output_entries",
        )?;
        let mut selected = Vec::with_capacity(facts.len());
        for ((sensor, zone), intervals) in &facts {
            consume(&mut result.operations, 1, ceiling.max_operations, "timeline_operations")?;
            let mut witnesses = 0;
            for covered in intervals {
                consume(&mut result.operations, 1, ceiling.max_operations, "timeline_operations")?;
                result.interval_checks += 1;
                if covered.earliest.0 <= first && covered.latest.0 >= last {
                    witnesses += 1;
                }
            }
            selected.push(CoverageObservation {
                sensor_id: sensor.clone(),
                zone_scope: zone.clone(),
                witnesses,
            });
        }
        let projection = SensorCoverageProjection::build(site, &selected)?;
        let answer = projection.single_points(GraphBudget {
            max_operations: ceiling.max_operations - result.operations,
            max_output_entries: ceiling.max_output_entries - result.output_entries,
        })?;
        consume(
            &mut result.operations,
            answer.analysis.operations,
            ceiling.max_operations,
            "timeline_operations",
        )?;
        consume(
            &mut result.output_entries,
            answer.analysis.output_entries,
            ceiling.max_output_entries,
            "timeline_output_entries",
        )?;
        result.segments.push(CoverageTimelineSegment {
            window: segment_window,
            projection,
            answer,
        });
    }
    Ok(result)
}
