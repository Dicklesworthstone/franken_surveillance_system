#![forbid(unsafe_code)]
//! Complete candidate construction and global ambiguity analysis.

use super::{
    ASSOCIATION_SCORE_SCALE, AssociatedPair, AssociationDisposition, AssociationExclusion,
    AssociationScore, CameraObservation, CrossCameraAlternative, CrossCameraCandidate,
    CrossCameraConfig, CrossCameraError, CrossCameraReport, MAX_CAMERA_ID_BYTES,
    MAX_CROSS_CAMERA_OBSERVATIONS,
};
use fss_geometry::WorkBudget;
use fss_twin::image_tracking::{ImageTrackingError, assignment::solve};

/// Associates complete per-camera batches without forcing unstable matches.
///
/// `ambiguity_margin_units` is a global objective margin in millionths of a
/// confidence point, bounded by 64 confidence points. The solver minimizes
/// `left_count * scale - sum(round(confidence * scale))`. Each left row has a
/// private unmatched column costing one confidence point, so matching is optional.
/// This is maximum total score, not greedy matching or maximum cardinality.
///
/// Scores are rounded to nearest integer. The effective margin adds one unit per
/// row: differences of two rounded assignment sums can err by at most this amount.
/// Thus quantization cannot turn an underlying-score tie into a stable association.
/// For each selected real edge, a complete exclusion solve tests whether it is
/// present in every solution within the effective margin. Close alternatives are
/// retained; no input is mutated and no partial report escapes on failure.
///
/// Time and position are caller-resolved point estimates, not certified intervals.
/// Unknown clock alignment or calibration must be resolved by the caller before
/// using this numeric API. A gate exclusion is never an absence certificate.
pub fn associate_detailed(
    config: &CrossCameraConfig,
    ambiguity_margin_units: u32,
    left: &[CameraObservation],
    right: &[CameraObservation],
    budget: &mut WorkBudget<'_>,
) -> Result<CrossCameraReport, CrossCameraError> {
    charge(budget, 1)?;
    config.validate()?;
    if ambiguity_margin_units > MAX_CROSS_CAMERA_OBSERVATIONS as u32 * ASSOCIATION_SCORE_SCALE {
        return Err(CrossCameraError::InvalidConfig(
            "global ambiguity margin exceeds 64 confidence points",
        ));
    }
    if left.len() > MAX_CROSS_CAMERA_OBSERVATIONS || right.len() > MAX_CROSS_CAMERA_OBSERVATIONS {
        return Err(CrossCameraError::Limit);
    }
    let left = ordered(left, budget)?;
    let right = ordered(right, budget)?;
    let rows = left.len();
    let columns = right.len() + rows;
    charge(budget, (rows * columns + rows * right.len()) as u64)?;
    let mut costs = reserve(rows * columns)?;
    let mut candidates = reserve(rows * right.len())?;
    let mut left_dispositions = reserve(rows)?;
    left_dispositions.resize(rows, AssociationDisposition::NoCandidate);
    let mut right_dispositions = reserve(right.len())?;
    right_dispositions.resize(right.len(), AssociationDisposition::NoCandidate);
    for (row, l) in left.iter().enumerate() {
        for (column, r) in right.iter().enumerate() {
            charge(budget, 32)?;
            let score = score(config, l, r);
            costs.push(match score {
                AssociationScore::Admissible { units, .. } => {
                    left_dispositions[row] = AssociationDisposition::Unresolved;
                    right_dispositions[column] = AssociationDisposition::Unresolved;
                    Some(ASSOCIATION_SCORE_SCALE - units)
                }
                AssociationScore::Excluded(_) => None,
            });
            candidates.push(CrossCameraCandidate {
                left: row,
                right: column,
                score,
                selected: false,
                ambiguous: false,
                exclusion_cost: None,
            });
        }
        for dummy in 0..rows {
            costs.push((dummy == row).then_some(ASSOCIATION_SCORE_SCALE));
        }
    }
    let best = solve(&costs, rows, columns, None, budget)?;
    let effective_margin = u64::from(ambiguity_margin_units) + rows as u64;
    let mut alternatives = reserve(rows)?;
    for (row, &column) in best.columns().iter().enumerate() {
        charge(budget, 1)?;
        if column >= right.len() {
            continue;
        }
        let alternate = solve(&costs, rows, columns, Some((row, column)), budget)?;
        let ambiguous = alternate.cost() <= best.cost() + effective_margin;
        let candidate = &mut candidates[row * right.len() + column];
        candidate.selected = true;
        candidate.ambiguous = ambiguous;
        candidate.exclusion_cost = Some(alternate.cost());
        if ambiguous {
            charge(budget, rows as u64)?;
            let mut selected = reserve(rows)?;
            for &assigned in alternate.columns() {
                selected.push((assigned < right.len()).then_some(assigned));
            }
            alternatives.push(CrossCameraAlternative {
                excluded: (row, column),
                columns: selected,
                cost: alternate.cost(),
            });
        } else {
            left_dispositions[row] = AssociationDisposition::Matched(column);
            right_dispositions[column] = AssociationDisposition::Matched(row);
        }
    }
    charge(budget, 0)?;
    Ok(CrossCameraReport {
        config: config.clone(),
        requested_margin: ambiguity_margin_units,
        left,
        right,
        candidates,
        left_dispositions,
        right_dispositions,
        alternatives,
        assignment_cost: best.cost(),
        effective_margin,
    })
}

fn ordered(
    input: &[CameraObservation],
    budget: &mut WorkBudget<'_>,
) -> Result<Vec<CameraObservation>, CrossCameraError> {
    charge(
        budget,
        (input.len() * (MAX_CAMERA_ID_BYTES + input.len() + 1)) as u64,
    )?;
    let mut result = reserve(input.len())?;
    for observation in input {
        if observation.camera_id.len() > MAX_CAMERA_ID_BYTES {
            return Err(CrossCameraError::Limit);
        }
        if observation.camera_id.is_empty()
            || observation.camera_id.chars().any(char::is_control)
            || observation.track_id == 0
            || !observation.ground_x.is_finite()
            || !observation.ground_y.is_finite()
        {
            return Err(CrossCameraError::InvalidObservation("identity or position"));
        }
        if input
            .first()
            .is_some_and(|first| first.camera_id != observation.camera_id)
        {
            return Err(CrossCameraError::InvalidObservation(
                "one camera is required per input slice",
            ));
        }
        result.push(copy_observation(observation)?);
    }
    result.sort_unstable_by_key(|observation| observation.track_id);
    if result
        .windows(2)
        .any(|pair| pair[0].track_id == pair[1].track_id)
    {
        return Err(CrossCameraError::DuplicateObservation);
    }
    Ok(result)
}

fn score(
    config: &CrossCameraConfig,
    l: &CameraObservation,
    r: &CameraObservation,
) -> AssociationScore {
    if l.camera_id == r.camera_id {
        return AssociationScore::Excluded(AssociationExclusion::SameCamera);
    }
    // abs_diff remains exact even for MIN versus MAX; signed subtraction does not.
    let delta = l.timestamp_ns.abs_diff(r.timestamp_ns);
    if delta > config.max_time_delta_ns.unsigned_abs() {
        return AssociationScore::Excluded(AssociationExclusion::Time);
    }
    // hypot avoids squaring overflow/underflow. Infinite separation between two
    // finite extremes necessarily exceeds every admitted finite distance gate.
    let distance = (l.ground_x - r.ground_x).hypot(l.ground_y - r.ground_y);
    if distance > config.max_position_distance {
        return AssociationScore::Excluded(AssociationExclusion::Position);
    }
    let confidence = (1.0 - delta as f64 / config.max_time_delta_ns as f64)
        * (1.0 - distance / config.max_position_distance);
    if confidence < config.min_confidence {
        AssociationScore::Excluded(AssociationExclusion::Confidence)
    } else {
        // Both validated components lie in [0,1], so this narrowing is bounded.
        let units = (confidence * f64::from(ASSOCIATION_SCORE_SCALE)).round() as u32;
        AssociationScore::Admissible { confidence, units }
    }
}

pub(super) fn pairs(
    report: &CrossCameraReport,
    budget: &mut WorkBudget<'_>,
) -> Result<Vec<AssociatedPair>, CrossCameraError> {
    charge(
        budget,
        (report.left.len() * (2 * MAX_CAMERA_ID_BYTES + 1)) as u64,
    )?;
    let mut pairs = reserve(report.left.len())?;
    for (row, disposition) in report.left_dispositions.iter().enumerate() {
        if let AssociationDisposition::Matched(column) = *disposition {
            let AssociationScore::Admissible { confidence, .. } =
                report.candidates[row * report.right.len() + column].score
            else {
                return Err(CrossCameraError::InvalidObservation(
                    "inconsistent association report",
                ));
            };
            pairs.push(AssociatedPair {
                first: copy_observation(&report.left[row])?,
                second: copy_observation(&report.right[column])?,
                confidence,
            });
        }
    }
    charge(budget, 0)?;
    Ok(pairs)
}

fn copy_observation(source: &CameraObservation) -> Result<CameraObservation, CrossCameraError> {
    let mut camera_id = String::new();
    camera_id
        .try_reserve_exact(source.camera_id.len())
        .map_err(|_| CrossCameraError::Limit)?;
    camera_id.push_str(&source.camera_id);
    Ok(CameraObservation {
        camera_id,
        track_id: source.track_id,
        timestamp_ns: source.timestamp_ns,
        ground_x: source.ground_x,
        ground_y: source.ground_y,
    })
}

fn reserve<T>(count: usize) -> Result<Vec<T>, CrossCameraError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| CrossCameraError::Limit)?;
    Ok(values)
}

fn charge(budget: &mut WorkBudget<'_>, units: u64) -> Result<(), CrossCameraError> {
    budget
        .charge(units)
        .map_err(|error| CrossCameraError::Assignment(ImageTrackingError::Geometry(error)))
}
