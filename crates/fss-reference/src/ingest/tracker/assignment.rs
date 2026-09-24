#![forbid(unsafe_code)]
//! Canonically ordered, maximum-cardinality / maximum-quantized-IoU assignment.
use super::{Detection, TrackedTarget, iou};

pub(super) const IOU_SCALE: i128 = 1_000_000;

pub(super) fn detection_order(detections: &[Detection]) -> Vec<usize> {
    let mut order: Vec<_> = (0..detections.len()).collect();
    order.sort_by(|a, b| {
        let left = &detections[*a];
        let right = &detections[*b];
        left.box_x
            .total_cmp(&right.box_x)
            .then(left.box_y.total_cmp(&right.box_y))
            .then(left.box_w.total_cmp(&right.box_w))
            .then(left.box_h.total_cmp(&right.box_h))
            .then(a.cmp(b))
    });
    order
}

pub(super) fn associate(
    tracks: &[TrackedTarget],
    detections: &[Detection],
    order: &[usize],
    threshold: f64,
) -> Vec<Option<usize>> {
    let mut result = vec![None; tracks.len()];
    if tracks.is_empty() || detections.is_empty() {
        return result;
    }
    let mut rows: Vec<_> = (0..tracks.len()).collect();
    rows.sort_by_key(|i| tracks[*i].id);
    // One extra unmatched track costs more than every real-edge cost combined.
    // There is one dummy per row, so a forbidden edge is never necessary.
    let unmatched = (tracks.len() as i128 + 1) * IOU_SCALE;
    let forbidden = unmatched + IOU_SCALE;
    let selected = minimum_cost(
        tracks.len(),
        detections.len() + tracks.len(),
        |row, column| {
            if column >= detections.len() {
                return unmatched;
            }
            let t = &tracks[rows[row]];
            let d = &detections[order[column]];
            let score = iou(
                t.cx - t.box_w / 2.0,
                t.cy - t.box_h / 2.0,
                t.box_w,
                t.box_h,
                d.box_x,
                d.box_y,
                d.box_w,
                d.box_h,
            );
            if !score.is_finite() || score <= 0.0 || score < threshold {
                return forbidden;
            }
            IOU_SCALE - (score.min(1.0) * IOU_SCALE as f64).round() as i128
        },
    );
    for (row, column) in selected.into_iter().enumerate() {
        if column < detections.len() {
            result[rows[row]] = Some(order[column]);
        }
    }
    result
}

/// Rectangular shortest-augmenting-path Hungarian solver, rows <= columns.
/// Costs are computed on demand: O(rows^2 * columns) work, O(rows + columns)
/// auxiliary storage, no dense pair matrix and no exponential subset search.
pub(super) fn minimum_cost(
    rows: usize,
    columns: usize,
    cost: impl Fn(usize, usize) -> i128,
) -> Vec<usize> {
    let mut u = vec![0_i128; rows + 1];
    let mut v = vec![0_i128; columns + 1];
    let mut owner = vec![0_usize; columns + 1];
    let mut predecessor = vec![0_usize; columns + 1];
    for row in 1..=rows {
        owner[0] = row;
        let mut column = 0;
        let mut distance = vec![i128::MAX; columns + 1];
        let mut visited = vec![false; columns + 1];
        loop {
            visited[column] = true;
            let current = owner[column];
            let mut delta = i128::MAX;
            let mut next = 0;
            for candidate in 1..=columns {
                if visited[candidate] {
                    continue;
                }
                let reduced = cost(current - 1, candidate - 1) - u[current] - v[candidate];
                if reduced < distance[candidate] {
                    distance[candidate] = reduced;
                    predecessor[candidate] = column;
                }
                if distance[candidate] < delta {
                    delta = distance[candidate];
                    next = candidate;
                }
            }
            for candidate in 0..=columns {
                if visited[candidate] {
                    u[owner[candidate]] += delta;
                    v[candidate] -= delta;
                } else if distance[candidate] != i128::MAX {
                    distance[candidate] -= delta;
                }
            }
            column = next;
            if owner[column] == 0 {
                break;
            }
        }
        loop {
            let previous = predecessor[column];
            owner[column] = owner[previous];
            column = previous;
            if column == 0 {
                break;
            }
        }
    }
    let mut result = vec![0; rows];
    for (column, row) in owner.into_iter().enumerate().skip(1) {
        if row != 0 {
            result[row - 1] = column - 1;
        }
    }
    result
}
