//! Structural gauge checks: camera connectivity through shared free landmarks and
//! control-point anchoring. Everything runs in canonical index order.

use super::{
    BundleCamera, BundleControlPoint, CONTROL_COLLINEARITY_RATIO, MIN_CONTROL_POINTS,
    UnderConstrainedReason,
};
use crate::math::{V3, cross, norm, sub};

/// First camera index not reachable from `start` through shared free landmarks
/// (deterministic flood fill over landmark-sorted observations).
pub(super) fn unreached_camera(
    cameras: usize,
    observations: &[(usize, usize, [f64; 2])],
    start: usize,
) -> Option<usize> {
    let mut connected = vec![false; cameras];
    connected[start] = true;
    let mut changed = true;
    while changed {
        changed = false;
        let mut first = 0;
        while first < observations.len() {
            let mut end = first;
            while end < observations.len() && observations[end].0 == observations[first].0 {
                end += 1;
            }
            let group = &observations[first..end];
            if group.iter().any(|o| connected[o.1]) {
                for o in group {
                    if !connected[o.1] {
                        connected[o.1] = true;
                        changed = true;
                    }
                }
            }
            first = end;
        }
    }
    connected.iter().position(|x| !x)
}

/// Whether the points span more than a line (see [`CONTROL_COLLINEARITY_RATIO`]).
pub(super) fn spans_plane(points: &[V3]) -> bool {
    let Some(&origin) = points.first() else {
        return false;
    };
    let mut far = origin;
    let mut span = 0.0;
    for &p in points {
        let d = norm(sub(p, origin));
        if d > span {
            span = d;
            far = p;
        }
    }
    if span <= 1e-9 {
        return false;
    }
    let axis = sub(far, origin);
    let mut off_line = 0.0_f64;
    for &p in points {
        off_line = off_line.max(norm(cross(axis, sub(p, origin))) / span);
    }
    off_line >= CONTROL_COLLINEARITY_RATIO * span
}

/// Control-point gauge: the observed control points must number at least
/// [`MIN_CONTROL_POINTS`] and be non-collinear, and every camera component
/// (cameras linked through shared free landmarks) must itself observe such a set.
pub(super) fn check_control_anchoring(
    cameras: &[BundleCamera],
    control_points: &[BundleControlPoint],
    observations: &[(usize, usize, [f64; 2])],
    control_observations: &[(usize, usize, [f64; 2])],
) -> Result<(), UnderConstrainedReason> {
    let mut observed = vec![false; control_points.len()];
    for &(k, _, _) in control_observations {
        observed[k] = true;
    }
    let seen: Vec<V3> = control_points
        .iter()
        .zip(&observed)
        .filter(|(_, o)| **o)
        .map(|(c, _)| c.position)
        .collect();
    if seen.len() < MIN_CONTROL_POINTS {
        return Err(UnderConstrainedReason::TooFewControlPoints {
            observed: seen.len(),
        });
    }
    if !spans_plane(&seen) {
        return Err(UnderConstrainedReason::CollinearControlPoints);
    }
    // Components through shared free landmarks, labelled by their smallest index.
    let mut component = vec![usize::MAX; cameras.len()];
    for start in 0..cameras.len() {
        if component[start] != usize::MAX {
            continue;
        }
        component[start] = start;
        let mut changed = true;
        while changed {
            changed = false;
            let mut first = 0;
            while first < observations.len() {
                let mut end = first;
                while end < observations.len() && observations[end].0 == observations[first].0 {
                    end += 1;
                }
                let group = &observations[first..end];
                if group.iter().any(|o| component[o.1] == start) {
                    for o in group {
                        if component[o.1] != start {
                            component[o.1] = start;
                            changed = true;
                        }
                    }
                }
                first = end;
            }
        }
    }
    for start in 0..cameras.len() {
        if component[start] != start {
            continue;
        }
        let mut anchored = vec![false; control_points.len()];
        for &(k, c, _) in control_observations {
            if component[c] == start {
                anchored[k] = true;
            }
        }
        let points: Vec<V3> = control_points
            .iter()
            .zip(&anchored)
            .filter(|(_, a)| **a)
            .map(|(c, _)| c.position)
            .collect();
        if points.len() < MIN_CONTROL_POINTS || !spans_plane(&points) {
            return Err(UnderConstrainedReason::UnanchoredCamera {
                camera: cameras[start].identity.camera,
            });
        }
    }
    Ok(())
}
