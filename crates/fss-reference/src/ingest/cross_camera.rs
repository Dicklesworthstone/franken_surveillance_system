#![forbid(unsafe_code)]
//! Cross-camera association of tracked objects using time proximity and
//! geometric consistency gates.
//!
//! Takes confirmed tracked objects from two or more cameras covering
//! overlapping zones and associates detections of the same physical object
//! across cameras. Association requires BOTH:
//! - capture timestamps within a bounded window (time gate)
//! - rectified ground-plane positions within a distance threshold (geometry gate)
//!
//! Output is a set of [`AssociatedPair`]s with confidence scores. Objects that
//! cannot be associated remain unassociated — the system never forces a match.
//!
//! All arithmetic is f64; deterministic across runs with the same input.

/// Configuration for the cross-camera associator.
#[derive(Clone, Debug)]
pub struct CrossCameraConfig {
    /// Maximum capture timestamp difference (in nanoseconds) for two
    /// observations to be considered temporally coincident.
    pub max_time_delta_ns: i64,
    /// Maximum Euclidean distance (in scene units, e.g. metres) between
    /// rectified ground-plane positions for two observations to be
    /// considered geometrically consistent.
    pub max_position_distance: f64,
    /// Minimum association confidence for a pair to be reported.
    /// Confidence = (1 - dist/max_dist) * (1 - |dt|/max_dt), must be >= this.
    pub min_confidence: f64,
}

impl CrossCameraConfig {
    /// Validates hard bounds.
    pub fn validate(&self) -> Result<(), CrossCameraError> {
        if self.max_time_delta_ns <= 0 {
            return Err(CrossCameraError::InvalidConfig("max_time_delta_ns must be positive"));
        }
        if !self.max_position_distance.is_finite() || self.max_position_distance <= 0.0 {
            return Err(CrossCameraError::InvalidConfig(
                "max_position_distance must be finite and positive"));
        }
        if !self.min_confidence.is_finite() || self.min_confidence < 0.0
            || self.min_confidence > 1.0 {
            return Err(CrossCameraError::InvalidConfig(
                "min_confidence must be finite and in [0, 1]"));
        }
        Ok(())
    }
}

/// Typed cross-camera association failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossCameraError {
    /// Configuration validation failed with a reason.
    InvalidConfig(&'static str),
}
impl std::fmt::Display for CrossCameraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid cross-camera config: {msg}"),
        }
    }
}
impl std::error::Error for CrossCameraError {}

/// A single camera's observation of a tracked object, already rectified to
/// the shared ground plane.
#[derive(Clone, Debug)]
pub struct CameraObservation {
    /// Camera identity (must be unique within one association batch).
    pub camera_id: String,
    /// Track ID from the per-camera Kalman tracker.
    pub track_id: u64,
    /// Capture timestamp in nanoseconds (ideally NTP/PTP-aligned).
    pub timestamp_ns: i64,
    /// Rectified ground-plane x coordinate (scene units, e.g. metres).
    pub ground_x: f64,
    /// Rectified ground-plane y coordinate (scene units, e.g. metres).
    pub ground_y: f64,
}

/// A confirmed cross-camera association between two observations.
#[derive(Clone, Debug)]
pub struct AssociatedPair {
    /// Observation from the first camera.
    pub first: CameraObservation,
    /// Observation from the second camera.
    pub second: CameraObservation,
    /// Association confidence in [0, 1]: combines time proximity and
    /// geometric consistency.
    pub confidence: f64,
}

/// Computes association confidence from time delta and spatial distance.
///
/// Both components are normalised to [0, 1] (1 = perfect match) and
/// multiplied together. Returns `None` if either gate fails.
fn association_score(
    dt_ns: i64,
    max_dt: i64,
    dist: f64,
    max_dist: f64,
    min_conf: f64,
) -> Option<f64> {
    let dt_abs = dt_ns.abs();
    if dt_abs > max_dt {
        return None;
    }
    if dist > max_dist || dist < 0.0 {
        return None;
    }
    let time_score = 1.0 - dt_abs as f64 / max_dt as f64;
    let geom_score = 1.0 - dist / max_dist;
    let confidence = time_score * geom_score;
    if confidence < min_conf {
        None
    } else {
        Some(confidence)
    }
}

/// Associates tracked-object observations across cameras.
///
/// Uses a greedy best-first strategy: all candidate pairs are scored, sorted
/// by confidence descending, and greedily assigned (each observation is used
/// at most once). This is O(n*m) for n and m observations from two cameras;
/// for >2 cameras the function is called pairwise.
///
/// Both input slices must be from different cameras (same-camera observations
/// are not associated).
pub fn associate(
    config: &CrossCameraConfig,
    left: &[CameraObservation],
    right: &[CameraObservation],
) -> Result<Vec<AssociatedPair>, CrossCameraError> {
    config.validate()?;
    let mut candidates = Vec::new();
    for l in left {
        for r in right {
            if l.camera_id == r.camera_id {
                continue;
            }
            let dt = (l.timestamp_ns - r.timestamp_ns).abs();
            let dx = l.ground_x - r.ground_x;
            let dy = l.ground_y - r.ground_y;
            let dist = (dx * dx + dy * dy).sqrt();
            if let Some(conf) = association_score(dt, config.max_time_delta_ns, dist, config.max_position_distance, config.min_confidence) {
                candidates.push((l.clone(), r.clone(), conf));
            }
        }
    }
    // Greedy: sort by confidence descending, assign each observation at most once.
    candidates.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    let mut used_left = Vec::new();
    let mut used_right = Vec::new();
    let mut result = Vec::new();
    for (l, r, conf) in candidates {
        let l_key = format!("{}:{}", l.camera_id, l.track_id);
        let r_key = format!("{}:{}", r.camera_id, r.track_id);
        if used_left.contains(&l_key) || used_right.contains(&r_key) {
            continue;
        }
        used_left.push(l_key);
        used_right.push(r_key);
        result.push(AssociatedPair { first: l, second: r, confidence: conf });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CrossCameraConfig {
        CrossCameraConfig {
            max_time_delta_ns: 50_000_000, // 50 ms
            max_position_distance: 2.0,    // 2 metres
            min_confidence: 0.1,
        }
    }

    fn obs(cam: &str, tid: u64, ts: i64, x: f64, y: f64) -> CameraObservation {
        CameraObservation {
            camera_id: cam.to_string(),
            track_id: tid,
            timestamp_ns: ts,
            ground_x: x,
            ground_y: y,
        }
    }

    #[test]
    fn same_object_in_two_cameras_associates() {
        let cfg = config();
        let left = [obs("cam_a", 1, 1_000_000_000, 1.0, 2.0)];
        let right = [obs("cam_b", 3, 1_010_000_000, 1.3, 2.1)];
        let pairs = associate(&cfg, &left, &right).unwrap();
        assert_eq!(pairs.len(), 1);
        assert!(pairs[0].confidence > 0.5, "close pair should have moderate-to-high confidence: {}", pairs[0].confidence);
    }

    #[test]
    fn different_objects_do_not_associate() {
        let cfg = config();
        let left = [obs("cam_a", 1, 1_000_000_000, 1.0, 2.0)];
        let right = [obs("cam_b", 3, 1_000_000_000, 15.0, 20.0)];
        let pairs = associate(&cfg, &left, &right).unwrap();
        assert!(pairs.is_empty(), "distant objects must not associate");
    }

    #[test]
    fn time_gap_beyond_max_delta_is_refused() {
        let cfg = config();
        let left = [obs("cam_a", 1, 1_000_000_000, 1.0, 2.0)];
        let right = [obs("cam_b", 3, 2_000_000_000, 1.0, 2.0)];
        let pairs = associate(&cfg, &left, &right).unwrap();
        assert!(pairs.is_empty(), "1-second gap must exceed 50 ms window");
    }

    #[test]
    fn greedy_best_first_prefers_closest_pair() {
        let cfg = config();
        let left = [
            obs("cam_a", 1, 1_000_000_000, 1.0, 2.0),
            obs("cam_a", 2, 1_000_000_000, 5.0, 6.0),
        ];
        let right = [
            obs("cam_b", 10, 1_010_000_000, 1.1, 2.1),
            obs("cam_b", 20, 1_010_000_000, 5.1, 6.1),
        ];
        let pairs = associate(&cfg, &left, &right).unwrap();
        assert_eq!(pairs.len(), 2, "both pairs should associate");
        // Closest matching should be preferred.
        let conf_a = pairs.iter().find(|p| p.first.track_id == 1).unwrap().confidence;
        let conf_b = pairs.iter().find(|p| p.first.track_id == 2).unwrap().confidence;
        assert!(conf_a > 0.5, "close pair should have moderate confidence: {conf_a}");
        assert!(conf_b > 0.5, "close pair should have moderate confidence: {conf_b}");
    }

    #[test]
    fn same_camera_observations_are_skipped() {
        let cfg = config();
        let left = [obs("cam_a", 1, 1_000_000_000, 1.0, 2.0)];
        let right = [obs("cam_a", 1, 1_000_000_000, 1.0, 2.0)];
        let pairs = associate(&cfg, &left, &right).unwrap();
        assert!(pairs.is_empty(), "same-camera observations must not cross-associate");
    }

    #[test]
    fn invalid_config_is_refused() {
        let bad = CrossCameraConfig { max_time_delta_ns: 0, ..config() };
        assert!(bad.validate().is_err());
        let bad = CrossCameraConfig { min_confidence: 1.5, ..config() };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn non_finite_config_values_are_refused_not_silently_enabled() {
        // NaN survives `<= 0.0` comparisons; without a finiteness check it would
        // disable the geometry gate and emit NaN confidences.
        let bad = CrossCameraConfig { max_position_distance: f64::NAN, ..config() };
        assert!(bad.validate().is_err());
        let bad = CrossCameraConfig { max_position_distance: f64::INFINITY, ..config() };
        assert!(bad.validate().is_err());
        let bad = CrossCameraConfig { min_confidence: f64::NAN, ..config() };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn deterministic_across_runs() {
        let cfg = config();
        let left = [obs("cam_a", 1, 1_000_000_000, 1.0, 2.0)];
        let right = [obs("cam_b", 3, 1_010_000_000, 1.1, 2.1)];
        let p1 = associate(&cfg, &left, &right).unwrap();
        let p2 = associate(&cfg, &left, &right).unwrap();
        assert_eq!(p1.len(), p2.len());
        assert_eq!(p1[0].confidence, p2[0].confidence);
    }
}
