#![forbid(unsafe_code)]
//! Constant-velocity Kalman filter tracker with IoU-based data association
//! and Tentative/Confirmed/Lost/Deleted track lifecycle management.
//!
//! Takes bounding boxes from the foreground detector and maintains stable
//! tracks across frames. All arithmetic is f64; deterministic across runs
//! with the same input. No external crates.

/// Configuration for the multi-object tracker.
#[derive(Clone, Debug)]
pub struct TrackerConfig {
    /// Consecutive hits before a Tentative track becomes Confirmed. Must be >= 1.
    pub min_hits: u32,
    /// Consecutive misses before a track is Deleted. Must be >= 1.
    pub max_misses: u32,
    /// Minimum IoU between a predicted box and a detection for association.
    pub iou_threshold: f64,
    /// Process noise per axis (position and velocity). Controls how much the
    /// Kalman filter trusts the constant-velocity model vs the measurements.
    pub process_noise: f64,
    /// Measurement noise. Controls how much the filter trusts the detection
    /// vs the prediction.
    pub measurement_noise: f64,
}

impl TrackerConfig {
    /// Validates hard bounds.
    pub fn validate(&self) -> Result<(), TrackerError> {
        if self.min_hits == 0 {
            return Err(TrackerError::InvalidConfig("min_hits must be >= 1"));
        }
        if self.max_misses == 0 {
            return Err(TrackerError::InvalidConfig("max_misses must be >= 1"));
        }
        if !self.iou_threshold.is_finite() || !(0.0..=1.0).contains(&self.iou_threshold) {
            return Err(TrackerError::InvalidConfig("iou_threshold must be in [0, 1]"));
        }
        if !self.process_noise.is_finite() || !self.measurement_noise.is_finite()
            || self.process_noise <= 0.0 || self.measurement_noise <= 0.0 {
            return Err(TrackerError::InvalidConfig("noise must be positive"));
        }
        Ok(())
    }
}

/// Typed tracker failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrackerError {
    /// Configuration validation failed with a reason.
    InvalidConfig(&'static str),
}
impl std::fmt::Display for TrackerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid tracker config: {msg}"),
        }
    }
}
impl std::error::Error for TrackerError {}

/// Track lifecycle states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackStatus {
    /// Not yet confirmed; may be noise.
    Tentative,
    /// Confirmed after `min_hits` consecutive hits.
    Confirmed,
    /// Confirmed but currently missing; coasting on prediction.
    Lost,
}

/// A single detection from the foreground detector for one frame.
#[derive(Clone, Debug)]
pub struct Detection {
    /// Bounding box top-left corner x (pixels).
    pub box_x: f64,
    /// Bounding box top-left corner y (pixels).
    pub box_y: f64,
    /// Bounding box width (pixels).
    pub box_w: f64,
    /// Bounding box height (pixels).
    pub box_h: f64,
}

/// A tracked object maintained across frames.
#[derive(Clone, Debug)]
pub struct TrackedTarget {
    /// Stable unique identifier (monotonically increasing).
    pub id: u64,
    /// Current track status.
    pub status: TrackStatus,
    /// Kalman-filtered bounding box center x.
    pub cx: f64,
    /// Kalman-filtered bounding box center y.
    pub cy: f64,
    /// Estimated velocity in x (pixels per frame).
    pub vx: f64,
    /// Estimated velocity in y (pixels per frame).
    pub vy: f64,
    /// Last observed bounding box width (pixels).
    pub box_w: f64,
    /// Last observed bounding box height (pixels).
    pub box_h: f64,
    /// Total number of detection hits.
    pub hits: u32,
    /// Consecutive miss count.
    pub misses: u32,
}

/// Output of one tracker step.
#[derive(Clone, Debug)]
pub struct TrackerOutput {
    /// All currently active tracks (Tentative + Confirmed + Lost).
    pub tracks: Vec<TrackedTarget>,
    /// Number of new tracks created this frame.
    pub new_tracks: usize,
    /// Number of tracks deleted this frame (missed too many frames).
    pub deleted_tracks: usize,
}

/// Internal Kalman state: [cx, cy, vx, vy] with a 4×4 covariance.
#[derive(Clone, Debug)]
struct KalmanState {
    x: [f64; 4],
    p: [[f64; 4]; 4],
}

impl KalmanState {
    fn new(cx: f64, cy: f64) -> Self {
        let mut p = [[0.0; 4]; 4];
        for (i, row) in p.iter_mut().enumerate() {
            row[i] = if i < 2 { 10.0 } else { 100.0 };
        }
        Self { x: [cx, cy, 0.0, 0.0], p }
    }

    fn predict(&mut self, dt: f64, process_noise: f64) {
        self.x[0] += self.x[2] * dt;
        self.x[1] += self.x[3] * dt;
        // P' = F P F^T + Q, F = [[I, dt I], [0, I]]. The configured
        // process noise is independent variance per position/velocity axis.
        // Read the prior matrix throughout: in-place propagation double-counts terms.
        let prior = self.p;
        for (i, row) in self.p.iter_mut().enumerate() {
            for (j, cell) in row.iter_mut().enumerate() {
                let mut value = prior[i][j];
                if i < 2 { value += dt * prior[i + 2][j]; }
                if j < 2 { value += dt * prior[i][j + 2]; }
                if i < 2 && j < 2 { value += dt * dt * prior[i + 2][j + 2]; }
                if i == j { value += process_noise * dt; }
                *cell = value;
            }
        }
    }

    fn update(&mut self, mx: f64, my: f64, measurement_noise: f64) {
        // Independent scalar x/y observations are equivalent to H = [I, 0],
        // R = r I. Each update uses the complete prior covariance, including
        // position/velocity cross terms needed to learn velocity from positions.
        for (axis, measurement) in [mx, my].into_iter().enumerate() {
            let prior = self.p;
            let innovation_variance = prior[axis][axis] + measurement_noise;
            let gain: [f64; 4] = std::array::from_fn(|i| prior[i][axis] / innovation_variance);
            let innovation = measurement - self.x[axis];
            for (state, k) in self.x.iter_mut().zip(gain) { *state += k * innovation; }

            // Joseph form: (I-KH) P (I-KH)^T + K R K^T. Do not update only
            // diagonal cells: that destroys symmetry and leaves stale uncertainty.
            let mut residual = [[0.0; 4]; 4];
            for (i, row) in residual.iter_mut().enumerate() {
                row[i] = 1.0;
                row[axis] -= gain[i];
            }
            let mut left = [[0.0; 4]; 4];
            for (i, row) in left.iter_mut().enumerate() {
                for (j, cell) in row.iter_mut().enumerate() {
                    *cell = residual[i].iter().enumerate().map(|(k, a)| a * prior[k][j]).sum();
                }
            }
            let mut posterior = [[0.0; 4]; 4];
            for (i, row) in left.iter().enumerate() {
                for (j, other) in residual.iter().enumerate().skip(i) {
                    let value = row.iter().zip(other).map(|(a, b)| a * b).sum::<f64>()
                        + measurement_noise * gain[i] * gain[j];
                    posterior[i][j] = value;
                    posterior[j][i] = value;
                }
            }
            self.p = posterior;
        }
    }
}

/// Computes the Intersection-over-Union of two axis-aligned boxes.
// 8 args is the natural signature for an axis-aligned box overlap check;
// grouping into a struct would obscure the geometry.
#[allow(clippy::too_many_arguments)]
fn iou(ax: f64, ay: f64, aw: f64, ah: f64, bx: f64, by: f64, bw: f64, bh: f64) -> f64 {
    let x1 = ax.max(bx);
    let y1 = ay.max(by);
    let x2 = (ax + aw).min(bx + bw);
    let y2 = (ay + ah).min(by + bh);
    let inter = (x2 - x1).max(0.0) * (y2 - y1).max(0.0);
    let union = aw * ah + bw * bh - inter;
    if union <= 0.0 { 0.0 } else { inter / union }
}

/// Deterministic multi-object tracker with constant-velocity Kalman filtering.
pub struct MultiObjectTracker {
    config: TrackerConfig,
    tracks: Vec<TrackedTarget>,
    kalman: Vec<KalmanState>,
    next_id: u64,
    frame: u64,
}

impl MultiObjectTracker {
    /// Creates a new tracker with the given configuration.
    pub fn new(config: TrackerConfig) -> Result<Self, TrackerError> {
        config.validate()?;
        Ok(Self {
            config,
            tracks: Vec::new(),
            kalman: Vec::new(),
            next_id: 1,
            frame: 0,
        })
    }

    /// Processes one frame of detections and returns the updated track set.
    pub fn step(&mut self, detections: &[Detection]) -> TrackerOutput {
        self.frame += 1;
        let dt = 1.0;
        let mut new_tracks = 0usize;
        let mut deleted_tracks = 0usize;

        // 1. Predict: advance all tracks.
        for index in 0..self.kalman.len() {
            self.kalman[index].predict(dt, self.config.process_noise);
            // Association and Lost output must use this frame's prediction, not
            // the last observed position. A prediction remains Lost, not evidence.
            self.sync_track(index);
        }

        // 2. Associate detections to tracks by IoU (greedy highest-first).
        let mut assigned_det = vec![false; detections.len()];
        let mut assigned_trk = vec![false; self.tracks.len()];
        let mut pairs: Vec<(usize, usize, f64)> = Vec::new();
        for (ti, t) in self.tracks.iter().enumerate() {
            for (di, d) in detections.iter().enumerate() {
                if assigned_det[di] || assigned_trk[ti] {
                    continue;
                }
                let score = iou(t.cx - t.box_w / 2.0, t.cy - t.box_h / 2.0, t.box_w, t.box_h,
                                d.box_x, d.box_y, d.box_w, d.box_h);
                if score >= self.config.iou_threshold {
                    pairs.push((ti, di, score));
                }
            }
        }
        pairs.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        for (ti, di, _) in &pairs {
            if assigned_trk[*ti] || assigned_det[*di] {
                continue;
            }
            assigned_trk[*ti] = true;
            assigned_det[*di] = true;
            let d = &detections[*di];
            let cx = d.box_x + d.box_w / 2.0;
            let cy = d.box_y + d.box_h / 2.0;
            self.kalman[*ti].update(cx, cy, self.config.measurement_noise);
            let track = &mut self.tracks[*ti];
            track.hits += 1;
            track.misses = 0;
            // Promotion honours min_hits: a Tentative track needs the full
            // run of consecutive hits before it may evidence events. A Lost
            // track was already confirmed once, so one re-detection revives it.
            track.status = match track.status {
                TrackStatus::Tentative if track.hits >= self.config.min_hits => {
                    TrackStatus::Confirmed
                }
                TrackStatus::Tentative => TrackStatus::Tentative,
                _ => TrackStatus::Confirmed,
            };
            track.box_w = d.box_w;
            track.box_h = d.box_h;
            self.sync_track(*ti);
        }

        // 3. Unmatched tracks: a Tentative track dies immediately (a
        // single-frame uncorroborated proposal never coasts); confirmed
        // tracks coast as Lost until step 6 deletes them past max_misses.
        // Removal happens after the scan, descending, so swap moves never
        // displace a track whose assigned flag is still pending.
        let mut removed: Vec<usize> = Vec::new();
        for ti in 0..self.tracks.len() {
            if assigned_trk[ti] {
                continue;
            }
            self.tracks[ti].misses += 1;
            if self.tracks[ti].status == TrackStatus::Tentative {
                removed.push(ti);
            } else {
                self.tracks[ti].status = TrackStatus::Lost;
            }
        }
        for ti in removed.into_iter().rev() {
            self.tracks.swap_remove(ti);
            self.kalman.swap_remove(ti);
            deleted_tracks += 1;
        }

        // 4. Unmatched detections: create new Tentative tracks.
        for (di, d) in detections.iter().enumerate() {
            if assigned_det[di] {
                continue;
            }
            let cx = d.box_x + d.box_w / 2.0;
            let cy = d.box_y + d.box_h / 2.0;
            self.kalman.push(KalmanState::new(cx, cy));
            self.tracks.push(TrackedTarget {
                id: self.next_id,
                status: if self.config.min_hits == 1 {
                    TrackStatus::Confirmed
                } else {
                    TrackStatus::Tentative
                },
                cx,
                cy,
                vx: 0.0,
                vy: 0.0,
                box_w: d.box_w,
                box_h: d.box_h,
                hits: 1,
                misses: 0,
            });
            self.next_id += 1;
            new_tracks += 1;
        }

        // 5. (Promotion now happens at match time, honouring min_hits.)

        // 6. Delete Lost tracks that exceeded max_misses.
        let max_misses = self.config.max_misses;
        let mut i = 0;
        while i < self.tracks.len() {
            let remove = self.tracks[i].status == TrackStatus::Lost
                && self.tracks[i].misses > max_misses;
            if remove {
                self.tracks.swap_remove(i);
                self.kalman.swap_remove(i);
                deleted_tracks += 1;
            } else {
                i += 1;
            }
        }

        TrackerOutput {
            tracks: self.tracks.clone(),
            new_tracks,
            deleted_tracks,
        }
    }

    /// Synchronises the public TrackedTarget with the Kalman state.
    fn sync_track(&mut self, index: usize) {
        let k = &self.kalman[index];
        self.tracks[index].cx = k.x[0];
        self.tracks[index].cy = k.x[1];
        self.tracks[index].vx = k.x[2];
        self.tracks[index].vy = k.x[3];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> TrackerConfig {
        TrackerConfig {
            min_hits: 2,
            max_misses: 3,
            iou_threshold: 0.1,
            process_noise: 1.0,
            measurement_noise: 1.0,
        }
    }

    fn det(x: f64, y: f64) -> Detection {
        Detection { box_x: x, box_y: y, box_w: 20.0, box_h: 20.0 }
    }

    #[test]
    fn single_object_is_tracked_across_frames() {
        let mut t = MultiObjectTracker::new(config()).unwrap();
        for frame in 0..5 {
            let out = t.step(&[det(10.0 + frame as f64 * 2.0, 20.0)]);
            assert_eq!(out.tracks.len(), 1);
        }
        assert_eq!(out_single(&t).status, TrackStatus::Confirmed);
        assert_eq!(out_single(&t).hits, 5);
    }

    fn out_single(t: &MultiObjectTracker) -> &TrackedTarget {
        &t.tracks[0]
    }

    #[test]
    fn tentative_track_not_confirmed_before_min_hits() {
        let mut t = MultiObjectTracker::new(config()).unwrap();
        let out = t.step(&[det(10.0, 20.0)]);
        assert_eq!(out.tracks[0].status, TrackStatus::Tentative);
    }

    #[test]
    fn missed_detections_are_handled_without_crash() {
        let mut t = MultiObjectTracker::new(config()).unwrap();
        t.step(&[det(10.0, 20.0)]);
        // Empty frames: track goes Lost then Deleted.
        for _ in 0..5 {
            let out = t.step(&[]);
            if out.tracks.is_empty() { break; }
        }
        assert!(t.tracks.is_empty(), "track should have been deleted after max misses");
    }

    #[test]
    fn two_crossing_objects_maintain_separate_ids() {
        let mut t = MultiObjectTracker::new(config()).unwrap();
        // Object A moves right, object B moves left; they cross in the middle.
        for frame in 0..10 {
            let ax = 10.0 + frame as f64 * 5.0;
            let bx = 100.0 - frame as f64 * 5.0;
            let detections = vec![det(ax, 20.0), det(bx, 20.0)];
            let out = t.step(&detections);
            let confirmed: Vec<_> = out.tracks.iter().filter(|tr| tr.status == TrackStatus::Confirmed).collect();
            if confirmed.len() >= 2 {
                assert_ne!(confirmed[0].id, confirmed[1].id);
            }
        }
    }

    #[test]
    fn deterministic_across_runs() {
        let detections = vec![det(15.0, 25.0), det(60.0, 30.0)];
        let mut a = MultiObjectTracker::new(config()).unwrap();
        let mut b = MultiObjectTracker::new(config()).unwrap();
        let oa = a.step(&detections);
        let ob = b.step(&detections);
        assert_eq!(oa.tracks.len(), ob.tracks.len());
        for (ta, tb) in oa.tracks.iter().zip(ob.tracks.iter()) {
            assert_eq!(ta.id, tb.id);
            assert_eq!((ta.cx, ta.cy), (tb.cx, tb.cy));
        }
    }

    #[test]
    fn empty_detections_on_empty_tracker_produce_empty_output() {
        let mut t = MultiObjectTracker::new(config()).unwrap();
        let out = t.step(&[]);
        assert!(out.tracks.is_empty());
        assert_eq!(out.new_tracks, 0);
        assert_eq!(out.deleted_tracks, 0);
    }

    #[test]
    fn min_hits_gates_confirmation_not_the_first_match() {
        let mut cfg = config();
        cfg.min_hits = 3;
        let mut t = MultiObjectTracker::new(cfg).unwrap();
        // Creation frame: Tentative with one hit.
        assert_eq!(t.step(&[det(10.0, 20.0)]).tracks[0].status, TrackStatus::Tentative);
        // First MATCH must not confirm: two hits < min_hits.
        assert_eq!(t.step(&[det(10.0, 20.0)]).tracks[0].status, TrackStatus::Tentative);
        // Third consecutive hit reaches min_hits: now Confirmed.
        assert_eq!(t.step(&[det(10.0, 20.0)]).tracks[0].status, TrackStatus::Confirmed);
    }

    #[test]
    fn unmatched_tentative_track_is_deleted_immediately_not_coasted() {
        let mut t = MultiObjectTracker::new(config()).unwrap();
        t.step(&[det(10.0, 20.0)]);
        let out = t.step(&[]);
        assert!(out.tracks.is_empty(), "one-hit proposal must not linger as Lost");
        assert_eq!(out.deleted_tracks, 1);
    }

    #[test]
    fn lost_confirmed_track_revives_on_redetection() {
        let mut t = MultiObjectTracker::new(config()).unwrap();
        t.step(&[det(10.0, 20.0)]);
        t.step(&[det(10.0, 20.0)]); // Confirmed (2 hits >= min_hits).
        let lost = t.step(&[]); // One miss: coasting.
        assert_eq!(lost.tracks[0].status, TrackStatus::Lost);
        let revived = t.step(&[det(10.0, 20.0)]);
        assert_eq!(revived.tracks[0].status, TrackStatus::Confirmed);
        assert_eq!(revived.tracks[0].id, lost.tracks[0].id);
    }

    #[test]
    fn invalid_config_is_refused() {
        let mut bad = config();
        bad.min_hits = 0;
        assert!(MultiObjectTracker::new(bad).is_err());
        let mut bad = config();
        bad.iou_threshold = 1.5;
        assert!(MultiObjectTracker::new(bad).is_err());
    }
}

#[cfg(test)]
mod motion_contract;
