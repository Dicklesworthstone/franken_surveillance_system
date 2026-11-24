#![forbid(unsafe_code)]
//! Calibrated 2D image foot-point → ground-plane homography projection with explicit
//! singularity/horizon guards and spatial relation descriptors.

use fss_core::CanonicalEncoder;

use crate::ingest::recorded_corroboration::GroundHomography;

use super::LiveCorroborateError;

/// Calibrated 2D image foot-point → ground-plane homography with explicit distance gate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CameraHomography {
    /// Row-major 3x3 planar homography matrix `h11..h33`.
    pub matrix: [f64; 9],
    /// Maximum ground-plane Euclidean distance between two projected foot-points (ground units).
    pub distance_gate: f64,
}

impl CameraHomography {
    /// Constructs a [`CameraHomography`] from an existing [`GroundHomography`] and distance gate.
    #[must_use]
    pub const fn from_ground_homography(homography: GroundHomography, distance_gate: f64) -> Self {
        Self {
            matrix: homography.matrix,
            distance_gate,
        }
    }

    /// Validates finiteness, non-singularity, and a positive finite distance gate.
    pub fn validate(&self) -> Result<(), LiveCorroborateError> {
        if !self.matrix.iter().all(|v| v.is_finite()) {
            return Err(LiveCorroborateError::InvalidTopology(
                "homography entry must be finite",
            ));
        }
        let scale = self.matrix.iter().fold(0.0_f64, |m, v| m.max(v.abs()));
        if scale == 0.0 {
            return Err(LiveCorroborateError::InvalidTopology(
                "homography matrix is zero",
            ));
        }
        let [a, b, c, d, e, f, g, h, i] = self.matrix.map(|v| v / scale);
        let det = a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g);
        if !det.is_finite() || det.abs() <= 1e-12 {
            return Err(LiveCorroborateError::InvalidTopology(
                "homography matrix is singular",
            ));
        }
        if !self.distance_gate.is_finite() || self.distance_gate <= 0.0 {
            return Err(LiveCorroborateError::InvalidTopology(
                "homography distance_gate must be finite and positive",
            ));
        }
        Ok(())
    }

    /// Projects an image foot-point `[u, v]` onto the ground plane `[x, y]`, or `None` if input is
    /// non-finite or maps to/beyond the ground horizon (`w <= scale * 1e-12`).
    #[must_use]
    pub fn project(&self, foot_px: [f64; 2]) -> Option<[f64; 2]> {
        let [u, v] = foot_px;
        if !u.is_finite() || !v.is_finite() {
            return None;
        }
        let [a, b, c, d, e, f, g, h, i] = self.matrix;
        let scale = self.matrix.iter().fold(0.0_f64, |m, x| m.max(x.abs()));
        let w = g * u + h * v + i;
        if !w.is_finite() || scale == 0.0 || w <= scale * 1e-12 {
            return None;
        }
        let x = (a * u + b * v + c) / w;
        let y = (d * u + e * v + f) / w;
        (x.is_finite() && y.is_finite()).then_some([x, y])
    }

    pub(crate) fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        for v in self.matrix {
            encoder.u64(canonical_f64_bits(v));
        }
        encoder.u64(canonical_f64_bits(self.distance_gate));
    }
}

/// Computes finite Euclidean distance between two ground-plane coordinates.
#[must_use]
pub fn ground_distance(a: [f64; 2], b: [f64; 2]) -> Option<f64> {
    if !a[0].is_finite() || !a[1].is_finite() || !b[0].is_finite() || !b[1].is_finite() {
        return None;
    }
    let d = (a[0] - b[0]).hypot(a[1] - b[1]);
    d.is_finite().then_some(d)
}

/// Spatial or corridor link evaluated between two observations from distinct cameras.
#[derive(Clone, Debug, PartialEq)]
pub enum SpatialRelation {
    /// Both cameras projected foot-points onto the shared ground plane within distance gate.
    GroundProximity {
        /// Euclidean ground distance between projected foot-points.
        distance: f64,
        /// Effective distance gate (`min(gate_a, gate_b)`).
        distance_gate: f64,
        /// Projected ground coordinates for observation A.
        ground_a: [f64; 2],
        /// Projected ground coordinates for observation B.
        ground_b: [f64; 2],
        /// Simultaneous worst-case time gate (ns).
        time_gate_ns: u64,
        /// Canonical zone label for the overlap.
        zone_id: String,
    },
    /// One camera's homography rejected a foot-point at or beyond the ground horizon.
    HorizonRefused {
        /// Camera whose homography refused projection.
        camera: String,
    },
    /// Both cameras observed the same declared coarse [`super::SharedZoneOverlap`].
    SharedZone {
        /// Shared zone identifier.
        zone_id: String,
        /// Maximum simultaneous separation (ns).
        max_separation_ns: u64,
    },
    /// Observations match a declared [`super::TransitCorridor`].
    TransitCorridor {
        /// Corridor identifier.
        corridor_id: String,
        /// Origin camera ID along the matched traversal direction.
        from_camera: String,
        /// Origin zone ID along the matched traversal direction.
        from_zone: String,
        /// Destination camera ID along the matched traversal direction.
        to_camera: String,
        /// Destination zone ID along the matched traversal direction.
        to_zone: String,
        /// Minimum admissible transit duration (ns).
        min_transit_ns: u64,
        /// Maximum admissible transit duration (ns).
        max_transit_ns: u64,
        /// `true` if A is origin and B is destination; `false` if B is origin and A is destination.
        direction_a_to_b: bool,
    },
    /// No overlapping ground proximity, shared zone, or transit corridor connects these observations.
    NoOverlap,
}

fn canonical_f64_bits(v: f64) -> u64 {
    if v == 0.0 {
        0.0_f64.to_bits()
    } else {
        v.to_bits()
    }
}
