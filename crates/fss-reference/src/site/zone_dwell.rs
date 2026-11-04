#![forbid(unsafe_code)]
//! Pure zone containment and dwell-interval reduction (VIT-012, smallest slice).
//!
//! This is the geometric/temporal primitive every zone-based QSR observation in
//! the plan (queue length, register presence, door-open duration, lane-stage
//! timing) would reduce to: "was this tracked point inside this declared zone,
//! and for how long." It does not itself classify an observation kind, attach
//! a coverage witness, or bind a model/policy generation — those are separate,
//! not-yet-built parts of VIT-012. No model, camera, network or clock
//! acquisition happens here; every input is a caller-supplied sample.

use super::{SITE_COORDINATE_SCALE, SiteZone};

/// Maximum samples reduced in one call. Bounded the same way every other input
/// to this crate is bounded; a longer session is the caller's to chunk.
pub const MAX_ZONE_SAMPLES: usize = 1_000_000;

/// Pure refusal categories; no coordinate or timestamp value is ever rendered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZoneDwellError {
    /// The zone's polygon is invalid, including its vertex and coordinate bounds.
    Zone,
    /// A sample's `at_ns` is not strictly increasing, or a coordinate exceeds
    /// [`SITE_COORDINATE_SCALE`]. Samples are refused whole, never reordered.
    Samples,
    /// More than [`MAX_ZONE_SAMPLES`] samples were supplied in one call.
    Limit,
}
impl ZoneDwellError {
    /// Stable, non-disclosing diagnostic identity.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Zone => "ERR-SITE-ZONE-DWELL-ZONE-001",
            Self::Samples => "ERR-SITE-ZONE-DWELL-SAMPLES-001",
            Self::Limit => "ERR-SITE-ZONE-DWELL-LIMIT-001",
        }
    }
}
impl std::fmt::Display for ZoneDwellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for ZoneDwellError {}

/// One timestamped 2D sample in the same normalized-millionths space as a
/// [`SiteZone`]'s vertices (see [`SITE_COORDINATE_SCALE`]). The caller decides
/// what the point represents (a track centroid, a single detection corner,
/// and so on); this module only ever tests it against a polygon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZoneSample {
    /// Monotonic or wall-clock nanosecond timestamp; the caller's choice, not
    /// interpreted here. Samples passed to [`SiteZone::dwell_intervals`] must
    /// be strictly increasing in this field.
    pub at_ns: u64,
    /// X coordinate, normalized millionths of the image, inclusive outer edge.
    pub x: u32,
    /// Y coordinate, normalized millionths of the image, inclusive outer edge.
    pub y: u32,
}

/// One maximal run of supplied samples strictly inside a zone. This is a sampled
/// span, not proof of continuous presence between its endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZoneDwellInterval {
    /// Timestamp of the first sample found inside the zone for this interval.
    pub enter_ns: u64,
    /// Timestamp of the last sample found inside the zone for this interval,
    /// before an outside/boundary sample, an excessive sampling gap (when a
    /// maximum gap was requested), or the end of the sequence.
    pub exit_ns: u64,
}
impl ZoneDwellInterval {
    /// Duration from the first to the last inside sample. Zero when a single
    /// isolated sample was inside (there is no next sample to bound the exit
    /// moment any tighter); this is the resolution of the sample sequence
    /// itself, not a claim about continuous presence between samples.
    #[must_use]
    pub const fn duration_ns(&self) -> u64 {
        self.exit_ns.saturating_sub(self.enter_ns)
    }
}

fn valid_coordinate(value: u32) -> bool {
    value <= SITE_COORDINATE_SCALE
}

// The caller validates the polygon and point coordinates before entering this
// loop. At normalized-millionth scale each cross product fits exactly in i64.
// Keep validation outside the per-sample loop when reducing a long sequence.
fn contains_validated_point(vertices: &[[u32; 2]], x: u32, y: u32) -> bool {
    let (x, y) = (i64::from(x), i64::from(y));
    let mut inside = false;
    for (i, &[xi, yi]) in vertices.iter().enumerate() {
        let [xj, yj] = vertices[(i + 1) % vertices.len()];
        let (xi, yi, xj, yj) = (i64::from(xi), i64::from(yi), i64::from(xj), i64::from(yj));
        let cross = (xj - xi) * (y - yi) - (yj - yi) * (x - xi);
        if cross == 0
            && (xi.min(xj)..=xi.max(xj)).contains(&x)
            && (yi.min(yj)..=yi.max(yj)).contains(&y)
        {
            return false;
        }
        // A straddling edge crosses the ray to the right exactly when cross
        // and its vertical direction have the same sign. Comparing products
        // avoids rounding an intersection inward or outward, and preserves
        // the result under either polygon winding.
        if (yi > y) != (yj > y) && ((cross > 0 && yj > yi) || (cross < 0 && yj < yi)) {
            inside = !inside;
        }
    }
    inside
}

impl SiteZone {
    /// Exact strict-interior membership in this zone's simple polygon, using
    /// integer cross products and the even-odd rule. Points on any edge or
    /// vertex are excluded, independent of vertex winding or starting vertex.
    ///
    /// An invalid polygon or out-of-range point returns false. Call
    /// [`Self::dwell_intervals`] when invalid input must be distinguished from
    /// an outside point through a typed refusal. This method validates the
    /// polygon on each call; the sequence reducers validate it only once.
    #[must_use]
    pub fn contains_point(&self, x: u32, y: u32) -> bool {
        valid_coordinate(x)
            && valid_coordinate(y)
            && super::polygon(&self.vertices).is_ok()
            && contains_validated_point(&self.vertices, x, y)
    }

    /// Group consecutive supplied samples strictly inside this zone into
    /// sampled spans. This compatibility method imposes no maximum sampling
    /// gap, so a span may include arbitrarily long periods without samples.
    /// Use [`Self::dwell_intervals_with_max_gap`] to split such periods.
    ///
    /// The polygon and complete sample sequence are validated before reducing;
    /// invalid input is refused whole. An empty sequence for a valid polygon
    /// returns an empty result, which is not evidence of absence or coverage.
    pub fn dwell_intervals(
        &self,
        samples: &[ZoneSample],
    ) -> Result<Vec<ZoneDwellInterval>, ZoneDwellError> {
        self.dwell_intervals_with_max_gap(samples, u64::MAX)
    }

    /// Group strictly inside samples, splitting whenever consecutive sample
    /// times differ by more than `maximum_sample_gap_ns`. Equality is admitted;
    /// zero keeps every inside sample as its own zero-duration interval. An
    /// outside or boundary sample always ends a span.
    ///
    /// The gap is a caller-selected sampling constraint, not a coverage
    /// witness. No interpolation, continuous-presence claim, or claim about
    /// the unobserved time between samples is made. Callers must supply one
    /// ordered source/track/zone generation and handle discontinuities and
    /// observation eligibility before this geometric reduction.
    ///
    /// Polygon validation runs once. With `v` vertices and `n` samples, work
    /// is bounded by `O(v² + n*v)` and output by at most `n` intervals, where
    /// `v <= MAX_ZONE_VERTICES` and `n <= MAX_ZONE_SAMPLES`. Inputs outside
    /// these bounds, malformed polygons, and invalid sample sequences are
    /// refused whole; no partial result is returned or silently truncated.
    pub fn dwell_intervals_with_max_gap(
        &self,
        samples: &[ZoneSample],
        maximum_sample_gap_ns: u64,
    ) -> Result<Vec<ZoneDwellInterval>, ZoneDwellError> {
        super::polygon(&self.vertices).map_err(|_| ZoneDwellError::Zone)?;
        if samples.len() > MAX_ZONE_SAMPLES {
            return Err(ZoneDwellError::Limit);
        }
        let mut last_at_ns: Option<u64> = None;
        for sample in samples {
            if !valid_coordinate(sample.x)
                || !valid_coordinate(sample.y)
                || last_at_ns.is_some_and(|last| sample.at_ns <= last)
            {
                return Err(ZoneDwellError::Samples);
            }
            last_at_ns = Some(sample.at_ns);
        }
        let mut intervals = Vec::new();
        let mut open: Option<ZoneDwellInterval> = None;
        for sample in samples {
            if contains_validated_point(&self.vertices, sample.x, sample.y) {
                if let Some(interval) = open.as_mut()
                    && sample.at_ns - interval.exit_ns <= maximum_sample_gap_ns
                {
                    // Strictly increasing timestamps were checked above, so
                    // this subtraction is exact even at the u64 endpoints.
                    interval.exit_ns = sample.at_ns;
                    continue;
                }
                if let Some(interval) = open.take() {
                    intervals.push(interval);
                }
                open = Some(ZoneDwellInterval {
                    enter_ns: sample.at_ns,
                    exit_ns: sample.at_ns,
                });
            } else if let Some(interval) = open.take() {
                intervals.push(interval);
            }
        }
        if let Some(interval) = open {
            intervals.push(interval);
        }
        Ok(intervals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Test = Result<(), Box<dyn std::error::Error>>;

    // A 2x2 (normalized-millionths) square, matching the kind of polygon
    // `SiteZone::validate` already admits elsewhere in this crate.
    fn square(side: u32) -> SiteZone {
        SiteZone {
            zone_id: "zone:test".to_owned(),
            kind: "door".to_owned(),
            vertices: vec![[0, 0], [side, 0], [side, side], [0, side]],
        }
    }

    fn sample(at_ns: u64, x: u32, y: u32) -> ZoneSample {
        ZoneSample { at_ns, x, y }
    }

    fn interval(enter_ns: u64, exit_ns: u64) -> ZoneDwellInterval {
        ZoneDwellInterval { enter_ns, exit_ns }
    }

    #[test]
    fn interior_and_exterior_points_are_classified_correctly() {
        let zone = square(1000);
        assert!(zone.contains_point(500, 500));
        assert!(!zone.contains_point(1500, 500));
        assert!(!zone.contains_point(500, 1500));
        assert!(!zone.contains_point(2000, 2000));
    }

    #[test]
    fn sloped_edges_do_not_round_away_interior_or_create_exterior_points() {
        let mut zone = SiteZone {
            zone_id: "zone:triangle".to_owned(),
            kind: "other".to_owned(),
            vertices: vec![[0, 0], [5, 0], [2, 5]],
        };
        for _ in 0..2 {
            // At y=1 the exact horizontal extent is (2/5, 22/5).
            assert!(zone.contains_point(4, 1));
            assert!(!zone.contains_point(0, 1));
            zone.vertices.reverse();
        }
    }

    #[test]
    fn containment_matches_independent_shapes_under_every_vertex_ordering() {
        type ShapeCase = (Vec<[u32; 2]>, fn(u32, u32) -> bool);
        let cases: [ShapeCase; 2] = [
            (
                vec![[0, 0], [5, 0], [2, 5]],
                // Exact strict half-planes for this triangle.
                |x, y| y > 0 && 5 * x > 2 * y && 5 * x + 3 * y < 25,
            ),
            (
                vec![[0, 0], [10, 0], [10, 5], [5, 5], [5, 10], [0, 10]],
                // The L shape's strict interior, including the inner seams.
                |x, y| x > 0 && y > 0 && ((x < 10 && y < 5) || (x < 5 && y < 10)),
            ),
        ];
        for (vertices, expected) in cases {
            let mut zone = square(1);
            zone.vertices = vertices;
            for _ in 0..2 {
                for _ in 0..zone.vertices.len() {
                    for x in 0..=12 {
                        for y in 0..=12 {
                            assert_eq!(
                                zone.contains_point(x, y),
                                expected(x, y),
                                "point ({x}, {y}), vertices {:?}",
                                zone.vertices
                            );
                        }
                    }
                    zone.vertices.rotate_left(1);
                }
                zone.vertices.reverse();
            }
        }
    }

    #[test]
    fn every_boundary_is_excluded_including_sloped_edges_and_concave_vertices() {
        let zone = square(10);
        for p in 0..=10 {
            assert!(!zone.contains_point(p, 0));
            assert!(!zone.contains_point(p, 10));
            assert!(!zone.contains_point(0, p));
            assert!(!zone.contains_point(10, p));
        }
        let mut triangle = square(1);
        triangle.vertices = vec![[0, 0], [10, 0], [4, 10]];
        for point in [[0, 0], [10, 0], [4, 10], [5, 0], [2, 5], [7, 5]] {
            assert!(!triangle.contains_point(point[0], point[1]));
        }
        let mut concave = square(1);
        concave.vertices = vec![[0, 0], [10, 0], [10, 5], [5, 5], [5, 10], [0, 10]];
        assert!(!concave.contains_point(5, 5));
        assert!(concave.contains_point(5, 4));
        assert!(concave.contains_point(4, 5));
    }

    #[test]
    fn normalized_coordinate_extremes_are_exact_and_unbounded_points_fail_closed() {
        let zone = square(SITE_COORDINATE_SCALE);
        assert!(zone.contains_point(1, 1));
        assert!(zone.contains_point(SITE_COORDINATE_SCALE - 1, SITE_COORDINATE_SCALE - 1));
        assert!(!zone.contains_point(SITE_COORDINATE_SCALE, SITE_COORDINATE_SCALE / 2));
        assert!(!zone.contains_point(u32::MAX, 1));
        assert!(!zone.contains_point(1, u32::MAX));
        assert!(!zone.contains_point(u32::MAX, u32::MAX));

        let mut triangle = square(1);
        triangle.vertices = vec![
            [0, 0],
            [SITE_COORDINATE_SCALE, 0],
            [0, SITE_COORDINATE_SCALE],
        ];
        assert!(triangle.contains_point(SITE_COORDINATE_SCALE - 2, 1));
        assert!(!triangle.contains_point(SITE_COORDINATE_SCALE - 1, 1));
        assert!(!triangle.contains_point(SITE_COORDINATE_SCALE - 1, 2));
    }

    #[test]
    fn a_concave_zone_excludes_its_own_notch() {
        // An L shape: the notch at (750, 750) is outside, even though it sits
        // inside the shape's own bounding box.
        let zone = SiteZone {
            zone_id: "zone:l".to_owned(),
            kind: "other".to_owned(),
            vertices: vec![
                [0, 0],
                [1000, 0],
                [1000, 500],
                [500, 500],
                [500, 1000],
                [0, 1000],
            ],
        };
        assert!(zone.contains_point(250, 250));
        assert!(!zone.contains_point(750, 750));
    }

    #[test]
    fn empty_and_single_sample_sequences_behave() -> Test {
        let zone = square(1000);
        assert_eq!(zone.dwell_intervals(&[])?, vec![]);
        let inside = zone.dwell_intervals(&[sample(1, 500, 500)])?;
        assert_eq!(
            inside,
            vec![ZoneDwellInterval {
                enter_ns: 1,
                exit_ns: 1
            }]
        );
        assert_eq!(inside[0].duration_ns(), 0);
        assert_eq!(zone.dwell_intervals(&[sample(1, 5000, 5000)])?, vec![]);
        Ok(())
    }

    #[test]
    fn one_sampled_visit_becomes_one_interval_spanning_entry_to_exit() -> Test {
        let zone = square(1000);
        let intervals = zone.dwell_intervals(&[
            sample(100, 5000, 5000), // outside
            sample(200, 500, 500),   // enter
            sample(300, 600, 600),   // inside
            sample(400, 700, 700),   // inside, last inside sample
            sample(500, 5000, 5000), // outside again
        ])?;
        assert_eq!(
            intervals,
            vec![ZoneDwellInterval {
                enter_ns: 200,
                exit_ns: 400
            }]
        );
        assert_eq!(intervals[0].duration_ns(), 200);
        Ok(())
    }

    #[test]
    fn separate_visits_become_separate_intervals_including_a_trailing_open_one() -> Test {
        let zone = square(1000);
        let intervals = zone.dwell_intervals(&[
            sample(100, 500, 500),   // visit 1 start
            sample(200, 500, 500),   // visit 1 end
            sample(300, 5000, 5000), // outside, between visits
            sample(400, 500, 500),   // visit 2 start, still open at sequence end
        ])?;
        assert_eq!(
            intervals,
            vec![
                ZoneDwellInterval {
                    enter_ns: 100,
                    exit_ns: 200
                },
                ZoneDwellInterval {
                    enter_ns: 400,
                    exit_ns: 400
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn out_of_order_or_out_of_range_samples_are_refused_whole() {
        let zone = square(1000);
        assert_eq!(
            zone.dwell_intervals(&[sample(10, 0, 0), sample(10, 1, 1)]),
            Err(ZoneDwellError::Samples)
        ); // not strictly increasing
        assert_eq!(
            zone.dwell_intervals(&[sample(20, 0, 0), sample(10, 1, 1)]),
            Err(ZoneDwellError::Samples)
        ); // out of order
        assert_eq!(
            zone.dwell_intervals(&[sample(10, SITE_COORDINATE_SCALE + 1, 0)]),
            Err(ZoneDwellError::Samples)
        ); // out of coordinate range
    }

    #[test]
    fn a_degenerate_zone_refuses_rather_than_guessing() {
        let zone = SiteZone {
            zone_id: "zone:bad".to_owned(),
            kind: "other".to_owned(),
            vertices: vec![[0, 0], [1, 1]],
        };
        assert_eq!(
            zone.dwell_intervals(&[sample(1, 0, 0)]),
            Err(ZoneDwellError::Zone)
        );
    }

    #[test]
    fn complete_polygon_validation_is_required_even_for_empty_samples() {
        let invalid = [
            vec![],
            vec![[0, 0], [1, 1]],
            vec![[0, 0], [1, 1], [2, 2]],
            vec![[0, 0], [10, 0], [10, 10], [10, 0], [0, 10]],
            vec![[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]],
            // Self-intersection with nonzero signed area, so area alone is
            // insufficient to detect it.
            vec![[0, 0], [10, 10], [0, 10], [8, 0]],
            vec![[0, 0], [SITE_COORDINATE_SCALE + 1, 0], [0, 10]],
            vec![[0, 0], [10, 0], [0, u32::MAX]],
        ];
        for vertices in invalid {
            let mut zone = square(1);
            zone.vertices = vertices;
            assert!(!zone.contains_point(1, 1));
            for samples in [&[][..], &[sample(1, 1, 1)][..]] {
                assert_eq!(zone.dwell_intervals(samples), Err(ZoneDwellError::Zone));
                assert_eq!(
                    zone.dwell_intervals_with_max_gap(samples, 10),
                    Err(ZoneDwellError::Zone)
                );
            }
        }
    }

    #[test]
    fn the_polygon_vertex_budget_is_enforced_without_rejecting_its_exact_limit() -> Test {
        // Collinear subdivisions along a rectangle are valid, distinct
        // vertices. Both inputs would otherwise describe a simple polygon.
        fn rectangle(vertex_count: usize) -> SiteZone {
            let mut zone = square(1);
            zone.vertices = (0..vertex_count - 2).map(|x| [x as u32, 0]).collect();
            zone.vertices.push([(vertex_count - 3) as u32, 10]);
            zone.vertices.push([0, 10]);
            zone
        }
        let samples = [sample(1, 1, 1), sample(2, 1, 1)];
        let zone = rectangle(super::super::MAX_ZONE_VERTICES);
        assert!(zone.contains_point(1, 1));
        assert_eq!(zone.dwell_intervals(&samples)?, vec![interval(1, 2)]);
        assert_eq!(
            zone.dwell_intervals_with_max_gap(&samples, 1)?,
            vec![interval(1, 2)]
        );
        let oversized = rectangle(super::super::MAX_ZONE_VERTICES + 1);
        assert!(!oversized.contains_point(1, 1));
        assert_eq!(
            oversized.dwell_intervals(&samples),
            Err(ZoneDwellError::Zone)
        );
        assert_eq!(
            oversized.dwell_intervals_with_max_gap(&samples, 1),
            Err(ZoneDwellError::Zone)
        );
        Ok(())
    }

    #[test]
    fn missing_sample_time_splits_dwell_without_inflating_its_duration() -> Test {
        let zone = square(10);
        let samples = [
            sample(0, 5, 5),
            sample(1, 5, 5),
            sample(1000, 5, 5),
            sample(1001, 5, 5),
        ];
        let bounded = zone.dwell_intervals_with_max_gap(&samples, 1)?;
        assert_eq!(bounded, vec![interval(0, 1), interval(1000, 1001)]);
        assert_eq!(
            bounded
                .iter()
                .map(ZoneDwellInterval::duration_ns)
                .sum::<u64>(),
            2
        );
        // Retain the previous API's explicitly unbounded sampled-span behavior.
        assert_eq!(zone.dwell_intervals(&samples)?, vec![interval(0, 1001)]);
        Ok(())
    }

    #[test]
    fn exact_gap_threshold_is_inclusive_and_boundary_samples_end_spans() -> Test {
        let zone = square(10);
        let samples = [
            sample(0, 5, 5),
            sample(10, 5, 5),
            sample(21, 5, 5),
            sample(31, 5, 5),
            sample(32, 0, 5), // Boundary is not an inside observation.
            sample(33, 5, 5),
            sample(34, 11, 5), // Outside terminates the final span.
        ];
        assert_eq!(
            zone.dwell_intervals_with_max_gap(&samples, 10)?,
            vec![interval(0, 10), interval(21, 31), interval(33, 33)]
        );
        assert_eq!(
            zone.dwell_intervals(&samples)?,
            vec![interval(0, 31), interval(33, 33)]
        );
        Ok(())
    }

    #[test]
    fn zero_gap_preserves_individual_observations_and_empty_results() -> Test {
        let zone = square(10);
        assert_eq!(zone.dwell_intervals_with_max_gap(&[], 0)?, vec![]);
        assert_eq!(
            zone.dwell_intervals_with_max_gap(&[sample(1, 0, 5), sample(2, 11, 5)], 0)?,
            vec![]
        );
        assert_eq!(
            zone.dwell_intervals_with_max_gap(&[sample(1, 5, 5), sample(2, 5, 5)], 0)?,
            vec![interval(1, 1), interval(2, 2)]
        );
        Ok(())
    }

    #[test]
    fn timestamp_extremes_use_exact_gap_arithmetic() -> Test {
        let zone = square(10);
        let endpoints = [sample(0, 5, 5), sample(u64::MAX, 5, 5)];
        assert_eq!(
            zone.dwell_intervals_with_max_gap(&endpoints, u64::MAX)?,
            vec![interval(0, u64::MAX)]
        );
        assert_eq!(
            zone.dwell_intervals_with_max_gap(&endpoints, u64::MAX - 1)?,
            vec![interval(0, 0), interval(u64::MAX, u64::MAX)]
        );
        let near_end = [sample(u64::MAX - 1, 5, 5), sample(u64::MAX, 5, 5)];
        assert_eq!(
            zone.dwell_intervals_with_max_gap(&near_end, 1)?,
            vec![interval(u64::MAX - 1, u64::MAX)]
        );
        Ok(())
    }

    #[test]
    fn malformed_sample_tail_refuses_the_complete_result_for_both_reducers() {
        let zone = square(10);
        let valid = [sample(1, 5, 5), sample(2, 5, 5), sample(3, 20, 20)];
        for invalid_tail in [
            sample(3, 5, 5),
            sample(0, 5, 5),
            sample(4, SITE_COORDINATE_SCALE + 1, 5),
            sample(4, 5, u32::MAX),
        ] {
            let mut samples = valid.to_vec();
            samples.push(invalid_tail);
            assert_eq!(zone.dwell_intervals(&samples), Err(ZoneDwellError::Samples));
            assert_eq!(
                zone.dwell_intervals_with_max_gap(&samples, 1),
                Err(ZoneDwellError::Samples)
            );
        }
    }

    #[test]
    fn million_sample_and_output_limits_are_exact_and_never_truncated() -> Test {
        let zone = square(10);
        let samples: Vec<_> = (0..=MAX_ZONE_SAMPLES)
            .map(|i| sample(i as u64, 5, 5))
            .collect();
        let admitted = &samples[..MAX_ZONE_SAMPLES];
        assert_eq!(
            zone.dwell_intervals(admitted)?,
            vec![interval(0, MAX_ZONE_SAMPLES as u64 - 1)]
        );
        // Every admitted observation can be a separate span, but no method
        // can emit more spans than input samples.
        let intervals = zone.dwell_intervals_with_max_gap(admitted, 0)?;
        assert_eq!(intervals.len(), MAX_ZONE_SAMPLES);
        for (i, result) in intervals.iter().enumerate() {
            assert_eq!(*result, interval(i as u64, i as u64));
        }
        assert_eq!(zone.dwell_intervals(&samples), Err(ZoneDwellError::Limit));
        assert_eq!(
            zone.dwell_intervals_with_max_gap(&samples, 0),
            Err(ZoneDwellError::Limit)
        );
        Ok(())
    }
}
