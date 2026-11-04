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
    /// The zone's own polygon is degenerate (caller must validate the zone first).
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

/// One continuous interval during which a sample sequence was inside a zone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZoneDwellInterval {
    /// Timestamp of the first sample found inside the zone for this interval.
    pub enter_ns: u64,
    /// Timestamp of the last sample found inside the zone for this interval,
    /// before either an outside sample or the sequence ended.
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

impl SiteZone {
    /// Exact point-in-polygon containment test against this zone's own simple
    /// polygon, using the even-odd (crossing-number) rule in `i64` arithmetic;
    /// no floating point. The caller's own `SiteZone::validate` (via
    /// `SiteSource::validate`) already bounds vertex count and coordinate
    /// range; this method does not re-validate the zone and returns an
    /// arbitrary (but deterministic) result for a zone that was never
    /// validated. Exact classification of a point that lies precisely on an
    /// edge is an implementation detail of the crossing-number rule, not a
    /// documented guarantee either way; see the boundary cases in this
    /// module's tests for what the current implementation actually does.
    #[must_use]
    pub fn contains_point(&self, x: u32, y: u32) -> bool {
        let (x, y) = (i64::from(x), i64::from(y));
        let vertices = &self.vertices;
        let mut inside = false;
        let mut j = vertices.len().wrapping_sub(1);
        for i in 0..vertices.len() {
            let (xi, yi) = (i64::from(vertices[i][0]), i64::from(vertices[i][1]));
            let (xj, yj) = (i64::from(vertices[j][0]), i64::from(vertices[j][1]));
            if (yi > y) != (yj > y) {
                let x_intersect = xi + (y - yi) * (xj - xi) / (yj - yi);
                if x < x_intersect {
                    inside = !inside;
                }
            }
            j = i;
        }
        inside
    }

    /// Reduce a time-ordered sample sequence to the continuous intervals
    /// during which the point was inside this zone. An empty input yields an
    /// empty output, never an error. Samples out of range, out of order, or
    /// over the bound are refused whole; nothing is silently dropped,
    /// clamped or reordered.
    pub fn dwell_intervals(
        &self,
        samples: &[ZoneSample],
    ) -> Result<Vec<ZoneDwellInterval>, ZoneDwellError> {
        if self.vertices.len() < 3 {
            return Err(ZoneDwellError::Zone);
        }
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
            if self.contains_point(sample.x, sample.y) {
                open = Some(match open {
                    None => ZoneDwellInterval {
                        enter_ns: sample.at_ns,
                        exit_ns: sample.at_ns,
                    },
                    Some(interval) => ZoneDwellInterval {
                        enter_ns: interval.enter_ns,
                        exit_ns: sample.at_ns,
                    },
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

    #[test]
    fn interior_and_exterior_points_are_classified_correctly() {
        let zone = square(1000);
        assert!(zone.contains_point(500, 500));
        assert!(!zone.contains_point(1500, 500));
        assert!(!zone.contains_point(500, 1500));
        assert!(!zone.contains_point(2000, 2000));
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
    fn one_continuous_visit_becomes_one_interval_spanning_entry_to_exit() -> Test {
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
}
