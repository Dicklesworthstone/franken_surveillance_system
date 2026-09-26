#![forbid(unsafe_code)]
//! Exact one-to-one observation witnesses from the tracker's own state transition.

use super::{Detection, MultiObjectTracker, TrackerOutput};

/// Provenance semantics, separate from the unchanged numerical tracking algorithm.
pub const TRACK_ASSIGNMENT_POLICY: &str =
    "fss.track_assignment.v1:original-input-index:actual-global-assignment:new-track-included:no-prediction-observation";

/// One input detection actually used to update or create a track in this frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrackAssignment {
    /// Stable tracker identity (not the index of a vector that can be swap-removed).
    pub track_id: u64,
    /// Index in the caller's original detection slice, before canonical sorting.
    pub detection_index: usize,
}

/// One atomic step and its complete, track-id-ordered observation witness.
#[derive(Clone, Debug)]
pub struct AssignedTrackerOutput {
    /// Identical state output to the compatibility API for identical admitted inputs.
    pub output: TrackerOutput,
    /// One entry per input detection. Coasting tracks have no entry.
    pub assignments: Vec<TrackAssignment>,
}
impl AssignedTrackerOutput {
    /// Returns the original input index actually assigned to this track, or `None` when the
    /// track was not observed. This never searches for a nearby box or invents an association.
    #[must_use]
    pub fn observed_detection(&self, track_id: u64) -> Option<usize> {
        self.assignments
            .binary_search_by_key(&track_id, |assignment| assignment.track_id)
            .ok()
            .map(|index| self.assignments[index].detection_index)
    }
}

impl MultiObjectTracker {
    // Only the checked path exposes this result. Both APIs use the same solver and update;
    // callback recording adds bounded bookkeeping, not a competing association algorithm.
    pub(super) fn step_assigned(&mut self, detections: &[Detection]) -> AssignedTrackerOutput {
        let mut assignments = Vec::with_capacity(detections.len());
        let output = self.step_observed(detections, |track_id, detection_index| {
            assignments.push(TrackAssignment { track_id, detection_index });
        });
        assignments.sort_unstable_by_key(|assignment| assignment.track_id);
        AssignedTrackerOutput { output, assignments }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{TrackStatus, TrackerConfig, TrackerLimits, TrackerStepError, iou};
    use std::collections::BTreeSet;

    type Result = std::result::Result<(), Box<dyn std::error::Error>>;

    fn config() -> TrackerConfig {
        TrackerConfig {
            min_hits: 2, max_misses: 2, iou_threshold: 0.1,
            process_noise: 1.0, measurement_noise: 1.0,
        }
    }
    fn detection(x: f64) -> Detection {
        Detection { box_x: x, box_y: 0.0, box_w: 20.0, box_h: 20.0 }
    }
    fn complete(result: &AssignedTrackerOutput, count: usize) {
        assert_eq!(result.assignments.len(), count);
        let rows: BTreeSet<_> = result.assignments.iter().map(|a| a.detection_index).collect();
        assert_eq!(rows, (0..count).collect());
        let ids: BTreeSet<_> = result.assignments.iter().map(|a| a.track_id).collect();
        assert_eq!(ids.len(), count);
        assert!(result.assignments.windows(2).all(|a| a[0].track_id < a[1].track_id));
        for track in &result.output.tracks {
            assert_eq!(result.observed_detection(track.id).is_some(), track.misses == 0);
        }
        assert_eq!(result.observed_detection(u64::MAX), None);
    }

    #[test]
    fn global_assignment_is_not_replaced_by_nearest_filtered_box() -> Result {
        let mut cfg = config();
        cfg.measurement_noise = 10_000.0;
        let mut tracker = MultiObjectTracker::new(cfg)?;
        tracker.try_step_assigned(&[detection(0.0), detection(8.0)], TrackerLimits::default())?;
        let detections = [detection(2.0), detection(20.0)];
        let result = tracker.try_step_assigned(&detections, TrackerLimits::default())?;
        complete(&result, 2);
        assert_eq!(result.observed_detection(1), Some(0));
        assert_eq!(result.observed_detection(2), Some(1));
        // High measurement uncertainty keeps both filtered boxes near the first observation.
        // The old downstream nearest-IoU reconstruction therefore borrows row zero twice.
        for track in &result.output.tracks {
            let overlaps: Vec<_> = detections.iter().map(|d| iou(
                track.cx - track.box_w / 2.0, track.cy - track.box_h / 2.0,
                track.box_w, track.box_h, d.box_x, d.box_y, d.box_w, d.box_h,
            )).collect();
            assert!(overlaps[0] > overlaps[1]);
        }
        Ok(())
    }

    #[test]
    fn identical_boxes_keep_distinct_original_rows() -> Result {
        let mut tracker = MultiObjectTracker::new(config())?;
        for _ in 0..4 {
            let result = tracker.try_step_assigned(&[detection(0.0), detection(0.0)], TrackerLimits::default())?;
            complete(&result, 2);
            assert_ne!(result.observed_detection(1), result.observed_detection(2));
        }
        Ok(())
    }

    #[test]
    fn canonical_sorting_does_not_renumber_the_callers_input() -> Result {
        let mut tracker = MultiObjectTracker::new(config())?;
        let initial = tracker.try_step_assigned(&[detection(100.0), detection(0.0)], TrackerLimits::default())?;
        assert_eq!(initial.observed_detection(1), Some(1));
        assert_eq!(initial.observed_detection(2), Some(0));
        let next = tracker.try_step_assigned(&[detection(0.0), detection(100.0)], TrackerLimits::default())?;
        assert_eq!(next.observed_detection(1), Some(0));
        assert_eq!(next.observed_detection(2), Some(1));
        complete(&next, 2);
        Ok(())
    }

    #[test]
    fn deletion_reordering_and_lost_tracks_do_not_acquire_an_observation() -> Result {
        let mut cfg = config();
        cfg.min_hits = 1;
        let mut tracker = MultiObjectTracker::new(cfg)?;
        tracker.try_step_assigned(&[detection(0.0), detection(100.0), detection(200.0)], TrackerLimits::default())?;
        for _ in 0..3 {
            let result = tracker.try_step_assigned(&[detection(100.0)], TrackerLimits::default())?;
            complete(&result, 1);
            assert_eq!(result.observed_detection(2), Some(0));
            assert_eq!(result.observed_detection(1), None);
            assert_eq!(result.observed_detection(3), None);
        }
        let empty = tracker.try_step_assigned(&[], TrackerLimits::default())?;
        complete(&empty, 0);
        assert_eq!(empty.output.tracks[0].status, TrackStatus::Lost);
        let revived = tracker.try_step_assigned(&[detection(100.0)], TrackerLimits::default())?;
        complete(&revived, 1);
        assert_eq!(revived.observed_detection(2), Some(0));
        Ok(())
    }

    #[test]
    fn failed_admission_returns_no_witness_and_does_not_spend_ids() -> Result {
        let mut tracker = MultiObjectTracker::new(config())?;
        let mut control = tracker.clone();
        let limits = TrackerLimits { max_tracks: 1, ..TrackerLimits::default() };
        assert!(matches!(tracker.try_step_assigned(&[detection(0.0), detection(100.0)], limits), Err(TrackerStepError::Limit)));
        assert!(matches!(tracker.try_step_assigned(&[detection(f64::NAN)], TrackerLimits::default()), Err(TrackerStepError::Detection)));
        let actual = tracker.try_step_assigned(&[detection(100.0)], TrackerLimits::default())?;
        let expected = control.try_step_assigned(&[detection(100.0)], TrackerLimits::default())?;
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
        Ok(())
    }

    #[test]
    fn adding_witnesses_preserves_legacy_motion_state_over_reordered_and_missing_frames() -> Result {
        for seed in 0..32_u64 {
            let mut legacy = MultiObjectTracker::new(config())?;
            let mut witnessed = legacy.clone();
            let mut state = seed + 1;
            for frame in 0..64 {
                state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let count = (state % 5) as usize;
                let mut detections: Vec<_> = (0..count).map(|i| detection(
                    i as f64 * 30.0 + f64::from(frame % 11),
                )).collect();
                if state & 0x100 != 0 { detections.reverse(); }
                let old = legacy.step(&detections);
                let new = witnessed.try_step_assigned(&detections, TrackerLimits::default())?;
                complete(&new, count);
                assert_eq!(format!("{old:?}"), format!("{:?}", new.output));
            }
        }
        Ok(())
    }
}
