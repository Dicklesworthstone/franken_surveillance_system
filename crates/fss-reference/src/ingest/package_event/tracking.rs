#![forbid(unsafe_code)]
//! One-to-one package observation provenance and source-discontinuity tracking epochs.

use std::collections::BTreeMap;

use super::{
    PackageDetectionRecord, PackageEventError, PackageObservation, PackageTrack,
    PackageTrackingBoundary, PackageTrackingConfig, Result, rounded,
};
use crate::ingest::detector_cascade::iou_ppm;
use crate::ingest::tracker::{Detection, MultiObjectTracker, TrackStatus, TrackerLimits};
use fss_core::ContentDigest;

/// Pure bounded frame composition. `checkpoint` is supplied by the authority-owning caller;
/// tests can exercise the same computation without filesystem or model dependencies.
pub(super) fn build_tracks(
    record: &PackageDetectionRecord,
    class_index: u64,
    config: PackageTrackingConfig,
    boundaries: &[PackageTrackingBoundary],
    mut checkpoint: impl FnMut() -> Result<()>,
) -> Result<Vec<PackageTrack>> {
    record.validate_shape()?;
    if class_index >= record.labels.len() as u64
        || boundaries
            .windows(2)
            .any(|pair| pair[0].before_segment >= pair[1].before_segment)
        || boundaries.iter().any(|boundary| {
            boundary.before_segment <= record.first_segment
                || boundary.before_segment >= record.first_segment + record.segment_count
                || !(boundary.source_gap || boundary.sequence_gap || boundary.dimensions_changed)
        })
    {
        return Err(PackageEventError::Mismatch);
    }
    let mut tracker = MultiObjectTracker::new(config.tracker()?)?;
    let mut tracks: BTreeMap<u64, PackageTrack> = BTreeMap::new();
    let mut epoch = 0;
    let mut id_base = 0_u64;
    let mut greatest_id = 0_u64;
    for frame in &record.frames {
        checkpoint()?;
        let frame_epoch =
            boundaries.partition_point(|boundary| boundary.before_segment <= frame.segment);
        if frame_epoch < epoch {
            // Display order may differ from source order within an epoch, but cannot return
            // across a discontinuity to revive pre-gap state. Never sort away this ambiguity.
            return Err(PackageEventError::InvalidRequest(
                "display order crosses a source discontinuity",
            ));
        }
        if frame_epoch != epoch {
            tracker = MultiObjectTracker::new(config.tracker()?)?;
            id_base = greatest_id;
            epoch = frame_epoch;
        }
        let chosen: Vec<_> = frame
            .detections
            .iter()
            .filter(|detection| detection.class_index == class_index)
            .collect();
        let detections: Vec<_> = chosen
            .iter()
            .map(|detection| Detection {
                box_x: f64::from(detection.bounds[0]) / 256.0,
                box_y: f64::from(detection.bounds[1]) / 256.0,
                box_w: f64::from(detection.bounds[2] - detection.bounds[0]) / 256.0,
                box_h: f64::from(detection.bounds[3] - detection.bounds[1]) / 256.0,
            })
            .collect();
        let result = tracker.try_step_assigned(&detections, TrackerLimits::default())?;
        for target in result
            .output
            .tracks
            .iter()
            .filter(|target| target.misses == 0)
        {
            let input_index = result
                .observed_detection(target.id)
                .ok_or(PackageEventError::Mismatch)?;
            let detection = chosen.get(input_index).ok_or(PackageEventError::Mismatch)?;
            let track_id = id_base
                .checked_add(target.id)
                .ok_or(PackageEventError::Limit)?;
            greatest_id = greatest_id.max(track_id);
            let track_box = [
                rounded(target.cx),
                rounded(target.cy),
                rounded(target.box_w),
                rounded(target.box_h),
            ];
            let entry = tracks.entry(track_id).or_insert_with(|| PackageTrack {
                identity: ContentDigest::sha256(&[]),
                track_id,
                confirmed: false,
                observations: Vec::new(),
            });
            entry.confirmed |= target.status == TrackStatus::Confirmed;
            entry.observations.push(PackageObservation {
                segment: frame.segment,
                capsule_digest: frame.capsule_digest,
                track_box,
                // This is the actual assigned source row, even if another detection has a
                // higher score or overlaps the filtered box more closely. The integer IoU is
                // descriptive geometry only; it cannot substitute a different source row.
                detection: Some((
                    detection.row,
                    detection.score_bits,
                    detection.bounds,
                    iou_ppm(detection.bounds, track_box),
                )),
            });
        }
    }
    Ok(tracks.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::super::{RecordDetection, RecordFrame};
    use super::*;
    use fss_core::{CaptureInterval, TimestampNs};
    use std::collections::BTreeSet;

    fn record(count: u64) -> PackageDetectionRecord {
        let d = ContentDigest::sha256(b"test");
        PackageDetectionRecord {
            report_digest: d,
            package_digest: d,
            manifest_digest: d,
            model_id: "MOD-TEST-001".into(),
            generation: "g1".into(),
            model_digest: d,
            graph_digest: d,
            contract_digest: d,
            import_identity: d,
            import_root: d,
            media_format: "mjpeg".into(),
            first_segment: 0,
            segment_count: count,
            minimum_score_ppm: 0,
            labels: vec!["person".into()],
            frames: (0..count)
                .map(|segment| RecordFrame {
                    segment,
                    capsule_digest: ContentDigest::sha256(&segment.to_be_bytes()),
                    sensor_id: "sensor:fixture".into(),
                    capture: CaptureInterval {
                        earliest: TimestampNs(10),
                        latest: TimestampNs(20),
                    },
                    dimensions: [64, 48],
                    color: "jpeg_rgb".into(),
                    inference_identity: d,
                    output_digest: d,
                    detection_report_digest: d,
                    detections: vec![RecordDetection {
                        row: 7,
                        class_index: 0,
                        score_bits: 0.75_f32.to_bits(),
                        bounds: [0, 0, 20 * 256, 20 * 256],
                        clipped: false,
                    }],
                })
                .collect(),
        }
    }
    fn config() -> PackageTrackingConfig {
        PackageTrackingConfig {
            confirmation_hits: 3,
            maximum_missed_frames: 2,
            minimum_iou_ppm: 100_000,
        }
    }
    fn gap(before_segment: u64) -> PackageTrackingBoundary {
        PackageTrackingBoundary {
            before_segment,
            source_gap: true,
            sequence_gap: false,
            dimensions_changed: false,
        }
    }

    #[test]
    fn package_observations_never_reuse_a_higher_scoring_nearby_source_row() -> Result<()> {
        let mut input = record(3);
        // With identical boxes, the previous nearest-IoU/score reconstruction selected row 9
        // for both tracks. The tracker's actual one-to-one assignments must preserve rows 7/9.
        // This is a structural tracking fixture, not an assertion about a package's NMS policy.
        for frame in &mut input.frames {
            let mut second = frame.detections[0];
            second.row = 9;
            second.score_bits = 0.9_f32.to_bits();
            frame.detections.push(second);
        }
        let tracks = build_tracks(&input, 0, config(), &[], || Ok(()))?;
        assert_eq!(tracks.len(), 2);
        assert!(tracks.iter().all(|track| track.confirmed));
        for segment in 0..3 {
            let rows: BTreeSet<_> = tracks
                .iter()
                .flat_map(|track| &track.observations)
                .filter(|observation| observation.segment == segment)
                .filter_map(|observation| observation.detection.map(|detection| detection.0))
                .collect();
            assert_eq!(rows, BTreeSet::from([7, 9]));
        }
        Ok(())
    }

    #[test]
    fn a_source_gap_cannot_finish_a_pre_gap_confirmation_run() -> Result<()> {
        let input = record(4);
        let clean = build_tracks(&input, 0, config(), &[], || Ok(()))?;
        assert_eq!(clean.len(), 1);
        assert!(clean[0].confirmed);
        let split = build_tracks(&input, 0, config(), &[gap(2)], || Ok(()))?;
        assert_eq!(split.len(), 2);
        assert!(split.iter().all(|track| !track.confirmed));
        assert_eq!(
            split[0]
                .observations
                .iter()
                .map(|o| o.segment)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(
            split[1]
                .observations
                .iter()
                .map(|o| o.segment)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_ne!(split[0].track_id, split[1].track_id);
        Ok(())
    }

    #[test]
    fn post_gap_tracks_can_confirm_without_reusing_pre_gap_ids() -> Result<()> {
        let input = record(6);
        for boundary in [
            gap(3),
            PackageTrackingBoundary {
                before_segment: 3,
                source_gap: false,
                sequence_gap: true,
                dimensions_changed: false,
            },
            PackageTrackingBoundary {
                before_segment: 3,
                source_gap: false,
                sequence_gap: false,
                dimensions_changed: true,
            },
        ] {
            let tracks = build_tracks(&input, 0, config(), &[boundary], || Ok(()))?;
            assert_eq!(tracks.len(), 2);
            assert!(tracks.iter().all(|track| track.confirmed));
            assert_eq!(tracks[0].track_id, 1);
            assert_eq!(tracks[1].track_id, 2);
            assert!(tracks[0].observations.iter().all(|o| o.segment < 3));
            assert!(tracks[1].observations.iter().all(|o| o.segment >= 3));
        }
        Ok(())
    }

    #[test]
    fn missing_detections_are_not_observations_and_tentative_ids_are_not_recycled() -> Result<()> {
        let mut input = record(6);
        input.frames[1].detections.clear();
        let tracks = build_tracks(&input, 0, config(), &[gap(3)], || Ok(()))?;
        assert_eq!(
            tracks
                .iter()
                .map(|track| track.track_id)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(
            tracks
                .iter()
                .flat_map(|track| &track.observations)
                .all(|o| o.segment != 1)
        );
        assert!(!tracks[0].confirmed && !tracks[1].confirmed && tracks[2].confirmed);
        Ok(())
    }

    #[test]
    fn display_order_is_preserved_within_epochs_but_cannot_return_across_a_gap() -> Result<()> {
        let mut input = record(4);
        input.frames.swap(0, 1);
        input.frames.swap(2, 3);
        let tracks = build_tracks(&input, 0, config(), &[gap(2)], || Ok(()))?;
        assert_eq!(
            tracks[0]
                .observations
                .iter()
                .map(|o| o.segment)
                .collect::<Vec<_>>(),
            vec![1, 0]
        );
        assert_eq!(
            tracks[1]
                .observations
                .iter()
                .map(|o| o.segment)
                .collect::<Vec<_>>(),
            vec![3, 2]
        );
        input.frames.swap(1, 2);
        assert!(build_tracks(&input, 0, config(), &[gap(2)], || Ok(())).is_err());
        Ok(())
    }

    #[test]
    fn cancellation_and_excess_detection_capacity_return_no_partial_tracks() {
        let input = record(4);
        let mut calls = 0;
        let cancelled = build_tracks(&input, 0, config(), &[], || {
            calls += 1;
            if calls == 3 {
                Err(PackageEventError::Cancelled)
            } else {
                Ok(())
            }
        });
        assert!(matches!(cancelled, Err(PackageEventError::Cancelled)));
        assert_eq!(calls, 3);
        let mut excess = record(1);
        let seed = excess.frames[0].detections[0];
        excess.frames[0].detections = (0..129)
            .map(|row| RecordDetection { row, ..seed })
            .collect();
        assert!(matches!(
            build_tracks(&excess, 0, config(), &[], || Ok(())),
            Err(PackageEventError::Limit)
        ));
    }
}
