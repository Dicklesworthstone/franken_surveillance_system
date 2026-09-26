#![forbid(unsafe_code)]
//! Recovery policy and diagnostics shared by the per-camera analysis and report renderer.

use crate::ingest::recorded_watch::decode_refusals_json;
use crate::ingest::tolerant_decode::DecodeRefusal;

/// Explicit opt-in recovery for both recordings. Default options preserve strict analysis.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CorroborationOptions {
    /// Recover from typed stream decode refusals using the watch pipeline's bounded decoder.
    /// Refused segments and tracking restarts remain uncovered; source gaps additionally make
    /// subsequent frame-index capture hints unreliable, excluding those entries from association.
    /// Custody, cancellation, resource and privacy failures are never made tolerable.
    pub tolerate_decode_refusals: bool,
}

/// Frame-index capture hints stop being reliable at the first source gap after segment zero.
/// The operator capture-start hint anchors the first retained frame, even with a leading gap.
/// A decode refusal alone does not remove retained source bytes or change their segment indices.
/// Missing continuity metadata is not proof of continuity.
pub(super) fn capture_time_reliable(segment_gaps: &[bool], segment: usize) -> bool {
    segment_gaps
        .get(..=segment)
        .is_some_and(|gaps| !gaps.iter().skip(1).any(|gap| *gap))
}

/// Append only diagnostics that actually occurred, preserving every clean report byte.
pub(super) fn camera_diagnostics_json(
    refusals: &[DecodeRefusal],
    restarts: &[usize],
    segment_gaps: &[bool],
) -> String {
    let mut out = decode_refusals_json(refusals);
    if !restarts.is_empty() {
        let segments: Vec<String> = restarts.iter().map(usize::to_string).collect();
        out.push_str(&format!(",\"tracking_restarts\":[{}]", segments.join(",")));
    }
    let gaps: Vec<String> = segment_gaps
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, gap)| **gap)
        .map(|(segment, _)| segment.to_string())
        .collect();
    if !gaps.is_empty() {
        out.push_str(&format!(",\"source_gap_segments\":[{}]", gaps.join(",")));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_analysis_is_the_default() {
        assert!(!CorroborationOptions::default().tolerate_decode_refusals);
    }

    #[test]
    fn capture_hints_are_reliable_only_before_the_first_source_gap() {
        let gaps = [false, false, true, false, false, true, false];
        assert!(capture_time_reliable(&gaps, 0));
        assert!(capture_time_reliable(&gaps, 1));
        for segment in 2..gaps.len() {
            assert!(!capture_time_reliable(&gaps, segment));
        }
    }

    #[test]
    fn capture_start_hint_anchors_the_first_retained_frame() {
        assert!(capture_time_reliable(&[true, false, true], 0));
        assert!(capture_time_reliable(&[true, false, true], 1));
        assert!(!capture_time_reliable(&[true, false, true], 2));
    }

    #[test]
    fn missing_continuity_metadata_never_implies_reliable_time() {
        assert!(!capture_time_reliable(&[], 0));
        assert!(!capture_time_reliable(&[false], 1));
        assert!(!capture_time_reliable(&[false], usize::MAX));
    }

    #[test]
    fn clean_reports_keep_their_exact_bytes() {
        assert_eq!(camera_diagnostics_json(&[], &[], &[false; 16]), "");
    }

    #[test]
    fn restart_without_a_refused_frame_remains_explicit() {
        assert_eq!(
            camera_diagnostics_json(&[], &[7], &[false; 10]),
            ",\"tracking_restarts\":[7]"
        );
    }

    #[test]
    fn refusals_restarts_and_source_gaps_are_distinct_diagnostics() {
        let refusals = [DecodeRefusal {
            first_segment: 3,
            last_segment: 4,
            error_id: "ERR-DECODE-MALFORMED-001".to_owned(),
        }];
        assert_eq!(
            camera_diagnostics_json(
                &refusals,
                &[5, 7],
                &[false, false, false, false, false, false, false, true],
            ),
            concat!(
                ",\"decode_refusals\":[{\"first_segment\":3,\"last_segment\":4,",
                "\"error_id\":\"ERR-DECODE-MALFORMED-001\",\"coverage\":\"decode_refused\"}],",
                "\"tracking_restarts\":[5,7],\"source_gap_segments\":[7]"
            )
        );
    }

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn ground_coverage(
        refused: bool,
        source_gap: bool,
    ) -> TestResult<crate::ingest::recorded_coverage::CoverageRecord> {
        use super::super::{
            CameraCoverageContext, CameraSummary, CorroborationCamera, CorroborationGates,
            CorroborationPlan, GroundHomography, GroundVisibilityPlan, GroundZone, camera_coverage,
        };
        use crate::ingest::privacy_mask::MaskBinding;
        use crate::ingest::recorded_coverage::CoverageFrame;
        use crate::ingest::recorded_decode::ComponentInterpretation;
        use crate::ingest::recorded_watch::{WatchDetectorConfig, WatchTrackerConfig};
        use fss_core::{CaptureInterval, ContentDigest, ContractError, LedgerAnchor, TimestampNs};

        let digest = |bytes: &[u8]| ContentDigest::sha256(bytes);
        let camera = |name: &str| CorroborationCamera {
            name: name.to_owned(),
            import_identity: digest(name.as_bytes()),
            homography: GroundHomography {
                matrix: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
            },
        };
        let plan = CorroborationPlan {
            cameras: [camera("east"), camera("west")],
            interpretation: ComponentInterpretation::Grayscale,
            zones: vec![GroundZone {
                zone_id: "door".to_owned(),
                x: 4.0,
                y: 4.0,
                width: 16.0,
                height: 16.0,
            }],
            gates: CorroborationGates {
                time_gate_ns: 250_000_000,
                distance_gate: 16.0,
            },
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        };
        let frames: Vec<CoverageFrame> = (0..20)
            .filter(|segment| !refused || *segment != 8)
            .map(|segment| {
                let time = 1_000_000_000 + segment as i128 * 100_000_000;
                Ok(CoverageFrame {
                    segment,
                    capture: CaptureInterval::new(
                        TimestampNs(time - 1_000_000),
                        TimestampNs(time + 1_000_000),
                    )?,
                })
            })
            .collect::<Result<_, ContractError>>()?;
        let mut gaps = vec![false; 20];
        gaps[8] = source_gap;
        let summary = CameraSummary {
            name: "east".to_owned(),
            import_identity: plan.cameras[0].import_identity,
            import_root: digest(b"root"),
            sensor_id: "sensor:east".to_owned(),
            failure_domain: "recorded-sensor:east".to_owned(),
            watch_plan_digest: digest(b"watch-plan"),
            watch_analysis_digest: digest(b"watch-analysis"),
            frames: frames.len(),
            confirmed_tracks: 0,
            capture_span: CaptureInterval::new(TimestampNs(0), TimestampNs(3_000_000_000))?,
            homography_digest: plan.cameras[0].homography.digest(),
            decode_refusals: if refused {
                vec![DecodeRefusal {
                    first_segment: 8,
                    last_segment: 8,
                    error_id: "ERR-DECODE-MALFORMED-001".to_owned(),
                }]
            } else {
                Vec::new()
            },
            tracking_restarts: vec![if refused { 9 } else { 8 }],
            sensor_digest: digest(b"sensor:east"),
            coverage_frames: frames,
            segment_gaps: gaps,
            dimensions: [64, 48],
            media_format: "mjpeg".to_owned(),
            privacy: MaskBinding::NoPolicy,
        };
        let record = camera_coverage(
            &CameraCoverageContext {
                plan: &plan,
                plan_digest: plan.digest(),
                entries: &[],
                candidates: &[],
                basis: &LedgerAnchor::genesis("site:recovery"),
                cascade: None,
                visibility: &GroundVisibilityPlan::default(),
                provenance: None,
            },
            0,
            &summary,
        )?;
        Ok(record)
    }

    #[test]
    fn ground_coverage_keeps_refusals_and_pre_restart_confirmation_latency() -> TestResult {
        use crate::ingest::recorded_coverage::{CoverageRecord, UncoveredReason};
        use fss_core::ContentDigest;

        let record = ground_coverage(true, false)?;
        let zone = &record.zones[0];
        assert!(zone.uncovered.iter().any(|gap| {
            gap.first_segment == 8
                && gap.last_segment == 8
                && matches!(gap.reason, UncoveredReason::DecodeRefused { .. })
        }));
        for segment in [6, 7] {
            assert!(zone.uncovered.iter().any(|gap| {
                gap.first_segment <= segment
                    && gap.last_segment >= segment
                    && gap.reason == UncoveredReason::ConfirmationLatency
            }));
        }
        assert!(zone.witnesses.iter().any(|w| w.first_segment >= 9));
        assert!(
            zone.witnesses
                .iter()
                .all(|w| w.last_segment < 6 || w.first_segment >= 9)
        );
        let bytes = record.to_bytes();
        assert_eq!(
            CoverageRecord::from_bytes(&bytes, ContentDigest::sha256(&bytes))?,
            record
        );
        Ok(())
    }

    #[test]
    fn ground_coverage_honors_restarts_even_without_a_missing_frame() -> TestResult {
        use crate::ingest::recorded_coverage::UncoveredReason;

        let record = ground_coverage(false, false)?;
        let zone = &record.zones[0];
        for segment in [6, 7] {
            assert!(zone.uncovered.iter().any(|gap| {
                gap.first_segment <= segment
                    && gap.last_segment >= segment
                    && gap.reason == UncoveredReason::ConfirmationLatency
            }));
        }
        assert!(zone.witnesses.iter().any(|w| w.first_segment >= 8));
        assert!(
            zone.witnesses
                .iter()
                .all(|w| w.last_segment < 6 || w.first_segment >= 8)
        );
        Ok(())
    }

    #[test]
    fn ground_coverage_never_certifies_later_frame_index_time_after_source_loss() -> TestResult {
        use crate::ingest::recorded_coverage::UncoveredReason;

        let record = ground_coverage(false, true)?;
        let zone = &record.zones[0];
        assert!(zone.witnesses.iter().all(|w| w.last_segment < 8));
        assert!(zone.uncovered.iter().any(|gap| {
            gap.first_segment == 8
                && gap.last_segment == 19
                && gap.reason == UncoveredReason::CaptureTimeUnreliableAfterGap
        }));
        Ok(())
    }
}
