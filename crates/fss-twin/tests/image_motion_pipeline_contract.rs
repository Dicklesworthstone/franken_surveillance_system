#![forbid(unsafe_code)]
//! Actual-pixel and native-JPEG motion pipeline contracts, without supplied boxes.
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits};
use fss_core::ContentDigest;
use fss_geometry::{PinholeIntrinsics, WorkBudget};
use fss_twin::foreground::pipeline::{FrameCapture, RectifiedBackground, RectifiedReference};
use fss_twin::foreground::{
    BackgroundModel, BackgroundPolicy, ForegroundFrame, ForegroundPolicy, ForegroundReport,
    ForegroundSource,
};
use fss_twin::image_motion::pipeline::*;
use fss_twin::image_motion::{
    ImageMotionError, ImageMotionOutcome, ImageMotionPolicy, MotionUnavailable,
    estimate_image_motion,
};
use fss_twin::image_tracking::{
    ImageTracker, ImageTrackingError, ImageTrackingPolicy, TrackingAvailability,
};
use fss_twin::localization::ImageIdentity;
use fss_twin::mjpeg::{
    JpegBackground, JpegFrameBinding, JpegReference, decode_rectified, decoded_image_domain,
};
use fss_twin::rectification::{
    LensDistortion, LumaRange, RawFrameIdentity, RawGrayFrame, RectificationPlan, RectificationSpec,
};
use std::error::Error;

type Test = Result<(), Box<dyn Error>>;
const ALLOWANCE: u64 = 100_000_000;
fn tracking_policy() -> ImageTrackingPolicy {
    ImageTrackingPolicy {
        maximum_tracks: 8,
        maximum_detections: 8,
        maximum_exposures: 100,
        minimum_observations: 2,
        maximum_misses: 2,
        maximum_gap_ns: 10_000_000_000,
        maximum_speed: 100,
        gate_padding: 2,
        miss_cost: 1000,
        ambiguity_margin: 0,
    }
}
fn tracker() -> Result<ImageTracker, Box<dyn Error>> {
    Ok(ImageTracker::new(
        [40; 32],
        tracking_policy(),
        &mut WorkBudget::new(ALLOWANCE),
    )?)
}
fn motion_policy() -> ImageMotionPolicy {
    ImageMotionPolicy {
        measurement_variance: 1.0,
        acceleration_variance: 0.1,
        initial_velocity_variance: 100.0,
        maximum_pair_gap_ns: 10_000_000_000,
        maximum_prediction_ns: 10_000_000_000,
    }
}
fn foreground_policy() -> ForegroundPolicy {
    ForegroundPolicy {
        minimum_change: 10,
        minimum_area: 1,
        maximum_regions: 32,
        widespread_per_mille: 900,
    }
}
fn pixels(rectangles: &[[usize; 4]]) -> Vec<u8> {
    let mut pixels = vec![100; 64 * 16];
    for &[left, top, right, bottom] in rectangles {
        for y in top..bottom {
            for x in left..right {
                pixels[y * 64 + x] = 160;
            }
        }
    }
    pixels
}
fn source(exposure: u8, pixels: &[u8]) -> ForegroundSource {
    ForegroundSource {
        image: ImageIdentity {
            exposure: [exposure; 32],
            pixels: ContentDigest::sha256(pixels).bytes(),
            image_domain: [5; 32],
            dimensions: [64, 16],
        },
        camera: 1,
        calibration: [6; 32],
        clock: 2,
        capture: [u64::from(exposure) * 1_000_000_000; 2],
    }
}
fn report(
    exposure: u8,
    rectangles: &[[usize; 4]],
    mask: &[u8],
    policy: ForegroundPolicy,
    selection: u8,
) -> Result<ForegroundReport, Box<dyn Error>> {
    let background = pixels(&[]);
    let allowed = vec![1; background.len()];
    let mut budget = WorkBudget::new(ALLOWANCE);
    let mut frames = Vec::new();
    for exposure in 1..=3 {
        frames.push(ForegroundFrame::new(
            source(exposure, &background),
            &background,
            &allowed,
            &mut budget,
        )?);
    }
    let baseline = BackgroundModel::build(
        &frames,
        BackgroundPolicy {
            selection_evidence: [selection; 32],
            validity: [0, u64::MAX],
            maximum_spread: 0,
        },
        &mut budget,
    )?;
    let query = pixels(rectangles);
    let frame = ForegroundFrame::new(source(exposure, &query), &query, mask, &mut budget)?;
    Ok(baseline.detect(&frame, policy, &mut budget)?)
}
fn track(tracker: &mut ImageTracker, report: &ForegroundReport) -> ForegroundMotionAnalysis {
    track_foreground_motion(
        tracker,
        report,
        motion_policy(),
        &mut WorkBudget::new(ALLOWANCE),
    )
}

#[test]
fn actual_foreground_regions_supply_boxes_provenance_and_partial_status() -> Test {
    let input = report(
        4,
        &[[0, 4, 4, 8], [20, 4, 24, 8]],
        &[1; 1024],
        foreground_policy(),
        8,
    )?;
    let mut tracker = tracker()?;
    let output = track(&mut tracker, &input);
    let MotionPipelineOutcome::Tracked { tracking, motion } = output.outcome() else {
        return Err("tracking failed".into());
    };
    assert_eq!(tracking.frame().source, input.source());
    assert_eq!(tracking.frame().permission_mask, input.mask_digest());
    assert_eq!(tracking.frame().evidence, input.digest());
    assert_eq!(output.foreground_digest(), input.digest());
    assert_eq!(tracking.decisions().len(), input.regions().len());
    for (decision, region) in tracking.decisions().iter().zip(input.regions()) {
        assert_eq!(decision.detection.min, region.min);
        assert_eq!(decision.detection.max, region.max);
        assert_eq!(
            decision.detection.partial,
            region.touches_edge || region.touches_unknown
        );
        assert_ne!(decision.detection.evidence, input.digest());
    }
    assert!(tracking.decisions()[0].detection.partial);
    assert!(!tracking.decisions()[1].detection.partial);
    assert_eq!(motion.as_ref().map_err(|e| *e)?.outcomes().len(), 2);
    Ok(())
}

#[test]
fn policy_background_and_permission_changes_cannot_reuse_trajectories() -> Test {
    let first = report(4, &[[4, 4, 8, 8]], &[1; 1024], foreground_policy(), 8)?;
    let mut tracker = tracker()?;
    let _first = track(&mut tracker, &first);
    let before = tracker.digest();
    let mut changed_policy = foreground_policy();
    changed_policy.minimum_change += 1;
    let mut mask = [1; 1024];
    mask[0] = 0;
    for changed in [
        report(5, &[[5, 4, 9, 8]], &[1; 1024], changed_policy, 8)?,
        report(5, &[[5, 4, 9, 8]], &[1; 1024], foreground_policy(), 9)?,
        report(5, &[[5, 4, 9, 8]], &mask, foreground_policy(), 8)?,
    ] {
        assert!(matches!(
            track(&mut tracker, &changed).outcome(),
            MotionPipelineOutcome::TrackingFailed(ImageTrackingError::BasisMismatch)
        ));
        assert_eq!(tracker.digest(), before);
        assert_eq!(tracker.exposure_count(), 1);
    }
    Ok(())
}

#[test]
fn full_input_capacity_refusal_never_selects_top_regions() -> Test {
    let input = report(
        4,
        &[[4, 4, 8, 8], [20, 4, 24, 8]],
        &[1; 1024],
        foreground_policy(),
        8,
    )?;
    let mut policy = tracking_policy();
    policy.maximum_detections = 1;
    let mut tracker = ImageTracker::new([40; 32], policy, &mut WorkBudget::new(ALLOWANCE))?;
    let before = tracker.digest();
    assert!(matches!(
        track(&mut tracker, &input).outcome(),
        MotionPipelineOutcome::TrackingFailed(ImageTrackingError::Limit)
    ));
    assert_eq!(tracker.digest(), before);
    assert!(tracker.tracks().is_empty());
    assert_eq!(tracker.exposure_count(), 0);
    Ok(())
}

#[test]
fn disturbed_and_unobservable_frames_are_not_available_empty_scenes() -> Test {
    for (mask, rectangles, expected) in [
        (
            [1; 1024],
            vec![[0, 0, 64, 16]],
            TrackingAvailability::Disturbed,
        ),
        ([0; 1024], vec![], TrackingAvailability::Unobservable),
    ] {
        let input = report(4, &rectangles, &mask, foreground_policy(), 8)?;
        let mut tracker = tracker()?;
        let output = track(&mut tracker, &input);
        let MotionPipelineOutcome::Tracked { tracking, .. } = output.outcome() else {
            return Err("tracking failed".into());
        };
        assert_eq!(tracking.frame().availability, expected);
        assert!(tracker.tracks().is_empty());
        assert_eq!(tracking.decisions().len(), input.regions().len());
    }
    Ok(())
}

#[test]
fn failed_optional_motion_retains_accepted_receipt_and_can_be_retried_alone() -> Test {
    let first = report(4, &[[4, 4, 8, 8]], &[1; 1024], foreground_policy(), 8)?;
    let second = report(5, &[[9, 4, 13, 8]], &[1; 1024], foreground_policy(), 8)?;
    let mut tracker = tracker()?;
    let _first = track(&mut tracker, &first);
    let mut invalid = motion_policy();
    invalid.measurement_variance = 0.0;
    let output = track_foreground_motion(
        &mut tracker,
        &second,
        invalid,
        &mut WorkBudget::new(ALLOWANCE),
    );
    let MotionPipelineOutcome::Tracked { tracking, motion } = output.outcome() else {
        return Err("tracking failed".into());
    };
    assert!(matches!(motion, Err(ImageMotionError::InvalidPolicy)));
    assert_eq!(tracker.digest(), tracking.digest());
    assert_eq!(tracker.exposure_count(), 2);
    let retry = estimate_image_motion(
        &tracker,
        tracking,
        motion_policy(),
        &mut WorkBudget::new(ALLOWANCE),
    )?;
    assert!(matches!(
        retry.outcomes()[0],
        ImageMotionOutcome::Estimated(_)
    ));
    assert!(matches!(
        track(&mut tracker, &second).outcome(),
        MotionPipelineOutcome::TrackingFailed(ImageTrackingError::ReusedExposure)
    ));
    assert_eq!(tracker.exposure_count(), 2);
    Ok(())
}

#[test]
fn every_budget_cut_preserves_either_old_state_or_complete_accepted_receipt() -> Test {
    let first = report(4, &[[4, 4, 8, 8]], &[1; 1024], foreground_policy(), 8)?;
    let second = report(5, &[[9, 4, 13, 8]], &[1; 1024], foreground_policy(), 8)?;
    let mut reference = tracker()?;
    let _first = track(&mut reference, &first);
    let mut full = WorkBudget::new(ALLOWANCE);
    let complete = track_foreground_motion(&mut reference, &second, motion_policy(), &mut full);
    let MotionPipelineOutcome::Tracked {
        tracking: expected,
        motion: Ok(_),
    } = complete.outcome()
    else {
        return Err("full pipeline failed".into());
    };
    let mut saw_accepted_without_motion = false;
    for limit in 0..full.used() {
        let mut tracker = tracker()?;
        let _first = track(&mut tracker, &first);
        let before = tracker.digest();
        let result = track_foreground_motion(
            &mut tracker,
            &second,
            motion_policy(),
            &mut WorkBudget::new(limit),
        );
        match result.outcome() {
            MotionPipelineOutcome::TrackingFailed(_) => {
                assert_eq!(tracker.digest(), before);
                assert_eq!(tracker.exposure_count(), 1);
                let retry = track(&mut tracker, &second);
                let MotionPipelineOutcome::Tracked { tracking, .. } = retry.outcome() else {
                    return Err("retry failed".into());
                };
                assert_eq!(tracking.digest(), expected.digest());
            }
            MotionPipelineOutcome::Tracked { tracking, motion } => {
                assert_eq!(tracking.digest(), expected.digest());
                assert_eq!(tracker.exposure_count(), 2);
                assert!(motion.is_err());
                saw_accepted_without_motion = true;
                let retry = estimate_image_motion(
                    &tracker,
                    tracking,
                    motion_policy(),
                    &mut WorkBudget::new(ALLOWANCE),
                )?;
                assert!(matches!(
                    retry.outcomes()[0],
                    ImageMotionOutcome::Estimated(_)
                ));
            }
        }
    }
    assert!(saw_accepted_without_motion);
    Ok(())
}

fn raw_identity(
    plan: &RectificationPlan,
    pixels: &[u8],
    mask: &[u8],
    exposure: u8,
) -> RawFrameIdentity {
    RawFrameIdentity {
        exposure: [exposure; 32],
        storage: ContentDigest::sha256(pixels).bytes(),
        allowed_mask: ContentDigest::sha256(mask).bytes(),
        image_domain: plan.spec().source_domain,
        calibration: plan.spec().calibration,
        dimensions: plan.spec().source.dimensions(),
        row_stride: plan.spec().source.dimensions()[0],
        range: LumaRange::Full,
    }
}
#[test]
fn raw_luma_rectification_reaches_measured_motion_without_caller_supplied_detections() -> Test {
    let mut budget = WorkBudget::new(ALLOWANCE);
    let k = PinholeIntrinsics::new(64, 16, 100.0, 100.0, 32.0, 8.0)?;
    let plan = RectificationPlan::compile(
        RectificationSpec {
            source: k,
            target: k,
            distortion: LensDistortion::Pinhole,
            maximum_radius: 1.0,
            source_domain: [7; 32],
            calibration: [8; 32],
            range: LumaRange::Full,
        },
        &mut budget,
    )?;
    let baseline = pixels(&[]);
    let mask = vec![1; baseline.len()];
    let mut frames = Vec::new();
    for exposure in 1..=3 {
        let raw = RawGrayFrame::new(
            raw_identity(&plan, &baseline, &mask, exposure),
            &baseline,
            &mask,
            &mut budget,
        )?;
        frames.push(plan.apply(&raw, &mut budget)?);
    }
    let references: Vec<_> = frames
        .iter()
        .enumerate()
        .map(|(i, frame)| RectifiedReference {
            frame,
            capture: FrameCapture {
                camera: 1,
                clock: 2,
                capture: [(i as u64 + 1) * 1_000_000_000; 2],
            },
        })
        .collect();
    let background = RectifiedBackground::build(
        &plan,
        &references,
        BackgroundPolicy {
            selection_evidence: [9; 32],
            validity: [0, u64::MAX],
            maximum_spread: 0,
        },
        &mut budget,
    )?;
    let mut tracker = tracker()?;
    for (exposure, left) in [(4, 4), (5, 9)] {
        let query = pixels(&[[left, 4, left + 4, 8]]);
        let raw = RawGrayFrame::new(
            raw_identity(&plan, &query, &mask, exposure),
            &query,
            &mask,
            &mut budget,
        )?;
        let result = analyze_luma_motion(
            &mut tracker,
            &background,
            &plan,
            &raw,
            FrameCapture {
                camera: 1,
                clock: 2,
                capture: [u64::from(exposure) * 1_000_000_000; 2],
            },
            foreground_policy(),
            motion_policy(),
            &mut budget,
        )?;
        assert_eq!(
            result.foreground().frame().receipt().source.storage,
            ContentDigest::sha256(&query).bytes()
        );
        let MotionPipelineOutcome::Tracked {
            motion: Ok(motion), ..
        } = result.analysis().outcome()
        else {
            return Err("luma pipeline failed".into());
        };
        if exposure == 5 {
            let ImageMotionOutcome::Estimated(estimate) = motion.outcomes()[0] else {
                return Err("no estimate".into());
            };
            assert!(estimate.velocity()[0] > 4.0);
            assert!(!estimate.predicted());
            assert_eq!(
                estimate.observations()[1].frame.source.image.exposure,
                [5; 32]
            );
        } else {
            assert!(matches!(
                motion.outcomes()[0],
                ImageMotionOutcome::Unavailable {
                    reason: MotionUnavailable::MissingPair,
                    ..
                }
            ));
        }
    }
    assert_eq!(tracker.tracks().len(), 1);
    assert_eq!(tracker.tracks()[0].observations(), 2);
    Ok(())
}

const BACKGROUND_JPEG: &[u8] =
    include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const QUERY_JPEG: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
fn jpeg_binding(bytes: &[u8], mask: &[u8], exposure: u8) -> JpegFrameBinding {
    JpegFrameBinding {
        encoded_sha256: ContentDigest::sha256(bytes).bytes(),
        exposure: [exposure; 32],
        allowed_mask: ContentDigest::sha256(mask).bytes(),
        camera_image_domain: [7; 32],
        calibration: [8; 32],
        interpretation: ComponentInterpretation::Grayscale,
    }
}
fn jpeg_background() -> Result<(RectificationPlan, JpegBackground, Vec<u8>), Box<dyn Error>> {
    let mut geometry = WorkBudget::new(ALLOWANCE);
    let mut decoder = DecodeBudget::new(ALLOWANCE);
    let k = PinholeIntrinsics::new(17, 13, 20.0, 20.0, 8.5, 6.5)?;
    let plan = RectificationPlan::compile(
        RectificationSpec {
            source: k,
            target: k,
            distortion: LensDistortion::Pinhole,
            maximum_radius: 1.0,
            source_domain: decoded_image_domain([7; 32], ComponentInterpretation::Grayscale),
            calibration: [8; 32],
            range: LumaRange::Full,
        },
        &mut geometry,
    )?;
    let mask = vec![1; 221];
    let mut frames = Vec::new();
    for exposure in 1..=3 {
        frames.push(decode_rectified(
            &plan,
            BACKGROUND_JPEG,
            &mask,
            jpeg_binding(BACKGROUND_JPEG, &mask, exposure),
            DecodeLimits::default(),
            &mut decoder,
            &mut geometry,
        )?);
    }
    let references: Vec<_> = frames
        .iter()
        .enumerate()
        .map(|(i, image)| JpegReference {
            image,
            capture: FrameCapture {
                camera: 1,
                clock: 2,
                capture: [(i as u64 + 1) * 10; 2],
            },
        })
        .collect();
    let model = JpegBackground::build(
        &plan,
        &references,
        BackgroundPolicy {
            selection_evidence: [9; 32],
            validity: [0, 1000],
            maximum_spread: 0,
        },
        &mut geometry,
    )?;
    Ok((plan, model, mask))
}
#[test]
fn native_jpeg_receipts_and_all_real_regions_survive_to_tracking() -> Test {
    let (plan, background, mask) = jpeg_background()?;
    let mut tracker = ImageTracker::new(
        [40; 32],
        ImageTrackingPolicy {
            maximum_tracks: 64,
            maximum_detections: 64,
            ..tracking_policy()
        },
        &mut WorkBudget::new(ALLOWANCE),
    )?;
    let input = JpegMotionInput {
        bytes: QUERY_JPEG,
        allowed: &mask,
        source: jpeg_binding(QUERY_JPEG, &mask, 4),
        capture: FrameCapture {
            camera: 1,
            clock: 2,
            capture: [40; 2],
        },
    };
    let result = analyze_jpeg_motion(
        &mut tracker,
        &background,
        &plan,
        input,
        foreground_policy(),
        motion_policy(),
        DecodeLimits::default(),
        &mut DecodeBudget::new(ALLOWANCE),
        &mut WorkBudget::new(ALLOWANCE),
    )?;
    assert_eq!(result.foreground().receipt().source, input.source);
    let foreground = result.foreground().analysis().report();
    assert!(!foreground.regions().is_empty());
    let MotionPipelineOutcome::Tracked {
        tracking,
        motion: Ok(_),
    } = result.analysis().outcome()
    else {
        return Err("JPEG tracking failed".into());
    };
    assert_eq!(tracking.frame().evidence, foreground.digest());
    assert_eq!(tracking.frame().source.image.exposure, [4; 32]);
    assert_eq!(tracking.decisions().len(), foreground.regions().len());
    assert_eq!(tracker.exposure_count(), 1);
    Ok(())
}
#[test]
fn invalid_jpeg_and_decode_budget_fail_before_any_tracking_commit() -> Test {
    let (plan, background, mask) = jpeg_background()?;
    let mut tracker = tracker()?;
    let before = tracker.digest();
    for (bytes, allowance) in [(b"not a jpeg".as_slice(), ALLOWANCE), (QUERY_JPEG, 0)] {
        let input = JpegMotionInput {
            bytes,
            allowed: &mask,
            source: jpeg_binding(bytes, &mask, 4),
            capture: FrameCapture {
                camera: 1,
                clock: 2,
                capture: [40; 2],
            },
        };
        assert!(
            analyze_jpeg_motion(
                &mut tracker,
                &background,
                &plan,
                input,
                foreground_policy(),
                motion_policy(),
                DecodeLimits::default(),
                &mut DecodeBudget::new(allowance),
                &mut WorkBudget::new(ALLOWANCE)
            )
            .is_err()
        );
        assert_eq!(tracker.digest(), before);
        assert_eq!(tracker.exposure_count(), 0);
    }
    Ok(())
}
#[test]
fn decoded_jpeg_is_retained_when_tracking_episode_is_exhausted() -> Test {
    let (plan, background, mask) = jpeg_background()?;
    let mut tracker = ImageTracker::new(
        [40; 32],
        ImageTrackingPolicy {
            maximum_exposures: 1,
            maximum_tracks: 64,
            maximum_detections: 64,
            ..tracking_policy()
        },
        &mut WorkBudget::new(ALLOWANCE),
    )?;
    for exposure in [4, 5] {
        let input = JpegMotionInput {
            bytes: QUERY_JPEG,
            allowed: &mask,
            source: jpeg_binding(QUERY_JPEG, &mask, exposure),
            capture: FrameCapture {
                camera: 1,
                clock: 2,
                capture: [u64::from(exposure) * 10; 2],
            },
        };
        let result = analyze_jpeg_motion(
            &mut tracker,
            &background,
            &plan,
            input,
            foreground_policy(),
            motion_policy(),
            DecodeLimits::default(),
            &mut DecodeBudget::new(ALLOWANCE),
            &mut WorkBudget::new(ALLOWANCE),
        )?;
        assert_eq!(result.foreground().receipt().source, input.source);
        if exposure == 5 {
            assert!(matches!(
                result.analysis().outcome(),
                MotionPipelineOutcome::TrackingFailed(ImageTrackingError::Limit)
            ));
            assert!(!result.foreground().analysis().report().regions().is_empty());
        }
    }
    assert_eq!(tracker.exposure_count(), 1);
    Ok(())
}

#[test]
fn direct_foreground_tracking_and_composite_motion_share_one_generation() -> Test {
    let first = report(4, &[[4, 4, 8, 8]], &[1; 1024], foreground_policy(), 8)?;
    let second = report(5, &[[9, 4, 13, 8]], &[1; 1024], foreground_policy(), 8)?;
    let mut tracker = tracker()?;
    let initial = tracker.update_foreground(&first, &mut WorkBudget::new(ALLOWANCE))?;
    let result = track(&mut tracker, &second);
    let MotionPipelineOutcome::Tracked {
        tracking,
        motion: Ok(motion),
    } = result.outcome()
    else {
        return Err("mixed entry points changed detector generation".into());
    };
    assert_eq!(initial.frame().detector, tracking.frame().detector);
    assert_eq!(tracking.prior_digest(), initial.digest());
    assert_eq!(tracker.tracks()[0].observations(), 2);
    assert!(matches!(
        motion.outcomes()[0],
        ImageMotionOutcome::Estimated(_)
    ));
    Ok(())
}
