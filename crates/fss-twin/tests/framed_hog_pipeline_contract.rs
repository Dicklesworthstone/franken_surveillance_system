#![forbid(unsafe_code)]
//! Stream/native JPEG/model/tracker integration with SYNTHETIC coefficients.
//! Resized fixtures test ownership and lineage, not pedestrian quality or coverage.
use fss_codec_mjpeg::stream::{FramedJpeg, FramingLimits, JpegStream, StreamBasis};
use fss_codec_mjpeg::{ComponentInterpretation as Color, DecodeBudget, DecodeLimits};
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, PinholeIntrinsics, WorkBudget};
use fss_twin::foreground::pipeline::FrameCapture;
use fss_twin::foreground::{BackgroundPolicy, ForegroundPolicy};
use fss_twin::hog::{HOG_PARAMETERS, HogModel};
use fss_twin::hog_scan::{ScanLevel, ScanPolicy};
use fss_twin::image_tracking::{ImageTrackingPolicy, TrackingAvailability};
use fss_twin::image_zones::pipeline::ImageZonePipeline;
use fss_twin::image_zones::{ImageZoneBasis, ImageZonePolicy, ImageZoneSpec};
use fss_twin::mjpeg::stream::FramedQuery;
use fss_twin::mjpeg::{
    JpegBackground, JpegFrameBinding, JpegReference, decode_rectified, decoded_image_domain,
};
use fss_twin::rectification::{LensDistortion, LumaRange, RectificationPlan, RectificationSpec};
use fss_twin::screening::tracking::hog::jpeg::stream::*;
use fss_twin::screening::tracking::hog::jpeg::*;
use fss_twin::screening::{ScreeningPolicy, ScreeningStamp};
use std::error::Error;
use std::sync::atomic::AtomicBool;

type Test = Result<(), Box<dyn Error>>;
const JPEG: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
const BACKGROUND: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const MALFORMED: &[u8] = &[0xff, 0xd8, 0xff, 0xda, 0, 2, 0xff, 0xd9];
const LIMIT: u64 = 1_000_000_000;
fn work() -> WorkBudget<'static> {
    WorkBudget::new(LIMIT)
}
fn decode() -> DecodeBudget<'static> {
    DecodeBudget::new(LIMIT)
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    ContentDigest::sha256(bytes).bytes()
}
fn basis() -> StreamBasis {
    StreamBasis {
        source: [90; 32],
        generation: 1,
    }
}
fn binding(bytes: &[u8], mask: &[u8], exposure: u8) -> JpegFrameBinding {
    JpegFrameBinding {
        encoded_sha256: hash(bytes),
        exposure: [exposure; 32],
        allowed_mask: hash(mask),
        camera_image_domain: [7; 32],
        calibration: [8; 32],
        interpretation: Color::Grayscale,
    }
}
fn frames(
    basis: StreamBasis,
    images: &[&[u8]],
    chunk: usize,
) -> Result<Vec<FramedJpeg>, Box<dyn Error>> {
    let bytes = images.concat();
    let mut stream = JpegStream::new(basis, FramingLimits::default())?;
    let mut output = Vec::new();
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let end = offset.saturating_add(chunk).min(bytes.len());
        let step = stream.push(offset as u64, &bytes[offset..end], &mut decode())?;
        if step.consumed == 0 {
            return Err("framer made no progress".into());
        }
        offset += step.consumed;
        if let Some(frame) = step.frame {
            output.push(frame);
        }
    }
    assert_eq!(output.len(), images.len());
    assert_eq!(stream.buffered_bytes(), 0);
    Ok(output)
}
struct Fixture {
    plan: RectificationPlan,
    background: JpegBackground,
    mask: Vec<u8>,
    basis: ImageZoneBasis,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let source = PinholeIntrinsics::new(17, 13, 20.0, 20.0, 8.5, 6.5)?;
        let target = PinholeIntrinsics::new(64, 128, 200.0, 400.0, 32.0, 64.0)?;
        let plan = RectificationPlan::compile(
            RectificationSpec {
                source,
                target,
                distortion: LensDistortion::Pinhole,
                maximum_radius: 1.0,
                source_domain: decoded_image_domain([7; 32], Color::Grayscale),
                calibration: [8; 32],
                range: LumaRange::Full,
            },
            &mut work(),
        )?;
        let mask = vec![1; 17 * 13];
        let a = decode_rectified(
            &plan,
            BACKGROUND,
            &mask,
            binding(BACKGROUND, &mask, 1),
            DecodeLimits::default(),
            &mut decode(),
            &mut work(),
        )?;
        let b = decode_rectified(
            &plan,
            BACKGROUND,
            &mask,
            binding(BACKGROUND, &mask, 2),
            DecodeLimits::default(),
            &mut decode(),
            &mut work(),
        )?;
        let c = decode_rectified(
            &plan,
            BACKGROUND,
            &mask,
            binding(BACKGROUND, &mask, 3),
            DecodeLimits::default(),
            &mut decode(),
            &mut work(),
        )?;
        let refs = [
            JpegReference {
                image: &a,
                capture: FrameCapture {
                    camera: 1,
                    clock: 2,
                    capture: [10; 2],
                },
            },
            JpegReference {
                image: &b,
                capture: FrameCapture {
                    camera: 1,
                    clock: 2,
                    capture: [20; 2],
                },
            },
            JpegReference {
                image: &c,
                capture: FrameCapture {
                    camera: 1,
                    clock: 2,
                    capture: [30; 2],
                },
            },
        ];
        let background = JpegBackground::build(
            &plan,
            &refs,
            BackgroundPolicy {
                selection_evidence: [9; 32],
                validity: [0, 10_000],
                maximum_spread: 0,
            },
            &mut work(),
        )?;
        let basis = ImageZoneBasis {
            camera: 1,
            clock: 2,
            calibration: [8; 32],
            image_domain: a.frame().identity().image_domain,
            dimensions: [64, 128],
        };
        Ok(Self {
            plan,
            background,
            mask,
            basis,
        })
    }
    fn inner(&self) -> Result<JpegHogPipeline, Box<dyn Error>> {
        let zones = ImageZonePipeline::new(
            [40; 32],
            ImageTrackingPolicy {
                maximum_tracks: 64,
                maximum_detections: 64,
                maximum_exposures: 64,
                minimum_observations: 1,
                maximum_misses: 3,
                maximum_gap_ns: 1000,
                maximum_speed: 200,
                gate_padding: 0,
                miss_cost: 1000,
                ambiguity_margin: 0,
            },
            self.basis,
            ImageZonePolicy {
                selection_evidence: [30; 32],
                maximum_sample_gap_ns: 100,
            },
            &[ImageZoneSpec {
                id: 1,
                vertices: vec![[1, 1], [63, 1], [63, 127], [1, 127]],
                margin: 0,
                dwell_ns: Some(20),
            }],
            &mut work(),
        )?;
        let mut weights = vec![0; HOG_PARAMETERS * 4];
        weights[(HOG_PARAMETERS - 1) * 4..].copy_from_slice(&1_f32.to_le_bytes());
        let model = HogModel::from_f32_le(&weights, hash(&weights), [50; 32], &mut work())?;
        Ok(JpegHogPipeline::new(
            zones,
            model,
            JpegHogConfig {
                stream_generation: 1,
                started_at_ns: 0,
                screening: ScreeningPolicy {
                    minimum_visible_pixels: 1,
                    dark_luma: 0,
                    bright_luma: 255,
                    extreme_per_mille: 1000,
                    flat_range: 0,
                    repeat_frames: 100,
                    repeat_duration_ns: 1,
                    stall_after_ns: 1000,
                    maximum_capture_uncertainty_ns: 0,
                    recovery_frames: 1,
                    minimum_analysis_interval_ns: 0,
                    sentinel_interval_ns: 20,
                    activity_hold_ns: 0,
                },
                levels: &[ScanLevel {
                    dimensions: [64, 128],
                }],
                scan: ScanPolicy {
                    stride: [64, 128],
                    minimum_margin: 0.0,
                    suppression_iou_ppm: 1_000_000,
                    maximum_windows: 256,
                    maximum_candidates: 256,
                },
            },
            &mut work(),
        )?)
    }
    fn owner(&self, stream: StreamBasis) -> Result<FramedJpegHogPipeline, Box<dyn Error>> {
        Ok(FramedJpegHogPipeline::new(
            self.inner()?,
            stream,
            &mut work(),
        )?)
    }
    fn query<'a>(&'a self, frame: &'a FramedJpeg) -> FramedQuery<'a> {
        FramedQuery {
            expected_stream: frame.basis(),
            frame,
            mask: &self.mask,
            binding: binding(frame.bytes(), &self.mask, (10 + frame.ordinal()) as u8),
            capture: FrameCapture {
                camera: 1,
                clock: 2,
                capture: [30 + frame.ordinal() * 10; 2],
            },
            policy: ForegroundPolicy {
                minimum_change: 10,
                minimum_area: 1,
                maximum_regions: 128,
                widespread_per_mille: 1000,
            },
            limits: DecodeLimits::default(),
        }
    }
    fn stamp(&self, frame: &FramedJpeg) -> ScreeningStamp {
        ScreeningStamp {
            stream_generation: frame.basis().generation,
            sequence: frame.ordinal(),
            received_at_ns: 30 + frame.ordinal() * 10,
            owner_requests_analysis: false,
        }
    }
    fn run(
        &self,
        owner: &mut FramedJpegHogPipeline,
        frame: &FramedJpeg,
        inference: &mut WorkBudget<'_>,
        downstream: &mut WorkBudget<'_>,
    ) -> Result<JpegHogProgress, FramedHogError> {
        owner.observe(
            Some(&self.background),
            &self.plan,
            self.query(frame),
            self.stamp(frame),
            &mut decode(),
            &mut work(),
            &mut work(),
            &mut work(),
            inference,
            downstream,
        )
    }
}
fn complete(progress: JpegHogProgress) -> Result<JpegHogCompletion, Box<dyn Error>> {
    match progress {
        JpegHogProgress::Complete(value) => Ok(value),
        other => Err(format!("not complete: {other:?}").into()),
    }
}

#[test]
fn actual_framed_jpegs_reach_learned_tracking_with_original_ranges() -> Test {
    let f = Fixture::new()?;
    let mut p = f.owner(basis())?;
    let inputs = frames(basis(), &[JPEG, JPEG], 7)?;
    for frame in &inputs {
        let analysis = complete(f.run(&mut p, frame, &mut work(), &mut work())?)?;
        let done = p.completion().ok_or("missing stream root")?;
        assert_eq!(done.analysis, analysis);
        assert_eq!(done.source.basis, basis());
        assert_eq!(done.source.ordinal, frame.ordinal());
        assert_eq!(done.source.byte_range, frame.byte_range());
        assert_eq!(done.source.encoded_sha256, hash(JPEG));
        assert_eq!(p.source_receipt(), Some(done.source));
        let report = p.pipeline().tracking_report().ok_or("tracking lost")?;
        assert_eq!(
            report.frame().source.capture,
            [30 + frame.ordinal() * 10; 2]
        );
        assert_eq!(report.digest(), analysis.tracking);
    }
    assert_eq!(
        p.pipeline().zones().pipeline().tracker().exposure_count(),
        2
    );
    Ok(())
}
#[test]
fn byte_chunking_does_not_change_any_complete_root() -> Test {
    let f = Fixture::new()?;
    let mut expected = None;
    for chunk in [1, 7, usize::MAX] {
        let inputs = frames(basis(), &[JPEG, JPEG], chunk)?;
        let mut p = f.owner(basis())?;
        for frame in &inputs {
            complete(f.run(&mut p, frame, &mut work(), &mut work())?)?;
        }
        if let Some(old) = expected {
            assert_eq!(p.completion(), Some(old));
        } else {
            expected = p.completion();
        }
    }
    assert!(expected.is_some());
    Ok(())
}
#[test]
fn pending_inference_and_tracking_keep_the_same_stream_frame() -> Test {
    let f = Fixture::new()?;
    let inputs = frames(basis(), &[JPEG, JPEG], 7)?;
    let mut p = f.owner(basis())?;
    assert!(matches!(
        f.run(&mut p, &inputs[0], &mut WorkBudget::new(0), &mut work())?,
        JpegHogProgress::Pending {
            stage: JpegHogStage::Inference,
            ..
        }
    ));
    let source = p.source_receipt();
    assert!(source.is_some());
    assert!(p.completion().is_none());
    assert_eq!(
        f.run(&mut p, &inputs[1], &mut work(), &mut work()),
        Err(FramedHogError::Analysis(JpegHogError::PendingAnalysis))
    );
    assert!(matches!(
        p.resume(&mut work(), &mut WorkBudget::new(0))?,
        JpegHogProgress::Pending {
            stage: JpegHogStage::Tracking,
            ..
        }
    ));
    assert_eq!(p.source_receipt(), source);
    let mut zero = WorkBudget::new(0);
    let analysis = complete(p.resume(&mut zero, &mut work())?)?;
    assert_eq!(zero.used(), 0);
    assert_eq!(p.source_receipt(), source);
    let done = p.completion();
    assert_eq!(
        complete(p.resume(&mut WorkBudget::new(0), &mut WorkBudget::new(0))?)?,
        analysis
    );
    assert_eq!(p.completion(), done);
    assert_eq!(
        p.pipeline().zones().pipeline().tracker().exposure_count(),
        1
    );
    Ok(())
}
#[test]
fn every_stream_binding_is_checked_before_source_consumption() -> Test {
    let f = Fixture::new()?;
    let inputs = frames(basis(), &[JPEG], 7)?;
    for variant in 0..5 {
        let mut p = f.owner(basis())?;
        let mut q = f.query(&inputs[0]);
        let mut s = f.stamp(&inputs[0]);
        match variant {
            0 => q.expected_stream.source = [91; 32],
            1 => q.expected_stream.generation = 2,
            2 => s.sequence = 2,
            3 => s.stream_generation = 2,
            _ => q.binding.encoded_sha256 = [92; 32],
        }
        let mut inf = work();
        assert_eq!(
            p.observe(
                Some(&f.background),
                &f.plan,
                q,
                s,
                &mut decode(),
                &mut work(),
                &mut work(),
                &mut work(),
                &mut inf,
                &mut work()
            ),
            Err(FramedHogError::BasisMismatch)
        );
        assert_eq!(inf.used(), 0);
        assert!(p.source_receipt().is_none());
        assert_eq!(p.pipeline().stage(), JpegHogStage::AwaitingImage);
        complete(f.run(&mut p, &inputs[0], &mut work(), &mut work())?)?;
    }
    let foreign = frames(
        StreamBasis {
            source: [91; 32],
            generation: 1,
        },
        &[JPEG],
        7,
    )?;
    let mut p = f.owner(basis())?;
    assert_eq!(
        f.run(&mut p, &foreign[0], &mut work(), &mut work()),
        Err(FramedHogError::BasisMismatch)
    );
    Ok(())
}
#[test]
fn replayed_and_overlapping_frames_do_not_replace_the_last_completion() -> Test {
    let f = Fixture::new()?;
    let inputs = frames(basis(), &[JPEG, JPEG], 7)?;
    let mut p = f.owner(basis())?;
    complete(f.run(&mut p, &inputs[0], &mut work(), &mut work())?)?;
    let old = p.completion();
    assert_eq!(
        f.run(&mut p, &inputs[0], &mut work(), &mut work()),
        Err(FramedHogError::OutOfOrder)
    );
    // Same claimed stream with a higher ordinal, but an overlapping byte range.
    let overlap = frames(basis(), &[MALFORMED, MALFORMED], 1)?;
    assert!(overlap[1].byte_range()[0] < inputs[0].byte_range()[1]);
    assert_eq!(
        f.run(&mut p, &overlap[1], &mut work(), &mut work()),
        Err(FramedHogError::OutOfOrder)
    );
    assert_eq!(p.completion(), old);
    complete(f.run(&mut p, &inputs[1], &mut work(), &mut work())?)?;
    Ok(())
}
#[test]
fn failed_native_decode_keeps_the_prior_stream_cursor_retryable() -> Test {
    let f = Fixture::new()?;
    let valid = frames(basis(), &[JPEG, JPEG], 7)?;
    let invalid = frames(basis(), &[JPEG, MALFORMED], 1)?;
    let mut p = f.owner(basis())?;
    complete(f.run(&mut p, &valid[0], &mut work(), &mut work())?)?;
    let old = p.completion();
    assert!(matches!(
        f.run(&mut p, &invalid[1], &mut work(), &mut work()),
        Err(FramedHogError::Analysis(JpegHogError::Image(_)))
    ));
    assert_eq!(p.completion(), old);
    assert_eq!(p.source_receipt(), old.map(|r| r.source));
    complete(f.run(&mut p, &valid[1], &mut work(), &mut work())?)?;
    Ok(())
}
#[test]
fn boundary_cancellation_and_budget_refusal_do_not_credit_a_frame() -> Test {
    let f = Fixture::new()?;
    let inputs = frames(basis(), &[JPEG], 7)?;
    let cancelled = AtomicBool::new(true);
    for cancel in [false, true] {
        let mut p = f.owner(basis())?;
        let mut health = if cancel {
            WorkBudget::cancellable(LIMIT, &cancelled)
        } else {
            WorkBudget::new(1023)
        };
        let expected = if cancel {
            GeometryError::Cancelled
        } else {
            GeometryError::BudgetExhausted
        };
        assert_eq!(
            p.observe(
                Some(&f.background),
                &f.plan,
                f.query(&inputs[0]),
                f.stamp(&inputs[0]),
                &mut decode(),
                &mut work(),
                &mut work(),
                &mut health,
                &mut work(),
                &mut work()
            ),
            Err(FramedHogError::Work(expected))
        );
        assert!(p.source_receipt().is_none());
        assert_eq!(p.pipeline().stage(), JpegHogStage::AwaitingImage);
        complete(f.run(&mut p, &inputs[0], &mut work(), &mut work())?)?;
    }
    Ok(())
}
#[test]
fn a_new_pending_frame_cannot_expose_the_predecessors_complete_root() -> Test {
    let f = Fixture::new()?;
    let inputs = frames(basis(), &[JPEG, JPEG], 7)?;
    let mut p = f.owner(basis())?;
    complete(f.run(&mut p, &inputs[0], &mut work(), &mut work())?)?;
    assert!(p.completion().is_some());
    assert!(matches!(
        f.run(&mut p, &inputs[1], &mut WorkBudget::new(0), &mut work())?,
        JpegHogProgress::Pending { .. }
    ));
    assert!(p.completion().is_none());
    assert_eq!(p.source_receipt().ok_or("source lost")?.ordinal, 2);
    complete(p.resume(&mut work(), &mut work())?)?;
    assert_eq!(p.completion().ok_or("root lost")?.source.ordinal, 2);
    Ok(())
}
#[test]
fn original_stream_identity_is_included_even_when_analysis_is_identical() -> Test {
    let f = Fixture::new()?;
    let mut results = Vec::new();
    for source in [[90; 32], [91; 32]] {
        let b = StreamBasis {
            source,
            generation: 1,
        };
        let input = frames(b, &[JPEG], 7)?;
        let mut p = f.owner(b)?;
        complete(f.run(&mut p, &input[0], &mut work(), &mut work())?)?;
        results.push(p.completion().ok_or("missing completion")?);
    }
    assert_eq!(results[0].analysis, results[1].analysis);
    assert_ne!(results[0].digest, results[1].digest);
    Ok(())
}
#[test]
fn ordinal_gaps_stay_degraded_in_the_existing_health_chain() -> Test {
    let f = Fixture::new()?;
    let inputs = frames(basis(), &[JPEG, JPEG, JPEG], 7)?;
    let mut p = f.owner(basis())?;
    complete(f.run(&mut p, &inputs[0], &mut work(), &mut work())?)?;
    complete(f.run(&mut p, &inputs[2], &mut work(), &mut work())?)?;
    assert!(p.pipeline().zones().health_history_gap());
    assert_eq!(
        p.pipeline()
            .tracking_report()
            .ok_or("tracking lost")?
            .frame()
            .availability,
        TrackingAvailability::Disturbed
    );
    assert_eq!(p.source_receipt().ok_or("source lost")?.ordinal, 3);
    Ok(())
}
#[test]
fn construction_refuses_zero_or_different_generations_and_started_owners() -> Test {
    let f = Fixture::new()?;
    for b in [
        StreamBasis {
            source: [0; 32],
            generation: 1,
        },
        StreamBasis {
            source: [90; 32],
            generation: 0,
        },
        StreamBasis {
            source: [90; 32],
            generation: 2,
        },
    ] {
        assert!(matches!(
            FramedJpegHogPipeline::new(f.inner()?, b, &mut work()),
            Err(FramedHogError::BasisMismatch)
        ));
    }
    let mut inner = f.inner()?;
    let input = frames(basis(), &[JPEG], 7)?;
    let q = f.query(&input[0]);
    inner.observe(
        Some(&f.background),
        &f.plan,
        fss_twin::screened_mjpeg::JpegScreeningQuery {
            bytes: q.frame.bytes(),
            mask: q.mask,
            binding: q.binding,
            capture: q.capture,
            foreground_policy: q.policy,
            decode_limits: q.limits,
            stamp: f.stamp(&input[0]),
            redaction: None,
        },
        &mut decode(),
        &mut work(),
        &mut work(),
        &mut work(),
        &mut WorkBudget::new(0),
        &mut work(),
    )?;
    assert!(matches!(
        FramedJpegHogPipeline::new(inner, basis(), &mut work()),
        Err(FramedHogError::BasisMismatch)
    ));
    Ok(())
}
#[test]
fn zone_postcommit_pressure_retains_source_and_resumes_without_inference() -> Test {
    let f = Fixture::new()?;
    let inputs = frames(basis(), &[JPEG], 7)?;
    let mut full = f.owner(basis())?;
    let mut measured = work();
    complete(f.run(&mut full, &inputs[0], &mut work(), &mut measured)?)?;
    let expected = full.completion();
    let mut p = f.owner(basis())?;
    assert!(matches!(
        f.run(
            &mut p,
            &inputs[0],
            &mut work(),
            &mut WorkBudget::new(measured.used() - 1)
        )?,
        JpegHogProgress::Pending {
            stage: JpegHogStage::Zones,
            ..
        }
    ));
    assert_eq!(p.source_receipt(), expected.map(|r| r.source));
    assert!(p.completion().is_none());
    assert_eq!(
        p.pipeline().zones().pipeline().tracker().exposure_count(),
        1
    );
    complete(p.resume(&mut WorkBudget::new(0), &mut work())?)?;
    assert_eq!(p.completion(), expected);
    Ok(())
}
#[test]
fn empty_resume_and_pending_watchdog_do_not_create_source_receipts() -> Test {
    let f = Fixture::new()?;
    let mut p = f.owner(basis())?;
    assert_eq!(
        p.resume(&mut work(), &mut work()),
        Err(FramedHogError::Analysis(JpegHogError::NoObservation))
    );
    assert!(p.source_receipt().is_none());
    let input = frames(basis(), &[JPEG], 7)?;
    f.run(&mut p, &input[0], &mut WorkBudget::new(0), &mut work())?;
    let source = p.source_receipt();
    p.poll(1041)?;
    assert_eq!(p.source_receipt(), source);
    assert_eq!(p.pipeline().stage(), JpegHogStage::Inference);
    Ok(())
}
