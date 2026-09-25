#![forbid(unsafe_code)]
//! Real pretrained coefficients and native JPEG pixels through the live-source owner.
//! Upsampling the tiny codec fixture exercises composition, not detector quality.
use super::*;
use crate::ingest::http_camera::learned::*;
use crate::ingest::privacy_mask::live::MaskRefusal;
use crate::ingest::privacy_mask::live::fixture::MaskFixture;
use fss_geometry::{PinholeIntrinsics, WorkBudget};
use fss_twin::foreground::pipeline::FrameCapture;
use fss_twin::foreground::{BackgroundPolicy, ForegroundPolicy};
use fss_twin::hog_scan::{ScanLevel, ScanPolicy};
use fss_twin::image_tracking::ImageTrackingPolicy;
use fss_twin::image_zones::pipeline::ImageZonePipeline;
use fss_twin::image_zones::{ImageZoneBasis, ImageZonePolicy, ImageZoneSpec};
use fss_twin::mjpeg::{
    JpegBackground, JpegDecodeRequest, JpegFrameBinding, JpegReference, decode_rectified_redacted,
    decoded_image_domain,
};
use fss_twin::pretrained_hog::load_opencv_people_candidate;
use fss_twin::rectification::{LensDistortion, LumaRange, RectificationPlan, RectificationSpec};
use fss_twin::screening::tracking::hog::jpeg::{JpegHogConfig, JpegHogPipeline, JpegHogStage};
use fss_twin::screening::{ScreeningPolicy, ScreeningStamp};

const WORK: u64 = 1_000_000_000;
const BACKGROUND: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fss-codec-mjpeg/tests/fixtures/background.jpg"
));
fn work() -> WorkBudget<'static> {
    WorkBudget::new(WORK)
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    ContentDigest::sha256(bytes).bytes()
}
fn binding(bytes: &[u8], mask: &[u8], exposure: u8) -> JpegFrameBinding {
    JpegFrameBinding {
        encoded_sha256: hash(bytes),
        exposure: [exposure; 32],
        allowed_mask: hash(mask),
        camera_image_domain: [7; 32],
        calibration: [8; 32],
        interpretation: ComponentInterpretation::Grayscale,
    }
}
/// Owner permission grid, frozen background and decoded image domain under one binding.
type Frozen = (Vec<u8>, JpegBackground, [u8; 32]);
struct Fixture {
    plan: RectificationPlan,
    background: JpegBackground,
    mask: Vec<u8>,
    basis: ImageZoneBasis,
    privacy: MaskFixture,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::build(MaskFixture::new("hog")?)
    }
    fn build(privacy: MaskFixture) -> Result<Self, Box<dyn std::error::Error>> {
        let source = PinholeIntrinsics::new(17, 13, 20.0, 20.0, 8.5, 6.5)?;
        let target = PinholeIntrinsics::new(64, 128, 200.0, 400.0, 32.0, 64.0)?;
        let plan = RectificationPlan::compile(
            RectificationSpec {
                source,
                target,
                distortion: LensDistortion::Pinhole,
                maximum_radius: 1.0,
                source_domain: decoded_image_domain([7; 32], ComponentInterpretation::Grayscale),
                calibration: [8; 32],
                range: LumaRange::Full,
            },
            &mut work(),
        )?;
        let (mask, background, image_domain) = Self::freeze(&plan, &privacy)?;
        let basis = ImageZoneBasis {
            camera: 1,
            clock: 2,
            calibration: [8; 32],
            image_domain,
            dimensions: [64, 128],
        };
        Ok(Self {
            plan,
            background,
            mask,
            basis,
            privacy,
        })
    }
    /// The owner permission grid excludes exactly the sensor's currently masked pixels, and the
    /// frozen background references are decoded under the same current mask.
    fn freeze(
        plan: &RectificationPlan,
        privacy: &MaskFixture,
    ) -> Result<Frozen, Box<dyn std::error::Error>> {
        let current = privacy.mask().resolve()?;
        let redaction = current.luma_redaction();
        let mask = current.allowed([17, 13])?;
        let mut images = Vec::new();
        for exposure in 1..=3 {
            images.push(decode_rectified_redacted(
                plan,
                JpegDecodeRequest {
                    bytes: BACKGROUND,
                    mask: &mask,
                    source: binding(BACKGROUND, &mask, exposure),
                    limits: DecodeLimits::default(),
                    redaction,
                },
                &mut budget(),
                &mut work(),
            )?);
        }
        let refs: Vec<JpegReference<'_>> = images
            .iter()
            .zip([10, 20, 30])
            .map(|(image, at)| JpegReference {
                image,
                capture: FrameCapture {
                    camera: 1,
                    clock: 2,
                    capture: [at; 2],
                },
            })
            .collect();
        let background = JpegBackground::build(
            plan,
            &refs,
            BackgroundPolicy {
                selection_evidence: [9; 32],
                validity: [0, 10_000],
                maximum_spread: 0,
            },
            &mut work(),
        )?;
        Ok((mask, background, images[0].frame().identity().image_domain))
    }
    /// Refreeze the permission grid and background under the sensor's current mask (after a
    /// policy change the old background is refused as unmasked access).
    fn refreeze(&mut self) -> Test {
        let (mask, background, _) = Self::freeze(&self.plan, &self.privacy)?;
        self.mask = mask;
        self.background = background;
        Ok(())
    }
    fn processor(&self) -> Result<JpegHogPipeline, Box<dyn std::error::Error>> {
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
        Ok(JpegHogPipeline::new(
            zones,
            load_opencv_people_candidate(&mut work())?,
            JpegHogConfig {
                stream_generation: 3,
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
                    minimum_margin: -100.0,
                    suppression_iou_ppm: 1_000_000,
                    maximum_windows: 64,
                    maximum_candidates: 64,
                },
            },
            &mut work(),
        )?)
    }
    fn owner(
        &self,
        source: &[u8],
        chunk: usize,
    ) -> Result<HttpHogCapture, Box<dyn std::error::Error>> {
        Ok(HttpHogCapture::attach(
            camera(source, chunk, HttpCameraLimits::default())?,
            self.processor()?,
        )?)
    }
    fn context<'a>(
        &'a self,
        c: &HttpHogCapture,
        n: u64,
    ) -> Result<HttpFrameContext<'a>, Box<dyn std::error::Error>> {
        let bytes = c.frame().ok_or("source missing")?.part().bytes();
        Ok(HttpFrameContext {
            expected_head: c.frame().ok_or("source missing")?.head(),
            mask: &self.mask,
            binding: binding(bytes, &self.mask, (10 + n) as u8),
            capture: FrameCapture {
                camera: 1,
                clock: 2,
                capture: [80 + n * 20; 2],
            },
            foreground_policy: ForegroundPolicy {
                minimum_change: 10,
                minimum_area: 1,
                maximum_regions: 128,
                widespread_per_mille: 1000,
            },
            decode_limits: DecodeLimits::default(),
            stamp: ScreeningStamp {
                stream_generation: 3,
                sequence: n,
                received_at_ns: 80 + n * 20,
                owner_requests_analysis: false,
            },
            privacy: self.privacy.mask(),
        })
    }
    /// One analysis attempt with an explicit permission grid and background.
    fn attempt(
        &self,
        c: &mut HttpHogCapture,
        n: u64,
        mask: &[u8],
        background: &JpegBackground,
        a: &dyn HttpCameraAuthority,
    ) -> Result<HttpHogStep, HttpHogError> {
        let mut context = self
            .context(c, n)
            .map_err(|_| HttpHogError::FrameMismatch)?;
        let bytes = c.frame().ok_or(HttpHogError::FrameMismatch)?.part().bytes();
        context.mask = mask;
        context.binding = binding(bytes, mask, (10 + n) as u8);
        c.analyze(
            context,
            Some(background),
            &self.plan,
            80 + n * 20,
            a,
            HttpHogBudgets {
                decode: &mut budget(),
                rectification: &mut work(),
                foreground: &mut work(),
                health: &mut work(),
                inference: &mut work(),
                downstream: &mut work(),
            },
        )
    }
    fn analyze(
        &self,
        c: &mut HttpHogCapture,
        n: u64,
        a: &dyn HttpCameraAuthority,
        inference: &mut WorkBudget<'static>,
        downstream: &mut WorkBudget<'static>,
    ) -> Result<HttpHogStep, Box<dyn std::error::Error>> {
        let ctx = self.context(c, n)?;
        Ok(c.analyze(
            ctx,
            Some(&self.background),
            &self.plan,
            80 + n * 20,
            a,
            HttpHogBudgets {
                decode: &mut budget(),
                rectification: &mut work(),
                foreground: &mut work(),
                health: &mut work(),
                inference,
                downstream,
            },
        )?)
    }
}
fn ready(c: &mut HttpHogCapture, a: &dyn HttpCameraAuthority, now: u64) -> Test {
    let mut framing = budget();
    for _ in 0..50_000 {
        match c.step(now, a, &mut framing)? {
            HttpHogStep::Source(HttpCameraStep::WireReady(r)) => c.acknowledge_wire(r, now, a)?,
            HttpHogStep::AwaitingContext => return Ok(()),
            HttpHogStep::Source(HttpCameraStep::Pending | HttpCameraStep::Advanced) => {}
            other => return Err(format!("unexpected readiness step: {other:?}").into()),
        }
    }
    Err("readiness bound exceeded".into())
}
fn completed(step: HttpHogStep) -> Result<HttpHogCompletion, Box<dyn std::error::Error>> {
    match step {
        HttpHogStep::ResultReady(r) => Ok(r),
        other => Err(format!("not complete: {other:?}").into()),
    }
}
#[test]
fn actual_coefficients_and_native_jpeg_reach_exact_current_source_linked_zones() -> Test {
    let f = Fixture::new()?;
    let source = response(true, false, 2);
    let mut expected = None;
    for chunk in [1, 7, 4096] {
        let mut c = f.owner(&source, chunk)?;
        let a = Authority::new(c.camera().route());
        ready(&mut c, &a, 100)?;
        assert!(c.analysis().is_none());
        let result = completed(f.analyze(&mut c, 1, &a, &mut work(), &mut work())?)?;
        let p = c.analysis().ok_or("accepted analysis lost")?;
        assert_eq!(result.encoded_sha256(), hash(JPEG));
        assert_eq!(result.ordinal(), 1);
        assert_eq!(
            p.scan().ok_or("scan missing")?.model_digest(),
            p.model().digest()
        );
        assert_eq!(p.scan().ok_or("scan missing")?.selected().count(), 1);
        assert_eq!(
            p.zone_report().ok_or("zone report missing")?.digest(),
            result.analysis().zones
        );
        assert_eq!(
            p.tracking_report().ok_or("tracking missing")?.digest(),
            result.analysis().tracking
        );
        assert!(
            p.image()
                .ok_or("screen missing")?
                .screening()
                .last_completed_analysis()
                .is_none()
        );
        if let Some(expected) = expected {
            assert_eq!(result, expected);
        } else {
            expected = Some(result);
        }
        let source = c.acknowledge_result(result, 100, &a)?;
        assert_eq!(source.part().bytes(), JPEG);
        assert_eq!(c.last_acknowledged(), Some(result));
        assert!(c.analysis().is_none());
        assert!(c.completion().is_none());
        ready(&mut c, &a, 120)?;
        assert_eq!(
            c.frame()
                .ok_or("second frame missing")?
                .part()
                .receipt()
                .ordinal,
            2
        );
        assert!(c.analysis().is_none());
    }
    Ok(())
}
#[test]
fn inference_and_tracking_pressure_block_all_source_advance_and_exact_resume() -> Test {
    let f = Fixture::new()?;
    let mut c = f.owner(&response(false, false, 2), 4096)?;
    let a = Authority::new(c.camera().route());
    ready(&mut c, &a, 100)?;
    let counts = c.camera().totals();
    assert_eq!(
        f.analyze(&mut c, 1, &a, &mut WorkBudget::new(0), &mut work())?,
        HttpHogStep::AnalysisPending(JpegHogStage::Inference)
    );
    for _ in 0..3 {
        assert_eq!(
            c.step(100, &a, &mut DecodeBudget::new(0))?,
            HttpHogStep::AnalysisPending(JpegHogStage::Inference)
        );
    }
    assert_eq!(c.camera().totals(), counts);
    let ctx = f.context(&c, 1)?;
    assert_eq!(
        c.analyze(
            ctx,
            Some(&f.background),
            &f.plan,
            100,
            &a,
            HttpHogBudgets {
                decode: &mut budget(),
                rectification: &mut work(),
                foreground: &mut work(),
                health: &mut work(),
                inference: &mut work(),
                downstream: &mut work()
            }
        ),
        Err(HttpHogError::AlreadyAccepted)
    );
    assert_eq!(
        c.resume(100, &a, &mut work(), &mut WorkBudget::new(0), &mut work())?,
        HttpHogStep::AnalysisPending(JpegHogStage::Tracking)
    );
    let scan = c
        .analysis()
        .ok_or("pending analysis lost")?
        .scan()
        .ok_or("scan lost")?
        .digest();
    let mut zero = WorkBudget::new(0);
    let result = completed(c.resume(100, &a, &mut zero, &mut work(), &mut work())?)?;
    assert_eq!(zero.used(), 0);
    assert_eq!(result.analysis().scan, scan);
    assert_eq!(c.camera().totals(), counts);
    for _ in 0..3 {
        assert_eq!(
            c.step(100, &a, &mut DecodeBudget::new(0))?,
            HttpHogStep::ResultReady(result)
        );
    }
    assert_eq!(
        c.resume(
            100,
            &a,
            &mut WorkBudget::new(0),
            &mut WorkBudget::new(0),
            &mut WorkBudget::new(0)
        )?,
        HttpHogStep::ResultReady(result)
    );
    assert_eq!(c.camera().totals(), counts);
    assert_eq!(
        c.analysis()
            .ok_or("analysis lost")?
            .zones()
            .pipeline()
            .tracker()
            .exposure_count(),
        1
    );
    let frame = c.acknowledge_result(result, 100, &a)?;
    assert_eq!(frame.part().bytes(), JPEG);
    ready(&mut c, &a, 120)?;
    let second = completed(f.analyze(&mut c, 2, &a, &mut work(), &mut work())?)?;
    assert!(matches!(
        c.acknowledge_result(result, 120, &a),
        Err(HttpHogError::ReceiptMismatch)
    ));
    assert_eq!(c.completion(), Some(second));
    assert_eq!(
        c.frame()
            .ok_or("second frame lost")?
            .part()
            .receipt()
            .ordinal,
        2
    );
    Ok(())
}
#[test]
fn every_downstream_boundary_keeps_the_accepted_stage_and_source() -> Test {
    let f = Fixture::new()?;
    let source = response(false, false, 1);
    let mut full = f.owner(&source, 4096)?;
    let a = Authority::new(full.camera().route());
    ready(&mut full, &a, 100)?;
    let mut measured = work();
    let expected = completed(f.analyze(&mut full, 1, &a, &mut work(), &mut measured)?)?;
    let units = measured.used();
    let mut saw_tracking = false;
    let mut saw_zones = false;
    for cut in [0, 1, 1024, units / 2, units - 1, units] {
        let mut c = f.owner(&source, 4096)?;
        ready(&mut c, &a, 100)?;
        let counts = c.camera().totals();
        match f.analyze(&mut c, 1, &a, &mut work(), &mut WorkBudget::new(cut))? {
            HttpHogStep::AnalysisPending(JpegHogStage::Tracking) => saw_tracking = true,
            HttpHogStep::AnalysisPending(JpegHogStage::Zones) => {
                saw_zones = true;
                let p = c.analysis().ok_or("accepted analysis lost")?;
                assert_eq!(
                    p.tracking_report()
                        .ok_or("accepted tracking lost")?
                        .digest(),
                    expected.analysis().tracking
                );
                assert!(p.zone_report().is_none());
            }
            HttpHogStep::ResultReady(result) => assert_eq!(result, expected),
            other => return Err(format!("unexpected stage: {other:?}").into()),
        }
        assert_eq!(
            completed(c.resume(100, &a, &mut WorkBudget::new(0), &mut work(), &mut work())?)?,
            expected
        );
        assert_eq!(c.camera().totals(), counts);
        assert_eq!(c.frame().ok_or("source lost")?.part().bytes(), JPEG);
        assert_eq!(
            c.analysis()
                .ok_or("analysis lost")?
                .zones()
                .pipeline()
                .tracker()
                .exposure_count(),
            1
        );
    }
    assert!(saw_tracking && saw_zones);
    Ok(())
}
#[test]
fn source_context_mismatch_refuses_before_any_analysis_credit() -> Test {
    let f = Fixture::new()?;
    let mut c = f.owner(&response(false, false, 1), 4096)?;
    let a = Authority::new(c.camera().route());
    ready(&mut c, &a, 100)?;
    let good = f.context(&c, 1)?;
    for kind in 0..4 {
        let mut bad = good;
        match kind {
            0 => bad.expected_head.wire.source = [99; 32],
            1 => bad.binding.encoded_sha256 = [99; 32],
            2 => bad.stamp.sequence = 2,
            _ => bad.stamp.stream_generation = 4,
        }
        assert_eq!(
            c.analyze(
                bad,
                Some(&f.background),
                &f.plan,
                100,
                &a,
                HttpHogBudgets {
                    decode: &mut budget(),
                    rectification: &mut work(),
                    foreground: &mut work(),
                    health: &mut work(),
                    inference: &mut work(),
                    downstream: &mut work()
                }
            ),
            Err(HttpHogError::FrameMismatch)
        );
        assert!(c.analysis().is_none());
        assert!(c.camera().failure().is_none());
    }
    let _complete = completed(f.analyze(&mut c, 1, &a, &mut work(), &mut work())?)?;
    Ok(())
}
#[test]
fn decode_refusal_and_linking_budget_refusal_leave_original_frame_retryable() -> Test {
    let f = Fixture::new()?;
    let mut c = f.owner(&response(false, false, 1), 4096)?;
    let a = Authority::new(c.camera().route());
    ready(&mut c, &a, 100)?;
    let counts = c.camera().totals();
    let ctx = f.context(&c, 1)?;
    assert!(matches!(
        c.analyze(
            ctx,
            Some(&f.background),
            &f.plan,
            100,
            &a,
            HttpHogBudgets {
                decode: &mut DecodeBudget::new(0),
                rectification: &mut work(),
                foreground: &mut work(),
                health: &mut work(),
                inference: &mut work(),
                downstream: &mut work()
            }
        ),
        Err(HttpHogError::Processing(_))
    ));
    assert!(c.processing_error().is_some());
    assert!(c.analysis().is_none());
    assert_eq!(c.camera().totals(), counts);
    assert!(matches!(
        c.analyze(
            ctx,
            Some(&f.background),
            &f.plan,
            100,
            &a,
            HttpHogBudgets {
                decode: &mut budget(),
                rectification: &mut WorkBudget::new(0),
                foreground: &mut work(),
                health: &mut work(),
                inference: &mut work(),
                downstream: &mut work()
            }
        ),
        Err(HttpHogError::Work(_))
    ));
    let _complete = completed(f.analyze(&mut c, 1, &a, &mut work(), &mut work())?)?;
    assert!(c.processing_error().is_none());
    assert_eq!(c.camera().totals(), counts);
    Ok(())
}
#[test]
fn post_analysis_revocation_retains_complete_or_pending_state_with_original_source() -> Test {
    let f = Fixture::new()?;
    for infer in [0, WORK] {
        let mut c = f.owner(&response(false, false, 1), 4096)?;
        let allow = Authority::new(c.camera().route());
        ready(&mut c, &allow, 100)?;
        let deny = Authority::deny(c.camera().route(), HttpCameraOperation::Analyze, 2);
        let ctx = f.context(&c, 1)?;
        assert_eq!(
            c.analyze(
                ctx,
                Some(&f.background),
                &f.plan,
                100,
                &deny,
                HttpHogBudgets {
                    decode: &mut budget(),
                    rectification: &mut work(),
                    foreground: &mut work(),
                    health: &mut work(),
                    inference: &mut WorkBudget::new(infer),
                    downstream: &mut work()
                }
            ),
            Err(HttpHogError::Source(HttpCameraError::Denied(
                HttpCameraDenial::Revoked
            )))
        );
        let retired = c.retire();
        assert_eq!(
            retired
                .source
                .frame
                .ok_or("original source lost")?
                .part()
                .bytes(),
            JPEG
        );
        assert!(retired.current_source_digest.is_some());
        assert!(retired.processor.image().is_some());
        if infer == 0 {
            assert_eq!(retired.processor.stage(), JpegHogStage::Inference);
            assert!(retired.complete.is_none());
        } else {
            assert_eq!(retired.processor.stage(), JpegHogStage::Complete);
            assert!(retired.complete.is_some());
        }
    }
    Ok(())
}
#[test]
fn late_result_release_denial_does_not_drop_source_or_grant_custody() -> Test {
    let f = Fixture::new()?;
    let mut c = f.owner(&response(false, false, 2), 4096)?;
    let a = Authority::new(c.camera().route());
    ready(&mut c, &a, 100)?;
    let result = completed(f.analyze(&mut c, 1, &a, &mut work(), &mut work())?)?;
    let deny = Authority::deny(c.camera().route(), HttpCameraOperation::ReleaseFrame, 1);
    assert!(matches!(
        c.acknowledge_result(result, 100, &deny),
        Err(HttpHogError::Source(HttpCameraError::Denied(
            HttpCameraDenial::Revoked
        )))
    ));
    assert_eq!(c.completion(), Some(result));
    assert!(c.last_acknowledged().is_none());
    assert_eq!(c.frame().ok_or("frame lost")?.part().bytes(), JPEG);
    Ok(())
}
#[test]
fn source_lineage_distinguishes_http_transfer_without_faking_independent_images() -> Test {
    let f = Fixture::new()?;
    let mut results = Vec::new();
    for chunked in [false, true] {
        let mut c = f.owner(&response(chunked, false, 1), 4096)?;
        let a = Authority::new(c.camera().route());
        ready(&mut c, &a, 100)?;
        results.push(completed(f.analyze(
            &mut c,
            1,
            &a,
            &mut work(),
            &mut work(),
        )?)?);
    }
    assert_eq!(results[0].encoded_sha256(), results[1].encoded_sha256());
    assert_eq!(results[0].analysis(), results[1].analysis());
    assert_ne!(results[0].source_digest(), results[1].source_digest());
    assert_ne!(results[0].digest(), results[1].digest());
    Ok(())
}
#[test]
fn watchdog_remains_available_during_model_pressure_without_reading_more_source() -> Test {
    let f = Fixture::new()?;
    let mut c = f.owner(&response(false, false, 2), 4096)?;
    let a = Authority::new(c.camera().route());
    ready(&mut c, &a, 100)?;
    let pending = f.analyze(&mut c, 1, &a, &mut WorkBudget::new(0), &mut work())?;
    assert_eq!(
        pending,
        HttpHogStep::AnalysisPending(JpegHogStage::Inference)
    );
    let counts = c.camera().totals();
    assert!(c.poll_health(1100, &a)?.stalled);
    assert_eq!(c.camera().totals(), counts);
    assert_eq!(c.step(1100, &a, &mut DecodeBudget::new(0))?, pending);
    Ok(())
}
#[test]
fn attachment_refusal_returns_both_original_owners() -> Test {
    let f = Fixture::new()?;
    let mut c = camera(
        &response(false, false, 1),
        4096,
        HttpCameraLimits::default(),
    )?;
    let a = Authority::new(c.route());
    let wire = wire_ready(&mut c, &a)?;
    let counts = c.totals();
    let refusal = HttpHogCapture::attach(c, f.processor()?)
        .err()
        .ok_or("nonfresh source accepted")?;
    assert_eq!(refusal.camera.totals(), counts);
    assert_eq!(
        refusal
            .camera
            .pending_wire()
            .ok_or("pending wire lost")?
            .receipt(),
        wire
    );
    assert_eq!(refusal.processor.stage(), JpegHogStage::AwaitingImage);
    Ok(())
}
#[test]
fn real_tcp_bytes_flow_to_pretrained_inference_before_a_second_source_read() -> Test {
    let f = Fixture::new()?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let peer = listener.local_addr()?;
    let source = response(false, false, 2);
    let original = source.clone();
    let handle = std::thread::spawn(move || -> io::Result<()> {
        let until = Instant::now() + Duration::from_secs(8);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(e) => return Err(e),
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut request = Vec::new();
        while request.len() < 4096 && !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];
            socket.read_exact(&mut byte)?;
            request.push(byte[0]);
        }
        if !request.starts_with(b"GET /video HTTP/1.1\r\n") {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        socket.write_all(&source)?;
        Ok(())
    });
    let r = HttpCameraRoute::new(
        StreamBasis {
            source: [7; 32],
            generation: 3,
        },
        peer,
        "localhost",
        "/video",
        HttpCameraSecurity::OwnerApprovedPlaintext,
    )?;
    let a = Authority::new(&r);
    let camera = HttpCamera::connect(r, HttpCameraLimits::default(), 0, 10_000_000_000, &a)?;
    let mut c = HttpHogCapture::attach(camera, f.processor()?)?;
    let mut framing = budget();
    let until = Instant::now() + Duration::from_secs(6);
    let mut saved = Vec::new();
    let mut done = false;
    while Instant::now() < until {
        match c.step(100, &a, &mut framing)? {
            HttpHogStep::Source(HttpCameraStep::WireReady(r)) => {
                saved.extend_from_slice(c.pending_wire().ok_or("wire missing")?.bytes());
                c.acknowledge_wire(r, 100, &a)?;
            }
            HttpHogStep::Source(HttpCameraStep::Pending) => {
                std::thread::sleep(Duration::from_millis(1))
            }
            HttpHogStep::Source(HttpCameraStep::Advanced) => {}
            HttpHogStep::AwaitingContext => {
                done = true;
                break;
            }
            other => return Err(format!("unexpected live step: {other:?}").into()),
        }
    }
    assert!(done);
    let counts = c.camera().totals();
    let result = completed(f.analyze(&mut c, 1, &a, &mut work(), &mut work())?)?;
    assert_eq!(
        c.step(100, &a, &mut DecodeBudget::new(0))?,
        HttpHogStep::ResultReady(result)
    );
    assert_eq!(c.camera().totals(), counts);
    let frame = c.frame().ok_or("frame lost")?;
    for map in frame.source_spans() {
        assert_eq!(
            &saved[map.wire_range[0] as usize..map.wire_range[1] as usize],
            &JPEG[map.jpeg_range[0] as usize..map.jpeg_range[1] as usize]
        );
    }
    assert_eq!(&saved[..], &original[..saved.len()]);
    assert_eq!(result.encoded_sha256(), hash(JPEG));
    handle.join().map_err(|_| "native server failed")??;
    Ok(())
}

#[test]
fn pending_wire_owner_moves_between_tasks_without_reading_or_discarding_source() -> Test {
    let input = response(false, false, 1);
    let mut c = camera(&input, 4096, HttpCameraLimits::default())?;
    let a = Authority::new(c.route());
    let receipt = wire_ready(&mut c, &a)?;
    let totals = c.totals();
    let handle = std::thread::spawn(move || -> Result<HttpCameraRetirement, HttpCameraError> {
        let a = Authority::new(c.route());
        if c.step(11, &a, &mut budget())? != HttpCameraStep::WireReady(receipt) {
            return Err(HttpCameraError::ReceiptMismatch);
        }
        Ok(c.retire())
    });
    let retired = handle.join().map_err(|_| "source owner task failed")??;
    assert_eq!(retired.totals, totals);
    let wire = retired.wire.ok_or("wire handoff lost source")?;
    assert_eq!(wire.receipt(), receipt);
    assert_eq!(wire.bytes(), input);
    assert!(!wire.acknowledged());
    Ok(())
}
#[test]
fn accepted_model_work_moves_between_tasks_and_resumes_the_same_source() -> Test {
    let f = Fixture::new()?;
    let mut c = f.owner(&response(false, false, 2), 4096)?;
    let a = Authority::new(c.camera().route());
    ready(&mut c, &a, 100)?;
    assert_eq!(
        f.analyze(&mut c, 1, &a, &mut WorkBudget::new(0), &mut work())?,
        HttpHogStep::AnalysisPending(JpegHogStage::Inference)
    );
    let counts = c.camera().totals();
    let image = c
        .analysis()
        .ok_or("analysis lost")?
        .image()
        .ok_or("image lost")?
        .digest();
    let handle = std::thread::spawn(
        move || -> Result<(HttpHogRetirement, HttpHogCompletion), HttpHogError> {
            let a = Authority::new(c.camera().route());
            let result = match c.resume(100, &a, &mut work(), &mut work(), &mut work())? {
                HttpHogStep::ResultReady(result) => result,
                _ => return Err(HttpHogError::NotReady),
            };
            Ok((c.retire(), result))
        },
    );
    let (retired, result) = handle.join().map_err(|_| "learned owner task failed")??;
    assert_eq!(retired.source.totals, counts);
    assert_eq!(result.analysis().image, image);
    assert_eq!(retired.complete, Some(result));
    assert_eq!(retired.processor.stage(), JpegHogStage::Complete);
    assert_eq!(
        retired
            .source
            .frame
            .ok_or("frame handoff lost source")?
            .part()
            .bytes(),
        JPEG
    );
    assert_eq!(
        retired
            .processor
            .zones()
            .pipeline()
            .tracker()
            .exposure_count(),
        1
    );
    Ok(())
}

/// A grayscale 17x13 frame equal to the uniform background everywhere except the 8x8 block at
/// the origin (block-aligned, quality 100: the uniform blocks decode to exactly 128 again).
fn motion_jpeg() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
    let mut pixels = vec![128_u8; 17 * 13];
    for y in 0..8 {
        for x in 0..8 {
            pixels[y * 17 + x] = if (x + y) % 2 == 0 { 250 } else { 5 };
        }
    }
    Ok(encode_jpeg(
        17,
        13,
        &pixels,
        &JpegConfig {
            quality: 100,
            subsampling: Subsampling::Grayscale,
            ..JpegConfig::default()
        },
    )?)
}
fn motion_response(jpeg: &[u8], count: usize) -> Vec<u8> {
    let mut body = Vec::new();
    for _ in 0..count {
        body.extend_from_slice(
            format!(
                "--fss\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
                jpeg.len()
            )
            .as_bytes(),
        );
        body.extend_from_slice(jpeg);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--fss--\r\n");
    let mut wire =
        b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=fss\r\n".to_vec();
    wire.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    wire.extend_from_slice(&body);
    wire
}
fn regions(c: &HttpHogCapture) -> Result<usize, Box<dyn std::error::Error>> {
    match c
        .analysis()
        .ok_or("analysis missing")?
        .image()
        .ok_or("screen missing")?
        .foreground()
    {
        fss_twin::screened_mjpeg::ForegroundStage::Complete(report) => Ok(report.regions().len()),
        other => Err(format!("foreground stage not complete: {other:?}").into()),
    }
}
fn decoded_luma(c: &HttpHogCapture) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(c.analysis()
        .ok_or("analysis missing")?
        .image()
        .ok_or("screen missing")?
        .source_receipt()
        .decode
        .luma_sha256)
}
const MOTION_BLOCK: [u32; 4] = [0, 0, 8, 8];

#[test]
fn motion_inside_the_sensor_mask_reaches_no_foreground_and_digests_only_masked_luma() -> Test {
    let jpeg = motion_jpeg()?;
    // Without a policy the block's motion is foreground; the decoded plane is the codec's.
    let open = Fixture::new()?;
    let mut c = HttpHogCapture::attach(
        camera(
            &motion_response(&jpeg, 1),
            4096,
            HttpCameraLimits::default(),
        )?,
        open.processor()?,
    )?;
    let a = Authority::new(c.camera().route());
    ready(&mut c, &a, 100)?;
    let unmasked = completed(open.analyze(&mut c, 1, &a, &mut work(), &mut work())?)?;
    assert!(regions(&c)? > 0, "unmasked motion is foreground");
    assert_eq!(unmasked.mask_policy(), None);
    assert_eq!(c.privacy_mask().label(), "no_policy_declared");
    let unmasked_luma = decoded_luma(&c)?;

    // With the sensor's policy over the block, the same frame has no foreground at all.
    let mut privacy = MaskFixture::new("hog-motion")?;
    let policy = privacy.declare([17, 13], &[MOTION_BLOCK])?;
    let retained = privacy.retained_luma_digest(&jpeg, ComponentInterpretation::Grayscale)?;
    let masked_fixture = Fixture::build(privacy)?;
    let mut c = HttpHogCapture::attach(
        camera(
            &motion_response(&jpeg, 1),
            4096,
            HttpCameraLimits::default(),
        )?,
        masked_fixture.processor()?,
    )?;
    let a = Authority::new(c.camera().route());
    ready(&mut c, &a, 100)?;
    let masked = completed(masked_fixture.analyze(&mut c, 1, &a, &mut work(), &mut work())?)?;
    assert_eq!(
        regions(&c)?,
        0,
        "motion inside the mask is never foreground"
    );
    assert_eq!(masked.mask_policy(), Some(policy));
    assert_eq!(masked.mask_generation(), Some(1));
    // The decoded-plane digest is the retained-decode masked digest of the same frame.
    assert_eq!(decoded_luma(&c)?, retained);
    assert_ne!(decoded_luma(&c)?, unmasked_luma);
    let receipt = c
        .analysis()
        .ok_or("analysis missing")?
        .image()
        .ok_or("screen missing")?
        .source_receipt();
    assert_eq!(receipt.raw.storage, retained);
    assert_eq!(receipt.redaction, Some(c.privacy_mask().digest().bytes()));
    assert_ne!(masked.digest(), unmasked.digest());
    Ok(())
}

#[test]
fn a_permission_grid_or_background_admitting_masked_pixels_is_refused_before_acceptance() -> Test {
    let open = Fixture::new()?;
    let mut privacy = MaskFixture::new("hog-refusal")?;
    privacy.declare([17, 13], &[MOTION_BLOCK])?;
    let f = Fixture::build(privacy)?;
    let mut c = f.owner(&response(false, false, 1), 4096)?;
    let a = Authority::new(c.camera().route());
    ready(&mut c, &a, 100)?;
    let everything = vec![1_u8; 17 * 13];
    for (mask, background) in [(&everything, &f.background), (&f.mask, &open.background)] {
        let refused = f.attempt(&mut c, 1, mask, background, &a);
        assert_eq!(
            refused,
            Err(HttpHogError::Privacy(MaskRefusal::UnmaskedAccess))
        );
        assert_eq!(
            MaskRefusal::UnmaskedAccess.stable_id(),
            "ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001"
        );
        assert!(c.analysis().is_none(), "nothing was accepted");
        assert!(c.frame().is_some(), "the original frame stays held");
    }
    // The corrected grid and masked background are accepted for the same frame.
    let result = completed(f.analyze(&mut c, 1, &a, &mut work(), &mut work())?)?;
    assert!(result.mask_policy().is_some());
    Ok(())
}

#[test]
fn a_policy_retained_mid_capture_applies_from_the_next_frame_only() -> Test {
    let mut f = Fixture::new()?;
    let mut c = f.owner(&response(false, false, 2), 4096)?;
    let a = Authority::new(c.camera().route());
    ready(&mut c, &a, 100)?;
    let first = completed(f.analyze(&mut c, 1, &a, &mut work(), &mut work())?)?;
    assert_eq!(first.mask_policy(), None);
    c.acknowledge_result(first, 100, &a)?;
    ready(&mut c, &a, 120)?;
    let policy = f.privacy.declare([17, 13], &[MOTION_BLOCK])?;
    // The grid and background frozen under the old (no) policy admit the newly masked pixels.
    assert_eq!(
        f.attempt(&mut c, 2, &f.mask, &f.background, &a),
        Err(HttpHogError::Privacy(MaskRefusal::UnmaskedAccess))
    );
    // A corrected grid alone is not enough: the old background holds unmasked pixels.
    let grid = MaskFixture::grid(&f.privacy, [17, 13])?;
    assert_eq!(
        f.attempt(&mut c, 2, &grid, &f.background, &a),
        Err(HttpHogError::Privacy(MaskRefusal::UnmaskedAccess))
    );
    f.refreeze()?;
    // The frame is accepted under the new generation: decoded, screened and scanned masked.
    // The running tracking episode is bound to the old permission grid, so it refuses this frame
    // (typed, retained) instead of silently mixing grids; the owner starts a new episode.
    let second = f.analyze(&mut c, 2, &a, &mut work(), &mut work())?;
    assert_eq!(second, HttpHogStep::AnalysisPending(JpegHogStage::Tracking));
    assert!(matches!(
        c.analysis_progress(),
        Some(
            fss_twin::screening::tracking::hog::jpeg::JpegHogProgress::Pending {
                error: fss_twin::screening::tracking::hog::jpeg::JpegHogRefusal::Tracking(_),
                ..
            }
        )
    ));
    assert_eq!(c.privacy_mask().policy_digest(), Some(policy));
    assert_eq!(c.privacy_mask().generation(), Some(1));
    let receipt = c
        .analysis()
        .ok_or("accepted frame lost")?
        .image()
        .ok_or("screen missing")?
        .source_receipt();
    assert_eq!(receipt.redaction, Some(c.privacy_mask().digest().bytes()));
    assert_eq!(receipt.decode.luma_sha256, receipt.raw.storage);
    // A fresh episode under the new grid completes the next frame under the new generation.
    let mut fresh = HttpHogCapture::attach(
        camera(
            &response(false, false, 1),
            4096,
            HttpCameraLimits::default(),
        )?,
        f.processor()?,
    )?;
    let fresh_authority = Authority::new(fresh.camera().route());
    ready(&mut fresh, &fresh_authority, 100)?;
    let next = completed(f.analyze(&mut fresh, 1, &fresh_authority, &mut work(), &mut work())?)?;
    assert_eq!(next.mask_policy(), Some(policy));
    assert_eq!(next.mask_generation(), Some(1));
    assert_ne!(next.digest(), first.digest());
    // The earlier record keeps the binding it was produced under.
    assert_eq!(c.last_acknowledged(), Some(first));
    assert_eq!(
        c.last_acknowledged().ok_or("history lost")?.mask_policy(),
        None
    );
    Ok(())
}

/// The no-policy completion keeps the bytes it had before live masking existed.
#[test]
fn no_policy_completion_digest_is_unchanged() -> Test {
    let f = Fixture::new()?;
    let mut c = f.owner(&response(false, false, 2), 4096)?;
    let a = Authority::new(c.camera().route());
    ready(&mut c, &a, 100)?;
    let result = completed(f.analyze(&mut c, 1, &a, &mut work(), &mut work())?)?;
    assert_eq!(result.mask_policy(), None);
    assert_eq!(result.digest(), GOLDEN_HOG_COMPLETION);
    assert_eq!(result.analysis().image, GOLDEN_HOG_IMAGE);
    Ok(())
}
// Captured from the pre-masking composition at 40bf5a6 (same fixture, frame 1).
const GOLDEN_HOG_COMPLETION: [u8; 32] = [
    35, 56, 253, 208, 202, 61, 98, 237, 30, 147, 57, 36, 89, 67, 247, 57, 80, 194, 237, 229, 40,
    121, 54, 12, 56, 145, 62, 34, 222, 121, 1, 23,
];
const GOLDEN_HOG_IMAGE: [u8; 32] = [
    73, 207, 178, 16, 178, 202, 184, 68, 209, 235, 30, 212, 205, 2, 234, 137, 103, 185, 242, 250,
    139, 231, 162, 203, 134, 13, 97, 208, 247, 61, 209, 172,
];
