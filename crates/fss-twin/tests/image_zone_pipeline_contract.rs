#![forbid(unsafe_code)]
//! Actual pixel/codec paths and transactional stage boundaries, not scripted labels.
use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits};
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, PinholeIntrinsics, WorkBudget};
use fss_twin::foreground::{BackgroundModel, BackgroundPolicy, ForegroundFrame, ForegroundPolicy,
    ForegroundReport, ForegroundSource};
use fss_twin::foreground::pipeline::{FrameCapture, RectifiedBackground, RectifiedReference};
use fss_twin::image_tracking::{ImageTracker, ImageTrackingError, ImageTrackingPolicy};
use fss_twin::image_zones::{ImageZoneBasis, ImageZoneError, ImageZoneEventKind, ImageZoneMonitor,
    ImageZonePolicy, ImageZoneRelation, ImageZoneSpec};
use fss_twin::image_zones::pipeline::*;
use fss_twin::localization::ImageIdentity;
use fss_twin::mjpeg::{JpegBackground, JpegFrameBinding, JpegReference, decode_rectified, decoded_image_domain};
use fss_twin::rectification::{LensDistortion, LumaRange, RawFrameIdentity, RawGrayFrame,
    RectificationPlan, RectificationSpec};

type Test = Result<(), Box<dyn Error>>;
const ALLOWANCE: u64 = 100_000_000;
const SECOND: u64 = 1_000_000_000;
fn work() -> WorkBudget<'static> { WorkBudget::new(ALLOWANCE) }
fn tracking_policy() -> ImageTrackingPolicy {
    ImageTrackingPolicy { maximum_tracks: 64, maximum_detections: 64, maximum_exposures: 64,
        minimum_observations: 2, maximum_misses: 2, maximum_gap_ns: 10*SECOND,
        maximum_speed: 100, gate_padding: 2, miss_cost: 1000, ambiguity_margin: 0 }
}
fn basis() -> ImageZoneBasis {
    ImageZoneBasis { camera: 1, clock: 2, calibration: [6;32], image_domain: [5;32], dimensions: [64,16] }
}
fn policy() -> ImageZonePolicy {
    ImageZonePolicy { selection_evidence: [30;32], maximum_sample_gap_ns: 3*SECOND }
}
fn zones() -> Vec<ImageZoneSpec> {
    vec![ImageZoneSpec { id: 1, vertices: vec![[20,1],[60,1],[60,14],[20,14]], margin: 0, dwell_ns: Some(2*SECOND) }]
}
fn pipeline() -> Result<ImageZonePipeline, ZonePipelineError> {
    ImageZonePipeline::new([40;32], tracking_policy(), basis(), policy(), &zones(), &mut work())
}
fn foreground_policy() -> ForegroundPolicy {
    ForegroundPolicy { minimum_change: 10, minimum_area: 1, maximum_regions: 64, widespread_per_mille: 900 }
}
fn pixels(rectangles: &[[usize;4]]) -> Vec<u8> {
    let mut values = vec![100;64*16];
    for &[left,top,right,bottom] in rectangles {
        for y in top..bottom { for x in left..right { values[y*64+x] = 160; } }
    }
    values
}
fn source(exposure: u8, pixels: &[u8]) -> ForegroundSource {
    ForegroundSource { image: ImageIdentity { exposure: [exposure;32],
        pixels: ContentDigest::sha256(pixels).bytes(), image_domain: [5;32], dimensions: [64,16] },
        camera: 1, calibration: [6;32], clock: 2, capture: [u64::from(exposure)*SECOND;2] }
}
fn report(exposure: u8, rectangles: &[[usize;4]], mask: &[u8]) -> Result<ForegroundReport, Box<dyn Error>> {
    let baseline = pixels(&[]); let allowed = vec![1;baseline.len()];
    let mut budget = work(); let mut frames = Vec::new();
    for exposure in 1..=3 {
        frames.push(ForegroundFrame::new(source(exposure,&baseline),&baseline,&allowed,&mut budget)?);
    }
    let model = BackgroundModel::build(&frames, BackgroundPolicy { selection_evidence: [9;32],
        validity: [0,u64::MAX], maximum_spread: 0 }, &mut budget)?;
    let query = pixels(rectangles);
    let frame = ForegroundFrame::new(source(exposure,&query),&query,mask,&mut budget)?;
    Ok(model.detect(&frame,foreground_policy(),&mut budget)?)
}
fn complete(progress: ZonePipelineProgress) -> Result<([u8;32],[u8;32]), Box<dyn Error>> {
    match progress {
        ZonePipelineProgress::Complete { tracking,zones } => Ok((tracking,zones)),
        ZonePipelineProgress::Pending { .. } => Err("unexpected pending zone stage".into()),
    }
}
#[test]
fn pixels_reach_entry_dwell_and_source_linked_operator_events() -> Test {
    let mut p = pipeline()?;
    for (exposure,left) in [(4,8),(5,16),(6,24),(7,28),(8,28)] {
        let foreground = report(exposure,&[[left,4,left+4,8]],&[1;1024])?;
        let (tracking,zones) = complete(p.observe_foreground(&foreground,&mut work())?)?;
        let result = p.zone_report().ok_or("missing zone result")?;
        assert_eq!(result.digest(),zones); assert_eq!(result.tracking_digest(),tracking);
        assert_eq!(result.frame().evidence,foreground.digest());
        assert_eq!(result.frame().source.image.exposure,[exposure;32]);
        assert_eq!(result.cells().len(),1);
        let kinds: Vec<_> = result.events().iter().map(|e|e.kind).collect();
        assert_eq!(kinds,match exposure {
            6 => vec![ImageZoneEventKind::EnteredBetweenObservations],
            8 => vec![ImageZoneEventKind::SampledDwell], _ => vec![],
        });
        if exposure==8 {
            assert_eq!(result.cells()[0].sampled_span_ns,Some([2*SECOND;2]));
            assert_eq!(result.events()[0].from.ok_or("missing dwell source")?.frame.source.image.exposure,[6;32]);
            assert_eq!(result.events()[0].to.frame.source.image.exposure,[8;32]);
        }
    }
    assert_eq!(p.tracker().tracks().len(),1);
    assert_eq!(p.tracker().tracks()[0].observations(),5);
    Ok(())
}
#[test]
fn direct_native_tracking_and_pipeline_have_identical_receipts() -> Test {
    let mut direct = ImageTracker::new([40;32],tracking_policy(),&mut work())?;
    let mut monitor = ImageZoneMonitor::new(&direct,basis(),policy(),&zones(),&mut work())?;
    let mut p = pipeline()?;
    for exposure in 4..=7 {
        let f = report(exposure,&[[24,4,28,8]],&[1;1024])?;
        let track = direct.update_foreground(&f,&mut work())?;
        let expected = monitor.observe(&direct,&track,&mut work())?.digest();
        assert_eq!(complete(p.observe_foreground(&f,&mut work())?)?,(track.digest(),expected));
    }
    Ok(())
}
#[test]
fn every_work_cut_preserves_accepted_receipts_and_resumes_only_unfinished_stage() -> Test {
    let first = report(4,&[[24,4,28,8]],&[1;1024])?;
    let second = report(5,&[[28,4,32,8]],&[1;1024])?;
    let third = report(6,&[[30,4,34,8]],&[1;1024])?;
    let mut full = pipeline()?;
    let initial = complete(full.observe_foreground(&first,&mut work())?)?;
    let mut measure = work();
    let expected = complete(full.observe_foreground(&second,&mut measure)?)?;
    let mut saw_before = false; let mut saw_after = false;
    for cut in 0..measure.used() {
        let mut p = pipeline()?;
        complete(p.observe_foreground(&first,&mut work())?)?;
        match p.observe_foreground(&second,&mut WorkBudget::new(cut)) {
            Err(ZonePipelineError::Tracking(ImageTrackingError::Geometry(GeometryError::BudgetExhausted))) => {
                saw_before = true;
                assert_eq!(p.tracker().digest(),initial.0); assert_eq!(p.tracker().exposure_count(),1);
                assert_eq!(p.zone_report().ok_or("lost prior result")?.digest(),initial.1);
                assert_eq!(complete(p.observe_foreground(&second,&mut work())?)?,expected);
            }
            Ok(ZonePipelineProgress::Pending { tracking,error:ImageZoneError::Geometry(GeometryError::BudgetExhausted) }) => {
                saw_after = true;
                assert_eq!(tracking,expected.0); assert_eq!(p.tracker().exposure_count(),2);
                assert_eq!(p.tracking_report().ok_or("lost accepted receipt")?.digest(),expected.0);
                assert_eq!(p.foreground_digest(),Some(second.digest()));
                assert!(p.zone_report().is_none()); assert!(p.is_pending());
                assert_eq!(p.observe_foreground(&third,&mut work()),Err(ZonePipelineError::PendingAnalysis));
                assert_eq!(p.tracker().digest(),expected.0);
                assert_eq!(complete(p.resume(&mut work())?)?,expected);
                assert_eq!(complete(p.resume(&mut WorkBudget::new(0))?)?,expected);
                assert_eq!(p.tracker().exposure_count(),2); assert!(!p.is_pending());
            }
            _ => return Err("budget cut failed to expose its exact stage".into()),
        }
    }
    assert!(saw_before && saw_after); Ok(())
}
#[test]
fn pending_cancellation_keeps_source_and_completed_retry_never_duplicates_dwell() -> Test {
    let f = report(4,&[[24,4,28,8]],&[1;1024])?;
    let mut direct = ImageTracker::new([40;32],tracking_policy(),&mut work())?;
    let mut measure = work(); direct.update_foreground(&f,&mut measure)?;
    let mut p = pipeline()?;
    assert!(matches!(p.observe_foreground(&f,&mut WorkBudget::new(measure.used()))?,ZonePipelineProgress::Pending{..}));
    let before = p.tracker().digest(); let cancel = AtomicBool::new(true);
    assert!(matches!(p.resume(&mut WorkBudget::cancellable(ALLOWANCE,&cancel))?,
        ZonePipelineProgress::Pending { error:ImageZoneError::Geometry(GeometryError::Cancelled),.. }));
    assert_eq!(p.tracker().digest(),before); assert!(p.zone_report().is_none());
    let result = complete(p.resume(&mut work())?)?;
    assert_eq!(complete(p.resume(&mut work())?)?,result);
    assert_eq!(p.zone_report().ok_or("missing zone result")?.events().len(),1);
    assert_eq!(p.tracker().exposure_count(),1);
    assert!(matches!(p.observe_foreground(&f,&mut work()),
        Err(ZonePipelineError::Tracking(ImageTrackingError::ReusedExposure))));
    assert_eq!(p.tracker().digest(),before); Ok(())
}
#[test]
fn zone_basis_and_privacy_generation_fail_before_consuming_source() -> Test {
    let f = report(4,&[[24,4,28,8]],&[1;1024])?;
    let mut wrong = basis(); wrong.camera = 99;
    let mut p = ImageZonePipeline::new([40;32],tracking_policy(),wrong,policy(),&zones(),&mut work())?;
    let before = p.tracker().digest();
    assert_eq!(p.resume(&mut work()),Err(ZonePipelineError::NoObservation));
    assert_eq!(p.observe_foreground(&f,&mut work()),Err(ZonePipelineError::Zones(ImageZoneError::BasisMismatch)));
    assert_eq!(p.tracker().digest(),before); assert!(p.tracking_report().is_none());
    let mut p = pipeline()?; complete(p.observe_foreground(&f,&mut work())?)?;
    let before = p.tracker().digest(); let mut mask = [1;1024]; mask[0]=0;
    let masked = report(5,&[[24,4,28,8]],&mask)?;
    assert_eq!(p.observe_foreground(&masked,&mut work()),
        Err(ZonePipelineError::Tracking(ImageTrackingError::BasisMismatch)));
    assert_eq!(p.tracker().digest(),before); assert_eq!(p.foreground_digest(),Some(f.digest()));
    assert!(!p.is_pending()); Ok(())
}
#[test]
fn broad_pixel_change_and_missing_foreground_do_not_accumulate_dwell_or_exit() -> Test {
    for (rectangles,relation) in [(vec![],ImageZoneRelation::Unobserved),
        (vec![[0,0,64,16]],ImageZoneRelation::Disturbed)] {
        let mut p = pipeline()?;
        complete(p.observe_foreground(&report(4,&[[24,4,28,8]],&[1;1024])?,&mut work())?)?;
        complete(p.observe_foreground(&report(5,&rectangles,&[1;1024])?,&mut work())?)?;
        let result = p.zone_report().ok_or("missing result")?;
        assert_eq!(result.cells()[0].relation,relation);
        assert_eq!(result.cells()[0].sampled_span_ns,None);
        assert_eq!(result.events()[0].kind,ImageZoneEventKind::ObservationInterrupted);
        assert!(!result.events().iter().any(|e|matches!(e.kind,
            ImageZoneEventKind::LeftBetweenObservations|ImageZoneEventKind::SampledDwell)));
    }
    Ok(())
}
fn raw_identity(plan:&RectificationPlan,pixels:&[u8],mask:&[u8],exposure:u8) -> RawFrameIdentity {
    RawFrameIdentity { exposure:[exposure;32],storage:ContentDigest::sha256(pixels).bytes(),
        allowed_mask:ContentDigest::sha256(mask).bytes(),image_domain:plan.spec().source_domain,
        calibration:plan.spec().calibration,dimensions:plan.spec().source.dimensions(),
        row_stride:plan.spec().source.dimensions()[0],range:LumaRange::Full }
}
#[test]
fn raw_luma_rectification_retains_source_and_reaches_zone_entry() -> Test {
    let mut budget = work();
    let k = PinholeIntrinsics::new(64,16,100.0,100.0,32.0,8.0)?;
    let plan = RectificationPlan::compile(RectificationSpec { source:k,target:k,
        distortion:LensDistortion::Pinhole,maximum_radius:1.0,source_domain:[7;32],
        calibration:[8;32],range:LumaRange::Full },&mut budget)?;
    let baseline=pixels(&[]); let mask=vec![1;1024]; let mut images=Vec::new();
    for exposure in 1..=3 {
        let raw=RawGrayFrame::new(raw_identity(&plan,&baseline,&mask,exposure),&baseline,&mask,&mut budget)?;
        images.push(plan.apply(&raw,&mut budget)?);
    }
    let refs:Vec<_>=images.iter().enumerate().map(|(i,frame)|RectifiedReference { frame,
        capture:FrameCapture { camera:1,clock:2,capture:[(i as u64+1)*SECOND;2] } }).collect();
    let background=RectifiedBackground::build(&plan,&refs,BackgroundPolicy { selection_evidence:[9;32],
        validity:[0,u64::MAX],maximum_spread:0 },&mut budget)?;
    let mut b=basis(); b.calibration=[8;32]; b.image_domain=plan.output_domain();
    let mut p=ImageZonePipeline::new([40;32],tracking_policy(),b,policy(),&zones(),&mut work())?;
    for (exposure,left) in [(4,8),(5,28)] {
        let query=pixels(&[[left,4,left+4,8]]);
        let raw=RawGrayFrame::new(raw_identity(&plan,&query,&mask,exposure),&query,&mask,&mut budget)?;
        let result=p.analyze_luma(&background,&plan,&raw,
            FrameCapture { camera:1,clock:2,capture:[u64::from(exposure)*SECOND;2] },foreground_policy(),&mut budget)?;
        complete(result.progress()?)?;
        assert_eq!(result.foreground().frame().receipt().source.storage,ContentDigest::sha256(&query).bytes());
        if exposure==5 {
            assert_eq!(p.zone_report().ok_or("missing result")?.events()[0].kind,
                ImageZoneEventKind::EnteredBetweenObservations);
        }
    }
    Ok(())
}
const BACKGROUND_JPEG:&[u8]=include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const QUERY_JPEG:&[u8]=include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
fn jpeg_binding(bytes:&[u8],mask:&[u8],exposure:u8) -> JpegFrameBinding {
    JpegFrameBinding { encoded_sha256:ContentDigest::sha256(bytes).bytes(),exposure:[exposure;32],
        allowed_mask:ContentDigest::sha256(mask).bytes(),camera_image_domain:[7;32],
        calibration:[8;32],interpretation:ComponentInterpretation::Grayscale }
}
fn jpeg_background() -> Result<(RectificationPlan,JpegBackground,Vec<u8>),Box<dyn Error>> {
    let mut geometry=work(); let mut decoder=DecodeBudget::new(ALLOWANCE);
    let k=PinholeIntrinsics::new(17,13,20.0,20.0,8.5,6.5)?;
    let plan=RectificationPlan::compile(RectificationSpec { source:k,target:k,
        distortion:LensDistortion::Pinhole,maximum_radius:1.0,
        source_domain:decoded_image_domain([7;32],ComponentInterpretation::Grayscale),
        calibration:[8;32],range:LumaRange::Full },&mut geometry)?;
    let mask=vec![1;221]; let mut frames=Vec::new();
    for exposure in 1..=3 {
        frames.push(decode_rectified(&plan,BACKGROUND_JPEG,&mask,jpeg_binding(BACKGROUND_JPEG,&mask,exposure),
            DecodeLimits::default(),&mut decoder,&mut geometry)?);
    }
    let refs:Vec<_>=frames.iter().enumerate().map(|(i,image)|JpegReference { image,
        capture:FrameCapture { camera:1,clock:2,capture:[(i as u64+1)*10;2] } }).collect();
    let model=JpegBackground::build(&plan,&refs,BackgroundPolicy { selection_evidence:[9;32],
        validity:[0,1000],maximum_spread:0 },&mut geometry)?;
    Ok((plan,model,mask))
}
fn jpeg_pipeline(plan:&RectificationPlan,maximum_exposures:usize) -> Result<ImageZonePipeline,ZonePipelineError> {
    let mut b=basis(); b.dimensions=[17,13]; b.calibration=[8;32]; b.image_domain=plan.output_domain();
    let zones=[ImageZoneSpec { id:1,vertices:vec![[0,0],[17,0],[17,13],[0,13]],margin:0,dwell_ns:None }];
    ImageZonePipeline::new([40;32],ImageTrackingPolicy { maximum_exposures,..tracking_policy() },b,policy(),&zones,&mut work())
}
#[test]
fn native_jpeg_keeps_encoded_source_and_all_derived_zone_relations() -> Test {
    let (plan,background,mask)=jpeg_background()?; let mut p=jpeg_pipeline(&plan,64)?;
    let binding=jpeg_binding(QUERY_JPEG,&mask,4);
    let result=p.analyze_jpeg(&background,&plan,JpegZoneInput { bytes:QUERY_JPEG,allowed:&mask,source:binding,
        capture:FrameCapture { camera:1,clock:2,capture:[40;2] },limits:DecodeLimits::default() },
        foreground_policy(),&mut DecodeBudget::new(ALLOWANCE),&mut work())?;
    let (tracking,zones)=complete(result.progress()?)?;
    assert_eq!(result.foreground().receipt().source,binding);
    let f=result.foreground().analysis().report(); assert!(!f.regions().is_empty());
    assert_eq!(p.tracking_report().ok_or("no tracking")?.decisions().len(),f.regions().len());
    let z=p.zone_report().ok_or("no zone result")?;
    assert_eq!(z.digest(),zones); assert_eq!(z.tracking_digest(),tracking);
    assert_eq!(z.frame().source.image.exposure,[4;32]); assert_eq!(z.frame().evidence,f.digest());
    assert_eq!(z.cells().len(),p.tracker().tracks().len());
    Ok(())
}
#[test]
fn malformed_jpeg_and_decode_budget_do_not_change_tracking_or_zone_state() -> Test {
    let (plan,background,mask)=jpeg_background()?; let mut p=jpeg_pipeline(&plan,64)?;
    let before=p.tracker().digest();
    for (bytes,allowance) in [(b"not a jpeg".as_slice(),ALLOWANCE),(QUERY_JPEG,0)] {
        let input=JpegZoneInput { bytes,allowed:&mask,source:jpeg_binding(bytes,&mask,4),
            capture:FrameCapture { camera:1,clock:2,capture:[40;2] },limits:DecodeLimits::default() };
        assert!(p.analyze_jpeg(&background,&plan,input,foreground_policy(),
            &mut DecodeBudget::new(allowance),&mut work()).is_err());
        assert_eq!(p.tracker().digest(),before); assert!(p.tracking_report().is_none());
        assert!(p.zone_report().is_none()); assert!(!p.is_pending());
    }
    Ok(())
}
#[test]
fn decoded_evidence_survives_when_episode_capacity_refuses_tracking() -> Test {
    let (plan,background,mask)=jpeg_background()?; let mut p=jpeg_pipeline(&plan,1)?;
    for exposure in [4,5] {
        let binding=jpeg_binding(QUERY_JPEG,&mask,exposure);
        let result=p.analyze_jpeg(&background,&plan,JpegZoneInput { bytes:QUERY_JPEG,allowed:&mask,source:binding,
            capture:FrameCapture { camera:1,clock:2,capture:[u64::from(exposure)*10;2] },limits:DecodeLimits::default() },
            foreground_policy(),&mut DecodeBudget::new(ALLOWANCE),&mut work())?;
        assert_eq!(result.foreground().receipt().source,binding);
        if exposure==4 { complete(result.progress()?)?; } else {
            assert_eq!(result.progress(),Err(ZonePipelineError::Tracking(ImageTrackingError::Limit)));
            assert!(!result.foreground().analysis().report().regions().is_empty());
        }
    }
    assert_eq!(p.tracker().exposure_count(),1); Ok(())
}
