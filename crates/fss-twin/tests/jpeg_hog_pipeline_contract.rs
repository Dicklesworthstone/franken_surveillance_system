#![forbid(unsafe_code)]
//! Native JPEG stage ownership and model execution. Synthetic coefficients test
//! plumbing, NOT pedestrian accuracy; enlarging fixtures adds no source detail.
use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_codec_mjpeg::{ComponentInterpretation as Color, DecodeBudget, DecodeLimits};
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, PinholeIntrinsics, WorkBudget};
use fss_twin::foreground::{BackgroundPolicy, ForegroundError, ForegroundPolicy};
use fss_twin::foreground::pipeline::FrameCapture;
use fss_twin::hog::{HOG_PARAMETERS, HogError, HogModel};
use fss_twin::hog_scan::{ScanLevel, ScanPolicy};
use fss_twin::image_tracking::ImageTrackingPolicy;
use fss_twin::image_zones::{ImageZoneBasis, ImageZoneEventKind, ImageZonePolicy, ImageZoneSpec};
use fss_twin::image_zones::pipeline::ImageZonePipeline;
use fss_twin::mjpeg::{JpegBackground, JpegFrameBinding, JpegReference, decode_rectified, decoded_image_domain};
use fss_twin::rectification::{LensDistortion, LumaRange, RectificationPlan, RectificationSpec};
use fss_twin::screened_mjpeg::{ForegroundStage, JpegScreeningQuery};
use fss_twin::screening::{AnalysisReason, HealthFlag, ScreeningHealth, ScreeningPolicy, ScreeningStamp};
use fss_twin::screening::tracking::hog::jpeg::*;

type Test = Result<(), Box<dyn Error>>;
const JPEG: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
const BACKGROUND: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const ALLOWANCE: u64 = 1_000_000_000;
fn work() -> WorkBudget<'static> { WorkBudget::new(ALLOWANCE) }
fn decode() -> DecodeBudget<'static> { DecodeBudget::new(ALLOWANCE) }
fn hash(b: &[u8]) -> [u8;32] { ContentDigest::sha256(b).bytes() }
fn binding(bytes: &[u8], mask: &[u8], exposure: u8) -> JpegFrameBinding {
    JpegFrameBinding { encoded_sha256:hash(bytes), exposure:[exposure;32], allowed_mask:hash(mask),
        camera_image_domain:[7;32], calibration:[8;32], interpretation:Color::Grayscale }
}
struct Fixture { plan: RectificationPlan, background: JpegBackground, mask: Vec<u8>, basis: ImageZoneBasis }
impl Fixture {
    fn new(dimensions: [u32;2]) -> Result<Self,Box<dyn Error>> {
        let source=PinholeIntrinsics::new(17,13,20.0,20.0,8.5,6.5)?;
        // Explicit interior resampling only to exercise HOG-sized native fixtures.
        let target=PinholeIntrinsics::new(dimensions[0],dimensions[1],
            f64::from(dimensions[0])*3.125,f64::from(dimensions[1])*3.125,
            f64::from(dimensions[0])/2.0,f64::from(dimensions[1])/2.0)?;
        let plan=RectificationPlan::compile(RectificationSpec { source,target,distortion:LensDistortion::Pinhole,
            maximum_radius:1.0,source_domain:decoded_image_domain([7;32],Color::Grayscale),
            calibration:[8;32],range:LumaRange::Full },&mut work())?;
        let mask=vec![1;17*13];
        let a=decode_rectified(&plan,BACKGROUND,&mask,binding(BACKGROUND,&mask,1),DecodeLimits::default(),&mut decode(),&mut work())?;
        let b=decode_rectified(&plan,BACKGROUND,&mask,binding(BACKGROUND,&mask,2),DecodeLimits::default(),&mut decode(),&mut work())?;
        let c=decode_rectified(&plan,BACKGROUND,&mask,binding(BACKGROUND,&mask,3),DecodeLimits::default(),&mut decode(),&mut work())?;
        let references=[JpegReference{image:&a,capture:FrameCapture{camera:1,clock:2,capture:[10;2]}},
            JpegReference{image:&b,capture:FrameCapture{camera:1,clock:2,capture:[20;2]}},
            JpegReference{image:&c,capture:FrameCapture{camera:1,clock:2,capture:[30;2]}}];
        let background=JpegBackground::build(&plan,&references,BackgroundPolicy{
            selection_evidence:[9;32],validity:[0,10_000],maximum_spread:0},&mut work())?;
        let basis=ImageZoneBasis{camera:1,clock:2,calibration:[8;32],image_domain:a.frame().identity().image_domain,dimensions};
        Ok(Self{plan,background,mask,basis})
    }
    fn processor(&self) -> Result<JpegHogPipeline,Box<dyn Error>> {
        let [w,h]=self.basis.dimensions;
        let zones=ImageZonePipeline::new([40;32],ImageTrackingPolicy{
            maximum_tracks:64,maximum_detections:64,maximum_exposures:64,minimum_observations:1,
            maximum_misses:3,maximum_gap_ns:1000,maximum_speed:200,gate_padding:0,miss_cost:1000,ambiguity_margin:0},
            self.basis,ImageZonePolicy{selection_evidence:[30;32],maximum_sample_gap_ns:100},
            &[ImageZoneSpec{id:1,vertices:vec![[1,1],[w-1,1],[w-1,h-1],[1,h-1]],margin:0,dwell_ns:Some(20)}],&mut work())?;
        let mut weights=vec![0;HOG_PARAMETERS*4];weights[(HOG_PARAMETERS-1)*4..].copy_from_slice(&1_f32.to_le_bytes());
        let model=HogModel::from_f32_le(&weights,hash(&weights),[50;32],&mut work())?;
        let levels=[ScanLevel{dimensions:self.basis.dimensions}];
        Ok(JpegHogPipeline::new(zones,model,JpegHogConfig{stream_generation:1,started_at_ns:0,
            screening:ScreeningPolicy{minimum_visible_pixels:1,dark_luma:0,bright_luma:255,
                extreme_per_mille:1000,flat_range:0,repeat_frames:100,repeat_duration_ns:1,
                stall_after_ns:1000,maximum_capture_uncertainty_ns:0,recovery_frames:1,
                minimum_analysis_interval_ns:0,sentinel_interval_ns:20,activity_hold_ns:0},
            levels:&levels,scan:ScanPolicy{stride:[64,128],minimum_margin:0.0,
                suppression_iou_ppm:1_000_000,maximum_windows:256,maximum_candidates:256}},&mut work())?)
    }
    fn query(&self,n:u64) -> JpegScreeningQuery<'_> {
        JpegScreeningQuery{bytes:JPEG,mask:&self.mask,binding:binding(JPEG,&self.mask,(10+n) as u8),
            capture:FrameCapture{camera:1,clock:2,capture:[30+n*10;2]},
            foreground_policy:ForegroundPolicy{minimum_change:10,minimum_area:1,maximum_regions:128,widespread_per_mille:1000},
            decode_limits:DecodeLimits::default(),stamp:ScreeningStamp{stream_generation:1,sequence:n,
                received_at_ns:30+n*10,owner_requests_analysis:false}}
    }
    fn run(&self,p:&mut JpegHogPipeline,n:u64,inf:&mut WorkBudget<'_>,down:&mut WorkBudget<'_>)
        -> Result<JpegHogProgress,JpegHogError> {
        p.observe(Some(&self.background),&self.plan,self.query(n),&mut decode(),&mut work(),&mut work(),&mut work(),inf,down)
    }
}
fn complete(p:JpegHogProgress) -> Result<JpegHogCompletion,Box<dyn Error>> {
    match p { JpegHogProgress::Complete(c)=>Ok(c), other=>Err(format!("not complete: {other:?}").into()) }
}
#[test]
fn native_jpeg_reaches_learned_scan_and_existing_zone_receipts() -> Test {
    let f=Fixture::new([64,128])?;let mut p=f.processor()?;
    let c=complete(f.run(&mut p,1,&mut work(),&mut work())?)?;
    let image=p.image().ok_or("image lost")?;let scan=p.scan().ok_or("scan lost")?;
    assert_eq!(image.source_receipt().source.encoded_sha256,hash(JPEG));
    assert_eq!(scan.source(),image.screening().source());assert_eq!(scan.selected().count(),1);
    assert_eq!(scan.digest(),c.scan);assert_eq!(image.digest(),c.image);
    assert_eq!(p.tracking_report().ok_or("tracking lost")?.digest(),c.tracking);
    assert_eq!(p.zone_report().ok_or("zones lost")?.digest(),c.zones);
    assert_eq!(p.zones().pipeline().tracker().exposure_count(),1);
    assert!(image.screening().last_completed_analysis().is_none());Ok(())
}
#[test]
fn inference_and_tracking_retries_do_not_redecode_or_reingest() -> Test {
    let f=Fixture::new([64,128])?;let mut p=f.processor()?;
    assert!(matches!(f.run(&mut p,1,&mut WorkBudget::new(0),&mut work())?,
        JpegHogProgress::Pending{stage:JpegHogStage::Inference,error:JpegHogRefusal::Inference(HogError::Work(GeometryError::BudgetExhausted)),..}));
    let image=p.image().ok_or("image lost")?.digest();assert!(p.scan().is_none());
    assert_eq!(f.run(&mut p,2,&mut work(),&mut work()),Err(JpegHogError::PendingAnalysis));
    assert!(matches!(p.resume(&mut work(),&mut WorkBudget::new(0))?,
        JpegHogProgress::Pending{stage:JpegHogStage::Tracking,..}));
    assert_eq!(p.image().ok_or("image changed")?.digest(),image);assert!(p.scan().is_some());
    assert_eq!(p.zones().pipeline().tracker().exposure_count(),0);
    let mut zero=WorkBudget::new(0);let c=complete(p.resume(&mut zero,&mut work())?)?;
    assert_eq!(zero.used(),0);assert_eq!(c.image,image);assert_eq!(p.zones().pipeline().tracker().exposure_count(),1);
    assert_eq!(complete(p.resume(&mut WorkBudget::new(0),&mut WorkBudget::new(0))?)?,c);Ok(())
}
#[test]
fn downstream_budget_boundaries_keep_the_exact_accepted_stage() -> Test {
    let f=Fixture::new([64,128])?;let mut full=f.processor()?;let mut measured=work();
    let expected=complete(f.run(&mut full,1,&mut work(),&mut measured)?)?;
    let units=measured.used();let mut pre=false;let mut post=false;
    for cut in [0,1,1023,1024,units/2,units-1,units] {
        let mut p=f.processor()?;let result=f.run(&mut p,1,&mut work(),&mut WorkBudget::new(cut))?;
        match result {
            JpegHogProgress::Pending{stage:JpegHogStage::Tracking,..}=>{
                pre=true;assert_eq!(p.zones().pipeline().tracker().exposure_count(),0);assert!(p.tracking_report().is_none());
            }
            JpegHogProgress::Pending{stage:JpegHogStage::Zones,..}=>{
                post=true;assert_eq!(p.zones().pipeline().tracker().exposure_count(),1);
                assert_eq!(p.tracking_report().ok_or("accepted tracking lost")?.digest(),expected.tracking);
                assert!(p.zone_report().is_none());
            }
            JpegHogProgress::Complete(c)=>assert_eq!(c,expected),
            other=>return Err(format!("unexpected boundary: {other:?}").into()),
        }
        assert_eq!(complete(p.resume(&mut WorkBudget::new(0),&mut work())?)?,expected);
        assert_eq!(p.zones().pipeline().tracker().exposure_count(),1);
    }
    assert!(pre&&post);Ok(())
}
#[test]
fn cancellation_preserves_image_before_inference_and_scan_before_tracking() -> Test {
    let f=Fixture::new([64,128])?;let flag=AtomicBool::new(true);
    for cancel_inference in [true,false] {
        let mut p=f.processor()?;let mut cancelled=WorkBudget::cancellable(ALLOWANCE,&flag);let mut ordinary=work();
        let (inf,down)=if cancel_inference {(&mut cancelled,&mut ordinary)} else {(&mut ordinary,&mut cancelled)};
        assert!(matches!(f.run(&mut p,1,inf,down)?,JpegHogProgress::Pending{..}));
        assert!(p.image().is_some());assert_eq!(p.scan().is_none(),cancel_inference);
        assert_eq!(p.zones().pipeline().tracker().exposure_count(),0);
        complete(p.resume(&mut work(),&mut work())?)?;
    }Ok(())
}
#[test]
fn failed_new_decode_keeps_prior_completion_and_source() -> Test {
    let f=Fixture::new([64,128])?;let mut p=f.processor()?;
    let original=complete(f.run(&mut p,1,&mut work(),&mut work())?)?;
    let mut corrupt=JPEG.to_vec();corrupt.push(0);let mut q=f.query(2);q.bytes=&corrupt;
    q.binding.encoded_sha256=hash(&corrupt);
    assert!(matches!(p.observe(Some(&f.background),&f.plan,q,&mut decode(),&mut work(),&mut work(),&mut work(),
        &mut work(),&mut work()),Err(JpegHogError::Image(_))));
    assert_eq!(complete(p.resume(&mut WorkBudget::new(0),&mut WorkBudget::new(0))?)?,original);
    assert_eq!(p.zones().pipeline().tracker().exposure_count(),1);Ok(())
}
#[test]
fn foreground_failure_cannot_starve_health_or_admit_learned_measurements() -> Test {
    let f=Fixture::new([64,128])?;let mut p=f.processor()?;
    complete(p.observe(Some(&f.background),&f.plan,f.query(1),&mut decode(),&mut work(),&mut WorkBudget::new(0),
        &mut work(),&mut work(),&mut work())?)?;
    let image=p.image().ok_or("missing health image")?;
    assert!(matches!(image.foreground(),ForegroundStage::Refused(ForegroundError::Geometry(GeometryError::BudgetExhausted))));
    assert!(image.screening().flags().contains(HealthFlag::ForegroundUnavailable));
    assert_eq!(image.screening().health(),ScreeningHealth::Degraded);
    assert_eq!(p.scan().ok_or("scan missing")?.selected().count(),1);
    assert!(p.zones().pipeline().tracker().tracks().is_empty());assert!(p.zone_report().ok_or("zones missing")?.events().is_empty());Ok(())
}
#[test]
fn stationary_native_jpeg_candidates_reach_dwell_without_crediting_semantic_custody() -> Test {
    let f=Fixture::new([192,320])?;let mut p=f.processor()?;
    for n in 1..=3 {
        complete(f.run(&mut p,n,&mut work(),&mut work())?)?;
        let image=p.image().ok_or("image missing")?;
        assert_eq!(image.screening().health(),ScreeningHealth::NoFaultObserved);
        assert_eq!(image.screening().reasons().contains(AnalysisReason::OwnerRequested),n>1);
        assert!(image.screening().last_completed_analysis().is_none());
        assert_eq!(p.zones().pipeline().tracker().tracks().len(),6);
        assert_eq!(p.zone_report().ok_or("zones missing")?.events().iter()
            .filter(|e|e.kind==ImageZoneEventKind::SampledDwell).count(),usize::from(n==3));
    }Ok(())
}
#[test]
fn watchdog_remains_available_while_inference_is_pending() -> Test {
    let f=Fixture::new([64,128])?;let mut p=f.processor()?;
    assert_eq!(p.resume(&mut work(),&mut work()),Err(JpegHogError::NoObservation));
    f.run(&mut p,1,&mut WorkBudget::new(0),&mut work())?;
    let original=p.image().ok_or("image missing")?.digest();let watchdog=p.poll(2000)?;
    assert!(watchdog.stalled);assert_eq!(p.stage(),JpegHogStage::Inference);
    assert_eq!(p.image().ok_or("image lost")?.digest(),original);assert!(p.scan().is_none());
    complete(p.resume(&mut work(),&mut work())?)?;assert_eq!(p.zones().pipeline().tracker().exposure_count(),1);Ok(())
}
#[test]
fn privacy_drift_retains_new_image_without_exposing_old_zone_results() -> Test {
    let f=Fixture::new([64,128])?;let mut p=f.processor()?;complete(f.run(&mut p,1,&mut work(),&mut work())?)?;
    let prior=p.zone_report().ok_or("zones missing")?.digest();
    let mut mask=f.mask.clone();mask[6*17+8]=0;let mut q=f.query(2);q.mask=&mask;q.binding.allowed_mask=hash(&mask);
    assert!(matches!(p.observe(Some(&f.background),&f.plan,q,&mut decode(),&mut work(),&mut work(),&mut work(),
        &mut work(),&mut work())?,JpegHogProgress::Pending{stage:JpegHogStage::Tracking,..}));
    assert!(p.zone_report().is_none());assert!(p.tracking_report().is_none());
    assert_eq!(p.zones().pipeline().zone_report().ok_or("historical zone lost")?.digest(),prior);
    assert_eq!(p.zones().pipeline().tracker().exposure_count(),1);
    assert_eq!(p.image().ok_or("new source lost")?.screening().stamp().sequence,2);Ok(())
}
