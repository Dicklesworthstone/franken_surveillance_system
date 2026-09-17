#![forbid(unsafe_code)]
use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_codec_mjpeg::{ComponentInterpretation as Color, DecodeBudget, DecodeLimits};
use fss_codec_mjpeg::stream::{FramedJpeg, FramingLimits, JpegStream, StreamBasis};
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, PinholeIntrinsics, WorkBudget};
use fss_twin::foreground::{BackgroundPolicy, ForegroundError, ForegroundPolicy};
use fss_twin::foreground::pipeline::FrameCapture;
use fss_twin::mjpeg::{JpegBackground, JpegFrameBinding, JpegReference, decode_rectified, decoded_image_domain};
use fss_twin::screened_mjpeg::{ForegroundStage, JpegScreeningError, JpegScreeningQuery,
    screen_framed_jpeg, screen_jpeg};
use fss_twin::mjpeg::stream::FramedQuery;
use fss_twin::rectification::{LensDistortion, LumaRange, RectificationPlan, RectificationSpec};
use fss_twin::screening::{AnalysisReason, HealthFlag, ScreeningHealth, ScreeningMonitor,
    ScreeningPolicy, ScreeningStamp};

type Test = Result<(),Box<dyn Error>>;
const BACKGROUND: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const QUERY: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
fn hash(b: &[u8]) -> [u8;32] { ContentDigest::sha256(b).bytes() }
fn binding(bytes: &[u8],mask: &[u8],exposure: u8) -> JpegFrameBinding {
    JpegFrameBinding {encoded_sha256:hash(bytes),exposure:[exposure;32],allowed_mask:hash(mask),
        camera_image_domain:[7;32],calibration:[8;32],interpretation:Color::Grayscale}
}
fn plan() -> Result<RectificationPlan,Box<dyn Error>> {
    let k=PinholeIntrinsics::new(17,13,20.0,20.0,8.5,6.5)?;
    Ok(RectificationPlan::compile(RectificationSpec {source:k,target:k,distortion:LensDistortion::Pinhole,
        maximum_radius:1.0,source_domain:decoded_image_domain([7;32],Color::Grayscale),
        calibration:[8;32],range:LumaRange::Full},&mut WorkBudget::new(100_000_000))?)
}
fn baseline(p: &RectificationPlan,mask: &[u8]) -> Result<JpegBackground,Box<dyn Error>> {
    let mut d=DecodeBudget::new(100_000_000); let mut g=WorkBudget::new(100_000_000);
    let a=decode_rectified(p,BACKGROUND,mask,binding(BACKGROUND,mask,1),DecodeLimits::default(),&mut d,&mut g)?;
    let b=decode_rectified(p,BACKGROUND,mask,binding(BACKGROUND,mask,2),DecodeLimits::default(),&mut d,&mut g)?;
    let c=decode_rectified(p,BACKGROUND,mask,binding(BACKGROUND,mask,3),DecodeLimits::default(),&mut d,&mut g)?;
    let refs=[JpegReference{image:&a,capture:FrameCapture{camera:1,clock:2,capture:[10,10]}},
        JpegReference{image:&b,capture:FrameCapture{camera:1,clock:2,capture:[20,20]}},
        JpegReference{image:&c,capture:FrameCapture{camera:1,clock:2,capture:[30,30]}}];
    Ok(JpegBackground::build(p,&refs,BackgroundPolicy{selection_evidence:[9;32],validity:[0,100],
        maximum_spread:0},&mut g)?)
}
fn foreground_policy() -> ForegroundPolicy {
    ForegroundPolicy{minimum_change:10,minimum_area:1,maximum_regions:128,widespread_per_mille:900}
}
fn monitor() -> Result<ScreeningMonitor,Box<dyn Error>> {
    Ok(ScreeningMonitor::new(ScreeningPolicy {minimum_visible_pixels:16,dark_luma:10,bright_luma:245,
        extreme_per_mille:900,flat_range:2,repeat_frames:3,repeat_duration_ns:20,stall_after_ns:100,
        maximum_capture_uncertainty_ns:5,recovery_frames:2,minimum_analysis_interval_ns:5,
        sentinel_interval_ns:40,activity_hold_ns:10},1,0)?)
}
fn query<'a>(bytes: &'a [u8],mask: &'a [u8],seq: u64,now: u64) -> JpegScreeningQuery<'a> {
    JpegScreeningQuery{bytes,mask,binding:binding(bytes,mask,(seq+3) as u8),
        capture:FrameCapture{camera:1,clock:2,capture:[now,now]},foreground_policy:foreground_policy(),
        decode_limits:DecodeLimits::default(),stamp:ScreeningStamp{stream_generation:1,sequence:seq,
            received_at_ns:now,owner_requests_analysis:false}}
}
#[test]
fn compressed_source_matches_existing_detector_and_reaches_analysis_admission() -> Test {
    let p=plan()?;let mask=vec![1;221];let model=baseline(&p,&mask)?;let mut m=monitor()?;
    let q=query(QUERY,&mask,1,40);
    let actual=screen_jpeg(&mut m,Some(&model),&p,q,&mut DecodeBudget::new(100_000_000),
        &mut WorkBudget::new(100_000_000),&mut WorkBudget::new(100_000_000),&mut WorkBudget::new(100_000_000))?;
    let expected=model.detect(&p,QUERY,&mask,q.binding,q.capture,q.foreground_policy,q.decode_limits,
        &mut DecodeBudget::new(100_000_000),&mut WorkBudget::new(100_000_000))?;
    let ForegroundStage::Complete(report)=actual.foreground() else {return Err("foreground not complete".into());};
    assert_eq!(report.digest(),expected.analysis().report().digest());
    assert!(!report.regions().is_empty());assert!(actual.analysis_frame().is_some());
    assert_eq!(actual.source_receipt().source.encoded_sha256,hash(QUERY));
    assert_eq!(actual.screening().source().image.exposure,[4;32]);
    assert!(actual.screening().reasons().contains(AnalysisReason::Initial));
    assert!(actual.screening().last_completed_analysis().is_none());
    Ok(())
}
#[test]
fn foreground_work_exhaustion_preserves_real_health_and_an_uncompleted_analysis() -> Test {
    let p=plan()?;let mask=vec![1;221];let model=baseline(&p,&mask)?;let mut m=monitor()?;
    let before=model.background().model().digest();
    let out=screen_jpeg(&mut m,Some(&model),&p,query(QUERY,&mask,1,40),&mut DecodeBudget::new(100_000_000),
        &mut WorkBudget::new(100_000_000),&mut WorkBudget::new(0),&mut WorkBudget::new(100_000_000))?;
    assert!(matches!(out.foreground(),ForegroundStage::Refused(ForegroundError::Geometry(GeometryError::BudgetExhausted))));
    assert!(out.screening().flags().contains(HealthFlag::ForegroundUnavailable));
    assert_eq!(out.screening().health(),ScreeningHealth::Degraded);
    assert!(out.screening().analysis_due());assert!(out.analysis_frame().is_some());
    assert!(out.screening().last_completed_analysis().is_none());
    assert_eq!(out.attempted_background(),Some(before));
    assert_eq!(out.foreground_allowance(),0);assert_eq!(out.foreground_units(),0);
    assert_eq!(model.background().model().digest(),before);
    Ok(())
}
#[test]
fn cancellation_at_every_budget_boundary_leaves_monitor_unchanged() -> Test {
    let p=plan()?;let mask=vec![1;221];let model=baseline(&p,&mask)?;
    let yes=AtomicBool::new(true);let no=AtomicBool::new(false);
    for selected in 0..4 {
        let flag=|n| if n==selected {&yes} else {&no};
        let mut m=monitor()?;
        let result=screen_jpeg(&mut m,Some(&model),&p,query(QUERY,&mask,1,40),
            &mut DecodeBudget::cancellable(100_000_000,flag(0)),
            &mut WorkBudget::cancellable(100_000_000,flag(1)),
            &mut WorkBudget::cancellable(100_000_000,flag(2)),
            &mut WorkBudget::cancellable(100_000_000,flag(3)));
        assert!(result.is_err());assert!(m.last_report().is_none());
    }
    Ok(())
}
#[test]
fn decode_corruption_and_wrong_mask_never_advance_temporal_state() -> Test {
    let p=plan()?;let mask=vec![1;221];let model=baseline(&p,&mask)?;let mut m=monitor()?;
    let first=screen_jpeg(&mut m,Some(&model),&p,query(QUERY,&mask,1,40),&mut DecodeBudget::new(100_000_000),
        &mut WorkBudget::new(100_000_000),&mut WorkBudget::new(100_000_000),&mut WorkBudget::new(100_000_000))?;
    let mut bytes=QUERY.to_vec();bytes.push(0);
    let bad=query(&bytes,&mask,2,50);
    assert!(matches!(screen_jpeg(&mut m,Some(&model),&p,bad,&mut DecodeBudget::new(100_000_000),
        &mut WorkBudget::new(100_000_000),&mut WorkBudget::new(100_000_000),&mut WorkBudget::new(100_000_000)),
        Err(JpegScreeningError::Image(_))));
    let mut bad=query(QUERY,&mask,2,50);bad.binding.allowed_mask=[99;32];
    assert!(screen_jpeg(&mut m,Some(&model),&p,bad,&mut DecodeBudget::new(100_000_000),
        &mut WorkBudget::new(100_000_000),&mut WorkBudget::new(100_000_000),&mut WorkBudget::new(100_000_000)).is_err());
    assert_eq!(m.last_report(),Some(first.screening()));
    m.acknowledge_analysis(first.screening().digest(),hash(b"retained-test-analysis"))?;
    Ok(())
}
#[test]
fn fully_masked_source_produces_no_semantic_analysis_image() -> Test {
    let p=plan()?;let mask=vec![0;221];let model=baseline(&p,&mask)?;let mut m=monitor()?;
    let result=screen_jpeg(&mut m,Some(&model),&p,query(QUERY,&mask,1,40),&mut DecodeBudget::new(100_000_000),
        &mut WorkBudget::new(100_000_000),&mut WorkBudget::new(100_000_000),&mut WorkBudget::new(100_000_000))?;
    assert_eq!(result.screening().health(),ScreeningHealth::NotObservable);
    assert!(result.analysis_frame().is_none());
    assert!(result.image().frame().pixels().iter().all(|x| *x==0));
    assert!(result.image().frame().allowed().iter().all(|x| *x==0));
    Ok(())
}
#[test]
fn unconfigured_and_expired_backgrounds_are_not_empty_successful_detections() -> Test {
    let p=plan()?;let mask=vec![1;221];let model=baseline(&p,&mask)?;
    let run=|background:Option<&JpegBackground>,now:u64| -> Result<fss_twin::screened_mjpeg::ScreenedJpeg,Box<dyn Error>> {
        let mut state=monitor()?;
        Ok(screen_jpeg(&mut state,background,&p,query(QUERY,&mask,1,now),
            &mut DecodeBudget::new(100_000_000),&mut WorkBudget::new(100_000_000),
            &mut WorkBudget::new(100_000_000),&mut WorkBudget::new(100_000_000))?)
    };
    let absent=run(None,40)?;let expired=run(Some(&model),101)?;
    assert!(matches!(absent.foreground(),ForegroundStage::NotConfigured));
    assert!(matches!(expired.foreground(),ForegroundStage::Refused(ForegroundError::OutsideValidity)));
    assert!(absent.screening().flags().contains(HealthFlag::ForegroundUnavailable));
    assert!(expired.screening().flags().contains(HealthFlag::ForegroundUnavailable));
    assert_ne!(absent.digest(),expired.digest());
    Ok(())
}
fn frame(bytes: &[u8],basis:StreamBasis) -> Result<FramedJpeg,Box<dyn Error>> {
    let mut stream=JpegStream::new(basis,FramingLimits::default())?;
    let frame=stream.push(0,bytes,&mut DecodeBudget::new(100_000_000))?.frame.ok_or("frame missing")?;
    stream.finish(&mut DecodeBudget::new(100_000_000))?;Ok(frame)
}
#[test]
fn framed_byte_ranges_and_capture_survive_screening_without_ordinal_time_invention() -> Test {
    let p=plan()?;let mask=vec![1;221];let model=baseline(&p,&mask)?;let mut m=monitor()?;
    let basis=StreamBasis{source:hash(QUERY),generation:1};let frame=frame(QUERY,basis)?;
    let q=query(QUERY,&mask,1,40);
    let framed=FramedQuery{expected_stream:basis,frame:&frame,mask:&mask,binding:q.binding,
        capture:q.capture,policy:q.foreground_policy,limits:q.decode_limits};
    let result=screen_framed_jpeg(&mut m,Some(&model),&p,framed,q.stamp,&mut DecodeBudget::new(100_000_000),
        &mut WorkBudget::new(100_000_000),&mut WorkBudget::new(100_000_000),&mut WorkBudget::new(100_000_000))?;
    assert_eq!(result.source().byte_range,[0,QUERY.len() as u64]);
    assert_eq!(result.source().basis,basis);assert_eq!(result.source().ordinal,1);
    assert_eq!(result.result().screening().source().capture,[40,40]);
    let mut wrong=q.stamp;wrong.sequence=2;
    assert!(matches!(screen_framed_jpeg(&mut m,Some(&model),&p,framed,wrong,&mut DecodeBudget::new(0),
        &mut WorkBudget::new(0),&mut WorkBudget::new(0),&mut WorkBudget::new(0)),Err(JpegScreeningError::Image(_))));
    assert_eq!(m.last_report(),Some(result.result().screening()));Ok(())
}
#[test]
fn identical_real_jpegs_raise_suspicion_and_replay_identically() -> Test {
    let p=plan()?;let mask=vec![1;221];let model=baseline(&p,&mask)?;
    let run=||->Result<Vec<[u8;32]>,Box<dyn Error>> {
        let mut m=monitor()?;let mut roots=Vec::new();
        for seq in 1..=3 {
            let out=screen_jpeg(&mut m,Some(&model),&p,query(QUERY,&mask,seq,30+seq*10),
                &mut DecodeBudget::new(100_000_000),&mut WorkBudget::new(100_000_000),
                &mut WorkBudget::new(100_000_000),&mut WorkBudget::new(100_000_000))?;
            assert_eq!(out.screening().flags().contains(HealthFlag::SuspectedFreeze),seq==3);
            let permitted:Vec<_>=out.image().frame().pixels().iter().zip(out.image().frame().allowed())
                .filter_map(|(v,mask)|(*mask==1).then_some(*v)).collect();
            assert_eq!(out.screening().dark_pixels(),permitted.iter().filter(|p|**p<=10).count());
            assert_eq!(out.screening().saturated_pixels(),permitted.iter().filter(|p|**p>=245).count());
            roots.push(out.digest());
        }
        Ok(roots)
    };
    assert_eq!(run()?,run()?);Ok(())
}
