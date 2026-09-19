#![forbid(unsafe_code)]
//! Actual-pixel reference contracts; no model, camera or coverage qualification is claimed.
use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};
use fss_twin::foreground::{BackgroundModel, BackgroundPolicy, ForegroundFrame, ForegroundPolicy,
    ForegroundReport, ForegroundSource};
use fss_twin::localization::ImageIdentity;
use fss_twin::screening::{AnalysisReason as A, HealthFlag as H, ScreeningHealth as S,
    ScreeningError, ScreeningMonitor, ScreeningPolicy, ScreeningStamp};

type TestResult = Result<(), Box<dyn Error>>;
fn hash(s: &[u8]) -> [u8; 32] { ContentDigest::sha256(s).bytes() }
fn policy() -> ScreeningPolicy {
    ScreeningPolicy { minimum_visible_pixels: 4, dark_luma: 10, bright_luma: 245,
        extreme_per_mille: 900, flat_range: 2, repeat_frames: 3, repeat_duration_ns: 20,
        stall_after_ns: 100, maximum_capture_uncertainty_ns: 5, recovery_frames: 2,
        minimum_analysis_interval_ns: 5, sentinel_interval_ns: 40, activity_hold_ns: 10 }
}
fn stamp(sequence: u64, received_at_ns: u64) -> ScreeningStamp {
    ScreeningStamp { stream_generation: 1, sequence, received_at_ns, owner_requests_analysis: false }
}
fn source(pixels: &[u8], exposure: u64, capture: [u64; 2]) -> ForegroundSource {
    ForegroundSource { image: ImageIdentity { exposure: hash(&exposure.to_le_bytes()),
        pixels: hash(pixels), image_domain: hash(b"domain"), dimensions: [4, 4] },
        camera: 1, calibration: hash(b"calibration"), clock: 1, capture }
}
fn pixels() -> Vec<u8> { (0..16).map(|i| if i%2 == 0 { 80 } else { 160 }).collect() }
fn baseline(mask: &[u8]) -> Result<BackgroundModel, Box<dyn Error>> {
    let p = pixels(); let mut budget = WorkBudget::new(1_000_000);
    let mut refs = Vec::new();
    for i in 1..=3 { refs.push(ForegroundFrame::new(source(&p, i, [i,i]), &p, mask, &mut budget)?); }
    Ok(BackgroundModel::build(&refs, BackgroundPolicy { selection_evidence: hash(b"selection"),
        validity: [0, 10_000], maximum_spread: 0 }, &mut budget)?)
}
fn detect(model: &BackgroundModel, p: &[u8], mask: &[u8], id: u64, capture: [u64; 2])
    -> Result<ForegroundReport, Box<dyn Error>> {
    let mut b = WorkBudget::new(1_000_000);
    let frame = ForegroundFrame::new(source(p,id,capture),p,mask,&mut b)?;
    Ok(model.detect(&frame, ForegroundPolicy { minimum_change: 4, minimum_area: 3,
        maximum_regions: 16, widespread_per_mille: 900 }, &mut b)?)
}
fn observe(m: &mut ScreeningMonitor, model: &BackgroundModel, p: &[u8], mask: &[u8], seq: u64, now: u64)
    -> Result<fss_twin::screening::ScreeningReport, Box<dyn Error>> {
    let r = detect(model,p,mask,seq+100,[now,now])?;
    Ok(m.observe(r.source(),p,mask,Some(&r),stamp(seq,now),&mut WorkBudget::new(1_000_000))?)
}
#[test]
fn quiet_never_disables_sentinel_and_unacknowledged_work_stays_due() -> TestResult {
    let mask=vec![1;16]; let model=baseline(&mask)?; let mut m=ScreeningMonitor::new(policy(),1,0)?;
    let p=pixels(); let first=observe(&mut m,&model,&p,&mask,1,10)?;
    assert!(first.reasons().contains(A::Initial));
    let mut q=p.clone(); q[0]+=1;
    let second=observe(&mut m,&model,&q,&mask,2,11)?;
    assert!(second.reasons().contains(A::Initial));
    assert_eq!(m.acknowledge_analysis(first.digest(),hash(b"synthetic-analysis-result")),Err(ScreeningError::StaleCompletion));
    m.acknowledge_analysis(second.digest(),hash(b"synthetic-analysis-result"))?;
    m.acknowledge_analysis(second.digest(),hash(b"synthetic-analysis-result"))?;
    assert_eq!(m.acknowledge_analysis(second.digest(),hash(b"different-result")),Err(ScreeningError::StaleCompletion));
    let quiet=observe(&mut m,&model,&p,&mask,3,30)?;
    assert!(!quiet.analysis_due());
    let due=observe(&mut m,&model,&q,&mask,4,51)?;
    assert!(due.reasons().contains(A::Sentinel));
    let still_due=observe(&mut m,&model,&p,&mask,5,52)?;
    assert!(still_due.reasons().contains(A::Sentinel));
    Ok(())
}
#[test]
fn actual_small_and_stationary_changes_survive_area_filtering_and_sampling() -> TestResult {
    let mask=vec![1;16]; let model=baseline(&mask)?; let mut m=ScreeningMonitor::new(policy(),1,0)?;
    let first=observe(&mut m,&model,&pixels(),&mask,1,10)?; m.acknowledge_analysis(first.digest(),hash(b"synthetic-analysis-result"))?;
    let mut p=pixels(); p[0]=200;
    let foreground=detect(&model,&p,&mask,102,[20,20])?;
    assert!(foreground.regions().is_empty()); assert_eq!(foreground.small_component_pixels(),1);
    for (seq,now) in [(2,20),(3,30),(4,40)] {
        let r=observe(&mut m,&model,&p,&mask,seq,now)?;
        assert!(r.reasons().contains(A::Foreground)); m.acknowledge_analysis(r.digest(),hash(b"synthetic-analysis-result"))?;
    }
    Ok(())
}
#[test]
fn repeated_pixels_with_advancing_source_records_raise_freeze_suspicion() -> TestResult {
    let mask=vec![1;16]; let model=baseline(&mask)?; let p=pixels(); let mut m=ScreeningMonitor::new(policy(),1,0)?;
    for (seq,now) in [(1,10),(2,20)] {
        let r=observe(&mut m,&model,&p,&mask,seq,now)?;
        assert!(!r.flags().contains(H::SuspectedFreeze));
    }
    let r=observe(&mut m,&model,&p,&mask,3,30)?;
    assert_eq!(r.identical_run(),3); assert!(r.flags().contains(H::SuspectedFreeze));
    assert_eq!(r.health(),S::Degraded); assert!(r.reasons().contains(A::HealthChanged));
    let mut p=p; p[0]+=1;
    assert_eq!(observe(&mut m,&model,&p,&mask,4,31)?.health(),S::Recovering);
    p[0]+=1;
    assert_eq!(observe(&mut m,&model,&p,&mask,5,32)?.health(),S::NoFaultObserved);
    Ok(())
}
#[test]
fn silence_is_detected_without_any_new_frame_and_reentry_is_degraded() -> TestResult {
    let mut m=ScreeningMonitor::new(policy(),1,5)?;
    assert_eq!(m.watchdog_deadline_ns(),Some(105)); assert!(!m.poll(104)?.stalled);
    let empty=m.poll(105)?; assert!(empty.stalled); assert!(empty.last_report.is_none());
    let mask=vec![1;16]; let model=baseline(&mask)?;
    let first=observe(&mut m,&model,&pixels(),&mask,1,106)?;
    assert!(first.flags().contains(H::ReceiveGap));
    assert_eq!(m.watchdog_deadline_ns(),Some(206)); assert!(m.poll(206)?.stalled);
    assert_eq!(m.poll(205),Err(ScreeningError::OutOfOrder));
    let next=observe(&mut m,&model,&pixels(),&mask,2,207)?;
    assert!(next.flags().contains(H::ReceiveGap)); assert_eq!(next.identical_run(),1);
    Ok(())
}
#[test]
fn privacy_excluded_pixels_never_change_statistics_or_the_repeat_run() -> TestResult {
    let mut mask=vec![1;16]; mask[0]=0; let model=baseline(&mask)?;
    let mut m=ScreeningMonitor::new(policy(),1,0)?; let mut p=pixels();
    let a=observe(&mut m,&model,&p,&mask,1,10)?; p[0]=0;
    let b=observe(&mut m,&model,&p,&mask,2,20)?; p[0]=255;
    let c=observe(&mut m,&model,&p,&mask,3,30)?;
    assert_eq!(a.visible_pixels(),15); assert_eq!(a.luma_range(),b.luma_range());
    assert_eq!(b.luma_range(),c.luma_range()); assert_eq!(c.dark_pixels(),0);
    assert_eq!(c.saturated_pixels(),0); assert_eq!(c.identical_run(),3);
    assert!(c.flags().contains(H::SuspectedFreeze));
    Ok(())
}
#[test]
fn all_masked_is_not_observable_not_dark_or_a_healthy_quiet_scene() -> TestResult {
    let mask=vec![0;16]; let model=baseline(&mask)?; let mut m=ScreeningMonitor::new(policy(),1,0)?;
    let r=observe(&mut m,&model,&[0; 16],&mask,1,10)?;
    assert_eq!(r.health(),S::NotObservable); assert_eq!(r.luma_range(),None);
    assert!(!r.flags().contains(H::Dark)); assert!(!r.flags().contains(H::SuspectedFreeze));
    assert!(r.analysis_due()); Ok(())
}
#[test]
fn dark_saturated_and_flat_inputs_produce_distinct_diagnostics() -> TestResult {
    let mask=vec![1;16]; let model=baseline(&mask)?;
    for (value,expected) in [(0,H::Dark),(255,H::Saturated),(100,H::LowTexture)] {
        let mut m=ScreeningMonitor::new(policy(),1,0)?;
        let r=observe(&mut m,&model,&[value; 16],&mask,1,10)?;
        assert!(r.flags().contains(expected)); assert!(r.flags().contains(H::LowTexture));
        assert_eq!(r.health(),S::Degraded);
    }
    Ok(())
}
#[test]
fn sequence_gaps_and_mask_changes_reset_repeat_history() -> TestResult {
    let mut mask=vec![1;16]; let model=baseline(&mask)?; let p=pixels();
    let mut m=ScreeningMonitor::new(policy(),1,0)?;
    observe(&mut m,&model,&p,&mask,1,10)?; observe(&mut m,&model,&p,&mask,2,20)?;
    let gap=observe(&mut m,&model,&p,&mask,4,30)?;
    assert!(gap.flags().contains(H::SequenceGap)); assert_eq!(gap.identical_run(),1);
    mask[0]=0;
    let changed=observe(&mut m,&model,&p,&mask,5,40)?;
    assert!(changed.flags().contains(H::MaskChanged)); assert_eq!(changed.identical_run(),1);
    Ok(())
}
#[test]
fn capture_overlap_widening_and_source_reuse_are_not_liveness_evidence() -> TestResult {
    let mask=vec![1;16]; let model=baseline(&mask)?; let p=pixels();
    let mut m=ScreeningMonitor::new(policy(),1,0)?;
    observe(&mut m,&model,&p,&mask,1,10)?;
    let r=detect(&model,&p,&mask,101,[8,20])?;
    let result=m.observe(r.source(),&p,&mask,Some(&r),stamp(2,20),&mut WorkBudget::new(1_000_000))?;
    for flag in [H::CaptureUncertain,H::WideCaptureInterval,H::ReusedExposure] {
        assert!(result.flags().contains(flag));
    }
    Ok(())
}
#[test]
fn failure_cancellation_and_wrong_basis_do_not_consume_state_or_sampling_credit() -> TestResult {
    let mask=vec![1;16]; let model=baseline(&mask)?; let p=pixels();
    let mut m=ScreeningMonitor::new(policy(),1,0)?;
    let first=observe(&mut m,&model,&p,&mask,1,10)?;
    let r=detect(&model,&p,&mask,102,[20,20])?;
    let cancelled=AtomicBool::new(true);
    assert!(matches!(m.observe(r.source(),&p,&mask,Some(&r),stamp(2,20),
        &mut WorkBudget::cancellable(1_000_000,&cancelled)),Err(ScreeningError::Work(GeometryError::Cancelled))));
    assert!(m.observe(r.source(),&p,&mask,Some(&r),stamp(2,20),&mut WorkBudget::new(1)).is_err());
    let mut wrong=r.source(); wrong.clock=2;
    assert_eq!(m.observe(wrong,&p,&mask,Some(&r),stamp(2,20),&mut WorkBudget::new(1_000_000)),Err(ScreeningError::BasisMismatch));
    let mut wrong=stamp(2,20); wrong.stream_generation=2;
    assert_eq!(m.observe(r.source(),&p,&mask,Some(&r),wrong,&mut WorkBudget::new(1_000_000)),Err(ScreeningError::BasisMismatch));
    assert_eq!(m.last_report(),Some(&first)); m.acknowledge_analysis(first.digest(),hash(b"synthetic-analysis-result"))?;
    assert_eq!(m.acknowledge_analysis([42;32],hash(b"synthetic-analysis-result")),Err(ScreeningError::StaleCompletion));
    Ok(())
}
#[test]
fn missing_foreground_and_unknown_background_do_not_suppress_initial_analysis() -> TestResult {
    let mask=vec![1;16]; let p=pixels(); let mut m=ScreeningMonitor::new(policy(),1,0)?;
    let r=m.observe(source(&p,100,[10,10]),&p,&mask,None,stamp(1,10),&mut WorkBudget::new(1_000_000))?;
    assert!(r.flags().contains(H::ForegroundUnavailable)); assert!(r.analysis_due());
    let mut old_mask=mask.clone(); old_mask[0]=0; let model=baseline(&old_mask)?;
    let r=observe(&mut m,&model,&p,&mask,2,20)?;
    assert!(r.flags().contains(H::BackgroundIncomplete)); assert!(r.analysis_due());
    Ok(())
}
#[test]
fn owner_floor_and_activity_hold_bypass_quiet_sampling_without_granting_effects() -> TestResult {
    let mask=vec![1;16]; let model=baseline(&mask)?; let mut m=ScreeningMonitor::new(policy(),1,0)?;
    let mut p=pixels(); p[0]=200;
    let first=observe(&mut m,&model,&p,&mask,1,10)?; m.acknowledge_analysis(first.digest(),hash(b"synthetic-analysis-result"))?;
    p=pixels(); let hold=observe(&mut m,&model,&p,&mask,2,16)?;
    assert!(hold.reasons().contains(A::ActivityHold)); m.acknowledge_analysis(hold.digest(),hash(b"synthetic-analysis-result"))?;
    let r=detect(&model,&p,&mask,103,[17,17])?; let mut s=stamp(3,17); s.owner_requests_analysis=true;
    let result=m.observe(r.source(),&p,&mask,Some(&r),s,&mut WorkBudget::new(1_000_000))?;
    assert!(result.reasons().contains(A::OwnerRequested)); Ok(())
}
#[test]
fn deterministic_replay_preserves_the_complete_receipt_chain() -> TestResult {
    let mask=vec![1;16]; let model=baseline(&mask)?;
    let run=||->Result<Vec<[u8;32]>,Box<dyn Error>> {
        let mut m=ScreeningMonitor::new(policy(),1,0)?; let mut out=Vec::new();
        for i in 1..=30 {
            let mut p=pixels(); p[0]+=(i%3) as u8;
            let r=observe(&mut m,&model,&p,&mask,i,i*10)?;
            if r.analysis_due() { m.acknowledge_analysis(r.digest(),hash(b"synthetic-analysis-result"))?; }
            out.push(r.digest());
        }
        Ok(out)
    };
    assert_eq!(run()?,run()?); Ok(())
}
#[test]
fn invalid_policy_and_extreme_clock_values_fail_without_wraparound() -> TestResult {
    let mut p=policy(); p.minimum_analysis_interval_ns=p.sentinel_interval_ns+1;
    assert!(matches!(ScreeningMonitor::new(p,1,0),Err(ScreeningError::InvalidPolicy)));
    assert!(matches!(ScreeningMonitor::new(policy(),0,0),Err(ScreeningError::BasisMismatch)));
    let mut m=ScreeningMonitor::new(policy(),1,u64::MAX-1)?;
    assert_eq!(m.watchdog_deadline_ns(),None); assert!(!m.poll(u64::MAX)?.stalled);
    Ok(())
}
