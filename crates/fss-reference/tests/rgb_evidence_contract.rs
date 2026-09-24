#![forbid(unsafe_code)]
//! RGB evidence envelopes rebuilt from original sources; forged or truncated envelopes are refused.
use fss_core::ContentDigest;
use fss_reference::ScalarExecCx;
use fss_reference::ingest::model_import::ImportBudget;
use fss_reference::ingest::rgb_detections::RgbDetectionBudget;
use fss_reference::ingest::rgb_evidence::*;
use fss_codec_mjpeg::DecodeBudget;
use fss_twin::image_tracking::TrackingAvailability;
mod rgb_evidence_support;
use rgb_evidence_support::*;

#[test]
fn original_sources_rebuild_outputs_after_every_old_runtime_object_is_gone() -> Test {
    let cx = context(&std::env::temp_dir())?;
    let original = capture(1,TrackingAvailability::Available,&cx)?;
    let expected = replay(&original,&cx)?; let identity = original.identity();
    let bytes = original.encode(RgbEvidenceLimits::default(),&mut RgbEvidenceBudget::new(WORK),&cx)?;
    drop(original); // Imported model, inputs, execution and original run already dropped by fixture.
    let restored = RgbEvidence::decode(&bytes,identity,RgbEvidenceLimits::default(),&mut RgbEvidenceBudget::new(WORK),&cx)?;
    let actual = replay(&restored,&cx)?;
    assert_eq!(actual.run().inference().identity(),expected.run().inference().identity());
    assert_eq!(actual.run().report().digest(),expected.run().report().digest());
    assert_eq!(actual.run().inference().outputs()["head"].values(),expected.run().inference().outputs()["head"].values());
    assert_eq!(actual.run().report().detections().len(),1);
    assert_eq!(restored.jpeg(),jpeg(1)); assert_eq!(restored.weights(),weights()); assert_eq!(restored.graph(),graph()?);
    assert_eq!(restored.encode(RgbEvidenceLimits::default(),&mut RgbEvidenceBudget::new(WORK),&cx)?,bytes); Ok(())
}
#[test]
fn changed_original_source_cannot_hide_behind_valid_envelope_framing() -> Test {
    let cx=context(&std::env::temp_dir())?; let e=capture(1,TrackingAvailability::Available,&cx)?;
    let original=e.encode(RgbEvidenceLimits::default(),&mut RgbEvidenceBudget::new(WORK),&cx)?;
    let mut at=8;
    for _ in 0..5 {
        let len=u64::from_le_bytes(original[at..at+8].try_into()?) as usize; at+=8;
        let mut bad=original.clone(); bad[at+len-1]^=1;
        assert!(RgbEvidence::decode(&bad,e.identity(),RgbEvidenceLimits::default(),&mut RgbEvidenceBudget::new(WORK),&cx).is_err());
        at+=len;
    } Ok(())
}
#[test]
fn self_consistent_envelope_does_not_certify_a_forged_result_digest() -> Test {
    let cx=context(&std::env::temp_dir())?; let e=capture(1,TrackingAvailability::Available,&cx)?;
    let mut bytes=e.encode(RgbEvidenceLimits::default(),&mut RgbEvidenceBudget::new(WORK),&cx)?;
    let n=u64::from_le_bytes(bytes[8..16].try_into()?) as usize;
    bytes[16+n-1]^=1; // Last recipe field is the claimed head result digest, not a source byte.
    let forged=ContentDigest::sha256(&bytes[16..16+n]);
    let structural=RgbEvidence::decode(&bytes,forged,RgbEvidenceLimits::default(),&mut RgbEvidenceBudget::new(WORK),&cx)?;
    assert!(matches!(structural.replay(limits(),&mut RgbEvidenceBudget::new(WORK),&mut ImportBudget::new(WORK),
        &mut DecodeBudget::new(WORK),&mut RgbDetectionBudget::new(WORK,32*1024*1024),&cx,&ScalarExecCx::new()),
        Err(RgbEvidenceError::Mismatch))); Ok(())
}
#[test]
fn all_truncations_suffix_and_unbounded_length_are_refused_before_output() -> Test {
    let cx=context(&std::env::temp_dir())?; let e=capture(1,TrackingAvailability::Available,&cx)?;
    let bytes=e.encode(RgbEvidenceLimits::default(),&mut RgbEvidenceBudget::new(WORK),&cx)?;
    for n in 0..bytes.len() {
        assert!(RgbEvidence::decode(&bytes[..n],e.identity(),RgbEvidenceLimits::default(),&mut RgbEvidenceBudget::new(WORK),&cx).is_err());
    }
    let mut suffix=bytes.clone(); suffix.push(0);
    let mut overflow=bytes.clone(); overflow[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    for bad in [suffix,overflow] {
        assert!(RgbEvidence::decode(&bad,e.identity(),RgbEvidenceLimits::default(),&mut RgbEvidenceBudget::new(WORK),&cx).is_err());
    } Ok(())
}
#[test]
fn availability_and_uncertain_capture_intervals_survive_exactly() -> Test {
    let cx=context(&std::env::temp_dir())?;
    for availability in [TrackingAvailability::Available,TrackingAvailability::Disturbed,TrackingAvailability::Unobservable] {
        let e=capture(2,availability,&cx)?; let r=replay(&e,&cx)?;
        assert_eq!(r.admission().availability(),availability); assert_eq!(r.admission().evidence(), ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [5; 32]));
        assert_eq!(r.admission().source().capture,[2_000_000_000,2_000_000_001]);
        assert_eq!(r.run().allowed(),&[1;128]);
    } Ok(())
}
#[test]
fn independent_resource_refusals_do_not_consume_or_change_evidence() -> Test {
    let cx=context(&std::env::temp_dir())?; let e=capture(1,TrackingAvailability::Available,&cx)?;
    let id=e.identity();
    for stage in 0..4 {
        let mut l=limits(); if stage==3 { l.run.execution.max_macs=0; }
        assert!(e.replay(l,&mut RgbEvidenceBudget::new(WORK),&mut ImportBudget::new(if stage==0 {0} else {WORK}),
            &mut DecodeBudget::new(if stage==1 {0} else {WORK}),&mut RgbDetectionBudget::new(if stage==2 {0} else {WORK},32*1024*1024),
            &cx,&ScalarExecCx::new()).is_err());
        assert_eq!(e.identity(),id); assert_eq!(replay(&e,&cx)?.evidence_identity(),id);
    }
    let cancelled=ScalarExecCx::new(); cancelled.request_cancellation();
    assert!(e.replay(limits(),&mut RgbEvidenceBudget::new(WORK),&mut ImportBudget::new(WORK),&mut DecodeBudget::new(WORK),
        &mut RgbDetectionBudget::new(WORK,32*1024*1024),&cx,&cancelled).is_err()); Ok(())
}
#[test]
fn successful_allowances_do_not_change_envelope_or_replayed_identity() -> Test {
    let cx=context(&std::env::temp_dir())?; let e=capture(1,TrackingAvailability::Available,&cx)?;
    let mut full=RgbEvidenceBudget::new(WORK);
    let bytes=e.encode(RgbEvidenceLimits::default(),&mut full,&cx)?;
    let exact=RgbEvidenceLimits { maximum_bytes:bytes.len(),maximum_source_bytes:e.weights().len().max(e.graph().len()).max(e.jpeg().len()) };
    assert_eq!(e.encode(exact,&mut RgbEvidenceBudget::new(full.used()),&cx)?,bytes);
    assert!(matches!(e.encode(exact,&mut RgbEvidenceBudget::new(full.used()-1),&cx),Err(RgbEvidenceError::BudgetExceeded)));
    let small=RgbEvidenceLimits { maximum_bytes:bytes.len()-1,..exact };
    assert!(matches!(e.encode(small,&mut RgbEvidenceBudget::new(WORK),&cx),Err(RgbEvidenceError::Limit)));
    let a=replay(&e,&cx)?; let mut l=limits(); l.run.execution.max_macs*=2;
    let b=e.replay(l,&mut RgbEvidenceBudget::new(WORK),&mut ImportBudget::new(WORK),&mut DecodeBudget::new(WORK),
        &mut RgbDetectionBudget::new(WORK,32*1024*1024),&cx,&ScalarExecCx::new())?;
    assert_eq!(a.run().report().digest(),b.run().report().digest()); Ok(())
}
