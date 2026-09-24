#![forbid(unsafe_code)]
//! Native HTTP sockets feed actual JPEG/color/neural/temporal engines, not boxes.
//! Numerical fixture coefficients are not a trained object detector.
mod rgb_zone_support;
mod http_rgb_support;
use rgb_zone_support::{Test, WORK, model, head, tracker, tracking_policy, jpeg, post};
use http_rgb_support::*;
use fss_codec_mjpeg::DecodeBudget;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};
use fss_reference::ScalarExecCx;
use fss_reference::ingest::http_camera::*;
use fss_reference::ingest::http_camera::rgb::*;
use fss_reference::ingest::rgb_detections::{RgbDetectionBudget, RgbDetectionError};
use fss_reference::ingest::rgb_tracking::RgbFrameAdmission;
use fss_reference::ingest::rgb_tracking::pipeline::{RgbJpegZoneError, RgbJpegZonePipeline,
    RgbJpegZoneProgress, RgbZonePhase};
use fss_twin::image_tracking::TrackingAvailability;
use fss_twin::image_zones::ImageZoneEventKind;

fn zero_post() -> RgbDetectionBudget { RgbDetectionBudget::new(0, 32 * 1024 * 1024) }
fn ready(step: HttpRgbStep) -> Test<HttpRgbReceipt> {
    match step { HttpRgbStep::ResultReady(r) => Ok(r), _ => Err("expected complete neural result".into()) }
}
#[test]
fn native_sequence_reaches_owned_entry_dwell_exit_with_exact_wire_and_jpeg() -> Test {
    for chunked in [false, true] {
        let model = model(1)?; let head = head(&model)?; let mut owner = tracker(&head, tracking_policy())?;
        let images: Vec<_> = [16, 240, 240, 16].into_iter().map(jpeg).collect();
        let wire = response(&images, chunked);
        let (mut c, a, mut server) = session(&model, &head, &mut owner, wire.clone(), 79)?;
        let mut saved = Vec::new(); let mut results = Vec::new();
        for n in 1..=4 {
            next_frame(&mut c, &a, &mut server, &mut saved)?;
            let r = complete(&mut c, &a, n)?;
            let output = c.take_result(r, NOW, &a)?;
            assert_eq!(output.frame().part().bytes(), images[usize::from(n - 1)]);
            assert_eq!(output.analysis().admission().source().capture, [u64::from(n) * 1_000_000_000; 2]);
            assert_eq!(output.analysis().detection_run().inference().source().exposure, r.exposure());
            assert_eq!(output.analysis().temporal().tracking_digest(), r.tracking());
            assert!(output.analysis().detection_run().inference().executed_macs() > 0);
            let mut rebuilt = Vec::new();
            for span in output.frame().source_spans() {
                assert_eq!(span.jpeg_range[0], rebuilt.len() as u64);
                rebuilt.extend_from_slice(&saved[span.wire_range[0] as usize..span.wire_range[1] as usize]);
            }
            assert_eq!(rebuilt, output.frame().part().bytes());
            results.push(output);
        }
        finish(&mut c, &a, &mut server, &mut saved)?;
        assert_eq!(saved, wire); assert_eq!(c.camera().totals().frames, 4);
        assert!(c.camera().completion().is_some()); assert!(c.completion().is_none());
        assert!(results[1].analysis().temporal().events().iter().any(|e| e.kind == ImageZoneEventKind::EnteredBetweenObservations));
        assert!(results[2].analysis().temporal().events().iter().any(|e| e.kind == ImageZoneEventKind::SampledDwell));
        assert!(results[3].analysis().temporal().events().iter().any(|e| e.kind == ImageZoneEventKind::LeftBetweenObservations));
        assert_eq!(results[1].analysis().temporal().tracking_prior(), results[0].receipt().tracking());
        assert_eq!(results[3].analysis().temporal().tracks()[0].observations(), 4);
        assert_eq!(results[0].analysis().temporal().tracks()[0].observations(), 1);
        assert_eq!(results[1].analysis().temporal().rgb_decisions().len(), 2);
        assert_eq!(results[1].analysis().temporal().decisions().len(), 1);
        drop(c); assert_eq!(owner.tracker().exposure_count(), 4);
    }
    Ok(())
}
#[test]
fn pending_projection_retains_original_mask_and_prevents_more_camera_reads() -> Test {
    let model = model(1)?; let head = head(&model)?; let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(&[jpeg(240), jpeg(16)], true), 37)?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let mut mask = [1; 512]; let ctx = context(&c, &mask, 1, TrackingAvailability::Available)?;
    let mut decoder = DecodeBudget::new(WORK);
    assert_eq!(analyze(&mut c, ctx, &a, &mut decoder, &mut zero_post(), &mut WorkBudget::new(WORK),
        &mut WorkBudget::new(WORK))?, HttpRgbStep::AnalysisPending(RgbZonePhase::Projection));
    assert!(matches!(c.processing_result(), Some(Ok(RgbJpegZoneProgress::ProjectionPending(RgbDetectionError::BudgetExceeded)))));
    let identity = c.analysis().ok_or("analysis")?.pending_inference().ok_or("tensors")?.inference().identity();
    let used = decoder.used(); let counts = c.camera().totals(); mask.fill(0);
    for _ in 0..5 {
        assert_eq!(c.step(NOW, &a, &mut DecodeBudget::new(0))?, HttpRgbStep::AnalysisPending(RgbZonePhase::Projection));
        assert_eq!(c.camera().totals(), counts);
    }
    let changed = context(&c, &mask, 2, TrackingAvailability::Available)?;
    assert_eq!(analyze(&mut c, changed, &a, &mut decoder, &mut post(), &mut WorkBudget::new(WORK),
        &mut WorkBudget::new(WORK)), Err(HttpRgbError::AlreadyAccepted));
    let r = ready(c.resume(NOW, &a, &mut post(), &mut WorkBudget::new(WORK),
        &mut WorkBudget::new(WORK), &ScalarExecCx::new())?)?;
    let output = c.take_result(r, NOW, &a)?;
    assert_eq!(output.analysis().detection_run().inference().identity(), identity);
    assert_eq!(output.analysis().detection_run().allowed(), &[1; 512]);
    assert_eq!(decoder.used(), used); assert_eq!(output.analysis().temporal().tracks()[0].observations(), 1);
    Ok(())
}
#[test]
fn complete_result_backpressures_source_and_old_receipt_cannot_release_next_part() -> Test {
    let model = model(1)?; let head = head(&model)?; let mut owner = tracker(&head, tracking_policy())?;
    let image = jpeg(240);
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(&[image.clone(), image], false), 4096)?;
    let mut saved = Vec::new(); next_frame(&mut c, &a, &mut s, &mut saved)?;
    let first = complete(&mut c, &a, 1)?; let counts = c.camera().totals();
    for _ in 0..3 {
        assert_eq!(c.step(NOW, &a, &mut DecodeBudget::new(0))?, HttpRgbStep::ResultReady(first));
        assert_eq!(c.camera().totals(), counts);
        assert_eq!(c.resume(NOW, &a, &mut zero_post(), &mut WorkBudget::new(0),
            &mut WorkBudget::new(0), &ScalarExecCx::new())?, HttpRgbStep::ResultReady(first));
    }
    let old_output = c.take_result(first, NOW, &a)?;
    next_frame(&mut c, &a, &mut s, &mut saved)?;
    assert!(c.analysis().is_none()); assert!(c.completion().is_none());
    let second = complete(&mut c, &a, 2)?;
    assert_eq!(first.encoded_sha256(), second.encoded_sha256()); assert_ne!(first.exposure(), second.exposure());
    assert_ne!(first, second);
    assert!(matches!(c.take_result(first, NOW, &a), Err(HttpRgbError::ReceiptMismatch)));
    assert_eq!(c.completion(), Some(second)); assert_eq!(c.frame().ok_or("frame")?.part().receipt().ordinal, 2);
    let next_output = c.take_result(second, NOW, &a)?;
    assert_eq!(next_output.analysis().temporal().tracks()[0].observations(), 2);
    assert_eq!(old_output.analysis().temporal().tracks()[0].observations(), 1);
    Ok(())
}
#[test]
fn head_ordinal_and_exposure_mismatches_fail_before_decoding_or_assimilation() -> Test {
    let model = model(1)?; let head = head(&model)?; let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(&[jpeg(240)], false), 71)?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let ctx = context(&c, &[1; 512], 1, TrackingAvailability::Available)?;
    for case in 0..4 {
        let mut wrong = ctx;
        match case {
            0 => wrong.ordinal += 1,
            1 => wrong.expected_head.header_sha256 = [8; 32],
            _ => {
                let mut source = wrong.admission.source();
                if case == 2 { source.exposure = [8; 32]; } else { source.encoded_sha256 = [8; 32]; }
                wrong.admission = RgbFrameAdmission::new(source, wrong.admission.availability(), wrong.admission.evidence())?;
            }
        }
        let mut decoder = DecodeBudget::new(WORK);
        assert_eq!(analyze(&mut c, wrong, &a, &mut decoder, &mut post(), &mut WorkBudget::new(WORK),
            &mut WorkBudget::new(WORK)), Err(HttpRgbError::FrameMismatch));
        assert_eq!(decoder.used(), 0); assert_eq!(c.phase(), RgbZonePhase::Ready);
        assert!(c.processing_result().is_none()); assert!(c.frame().is_some());
    }
    let r = complete(&mut c, &a, 1)?; assert_eq!(c.take_result(r, NOW, &a)?.analysis().temporal().tracks()[0].observations(), 1);
    Ok(())
}
#[test]
fn source_link_budget_and_cancellation_leave_unaccepted_frame_retryable() -> Test {
    use std::sync::atomic::AtomicBool;
    let model = model(1)?; let head = head(&model)?; let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(&[jpeg(240)], true), 13)?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let ctx = context(&c, &[1; 512], 1, TrackingAvailability::Available)?;
    let mut measured = WorkBudget::new(WORK); http_rgb_exposure(c.frame().ok_or("frame")?, &mut measured)?;
    let required = measured.used() + 256;
    let mut decoder = DecodeBudget::new(WORK);
    for limit in [0, 511, required - 1] {
        assert_eq!(analyze(&mut c, ctx, &a, &mut decoder, &mut post(), &mut WorkBudget::new(WORK),
            &mut WorkBudget::new(limit)), Err(HttpRgbError::Work(GeometryError::BudgetExhausted)));
        assert_eq!(decoder.used(), 0); assert!(c.analysis().is_none());
    }
    let cancelled = AtomicBool::new(true);
    assert_eq!(analyze(&mut c, ctx, &a, &mut decoder, &mut post(), &mut WorkBudget::new(WORK),
        &mut WorkBudget::cancellable(WORK, &cancelled)), Err(HttpRgbError::Work(GeometryError::Cancelled)));
    assert_eq!(decoder.used(), 0); assert!(c.frame().is_some());
    let r = complete(&mut c, &a, 1)?; let _output = c.take_result(r, NOW, &a)?; Ok(())
}
#[test]
fn decode_and_mask_refusals_preserve_the_same_mapped_source() -> Test {
    let model = model(1)?; let head = head(&model)?; let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(&[jpeg(240)], false), 4096)?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let ctx = context(&c, &[1; 512], 1, TrackingAvailability::Available)?;
    assert_eq!(analyze(&mut c, ctx, &a, &mut DecodeBudget::new(0), &mut post(), &mut WorkBudget::new(WORK),
        &mut WorkBudget::new(WORK))?, HttpRgbStep::AnalysisRefused(RgbZonePhase::Ready));
    assert!(matches!(c.processing_result(), Some(Err(RgbJpegZoneError::Detector(_)))));
    let wrong = HttpRgbContext { allowed: &[0; 512], ..ctx };
    assert_eq!(analyze(&mut c, wrong, &a, &mut DecodeBudget::new(WORK), &mut post(), &mut WorkBudget::new(WORK),
        &mut WorkBudget::new(WORK))?, HttpRgbStep::AnalysisRefused(RgbZonePhase::Ready));
    assert!(c.frame().is_some()); assert!(c.completed().is_none());
    let r = complete(&mut c, &a, 1)?; assert_eq!(r.exposure(), ctx.admission.source().exposure);
    let _output = c.take_result(r, NOW, &a)?; Ok(())
}
#[test]
fn tracking_budget_refusal_resumes_without_reading_decoding_or_head_projection() -> Test {
    let model = model(1)?; let head = head(&model)?; let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(&[jpeg(240)], false), 4096)?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let ctx = context(&c, &[1; 512], 1, TrackingAvailability::Available)?;
    let mut decoder = DecodeBudget::new(WORK);
    assert_eq!(analyze(&mut c, ctx, &a, &mut decoder, &mut post(), &mut WorkBudget::new(0),
        &mut WorkBudget::new(WORK))?, HttpRgbStep::AnalysisPending(RgbZonePhase::Tracking));
    let inference = c.analysis().ok_or("analysis")?.detection_run().ok_or("detector")?.inference().identity();
    let counts = c.camera().totals(); let used = decoder.used(); let mut no_head = zero_post();
    let r = ready(c.resume(NOW, &a, &mut no_head, &mut WorkBudget::new(WORK),
        &mut WorkBudget::new(WORK), &ScalarExecCx::new())?)?;
    assert_eq!(no_head.used(), 0); assert_eq!(decoder.used(), used); assert_eq!(c.camera().totals(), counts);
    assert_eq!(r.inference(), inference.bytes());
    let _output = c.take_result(r, NOW, &a)?; Ok(())
}
#[test]
fn revocation_before_analysis_leaves_source_and_temporal_state_untouched() -> Test {
    let model = model(1)?; let head = head(&model)?; let mut owner = tracker(&head, tracking_policy())?;
    let before = owner.tracker().digest();
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(&[jpeg(240)], false), 4096)?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let ctx = context(&c, &[1; 512], 1, TrackingAvailability::Available)?;
    a.deny_on(HttpCameraOperation::Analyze, 1); let mut decoder = DecodeBudget::new(WORK);
    assert_eq!(analyze(&mut c, ctx, &a, &mut decoder, &mut post(), &mut WorkBudget::new(WORK),
        &mut WorkBudget::new(WORK)), Err(HttpRgbError::Source(HttpCameraError::Denied(HttpCameraDenial::Revoked))));
    assert_eq!(decoder.used(), 0);
    let retired = c.retire(); assert!(retired.source.frame.is_some()); assert!(retired.exposure.is_none());
    assert_eq!(retired.processor.phase, RgbZonePhase::Ready); assert_eq!(owner.tracker().digest(), before); Ok(())
}
#[test]
fn post_analysis_revocation_retains_completed_neural_and_temporal_result() -> Test {
    let model = model(1)?; let head = head(&model)?; let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(&[jpeg(240)], false), 4096)?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let ctx = context(&c, &[1; 512], 1, TrackingAvailability::Available)?;
    a.deny_on(HttpCameraOperation::Analyze, 2);
    assert_eq!(analyze(&mut c, ctx, &a, &mut DecodeBudget::new(WORK), &mut post(), &mut WorkBudget::new(WORK),
        &mut WorkBudget::new(WORK)), Err(HttpRgbError::Source(HttpCameraError::Denied(HttpCameraDenial::Revoked))));
    assert!(matches!(c.processing_result(), Some(Ok(RgbJpegZoneProgress::Complete { .. }))));
    let r = c.completion().ok_or("lost receipt")?;
    assert_eq!(c.completed().ok_or("lost complete")?.temporal().tracking_digest(), r.tracking());
    let retired = c.retire(); assert!(retired.source.frame.is_some());
    assert_eq!(retired.processor.complete.ok_or("lost owned result")?.temporal().tracking_digest(), r.tracking());
    assert_eq!(owner.tracker().exposure_count(), 1); Ok(())
}
#[test]
fn release_frame_revocation_keeps_result_taken_from_processor_and_original_together() -> Test {
    let model = model(1)?; let head = head(&model)?; let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(&[jpeg(240)], false), 4096)?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?; let r = complete(&mut c, &a, 1)?;
    a.deny_on(HttpCameraOperation::ReleaseFrame, 1);
    assert!(matches!(c.take_result(r, NOW, &a), Err(HttpRgbError::Source(HttpCameraError::Denied(HttpCameraDenial::Revoked)))));
    assert_eq!(c.completion(), Some(r)); assert_eq!(c.phase(), RgbZonePhase::Complete);
    assert_eq!(c.completed().ok_or("dropped result")?.temporal().zone_digest(), r.zones());
    assert!(c.frame().is_some()); assert!(c.last_taken().is_none());
    let retired = c.retire(); assert!(retired.source.frame.is_some());
    assert!(retired.processor.complete.is_none()); assert_eq!(retired.processor.phase, RgbZonePhase::Ready);
    assert_eq!(retired.held.ok_or("lost transfer slot")?.temporal().tracking_digest(), r.tracking());
    assert_eq!(owner.tracker().exposure_count(), 1); Ok(())
}
#[test]
fn release_result_revocation_does_not_transfer_either_owner() -> Test {
    let model = model(1)?; let head = head(&model)?; let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(&[jpeg(240)], false), 4096)?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?; let r = complete(&mut c, &a, 1)?;
    a.deny_on(HttpCameraOperation::ReleaseResult, 1);
    assert!(matches!(c.take_result(r, NOW, &a), Err(HttpRgbError::Source(HttpCameraError::Denied(HttpCameraDenial::Revoked)))));
    let retired = c.retire(); assert!(retired.source.frame.is_some()); assert!(retired.held.is_none());
    assert!(retired.processor.complete.is_some()); assert_eq!(retired.complete, Some(r)); Ok(())
}
#[test]
fn retirement_while_projection_is_pending_retains_tensors_mask_and_mapped_jpeg() -> Test {
    let model = model(1)?; let head = head(&model)?; let mut owner = tracker(&head, tracking_policy())?;
    let image = jpeg(240);
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(std::slice::from_ref(&image), true), 4096)?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let ctx = context(&c, &[1; 512], 1, TrackingAvailability::Available)?;
    assert_eq!(analyze(&mut c, ctx, &a, &mut DecodeBudget::new(WORK), &mut zero_post(), &mut WorkBudget::new(WORK),
        &mut WorkBudget::new(WORK))?, HttpRgbStep::AnalysisPending(RgbZonePhase::Projection));
    let retired = c.retire(); assert!(retired.complete.is_none());
    assert_eq!(retired.source.frame.ok_or("lost JPEG")?.part().bytes(), image);
    let pending = retired.processor.inference.ok_or("lost tensor output")?;
    assert_eq!(pending.inference().source().exposure, ctx.admission.source().exposure);
    assert_eq!(pending.allowed(), &[1; 512]); assert_eq!(owner.tracker().exposure_count(), 0); Ok(())
}
#[test]
fn explicit_capture_interval_and_unobservable_admission_are_not_replaced_by_arrival() -> Test {
    let model = model(1)?; let head = head(&model)?; let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(&[jpeg(240)], false), 4096)?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let mut ctx = context(&c, &[1; 512], 1, TrackingAvailability::Unobservable)?;
    let mut source = ctx.admission.source(); source.capture = [10, 100];
    ctx.admission = RgbFrameAdmission::new(source, TrackingAvailability::Unobservable, ContentDigest::sha256(b"independent uncertainty"))?;
    let r = ready(analyze(&mut c, ctx, &a, &mut DecodeBudget::new(WORK), &mut post(), &mut WorkBudget::new(WORK),
        &mut WorkBudget::new(WORK))?)?;
    let output = c.take_result(r, NOW, &a)?;
    assert_eq!(output.analysis().admission().source().capture, [10, 100]);
    assert_eq!(output.analysis().temporal().frame().availability, TrackingAvailability::Unobservable);
    assert!(output.analysis().temporal().tracks().is_empty());
    assert!(!output.analysis().detection_run().report().detections().is_empty());
    Ok(())
}
#[test]
fn refused_attachment_returns_a_pending_processor_and_fresh_camera() -> Test {
    let model = model(1)?; let head = head(&model)?; let mut owner = tracker(&head, tracking_policy())?;
    let mut processor = RgbJpegZonePipeline::new(&model, &head, &mut owner)?;
    let bytes = jpeg(240); let input = rgb_zone_support::input(&bytes, &[1; 512], 1);
    assert!(matches!(processor.run_jpeg(input, rgb_zone_support::admission(input.source, TrackingAvailability::Available)?,
        rgb_zone_support::limits(), &mut DecodeBudget::new(WORK), &mut zero_post(),
        &mut WorkBudget::new(WORK), &ScalarExecCx::new())?, RgbJpegZoneProgress::ProjectionPending(_)));
    let (camera, _a, _server) = camera(response(&[bytes], false), 4096)?;
    let refusal = match HttpRgbCapture::attach(camera, processor) {
        Err(refusal) => refusal, Ok(_) => return Err("pending processor was attached".into()),
    };
    assert_eq!(refusal.camera.totals(), HttpCameraTotals::default());
    assert_eq!(refusal.processor.phase(), RgbZonePhase::Projection);
    assert!(refusal.processor.pending_inference().is_some());
    let _source = refusal.camera.retire(); let work = refusal.processor.retire();
    assert!(work.inference.is_some()); assert_eq!(owner.tracker().exposure_count(), 0); Ok(())
}
