#![forbid(unsafe_code)]
//! Native HTTP sockets feed actual JPEG/color/neural/temporal engines, not boxes.
//! Numerical fixture coefficients are not a trained object detector.
mod http_rgb_support;
mod privacy_live_support;
mod rgb_zone_support;
use fss_codec_mjpeg::DecodeBudget;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};
use fss_reference::ScalarExecCx;
use fss_reference::ingest::http_camera::rgb::*;
use fss_reference::ingest::http_camera::*;
use fss_reference::ingest::rgb_detections::{RgbDetectionBudget, RgbDetectionError};
use fss_reference::ingest::rgb_tracking::RgbFrameAdmission;
use fss_reference::ingest::rgb_tracking::pipeline::{
    RgbJpegZoneError, RgbJpegZonePipeline, RgbJpegZoneProgress, RgbZonePhase,
};
use fss_twin::image_tracking::TrackingAvailability;
use fss_twin::image_zones::ImageZoneEventKind;
use http_rgb_support::*;
use privacy_live_support::PrivacyDeployment;
use rgb_zone_support::{Test, WORK, head, jpeg, model, post, tracker, tracking_policy};

fn zero_post() -> RgbDetectionBudget {
    RgbDetectionBudget::new(0, 32 * 1024 * 1024)
}
fn ready(step: HttpRgbStep) -> Test<HttpRgbReceipt> {
    match step {
        HttpRgbStep::ResultReady(r) => Ok(r),
        _ => Err("expected complete neural result".into()),
    }
}
#[test]
fn native_sequence_reaches_owned_entry_dwell_exit_with_exact_wire_and_jpeg() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb")?;
    for chunked in [false, true] {
        let model = model(1)?;
        let head = head(&model)?;
        let mut owner = tracker(&head, tracking_policy())?;
        let images: Vec<_> = [16, 240, 240, 16].into_iter().map(jpeg).collect();
        let wire = response(&images, chunked);
        let (mut c, a, mut server) = session(&model, &head, &mut owner, wire.clone(), 79)?;
        let mut saved = Vec::new();
        let mut results = Vec::new();
        for n in 1..=4 {
            next_frame(&mut c, &a, &mut server, &mut saved)?;
            let r = complete(&mut c, &a, n, privacy.mask())?;
            let output = c.take_result(r, NOW, &a)?;
            assert_eq!(output.frame().part().bytes(), images[usize::from(n - 1)]);
            assert_eq!(
                output.analysis().admission().source().capture,
                [u64::from(n) * 1_000_000_000; 2]
            );
            assert_eq!(
                output
                    .analysis()
                    .detection_run()
                    .inference()
                    .source()
                    .exposure,
                r.exposure()
            );
            assert_eq!(output.analysis().temporal().tracking_digest(), r.tracking());
            assert!(
                output
                    .analysis()
                    .detection_run()
                    .inference()
                    .executed_macs()
                    > 0
            );
            let mut rebuilt = Vec::new();
            for span in output.frame().source_spans() {
                assert_eq!(span.jpeg_range[0], rebuilt.len() as u64);
                rebuilt.extend_from_slice(
                    &saved[span.wire_range[0] as usize..span.wire_range[1] as usize],
                );
            }
            assert_eq!(rebuilt, output.frame().part().bytes());
            results.push(output);
        }
        finish(&mut c, &a, &mut server, &mut saved)?;
        assert_eq!(saved, wire);
        assert_eq!(c.camera().totals().frames, 4);
        assert!(c.camera().completion().is_some());
        assert!(c.completion().is_none());
        assert!(
            results[1]
                .analysis()
                .temporal()
                .events()
                .iter()
                .any(|e| e.kind == ImageZoneEventKind::EnteredBetweenObservations)
        );
        assert!(
            results[2]
                .analysis()
                .temporal()
                .events()
                .iter()
                .any(|e| e.kind == ImageZoneEventKind::SampledDwell)
        );
        assert!(
            results[3]
                .analysis()
                .temporal()
                .events()
                .iter()
                .any(|e| e.kind == ImageZoneEventKind::LeftBetweenObservations)
        );
        assert_eq!(
            results[1].analysis().temporal().tracking_prior(),
            results[0].receipt().tracking()
        );
        assert_eq!(
            results[3].analysis().temporal().tracks()[0].observations(),
            4
        );
        assert_eq!(
            results[0].analysis().temporal().tracks()[0].observations(),
            1
        );
        assert_eq!(results[1].analysis().temporal().rgb_decisions().len(), 2);
        assert_eq!(results[1].analysis().temporal().decisions().len(), 1);
        drop(c);
        assert_eq!(owner.tracker().exposure_count(), 4);
    }
    Ok(())
}
#[test]
fn pending_projection_retains_original_mask_and_prevents_more_camera_reads() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb")?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(
        &model,
        &head,
        &mut owner,
        response(&[jpeg(240), jpeg(16)], true),
        37,
    )?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let mut mask = [1; 512];
    let ctx = context(
        &c,
        &mask,
        1,
        TrackingAvailability::Available,
        privacy.mask(),
    )?;
    let mut decoder = DecodeBudget::new(WORK);
    assert_eq!(
        analyze(
            &mut c,
            ctx,
            &a,
            &mut decoder,
            &mut zero_post(),
            &mut WorkBudget::new(WORK),
            &mut WorkBudget::new(WORK)
        )?,
        HttpRgbStep::AnalysisPending(RgbZonePhase::Projection)
    );
    assert!(matches!(
        c.processing_result(),
        Some(Ok(RgbJpegZoneProgress::ProjectionPending(
            RgbDetectionError::BudgetExceeded
        )))
    ));
    let identity = c
        .analysis()
        .ok_or("analysis")?
        .pending_inference()
        .ok_or("tensors")?
        .inference()
        .identity();
    let used = decoder.used();
    let counts = c.camera().totals();
    mask.fill(0);
    for _ in 0..5 {
        assert_eq!(
            c.step(NOW, &a, &mut DecodeBudget::new(0))?,
            HttpRgbStep::AnalysisPending(RgbZonePhase::Projection)
        );
        assert_eq!(c.camera().totals(), counts);
    }
    let changed = context(
        &c,
        &mask,
        2,
        TrackingAvailability::Available,
        privacy.mask(),
    )?;
    assert_eq!(
        analyze(
            &mut c,
            changed,
            &a,
            &mut decoder,
            &mut post(),
            &mut WorkBudget::new(WORK),
            &mut WorkBudget::new(WORK)
        ),
        Err(HttpRgbError::AlreadyAccepted)
    );
    let r = ready(c.resume(
        NOW,
        &a,
        &mut post(),
        &mut WorkBudget::new(WORK),
        &mut WorkBudget::new(WORK),
        &ScalarExecCx::new(),
    )?)?;
    let output = c.take_result(r, NOW, &a)?;
    assert_eq!(
        output.analysis().detection_run().inference().identity(),
        identity
    );
    assert_eq!(output.analysis().detection_run().allowed(), &[1; 512]);
    assert_eq!(decoder.used(), used);
    assert_eq!(output.analysis().temporal().tracks()[0].observations(), 1);
    Ok(())
}
#[test]
fn complete_result_backpressures_source_and_old_receipt_cannot_release_next_part() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb")?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let image = jpeg(240);
    let (mut c, a, mut s) = session(
        &model,
        &head,
        &mut owner,
        response(&[image.clone(), image], false),
        4096,
    )?;
    let mut saved = Vec::new();
    next_frame(&mut c, &a, &mut s, &mut saved)?;
    let first = complete(&mut c, &a, 1, privacy.mask())?;
    let counts = c.camera().totals();
    for _ in 0..3 {
        assert_eq!(
            c.step(NOW, &a, &mut DecodeBudget::new(0))?,
            HttpRgbStep::ResultReady(first)
        );
        assert_eq!(c.camera().totals(), counts);
        assert_eq!(
            c.resume(
                NOW,
                &a,
                &mut zero_post(),
                &mut WorkBudget::new(0),
                &mut WorkBudget::new(0),
                &ScalarExecCx::new()
            )?,
            HttpRgbStep::ResultReady(first)
        );
    }
    let old_output = c.take_result(first, NOW, &a)?;
    next_frame(&mut c, &a, &mut s, &mut saved)?;
    assert!(c.analysis().is_none());
    assert!(c.completion().is_none());
    let second = complete(&mut c, &a, 2, privacy.mask())?;
    assert_eq!(first.encoded_sha256(), second.encoded_sha256());
    assert_ne!(first.exposure(), second.exposure());
    assert_ne!(first, second);
    assert!(matches!(
        c.take_result(first, NOW, &a),
        Err(HttpRgbError::ReceiptMismatch)
    ));
    assert_eq!(c.completion(), Some(second));
    assert_eq!(c.frame().ok_or("frame")?.part().receipt().ordinal, 2);
    let next_output = c.take_result(second, NOW, &a)?;
    assert_eq!(
        next_output.analysis().temporal().tracks()[0].observations(),
        2
    );
    assert_eq!(
        old_output.analysis().temporal().tracks()[0].observations(),
        1
    );
    Ok(())
}
#[test]
fn head_ordinal_and_exposure_mismatches_fail_before_decoding_or_assimilation() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb")?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(&[jpeg(240)], false), 71)?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let ctx = context(
        &c,
        &[1; 512],
        1,
        TrackingAvailability::Available,
        privacy.mask(),
    )?;
    for case in 0..4 {
        let mut wrong = ctx;
        match case {
            0 => wrong.ordinal += 1,
            1 => wrong.expected_head.header_sha256 = [8; 32],
            _ => {
                let mut source = wrong.admission.source();
                if case == 2 {
                    source.exposure = [8; 32];
                } else {
                    source.encoded_sha256 = [8; 32];
                }
                wrong.admission = RgbFrameAdmission::new(
                    source,
                    wrong.admission.availability(),
                    wrong.admission.evidence(),
                )?;
            }
        }
        let mut decoder = DecodeBudget::new(WORK);
        assert_eq!(
            analyze(
                &mut c,
                wrong,
                &a,
                &mut decoder,
                &mut post(),
                &mut WorkBudget::new(WORK),
                &mut WorkBudget::new(WORK)
            ),
            Err(HttpRgbError::FrameMismatch)
        );
        assert_eq!(decoder.used(), 0);
        assert_eq!(c.phase(), RgbZonePhase::Ready);
        assert!(c.processing_result().is_none());
        assert!(c.frame().is_some());
    }
    let r = complete(&mut c, &a, 1, privacy.mask())?;
    assert_eq!(
        c.take_result(r, NOW, &a)?.analysis().temporal().tracks()[0].observations(),
        1
    );
    Ok(())
}
#[test]
fn source_link_budget_and_cancellation_leave_unaccepted_frame_retryable() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb")?;
    use std::sync::atomic::AtomicBool;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(&[jpeg(240)], true), 13)?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let ctx = context(
        &c,
        &[1; 512],
        1,
        TrackingAvailability::Available,
        privacy.mask(),
    )?;
    let mut measured = WorkBudget::new(WORK);
    http_rgb_exposure(c.frame().ok_or("frame")?, &mut measured)?;
    let required = measured.used() + 256;
    let mut decoder = DecodeBudget::new(WORK);
    for limit in [0, 511, required - 1] {
        assert_eq!(
            analyze(
                &mut c,
                ctx,
                &a,
                &mut decoder,
                &mut post(),
                &mut WorkBudget::new(WORK),
                &mut WorkBudget::new(limit)
            ),
            Err(HttpRgbError::Work(GeometryError::BudgetExhausted))
        );
        assert_eq!(decoder.used(), 0);
        assert!(c.analysis().is_none());
    }
    let cancelled = AtomicBool::new(true);
    assert_eq!(
        analyze(
            &mut c,
            ctx,
            &a,
            &mut decoder,
            &mut post(),
            &mut WorkBudget::new(WORK),
            &mut WorkBudget::cancellable(WORK, &cancelled)
        ),
        Err(HttpRgbError::Work(GeometryError::Cancelled))
    );
    assert_eq!(decoder.used(), 0);
    assert!(c.frame().is_some());
    let r = complete(&mut c, &a, 1, privacy.mask())?;
    let _output = c.take_result(r, NOW, &a)?;
    Ok(())
}
#[test]
fn decode_and_mask_refusals_preserve_the_same_mapped_source() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb")?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(
        &model,
        &head,
        &mut owner,
        response(&[jpeg(240)], false),
        4096,
    )?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let ctx = context(
        &c,
        &[1; 512],
        1,
        TrackingAvailability::Available,
        privacy.mask(),
    )?;
    assert_eq!(
        analyze(
            &mut c,
            ctx,
            &a,
            &mut DecodeBudget::new(0),
            &mut post(),
            &mut WorkBudget::new(WORK),
            &mut WorkBudget::new(WORK)
        )?,
        HttpRgbStep::AnalysisRefused(RgbZonePhase::Ready)
    );
    assert!(matches!(
        c.processing_result(),
        Some(Err(RgbJpegZoneError::Detector(_)))
    ));
    let wrong = HttpRgbContext {
        allowed: &[0; 512],
        ..ctx
    };
    assert_eq!(
        analyze(
            &mut c,
            wrong,
            &a,
            &mut DecodeBudget::new(WORK),
            &mut post(),
            &mut WorkBudget::new(WORK),
            &mut WorkBudget::new(WORK)
        )?,
        HttpRgbStep::AnalysisRefused(RgbZonePhase::Ready)
    );
    assert!(c.frame().is_some());
    assert!(c.completed().is_none());
    let r = complete(&mut c, &a, 1, privacy.mask())?;
    assert_eq!(r.exposure(), ctx.admission.source().exposure);
    let _output = c.take_result(r, NOW, &a)?;
    Ok(())
}
#[test]
fn tracking_budget_refusal_resumes_without_reading_decoding_or_head_projection() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb")?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(
        &model,
        &head,
        &mut owner,
        response(&[jpeg(240)], false),
        4096,
    )?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let ctx = context(
        &c,
        &[1; 512],
        1,
        TrackingAvailability::Available,
        privacy.mask(),
    )?;
    let mut decoder = DecodeBudget::new(WORK);
    assert_eq!(
        analyze(
            &mut c,
            ctx,
            &a,
            &mut decoder,
            &mut post(),
            &mut WorkBudget::new(0),
            &mut WorkBudget::new(WORK)
        )?,
        HttpRgbStep::AnalysisPending(RgbZonePhase::Tracking)
    );
    let inference = c
        .analysis()
        .ok_or("analysis")?
        .detection_run()
        .ok_or("detector")?
        .inference()
        .identity();
    let counts = c.camera().totals();
    let used = decoder.used();
    let mut no_head = zero_post();
    let r = ready(c.resume(
        NOW,
        &a,
        &mut no_head,
        &mut WorkBudget::new(WORK),
        &mut WorkBudget::new(WORK),
        &ScalarExecCx::new(),
    )?)?;
    assert_eq!(no_head.used(), 0);
    assert_eq!(decoder.used(), used);
    assert_eq!(c.camera().totals(), counts);
    assert_eq!(r.inference(), inference.bytes());
    let _output = c.take_result(r, NOW, &a)?;
    Ok(())
}
#[test]
fn revocation_before_analysis_leaves_source_and_temporal_state_untouched() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb")?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let before = owner.tracker().digest();
    let (mut c, a, mut s) = session(
        &model,
        &head,
        &mut owner,
        response(&[jpeg(240)], false),
        4096,
    )?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let ctx = context(
        &c,
        &[1; 512],
        1,
        TrackingAvailability::Available,
        privacy.mask(),
    )?;
    a.deny_on(HttpCameraOperation::Analyze, 1);
    let mut decoder = DecodeBudget::new(WORK);
    assert_eq!(
        analyze(
            &mut c,
            ctx,
            &a,
            &mut decoder,
            &mut post(),
            &mut WorkBudget::new(WORK),
            &mut WorkBudget::new(WORK)
        ),
        Err(HttpRgbError::Source(HttpCameraError::Denied(
            HttpCameraDenial::Revoked
        )))
    );
    assert_eq!(decoder.used(), 0);
    let retired = c.retire();
    assert!(retired.source.frame.is_some());
    assert!(retired.exposure.is_none());
    assert_eq!(retired.processor.phase, RgbZonePhase::Ready);
    assert_eq!(owner.tracker().digest(), before);
    Ok(())
}
#[test]
fn post_analysis_revocation_retains_completed_neural_and_temporal_result() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb")?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(
        &model,
        &head,
        &mut owner,
        response(&[jpeg(240)], false),
        4096,
    )?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let ctx = context(
        &c,
        &[1; 512],
        1,
        TrackingAvailability::Available,
        privacy.mask(),
    )?;
    a.deny_on(HttpCameraOperation::Analyze, 2);
    assert_eq!(
        analyze(
            &mut c,
            ctx,
            &a,
            &mut DecodeBudget::new(WORK),
            &mut post(),
            &mut WorkBudget::new(WORK),
            &mut WorkBudget::new(WORK)
        ),
        Err(HttpRgbError::Source(HttpCameraError::Denied(
            HttpCameraDenial::Revoked
        )))
    );
    assert!(matches!(
        c.processing_result(),
        Some(Ok(RgbJpegZoneProgress::Complete { .. }))
    ));
    let r = c.completion().ok_or("lost receipt")?;
    assert_eq!(
        c.completed()
            .ok_or("lost complete")?
            .temporal()
            .tracking_digest(),
        r.tracking()
    );
    let retired = c.retire();
    assert!(retired.source.frame.is_some());
    assert_eq!(
        retired
            .processor
            .complete
            .ok_or("lost owned result")?
            .temporal()
            .tracking_digest(),
        r.tracking()
    );
    assert_eq!(owner.tracker().exposure_count(), 1);
    Ok(())
}
#[test]
fn release_frame_revocation_keeps_result_taken_from_processor_and_original_together() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb")?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(
        &model,
        &head,
        &mut owner,
        response(&[jpeg(240)], false),
        4096,
    )?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let r = complete(&mut c, &a, 1, privacy.mask())?;
    a.deny_on(HttpCameraOperation::ReleaseFrame, 1);
    assert!(matches!(
        c.take_result(r, NOW, &a),
        Err(HttpRgbError::Source(HttpCameraError::Denied(
            HttpCameraDenial::Revoked
        )))
    ));
    assert_eq!(c.completion(), Some(r));
    assert_eq!(c.phase(), RgbZonePhase::Complete);
    assert_eq!(
        c.completed()
            .ok_or("dropped result")?
            .temporal()
            .zone_digest(),
        r.zones()
    );
    assert!(c.frame().is_some());
    assert!(c.last_taken().is_none());
    let retired = c.retire();
    assert!(retired.source.frame.is_some());
    assert!(retired.processor.complete.is_none());
    assert_eq!(retired.processor.phase, RgbZonePhase::Ready);
    assert_eq!(
        retired
            .held
            .ok_or("lost transfer slot")?
            .temporal()
            .tracking_digest(),
        r.tracking()
    );
    assert_eq!(owner.tracker().exposure_count(), 1);
    Ok(())
}
#[test]
fn release_result_revocation_does_not_transfer_either_owner() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb")?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(
        &model,
        &head,
        &mut owner,
        response(&[jpeg(240)], false),
        4096,
    )?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let r = complete(&mut c, &a, 1, privacy.mask())?;
    a.deny_on(HttpCameraOperation::ReleaseResult, 1);
    assert!(matches!(
        c.take_result(r, NOW, &a),
        Err(HttpRgbError::Source(HttpCameraError::Denied(
            HttpCameraDenial::Revoked
        )))
    ));
    let retired = c.retire();
    assert!(retired.source.frame.is_some());
    assert!(retired.held.is_none());
    assert!(retired.processor.complete.is_some());
    assert_eq!(retired.complete, Some(r));
    Ok(())
}
#[test]
fn retirement_while_projection_is_pending_retains_tensors_mask_and_mapped_jpeg() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb")?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let image = jpeg(240);
    let (mut c, a, mut s) = session(
        &model,
        &head,
        &mut owner,
        response(std::slice::from_ref(&image), true),
        4096,
    )?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let ctx = context(
        &c,
        &[1; 512],
        1,
        TrackingAvailability::Available,
        privacy.mask(),
    )?;
    assert_eq!(
        analyze(
            &mut c,
            ctx,
            &a,
            &mut DecodeBudget::new(WORK),
            &mut zero_post(),
            &mut WorkBudget::new(WORK),
            &mut WorkBudget::new(WORK)
        )?,
        HttpRgbStep::AnalysisPending(RgbZonePhase::Projection)
    );
    let retired = c.retire();
    assert!(retired.complete.is_none());
    assert_eq!(
        retired.source.frame.ok_or("lost JPEG")?.part().bytes(),
        image
    );
    let pending = retired.processor.inference.ok_or("lost tensor output")?;
    assert_eq!(
        pending.inference().source().exposure,
        ctx.admission.source().exposure
    );
    assert_eq!(pending.allowed(), &[1; 512]);
    assert_eq!(owner.tracker().exposure_count(), 0);
    Ok(())
}
#[test]
fn explicit_capture_interval_and_unobservable_admission_are_not_replaced_by_arrival() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb")?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(
        &model,
        &head,
        &mut owner,
        response(&[jpeg(240)], false),
        4096,
    )?;
    next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
    let mut ctx = context(
        &c,
        &[1; 512],
        1,
        TrackingAvailability::Unobservable,
        privacy.mask(),
    )?;
    let mut source = ctx.admission.source();
    source.capture = [10, 100];
    ctx.admission = RgbFrameAdmission::new(
        source,
        TrackingAvailability::Unobservable,
        ContentDigest::sha256(b"independent uncertainty"),
    )?;
    let r = ready(analyze(
        &mut c,
        ctx,
        &a,
        &mut DecodeBudget::new(WORK),
        &mut post(),
        &mut WorkBudget::new(WORK),
        &mut WorkBudget::new(WORK),
    )?)?;
    let output = c.take_result(r, NOW, &a)?;
    assert_eq!(output.analysis().admission().source().capture, [10, 100]);
    assert_eq!(
        output.analysis().temporal().frame().availability,
        TrackingAvailability::Unobservable
    );
    assert!(output.analysis().temporal().tracks().is_empty());
    assert!(
        !output
            .analysis()
            .detection_run()
            .report()
            .detections()
            .is_empty()
    );
    Ok(())
}
#[test]
fn refused_attachment_returns_a_pending_processor_and_fresh_camera() -> Test {
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let mut processor = RgbJpegZonePipeline::new(&model, &head, &mut owner)?;
    let bytes = jpeg(240);
    let input = rgb_zone_support::input(&bytes, &[1; 512], 1);
    assert!(matches!(
        processor.run_jpeg(
            input,
            rgb_zone_support::admission(input.source, TrackingAvailability::Available)?,
            rgb_zone_support::limits(),
            &mut DecodeBudget::new(WORK),
            &mut zero_post(),
            &mut WorkBudget::new(WORK),
            &ScalarExecCx::new()
        )?,
        RgbJpegZoneProgress::ProjectionPending(_)
    ));
    let (camera, _a, _server) = camera(response(&[bytes], false), 4096)?;
    let refusal = match HttpRgbCapture::attach(camera, processor) {
        Err(refusal) => refusal,
        Ok(_) => return Err("pending processor was attached".into()),
    };
    assert_eq!(refusal.camera.totals(), HttpCameraTotals::default());
    assert_eq!(refusal.processor.phase(), RgbZonePhase::Projection);
    assert!(refusal.processor.pending_inference().is_some());
    let _source = refusal.camera.retire();
    let work = refusal.processor.retire();
    assert!(work.inference.is_some());
    assert_eq!(owner.tracker().exposure_count(), 0);
    Ok(())
}

/// The zone half of the 32x16 frame (x >= 14): where the bright-value boxes land.
const ZONE_MASK: [u32; 4] = [14, 0, 18, 16];
fn declare(p: &mut PrivacyDeployment, rectangles: &[[u32; 4]]) -> Test<fss_core::ContentDigest> {
    use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
    let policy = PrivacyMaskPolicy::new(p.sensor.clone(), [32, 16], rectangles)?;
    let preview = preview_mask(&p.deployment, &policy)?;
    Ok(declare_mask(&mut p.deployment, &policy, preview.approval, &p.cx)?.policy_digest)
}
/// Native RGB decode with every masked pixel set to the fill by hand (x >= 14): an independent
/// statement of the retained-decode masked RGB digest.
fn masked_rgb_digest(bytes: &[u8]) -> Test<[u8; 32]> {
    use fss_codec_mjpeg::ComponentInterpretation;
    use fss_codec_mjpeg::color::decode_rgb;
    let image = decode_rgb(
        bytes,
        ContentDigest::sha256(bytes).bytes(),
        ComponentInterpretation::YCbCr,
        Default::default(),
        &mut DecodeBudget::new(WORK),
    )?;
    let mut rgb = image.pixels().to_vec();
    for y in 0..16 {
        for x in 14..32 {
            let at = (y * 32 + x) * 3;
            rgb[at..at + 3].copy_from_slice(&[16, 16, 16]);
        }
    }
    Ok(ContentDigest::sha256(&rgb).bytes())
}
fn privacy_refusal(c: &HttpRgbCapture<'_, '_>) -> Option<&'static str> {
    use fss_reference::ingest::rgb_detections::pipeline::RgbDetectorError;
    match c.processing_result()? {
        Err(RgbJpegZoneError::Detector(RgbDetectorError::Privacy(error))) => {
            Some(error.stable_id())
        }
        _ => None,
    }
}
#[test]
fn motion_into_a_masked_zone_yields_no_detection_track_or_zone_event() -> Test {
    let mut privacy = PrivacyDeployment::new("http-rgb-masked")?;
    let policy = declare(&mut privacy, &[ZONE_MASK])?;
    let grid = privacy.mask().resolve()?.allowed([32, 16])?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let images: Vec<_> = [16, 240, 240, 16].into_iter().map(jpeg).collect();
    let (mut c, a, mut server) = session(&model, &head, &mut owner, response(&images, false), 79)?;
    let mut saved = Vec::new();
    let mut outputs = Vec::new();
    for n in 1..=4_u8 {
        next_frame(&mut c, &a, &mut server, &mut saved)?;
        // The owner grid still admitting the masked zone is refused as unmasked access.
        let everything = [1_u8; 512];
        let open = context(
            &c,
            &everything,
            n,
            TrackingAvailability::Available,
            privacy.mask(),
        )?;
        let step = analyze(
            &mut c,
            open,
            &a,
            &mut DecodeBudget::new(WORK),
            &mut post(),
            &mut WorkBudget::new(WORK),
            &mut WorkBudget::new(WORK),
        )?;
        assert_eq!(step, HttpRgbStep::AnalysisRefused(RgbZonePhase::Ready));
        assert_eq!(
            privacy_refusal(&c),
            Some("ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001")
        );
        let ctx = context(
            &c,
            &grid,
            n,
            TrackingAvailability::Available,
            privacy.mask(),
        )?;
        let r = ready(analyze(
            &mut c,
            ctx,
            &a,
            &mut DecodeBudget::new(WORK),
            &mut post(),
            &mut WorkBudget::new(WORK),
            &mut WorkBudget::new(WORK),
        )?)?;
        assert_eq!(r.mask_policy(), Some(policy));
        assert_eq!(r.mask_generation(), Some(1));
        let output = c.take_result(r, NOW, &a)?;
        let run = output.analysis().detection_run();
        // The model saw the retained-decode masked RGB of this frame, and nothing else.
        assert_eq!(
            run.inference().decode_receipt().rgb_sha256,
            masked_rgb_digest(&images[usize::from(n - 1)])?
        );
        assert_eq!(run.mask_policy(), Some(policy));
        outputs.push(output);
    }
    // Frames whose box lies in the masked zone produce no detection at all.
    for bright in [1, 2] {
        assert!(
            outputs[bright]
                .analysis()
                .detection_run()
                .report()
                .detections()
                .is_empty()
        );
    }
    assert!(
        !outputs[0]
            .analysis()
            .detection_run()
            .report()
            .detections()
            .is_empty()
    );
    // No entry, dwell or exit is derived from motion inside the mask.
    for output in &outputs {
        assert!(
            output
                .analysis()
                .temporal()
                .events()
                .iter()
                .all(|e| !matches!(
                    e.kind,
                    ImageZoneEventKind::EnteredBetweenObservations
                        | ImageZoneEventKind::SampledDwell
                        | ImageZoneEventKind::LeftBetweenObservations
                ))
        );
    }
    Ok(())
}
#[test]
fn a_policy_retained_mid_capture_applies_from_the_next_frame_only() -> Test {
    let mut privacy = PrivacyDeployment::new("http-rgb-midcapture")?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let images: Vec<_> = [16, 240].into_iter().map(jpeg).collect();
    let (mut c, a, mut server) = session(&model, &head, &mut owner, response(&images, false), 79)?;
    let mut saved = Vec::new();
    next_frame(&mut c, &a, &mut server, &mut saved)?;
    let first = complete(&mut c, &a, 1, privacy.mask())?;
    assert_eq!(first.mask_policy(), None);
    c.take_result(first, NOW, &a)?;
    let policy = declare(&mut privacy, &[ZONE_MASK])?;
    next_frame(&mut c, &a, &mut server, &mut saved)?;
    let everything = [1_u8; 512];
    let open = context(
        &c,
        &everything,
        2,
        TrackingAvailability::Available,
        privacy.mask(),
    )?;
    assert_eq!(
        analyze(
            &mut c,
            open,
            &a,
            &mut DecodeBudget::new(WORK),
            &mut post(),
            &mut WorkBudget::new(WORK),
            &mut WorkBudget::new(WORK),
        )?,
        HttpRgbStep::AnalysisRefused(RgbZonePhase::Ready)
    );
    let grid = privacy.mask().resolve()?.allowed([32, 16])?;
    let ctx = context(
        &c,
        &grid,
        2,
        TrackingAvailability::Available,
        privacy.mask(),
    )?;
    // The frame is decoded and inferred under the new generation. The running trajectory
    // episode is bound to the old permission grid, so it refuses the frame (typed, retained)
    // instead of mixing grids; the owner starts a new episode for masked tracking.
    let step = analyze(
        &mut c,
        ctx,
        &a,
        &mut DecodeBudget::new(WORK),
        &mut post(),
        &mut WorkBudget::new(WORK),
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(step, HttpRgbStep::AnalysisPending(RgbZonePhase::Tracking));
    assert_eq!(c.privacy_mask().policy_digest(), Some(policy));
    let run = c
        .analysis()
        .ok_or("accepted analysis lost")?
        .detection_run()
        .ok_or("detection run missing")?;
    assert_eq!(run.mask_policy(), Some(policy));
    assert_eq!(
        run.inference().decode_receipt().rgb_sha256,
        masked_rgb_digest(&images[1])?
    );
    assert!(
        run.report().detections().is_empty(),
        "the box lies in the mask"
    );
    // The earlier record keeps the binding it was produced under.
    assert_eq!(c.last_taken(), Some(first));
    assert_eq!(c.last_taken().ok_or("history lost")?.mask_policy(), None);
    Ok(())
}

/// No-policy receipts keep the bytes they had before live masking existed.
#[test]
fn no_policy_receipt_digests_are_unchanged() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb-golden")?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let images: Vec<_> = [16, 240, 240, 16].into_iter().map(jpeg).collect();
    let (mut c, a, mut server) = session(&model, &head, &mut owner, response(&images, false), 79)?;
    let mut saved = Vec::new();
    for (n, (digest, inference)) in (1..=4_u8).zip(GOLDEN_RGB_RECEIPTS) {
        next_frame(&mut c, &a, &mut server, &mut saved)?;
        let r = complete(&mut c, &a, n, privacy.mask())?;
        assert_eq!(r.mask_policy(), None);
        assert_eq!(r.digest(), digest, "frame {n}");
        assert_eq!(r.inference(), inference, "frame {n}");
        c.take_result(r, NOW, &a)?;
    }
    Ok(())
}
// Captured from the pre-masking composition at 40bf5a6: (receipt digest, inference identity).
const GOLDEN_RGB_RECEIPTS: [([u8; 32], [u8; 32]); 4] = [
    (
        [
            168, 37, 191, 161, 136, 13, 174, 207, 238, 183, 124, 186, 93, 127, 25, 156, 108, 122,
            250, 39, 123, 57, 74, 126, 165, 210, 124, 35, 97, 18, 158, 249,
        ],
        [
            74, 143, 123, 224, 40, 222, 117, 42, 129, 18, 111, 8, 74, 120, 213, 227, 55, 241, 101,
            52, 212, 131, 153, 30, 132, 58, 181, 162, 48, 9, 165, 213,
        ],
    ),
    (
        [
            168, 1, 15, 152, 63, 146, 213, 231, 196, 97, 200, 51, 161, 67, 46, 118, 106, 180, 166,
            70, 61, 247, 135, 217, 201, 17, 7, 77, 27, 66, 109, 190,
        ],
        [
            239, 108, 159, 32, 100, 156, 120, 245, 163, 148, 242, 252, 57, 1, 104, 17, 178, 9, 241,
            47, 7, 35, 4, 107, 240, 130, 142, 172, 44, 18, 120, 87,
        ],
    ),
    (
        [
            37, 144, 46, 214, 69, 88, 251, 215, 201, 85, 101, 48, 148, 69, 113, 100, 7, 56, 207,
            66, 227, 201, 136, 83, 34, 237, 106, 103, 238, 231, 179, 131,
        ],
        [
            66, 148, 254, 177, 146, 231, 159, 229, 44, 64, 75, 196, 235, 68, 90, 242, 69, 254, 13,
            3, 184, 170, 178, 80, 156, 232, 17, 180, 232, 90, 60, 130,
        ],
    ),
    (
        [
            63, 216, 142, 100, 125, 6, 56, 183, 155, 194, 131, 91, 159, 152, 65, 233, 43, 197, 222,
            152, 72, 146, 247, 126, 209, 234, 93, 214, 5, 110, 214, 32,
        ],
        [
            25, 33, 31, 141, 2, 226, 119, 193, 12, 148, 168, 142, 113, 7, 48, 90, 68, 13, 89, 182,
            252, 250, 129, 90, 177, 196, 145, 30, 236, 12, 97, 95,
        ],
    ),
];
