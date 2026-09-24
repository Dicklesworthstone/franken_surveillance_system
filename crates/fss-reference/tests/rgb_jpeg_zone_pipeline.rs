#![forbid(unsafe_code)]
//! Actual JPEG/neural execution across every retained temporal stage boundary.
mod rgb_zone_support;
use fss_codec_mjpeg::DecodeBudget;
use fss_geometry::{GeometryError, WorkBudget};
use fss_reference::ScalarExecCx;
use fss_reference::ingest::rgb_detections::RgbDetectionContract;
use fss_reference::ingest::rgb_detections::{RgbDetectionBudget, RgbDetectionError};
use fss_reference::ingest::rgb_inference::RgbInferenceModel;
use fss_reference::ingest::rgb_tracking::pipeline::*;
use fss_reference::ingest::rgb_tracking::{RgbTrackingError, RgbZoneProgress};
use fss_twin::image_tracking::{ImageTrackingError, TrackingAvailability};
use fss_twin::image_zones::{ImageZoneError, ImageZoneEventKind, ImageZoneRelation};
use rgb_zone_support::*;

fn zero_post() -> RgbDetectionBudget {
    RgbDetectionBudget::new(0, 32 * 1024 * 1024)
}
fn completed(p: &mut RgbJpegZonePipeline<'_, '_>, value: u8, n: u8) -> Test<RgbZoneCompletion> {
    let bytes = jpeg(value);
    let mask = [1; 512];
    let input = input(&bytes, &mask, n);
    let step = p.run_jpeg(
        input,
        admission(input.source, TrackingAvailability::Available)?,
        limits(),
        &mut DecodeBudget::new(WORK),
        &mut post(),
        &mut WorkBudget::new(WORK),
        &ScalarExecCx::new(),
    )?;
    assert!(matches!(step, RgbJpegZoneProgress::Complete { .. }));
    Ok(p.take_complete().ok_or("missing complete owned output")?)
}
fn temporal_work(model: &RgbInferenceModel, head: &RgbDetectionContract) -> Test<u64> {
    let run = detection(model, head, 240, 1)?;
    let mut temporal = tracker(head, tracking_policy())?;
    let mut work = WorkBudget::new(WORK);
    assert!(matches!(
        temporal.observe(
            run.inference(),
            run.report(),
            admission(run.report().source(), TrackingAvailability::Available)?,
            &mut work
        )?,
        RgbZoneProgress::Complete { .. }
    ));
    Ok(work.used())
}
#[test]
fn actual_jpeg_sequence_produces_owned_entry_dwell_exit_and_history() -> Test {
    let model = model(1)?;
    let head = head(&model)?;
    let mut temporal = tracker(&head, tracking_policy())?;
    let mut pipeline = RgbJpegZonePipeline::new(&model, &head, &mut temporal)?;
    let a = completed(&mut pipeline, 16, 1)?;
    let b = completed(&mut pipeline, 240, 2)?;
    let c = completed(&mut pipeline, 240, 3)?;
    let d = completed(&mut pipeline, 16, 4)?;
    assert_eq!(a.temporal().cells()[0].relation, ImageZoneRelation::Outside);
    assert!(
        b.temporal()
            .events()
            .iter()
            .any(|e| e.kind == ImageZoneEventKind::EnteredBetweenObservations)
    );
    assert!(
        c.temporal()
            .events()
            .iter()
            .any(|e| e.kind == ImageZoneEventKind::SampledDwell)
    );
    assert!(
        d.temporal()
            .events()
            .iter()
            .any(|e| e.kind == ImageZoneEventKind::LeftBetweenObservations)
    );
    assert_eq!(
        b.temporal().tracking_prior(),
        a.temporal().tracking_digest()
    );
    assert_eq!(b.temporal().zone_prior(), a.temporal().zone_digest());
    assert_eq!(a.temporal().tracks()[0].id(), d.temporal().tracks()[0].id());
    assert_eq!(b.temporal().rgb_decisions().len(), 2);
    assert_eq!(b.temporal().decisions().len(), 1);
    assert_eq!(b.temporal().candidates().len(), 1);
    assert!(b.temporal().expired().is_empty());
    assert_eq!(b.detection_run().allowed(), &[1; 512]);
    assert!(b.detection_run().inference().executed_macs() > 0);
    assert_eq!(b.admission().source(), b.detection_run().report().source());
    assert_eq!(b.temporal().frame().source.image.exposure, [2; 32]);
    assert!(pipeline.completed().is_none());
    assert!(pipeline.tracking_report().is_none());
    drop(pipeline);
    assert_eq!(temporal.tracker().exposure_count(), 4);
    // Old records stay independently owned after the processor/temporal owner end.
    drop(temporal);
    assert_eq!(a.temporal().tracks()[0].observations(), 1);
    assert_eq!(d.temporal().tracks()[0].observations(), 4);
    assert_eq!(
        b.temporal().events()[0].to.frame.source.image.exposure,
        [2; 32]
    );
    Ok(())
}
#[test]
fn pending_head_preserves_mask_and_tensors_and_does_not_admit_next_frame() -> Test {
    let model = model(1)?;
    let head = head(&model)?;
    let mut temporal = tracker(&head, tracking_policy())?;
    let mut pipeline = RgbJpegZonePipeline::new(&model, &head, &mut temporal)?;
    let bytes = jpeg(240);
    let mut mask = [1; 512];
    let mut decoder = DecodeBudget::new(WORK);
    let frame = input(&bytes, &mask, 1);
    let admit = admission(frame.source, TrackingAvailability::Available)?;
    assert!(matches!(
        pipeline.run_jpeg(
            frame,
            admit,
            limits(),
            &mut decoder,
            &mut zero_post(),
            &mut WorkBudget::new(WORK),
            &ScalarExecCx::new()
        )?,
        RgbJpegZoneProgress::ProjectionPending(RgbDetectionError::BudgetExceeded)
    ));
    let identity = pipeline
        .pending_inference()
        .ok_or("lost inference")?
        .inference()
        .identity();
    let used = decoder.used();
    mask.fill(0);
    let next = input(&bytes, &mask, 2);
    assert!(matches!(
        pipeline.run_jpeg(
            next,
            admission(next.source, TrackingAvailability::Available)?,
            limits(),
            &mut decoder,
            &mut post(),
            &mut WorkBudget::new(WORK),
            &ScalarExecCx::new()
        ),
        Err(RgbJpegZoneError::PendingFrame)
    ));
    assert_eq!(decoder.used(), used);
    assert!(pipeline.zone_report().is_none());
    assert!(pipeline.tracking_report().is_none());
    assert!(pipeline.take_complete().is_none());
    assert!(matches!(
        pipeline.resume(
            &mut post(),
            &mut WorkBudget::new(WORK),
            &ScalarExecCx::new()
        )?,
        RgbJpegZoneProgress::Complete { .. }
    ));
    let result = pipeline.take_complete().ok_or("lost complete")?;
    assert_eq!(result.detection_run().inference().identity(), identity);
    assert_eq!(result.detection_run().allowed(), &[1; 512]);
    assert_eq!(decoder.used(), used);
    assert_eq!(result.temporal().tracks()[0].observations(), 1);
    Ok(())
}
#[test]
fn tracking_pressure_retains_full_detector_output_and_resume_spends_no_head_work() -> Test {
    let model = model(1)?;
    let head = head(&model)?;
    let mut temporal = tracker(&head, tracking_policy())?;
    let before = temporal.tracker().digest();
    let mut pipeline = RgbJpegZonePipeline::new(&model, &head, &mut temporal)?;
    let bytes = jpeg(240);
    let frame = input(&bytes, &[1; 512], 1);
    let mut decoder = DecodeBudget::new(WORK);
    assert!(matches!(
        pipeline.run_jpeg(
            frame,
            admission(frame.source, TrackingAvailability::Available)?,
            limits(),
            &mut decoder,
            &mut post(),
            &mut WorkBudget::new(0),
            &ScalarExecCx::new()
        )?,
        RgbJpegZoneProgress::TrackingPending(RgbTrackingError::Work(
            GeometryError::BudgetExhausted
        ))
    ));
    assert_eq!(pipeline.phase(), RgbZonePhase::Tracking);
    let d = pipeline
        .detection_run()
        .ok_or("lost detector output")?
        .report()
        .digest();
    let used = decoder.used();
    assert!(pipeline.pending_inference().is_none());
    assert!(pipeline.tracking_report().is_none());
    let mut no_head = zero_post();
    assert!(matches!(
        pipeline.resume(
            &mut no_head,
            &mut WorkBudget::new(WORK),
            &ScalarExecCx::new()
        )?,
        RgbJpegZoneProgress::Complete { .. }
    ));
    let result = pipeline.take_complete().ok_or("completion")?;
    assert_eq!(result.detection_run().report().digest(), d);
    assert_eq!(no_head.used(), 0);
    assert_eq!(decoder.used(), used);
    assert_eq!(result.temporal().tracking_prior(), before);
    drop(pipeline);
    assert_eq!(temporal.tracker().exposure_count(), 1);
    Ok(())
}
#[test]
fn pending_zones_resume_only_the_consumed_tracking_receipt() -> Test {
    let model = model(1)?;
    let head = head(&model)?;
    let units = temporal_work(&model, &head)?;
    let mut temporal = tracker(&head, tracking_policy())?;
    let mut pipeline = RgbJpegZonePipeline::new(&model, &head, &mut temporal)?;
    let bytes = jpeg(240);
    let frame = input(&bytes, &[1; 512], 1);
    assert!(matches!(
        pipeline.run_jpeg(
            frame,
            admission(frame.source, TrackingAvailability::Available)?,
            limits(),
            &mut DecodeBudget::new(WORK),
            &mut post(),
            &mut WorkBudget::new(units - 1),
            &ScalarExecCx::new()
        )?,
        RgbJpegZoneProgress::ZonesPending(ImageZoneError::Geometry(GeometryError::BudgetExhausted))
    ));
    assert_eq!(pipeline.phase(), RgbZonePhase::Zones);
    assert!(pipeline.zone_report().is_none());
    let tracking = pipeline
        .tracking_report()
        .ok_or("lost consumed receipt")?
        .digest();
    assert!(matches!(
        pipeline.resume(
            &mut zero_post(),
            &mut WorkBudget::new(0),
            &ScalarExecCx::new()
        )?,
        RgbJpegZoneProgress::ZonesPending(_)
    ));
    assert_eq!(
        pipeline
            .tracking_report()
            .ok_or("lost consumed receipt")?
            .digest(),
        tracking
    );
    assert!(matches!(
        pipeline.resume(
            &mut zero_post(),
            &mut WorkBudget::new(WORK),
            &ScalarExecCx::new()
        )?,
        RgbJpegZoneProgress::Complete { .. }
    ));
    let result = pipeline.take_complete().ok_or("completion")?;
    assert_eq!(result.temporal().tracking_digest(), tracking);
    assert_eq!(result.temporal().events().len(), 1);
    drop(pipeline);
    assert_eq!(temporal.tracker().exposure_count(), 1);
    Ok(())
}
#[test]
fn output_copy_pressure_retains_committed_zones_without_duplicate_events() -> Test {
    let model = model(1)?;
    let head = head(&model)?;
    let units = temporal_work(&model, &head)?;
    let mut temporal = tracker(&head, tracking_policy())?;
    let mut pipeline = RgbJpegZonePipeline::new(&model, &head, &mut temporal)?;
    let bytes = jpeg(240);
    let frame = input(&bytes, &[1; 512], 1);
    assert!(matches!(
        pipeline.run_jpeg(
            frame,
            admission(frame.source, TrackingAvailability::Available)?,
            limits(),
            &mut DecodeBudget::new(WORK),
            &mut post(),
            &mut WorkBudget::new(units),
            &ScalarExecCx::new()
        )?,
        RgbJpegZoneProgress::SnapshotPending(RgbTrackingError::Work(
            GeometryError::BudgetExhausted
        ))
    ));
    assert_eq!(pipeline.phase(), RgbZonePhase::Snapshot);
    let zones = pipeline
        .zone_report()
        .ok_or("lost committed zones")?
        .digest();
    let events = pipeline
        .zone_report()
        .ok_or("lost events")?
        .events()
        .to_vec();
    let tracking = pipeline.tracking_report().ok_or("lost tracks")?.digest();
    for _ in 0..3 {
        assert!(matches!(
            pipeline.resume(
                &mut zero_post(),
                &mut WorkBudget::new(0),
                &ScalarExecCx::new()
            )?,
            RgbJpegZoneProgress::SnapshotPending(_)
        ));
        assert_eq!(pipeline.zone_report().ok_or("lost zones")?.events(), events);
    }
    assert!(matches!(
        pipeline.resume(
            &mut zero_post(),
            &mut WorkBudget::new(WORK),
            &ScalarExecCx::new()
        )?,
        RgbJpegZoneProgress::Complete { .. }
    ));
    let result = pipeline.take_complete().ok_or("completion")?;
    assert_eq!(result.temporal().zone_digest(), zones);
    assert_eq!(result.temporal().tracking_digest(), tracking);
    assert_eq!(result.temporal().events(), events);
    drop(pipeline);
    assert_eq!(temporal.tracker().exposure_count(), 1);
    Ok(())
}
#[test]
fn untaken_completed_result_blocks_input_but_resume_is_idempotent() -> Test {
    let model = model(1)?;
    let head = head(&model)?;
    let mut temporal = tracker(&head, tracking_policy())?;
    let mut pipeline = RgbJpegZonePipeline::new(&model, &head, &mut temporal)?;
    let bytes = jpeg(240);
    let frame = input(&bytes, &[1; 512], 1);
    assert!(matches!(
        pipeline.run_jpeg(
            frame,
            admission(frame.source, TrackingAvailability::Available)?,
            limits(),
            &mut DecodeBudget::new(WORK),
            &mut post(),
            &mut WorkBudget::new(WORK),
            &ScalarExecCx::new()
        )?,
        RgbJpegZoneProgress::Complete { .. }
    ));
    let result = pipeline.completed().ok_or("lost result")?;
    let identity = result.detection_run().inference().identity();
    let next = input(&bytes, &[1; 512], 2);
    let mut decoder = DecodeBudget::new(0);
    assert!(matches!(
        pipeline.run_jpeg(
            next,
            admission(next.source, TrackingAvailability::Available)?,
            limits(),
            &mut decoder,
            &mut zero_post(),
            &mut WorkBudget::new(0),
            &ScalarExecCx::new()
        ),
        Err(RgbJpegZoneError::ResultNotTaken)
    ));
    let mut work = WorkBudget::new(0);
    let mut no_head = zero_post();
    match pipeline.resume(&mut no_head, &mut work, &ScalarExecCx::new())? {
        RgbJpegZoneProgress::Complete { inference, .. } => assert_eq!(inference, identity),
        _ => return Err("repeat not complete".into()),
    }
    assert_eq!(work.used(), 0);
    assert_eq!(no_head.used(), 0);
    assert_eq!(decoder.used(), 0);
    let held = pipeline.take_complete().ok_or("missing transfer")?;
    assert!(pipeline.take_complete().is_none());
    let second = completed(&mut pipeline, 240, 2)?;
    assert_eq!(
        second.temporal().tracking_prior(),
        held.temporal().tracking_digest()
    );
    Ok(())
}
#[test]
fn bad_admission_and_bad_jpeg_leave_ready_state_and_previous_history_intact() -> Test {
    let model = model(1)?;
    let head = head(&model)?;
    let mut temporal = tracker(&head, tracking_policy())?;
    let mut pipeline = RgbJpegZonePipeline::new(&model, &head, &mut temporal)?;
    let previous = completed(&mut pipeline, 240, 1)?;
    let bytes = jpeg(240);
    let frame = input(&bytes, &[1; 512], 2);
    let mut wrong = frame.source;
    wrong.clock += 1;
    let mut decoder = DecodeBudget::new(0);
    assert!(matches!(
        pipeline.run_jpeg(
            frame,
            admission(wrong, TrackingAvailability::Available)?,
            limits(),
            &mut decoder,
            &mut post(),
            &mut WorkBudget::new(WORK),
            &ScalarExecCx::new()
        ),
        Err(RgbJpegZoneError::AdmissionMismatch)
    ));
    assert_eq!(decoder.used(), 0);
    assert_eq!(pipeline.phase(), RgbZonePhase::Ready);
    let invalid = input(b"not JPEG", &[1; 512], 2);
    assert!(matches!(
        pipeline.run_jpeg(
            invalid,
            admission(invalid.source, TrackingAvailability::Available)?,
            limits(),
            &mut DecodeBudget::new(WORK),
            &mut post(),
            &mut WorkBudget::new(WORK),
            &ScalarExecCx::new()
        ),
        Err(RgbJpegZoneError::Detector(_))
    ));
    assert_eq!(pipeline.phase(), RgbZonePhase::Ready);
    assert!(pipeline.detection_run().is_none());
    assert!(pipeline.tracking_report().is_none());
    assert!(pipeline.zone_report().is_none());
    assert!(matches!(
        pipeline.resume(
            &mut post(),
            &mut WorkBudget::new(WORK),
            &ScalarExecCx::new()
        ),
        Err(RgbJpegZoneError::NoPendingFrame)
    ));
    drop(pipeline);
    assert_eq!(
        temporal.tracker().digest(),
        previous.temporal().tracking_digest()
    );
    Ok(())
}
#[test]
fn explicit_retirement_transfers_accepted_inputs_at_every_unfinished_boundary() -> Test {
    let model = model(1)?;
    let head = head(&model)?;
    let units = temporal_work(&model, &head)?;
    for (phase, work_units, head_units) in [
        (RgbZonePhase::Projection, WORK, 0),
        (RgbZonePhase::Tracking, 0, WORK),
        (RgbZonePhase::Zones, units - 1, WORK),
        (RgbZonePhase::Snapshot, units, WORK),
        (RgbZonePhase::Complete, WORK, WORK),
    ] {
        let mut temporal = tracker(&head, tracking_policy())?;
        let mut pipeline = RgbJpegZonePipeline::new(&model, &head, &mut temporal)?;
        let bytes = jpeg(240);
        let frame = input(&bytes, &[1; 512], 1);
        let _progress = pipeline.run_jpeg(
            frame,
            admission(frame.source, TrackingAvailability::Available)?,
            limits(),
            &mut DecodeBudget::new(WORK),
            &mut RgbDetectionBudget::new(head_units, 32 * 1024 * 1024),
            &mut WorkBudget::new(work_units),
            &ScalarExecCx::new(),
        )?;
        assert_eq!(pipeline.phase(), phase);
        let retired = pipeline.retire();
        assert_eq!(retired.phase, phase);
        assert!(retired.admission.is_some());
        match phase {
            RgbZonePhase::Projection => {
                assert!(retired.inference.is_some());
                assert!(retired.detections.is_none());
                assert_eq!(temporal.tracker().exposure_count(), 0);
            }
            RgbZonePhase::Tracking => {
                assert!(retired.detections.is_some());
                assert_eq!(temporal.tracker().exposure_count(), 0);
            }
            RgbZonePhase::Zones => {
                assert!(retired.detections.is_some());
                assert!(temporal.is_pending());
                assert!(matches!(
                    temporal.resume(&mut WorkBudget::new(WORK))?,
                    RgbZoneProgress::Complete { .. }
                ));
                assert_eq!(temporal.tracker().exposure_count(), 1);
            }
            RgbZonePhase::Snapshot => {
                assert!(retired.detections.is_some());
                assert!(!temporal.is_pending());
                assert!(temporal.zone_report().is_some());
            }
            RgbZonePhase::Complete => {
                assert!(retired.complete.is_some());
                assert!(retired.inference.is_none());
                assert!(retired.detections.is_none());
            }
            RgbZonePhase::Ready => return Err("fixture should own a source".into()),
        }
    }
    Ok(())
}
#[test]
fn cancellation_preserves_pending_outputs_and_accepted_temporal_receipts() -> Test {
    let model = model(1)?;
    let head = head(&model)?;
    let units = temporal_work(&model, &head)?;
    for (phase, allowance) in [
        (RgbZonePhase::Tracking, 0),
        (RgbZonePhase::Zones, units - 1),
        (RgbZonePhase::Snapshot, units),
    ] {
        let mut temporal = tracker(&head, tracking_policy())?;
        let mut pipeline = RgbJpegZonePipeline::new(&model, &head, &mut temporal)?;
        let bytes = jpeg(240);
        let frame = input(&bytes, &[1; 512], 1);
        let _progress = pipeline.run_jpeg(
            frame,
            admission(frame.source, TrackingAvailability::Available)?,
            limits(),
            &mut DecodeBudget::new(WORK),
            &mut post(),
            &mut WorkBudget::new(allowance),
            &ScalarExecCx::new(),
        )?;
        let identity = pipeline
            .detection_run()
            .ok_or("lost detections")?
            .inference()
            .identity();
        let cx = ScalarExecCx::new();
        cx.request_cancellation();
        assert!(matches!(
            pipeline.resume(&mut zero_post(), &mut WorkBudget::new(WORK), &cx),
            Err(RgbJpegZoneError::Cancelled)
        ));
        assert_eq!(pipeline.phase(), phase);
        assert_eq!(
            pipeline
                .detection_run()
                .ok_or("lost accepted source")?
                .inference()
                .identity(),
            identity
        );
        assert!(pipeline.take_complete().is_none());
        let retired = pipeline.retire();
        assert_eq!(
            retired
                .detections
                .ok_or("lost retired source")?
                .inference()
                .identity(),
            identity
        );
        assert_eq!(
            temporal.tracker().exposure_count(),
            if phase == RgbZonePhase::Tracking {
                0
            } else {
                1
            }
        );
    }
    Ok(())
}
#[test]
fn source_replay_and_contract_changes_never_reset_the_existing_tracker() -> Test {
    let model = model(1)?;
    let head = head(&model)?;
    let mut temporal = tracker(&head, tracking_policy())?;
    let mut pipeline = RgbJpegZonePipeline::new(&model, &head, &mut temporal)?;
    let prior = completed(&mut pipeline, 240, 1)?;
    let bytes = jpeg(240);
    let frame = input(&bytes, &[1; 512], 1);
    assert!(matches!(
        pipeline.run_jpeg(
            frame,
            admission(frame.source, TrackingAvailability::Available)?,
            limits(),
            &mut DecodeBudget::new(WORK),
            &mut post(),
            &mut WorkBudget::new(WORK),
            &ScalarExecCx::new()
        )?,
        RgbJpegZoneProgress::TrackingPending(RgbTrackingError::Tracking(
            ImageTrackingError::ReusedExposure
        ))
    ));
    let unfinished = pipeline.retire();
    assert!(unfinished.detections.is_some());
    assert_eq!(
        temporal.tracker().digest(),
        prior.temporal().tracking_digest()
    );
    let mut changed = head.spec().clone();
    changed.minimum_score_ppm += 1;
    let changed = RgbDetectionContract::new(changed)?;
    assert!(matches!(
        RgbJpegZonePipeline::new(&model, &changed, &mut temporal),
        Err(RgbJpegZoneError::ContractMismatch)
    ));
    assert_eq!(temporal.tracker().exposure_count(), 1);
    assert_ne!(changed.digest(), head.digest());
    Ok(())
}
