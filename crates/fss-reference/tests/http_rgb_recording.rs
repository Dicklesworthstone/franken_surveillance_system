#![forbid(unsafe_code)]
//! Real native neural processing plus mandatory root-last original custody.
mod http_rgb_recording_support;
#[allow(dead_code)]
mod http_rgb_support;
mod privacy_live_support;
mod rgb_zone_support;
use fss_codec_mjpeg::DecodeBudget;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_publication::{
    LocalPublicationState, NeverCancel, PublishCancellation, PublishCutPoint, PublishOutcome,
};
use fss_reference::ScalarExecCx;
use fss_reference::ingest::http_archive::HttpWireArchive;
use fss_reference::ingest::http_camera::rgb::{HttpRgbBudgets, HttpRgbReceipt, HttpRgbStep};
use fss_reference::ingest::http_camera::{HttpCameraDenial, HttpCameraError, HttpCameraOperation};
use fss_reference::ingest::http_replay::completion::VerifiedHttpCompletion;
use fss_reference::ingest::http_rgb_recording::*;
use fss_reference::ingest::privacy_mask::live::SensorMask;
use fss_reference::ingest::rgb_tracking::pipeline::RgbZonePhase;
use fss_twin::image_tracking::TrackingAvailability;
use fss_twin::image_zones::ImageZoneEventKind;
use http_rgb_recording_support::*;
use http_rgb_support::{context, response};
use privacy_live_support::PrivacyDeployment;
use rgb_zone_support::{Test, WORK, head, jpeg, model, tracker, tracking_policy};

struct Stop;
impl PublishCancellation for Stop {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}
fn analyze(
    recording: &mut HttpRgbRecording<'_, '_>,
    publisher: &fss_publication::LocalRootPublisher,
    auth: &Authority,
    n: u8,
    privacy: SensorMask<'_>,
) -> Test<HttpRgbReceipt> {
    let context = context(
        recording.capture(),
        &[1; 512],
        n,
        TrackingAvailability::Available,
        privacy,
    )?;
    let result = recording.analyze(
        context,
        rgb_zone_support::limits(),
        publisher,
        auth.access(&NeverCancel),
        HttpRgbBudgets {
            decoder: &mut DecodeBudget::new(WORK),
            projection: &mut rgb_zone_support::post(),
            temporal: &mut WorkBudget::new(WORK),
            linking: &mut WorkBudget::new(WORK),
        },
        &ScalarExecCx::new(),
    )?;
    match result {
        HttpRgbStep::ResultReady(receipt) => Ok(receipt),
        _ => Err("native analysis incomplete".into()),
    }
}

#[test]
fn native_rgb_recording_enforces_every_barrier_and_cold_source_completion() -> Test {
    for chunked in [false, true] {
        let privacy = PrivacyDeployment::new("durable-rgb")?;
        let directory = Directory::new("complete")?;
        let mut publisher = directory.open()?;
        let model = model(1)?;
        let head = head(&model)?;
        let mut owner = tracker(&head, tracking_policy())?;
        let wire = response(&[jpeg(16), jpeg(240)], chunked);
        let (capture, auth, mut server) = session(&model, &head, &mut owner, wire.clone(), 257)?;
        let mut recording = attach(capture, &publisher, &auth, limits())?;
        let scope = recording.scope();
        let mut outputs = Vec::new();
        let completion = loop {
            match next_barrier(&mut recording, &mut publisher, &auth, &mut server, false)? {
                HttpRgbRecordingStep::WirePrepared(plan) => {
                    let counts = recording.capture().camera().totals();
                    let before = recording.pin();
                    for _ in 0..3 {
                        assert_eq!(
                            recording.poll(auth.access(&NeverCancel))?,
                            HttpRgbRecordingStep::WirePrepared(plan)
                        );
                        assert_eq!(recording.pin(), before);
                        assert_eq!(recording.capture().camera().totals(), counts);
                    }
                    let commit =
                        recording.commit_wire(plan, &mut publisher, auth.access(&NeverCancel))?;
                    assert_eq!(commit.publication().pin, plan.expected_pin());
                    assert_eq!(
                        commit.publication().local.claims.local,
                        LocalPublicationState::Durable
                    );
                    assert_eq!(commit.acknowledgement(), Ok(()));
                    assert!(matches!(
                        recording.commit_wire(plan, &mut publisher, auth.access(&NeverCancel)),
                        Err(HttpRgbRecordingError::PlanMismatch)
                    ));
                }
                HttpRgbRecordingStep::Analysis(HttpRgbStep::AwaitingContext) => {
                    let receipt = analyze(
                        &mut recording,
                        &publisher,
                        &auth,
                        outputs.len() as u8 + 1,
                        privacy.mask(),
                    )?;
                    let counts = recording.capture().camera().totals();
                    assert_eq!(
                        recording.poll(auth.access(&NeverCancel))?,
                        HttpRgbRecordingStep::Analysis(HttpRgbStep::ResultReady(receipt))
                    );
                    assert_eq!(recording.capture().camera().totals(), counts);
                    assert_eq!(recording.capture().phase(), RgbZonePhase::Complete);
                    outputs.push(recording.take_result(
                        receipt,
                        &publisher,
                        auth.access(&NeverCancel),
                    )?);
                }
                HttpRgbRecordingStep::CompletionPrepared(pin) => break pin,
                _ => return Err("unexpected durable recording state".into()),
            }
        };
        assert_eq!(outputs.len(), 2);
        assert_eq!(recording.work().transferred, 2);
        assert_eq!(recording.pin().bytes as usize, wire.len());
        assert!(
            outputs[1]
                .analysis()
                .temporal()
                .events()
                .iter()
                .any(|event| event.kind == ImageZoneEventKind::EnteredBetweenObservations)
        );
        assert!(recording.completion().is_none());
        let mut wrong = completion;
        wrong.root = ContentDigest::sha256(b"not this ending");
        assert!(matches!(
            recording.commit_completion(wrong, &mut publisher, auth.access(&NeverCancel)),
            Err(HttpRgbRecordingError::PlanMismatch)
        ));
        let receipt =
            recording.commit_completion(completion, &mut publisher, auth.access(&NeverCancel))?;
        assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
        assert_eq!(
            recording
                .commit_completion(completion, &mut publisher, auth.access(&NeverCancel))?
                .outcome,
            PublishOutcome::AlreadyPublished
        );
        let retired = recording.retire();
        assert_eq!(retired.completion, Some(completion));
        let archive_limits = retired.archive.limits();
        drop(retired);
        drop(publisher);
        drop(server);
        let publisher = directory.open()?;
        let restored = HttpWireArchive::load(
            &publisher,
            scope,
            completion.wire,
            archive_limits,
            &NeverCancel,
            &mut WorkBudget::new(100_000_000_000),
        )?;
        VerifiedHttpCompletion::load(
            &publisher,
            &restored,
            completion,
            &NeverCancel,
            &mut WorkBudget::new(100_000_000_000),
        )?;
        assert_eq!(
            restored.read_range(
                &publisher,
                [0, completion.wire.bytes],
                &NeverCancel,
                &mut WorkBudget::new(100_000_000_000)
            )?,
            wire
        );
        for output in outputs {
            restored.verify_frame(
                &publisher,
                output.frame(),
                &NeverCancel,
                &mut WorkBudget::new(WORK),
            )?;
        }
        assert_eq!(owner.tracker().exposure_count(), 2);
    }
    Ok(())
}

#[test]
fn cancellation_and_each_storage_cut_leave_the_native_parse_barrier_closed() -> Test {
    for cut in [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
        PublishCutPoint::AfterRootRename,
    ] {
        let directory = Directory::new("cuts")?;
        let mut publisher = directory.open()?;
        let model = model(1)?;
        let head = head(&model)?;
        let mut owner = tracker(&head, tracking_policy())?;
        let (capture, auth, mut server) = session(
            &model,
            &head,
            &mut owner,
            response(&[jpeg(240)], false),
            4096,
        )?;
        let mut recording = attach(capture, &publisher, &auth, limits())?;
        let before = recording.pin();
        assert!(matches!(
            recording.poll(auth.access(&Stop)),
            Err(HttpRgbRecordingError::Cancelled)
        ));
        assert_eq!(recording.work().polls, 0);
        let HttpRgbRecordingStep::WirePrepared(plan) =
            next_barrier(&mut recording, &mut publisher, &auth, &mut server, false)?
        else {
            return Err("wire barrier missing".into());
        };
        assert!(matches!(
            recording.commit_wire(plan, &mut publisher, auth.access(&Stop)),
            Err(HttpRgbRecordingError::Cancelled)
        ));
        assert_eq!(publisher.visible_roots().count(), 0);
        let counts = recording.capture().camera().totals();
        publisher.inject_crash_at(cut);
        assert!(
            recording
                .commit_wire(plan, &mut publisher, auth.access(&NeverCancel))
                .is_err()
        );
        assert_eq!(recording.pin(), before);
        assert_eq!(recording.pending_wire_plan(), Some(plan));
        assert!(
            !recording
                .capture()
                .pending_wire()
                .ok_or("raw")?
                .acknowledged()
        );
        assert_eq!(
            recording.poll(auth.access(&NeverCancel))?,
            HttpRgbRecordingStep::WirePrepared(plan)
        );
        assert_eq!(recording.capture().camera().totals(), counts);
        assert!(recording.capture().analysis().is_none());
        // Reopen storage without replacing/reconnecting the native source or granting a
        // mutable archive escape. The existing owner must reconcile this exact plan itself.
        drop(publisher);
        let mut publisher = directory.open()?;
        let result = recording.commit_wire(plan, &mut publisher, auth.access(&NeverCancel))?;
        assert_eq!(result.publication().pin, plan.expected_pin());
        assert_eq!(result.acknowledgement(), Ok(()));
        assert_eq!(publisher.visible_roots().count(), 1);
        assert_eq!(recording.capture().camera().totals(), counts);
        assert!(recording.completion().is_none());
        drop(recording.retire());
        assert_eq!(owner.tracker().exposure_count(), 0);
    }
    Ok(())
}

#[test]
fn late_ack_revocation_returns_successful_storage_and_all_retirement_ownership() -> Test {
    let directory = Directory::new("revoked")?;
    let mut publisher = directory.open()?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let (capture, auth, mut server) = session(
        &model,
        &head,
        &mut owner,
        response(&[jpeg(240)], false),
        4096,
    )?;
    let mut recording = attach(capture, &publisher, &auth, limits())?;
    let HttpRgbRecordingStep::WirePrepared(plan) =
        next_barrier(&mut recording, &mut publisher, &auth, &mut server, false)?
    else {
        return Err("wire barrier missing".into());
    };
    auth.deny(HttpCameraOperation::AcknowledgeWire);
    let result = recording.commit_wire(plan, &mut publisher, auth.access(&NeverCancel))?;
    assert_eq!(
        result.publication().local.claims.local,
        LocalPublicationState::Durable
    );
    assert_eq!(
        result.acknowledgement(),
        Err(HttpCameraError::Denied(HttpCameraDenial::Revoked))
    );
    assert_eq!(recording.pin(), plan.expected_pin());
    assert_eq!(recording.pending_wire_plan(), Some(plan));
    let retired = recording.retire();
    assert_eq!(
        retired
            .capture
            .source
            .wire
            .as_ref()
            .ok_or("wire lost")?
            .receipt(),
        plan.wire()
    );
    assert_eq!(retired.archive.pin(), plan.expected_pin());
    assert_eq!(retired.work.transferred, 0);
    assert!(retired.completion.is_none());
    Ok(())
}

#[test]
fn complete_result_is_not_discarded_when_delivery_authority_is_revoked() -> Test {
    let privacy = PrivacyDeployment::new("recording-release")?;
    let directory = Directory::new("release")?;
    let mut publisher = directory.open()?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let (capture, auth, mut server) = session(
        &model,
        &head,
        &mut owner,
        response(&[jpeg(240)], false),
        4096,
    )?;
    let mut recording = attach(capture, &publisher, &auth, limits())?;
    assert_eq!(
        next_barrier(&mut recording, &mut publisher, &auth, &mut server, true)?,
        HttpRgbRecordingStep::Analysis(HttpRgbStep::AwaitingContext)
    );
    let receipt = analyze(&mut recording, &publisher, &auth, 1, privacy.mask())?;
    auth.deny(HttpCameraOperation::ReleaseResult);
    assert!(
        recording
            .take_result(receipt, &publisher, auth.access(&NeverCancel))
            .is_err()
    );
    assert_eq!(recording.capture().completion(), Some(receipt));
    assert!(recording.capture().completed().is_some());
    assert!(recording.capture().frame().is_some());
    assert_eq!(recording.work().transferred, 0);
    let retired = recording.retire();
    assert_eq!(retired.capture.complete, Some(receipt));
    assert!(retired.completion.is_none());
    Ok(())
}
