#![forbid(unsafe_code)]
//! Real loopback input and real root-last storage, not a mock acknowledgement.
mod http_rgb_support;
mod privacy_live_support;
mod rgb_zone_support;
use fss_codec_mjpeg::DecodeBudget;
use fss_geometry::{GeometryError, WorkBudget};
use fss_object::SpoolLimits;
use fss_publication::{
    LocalPublicationLimits, LocalPublicationState, LocalRootPublisher, NeverCancel,
    PublishCancellation, PublishCutPoint, PublishOutcome,
};
use fss_reference::ingest::http_archive::{
    HttpArchiveError, HttpArchiveLimits, HttpWireArchive, HttpWireScope,
};
use fss_reference::ingest::http_camera::rgb::custody::*;
use fss_reference::ingest::http_camera::rgb::*;
use fss_reference::ingest::http_camera::*;
use fss_twin::image_zones::ImageZoneEventKind;
use http_rgb_support::*;
use privacy_live_support::PrivacyDeployment;
use rgb_zone_support::{Test, WORK, head, jpeg, model, tracker, tracking_policy};
use std::path::PathBuf;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        // Fixed attempt bound, no shared process counter and no deletion of a
        // possibly owned directory to make a fixture path available.
        for attempt in 0..16 {
            let path = std::env::temp_dir().join(format!(
                "fss-http-rgb-{label}-{}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture directory attempts exhausted".into())
    }
    fn open(&self) -> Test<LocalRootPublisher> {
        Ok(LocalRootPublisher::open(
            &self.0,
            LocalPublicationLimits::new(
                128,
                16,
                128,
                1024,
                SpoolLimits::new(1024, 16 * 1024 * 1024, 65536, 1024),
            ),
        )?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn limits() -> HttpArchiveLimits {
    HttpArchiveLimits {
        maximum_reads: 128,
        maximum_bytes: 1024 * 1024,
        maximum_scan_roots: 256,
        maximum_spool_object_bytes: 65536,
    }
}
fn scope(camera: &HttpCamera) -> HttpWireScope {
    HttpWireScope {
        stream: camera.route().basis(),
        receive_clock: [21; 32],
        retention_evidence: [22; 32],
    }
}
fn next_wire(
    c: &mut HttpRgbCapture<'_, '_>,
    a: &Authority,
    s: &mut Server,
) -> Test<HttpWireReceipt> {
    let mut framing = DecodeBudget::new(WORK);
    for _ in 0..50000 {
        match pump(c, a, s, &mut framing)? {
            HttpRgbStep::Source(HttpCameraStep::WireReady(r)) => return Ok(r),
            HttpRgbStep::Source(HttpCameraStep::Pending | HttpCameraStep::Advanced) => {
                std::thread::yield_now()
            }
            _ => return Err("unexpected frame before next raw read".into()),
        }
    }
    Err("raw read step bound".into())
}
fn retain(
    c: &mut HttpRgbCapture<'_, '_>,
    a: &Authority,
    expected: HttpRgbWirePlan,
    archive: &mut HttpWireArchive,
    publisher: &mut LocalRootPublisher,
    cancel: &dyn PublishCancellation,
    budget: &mut WorkBudget<'_>,
) -> Result<HttpRgbWireCommit, HttpRgbCustodyError> {
    c.retain_wire(
        expected,
        NOW,
        a,
        HttpRgbCustody {
            archive,
            publisher,
            cancellation: cancel,
            work: budget,
        },
    )
}
struct Stop;
impl PublishCancellation for Stop {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}

#[test]
fn durable_original_reads_feed_neural_events_and_survive_cold_restore() -> Test {
    let privacy = PrivacyDeployment::new("http-rgb-custody")?;
    let d = Directory::new("native-cold")?;
    let mut publisher = d.open()?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let wire = response(&[jpeg(16), jpeg(240)], true);
    let (mut c, a, mut s) = session(&model, &head, &mut owner, wire.clone(), 257)?;
    let scope = scope(c.camera());
    let mut archive = HttpWireArchive::new(scope, limits())?;
    let mut framing = DecodeBudget::new(WORK);
    let mut outputs = Vec::new();
    let mut terminated = false;
    for _ in 0..50000 {
        match pump(&mut c, &a, &mut s, &mut framing)? {
            HttpRgbStep::Source(HttpCameraStep::WireReady(read)) => {
                let plan = c.prepare_wire_custody(&archive, NOW, &a, &mut WorkBudget::new(WORK))?;
                assert_eq!(plan.wire(), read);
                let expected = plan.expected_pin(); // Known BEFORE any storage write.
                let commit = retain(
                    &mut c,
                    &a,
                    plan,
                    &mut archive,
                    &mut publisher,
                    &NeverCancel,
                    &mut WorkBudget::new(WORK),
                )?;
                assert_eq!(commit.publication().pin, expected);
                assert_eq!(commit.publication().wire, read);
                assert_eq!(
                    commit.publication().local.claims.local,
                    LocalPublicationState::Durable
                );
                assert_eq!(commit.acknowledgement(), Ok(()));
                assert!(c.pending_wire().ok_or("raw read")?.acknowledged());
                assert_eq!(
                    archive.read_range(
                        &publisher,
                        read.range,
                        &NeverCancel,
                        &mut WorkBudget::new(WORK)
                    )?,
                    wire[read.range[0] as usize..read.range[1] as usize]
                );
            }
            HttpRgbStep::AwaitingContext => {
                // The existing helper sees the already-held frame: no unretained
                // read may be acknowledged as a side effect of this check.
                let counts = c.camera().totals();
                next_frame(&mut c, &a, &mut s, &mut Vec::new())?;
                assert_eq!(counts, c.camera().totals());
                archive.verify_frame(
                    &publisher,
                    c.frame().ok_or("frame")?,
                    &NeverCancel,
                    &mut WorkBudget::new(WORK),
                )?;
                let receipt = complete(&mut c, &a, (outputs.len() + 1) as u8, privacy.mask())?;
                outputs.push(c.take_result(receipt, NOW, &a)?);
            }
            HttpRgbStep::Source(HttpCameraStep::Complete) => {
                terminated = true;
                break;
            }
            HttpRgbStep::Source(HttpCameraStep::Pending | HttpCameraStep::Advanced) => {
                std::thread::yield_now()
            }
            _ => return Err("unexpected source/result phase".into()),
        }
    }
    assert!(terminated);
    assert_eq!(outputs.len(), 2);
    assert!(
        outputs[1]
            .analysis()
            .temporal()
            .events()
            .iter()
            .any(|e| e.kind == ImageZoneEventKind::EnteredBetweenObservations)
    );
    let counts = c.camera().totals();
    finish(&mut c, &a, &mut s, &mut Vec::new())?;
    assert_eq!(counts, c.camera().totals());
    let pin = archive.pin();
    assert_eq!(pin.bytes as usize, wire.len());
    drop(c);
    drop(archive);
    drop(publisher);
    drop(s);
    let publisher = d.open()?;
    let restored = HttpWireArchive::load(
        &publisher,
        scope,
        pin,
        limits(),
        &NeverCancel,
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(
        restored.read_range(
            &publisher,
            [0, pin.bytes],
            &NeverCancel,
            &mut WorkBudget::new(WORK)
        )?,
        wire
    );
    for output in &outputs {
        restored.verify_frame(
            &publisher,
            output.frame(),
            &NeverCancel,
            &mut WorkBudget::new(WORK),
        )?;
    }
    assert_eq!(owner.tracker().exposure_count(), 2);
    Ok(())
}

#[test]
fn every_publication_crash_cut_keeps_camera_bytes_unacknowledged() -> Test {
    for (index, cut) in [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
        PublishCutPoint::AfterRootRename,
    ]
    .into_iter()
    .enumerate()
    {
        let d = Directory::new(&format!("crash-{index}"))?;
        let mut publisher = d.open()?;
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
        let read = next_wire(&mut c, &a, &mut s)?;
        let mut archive = HttpWireArchive::new(scope(c.camera()), limits())?;
        let before = archive.pin();
        let plan = c.prepare_wire_custody(&archive, NOW, &a, &mut WorkBudget::new(WORK))?;
        let bytes = c.pending_wire().ok_or("wire")?.bytes().to_vec();
        let counts = c.camera().totals();
        publisher.inject_crash_at(cut);
        assert!(matches!(
            retain(
                &mut c,
                &a,
                plan,
                &mut archive,
                &mut publisher,
                &NeverCancel,
                &mut WorkBudget::new(WORK)
            ),
            Err(HttpRgbCustodyError::Archive(_))
        ));
        assert!(publisher.is_poisoned());
        assert_eq!(archive.pin(), before);
        assert!(!c.pending_wire().ok_or("lost raw")?.acknowledged());
        assert_eq!(c.pending_wire().ok_or("lost raw")?.bytes(), bytes);
        assert_eq!(
            c.step(NOW, &a, &mut DecodeBudget::new(0))?,
            HttpRgbStep::Source(HttpCameraStep::WireReady(read))
        );
        assert_eq!(c.camera().totals(), counts);
        assert!(c.frame().is_none());
        let retired = c.retire();
        assert_eq!(retired.source.wire.ok_or("lost retirement")?.bytes(), bytes);
        assert_eq!(owner.tracker().exposure_count(), 0);
    }
    Ok(())
}

#[test]
fn lost_root_rename_acknowledgement_recovers_exact_pin_then_acks_without_duplicate_root() -> Test {
    let d = Directory::new("lost-ack")?;
    let mut publisher = d.open()?;
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
    next_wire(&mut c, &a, &mut s)?;
    let scope = scope(c.camera());
    let mut archive = HttpWireArchive::new(scope, limits())?;
    let plan = c.prepare_wire_custody(&archive, NOW, &a, &mut WorkBudget::new(WORK))?;
    let expected = plan.expected_pin();
    let counts = c.camera().totals();
    publisher.inject_crash_at(PublishCutPoint::AfterRootRename);
    assert!(
        retain(
            &mut c,
            &a,
            plan,
            &mut archive,
            &mut publisher,
            &NeverCancel,
            &mut WorkBudget::new(WORK)
        )
        .is_err()
    );
    assert!(!c.pending_wire().ok_or("raw")?.acknowledged());
    drop(archive);
    drop(publisher);
    let mut publisher = d.open()?;
    let mut archive = HttpWireArchive::load(
        &publisher,
        scope,
        expected,
        limits(),
        &NeverCancel,
        &mut WorkBudget::new(WORK),
    )?;
    let commit = retain(
        &mut c,
        &a,
        plan,
        &mut archive,
        &mut publisher,
        &NeverCancel,
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(commit.publication().pin, expected);
    assert_eq!(
        commit.publication().local.outcome,
        PublishOutcome::AlreadyPublished
    );
    assert_eq!(commit.acknowledgement(), Ok(()));
    assert_eq!(publisher.visible_roots().count(), 1);
    assert_eq!(c.camera().totals(), counts);
    assert_eq!(archive.pin().reads, 1);
    Ok(())
}

#[test]
fn post_storage_camera_revocation_returns_durable_receipt_and_retains_unacked_source() -> Test {
    let d = Directory::new("late-revoke")?;
    let mut publisher = d.open()?;
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
    let read = next_wire(&mut c, &a, &mut s)?;
    let mut archive = HttpWireArchive::new(scope(c.camera()), limits())?;
    let plan = c.prepare_wire_custody(&archive, NOW, &a, &mut WorkBudget::new(WORK))?;
    a.deny_on(HttpCameraOperation::AcknowledgeWire, 1);
    let commit = retain(
        &mut c,
        &a,
        plan,
        &mut archive,
        &mut publisher,
        &NeverCancel,
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(commit.publication().pin, plan.expected_pin());
    assert_eq!(
        commit.publication().local.claims.local,
        LocalPublicationState::Durable
    );
    assert_eq!(
        commit.acknowledgement(),
        Err(HttpCameraError::Denied(HttpCameraDenial::Revoked))
    );
    assert_eq!(archive.pin(), plan.expected_pin());
    assert_eq!(publisher.visible_roots().count(), 1);
    assert!(!c.pending_wire().ok_or("raw")?.acknowledged());
    assert!(c.frame().is_none());
    let retired = c.retire();
    assert_eq!(retired.source.wire.ok_or("raw lost")?.receipt(), read);
    assert_eq!(
        retired.source.reason,
        Some(HttpCameraError::Denied(HttpCameraDenial::Revoked))
    );
    assert_eq!(owner.tracker().exposure_count(), 0);
    Ok(())
}

#[test]
fn storage_cancellation_and_work_refusal_do_not_unlock_parsing() -> Test {
    let d = Directory::new("storage-refusal")?;
    let mut publisher = d.open()?;
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
    next_wire(&mut c, &a, &mut s)?;
    let mut archive = HttpWireArchive::new(scope(c.camera()), limits())?;
    let before = archive.pin();
    let plan = c.prepare_wire_custody(&archive, NOW, &a, &mut WorkBudget::new(WORK))?;
    assert!(matches!(
        retain(
            &mut c,
            &a,
            plan,
            &mut archive,
            &mut publisher,
            &Stop,
            &mut WorkBudget::new(WORK)
        ),
        Err(HttpRgbCustodyError::Archive(HttpArchiveError::Cancelled))
    ));
    for units in [0, 1, 1023] {
        assert!(matches!(
            retain(
                &mut c,
                &a,
                plan,
                &mut archive,
                &mut publisher,
                &NeverCancel,
                &mut WorkBudget::new(units)
            ),
            Err(HttpRgbCustodyError::Archive(HttpArchiveError::Work(
                GeometryError::BudgetExhausted
            )))
        ));
    }
    assert_eq!(archive.pin(), before);
    assert_eq!(publisher.visible_roots().count(), 0);
    assert!(!c.pending_wire().ok_or("raw lost")?.acknowledged());
    assert!(c.frame().is_none());
    let commit = retain(
        &mut c,
        &a,
        plan,
        &mut archive,
        &mut publisher,
        &NeverCancel,
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(commit.acknowledgement(), Ok(()));
    Ok(())
}

#[test]
fn changed_storage_scope_is_refused_before_writing_any_object() -> Test {
    let d = Directory::new("scope")?;
    let mut publisher = d.open()?;
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
    next_wire(&mut c, &a, &mut s)?;
    let scope = scope(c.camera());
    let archive = HttpWireArchive::new(scope, limits())?;
    let plan = c.prepare_wire_custody(&archive, NOW, &a, &mut WorkBudget::new(WORK))?;
    let mut changed = HttpWireArchive::new(
        HttpWireScope {
            retention_evidence: [29; 32],
            ..scope
        },
        limits(),
    )?;
    assert!(matches!(
        retain(
            &mut c,
            &a,
            plan,
            &mut changed,
            &mut publisher,
            &NeverCancel,
            &mut WorkBudget::new(WORK)
        ),
        Err(HttpRgbCustodyError::PlanMismatch)
    ));
    assert_eq!(publisher.visible_roots().count(), 0);
    assert_eq!(
        std::fs::read_dir(publisher.root_dir().join("spool/objects"))?.count(),
        0
    );
    assert!(!c.pending_wire().ok_or("raw")?.acknowledged());
    Ok(())
}

#[test]
fn stale_read_plan_and_already_acknowledged_read_cannot_consume_a_new_source() -> Test {
    let d = Directory::new("stale-read")?;
    let mut publisher = d.open()?;
    let model = model(1)?;
    let head = head(&model)?;
    let mut owner = tracker(&head, tracking_policy())?;
    let (mut c, a, mut s) = session(&model, &head, &mut owner, response(&[jpeg(240)], false), 79)?;
    next_wire(&mut c, &a, &mut s)?;
    let mut archive = HttpWireArchive::new(scope(c.camera()), limits())?;
    let plan = c.prepare_wire_custody(&archive, NOW, &a, &mut WorkBudget::new(WORK))?;
    assert_eq!(
        retain(
            &mut c,
            &a,
            plan,
            &mut archive,
            &mut publisher,
            &NeverCancel,
            &mut WorkBudget::new(WORK)
        )?
        .acknowledgement(),
        Ok(())
    );
    assert!(matches!(
        c.prepare_wire_custody(&archive, NOW, &a, &mut WorkBudget::new(WORK)),
        Err(HttpRgbCustodyError::NotPending)
    ));
    assert!(matches!(
        retain(
            &mut c,
            &a,
            plan,
            &mut archive,
            &mut publisher,
            &NeverCancel,
            &mut WorkBudget::new(WORK)
        ),
        Err(HttpRgbCustodyError::NotPending)
    ));
    let read = next_wire(&mut c, &a, &mut s)?;
    assert_ne!(read, plan.wire());
    let before = archive.pin();
    assert!(matches!(
        retain(
            &mut c,
            &a,
            plan,
            &mut archive,
            &mut publisher,
            &NeverCancel,
            &mut WorkBudget::new(WORK)
        ),
        Err(HttpRgbCustodyError::PlanMismatch)
    ));
    assert_eq!(archive.pin(), before);
    assert_eq!(publisher.visible_roots().count(), 1);
    assert_eq!(c.pending_wire().ok_or("raw")?.receipt(), read);
    assert!(!c.pending_wire().ok_or("raw")?.acknowledged());
    Ok(())
}

#[test]
fn camera_revocation_before_publication_does_not_touch_storage() -> Test {
    let d = Directory::new("pre-revoke")?;
    let mut publisher = d.open()?;
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
    next_wire(&mut c, &a, &mut s)?;
    let mut archive = HttpWireArchive::new(scope(c.camera()), limits())?;
    let plan = c.prepare_wire_custody(&archive, NOW, &a, &mut WorkBudget::new(WORK))?;
    a.deny_on(HttpCameraOperation::Poll, 1);
    assert!(matches!(
        retain(
            &mut c,
            &a,
            plan,
            &mut archive,
            &mut publisher,
            &NeverCancel,
            &mut WorkBudget::new(WORK)
        ),
        Err(HttpRgbCustodyError::Source(HttpCameraError::Denied(
            HttpCameraDenial::Revoked
        )))
    ));
    assert_eq!(archive.pin().reads, 0);
    assert_eq!(publisher.visible_roots().count(), 0);
    assert!(!c.pending_wire().ok_or("raw")?.acknowledged());
    Ok(())
}
