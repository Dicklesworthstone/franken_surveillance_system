#![forbid(unsafe_code)]
//! Real native JPEG -> retained localization -> measured frozen-pose residuals. The adopted
//! baseline is controlled synthetic geometry; pixel decoding, extraction, matching, retention
//! and replay use the production owners. No test-provided feature output enters the monitor.

use super::*;
use fss_core::DigestAlgorithm;
use fss_reference::ingest::calibration_adoption::{
    CalibrationSubject, CameraGeneration, adopt, preview_adoption, retained_adoptions,
};
use fss_reference::ingest::calibration_invalidation::{
    InvalidationReason, InvalidationRequest, invalidate, preview_invalidation,
};
use fss_reference::ingest::calibration_monitor::{
    MonitorError, MonitorRequest, MonitorStatus, RecordedCalibrationMonitor, preview_monitor,
    replay_monitor, retain_monitor,
};
use fss_reference::ingest::site_calibration::{
    CalibratedCamera, CalibrationInput, SeedMode, SiteCalibration,
};

fn digest(bytes: [u8; 32]) -> ContentDigest {
    ContentDigest::new(DigestAlgorithm::Sha256, bytes)
}
fn original_input(image: ImageIdentity, exposure: ContentDigest, pixels: ContentDigest) -> Vec<u8> {
    format!(
        "fss.site_camera_observations.v1\ncamera 21 1 1\nimage 96 96\nexposure {exposure}\npixels {pixels}\nimage-domain {}\ndescriptor-domain {}\nintrinsics fixed 80 80 48 48\n",
        digest(image.image_domain), digest(descriptor_domain()),
    ).into_bytes()
}
fn calibration(
    archives: &Archives,
    atlas: &LocalizationAtlas,
    input: &[u8],
    translation: [f64; 3],
) -> SiteCalibration {
    let rotation = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
    SiteCalibration {
        twin_package: ContentDigest::sha256(&archives.twin),
        twin_source: digest([1; 32]),
        atlas_package: ContentDigest::sha256(&archives.atlas),
        atlas_fingerprint: atlas.digest(),
        atlas_provenance: digest([7; 32]),
        descriptor_domain: descriptor_domain(),
        control_error_bound: None,
        initial_rms_px: 0.0,
        final_rms_px: 0.0,
        iterations: 1,
        accepted_steps: 1,
        convergence: "gradient".to_owned(),
        observation_sigma_px: 1.0,
        sigma_estimated: false,
        control_points: atlas.landmarks().iter().map(|p| p.id).collect(),
        tie_points: vec![],
        excluded_points: vec![],
        frame_policy: None,
        cameras: vec![CalibratedCamera {
            name: "east".to_owned(),
            identity: CameraGeneration {
                camera: 21,
                intrinsics: 1,
                extrinsics: 1,
            },
            observations: ContentDigest::sha256(input),
            input: CalibrationInput::Correspondences,
            dimensions: [96, 96],
            mode: SeedMode::Fixed,
            seed_sample: None,
            seed_candidate: 0,
            seed_alternatives: 1,
            seed_inliers: atlas.landmarks().len() as u64,
            seed_fit_rms_px: 0.0,
            seed_intrinsics: [80.0, 80.0, 48.0, 48.0],
            seed_rotation: rotation,
            seed_translation: translation,
            intrinsics: [80.0, 80.0, 48.0, 48.0],
            distortion: [0.0, 0.0],
            rotation,
            translation,
            covariance_parameters: vec![],
            covariance: vec![],
            fixed_parameters: vec![],
            seed_rms_px: 0.0,
            refined_rms_px: 0.0,
            control_observations: atlas.landmarks().len() as u64,
            free_observations: 0,
        }],
    }
}
struct Fixture {
    imported: Imported,
    calibration: SiteCalibration,
    encoded: Vec<u8>,
    input: Vec<u8>,
    adoption: ContentDigest,
    package: RetainedLocalization,
}
impl Fixture {
    fn new(tag: &str, translation: [f64; 3], reuse_fit: bool) -> Test<Self> {
        let mut imported = import(tag, JPEG, None)?;
        let source = jpeg(imported.identity);
        let (twin, atlas, spec) = setup([1; 32])?;
        let archives = Archives::new(&twin, &atlas)?;
        let (native, package) = retain(
            &mut imported,
            &source,
            &archives,
            RecordedImageMode::Raw(spec),
        )?;
        let image = native.result().query_features().identity();
        let input = original_input(
            image,
            if reuse_fit {
                digest(image.exposure)
            } else {
                ContentDigest::sha256(b"earlier calibration exposure")
            },
            ContentDigest::sha256(b"earlier calibration pixels"),
        );
        let calibration = calibration(&archives, &atlas, &input, translation);
        let encoded = calibration.encode()?;
        let subject = CalibrationSubject::from_calibration(&calibration, calibration.digest()?);
        let bindings = [(
            "east".to_owned(),
            SensorId::parse("sensor:retained-localize")?,
        )];
        let approval = preview_adoption(&imported.deployment, &subject, &bindings)?.approval;
        let adopted = adopt(
            &mut imported.deployment,
            &subject,
            &bindings,
            approval,
            &imported.cx,
        )?;
        let adoption = adopted.cameras[0].receipt.digest();
        Ok(Self {
            imported,
            calibration,
            encoded,
            input,
            adoption,
            package,
        })
    }
    fn observe(
        &mut self,
        approve: Option<ContentDigest>,
    ) -> Result<RecordedCalibrationMonitor, MonitorError> {
        let request = MonitorRequest {
            calibration_bytes: &self.encoded,
            calibration_digest: self.calibration.digest()?,
            camera_handle: 21,
            adoption_digest: self.adoption,
            camera_input: &self.input,
            localization_identity: self.package.identity(),
            localization_root: self.package.publication_root(),
            localization_receipt: self.package.receipt_digest(),
        };
        let mut jpeg = DecodeBudget::new(1_000_000_000);
        let mut video = RecordedVideoDecodeBudget::new(1_000_000_000);
        let mut geometry = WorkBudget::new(2_000_000_000);
        let result = match approve {
            None => preview_monitor(
                &mut self.imported.deployment,
                &request,
                &mut jpeg,
                &mut video,
                &mut geometry,
                &self.imported.cx,
            ),
            Some(approval) => retain_monitor(
                &mut self.imported.deployment,
                &request,
                approval,
                &mut jpeg,
                &mut video,
                &mut geometry,
                &self.imported.cx,
            ),
        };
        if result.is_ok() {
            assert!(jpeg.used() > 0, "the monitor must actually decode the JPEG");
        }
        result
    }

    fn replay(
        &mut self,
        retained: &RecordedCalibrationMonitor,
    ) -> Result<RecordedCalibrationMonitor, MonitorError> {
        let mut jpeg = DecodeBudget::new(1_000_000_000);
        let report = replay_monitor(
            &mut self.imported.deployment,
            retained.identity(),
            retained.publication_root()?,
            retained.digest(),
            &mut jpeg,
            &mut RecordedVideoDecodeBudget::new(1_000_000_000),
            &mut WorkBudget::new(2_000_000_000),
            &self.imported.cx,
        )?;
        assert!(
            jpeg.used() > 0,
            "historical reproduction must decode the source again"
        );
        Ok(report)
    }
}

#[test]
fn measured_monitor_preview_approval_retry_and_cold_replay_use_retained_native_evidence() -> Test {
    let mut fixture = Fixture::new("monitor-cold", [0.0; 3], false)?;
    let before = fixture.imported.deployment.current_anchor().clone();
    let objects = storage(&fixture.imported.deployment);
    let proposal = fixture.observe(None)?;
    assert_eq!(proposal.status(), MonitorStatus::Proposed);
    assert_eq!(proposal.outcome(), "pass_under_policy");
    assert!(proposal.result().inliers >= 8);
    assert!(proposal.result().rms_inlier_px.is_some_and(|rms| rms < 1.5));
    assert_eq!(fixture.imported.deployment.current_anchor(), &before);
    assert_eq!(storage(&fixture.imported.deployment), objects);
    assert!(matches!(
        fixture.observe(Some(ContentDigest::sha256(b"wrong review"))),
        Err(MonitorError::StaleApproval(_))
    ));
    assert_eq!(fixture.imported.deployment.current_anchor(), &before);
    assert_eq!(storage(&fixture.imported.deployment), objects);
    let retained = fixture.observe(Some(proposal.approval()))?;
    assert_eq!(retained.status(), MonitorStatus::Retained);
    assert_eq!(retained.digest(), proposal.digest());
    assert_eq!(retained.encoded(), proposal.encoded());
    let committed = fixture.imported.deployment.current_anchor().clone();
    assert_eq!(committed.commit_sequence, before.commit_sequence + 1);
    let objects = storage(&fixture.imported.deployment);
    let retry = fixture.observe(Some(proposal.approval()))?;
    assert_eq!(retry.status(), MonitorStatus::AlreadyRetained);
    assert_eq!(fixture.imported.deployment.current_anchor(), &committed);
    assert_eq!(storage(&fixture.imported.deployment), objects);
    let history = retained_adoptions(&fixture.imported.deployment)?;
    assert_eq!(history.len(), 1);
    assert!(
        history
            .get(&21)
            .and_then(|history| history.last())
            .ok_or("current camera adoption")?
            .invalidation
            .is_none()
    );
    assert!(
        retained
            .to_json()?
            .contains("\"adoption_invalidated\":false")
    );
    fixture.encoded.clear();
    fixture.input.clear();
    drop(fixture.imported.deployment);
    fixture.imported.deployment = ReferenceDeployment::open(
        &fixture.imported.directory.0.join("deployment"),
        SITE,
        &fixture.imported.cx,
    )?;
    let mut jpeg = DecodeBudget::new(1_000_000_000);
    let replayed = replay_monitor(
        &mut fixture.imported.deployment,
        retained.identity(),
        retained.publication_root()?,
        retained.digest(),
        &mut jpeg,
        &mut RecordedVideoDecodeBudget::new(1_000_000_000),
        &mut WorkBudget::new(2_000_000_000),
        &fixture.imported.cx,
    )?;
    assert_eq!(replayed.status(), MonitorStatus::Replayed);
    assert_eq!(replayed.encoded(), retained.encoded());
    assert!(jpeg.used() > 0);
    assert_eq!(fixture.imported.deployment.current_anchor(), &committed);
    assert_eq!(storage(&fixture.imported.deployment), objects);
    Ok(())
}

#[test]
fn contradiction_remains_auditable_after_withdrawal_and_replacement_without_restoring_currency()
-> Test {
    let mut fixture = Fixture::new("monitor-drift", [1.0, 0.0, 0.0], false)?;
    let proposal = fixture.observe(None)?;
    assert_eq!(proposal.outcome(), "contradicted");
    assert!(proposal.result().projected >= 8);
    assert!(
        proposal
            .result()
            .residuals
            .iter()
            .any(|r| r.error_px.is_some_and(|error| error > 3.0))
    );
    assert!(
        proposal
            .to_json()?
            .contains("\"action\":\"preview_owner_withdrawal\"")
    );
    let publication_basis = fixture.imported.deployment.current_anchor().clone();
    let retained = fixture.observe(Some(proposal.approval()))?;
    assert!(
        retained_adoptions(&fixture.imported.deployment)?
            .get(&21)
            .and_then(|history| history.last())
            .ok_or("current camera adoption")?
            .invalidation
            .is_none()
    );
    let withdrawal = InvalidationRequest {
        camera_handle: 21,
        adoption_digest: fixture.adoption,
        reason: InvalidationReason::ResidualDrift,
        evidence: Some(retained.source().capsule),
    };
    let approval = preview_invalidation(&fixture.imported.deployment, &withdrawal)?.approval;
    let invalidated = invalidate(
        &mut fixture.imported.deployment,
        &withdrawal,
        approval,
        &fixture.imported.cx,
    )?;
    let committed = fixture.imported.deployment.current_anchor().clone();
    let objects = storage(&fixture.imported.deployment);
    assert!(fixture.observe(None).is_err());
    assert!(fixture.observe(Some(proposal.approval())).is_err());
    drop(fixture.imported.deployment);
    fixture.imported.deployment = ReferenceDeployment::open(
        &fixture.imported.directory.0.join("deployment"),
        SITE,
        &fixture.imported.cx,
    )?;
    let replayed = fixture.replay(&retained)?;
    assert_eq!(replayed.status(), MonitorStatus::Replayed);
    assert_eq!(replayed.outcome(), "contradicted");
    assert_eq!(replayed.encoded(), retained.encoded());
    let json = replayed.to_json()?;
    assert!(json.contains("\"adoption_check\":\"monitor_publication_prefix\""));
    assert!(json.contains(&format!(
        "\"adoption_basis_sequence\":{}",
        publication_basis.commit_sequence
    )));
    assert!(json.contains(&format!(
        "\"adoption_basis_state_root\":\"{}\"",
        publication_basis.state_root
    )));
    assert!(json.contains("\"recommendation\":null"));
    assert_eq!(fixture.imported.deployment.current_anchor(), &committed);
    assert_eq!(storage(&fixture.imported.deployment), objects);
    let history = retained_adoptions(&fixture.imported.deployment)?;
    assert_eq!(
        history
            .get(&21)
            .and_then(|history| history.last())
            .and_then(|adoption| adoption.invalidation.as_ref())
            .map(|invalidation| invalidation.digest),
        Some(invalidated.receipt.digest())
    );

    // Recover separately with a fresh newer generation. Historical replay must still use the
    // old published prefix, while neither old preview nor its original approval becomes current.
    let mut replacement = fixture.calibration.clone();
    replacement.cameras[0].identity.extrinsics = 2;
    replacement.cameras[0].translation = [0.0; 3];
    replacement.cameras[0].seed_translation = [0.0; 3];
    let replacement_input =
        std::str::from_utf8(&fixture.input)?.replace("camera 21 1 1", "camera 21 1 2");
    replacement.cameras[0].observations = ContentDigest::sha256(replacement_input.as_bytes());
    let subject = CalibrationSubject::from_calibration(&replacement, replacement.digest()?);
    let bindings = [(
        "east".to_owned(),
        SensorId::parse("sensor:retained-localize")?,
    )];
    let approval = preview_adoption(&fixture.imported.deployment, &subject, &bindings)?.approval;
    let recovered = adopt(
        &mut fixture.imported.deployment,
        &subject,
        &bindings,
        approval,
        &fixture.imported.cx,
    )?;
    let committed = fixture.imported.deployment.current_anchor().clone();
    let objects = storage(&fixture.imported.deployment);
    assert!(fixture.observe(None).is_err());
    assert!(fixture.observe(Some(proposal.approval())).is_err());
    assert_eq!(fixture.replay(&retained)?.encoded(), retained.encoded());
    let history = retained_adoptions(&fixture.imported.deployment)?;
    let current = history
        .get(&21)
        .and_then(|history| history.last())
        .ok_or("recovered adoption")?;
    assert_eq!(current.digest, recovered.cameras[0].receipt.digest());
    assert!(current.invalidation.is_none());
    assert_eq!(fixture.imported.deployment.current_anchor(), &committed);
    assert_eq!(storage(&fixture.imported.deployment), objects);

    // Only adoption history is historical. Privacy remains the current source-access boundary.
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:retained-localize")?,
        [96, 96],
        &[[0, 0, 96, 96]],
    )?;
    let approval = preview_mask(&fixture.imported.deployment, &policy)?.approval;
    declare_mask(
        &mut fixture.imported.deployment,
        &policy,
        approval,
        &fixture.imported.cx,
    )?;
    let committed = fixture.imported.deployment.current_anchor().clone();
    let objects = storage(&fixture.imported.deployment);
    assert!(fixture.replay(&retained).is_err());
    assert_eq!(fixture.imported.deployment.current_anchor(), &committed);
    assert_eq!(storage(&fixture.imported.deployment), objects);
    Ok(())
}

#[test]
fn publication_after_withdrawal_cannot_turn_an_old_proposal_into_historical_admission() -> Test {
    let mut fixture = Fixture::new("monitor-late-publication", [1.0, 0.0, 0.0], false)?;
    let proposal = fixture.observe(None)?;
    let root = fixture.imported.directory.0.join("deployment");
    fixture
        .imported
        .cx
        .set_cancel_at_checkpoint("calibration_monitor:publish");
    assert!(matches!(
        fixture.observe(Some(proposal.approval())),
        Err(MonitorError::Cancelled)
    ));
    // Retention staged exact replay bytes but never published a root or authority delta.
    drop(fixture.imported.deployment);
    fixture.imported.cx = context(&root)?;
    fixture.imported.deployment = ReferenceDeployment::open(&root, SITE, &fixture.imported.cx)?;
    let withdrawal = InvalidationRequest {
        camera_handle: 21,
        adoption_digest: fixture.adoption,
        reason: InvalidationReason::ResidualDrift,
        evidence: Some(proposal.source().capsule),
    };
    let approval = preview_invalidation(&fixture.imported.deployment, &withdrawal)?.approval;
    invalidate(
        &mut fixture.imported.deployment,
        &withdrawal,
        approval,
        &fixture.imported.cx,
    )?;
    assert!(fixture.observe(Some(proposal.approval())).is_err());

    // A generic derived-root writer can publish staged bytes later, but cannot manufacture the
    // old owner state at that later commit. Historical replay checks this exact ledger prefix.
    let slot = SlotName::parse(&format!(
        "calibration-monitor-{}",
        &proposal.identity().to_text()[7..]
    ))?;
    let manifest = ObjectManifest::new(
        slot.as_str(),
        vec![
            ContentDigest::sha256(&fixture.encoded),
            ContentDigest::sha256(&fixture.input),
            fixture.package.publication_root(),
            proposal.digest(),
            proposal.approval(),
            fixture.adoption,
        ],
        Some(proposal.identity()),
    )?;
    assert_eq!(manifest.root(), proposal.publication_root()?);
    let source = RetainedFileImport::open(
        &fixture.imported.deployment,
        fixture.imported.identity,
        RetainedReadLimits::default(),
        &fixture.imported.cx,
    )?;
    let capture = retained_source_capsule(&fixture.imported.deployment, &source, 0)?.capture;
    fixture
        .imported
        .deployment
        .publisher_mut()
        .stage_manifest(&slot, &manifest)?;
    fixture.imported.deployment.publish_and_commit(
        &slot,
        &manifest,
        capture,
        &fixture.imported.cx,
    )?;
    let committed = fixture.imported.deployment.current_anchor().clone();
    let objects = storage(&fixture.imported.deployment);
    assert!(matches!(
        fixture.replay(&proposal),
        Err(MonitorError::Adoption(_))
    ));
    assert_eq!(fixture.imported.deployment.current_anchor(), &committed);
    assert_eq!(storage(&fixture.imported.deployment), objects);
    Ok(())
}

#[test]
fn out_of_view_landmarks_are_indeterminate_and_fit_exposure_is_refused_without_writes() -> Test {
    let mut fixture = Fixture::new("monitor-unobserved", [0.0, 0.0, -100.0], false)?;
    let before = fixture.imported.deployment.current_anchor().clone();
    let objects = storage(&fixture.imported.deployment);
    let result = fixture.observe(None)?;
    assert_eq!(result.outcome(), "indeterminate");
    assert_eq!(result.result().projected, 0);
    assert_eq!(fixture.imported.deployment.current_anchor(), &before);
    assert_eq!(storage(&fixture.imported.deployment), objects);
    let mut fit = Fixture::new("monitor-fit", [0.0; 3], true)?;
    let before = fit.imported.deployment.current_anchor().clone();
    let objects = storage(&fit.imported.deployment);
    assert!(matches!(fit.observe(None), Err(MonitorError::FitExposure)));
    assert_eq!(fit.imported.deployment.current_anchor(), &before);
    assert_eq!(storage(&fit.imported.deployment), objects);
    Ok(())
}

#[test]
fn replacing_original_input_or_source_pins_and_cancelled_retention_cannot_create_a_monitor() -> Test
{
    let mut fixture = Fixture::new("monitor-pins", [0.0; 3], false)?;
    let before = fixture.imported.deployment.current_anchor().clone();
    let objects = storage(&fixture.imported.deployment);
    fixture.input.extend_from_slice(b"# changed input\n");
    assert!(matches!(
        fixture.observe(None),
        Err(MonitorError::Calibration(_))
    ));
    fixture
        .input
        .truncate(fixture.input.len() - b"# changed input\n".len());
    let proposal = fixture.observe(None)?;
    let wrong = MonitorRequest {
        calibration_bytes: &fixture.encoded,
        calibration_digest: fixture.calibration.digest()?,
        camera_handle: 21,
        adoption_digest: fixture.adoption,
        camera_input: &fixture.input,
        localization_identity: fixture.package.identity(),
        localization_root: fixture.package.publication_root(),
        localization_receipt: ContentDigest::sha256(b"wrong localization receipt"),
    };
    assert!(
        preview_monitor(
            &mut fixture.imported.deployment,
            &wrong,
            &mut DecodeBudget::new(1_000_000_000),
            &mut RecordedVideoDecodeBudget::new(1_000_000_000),
            &mut WorkBudget::new(2_000_000_000),
            &fixture.imported.cx,
        )
        .is_err()
    );
    fixture
        .imported
        .cx
        .set_cancel_at_checkpoint("calibration_monitor:stage");
    assert!(matches!(
        fixture.observe(Some(proposal.approval())),
        Err(MonitorError::Cancelled)
    ));
    assert_eq!(fixture.imported.deployment.current_anchor(), &before);
    assert_eq!(storage(&fixture.imported.deployment), objects);
    Ok(())
}
