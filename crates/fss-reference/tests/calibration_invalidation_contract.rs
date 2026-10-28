#![forbid(unsafe_code)]
//! Retained owner invalidation must stop new uses of an exact calibration adoption.
//!
//! These tests use real file ingestion, retained sensor capsules, the authority ledger,
//! source-backed coverage retention and cold reopening. Geometry is deliberately synthetic:
//! this checks authority and custody, not physical drift detection or camera qualification.

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BatchId, BudgetVector, CanonicalEncode, CaptureInterval, ContentDigest, EvidenceDelta,
    ObjectId, OperationId, Plane, SensorId, StreamId, TimestampNs,
};
use fss_geometry::{
    AdjustedCamera, BundleParameter, CameraCovariance, PinholeIntrinsics, RadialDistortion,
    RigidPose, WorkBudget,
};
use fss_reference::calibrated_coverage::{
    CoverageProjectionInput, GuardedCoverageRetentionError, GuardedCoverageSet,
};
use fss_reference::ingest::calibration_adoption::{
    AdoptionError, AdoptionReceipt, AdoptionStatus, CalibrationSubject, CameraGeneration, adopt,
    adopted_currency, preview_adoption, retained_adoptions, state_json,
};
use fss_reference::ingest::calibration_coverage::{
    CalibrationCoverageAssessment, CalibrationCoverageInput, MAX_CALIBRATION_COVERAGE_WORK,
    assess_calibration_coverage,
};
use fss_reference::ingest::calibration_invalidation::{
    InvalidationError, InvalidationReason, InvalidationRequest, InvalidationStatus, invalidate,
    invalidation_object_id, preview_invalidation,
};
use fss_reference::ingest::ground_visibility::{
    CameraModel, Occlusion, OcclusionUnknownReason, PoseCovariance, PoseRobustness,
    PoseRobustnessClass, VisibilityPolicy, ZoneVisibility,
};
use fss_reference::ingest::privacy_mask::MaskBinding;
use fss_reference::ingest::recorded_corroboration::GroundZone;
use fss_reference::ingest::recorded_coverage::{
    CoverageError, CoverageExtras, CoverageFrame, CoverageInput, CoverageRecord, CoverageSource,
    CoverageStatus, CoverageZoneInput, GenerationCurrency, PoseProvenance, PoseUncertainty,
    approval_digest, build_coverage_with, check_approval, retain_coverage,
};
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestReceipt, FileIngestRequest, RetainedReadLimits,
};
use fss_reference::{ReferenceDeployment, ReferenceError, ReplayCx};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const SITE: &str = "site:calibration-invalidation";
const EAST: u64 = 21;
const WEST: u64 = 22;
const JPEG: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Directory(PathBuf);

impl Directory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-calibration-invalidation-{name}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path, site: &str) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:calibration-invalidation".to_owned(),
        operation_id: OperationId::parse("operation:calibration-invalidation")?,
        principal: "principal:calibration-invalidation".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

fn sensor(name: &str) -> TestResult<SensorId> {
    Ok(SensorId::parse(format!("sensor:{name}"))?)
}

fn generation(camera: u64, intrinsics: u64, extrinsics: u64) -> CameraGeneration {
    CameraGeneration {
        camera,
        intrinsics,
        extrinsics,
    }
}

fn subject(label: &str, east: (u64, u64)) -> CalibrationSubject {
    CalibrationSubject {
        calibration_digest: ContentDigest::sha256(label.as_bytes()),
        twin_package: ContentDigest::sha256(b"twin"),
        cameras: vec![
            ("east".to_owned(), generation(EAST, east.0, east.1)),
            ("west".to_owned(), generation(WEST, 2, 3)),
        ],
    }
}

fn both_bindings() -> TestResult<Vec<(String, SensorId)>> {
    Ok(vec![
        ("east".to_owned(), sensor("east")?),
        ("west".to_owned(), sensor("west")?),
    ])
}

fn east_binding() -> TestResult<Vec<(String, SensorId)>> {
    Ok(vec![("east".to_owned(), sensor("east")?)])
}

struct Fixture {
    directory: Directory,
    root: PathBuf,
    site: String,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    east: FileIngestReceipt,
    west: FileIngestReceipt,
}

impl Fixture {
    fn source(&self, camera: u64) -> &FileIngestReceipt {
        match camera {
            EAST => &self.east,
            WEST => &self.west,
            _ => panic!("unknown fixture camera"),
        }
    }

    fn restart(self) -> TestResult<Self> {
        let Self {
            directory,
            root,
            site,
            cx,
            deployment,
            east,
            west,
        } = self;
        drop(deployment);
        let deployment = ReferenceDeployment::open(&root, &site, &cx)?;
        Ok(Self {
            directory,
            root,
            site,
            cx,
            deployment,
            east,
            west,
        })
    }

    fn adopt_both(&mut self, subject: &CalibrationSubject) -> TestResult<ContentDigest> {
        let bindings = both_bindings()?;
        let preview = preview_adoption(&self.deployment, subject, &bindings)?;
        adopt(
            &mut self.deployment,
            subject,
            &bindings,
            preview.approval,
            &self.cx,
        )?;
        Ok(preview.approval)
    }

    fn request(&self, camera: u64) -> TestResult<InvalidationRequest> {
        let history = retained_adoptions(&self.deployment)?;
        let current = history
            .get(&camera)
            .and_then(|chain| chain.last())
            .ok_or("fixture adoption missing")?;
        Ok(InvalidationRequest {
            camera_handle: camera,
            adoption_digest: current.digest,
            reason: InvalidationReason::CameraMoved,
            evidence: None,
        })
    }

    fn invalidate(&mut self, request: &InvalidationRequest) -> TestResult<ContentDigest> {
        let preview = preview_invalidation(&self.deployment, request)?;
        let retained = invalidate(&mut self.deployment, request, preview.approval, &self.cx)?;
        assert_eq!(retained.status, InvalidationStatus::Retained);
        Ok(retained.receipt.digest())
    }
}

fn fixture(name: &str) -> TestResult<Fixture> {
    fixture_at(name, SITE)
}

fn fixture_at(name: &str, site: &str) -> TestResult<Fixture> {
    let directory = Directory::new(name)?;
    let root = directory.0.join("deployment");
    let cx = context(&root, site)?;
    let mut deployment = ReferenceDeployment::open(&root, site, &cx)?;
    let mut import = |name: &str| -> TestResult<FileIngestReceipt> {
        let path = directory.0.join(format!("{name}.mjpeg"));
        fs::write(&path, JPEG.repeat(20))?;
        let request = FileIngestRequest::new(
            path,
            sensor(name)?,
            StreamId::parse(format!("stream:{name}"))?,
        )
        .with_capture_hint(CaptureHint::new(TimestampNs(1001), 1, 10_000_000.0)?)
        .with_receive_time(TimestampNs(1_000_000_000));
        Ok(FileIngestAdapter::ingest(request, &cx, &mut deployment)?)
    };
    let east = import("east")?;
    let west = import("west")?;
    Ok(Fixture {
        directory,
        root,
        site: site.to_owned(),
        cx,
        deployment,
        east,
        west,
    })
}

fn inventory(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0_usize;
    while let Some(path) = pending.pop() {
        visited += 1;
        if visited > 4096 {
            return Err("test inventory bound".into());
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else if entry.file_type()?.is_file() {
                files.insert(entry.path(), fs::read(entry.path())?);
            } else {
                return Err("unexpected test directory entry".into());
            }
        }
    }
    Ok(files)
}

fn capsule_digest(source: &FileIngestReceipt) -> TestResult<ContentDigest> {
    let capsule = source
        .capsules
        .first()
        .ok_or("no retained source capsule")?;
    Ok(ContentDigest::sha256(&capsule.try_canonical_bytes()?))
}

fn corrupt_payload(deployment: &ReferenceDeployment, digest: ContentDigest) -> TestResult {
    let path = deployment.publisher().spool().object_path(digest);
    let mut bytes = fs::read(&path)?;
    let last = bytes.last_mut().ok_or("empty retained object")?;
    *last ^= 1;
    fs::write(path, bytes)?;
    Ok(())
}

#[test]
fn frozen_adoption_receipt_bytes_remain_decodable_without_invalidation_fields() -> TestResult {
    // Frozen independently from the version-1 canonical layout before invalidation existed.
    // This does not regenerate its expected bytes using the production encoder.
    let hex = concat!(
        "0000000000000008465353544c523031000000010000000000000020",
        "6673732e7477696e5f6c6f63616c697a6174696f6e5f726563656970742e7631",
        "00000000000000010000000000000015000000000000000465617374",
        "000000000000000b73656e736f723a65617374",
        "015c7dba632323a191a4905ecb8a99ef116df81b30daa812ca78632546b0b285e2",
        "0172b33a1cb0bfc9cdd3db0102962414c7a0d85aad94eba64cd8c33265242f7f9f",
        "0000000000000002000000000000000300",
    );
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    let digest = ContentDigest::parse(
        "sha256:f804a148c94aa4cd594d9f80453d235980c170403b42bb6479043ae98c5077dd",
    )?;
    assert_eq!(ContentDigest::sha256(&bytes), digest);
    let receipt = AdoptionReceipt::from_bytes(&bytes, digest)?;
    assert_eq!(receipt.camera_handle, EAST);
    assert_eq!(receipt.sensor_id, sensor("east")?);
    assert_eq!(receipt.generation(), (2, 3));
    assert_eq!(receipt.supersedes, None);
    assert_eq!(receipt.to_bytes(), bytes);
    Ok(())
}

#[test]
fn preview_is_read_only_and_only_its_exact_approval_can_retain_one_invalidation() -> TestResult {
    let mut f = fixture("preview")?;
    let calibration = subject("calibration-v1", (2, 3));
    f.adopt_both(&calibration)?;
    let request = f.request(EAST)?;
    let adoption_bytes = retained_adoptions(&f.deployment)?[&EAST][0]
        .receipt
        .to_bytes();
    let before = inventory(&f.root)?;
    let anchor = f.deployment.current_anchor().clone();
    let preview = preview_invalidation(&f.deployment, &request)?;
    assert_eq!(preview.status, InvalidationStatus::Proposed);
    assert_eq!(
        preview_invalidation(&f.deployment, &request)?.approval,
        preview.approval,
    );
    assert_eq!(f.deployment.current_anchor(), &anchor);
    assert_eq!(inventory(&f.root)?, before);
    assert!(
        invalidate(
            &mut f.deployment,
            &request,
            ContentDigest::sha256(b"not the reviewed invalidation"),
            &f.cx,
        )
        .is_err()
    );
    assert_eq!(f.deployment.current_anchor(), &anchor);
    assert_eq!(inventory(&f.root)?, before);
    let retained = invalidate(&mut f.deployment, &request, preview.approval, &f.cx)?;
    assert_eq!(retained.status, InvalidationStatus::Retained);
    assert_eq!(retained.receipt, preview.receipt);
    assert_eq!(
        f.deployment.current_anchor().commit_sequence,
        anchor.commit_sequence + 1,
    );
    let batch = f.deployment.ledger().batches().last().ok_or("no commit")?;
    assert_eq!(batch.deltas.len(), 1);
    let delta = &batch.deltas[0];
    assert_eq!(delta.family, "calibration_invalidation");
    assert_eq!(delta.plane, Plane::Authority);
    assert_eq!(
        delta.object_id,
        invalidation_object_id(request.adoption_digest)?
    );
    assert_eq!(delta.prior_generation, None);
    assert_eq!(delta.new_generation, 1);
    assert_eq!(delta.payload_digest, retained.receipt.digest());
    assert_eq!(delta.witness_digest, Some(preview.approval));
    assert_eq!(delta.operation_id, None);
    assert!(batch.children.contains(&delta.payload_digest));
    assert_eq!(
        f.deployment
            .publisher()
            .spool()
            .read(delta.payload_digest)?,
        retained.receipt.to_bytes(),
    );
    let history = retained_adoptions(&f.deployment)?;
    assert!(history[&EAST][0].invalidation.is_some());
    assert!(history[&WEST][0].invalidation.is_none());
    assert_eq!(history[&EAST][0].receipt.to_bytes(), adoption_bytes);
    assert_eq!(
        f.deployment
            .publisher()
            .spool()
            .read(request.adoption_digest)?,
        adoption_bytes,
    );
    Ok(())
}

#[test]
fn exact_invalidation_retry_survives_restart_without_writing_or_reinterpreting_history()
-> TestResult {
    let mut f = fixture("restart")?;
    let calibration = subject("calibration-v1", (2, 3));
    f.adopt_both(&calibration)?;
    let request = f.request(EAST)?;
    let preview = preview_invalidation(&f.deployment, &request)?;
    f.invalidate(&request)?;
    f = f.restart()?;
    let before = inventory(&f.root)?;
    let anchor = f.deployment.current_anchor().clone();
    let fresh = preview_invalidation(&f.deployment, &request)?;
    assert_eq!(fresh.status, InvalidationStatus::AlreadyInvalidated);
    for approval in [preview.approval, fresh.approval] {
        let retry = invalidate(&mut f.deployment, &request, approval, &f.cx)?;
        assert_eq!(retry.status, InvalidationStatus::AlreadyInvalidated);
        assert_eq!(retry.receipt, preview.receipt);
        assert_eq!(f.deployment.current_anchor(), &anchor);
        assert_eq!(inventory(&f.root)?, before);
    }
    let history = retained_adoptions(&f.deployment)?;
    let consulted_source = Cell::new(false);
    let refused = adopted_currency(
        &history,
        calibration.calibration_digest,
        "east",
        generation(EAST, 2, 3),
        || {
            consulted_source.set(true);
            Err(AdoptionError::Cancelled)
        },
    );
    assert!(matches!(refused, Err(AdoptionError::Invalidated { .. })));
    assert!(!consulted_source.get());
    assert!(
        adopted_currency(
            &history,
            calibration.calibration_digest,
            "west",
            generation(WEST, 2, 3),
            || SensorId::parse("sensor:west").map_err(AdoptionError::from),
        )?
        .is_some()
    );
    let state = state_json(&f.deployment)?;
    assert!(state.contains("invalidated"));
    assert!(state.contains(&request.adoption_digest.to_string()));
    Ok(())
}

#[test]
fn reason_evidence_and_deployment_are_bound_to_the_reviewed_approval() -> TestResult {
    let mut f = fixture("exact-approval")?;
    let calibration = subject("calibration-v1", (2, 3));
    f.adopt_both(&calibration)?;
    let request = f.request(EAST)?;
    let preview = preview_invalidation(&f.deployment, &request)?;
    let before = inventory(&f.root)?;
    let anchor = f.deployment.current_anchor().clone();
    for changed in [
        InvalidationRequest {
            reason: InvalidationReason::OpticsChanged,
            ..request.clone()
        },
        InvalidationRequest {
            evidence: Some(capsule_digest(&f.east)?),
            ..request.clone()
        },
    ] {
        assert_ne!(
            preview_invalidation(&f.deployment, &changed)?.approval,
            preview.approval,
        );
        assert!(invalidate(&mut f.deployment, &changed, preview.approval, &f.cx).is_err());
        assert_eq!(f.deployment.current_anchor(), &anchor);
        assert_eq!(inventory(&f.root)?, before);
    }
    let mut foreign = fixture_at("foreign-approval", "site:foreign-calibration")?;
    foreign.adopt_both(&calibration)?;
    let same_target = foreign.request(EAST)?;
    assert_eq!(same_target.adoption_digest, request.adoption_digest);
    assert_ne!(
        preview_invalidation(&foreign.deployment, &same_target)?.approval,
        preview.approval,
    );
    let foreign_before = inventory(&foreign.root)?;
    let foreign_anchor = foreign.deployment.current_anchor().clone();
    assert!(
        invalidate(
            &mut foreign.deployment,
            &same_target,
            preview.approval,
            &foreign.cx,
        )
        .is_err()
    );
    assert_eq!(foreign.deployment.current_anchor(), &foreign_anchor);
    assert_eq!(inventory(&foreign.root)?, foreign_before);
    Ok(())
}

#[test]
fn invalidation_targets_exactly_the_current_adoption_and_cannot_retarget_a_new_generation()
-> TestResult {
    let mut f = fixture("stale-target")?;
    let v1 = subject("calibration-v1", (2, 3));
    f.adopt_both(&v1)?;
    let old = f.request(EAST)?;
    let preview = preview_invalidation(&f.deployment, &old)?;
    let v2 = subject("calibration-v2", (2, 4));
    let adoption = preview_adoption(&f.deployment, &v2, &east_binding()?)?;
    adopt(
        &mut f.deployment,
        &v2,
        &east_binding()?,
        adoption.approval,
        &f.cx,
    )?;
    let before = inventory(&f.root)?;
    let anchor = f.deployment.current_anchor().clone();
    assert!(preview_invalidation(&f.deployment, &old).is_err());
    assert!(invalidate(&mut f.deployment, &old, preview.approval, &f.cx).is_err());
    let current = f.request(EAST)?;
    assert_ne!(current.adoption_digest, old.adoption_digest);
    assert!(invalidate(&mut f.deployment, &current, preview.approval, &f.cx).is_err());
    let wrong_camera = InvalidationRequest {
        camera_handle: WEST,
        ..current.clone()
    };
    assert!(preview_invalidation(&f.deployment, &wrong_camera).is_err());
    assert_eq!(f.deployment.current_anchor(), &anchor);
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn an_existing_invalidation_cannot_be_rewritten_with_a_different_reason_or_evidence() -> TestResult
{
    let mut f = fixture("immutable")?;
    f.adopt_both(&subject("calibration-v1", (2, 3)))?;
    let request = f.request(EAST)?;
    let preview = preview_invalidation(&f.deployment, &request)?;
    f.invalidate(&request)?;
    let before = inventory(&f.root)?;
    let anchor = f.deployment.current_anchor().clone();
    for changed in [
        InvalidationRequest {
            reason: InvalidationReason::OwnerRevoked,
            ..request.clone()
        },
        InvalidationRequest {
            evidence: Some(capsule_digest(&f.east)?),
            ..request.clone()
        },
    ] {
        assert!(preview_invalidation(&f.deployment, &changed).is_err());
        assert!(invalidate(&mut f.deployment, &changed, preview.approval, &f.cx).is_err());
        assert_eq!(f.deployment.current_anchor(), &anchor);
        assert_eq!(inventory(&f.root)?, before);
    }
    Ok(())
}

#[test]
fn optional_evidence_must_be_a_readable_retained_capsule_from_the_adopted_sensor() -> TestResult {
    let mut f = fixture("evidence")?;
    f.adopt_both(&subject("calibration-v1", (2, 3)))?;
    let request = f.request(EAST)?;
    let east_capsule = capsule_digest(&f.east)?;
    // This proves the evidence fixture is the authority's payload, not its domain-separated
    // semantic fingerprint, an import identity, a source chunk, or merely staged bytes.
    assert!(f.deployment.ledger().batches().iter().any(|batch| {
        batch
            .deltas
            .iter()
            .any(|delta| delta.family == "sensor_capsule" && delta.payload_digest == east_capsule)
    }));
    let before = inventory(&f.root)?;
    let anchor = f.deployment.current_anchor().clone();
    for bad in [
        ContentDigest::sha256(b"unknown capsule"),
        capsule_digest(&f.west)?,
        f.east.import_root,
        f.east.manifest_digest,
    ] {
        let changed = InvalidationRequest {
            evidence: Some(bad),
            ..request.clone()
        };
        assert!(preview_invalidation(&f.deployment, &changed).is_err());
        assert_eq!(f.deployment.current_anchor(), &anchor);
        assert_eq!(inventory(&f.root)?, before);
    }
    let valid = InvalidationRequest {
        evidence: Some(east_capsule),
        ..request
    };
    let preview = preview_invalidation(&f.deployment, &valid)?;
    assert_eq!(preview.status, InvalidationStatus::Proposed);
    f.invalidate(&valid)?;
    assert!(
        retained_adoptions(&f.deployment)?[&EAST][0]
            .invalidation
            .is_some()
    );
    Ok(())
}

#[test]
fn evidence_corruption_between_preview_and_commit_refuses_before_any_write() -> TestResult {
    let mut f = fixture("evidence-corrupt")?;
    f.adopt_both(&subject("calibration-v1", (2, 3)))?;
    let evidence = capsule_digest(&f.east)?;
    let request = InvalidationRequest {
        evidence: Some(evidence),
        ..f.request(EAST)?
    };
    let preview = preview_invalidation(&f.deployment, &request)?;
    corrupt_payload(&f.deployment, evidence)?;
    let before = inventory(&f.root)?;
    let anchor = f.deployment.current_anchor().clone();
    assert!(preview_invalidation(&f.deployment, &request).is_err());
    assert!(invalidate(&mut f.deployment, &request, preview.approval, &f.cx).is_err());
    assert_eq!(f.deployment.current_anchor(), &anchor);
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn recovery_needs_a_different_calibration_and_a_strict_monotone_generation_advance() -> TestResult {
    let mut f = fixture("recovery")?;
    let v1 = subject("calibration-v1", (2, 3));
    let old_adoption_approval = f.adopt_both(&v1)?;
    let v2 = subject("calibration-v2", (2, 4));
    let prepared_before_withdrawal = preview_adoption(&f.deployment, &v2, &east_binding()?)?;
    let request = f.request(EAST)?;
    let old_invalidation = preview_invalidation(&f.deployment, &request)?;
    f.invalidate(&request)?;
    let before = inventory(&f.root)?;
    let anchor = f.deployment.current_anchor().clone();
    for rejected in [
        v1.clone(),
        subject("different-bytes-same-generation", (2, 3)),
        subject("intrinsics-regressed", (1, 4)),
        subject("extrinsics-regressed", (3, 2)),
        subject("calibration-v1", (2, 4)),
    ] {
        assert!(preview_adoption(&f.deployment, &rejected, &east_binding()?).is_err());
        assert!(
            adopt(
                &mut f.deployment,
                &rejected,
                &east_binding()?,
                old_adoption_approval,
                &f.cx,
            )
            .is_err()
        );
        assert_eq!(f.deployment.current_anchor(), &anchor);
        assert_eq!(inventory(&f.root)?, before);
    }
    let recovery = preview_adoption(&f.deployment, &v2, &east_binding()?)?;
    assert_ne!(recovery.approval, prepared_before_withdrawal.approval);
    // A previously prepared replacement is also stale: the owner must review recovery
    // after the withdrawal, even though its calibration and generations would qualify.
    for stale in [old_adoption_approval, prepared_before_withdrawal.approval] {
        assert!(adopt(&mut f.deployment, &v2, &east_binding()?, stale, &f.cx).is_err());
    }
    assert_eq!(f.deployment.current_anchor(), &anchor);
    assert_eq!(inventory(&f.root)?, before);
    let adopted = adopt(
        &mut f.deployment,
        &v2,
        &east_binding()?,
        recovery.approval,
        &f.cx,
    )?;
    assert_eq!(adopted.status(), AdoptionStatus::Retained);
    f = f.restart()?;
    let history = retained_adoptions(&f.deployment)?;
    assert_eq!(history[&EAST].len(), 2);
    assert!(history[&EAST][0].invalidation.is_some());
    assert!(history[&EAST][1].invalidation.is_none());
    assert_eq!(
        history[&EAST][1].receipt.supersedes,
        Some(request.adoption_digest)
    );
    assert!(
        adopted_currency(
            &history,
            v2.calibration_digest,
            "east",
            generation(EAST, 2, 4),
            || SensorId::parse("sensor:east").map_err(AdoptionError::from),
        )?
        .is_some()
    );
    let recovered_before = inventory(&f.root)?;
    let recovered_anchor = f.deployment.current_anchor().clone();
    for approval in [
        recovery.approval,
        preview_adoption(&f.deployment, &v2, &east_binding()?)?.approval,
    ] {
        assert_eq!(
            adopt(&mut f.deployment, &v2, &east_binding()?, approval, &f.cx)?.status(),
            AdoptionStatus::AlreadyCurrent,
        );
        assert_eq!(f.deployment.current_anchor(), &recovered_anchor);
        assert_eq!(inventory(&f.root)?, recovered_before);
    }
    // A historical invalidation receipt is not permission to invalidate the replacement.
    assert!(preview_invalidation(&f.deployment, &request).is_err());
    assert!(
        invalidate(
            &mut f.deployment,
            &request,
            old_invalidation.approval,
            &f.cx,
        )
        .is_err()
    );
    assert_eq!(f.deployment.current_anchor(), &recovered_anchor);
    assert_eq!(inventory(&f.root)?, recovered_before);
    Ok(())
}

#[test]
fn generic_append_cannot_forge_the_reserved_invalidation_family_or_object_namespace() -> TestResult
{
    let mut f = fixture("reserved")?;
    let before = inventory(&f.root)?;
    let anchor = f.deployment.current_anchor().clone();
    let payload = ContentDigest::sha256(b"not staged and never authorized");
    for (family, object) in [
        ("calibration_invalidation", "object:anywhere"),
        ("another_family", "object:calibration-invalidation:shadow"),
    ] {
        let result = f.deployment.append_batch(
            BatchId::parse("batch:forged-calibration-invalidation")?,
            vec![EvidenceDelta {
                delta_id: "delta:forged-calibration-invalidation".to_owned(),
                family: family.to_owned(),
                object_id: ObjectId::parse(object)?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(0), TimestampNs(0))?,
                plane: Plane::Authority,
                payload_digest: payload,
                witness_digest: Some(ContentDigest::sha256(b"forged approval")),
                operation_id: None,
            }],
            vec![payload],
            &f.cx,
        );
        assert!(matches!(
            result,
            Err(ReferenceError::ReservedDeltaFamily { .. })
        ));
        assert_eq!(f.deployment.current_anchor(), &anchor);
        assert_eq!(inventory(&f.root)?, before);
    }
    Ok(())
}

#[test]
fn cancellation_before_staging_writes_nothing_and_a_fresh_owned_retry_can_commit() -> TestResult {
    let mut f = fixture("cancel-before")?;
    f.adopt_both(&subject("calibration-v1", (2, 3)))?;
    let request = f.request(EAST)?;
    let preview = preview_invalidation(&f.deployment, &request)?;
    let before = inventory(&f.root)?;
    let anchor = f.deployment.current_anchor().clone();
    f.cx.set_cancel_at_checkpoint("calibration_invalidation:retain");
    assert!(matches!(
        invalidate(&mut f.deployment, &request, preview.approval, &f.cx),
        Err(InvalidationError::Cancelled),
    ));
    assert_eq!(f.deployment.current_anchor(), &anchor);
    assert_eq!(inventory(&f.root)?, before);
    f.cx = context(&f.root, &f.site)?;
    assert_eq!(
        invalidate(&mut f.deployment, &request, preview.approval, &f.cx)?.status,
        InvalidationStatus::Retained,
    );
    Ok(())
}

#[test]
fn cancellation_after_commit_preserves_the_receipt_and_cold_invalidation_authority() -> TestResult {
    let mut f = fixture("cancel-after")?;
    let calibration = subject("calibration-v1", (2, 3));
    f.adopt_both(&calibration)?;
    let request = f.request(EAST)?;
    let preview = preview_invalidation(&f.deployment, &request)?;
    f.cx.set_cancel_at_checkpoint("calibration_invalidation:retained");
    let retained = invalidate(&mut f.deployment, &request, preview.approval, &f.cx)?;
    assert_eq!(retained.status, InvalidationStatus::Retained);
    f.cx = context(&f.root, &f.site)?;
    f = f.restart()?;
    let history = retained_adoptions(&f.deployment)?;
    assert!(history[&EAST][0].invalidation.is_some());
    assert!(matches!(
        adopted_currency(
            &history,
            calibration.calibration_digest,
            "east",
            generation(EAST, 2, 3),
            || Err(AdoptionError::Cancelled),
        ),
        Err(AdoptionError::Invalidated { .. }),
    ));
    Ok(())
}

#[test]
fn losing_optional_evidence_does_not_resurrect_a_withdrawn_calibration() -> TestResult {
    let mut f = fixture("evidence-after")?;
    let calibration = subject("calibration-v1", (2, 3));
    f.adopt_both(&calibration)?;
    let evidence = capsule_digest(&f.east)?;
    let request = InvalidationRequest {
        evidence: Some(evidence),
        ..f.request(EAST)?
    };
    let preview = preview_invalidation(&f.deployment, &request)?;
    f.invalidate(&request)?;
    fs::remove_file(f.deployment.publisher().spool().object_path(evidence))?;
    let before = inventory(&f.root)?;
    let anchor = f.deployment.current_anchor().clone();
    let history = retained_adoptions(&f.deployment)?;
    assert!(matches!(
        adopted_currency(
            &history,
            calibration.calibration_digest,
            "east",
            generation(EAST, 2, 3),
            || Err(AdoptionError::Cancelled),
        ),
        Err(AdoptionError::Invalidated { .. }),
    ));
    assert_eq!(
        invalidate(&mut f.deployment, &request, preview.approval, &f.cx)?.status,
        InvalidationStatus::AlreadyInvalidated,
    );
    assert_eq!(f.deployment.current_anchor(), &anchor);
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn deleting_invalidation_evidence_preserves_withdrawal_and_approval_authority_after_restart()
-> TestResult {
    use fss_reference::deletion::{commit_deletion, plan_deletion};

    let mut f = fixture("delete-evidence")?;
    let calibration = subject("calibration-v1", (2, 3));
    f.adopt_both(&calibration)?;
    // A separate recording has an exclusive source chunk. The ordinary east/west fixture
    // intentionally shares its bytes, which alone could not exercise physical unlinking.
    let path = f.directory.0.join("east-drift-evidence.mjpeg");
    fs::write(&path, JPEG.repeat(19))?;
    let source = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            path,
            sensor("east")?,
            StreamId::parse("stream:east-drift-evidence")?,
        )
        .with_receive_time(TimestampNs(2_000_000_000)),
        &f.cx,
        &mut f.deployment,
    )?;
    let evidence = capsule_digest(&source)?;
    let request = InvalidationRequest {
        evidence: Some(evidence),
        ..f.request(EAST)?
    };
    let preview = preview_invalidation(&f.deployment, &request)?;
    let withdrawal = f.invalidate(&request)?;
    let plan = plan_deletion(&f.deployment, source.import_identity, &f.cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    let deleted = plan.deleted_set();
    for digest in [
        withdrawal,
        preview.approval,
        request.adoption_digest,
        evidence,
    ] {
        assert!(
            !deleted.contains(&digest),
            "authority was scheduled for unlink: {digest}"
        );
        assert!(
            plan.retained
                .iter()
                .any(|object| { object.digest == digest && object.reason == "authority_history" }),
            "retained owner history not classified as authority: {digest}",
        );
    }
    let chunk = *source
        .manifest
        .ordered_chunks
        .first()
        .ok_or("no source chunk")?;
    assert!(
        deleted.contains(&chunk),
        "exclusive source bytes were not selected"
    );
    let principal = "principal:calibration-invalidation";
    commit_deletion(
        &mut f.deployment,
        plan.digest()?,
        plan.approval_digest(principal)?,
        principal,
        &f.cx,
    )?;
    assert!(!f.deployment.publisher().spool().object_path(chunk).exists());
    f = f.restart()?;
    for digest in [
        withdrawal,
        preview.approval,
        request.adoption_digest,
        evidence,
    ] {
        let bytes = f.deployment.publisher().spool().read(digest)?;
        assert_eq!(ContentDigest::sha256(&bytes), digest);
    }
    let history = retained_adoptions(&f.deployment)?;
    assert!(matches!(
        adopted_currency(
            &history,
            calibration.calibration_digest,
            "east",
            generation(EAST, 2, 3),
            || Err(AdoptionError::Cancelled),
        ),
        Err(AdoptionError::Invalidated { .. }),
    ));
    assert_eq!(
        invalidate(&mut f.deployment, &request, preview.approval, &f.cx)?.status,
        InvalidationStatus::AlreadyInvalidated,
    );
    Ok(())
}

fn coverage_fixture(
    f: &Fixture,
    calibration: &CalibrationSubject,
    camera_handle: u64,
) -> TestResult<(CoverageRecord, CalibrationCoverageAssessment)> {
    use BundleParameter::{Cx, Cy, Fx, Fy, K1, K2, Rotation, Translation};
    let history = retained_adoptions(&f.deployment)?;
    let adoption = history[&camera_handle]
        .last()
        .ok_or("no current adoption")?;
    let receipt = &adoption.receipt;
    let identity = generation(
        camera_handle,
        receipt.intrinsics_generation,
        receipt.extrinsics_generation,
    );
    let model = AdjustedCamera {
        identity,
        intrinsics: PinholeIntrinsics::new(100, 100, 100.0, 100.0, 50.0, 50.0)?,
        distortion: RadialDistortion::NONE,
        pose: RigidPose::new(
            [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
            [0.0, 0.0, 10.0],
        )?,
        covariance: CameraCovariance {
            parameters: vec![Cx],
            matrix: vec![4.0],
            fixed: vec![
                Rotation(0),
                Rotation(1),
                Rotation(2),
                Translation(0),
                Translation(1),
                Translation(2),
                Fx,
                Fy,
                Cy,
                K1,
                K2,
            ],
        },
    };
    let ground = [GroundZone {
        zone_id: "center".to_owned(),
        x: -1.0,
        y: -1.0,
        width: 2.0,
        height: 2.0,
    }];
    let assessment = assess_calibration_coverage(
        CalibrationCoverageInput {
            camera_name: &receipt.camera_name,
            camera: &model,
            calibration_digest: calibration.calibration_digest,
            sensor: &receipt.sensor_id,
            privacy: &MaskBinding::NoPolicy,
            zones: &ground,
            policy: VisibilityPolicy {
                grid: 2,
                threshold_ppm: 1_000_000,
            },
        },
        &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
    )?;
    let source = f.source(camera_handle);
    let frames = source
        .capsules
        .iter()
        .enumerate()
        .map(|(index, capsule)| CoverageFrame {
            segment: index,
            capture: capsule.capture,
        })
        .collect::<Vec<_>>();
    let gaps = source
        .capsules
        .iter()
        .map(|capsule| capsule.gap_before)
        .collect::<Vec<_>>();
    let visibility = ZoneVisibility {
        camera_model: CameraModel::CalibratedPose,
        grid: 2,
        threshold_ppm: 1_000_000,
        samples: 4,
        visible: 4,
        outside_frustum: 0,
        occluded: 0,
        privacy_masked: 0,
        occlusion: Occlusion::Unknown(OcclusionUnknownReason::NoSceneMesh),
    };
    let robust = PoseRobustness {
        nominal: PoseRobustnessClass::Observable,
        perturbations: 12,
        observable: 12,
        occluded: 0,
        outside_frustum: 0,
        privacy_masked: 0,
    };
    let record = build_coverage_with(
        &CoverageInput {
            source: CoverageSource::Corroborate,
            import_identity: source.import_identity,
            import_root: source.import_root,
            sensor_id: receipt.sensor_id.as_str(),
            analysis_digest: ContentDigest::sha256(receipt.camera_name.as_bytes()),
            basis: f.deployment.current_anchor().clone(),
            capture_time_label: source.capture_time_label,
            segment_gaps: &gaps,
            first_segment: 0,
            last_segment: frames.len() - 1,
            frames: &frames,
            confirmation_hits: 3,
            zones: vec![CoverageZoneInput {
                zone_id: "center".to_owned(),
                geometry: "-1,-1,2,2".to_owned(),
                inside_frame: true,
                pipeline_generation: ContentDigest::sha256(b"invalidation coverage fixture"),
                entries: Vec::new(),
            }],
        },
        &CoverageExtras {
            sensor_health: None,
            visibility: vec![Some(visibility)],
            refusals: Vec::new(),
            restarts: Vec::new(),
            pose_provenance: Some(PoseProvenance::SiteCalibration {
                calibration_digest: calibration.calibration_digest,
                camera_handle,
                intrinsics_generation: identity.intrinsics,
                extrinsics_generation: identity.extrinsics,
                currency: GenerationCurrency::AdoptedCurrent {
                    receipt: adoption.digest,
                },
            }),
            pose_uncertainty: Some(PoseUncertainty::SigmaPoints {
                covariance: PoseCovariance::new([[0.0; 6]; 6])?,
            }),
            pose_robustness: vec![Some(robust)],
        },
    )?;
    Ok((record, assessment))
}

fn guarded_set(
    inputs: &[(&CoverageRecord, &CalibrationCoverageAssessment)],
) -> TestResult<GuardedCoverageSet> {
    let privacy = MaskBinding::NoPolicy;
    let inputs = inputs
        .iter()
        .map(|(record, assessment)| CoverageProjectionInput {
            record,
            assessment: Some(assessment),
            privacy: &privacy,
        })
        .collect::<Vec<_>>();
    Ok(GuardedCoverageSet::project(
        &inputs,
        &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
    )?)
}

#[test]
fn every_coverage_publication_guard_refuses_invalidated_adoption_including_retained_retry()
-> TestResult {
    for already_retained in [false, true] {
        let mut f = fixture(if already_retained {
            "guard-retry"
        } else {
            "guard-new"
        })?;
        let calibration = subject("calibration-v1", (2, 3));
        f.adopt_both(&calibration)?;
        let (east, east_screen) = coverage_fixture(&f, &calibration, EAST)?;
        let (west, west_screen) = coverage_fixture(&f, &calibration, WEST)?;
        let set = guarded_set(&[(&east, &east_screen), (&west, &west_screen)])?;
        let unaffected = guarded_set(&[(&west, &west_screen)])?;
        let legacy_approval = approval_digest(&[&east]);
        check_approval(&f.deployment, &[&east], legacy_approval)?;
        assert!(
            set.records()
                .iter()
                .all(|record| !record.zones[0].witnesses.is_empty())
        );
        let approval = set.approval();
        set.check_approval(
            &f.deployment,
            approval,
            RetainedReadLimits::default(),
            &f.cx,
        )?;
        if already_retained {
            assert_eq!(
                retain_coverage(&mut f.deployment, &[&east], legacy_approval, &f.cx)?,
                CoverageStatus::Retained,
            );
            assert_eq!(
                set.retain(
                    &mut f.deployment,
                    approval,
                    RetainedReadLimits::default(),
                    &f.cx
                )?,
                CoverageStatus::Retained,
            );
        }
        let request = f.request(EAST)?;
        f.invalidate(&request)?;
        f = f.restart()?;
        let anchor = f.deployment.current_anchor().clone();
        let before = inventory(&f.root)?;
        assert!(matches!(
            set.revalidate(&f.deployment, RetainedReadLimits::default(), &f.cx),
            Err(GuardedCoverageRetentionError::Adoption(_)),
        ));
        assert!(matches!(
            set.check_approval(
                &f.deployment,
                approval,
                RetainedReadLimits::default(),
                &f.cx
            ),
            Err(GuardedCoverageRetentionError::Adoption(_)),
        ));
        assert!(matches!(
            set.retain(
                &mut f.deployment,
                approval,
                RetainedReadLimits::default(),
                &f.cx
            ),
            Err(GuardedCoverageRetentionError::Adoption(_)),
        ));
        // The underlying version-6 publisher independently rechecks currency. Skipping
        // GuardedCoverageSet cannot use an old approved receipt to publish new silence.
        let records = set.records().iter().collect::<Vec<_>>();
        assert!(matches!(
            check_approval(&f.deployment, &records, approval_digest(&records)),
            Err(CoverageError::Currency { .. }),
        ));
        assert!(matches!(
            retain_coverage(&mut f.deployment, &records, approval, &f.cx),
            Err(CoverageError::Currency { .. }),
        ));
        // Nominal version-5 coverage predates the full-camera screening receipt.
        // Keeping that wire version cannot bypass a later explicit withdrawal, including
        // the idempotent path of a nominal record already retained before withdrawal.
        assert!(matches!(
            check_approval(&f.deployment, &[&east], legacy_approval),
            Err(CoverageError::Currency { .. }),
        ));
        assert!(matches!(
            retain_coverage(&mut f.deployment, &[&east], legacy_approval, &f.cx),
            Err(CoverageError::Currency { .. }),
        ));
        assert_eq!(f.deployment.current_anchor(), &anchor);
        assert_eq!(inventory(&f.root)?, before);
        // Revocation is per camera. Other-camera ancestry need not equal the latest head.
        unaffected.check_approval(
            &f.deployment,
            unaffected.approval(),
            RetainedReadLimits::default(),
            &f.cx,
        )?;
        // Historical evidence remains decodable; its old bytes do not confer new authority.
        for record in set.records() {
            assert_eq!(
                CoverageRecord::from_bytes(&record.to_bytes(), record.digest())?,
                *record
            );
        }
    }
    Ok(())
}

#[test]
fn corrupt_invalidation_custody_is_never_treated_as_no_invalidation() -> TestResult {
    let mut f = fixture("receipt-corrupt")?;
    let calibration = subject("calibration-v1", (2, 3));
    f.adopt_both(&calibration)?;
    let (nominal, screen) = coverage_fixture(&f, &calibration, EAST)?;
    let set = guarded_set(&[(&nominal, &screen)])?;
    let request = f.request(EAST)?;
    let retained_digest = f.invalidate(&request)?;
    corrupt_payload(&f.deployment, retained_digest)?;
    let before = inventory(&f.root)?;
    let anchor = f.deployment.current_anchor().clone();
    assert!(retained_adoptions(&f.deployment).is_err());
    assert!(preview_invalidation(&f.deployment, &request).is_err());
    assert!(preview_adoption(&f.deployment, &calibration, &east_binding()?).is_err());
    assert!(
        set.revalidate(&f.deployment, RetainedReadLimits::default(), &f.cx)
            .is_err()
    );
    assert!(matches!(
        check_approval(&f.deployment, &[&set.records()[0]], set.approval()),
        Err(CoverageError::Currency { .. }),
    ));
    assert_eq!(f.deployment.current_anchor(), &anchor);
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}
