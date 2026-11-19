#![forbid(unsafe_code)]
use super::*;
use crate::calibrated_coverage::{CoverageProjectionInput, tests::fixture as nominal_fixture};
use crate::ingest::calibration_adoption::{
    AdoptionReceipt, CalibrationSubject, adopt, preview_adoption, recording_sensor,
};
use crate::ingest::calibration_coverage::MAX_CALIBRATION_COVERAGE_WORK;
use crate::ingest::privacy_mask::{MaskBinding, PrivacyMaskPolicy, declare_mask, preview_mask};
use crate::ingest::recorded_coverage::{GenerationCurrency, approval_digest};
use crate::ingest::{CaptureHint, FileIngestAdapter, FileIngestRequest};
use crate::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedReadUsage,
};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, StreamId, TimestampNs};
use fss_geometry::WorkBudget;
use std::fs;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:guarded-coverage";
const JPEG: &[u8] = include_bytes!("../../../../fss-codec-mjpeg/tests/fixtures/gray.jpg");

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-guarded-retention-{name}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(std::io::Error::other("test directory limit").into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:guarded-coverage".to_owned(),
        operation_id: OperationId::parse("operation:guarded-coverage")?,
        principal: "principal:guarded-coverage".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(4096)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

struct Fixture {
    _directory: Directory,
    root: PathBuf,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    set: GuardedCoverageSet,
    nominal_approval: ContentDigest,
}

fn fixture(name: &str) -> TestResult<Fixture> {
    let directory = Directory::new(name)?;
    let root = directory.0.join("deployment");
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let mut records = Vec::new();
    let mut screens = Vec::new();
    for index in 1..=2 {
        let (mut record, assessment) = nominal_fixture(index, true)?;
        let path = directory.0.join(format!("{index}.mjpeg"));
        fs::write(&path, JPEG.repeat(20))?;
        let request = FileIngestRequest::new(
            path,
            SensorId::parse(&record.sensor_id)?,
            StreamId::parse(format!("stream:camera-{index}"))?,
        )
        .with_capture_hint(CaptureHint::new(TimestampNs(1001), 1, 10_000_000.0)?)
        .with_receive_time(TimestampNs(1_000_000_000));
        let imported = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
        record.import_identity = imported.import_identity;
        record.import_root = imported.import_root;
        records.push(record);
        screens.push(assessment);
    }
    for record in &mut records {
        record.basis = deployment.current_anchor().clone();
        for zone in &mut record.zones {
            for witness in &mut zone.witnesses {
                witness.witness.anchor = record.basis.clone();
            }
        }
    }
    let nominal_approval = approval_digest(&records.iter().collect::<Vec<_>>());
    let privacy = MaskBinding::NoPolicy;
    let inputs: Vec<_> = records
        .iter()
        .zip(&screens)
        .map(|(record, screen)| CoverageProjectionInput {
            record,
            assessment: Some(screen),
            privacy: &privacy,
        })
        .collect();
    let set =
        GuardedCoverageSet::project(&inputs, &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK))?;
    Ok(Fixture {
        _directory: directory,
        root,
        cx,
        deployment,
        set,
        nominal_approval,
    })
}

fn inventory(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    let mut paths = vec![root.to_path_buf()];
    let mut files = BTreeMap::new();
    while let Some(path) = paths.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                paths.push(entry.path());
            } else {
                files.insert(entry.path(), fs::read(entry.path())?);
            }
        }
    }
    Ok(files)
}

#[test]
fn exact_guarded_retention_is_one_batch_and_a_restart_rerun_writes_nothing() -> TestResult {
    let mut f = fixture("roundtrip")?;
    let approval = f.set.approval();
    assert_ne!(approval, f.nominal_approval);
    f.set.check_approval(
        &f.deployment,
        approval,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    let before = f.deployment.current_anchor().commit_sequence;
    assert_eq!(
        f.set.retain(
            &mut f.deployment,
            approval,
            RetainedReadLimits::default(),
            &f.cx
        )?,
        CoverageStatus::Retained
    );
    assert_eq!(f.deployment.current_anchor().commit_sequence, before + 1);
    assert_eq!(
        f.set.status(&f.deployment)?,
        CoverageStatus::AlreadyRetained
    );
    let Fixture {
        _directory,
        root,
        cx,
        deployment,
        set,
        nominal_approval: _,
    } = f;
    drop(deployment);
    let mut reopened = ReferenceDeployment::open(&root, SITE, &cx)?;
    let files = inventory(&root)?;
    let anchor = reopened.current_anchor().clone();
    assert_eq!(
        set.retain(&mut reopened, approval, RetainedReadLimits::default(), &cx)?,
        CoverageStatus::AlreadyRetained
    );
    assert_eq!(reopened.current_anchor(), &anchor);
    assert_eq!(inventory(&root)?, files);
    drop(reopened);
    drop(_directory);
    Ok(())
}

#[test]
fn nominal_or_wrong_approvals_never_stage_any_guarded_record() -> TestResult {
    let mut f = fixture("approvals")?;
    for approval in [f.nominal_approval, ContentDigest::sha256(b"wrong approval")] {
        let files = inventory(&f.root)?;
        let anchor = f.deployment.current_anchor().clone();
        assert!(matches!(
            f.set.retain(
                &mut f.deployment,
                approval,
                RetainedReadLimits::default(),
                &f.cx
            ),
            Err(GuardedCoverageRetentionError::Coverage(_))
        ));
        assert_eq!(f.deployment.current_anchor(), &anchor);
        assert_eq!(inventory(&f.root)?, files);
    }
    Ok(())
}

#[test]
fn a_changed_second_sensor_mask_refuses_before_any_write_even_for_a_retained_rerun() -> TestResult {
    for retained in [false, true] {
        let mut f = fixture(if retained {
            "mask-retained"
        } else {
            "mask-new"
        })?;
        let approval = f.set.approval();
        if retained {
            f.set.retain(
                &mut f.deployment,
                approval,
                RetainedReadLimits::default(),
                &f.cx,
            )?;
        }
        let policy = PrivacyMaskPolicy::new(
            SensorId::parse("sensor:camera-2")?,
            [100, 100],
            &[[95, 0, 5, 100]],
        )?;
        let preview = preview_mask(&f.deployment, &policy)?;
        declare_mask(&mut f.deployment, &policy, preview.approval, &f.cx)?;
        let files = inventory(&f.root)?;
        assert!(matches!(
            f.set.retain(
                &mut f.deployment,
                approval,
                RetainedReadLimits::default(),
                &f.cx
            ),
            Err(GuardedCoverageRetentionError::Privacy(_))
        ));
        assert_eq!(inventory(&f.root)?, files);
    }
    Ok(())
}

#[test]
fn unrelated_authority_advance_does_not_invalidate_the_retained_ancestor() -> TestResult {
    let mut f = fixture("unrelated")?;
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:unrelated")?,
        [100, 100],
        &[[0, 0, 1, 1]],
    )?;
    let preview = preview_mask(&f.deployment, &policy)?;
    declare_mask(&mut f.deployment, &policy, preview.approval, &f.cx)?;
    let approval = f.set.approval();
    assert_eq!(
        f.set.retain(
            &mut f.deployment,
            approval,
            RetainedReadLimits::default(),
            &f.cx
        )?,
        CoverageStatus::Retained
    );
    Ok(())
}

fn current(record: &CoverageRecord) -> TestResult<RetainedAdoption> {
    let Some(PoseProvenance::SiteCalibration {
        calibration_digest,
        camera_handle,
        intrinsics_generation,
        extrinsics_generation,
        ..
    }) = record.pose_provenance
    else {
        return Err(std::io::Error::other("missing fixture provenance").into());
    };
    let receipt = AdoptionReceipt {
        adoption: 1,
        camera_handle,
        camera_name: "front".to_owned(),
        sensor_id: SensorId::parse(&record.sensor_id)?,
        calibration_digest,
        twin_package: ContentDigest::sha256(b"twin"),
        intrinsics_generation,
        extrinsics_generation,
        supersedes: None,
    };
    Ok(RetainedAdoption {
        digest: receipt.digest(),
        receipt,
        committed_sequence: 1,
        invalidation: None,
    })
}

#[test]
fn first_adoption_requires_fresh_currency_and_stale_or_disappeared_adoptions_fail() -> TestResult {
    let (mut record, _) = nominal_fixture(1, true)?;
    let sensor = SensorId::parse(&record.sensor_id)?;
    let adoption = current(&record)?;
    let history = BTreeMap::from([(adoption.receipt.camera_handle, vec![adoption.clone()])]);
    check_adoption(&record, &sensor, &BTreeMap::new())?;
    assert!(check_adoption(&record, &sensor, &history).is_err());
    if let Some(PoseProvenance::SiteCalibration { currency, .. }) = &mut record.pose_provenance {
        *currency = GenerationCurrency::AdoptedCurrent {
            receipt: adoption.digest,
        };
    }
    check_adoption(&record, &sensor, &history)?;
    assert!(check_adoption(&record, &sensor, &BTreeMap::new()).is_err());
    for changed in 0..3 {
        let mut successor = adoption.clone();
        match changed {
            0 => successor.receipt.calibration_digest = ContentDigest::sha256(b"new calibration"),
            1 => successor.receipt.extrinsics_generation += 1,
            _ => successor.receipt.sensor_id = SensorId::parse("sensor:other")?,
        }
        successor.digest = successor.receipt.digest();
        assert!(check_adoption(&record, &sensor, &BTreeMap::from([(1, vec![successor])])).is_err());
    }
    Ok(())
}

#[test]
fn an_adopted_sensor_cannot_be_reintroduced_as_an_unadopted_camera() -> TestResult {
    let (record, _) = nominal_fixture(1, true)?;
    let sensor = SensorId::parse(&record.sensor_id)?;
    let mut adoption = current(&record)?;
    adoption.receipt.camera_handle = 99;
    adoption.digest = adoption.receipt.digest();
    assert!(matches!(
        check_adoption(&record, &sensor, &BTreeMap::from([(99, vec![adoption])])),
        Err(GuardedCoverageRetentionError::Adoption(_))
    ));
    Ok(())
}

fn immutable_limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: crate::agent_orient::OrientLimits::default(),
        max_read_bytes: 64 * 1024 * 1024,
        max_read_objects: 4096,
    }
}

#[test]
fn immutable_guarded_reads_share_final_validation_allowance_with_a_live_writer() -> TestResult {
    let f = fixture("immutable-guarded")?;
    let before = inventory(&f.root)?;
    let read = |limits| -> TestResult<RetainedReadUsage> {
        // Keep the operational owner open: immutable inspection must not acquire its lock.
        let source = ImmutableRetainedSource::open(&f.root, limits, &f.cx)?;
        assert_eq!(source.current_anchor(), f.deployment.current_anchor());
        assert_eq!(f.set.status(&source)?, f.set.status(&f.deployment)?);
        f.set
            .revalidate(&source, RetainedReadLimits::default(), &f.cx)?;
        for record in f.set.records() {
            assert_eq!(
                recording_sensor(
                    &source,
                    record.import_identity,
                    RetainedReadLimits::default(),
                    &f.cx,
                )?,
                SensorId::parse(&record.sensor_id)?,
            );
        }
        source.revalidate()?;
        Ok(source.usage())
    };

    let usage = read(immutable_limits())?;
    assert!(usage.read_bytes > 0 && usage.read_objects > 0);
    let exact = ImmutableRetainedReadLimits {
        max_read_bytes: usize::try_from(usage.read_bytes)?,
        max_read_objects: usize::try_from(usage.read_objects)?,
        ..immutable_limits()
    };
    assert_eq!(read(exact)?, usage);
    assert!(
        read(ImmutableRetainedReadLimits {
            max_read_bytes: exact.max_read_bytes - 1,
            ..exact
        })
        .is_err()
    );
    assert!(
        read(ImmutableRetainedReadLimits {
            max_read_objects: exact.max_read_objects - 1,
            ..exact
        })
        .is_err()
    );
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn immutable_adoption_reads_preserve_currency_and_final_payload_checks() -> TestResult {
    let mut f = fixture("immutable-adoption")?;
    let record = &f.set.records()[0];
    let Some(PoseProvenance::SiteCalibration {
        calibration_digest,
        camera_handle,
        intrinsics_generation,
        extrinsics_generation,
        ..
    }) = record.pose_provenance
    else {
        return Err(std::io::Error::other("missing fixture provenance").into());
    };
    let subject = CalibrationSubject {
        calibration_digest,
        twin_package: ContentDigest::sha256(b"immutable-adoption-twin"),
        cameras: vec![(
            "front".to_owned(),
            CameraGeneration {
                camera: camera_handle,
                intrinsics: intrinsics_generation,
                extrinsics: extrinsics_generation,
            },
        )],
    };
    let bindings = vec![("front".to_owned(), SensorId::parse(&record.sensor_id)?)];
    let old_source = ImmutableRetainedSource::open(&f.root, immutable_limits(), &f.cx)?;
    assert!(retained_adoptions(&old_source)?.is_empty());

    let preview = preview_adoption(&f.deployment, &subject, &bindings)?;
    let adopted = adopt(
        &mut f.deployment,
        &subject,
        &bindings,
        preview.approval,
        &f.cx,
    )?;
    let receipt = adopted.cameras[0].receipt.digest();
    // A snapshot cannot silently advance to a new adoption, even while the writer stays open.
    assert!(retained_adoptions(&old_source)?.is_empty());
    assert!(old_source.revalidate().is_err());

    let source = ImmutableRetainedSource::open(&f.root, immutable_limits(), &f.cx)?;
    let history = retained_adoptions(&source)?;
    let operational = retained_adoptions(&f.deployment)?;
    assert_eq!(history.len(), operational.len());
    assert_eq!(history[&camera_handle][0].digest, receipt);
    assert_eq!(
        history[&camera_handle][0].digest,
        operational[&camera_handle][0].digest,
    );
    // Pre-adoption owner assertions cannot masquerade as freshly adopted coverage.
    assert!(matches!(
        f.set
            .revalidate(&source, RetainedReadLimits::default(), &f.cx),
        Err(GuardedCoverageRetentionError::Adoption(_))
    ));
    source.revalidate()?;

    // Adoption payloads participate in the same final tamper check as retained source bytes.
    let path = f.deployment.publisher().spool().object_path(receipt);
    let mut permissions = fs::metadata(&path)?.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    fs::set_permissions(&path, permissions)?;
    fs::write(path, b"damaged adoption receipt")?;
    assert!(source.revalidate().is_err());
    Ok(())
}
