#![forbid(unsafe_code)]

use super::*;
use crate::ingest::{FileIngestAdapter, FileIngestRequest};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, StreamId};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

const JPEG: &[u8] = include_bytes!("../../../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
const SITE: &str = "site:calibration-adoption";
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-calibration-adoption-{name}-{}-{attempt}",
                std::process::id()
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
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &std::path::Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:calibration-adoption".to_owned(),
        operation_id: OperationId::parse("operation:calibration-adoption")?,
        principal: "principal:calibration-adoption".to_owned(),
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
    _directory: OwnedDirectory,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    east_import: ContentDigest,
    west_import: ContentDigest,
}

fn sensor(name: &str) -> TestResult<SensorId> {
    Ok(SensorId::parse(format!("sensor:{name}"))?)
}

/// A deployment retaining one recording of `sensor:east` and one of `sensor:west`.
fn fixture(name: &str) -> TestResult<Fixture> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let mut imports = Vec::new();
    for camera in ["east", "west"] {
        let path = directory.0.join(format!("{camera}.mjpeg"));
        fs::write(&path, [JPEG, JPEG].concat())?;
        let request = FileIngestRequest::new(
            path,
            sensor(camera)?,
            StreamId::parse(format!("stream:{camera}"))?,
        )
        .with_receive_time(TimestampNs(1_000_000_000));
        imports.push(FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity);
    }
    Ok(Fixture {
        _directory: directory,
        cx,
        deployment,
        east_import: imports[0],
        west_import: imports[1],
    })
}

fn generation(camera: u64, intrinsics: u64, extrinsics: u64) -> CameraGeneration {
    CameraGeneration {
        camera,
        intrinsics,
        extrinsics,
    }
}

/// A calibration of east (handle 21) and west (handle 22) at the given east generation.
fn subject(label: &str, east: (u64, u64)) -> CalibrationSubject {
    CalibrationSubject {
        calibration_digest: ContentDigest::sha256(label.as_bytes()),
        twin_package: ContentDigest::sha256(b"twin"),
        cameras: vec![
            ("east".to_owned(), generation(21, east.0, east.1)),
            ("west".to_owned(), generation(22, 1, 1)),
        ],
    }
}

fn east_binding() -> TestResult<Vec<(String, SensorId)>> {
    Ok(vec![("east".to_owned(), sensor("east")?)])
}

fn both_bindings() -> TestResult<Vec<(String, SensorId)>> {
    Ok(vec![
        ("west".to_owned(), sensor("west")?),
        ("east".to_owned(), sensor("east")?),
    ])
}

fn sample_receipt() -> TestResult<AdoptionReceipt> {
    Ok(AdoptionReceipt {
        adoption: 2,
        camera_handle: 21,
        camera_name: "east".to_owned(),
        sensor_id: sensor("east")?,
        calibration_digest: ContentDigest::sha256(b"calibration"),
        twin_package: ContentDigest::sha256(b"twin"),
        intrinsics_generation: 1,
        extrinsics_generation: 2,
        supersedes: Some(ContentDigest::sha256(b"prior")),
    })
}

#[test]
fn receipts_are_canonical_deterministic_and_strictly_decoded() -> TestResult {
    let receipt = sample_receipt()?;
    let bytes = receipt.to_bytes();
    assert_eq!(bytes, sample_receipt()?.to_bytes());
    assert!(
        bytes
            .windows(RECEIPT_MAGIC.len())
            .any(|w| w == RECEIPT_MAGIC)
    );
    assert!(
        bytes
            .windows(ADOPTION_RECEIPT_DOMAIN.len())
            .any(|w| w == ADOPTION_RECEIPT_DOMAIN.as_bytes())
    );
    assert_eq!(
        AdoptionReceipt::from_bytes(&bytes, receipt.digest())?,
        receipt
    );
    // Any flipped byte is refused under the retained authority digest; a flipped magic or domain
    // byte is refused even when rehashed.
    for index in 0..bytes.len() {
        let mut tampered = bytes.clone();
        tampered[index] ^= 1;
        assert!(
            AdoptionReceipt::from_bytes(&tampered, receipt.digest()).is_err(),
            "{index}"
        );
    }
    for index in [8, 20, 30] {
        let mut tampered = bytes.clone();
        tampered[index] ^= 1;
        assert!(
            AdoptionReceipt::from_bytes(&tampered, ContentDigest::sha256(&tampered)).is_err(),
            "{index}"
        );
    }
    assert!(AdoptionReceipt::from_bytes(&bytes, ContentDigest::sha256(b"other")).is_err());
    let mut suffixed = bytes;
    suffixed.push(0);
    assert!(AdoptionReceipt::from_bytes(&suffixed, ContentDigest::sha256(&suffixed)).is_err());
    // The supersedes link exists exactly after the first adoption; zero generations are invalid.
    let first_with_link = AdoptionReceipt {
        adoption: 1,
        ..receipt.clone()
    };
    let bytes = first_with_link.to_bytes();
    assert!(AdoptionReceipt::from_bytes(&bytes, ContentDigest::sha256(&bytes)).is_err());
    let unlinked = AdoptionReceipt {
        supersedes: None,
        ..receipt.clone()
    };
    assert!(unlinked.validate().is_err());
    let zero = AdoptionReceipt {
        extrinsics_generation: 0,
        ..receipt
    };
    assert!(zero.validate().is_err());
    Ok(())
}

#[test]
fn preview_writes_nothing_and_adoption_retains_exactly_the_approved_receipts() -> TestResult {
    let mut f = fixture("adopt")?;
    let v1 = subject("calibration-v1", (1, 1));
    let before = f.deployment.current_anchor().clone();
    let preview = preview_adoption(&f.deployment, &v1, &both_bindings()?)?;
    assert_eq!(preview.status(), AdoptionStatus::Proposed);
    assert_eq!(f.deployment.current_anchor(), &before);
    // Deterministic, and binding order does not matter: cameras are in handle order.
    let reordered = preview_adoption(
        &f.deployment,
        &v1,
        &[
            ("east".to_owned(), sensor("east")?),
            ("west".to_owned(), sensor("west")?),
        ],
    )?;
    assert_eq!(reordered, preview);
    let handles: Vec<u64> = preview
        .cameras
        .iter()
        .map(|c| c.receipt.camera_handle)
        .collect();
    assert_eq!(handles, [21, 22]);

    let adopted = adopt(
        &mut f.deployment,
        &v1,
        &both_bindings()?,
        preview.approval,
        &f.cx,
    )?;
    assert_eq!(adopted.status(), AdoptionStatus::Retained);
    assert_eq!(
        f.deployment.current_anchor().commit_sequence,
        before.commit_sequence + 1
    );
    let retained = retained_adoptions(&f.deployment)?;
    assert_eq!(retained.len(), 2);
    let east = &retained[&21];
    assert_eq!(east.len(), 1);
    assert_eq!(east[0].receipt, preview.cameras[0].receipt);
    assert_eq!(east[0].receipt.supersedes, None);
    assert_eq!(east[0].receipt.sensor_id, sensor("east")?);

    // Re-presenting the retaining approval, or the fresh one, writes nothing.
    let anchor = f.deployment.current_anchor().clone();
    for approval in [
        preview.approval,
        preview_adoption(&f.deployment, &v1, &both_bindings()?)?.approval,
    ] {
        let again = adopt(&mut f.deployment, &v1, &both_bindings()?, approval, &f.cx)?;
        assert_eq!(again.status(), AdoptionStatus::AlreadyCurrent);
        assert_eq!(f.deployment.current_anchor(), &anchor);
    }
    Ok(())
}

#[test]
fn a_new_generation_supersedes_history_is_kept_and_stale_approvals_are_refused() -> TestResult {
    let mut f = fixture("supersede")?;
    let v1 = subject("calibration-v1", (1, 1));
    let v2 = subject("calibration-v2", (1, 2));
    let first = preview_adoption(&f.deployment, &v1, &east_binding()?)?;
    adopt(
        &mut f.deployment,
        &v1,
        &east_binding()?,
        first.approval,
        &f.cx,
    )?;
    let v1_receipt = retained_adoptions(&f.deployment)?[&21][0].digest;

    let second = preview_adoption(&f.deployment, &v2, &east_binding()?)?;
    assert_eq!(second.cameras[0].receipt.adoption, 2);
    assert_eq!(second.cameras[0].receipt.supersedes, Some(v1_receipt));
    // The approval of the first adoption is stale for the second; a tampered one is refused.
    let anchor = f.deployment.current_anchor().clone();
    let mut tampered = second.approval.bytes();
    tampered[0] ^= 1;
    for approval in [
        first.approval,
        ContentDigest::new(DigestAlgorithm::Sha256, tampered),
    ] {
        let refused = adopt(&mut f.deployment, &v2, &east_binding()?, approval, &f.cx);
        assert!(
            matches!(&refused, Err(e) if e.stable_id() == "ERR-CALIBRATION-ADOPTION-APPROVAL-STALE-001"),
            "{refused:?}"
        );
        assert_eq!(f.deployment.current_anchor(), &anchor);
    }
    adopt(
        &mut f.deployment,
        &v2,
        &east_binding()?,
        second.approval,
        &f.cx,
    )?;
    // History is never erased: both receipts remain, linked.
    let history = &retained_adoptions(&f.deployment)?[&21];
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].digest, v1_receipt);
    assert_eq!(history[1].receipt.supersedes, Some(v1_receipt));
    assert_eq!(history[1].receipt.generation(), (1, 2));

    // Monotone: re-adopting v1 or a lower generation is refused before any write.
    let anchor = f.deployment.current_anchor().clone();
    for (older, label) in [
        (v1.clone(), "superseded calibration"),
        (subject("calibration-v0", (1, 1)), "lower generation"),
    ] {
        let refused = preview_adoption(&f.deployment, &older, &east_binding()?);
        assert!(
            matches!(&refused, Err(e) if e.stable_id() == "ERR-CALIBRATION-ADOPTION-REGRESSION-001"),
            "{label}: {refused:?}"
        );
    }
    assert_eq!(f.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn sensor_bindings_are_verified_and_fixed_per_camera() -> TestResult {
    let mut f = fixture("sensors")?;
    let v1 = subject("calibration-v1", (1, 1));
    // A sensor without retained evidence cannot be bound.
    let ghost = [("east".to_owned(), sensor("ghost")?)];
    let refused = preview_adoption(&f.deployment, &v1, &ghost);
    assert!(matches!(
        &refused,
        Err(e) if e.stable_id() == "ERR-CALIBRATION-ADOPTION-SENSOR-UNRETAINED-001"
    ));
    // Input refusals: no binding, an unknown camera, a camera or sensor bound twice.
    for bindings in [
        vec![],
        vec![("north".to_owned(), sensor("east")?)],
        vec![
            ("east".to_owned(), sensor("east")?),
            ("east".to_owned(), sensor("west")?),
        ],
        vec![
            ("east".to_owned(), sensor("east")?),
            ("west".to_owned(), sensor("east")?),
        ],
    ] {
        let refused = preview_adoption(&f.deployment, &v1, &bindings);
        assert!(
            matches!(&refused, Err(e) if e.stable_id() == "ERR-CALIBRATION-ADOPTION-INPUT-001"),
            "{bindings:?}: {refused:?}"
        );
    }
    let preview = preview_adoption(&f.deployment, &v1, &east_binding()?)?;
    adopt(
        &mut f.deployment,
        &v1,
        &east_binding()?,
        preview.approval,
        &f.cx,
    )?;
    let v2 = subject("calibration-v2", (1, 2));
    for bindings in [
        // East is bound to sensor:east; it cannot move to sensor:west.
        vec![("east".to_owned(), sensor("west")?)],
        // sensor:east belongs to handle 21; west (22) cannot take it.
        vec![("west".to_owned(), sensor("east")?)],
    ] {
        let refused = preview_adoption(&f.deployment, &v2, &bindings);
        assert!(
            matches!(&refused, Err(e) if e.stable_id() == "ERR-CALIBRATION-ADOPTION-SENSOR-CONFLICT-001"),
            "{bindings:?}: {refused:?}"
        );
    }
    Ok(())
}

#[test]
fn adopted_currency_is_current_stale_unadopted_or_absent() -> TestResult {
    let mut f = fixture("currency")?;
    let v1 = subject("calibration-v1", (1, 1));
    let v2 = subject("calibration-v2", (1, 2));
    let east_sensor = |f: &Fixture| {
        recording_sensor(
            &f.deployment,
            f.east_import,
            RetainedReadLimits::default(),
            &f.cx,
        )
    };
    assert_eq!(east_sensor(&f)?, sensor("east")?);

    // Nothing adopted: no currency statement, the recording is not even read.
    let none = retained_adoptions(&f.deployment)?;
    assert_eq!(
        adopted_currency(
            &none,
            v1.calibration_digest,
            "east",
            generation(21, 1, 1),
            || Err(AdoptionError::Cancelled)
        )?,
        None
    );

    let preview = preview_adoption(&f.deployment, &v1, &east_binding()?)?;
    adopt(
        &mut f.deployment,
        &v1,
        &east_binding()?,
        preview.approval,
        &f.cx,
    )?;
    let adopted = retained_adoptions(&f.deployment)?;
    let current = adopted_currency(
        &adopted,
        v1.calibration_digest,
        "east",
        generation(21, 1, 1),
        || east_sensor(&f),
    )?
    .ok_or("adopted camera has no current adoption")?;
    assert_eq!(current.receipt.calibration_digest, v1.calibration_digest);
    // West (handle 22) was not adopted: unchanged behaviour.
    assert_eq!(
        adopted_currency(
            &adopted,
            v1.calibration_digest,
            "west",
            generation(22, 1, 1),
            || Err(AdoptionError::Cancelled)
        )?,
        None
    );
    // The adopted camera's calibration over another sensor's recording is refused.
    let mismatch = adopted_currency(
        &adopted,
        v1.calibration_digest,
        "east",
        generation(21, 1, 1),
        || {
            recording_sensor(
                &f.deployment,
                f.west_import,
                RetainedReadLimits::default(),
                &f.cx,
            )
        },
    );
    assert!(matches!(
        &mismatch,
        Err(e) if e.stable_id() == "ERR-CALIBRATION-ADOPTION-SENSOR-MISMATCH-001"
    ));
    // A newer, never-adopted calibration is unadopted.
    let unadopted = adopted_currency(
        &adopted,
        v2.calibration_digest,
        "east",
        generation(21, 1, 2),
        || east_sensor(&f),
    );
    assert!(matches!(
        &unadopted,
        Err(e) if e.stable_id() == "ERR-CALIBRATION-ADOPTION-UNADOPTED-001"
    ));

    let preview = preview_adoption(&f.deployment, &v2, &east_binding()?)?;
    adopt(
        &mut f.deployment,
        &v2,
        &east_binding()?,
        preview.approval,
        &f.cx,
    )?;
    let adopted = retained_adoptions(&f.deployment)?;
    let stale = adopted_currency(
        &adopted,
        v1.calibration_digest,
        "east",
        generation(21, 1, 1),
        || east_sensor(&f),
    );
    assert!(
        matches!(&stale, Err(e) if e.stable_id() == "ERR-CALIBRATION-ADOPTION-STALE-001"),
        "{stale:?}"
    );
    assert!(
        adopted_currency(
            &adopted,
            v2.calibration_digest,
            "east",
            generation(21, 1, 2),
            || east_sensor(&f),
        )?
        .is_some()
    );
    Ok(())
}
