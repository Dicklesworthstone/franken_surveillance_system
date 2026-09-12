#![forbid(unsafe_code)]
//! Contract tests for offline model-package import, staging, and verification (FSS-071 / fss-x4a.14.2).

use std::error::Error;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::{CalibrationGeneration, ContentDigest, ModelGeneration, SchemaId};
use fss_object::{
    FaultInjectingSpoolIo, HostSpoolIo, ImportOutcome, ModelId, ModelLicenseRecord,
    ModelManifestV1, ModelPackage, ModelPackageArchive, ModelPackageArtifact, ModelPackageError,
    ModelPackageImporter, ModelPackageLimits, SpoolFaultPlan, SpoolIo, SpoolIoCall, SpoolLimits,
    SpoolObjectState, StagingSpool,
};

type TestResult = Result<(), Box<dyn Error>>;

fn temp_dir(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = std::env::temp_dir()
        .join("fss_model_package_test")
        .join(test_name);
    if dir.exists() {
        let _ = fs::remove_dir_all(&dir);
    }
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn sample_manifest_and_artifacts()
-> Result<(ModelManifestV1, Vec<ModelPackageArtifact>), Box<dyn Error>> {
    let weights_payload = b"model-weights-binary-payload-v1".to_vec();
    let weights_digest = ContentDigest::sha256(&weights_payload);

    let license_payload = b"Apache-2.0 license full text terms".to_vec();
    let license_digest = ContentDigest::sha256(&license_payload);

    let part2_payload = b"model-weights-part-2-payload-v1".to_vec();
    let part2_digest = ContentDigest::sha256(&part2_payload);

    let model_id = ModelId::parse("MOD-RFDETR-001")?;
    let generation = ModelGeneration::parse("model:rfdetr:fp16:v1")?;
    let input_schema = SchemaId::parse("fss.model_input.v1")?;
    let output_schema = SchemaId::parse("fss.model_output.v1")?;
    let calibration_generation = CalibrationGeneration::parse("cal:camera-rig:v1")?;

    let license = ModelLicenseRecord {
        spdx_or_identity: "Apache-2.0".to_string(),
        text_digest: Some(license_digest),
        use_approved: true,
        restrictions: vec!["internal_evaluation_only".to_string()],
        source_identity: "https://example.com/weights".to_string(),
        artifact_digests: vec![part2_digest],
        upstream_revision: Some("rev-123".to_string()),
    };

    let manifest = ModelManifestV1 {
        model_id,
        generation,
        weights_digest,
        input_schema,
        output_schema,
        calibration_generation,
        license,
        supersedes_generation: None,
    };

    let artifacts = vec![
        ModelPackageArtifact {
            name: "weights.bin".to_string(),
            digest: weights_digest,
            payload: weights_payload,
        },
        ModelPackageArtifact {
            name: "LICENSE.txt".to_string(),
            digest: license_digest,
            payload: license_payload,
        },
        ModelPackageArtifact {
            name: "part2.bin".to_string(),
            digest: part2_digest,
            payload: part2_payload,
        },
    ];

    Ok((manifest, artifacts))
}

fn sample_spool(dir: &Path) -> Result<StagingSpool, Box<dyn Error>> {
    let limits = SpoolLimits::new(64, 100 * 1024 * 1024, 10 * 1024 * 1024, 64);
    let spool = StagingSpool::open(dir, limits)?;
    Ok(spool)
}

fn sample_spool_with_io(dir: &Path, io: Arc<dyn SpoolIo>) -> Result<StagingSpool, Box<dyn Error>> {
    let limits = SpoolLimits::new(64, 100 * 1024 * 1024, 10 * 1024 * 1024, 64);
    let spool = StagingSpool::open_with_io(dir, limits, io)?;
    Ok(spool)
}

#[test]
fn test_archive_roundtrip() -> TestResult {
    let (manifest, artifacts) = sample_manifest_and_artifacts()?;
    let package = ModelPackage::new(manifest.clone(), artifacts.clone())?;

    let archive_bytes = package.to_archive_bytes()?;
    let limits = ModelPackageLimits::default();
    let decoded = ModelPackageArchive::decode(&archive_bytes, &limits)?;

    assert_eq!(decoded.manifest, manifest);
    assert_eq!(decoded.artifacts.len(), artifacts.len());
    for art in &artifacts {
        let decoded_art = decoded
            .artifacts
            .get(&art.digest)
            .ok_or("missing artifact in decoded archive")?;
        assert_eq!(decoded_art.name, art.name);
        assert_eq!(decoded_art.digest, art.digest);
        assert_eq!(decoded_art.payload, art.payload);
    }
    Ok(())
}

#[test]
fn test_import_from_archive_stages_not_verified_then_verifies() -> TestResult {
    let root = temp_dir("test_import_archive_stages")?;
    let spool_dir = root.join("spool");
    let spool = sample_spool(&spool_dir)?;

    let (manifest, artifacts) = sample_manifest_and_artifacts()?;
    let package = ModelPackage::new(manifest.clone(), artifacts)?;
    let archive_bytes = package.to_archive_bytes()?;

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default());
    let receipt = importer.import_from_archive(&archive_bytes, Some("model:rfdetr:fp16:v1"))?;

    assert_eq!(receipt.outcome, ImportOutcome::NewlyStaged);
    assert_eq!(receipt.generation, manifest.generation);
    assert_eq!(receipt.manifest_digest, manifest.manifest_digest());

    // Verify all objects are currently Staged in spool, NOT yet Verified
    assert_eq!(
        importer.spool().state(manifest.manifest_digest()),
        Some(SpoolObjectState::Staged)
    );
    assert_eq!(
        importer.spool().state(manifest.weights_digest),
        Some(SpoolObjectState::Staged)
    );

    // Explicit verification step
    let verify_receipt = importer.verify_package(receipt.manifest_digest)?;
    assert_eq!(verify_receipt.manifest_digest, receipt.manifest_digest);
    assert_eq!(verify_receipt.generation, receipt.generation);
    assert_eq!(verify_receipt.verified_artifacts.len(), 3);

    // Verify all objects are now Verified in spool
    assert_eq!(
        importer.spool().state(manifest.manifest_digest()),
        Some(SpoolObjectState::Verified)
    );
    assert_eq!(
        importer.spool().state(manifest.weights_digest),
        Some(SpoolObjectState::Verified)
    );

    Ok(())
}

#[test]
fn test_import_from_directory_stages_not_verified() -> TestResult {
    let root = temp_dir("test_import_dir_stages")?;
    let package_dir = root.join("pkg_dir");
    let spool_dir = root.join("spool");
    let spool = sample_spool(&spool_dir)?;

    let (manifest, artifacts) = sample_manifest_and_artifacts()?;
    let package = ModelPackage::new(manifest.clone(), artifacts)?;
    let io = HostSpoolIo;
    package.write_to_directory(&package_dir, &io)?;

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default());
    let receipt = importer.import_from_directory(&package_dir, &io, None)?;

    assert_eq!(receipt.outcome, ImportOutcome::NewlyStaged);
    assert_eq!(receipt.generation, manifest.generation);
    assert_eq!(
        importer.spool().state(manifest.manifest_digest()),
        Some(SpoolObjectState::Staged)
    );

    Ok(())
}

#[test]
fn test_reject_latest_generation() -> TestResult {
    let root = temp_dir("test_reject_latest")?;
    let spool = sample_spool(&root.join("spool"))?;
    let (manifest, artifacts) = sample_manifest_and_artifacts()?;
    let package = ModelPackage::new(manifest, artifacts)?;
    let archive_bytes = package.to_archive_bytes()?;

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default());

    // 1. Explicit requested generation is "latest"
    let res = importer.import_from_archive(&archive_bytes, Some("latest"));
    assert!(matches!(res, Err(ModelPackageError::LatestNotResolvable)));

    // 2. Explicit requested generation contains ":latest"
    let res2 = importer.import_from_archive(&archive_bytes, Some("model:detector:latest"));
    assert!(matches!(res2, Err(ModelPackageError::LatestNotResolvable)));

    Ok(())
}

#[test]
fn test_generation_mismatch() -> TestResult {
    let root = temp_dir("test_gen_mismatch")?;
    let spool = sample_spool(&root.join("spool"))?;
    let (manifest, artifacts) = sample_manifest_and_artifacts()?;
    let package = ModelPackage::new(manifest, artifacts)?;
    let archive_bytes = package.to_archive_bytes()?;

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default());

    let res = importer.import_from_archive(&archive_bytes, Some("model:rfdetr:fp16:v2"));
    assert!(matches!(
        res,
        Err(ModelPackageError::GenerationMismatch { .. })
    ));
    Ok(())
}

#[test]
fn test_missing_artifact_rejected() -> TestResult {
    let (manifest, mut artifacts) = sample_manifest_and_artifacts()?;
    // Drop the weights artifact
    artifacts.retain(|a| a.digest != manifest.weights_digest);

    let res = ModelPackage::new(manifest, artifacts);
    assert!(matches!(
        res,
        Err(ModelPackageError::MissingArtifact { .. })
    ));
    Ok(())
}

#[test]
fn test_extra_artifact_rejected() -> TestResult {
    let (manifest, mut artifacts) = sample_manifest_and_artifacts()?;
    let extra_payload = b"untracked-extra-weights".to_vec();
    artifacts.push(ModelPackageArtifact {
        name: "extra.bin".to_string(),
        digest: ContentDigest::sha256(&extra_payload),
        payload: extra_payload,
    });

    let res = ModelPackage::new(manifest, artifacts);
    assert!(matches!(res, Err(ModelPackageError::ExtraArtifact { .. })));
    Ok(())
}

#[test]
fn test_artifact_digest_mismatch_rejected() -> TestResult {
    let (manifest, mut artifacts) = sample_manifest_and_artifacts()?;
    // Corrupt the weights payload while retaining declared digest
    artifacts[0].payload = b"corrupted-tampered-weights".to_vec();

    let res = ModelPackage::new(manifest, artifacts);
    assert!(matches!(
        res,
        Err(ModelPackageError::ArtifactDigestMismatch { .. })
    ));
    Ok(())
}

#[test]
fn test_corrupt_archive_rejected() -> TestResult {
    let (manifest, artifacts) = sample_manifest_and_artifacts()?;
    let package = ModelPackage::new(manifest, artifacts)?;
    let mut archive_bytes = package.to_archive_bytes()?;

    let limits = ModelPackageLimits::default();

    // 1. Truncated
    assert!(matches!(
        ModelPackageArchive::decode(&archive_bytes[..10], &limits),
        Err(ModelPackageError::CorruptArchive { .. })
    ));

    // 2. Corrupt magic
    let mut bad_magic = archive_bytes.clone();
    bad_magic[0] = b'X';
    assert!(matches!(
        ModelPackageArchive::decode(&bad_magic, &limits),
        Err(ModelPackageError::CorruptArchive { .. })
    ));

    // 3. Corrupt checksum (last byte flipped)
    let last = archive_bytes.len() - 1;
    archive_bytes[last] ^= 0xFF;
    assert!(matches!(
        ModelPackageArchive::decode(&archive_bytes, &limits),
        Err(ModelPackageError::CorruptArchive { .. })
    ));

    Ok(())
}

#[test]
fn test_idempotent_reimport_and_conflict_detection() -> TestResult {
    let root = temp_dir("test_idempotent_and_conflict")?;
    let spool = sample_spool(&root.join("spool"))?;

    let (manifest, artifacts) = sample_manifest_and_artifacts()?;
    let package = ModelPackage::new(manifest.clone(), artifacts.clone())?;

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default());

    // First import succeeds
    let rec1 = importer.import_package(&package, None)?;
    assert_eq!(rec1.outcome, ImportOutcome::NewlyStaged);

    // Second import of identical package is idempotent
    let rec2 = importer.import_package(&package, None)?;
    assert_eq!(rec2.outcome, ImportOutcome::AlreadyPresent);
    assert_eq!(rec1.manifest_digest, rec2.manifest_digest);

    // Third import with same generation but different weights is a typed conflict
    let mut modified_manifest = manifest.clone();
    let new_weights = b"different-model-weights-bytes".to_vec();
    let new_weights_digest = ContentDigest::sha256(&new_weights);
    modified_manifest.weights_digest = new_weights_digest;

    let mut modified_artifacts = artifacts;
    modified_artifacts[0] = ModelPackageArtifact {
        name: "weights.bin".to_string(),
        digest: new_weights_digest,
        payload: new_weights,
    };

    let conflicting_package = ModelPackage::new(modified_manifest, modified_artifacts)?;
    let conflict_err = importer.import_package(&conflicting_package, None);

    assert!(matches!(
        conflict_err,
        Err(ModelPackageError::GenerationConflict { .. })
    ));

    Ok(())
}

#[test]
fn test_bounds_at_bound_and_bound_plus_one() -> TestResult {
    let (base_manifest, base_artifacts) = sample_manifest_and_artifacts()?;

    // 1. Artifact count bound: bound=3, bound+1=4
    let limits_3_artifacts = ModelPackageLimits {
        max_artifacts_count: 3,
        max_manifest_bytes: 1024 * 1024,
        max_artifact_bytes: 10 * 1024 * 1024,
        max_package_total_bytes: 50 * 1024 * 1024,
    };
    let pkg = ModelPackage::new(base_manifest.clone(), base_artifacts.clone())?;
    assert!(pkg.validate(&limits_3_artifacts).is_ok());

    let limits_2_artifacts = ModelPackageLimits {
        max_artifacts_count: 2,
        ..limits_3_artifacts
    };
    assert!(matches!(
        pkg.validate(&limits_2_artifacts),
        Err(ModelPackageError::BoundExceeded {
            bound: "artifact_count",
            limit: 2,
            actual: 3
        })
    ));

    // 2. Max artifact bytes bound
    let max_art_len = base_artifacts
        .iter()
        .map(|a| a.payload.len() as u64)
        .max()
        .ok_or("no artifacts")?;
    let limits_art_exact = ModelPackageLimits {
        max_artifact_bytes: max_art_len,
        ..limits_3_artifacts
    };
    assert!(pkg.validate(&limits_art_exact).is_ok());

    let limits_art_minus_one = ModelPackageLimits {
        max_artifact_bytes: max_art_len - 1,
        ..limits_3_artifacts
    };
    assert!(matches!(
        pkg.validate(&limits_art_minus_one),
        Err(ModelPackageError::BoundExceeded {
            bound: "artifact_bytes",
            ..
        })
    ));

    // 3. Max manifest bytes bound
    let manifest_len = pkg.manifest_bytes.len();
    let limits_manifest_exact = ModelPackageLimits {
        max_manifest_bytes: manifest_len,
        ..limits_3_artifacts
    };
    assert!(pkg.validate(&limits_manifest_exact).is_ok());

    let limits_manifest_minus_one = ModelPackageLimits {
        max_manifest_bytes: manifest_len - 1,
        ..limits_3_artifacts
    };
    assert!(matches!(
        pkg.validate(&limits_manifest_minus_one),
        Err(ModelPackageError::BoundExceeded {
            bound: "manifest_bytes",
            ..
        })
    ));

    // 4. Max package total bytes bound
    let total_len = pkg.total_bytes();
    let limits_tot_exact = ModelPackageLimits {
        max_package_total_bytes: total_len,
        ..limits_3_artifacts
    };
    assert!(pkg.validate(&limits_tot_exact).is_ok());

    let limits_tot_minus_one = ModelPackageLimits {
        max_package_total_bytes: total_len - 1,
        ..limits_3_artifacts
    };
    assert!(matches!(
        pkg.validate(&limits_tot_minus_one),
        Err(ModelPackageError::BoundExceeded {
            bound: "package_total_bytes",
            ..
        })
    ));

    Ok(())
}

#[test]
fn test_fault_injecting_spool_io_fail_closed() -> TestResult {
    let root = temp_dir("test_fault_injecting_fail_closed")?;
    let spool_dir = root.join("spool");

    // Fail the 1st staging file creation
    let plan = SpoolFaultPlan::new().fail(SpoolIoCall::CreateNew, 1, ErrorKind::PermissionDenied);
    let io = Arc::new(FaultInjectingSpoolIo::new(plan));
    let spool = sample_spool_with_io(&spool_dir, io)?;

    let (manifest, artifacts) = sample_manifest_and_artifacts()?;
    let package = ModelPackage::new(manifest.clone(), artifacts)?;

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default());
    let res = importer.import_package(&package, None);

    assert!(res.is_err());
    assert!(matches!(res, Err(ModelPackageError::Spool(_))));

    // Verify fail-closed: nothing admitted into the spool
    assert_eq!(importer.spool().object_count(), 0);

    Ok(())
}
