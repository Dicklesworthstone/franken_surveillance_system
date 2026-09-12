#![forbid(unsafe_code)]
//! Contract tests for offline model-package import, staging, and verification (FSS-071 / fss-x4a.14.2).

use std::error::Error;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::{CalibrationGeneration, ContentDigest, ModelGeneration, SchemaId};
use fss_object::{
    ArtifactNameViolation, DEFAULT_MAX_ARTIFACTS_COUNT, FaultInjectingSpoolIo, HostSpoolIo,
    ImportOutcome, ImportReceipt, MAX_ARTIFACT_DIGESTS_COUNT, MAX_ARTIFACT_NAME_LEN, ModelId,
    ModelLicenseRecord, ModelManifestError, ModelManifestV1, ModelPackage, ModelPackageArchive,
    ModelPackageArtifact, ModelPackageError, ModelPackageImporter, ModelPackageLimits,
    SPOOL_OBJECTS_DIR, SpoolError, SpoolFaultPlan, SpoolIo, SpoolIoCall, SpoolLimits,
    SpoolObjectState, StagingSpool,
};

type TestResult = Result<(), Box<dyn Error>>;

/// Generation every sample package carries; imports pin it explicitly.
const GENERATION: &str = "model:rfdetr:fp16:v1";

fn temp_dir(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = option_env!("CARGO_TARGET_TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
    let dir = base
        .join("fss_model_package_test")
        .join(format!("{}-{test_name}", std::process::id()));
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn sample_license(
    text_digest: ContentDigest,
    provenance: Vec<ContentDigest>,
) -> ModelLicenseRecord {
    ModelLicenseRecord {
        spdx_or_identity: "Apache-2.0".to_string(),
        text_digest: Some(text_digest),
        use_approved: true,
        restrictions: vec!["internal_evaluation_only".to_string()],
        source_identity: "https://example.com/weights".to_string(),
        artifact_digests: provenance,
        upstream_revision: Some("rev-123".to_string()),
    }
}

fn manifest_for(
    generation: &str,
    weights_digest: ContentDigest,
    license: ModelLicenseRecord,
) -> Result<ModelManifestV1, ModelManifestError> {
    ModelManifestV1::new(
        ModelId::parse("MOD-RFDETR-001")?,
        ModelGeneration::parse(generation)?,
        weights_digest,
        SchemaId::parse("fss.model_input.v1")?,
        SchemaId::parse("fss.model_output.v1")?,
        CalibrationGeneration::parse("cal:camera-rig:v1")?,
        license,
    )
}

/// The sample package for [`GENERATION`] whose weights are `weights_payload`.
fn manifest_with_weights(
    weights_payload: &[u8],
) -> Result<(ModelManifestV1, Vec<ModelPackageArtifact>), Box<dyn Error>> {
    let weights_payload = weights_payload.to_vec();
    let weights_digest = ContentDigest::sha256(&weights_payload);

    let license_payload = b"Apache-2.0 license full text terms".to_vec();
    let license_digest = ContentDigest::sha256(&license_payload);

    let part2_payload = b"model-weights-part-2-payload-v1".to_vec();
    let part2_digest = ContentDigest::sha256(&part2_payload);

    let manifest = manifest_for(
        GENERATION,
        weights_digest,
        sample_license(license_digest, vec![part2_digest]),
    )?;

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

fn sample_manifest_and_artifacts()
-> Result<(ModelManifestV1, Vec<ModelPackageArtifact>), Box<dyn Error>> {
    manifest_with_weights(b"model-weights-binary-payload-v1")
}

fn sample_package() -> Result<ModelPackage, Box<dyn Error>> {
    let (manifest, artifacts) = sample_manifest_and_artifacts()?;
    Ok(ModelPackage::new(manifest, artifacts)?)
}

/// Builds a package through its public fields, bypassing [`ModelPackage::new`] verification.
fn literal_package(
    manifest: ModelManifestV1,
    artifacts: Vec<ModelPackageArtifact>,
) -> Result<ModelPackage, Box<dyn Error>> {
    Ok(ModelPackage {
        manifest_bytes: manifest.to_canonical_bytes()?,
        manifest,
        artifacts: artifacts.into_iter().map(|art| (art.digest, art)).collect(),
    })
}

fn spool_limits() -> SpoolLimits {
    SpoolLimits::new(64, 100 * 1024 * 1024, 10 * 1024 * 1024, 64)
}

fn sample_spool(dir: &Path) -> Result<StagingSpool, Box<dyn Error>> {
    Ok(StagingSpool::open(dir, spool_limits())?)
}

fn sample_spool_with_io(dir: &Path, io: Arc<dyn SpoolIo>) -> Result<StagingSpool, Box<dyn Error>> {
    Ok(StagingSpool::open_with_io(dir, spool_limits(), io)?)
}

fn object_files_on_disk(spool_dir: &Path) -> Result<usize, Box<dyn Error>> {
    Ok(fs::read_dir(spool_dir.join(SPOOL_OBJECTS_DIR))?.count())
}

fn call_counts(io: &FaultInjectingSpoolIo) -> Vec<u64> {
    SpoolIoCall::ALL
        .iter()
        .map(|call| io.calls(*call))
        .collect()
}

fn call_index(call: SpoolIoCall) -> Result<usize, Box<dyn Error>> {
    SpoolIoCall::ALL
        .iter()
        .position(|candidate| *candidate == call)
        .ok_or_else(|| format!("{call} missing from SpoolIoCall::ALL").into())
}

/// Replaces the single occurrence of `needle` in `haystack`.
fn replace_once(
    haystack: &[u8],
    needle: &[u8],
    replacement: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let at = haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .ok_or("needle not found")?;
    let mut out = haystack.to_vec();
    out.splice(at..at + needle.len(), replacement.iter().copied());
    Ok(out)
}

/// Recomputes an archive's trailing checksum after a deliberate edit.
fn reseal(archive: &mut Vec<u8>) {
    let body_len = archive.len() - 32;
    let checksum = ContentDigest::sha256(&archive[..body_len]);
    archive.truncate(body_len);
    archive.extend_from_slice(&checksum.bytes());
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

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?;
    let receipt = importer.import_from_archive(&archive_bytes, "model:rfdetr:fp16:v1")?;

    assert_eq!(receipt.outcome, ImportOutcome::NewlyStaged);
    assert_eq!(&receipt.generation, manifest.generation());
    assert_eq!(receipt.manifest_digest, manifest.manifest_digest()?);

    // Verify all objects are currently Staged in spool, NOT yet Verified
    assert_eq!(
        importer.spool().state(manifest.manifest_digest()?),
        Some(SpoolObjectState::Staged)
    );
    assert_eq!(
        importer.spool().state(manifest.weights_digest()),
        Some(SpoolObjectState::Staged)
    );

    // Explicit verification step
    let verify_receipt = importer.verify_package(receipt.manifest_digest)?;
    assert_eq!(verify_receipt.manifest_digest, receipt.manifest_digest);
    assert_eq!(verify_receipt.generation, receipt.generation);
    assert_eq!(verify_receipt.verified_artifacts.len(), 3);

    // Verify all objects are now Verified in spool
    assert_eq!(
        importer.spool().state(manifest.manifest_digest()?),
        Some(SpoolObjectState::Verified)
    );
    assert_eq!(
        importer.spool().state(manifest.weights_digest()),
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

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?;
    let receipt = importer.import_from_directory(&package_dir, &io, GENERATION)?;

    assert_eq!(receipt.outcome, ImportOutcome::NewlyStaged);
    assert_eq!(&receipt.generation, manifest.generation());
    assert_eq!(
        importer.spool().state(manifest.manifest_digest()?),
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

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?;

    // 1. Explicit requested generation is "latest"
    let res = importer.import_from_archive(&archive_bytes, "latest");
    assert!(matches!(res, Err(ModelPackageError::LatestNotResolvable)));

    // 2. Explicit requested generation contains ":latest"
    let res2 = importer.import_from_archive(&archive_bytes, "model:detector:latest");
    assert!(matches!(res2, Err(ModelPackageError::LatestNotResolvable)));

    Ok(())
}

/// Review-526 finding 3: every spelling of `latest` is refused on every import path, and no
/// manifest naming `latest` can be built, so there is no unpinned route to one.
#[test]
fn test_import_rejects_every_latest_form() -> TestResult {
    let root = temp_dir("import_latest_forms")?;
    let package = sample_package()?;
    let archive = package.to_archive_bytes()?;
    let package_dir = root.join("pkg");
    package.write_to_directory(&package_dir, &HostSpoolIo)?;
    let mut importer = ModelPackageImporter::new(
        sample_spool(&root.join("spool"))?,
        ModelPackageLimits::default(),
    )?;
    for requested in [
        "latest",
        "LATEST",
        "Latest:v1",
        "model:latest:v1",
        "model:rfdetr:LaTeSt",
        "model:rfdetr:fp16:latest",
        "latest.weights",
        "model:rfdetr:latest:fp16:v1",
    ] {
        assert!(
            matches!(
                importer.import_package(&package, requested),
                Err(ModelPackageError::LatestNotResolvable)
            ),
            "{requested}"
        );
        assert!(
            matches!(
                importer.import_from_archive(&archive, requested),
                Err(ModelPackageError::LatestNotResolvable)
            ),
            "{requested}"
        );
        assert!(
            matches!(
                importer.import_from_directory(&package_dir, &HostSpoolIo, requested),
                Err(ModelPackageError::LatestNotResolvable)
            ),
            "{requested}"
        );
    }
    assert_eq!(importer.spool().object_count(), 0);

    let (weights, text) = (ContentDigest::sha256(b"w"), ContentDigest::sha256(b"t"));
    assert_eq!(
        manifest_for("model:latest:v1", weights, sample_license(text, Vec::new())),
        Err(ModelManifestError::LatestNotResolvable)
    );
    Ok(())
}

#[test]
fn test_generation_mismatch() -> TestResult {
    let root = temp_dir("test_gen_mismatch")?;
    let spool = sample_spool(&root.join("spool"))?;
    let (manifest, artifacts) = sample_manifest_and_artifacts()?;
    let package = ModelPackage::new(manifest, artifacts)?;
    let archive_bytes = package.to_archive_bytes()?;

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?;

    let res = importer.import_from_archive(&archive_bytes, "model:rfdetr:fp16:v2");
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
    artifacts.retain(|a| a.digest != manifest.weights_digest());

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

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?;

    // First import succeeds
    let rec1 = importer.import_package(&package, GENERATION)?;
    assert_eq!(rec1.outcome, ImportOutcome::NewlyStaged);

    // Second import of identical package is idempotent
    let rec2 = importer.import_package(&package, GENERATION)?;
    assert_eq!(rec2.outcome, ImportOutcome::AlreadyPresent);
    assert_eq!(rec1.manifest_digest, rec2.manifest_digest);

    // Third import with same generation but different weights is a typed conflict
    let (modified_manifest, modified_artifacts) =
        manifest_with_weights(b"different-model-weights-bytes")?;
    assert_eq!(modified_manifest.generation(), manifest.generation());
    let conflicting_package = ModelPackage::new(modified_manifest, modified_artifacts)?;
    let objects_before = importer.spool().object_count();
    let conflict_err = importer.import_package(&conflicting_package, GENERATION);

    assert!(matches!(
        conflict_err,
        Err(ModelPackageError::GenerationConflict { .. })
    ));
    assert_eq!(importer.spool().object_count(), objects_before);

    Ok(())
}

/// Review-526 finding 4: generation records are rebuilt from the spool, so a contradictory
/// package for an already staged generation is a typed conflict after an importer reopen.
#[test]
fn test_generation_conflict_survives_importer_reopen() -> TestResult {
    let root = temp_dir("reopen_conflict")?;
    let spool_dir = root.join("spool");
    let package1 = sample_package()?;
    let manifest1_digest = package1.manifest.manifest_digest()?;

    // Session 1: stage package 1, then drop the importer and release the spool.
    {
        let mut importer1 =
            ModelPackageImporter::new(sample_spool(&spool_dir)?, ModelPackageLimits::default())?;
        let res1 = importer1.import_package(&package1, GENERATION)?;
        assert_eq!(res1.outcome, ImportOutcome::NewlyStaged);
    }

    // Session 2: a different manifest for the same generation.
    let (manifest2, artifacts2) = manifest_with_weights(b"conflicting_weights_v2")?;
    let package2 = ModelPackage::new(manifest2, artifacts2)?;
    assert_eq!(
        package2.manifest.generation(),
        package1.manifest.generation()
    );
    let manifest2_digest = package2.manifest.manifest_digest()?;

    let mut importer2 =
        ModelPackageImporter::new(sample_spool(&spool_dir)?, ModelPackageLimits::default())?;
    assert_eq!(
        importer2.staged_manifest(package1.manifest.generation()),
        Some(manifest1_digest)
    );
    let objects_before = importer2.spool().object_count();
    let res2 = importer2.import_package(&package2, GENERATION);
    match res2 {
        Err(ModelPackageError::GenerationConflict {
            generation,
            existing_manifest,
            new_manifest,
        }) => {
            assert_eq!(&generation, package1.manifest.generation());
            assert_eq!(existing_manifest, manifest1_digest);
            assert_eq!(new_manifest, manifest2_digest);
        }
        other => {
            return Err(
                format!("importer failed to detect conflict across reopen: {other:?}").into(),
            );
        }
    }
    assert_eq!(
        importer2.spool().object_count(),
        objects_before,
        "conflicting package staged"
    );

    // The identical package stays idempotent across the reopen.
    let again = importer2.import_package(&package1, GENERATION)?;
    assert_eq!(again.outcome, ImportOutcome::AlreadyPresent);
    Ok(())
}

/// Review-526 finding 4: an importer refuses to open over a spool whose manifests already
/// contradict each other, or over a manifest-shaped object it cannot classify.
#[test]
fn test_importer_open_fails_closed_on_ambiguous_spool() -> TestResult {
    let root = temp_dir("open_ambiguous")?;
    let (manifest1, _) = sample_manifest_and_artifacts()?;
    let (manifest2, _) = manifest_with_weights(b"other-weights")?;

    let mut conflicting = sample_spool(&root.join("conflicting"))?;
    conflicting.stage_bytes(&manifest1.to_canonical_bytes()?)?;
    conflicting.stage_bytes(&manifest2.to_canonical_bytes()?)?;
    assert!(matches!(
        ModelPackageImporter::new(conflicting, ModelPackageLimits::default()),
        Err(ModelPackageError::GenerationConflict { .. })
    ));

    let mut undecodable = sample_spool(&root.join("undecodable"))?;
    let mut bytes = manifest1.to_canonical_bytes()?;
    bytes.push(0xAA);
    undecodable.stage_bytes(&bytes)?;
    assert!(matches!(
        ModelPackageImporter::new(undecodable, ModelPackageLimits::default()),
        Err(ModelPackageError::UndecodableManifestObject { .. })
    ));

    // An artifact that merely starts with the manifest magic is classified by its manifest.
    let spool_dir = root.join("magic_artifact");
    let (manifest, artifacts) = manifest_with_weights(b"FSMN-prefixed weights, not a manifest")?;
    let package = ModelPackage::new(manifest, artifacts)?;
    {
        let mut importer =
            ModelPackageImporter::new(sample_spool(&spool_dir)?, ModelPackageLimits::default())?;
        importer.import_package(&package, GENERATION)?;
    }
    let reopened =
        ModelPackageImporter::new(sample_spool(&spool_dir)?, ModelPackageLimits::default())?;
    assert_eq!(
        reopened.staged_manifest(package.manifest.generation()),
        Some(package.manifest.manifest_digest()?)
    );
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
    let total_len = pkg.total_bytes()?;
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

/// Review-526 finding 10: the default artifact-count bound is reachable by a valid package and
/// enforced at bound and bound + 1, both in memory and through the archive count field.
#[test]
fn test_default_artifact_count_bound_at_bound_and_plus_one() -> TestResult {
    assert_eq!(DEFAULT_MAX_ARTIFACTS_COUNT, 2 + MAX_ARTIFACT_DIGESTS_COUNT);
    let limits = ModelPackageLimits::default();
    let bound = DEFAULT_MAX_ARTIFACTS_COUNT as u64;

    // The largest valid package: weights, license text, and every provenance artifact.
    let weights = ModelPackageArtifact::new("weights.bin", b"bound-weights".to_vec())?;
    let text = ModelPackageArtifact::new("LICENSE.txt", b"bound-license".to_vec())?;
    let provenance = (0..MAX_ARTIFACT_DIGESTS_COUNT)
        .map(|i| {
            ModelPackageArtifact::new(format!("part-{i}.bin"), format!("part {i}").into_bytes())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let license = sample_license(
        text.digest,
        provenance.iter().map(|art| art.digest).collect(),
    );
    let manifest = manifest_for(GENERATION, weights.digest, license)?;
    let mut all = vec![weights, text];
    all.extend(provenance);
    let package = ModelPackage::new(manifest, all)?;
    assert_eq!(package.artifacts.len(), DEFAULT_MAX_ARTIFACTS_COUNT);
    package.validate(&limits)?;
    let archive = package.to_archive_bytes()?;
    assert_eq!(ModelPackageArchive::decode(&archive, &limits)?, package);

    // Bound + 1 in memory.
    let mut over = package.clone();
    let extra = ModelPackageArtifact::new("extra.bin", b"one too many".to_vec())?;
    over.artifacts.insert(extra.digest, extra);
    assert!(matches!(
        over.validate(&limits),
        Err(ModelPackageError::BoundExceeded { bound: "artifact_count", limit, actual })
            if limit == bound && actual == bound + 1
    ));

    // Bound + 1 in the archive's declared artifact count.
    let count_at = 4 + 4 + 4 + package.manifest_bytes.len();
    let mut bumped = archive.clone();
    bumped[count_at..count_at + 4].copy_from_slice(&u32::try_from(bound + 1)?.to_be_bytes());
    reseal(&mut bumped);
    assert!(matches!(
        ModelPackageArchive::decode(&bumped, &limits),
        Err(ModelPackageError::BoundExceeded { bound: "artifact_count", limit, actual })
            if limit == bound && actual == bound + 1
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

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?;
    let res = importer.import_package(&package, GENERATION);

    assert!(res.is_err());
    assert!(matches!(res, Err(ModelPackageError::Spool(_))));

    // Verify fail-closed: nothing admitted into the spool
    assert_eq!(importer.spool().object_count(), 0);

    Ok(())
}

/// Review-526 finding 1: a failure while staging the second artifact discards the first.
#[test]
fn test_partial_import_discards_staged_artifacts() -> TestResult {
    let root = temp_dir("partial_import_rollback")?;
    let spool_dir = root.join("spool");

    // Fail the 2nd staging file creation (artifact 2)
    let plan = SpoolFaultPlan::new().fail(SpoolIoCall::CreateNew, 2, ErrorKind::PermissionDenied);
    let io = Arc::new(FaultInjectingSpoolIo::new(plan));
    let spool = sample_spool_with_io(&spool_dir, io.clone())?;

    let (manifest, artifacts) = sample_manifest_and_artifacts()?;
    assert!(artifacts.len() >= 2);
    let package = ModelPackage::new(manifest, artifacts)?;

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?;
    let res = importer.import_package(&package, GENERATION);

    assert!(io.all_fired());
    assert!(
        matches!(res, Err(ModelPackageError::Spool(SpoolError::Io { .. }))),
        "{res:?}"
    );
    assert_eq!(
        importer.spool().object_count(),
        0,
        "partial import leaked staged artifacts into the spool"
    );
    assert_eq!(importer.spool().occupied_bytes()?, 0);
    assert_eq!(object_files_on_disk(&spool_dir)?, 0);

    // The rollback is on disk, not only in the in-memory index.
    drop(importer);
    let reopened = sample_spool(&spool_dir)?;
    assert_eq!(reopened.object_count(), 0);
    assert!(reopened.recovery_report().is_clean());
    Ok(())
}

/// How one faulted import ended under the all-or-nothing contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict {
    /// The import succeeded and the whole package is staged.
    Completed,
    /// The import failed and its own rollback left nothing staged.
    RolledBack,
    /// The rollback could not finish in-process; a reopened importer removed the residual or
    /// found the package complete.
    RecoveredAfterReopen,
}

/// Per-call counts around one import attempt, indexed like [`SpoolIoCall::ALL`].
struct CallWindow {
    /// Counts after importer construction, before the import.
    before: Vec<u64>,
    /// Counts after the import attempt returned.
    after: Vec<u64>,
    /// Whether the import attempt succeeded.
    succeeded: bool,
}

/// Measures the [`CallWindow`] of one import attempt under `plan`. `label` must be unique among
/// concurrently running tests.
fn import_call_window(
    label: &str,
    package: &ModelPackage,
    plan: SpoolFaultPlan,
) -> Result<CallWindow, Box<dyn Error>> {
    let root = temp_dir(label)?;
    let io = Arc::new(FaultInjectingSpoolIo::new(plan));
    let spool = sample_spool_with_io(&root.join("spool"), io.clone())?;
    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?;
    let before = call_counts(&io);
    let succeeded = importer.import_package(package, GENERATION).is_ok();
    let after = call_counts(&io);
    drop(importer);
    fs::remove_dir_all(&root)?;
    Ok(CallWindow {
        before,
        after,
        succeeded,
    })
}

/// Checks the all-or-nothing contract after one faulted import attempt.
fn assert_all_or_nothing(
    case: &str,
    outcome: Result<ImportReceipt, ModelPackageError>,
    importer: ModelPackageImporter,
    spool_dir: &Path,
    package: &ModelPackage,
) -> Result<Verdict, Box<dyn Error>> {
    let complete = package.artifacts.len() + 1;
    match outcome {
        Ok(receipt) => {
            if importer.spool().object_count() != complete
                || receipt.outcome != ImportOutcome::NewlyStaged
            {
                return Err(format!("{case}: success reported without a complete package").into());
            }
            Ok(Verdict::Completed)
        }
        Err(ModelPackageError::RollbackIncomplete { residual, .. }) => {
            if residual.is_empty() {
                return Err(format!("{case}: rollback incomplete with no residual").into());
            }
            drop(importer);
            let mut reopened =
                ModelPackageImporter::new(sample_spool(spool_dir)?, ModelPackageLimits::default())?;
            reopened.discard_residual(&residual)?;
            let count = reopened.spool().object_count();
            match reopened.staged_manifest(package.manifest.generation()) {
                Some(manifest_digest) => {
                    // The manifest is staged last, so its presence means the package is whole.
                    if count != complete {
                        return Err(format!("{case}: manifest present, {count} objects").into());
                    }
                    reopened.verify_package(manifest_digest)?;
                }
                None => {
                    if count != 0 || object_files_on_disk(spool_dir)? != 0 {
                        return Err(format!("{case}: {count} residual objects survived").into());
                    }
                }
            }
            Ok(Verdict::RecoveredAfterReopen)
        }
        Err(error) => {
            let spool = importer.spool();
            let orphan_bytes: u64 = spool.orphaned_staging().map(|orphan| orphan.bytes).sum();
            if spool.object_count() != 0
                || object_files_on_disk(spool_dir)? != 0
                || spool.occupied_bytes()? != orphan_bytes
            {
                return Err(format!("{case}: failed import ({error}) left objects staged").into());
            }
            Ok(Verdict::RolledBack)
        }
    }
}

/// Runs one faulted import per (call kind, occurrence) inside the window measured under
/// `window_plan`, and checks the all-or-nothing contract for each.
fn sweep(
    label: &str,
    package: &ModelPackage,
    window_plan: SpoolFaultPlan,
    fault: impl Fn(SpoolIoCall, u64) -> SpoolFaultPlan,
) -> Result<Vec<Verdict>, Box<dyn Error>> {
    let window_is_clean = window_plan == SpoolFaultPlan::new();
    let CallWindow {
        before,
        after,
        succeeded,
    } = import_call_window(&format!("{label}_window"), package, window_plan)?;
    if window_is_clean && !succeeded {
        return Err(format!("{label}: the unfaulted baseline import failed").into());
    }
    let root = temp_dir(label)?;
    let mut verdicts = Vec::new();
    for (index, call) in SpoolIoCall::ALL.iter().copied().enumerate() {
        for occurrence in before[index] + 1..=after[index] {
            let case = format!("{label}:{call}#{occurrence}");
            let spool_dir = root.join(format!("{call}-{occurrence}"));
            let io = Arc::new(FaultInjectingSpoolIo::new(fault(call, occurrence)));
            let spool = sample_spool_with_io(&spool_dir, io.clone())?;
            let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?;
            let outcome = importer.import_package(package, GENERATION);
            if io.fired() == 0 {
                return Err(format!("{case}: no planned fault fired").into());
            }
            verdicts.push(assert_all_or_nothing(
                &case, outcome, importer, &spool_dir, package,
            )?);
        }
    }
    fs::remove_dir_all(&root)?;
    Ok(verdicts)
}

/// Review-526 findings 1 and 10: a fault at every I/O step of an import, not only the first
/// call, leaves either the whole package or nothing.
#[test]
fn test_fault_at_every_import_step_is_all_or_nothing() -> TestResult {
    let package = sample_package()?;
    let verdicts = sweep("sweep_fail", &package, SpoolFaultPlan::new(), |call, n| {
        SpoolFaultPlan::new().fail(call, n, ErrorKind::PermissionDenied)
    })?;
    assert!(
        verdicts.len() >= 4 * 5,
        "sweep too small: {}",
        verdicts.len()
    );
    assert!(verdicts.contains(&Verdict::RolledBack));
    assert!(verdicts.contains(&Verdict::RecoveredAfterReopen));
    Ok(())
}

/// Review-526 finding 10: the same sweep with ambiguous faults, where each call takes effect on
/// the host but reports failure.
#[test]
fn test_ambiguous_fault_at_every_import_step_is_all_or_nothing() -> TestResult {
    let package = sample_package()?;
    let verdicts = sweep("sweep_after", &package, SpoolFaultPlan::new(), |call, n| {
        SpoolFaultPlan::new().fail_after_applying(call, n, ErrorKind::PermissionDenied)
    })?;
    assert!(
        verdicts.len() >= 4 * 5,
        "sweep too small: {}",
        verdicts.len()
    );
    assert!(verdicts.contains(&Verdict::RolledBack));
    assert!(verdicts.contains(&Verdict::RecoveredAfterReopen));
    Ok(())
}

/// Review-526 findings 1 and 10: with the manifest's staging failing after every artifact was
/// staged, a second fault at every later step, including each rollback step, still ends whole or
/// empty, and an unfinished rollback is typed and recoverable.
#[test]
fn test_fault_during_rollback_is_typed_and_recoverable() -> TestResult {
    let package = sample_package()?;
    let window = import_call_window("rollback_window", &package, SpoolFaultPlan::new())?;
    assert!(window.succeeded, "the unfaulted baseline import failed");
    let before = window.before;
    let manifest_create =
        before[call_index(SpoolIoCall::CreateNew)?] + package.artifacts.len() as u64 + 1;
    let fixed = move || {
        SpoolFaultPlan::new().fail(
            SpoolIoCall::CreateNew,
            manifest_create,
            ErrorKind::PermissionDenied,
        )
    };

    // Alone, the fixed fault is fully rolled back.
    let root = temp_dir("rollback_fixed")?;
    let io = Arc::new(FaultInjectingSpoolIo::new(fixed()));
    let spool_dir = root.join("spool");
    let mut importer = ModelPackageImporter::new(
        sample_spool_with_io(&spool_dir, io.clone())?,
        ModelPackageLimits::default(),
    )?;
    let outcome = importer.import_package(&package, GENERATION);
    assert!(io.all_fired());
    assert_eq!(
        assert_all_or_nothing("fixed", outcome, importer, &spool_dir, &package)?,
        Verdict::RolledBack
    );

    let verdicts = sweep("sweep_rollback", &package, fixed(), |call, n| {
        fixed().fail(call, n, ErrorKind::PermissionDenied)
    })?;
    assert!(verdicts.contains(&Verdict::RolledBack));
    assert!(
        verdicts.contains(&Verdict::RecoveredAfterReopen),
        "no rollback-step fault was exercised"
    );
    Ok(())
}

/// Review-526 finding 2: every package inconsistency is refused before the first staging call.
#[test]
fn test_every_inconsistency_rejected_before_any_staging() -> TestResult {
    let valid = sample_package()?;
    let weights_digest = valid.manifest.weights_digest();

    type Expect = fn(&ModelPackageError) -> bool;
    let mut cases: Vec<(&str, ModelPackage, Expect)> = Vec::new();

    let mut rogue = valid.clone();
    let rogue_art = ModelPackageArtifact::new("rogue.bin", b"rogue_data_not_in_manifest".to_vec())?;
    rogue.artifacts.insert(rogue_art.digest, rogue_art);
    cases.push(("rogue", rogue, |e| {
        matches!(e, ModelPackageError::ExtraArtifact { .. })
    }));

    let mut missing = valid.clone();
    missing.artifacts.remove(&weights_digest);
    cases.push(("missing", missing, |e| {
        matches!(e, ModelPackageError::MissingArtifact { .. })
    }));

    let mut tampered = valid.clone();
    if let Some(art) = tampered.artifacts.get_mut(&weights_digest) {
        art.payload = b"tampered weights".to_vec();
    }
    cases.push(("tampered", tampered, |e| {
        matches!(e, ModelPackageError::ArtifactDigestMismatch { .. })
    }));

    let mut rekeyed = valid.clone();
    let weights = rekeyed
        .artifacts
        .remove(&weights_digest)
        .ok_or("weights missing")?;
    rekeyed
        .artifacts
        .insert(ContentDigest::sha256(b"another key"), weights);
    cases.push(("rekeyed", rekeyed, |e| {
        matches!(e, ModelPackageError::ArtifactKeyMismatch { .. })
    }));

    let mut rebytes = valid.clone();
    rebytes.manifest_bytes.push(0);
    cases.push(("manifest_bytes", rebytes, |e| {
        matches!(e, ModelPackageError::ManifestBytesMismatch)
    }));

    let mut swapped = valid.clone();
    let (other_manifest, _) = manifest_with_weights(b"other weights")?;
    swapped.manifest = other_manifest;
    cases.push(("swapped_manifest", swapped, |e| {
        matches!(e, ModelPackageError::ManifestBytesMismatch)
    }));

    let mut escaping = valid.clone();
    if let Some(art) = escaping.artifacts.get_mut(&weights_digest) {
        art.name = "../escaped.bin".to_string();
    }
    cases.push(("escaping_name", escaping, |e| {
        matches!(e, ModelPackageError::InvalidArtifactName { .. })
    }));

    let mut duplicate_names = valid.clone();
    for art in duplicate_names.artifacts.values_mut() {
        art.name = "same.bin".to_string();
    }
    cases.push(("duplicate_names", duplicate_names, |e| {
        matches!(e, ModelPackageError::DuplicateArtifactName { .. })
    }));

    let root = temp_dir("verify_before_staging")?;
    for (label, package, expected) in cases {
        let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
        let spool = sample_spool_with_io(&root.join(label), io.clone())?;
        let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?;
        let before = call_counts(&io);
        let result = importer.import_package(&package, GENERATION);
        match &result {
            Err(error) if expected(error) => {}
            other => return Err(format!("{label}: unexpected outcome {other:?}").into()),
        }
        assert_eq!(
            call_counts(&io),
            before,
            "{label}: the spool was touched before verification"
        );
        assert_eq!(importer.spool().object_count(), 0, "{label}");

        // Writing the same package out is refused before any filesystem call as well.
        let write_io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
        assert!(
            package
                .write_to_directory(&root.join(format!("{label}-out")), &write_io)
                .is_err()
        );
        assert_eq!(call_counts(&write_io), vec![0; SpoolIoCall::ALL.len()]);
    }
    Ok(())
}

/// Review-526 finding 9: an artifact name must be one portable file name.
#[test]
fn test_artifact_names_reject_traversal_and_escape_forms() -> TestResult {
    use ArtifactNameViolation::{DisallowedByte, DotSegment, Empty, PathSeparator, Reserved};
    let cases: [(&str, ArtifactNameViolation); 16] = [
        ("", Empty),
        (".", DotSegment),
        ("..", DotSegment),
        ("../escaped.bin", PathSeparator),
        ("../../etc/cron.d/evil", PathSeparator),
        ("/etc/passwd", PathSeparator),
        ("weights/../../x", PathSeparator),
        ("a/b", PathSeparator),
        ("..\\evil.bin", PathSeparator),
        (
            "C:evil.bin",
            DisallowedByte {
                index: 1,
                byte: b':',
            },
        ),
        ("nul\0.bin", DisallowedByte { index: 3, byte: 0 }),
        (
            "new\nline",
            DisallowedByte {
                index: 3,
                byte: b'\n',
            },
        ),
        (
            "sp ace.bin",
            DisallowedByte {
                index: 2,
                byte: b' ',
            },
        ),
        (
            "caf\u{e9}.bin",
            DisallowedByte {
                index: 3,
                byte: 0xc3,
            },
        ),
        ("manifest.bin", Reserved),
        ("manifest.json", Reserved),
    ];
    for (name, reason) in cases {
        match ModelPackageArtifact::new(name, b"payload".to_vec()) {
            Err(ModelPackageError::InvalidArtifactName {
                name: rejected,
                reason: rejected_reason,
            }) => {
                assert_eq!(rejected, name);
                assert_eq!(rejected_reason, reason, "{name:?}");
            }
            other => return Err(format!("{name:?} was accepted: {other:?}").into()),
        }
    }

    // Length bound at bound and bound + 1.
    ModelPackageArtifact::new("a".repeat(MAX_ARTIFACT_NAME_LEN), Vec::new())?;
    assert!(matches!(
        ModelPackageArtifact::new("a".repeat(MAX_ARTIFACT_NAME_LEN + 1), Vec::new()),
        Err(ModelPackageError::InvalidArtifactName {
            reason: ArtifactNameViolation::TooLong {
                length: 256,
                maximum: 255
            },
            ..
        })
    ));

    for name in [
        "weights.bin",
        "LICENSE.txt",
        "part-2_v1+fp16.safetensors",
        "...",
    ] {
        ModelPackageArtifact::new(name, Vec::new())?;
    }

    // A package can never be built around an escaping name either.
    let (manifest, mut artifacts) = sample_manifest_and_artifacts()?;
    artifacts[0].name = "../../etc/cron.d/evil".to_string();
    assert!(matches!(
        ModelPackage::new(manifest, artifacts),
        Err(ModelPackageError::InvalidArtifactName {
            reason: ArtifactNameViolation::PathSeparator,
            ..
        })
    ));
    Ok(())
}

/// Review-526 finding 9: `write_to_directory` refuses an escaping name with a typed error
/// before it creates a directory or writes a byte, and nothing lands outside the target.
#[test]
fn test_write_to_directory_rejects_traversal_before_any_write() -> TestResult {
    let root = temp_dir("write_traversal")?;
    let target = root.join("pkg");
    let absolute = root.join("absolute-escape.bin");
    let outside = root.join("escaped.bin");
    let far_outside = root
        .parent()
        .ok_or("root has no parent")?
        .join("escaped.bin");
    for escaping in [
        "../escaped.bin".to_string(),
        "../../escaped.bin".to_string(),
        absolute.display().to_string(),
        "..".to_string(),
        String::new(),
    ] {
        let (manifest, mut artifacts) = sample_manifest_and_artifacts()?;
        artifacts[0].name = escaping.clone();
        let package = literal_package(manifest, artifacts)?;
        let io = FaultInjectingSpoolIo::new(SpoolFaultPlan::new());
        let result = package.write_to_directory(&target, &io);
        match &result {
            Err(ModelPackageError::InvalidArtifactName { name, .. }) if *name == escaping => {}
            other => return Err(format!("{escaping:?} was not refused: {other:?}").into()),
        }
        assert_eq!(
            call_counts(&io),
            vec![0; SpoolIoCall::ALL.len()],
            "filesystem touched before refusing {escaping:?}"
        );
        assert!(!target.exists());
        assert!(!outside.exists());
        assert!(!far_outside.exists());
        assert!(!absolute.exists());
    }
    Ok(())
}

/// Review-526 finding 9: a traversal name smuggled into an archive is refused on decode and
/// never reaches the spool.
#[test]
fn test_archive_with_traversal_name_rejected() -> TestResult {
    let root = temp_dir("archive_traversal")?;
    let archive = sample_package()?.to_archive_bytes()?;
    let mut tampered = replace_once(&archive, b"part2.bin", b"../p2.bin")?;
    reseal(&mut tampered);
    assert!(matches!(
        ModelPackageArchive::decode(&tampered, &ModelPackageLimits::default()),
        Err(ModelPackageError::InvalidArtifactName {
            reason: ArtifactNameViolation::PathSeparator,
            ..
        })
    ));

    let mut importer = ModelPackageImporter::new(
        sample_spool(&root.join("spool"))?,
        ModelPackageLimits::default(),
    )?;
    assert!(matches!(
        importer.import_from_archive(&tampered, GENERATION),
        Err(ModelPackageError::InvalidArtifactName { .. })
    ));
    assert_eq!(importer.spool().object_count(), 0);
    Ok(())
}

/// The rollback primitive: `discard_staged` releases exactly the charged bytes, persists the
/// removal, and never touches a verified object.
#[test]
fn test_spool_discard_staged_releases_exact_quota_and_refuses_verified() -> TestResult {
    let root = temp_dir("discard_staged")?;
    let spool_dir = root.join("spool");
    let mut spool = sample_spool(&spool_dir)?;
    let alpha = spool.stage_bytes(b"alpha")?;
    let bravo = spool.stage_bytes(b"bravo-bytes")?;
    spool.verify(bravo.digest)?;

    assert_eq!(spool.discard_staged(alpha.digest)?, alpha.payload_len);
    assert_eq!(spool.state(alpha.digest), None);
    assert_eq!(spool.occupied_bytes()?, bravo.payload_len);
    assert!(matches!(
        spool.discard_staged(bravo.digest),
        Err(SpoolError::NotDiscardable {
            state: SpoolObjectState::Verified,
            ..
        })
    ));
    assert_eq!(spool.state(bravo.digest), Some(SpoolObjectState::Verified));
    assert!(matches!(
        spool.discard_staged(alpha.digest),
        Err(SpoolError::Missing(_))
    ));

    drop(spool);
    let reopened = sample_spool(&spool_dir)?;
    assert_eq!(reopened.object_count(), 1);
    assert_eq!(reopened.state(bravo.digest), Some(SpoolObjectState::Staged));
    Ok(())
}
