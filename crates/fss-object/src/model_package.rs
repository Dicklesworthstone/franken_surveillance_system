#![forbid(unsafe_code)]
//! Offline model-package import, staging, and verifier (FSS-071 / fss-x4a.14.2).
//!
//! Provides deterministic, offline packaging, staging, and verification for model packages:
//! - Package import from local directory or archive only; strictly no network and never `"latest"`.
//! - Verification of every artifact digest against the manifest BEFORE any staging occurs.
//! - Staging through the content-addressed [`StagingSpool`](crate::StagingSpool), leaving objects
//!   in [`SpoolObjectState::Staged`](crate::SpoolObjectState::Staged) until an explicit verification step.
//! - Typed failures with never partial success: manifest/artifact digest mismatch, missing or extra
//!   artifacts, generation mismatch, oversize packages, and corrupt archives.
//! - Idempotent re-import of the exact same generation; typed conflict on same generation with different bytes.
//! - Full support for [`SpoolIo`](crate::SpoolIo) capability and [`FaultInjectingSpoolIo`](crate::FaultInjectingSpoolIo)
//!   for fail-closed behavior testing.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, ContractError, DigestAlgorithm, ModelGeneration};

use crate::model_manifest::{ModelManifestError, ModelManifestV1};
use crate::spool::{SpoolError, SpoolIo, StagingSpool};

/// Format magic header for offline model package archive (`FMPK`).
pub const MODEL_PACKAGE_ARCHIVE_MAGIC: [u8; 4] = *b"FMPK";

/// Format version for offline model package archive v1.
pub const MODEL_PACKAGE_ARCHIVE_VERSION_1: u32 = 1;

/// Default maximum allowed bytes for a model manifest in a package (1 MiB).
pub const DEFAULT_MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// Default maximum number of artifacts in a single model package.
pub const DEFAULT_MAX_ARTIFACTS_COUNT: usize = 256;

/// Default maximum allowed bytes for a single artifact in a model package (100 MiB).
pub const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 100 * 1024 * 1024;

/// Default maximum allowed total bytes for all artifacts + manifest in a model package (500 MiB).
pub const DEFAULT_MAX_PACKAGE_TOTAL_BYTES: u64 = 500 * 1024 * 1024;

/// Resource bounds and limits for model package import and verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelPackageLimits {
    /// Maximum allowed bytes for manifest file.
    pub max_manifest_bytes: usize,
    /// Maximum allowed count of distinct artifacts in package.
    pub max_artifacts_count: usize,
    /// Maximum allowed byte length for any single artifact.
    pub max_artifact_bytes: u64,
    /// Maximum allowed combined byte length for all artifacts and manifest.
    pub max_package_total_bytes: u64,
}

impl Default for ModelPackageLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: DEFAULT_MAX_MANIFEST_BYTES,
            max_artifacts_count: DEFAULT_MAX_ARTIFACTS_COUNT,
            max_artifact_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
            max_package_total_bytes: DEFAULT_MAX_PACKAGE_TOTAL_BYTES,
        }
    }
}

/// One named, digest-verified artifact in an offline model package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelPackageArtifact {
    /// Relative filename or identifier within the package.
    pub name: String,
    /// Verified content digest of the artifact payload.
    pub digest: ContentDigest,
    /// Raw payload bytes of the artifact.
    pub payload: Vec<u8>,
}

impl ModelPackageArtifact {
    /// Constructs and validates an artifact against its computed digest.
    pub fn new(name: impl Into<String>, payload: Vec<u8>) -> Self {
        let name = name.into();
        let digest = ContentDigest::sha256(&payload);
        Self {
            name,
            digest,
            payload,
        }
    }
}

/// In-memory model package containing a validated manifest and all required artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelPackage {
    /// Canonical model manifest v1.
    pub manifest: ModelManifestV1,
    /// Canonical encoded bytes of the manifest.
    pub manifest_bytes: Vec<u8>,
    /// All package artifacts indexed by content digest.
    pub artifacts: BTreeMap<ContentDigest, ModelPackageArtifact>,
}

impl ModelPackage {
    /// Creates and verifies a model package from a manifest and list of artifacts.
    ///
    /// Validates:
    /// - Every artifact payload matches its declared digest.
    /// - Every expected artifact from the manifest (weights, license text, license artifacts) is present.
    /// - No extraneous artifacts are included.
    pub fn new(
        manifest: ModelManifestV1,
        artifacts_list: Vec<ModelPackageArtifact>,
    ) -> Result<Self, ModelPackageError> {
        manifest.validate().map_err(ModelPackageError::Manifest)?;

        // Verify each artifact's content digest internally
        let mut artifacts = BTreeMap::new();
        for art in artifacts_list {
            let computed = ContentDigest::sha256(&art.payload);
            if computed != art.digest {
                return Err(ModelPackageError::ArtifactDigestMismatch {
                    name: art.name,
                    expected: art.digest,
                    computed,
                });
            }
            if artifacts.insert(art.digest, art).is_some() {
                // Duplicate digest in artifacts list
                return Err(ModelPackageError::CorruptArchive {
                    detail: "duplicate artifact digest in package".to_string(),
                });
            }
        }

        // Expected set of digests from manifest
        let expected_digests = collect_expected_digests(&manifest);

        // Check for missing artifacts
        for expected in &expected_digests {
            if !artifacts.contains_key(expected) {
                return Err(ModelPackageError::MissingArtifact { digest: *expected });
            }
        }

        // Check for extra artifacts
        for (actual_digest, art) in &artifacts {
            if !expected_digests.contains(actual_digest) {
                return Err(ModelPackageError::ExtraArtifact {
                    name: art.name.clone(),
                    digest: *actual_digest,
                });
            }
        }

        let manifest_bytes = manifest.to_canonical_bytes();

        Ok(Self {
            manifest,
            manifest_bytes,
            artifacts,
        })
    }

    /// Validates package size bounds against configured limits.
    pub fn validate(&self, limits: &ModelPackageLimits) -> Result<(), ModelPackageError> {
        if self.manifest_bytes.len() > limits.max_manifest_bytes {
            return Err(ModelPackageError::BoundExceeded {
                bound: "manifest_bytes",
                limit: limits.max_manifest_bytes as u64,
                actual: self.manifest_bytes.len() as u64,
            });
        }
        if self.artifacts.len() > limits.max_artifacts_count {
            return Err(ModelPackageError::BoundExceeded {
                bound: "artifact_count",
                limit: limits.max_artifacts_count as u64,
                actual: self.artifacts.len() as u64,
            });
        }
        let mut total_bytes = self.manifest_bytes.len() as u64;
        for art in self.artifacts.values() {
            let art_len = art.payload.len() as u64;
            if art_len > limits.max_artifact_bytes {
                return Err(ModelPackageError::BoundExceeded {
                    bound: "artifact_bytes",
                    limit: limits.max_artifact_bytes,
                    actual: art_len,
                });
            }
            total_bytes = total_bytes
                .checked_add(art_len)
                .ok_or(ModelPackageError::AccountingOverflow)?;
            if total_bytes > limits.max_package_total_bytes {
                return Err(ModelPackageError::BoundExceeded {
                    bound: "package_total_bytes",
                    limit: limits.max_package_total_bytes,
                    actual: total_bytes,
                });
            }
        }
        Ok(())
    }

    /// Combined byte length of all artifacts and the manifest.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        let mut sum = self.manifest_bytes.len() as u64;
        for art in self.artifacts.values() {
            sum = sum.saturating_add(art.payload.len() as u64);
        }
        sum
    }

    /// Serializes the model package into a self-verifying canonical binary archive (`FMPK` v1).
    pub fn to_archive_bytes(&self) -> Result<Vec<u8>, ModelPackageError> {
        ModelPackageArchive::encode(self)
    }

    /// Writes this package into a local directory using the provided `SpoolIo` capability.
    pub fn write_to_directory(
        &self,
        dir_path: &Path,
        io: &dyn SpoolIo,
    ) -> Result<(), ModelPackageError> {
        io.create_dir_all(dir_path)
            .map_err(|e| ModelPackageError::Io {
                operation: "create_dir_all",
                path: dir_path.to_path_buf(),
                kind: e.kind(),
            })?;

        // Write manifest.bin
        let manifest_path = dir_path.join("manifest.bin");
        let mut m_file = io
            .create_new(&manifest_path)
            .map_err(|e| ModelPackageError::Io {
                operation: "create_new",
                path: manifest_path.clone(),
                kind: e.kind(),
            })?;
        io.write(&mut m_file, &self.manifest_bytes)
            .map_err(|e| ModelPackageError::Io {
                operation: "write",
                path: manifest_path.clone(),
                kind: e.kind(),
            })?;
        io.sync_file(&m_file).map_err(|e| ModelPackageError::Io {
            operation: "sync_file",
            path: manifest_path,
            kind: e.kind(),
        })?;

        // Write each artifact
        for art in self.artifacts.values() {
            let art_path = dir_path.join(&art.name);
            let mut a_file = io
                .create_new(&art_path)
                .map_err(|e| ModelPackageError::Io {
                    operation: "create_new",
                    path: art_path.clone(),
                    kind: e.kind(),
                })?;
            io.write(&mut a_file, &art.payload)
                .map_err(|e| ModelPackageError::Io {
                    operation: "write",
                    path: art_path.clone(),
                    kind: e.kind(),
                })?;
            io.sync_file(&a_file).map_err(|e| ModelPackageError::Io {
                operation: "sync_file",
                path: art_path,
                kind: e.kind(),
            })?;
        }

        io.sync_directory(dir_path)
            .map_err(|e| ModelPackageError::Io {
                operation: "sync_directory",
                path: dir_path.to_path_buf(),
                kind: e.kind(),
            })?;

        Ok(())
    }

    /// Reads and verifies a model package from a local directory using the provided `SpoolIo` capability.
    pub fn from_directory(
        dir_path: &Path,
        io: &dyn SpoolIo,
        limits: &ModelPackageLimits,
    ) -> Result<Self, ModelPackageError> {
        let mut read_dir = io.read_dir(dir_path).map_err(|e| ModelPackageError::Io {
            operation: "read_dir",
            path: dir_path.to_path_buf(),
            kind: e.kind(),
        })?;

        let mut manifest_bytes: Option<Vec<u8>> = None;
        let mut artifact_entries: Vec<(String, Vec<u8>)> = Vec::new();

        while let Some(entry_res) = io.next_dir_entry(&mut read_dir) {
            let entry = entry_res.map_err(|e| ModelPackageError::Io {
                operation: "next_dir_entry",
                path: dir_path.to_path_buf(),
                kind: e.kind(),
            })?;
            let file_type = io
                .entry_file_type(&entry)
                .map_err(|e| ModelPackageError::Io {
                    operation: "entry_file_type",
                    path: entry.path(),
                    kind: e.kind(),
                })?;
            if !file_type.is_file() {
                continue;
            }

            let file_name = entry.file_name().to_string_lossy().to_string();
            let file_path = entry.path();

            let mut file = io
                .open_read(&file_path)
                .map_err(|e| ModelPackageError::Io {
                    operation: "open_read",
                    path: file_path.clone(),
                    kind: e.kind(),
                })?;

            // Read up to limit + 1 to detect over-limit files
            let max_read = limits.max_artifact_bytes.saturating_add(1);
            let content =
                io.read_bounded(&mut file, max_read)
                    .map_err(|e| ModelPackageError::Io {
                        operation: "read_bounded",
                        path: file_path,
                        kind: e.kind(),
                    })?;

            if file_name == "manifest.bin" || file_name == "manifest.json" {
                if manifest_bytes.is_some() {
                    return Err(ModelPackageError::CorruptArchive {
                        detail: "multiple manifest files found in directory".to_string(),
                    });
                }
                manifest_bytes = Some(content);
            } else {
                artifact_entries.push((file_name, content));
            }
        }

        let m_bytes = manifest_bytes.ok_or_else(|| ModelPackageError::CorruptArchive {
            detail: "manifest file (manifest.bin or manifest.json) not found in directory"
                .to_string(),
        })?;

        let manifest = if m_bytes.starts_with(&crate::model_manifest::MODEL_MANIFEST_MAGIC) {
            ModelManifestV1::from_canonical_bytes(&m_bytes).map_err(ModelPackageError::Manifest)?
        } else {
            let json_str =
                std::str::from_utf8(&m_bytes).map_err(|_| ModelPackageError::CorruptArchive {
                    detail: "invalid utf-8 in manifest.json".to_string(),
                })?;
            ModelManifestV1::from_canonical_json(json_str).map_err(ModelPackageError::Manifest)?
        };

        let mut artifacts = Vec::with_capacity(artifact_entries.len());
        for (name, payload) in artifact_entries {
            let art = ModelPackageArtifact::new(name, payload);
            artifacts.push(art);
        }

        let package = Self::new(manifest, artifacts)?;
        package.validate(limits)?;
        Ok(package)
    }
}

fn collect_expected_digests(manifest: &ModelManifestV1) -> BTreeSet<ContentDigest> {
    let mut set = BTreeSet::new();
    set.insert(manifest.weights_digest);
    if let Some(td) = manifest.license.text_digest {
        set.insert(td);
    }
    for ad in &manifest.license.artifact_digests {
        set.insert(*ad);
    }
    set
}

/// Offline model package archive encoder and decoder (`FMPK` format).
pub struct ModelPackageArchive;

impl ModelPackageArchive {
    /// Encodes a `ModelPackage` into self-verifying archive bytes.
    pub fn encode(package: &ModelPackage) -> Result<Vec<u8>, ModelPackageError> {
        let mut buf = Vec::new();

        // Magic and version
        buf.extend_from_slice(&MODEL_PACKAGE_ARCHIVE_MAGIC);
        buf.extend_from_slice(&MODEL_PACKAGE_ARCHIVE_VERSION_1.to_be_bytes());

        // Manifest bytes
        let m_len = u32::try_from(package.manifest_bytes.len())
            .map_err(|_| ModelPackageError::AccountingOverflow)?;
        buf.extend_from_slice(&m_len.to_be_bytes());
        buf.extend_from_slice(&package.manifest_bytes);

        // Artifacts
        let art_count = u32::try_from(package.artifacts.len())
            .map_err(|_| ModelPackageError::AccountingOverflow)?;
        buf.extend_from_slice(&art_count.to_be_bytes());

        for art in package.artifacts.values() {
            let name_bytes = art.name.as_bytes();
            let n_len = u16::try_from(name_bytes.len())
                .map_err(|_| ModelPackageError::AccountingOverflow)?;
            buf.extend_from_slice(&n_len.to_be_bytes());
            buf.extend_from_slice(name_bytes);

            buf.extend_from_slice(&art.digest.bytes());

            let p_len = u64::try_from(art.payload.len())
                .map_err(|_| ModelPackageError::AccountingOverflow)?;
            buf.extend_from_slice(&p_len.to_be_bytes());
            buf.extend_from_slice(&art.payload);
        }

        // Trailing checksum over all preceding archive bytes
        let checksum = ContentDigest::sha256(&buf);
        buf.extend_from_slice(&checksum.bytes());

        Ok(buf)
    }

    /// Decodes and verifies a `ModelPackage` from archive bytes.
    pub fn decode(
        bytes: &[u8],
        limits: &ModelPackageLimits,
    ) -> Result<ModelPackage, ModelPackageError> {
        // Minimum header: magic (4) + version (4) + manifest_len (4) + art_count (4) + checksum (32) = 48 bytes
        if bytes.len() < 48 {
            return Err(ModelPackageError::CorruptArchive {
                detail: format!("archive length too short: {}", bytes.len()),
            });
        }

        if bytes[0..4] != MODEL_PACKAGE_ARCHIVE_MAGIC {
            return Err(ModelPackageError::CorruptArchive {
                detail: format!("invalid archive magic: {:?}", &bytes[0..4]),
            });
        }

        let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if version != MODEL_PACKAGE_ARCHIVE_VERSION_1 {
            return Err(ModelPackageError::CorruptArchive {
                detail: format!("unsupported archive version: {version}"),
            });
        }

        // Verify trailing checksum
        let payload_len = bytes.len() - 32;
        let expected_checksum = ContentDigest::sha256(&bytes[..payload_len]);
        let stored_bytes: [u8; 32] =
            bytes[payload_len..]
                .try_into()
                .map_err(|_| ModelPackageError::CorruptArchive {
                    detail: "invalid checksum length".to_string(),
                })?;
        let stored_checksum = ContentDigest::new(DigestAlgorithm::Sha256, stored_bytes);

        if expected_checksum != stored_checksum {
            return Err(ModelPackageError::CorruptArchive {
                detail: "archive trailing checksum mismatch".to_string(),
            });
        }

        let mut offset = 8;

        // Read manifest length
        if offset + 4 > payload_len {
            return Err(ModelPackageError::CorruptArchive {
                detail: "truncated manifest length".to_string(),
            });
        }
        let m_len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;

        if m_len > limits.max_manifest_bytes {
            return Err(ModelPackageError::BoundExceeded {
                bound: "manifest_bytes",
                limit: limits.max_manifest_bytes as u64,
                actual: m_len as u64,
            });
        }

        if offset + m_len > payload_len {
            return Err(ModelPackageError::CorruptArchive {
                detail: "truncated manifest payload".to_string(),
            });
        }
        let manifest_bytes = bytes[offset..offset + m_len].to_vec();
        offset += m_len;

        let manifest = ModelManifestV1::from_canonical_bytes(&manifest_bytes)
            .map_err(ModelPackageError::Manifest)?;

        // Read artifacts count
        if offset + 4 > payload_len {
            return Err(ModelPackageError::CorruptArchive {
                detail: "truncated artifact count".to_string(),
            });
        }
        let art_count = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;

        if art_count > limits.max_artifacts_count {
            return Err(ModelPackageError::BoundExceeded {
                bound: "artifact_count",
                limit: limits.max_artifacts_count as u64,
                actual: art_count as u64,
            });
        }

        let mut artifacts = Vec::with_capacity(art_count);
        for _ in 0..art_count {
            if offset + 2 > payload_len {
                return Err(ModelPackageError::CorruptArchive {
                    detail: "truncated artifact name length".to_string(),
                });
            }
            let n_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2;

            if offset + n_len > payload_len {
                return Err(ModelPackageError::CorruptArchive {
                    detail: "truncated artifact name".to_string(),
                });
            }
            let name = std::str::from_utf8(&bytes[offset..offset + n_len])
                .map_err(|_| ModelPackageError::CorruptArchive {
                    detail: "invalid utf-8 in artifact name".to_string(),
                })?
                .to_string();
            offset += n_len;

            if offset + 32 > payload_len {
                return Err(ModelPackageError::CorruptArchive {
                    detail: "truncated artifact digest".to_string(),
                });
            }
            let digest_bytes: [u8; 32] = bytes[offset..offset + 32].try_into().map_err(|_| {
                ModelPackageError::CorruptArchive {
                    detail: "invalid artifact digest length".to_string(),
                }
            })?;
            let declared_digest = ContentDigest::new(DigestAlgorithm::Sha256, digest_bytes);
            offset += 32;

            if offset + 8 > payload_len {
                return Err(ModelPackageError::CorruptArchive {
                    detail: "truncated artifact payload length".to_string(),
                });
            }
            let p_len = u64::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
            offset += 8;

            if p_len > limits.max_artifact_bytes {
                return Err(ModelPackageError::BoundExceeded {
                    bound: "artifact_bytes",
                    limit: limits.max_artifact_bytes,
                    actual: p_len,
                });
            }

            let p_len_usize =
                usize::try_from(p_len).map_err(|_| ModelPackageError::BoundExceeded {
                    bound: "artifact_bytes",
                    limit: limits.max_artifact_bytes,
                    actual: p_len,
                })?;

            if offset + p_len_usize > payload_len {
                return Err(ModelPackageError::CorruptArchive {
                    detail: "truncated artifact payload".to_string(),
                });
            }
            let payload = bytes[offset..offset + p_len_usize].to_vec();
            offset += p_len_usize;

            artifacts.push(ModelPackageArtifact {
                name,
                digest: declared_digest,
                payload,
            });
        }

        if offset != payload_len {
            return Err(ModelPackageError::CorruptArchive {
                detail: format!(
                    "extra trailing bytes in archive payload: {} bytes",
                    payload_len - offset
                ),
            });
        }

        let package = ModelPackage::new(manifest, artifacts)?;
        package.validate(limits)?;
        Ok(package)
    }
}

/// Outcome of a model package import.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportOutcome {
    /// Newly staged objects written into the staging spool.
    NewlyStaged,
    /// Identical generation with identical manifest and artifacts already present in spool.
    AlreadyPresent,
}

/// Receipt returned upon successful package import and staging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportReceipt {
    /// Content digest of the staged manifest.
    pub manifest_digest: ContentDigest,
    /// Model generation identity.
    pub generation: ModelGeneration,
    /// Outcome (newly staged vs already present).
    pub outcome: ImportOutcome,
    /// Staged artifact content digests.
    pub staged_artifacts: Vec<ContentDigest>,
    /// Total bytes staged.
    pub total_staged_bytes: u64,
}

/// Receipt returned upon successful package verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReceipt {
    /// Content digest of the verified manifest.
    pub manifest_digest: ContentDigest,
    /// Model generation identity.
    pub generation: ModelGeneration,
    /// Content digests of all verified artifacts.
    pub verified_artifacts: Vec<ContentDigest>,
    /// Total verified payload bytes.
    pub total_verified_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StagedGenerationRecord {
    manifest_digest: ContentDigest,
    artifact_digests: Vec<ContentDigest>,
    total_bytes: u64,
}

/// Importer and verifier for offline model packages over a [`StagingSpool`].
pub struct ModelPackageImporter {
    spool: StagingSpool,
    limits: ModelPackageLimits,
    staged_generations: BTreeMap<ModelGeneration, StagedGenerationRecord>,
}

impl ModelPackageImporter {
    /// Constructs a new importer over the specified staging spool.
    pub fn new(spool: StagingSpool, limits: ModelPackageLimits) -> Self {
        Self {
            spool,
            limits,
            staged_generations: BTreeMap::new(),
        }
    }

    /// Read-only access to the underlying staging spool.
    #[must_use]
    pub fn spool(&self) -> &StagingSpool {
        &self.spool
    }

    /// Mutable access to the underlying staging spool.
    pub fn spool_mut(&mut self) -> &mut StagingSpool {
        &mut self.spool
    }

    /// Configured limits for package operations.
    #[must_use]
    pub const fn limits(&self) -> ModelPackageLimits {
        self.limits
    }

    /// Imports a model package from raw archive bytes into the staging spool.
    pub fn import_from_archive(
        &mut self,
        archive_bytes: &[u8],
        expected_generation: Option<&str>,
    ) -> Result<ImportReceipt, ModelPackageError> {
        let package = ModelPackageArchive::decode(archive_bytes, &self.limits)?;
        self.import_package(&package, expected_generation)
    }

    /// Imports a model package from a local directory into the staging spool.
    pub fn import_from_directory(
        &mut self,
        dir_path: &Path,
        io: &dyn SpoolIo,
        expected_generation: Option<&str>,
    ) -> Result<ImportReceipt, ModelPackageError> {
        let package = ModelPackage::from_directory(dir_path, io, &self.limits)?;
        self.import_package(&package, expected_generation)
    }

    /// Imports and stages a validated `ModelPackage`.
    ///
    /// Sequence:
    /// 1. Reject any request attempting to resolve `"latest"`.
    /// 2. If `expected_generation` is given, assert it matches `package.manifest.generation`.
    /// 3. Validate package bounds.
    /// 4. Check for existing import of this generation:
    ///    - If same generation with identical manifest digest & artifacts: returns `AlreadyPresent` (idempotent).
    ///    - If same generation with differing manifest or artifacts: returns `GenerationConflict`.
    /// 5. Stage each artifact through `StagingSpool::stage`.
    /// 6. Stage the manifest through `StagingSpool::stage`.
    /// 7. Record staged generation state. Objects remain in `SpoolObjectState::Staged` (not `Verified`).
    pub fn import_package(
        &mut self,
        package: &ModelPackage,
        expected_generation: Option<&str>,
    ) -> Result<ImportReceipt, ModelPackageError> {
        // Enforce anti-latest rule
        if let Some(req_gen) = expected_generation {
            if req_gen == "latest"
                || req_gen == "LATEST"
                || req_gen.starts_with("latest:")
                || req_gen.ends_with(":latest")
                || req_gen == "latest.weights"
            {
                return Err(ModelPackageError::LatestNotResolvable);
            }
            let parsed_expected =
                ModelGeneration::parse(req_gen).map_err(ModelPackageError::Contract)?;
            if parsed_expected != package.manifest.generation {
                return Err(ModelPackageError::GenerationMismatch {
                    expected: parsed_expected,
                    actual: package.manifest.generation.clone(),
                });
            }
        }

        // Package validation against limits
        package.validate(&self.limits)?;

        let manifest_digest = package.manifest.manifest_digest();
        let generation = package.manifest.generation.clone();

        let mut artifact_digests: Vec<ContentDigest> = package.artifacts.keys().copied().collect();
        artifact_digests.sort();

        // Check for idempotent re-import or typed conflict
        if let Some(existing) = self.staged_generations.get(&generation) {
            if existing.manifest_digest == manifest_digest
                && existing.artifact_digests == artifact_digests
            {
                return Ok(ImportReceipt {
                    manifest_digest,
                    generation,
                    outcome: ImportOutcome::AlreadyPresent,
                    staged_artifacts: artifact_digests,
                    total_staged_bytes: existing.total_bytes,
                });
            } else {
                return Err(ModelPackageError::GenerationConflict {
                    generation,
                    existing_manifest: existing.manifest_digest,
                    new_manifest: manifest_digest,
                });
            }
        }

        // Stage all artifacts through spool
        let mut total_staged = 0u64;
        for art in package.artifacts.values() {
            let receipt = self
                .spool
                .stage(art.digest, &art.payload)
                .map_err(ModelPackageError::Spool)?;
            total_staged = total_staged
                .checked_add(receipt.payload_len)
                .ok_or(ModelPackageError::AccountingOverflow)?;
        }

        // Stage manifest through spool
        let manifest_receipt = self
            .spool
            .stage(manifest_digest, &package.manifest_bytes)
            .map_err(ModelPackageError::Spool)?;
        total_staged = total_staged
            .checked_add(manifest_receipt.payload_len)
            .ok_or(ModelPackageError::AccountingOverflow)?;

        // Record in staged generations
        self.staged_generations.insert(
            generation.clone(),
            StagedGenerationRecord {
                manifest_digest,
                artifact_digests: artifact_digests.clone(),
                total_bytes: total_staged,
            },
        );

        Ok(ImportReceipt {
            manifest_digest,
            generation,
            outcome: ImportOutcome::NewlyStaged,
            staged_artifacts: artifact_digests,
            total_staged_bytes: total_staged,
        })
    }

    /// Verifies all objects associated with a staged model package.
    ///
    /// Reads and rehashes the manifest and each referenced artifact from disk,
    /// transitioning their states in the spool from `Staged` to `Verified`.
    pub fn verify_package(
        &mut self,
        manifest_digest: ContentDigest,
    ) -> Result<VerificationReceipt, ModelPackageError> {
        // Verify manifest object in spool
        self.spool
            .verify(manifest_digest)
            .map_err(ModelPackageError::Spool)?;

        let manifest_bytes = self
            .spool
            .read(manifest_digest)
            .map_err(ModelPackageError::Spool)?;
        let manifest = ModelManifestV1::from_canonical_bytes(&manifest_bytes)
            .map_err(ModelPackageError::Manifest)?;

        let mut verified_artifacts = Vec::new();
        let mut total_verified_bytes = manifest_bytes.len() as u64;

        let expected_digests = collect_expected_digests(&manifest);
        for digest in expected_digests {
            self.spool
                .verify(digest)
                .map_err(ModelPackageError::Spool)?;
            let art_bytes = self.spool.read(digest).map_err(ModelPackageError::Spool)?;
            total_verified_bytes = total_verified_bytes
                .checked_add(art_bytes.len() as u64)
                .ok_or(ModelPackageError::AccountingOverflow)?;
            verified_artifacts.push(digest);
        }

        Ok(VerificationReceipt {
            manifest_digest,
            generation: manifest.generation,
            verified_artifacts,
            total_verified_bytes,
        })
    }
}

/// Errors returned during model package import, staging, and verification.
#[derive(Debug)]
pub enum ModelPackageError {
    /// Manifest validation or parsing error.
    Manifest(ModelManifestError),
    /// Computed artifact content digest does not match declared digest.
    ArtifactDigestMismatch {
        /// Artifact filename or identifier.
        name: String,
        /// Declared digest in package or manifest.
        expected: ContentDigest,
        /// Computed digest from bytes.
        computed: ContentDigest,
    },
    /// An expected artifact declared in the manifest was missing from the package.
    MissingArtifact {
        /// Missing artifact content digest.
        digest: ContentDigest,
    },
    /// An unexpected extra artifact was found in the package.
    ExtraArtifact {
        /// Extraneous artifact name.
        name: String,
        /// Extraneous artifact content digest.
        digest: ContentDigest,
    },
    /// Requested model generation does not match the package manifest's generation.
    GenerationMismatch {
        /// Expected generation requested by caller.
        expected: ModelGeneration,
        /// Actual generation in package manifest.
        actual: ModelGeneration,
    },
    /// Re-importing a generation with conflicting bytes or manifest.
    GenerationConflict {
        /// Conflicted model generation identifier.
        generation: ModelGeneration,
        /// Staged manifest digest already on record.
        existing_manifest: ContentDigest,
        /// New manifest digest presented for import.
        new_manifest: ContentDigest,
    },
    /// Attempt to resolve `"latest"`, which is strictly forbidden by system policy.
    LatestNotResolvable,
    /// Model package archive is corrupted or malformed.
    CorruptArchive {
        /// Error description.
        detail: String,
    },
    /// A configured resource bound or limit was exceeded.
    BoundExceeded {
        /// Name of the bound.
        bound: &'static str,
        /// Maximum allowed limit.
        limit: u64,
        /// Actual observed value.
        actual: u64,
    },
    /// Arithmetic accounting overflow.
    AccountingOverflow,
    /// Error from the underlying staging spool.
    Spool(SpoolError),
    /// I/O error from the filesystem capability.
    Io {
        /// Operation that failed.
        operation: &'static str,
        /// Target path.
        path: PathBuf,
        /// Kind of I/O error.
        kind: io::ErrorKind,
    },
    /// Core semantic contract error.
    Contract(ContractError),
}

impl fmt::Display for ModelPackageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(err) => write!(f, "manifest error: {err}"),
            Self::ArtifactDigestMismatch {
                name,
                expected,
                computed,
            } => {
                write!(
                    f,
                    "artifact digest mismatch for '{name}': expected {expected}, computed {computed}"
                )
            }
            Self::MissingArtifact { digest } => {
                write!(f, "missing artifact declared in manifest: {digest}")
            }
            Self::ExtraArtifact { name, digest } => {
                write!(
                    f,
                    "extra unmanifested artifact '{name}' with digest {digest}"
                )
            }
            Self::GenerationMismatch { expected, actual } => {
                write!(
                    f,
                    "generation mismatch: expected '{expected}', found '{actual}'"
                )
            }
            Self::GenerationConflict {
                generation,
                existing_manifest,
                new_manifest,
            } => {
                write!(
                    f,
                    "generation conflict for '{generation}': existing manifest {existing_manifest}, new manifest {new_manifest}"
                )
            }
            Self::LatestNotResolvable => {
                write!(
                    f,
                    "resolution of 'latest' is forbidden: model weights must be pinned to explicit immutable generations"
                )
            }
            Self::CorruptArchive { detail } => write!(f, "corrupt model package archive: {detail}"),
            Self::BoundExceeded {
                bound,
                limit,
                actual,
            } => {
                write!(
                    f,
                    "model package bound '{bound}' exceeded: limit={limit}, actual={actual}"
                )
            }
            Self::AccountingOverflow => write!(f, "accounting overflow in model package sizing"),
            Self::Spool(err) => write!(f, "spool error: {err}"),
            Self::Io {
                operation,
                path,
                kind,
            } => {
                write!(
                    f,
                    "io error during '{operation}' on {}: {kind:?}",
                    path.display()
                )
            }
            Self::Contract(err) => write!(f, "contract error: {err}"),
        }
    }
}

impl Error for ModelPackageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Manifest(err) => Some(err),
            Self::Spool(err) => Some(err),
            Self::Contract(err) => Some(err),
            _ => None,
        }
    }
}

impl From<ModelManifestError> for ModelPackageError {
    fn from(err: ModelManifestError) -> Self {
        Self::Manifest(err)
    }
}

impl From<SpoolError> for ModelPackageError {
    fn from(err: SpoolError) -> Self {
        Self::Spool(err)
    }
}

impl From<ContractError> for ModelPackageError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}
