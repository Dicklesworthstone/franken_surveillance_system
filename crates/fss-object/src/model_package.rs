#![forbid(unsafe_code)]
//! Offline model-package import, staging, and verifier (FSS-071 / fss-x4a.14.2).
//!
//! Provides deterministic, offline packaging, staging, and verification for model packages:
//! - Package import from a local directory or archive only; strictly no network and never
//!   `latest`: every import names the exact generation it expects.
//! - Every artifact name, artifact digest, manifest byte, and manifest/artifact correspondence is
//!   verified BEFORE the first byte is staged.
//! - Staging through the content-addressed [`StagingSpool`](crate::StagingSpool), leaving objects
//!   in [`SpoolObjectState::Staged`](crate::SpoolObjectState::Staged) until an explicit
//!   verification step. The manifest is staged last, so a manifest in the spool implies that
//!   every artifact it names was staged before it.
//! - All-or-nothing import: a failure after staging began discards every object this import
//!   newly staged. When the spool cannot finish that rollback (for example because an
//!   indeterminate ingest poisoned it), [`ModelPackageError::RollbackIncomplete`] names every
//!   object that may remain, and [`ModelPackageImporter::discard_residual`] on a reopened spool
//!   removes them.
//! - Idempotent re-import of the exact same generation; typed conflict for the same generation
//!   with different bytes, including across importer reopens, because generations are rebuilt
//!   from the manifests already present in the spool.
//! - Artifact names are single portable path components that are also valid, distinct file names
//!   on Windows and case-insensitive filesystems, so writing a package directory can never escape
//!   its target directory, open a device, or make two artifacts alias one file.
//! - Full support for [`SpoolIo`](crate::SpoolIo) capability and
//!   [`FaultInjectingSpoolIo`](crate::FaultInjectingSpoolIo) for fail-closed behavior testing.

use core::fmt;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsStr;
use std::io;
use std::iter;
use std::path::{Component, Path, PathBuf};

use fss_core::{ContentDigest, ContractError, DigestAlgorithm, ModelGeneration};

use crate::model_manifest::{
    MAX_ARTIFACT_DIGESTS_COUNT, MODEL_MANIFEST_MAGIC, ModelManifestError, ModelManifestV1,
};
use crate::spool::{SpoolError, SpoolIo, StageOutcome, StagePhase, StagingSpool};

/// Format magic header for offline model package archive (`FMPK`).
pub const MODEL_PACKAGE_ARCHIVE_MAGIC: [u8; 4] = *b"FMPK";

/// Format version for offline model package archive v1.
pub const MODEL_PACKAGE_ARCHIVE_VERSION_1: u32 = 1;

/// Default maximum allowed bytes for a model manifest in a package (1 MiB).
pub const DEFAULT_MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// Default maximum number of artifacts in a single model package.
///
/// A valid manifest names at most the weights, the license text, and
/// [`MAX_ARTIFACT_DIGESTS_COUNT`] provenance artifacts, so this is the largest count a valid
/// package can reach. A larger default would be a bound no valid package could ever meet.
pub const DEFAULT_MAX_ARTIFACTS_COUNT: usize = 2 + MAX_ARTIFACT_DIGESTS_COUNT;

/// Default maximum allowed bytes for a single artifact in a model package (100 MiB).
pub const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 100 * 1024 * 1024;

/// Default maximum allowed total bytes for all artifacts + manifest in a model package (500 MiB).
pub const DEFAULT_MAX_PACKAGE_TOTAL_BYTES: u64 = 500 * 1024 * 1024;

/// Maximum byte length of one artifact name, which is exactly one portable file name.
pub const MAX_ARTIFACT_NAME_LEN: usize = 255;

/// File name of the binary manifest in a package directory; never usable as an artifact name.
pub const PACKAGE_MANIFEST_BIN: &str = "manifest.bin";

/// File name of the JSON manifest in a package directory; never usable as an artifact name.
pub const PACKAGE_MANIFEST_JSON: &str = "manifest.json";

/// Byte length of the trailing archive checksum.
const ARCHIVE_CHECKSUM_LEN: usize = 32;

/// Smallest archive: magic, version, manifest length, artifact count, and checksum.
const ARCHIVE_MIN_LEN: usize = 4 + 4 + 4 + 4 + ARCHIVE_CHECKSUM_LEN;

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

/// Why an artifact name cannot be used as one file name inside a package directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactNameViolation {
    /// The name is empty.
    Empty,
    /// The name exceeds [`MAX_ARTIFACT_NAME_LEN`] bytes.
    TooLong {
        /// Observed byte length.
        length: usize,
        /// Maximum byte length.
        maximum: usize,
    },
    /// The name consists only of dots (`.`, `..`, `...`, and longer runs).
    DotSegment,
    /// The name contains `/` or `\`, which includes every absolute path.
    PathSeparator,
    /// The name is a reserved package manifest file name, compared ASCII case-insensitively.
    Reserved,
    /// The stem before the first `.` is a Windows reserved device name (`CON`, `PRN`, `AUX`,
    /// `NUL`, `COM0`-`COM9`, or `LPT0`-`LPT9`), compared ASCII case-insensitively.
    WindowsDeviceName,
    /// The name ends in `.`, which Windows strips, so it would alias a different file name.
    TrailingDot,
    /// The name contains a byte outside `[A-Za-z0-9._+-]`.
    DisallowedByte {
        /// Byte offset of the first disallowed byte.
        index: usize,
        /// The disallowed byte.
        byte: u8,
    },
    /// A directory entry name is not valid UTF-8.
    NotUtf8,
    /// The name does not resolve to exactly one normal path component inside the target.
    NotSingleComponent,
}

impl fmt::Display for ArtifactNameViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("name is empty"),
            Self::TooLong { length, maximum } => {
                write!(f, "name is {length} bytes, maximum is {maximum}")
            }
            Self::DotSegment => f.write_str("name consists only of dots"),
            Self::PathSeparator => f.write_str("name contains a path separator"),
            Self::Reserved => f.write_str("name is a reserved manifest file name"),
            Self::WindowsDeviceName => f.write_str("name stem is a Windows reserved device name"),
            Self::TrailingDot => f.write_str("name ends in a dot"),
            Self::DisallowedByte { index, byte } => {
                write!(f, "disallowed byte {byte:#04x} at index {index}")
            }
            Self::NotUtf8 => f.write_str("name is not valid UTF-8"),
            Self::NotSingleComponent => {
                f.write_str("name does not resolve to one component inside the target directory")
            }
        }
    }
}

/// Validates that `name` is one portable file name that stays inside any target directory.
///
/// Accepted names are 1 to [`MAX_ARTIFACT_NAME_LEN`] bytes of `[A-Za-z0-9._+-]`, do not consist
/// only of dots, do not end in `.`, are not a reserved manifest file name in any ASCII case, have
/// no Windows reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM0`-`COM9`, `LPT0`-`LPT9`, in
/// any ASCII case) as the stem before their first `.`, and parse as exactly one normal path
/// component. Absolute paths, parent references, and every path separator are therefore refused.
/// Uniqueness within a package is ASCII case-insensitive; see [`ModelPackage::verify_contents`].
pub fn validate_artifact_name(name: &str) -> Result<(), ModelPackageError> {
    match artifact_name_violation(name) {
        None => Ok(()),
        Some(reason) => Err(ModelPackageError::InvalidArtifactName {
            name: name.to_string(),
            reason,
        }),
    }
}

fn artifact_name_violation(name: &str) -> Option<ArtifactNameViolation> {
    if name.is_empty() {
        return Some(ArtifactNameViolation::Empty);
    }
    if name.len() > MAX_ARTIFACT_NAME_LEN {
        return Some(ArtifactNameViolation::TooLong {
            length: name.len(),
            maximum: MAX_ARTIFACT_NAME_LEN,
        });
    }
    if name.bytes().all(|byte| byte == b'.') {
        return Some(ArtifactNameViolation::DotSegment);
    }
    if name.bytes().any(|byte| byte == b'/' || byte == b'\\') {
        return Some(ArtifactNameViolation::PathSeparator);
    }
    if name.eq_ignore_ascii_case(PACKAGE_MANIFEST_BIN)
        || name.eq_ignore_ascii_case(PACKAGE_MANIFEST_JSON)
    {
        return Some(ArtifactNameViolation::Reserved);
    }
    if let Some((index, byte)) = name
        .bytes()
        .enumerate()
        .find(|&(_, byte)| !is_portable_name_byte(byte))
    {
        return Some(ArtifactNameViolation::DisallowedByte { index, byte });
    }
    if name.ends_with('.') {
        return Some(ArtifactNameViolation::TrailingDot);
    }
    let stem = name.split_once('.').map_or(name, |(stem, _)| stem);
    if is_windows_device_stem(stem) {
        return Some(ArtifactNameViolation::WindowsDeviceName);
    }
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(component)), None) if component == OsStr::new(name) => None,
        _ => Some(ArtifactNameViolation::NotSingleComponent),
    }
}

const fn is_portable_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
}

/// Windows device names reserved in every directory, whatever the extension.
const WINDOWS_DEVICE_STEMS: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];

/// Windows device name prefixes reserved when followed by one ASCII digit.
const WINDOWS_NUMBERED_DEVICE_PREFIXES: [&str; 2] = ["COM", "LPT"];

/// Whether `stem` is a Windows reserved device name, compared ASCII case-insensitively.
fn is_windows_device_stem(stem: &str) -> bool {
    if WINDOWS_DEVICE_STEMS
        .iter()
        .any(|device| stem.eq_ignore_ascii_case(device))
    {
        return true;
    }
    match stem.as_bytes() {
        [prefix @ .., digit] if digit.is_ascii_digit() => WINDOWS_NUMBERED_DEVICE_PREFIXES
            .iter()
            .any(|device| device.as_bytes().eq_ignore_ascii_case(prefix)),
        _ => false,
    }
}

/// One named, digest-verified artifact in an offline model package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelPackageArtifact {
    /// Relative filename within the package; see [`validate_artifact_name`].
    pub name: String,
    /// Verified content digest of the artifact payload.
    pub digest: ContentDigest,
    /// Raw payload bytes of the artifact.
    pub payload: Vec<u8>,
}

impl ModelPackageArtifact {
    /// Constructs an artifact after validating its name, computing its SHA-256 content digest.
    pub fn new(name: impl Into<String>, payload: Vec<u8>) -> Result<Self, ModelPackageError> {
        let name = name.into();
        validate_artifact_name(&name)?;
        let digest = ContentDigest::sha256(&payload);
        Ok(Self {
            name,
            digest,
            payload,
        })
    }
}

/// In-memory model package containing a validated manifest and all required artifacts.
///
/// The fields are public for inspection and fixture construction, so every consumer
/// ([`Self::write_to_directory`], [`ModelPackageArchive::encode`], and
/// [`ModelPackageImporter::import_package`]) re-runs [`Self::verify_contents`] before acting.
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
    /// See [`Self::verify_contents`] for every invariant checked.
    pub fn new(
        manifest: ModelManifestV1,
        artifacts_list: Vec<ModelPackageArtifact>,
    ) -> Result<Self, ModelPackageError> {
        let manifest_bytes = manifest.to_canonical_bytes()?;
        let mut artifacts = BTreeMap::new();
        for art in artifacts_list {
            let digest = art.digest;
            match artifacts.entry(digest) {
                Entry::Vacant(slot) => {
                    slot.insert(art);
                }
                Entry::Occupied(_) => return Err(ModelPackageError::DuplicateArtifact { digest }),
            }
        }
        let package = Self {
            manifest,
            manifest_bytes,
            artifacts,
        };
        package.verify_contents()?;
        Ok(package)
    }

    /// Verifies every structural and content invariant without touching storage.
    ///
    /// - The manifest validates and `manifest_bytes` is exactly its canonical encoding.
    /// - Every artifact name passes [`validate_artifact_name`] and names are unique under ASCII
    ///   case folding, so no two artifacts alias one file on a case-insensitive filesystem.
    /// - Every artifact is keyed by its declared digest and its payload hashes to that digest.
    /// - The artifact set equals the set the manifest names (weights, license text, and
    ///   provenance artifacts): nothing missing, nothing extra.
    pub fn verify_contents(&self) -> Result<(), ModelPackageError> {
        self.manifest.validate()?;
        if self.manifest.to_canonical_bytes()? != self.manifest_bytes {
            return Err(ModelPackageError::ManifestBytesMismatch);
        }
        let mut names: BTreeMap<String, &str> = BTreeMap::new();
        for (key, art) in &self.artifacts {
            validate_artifact_name(&art.name)?;
            if *key != art.digest {
                return Err(ModelPackageError::ArtifactKeyMismatch {
                    name: art.name.clone(),
                    key: *key,
                    declared: art.digest,
                });
            }
            let computed = ContentDigest::sha256(&art.payload);
            if computed != art.digest {
                return Err(ModelPackageError::ArtifactDigestMismatch {
                    name: art.name.clone(),
                    expected: art.digest,
                    computed,
                });
            }
            match names.entry(art.name.to_ascii_lowercase()) {
                Entry::Vacant(slot) => {
                    slot.insert(art.name.as_str());
                }
                Entry::Occupied(slot) if *slot.get() == art.name => {
                    return Err(ModelPackageError::DuplicateArtifactName {
                        name: art.name.clone(),
                    });
                }
                Entry::Occupied(slot) => {
                    return Err(ModelPackageError::ArtifactNameCaseCollision {
                        name: art.name.clone(),
                        existing: (*slot.get()).to_string(),
                    });
                }
            }
        }

        let expected_digests = collect_expected_digests(&self.manifest);
        for expected in &expected_digests {
            if !self.artifacts.contains_key(expected) {
                return Err(ModelPackageError::MissingArtifact { digest: *expected });
            }
        }
        for (actual_digest, art) in &self.artifacts {
            if !expected_digests.contains(actual_digest) {
                return Err(ModelPackageError::ExtraArtifact {
                    name: art.name.clone(),
                    digest: *actual_digest,
                });
            }
        }
        Ok(())
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
    pub fn total_bytes(&self) -> Result<u64, ModelPackageError> {
        self.artifacts
            .values()
            .try_fold(self.manifest_bytes.len() as u64, |sum, art| {
                sum.checked_add(art.payload.len() as u64)
            })
            .ok_or(ModelPackageError::AccountingOverflow)
    }

    /// Serializes the model package into a self-verifying canonical binary archive (`FMPK` v1).
    pub fn to_archive_bytes(&self) -> Result<Vec<u8>, ModelPackageError> {
        ModelPackageArchive::encode(self)
    }

    /// Writes this package into a local directory using the provided `SpoolIo` capability.
    ///
    /// The whole package, including every artifact name, is verified and every target path is
    /// planned before the first filesystem call, so an invalid or escaping name fails typed with
    /// nothing created or written. Every file is created with `create_new`, so an existing file
    /// or symlink at a target name is never followed or overwritten.
    pub fn write_to_directory(
        &self,
        dir_path: &Path,
        io: &dyn SpoolIo,
    ) -> Result<(), ModelPackageError> {
        self.verify_contents()?;
        let mut planned = Vec::with_capacity(self.artifacts.len());
        for art in self.artifacts.values() {
            let art_path = dir_path.join(&art.name);
            if art_path.parent() != Some(dir_path) {
                return Err(ModelPackageError::InvalidArtifactName {
                    name: art.name.clone(),
                    reason: ArtifactNameViolation::NotSingleComponent,
                });
            }
            planned.push((art_path, art.payload.as_slice()));
        }

        io.create_dir_all(dir_path)
            .map_err(|e| io_failure("create_dir_all", dir_path, &e))?;
        write_new_file(
            io,
            &dir_path.join(PACKAGE_MANIFEST_BIN),
            &self.manifest_bytes,
        )?;
        for (art_path, payload) in &planned {
            write_new_file(io, art_path, payload)?;
        }
        io.sync_directory(dir_path)
            .map_err(|e| io_failure("sync_directory", dir_path, &e))?;
        Ok(())
    }

    /// Reads and verifies a model package from a local directory using the provided `SpoolIo` capability.
    pub fn from_directory(
        dir_path: &Path,
        io: &dyn SpoolIo,
        limits: &ModelPackageLimits,
    ) -> Result<Self, ModelPackageError> {
        let mut read_dir = io
            .read_dir(dir_path)
            .map_err(|e| io_failure("read_dir", dir_path, &e))?;

        let mut manifest_bytes: Option<Vec<u8>> = None;
        let mut artifact_entries: Vec<(String, Vec<u8>)> = Vec::new();

        while let Some(entry_res) = io.next_dir_entry(&mut read_dir) {
            let entry = entry_res.map_err(|e| io_failure("next_dir_entry", dir_path, &e))?;
            let file_type = io
                .entry_file_type(&entry)
                .map_err(|e| io_failure("entry_file_type", &entry.path(), &e))?;
            if !file_type.is_file() {
                continue;
            }

            let file_name = entry.file_name().into_string().map_err(|raw| {
                ModelPackageError::InvalidArtifactName {
                    name: raw.to_string_lossy().into_owned(),
                    reason: ArtifactNameViolation::NotUtf8,
                }
            })?;
            let file_path = entry.path();
            let is_manifest =
                file_name == PACKAGE_MANIFEST_BIN || file_name == PACKAGE_MANIFEST_JSON;
            let (bound_name, bound) = if is_manifest {
                ("manifest_bytes", limits.max_manifest_bytes as u64)
            } else {
                ("artifact_bytes", limits.max_artifact_bytes)
            };

            let mut file = io
                .open_read(&file_path)
                .map_err(|e| io_failure("open_read", &file_path, &e))?;
            // Read up to bound + 1 so an over-limit file is detected rather than truncated.
            let content = io
                .read_bounded(&mut file, bound.saturating_add(1))
                .map_err(|e| io_failure("read_bounded", &file_path, &e))?;
            if content.len() as u64 > bound {
                return Err(ModelPackageError::BoundExceeded {
                    bound: bound_name,
                    limit: bound,
                    actual: content.len() as u64,
                });
            }

            if is_manifest {
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

        let manifest = if m_bytes.starts_with(&MODEL_MANIFEST_MAGIC) {
            ModelManifestV1::from_canonical_bytes(&m_bytes)?
        } else {
            let json_str =
                std::str::from_utf8(&m_bytes).map_err(|_| ModelPackageError::CorruptArchive {
                    detail: "invalid utf-8 in manifest.json".to_string(),
                })?;
            ModelManifestV1::from_canonical_json(json_str)?
        };

        let mut artifacts = Vec::with_capacity(artifact_entries.len());
        for (name, payload) in artifact_entries {
            artifacts.push(ModelPackageArtifact::new(name, payload)?);
        }

        let package = Self::new(manifest, artifacts)?;
        package.validate(limits)?;
        Ok(package)
    }
}

fn io_failure(operation: &'static str, path: &Path, error: &io::Error) -> ModelPackageError {
    ModelPackageError::Io {
        operation,
        path: path.to_path_buf(),
        kind: error.kind(),
    }
}

/// Creates one new file, writes all of `bytes`, and fsyncs it.
///
/// A write that accepts zero bytes fails with [`io::ErrorKind::WriteZero`]. An interrupted write
/// is retried at the same offset at most `MAX_INTERRUPTED_ATTEMPTS - 1` times.
fn write_new_file(io: &dyn SpoolIo, path: &Path, bytes: &[u8]) -> Result<(), ModelPackageError> {
    let mut file = io
        .create_new(path)
        .map_err(|e| io_failure("create_new", path, &e))?;
    let mut written = 0_usize;
    let mut interrupted = 0_u32;
    while let Some(rest) = bytes.get(written..).filter(|rest| !rest.is_empty()) {
        match io.write(&mut file, rest) {
            Ok(0) => {
                return Err(ModelPackageError::Io {
                    operation: "write",
                    path: path.to_path_buf(),
                    kind: io::ErrorKind::WriteZero,
                });
            }
            Ok(accepted) => {
                written = written.saturating_add(accepted.min(rest.len()));
                interrupted = 0;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                interrupted = interrupted.saturating_add(1);
                if interrupted >= crate::MAX_INTERRUPTED_ATTEMPTS {
                    return Err(io_failure("write", path, &error));
                }
            }
            Err(error) => return Err(io_failure("write", path, &error)),
        }
    }
    io.sync_file(&file)
        .map_err(|e| io_failure("sync_file", path, &e))
}

fn collect_expected_digests(manifest: &ModelManifestV1) -> BTreeSet<ContentDigest> {
    let mut set = BTreeSet::new();
    set.insert(manifest.weights_digest());
    if let Some(td) = manifest.license().text_digest {
        set.insert(td);
    }
    for ad in &manifest.license().artifact_digests {
        set.insert(*ad);
    }
    set
}

/// Offline model package archive encoder and decoder (`FMPK` format).
pub struct ModelPackageArchive;

struct ArchiveReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ArchiveReader<'a> {
    fn take(&mut self, len: usize, what: &str) -> Result<&'a [u8], ModelPackageError> {
        let slice = self
            .offset
            .checked_add(len)
            .and_then(|end| self.bytes.get(self.offset..end))
            .ok_or_else(|| ModelPackageError::CorruptArchive {
                detail: format!("truncated {what}"),
            })?;
        self.offset += len;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self, what: &str) -> Result<[u8; N], ModelPackageError> {
        <[u8; N]>::try_from(self.take(N, what)?).map_err(|_| ModelPackageError::CorruptArchive {
            detail: format!("truncated {what}"),
        })
    }

    fn u16(&mut self, what: &str) -> Result<u16, ModelPackageError> {
        Ok(u16::from_be_bytes(self.array(what)?))
    }

    fn u32(&mut self, what: &str) -> Result<u32, ModelPackageError> {
        Ok(u32::from_be_bytes(self.array(what)?))
    }

    fn u64(&mut self, what: &str) -> Result<u64, ModelPackageError> {
        Ok(u64::from_be_bytes(self.array(what)?))
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
}

fn usize_bound(value: u64, bound: &'static str, limit: u64) -> Result<usize, ModelPackageError> {
    usize::try_from(value).map_err(|_| ModelPackageError::BoundExceeded {
        bound,
        limit,
        actual: value,
    })
}

impl ModelPackageArchive {
    /// Encodes a `ModelPackage` into self-verifying archive bytes.
    pub fn encode(package: &ModelPackage) -> Result<Vec<u8>, ModelPackageError> {
        package.verify_contents()?;
        let mut buf = Vec::new();

        buf.extend_from_slice(&MODEL_PACKAGE_ARCHIVE_MAGIC);
        buf.extend_from_slice(&MODEL_PACKAGE_ARCHIVE_VERSION_1.to_be_bytes());

        let m_len = u32::try_from(package.manifest_bytes.len())
            .map_err(|_| ModelPackageError::AccountingOverflow)?;
        buf.extend_from_slice(&m_len.to_be_bytes());
        buf.extend_from_slice(&package.manifest_bytes);

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
    ///
    /// Every length is checked against the remaining bytes with overflow-checked arithmetic, and
    /// the decoded package passes [`ModelPackage::new`] and [`ModelPackage::validate`].
    pub fn decode(
        bytes: &[u8],
        limits: &ModelPackageLimits,
    ) -> Result<ModelPackage, ModelPackageError> {
        if bytes.len() < ARCHIVE_MIN_LEN {
            return Err(ModelPackageError::CorruptArchive {
                detail: format!("archive length too short: {}", bytes.len()),
            });
        }
        let (body, trailer) = bytes
            .split_at_checked(bytes.len() - ARCHIVE_CHECKSUM_LEN)
            .ok_or_else(|| ModelPackageError::CorruptArchive {
                detail: "archive shorter than its checksum".to_string(),
            })?;

        let mut reader = ArchiveReader {
            bytes: body,
            offset: 0,
        };
        let magic: [u8; 4] = reader.array("archive magic")?;
        if magic != MODEL_PACKAGE_ARCHIVE_MAGIC {
            return Err(ModelPackageError::CorruptArchive {
                detail: format!("invalid archive magic: {magic:?}"),
            });
        }
        let version = reader.u32("archive version")?;
        if version != MODEL_PACKAGE_ARCHIVE_VERSION_1 {
            return Err(ModelPackageError::CorruptArchive {
                detail: format!("unsupported archive version: {version}"),
            });
        }

        let stored: [u8; ARCHIVE_CHECKSUM_LEN] =
            trailer
                .try_into()
                .map_err(|_| ModelPackageError::CorruptArchive {
                    detail: "invalid checksum length".to_string(),
                })?;
        if ContentDigest::sha256(body) != ContentDigest::new(DigestAlgorithm::Sha256, stored) {
            return Err(ModelPackageError::CorruptArchive {
                detail: "archive trailing checksum mismatch".to_string(),
            });
        }

        let m_len = reader.u32("manifest length")? as usize;
        if m_len > limits.max_manifest_bytes {
            return Err(ModelPackageError::BoundExceeded {
                bound: "manifest_bytes",
                limit: limits.max_manifest_bytes as u64,
                actual: m_len as u64,
            });
        }
        let manifest = ModelManifestV1::from_canonical_bytes(reader.take(m_len, "manifest")?)?;

        let art_count = reader.u32("artifact count")? as usize;
        if art_count > limits.max_artifacts_count {
            return Err(ModelPackageError::BoundExceeded {
                bound: "artifact_count",
                limit: limits.max_artifacts_count as u64,
                actual: art_count as u64,
            });
        }

        let mut artifacts = Vec::with_capacity(art_count);
        for _ in 0..art_count {
            let n_len = usize::from(reader.u16("artifact name length")?);
            let name = std::str::from_utf8(reader.take(n_len, "artifact name")?)
                .map_err(|_| ModelPackageError::InvalidArtifactName {
                    name: String::new(),
                    reason: ArtifactNameViolation::NotUtf8,
                })?
                .to_string();
            let declared_digest =
                ContentDigest::new(DigestAlgorithm::Sha256, reader.array("artifact digest")?);
            let p_len = reader.u64("artifact payload length")?;
            if p_len > limits.max_artifact_bytes {
                return Err(ModelPackageError::BoundExceeded {
                    bound: "artifact_bytes",
                    limit: limits.max_artifact_bytes,
                    actual: p_len,
                });
            }
            let p_len = usize_bound(p_len, "artifact_bytes", limits.max_artifact_bytes)?;
            let payload = reader.take(p_len, "artifact payload")?.to_vec();

            artifacts.push(ModelPackageArtifact {
                name,
                digest: declared_digest,
                payload,
            });
        }

        if reader.remaining() != 0 {
            return Err(ModelPackageError::CorruptArchive {
                detail: format!(
                    "extra trailing bytes in archive payload: {} bytes",
                    reader.remaining()
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
    /// At least one object was newly written into the staging spool.
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
struct GenerationRecord {
    manifest_digest: ContentDigest,
    /// The manifest digest plus every artifact digest it names.
    objects: BTreeSet<ContentDigest>,
}

/// Importer and verifier for offline model packages over a [`StagingSpool`].
///
/// The importer owns its spool. Generation records are rebuilt from the manifests already in the
/// spool whenever an importer is constructed, so conflict detection survives process restarts.
#[derive(Debug)]
pub struct ModelPackageImporter {
    spool: StagingSpool,
    limits: ModelPackageLimits,
    generations: BTreeMap<ModelGeneration, GenerationRecord>,
}

impl ModelPackageImporter {
    /// Constructs an importer over `spool`, rebuilding generation records from its manifests.
    ///
    /// Every indexed object is read and rehashed. An object that begins with the manifest magic
    /// and decodes as a canonical manifest records its generation. Construction fails closed:
    /// - with the spool's typed error if any object cannot be read (for example, it is corrupt),
    ///   because its generation could not be ruled out;
    /// - with [`ModelPackageError::UndecodableManifestObject`] for an object that carries the
    ///   manifest magic, does not decode, and is not an artifact named by a decoded manifest;
    /// - with [`ModelPackageError::GenerationConflict`] if two manifests claim one generation.
    pub fn new(spool: StagingSpool, limits: ModelPackageLimits) -> Result<Self, ModelPackageError> {
        let mut manifests: Vec<(ContentDigest, ModelManifestV1)> = Vec::new();
        let mut undecodable: Vec<(ContentDigest, ModelManifestError)> = Vec::new();
        let digests: Vec<ContentDigest> = spool.digests().collect();
        for digest in digests {
            let bytes = spool.read(digest)?;
            if !bytes.starts_with(&MODEL_MANIFEST_MAGIC) {
                continue;
            }
            match ModelManifestV1::from_canonical_bytes(&bytes) {
                Ok(manifest) => manifests.push((digest, manifest)),
                Err(error) => undecodable.push((digest, error)),
            }
        }

        let referenced_artifacts: BTreeSet<ContentDigest> = manifests
            .iter()
            .flat_map(|(_, manifest)| collect_expected_digests(manifest))
            .collect();
        if let Some((digest, error)) = undecodable
            .into_iter()
            .find(|(digest, _)| !referenced_artifacts.contains(digest))
        {
            return Err(ModelPackageError::UndecodableManifestObject {
                digest,
                error: Box::new(error),
            });
        }

        let mut generations = BTreeMap::new();
        for (manifest_digest, manifest) in manifests {
            let mut objects = collect_expected_digests(&manifest);
            objects.insert(manifest_digest);
            match generations.entry(manifest.generation().clone()) {
                Entry::Vacant(slot) => {
                    slot.insert(GenerationRecord {
                        manifest_digest,
                        objects,
                    });
                }
                Entry::Occupied(slot) => {
                    return Err(ModelPackageError::GenerationConflict {
                        generation: manifest.generation().clone(),
                        existing_manifest: slot.get().manifest_digest,
                        new_manifest: manifest_digest,
                    });
                }
            }
        }

        Ok(Self {
            spool,
            limits,
            generations,
        })
    }

    /// Read-only access to the underlying staging spool.
    #[must_use]
    pub fn spool(&self) -> &StagingSpool {
        &self.spool
    }

    /// Configured limits for package operations.
    #[must_use]
    pub const fn limits(&self) -> ModelPackageLimits {
        self.limits
    }

    /// Manifest digest recorded for `generation`, if its manifest is in the spool.
    #[must_use]
    pub fn staged_manifest(&self, generation: &ModelGeneration) -> Option<ContentDigest> {
        self.generations
            .get(generation)
            .map(|record| record.manifest_digest)
    }

    /// Imports a model package from raw archive bytes into the staging spool.
    pub fn import_from_archive(
        &mut self,
        archive_bytes: &[u8],
        expected_generation: &str,
    ) -> Result<ImportReceipt, ModelPackageError> {
        resolve_pin(expected_generation)?;
        let package = ModelPackageArchive::decode(archive_bytes, &self.limits)?;
        self.import_package(&package, expected_generation)
    }

    /// Imports a model package from a local directory into the staging spool.
    pub fn import_from_directory(
        &mut self,
        dir_path: &Path,
        io: &dyn SpoolIo,
        expected_generation: &str,
    ) -> Result<ImportReceipt, ModelPackageError> {
        resolve_pin(expected_generation)?;
        let package = ModelPackage::from_directory(dir_path, io, &self.limits)?;
        self.import_package(&package, expected_generation)
    }

    /// Imports and stages a validated `ModelPackage`, all or nothing.
    ///
    /// Sequence:
    /// 1. Resolve `expected_generation` exactly; any form of `latest` is refused.
    /// 2. Require it to equal the package manifest's generation.
    /// 3. Validate package bounds and every content invariant ([`ModelPackage::verify_contents`]).
    /// 4. Refuse a generation already recorded with a different manifest
    ///    ([`ModelPackageError::GenerationConflict`]).
    /// 5. Stage every artifact, then the manifest last. Restaging identical bytes is idempotent.
    /// 6. On any staging failure, discard every object this call newly staged. If that rollback
    ///    cannot complete, return [`ModelPackageError::RollbackIncomplete`] naming each object
    ///    that may remain.
    ///
    /// Nothing is staged before steps 1 to 4 pass. Objects remain `Staged` (not `Verified`).
    ///
    /// The expected generation is mandatory: an unpinned import would resolve whatever generation
    /// the package carries, which is `latest` resolution under another name.
    ///
    /// ```compile_fail,E0308
    /// fn import_unpinned(
    ///     importer: &mut fss_object::ModelPackageImporter,
    ///     package: &fss_object::ModelPackage,
    /// ) {
    ///     let _ = importer.import_package(package, None);
    /// }
    /// ```
    pub fn import_package(
        &mut self,
        package: &ModelPackage,
        expected_generation: &str,
    ) -> Result<ImportReceipt, ModelPackageError> {
        let pinned = resolve_pin(expected_generation)?;
        if &pinned != package.manifest.generation() {
            return Err(ModelPackageError::GenerationMismatch {
                expected: pinned,
                actual: package.manifest.generation().clone(),
            });
        }
        package.validate(&self.limits)?;
        package.verify_contents()?;
        let manifest_digest = ContentDigest::sha256(&package.manifest_bytes);
        let total_staged_bytes = package.total_bytes()?;

        if let Some(existing) = self.generations.get(&pinned)
            && existing.manifest_digest != manifest_digest
        {
            return Err(ModelPackageError::GenerationConflict {
                generation: pinned,
                existing_manifest: existing.manifest_digest,
                new_manifest: manifest_digest,
            });
        }

        let objects = package
            .artifacts
            .values()
            .map(|art| (art.digest, art.payload.as_slice()))
            .chain(iter::once((
                manifest_digest,
                package.manifest_bytes.as_slice(),
            )));
        let mut newly_staged = Vec::new();
        for (digest, payload) in objects {
            match self.spool.stage(digest, payload) {
                Ok(receipt) => {
                    if receipt.outcome == StageOutcome::NewlyStaged {
                        newly_staged.push(digest);
                    }
                }
                Err(error) => return Err(self.roll_back(newly_staged, digest, error)),
            }
        }

        let mut objects: BTreeSet<ContentDigest> = package.artifacts.keys().copied().collect();
        objects.insert(manifest_digest);
        self.generations.insert(
            pinned.clone(),
            GenerationRecord {
                manifest_digest,
                objects,
            },
        );

        Ok(ImportReceipt {
            manifest_digest,
            generation: pinned,
            outcome: if newly_staged.is_empty() {
                ImportOutcome::AlreadyPresent
            } else {
                ImportOutcome::NewlyStaged
            },
            staged_artifacts: package.artifacts.keys().copied().collect(),
            total_staged_bytes,
        })
    }

    /// Discards every object this import newly staged after `cause` stopped it at `failed`.
    fn roll_back(
        &mut self,
        newly_staged: Vec<ContentDigest>,
        failed: ContentDigest,
        cause: SpoolError,
    ) -> ModelPackageError {
        let mut residual = BTreeSet::new();
        // These outcomes may leave `failed` itself in place under its object name.
        if matches!(
            cause,
            SpoolError::StageIndeterminate { .. }
                | SpoolError::InjectedCrash {
                    phase: StagePhase::AfterRename
                }
        ) {
            residual.insert(failed);
        }
        let mut rollback_errors = Vec::new();
        for digest in newly_staged.into_iter().rev() {
            if let Err(error) = self.spool.discard_staged(digest) {
                residual.insert(digest);
                rollback_errors.push(error);
            }
        }
        if residual.is_empty() {
            ModelPackageError::Spool(cause)
        } else {
            ModelPackageError::RollbackIncomplete {
                cause: Box::new(cause),
                residual: residual.into_iter().collect(),
                rollback_errors,
            }
        }
    }

    /// Discards the residual objects named by a [`ModelPackageError::RollbackIncomplete`].
    ///
    /// Call it on an importer constructed over the reopened spool. An object that belongs to a
    /// generation whose manifest reached the spool is part of a complete import and is kept, and
    /// an object that is no longer present needs nothing. Every other named object is discarded
    /// with [`StagingSpool::discard_staged`], whose typed error is returned if it refuses.
    /// Returns the discarded digests in ascending order.
    pub fn discard_residual(
        &mut self,
        residual: &[ContentDigest],
    ) -> Result<Vec<ContentDigest>, ModelPackageError> {
        let referenced: BTreeSet<ContentDigest> = self
            .generations
            .values()
            .flat_map(|record| record.objects.iter().copied())
            .collect();
        let targets: BTreeSet<ContentDigest> = residual.iter().copied().collect();
        let mut discarded = Vec::new();
        for digest in targets {
            if referenced.contains(&digest) || self.spool.state(digest).is_none() {
                continue;
            }
            self.spool.discard_staged(digest)?;
            discarded.push(digest);
        }
        Ok(discarded)
    }

    /// Verifies all objects associated with a staged model package.
    ///
    /// Reads and rehashes the manifest and each referenced artifact from disk,
    /// transitioning their states in the spool from `Staged` to `Verified`.
    pub fn verify_package(
        &mut self,
        manifest_digest: ContentDigest,
    ) -> Result<VerificationReceipt, ModelPackageError> {
        self.spool.verify(manifest_digest)?;
        let manifest_bytes = self.spool.read(manifest_digest)?;
        let manifest = ModelManifestV1::from_canonical_bytes(&manifest_bytes)?;

        let mut verified_artifacts = Vec::new();
        let mut total_verified_bytes = manifest_bytes.len() as u64;

        for digest in collect_expected_digests(&manifest) {
            self.spool.verify(digest)?;
            let art_bytes = self.spool.read(digest)?;
            total_verified_bytes = total_verified_bytes
                .checked_add(art_bytes.len() as u64)
                .ok_or(ModelPackageError::AccountingOverflow)?;
            verified_artifacts.push(digest);
        }

        Ok(VerificationReceipt {
            manifest_digest,
            generation: manifest.generation().clone(),
            verified_artifacts,
            total_verified_bytes,
        })
    }
}

/// Resolves the caller's pinned generation, surfacing `latest` as its own typed refusal.
fn resolve_pin(expected_generation: &str) -> Result<ModelGeneration, ModelPackageError> {
    ModelManifestV1::resolve_generation(expected_generation).map_err(|error| match error {
        ModelManifestError::LatestNotResolvable => ModelPackageError::LatestNotResolvable,
        other => ModelPackageError::Manifest(other),
    })
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
    /// An artifact is indexed under a key that differs from its declared digest.
    ArtifactKeyMismatch {
        /// Artifact name.
        name: String,
        /// Map key the artifact is stored under.
        key: ContentDigest,
        /// Digest the artifact declares.
        declared: ContentDigest,
    },
    /// Two artifacts in one package list share a content digest.
    DuplicateArtifact {
        /// Duplicated digest.
        digest: ContentDigest,
    },
    /// Two artifacts share a name and would collide in a package directory.
    DuplicateArtifactName {
        /// Duplicated name.
        name: String,
    },
    /// Two artifact names differ only by ASCII case and would collide on a case-insensitive
    /// filesystem.
    ArtifactNameCaseCollision {
        /// Name that collides, seen second in artifact digest order.
        name: String,
        /// Name seen first that `name` collides with.
        existing: String,
    },
    /// An artifact name is not one portable file name inside the package directory.
    InvalidArtifactName {
        /// Offending name (lossily rendered when it is not UTF-8).
        name: String,
        /// Why the name is refused.
        reason: ArtifactNameViolation,
    },
    /// The package's manifest bytes are not the canonical encoding of its manifest.
    ManifestBytesMismatch,
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
    /// Error from the underlying staging spool; nothing from this import remains staged.
    Spool(SpoolError),
    /// An import failed after staging began and its rollback could not be completed.
    ///
    /// Every object in `residual` may still be in the spool (or reappear after a crash). Reopen
    /// the spool, construct a new importer, and call [`ModelPackageImporter::discard_residual`].
    RollbackIncomplete {
        /// Failure that stopped the import.
        cause: Box<SpoolError>,
        /// Objects that may remain, in ascending digest order.
        residual: Vec<ContentDigest>,
        /// Errors the spool returned while discarding, in discard order.
        rollback_errors: Vec<SpoolError>,
    },
    /// A spool object carries the manifest magic but does not decode as a manifest.
    UndecodableManifestObject {
        /// Object digest.
        digest: ContentDigest,
        /// Decode failure.
        error: Box<ModelManifestError>,
    },
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
            Self::ArtifactKeyMismatch {
                name,
                key,
                declared,
            } => write!(
                f,
                "artifact '{name}' is indexed under {key} but declares {declared}"
            ),
            Self::DuplicateArtifact { digest } => {
                write!(f, "duplicate artifact digest in package: {digest}")
            }
            Self::DuplicateArtifactName { name } => {
                write!(f, "duplicate artifact name in package: '{name}'")
            }
            Self::ArtifactNameCaseCollision { name, existing } => write!(
                f,
                "artifact names '{existing}' and '{name}' differ only by case and collide on case-insensitive filesystems"
            ),
            Self::InvalidArtifactName { name, reason } => {
                write!(f, "invalid artifact name {name:?}: {reason}")
            }
            Self::ManifestBytesMismatch => {
                f.write_str("package manifest bytes are not the canonical manifest encoding")
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
            Self::RollbackIncomplete {
                cause, residual, ..
            } => write!(
                f,
                "import failed ({cause}) and rollback left {} object(s) that may remain staged; reopen the spool and discard the residual",
                residual.len()
            ),
            Self::UndecodableManifestObject { digest, error } => write!(
                f,
                "spool object {digest} carries the manifest magic but does not decode: {error}"
            ),
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
            Self::RollbackIncomplete { cause, .. } => Some(cause.as_ref()),
            Self::UndecodableManifestObject { error, .. } => Some(error.as_ref()),
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
