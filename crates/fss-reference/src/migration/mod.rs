#![forbid(unsafe_code)]
//! Non-destructive v1-to-v2 deployment upgrader, format detection, and cryptographic
//! equivalence receipts (`fss migrate`).
//!
//! Migrates an existing v1 reference deployment (`LAYOUT` v1, single-file `ledger/journal.fssj`,
//! per-file `objects/spool/` + `objects/roots/`) into a brand-new v2 deployment root backed by:
//!
//! - segmented Merkle epoch ledger (`<dest>/ledger/epochs/` + `<dest>/ledger/checkpoints/`),
//! - append-only sealed packfile store (`<dest>/objects/packs/` + `<dest>/objects/index/`) and
//!   unbounded virtual root catalog (`<dest>/objects/roots/`),
//! - anchor-pinned derived MVCC projection store (`<dest>/projections/mvcc/`),
//! - byte-verified `effects/journal.fssj`, preserved local `objects/tombstones/`, and `agent/`
//!   subtrees when present,
//! - canonical v2 `LAYOUT` (`fss.reference_deployment.layout.v2`) and self-verifying
//!   `migration_receipt.json` (`fss.migration_receipt.v1`).
//!
//! The v1 source deployment is inspected strictly read-only and NEVER mutated or locked.
//! An atomic `.migrate-incomplete` sentinel guards the destination directory until every
//! artifact is fsynced and verified.

pub mod receipt;
pub mod v1_to_v2;

#[cfg(test)]
mod tests;

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use fss_core::ContentDigest;

use crate::deployment_backup::RESTORE_INCOMPLETE_FILENAME;
use crate::reference_deployment::{
    DEPLOYMENT_LAYOUT_FILENAME, DeploymentLayout, RELATIVE_PATH_EFFECTS, RELATIVE_PATH_OBJECTS,
    validate_site_lineage,
};

pub use receipt::{
    MIGRATION_RECEIPT_DOMAIN, MIGRATION_RECEIPT_FILENAME, MIGRATION_RECEIPT_SCHEMA,
    MigrationEquivalenceReceipt,
};
pub use v1_to_v2::{
    MIGRATION_PROGRESS_SCHEMA, MigrationProgressEvent, MigrationRequest, migrate_v1_to_v2,
    migrate_v1_to_v2_with_progress,
};

/// Canonical schema identifier for a v2 deployment `LAYOUT` descriptor.
pub const DEPLOYMENT_LAYOUT_V2_SCHEMA: &str = "fss.reference_deployment.layout.v2";
/// Format version integer for a v2 deployment `LAYOUT` descriptor.
pub const DEPLOYMENT_LAYOUT_V2_FORMAT_VERSION: u32 = 2;
/// Relative path to the v2 Merkle epoch ledger directory inside a v2 deployment root.
pub const RELATIVE_PATH_V2_LEDGER: &str = "ledger";
/// Relative path to the v2 derived MVCC projection directory inside a v2 deployment root.
pub const RELATIVE_PATH_V2_PROJECTIONS: &str = "projections/mvcc";
/// Atomic in-progress sentinel written upon reserving a v2 destination and removed only last.
pub const MIGRATE_INCOMPLETE_FILENAME: &str = ".migrate-incomplete";

/// Stable error identity emitted when a v2-only path is invoked against a v1 deployment root.
pub const ERR_DEPLOYMENT_FORMAT_V1_001: &str = "ERR-DEPLOYMENT-FORMAT-V1-001";
/// Stable error identity emitted when a destination carries an unremoved `.migrate-incomplete`
/// sentinel from an interrupted or failed migration.
pub const ERR_DEPLOYMENT_MIGRATE_INCOMPLETE_001: &str = "ERR-DEPLOYMENT-MIGRATE-INCOMPLETE-001";
/// Stable error identity emitted when the requested migration destination already exists.
pub const ERR_MIGRATION_DESTINATION_EXISTS_001: &str = "ERR-MIGRATION-DESTINATION-EXISTS-001";
/// Stable error identity emitted when the v1 source deployment is not clean for migration.
pub const ERR_MIGRATION_SOURCE_NOT_CLEAN_001: &str = "ERR-MIGRATION-SOURCE-NOT-CLEAN-001";
/// Stable error identity emitted when a migration is cancelled cooperatively.
pub const ERR_MIGRATION_CANCELLED_001: &str = "ERR-MIGRATION-CANCELLED-001";
/// Stable error identity emitted when post-migration cryptographic verification fails.
pub const ERR_MIGRATION_VERIFICATION_FAILED_001: &str = "ERR-MIGRATION-VERIFICATION-FAILED-001";
/// Stable error identity emitted when the source path is already a v2 deployment.
pub const ERR_MIGRATION_SOURCE_ALREADY_V2_001: &str = "ERR-MIGRATION-SOURCE-ALREADY-V2-001";
/// Stable error identity emitted when a path is not a recognized deployment root.
pub const ERR_MIGRATION_NOT_A_DEPLOYMENT_001: &str = "ERR-MIGRATION-NOT-A-DEPLOYMENT-001";
/// Stable error identity emitted when an input or destination path fails safety validation.
pub const ERR_MIGRATION_INVALID_PATH_001: &str = "ERR-MIGRATION-INVALID-PATH-001";
/// Stable error identity emitted on underlying storage or I/O failure during migration.
pub const ERR_MIGRATION_IO_001: &str = "ERR-MIGRATION-IO-001";

/// Maximum admitted byte length when reading `LAYOUT` or `.migrate-incomplete`.
const MAX_DESCRIPTOR_BYTES: usize = 4_096;

/// On-disk canonical `LAYOUT` descriptor for a v2 deployment root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentLayoutV2 {
    /// Schema identity (`fss.reference_deployment.layout.v2`).
    pub schema: String,
    /// Layout format version (`2`).
    pub format_version: u32,
    /// Site lineage identifier preserved verbatim from v1.
    pub site_lineage: String,
    /// Relative path to the v2 Merkle epoch ledger directory (`ledger`).
    pub ledger_relpath: String,
    /// Relative path to the v2 object storage directory (`objects`).
    pub objects_relpath: String,
    /// Relative path to the v2 derived MVCC projection directory (`projections/mvcc`).
    pub projections_relpath: String,
    /// Relative path to the durable effect journal (`effects/journal.fssj`).
    pub effects_relpath: String,
    /// Canonical digest of the deployment capacity limits preserved from v1.
    pub limits_digest: ContentDigest,
}

impl DeploymentLayoutV2 {
    /// Constructs a canonical v2 layout descriptor preserving `site_lineage` and `limits_digest`.
    #[must_use]
    pub fn new(site_lineage: &str, limits_digest: ContentDigest) -> Self {
        Self {
            schema: DEPLOYMENT_LAYOUT_V2_SCHEMA.to_owned(),
            format_version: DEPLOYMENT_LAYOUT_V2_FORMAT_VERSION,
            site_lineage: site_lineage.to_owned(),
            ledger_relpath: RELATIVE_PATH_V2_LEDGER.to_owned(),
            objects_relpath: RELATIVE_PATH_OBJECTS.to_owned(),
            projections_relpath: RELATIVE_PATH_V2_PROJECTIONS.to_owned(),
            effects_relpath: RELATIVE_PATH_EFFECTS.to_owned(),
            limits_digest,
        }
    }

    /// Serializes this v2 layout descriptor to its exact canonical text representation.
    #[must_use]
    pub fn to_canonical_text(&self) -> String {
        format!(
            "schema={}\nversion={}\nsite_lineage={}\nledger={}\nobjects={}\nprojections={}\neffects={}\nlimits_digest={}\n",
            self.schema,
            self.format_version,
            self.site_lineage,
            self.ledger_relpath,
            self.objects_relpath,
            self.projections_relpath,
            self.effects_relpath,
            self.limits_digest.to_text(),
        )
    }

    /// Strictly parses canonical v2 `LAYOUT` text, rejecting unknown keys, non-canonical ordering,
    /// or unsupported versions.
    pub fn parse_canonical_text(text: &str) -> Result<Self, MigrationError> {
        let mut schema = None;
        let mut version = None;
        let mut site_lineage = None;
        let mut ledger = None;
        let mut objects = None;
        let mut projections = None;
        let mut effects = None;
        let mut limits_digest = None;

        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                return Err(MigrationError::InvalidLayout(
                    "layout line must use '=' separator".to_owned(),
                ));
            };
            match key {
                "schema" => {
                    if schema.is_some() {
                        return Err(MigrationError::InvalidLayout(
                            "duplicate layout key: schema".to_owned(),
                        ));
                    }
                    schema = Some(value.to_owned());
                }
                "version" => {
                    if version.is_some() {
                        return Err(MigrationError::InvalidLayout(
                            "duplicate layout key: version".to_owned(),
                        ));
                    }
                    let parsed = value.parse::<u32>().map_err(|_| {
                        MigrationError::InvalidLayout("invalid layout version".to_owned())
                    })?;
                    version = Some(parsed);
                }
                "site_lineage" => {
                    if site_lineage.is_some() {
                        return Err(MigrationError::InvalidLayout(
                            "duplicate layout key: site_lineage".to_owned(),
                        ));
                    }
                    validate_site_lineage(value).map_err(|err| {
                        MigrationError::InvalidLayout(format!("invalid site_lineage: {err}"))
                    })?;
                    site_lineage = Some(value.to_owned());
                }
                "ledger" => {
                    if ledger.is_some() {
                        return Err(MigrationError::InvalidLayout(
                            "duplicate layout key: ledger".to_owned(),
                        ));
                    }
                    if value != RELATIVE_PATH_V2_LEDGER {
                        return Err(MigrationError::InvalidLayout(
                            "invalid v2 layout ledger relpath".to_owned(),
                        ));
                    }
                    ledger = Some(value.to_owned());
                }
                "objects" => {
                    if objects.is_some() {
                        return Err(MigrationError::InvalidLayout(
                            "duplicate layout key: objects".to_owned(),
                        ));
                    }
                    if value != RELATIVE_PATH_OBJECTS {
                        return Err(MigrationError::InvalidLayout(
                            "invalid v2 layout objects relpath".to_owned(),
                        ));
                    }
                    objects = Some(value.to_owned());
                }
                "projections" => {
                    if projections.is_some() {
                        return Err(MigrationError::InvalidLayout(
                            "duplicate layout key: projections".to_owned(),
                        ));
                    }
                    if value != RELATIVE_PATH_V2_PROJECTIONS {
                        return Err(MigrationError::InvalidLayout(
                            "invalid v2 layout projections relpath".to_owned(),
                        ));
                    }
                    projections = Some(value.to_owned());
                }
                "effects" => {
                    if effects.is_some() {
                        return Err(MigrationError::InvalidLayout(
                            "duplicate layout key: effects".to_owned(),
                        ));
                    }
                    if value != RELATIVE_PATH_EFFECTS {
                        return Err(MigrationError::InvalidLayout(
                            "invalid v2 layout effects relpath".to_owned(),
                        ));
                    }
                    effects = Some(value.to_owned());
                }
                "limits_digest" => {
                    if limits_digest.is_some() {
                        return Err(MigrationError::InvalidLayout(
                            "duplicate layout key: limits_digest".to_owned(),
                        ));
                    }
                    let digest = ContentDigest::parse(value).map_err(|_| {
                        MigrationError::InvalidLayout("invalid limits_digest".to_owned())
                    })?;
                    limits_digest = Some(digest);
                }
                _ => {
                    return Err(MigrationError::InvalidLayout(format!(
                        "unknown v2 layout key: {key}"
                    )));
                }
            }
        }

        let schema =
            schema.ok_or_else(|| MigrationError::InvalidLayout("missing schema".to_owned()))?;
        let version =
            version.ok_or_else(|| MigrationError::InvalidLayout("missing version".to_owned()))?;
        let site_lineage = site_lineage
            .ok_or_else(|| MigrationError::InvalidLayout("missing site_lineage".to_owned()))?;
        let ledger =
            ledger.ok_or_else(|| MigrationError::InvalidLayout("missing ledger".to_owned()))?;
        let objects =
            objects.ok_or_else(|| MigrationError::InvalidLayout("missing objects".to_owned()))?;
        let projections = projections
            .ok_or_else(|| MigrationError::InvalidLayout("missing projections".to_owned()))?;
        let effects =
            effects.ok_or_else(|| MigrationError::InvalidLayout("missing effects".to_owned()))?;
        let limits_digest = limits_digest
            .ok_or_else(|| MigrationError::InvalidLayout("missing limits_digest".to_owned()))?;

        if schema != DEPLOYMENT_LAYOUT_V2_SCHEMA {
            return Err(MigrationError::InvalidLayout(
                "incompatible v2 layout schema".to_owned(),
            ));
        }
        if version != DEPLOYMENT_LAYOUT_V2_FORMAT_VERSION {
            return Err(MigrationError::InvalidLayout(
                "incompatible v2 layout version".to_owned(),
            ));
        }

        let layout = Self {
            schema,
            format_version: version,
            site_lineage,
            ledger_relpath: ledger,
            objects_relpath: objects,
            projections_relpath: projections,
            effects_relpath: effects,
            limits_digest,
        };
        if layout.to_canonical_text() != text {
            return Err(MigrationError::InvalidLayout(
                "v2 layout text is not canonical".to_owned(),
            ));
        }
        Ok(layout)
    }
}

/// Detected on-disk format classification for a candidate deployment directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeploymentFormatVersion {
    /// Legacy v1 reference deployment (`LAYOUT` v1, single-file ledger journal, staging spool).
    V1 {
        /// Parsed canonical v1 `LAYOUT` descriptor.
        layout: DeploymentLayout,
    },
    /// v2 deployment (`LAYOUT` v2, segmented Merkle epochs, packfiles, MVCC projections).
    V2 {
        /// Parsed canonical v2 `LAYOUT` descriptor.
        layout: DeploymentLayoutV2,
    },
    /// Destination directory carries an unremoved `.migrate-incomplete` sentinel and MUST be
    /// refused by v2 readers and writers.
    MigrateIncomplete {
        /// Bounded human-readable summary of the sentinel file contents.
        marker_detail: String,
    },
    /// Directory is absent, a symlink/non-directory, or does not carry a recognized layout.
    NotADeployment {
        /// Explicit reason the path was not recognized.
        reason: String,
    },
}

/// Typed `ERR-DEPLOYMENT-FORMAT-V1-001` refusal guidance emitted when a v2-only path encounters a
/// v1 deployment root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V1FormatRefusalGuidance {
    /// Stable error identity (`ERR-DEPLOYMENT-FORMAT-V1-001`).
    pub error_id: &'static str,
    /// Observed v1 deployment root path.
    pub source_root: PathBuf,
    /// Suggested non-destructive destination path for the new v2 deployment.
    pub suggested_dest: PathBuf,
    /// Exact copy-pasteable `fss migrate` command line for operator execution.
    pub migrate_command: String,
    /// Explicit explanation why v2-only execution refused the v1 root.
    pub reason: String,
}

impl V1FormatRefusalGuidance {
    /// Renders this refusal guidance as canonical zero-Serde JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            "{{\"error_id\":\"{}\",\"detected_format\":\"v1\",\"source_root\":\"{}\",\"suggested_dest\":\"{}\",\"migrate_command\":\"{}\",\"reason\":\"{}\"}}",
            escape_json_str(self.error_id),
            escape_json_str(&self.source_root.to_string_lossy()),
            escape_json_str(&self.suggested_dest.to_string_lossy()),
            escape_json_str(&self.migrate_command),
            escape_json_str(&self.reason),
        )
    }
}

/// Builds typed [`ERR_DEPLOYMENT_FORMAT_V1_001`] refusal guidance naming the exact
/// `fss migrate --from <v1-root> --to <new-v2-root>` command.
#[must_use]
pub fn v1_format_refusal_guidance(
    v1_root: &Path,
    suggested_v2_root: Option<&Path>,
) -> V1FormatRefusalGuidance {
    let suggested_dest = match suggested_v2_root {
        Some(path) => path.to_path_buf(),
        None => default_suggested_v2_path(v1_root),
    };
    let migrate_command = format!(
        "fss migrate --from {} --to {}",
        v1_root.display(),
        suggested_dest.display()
    );
    let reason = format!(
        "deployment root '{}' uses legacy v1 storage format; run `{migrate_command}` to perform a non-destructive v1-to-v2 migration",
        v1_root.display()
    );
    V1FormatRefusalGuidance {
        error_id: ERR_DEPLOYMENT_FORMAT_V1_001,
        source_root: v1_root.to_path_buf(),
        suggested_dest,
        migrate_command,
        reason,
    }
}

fn default_suggested_v2_path(v1_root: &Path) -> PathBuf {
    match (v1_root.parent(), v1_root.file_name()) {
        (Some(parent), Some(name)) => {
            let mut next_name = name.to_os_string();
            next_name.push("-v2");
            parent.join(next_name)
        }
        _ => PathBuf::from(format!("{}-v2", v1_root.display())),
    }
}

/// Inspects `root` read-only and classifies its on-disk deployment format version without locking
/// or mutating any file.
///
/// `.migrate-incomplete` ALWAYS takes precedence over `LAYOUT` so an interrupted migration can
/// never be mistaken for an active v2 deployment.
pub fn detect_deployment_format(root: &Path) -> Result<DeploymentFormatVersion, MigrationError> {
    let meta = match fs::symlink_metadata(root) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(DeploymentFormatVersion::NotADeployment {
                reason: "deployment root does not exist".to_owned(),
            });
        }
        Err(err) => {
            return Err(MigrationError::io("stat_root", err));
        }
    };
    if meta.file_type().is_symlink() {
        return Ok(DeploymentFormatVersion::NotADeployment {
            reason: "deployment root is a symlink".to_owned(),
        });
    }
    if !meta.is_dir() {
        return Ok(DeploymentFormatVersion::NotADeployment {
            reason: "deployment root is not a directory".to_owned(),
        });
    }

    let sentinel_path = root.join(MIGRATE_INCOMPLETE_FILENAME);
    match fs::symlink_metadata(&sentinel_path) {
        Ok(sentinel_meta) => {
            let detail = if sentinel_meta.is_file() {
                read_bounded_utf8(&sentinel_path, MAX_DESCRIPTOR_BYTES)
                    .unwrap_or_else(|_| "unreadable .migrate-incomplete sentinel".to_owned())
                    .trim()
                    .to_owned()
            } else {
                "non-regular .migrate-incomplete sentinel present".to_owned()
            };
            return Ok(DeploymentFormatVersion::MigrateIncomplete {
                marker_detail: detail,
            });
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(MigrationError::io("stat_migrate_sentinel", err)),
    }

    let restore_marker = root.join(RESTORE_INCOMPLETE_FILENAME);
    match fs::symlink_metadata(&restore_marker) {
        Ok(_) => {
            return Ok(DeploymentFormatVersion::NotADeployment {
                reason: "incomplete restore marker present".to_owned(),
            });
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(MigrationError::io("stat_restore_marker", err)),
    }

    let layout_path = root.join(DEPLOYMENT_LAYOUT_FILENAME);
    match fs::symlink_metadata(&layout_path) {
        Ok(layout_meta) if layout_meta.is_file() && !layout_meta.file_type().is_symlink() => {}
        Ok(_) => {
            return Ok(DeploymentFormatVersion::NotADeployment {
                reason: "LAYOUT is not a regular file".to_owned(),
            });
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(DeploymentFormatVersion::NotADeployment {
                reason: "missing LAYOUT descriptor".to_owned(),
            });
        }
        Err(err) => return Err(MigrationError::io("stat_layout", err)),
    }

    let layout_text = match read_bounded_utf8(&layout_path, MAX_DESCRIPTOR_BYTES) {
        Ok(text) => text,
        Err(reason) => {
            return Ok(DeploymentFormatVersion::NotADeployment { reason });
        }
    };

    if let Ok(v1_layout) = DeploymentLayout::parse_canonical_text(&layout_text) {
        return Ok(DeploymentFormatVersion::V1 { layout: v1_layout });
    }
    if let Ok(v2_layout) = DeploymentLayoutV2::parse_canonical_text(&layout_text) {
        let epochs_dir = root.join(&v2_layout.ledger_relpath).join("epochs");
        match fs::symlink_metadata(&epochs_dir) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {
                return Ok(DeploymentFormatVersion::V2 { layout: v2_layout });
            }
            _ => {
                return Ok(DeploymentFormatVersion::NotADeployment {
                    reason: "v2 LAYOUT present but ledger/epochs directory is missing".to_owned(),
                });
            }
        }
    }

    Ok(DeploymentFormatVersion::NotADeployment {
        reason: "LAYOUT matches neither canonical v1 nor canonical v2 schema".to_owned(),
    })
}

/// Requires `root` to be a complete, verified v2 deployment root, returning structured
/// [`ERR_DEPLOYMENT_FORMAT_V1_001`] guidance when invoked on a v1 root and refusing incomplete
/// migrations.
pub fn require_v2_deployment(root: &Path) -> Result<DeploymentLayoutV2, MigrationError> {
    match detect_deployment_format(root)? {
        DeploymentFormatVersion::V2 { layout } => Ok(layout),
        DeploymentFormatVersion::V1 { .. } => Err(MigrationError::UnsupportedV1Format(
            v1_format_refusal_guidance(root, None),
        )),
        DeploymentFormatVersion::MigrateIncomplete { marker_detail } => {
            Err(MigrationError::IncompleteMigration {
                path: root.to_path_buf(),
                detail: marker_detail,
            })
        }
        DeploymentFormatVersion::NotADeployment { reason } => Err(MigrationError::NotADeployment {
            path: root.to_path_buf(),
            reason,
        }),
    }
}

/// Fail-closed typed error surface for v1-to-v2 deployment migration and format detection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MigrationError {
    /// Destination path already exists; migration never overwrites or merges into existing paths.
    DestinationExists {
        /// Existing destination path.
        path: PathBuf,
    },
    /// Source or destination path failed strict local-path validation or overlapped.
    InvalidPath {
        /// Bounded explanation.
        detail: String,
    },
    /// Layout descriptor failed canonical parsing.
    InvalidLayout(String),
    /// Source v1 deployment is corrupt, has an incomplete tail, unfinished deletion, or failed
    /// linkage verification; repair before migrating.
    SourceNotClean {
        /// Specific cleanliness failure reason.
        detail: String,
    },
    /// Source path is already a v2 deployment root.
    SourceAlreadyV2 {
        /// Path of the already-v2 deployment.
        path: PathBuf,
    },
    /// Target path is not a recognized deployment root.
    NotADeployment {
        /// Inspected path.
        path: PathBuf,
        /// Reason the path was rejected.
        reason: String,
    },
    /// A v2-only operation was invoked against a v1 root; carries exact migration guidance.
    UnsupportedV1Format(V1FormatRefusalGuidance),
    /// Target directory holds an unremoved `.migrate-incomplete` sentinel.
    IncompleteMigration {
        /// Incomplete destination path.
        path: PathBuf,
        /// Marker detail observed on disk.
        detail: String,
    },
    /// Migration stopped cooperatively at a cancellation boundary.
    Cancelled {
        /// Stage where cancellation was observed.
        stage: &'static str,
    },
    /// Underlying v2 Merkle epoch ledger operation failed.
    Ledger(String),
    /// Underlying v2 packfile or virtual root catalog operation failed.
    Pack(String),
    /// Underlying MVCC projection store operation failed.
    Projection(String),
    /// Cryptographic equivalence or post-write verification failed.
    VerificationFailed {
        /// Detailed mismatch explanation.
        detail: String,
    },
    /// Underlying host filesystem I/O failure.
    Io {
        /// Bounded operation name.
        operation: &'static str,
        /// Standard I/O error kind.
        kind: io::ErrorKind,
        /// Human-readable detail.
        detail: String,
    },
}

impl MigrationError {
    pub(crate) fn io(operation: &'static str, err: io::Error) -> Self {
        Self::Io {
            operation,
            kind: err.kind(),
            detail: err.to_string(),
        }
    }

    /// Stable machine-readable error identity for diagnostics and CLI reporting.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::DestinationExists { .. } => ERR_MIGRATION_DESTINATION_EXISTS_001,
            Self::InvalidPath { .. } | Self::InvalidLayout(_) => ERR_MIGRATION_INVALID_PATH_001,
            Self::SourceNotClean { .. } => ERR_MIGRATION_SOURCE_NOT_CLEAN_001,
            Self::SourceAlreadyV2 { .. } => ERR_MIGRATION_SOURCE_ALREADY_V2_001,
            Self::NotADeployment { .. } => ERR_MIGRATION_NOT_A_DEPLOYMENT_001,
            Self::UnsupportedV1Format(_) => ERR_DEPLOYMENT_FORMAT_V1_001,
            Self::IncompleteMigration { .. } => ERR_DEPLOYMENT_MIGRATE_INCOMPLETE_001,
            Self::Cancelled { .. } => ERR_MIGRATION_CANCELLED_001,
            Self::Ledger(_)
            | Self::Pack(_)
            | Self::Projection(_)
            | Self::VerificationFailed { .. } => ERR_MIGRATION_VERIFICATION_FAILED_001,
            Self::Io { .. } => ERR_MIGRATION_IO_001,
        }
    }
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestinationExists { path } => write!(
                f,
                "migration destination '{}' already exists; refusing to overwrite",
                path.display()
            ),
            Self::InvalidPath { detail } => write!(f, "invalid migration path: {detail}"),
            Self::InvalidLayout(detail) => write!(f, "invalid deployment layout: {detail}"),
            Self::SourceNotClean { detail } => {
                write!(
                    f,
                    "source v1 deployment is not clean for migration: {detail}"
                )
            }
            Self::SourceAlreadyV2 { path } => write!(
                f,
                "source deployment '{}' is already in v2 format",
                path.display()
            ),
            Self::NotADeployment { path, reason } => write!(
                f,
                "'{}' is not a recognized deployment root: {reason}",
                path.display()
            ),
            Self::UnsupportedV1Format(guidance) => write!(
                f,
                "{} ({}): {}",
                guidance.error_id, guidance.migrate_command, guidance.reason
            ),
            Self::IncompleteMigration { path, detail } => write!(
                f,
                "deployment '{}' has an incomplete migration sentinel ({MIGRATE_INCOMPLETE_FILENAME}): {detail}",
                path.display()
            ),
            Self::Cancelled { stage } => {
                write!(f, "migration cancelled at stage '{stage}'")
            }
            Self::Ledger(detail) => write!(f, "v2 epoch ledger error: {detail}"),
            Self::Pack(detail) => write!(f, "v2 pack store error: {detail}"),
            Self::Projection(detail) => write!(f, "v2 projection store error: {detail}"),
            Self::VerificationFailed { detail } => {
                write!(f, "migration cryptographic verification failed: {detail}")
            }
            Self::Io {
                operation, detail, ..
            } => write!(f, "migration I/O failed during {operation}: {detail}"),
        }
    }
}

impl Error for MigrationError {}

impl From<crate::deletion::DeletionError> for MigrationError {
    fn from(err: crate::deletion::DeletionError) -> Self {
        Self::SourceNotClean {
            detail: format!("deletion history inspection failed: {err}"),
        }
    }
}

/// Pure RFC 8259 string escaping helper for deterministic zero-Serde JSON output.
pub(crate) fn escape_json_str(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                use core::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn read_bounded_utf8(path: &Path, max_bytes: usize) -> Result<String, String> {
    let file = fs::File::open(path).map_err(|err| format!("open failed: {err}"))?;
    let mut buf = Vec::new();
    let limit = (max_bytes as u64).saturating_add(1);
    file.take(limit)
        .read_to_end(&mut buf)
        .map_err(|err| format!("read failed: {err}"))?;
    if buf.len() > max_bytes {
        return Err(format!("file exceeds {max_bytes} byte limit"));
    }
    String::from_utf8(buf).map_err(|_| "file is not valid UTF-8".to_owned())
}
