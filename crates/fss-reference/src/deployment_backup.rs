#![forbid(unsafe_code)]
//! Current-format recovery of the core local deployment, with exact original custody.
//!
//! A bundle is a private copy of a verified deployment prefix, not a live replica. The source
//! is never opened for mutation or reconciliation. Restoration keeps that prefix, appends an
//! irreversible effect fence, and activates LAYOUT last. No alert or adapter is invoked here.
//! Populated native agent state uses a separate versioned profile and remains historical
//! read-only after restore. External archives and secret stores remain unsupported.

use std::path::Path;

use fss_core::{ContentDigest, LedgerAnchor};

use crate::{DeploymentLimits, ReplayCx};

mod agent;
mod io;
mod manifest;
mod snapshot;
mod transfer;

pub use agent::{AgentBackupSummary, AgentPublicationState, AgentRecoveryState};
pub use manifest::{BackupFile, BackupManifest, RestoreFence};
pub use transfer::{
    create_backup, inspect_agent_state, inspect_backup, prepare_backup, restore_backup,
};

/// Exact supported semantic profile. Unknown profiles are refused, never migrated implicitly.
pub const BACKUP_PROFILE: &str = "reference-core-local-v1";
/// Native agent recovery profile; restored sessions and claims remain historical only.
pub const AGENT_BACKUP_PROFILE: &str = "reference-local-with-agent-v1";
/// Additive manifest domain for the native agent recovery profile.
pub const AGENT_BACKUP_MANIFEST_DOMAIN: &str = "fss.deployment_backup_manifest.v2";
/// Manifest commitment domain, independent of convenience JSON.
pub const BACKUP_MANIFEST_DOMAIN: &str = "fss.deployment_backup_manifest.v1";
/// The sole completion record at the root of a recovery bundle.
pub const BACKUP_MANIFEST_FILENAME: &str = "MANIFEST";
/// Copied deployment tree beneath a bundle; never opened as a live deployment by this module.
pub const BACKUP_PAYLOAD_DIRECTORY: &str = "payload";
/// A partial restoration is refused by normal deployment opening, even if LAYOUT exists.
pub const RESTORE_INCOMPLETE_FILENAME: &str = "RESTORE_INCOMPLETE";
/// Reserved authority family: restored deployments may not prepare or dispatch alerts.
pub const FAMILY_RESTORE_FENCE: &str = "deployment_restore_fence";
/// Stable authority object of the irreversible restore fence.
pub const RESTORE_FENCE_OBJECT_ID: &str = "object:deployment:restore-fence";
/// Canonical retained provenance of a restoration fence.
pub const RESTORE_FENCE_DOMAIN: &str = "fss.deployment_restore_fence.v1";

/// Before each source/bundle read and between bounded filesystem steps.
pub const STAGE_BACKUP_READ: &str = "deployment_backup:read";
/// Before each copied file, with live disclosure and destination authority rechecked.
pub const STAGE_BACKUP_COPY: &str = "deployment_backup:copy";
/// Final cancellation boundary before a bundle manifest is published.
pub const STAGE_BACKUP_PUBLISH: &str = "deployment_backup:publish";
/// After destination reservation; cancellation leaves the explicit incomplete marker.
pub const STAGE_RESTORE_RESERVED: &str = "deployment_backup:restore_reserved";
/// After the copied authority prefix acquired its durable restoration fence.
pub const STAGE_RESTORE_FENCED: &str = "deployment_backup:restore_fenced";
/// Last cancellation boundary before LAYOUT activation.
pub const STAGE_RESTORE_ACTIVATE: &str = "deployment_backup:restore_activate";

/// Separate, exact original-read and destination-write grants. No variant supplies authority.
#[derive(Clone, Copy, Debug)]
pub enum BackupAccess<'a> {
    /// Inspect every original in this selected core deployment.
    ReadDeployment { source: &'a Path },
    /// Retain this exact approved deployment snapshot in a new bundle.
    WriteBundle {
        source: &'a Path,
        bundle: &'a Path,
        manifest: ContentDigest,
    },
    /// Read the exact independently pinned recovery bundle.
    ReadBundle {
        bundle: &'a Path,
        manifest: ContentDigest,
    },
    /// Retain that exact bundle as a fenced deployment at a new destination.
    RestoreDeployment {
        bundle: &'a Path,
        destination: &'a Path,
        manifest: ContentDigest,
    },
}

/// Caller-owned live permission check, including revocation, disclosure and destination policy.
pub trait BackupAuthority: Sync {
    /// Permit exactly the supplied access; implementations must not infer grants from filenames.
    fn permit(&self, access: BackupAccess<'_>) -> bool;
}

/// Bounds on the complete inventory and each bounded read; no file or object is truncated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupLimits {
    /// Includes journal/layout, object envelopes, verification markers and publication records.
    pub max_files: usize,
    /// Maximum file length, including a spool envelope's 52-byte header.
    pub max_file_bytes: u64,
    /// Aggregate inventory bytes. Each object is copied once even when many roots share it.
    pub max_total_bytes: u64,
    /// Maximum canonical manifest bytes, checked before parsing or cloning inventory fields.
    pub max_manifest_bytes: usize,
    /// Maximum complete journal bytes admitted by the existing semantic readers.
    pub max_journal_bytes: usize,
}
impl Default for BackupLimits {
    fn default() -> Self {
        Self {
            max_files: 131_584,
            max_file_bytes: 64 * 1024 * 1024 + 52,
            max_total_bytes: 1024 * 1024 * 1024,
            max_manifest_bytes: 32 * 1024 * 1024,
            max_journal_bytes: 64 * 1024 * 1024,
        }
    }
}
impl BackupLimits {
    pub(super) fn validate(self) -> Result<()> {
        if self.max_files > 262_144
            || self.max_file_bytes > 256 * 1024 * 1024 + 52
            || self.max_total_bytes > 4 * 1024 * 1024 * 1024
            || self.max_manifest_bytes > 64 * 1024 * 1024
            || self.max_journal_bytes > 256 * 1024 * 1024
        {
            return Err(BackupError::Limit("configured_limit"));
        }
        Ok(())
    }
}

/// Fail-closed recovery outcomes. No error claims that a partial destination is activated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackupError {
    /// Live original-read or destination authority refused the request.
    Unauthorized,
    /// Request cancellation before the activation point.
    Cancelled,
    /// A deployment or bundle writer still owns a required lock.
    Locked,
    /// An admitted resource ceiling was exhausted.
    Limit(&'static str),
    /// Unknown version/profile, invalid layout, unsafe file type or unsupported populated state.
    Unsupported(&'static str),
    /// A committed object, journal or declared graph failed verification.
    Corrupt(&'static str),
    /// Explicit recovery/reconciliation is required before a clean snapshot can be copied.
    RecoveryRequired(&'static str),
    /// The expected snapshot or a previously observed source changed.
    Changed,
    /// No existing destination is ever overwritten or merged.
    DestinationExists,
    /// The path overlaps the source or fails the strict local-path contract.
    InvalidPath,
    /// I/O failed before completion; a reserved destination remains explicitly incomplete.
    Io(std::io::ErrorKind),
    /// A final activation filesystem operation may have completed; inspect before retrying.
    Indeterminate,
}
impl BackupError {
    /// Stable non-disclosing machine classification.
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Unauthorized => "backup_authority_refused",
            Self::Cancelled => "backup_cancelled",
            Self::Locked => "backup_source_locked",
            Self::Limit(_) => "backup_budget_exhausted",
            Self::Unsupported(_) => "backup_profile_unsupported",
            Self::Corrupt(_) => "backup_verification_failed",
            Self::RecoveryRequired(_) => "backup_source_recovery_required",
            Self::Changed => "backup_snapshot_changed",
            Self::DestinationExists => "backup_destination_exists",
            Self::InvalidPath => "backup_path_refused",
            Self::Io(_) => "backup_io_failed",
            Self::Indeterminate => "backup_activation_indeterminate",
        }
    }
}
impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Limit(reason)
            | Self::Unsupported(reason)
            | Self::Corrupt(reason)
            | Self::RecoveryRequired(reason) => write!(f, "{}: {reason}", self.reason()),
            _ => f.write_str(self.reason()),
        }
    }
}
impl std::error::Error for BackupError {}
impl From<std::io::Error> for BackupError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}
impl From<fss_core::ContractError> for BackupError {
    fn from(_: fss_core::ContractError) -> Self {
        Self::Corrupt("canonical_encoding")
    }
}
impl From<crate::deletion::DeletionError> for BackupError {
    fn from(_: crate::deletion::DeletionError) -> Self {
        Self::Corrupt("deletion_authority")
    }
}
/// Result of one bounded local recovery operation.
pub type Result<T> = std::result::Result<T, BackupError>;

/// A complete published bundle. Its payload remains private original evidence.
#[derive(Clone, Debug)]
pub struct BackupReceipt {
    pub(super) manifest: BackupManifest,
}
impl BackupReceipt {
    /// Exact independent identity to pin before using the bundle for restoration.
    pub fn manifest(&self) -> &BackupManifest {
        &self.manifest
    }
}
/// A restored historical prefix plus a new irreversible authority fence.
#[derive(Clone, Debug)]
pub struct RestoreReceipt {
    pub(super) manifest: BackupManifest,
    pub(super) destination_anchor: LedgerAnchor,
    pub(super) destination_ledger_root: ContentDigest,
    pub(super) fence_digest: ContentDigest,
}
impl RestoreReceipt {
    /// Exact original snapshot, before the destination's appended fence.
    pub fn manifest(&self) -> &BackupManifest {
        &self.manifest
    }
    /// The new head after the fenced restore, preserving the historical source prefix.
    pub fn destination_anchor(&self) -> &LedgerAnchor {
        &self.destination_anchor
    }
    /// Complete durable destination journal root after the fence append.
    pub const fn destination_ledger_root(&self) -> ContentDigest {
        self.destination_ledger_root
    }
    /// Retained canonical fence record committed by the destination authority.
    pub const fn fence_digest(&self) -> ContentDigest {
        self.fence_digest
    }
}

pub(super) fn authorize(
    authority: &dyn BackupAuthority,
    access: BackupAccess<'_>,
    cx: &ReplayCx,
) -> Result<()> {
    cx.checkpoint(STAGE_BACKUP_READ)
        .map_err(|_| BackupError::Cancelled)?;
    if !cx.io_authority().is_valid() || !authority.permit(access) {
        return Err(BackupError::Unauthorized);
    }
    Ok(())
}
