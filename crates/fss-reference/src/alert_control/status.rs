#![forbid(unsafe_code)]
//! Bounded, read-only operation inventory for recovery when original evidence is unavailable.
//!
//! Only `LAYOUT` and the authority/effect journals are read. Their committed records still pass
//! their existing typed replay owners; source objects and terminal-proof payloads are never
//! hydrated. A recorded terminal state is not a fresh custody or delivery certification. All
//! three input files are read again before returning, so a changing history cannot silently
//! produce a mixed inventory. No deployment lock, restart recovery, repair, or write is used.

use std::io;
use std::path::Path;

use fss_core::{ContentDigest, DigestAlgorithm, LedgerAnchor, Obligation, OperationReceipt};
use fss_ledger::{
    DurableLedgerError, DurableLedgerStatus, HostJournalReadIo, JournalFileMetadata, JournalReadIo,
    inspect_durable_with_io,
};

pub use crate::deployment_status::StatusError;
use crate::doctor::MAX_LAYOUT_BYTES;
use crate::reference_deployment::{DEPLOYMENT_LAYOUT_FILENAME, DeploymentLayout};
use crate::{DurableEffectError, DurableEffectJournal};

use super::{MAX_ALERT_OPERATIONS, MAX_CONTROL_JOURNAL_BYTES};

/// Verified committed journal identities and recorded operation states, without object custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertOperationSnapshot {
    /// Site named by the validated deployment layout.
    pub site_lineage: String,
    /// Replayed authority anchor; a missing ledger is distinguished by its presence flag.
    pub anchor: LedgerAnchor,
    /// Raw committed effect-journal record root, or zero when absent or empty.
    pub effect_journal_root: ContentDigest,
    /// Whether the authority journal existed during both observations.
    pub ledger_journal_present: bool,
    /// Whether the effect journal existed during both observations.
    pub effect_journal_present: bool,
    /// An incomplete suffix remains outside the verified authority prefix.
    pub ledger_tail_uncommitted: bool,
    /// An incomplete suffix remains outside the verified effect prefix.
    pub effect_tail_uncommitted: bool,
    /// All recorded operations, bounded before cloning; callers may select alert dispatches.
    pub operations: Vec<OperationReceipt>,
    /// Journal-owned obligations; proof digests are references whose custody was not inspected.
    pub obligations: Vec<Obligation>,
}

impl AlertOperationSnapshot {
    /// The entire observed operation inventory is committed, not a source-availability claim.
    #[must_use]
    pub const fn complete_committed_snapshot(&self) -> bool {
        self.ledger_journal_present
            && self.effect_journal_present
            && !self.ledger_tail_uncommitted
            && !self.effect_tail_uncommitted
    }
}

/// Reads a local deployment's durable operations without opening its mutation/recovery owner.
pub fn read_alert_operations(root: &Path) -> Result<AlertOperationSnapshot, StatusError> {
    read_alert_operations_with_io(&HostJournalReadIo, root)
}

/// Reads through an explicit bounded filesystem capability, permitting deterministic fault tests.
///
/// At most 4096 operations and obligations are returned. Layout reads admit 4096 bytes, and each
/// journal admits 64 MiB. An absent journal leaves completeness unknown; corruption in committed
/// journal bytes or semantics is refused. Missing or damaged source/proof objects cannot hide
/// durable operation identities because those objects are outside this read's scope.
pub fn read_alert_operations_with_io(
    io: &dyn JournalReadIo,
    root: &Path,
) -> Result<AlertOperationSnapshot, StatusError> {
    let root_meta = io
        .symlink_metadata(root)
        .map_err(|_| StatusError::NotADeployment)?;
    if root_meta.is_file || root_meta.is_symlink {
        return Err(StatusError::NotADeployment);
    }
    let layout_path = root.join(DEPLOYMENT_LAYOUT_FILENAME);
    let layout_bytes =
        read_file(io, &layout_path, MAX_LAYOUT_BYTES)?.ok_or(StatusError::NotADeployment)?;
    let layout = DeploymentLayout::parse_canonical_text(
        std::str::from_utf8(&layout_bytes).map_err(|_| StatusError::NotADeployment)?,
    )
    .map_err(|_| StatusError::NotADeployment)?;
    let maximum =
        usize::try_from(MAX_CONTROL_JOURNAL_BYTES).map_err(|_| StatusError::OverBudget)?;
    let ledger_path = root.join(&layout.ledger_relpath);
    let effect_path = root.join(&layout.effects_relpath);
    let ledger_bytes = read_file(io, &ledger_path, maximum)?;
    let effect_bytes = read_file(io, &effect_path, maximum)?;

    // Doctor-oriented inspectors classify malformed fully present records as a foreign tail.
    // Recovery status must not silently discard such corruption: validate the entire bounded
    // input with the strict framing owner first. Genuine torn final records remain inspectable.
    if let Some(bytes) = &ledger_bytes {
        fss_ledger::recover_bytes(bytes).map_err(|_| StatusError::Corrupt)?;
    }
    let effect_journal_root = match &effect_bytes {
        Some(bytes) => fss_ledger::recover_bytes(bytes)
            .map_err(|_| StatusError::Corrupt)?
            .last_root(),
        None => ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]),
    };

    let ledger = inspect_durable_with_io(
        &SnapshotJournalIo {
            path: &ledger_path,
            bytes: ledger_bytes.as_deref(),
        },
        &ledger_path,
        layout.site_lineage.clone(),
        maximum,
    )
    .map_err(|error| match error {
        DurableLedgerError::OverBudget { .. } => StatusError::OverBudget,
        _ => StatusError::Corrupt,
    })?;
    let effects = DurableEffectJournal::inspect_with_io(
        &SnapshotJournalIo {
            path: &effect_path,
            bytes: effect_bytes.as_deref(),
        },
        &effect_path,
        maximum,
    )
    .map_err(|error| match error {
        DurableEffectError::OverBudget { .. } => StatusError::OverBudget,
        _ => StatusError::Corrupt,
    })?;
    let mut operations = Vec::new();
    let mut obligations = Vec::new();
    if let Some(journal) = &effects.journal {
        for operation in journal.operations() {
            if operations.len() == MAX_ALERT_OPERATIONS {
                return Err(StatusError::OverBudget);
            }
            operations.push(operation.clone());
        }
        for obligation in journal.obligations() {
            if obligations.len() == MAX_ALERT_OPERATIONS {
                return Err(StatusError::OverBudget);
            }
            obligations.push(obligation.clone());
        }
    }
    if read_file(io, &layout_path, MAX_LAYOUT_BYTES)?.as_deref() != Some(layout_bytes.as_slice())
        || read_file(io, &ledger_path, maximum)? != ledger_bytes
        || read_file(io, &effect_path, maximum)? != effect_bytes
    {
        return Err(StatusError::Changed);
    }
    Ok(AlertOperationSnapshot {
        site_lineage: layout.site_lineage,
        anchor: ledger.snapshot.anchor.clone(),
        effect_journal_root,
        ledger_journal_present: ledger.status == DurableLedgerStatus::Present,
        effect_journal_present: !effects.is_absent(),
        ledger_tail_uncommitted: !ledger.is_clean(),
        effect_tail_uncommitted: effects.incomplete_tail.is_some()
            || effects.foreign_range.is_some(),
        operations,
        obligations,
    })
}

fn read_file(
    io: &dyn JournalReadIo,
    path: &Path,
    maximum: usize,
) -> Result<Option<Vec<u8>>, StatusError> {
    let metadata = match io.symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(StatusError::Unreadable),
    };
    if metadata.is_symlink || !metadata.is_file {
        return Err(StatusError::Corrupt);
    }
    if metadata.len > u64::try_from(maximum).unwrap_or(u64::MAX) {
        return Err(StatusError::OverBudget);
    }
    let bytes = io
        .read_bounded(path, maximum.saturating_add(1))
        .map_err(|_| StatusError::Unreadable)?;
    if bytes.len() > maximum {
        return Err(StatusError::OverBudget);
    }
    Ok(Some(bytes))
}

/// Existing journal inspectors see a single already-bounded snapshot, including absence.
struct SnapshotJournalIo<'a> {
    path: &'a Path,
    bytes: Option<&'a [u8]>,
}

impl JournalReadIo for SnapshotJournalIo<'_> {
    fn symlink_metadata(&self, path: &Path) -> io::Result<JournalFileMetadata> {
        let bytes = self
            .bytes
            .filter(|_| path == self.path)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        Ok(JournalFileMetadata {
            is_file: true,
            is_symlink: false,
            len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        })
    }

    fn read_bounded(&self, path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
        let bytes = self
            .bytes
            .filter(|_| path == self.path)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        Ok(bytes
            .get(..maximum.min(bytes.len()))
            .unwrap_or_default()
            .to_vec())
    }
}
