#![forbid(unsafe_code)]
//! Explicit recovery actions and journal-framing integrity scanning for [`super::ReferenceDeployment`].

use std::fs::{self, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::ContentDigest;
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy, RepairReceipt, doctor};
use fss_object::{HostSpoolIo, SpoolLock};
use fss_publication::LocalPublicationError;

use super::ReferenceDeployment;
use super::constants::{
    DEPLOYMENT_LAYOUT_FILENAME, RELATIVE_PATH_EFFECTS, RELATIVE_PATH_LEDGER, RELATIVE_PATH_OBJECTS,
    STAGE_DEPLOYMENT_OPEN,
};
use super::layout::DeploymentLayout;
use crate::adapter_replay::ReplayCx;
use crate::durable_effect::DurableEffectJournal;
use crate::error::ReferenceError;

const ROOT_DOMAIN: &[u8] = b"FSS-JOURNAL-RECORD-ROOT-V1\0";
const RECORD_MAGIC: [u8; 8] = *b"FSSJRN01";
const COMMIT_MAGIC: [u8; 8] = *b"FSSCMT01";
const FORMAT_VERSION: u16 = 1;
const HEADER_LEN: usize = 88;
const TRAILER_LEN: usize = 40;
const MAX_RECORD_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

fn compute_record_root(
    sequence: u64,
    kind: u16,
    payload_len: u32,
    previous_root: &[u8; 32],
    payload_digest: &[u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(ROOT_DOMAIN.len() + 8 + 2 + 4 + 32 + 32);
    bytes.extend_from_slice(ROOT_DOMAIN);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.extend_from_slice(previous_root);
    bytes.extend_from_slice(payload_digest);
    fss_core::sha256(&bytes)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn is_structurally_valid_record(slice: &[u8]) -> bool {
    if slice.len() < HEADER_LEN + TRAILER_LEN {
        return false;
    }
    if slice[0..8] != RECORD_MAGIC {
        return false;
    }
    if read_u16(slice, 8) != FORMAT_VERSION {
        return false;
    }
    let sequence = read_u64(slice, 10);
    let kind = read_u16(slice, 18);
    let payload_len = read_u32(slice, 20);
    let payload_len_usize = match usize::try_from(payload_len) {
        Ok(len) if len <= MAX_RECORD_PAYLOAD_BYTES => len,
        _ => return false,
    };
    let total_len = HEADER_LEN + payload_len_usize + TRAILER_LEN;
    if slice.len() < total_len {
        return false;
    }
    let mut previous_root = [0_u8; 32];
    previous_root.copy_from_slice(&slice[24..56]);
    let mut named_payload_digest = [0_u8; 32];
    named_payload_digest.copy_from_slice(&slice[56..88]);

    let payload = &slice[88..88 + payload_len_usize];
    if fss_core::sha256(payload) != named_payload_digest {
        return false;
    }

    let trailer_offset = 88 + payload_len_usize;
    if slice[trailer_offset..trailer_offset + 8] != COMMIT_MAGIC {
        return false;
    }

    let mut committed_root = [0_u8; 32];
    committed_root.copy_from_slice(&slice[trailer_offset + 8..trailer_offset + 40]);

    let expected_root = compute_record_root(
        sequence,
        kind,
        payload_len,
        &previous_root,
        &named_payload_digest,
    );
    committed_root == expected_root
}

pub(crate) fn find_structurally_valid_record(
    bytes: &[u8],
    foreign_offset: u64,
    foreign_length: u64,
) -> Option<u64> {
    let start = foreign_offset as usize;
    let end = (foreign_offset.saturating_add(foreign_length)) as usize;
    if start >= bytes.len() || end > bytes.len() || start >= end {
        return None;
    }
    let slice = &bytes[start..end];
    let magic = &RECORD_MAGIC;
    for (i, window) in slice.windows(magic.len()).enumerate() {
        if window == magic {
            let candidate_slice = &slice[i..];
            if is_structurally_valid_record(candidate_slice) {
                return Some(foreign_offset + i as u64);
            }
        }
    }
    None
}

/// Recovery action requested when invoking [`ReferenceDeployment::open_for_recovery`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    /// Truncate an incomplete record tail from the authority ledger journal.
    TruncateIncompleteLedgerTail,
    /// Truncate an incomplete record tail from the durable effect journal.
    TruncateIncompleteEffectTail,
    /// Apply a pre-computed sealed repair plan to quarantine trailing foreign bytes in the ledger.
    ApplySealedLedgerRepair {
        /// Expected plan digest.
        plan_digest: ContentDigest,
    },
    /// Apply a pre-computed sealed repair plan to quarantine trailing foreign bytes in the effect journal.
    ApplySealedEffectRepair {
        /// Expected plan digest.
        plan_digest: ContentDigest,
    },
}

/// Typed receipt produced by an explicit recovery action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryReceipt {
    /// Incomplete ledger tail was truncated.
    TruncatedLedgerTail {
        /// Journal path.
        path: PathBuf,
        /// File offset through the last complete committed record.
        committed_len: u64,
        /// Number of incomplete trailing bytes truncated.
        truncated_bytes: u64,
        /// Last root digest before truncation.
        last_root_before: ContentDigest,
        /// Last root digest after truncation.
        last_root_after: ContentDigest,
    },
    /// Incomplete effect tail was truncated.
    TruncatedEffectTail {
        /// Journal path.
        path: PathBuf,
        /// File offset through the last complete committed record.
        committed_len: u64,
        /// Number of incomplete trailing bytes truncated.
        truncated_bytes: u64,
        /// Last root digest before truncation.
        last_root_before: ContentDigest,
        /// Last root digest after truncation.
        last_root_after: ContentDigest,
    },
    /// Sealed ledger repair plan was applied.
    AppliedLedgerRepair(RepairReceipt),
    /// Sealed effect repair plan was applied.
    AppliedEffectRepair(RepairReceipt),
}

impl ReferenceDeployment {
    /// Performs an explicit recovery action on a deployment root while holding the deployment lock.
    ///
    /// Never creates LAYOUT on an uninitialized root. Refuses recovery if foreign bytes contain
    /// a structurally valid committed record.
    pub fn open_for_recovery(
        root: &Path,
        action: RecoveryAction,
        cx: &ReplayCx,
    ) -> Result<RecoveryReceipt, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_DEPLOYMENT_OPEN,
            });
        }

        let root_buf = root.to_path_buf();
        // Classify the root before probing a child path, retaining real metadata errors.
        match fs::metadata(root) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(ReferenceError::NotADeployment { path: root_buf }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ReferenceError::NotADeployment { path: root_buf });
            }
            Err(error) => return Err(ReferenceError::Io(error)),
        }
        // An inert backup payload or incomplete restoration is not a repairable live root.
        // Refuse before opening locks, truncating journals or clearing temporary layout files.
        match fs::symlink_metadata(root.join(crate::deployment_backup::RESTORE_INCOMPLETE_FILENAME))
        {
            Ok(_) => return Err(ReferenceError::NotADeployment { path: root_buf }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ReferenceError::Io(error)),
        }

        let layout_path = root.join(DEPLOYMENT_LAYOUT_FILENAME);

        // Acquire exclusive deployment lock on <root>/objects/LOCK for the whole recovery duration.
        // open_for_recovery must NOT create objects/.
        let objects_dir = root.join(RELATIVE_PATH_OBJECTS);
        if !objects_dir.exists() || !objects_dir.is_dir() {
            return Err(ReferenceError::NotADeployment { path: root_buf });
        }
        let lock_path = objects_dir.join("LOCK");
        match fs::symlink_metadata(&lock_path) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(ReferenceError::LocalPublication(Box::new(
                    LocalPublicationError::InvalidLayout { path: lock_path },
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ReferenceError::Io(error)),
        }
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        let _lock = match SpoolLock::try_acquire(lock_file, Arc::new(HostSpoolIo)) {
            Ok(lock) => lock,
            Err(TryLockError::WouldBlock) => {
                return Err(ReferenceError::DeploymentLocked { path: lock_path });
            }
            Err(TryLockError::Error(e)) => return Err(ReferenceError::Io(e)),
        };

        // Recheck the activation boundary under the same exclusive deployment lock.
        match fs::symlink_metadata(root.join(crate::deployment_backup::RESTORE_INCOMPLETE_FILENAME))
        {
            Ok(_) => return Err(ReferenceError::NotADeployment { path: root_buf }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ReferenceError::Io(error)),
        }

        // Under lock: clean up stale LAYOUT.tmp.*
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("LAYOUT.tmp.") {
                fs::remove_file(entry.path())?;
            }
        }

        // Verify layout descriptor exists and is valid; open_for_recovery never creates LAYOUT.
        let layout = if layout_path.exists() {
            let content = fs::read_to_string(&layout_path)?;
            DeploymentLayout::parse_canonical_text(&content)?
        } else {
            return Err(ReferenceError::NotADeployment { path: root_buf });
        };

        match action {
            RecoveryAction::TruncateIncompleteLedgerTail => {
                let target_path = root.join(RELATIVE_PATH_LEDGER);
                if !target_path.exists() {
                    return Err(ReferenceError::NoIncompleteTail { path: target_path });
                }
                let pre_report = fss_ledger::inspect(&target_path)?;
                if pre_report.incomplete_tail().is_none() {
                    return Err(ReferenceError::NoIncompleteTail { path: target_path });
                }
                let total_len = fs::metadata(&target_path)?.len();
                let committed_len = pre_report.committed_len();
                let truncated_bytes = total_len.saturating_sub(committed_len);
                let last_root_before = pre_report.last_root();
                let _opened = DurableReferenceLedger::open(
                    &target_path,
                    &layout.site_lineage,
                    IncompleteTailPolicy::Truncate,
                )?;
                let post_report = fss_ledger::inspect(&target_path)?;
                let last_root_after = post_report.last_root();
                Ok(RecoveryReceipt::TruncatedLedgerTail {
                    path: target_path,
                    committed_len,
                    truncated_bytes,
                    last_root_before,
                    last_root_after,
                })
            }
            RecoveryAction::TruncateIncompleteEffectTail => {
                let target_path = root.join(RELATIVE_PATH_EFFECTS);
                if !target_path.exists() {
                    return Err(ReferenceError::NoIncompleteTail { path: target_path });
                }
                let pre_report = fss_ledger::inspect(&target_path)?;
                if pre_report.incomplete_tail().is_none() {
                    return Err(ReferenceError::NoIncompleteTail { path: target_path });
                }
                let total_len = fs::metadata(&target_path)?.len();
                let committed_len = pre_report.committed_len();
                let truncated_bytes = total_len.saturating_sub(committed_len);
                let last_root_before = pre_report.last_root();
                let _opened =
                    DurableEffectJournal::open(&target_path, IncompleteTailPolicy::Truncate)?;
                let post_report = fss_ledger::inspect(&target_path)?;
                let last_root_after = post_report.last_root();
                Ok(RecoveryReceipt::TruncatedEffectTail {
                    path: target_path,
                    committed_len,
                    truncated_bytes,
                    last_root_before,
                    last_root_after,
                })
            }
            RecoveryAction::ApplySealedLedgerRepair { plan_digest } => {
                let target_path = root.join(RELATIVE_PATH_LEDGER);
                let bytes = fs::read(&target_path)?;
                let report = doctor(&bytes)?;
                let foreign = report
                    .foreign_range()
                    .ok_or(fss_ledger::RepairError::NoForeignBytes)?;

                if let Some(offset) =
                    find_structurally_valid_record(&bytes, foreign.offset, foreign.length)
                {
                    return Err(ReferenceError::RecoverCorruptHistory {
                        path: target_path,
                        offset,
                    });
                }

                let plan = report.plan(&target_path)?;
                if plan.plan_digest() != plan_digest {
                    return Err(ReferenceError::PlanDigestMismatch {
                        expected: plan_digest,
                        actual: plan.plan_digest(),
                    });
                }
                let receipt = plan.apply()?;
                Ok(RecoveryReceipt::AppliedLedgerRepair(receipt))
            }
            RecoveryAction::ApplySealedEffectRepair { plan_digest } => {
                let target_path = root.join(RELATIVE_PATH_EFFECTS);
                let bytes = fs::read(&target_path)?;
                let report = doctor(&bytes)?;
                let foreign = report
                    .foreign_range()
                    .ok_or(fss_ledger::RepairError::NoForeignBytes)?;

                if let Some(offset) =
                    find_structurally_valid_record(&bytes, foreign.offset, foreign.length)
                {
                    return Err(ReferenceError::RecoverCorruptHistory {
                        path: target_path,
                        offset,
                    });
                }

                let plan = report.plan(&target_path)?;
                if plan.plan_digest() != plan_digest {
                    return Err(ReferenceError::PlanDigestMismatch {
                        expected: plan_digest,
                        actual: plan.plan_digest(),
                    });
                }
                let receipt = plan.apply()?;
                Ok(RecoveryReceipt::AppliedEffectRepair(receipt))
            }
        }
    }
}
