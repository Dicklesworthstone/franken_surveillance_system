#![forbid(unsafe_code)]
//! Non-mutating local publication inspection and verified read entrypoints.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::ContentDigest;
use fss_object::{HostSpoolIo, SpoolInspection, SpoolIo};

use super::classify::{
    LocalClassification, LocalLayout, RedundantTemp, ReferenceCheck, classify_local,
};
use super::fs_io::{compute_closure, directory_present, unreferenced_spool_objects};
use super::{
    BlockReason, LOCAL_LOCK_FILE, LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR, LOCAL_TOMBSTONES_DIR,
    LocalInspection, LocalPublicationError, LocalPublicationLimits, LocalRecoveryReport,
    LockTableSource, WriterDetectionOptions, detect_writers,
};

/// Read-only reference checks for inspection.
///
/// The spool classification has already reread and rehashed every object file, so a reference
/// passes exactly when the open's verify would accept it for the same bytes: admitted objects
/// pass, corrupt (including vanished) ones are `Corrupt`, anything unindexed is `Missing`.
/// Manifest bodies are reread and rehashed without the lock; nothing is held or written.
struct ObservedReferences<'a> {
    io: &'a dyn SpoolIo,
    spool_root: PathBuf,
    max_object_bytes: usize,
    admitted: BTreeSet<ContentDigest>,
    corrupt: BTreeSet<ContentDigest>,
}

impl ReferenceCheck for ObservedReferences<'_> {
    fn check_reference(
        &mut self,
        object: ContentDigest,
    ) -> Result<Result<(), BlockReason>, LocalPublicationError> {
        if self.corrupt.contains(&object) {
            return Ok(Err(BlockReason::Corrupt));
        }
        if self.admitted.contains(&object) {
            return Ok(Ok(()));
        }
        Ok(Err(BlockReason::Missing))
    }

    fn manifest_body(&mut self, root: ContentDigest) -> Result<Vec<u8>, LocalPublicationError> {
        fss_object::read_verified_payload(&self.spool_root, root, self.max_object_bytes, self.io)
            .map_err(LocalPublicationError::Spool)
    }

    fn redundant_temp(&mut self, _path: &Path) -> RedundantTemp {
        RedundantTemp::Reported
    }
}

/// Inspects a local publication root without taking locks, creating directories, or repairing
/// state, with the host filesystem and the default read-only writer check. See
/// [`inspect_with_io`].
pub fn inspect(
    root: impl AsRef<Path>,
    limits: impl Into<LocalPublicationLimits>,
) -> Result<LocalInspection, LocalPublicationError> {
    inspect_with_io(
        &HostSpoolIo,
        root.as_ref(),
        limits.into(),
        None,
        WriterDetectionOptions::default(),
    )
}

/// [`inspect_with_io`] taking a shared I/O capability.
pub fn inspect_with_options(
    io: Arc<dyn SpoolIo>,
    root: &Path,
    limits: LocalPublicationLimits,
    lock_table: Option<&dyn LockTableSource>,
    options: WriterDetectionOptions,
) -> Result<LocalInspection, LocalPublicationError> {
    inspect_with_io(io.as_ref(), root, limits, lock_table, options)
}

/// Inspects a local publication root through explicit I/O and lock-table capabilities.
///
/// Only lists, stats, and reads through `io`: it never creates, locks, renames, removes, or
/// fsyncs, and the only lock call is the opt-in shared probe of
/// [`WriterDetectionOptions::probe_shared_lock`]. The spool and the root are classified by the
/// same classifiers the open runs (see [`LocalInspection`] for the documented differences). A
/// listing over its bound is the typed [`LocalPublicationError::EntryLimit`] or
/// [`fss_object::SpoolError::EntryLimit`] the open returns.
pub fn inspect_with_io(
    io: &dyn SpoolIo,
    root: &Path,
    limits: LocalPublicationLimits,
    lock_table: Option<&dyn LockTableSource>,
    options: WriterDetectionOptions,
) -> Result<LocalInspection, LocalPublicationError> {
    inspect_with_ledger_journal(io, root, None, limits, lock_table, options)
}

/// [`inspect_with_io`] that also checks the deployment's canonical ledger journal for a writer.
///
/// `root` is the publication root; writer detection checks exactly `<root>/LOCK`,
/// `<root>/spool/LOCK`, and `ledger_journal` when given. The journal path is always passed
/// explicitly, never derived from the publication root, because the deployment layout places it
/// beside the publication root (a ledger repair apply flocks it). With `None` the journal is not
/// checked.
pub fn inspect_with_ledger_journal(
    io: &dyn SpoolIo,
    root: &Path,
    ledger_journal: Option<&Path>,
    limits: LocalPublicationLimits,
    lock_table: Option<&dyn LockTableSource>,
    options: WriterDetectionOptions,
) -> Result<LocalInspection, LocalPublicationError> {
    let limits = limits.validate()?;
    let spool_root = root.join(LOCAL_SPOOL_DIR);
    let root_present = directory_present(io, root)?;
    let (roots, tombstones) = if root_present {
        (
            directory_present(io, &root.join(LOCAL_ROOTS_DIR))?,
            directory_present(io, &root.join(LOCAL_TOMBSTONES_DIR))?,
        )
    } else {
        (false, false)
    };
    let spool = if root_present {
        fss_object::inspect_with_io(&spool_root, &limits.spool, io)
            .map_err(LocalPublicationError::Spool)?
    } else {
        SpoolInspection {
            missing_layout: true,
            ..SpoolInspection::default()
        }
    };
    let classified = if root_present {
        let mut references = ObservedReferences {
            io,
            spool_root: spool_root.clone(),
            max_object_bytes: limits.spool.max_object_bytes,
            admitted: spool.report.admitted.iter().copied().collect(),
            corrupt: spool.report.corrupt.iter().map(|c| c.digest).collect(),
        };
        let layout = LocalLayout { roots, tombstones };
        classify_local(
            io,
            root,
            &limits,
            layout,
            spool.report.clone(),
            &mut references,
        )?
    } else {
        LocalClassification {
            report: LocalRecoveryReport {
                spool: spool.report.clone(),
                ..LocalRecoveryReport::default()
            },
            ..LocalClassification::default()
        }
    };

    let LocalClassification {
        mut report,
        redundant_temps,
        visible,
        broken_slots,
        ..
    } = classified;
    // Every admitted root is one the open would fsync and admit, so closures span all of them.
    // Their state stays `Visible`: this inspection observed no fsync.
    let manifests: BTreeMap<ContentDigest, &[ContentDigest]> = visible
        .values()
        .map(|entry| (entry.visible.root, entry.children.as_slice()))
        .collect();
    let mut referenced = BTreeSet::new();
    let mut root_closures = BTreeMap::new();
    for (slot, entry) in &visible {
        let closure = compute_closure(&manifests, entry.visible.root, &entry.children);
        referenced.extend(closure.iter().copied());
        root_closures.insert(slot.clone(), closure);
        report.roots.push(entry.visible.clone());
    }
    report.unreferenced_objects = unreferenced_spool_objects(&report.spool, &referenced);

    let mut lock_paths = vec![
        root.join(LOCAL_LOCK_FILE),
        spool_root.join(fss_object::SPOOL_LOCK_FILE),
    ];
    lock_paths.extend(ledger_journal.map(Path::to_path_buf));
    let writer_state = detect_writers(io, &lock_paths, lock_table, options);
    let possibly_stale = writer_state.possibly_stale();
    let possibly_in_flight = writer_state.is_held()
        || !redundant_temps.is_empty()
        || !report.spool.orphaned_staging.is_empty();

    Ok(LocalInspection {
        report,
        redundant_temps,
        durability_not_resynced: !visible.is_empty(),
        holds_migration_pending: spool.holds_migration_pending,
        missing_layout: !root_present || !roots || !tombstones || spool.missing_layout,
        spool_over_capacity: spool.over_capacity,
        writer_state,
        root_closures,
        broken_slots,
        possibly_stale,
        possibly_in_flight,
    })
}

/// Reads and verifies an object's payload directly from a deployment's spool
/// without taking locks, creating holds, or modifying state.
pub fn read_verified(
    root: impl AsRef<Path>,
    digest: ContentDigest,
    max_bytes: usize,
) -> Result<Vec<u8>, LocalPublicationError> {
    read_verified_with_io(root.as_ref(), digest, max_bytes, &HostSpoolIo)
}

/// Reads and verifies an object's payload through the given I/O capability without taking
/// locks, creating holds, or modifying state.
///
/// A missing or non-directory `<root>/spool` is [`LocalPublicationError::InvalidLayout`]; the
/// root itself is never read as a spool. A payload longer than `max_bytes` or bytes that do not
/// rehash to `digest` are [`fss_object::SpoolError::Corrupt`].
pub fn read_verified_with_io(
    root: &Path,
    digest: ContentDigest,
    max_bytes: usize,
    io: &dyn SpoolIo,
) -> Result<Vec<u8>, LocalPublicationError> {
    let spool_root = root.join(LOCAL_SPOOL_DIR);
    if !directory_present(io, &spool_root)? {
        return Err(LocalPublicationError::InvalidLayout { path: spool_root });
    }
    fss_object::read_verified_payload(&spool_root, digest, max_bytes, io)
        .map_err(LocalPublicationError::Spool)
}
