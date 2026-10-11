#![forbid(unsafe_code)]
//! Complete current-format inventory, checked against the existing semantic storage readers.

use std::collections::BTreeSet;
use std::path::Path;

use fss_core::ContentDigest;
use fss_ledger::{DurableLedgerLimits, DurableLedgerStatus};
use fss_object::SpoolIo;
use fss_publication::WriterDetectionOptions;

use crate::deletion::DeletionIndex;
use crate::{DeploymentLayout, DurableEffectJournal};

use super::io::{ReadIo, directory, regular};
use super::manifest::{
    BackupFile, BackupManifest, named_digest, valid_path, validate_deployment_limits,
};
use super::{BackupError, BackupLimits, DeploymentLimits, RESTORE_INCOMPLETE_FILENAME, Result};

pub(super) const DIRECTORIES: &[&str] = &[
    "ledger",
    "effects",
    "objects",
    "objects/roots",
    "objects/tombstones",
    "objects/spool",
    "objects/spool/objects",
    "objects/spool/staging",
    "objects/spool/verified",
];
/// Bundle payloads always remain inert, including after an interrupted inspection or copy.
pub(super) const PAYLOAD_GUARD: &[u8] = b"fss.deployment_backup.inert_payload.v1\n";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum SnapshotKind {
    Source,
    BundlePayload,
}

pub(super) fn inventory(
    root: &Path,
    limits: BackupLimits,
    io: &ReadIo<'_>,
    kind: SnapshotKind,
) -> Result<Vec<BackupFile>> {
    directory(root)?;
    let mut files = Vec::new();
    let mut total = 0_u64;
    let mut seen_dirs = BTreeSet::new();
    let mut seen_locks = BTreeSet::new();
    let mut guard_seen = false;
    for relative in std::iter::once("").chain(DIRECTORIES.iter().copied()) {
        let path = root.join(relative);
        directory(&path).map_err(|_| BackupError::RecoveryRequired("missing_directory"))?;
        let mut listing = SpoolIo::read_dir(io, &path)?;
        let mut entries = 0_usize;
        while let Some(entry) = SpoolIo::next_dir_entry(io, &mut listing) {
            io.check()?;
            entries = entries
                .checked_add(1)
                .ok_or(BackupError::Limit("directory_entries"))?;
            if entries > limits.max_files.saturating_add(16) {
                return Err(BackupError::Limit("directory_entries"));
            }
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| BackupError::Unsupported("filename_encoding"))?;
            let name = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            let metadata = SpoolIo::symlink_metadata(io, &entry.path())?;
            if metadata.is_dir() {
                if DIRECTORIES.contains(&name.as_str()) {
                    seen_dirs.insert(name);
                    continue;
                }
                if name == "agent" {
                    // Independent agent journals/archives have their own writers and recovery
                    // obligations. Only an entirely unused directory can be outside this profile.
                    let mut agent = SpoolIo::read_dir(io, &entry.path())?;
                    if SpoolIo::next_dir_entry(io, &mut agent).is_none() {
                        continue;
                    }
                }
                return Err(BackupError::Unsupported("populated_subtree"));
            }
            regular(&metadata)?;
            if matches!(name.as_str(), "objects/LOCK" | "objects/spool/LOCK") {
                if kind != SnapshotKind::Source || metadata.len() != 0 {
                    return Err(BackupError::Unsupported("lock_record"));
                }
                seen_locks.insert(name);
                continue;
            }
            if name == RESTORE_INCOMPLETE_FILENAME {
                if kind == SnapshotKind::Source {
                    return Err(BackupError::RecoveryRequired("incomplete_restore"));
                }
                if io.read_exact(&entry.path(), PAYLOAD_GUARD.len() as u64)? != PAYLOAD_GUARD {
                    return Err(BackupError::Corrupt("inert_payload_guard"));
                }
                guard_seen = true;
                continue;
            }
            if name.starts_with("objects/spool/staging/") {
                return Err(BackupError::RecoveryRequired("staging_not_empty"));
            }
            valid_path(&name)?;
            if files.len() >= limits.max_files {
                return Err(BackupError::Limit("inventory_files"));
            }
            if metadata.len() > limits.max_file_bytes {
                return Err(BackupError::Limit("file_bytes"));
            }
            total = total
                .checked_add(metadata.len())
                .ok_or(BackupError::Limit("inventory_bytes"))?;
            if total > limits.max_total_bytes {
                return Err(BackupError::Limit("inventory_bytes"));
            }
            let bytes = io.read_exact(&entry.path(), limits.max_file_bytes)?;
            if bytes.len() as u64 != metadata.len() {
                return Err(BackupError::Changed);
            }
            if name.starts_with("objects/spool/verified/") && !bytes.is_empty() {
                return Err(BackupError::Corrupt("verification_marker"));
            }
            files.push(BackupFile {
                path: name,
                bytes: bytes.len() as u64,
                digest: ContentDigest::sha256(&bytes),
            });
        }
    }
    if seen_dirs.len() != DIRECTORIES.len() {
        return Err(BackupError::RecoveryRequired("missing_directory"));
    }
    if kind == SnapshotKind::Source && seen_locks.len() != 2 {
        return Err(BackupError::RecoveryRequired("missing_lock"));
    }
    if kind == SnapshotKind::BundlePayload && !guard_seen {
        return Err(BackupError::Corrupt("missing_inert_payload_guard"));
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    for required in ["LAYOUT", "ledger/journal.fssj", "effects/journal.fssj"] {
        if !files.iter().any(|f| f.path == required) {
            return Err(BackupError::RecoveryRequired("required_file"));
        }
    }
    io.check()?;
    Ok(files)
}

pub(super) fn snapshot(
    root: &Path,
    deployment_limits: DeploymentLimits,
    limits: BackupLimits,
    io: &ReadIo<'_>,
    kind: SnapshotKind,
) -> Result<BackupManifest> {
    let result = snapshot_inner(root, deployment_limits, limits, io, kind);
    io.check()?;
    result
}

fn snapshot_inner(
    root: &Path,
    deployment_limits: DeploymentLimits,
    limits: BackupLimits,
    io: &ReadIo<'_>,
    kind: SnapshotKind,
) -> Result<BackupManifest> {
    limits.validate()?;
    validate_deployment_limits(&deployment_limits, limits)?;
    let first = inventory(root, limits, io, kind)?;
    let layout_bytes = io.read_exact(&root.join("LAYOUT"), 4096)?;
    let layout = DeploymentLayout::parse_canonical_text(
        std::str::from_utf8(&layout_bytes).map_err(|_| BackupError::Corrupt("layout_encoding"))?,
    )
    .map_err(|_| BackupError::Unsupported("layout_version"))?;
    if layout.limits_digest != deployment_limits.canonical_digest()? {
        return Err(BackupError::Unsupported("deployment_limits_mismatch"));
    }
    if layout.site_lineage.len() > 256 {
        return Err(BackupError::Limit("site_bytes"));
    }
    let journal_limits = DurableLedgerLimits {
        max_journal_bytes: limits.max_journal_bytes,
    };
    let ledger = fss_ledger::inspect_durable_with_io(
        io,
        root.join("ledger/journal.fssj"),
        &layout.site_lineage,
        journal_limits,
    );
    io.check()?;
    let ledger = ledger.map_err(|_| BackupError::Corrupt("authority_journal"))?;
    if ledger.status != DurableLedgerStatus::Present || !ledger.is_clean() {
        return Err(BackupError::RecoveryRequired("authority_journal_tail"));
    }
    let effects = DurableEffectJournal::inspect_with_io(
        io,
        root.join("effects/journal.fssj"),
        journal_limits,
    );
    io.check()?;
    let effects = effects.map_err(|_| BackupError::Corrupt("effect_journal"))?;
    if !effects.is_clean() {
        return Err(BackupError::RecoveryRequired("effect_journal_tail"));
    }
    let effect_bytes = io.read_exact(
        &root.join("effects/journal.fssj"),
        limits.max_journal_bytes as u64,
    )?;
    let effect_report = fss_ledger::recover_bytes(&effect_bytes)
        .map_err(|_| BackupError::Corrupt("effect_journal"))?;

    let local = fss_publication::inspect_with_io(
        io,
        &root.join("objects"),
        deployment_limits.to_publication_limits(),
        None,
        WriterDetectionOptions {
            probe_shared_lock: false,
            self_holds_lock: true,
        },
    );
    io.check()?;
    let local = local.map_err(|_| BackupError::Corrupt("publication"))?;
    if !local.report.spool.is_clean()
        || !local.report.broken_roots.is_empty()
        || !local.report.foreign.is_empty()
        || local.missing_layout
        || local.spool_over_capacity
    {
        return Err(BackupError::Corrupt("object_custody"));
    }
    if !local.report.orphaned_temps.is_empty()
        || !local.redundant_temps.is_empty()
        || local.holds_migration_pending
    {
        return Err(BackupError::RecoveryRequired("publication_incomplete"));
    }
    // Standalone durable local roots and unreferenced originals are real custody, even before
    // any authority reachability claim. Preserve them. Contradictory or unbacked claims refuse.
    let linkage = fss_publication::inspect_linkage(&local, &ledger);
    if !linkage.not_durable.is_empty()
        || !linkage.conflicts.is_empty()
        || !linkage.unbacked_ledger_claims.is_empty()
        || !linkage.broken.is_empty()
        || linkage.ledger_tail_incomplete.is_some()
    {
        return Err(BackupError::Corrupt("root_authority_linkage"));
    }
    let deletion = DeletionIndex::from_batches::<BackupError>(&ledger.batches, |digest| {
        let result = fss_publication::read_verified_with_io(
            &root.join("objects"),
            digest,
            deployment_limits.spool_object_max_bytes as usize,
            io,
        );
        io.check()?;
        result.map_err(|_| BackupError::Corrupt("deletion_custody"))
    })?;
    if deletion.entries().iter().any(|entry| !entry.is_complete()) {
        return Err(BackupError::RecoveryRequired("deletion_incomplete"));
    }
    let mut deleted = deletion.deleted_objects();
    // A local tombstone is already a denial even when no deletion-index record owns it.
    // Backups may not make retained local bytes readable again under another directory.
    deleted.extend(local.report.tombstones.iter().copied());
    for file in &first {
        if let Some(name) = file.path.strip_prefix("objects/spool/objects/")
            && deleted.contains(&named_digest(name)?)
        {
            return Err(BackupError::RecoveryRequired("deleted_bytes_remain"));
        }
    }
    // Reuse the hold owner's exact lifecycle and binding verifier without opening a mutable
    // deployment. The same I/O owner meters every record and retains any original refusal.
    let holds = crate::deletion::holds::verify_retained_hold_history(
        &ledger.snapshot,
        &ledger.batches,
        io.cx(),
        |digest| {
            fss_publication::read_verified_with_io(
                &root.join("objects"),
                digest,
                crate::deletion::holds::MAX_HOLD_RECORD_BYTES
                    .min(deployment_limits.spool_object_max_bytes as usize),
                io,
            )
            .map_err(|_| crate::deletion::holds::HoldError::InvalidRecord)
        },
    );
    io.check()?;
    holds.map_err(|error| match error {
        crate::deletion::holds::HoldError::Cancelled => BackupError::Cancelled,
        crate::deletion::holds::HoldError::Limit => BackupError::Limit("hold_history"),
        _ => BackupError::Corrupt("hold_authority"),
    })?;
    let second = inventory(root, limits, io, kind)?;
    if first != second {
        return Err(BackupError::Changed);
    }
    let ledger_file = first
        .iter()
        .find(|f| f.path == "ledger/journal.fssj")
        .ok_or(BackupError::Corrupt("authority_journal"))?;
    if ledger_file.bytes != ledger.committed_len {
        return Err(BackupError::Changed);
    }
    let total_bytes = first
        .iter()
        .try_fold(0_u64, |total, file| total.checked_add(file.bytes))
        .ok_or(BackupError::Limit("inventory_bytes"))?;
    let manifest = BackupManifest {
        site: layout.site_lineage,
        deployment_limits,
        source_anchor: ledger.snapshot.anchor,
        ledger_root: ledger.last_root,
        ledger_bytes: ledger_file.bytes,
        effects_root: effect_report.last_root(),
        effects_bytes: effect_bytes.len() as u64,
        total_bytes,
        files: first,
    };
    let bytes = manifest.to_bytes();
    // Shared strict decoder proves the manifest's own bounds before any destination exists.
    BackupManifest::from_bytes(&bytes, ContentDigest::sha256(&bytes), limits)?;
    io.check()?;
    Ok(manifest)
}
