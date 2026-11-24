#![forbid(unsafe_code)]
//! Shared local publication classifier used by both open-time recovery and read-only inspection.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, TombstoneRecord};
use fss_object::{ObjectManifest, SpoolIo, SpoolRecoveryReport};

use super::fs_io::{parse_digest_file_stem, read_bounded, scan_directory};
use super::record;
use super::types::{RootEntry, TOP_LEVEL_SCAN_BOUND};
use super::{
    BlockReason, BrokenRoot, BrokenRootReason, CapacityResource, LOCAL_LOCK_FILE, LOCAL_ROOTS_DIR,
    LOCAL_SPOOL_DIR, LOCAL_TOMBSTONES_DIR, LocalPublicationError, LocalPublicationLimits,
    LocalPublicationState, LocalRecoveryReport, MAX_ROOT_RECORD_BYTES, MAX_TOMBSTONE_RECORD_BYTES,
    ROOT_INDETERMINATE_SUFFIX, ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, ReferenceRole, SlotName,
    TOMBSTONE_RECORD_SUFFIX, VisibleRoot,
};

/// How a root temp file whose target record exists was settled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RedundantTemp {
    /// The open removed it (or it was already gone).
    Removed,
    /// The open could not remove it; it stays an orphaned temp.
    Kept,
    /// Inspection left it in place and reports it.
    Reported,
}

/// What the shared classifier asks of its caller.
///
/// `RecoveryReferences` consumes fresh spool checks, holds unheld references and removes
/// redundant temps; `ObservedReferences` answers from the spool classification without writing.
pub(super) trait ReferenceCheck {
    /// Classifies one reference that no tombstone names: `Ok(Err(_))` blocks it, `Err(_)` fails
    /// the caller.
    fn check_reference(
        &mut self,
        object: ContentDigest,
    ) -> Result<Result<(), BlockReason>, LocalPublicationError>;
    /// The rehashed body of a manifest whose reference check passed.
    fn manifest_body(&mut self, root: ContentDigest) -> Result<Vec<u8>, LocalPublicationError>;
    /// Verifies and returns a manifest body in a single pass when backed by a spool.
    fn check_and_read_manifest(
        &mut self,
        root: ContentDigest,
    ) -> Result<Result<Vec<u8>, BlockReason>, LocalPublicationError> {
        match self.check_reference(root)? {
            Ok(()) => self.manifest_body(root).map(Ok),
            Err(reason) => Ok(Err(reason)),
        }
    }
    /// Settles the root temp at `path`, whose target record exists.
    fn redundant_temp(&mut self, path: &Path) -> RedundantTemp;
}

/// Which publication directories exist when the root is classified. The open creates both
/// first; inspection skips a missing one, which is what the open would find in the empty
/// directory it creates.
#[derive(Clone, Copy, Debug)]
pub(super) struct LocalLayout {
    pub(super) roots: bool,
    pub(super) tombstones: bool,
}

/// What [`classify_local`] found; the caller decides durability.
#[derive(Clone, Debug, Default)]
pub(super) struct LocalClassification {
    /// Everything but `roots` and `unreferenced_objects`, which depend on durability.
    pub(super) report: LocalRecoveryReport,
    /// Root temps inspection left in place; always empty for the open.
    pub(super) redundant_temps: Vec<PathBuf>,
    pub(super) visible: BTreeMap<SlotName, RootEntry>,
    pub(super) tombstones: BTreeMap<ContentDigest, TombstoneRecord>,
    pub(super) broken_slots: BTreeSet<SlotName>,
    pub(super) orphan_temps: BTreeSet<PathBuf>,
}

/// The one classifier of a publication root, shared by [`super::LocalRootPublisher::open`] and
/// [`super::inspect_with_io`].
///
/// It lists, stats, and reads, and asks `references` to check every reference, read every
/// manifest body, and settle every redundant temp; those three are the only points where the
/// open and inspection differ. Immediate open-time recovery reuses its fresh spool scan for
/// already-held references; subsequent reads and publication still verify current bytes.
pub(super) fn classify_local(
    io: &dyn SpoolIo,
    root: &Path,
    limits: &LocalPublicationLimits,
    layout: LocalLayout,
    spool: SpoolRecoveryReport,
    references: &mut dyn ReferenceCheck,
) -> Result<LocalClassification, LocalPublicationError> {
    let mut classified = LocalClassification {
        report: LocalRecoveryReport {
            spool,
            ..LocalRecoveryReport::default()
        },
        ..LocalClassification::default()
    };

    for (name, _) in scan_directory(io, root, TOP_LEVEL_SCAN_BOUND)? {
        let known = [
            LOCAL_LOCK_FILE,
            LOCAL_SPOOL_DIR,
            LOCAL_ROOTS_DIR,
            LOCAL_TOMBSTONES_DIR,
        ];
        if !known.iter().any(|entry| name == *entry) {
            classified.report.foreign.push(PathBuf::from(&name));
        }
    }

    if layout.tombstones {
        classify_tombstones(io, root, limits, &mut classified)?;
    }
    if layout.roots {
        classify_roots(io, root, limits, &mut classified, references)?;
    }

    classified.report.tombstones = classified.tombstones.keys().copied().collect();
    classified.report.orphaned_temps = classified.orphan_temps.iter().cloned().collect();
    classified.report.foreign.sort();
    Ok(classified)
}

/// A reference named by a durable tombstone is blocked before `references` is asked.
/// Otherwise each unique content digest is checked at most once per `classify_roots` pass.
fn check_reference_memoized(
    tombstones: &BTreeMap<ContentDigest, TombstoneRecord>,
    references: &mut dyn ReferenceCheck,
    checked_references: &mut BTreeMap<ContentDigest, Result<(), BlockReason>>,
    object: ContentDigest,
) -> Result<Result<(), BlockReason>, LocalPublicationError> {
    if tombstones.contains_key(&object) {
        return Ok(Err(BlockReason::Tombstoned));
    }
    if let Some(cached) = checked_references.get(&object).cloned() {
        return Ok(cached);
    }
    let outcome = references.check_reference(object)?;
    checked_references.insert(object, outcome.clone());
    Ok(outcome)
}

/// Verifies and reads a candidate root manifest body in a single spool pass while recording its
/// verification outcome in `checked_references` so child/descendant references do not re-verify it.
fn check_and_read_manifest_memoized(
    tombstones: &BTreeMap<ContentDigest, TombstoneRecord>,
    references: &mut dyn ReferenceCheck,
    checked_references: &mut BTreeMap<ContentDigest, Result<(), BlockReason>>,
    root: ContentDigest,
) -> Result<Result<Vec<u8>, BlockReason>, LocalPublicationError> {
    if tombstones.contains_key(&root) {
        return Ok(Err(BlockReason::Tombstoned));
    }
    match checked_references.get(&root).cloned() {
        Some(Err(reason)) => Ok(Err(reason)),
        Some(Ok(())) => references.manifest_body(root).map(Ok),
        None => {
            let outcome = references.check_and_read_manifest(root)?;
            checked_references.insert(
                root,
                outcome
                    .as_ref()
                    .map(|_| ())
                    .map_err(|reason| reason.clone()),
            );
            Ok(outcome)
        }
    }
}

fn classify_tombstones(
    io: &dyn SpoolIo,
    root: &Path,
    limits: &LocalPublicationLimits,
    classified: &mut LocalClassification,
) -> Result<(), LocalPublicationError> {
    let tombstones_dir = root.join(LOCAL_TOMBSTONES_DIR);
    let entries = scan_directory(io, &tombstones_dir, limits.max_scan_entries)?;
    for (name, file_type) in entries {
        let relative = Path::new(LOCAL_TOMBSTONES_DIR).join(&name);
        let Some(text) = name.to_str() else {
            classified.report.foreign.push(relative);
            continue;
        };
        if let Some(stem) = text.strip_suffix(ROOT_INDETERMINATE_SUFFIX) {
            let parsed = stem
                .strip_suffix(TOMBSTONE_RECORD_SUFFIX)
                .and_then(parse_digest_file_stem);
            if parsed.is_some() {
                return Err(LocalPublicationError::CorruptTombstone { path: relative });
            }
            classified.report.foreign.push(relative);
            continue;
        }
        if let Some(stem) = text.strip_suffix(ROOT_TEMP_SUFFIX) {
            let parsed = stem
                .strip_suffix(TOMBSTONE_RECORD_SUFFIX)
                .and_then(parse_digest_file_stem);
            if parsed.is_some() && file_type.is_file() {
                classified.orphan_temps.insert(relative);
            } else {
                classified.report.foreign.push(relative);
            }
            continue;
        }
        let Some(object) = text
            .strip_suffix(TOMBSTONE_RECORD_SUFFIX)
            .and_then(parse_digest_file_stem)
        else {
            classified.report.foreign.push(relative);
            continue;
        };
        if !file_type.is_file() {
            return Err(LocalPublicationError::CorruptTombstone { path: relative });
        }
        let path = tombstones_dir.join(&name);
        let Some(bytes) = read_bounded(io, &path, MAX_TOMBSTONE_RECORD_BYTES)? else {
            return Err(LocalPublicationError::CorruptTombstone { path: relative });
        };
        let record = match record::decode_tombstone_record(&bytes) {
            Ok(record) if record.payload_digest == object => record,
            _ => return Err(LocalPublicationError::CorruptTombstone { path: relative }),
        };
        classified.tombstones.insert(object, record);
    }
    if classified.tombstones.len() > limits.max_tombstones {
        return Err(LocalPublicationError::Capacity {
            resource: CapacityResource::Tombstones,
            current: classified.tombstones.len(),
            maximum: limits.max_tombstones,
        });
    }
    Ok(())
}

fn classify_roots(
    io: &dyn SpoolIo,
    root: &Path,
    limits: &LocalPublicationLimits,
    classified: &mut LocalClassification,
    references: &mut dyn ReferenceCheck,
) -> Result<(), LocalPublicationError> {
    struct CandidateRoot {
        relative: PathBuf,
        root: ContentDigest,
        manifest: ObjectManifest,
        record_bytes: Vec<u8>,
    }

    let roots_dir = root.join(LOCAL_ROOTS_DIR);
    let entries = scan_directory(io, &roots_dir, limits.max_scan_entries)?;

    let mut candidates: BTreeMap<SlotName, CandidateRoot> = BTreeMap::new();
    let mut broken_slot_roots: BTreeSet<ContentDigest> = BTreeSet::new();
    let mut indeterminate: BTreeMap<SlotName, PathBuf> = BTreeMap::new();
    let mut record_slots: BTreeSet<SlotName> = BTreeSet::new();
    let mut checked_references: BTreeMap<ContentDigest, Result<(), BlockReason>> = BTreeMap::new();

    for (name, file_type) in entries {
        let relative = Path::new(LOCAL_ROOTS_DIR).join(&name);
        let Some(text) = name.to_str() else {
            classified.report.foreign.push(relative);
            continue;
        };
        if let Some(stem) = text.strip_suffix(ROOT_INDETERMINATE_SUFFIX) {
            // Classified by existence alone, whatever its type or contents: fail closed.
            match stem.strip_suffix(ROOT_RECORD_SUFFIX).map(SlotName::parse) {
                Some(Ok(slot)) => {
                    indeterminate.insert(slot, relative);
                }
                Some(Err(_)) | None => classified.report.foreign.push(relative),
            }
            continue;
        }
        if let Some(stem) = text.strip_suffix(ROOT_TEMP_SUFFIX) {
            let parsed = stem.strip_suffix(ROOT_RECORD_SUFFIX).map(SlotName::parse);
            if let Some(Ok(slot)) = parsed {
                if file_type.is_file() {
                    let target_path = roots_dir.join(format!("{slot}{ROOT_RECORD_SUFFIX}"));
                    if io.symlink_metadata(&target_path).is_ok() {
                        match references.redundant_temp(&root.join(&relative)) {
                            RedundantTemp::Removed => {}
                            RedundantTemp::Kept => {
                                classified.orphan_temps.insert(relative);
                            }
                            RedundantTemp::Reported => classified.redundant_temps.push(relative),
                        }
                        continue;
                    }
                    classified.orphan_temps.insert(relative);
                } else {
                    classified.report.foreign.push(relative);
                }
            } else {
                classified.report.foreign.push(relative);
            }
            continue;
        }
        let Some(Ok(slot)) = text.strip_suffix(ROOT_RECORD_SUFFIX).map(SlotName::parse) else {
            classified.report.foreign.push(relative);
            continue;
        };
        record_slots.insert(slot.clone());
        if !file_type.is_file() {
            classified.broken_slots.insert(slot);
            classified.report.broken_roots.push(BrokenRoot {
                path: relative,
                reason: BrokenRootReason::NotRegularFile,
            });
            continue;
        }
        let path = roots_dir.join(format!("{slot}{ROOT_RECORD_SUFFIX}"));
        let Some(bytes) = read_bounded(io, &path, MAX_ROOT_RECORD_BYTES)? else {
            classified.broken_slots.insert(slot);
            classified.report.broken_roots.push(BrokenRoot {
                path: relative,
                reason: BrokenRootReason::RecordTooLarge,
            });
            continue;
        };
        let decoded = match record::decode_root_record(&bytes) {
            Ok(decoded) => decoded,
            Err(reason) => {
                classified.broken_slots.insert(slot);
                classified.report.broken_roots.push(BrokenRoot {
                    path: relative,
                    reason,
                });
                continue;
            }
        };
        if decoded.slot != slot.as_str() {
            broken_slot_roots.insert(decoded.root);
            classified.broken_slots.insert(slot);
            classified.report.broken_roots.push(BrokenRoot {
                path: relative,
                reason: BrokenRootReason::SlotMismatch,
            });
            continue;
        }
        let root_digest = decoded.root;
        let body = match check_and_read_manifest_memoized(
            &classified.tombstones,
            references,
            &mut checked_references,
            root_digest,
        )? {
            Ok(body) => body,
            Err(reason) => {
                broken_slot_roots.insert(root_digest);
                classified.broken_slots.insert(slot);
                classified.report.broken_roots.push(BrokenRoot {
                    path: relative,
                    reason: BrokenRootReason::ReferenceBlocked {
                        object: root_digest,
                        role: ReferenceRole::ManifestBody,
                        reason,
                    },
                });
                continue;
            }
        };
        let manifest = match ObjectManifest::from_canonical_bytes(&body) {
            Ok(manifest) if manifest.root() == root_digest => manifest,
            _ => {
                broken_slot_roots.insert(root_digest);
                classified.broken_slots.insert(slot);
                classified.report.broken_roots.push(BrokenRoot {
                    path: relative,
                    reason: BrokenRootReason::ManifestUndecodable,
                });
                continue;
            }
        };
        let child_count = manifest.children().len();
        if decoded.child_count != child_count as u64 {
            broken_slot_roots.insert(root_digest);
            classified.broken_slots.insert(slot);
            classified.report.broken_roots.push(BrokenRoot {
                path: relative,
                reason: BrokenRootReason::ChildCountMismatch {
                    recorded: decoded.child_count,
                    actual: child_count,
                },
            });
            continue;
        }
        if child_count > limits.max_children {
            broken_slot_roots.insert(root_digest);
            classified.broken_slots.insert(slot);
            classified.report.broken_roots.push(BrokenRoot {
                path: relative,
                reason: BrokenRootReason::ChildBoundExceeded {
                    count: child_count,
                    maximum: limits.max_children,
                },
            });
            continue;
        }
        candidates.insert(
            slot,
            CandidateRoot {
                relative,
                root: root_digest,
                manifest,
                record_bytes: bytes,
            },
        );
    }

    // A durable indeterminate marker overrides whatever the slot's record says: its record,
    // if any, is never admitted, and roots that reach it are broken below.
    for (slot, relative) in indeterminate {
        if let Some(candidate) = candidates.remove(&slot) {
            broken_slot_roots.insert(candidate.root);
        }
        let record_present = record_slots.contains(&slot);
        classified.broken_slots.insert(slot);
        classified.report.broken_roots.push(BrokenRoot {
            path: relative,
            reason: BrokenRootReason::VisibilityIndeterminate { record_present },
        });
    }

    // Multi-pass fixed-point validation of direct references and transitive descendants
    loop {
        let mut newly_broken = Vec::new();
        let candidate_manifests: BTreeMap<ContentDigest, Vec<ContentDigest>> = candidates
            .values()
            .map(|c| (c.root, c.manifest.children().to_vec()))
            .collect();

        for (slot, candidate) in &candidates {
            let mut broken_reason = None;

            // 1. Direct children
            for child in candidate.manifest.children() {
                let role = if candidate.manifest.metadata_digest() == Some(*child) {
                    ReferenceRole::Metadata
                } else {
                    ReferenceRole::Child
                };
                if broken_slot_roots.contains(child) {
                    broken_reason = Some(BrokenRootReason::ReferenceBlocked {
                        object: *child,
                        role,
                        reason: BlockReason::NotVerified,
                    });
                    break;
                }
                match check_reference_memoized(
                    &classified.tombstones,
                    references,
                    &mut checked_references,
                    *child,
                )? {
                    Ok(()) => {}
                    Err(reason) => {
                        broken_reason = Some(BrokenRootReason::ReferenceBlocked {
                            object: *child,
                            role,
                            reason,
                        });
                        break;
                    }
                }
            }

            // 2. Transitive descendants
            if broken_reason.is_none() {
                let direct: BTreeSet<ContentDigest> =
                    candidate.manifest.children().iter().copied().collect();
                let mut seen = BTreeSet::from([candidate.root]);
                let mut pending = candidate.manifest.children().to_vec();
                while let Some(digest) = pending.pop() {
                    if seen.insert(digest)
                        && let Some(grandchildren) = candidate_manifests.get(&digest)
                    {
                        pending.extend_from_slice(grandchildren);
                    }
                }
                for descendant in seen {
                    if descendant == candidate.root || direct.contains(&descendant) {
                        continue;
                    }
                    if broken_slot_roots.contains(&descendant) {
                        broken_reason = Some(BrokenRootReason::ReferenceBlocked {
                            object: descendant,
                            role: ReferenceRole::Descendant,
                            reason: BlockReason::NotVerified,
                        });
                        break;
                    }
                    match check_reference_memoized(
                        &classified.tombstones,
                        references,
                        &mut checked_references,
                        descendant,
                    )? {
                        Ok(()) => {}
                        Err(reason) => {
                            broken_reason = Some(BrokenRootReason::ReferenceBlocked {
                                object: descendant,
                                role: ReferenceRole::Descendant,
                                reason,
                            });
                            break;
                        }
                    }
                }
            }

            if let Some(reason) = broken_reason {
                newly_broken.push((slot.clone(), reason));
            }
        }

        if newly_broken.is_empty() {
            break;
        }

        for (slot, reason) in newly_broken {
            if let Some(candidate) = candidates.remove(&slot) {
                broken_slot_roots.insert(candidate.root);
                classified.broken_slots.insert(slot);
                classified.report.broken_roots.push(BrokenRoot {
                    path: candidate.relative,
                    reason,
                });
            }
        }
    }

    classified
        .report
        .broken_roots
        .sort_by(|left, right| left.path.cmp(&right.path));

    for (slot, candidate) in candidates {
        classified.visible.insert(
            slot.clone(),
            RootEntry {
                visible: VisibleRoot {
                    slot,
                    root: candidate.root,
                    record_digest: ContentDigest::sha256(&candidate.record_bytes),
                    child_count: candidate.manifest.children().len(),
                    state: LocalPublicationState::Visible,
                },
                children: candidate.manifest.children().to_vec(),
            },
        );
    }

    if classified.visible.len() > limits.max_roots {
        return Err(LocalPublicationError::Capacity {
            resource: CapacityResource::Roots,
            current: classified.visible.len(),
            maximum: limits.max_roots,
        });
    }
    Ok(())
}
