#![forbid(unsafe_code)]
//! Staging, verification, root-last publication, and rollback paths for [`super::LocalRootPublisher`].

use std::collections::BTreeSet;
use std::io;
use std::path::Path;

use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::{ObjectManifest, SpoolError, VerifiedObjectCatalog};

use super::fs_io::{io_error, read_bounded, record_directory, write_all};
use super::types::RootEntry;
use super::{
    BlockReason, CapacityResource, IoFaultPoint, LocalIoOperation, LocalPublicationError,
    LocalPublicationReceipt, LocalPublicationState, LocalRootPublisher, MAX_ROOT_RECORD_BYTES,
    NeverCancel, PublicationClaims, PublicationTransition, PublishCancellation, PublishCutPoint,
    PublishOutcome, ROOT_INDETERMINATE_SUFFIX, ROOT_RECORD_SUFFIX, ReferenceRole, SlotName,
    VisibleRoot, root_record_bytes,
};

impl LocalRootPublisher {
    /// Stages `manifest` body for `slot` without publishing it to disk as a root record.
    ///
    /// The manifest is verified and decodes from the spool, and every reference is verified.
    /// The slot's root state becomes observable as [`LocalPublicationState::Staged`].
    pub fn stage_manifest(
        &mut self,
        slot: &SlotName,
        manifest: &ObjectManifest,
    ) -> Result<ContentDigest, LocalPublicationError> {
        self.require_live()?;
        let root = manifest.root();
        if manifest.computed_root() != root {
            return Err(LocalPublicationError::ManifestMismatch { root });
        }
        if let Some(entry) = self.visible.get(slot) {
            return Err(LocalPublicationError::SlotConflict {
                slot: slot.clone(),
                existing: entry.visible.root,
                requested: root,
            });
        }
        let child_count = manifest.children().len();
        if child_count > self.limits.max_children {
            return Err(LocalPublicationError::ManifestChildBound {
                count: child_count,
                maximum: self.limits.max_children,
            });
        }
        self.require_references(manifest)?;
        self.stage_manifest_body(manifest)?;
        self.staged.insert(
            slot.clone(),
            RootEntry {
                visible: VisibleRoot {
                    slot: slot.clone(),
                    root,
                    record_digest: ContentDigest::sha256(b""),
                    child_count,
                    state: LocalPublicationState::Staged,
                },
                children: manifest.children().to_vec(),
            },
        );
        Ok(root)
    }

    /// Stages `bytes` in the spool and verifies them, returning their content digest.
    ///
    /// Staging is custody, not publication: a tombstoned digest may still be staged, but it can
    /// never be published.
    pub fn stage_object(&mut self, bytes: &[u8]) -> Result<ContentDigest, LocalPublicationError> {
        self.require_live()?;
        let receipt = self
            .spool
            .stage_bytes(bytes)
            .map_err(|error| self.spool_error(error))?;
        self.spool
            .verify(receipt.digest)
            .map_err(|error| self.spool_error(error))?;
        Ok(receipt.digest)
    }

    /// Re-reads and rehashes one spool object and marks it `Verified`.
    pub fn verify_object(&mut self, digest: ContentDigest) -> Result<(), LocalPublicationError> {
        self.require_live()?;
        self.spool
            .verify(digest)
            .map_err(|error| self.spool_error(error))?;
        Ok(())
    }

    /// Publishes `manifest` into `slot` root-last. See [`Self::publish_cancellable`].
    pub fn publish(
        &mut self,
        slot: &SlotName,
        manifest: &ObjectManifest,
    ) -> Result<LocalPublicationReceipt, LocalPublicationError> {
        self.publish_cancellable(slot, manifest, &NeverCancel)
    }

    /// Publishes `manifest` into `slot` root-last, consulting `cancel` before the rename.
    ///
    /// Republishing the identical root is idempotent and writes nothing. A different root for a
    /// visible slot is [`LocalPublicationError::SlotConflict`]. A missing, unverified, corrupt, or
    /// tombstoned reference fails with [`LocalPublicationError::ReferenceBlocked`] naming it, and
    /// nothing becomes visible.
    pub fn publish_cancellable(
        &mut self,
        slot: &SlotName,
        manifest: &ObjectManifest,
        cancel: &dyn PublishCancellation,
    ) -> Result<LocalPublicationReceipt, LocalPublicationError> {
        self.require_live()?;
        let root = manifest.root();
        if manifest.computed_root() != root {
            return Err(LocalPublicationError::ManifestMismatch { root });
        }
        if let Some(entry) = self.visible.get(slot) {
            if entry.visible.root != root {
                return Err(LocalPublicationError::SlotConflict {
                    slot: slot.clone(),
                    existing: entry.visible.root,
                    requested: root,
                });
            }
            return self.reverify_existing(slot, manifest);
        }
        if self.broken_slots.contains(slot) {
            return Err(LocalPublicationError::BrokenSlot { slot: slot.clone() });
        }
        let child_count = manifest.children().len();
        if child_count > self.limits.max_children {
            return Err(LocalPublicationError::ManifestChildBound {
                count: child_count,
                maximum: self.limits.max_children,
            });
        }
        if self.visible.len() >= self.limits.max_roots {
            return Err(LocalPublicationError::Capacity {
                resource: CapacityResource::Roots,
                current: self.visible.len(),
                maximum: self.limits.max_roots,
            });
        }
        let root_name = format!("{slot}{ROOT_RECORD_SUFFIX}");
        let temp_relative = Self::root_temp_path(slot);
        if self.orphan_temps.contains(&temp_relative) {
            return Err(LocalPublicationError::OrphanedTemp {
                path: temp_relative,
            });
        }
        let mut transitions = Vec::with_capacity(5);

        // 1. Every reference is verified, durable, and not tombstoned.
        self.require_references(manifest)?;
        transitions.push(PublicationTransition::ChildrenVerified);
        self.cut(PublishCutPoint::AfterChildrenVerified, cancel, None)?;

        // 2. The canonical manifest body is staged, verified, and decodes to this manifest.
        self.stage_manifest_body(manifest)?;
        transitions.push(PublicationTransition::ManifestBodyStaged);
        self.cut(PublishCutPoint::AfterManifestBody, cancel, None)?;

        // 3. The root record is written to a temporary name, fsynced, and read back.
        let record = root_record_bytes(slot, root, child_count)?;
        let temp_path = self.root.join(&temp_relative);
        let target_path = self.roots_dir.join(&root_name);
        self.write_temp(&temp_relative, &temp_path, &record)?;
        transitions.push(PublicationTransition::RootTempWritten);
        self.cut(
            PublishCutPoint::AfterRootTempWrite,
            cancel,
            Some((&temp_relative, &temp_path)),
        )?;

        // 4. Re-prove custody immediately before the commit point.
        if let Err(error) = self.require_references(manifest).and_then(|()| {
            self.spool.require_verified(root).map_err(|error| {
                LocalPublicationError::ReferenceBlocked {
                    object: root,
                    role: ReferenceRole::ManifestBody,
                    reason: error.into(),
                }
            })
        }) {
            let cleanup = self.remove_temp(&temp_relative, &temp_path);
            return Err(Self::fail_with_cleanup(error, cleanup));
        }
        match self.io.symlink_metadata(&target_path) {
            Ok(_) => {
                let original = LocalPublicationError::InvalidLayout { path: target_path };
                let cleanup = self.remove_temp(&temp_relative, &temp_path);
                return Err(Self::fail_with_cleanup(original, cleanup));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                let original = io_error(LocalIoOperation::Inspect, &target_path, &error);
                let cleanup = self.remove_temp(&temp_relative, &temp_path);
                return Err(Self::fail_with_cleanup(original, cleanup));
            }
        }

        // 5. Commit point: the hard link makes the root visible atomically without clobbering.
        // If a file was created at target_path between inspection and commit (TOCTOU race),
        // hard_link fails with io::ErrorKind::AlreadyExists and never clobbers target_path.
        let linked = match self.take_io_fault(IoFaultPoint::RootRename) {
            Some(kind) => Err(io::Error::from(kind)),
            None => self.io.hard_link(&temp_path, &target_path),
        };
        if let Err(error) = linked {
            if error.kind() == io::ErrorKind::AlreadyExists {
                let original = LocalPublicationError::InvalidLayout { path: target_path };
                let cleanup = self.remove_temp(&temp_relative, &temp_path);
                return Err(Self::fail_with_cleanup(original, cleanup));
            }
            return Err(self.roll_back_failed_rename(
                slot,
                (&temp_relative, &temp_path),
                &target_path,
                &record,
                error.kind(),
            ));
        }

        // The target is now atomically visible. Remove the temporary link.
        match self.io.remove_file(&temp_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                self.orphan_temps.insert(temp_relative.to_path_buf());
            }
        }
        self.staged.remove(slot);
        transitions.push(PublicationTransition::RootRenamed);
        let closure_object_count = self.closure(root, manifest.children()).len();
        let record_digest = ContentDigest::sha256(&record);
        self.visible.insert(
            slot.clone(),
            RootEntry {
                visible: VisibleRoot {
                    slot: slot.clone(),
                    root,
                    record_digest,
                    child_count,
                    state: LocalPublicationState::Visible,
                },
                children: manifest.children().to_vec(),
            },
        );
        self.cut(PublishCutPoint::AfterRootRename, cancel, None)?;

        // 6. The directory fsync makes the rename durable.
        let synced = match self.take_io_fault(IoFaultPoint::RootDirectorySync) {
            Some(kind) => Err(io::Error::from(kind)),
            None => self.io.sync_directory(&self.roots_dir),
        };
        if let Err(error) = synced {
            self.poisoned = true;
            return Err(LocalPublicationError::Indeterminate {
                path: target_path,
                kind: error.kind(),
            });
        }
        if let Some(entry) = self.visible.get_mut(slot) {
            entry.visible.state = LocalPublicationState::Durable;
        }
        transitions.push(PublicationTransition::RootDirectorySynced);
        Ok(LocalPublicationReceipt {
            slot: slot.clone(),
            root,
            record_digest,
            child_count,
            closure_object_count,
            outcome: PublishOutcome::Published,
            claims: PublicationClaims::local_only(LocalPublicationState::Durable),
            transitions,
        })
    }

    /// Disarms and returns the injected error kind if the armed fault is at `point`.
    fn take_io_fault(&mut self, point: IoFaultPoint) -> Option<io::ErrorKind> {
        match self.injected_io_fault {
            Some(fault) if fault.point == point => {
                self.injected_io_fault = None;
                Some(fault.kind)
            }
            _ => None,
        }
    }

    fn cut(
        &mut self,
        point: PublishCutPoint,
        cancel: &dyn PublishCancellation,
        temp: Option<(&Path, &Path)>,
    ) -> Result<(), LocalPublicationError> {
        if self.injected_crash == Some(point) {
            self.injected_crash = None;
            self.poisoned = true;
            return Err(LocalPublicationError::InjectedCrash { point });
        }
        if point != PublishCutPoint::AfterRootRename && cancel.cancel_requested(point) {
            let original = LocalPublicationError::Cancelled { point };
            if let Some((relative, path)) = temp {
                let cleanup = self.remove_temp(relative, path);
                return Err(Self::fail_with_cleanup(original, cleanup));
            }
            return Err(original);
        }
        Ok(())
    }

    fn require_references(&self, manifest: &ObjectManifest) -> Result<(), LocalPublicationError> {
        let root = manifest.root();
        if self.tombstones.contains_key(&root) {
            return Err(LocalPublicationError::ReferenceBlocked {
                object: root,
                role: ReferenceRole::ManifestBody,
                reason: BlockReason::Tombstoned,
            });
        }
        for child in manifest.children() {
            let role = if manifest.metadata_digest() == Some(*child) {
                ReferenceRole::Metadata
            } else {
                ReferenceRole::Child
            };
            if self.tombstones.contains_key(child) {
                return Err(LocalPublicationError::ReferenceBlocked {
                    object: *child,
                    role,
                    reason: BlockReason::Tombstoned,
                });
            }
            if let Some(entry) = self.visible.values().find(|e| e.visible.root == *child)
                && entry.visible.state != LocalPublicationState::Durable
            {
                return Err(LocalPublicationError::ReferenceBlocked {
                    object: *child,
                    role,
                    reason: BlockReason::NotVerified,
                });
            }
            self.spool.require_verified(*child).map_err(|error| {
                LocalPublicationError::ReferenceBlocked {
                    object: *child,
                    role,
                    reason: error.into(),
                }
            })?;
        }
        let direct: BTreeSet<ContentDigest> = manifest.children().iter().copied().collect();
        for descendant in self.closure(root, manifest.children()) {
            if descendant == root || direct.contains(&descendant) {
                continue;
            }
            if self.tombstones.contains_key(&descendant) {
                return Err(LocalPublicationError::ReferenceBlocked {
                    object: descendant,
                    role: ReferenceRole::Descendant,
                    reason: BlockReason::Tombstoned,
                });
            }
            if let Some(entry) = self.visible.values().find(|e| e.visible.root == descendant)
                && entry.visible.state != LocalPublicationState::Durable
            {
                return Err(LocalPublicationError::ReferenceBlocked {
                    object: descendant,
                    role: ReferenceRole::Descendant,
                    reason: BlockReason::NotVerified,
                });
            }
            self.spool.require_verified(descendant).map_err(|error| {
                LocalPublicationError::ReferenceBlocked {
                    object: descendant,
                    role: ReferenceRole::Descendant,
                    reason: error.into(),
                }
            })?;
        }
        Ok(())
    }

    fn stage_manifest_body(
        &mut self,
        manifest: &ObjectManifest,
    ) -> Result<(), LocalPublicationError> {
        let root = manifest.root();
        let body = manifest
            .try_canonical_bytes()
            .map_err(LocalPublicationError::Encoding)?;
        self.spool
            .stage(root, &body)
            .map_err(|error| self.manifest_body_error(root, error))?;
        self.spool
            .verify(root)
            .map_err(|error| self.manifest_body_error(root, error))?;
        let read_back = self
            .spool
            .read(root)
            .map_err(|error| self.manifest_body_error(root, error))?;
        match ObjectManifest::from_canonical_bytes(&read_back) {
            Ok(decoded) if &decoded == manifest => Ok(()),
            _ => Err(LocalPublicationError::ManifestMismatch { root }),
        }
    }

    /// Classifies a spool failure on the manifest body: corrupt stored bytes under the root are a
    /// blocked [`ReferenceRole::ManifestBody`] reference, as on the idempotent republish path.
    fn manifest_body_error(
        &mut self,
        root: ContentDigest,
        error: SpoolError,
    ) -> LocalPublicationError {
        match error {
            SpoolError::Corrupt { digest, .. } if digest == root => {
                LocalPublicationError::ReferenceBlocked {
                    object: root,
                    role: ReferenceRole::ManifestBody,
                    reason: BlockReason::Corrupt,
                }
            }
            other => self.spool_error(other),
        }
    }

    pub(super) fn fail_with_cleanup(
        original: LocalPublicationError,
        cleanup: Result<(), LocalPublicationError>,
    ) -> LocalPublicationError {
        match cleanup {
            Ok(()) => original,
            Err(cleanup) => LocalPublicationError::cleanup_failed(original, cleanup),
        }
    }

    /// Rolls back a root rename that was reported failed and returns the error to report.
    ///
    /// The rename may have taken effect anyway, so the record at `target` is removed (the slot
    /// had no record before the rename) and the removal is fsynced; `NotFound` proves the rename
    /// did not take effect. When the rollback completes, nothing is visible and the rename error
    /// is returned. When the removal or its fsync fails, the root may be visible or may reappear
    /// after a crash: the slot is marked indeterminate on disk and in this instance, the instance
    /// is poisoned, and [`LocalPublicationError::RootVisibilityIndeterminate`] carries every
    /// observed outcome. A temporary record left in that case is classified on reopen.
    fn roll_back_failed_rename(
        &mut self,
        slot: &SlotName,
        (temp_relative, temp_path): (&Path, &Path),
        target: &Path,
        record: &[u8],
        rename_kind: io::ErrorKind,
    ) -> LocalPublicationError {
        let rollback = match self.io.remove_file(target) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => Some((LocalIoOperation::RemoveRecord, error.kind())),
            Ok(()) => match self.io.sync_directory(&self.roots_dir) {
                Ok(()) => None,
                Err(error) => Some((LocalIoOperation::SyncDirectory, error.kind())),
            },
        };
        let Some((rollback_operation, rollback_kind)) = rollback else {
            let original = LocalPublicationError::Io {
                operation: LocalIoOperation::Rename,
                path: target.to_path_buf(),
                kind: rename_kind,
            };
            return Self::fail_with_cleanup(original, self.remove_temp(temp_relative, temp_path));
        };
        self.poisoned = true;
        self.staged.remove(slot);
        self.broken_slots.insert(slot.clone());
        // The marker's success value is `()`, so its failure kind is all there is to keep.
        let marker_kind = self.record_indeterminate_marker(slot, record).err();
        LocalPublicationError::RootVisibilityIndeterminate {
            slot: slot.clone(),
            path: target.to_path_buf(),
            rename_kind,
            rollback_operation,
            rollback_kind,
            marker_kind,
        }
    }

    /// Durably records `<slot>.root.indeterminate`, holding the attempted root `record`.
    ///
    /// A marker that already exists records the same fact and is kept. A marker left partially
    /// written by a failure here still marks the slot on reopen, which classifies it by
    /// existence alone.
    fn record_indeterminate_marker(
        &self,
        slot: &SlotName,
        record: &[u8],
    ) -> Result<(), io::ErrorKind> {
        let path = self.roots_dir.join(format!(
            "{slot}{ROOT_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}"
        ));
        match self.io.create_new(&path) {
            Ok(mut file) => {
                let written = write_all(self.io.as_ref(), &mut file, record)
                    .and_then(|()| self.io.sync_file(&file));
                drop(file);
                written.map_err(|error| error.kind())?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.kind()),
        }
        self.io
            .sync_directory(&self.roots_dir)
            .map_err(|error| error.kind())
    }

    pub(super) fn write_temp(
        &mut self,
        relative: &Path,
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), LocalPublicationError> {
        let parent = record_directory(path)?.to_path_buf();
        let mut file = match self.io.create_new(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(LocalPublicationError::OrphanedTemp {
                    path: relative.to_path_buf(),
                });
            }
            Err(error) => return Err(io_error(LocalIoOperation::CreateTemp, path, &error)),
        };
        let written =
            write_all(self.io.as_ref(), &mut file, bytes).and_then(|()| self.io.sync_file(&file));
        drop(file);
        if let Err(error) = written {
            let original = io_error(LocalIoOperation::WriteTemp, path, &error);
            let cleanup = self.remove_temp(relative, path);
            return Err(Self::fail_with_cleanup(original, cleanup));
        }
        if let Err(error) = self.io.sync_directory(&parent) {
            let original = io_error(LocalIoOperation::SyncDirectory, &parent, &error);
            let cleanup = self.remove_temp(relative, path);
            return Err(Self::fail_with_cleanup(original, cleanup));
        }
        let limit = bytes.len() as u64;
        match read_bounded(self.io.as_ref(), path, limit) {
            Ok(Some(read_back)) if read_back == bytes => Ok(()),
            Ok(_) => {
                let original = LocalPublicationError::Io {
                    operation: LocalIoOperation::ReadRecord,
                    path: path.to_path_buf(),
                    kind: io::ErrorKind::InvalidData,
                };
                let cleanup = self.remove_temp(relative, path);
                Err(Self::fail_with_cleanup(original, cleanup))
            }
            Err(error) => {
                let cleanup = self.remove_temp(relative, path);
                Err(Self::fail_with_cleanup(error, cleanup))
            }
        }
    }

    /// Removes a temporary record this call created. If removal fails, the path is remembered
    /// as an orphan so it is never silently reused, and the removal failure is returned.
    pub(super) fn remove_temp(
        &mut self,
        relative: &Path,
        path: &Path,
    ) -> Result<(), LocalPublicationError> {
        let parent = match record_directory(path) {
            Ok(parent) => parent.to_path_buf(),
            Err(error) => {
                self.orphan_temps.insert(relative.to_path_buf());
                return Err(error);
            }
        };
        match self.io.remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                self.orphan_temps.insert(relative.to_path_buf());
                return Err(io_error(LocalIoOperation::RemoveTemp, path, &error));
            }
        }
        self.io
            .sync_directory(&parent)
            .map_err(|error| io_error(LocalIoOperation::SyncDirectory, &parent, &error))
    }

    fn reverify_existing(
        &mut self,
        slot: &SlotName,
        manifest: &ObjectManifest,
    ) -> Result<LocalPublicationReceipt, LocalPublicationError> {
        let (visible, closure_object_count) = match self.visible.get(slot) {
            Some(entry) => (
                entry.visible.clone(),
                self.closure(entry.visible.root, &entry.children).len(),
            ),
            None => return Err(LocalPublicationError::BrokenSlot { slot: slot.clone() }),
        };
        self.require_references(manifest)?;
        self.spool.require_verified(visible.root).map_err(|error| {
            LocalPublicationError::ReferenceBlocked {
                object: visible.root,
                role: ReferenceRole::ManifestBody,
                reason: error.into(),
            }
        })?;
        let path = self.roots_dir.join(format!("{slot}{ROOT_RECORD_SUFFIX}"));
        match read_bounded(self.io.as_ref(), &path, MAX_ROOT_RECORD_BYTES)? {
            Some(bytes) if ContentDigest::sha256(&bytes) == visible.record_digest => {}
            _ => return Err(LocalPublicationError::BrokenSlot { slot: slot.clone() }),
        }
        Ok(LocalPublicationReceipt {
            slot: slot.clone(),
            root: visible.root,
            record_digest: visible.record_digest,
            child_count: visible.child_count,
            closure_object_count,
            outcome: PublishOutcome::AlreadyPublished,
            claims: PublicationClaims::local_only(visible.state),
            transitions: vec![PublicationTransition::ExistingRootReverified],
        })
    }
}
