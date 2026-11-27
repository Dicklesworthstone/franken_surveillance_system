#![forbid(unsafe_code)]
//! Tombstoning, deletion retraction, and orphaned temp/staging maintenance for [`super::LocalRootPublisher`].

use std::io;
use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, TombstoneRecord};
use fss_object::{DiscardReceipt, ObjectManifest, SpoolError, VerifiedObjectCatalog};

use super::fs_io::{digest_file_stem, directory_present, io_error, read_bounded, write_all};
use super::record;
use super::{
    CapacityResource, LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR, LOCAL_TOMBSTONES_DIR, LocalIoOperation,
    LocalPublicationError, LocalRootPublisher, MAX_ROOT_RECORD_BYTES, ROOT_INDETERMINATE_SUFFIX,
    ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, ReferenceRole, SlotName, TOMBSTONE_RECORD_SUFFIX,
    TombstoneOutcome, root_record_bytes,
};

impl LocalRootPublisher {
    /// Makes a tombstone for `record.payload_digest` durable; it blocks every later publication
    /// that references the object.
    ///
    /// Requires a deletion authority witness verified in the spool. Tombstoning an object
    /// reachable from a visible root is refused: removing a visible closure is the deletion-closure
    /// owner's effect, not a silent local unpublish. Spool bytes are retained; releasing them is
    /// not claimed.
    pub fn record_tombstone(
        &mut self,
        record: TombstoneRecord,
    ) -> Result<TombstoneOutcome, LocalPublicationError> {
        self.require_live()?;
        let object = record.payload_digest;
        if let Some(existing) = self.tombstones.get(&object) {
            if existing == &record {
                return Ok(TombstoneOutcome::AlreadyRecorded);
            }
            return Err(LocalPublicationError::TombstoneConflict { object });
        }
        let witness = record
            .witness_digest
            .ok_or(LocalPublicationError::MissingDeletionAuthority { object })?;
        self.spool.require_verified(witness).map_err(|error| {
            LocalPublicationError::ReferenceBlocked {
                object: witness,
                role: ReferenceRole::DeletionWitness,
                reason: error.into(),
            }
        })?;
        if let Some(entry) = self.visible.values().find(|entry| {
            self.closure(entry.visible.root, &entry.children)
                .contains(&object)
        }) {
            return Err(LocalPublicationError::TombstoneBlockedByVisibleRoot {
                object,
                slot: entry.visible.slot.clone(),
            });
        }
        if self.tombstones.len() >= self.limits.max_tombstones {
            return Err(LocalPublicationError::Capacity {
                resource: CapacityResource::Tombstones,
                current: self.tombstones.len(),
                maximum: self.limits.max_tombstones,
            });
        }
        let bytes = record::tombstone_record_bytes(&record)?;
        let name = format!("{}{TOMBSTONE_RECORD_SUFFIX}", digest_file_stem(object));
        let temp_relative =
            Path::new(LOCAL_TOMBSTONES_DIR).join(format!("{name}{ROOT_TEMP_SUFFIX}"));
        if self.orphan_temps.contains(&temp_relative) {
            return Err(LocalPublicationError::OrphanedTemp {
                path: temp_relative,
            });
        }
        let temp_path = self.root.join(&temp_relative);
        let target_path = self.tombstones_dir.join(&name);
        self.write_temp(&temp_relative, &temp_path, &bytes)?;
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
        if let Err(error) = self.io.rename(&temp_path, &target_path) {
            return Err(self.roll_back_failed_tombstone_rename(
                &object,
                (&temp_relative, &temp_path),
                &target_path,
                &bytes,
                error.kind(),
            ));
        }
        if let Err(error) = self.io.sync_directory(&self.tombstones_dir) {
            self.poisoned = true;
            let rollback = match self.io.remove_file(&target_path) {
                Ok(()) => self.io.sync_directory(&self.tombstones_dir).is_ok(),
                Err(_) => false,
            };
            if !rollback {
                let marker_kind = self
                    .record_indeterminate_tombstone_marker(&object, &bytes)
                    .err();
                if marker_kind.is_some()
                    && let Ok(mut file) = self.io.open_lock(&target_path)
                {
                    let _ = write_all(
                        self.io.as_ref(),
                        &mut file,
                        b"corrupted_indeterminate_tombstone",
                    );
                    let _ = self.io.sync_file(&file);
                }
            }
            return Err(LocalPublicationError::Indeterminate {
                path: target_path,
                kind: error.kind(),
            });
        }
        self.tombstones.insert(object, record);
        Ok(TombstoneOutcome::Recorded)
    }

    /// Retracts the root visible in `slot` for a deletion whose authority is durable.
    ///
    /// `witness` is the deletion record (the sealed deletion plan) and must be verified in the
    /// spool, exactly like a tombstone's deletion authority. The root record is unlinked and the
    /// roots directory fsynced; the manifest body and children stay in custody until the caller
    /// removes them. This is the deletion-closure owner's effect, never a silent local unpublish:
    /// the ledger records the retraction before this runs. A slot that holds no visible root
    /// returns `false` without touching the disk, so a retry is idempotent. A failed fsync
    /// poisons this instance.
    pub fn retract_root(
        &mut self,
        slot: &SlotName,
        witness: ContentDigest,
    ) -> Result<bool, LocalPublicationError> {
        self.require_live()?;
        self.spool.require_verified(witness).map_err(|error| {
            LocalPublicationError::ReferenceBlocked {
                object: witness,
                role: ReferenceRole::DeletionWitness,
                reason: error.into(),
            }
        })?;
        if !self.visible.contains_key(slot) {
            return Ok(false);
        }
        let path = self.roots_dir.join(format!("{slot}{ROOT_RECORD_SUFFIX}"));
        match self.io.remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(LocalIoOperation::RemoveRecord, &path, &error)),
        }
        self.visible.remove(slot);
        if let Err(error) = self.io.sync_directory(&self.roots_dir) {
            self.poisoned = true;
            return Err(LocalPublicationError::Indeterminate {
                path,
                kind: error.kind(),
            });
        }
        Ok(true)
    }

    /// Unlinks one object named by a durable deletion record from the owned spool.
    ///
    /// `witness` is the verified deletion record. An object still reachable from any visible root
    /// is refused with [`LocalPublicationError::TombstoneBlockedByVisibleRoot`]: every root of the
    /// closure must be retracted first. The removal is local filesystem unlinking (see
    /// [`fss_object::StagingSpool::remove_for_deletion`]), never cryptographic erasure.
    pub fn remove_deleted_object(
        &mut self,
        object: ContentDigest,
        witness: ContentDigest,
    ) -> Result<fss_object::DeletionRemoval, LocalPublicationError> {
        self.require_live()?;
        if object == witness {
            return Err(LocalPublicationError::MissingDeletionAuthority { object });
        }
        self.spool.require_verified(witness).map_err(|error| {
            LocalPublicationError::ReferenceBlocked {
                object: witness,
                role: ReferenceRole::DeletionWitness,
                reason: error.into(),
            }
        })?;
        if let Some(entry) = self.visible.values().find(|entry| {
            self.closure(entry.visible.root, &entry.children)
                .contains(&object)
        }) {
            return Err(LocalPublicationError::TombstoneBlockedByVisibleRoot {
                object,
                slot: entry.visible.slot.clone(),
            });
        }
        self.spool
            .remove_for_deletion(object)
            .map_err(|error| self.spool_error(error))
    }

    /// Whether a directory entry still occupies the spool object or hold name of `digest`.
    #[must_use]
    pub fn object_name_present(&self, digest: ContentDigest) -> bool {
        self.spool.name_present(digest)
    }

    /// Confirm the owned directories exist before interpreting missing deletion names.
    /// A missing directory or a replacement symlink cannot witness an empty namespace.
    pub fn verify_deletion_directories(&self) -> Result<(), LocalPublicationError> {
        let spool = self.root.join(LOCAL_SPOOL_DIR);
        let objects = spool.join(fss_object::SPOOL_OBJECTS_DIR);
        let holds = spool.join(fss_object::SPOOL_HOLDS_DIR);
        for path in [&self.root, &spool, &objects, &holds, &self.roots_dir] {
            if !directory_present(self.io.as_ref(), path)? {
                return Err(LocalPublicationError::InvalidLayout { path: path.clone() });
            }
        }
        Ok(())
    }

    /// Inspect the root record name without following its final component. Only an
    /// observed missing name counts as absent, even when the slot is absent from memory.
    pub fn root_record_name_present(&self, slot: &SlotName) -> Result<bool, LocalPublicationError> {
        let path = self.roots_dir.join(format!("{slot}{ROOT_RECORD_SUFFIX}"));
        match self.io.symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(io_error(LocalIoOperation::Inspect, &path, &error)),
        }
    }

    /// Removes exactly the orphaned temporary records classified on open or left by a failed
    /// cleanup. Returns how many were removed. Nothing else is touched.
    pub fn discard_orphaned_temps(&mut self) -> Result<usize, LocalPublicationError> {
        self.require_live()?;
        let mut removed = 0;
        for relative in self.orphan_temps.clone() {
            let path = self.root.join(&relative);
            match self.io.symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    self.io
                        .remove_file(&path)
                        .map_err(|error| io_error(LocalIoOperation::RemoveTemp, &path, &error))?;
                    removed += 1;
                }
                Ok(_) => return Err(LocalPublicationError::InvalidLayout { path }),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(LocalIoOperation::Inspect, &path, &error)),
            }
            self.orphan_temps.remove(&relative);
        }
        for directory in [&self.roots_dir, &self.tombstones_dir] {
            self.io
                .sync_directory(directory)
                .map_err(|error| io_error(LocalIoOperation::SyncDirectory, directory, &error))?;
        }
        Ok(removed)
    }

    /// Removes exactly the orphaned staging files the owned spool classified on open, through
    /// [`fss_object::StagingSpool::discard_orphaned_staging`] (fss-vmau3). Spool objects, root
    /// records, tombstones, and foreign entries are never touched.
    ///
    /// The spool's contract is kept unchanged: every removal it released is fsynced before this
    /// returns, a settled failure leaves the remaining orphans charged and listed, and an outcome
    /// that cannot be observed ([`SpoolError::DiscardIndeterminate`], or an accounting overflow)
    /// poisons the spool. Such a failure also poisons this publisher, so every later mutating
    /// call fails until a reopen reclassifies the staging directory; a retry can never report an
    /// empty success for removals that may not be durable.
    pub fn discard_orphaned_staging(&mut self) -> Result<DiscardReceipt, LocalPublicationError> {
        self.require_live()?;
        self.spool.discard_orphaned_staging().map_err(|error| {
            if matches!(
                error,
                SpoolError::DiscardIndeterminate { .. }
                    | SpoolError::AccountingOverflow
                    | SpoolError::Poisoned
            ) {
                self.poisoned = true;
            }
            LocalPublicationError::Spool(error)
        })
    }

    /// Every orphaned temporary record this instance currently knows, in path order: those
    /// classified on open and those a failed cleanup left since, minus those since discarded.
    /// Unlike [`Self::recovery_report`], this is the live set, not the open-time snapshot.
    pub fn orphaned_temps(&self) -> impl Iterator<Item = &Path> {
        self.orphan_temps.iter().map(PathBuf::as_path)
    }

    /// Path, relative to the publication root, of the temporary root record that a
    /// publication into `slot` writes before its root-last commit.
    #[must_use]
    pub fn root_temp_path(slot: &SlotName) -> PathBuf {
        Path::new(LOCAL_ROOTS_DIR).join(format!("{slot}{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}"))
    }

    /// Discards the orphaned temporary root record of `slot` only when it is provably a crashed
    /// attempt of publishing exactly `manifest` into `slot`, so that publication can be redone.
    ///
    /// Proof is byte equality with the record this publication writes, which names the slot,
    /// the manifest root, and its child count. Returns `Ok(false)` and touches nothing when no
    /// orphaned temp is known for `slot`, and `Ok(true)` once the temp is gone durably. A temp
    /// with any other content, one that is not a regular file, or one whose slot is visible or
    /// broken is kept and refused as [`LocalPublicationError::OrphanedTemp`]. No other temp,
    /// record, or object is touched.
    pub fn discard_orphaned_root_temp_for(
        &mut self,
        slot: &SlotName,
        manifest: &ObjectManifest,
    ) -> Result<bool, LocalPublicationError> {
        self.require_live()?;
        let root = manifest.root();
        if manifest.computed_root() != root {
            return Err(LocalPublicationError::ManifestMismatch { root });
        }
        let relative = Self::root_temp_path(slot);
        if !self.orphan_temps.contains(&relative) {
            return Ok(false);
        }
        let refused = || LocalPublicationError::OrphanedTemp {
            path: relative.clone(),
        };
        if self.visible.contains_key(slot) || self.broken_slots.contains(slot) {
            return Err(refused());
        }
        let expected = root_record_bytes(slot, root, manifest.children().len())?;
        let path = self.root.join(&relative);
        match self.io.symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => return Err(refused()),
            Err(error) => return Err(io_error(LocalIoOperation::Inspect, &path, &error)),
        }
        match read_bounded(self.io.as_ref(), &path, MAX_ROOT_RECORD_BYTES)? {
            Some(bytes) if bytes == expected => {}
            _ => return Err(refused()),
        }
        self.remove_temp(&relative, &path)?;
        self.orphan_temps.remove(&relative);
        Ok(true)
    }

    /// Rolls back a tombstone rename that was reported failed and returns the error to report.
    ///
    /// The rename may have taken effect anyway, so the record at `target` is removed and the
    /// removal is fsynced; `NotFound` proves the rename did not take effect. When the rollback
    /// completes, nothing is visible and the rename error is returned. When the removal or its
    /// fsync fails, the tombstone may be visible or may reappear after a crash: the tombstone is
    /// marked indeterminate on disk, the instance is poisoned, and
    /// [`LocalPublicationError::TombstoneVisibilityIndeterminate`] carries every observed outcome.
    fn roll_back_failed_tombstone_rename(
        &mut self,
        object: &ContentDigest,
        (temp_relative, temp_path): (&Path, &Path),
        target: &Path,
        record: &[u8],
        rename_kind: io::ErrorKind,
    ) -> LocalPublicationError {
        let rollback = match self.io.remove_file(target) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => Some((LocalIoOperation::RemoveRecord, error.kind())),
            Ok(()) => match self.io.sync_directory(&self.tombstones_dir) {
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
        self.tombstones.remove(object);
        let marker_kind = self
            .record_indeterminate_tombstone_marker(object, record)
            .err();
        if marker_kind.is_some()
            && let Ok(mut file) = self.io.open_lock(target)
        {
            let _ = write_all(
                self.io.as_ref(),
                &mut file,
                b"corrupted_indeterminate_tombstone",
            );
            let _ = self.io.sync_file(&file);
        }
        LocalPublicationError::TombstoneVisibilityIndeterminate {
            object: *object,
            path: target.to_path_buf(),
            rename_kind,
            rollback_operation,
            rollback_kind,
            marker_kind,
        }
    }

    /// Durably records `<stem>.tomb.indeterminate`, holding the attempted tombstone `record`.
    ///
    /// A marker that already exists records the same fact and is kept. A marker left partially
    /// written by a failure here still marks the tombstone on reopen, which classifies it by
    /// existence alone.
    fn record_indeterminate_tombstone_marker(
        &self,
        object: &ContentDigest,
        record: &[u8],
    ) -> Result<(), io::ErrorKind> {
        let stem = digest_file_stem(*object);
        let path = self.tombstones_dir.join(format!(
            "{stem}{TOMBSTONE_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}"
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
            .sync_directory(&self.tombstones_dir)
            .map_err(|error| error.kind())
    }
}
