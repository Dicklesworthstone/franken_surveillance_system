#![forbid(unsafe_code)]
//! Open-time initialization and recovery for [`super::LocalRootPublisher`].

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;
use std::sync::Arc;

use fss_core::ContentDigest;
use fss_object::{SpoolError, SpoolIo, SpoolObjectState, StagingSpool};

use super::classify::{LocalLayout, RedundantTemp, ReferenceCheck, classify_local};
use super::fs_io::{acquire_lock, ensure_subdirectory, io_error, unreferenced_spool_objects};
use super::{
    BlockReason, LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR, LOCAL_TOMBSTONES_DIR, LocalIoOperation,
    LocalPublicationError, LocalPublicationLimits, LocalPublicationState, LocalRecoveryReport,
    LocalRootPublisher,
};

impl LocalRootPublisher {
    pub(super) fn open_through(
        root: &Path,
        limits: LocalPublicationLimits,
        io: Arc<dyn SpoolIo>,
    ) -> Result<Self, LocalPublicationError> {
        let limits = limits.validate()?;
        let root = root.to_path_buf();
        io.create_dir_all(&root)
            .map_err(|error| io_error(LocalIoOperation::CreateDirectory, &root, &error))?;
        let metadata = io
            .symlink_metadata(&root)
            .map_err(|error| io_error(LocalIoOperation::Inspect, &root, &error))?;
        if !metadata.file_type().is_dir() {
            return Err(LocalPublicationError::InvalidLayout { path: root });
        }
        let lock = acquire_lock(&io, &root)?;
        let roots_dir = root.join(LOCAL_ROOTS_DIR);
        let tombstones_dir = root.join(LOCAL_TOMBSTONES_DIR);
        ensure_subdirectory(io.as_ref(), &roots_dir)?;
        ensure_subdirectory(io.as_ref(), &tombstones_dir)?;
        let spool = StagingSpool::open_with_verified_recovery(
            root.join(LOCAL_SPOOL_DIR),
            limits.spool,
            Arc::clone(&io),
        )
        .map_err(LocalPublicationError::Spool)?;
        io.sync_directory(&root)
            .map_err(|error| io_error(LocalIoOperation::SyncDirectory, &root, &error))?;

        let mut publisher = Self {
            io,
            root,
            roots_dir,
            tombstones_dir,
            limits,
            spool,
            visible: BTreeMap::new(),
            staged: BTreeMap::new(),
            broken_slots: BTreeSet::new(),
            orphan_temps: BTreeSet::new(),
            tombstones: BTreeMap::new(),
            recovery: LocalRecoveryReport::default(),
            injected_crash: None,
            injected_io_fault: None,
            poisoned: false,
            _lock: lock,
        };
        publisher.recover()?;
        Ok(publisher)
    }

    /// Classifies the publication root through [`classify_local`], verifying every reference
    /// through the owned spool, then fsyncs `roots/` and `tombstones/`. Admitted roots are
    /// reported `Durable` only if the roots fsync succeeded.
    fn recover(&mut self) -> Result<(), LocalPublicationError> {
        let io = Arc::clone(&self.io);
        let root = self.root.clone();
        let limits = self.limits;
        let spool = self.spool.recovery_report().clone();
        let layout = LocalLayout {
            roots: true,
            tombstones: true,
        };
        let classified = {
            // The fast reference checker cannot escape this opening operation. Only the
            // references actually consumed by classification retain Verified eligibility;
            // unrelated staged work still requires explicit verification before publishing.
            let mut references = RecoveryReferences {
                publisher: self,
                verified: BTreeSet::new(),
            };
            let classified =
                classify_local(io.as_ref(), &root, &limits, layout, spool, &mut references)?;
            references
                .publisher
                .spool
                .retain_verification(&references.verified);
            classified
        };
        let mut report = classified.report;
        self.visible = classified.visible;
        self.broken_slots = classified.broken_slots;
        self.orphan_temps = classified.orphan_temps;
        self.tombstones = classified.tombstones;

        let roots_synced = self.io.sync_directory(&self.roots_dir).is_ok();
        let _ = self.io.sync_directory(&self.tombstones_dir);

        for entry in self.visible.values_mut() {
            if roots_synced {
                entry.visible.state = LocalPublicationState::Durable;
            }
            report.roots.push(entry.visible.clone());
        }
        let mut referenced = BTreeSet::new();
        for entry in self.visible.values() {
            referenced.extend(self.closure(entry.visible.root, &entry.children));
        }
        report.unreferenced_objects = unreferenced_spool_objects(&report.spool, &referenced);
        self.recovery = report;
        Ok(())
    }
}

/// Fresh verification reuse is scoped to the immediate root-opening classifier.
struct RecoveryReferences<'a> {
    publisher: &'a mut LocalRootPublisher,
    verified: BTreeSet<ContentDigest>,
}

impl ReferenceCheck for RecoveryReferences<'_> {
    /// Used only by immediate open-time recovery. Reuses the owned spool's fresh verification
    /// for held objects; an unheld object still needs the normal verification/hold barrier.
    /// Corrupt or missing objects block a reference; every other spool failure fails the open.
    fn check_reference(
        &mut self,
        object: ContentDigest,
    ) -> Result<Result<(), BlockReason>, LocalPublicationError> {
        // Do not move this fast path into require_verified, read, or publish. Those operations
        // must observe current bytes, not the earlier startup snapshot. A successful fallback
        // also settles an unheld reference once, even when many roots share it.
        let verified = match self.publisher.spool.state(object) {
            Some(SpoolObjectState::Verified) => Ok(SpoolObjectState::Verified),
            _ => self.publisher.spool.verify(object),
        };
        match verified {
            Ok(SpoolObjectState::Verified) => {
                self.verified.insert(object);
                Ok(Ok(()))
            }
            Ok(SpoolObjectState::Staged) => Ok(Err(BlockReason::NotVerified)),
            Ok(SpoolObjectState::Corrupt(_)) | Err(SpoolError::Corrupt { .. }) => {
                Ok(Err(BlockReason::Corrupt))
            }
            Err(SpoolError::Missing(_)) => Ok(Err(BlockReason::Missing)),
            Err(error) => Err(self.publisher.spool_error(error)),
        }
    }

    fn check_and_read_manifest(
        &mut self,
        root: ContentDigest,
    ) -> Result<Result<Vec<u8>, BlockReason>, LocalPublicationError> {
        match self.publisher.spool.verify_and_read(root) {
            Ok((SpoolObjectState::Verified, bytes)) => {
                self.verified.insert(root);
                Ok(Ok(bytes))
            }
            Ok((SpoolObjectState::Staged, _)) => Ok(Err(BlockReason::NotVerified)),
            Ok((SpoolObjectState::Corrupt(_), _)) | Err(SpoolError::Corrupt { .. }) => {
                Ok(Err(BlockReason::Corrupt))
            }
            Err(SpoolError::Missing(_)) => Ok(Err(BlockReason::Missing)),
            Err(error) => Err(self.publisher.spool_error(error)),
        }
    }

    fn manifest_body(&mut self, root: ContentDigest) -> Result<Vec<u8>, LocalPublicationError> {
        self.publisher
            .spool
            .read(root)
            .map_err(|error| self.publisher.spool_error(error))
    }

    fn redundant_temp(&mut self, path: &Path) -> RedundantTemp {
        match self.publisher.io.remove_file(path) {
            Ok(()) => RedundantTemp::Removed,
            Err(error) if error.kind() == io::ErrorKind::NotFound => RedundantTemp::Removed,
            Err(_) => RedundantTemp::Kept,
        }
    }
}
