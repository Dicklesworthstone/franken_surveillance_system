#![forbid(unsafe_code)]
//! Coordinated [`PackStore`] facade uniting sealed packfiles, derived index, bounded FD pool,
//! and the unbounded virtual root catalog under the root-last publication invariant.

mod maintenance;
mod publication;
mod reader;

use std::fs::{self, File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use fss_core::{ContentDigest, RegionTree};
use fss_object::{ObjectError, VerifiedObjectCatalog};
use fss_runtime::authority::AuthorityCx;

use crate::catalog::{
    CatalogRecoveryReport, CatalogRootEntry, CompactionReceipt, QuotaStatus, RootPage,
    RootPublishReceipt, VirtualRootCatalog, VirtualRootRecord,
};
use crate::compaction::ReaderEpochTracker;
use crate::error::{PackCutPoint, PackError, PackIoOperation};
use crate::fd_pool::{FdPool, FdPoolStats};
use crate::format::{PackFooter, PackId, PackLocation, PackObjectInput};
use crate::index::PackIndex;
use crate::packfile::{
    PackConfig, PackRecoveryReport, PackWriter, SealedPackReceipt, recover_packs_and_index,
    verify_sealed_pack,
};
use crate::retention::ObjectTombstoneLog;

pub use maintenance::PreparedEviction;
pub use reader::{PackReadBudget, PackReader};

/// Combined recovery summary returned by [`PackStore::recovery_report`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoreRecoveryReport {
    /// Packfile and derived index recovery details.
    pub packs: PackRecoveryReport,
    /// Virtual root catalog journal/snapshot recovery details.
    pub catalog: CatalogRecoveryReport,
}

/// Receipt returned by [`PackStore::publish_graph`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphPublishReceipt {
    /// Packfile locations assigned to every child object (in input order).
    pub child_locations: Vec<PackLocation>,
    /// Durably published root entry in the virtual root catalog.
    pub root_entry: CatalogRootEntry,
    /// Quota status after publishing the root.
    pub quota_status: QuotaStatus,
    /// Packfile fsync barriers performed during this publish call.
    pub pack_fsyncs: u64,
    /// Catalog fsync barriers performed during this publish call.
    pub catalog_fsyncs: u64,
}

/// Structured telemetry snapshot suitable for JSONL diagnostic logging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackTelemetrySnapshot {
    /// Most recently written or active pack identifier, if any.
    pub latest_pack_id: Option<PackId>,
    /// Total unique indexed objects.
    pub indexed_objects: usize,
    /// Total unique logical payload bytes stored.
    pub total_payload_bytes: u64,
    /// Total live roots in the virtual root catalog.
    pub live_roots: u64,
    /// Cumulative packfile durability barriers executed.
    pub pack_fsync_count: u64,
    /// Cumulative catalog durability barriers executed.
    pub catalog_fsync_count: u64,
    /// Open-FD LRU cache statistics.
    pub fd_pool: FdPoolStats,
}

/// Append-only sealed packfile object store and unbounded virtual root catalog.
pub struct PackStore {
    root_dir: PathBuf,
    packs_dir: PathBuf,
    index_dir: PathBuf,
    config: PackConfig,
    _lock_file: File,
    index: Arc<RwLock<PackIndex>>,
    fd_pool: Arc<FdPool>,
    reader_epochs: Arc<ReaderEpochTracker>,
    tombstones: Arc<RwLock<ObjectTombstoneLog>>,
    writer: Mutex<PackWriter>,
    // Prepared retention holds this fence across canonical metadata appends. Keep it
    // separate from the catalog RwLock so the combiner can still append/read objects.
    catalog_mutation: Mutex<()>,
    catalog: RwLock<VirtualRootCatalog>,
    pack_fsync_count: Arc<AtomicU64>,
    recovery_report: StoreRecoveryReport,
}

impl PackStore {
    /// Opens or initializes a [`PackStore`] rooted at `root_dir`, acquiring an exclusive lock
    /// and deterministically recovering packs, derived index, and root catalog.
    pub fn open(root_dir: impl AsRef<Path>, config: PackConfig) -> Result<Self, PackError> {
        let config = config.validate()?;
        let root_dir = root_dir.as_ref().to_path_buf();
        let objects_dir = root_dir.join("objects");
        let packs_dir = objects_dir.join("packs");
        let index_dir = objects_dir.join("index");
        let roots_dir = objects_dir.join("roots");

        fs::create_dir_all(&packs_dir)
            .map_err(|err| PackError::io(PackIoOperation::CreateDir, err))?;
        fs::create_dir_all(&index_dir)
            .map_err(|err| PackError::io(PackIoOperation::CreateDir, err))?;
        fs::create_dir_all(&roots_dir)
            .map_err(|err| PackError::io(PackIoOperation::CreateDir, err))?;

        let lock_path = root_dir.join("LOCK");
        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|err| PackError::io(PackIoOperation::Open, err))?;
        match lock_file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(PackError::StoreLocked),
            Err(TryLockError::Error(err)) => {
                return Err(PackError::io(PackIoOperation::Lock, err));
            }
        }

        let tombstone_log = ObjectTombstoneLog::open_for_store(
            &roots_dir,
            &packs_dir,
            &index_dir,
            config.durability,
        )?;
        let tombstoned_snapshot = tombstone_log.snapshot_map();

        let (pack_index, active_state, next_seq, pack_recovery) =
            recover_packs_and_index(&packs_dir, &index_dir, config, &tombstoned_snapshot)?;
        let (catalog, catalog_recovery) =
            VirtualRootCatalog::open(roots_dir, config.durability, config.quota)?;

        let index = Arc::new(RwLock::new(pack_index));
        let fd_pool = Arc::new(FdPool::new(packs_dir.clone(), config.max_open_packs)?);
        let reader_epochs = Arc::new(ReaderEpochTracker::new());
        let tombstones = Arc::new(RwLock::new(tombstone_log));
        let pack_fsync_count = Arc::new(AtomicU64::new(0));
        let writer = PackWriter::new(
            packs_dir.clone(),
            index_dir.clone(),
            config,
            Arc::clone(&index),
            Arc::clone(&tombstones),
            active_state,
            next_seq,
            Arc::clone(&pack_fsync_count),
        );

        Ok(Self {
            root_dir,
            packs_dir,
            index_dir,
            config,
            _lock_file: lock_file,
            index,
            fd_pool,
            reader_epochs,
            tombstones,
            writer: Mutex::new(writer),
            catalog_mutation: Mutex::new(()),
            catalog: RwLock::new(catalog),
            pack_fsync_count,
            recovery_report: StoreRecoveryReport {
                packs: pack_recovery,
                catalog: catalog_recovery,
            },
        })
    }

    /// Returns the store root directory path.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Returns the recovery summary captured when this store was opened.
    #[must_use]
    pub const fn recovery_report(&self) -> &StoreRecoveryReport {
        &self.recovery_report
    }

    /// Returns the bounded open-FD LRU pool for inspecting open handle counts and eviction metrics.
    #[must_use]
    pub fn fd_pool(&self) -> &FdPool {
        &self.fd_pool
    }

    /// Returns a cloneable concurrent [`PackReader`] sharing the index, bounded FD pool,
    /// reader-epoch barrier, and durable object tombstone state.
    #[must_use]
    pub fn reader(&self) -> PackReader {
        PackReader {
            index: Arc::clone(&self.index),
            fd_pool: Arc::clone(&self.fd_pool),
            reader_epochs: Arc::clone(&self.reader_epochs),
            tombstones: Arc::clone(&self.tombstones),
            max_object_bytes: self.config.max_object_bytes,
            max_read_bytes: self.config.max_read_bytes,
        }
    }

    /// Appends a batch of objects with group-commit durability and automatic deduplication.
    pub fn append_batch(
        &self,
        objects: &[PackObjectInput<'_>],
    ) -> Result<Vec<PackLocation>, PackError> {
        // Hold the deletion fence from the batch digest preflight through index publication.
        let _catalog = self.catalog.read().map_err(|_| PackError::LockPoisoned)?;
        self.append_under_catalog_lock(objects)
    }

    fn append_under_catalog_lock(
        &self,
        objects: &[PackObjectInput<'_>],
    ) -> Result<Vec<PackLocation>, PackError> {
        let mut writer = self.writer.lock().map_err(|_| PackError::LockPoisoned)?;
        writer.append_batch(objects)
    }

    /// Appends a batch after explicitly verifying that the caller's [`AuthorityCx`] is not cancelled.
    pub fn append_batch_with_authority(
        &self,
        cx: &AuthorityCx,
        tree: &RegionTree,
        objects: &[PackObjectInput<'_>],
    ) -> Result<Vec<PackLocation>, PackError> {
        if cx.is_cancel_requested(tree)? {
            return Err(PackError::Cancelled);
        }
        self.append_batch(objects)
    }

    /// Explicitly seals the currently active packfile (if non-empty) and drops its writer FD.
    pub fn seal_active_pack(&self) -> Result<Option<SealedPackReceipt>, PackError> {
        let mut writer = self.writer.lock().map_err(|_| PackError::LockPoisoned)?;
        writer.seal_active()
    }

    /// Looks up a content digest in O(1) time without touching disk.
    pub fn lookup(&self, digest: &ContentDigest) -> Result<Option<PackLocation>, PackError> {
        let guard = self.index.read().map_err(|_| PackError::LockPoisoned)?;
        Ok(guard.get(digest))
    }

    /// Reads and cryptographically verifies an object payload by SHA-256 [`ContentDigest`].
    pub fn read_verified(&self, digest: &ContentDigest) -> Result<Vec<u8>, PackError> {
        self.reader().read_verified(digest)
    }

    /// Reads and verifies an object payload while enforcing a cumulative [`PackReadBudget`].
    pub fn read_verified_with_budget(
        &self,
        digest: &ContentDigest,
        budget: &PackReadBudget,
    ) -> Result<Vec<u8>, PackError> {
        self.reader().read_verified_with_budget(digest, budget)
    }

    /// Verifies the full on-disk integrity (`FSSF`..`FSSE` footer and `whole_pack_sha256`) of a
    /// sealed packfile.
    pub fn verify_pack(&self, pack_id: PackId) -> Result<PackFooter, PackError> {
        verify_sealed_pack(&self.packs_dir, pack_id)
    }

    /// Persists the derived `pack-index.fssi` snapshot atomically.
    pub fn save_index_snapshot(&self) -> Result<usize, PackError> {
        let snapshot = self
            .index
            .read()
            .map_err(|_| PackError::LockPoisoned)?
            .clone();
        snapshot.save_atomic(&self.index_dir, self.config.durability)
    }

    /// Root-last publication: flushes and `fsync`s every child object in the packfile BEFORE
    /// appending and `fsync`ing the root publication record in `catalog.fssr`.
    pub fn publish_graph(
        &self,
        children: &[PackObjectInput<'_>],
        root_record: VirtualRootRecord,
    ) -> Result<GraphPublishReceipt, PackError> {
        self.publish_graph_internal(children, root_record, None)
    }

    /// Authority-checked root-last publication verifying `cx` is active before mutating I/O.
    pub fn publish_graph_with_authority(
        &self,
        cx: &AuthorityCx,
        tree: &RegionTree,
        children: &[PackObjectInput<'_>],
        root_record: VirtualRootRecord,
    ) -> Result<GraphPublishReceipt, PackError> {
        if cx.is_cancel_requested(tree)? {
            return Err(PackError::Cancelled);
        }
        self.publish_graph(children, root_record)
    }

    /// Fault-injection seam for deterministic crash-cut verification of the root-last invariant.
    pub fn publish_graph_with_cut_point(
        &self,
        children: &[PackObjectInput<'_>],
        root_record: VirtualRootRecord,
        cut_point: PackCutPoint,
    ) -> Result<GraphPublishReceipt, PackError> {
        self.publish_graph_internal(children, root_record, Some(cut_point))
    }

    fn publish_graph_internal(
        &self,
        children: &[PackObjectInput<'_>],
        root_record: VirtualRootRecord,
        cut_point: Option<PackCutPoint>,
    ) -> Result<GraphPublishReceipt, PackError> {
        root_record.validate()?;
        // The complete supplied batch stays protected against deletion until its root is
        // visible. This includes children outside the descriptor's direct root/metadata pair.
        let _mutation = self
            .catalog_mutation
            .lock()
            .map_err(|_| PackError::LockPoisoned)?;
        let mut catalog_guard = self.catalog.write().map_err(|_| PackError::LockPoisoned)?;
        if catalog_guard.get_root(&root_record.root_id).is_some() {
            return Err(PackError::RootAlreadyExists(root_record.root_id));
        }

        let pack_fsyncs_before = self.pack_fsync_count.load(Ordering::Relaxed);
        let child_locations = self.append_under_catalog_lock(children)?;
        let pack_fsyncs_after = self.pack_fsync_count.load(Ordering::Relaxed);

        let custody = publication::PublicationCustody::new(self)?;
        custody.verify_root(&root_record)?;
        if let Some(PackCutPoint::AfterPackSyncBeforeRootAppend) = cut_point {
            return Err(PackError::InjectedCrash(
                PackCutPoint::AfterPackSyncBeforeRootAppend,
            ));
        }
        let before = catalog_guard.fsync_count();
        let receipt = catalog_guard.publish_root(root_record)?;
        let catalog_fsyncs = catalog_guard.fsync_count().saturating_sub(before);

        Ok(GraphPublishReceipt {
            child_locations,
            root_entry: receipt.entry,
            quota_status: receipt.quota_status,
            pack_fsyncs: pack_fsyncs_after.saturating_sub(pack_fsyncs_before),
            catalog_fsyncs,
        })
    }

    /// Publishes one root after freshly verifying its root and attached metadata bytes.
    /// Missing, corrupt, tombstoned, or over-budget references refuse before catalog mutation.
    pub fn publish_root(
        &self,
        root_record: VirtualRootRecord,
    ) -> Result<RootPublishReceipt, PackError> {
        root_record.validate()?;
        let _mutation = self
            .catalog_mutation
            .lock()
            .map_err(|_| PackError::LockPoisoned)?;
        let mut catalog_guard = self.catalog.write().map_err(|_| PackError::LockPoisoned)?;
        let custody = publication::PublicationCustody::new(self)?;
        custody.verify_root(&root_record)?;
        catalog_guard.publish_root(root_record)
    }

    /// Group-commits roots only after every root and attached metadata object verifies.
    /// A rejected reference leaves the entire catalog batch unpublished.
    pub fn publish_roots_batch(
        &self,
        root_records: &[VirtualRootRecord],
    ) -> Result<Vec<RootPublishReceipt>, PackError> {
        for rec in root_records {
            rec.validate()?;
        }
        let _mutation = self
            .catalog_mutation
            .lock()
            .map_err(|_| PackError::LockPoisoned)?;
        let mut catalog_guard = self.catalog.write().map_err(|_| PackError::LockPoisoned)?;
        let custody = publication::PublicationCustody::new(self)?;
        for rec in root_records {
            custody.verify_root(rec)?;
        }
        catalog_guard.publish_roots_batch(root_records)
    }

    /// Atomically supersedes a `Live` root after verifying the replacement's root and metadata.
    /// Failed custody verification leaves the previous root live.
    pub fn supersede_root(
        &self,
        old_id: &str,
        new_record: VirtualRootRecord,
    ) -> Result<RootPublishReceipt, PackError> {
        new_record.validate()?;
        let _mutation = self
            .catalog_mutation
            .lock()
            .map_err(|_| PackError::LockPoisoned)?;
        let mut catalog_guard = self.catalog.write().map_err(|_| PackError::LockPoisoned)?;
        let custody = publication::PublicationCustody::new(self)?;
        custody.verify_root(&new_record)?;
        catalog_guard.supersede_root(old_id, new_record)
    }

    /// Permanently tombstones `root_id` with an explicit reason/authority digest.
    pub fn tombstone_root(
        &self,
        root_id: &str,
        reason_digest: ContentDigest,
    ) -> Result<CatalogRootEntry, PackError> {
        let _mutation = self
            .catalog_mutation
            .lock()
            .map_err(|_| PackError::LockPoisoned)?;
        let mut catalog_guard = self.catalog.write().map_err(|_| PackError::LockPoisoned)?;
        catalog_guard.tombstone_root(root_id, reason_digest)
    }

    /// Looks up a root entry in O(1) time.
    pub fn get_root(&self, root_id: &str) -> Result<Option<CatalogRootEntry>, PackError> {
        let catalog_guard = self.catalog.read().map_err(|_| PackError::LockPoisoned)?;
        Ok(catalog_guard.get_root(root_id).cloned())
    }

    /// Lists roots deterministically in ascending `root_id` order starting strictly after `cursor`.
    pub fn list_roots(&self, cursor: Option<&str>, limit: usize) -> Result<RootPage, PackError> {
        let catalog_guard = self.catalog.read().map_err(|_| PackError::LockPoisoned)?;
        Ok(catalog_guard.list_roots(cursor, limit))
    }

    /// Lists only `Live` roots deterministically in ascending `root_id` order after `cursor`.
    pub fn list_live_roots(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<RootPage, PackError> {
        let catalog_guard = self.catalog.read().map_err(|_| PackError::LockPoisoned)?;
        Ok(catalog_guard.list_live_roots(cursor, limit))
    }

    /// Returns the exact number of currently `Live` roots in O(1) time.
    pub fn live_root_count(&self) -> Result<u64, PackError> {
        let catalog_guard = self.catalog.read().map_err(|_| PackError::LockPoisoned)?;
        Ok(catalog_guard.live_root_count())
    }

    /// Compacts the virtual root catalog journal into an atomic `catalog.snap` snapshot.
    pub fn compact_catalog(&self) -> Result<CompactionReceipt, PackError> {
        let _mutation = self
            .catalog_mutation
            .lock()
            .map_err(|_| PackError::LockPoisoned)?;
        let mut catalog_guard = self.catalog.write().map_err(|_| PackError::LockPoisoned)?;
        catalog_guard.compact()
    }

    /// Returns a point-in-time telemetry snapshot of packfile, index, catalog, and FD-pool state.
    pub fn telemetry_snapshot(&self) -> Result<PackTelemetrySnapshot, PackError> {
        let (indexed_objects, total_payload_bytes, latest_pack_id) = {
            let index_guard = self.index.read().map_err(|_| PackError::LockPoisoned)?;
            (
                index_guard.len(),
                index_guard.total_payload_bytes(),
                index_guard.packs().keys().next_back().copied(),
            )
        };
        let (live_roots, catalog_fsync_count) = {
            let catalog_guard = self.catalog.read().map_err(|_| PackError::LockPoisoned)?;
            (catalog_guard.live_root_count(), catalog_guard.fsync_count())
        };
        Ok(PackTelemetrySnapshot {
            latest_pack_id,
            indexed_objects,
            total_payload_bytes,
            live_roots,
            pack_fsync_count: self.pack_fsync_count.load(Ordering::Relaxed),
            catalog_fsync_count,
            fd_pool: self.fd_pool.stats(),
        })
    }
}

impl VerifiedObjectCatalog for PackStore {
    fn require_verified(&self, digest: ContentDigest) -> Result<(), ObjectError> {
        self.read_verified(&digest)
            .map(|_| ())
            .map_err(|err| err.to_object_error(digest))
    }
}
