//! Source disclosure through a borrowed, lock-owning local publisher and explicit I/O.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{ContentDigest, HydrationRequest, HydrationResponse, TimestampNs};
use fss_object::{MAX_OBJECT_BYTES, SpoolIo};
use fss_publication::{
    LocalInspection, LocalPublicationError, LocalPublicationState, LocalRootPublisher, SlotName,
    WriterDetectionOptions, inspect_with_io, read_verified_with_io,
};

use super::{
    PublishedSourceReader, ReferenceHydrationCatalog, SourceHydrationError, SourceObjectBinding,
};

/// Borrowing the publisher keeps its exclusive ownership lock alive throughout disclosure.
/// The caller supplies the same scoped I/O capability used by that publisher.
struct LocalSourceReader<'a> {
    publisher: &'a LocalRootPublisher,
    io: &'a dyn SpoolIo,
}

type RootIdentities = BTreeMap<SlotName, (ContentDigest, ContentDigest, usize)>;

impl LocalSourceReader<'_> {
    fn verify_snapshot(
        &self,
        publication_root: ContentDigest,
        subject_digest: ContentDigest,
    ) -> Result<(), SourceHydrationError> {
        if self.publisher.is_poisoned() {
            return Err(LocalPublicationError::Poisoned.into());
        }
        let mut expected = RootIdentities::new();
        let mut selected = None;
        for root in self.publisher.visible_roots() {
            // Inspection alone cannot establish durability. Only the live owner can do that.
            if root.state != LocalPublicationState::Durable {
                return Err(SourceHydrationError::SnapshotChanged);
            }
            expected.insert(
                root.slot.clone(),
                (root.root, root.record_digest, root.child_count),
            );
            if root.root == publication_root && selected.is_none() {
                selected = Some(root.slot.clone());
            }
        }
        let selected = selected.ok_or(SourceHydrationError::NotReachable)?;
        let snapshot = inspect_with_io(
            self.io,
            self.publisher.root_dir(),
            self.publisher.limits(),
            None,
            WriterDetectionOptions {
                probe_shared_lock: false,
                self_holds_lock: true,
            },
        )?;
        self.validate_snapshot(&snapshot, &expected)?;
        let observed = snapshot
            .root_closures
            .get(&selected)
            .ok_or(SourceHydrationError::SnapshotChanged)?;
        let expected_closure = self
            .publisher
            .root_closure(&selected)
            .ok_or(SourceHydrationError::SnapshotChanged)?;
        if observed != &expected_closure {
            return Err(SourceHydrationError::SnapshotChanged);
        }
        if !observed.contains(&subject_digest) {
            return Err(SourceHydrationError::NotReachable);
        }
        Ok(())
    }

    fn validate_snapshot(
        &self,
        snapshot: &LocalInspection,
        expected: &RootIdentities,
    ) -> Result<(), SourceHydrationError> {
        if snapshot.missing_layout
            || snapshot.spool_over_capacity
            || snapshot.holds_migration_pending
        {
            return Err(SourceHydrationError::SnapshotChanged);
        }
        // Compare all publication identities: losing a nested root must never turn its
        // manifest into an opaque leaf and silently shrink the authorized closure.
        let observed: RootIdentities = snapshot
            .report
            .roots
            .iter()
            .map(|root| {
                (
                    root.slot.clone(),
                    (root.root, root.record_digest, root.child_count),
                )
            })
            .collect();
        let tombstones: BTreeSet<_> = self.publisher.tombstones().copied().collect();
        let observed_tombstones: BTreeSet<_> = snapshot.report.tombstones.iter().copied().collect();
        if observed != *expected || tombstones != observed_tombstones {
            return Err(SourceHydrationError::SnapshotChanged);
        }
        Ok(())
    }
}

impl PublishedSourceReader for LocalSourceReader<'_> {
    fn read_published_source(
        &self,
        publication_root: ContentDigest,
        subject_digest: ContentDigest,
        max_payload_bytes: u64,
    ) -> Result<Vec<u8>, SourceHydrationError> {
        self.verify_snapshot(publication_root, subject_digest)?;
        let ceiling = usize::try_from(max_payload_bytes.min(MAX_OBJECT_BYTES as u64))
            .map_err(|_| SourceHydrationError::SourceMismatch)?;
        let payload =
            read_verified_with_io(self.publisher.root_dir(), subject_digest, ceiling, self.io)?;
        // A read can race hardware faults or out-of-contract filesystem writes even while
        // the legitimate writer lock is held. Do not return bytes after observed drift.
        self.verify_snapshot(publication_root, subject_digest)?;
        Ok(payload)
    }
}

impl ReferenceHydrationCatalog {
    /// Binds H3 to a durable local publication without retaining a second copy of source bytes.
    ///
    /// `publisher` must be the live, lock-owning authority for this root. `io` must be the same
    /// scoped capability supplied to that publisher. Root records, nested publication identity,
    /// all reachable bytes, and deletion state are rechecked before and after the bounded read.
    /// Registration remains authority-owned; it is not an untrusted request operation.
    pub fn bind_local_source_object(
        &mut self,
        handle_id: &str,
        descriptor_digest: ContentDigest,
        publication_root: ContentDigest,
        publisher: &LocalRootPublisher,
        io: &dyn SpoolIo,
    ) -> Result<SourceObjectBinding, SourceHydrationError> {
        self.bind_source_object(
            handle_id,
            descriptor_digest,
            publication_root,
            &LocalSourceReader { publisher, io },
        )
    }

    /// Reads authorized H3 bytes from an existing local publication, including after reopen.
    ///
    /// Uses ordinary request admission, resource quotes, receipts, and single-use continuation.
    /// Denied or expired requests do not inspect storage. Neither this operation nor the reader
    /// creates files, takes locks, writes verification holds, or repairs the store. The borrowed
    /// publisher already owns the lock; opening/recovering it is the caller's separate action.
    ///
    /// The reference reader performs bounded whole-store inspections around each read. It is
    /// intentionally conservative: drift in another owned publication can also block disclosure.
    /// This is not a streaming reader, canonical-ledger reachability proof, or durable cursor
    /// store. Catalog/session persistence, actual I/O pricing, and production qualification are
    /// separate contracts. Source bytes already returned to a caller cannot be recalled.
    pub fn hydrate_from_local_source(
        &mut self,
        request: &HydrationRequest,
        publisher: &LocalRootPublisher,
        io: &dyn SpoolIo,
        now: TimestampNs,
    ) -> Result<HydrationResponse, SourceHydrationError> {
        self.hydrate_from_source(request, &LocalSourceReader { publisher, io }, now)
    }
}
