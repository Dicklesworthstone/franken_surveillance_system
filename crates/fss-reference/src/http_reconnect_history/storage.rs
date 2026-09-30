#![forbid(unsafe_code)]
//! Existing immutable object-graph publication, never a second append journal or mutable head.

use super::record::{ArchivedReconnectBoundary, KIND, MAX_METADATA};
use super::{HistoryError, ReconnectHistoryLimits, ReconnectHistoryPin};
use crate::ingest::http_archive::HttpWireArchive;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_object::{MAX_MANIFEST_CHILDREN, ObjectManifest};
use fss_publication::{
    LocalPublicationReceipt, LocalPublicationState, LocalRootPublisher, PublishCancellation,
    PublishCutPoint, SlotName,
};

pub(super) fn probe(cancel: &dyn PublishCancellation) -> Result<(), HistoryError> {
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
        Err(HistoryError::Cancelled)
    } else {
        Ok(())
    }
}
fn slot(session: ContentDigest, connection: u32) -> Result<SlotName, HistoryError> {
    if !super::sha(session) || !(1..=32).contains(&connection) {
        return Err(HistoryError::Configuration);
    }
    SlotName::parse(&format!(
        "fsshrb1-{}-{connection}",
        session
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
    .map_err(|_| HistoryError::Configuration)
}
fn publisher_bound(
    publisher: &LocalRootPublisher,
    limits: ReconnectHistoryLimits,
) -> Result<(), HistoryError> {
    limits.validate()?;
    if publisher.limits().spool.max_object_bytes > limits.archive.maximum_spool_object_bytes {
        return Err(HistoryError::Limit);
    }
    if publisher.is_poisoned() {
        return Err(HistoryError::NotDurable);
    }
    Ok(())
}
pub(super) fn require_empty(
    publisher: &LocalRootPublisher,
    session: ContentDigest,
    limits: ReconnectHistoryLimits,
    cancel: &dyn PublishCancellation,
    work: &mut WorkBudget<'_>,
) -> Result<(), HistoryError> {
    publisher_bound(publisher, limits)?;
    for connection in 1..=32 {
        require_unused_slot(publisher, session, connection, limits, cancel, work)?;
    }
    Ok(())
}
pub(super) fn require_unused_slot(
    publisher: &LocalRootPublisher,
    session: ContentDigest,
    connection: u32,
    limits: ReconnectHistoryLimits,
    cancel: &dyn PublishCancellation,
    work: &mut WorkBudget<'_>,
) -> Result<(), HistoryError> {
    probe(cancel)?;
    publisher_bound(publisher, limits)?;
    work.charge(256 + limits.archive.maximum_scan_roots as u64)?;
    let slot = slot(session, connection)?;
    let temp = LocalRootPublisher::root_temp_path(&slot);
    if publisher.root(&slot).is_some() || publisher.is_broken_slot(&slot) {
        return Err(HistoryError::Occupied);
    }
    for (index, path) in publisher.orphaned_temps().enumerate() {
        if index >= limits.archive.maximum_scan_roots {
            return Err(HistoryError::Limit);
        }
        if path == temp {
            return Err(HistoryError::Occupied);
        }
    }
    Ok(())
}
fn manifest(
    record: &ArchivedReconnectBoundary,
    archive: &HttpWireArchive,
    work: &mut WorkBudget<'_>,
) -> Result<ObjectManifest, HistoryError> {
    if archive.pin() != record.prefix
        || archive.scope() != record.scope
        || record.prefix.reads > MAX_MANIFEST_CHILDREN.saturating_sub(2) as u64
    {
        return Err(HistoryError::Mismatch);
    }
    work.charge(4096 + record.prefix.reads * 512)?;
    ObjectManifest::new(
        KIND,
        record
            .prior
            .iter()
            .map(|p| p.root)
            .chain(archive.reads().map(|(pin, _)| pin.head)),
        Some(ContentDigest::sha256(&record.encode()?)),
    )
    .map_err(|_| HistoryError::Metadata)
}
fn checked_manifest(
    publisher: &LocalRootPublisher,
    record: &ArchivedReconnectBoundary,
    limits: ReconnectHistoryLimits,
    cancel: &dyn PublishCancellation,
    work: &mut WorkBudget<'_>,
) -> Result<ObjectManifest, HistoryError> {
    probe(cancel)?;
    publisher_bound(publisher, limits)?;
    record.validate()?;
    let (mut reads, mut bytes) = (record.prefix.reads, record.prefix.bytes);
    if let Some(prior) = record.prior {
        let verified = VerifiedReconnectHistory::load(publisher, prior, limits, cancel, work)?;
        record.follows(verified.boundaries.last().ok_or(HistoryError::Mismatch)?)?;
        reads = reads
            .checked_add(verified.reads)
            .ok_or(HistoryError::Limit)?;
        bytes = bytes
            .checked_add(verified.bytes)
            .ok_or(HistoryError::Limit)?;
    }
    if reads > limits.maximum_reads || bytes > limits.maximum_bytes {
        return Err(HistoryError::Limit);
    }
    let archive = HttpWireArchive::load(
        publisher,
        record.scope,
        record.prefix,
        limits.archive,
        cancel,
        work,
    )?;
    manifest(record, &archive, work)
}
pub(super) fn prepare(
    publisher: &LocalRootPublisher,
    record: &ArchivedReconnectBoundary,
    limits: ReconnectHistoryLimits,
    cancel: &dyn PublishCancellation,
    work: &mut WorkBudget<'_>,
) -> Result<ReconnectHistoryPin, HistoryError> {
    let manifest = checked_manifest(publisher, record, limits, cancel, work)?;
    Ok(ReconnectHistoryPin {
        session: record.session,
        root: manifest.root(),
        connections: record.connection,
    })
}
pub(super) fn publish(
    publisher: &mut LocalRootPublisher,
    record: &ArchivedReconnectBoundary,
    expected: ReconnectHistoryPin,
    limits: ReconnectHistoryLimits,
    cancel: &dyn PublishCancellation,
    work: &mut WorkBudget<'_>,
) -> Result<LocalPublicationReceipt, HistoryError> {
    expected.validate()?;
    let manifest = checked_manifest(publisher, record, limits, cancel, work)?;
    if expected
        != (ReconnectHistoryPin {
            session: record.session,
            root: manifest.root(),
            connections: record.connection,
        })
    {
        return Err(HistoryError::Mismatch);
    }
    let metadata = record.encode()?;
    let digest = ContentDigest::sha256(&metadata);
    work.charge(4096 + metadata.len() as u64 * 8 + publisher.limits().max_tombstones as u64)?;
    if publisher
        .tombstones()
        .any(|d| *d == expected.root || *d == digest)
    {
        return Err(HistoryError::Tombstoned);
    }
    probe(cancel)?;
    if publisher
        .stage_object(&metadata)
        .map_err(|_| HistoryError::Storage)?
        != digest
    {
        return Err(HistoryError::Storage);
    }
    probe(cancel)?;
    work.charge(0)?;
    let receipt = publisher
        .publish_cancellable(
            &slot(expected.session, expected.connections)?,
            &manifest,
            cancel,
        )
        .map_err(|_| HistoryError::Storage)?;
    if receipt.root != expected.root || receipt.claims.local != LocalPublicationState::Durable {
        return Err(HistoryError::NotDurable);
    }
    // Never turn an actual durable publication into a late cancellation/error report.
    Ok(receipt)
}
fn read(
    publisher: &LocalRootPublisher,
    digest: ContentDigest,
    maximum: usize,
    cancel: &dyn PublishCancellation,
    work: &mut WorkBudget<'_>,
) -> Result<Vec<u8>, HistoryError> {
    probe(cancel)?;
    work.charge(
        publisher.limits().spool.max_object_bytes as u64 * 3
            + publisher.limits().max_tombstones as u64
            + 1,
    )?;
    if publisher.tombstones().any(|d| *d == digest) {
        return Err(HistoryError::Tombstoned);
    }
    let bytes = publisher
        .spool()
        .read(digest)
        .map_err(|_| HistoryError::Storage)?;
    if bytes.len() > maximum {
        return Err(HistoryError::Limit);
    }
    if ContentDigest::sha256(&bytes) != digest {
        return Err(HistoryError::Metadata);
    }
    probe(cancel)?;
    work.charge(0)?;
    Ok(bytes.to_vec())
}

/// Cold-verified selected prefix. No current-head inference, acquisition grant or automatic resume.
#[derive(Debug)]
pub struct VerifiedReconnectHistory {
    pin: ReconnectHistoryPin,
    boundaries: Vec<ArchivedReconnectBoundary>,
    reads: u64,
    bytes: u64,
}
impl VerifiedReconnectHistory {
    /// Reverify every selected boundary and every original prefix under independent limits.
    /// Missing parents, reordered sources, invalid backoff, corrupt bytes and tombstones refuse
    /// the WHOLE result. There is no partial-success vector or recursive unbounded traversal.
    pub fn load(
        publisher: &LocalRootPublisher,
        expected: ReconnectHistoryPin,
        limits: ReconnectHistoryLimits,
        cancel: &dyn PublishCancellation,
        work: &mut WorkBudget<'_>,
    ) -> Result<Self, HistoryError> {
        expected.validate()?;
        publisher_bound(publisher, limits)?;
        probe(cancel)?;
        work.charge(1024 + u64::from(expected.connections) * 2048)?;
        let mut boundaries: Vec<ArchivedReconnectBoundary> =
            Vec::with_capacity(expected.connections as usize);
        let (mut reads, mut bytes) = (0_u64, 0_u64);
        let mut next = Some(expected);
        for count in (1..=expected.connections).rev() {
            let pin = next.ok_or(HistoryError::Mismatch)?;
            pin.validate()?;
            if pin.connections != count || pin.session != expected.session {
                return Err(HistoryError::Mismatch);
            }
            let slot = slot(pin.session, count)?;
            probe(cancel)?;
            if publisher.is_broken_slot(&slot)
                || publisher.root(&slot).is_none_or(|root| {
                    root.root != pin.root || root.state != LocalPublicationState::Durable
                })
            {
                return Err(HistoryError::NotDurable);
            }
            let raw = read(
                publisher,
                pin.root,
                limits.archive.maximum_spool_object_bytes,
                cancel,
                work,
            )?;
            let actual =
                ObjectManifest::from_canonical_bytes(&raw).map_err(|_| HistoryError::Metadata)?;
            if actual.root() != pin.root || actual.kind() != KIND {
                return Err(HistoryError::Mismatch);
            }
            let metadata = read(
                publisher,
                actual.metadata_digest().ok_or(HistoryError::Metadata)?,
                MAX_METADATA,
                cancel,
                work,
            )?;
            let record = ArchivedReconnectBoundary::decode(&metadata)?;
            if record.session != pin.session || record.connection != count {
                return Err(HistoryError::Mismatch);
            }
            reads = reads
                .checked_add(record.prefix.reads)
                .ok_or(HistoryError::Limit)?;
            bytes = bytes
                .checked_add(record.prefix.bytes)
                .ok_or(HistoryError::Limit)?;
            if reads > limits.maximum_reads || bytes > limits.maximum_bytes {
                return Err(HistoryError::Limit);
            }
            let archive = HttpWireArchive::load(
                publisher,
                record.scope,
                record.prefix,
                limits.archive,
                cancel,
                work,
            )?;
            if manifest(&record, &archive, work)? != actual {
                return Err(HistoryError::Mismatch);
            }
            if let Some(later) = boundaries.last() {
                later.follows(&record)?;
            }
            next = record.prior;
            boundaries.push(record);
        }
        if next.is_some() {
            return Err(HistoryError::Mismatch);
        }
        boundaries.reverse();
        probe(cancel)?;
        work.charge(0)?;
        Ok(Self {
            pin: expected,
            boundaries,
            reads,
            bytes,
        })
    }
    /// The independently selected prefix, not a discovered latest head.
    pub fn pin(&self) -> ReconnectHistoryPin {
        self.pin
    }
    /// Native observations in exact connection order, including byte-empty failed attempts.
    pub fn boundaries(&self) -> &[ArchivedReconnectBoundary] {
        &self.boundaries
    }
    /// Total verified original reads, not frames or model results.
    pub fn reads(&self) -> u64 {
        self.reads
    }
    /// Total verified original response bytes across all selected generations.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}
