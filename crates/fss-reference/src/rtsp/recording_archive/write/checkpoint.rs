#![forbid(unsafe_code)]
//! Durable AVC archive work using the existing content-addressed publication owner.
//!
//! The bundle roots the exact old inventory and every pending byte. It is not an archive
//! completion, retention grant, mutable job queue, or new evidence ledger. No source is copied
//! into a journal. Explicitly pin the prepared root before publishing; a lost final ACK can
//! then be resolved by opening that exact root after the storage owner has been reconciled.

use fss_core::{CanonicalDecoder, CanonicalEncode, SensorId, StreamId};
use fss_object::{ObjectManifest, MAX_MANIFEST_CHILDREN};
use crate::rtsp::archive_recovery::archive_retirement_digest;
use crate::rtsp::recording::{RecordingScope, RECORDING_KIND};
use crate::rtsp::recording_catalog::MAX_CATALOG_BYTES;
use super::*;

/// Private work-bundle family. It cannot be substituted for a recording or catalog root.
pub const ARCHIVE_WORK_KIND: &str = "avc_archive_work_v1";
const DOMAIN: &str = "fss.avc_archive_work.v1";
const MAX_METADATA: usize = 4096;
const MAX_MANIFEST: usize = MAX_MANIFEST_CHILDREN * 33 + 1024;
/// New work payload ceiling, excluding already durable historical media (which is referenced).
pub const MAX_ARCHIVE_WORK_BYTES: usize = MAX_RECORDING_BYTES + MAX_CATALOG_BYTES + MAX_MANIFEST + MAX_METADATA;

/// Independent runtime ceilings. Serialized historical limits may never widen these bounds.
#[derive(Clone, Copy, Debug)]
pub struct ArchiveWorkLimits {
    /// Maximum accepted historical discovery and inventory limits, including page size.
    pub archive: ArchiveLimits,
    /// Complete pending recording allowance. Zero admits only work without a pending recording.
    pub max_pending_bytes: usize,
    /// Manifest/scratch identity bound including duplicates before canonical deduplication.
    pub max_graph_objects: usize,
    /// Pending recording, pending catalog, work metadata and work-root payload allowance.
    /// Existing historical media is not recopied, but verification still reads it.
    pub max_new_bytes: usize,
}
impl Default for ArchiveWorkLimits {
    fn default() -> Self {
        Self { archive: ArchiveLimits::default(), max_pending_bytes: MAX_RECORDING_BYTES,
            max_graph_objects: MAX_MANIFEST_CHILDREN, max_new_bytes: MAX_ARCHIVE_WORK_BYTES }
    }
}
impl ArchiveWorkLimits {
    fn validate(self, stored: ArchiveLimits) -> ArchiveResult<()> {
        self.archive.validate()?;
        stored.validate()?;
        if self.max_pending_bytes > MAX_RECORDING_BYTES
            || self.max_graph_objects == 0 || self.max_graph_objects > MAX_MANIFEST_CHILDREN
            || self.max_new_bytes > MAX_ARCHIVE_WORK_BYTES
            || stored.max_windows > self.archive.max_windows || stored.max_pages > self.archive.max_pages
            || stored.max_scan_roots > self.archive.max_scan_roots
            || stored.windows_per_page > self.archive.windows_per_page {
            return Err(ArchiveError::Limit);
        }
        Ok(())
    }
}

/// Immutable, read-prepared work graph. The original pending objects stay caller-owned.
/// Its three content-derived slots are outside the archive's window/catalog namespace.
#[must_use]
pub struct PreparedArchiveWork<'a> {
    work: &'a ArchiveRetirement,
    stamp: Stamp,
    metadata: Vec<u8>,
    manifest: ObjectManifest,
    slot: SlotName,
    window_slot: SlotName,
    page_slot: SlotName,
    bytes: usize,
    limits: ArchiveWorkLimits,
}
impl std::fmt::Debug for PreparedArchiveWork<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedArchiveWork").field("root", &self.root())
            .field("new_payload_bytes", &self.bytes).finish_non_exhaustive()
    }
}
impl<'a> PreparedArchiveWork<'a> {
    /// Read and bind the exact historical root closure. No object or root is written here.
    /// This is a trusted storage-owner API: the supplied publisher/cancellation capability
    /// must authorize retention and reads of all referenced source, not just its metadata.
    pub fn prepare(work: &'a ArchiveRetirement, publisher: &LocalRootPublisher,
        limits: ArchiveWorkLimits, cancel: &dyn PublishCancellation) -> ArchiveResult<Self> {
        limits.validate(work.snapshot.limits())?;
        owner_ready(publisher)?;
        validate_pending(work, limits)?;
        let stamp = Stamp::from_work(work)?;
        let metadata = stamp.encode()?;
        let slot = work_slot(stamp.retirement, 'r')?;
        let window_slot = work_slot(stamp.retirement, 'w')?;
        let page_slot = work_slot(stamp.retirement, 'c')?;
        let manifest = graph(work, &metadata, publisher, limits, cancel)?;
        let bytes = metadata.len().checked_add(manifest.canonical_bytes().len())
            .and_then(|n| n.checked_add(stamp.pending.map_or(0, |(_, bytes)| bytes)))
            .and_then(|n| n.checked_add(work.prepared_page.as_ref().map_or(0, RecordingCatalog::byte_len)))
            .ok_or(ArchiveError::Limit)?;
        if bytes > limits.max_new_bytes || manifest.children().len() > publisher.limits().max_children {
            return Err(ArchiveError::Limit);
        }
        check_slot(publisher, &slot, manifest.root())?;
        if let Some(window) = &work.pending { check_slot(publisher, &window_slot, window.manifest().root())?; }
        if let Some(page) = &work.prepared_page { check_slot(publisher, &page_slot, page.manifest().root())?; }
        probe(cancel)?;
        Ok(Self { work, stamp, metadata, manifest, slot, window_slot, page_slot, bytes, limits })
    }
    /// Pin independently before attempting I/O; this is not proof that publication succeeded.
    pub fn root(&self) -> ContentDigest { self.manifest.root() }
    /// Deterministic bundle route. The independently trusted root is still required on read.
    pub fn slot(&self) -> &SlotName { &self.slot }
    /// Existing archive-recovery commitment, without another retry/operation identity.
    pub fn retirement_digest(&self) -> ContentDigest { self.stamp.retirement }
    /// Complete new payload quote; content addressing deduplicates identical stored objects.
    pub fn new_payload_bytes(&self) -> usize { self.bytes }

    /// Publish pending source first, then auxiliary recording/catalog roots, and the complete
    /// work root LAST. This neither allocates an archive ordinal nor publishes its normal page.
    /// All calls are synchronous and bounded; the cancellation owner enforces live deadlines
    /// at storage cut points. A failed call leaves the borrowed input intact and may have
    /// committed auxiliary roots. Reopen/reconcile a poisoned publisher before another attempt.
    pub fn publish(&self, publisher: &mut LocalRootPublisher, now: u64, deadline: u64,
        cancel: &dyn PublishCancellation) -> ArchiveResult<LocalPublicationReceipt> {
        if now >= deadline { return Err(ArchiveError::Deadline); }
        owner_ready(publisher)?;
        probe(cancel)?;
        if self.manifest.children().len() > publisher.limits().max_children
            || graph(self.work, &self.metadata, publisher, self.limits, cancel)? != self.manifest {
            return Err(ArchiveError::Metadata);
        }
        check_slot(publisher, &self.slot, self.root())?;
        if publisher.root(&self.slot).is_some() {
            return durable(publisher.publish_cancellable(&self.slot, &self.manifest, cancel)
                .map_err(RecordingIoError::Publication)?);
        }
        if let Some(window) = &self.work.pending {
            let mut job = RecordingPublication::new(window, publisher, self.window_slot.clone(),
                window.byte_len(), deadline)?;
            let mut published = false;
            for _ in 0..5 {
                if let RecordingProgress::Published(receipt) = job.step(now, cancel)? {
                    durable(receipt)?; published = true; break;
                }
            }
            if !published { return Err(ArchiveError::Metadata); }
        }
        if let Some(page) = &self.work.prepared_page {
            probe(cancel)?;
            check_slot(publisher, &self.page_slot, page.manifest().root())?;
            let digest = publisher.stage_object(page.index_bytes()).map_err(RecordingIoError::Publication)?;
            if Some(digest) != page.manifest().metadata_digest() { return Err(ArchiveError::Metadata); }
            durable(publisher.publish_cancellable(&self.page_slot, page.manifest(), cancel)
                .map_err(RecordingIoError::Publication)?)?;
        }
        probe(cancel)?;
        let metadata = publisher.stage_object(&self.metadata).map_err(RecordingIoError::Publication)?;
        if Some(metadata) != self.manifest.metadata_digest() { return Err(ArchiveError::Metadata); }
        durable(publisher.publish_cancellable(&self.slot, &self.manifest, cancel)
            .map_err(RecordingIoError::Publication)?)
    }
}

/// Recover ordinary ArchiveRetirement after losing every in-memory pending object. Requires
/// an independently trusted bundle root, current matching custody, and external ceilings.
/// No archive publication, source substitution, head rollback, or camera operation occurs.
/// Feed the result to RecordingArchiveResume with its normal independently scoped authority.
pub fn load_archive_work(publisher: &LocalRootPublisher, slot: &SlotName,
    expected_root: ContentDigest, limits: ArchiveWorkLimits, cancel: &dyn PublishCancellation)
    -> ArchiveResult<ArchiveRetirement> {
    limits.validate(limits.archive)?;
    owner_ready(publisher)?;
    require_slot(publisher, slot, expected_root)?;
    let manifest = read_manifest(publisher, expected_root, MAX_MANIFEST, cancel)?;
    if manifest.kind() != ARCHIVE_WORK_KIND || manifest.children().len() > limits.max_graph_objects {
        return Err(ArchiveError::Metadata);
    }
    let meta = manifest.metadata_digest().ok_or(ArchiveError::Metadata)?;
    let bytes = read(publisher, meta, MAX_METADATA, cancel)?;
    let stamp = Stamp::decode(&bytes)?;
    limits.validate(stamp.limits)?;
    if slot != &work_slot(stamp.retirement, 'r')?
        || stamp.pending.is_some_and(|(_, bytes)| bytes > limits.max_pending_bytes) {
        return Err(ArchiveError::Limit);
    }
    let namespace = ArchiveNamespace::new(stamp.scope.clone())?;
    let mut snapshot = ArchiveSnapshot::load(publisher, namespace, stamp.limits, cancel)?;
    // An exact old prefix is not permission to silently follow additional unaccounted work.
    if snapshot.windows.len() < stamp.windows
        || snapshot.windows.len() > stamp.windows + usize::from(stamp.pending.is_some())
        || snapshot.pages.len() < stamp.pages
        || snapshot.pages.len() > stamp.pages + usize::from(stamp.page.is_some()) {
        return Err(ArchiveError::Sequence);
    }
    if snapshot.windows.len() > stamp.windows {
        if Some(snapshot.windows[stamp.windows].root()) != stamp.pending.map(|(root, _)| root)
            || stamp.page.is_some() && snapshot.pages.len() == stamp.pages {
            return Err(ArchiveError::Metadata);
        }
    }
    if snapshot.pages.len() > stamp.pages {
        let page = &snapshot.pages[stamp.pages];
        if Some(page.catalog.manifest().root()) != stamp.page || page.first != stamp.indexed {
            return Err(ArchiveError::Metadata);
        }
    }
    // Only this child of the archive owner can reconstruct an opaque historical inventory.
    // Current source replay happened above; exact old digest validation happens before return.
    snapshot.windows.truncate(stamp.windows);
    snapshot.pages.truncate(stamp.pages);
    let indexed: usize = snapshot.pages.iter().map(|p| p.catalog.entries().len()).sum();
    if indexed != stamp.indexed || indexed > snapshot.windows.len() { return Err(ArchiveError::Metadata); }
    snapshot.indexed = indexed;
    if snapshot.digest()? != stamp.snapshot { return Err(ArchiveError::Metadata); }
    let pending = match stamp.pending {
        None => None,
        Some((root, bytes)) => {
            let window = load_recording(publisher, &work_slot(stamp.retirement, 'w')?, root,
                &stamp.scope.recording, cancel)?;
            if window.byte_len() != bytes { return Err(ArchiveError::Metadata); }
            Some(window)
        }
    };
    let prepared_page = match stamp.page {
        None => None,
        Some(root) => Some(load_catalog(publisher, &work_slot(stamp.retirement, 'c')?, root, &stamp.scope, cancel)?),
    };
    let work = ArchiveRetirement { snapshot, pending, prepared_page };
    // Reconstruct every canonical byte and the complete flat graph, not just checksums on a
    // plausible metadata body. No unregistered child, missing derivative, or re-tagged root.
    {
        let prepared = PreparedArchiveWork::prepare(&work, publisher, limits, cancel)?;
        if prepared.root() != expected_root || prepared.metadata != bytes
            || prepared.retirement_digest() != stamp.retirement {
            return Err(ArchiveError::Metadata);
        }
        for child in manifest.children() {
            probe(cancel)?;
            // Rehash even retained historical metadata; deletion/corruption cannot be hidden
            // by a once-valid root inventory. Only one bounded temporary object at a time.
            let _ = read(publisher, *child, MAX_RECORDING_BYTES, cancel)?;
        }
    }
    probe(cancel)?;
    Ok(work)
}

fn validate_pending(work: &ArchiveRetirement, limits: ArchiveWorkLimits) -> ArchiveResult<()> {
    let old = &work.snapshot;
    if let Some(window) = &work.pending {
        if window.byte_len() > limits.max_pending_bytes || old.windows.len() >= old.limits.max_windows {
            return Err(ArchiveError::Limit);
        }
        let slot = old.namespace.window_slot(old.windows.len())?;
        let entry = descriptor_for::<AvcArchiveCodec>(old.namespace.scope(), &slot, window)?;
        if old.windows.last().is_some_and(|p| p.decode_interval().end > entry.decode_interval().start)
            || old.windows.iter().any(|p| p.root() == entry.root()) { return Err(ArchiveError::Sequence); }
    }
    if let Some(page) = &work.prepared_page {
        if page.scope() != old.namespace.scope() || page.entries() != old.unindexed_windows()
            || page.entries().is_empty() || old.pages.len() >= old.limits.max_pages {
            return Err(ArchiveError::Metadata);
        }
    }
    Ok(())
}

fn graph(work: &ArchiveRetirement, metadata: &[u8], p: &LocalRootPublisher,
    limits: ArchiveWorkLimits, cancel: &dyn PublishCancellation) -> ArchiveResult<ObjectManifest> {
    // Conservative pre-deduplication scratch reservation. No optimistic sharing assumption.
    let bound = work.snapshot.windows.len().checked_mul(5)
        .and_then(|n| n.checked_add(work.snapshot.pages.len() * 2))
        .and_then(|n| n.checked_add(if work.pending.is_some() { 5 } else { 0 }))
        .and_then(|n| n.checked_add(work.prepared_page.as_ref().map_or(0, |page| page.manifest().children().len() + 1)))
        .and_then(|n| n.checked_add(1)).ok_or(ArchiveError::Limit)?;
    if bound > limits.max_graph_objects { return Err(ArchiveError::Limit); }
    let mut children = Vec::new();
    children.try_reserve_exact(bound).map_err(|_| ArchiveError::Limit)?;
    for entry in work.snapshot.windows() {
        require_slot(p, entry.slot(), entry.root())?;
        let manifest = read_manifest(p, entry.root(), 1024, cancel)?;
        if manifest.kind() != RECORDING_KIND || manifest.children().len() != 4 { return Err(ArchiveError::Metadata); }
        children.push(entry.root()); children.extend_from_slice(manifest.children());
    }
    for page in work.snapshot.pages() {
        require_slot(p, page.slot(), page.catalog().manifest().root())?;
        let manifest = read_manifest(p, page.catalog().manifest().root(), MAX_CATALOG_BYTES, cancel)?;
        if &manifest != page.catalog().manifest() { return Err(ArchiveError::Metadata); }
        children.push(manifest.root()); children.push(manifest.metadata_digest().ok_or(ArchiveError::Metadata)?);
    }
    if let Some(window) = &work.pending {
        children.push(window.manifest().root()); children.extend_from_slice(window.manifest().children());
    }
    if let Some(page) = &work.prepared_page {
        children.push(page.manifest().root()); children.extend_from_slice(page.manifest().children());
    }
    children.sort_unstable(); children.dedup();
    ObjectManifest::new(ARCHIVE_WORK_KIND, children, Some(ContentDigest::sha256(metadata)))
        .map_err(|_| ArchiveError::Metadata)
}
fn work_slot(digest: ContentDigest, role: char) -> ArchiveResult<SlotName> {
    let text = digest.to_text();
    let hex = text.strip_prefix("sha256:").ok_or(ArchiveError::Metadata)?;
    SlotName::parse(&format!("fssaw1-{hex}-{role}")).map_err(|_| ArchiveError::Metadata)
}
fn check_slot(p: &LocalRootPublisher, slot: &SlotName, root: ContentDigest) -> ArchiveResult<()> {
    if p.root(slot).is_some_and(|r| r.root != root) { return Err(RecordingIoError::RootConflict.into()); }
    Ok(())
}
fn require_slot(p: &LocalRootPublisher, slot: &SlotName, root: ContentDigest) -> ArchiveResult<()> {
    check_slot(p, slot, root)?;
    if p.root(slot).is_none_or(|r| r.state != LocalPublicationState::Durable) {
        return Err(RecordingIoError::NotDurable.into());
    }
    Ok(())
}
fn durable(receipt: LocalPublicationReceipt) -> ArchiveResult<LocalPublicationReceipt> {
    if receipt.claims.local != LocalPublicationState::Durable { return Err(RecordingIoError::NotDurable.into()); }
    Ok(receipt)
}
fn read(p: &LocalRootPublisher, digest: ContentDigest, maximum: usize,
    cancel: &dyn PublishCancellation) -> ArchiveResult<Vec<u8>> {
    probe(cancel)?;
    // Allocation is bounded BEFORE I/O by the actual spool owner, not merely by a post-read
    // length assertion. Metadata-specific bounds below are stricter semantic limits.
    if p.limits().spool.max_object_bytes > MAX_RECORDING_BYTES { return Err(ArchiveError::Limit); }
    if p.tombstones().any(|d| *d == digest) { return Err(RecordingIoError::Tombstoned.into()); }
    let bytes = p.spool().read(digest).map_err(RecordingIoError::Spool)?;
    if bytes.len() > maximum { return Err(ArchiveError::Limit); }
    probe(cancel)?;
    Ok(bytes)
}
fn read_manifest(p: &LocalRootPublisher, root: ContentDigest, maximum: usize,
    cancel: &dyn PublishCancellation) -> ArchiveResult<ObjectManifest> {
    let bytes = read(p, root, maximum, cancel)?;
    let manifest = ObjectManifest::from_canonical_bytes(&bytes).map_err(|_| ArchiveError::Metadata)?;
    if manifest.root() != root { return Err(ArchiveError::Metadata); }
    Ok(manifest)
}

#[derive(Clone)]
struct Stamp {
    scope: CatalogScope, limits: ArchiveLimits,
    windows: usize, pages: usize, indexed: usize,
    snapshot: ContentDigest, retirement: ContentDigest,
    pending: Option<(ContentDigest, usize)>, page: Option<ContentDigest>,
}
impl Stamp {
    fn from_work(work: &ArchiveRetirement) -> ArchiveResult<Self> {
        Ok(Self { scope: work.snapshot.namespace().scope().clone(), limits: work.snapshot.limits(),
            windows: work.snapshot.windows().len(), pages: work.snapshot.pages().len(),
            indexed: work.snapshot.indexed_windows(), snapshot: work.snapshot.digest()?,
            retirement: archive_retirement_digest(work)?,
            pending: work.pending.as_ref().map(|w| (w.manifest().root(), w.byte_len())),
            page: work.prepared_page.as_ref().map(|p| p.manifest().root()) })
    }
    fn encode(&self) -> ArchiveResult<Vec<u8>> {
        let mut e = CanonicalEncoder::new(); e.text(DOMAIN);
        let s = &self.scope.recording;
        e.text(s.sensor.as_str()); e.text(s.stream.as_str()); e.u64(s.generation);
        e.digest(s.anchor); e.digest(s.receive_clock); e.digest(self.scope.decode_clock); e.u32(self.scope.time_scale);
        for value in [self.limits.max_windows, self.limits.max_pages, self.limits.max_scan_roots,
            self.limits.windows_per_page, self.windows, self.pages, self.indexed] { e.u64(value as u64); }
        e.digest(self.snapshot); e.digest(self.retirement);
        e.bool(self.pending.is_some());
        if let Some((root, bytes)) = self.pending { e.digest(root); e.u64(bytes as u64); }
        e.bool(self.page.is_some()); if let Some(root) = self.page { e.digest(root); }
        let bytes = e.finish_checked().map_err(|_| ArchiveError::Metadata)?;
        if bytes.len() > MAX_METADATA { return Err(ArchiveError::Limit); }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> ArchiveResult<Self> {
        let decode = || -> Result<Self, fss_core::ContractError> {
            let mut d = CanonicalDecoder::new(bytes);
            if d.text()? != DOMAIN { return Err(fss_core::ContractError::InvalidIdentifier); }
            let scope = CatalogScope { recording: RecordingScope {
                sensor: SensorId::parse(d.text()?)?, stream: StreamId::parse(d.text()?)?, generation: d.u64()?,
                anchor: d.digest()?, receive_clock: d.digest()?,
            }, decode_clock: d.digest()?, time_scale: d.u32()? };
            let mut count = || -> Result<usize, fss_core::ContractError> {
                usize::try_from(d.u64()?).map_err(|_| fss_core::ContractError::ArithmeticOverflow)
            };
            let limits = ArchiveLimits { max_windows: count()?, max_pages: count()?,
                max_scan_roots: count()?, windows_per_page: count()? };
            let (windows, pages, indexed) = (count()?, count()?, count()?);
            let (snapshot, retirement) = (d.digest()?, d.digest()?);
            let pending = if d.bool()? { Some((d.digest()?, usize::try_from(d.u64()?)
                .map_err(|_| fss_core::ContractError::ArithmeticOverflow)?)) } else { None };
            let page = if d.bool()? { Some(d.digest()?) } else { None };
            d.ensure_finished()?;
            Ok(Self { scope, limits, windows, pages, indexed, snapshot, retirement, pending, page })
        };
        let value = decode().map_err(|_| ArchiveError::Metadata)?;
        value.limits.validate()?;
        if value.windows > value.limits.max_windows || value.pages > value.limits.max_pages
            || value.indexed > value.windows || value.pending.is_some_and(|(_, n)| n == 0 || n > MAX_RECORDING_BYTES)
            || value.encode()? != bytes { return Err(ArchiveError::Metadata); }
        Ok(value)
    }
}

