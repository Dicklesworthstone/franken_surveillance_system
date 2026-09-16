#![forbid(unsafe_code)]
//! Bounded, restartable local recording discovery over an explicitly supplied owner.
//! Namespace slots are routing, not a grant or an authoritative camera-coverage ledger.

mod read;
pub use read::*;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_publication::{LocalPublicationState, LocalRootPublisher, PublishCancellation,
    PublishCutPoint, SlotName};
use super::recording::{PreparedRecording, MAX_RECORDING_BYTES};
use super::recording::local::{RecordingIoError, load_recording};
use super::recording_catalog::{CatalogEntry, CatalogError, CatalogScope, CatalogWindow,
    RecordingCatalog, MAX_CATALOG_WINDOWS, prepare_catalog};
use super::recording_catalog::local::{CatalogIoError, load_catalog};

/// Maximum recording descriptors in one bounded local archive session.
pub const MAX_ARCHIVE_WINDOWS: usize = 4096;
/// Maximum root metadata entries examined in the supplied owner, including other namespaces.
pub const MAX_ARCHIVE_SCAN_ROOTS: usize = 65_536;

/// Explicit metadata, discovery-work, and page bounds. No implicit eviction or deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveLimits {
    /// Recording descriptors retained in this session.
    pub max_windows: usize,
    /// Immutable catalog pages retained in this session.
    pub max_pages: usize,
    /// Entries examined in each owner metadata inventory, including unrelated roots.
    pub max_scan_roots: usize,
    /// Automatic publication threshold; a manual flush can publish a smaller page.
    pub windows_per_page: usize,
}
impl Default for ArchiveLimits {
    fn default() -> Self {
        Self { max_windows: 4096, max_pages: 1024, max_scan_roots: 16_384, windows_per_page: 64 }
    }
}
impl ArchiveLimits {
    /// Validate before scanning or admitting media.
    pub fn validate(self) -> ArchiveResult<()> {
        if !(1..=MAX_ARCHIVE_WINDOWS).contains(&self.max_windows)
            || !(1..=MAX_ARCHIVE_WINDOWS).contains(&self.max_pages)
            || !(1..=MAX_ARCHIVE_SCAN_ROOTS).contains(&self.max_scan_roots)
            || !(1..=MAX_CATALOG_WINDOWS).contains(&self.windows_per_page) {
            return Err(ArchiveError::Limit);
        }
        Ok(())
    }
}

/// Refusals retain the lower owner's typed storage/indeterminacy error.
#[derive(Debug)]
pub enum ArchiveError {
    /// Pure catalog validation failure.
    Catalog(CatalogError),
    /// Catalog owner failure, including its typed storage refusal.
    CatalogIo(CatalogIoError),
    /// Recording owner failure; ambiguous effects are not flattened into ordinary failure.
    Storage(RecordingIoError),
    /// Count, allocation, work, object, or output budget exceeded.
    Limit,
    /// Noncanonical namespace slot, missing ordinal, overlapping page, or inconsistent ordering.
    Sequence,
    /// The explicitly supplied clock/stream scope differs.
    Scope,
    /// A descriptor or content identity disagrees with fully verified original bytes.
    Metadata,
    /// A broken root or unresolved temporary in this namespace requires explicit owner repair.
    RecoveryRequired,
    /// Finish the retained write or requested catalog flush before offering another recording.
    Backpressure,
    /// Admission has ended for this session.
    Closed,
    /// A failed/cancelled attempt must be explicitly retried or retired.
    Blocked,
    /// The supplied admission deadline expired.
    Deadline,
    /// Supplied monotonic time moved backwards; no new work was performed.
    ClockReversed,
    /// Caller cancellation/revocation stopped further work.
    Cancelled,
    /// This exact recording root is already present; no second ordinal is admitted.
    Duplicate,
}
impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "local recording archive refusal: {self:?}")
    }
}
impl std::error::Error for ArchiveError {}
impl From<CatalogError> for ArchiveError { fn from(e: CatalogError) -> Self { Self::Catalog(e) } }
impl From<CatalogIoError> for ArchiveError { fn from(e: CatalogIoError) -> Self { Self::CatalogIo(e) } }
impl From<RecordingIoError> for ArchiveError { fn from(e: RecordingIoError) -> Self { Self::Storage(e) } }
/// Archive result preserving typed underlying refusals.
pub type ArchiveResult<T> = Result<T, ArchiveError>;

/// Full-hash scope-derived routing namespace inside an already authorized owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveNamespace {
    scope: CatalogScope,
    digest: ContentDigest,
    prefix: String,
}
impl ArchiveNamespace {
    /// Bind every recording scope field and the explicit decode clock/tick rate.
    pub fn new(scope: CatalogScope) -> ArchiveResult<Self> {
        if scope.recording.generation == 0 || scope.time_scale == 0 { return Err(ArchiveError::Scope); }
        let mut e = CanonicalEncoder::new();
        e.text("fss.local_recording_archive_namespace.v1");
        e.text(scope.recording.sensor.as_str()); e.text(scope.recording.stream.as_str());
        e.u64(scope.recording.generation); e.digest(scope.recording.anchor);
        e.digest(scope.recording.receive_clock); e.digest(scope.decode_clock); e.u32(scope.time_scale);
        let bytes = e.finish_checked().map_err(|_| ArchiveError::Limit)?;
        let digest = ContentDigest::try_sha256(&bytes).map_err(|_| ArchiveError::Limit)?;
        let text = digest.to_text();
        let hex = text.strip_prefix("sha256:").ok_or(ArchiveError::Metadata)?;
        Ok(Self { scope, digest, prefix: format!("fssa1-{hex}") })
    }
    /// Exact declared stream/decode basis; not inferred capture time.
    pub fn scope(&self) -> &CatalogScope { &self.scope }
    /// Semantic identity of this namespace, not a published archive root.
    pub fn digest(&self) -> ContentDigest { self.digest }
    /// Bounded deterministic slot for a zero-based recording ordinal.
    pub fn window_slot(&self, ordinal: usize) -> ArchiveResult<SlotName> { self.slot('w', ordinal) }
    /// Bounded deterministic slot for a page's first recording ordinal.
    pub fn page_slot(&self, first: usize) -> ArchiveResult<SlotName> { self.slot('c', first) }
    fn slot(&self, role: char, ordinal: usize) -> ArchiveResult<SlotName> {
        if ordinal >= MAX_ARCHIVE_WINDOWS { return Err(ArchiveError::Limit); }
        SlotName::parse(&format!("{}-{role}-{ordinal:016x}", self.prefix)).map_err(|_| ArchiveError::Sequence)
    }
    fn parse_slot(&self, slot: &SlotName) -> ArchiveResult<Option<(char, usize)>> {
        let Some(rest) = slot.as_str().strip_prefix(&self.prefix) else { return Ok(None); };
        let (role, value) = rest.strip_prefix('-').and_then(|s| s.split_once('-')).ok_or(ArchiveError::Sequence)?;
        if !matches!(role, "w" | "c") || value.len() != 16
            || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(ArchiveError::Sequence);
        }
        let ordinal = usize::from_str_radix(value, 16).map_err(|_| ArchiveError::Sequence)?;
        if ordinal >= MAX_ARCHIVE_WINDOWS { return Err(ArchiveError::Limit); }
        Ok(Some((if role == "w" { 'w' } else { 'c' }, ordinal)))
    }
}

/// A discovered immutable catalog page, not a mutable latest/head pointer.
#[derive(Debug)]
pub struct ArchivePage {
    slot: SlotName,
    first: usize,
    catalog: RecordingCatalog,
}
impl ArchivePage {
    /// Exact local root slot.
    pub fn slot(&self) -> &SlotName { &self.slot }
    /// First zero-based recording ordinal named by this page.
    pub fn first_ordinal(&self) -> usize { self.first }
    /// Immutable catalog; its root pins every source and derived object.
    pub fn catalog(&self) -> &RecordingCatalog { &self.catalog }
}

/// Bounded point-in-time inventory, recovered by rehashing original recordings.
/// This is not an authoritative history, a retention lease, or a coverage/absence proof.
#[derive(Debug)]
pub struct ArchiveSnapshot {
    namespace: ArchiveNamespace,
    limits: ArchiveLimits,
    windows: Vec<CatalogEntry>,
    pages: Vec<ArchivePage>,
    indexed: usize,
}
impl ArchiveSnapshot {
    /// Discover this exact scope from the supplied publisher's existing metadata only.
    /// No filesystem listing/path read occurs here. Every admitted original window is
    /// loaded and source-verified, one at a time; total recovery work is bounded by
    /// max_windows, with cancellation between reads. Partial recovery is never returned.
    /// Broken roots and unresolved root temporaries are refused, never skipped as absence.
    pub fn load(p: &LocalRootPublisher, namespace: ArchiveNamespace, limits: ArchiveLimits,
        cancel: &dyn PublishCancellation) -> ArchiveResult<Self>
    {
        limits.validate()?; owner_ready(p)?;
        for (n, slot) in p.broken_slots().enumerate() {
            scan_admit(n, limits, cancel)?;
            if slot.as_str().starts_with(&namespace.prefix) { return Err(ArchiveError::RecoveryRequired); }
        }
        let report = p.recovery_report();
        for (n, broken) in report.broken_roots.iter().enumerate() {
            scan_admit(n, limits, cancel)?;
            if broken.path.file_name().is_some_and(|s| s.as_encoded_bytes().starts_with(namespace.prefix.as_bytes())) {
                return Err(ArchiveError::RecoveryRequired);
            }
        }
        for paths in [&report.orphaned_temps, &report.foreign] {
            for (n, path) in paths.iter().enumerate() {
                scan_admit(n, limits, cancel)?;
                if path.file_name().is_some_and(|s| s.as_encoded_bytes().starts_with(namespace.prefix.as_bytes())) {
                    return Err(ArchiveError::RecoveryRequired);
                }
            }
        }
        let mut roots = Vec::new(); let mut page_roots = Vec::new();
        for (n, root) in p.visible_roots().enumerate() {
            scan_admit(n, limits, cancel)?;
            let Some((role, ordinal)) = namespace.parse_slot(&root.slot)? else { continue; };
            if root.state != LocalPublicationState::Durable { return Err(RecordingIoError::NotDurable.into()); }
            let (target, maximum) = if role == 'w' { (&mut roots, limits.max_windows) }
                else { (&mut page_roots, limits.max_pages) };
            if target.len() == maximum { return Err(ArchiveError::Limit); }
            target.try_reserve_exact(1).map_err(|_| ArchiveError::Limit)?;
            target.push((ordinal, root.slot.clone(), root.root));
        }
        roots.sort_by_key(|r| r.0); page_roots.sort_by_key(|r| r.0);
        if roots.iter().enumerate().any(|(n, r)| n != r.0) { return Err(ArchiveError::Sequence); }
        let mut pages = bounded_vec(page_roots.len())?;
        let mut indexed = 0_usize;
        for (first, slot, root) in page_roots {
            probe(cancel)?;
            if first != indexed { return Err(ArchiveError::Sequence); }
            let catalog = load_catalog(p, &slot, root, &namespace.scope, cancel)?;
            let end = first.checked_add(catalog.entries().len()).ok_or(ArchiveError::Limit)?;
            if end > roots.len() { return Err(ArchiveError::Sequence); }
            for (entry, reference) in catalog.entries().iter().zip(&roots[first..end]) {
                if entry.slot() != &reference.1 || entry.root() != reference.2 { return Err(ArchiveError::Metadata); }
            }
            indexed = end; pages.push(ArchivePage { slot, first, catalog });
        }
        // The writer seals before admitting another page. A larger tail is not its
        // recoverable state; do not silently import an arbitrary foreign layout.
        if roots.len() - indexed > MAX_CATALOG_WINDOWS { return Err(ArchiveError::Sequence); }
        let mut windows: Vec<CatalogEntry> = bounded_vec(roots.len())?;
        let mut page_at = 0;
        for (ordinal, slot, root) in roots {
            let recording = load_recording(p, &slot, root, &namespace.scope.recording, cancel)?;
            let entry = descriptor(&namespace.scope, &slot, &recording)?;
            if windows.last().is_some_and(|last| last.decode_interval().end > entry.decode_interval().start)
                || windows.iter().any(|old| old.root() == entry.root()) { return Err(ArchiveError::Sequence); }
            if ordinal < indexed {
                while ordinal >= pages[page_at].first + pages[page_at].catalog.entries().len() { page_at += 1; }
                if entry != pages[page_at].catalog.entries()[ordinal - pages[page_at].first] { return Err(ArchiveError::Metadata); }
            }
            windows.push(entry);
        }
        probe(cancel)?;
        Ok(Self { namespace, limits, windows, pages, indexed })
    }
    /// Bounds applied to this recovered inventory.
    pub fn limits(&self) -> ArchiveLimits { self.limits }
    /// Exact scope-derived namespace.
    pub fn namespace(&self) -> &ArchiveNamespace { &self.namespace }
    /// Fully source-verified descriptors at recovery time; not future retrieval guarantees.
    pub fn windows(&self) -> &[CatalogEntry] { &self.windows }
    /// Only durably published pages, in recording order.
    pub fn pages(&self) -> &[ArchivePage] { &self.pages }
    /// Durable windows that also have published discovery metadata.
    pub fn indexed_windows(&self) -> usize { self.indexed }
    /// Durable original windows awaiting catalog publication after a flush/crash.
    pub fn unindexed_windows(&self) -> &[CatalogEntry] { &self.windows[self.indexed..] }
    /// Deterministic inventory identity. This digest is NOT a published ledger/head root.
    pub fn digest(&self) -> ArchiveResult<ContentDigest> {
        let mut e = CanonicalEncoder::new(); e.text("fss.local_recording_archive_snapshot.v1");
        e.digest(self.namespace.digest); e.u64(self.windows.len() as u64); e.u64(self.indexed as u64);
        for entry in &self.windows { e.digest(entry.root()); }
        e.u64(self.pages.len() as u64);
        for page in &self.pages { e.u64(page.first as u64); e.digest(page.catalog.manifest().root()); }
        ContentDigest::try_sha256(&e.finish_checked().map_err(|_| ArchiveError::Limit)?)
            .map_err(|_| ArchiveError::Limit)
    }
}

fn descriptor(scope: &CatalogScope, slot: &SlotName, recording: &PreparedRecording) -> ArchiveResult<CatalogEntry> {
    let c = prepare_catalog(scope.clone(), &[CatalogWindow { slot, recording }])?;
    c.entries().first().cloned().ok_or(ArchiveError::Metadata)
}
fn verify_descriptor(scope: &CatalogScope, entry: &CatalogEntry, recording: &PreparedRecording) -> ArchiveResult<()> {
    if &descriptor(scope, entry.slot(), recording)? != entry { return Err(ArchiveError::Metadata); }
    Ok(())
}
fn owner_ready(p: &LocalRootPublisher) -> ArchiveResult<()> {
    if p.is_poisoned() { return Err(RecordingIoError::ReopenRequired.into()); }
    if p.limits().spool.max_object_bytes > MAX_RECORDING_BYTES { return Err(ArchiveError::Limit); }
    Ok(())
}
fn probe(cancel: &dyn PublishCancellation) -> ArchiveResult<()> {
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) { return Err(ArchiveError::Cancelled); }
    Ok(())
}
fn scan_admit(n: usize, limits: ArchiveLimits, cancel: &dyn PublishCancellation) -> ArchiveResult<()> {
    if n >= limits.max_scan_roots { return Err(ArchiveError::Limit); }
    probe(cancel)
}
fn bounded_vec<T>(capacity: usize) -> ArchiveResult<Vec<T>> {
    let mut v = Vec::new(); v.try_reserve_exact(capacity).map_err(|_| ArchiveError::Limit)?; Ok(v)
}
