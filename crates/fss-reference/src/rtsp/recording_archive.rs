#![forbid(unsafe_code)]
//! Bounded, restartable local recording discovery over an explicitly supplied owner.
//! Namespace slots are routing, not a grant or an authoritative camera-coverage ledger.

/// Codec-pinned HEVC archive recovery and cross-page retrieval.
pub mod hevc {
#![forbid(unsafe_code)]
//! Codec-pinned HEVC archive recovery and whole-window cross-page retrieval.
//!
//! These aliases use the same sealed archive engine as AVC. Only the existing
//! HEVC recording/catalog loaders supply their typed media and metadata. No
//! unchecked conversion, metadata-controlled fallback, or external codec exists.
//! The namespace is distinct from AVC even for an identical logical clock scope.

use super::*;

/// Scope-derived HEVC routing namespace; not a published authority root.
pub type HevcArchiveNamespace = CodecArchiveNamespace<HevcArchiveCodec>;
/// Immutable HEVC catalog page with its exact storage slot and first ordinal.
pub type HevcArchivePage = CodecArchivePage<HevcArchiveCodec>;
/// Bounded source-replay-verified recovery, including the durable unindexed tail.
pub type HevcArchiveSnapshot = CodecArchiveSnapshot<HevcArchiveCodec>;
/// Incremental source-replay-verified cross-page HEVC read request.
pub type HevcArchiveRead<'a> = CodecArchiveRead<'a, HevcArchiveCodec>;
/// Typed whole HEVC windows, aggregate completion, or exhausted disposition.
pub type HevcArchiveReadProgress = ArchiveReadProgress<HevcArchiveCodec>;
}
mod codec {
#![forbid(unsafe_code)]
//! Sealed, compile-time codec dispatch for one archive/recovery implementation.
//! No metadata can select a verifier, and external code cannot supply a codec.

use super::*;
use fss_object::ObjectManifest;
use crate::rtsp::recording::hevc::{PreparedHevcRecording, local::load_hevc_recording};
use crate::rtsp::recording_catalog::{CatalogBuilder, hevc::{HevcCatalogBuilder, HevcRecordingCatalog}};
use crate::rtsp::recording_catalog::hevc::local::load_hevc_catalog;

mod sealed {
    pub trait Sealed {}
}

/// Internal closed family marker. Use the concrete AVC/HEVC archive aliases.
///
/// Sealing prevents public extension, including substituting a weaker verifier.
/// The family exists only in types; it is never recovered from an untrusted tag.
#[doc(hidden)]
pub trait ArchiveCodec: sealed::Sealed + std::fmt::Debug {
    /// Immutable output of this family's native recording verifier.
    type Recording: std::fmt::Debug;
    /// Immutable, codec-pinned catalog page.
    type Catalog: std::fmt::Debug;
    /// Metadata-only builder for this family.
    type Builder;
    /// Stable namespace encoding domain.
    const NAMESPACE_DOMAIN: &'static str;
    /// Stable inventory digest domain; this is not a published root.
    const SNAPSHOT_DOMAIN: &'static str;
    /// Disjoint codec routing prefix, without the full scope hash.
    const SLOT_PREFIX: &'static str;

    /// Borrow the unchanged root-last publication plan.
    fn plan(recording: &Self::Recording) -> &PreparedRecording;
    /// Load an exact slot/root/scope through the existing codec-specific verifier.
    fn load_recording(p: &LocalRootPublisher, slot: &SlotName, root: ContentDigest,
        scope: &super::super::recording::RecordingScope, cancel: &dyn PublishCancellation)
        -> ArchiveResult<Self::Recording>;
    /// Load an exact durable, codec-pinned catalog without inferring its family.
    fn load_catalog(p: &LocalRootPublisher, slot: &SlotName, root: ContentDigest,
        scope: &CatalogScope, cancel: &dyn PublishCancellation) -> ArchiveResult<Self::Catalog>;
    /// Borrow the exact flat root/leaf closure.
    fn manifest(catalog: &Self::Catalog) -> &ObjectManifest;
    /// Borrow canonical metadata bytes without reserialization.
    fn index(catalog: &Self::Catalog) -> &[u8];
    /// Borrow chronologically ordered descriptors.
    fn entries(catalog: &Self::Catalog) -> &[CatalogEntry];
    /// Bind a metadata builder to the supplied scope and codec.
    fn builder(scope: CatalogScope) -> ArchiveResult<Self::Builder>;
    /// Transactionally append a typed recording to that builder.
    fn push(builder: &mut Self::Builder, slot: &SlotName, recording: &Self::Recording)
        -> ArchiveResult<()>;
    /// Seal metadata using the existing codec-pinned catalog constructor.
    fn prepare(builder: Self::Builder) -> ArchiveResult<Self::Catalog>;
}

/// Closed AVC family; existing public archive aliases select this marker.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvcArchiveCodec {}
impl sealed::Sealed for AvcArchiveCodec {}
impl ArchiveCodec for AvcArchiveCodec {
    type Recording = PreparedRecording;
    type Catalog = RecordingCatalog;
    type Builder = CatalogBuilder;
    const NAMESPACE_DOMAIN: &'static str = "fss.local_recording_archive_namespace.v1";
    const SNAPSHOT_DOMAIN: &'static str = "fss.local_recording_archive_snapshot.v1";
    const SLOT_PREFIX: &'static str = "fssa1";
    fn plan(recording: &Self::Recording) -> &PreparedRecording { recording }
    fn load_recording(p: &LocalRootPublisher, slot: &SlotName, root: ContentDigest,
        scope: &super::super::recording::RecordingScope, cancel: &dyn PublishCancellation)
        -> ArchiveResult<Self::Recording>
    { Ok(load_recording(p, slot, root, scope, cancel)?) }
    fn load_catalog(p: &LocalRootPublisher, slot: &SlotName, root: ContentDigest,
        scope: &CatalogScope, cancel: &dyn PublishCancellation) -> ArchiveResult<Self::Catalog>
    { Ok(load_catalog(p, slot, root, scope, cancel)?) }
    fn manifest(catalog: &Self::Catalog) -> &ObjectManifest { catalog.manifest() }
    fn index(catalog: &Self::Catalog) -> &[u8] { catalog.index_bytes() }
    fn entries(catalog: &Self::Catalog) -> &[CatalogEntry] { catalog.entries() }
    fn builder(scope: CatalogScope) -> ArchiveResult<Self::Builder> { Ok(CatalogBuilder::new(scope)?) }
    fn push(builder: &mut Self::Builder, slot: &SlotName, recording: &Self::Recording)
        -> ArchiveResult<()> { Ok(builder.push(slot, recording)?) }
    fn prepare(builder: Self::Builder) -> ArchiveResult<Self::Catalog> { Ok(builder.prepare()?) }
}

/// Closed HEVC family; typed APIs cannot receive or return AVC media as HEVC.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HevcArchiveCodec {}
impl sealed::Sealed for HevcArchiveCodec {}
impl ArchiveCodec for HevcArchiveCodec {
    type Recording = PreparedHevcRecording;
    type Catalog = HevcRecordingCatalog;
    type Builder = HevcCatalogBuilder;
    const NAMESPACE_DOMAIN: &'static str = "fss.local_hevc_recording_archive_namespace.v1";
    const SNAPSHOT_DOMAIN: &'static str = "fss.local_hevc_recording_archive_snapshot.v1";
    const SLOT_PREFIX: &'static str = "fssh1";
    fn plan(recording: &Self::Recording) -> &PreparedRecording { recording.publication_plan() }
    fn load_recording(p: &LocalRootPublisher, slot: &SlotName, root: ContentDigest,
        scope: &super::super::recording::RecordingScope, cancel: &dyn PublishCancellation)
        -> ArchiveResult<Self::Recording>
    { Ok(load_hevc_recording(p, slot, root, scope, cancel)?) }
    fn load_catalog(p: &LocalRootPublisher, slot: &SlotName, root: ContentDigest,
        scope: &CatalogScope, cancel: &dyn PublishCancellation) -> ArchiveResult<Self::Catalog>
    { Ok(load_hevc_catalog(p, slot, root, scope, cancel)?) }
    fn manifest(catalog: &Self::Catalog) -> &ObjectManifest { catalog.manifest() }
    fn index(catalog: &Self::Catalog) -> &[u8] { catalog.index_bytes() }
    fn entries(catalog: &Self::Catalog) -> &[CatalogEntry] { catalog.entries() }
    fn builder(scope: CatalogScope) -> ArchiveResult<Self::Builder> { Ok(HevcCatalogBuilder::new(scope)?) }
    fn push(builder: &mut Self::Builder, slot: &SlotName, recording: &Self::Recording)
        -> ArchiveResult<()> { Ok(builder.push(slot, recording)?) }
    fn prepare(builder: Self::Builder) -> ArchiveResult<Self::Catalog> { Ok(builder.prepare()?) }
}
}
#[doc(hidden)]
pub use codec::{ArchiveCodec, AvcArchiveCodec, HevcArchiveCodec};

mod read;
mod write;
pub use read::*;
pub use write::*;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_publication::{LocalPublicationState, LocalRootPublisher, PublishCancellation,
    PublishCutPoint, SlotName};
use super::recording::{PreparedRecording, MAX_RECORDING_BYTES};
use super::recording::local::{RecordingIoError, load_recording};
use super::recording_catalog::{CatalogEntry, CatalogError, CatalogScope,
    RecordingCatalog, MAX_CATALOG_WINDOWS};
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
pub type ArchiveNamespace = CodecArchiveNamespace<AvcArchiveCodec>;

/// Shared namespace representation. Its sealed family fixes all durable identities.
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodecArchiveNamespace<C: ArchiveCodec> {
    scope: CatalogScope,
    digest: ContentDigest,
    prefix: String,
    codec: std::marker::PhantomData<C>,
}
impl<C: ArchiveCodec> CodecArchiveNamespace<C> {
    /// Bind every recording scope field and the explicit decode clock/tick rate.
    pub fn new(scope: CatalogScope) -> ArchiveResult<Self> {
        if scope.recording.generation == 0 || scope.time_scale == 0 { return Err(ArchiveError::Scope); }
        let mut e = CanonicalEncoder::new();
        e.text(C::NAMESPACE_DOMAIN);
        e.text(scope.recording.sensor.as_str()); e.text(scope.recording.stream.as_str());
        e.u64(scope.recording.generation); e.digest(scope.recording.anchor);
        e.digest(scope.recording.receive_clock); e.digest(scope.decode_clock); e.u32(scope.time_scale);
        let bytes = e.finish_checked().map_err(|_| ArchiveError::Limit)?;
        let digest = ContentDigest::try_sha256(&bytes).map_err(|_| ArchiveError::Limit)?;
        let text = digest.to_text();
        let hex = text.strip_prefix("sha256:").ok_or(ArchiveError::Metadata)?;
        Ok(Self { scope, digest, prefix: format!("{}-{hex}", C::SLOT_PREFIX),
            codec: std::marker::PhantomData })
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
pub type ArchivePage = CodecArchivePage<AvcArchiveCodec>;

/// Shared typed page representation; catalog bytes retain their codec's format.
#[doc(hidden)]
#[derive(Debug)]
pub struct CodecArchivePage<C: ArchiveCodec> {
    slot: SlotName,
    first: usize,
    catalog: C::Catalog,
}
impl<C: ArchiveCodec> CodecArchivePage<C> {
    /// Exact local root slot.
    pub fn slot(&self) -> &SlotName { &self.slot }
    /// First zero-based recording ordinal named by this page.
    pub fn first_ordinal(&self) -> usize { self.first }
    /// Immutable catalog; its root pins every source and derived object.
    pub fn catalog(&self) -> &C::Catalog { &self.catalog }
}

/// Bounded point-in-time inventory, recovered by rehashing original recordings.
/// This is not an authoritative history, a retention lease, or a coverage/absence proof.
pub type ArchiveSnapshot = CodecArchiveSnapshot<AvcArchiveCodec>;

/// One bounded recovery implementation with a sealed, compile-time codec family.
#[doc(hidden)]
#[derive(Debug)]
pub struct CodecArchiveSnapshot<C: ArchiveCodec> {
    namespace: CodecArchiveNamespace<C>,
    limits: ArchiveLimits,
    windows: Vec<CatalogEntry>,
    pages: Vec<CodecArchivePage<C>>,
    indexed: usize,
}
impl<C: ArchiveCodec> CodecArchiveSnapshot<C> {
    /// Discover this exact scope from the supplied publisher's existing metadata only.
    /// No filesystem listing/path read occurs here. Every admitted original window is
    /// loaded and source-verified, one at a time; total recovery work is bounded by
    /// max_windows, with cancellation between reads. Partial recovery is never returned.
    /// Broken roots and unresolved root temporaries are refused, never skipped as absence.
    pub fn load(p: &LocalRootPublisher, namespace: CodecArchiveNamespace<C>, limits: ArchiveLimits,
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
            let catalog = C::load_catalog(p, &slot, root, &namespace.scope, cancel)?;
            let end = first.checked_add(C::entries(&catalog).len()).ok_or(ArchiveError::Limit)?;
            if end > roots.len() { return Err(ArchiveError::Sequence); }
            for (entry, reference) in C::entries(&catalog).iter().zip(&roots[first..end]) {
                if entry.slot() != &reference.1 || entry.root() != reference.2 { return Err(ArchiveError::Metadata); }
            }
            indexed = end; pages.push(CodecArchivePage::<C> { slot, first, catalog });
        }
        // The writer seals before admitting another page. A larger tail is not its
        // recoverable state; do not silently import an arbitrary foreign layout.
        if roots.len() - indexed > MAX_CATALOG_WINDOWS { return Err(ArchiveError::Sequence); }
        let mut windows: Vec<CatalogEntry> = bounded_vec(roots.len())?;
        let mut page_at = 0;
        for (ordinal, slot, root) in roots {
            let recording = C::load_recording(p, &slot, root, &namespace.scope.recording, cancel)?;
            let entry = descriptor_for::<C>(&namespace.scope, &slot, &recording)?;
            if windows.last().is_some_and(|last| last.decode_interval().end > entry.decode_interval().start)
                || windows.iter().any(|old| old.root() == entry.root()) { return Err(ArchiveError::Sequence); }
            if ordinal < indexed {
                while ordinal >= pages[page_at].first + C::entries(&pages[page_at].catalog).len() { page_at += 1; }
                if entry != C::entries(&pages[page_at].catalog)[ordinal - pages[page_at].first] { return Err(ArchiveError::Metadata); }
            }
            windows.push(entry);
        }
        probe(cancel)?;
        Ok(Self { namespace, limits, windows, pages, indexed })
    }
    /// Bounds applied to this recovered inventory.
    pub fn limits(&self) -> ArchiveLimits { self.limits }
    /// Exact scope-derived namespace.
    pub fn namespace(&self) -> &CodecArchiveNamespace<C> { &self.namespace }
    /// Fully source-verified descriptors at recovery time; not future retrieval guarantees.
    pub fn windows(&self) -> &[CatalogEntry] { &self.windows }
    /// Only durably published pages, in recording order.
    pub fn pages(&self) -> &[CodecArchivePage<C>] { &self.pages }
    /// Durable windows that also have published discovery metadata.
    pub fn indexed_windows(&self) -> usize { self.indexed }
    /// Durable original windows awaiting catalog publication after a flush/crash.
    pub fn unindexed_windows(&self) -> &[CatalogEntry] { &self.windows[self.indexed..] }
    /// Deterministic inventory identity. This digest is NOT a published ledger/head root.
    pub fn digest(&self) -> ArchiveResult<ContentDigest> {
        let mut e = CanonicalEncoder::new(); e.text(C::SNAPSHOT_DOMAIN);
        e.digest(self.namespace.digest); e.u64(self.windows.len() as u64); e.u64(self.indexed as u64);
        for entry in &self.windows { e.digest(entry.root()); }
        e.u64(self.pages.len() as u64);
        for page in &self.pages { e.u64(page.first as u64); e.digest(C::manifest(&page.catalog).root()); }
        ContentDigest::try_sha256(&e.finish_checked().map_err(|_| ArchiveError::Limit)?)
            .map_err(|_| ArchiveError::Limit)
    }
}

fn descriptor(scope: &CatalogScope, slot: &SlotName, recording: &PreparedRecording) -> ArchiveResult<CatalogEntry> {
    descriptor_for::<AvcArchiveCodec>(scope, slot, recording)
}
fn verify_descriptor(scope: &CatalogScope, entry: &CatalogEntry, recording: &PreparedRecording) -> ArchiveResult<()> {
    verify_descriptor_for::<AvcArchiveCodec>(scope, entry, recording)
}
fn descriptor_for<C: ArchiveCodec>(scope: &CatalogScope, slot: &SlotName,
    recording: &C::Recording) -> ArchiveResult<CatalogEntry>
{
    let mut builder = C::builder(scope.clone())?;
    C::push(&mut builder, slot, recording)?;
    let catalog = C::prepare(builder)?;
    C::entries(&catalog).first().cloned().ok_or(ArchiveError::Metadata)
}
fn verify_descriptor_for<C: ArchiveCodec>(scope: &CatalogScope, entry: &CatalogEntry,
    recording: &C::Recording) -> ArchiveResult<()>
{
    if &descriptor_for::<C>(scope, entry.slot(), recording)? != entry { return Err(ArchiveError::Metadata); }
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
