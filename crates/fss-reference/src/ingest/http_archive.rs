#![forbid(unsafe_code)]
//! Durable original HTTP reads through the EXISTING content-addressed publisher.
//! Each read is a small independent root; its predecessor is an ordered commitment,
//! not recursive manifest descent. A prefix pin is verified against every required
//! root on load. No new journal, camera timestamp, event authority or silent head.

use fss_codec_mjpeg::http_mjpeg::HttpJpegFrame;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryError, WorkBudget};
use fss_object::ObjectManifest;
use fss_publication::{LocalPublicationReceipt, LocalPublicationState, LocalRootPublisher,
    PublishCancellation, PublishCutPoint, SlotName};
use super::http_camera::{HttpWireRead, HttpWireReceipt};

/// Durable object family; never a recording-complete or canonical event root.
pub const HTTP_WIRE_KIND: &str = "http_camera_wire_v1";
/// Bounded metadata inventory; rotate to a new independently identified stream at capacity.
pub const MAX_HTTP_WIRE_READS: usize = 4096;
const MAX_READ: usize = 65536;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RANGE: usize = 16 * 1024 * 1024;
const MAX_METADATA: usize = 512;
const MAX_MANIFEST: usize = 1024;
const DOMAIN: &str = "fss.http_camera_wire.v1";

/// Requested source/retention scope, NOT a storage capability or physical-camera authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpWireScope {
    /// Original plaintext-response identity and generation.
    pub stream: StreamBasis,
    /// Owner-admitted monotonic RECEIVE clock, not the camera's capture clock.
    pub receive_clock: [u8; 32],
    /// Explicit authority/policy evidence for retaining raw headers AND image bytes.
    pub retention_evidence: [u8; 32],
}
impl HttpWireScope {
    /// Exact immutable source and retention interpretation.
    pub fn digest(self) -> Result<ContentDigest, HttpArchiveError> {
        if self.stream.source == [0; 32] || self.stream.generation == 0
            || self.receive_clock == [0; 32] || self.retention_evidence == [0; 32] {
            return Err(HttpArchiveError::Configuration);
        }
        let mut e = CanonicalEncoder::new(); e.text("fss.http_wire_scope.v1");
        e.digest(sha(self.stream.source)); e.u64(self.stream.generation);
        e.digest(sha(self.receive_clock)); e.digest(sha(self.retention_evidence));
        Ok(ContentDigest::sha256(&e.finish_checked().map_err(|_| HttpArchiveError::Metadata)?))
    }
    fn prefix(self) -> Result<String, HttpArchiveError> {
        self.digest()?;
        // Changing retention or receive-clock assumptions cannot evade an occupied source slot.
        let mut e = CanonicalEncoder::new(); e.text("fss.http_wire_namespace.v1");
        e.digest(sha(self.stream.source)); e.u64(self.stream.generation);
        let digest = ContentDigest::sha256(&e.finish_checked().map_err(|_| HttpArchiveError::Metadata)?);
        let text = digest.to_text();
        Ok(format!("fsshw1-{}-", text.strip_prefix("sha256:").ok_or(HttpArchiveError::Metadata)?))
    }
}
/// Independent runtime ceilings. Historical metadata never widens these values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpArchiveLimits {
    /// Complete read inventory, at most MAX_HTTP_WIRE_READS; no top-k truncation.
    pub maximum_reads: usize,
    /// Complete original-byte prefix, at most 256 MiB.
    pub maximum_bytes: u64,
    /// Whole-publisher root/broken/temp scan allowance, at most 65536.
    pub maximum_scan_roots: usize,
    /// Maximum configured spool object size admitted BEFORE any allocating read.
    /// This may exceed a wire-read size to share the existing publisher with other families.
    pub maximum_spool_object_bytes: usize,
}
impl HttpArchiveLimits {
    fn validate(self) -> Result<(), HttpArchiveError> {
        if !(1..=MAX_HTTP_WIRE_READS).contains(&self.maximum_reads)
            || !(1..=MAX_BYTES).contains(&self.maximum_bytes)
            || !(1..=65536).contains(&self.maximum_scan_roots)
            || !(MAX_MANIFEST..=MAX_RANGE).contains(&self.maximum_spool_object_bytes) {
            return Err(HttpArchiveError::Configuration);
        }
        Ok(())
    }
}
/// An independently retained checkpoint, not proof that its publication succeeded.
/// Load requires this exact prefix and rejects additional unaccounted source roots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpWirePin {
    /// Exact HttpWireScope identity.
    pub scope: ContentDigest,
    /// Last read root, or scope identity for an empty prefix.
    pub head: ContentDigest,
    /// Number of contiguous original reads, not JPEG frames.
    pub reads: u64,
    /// Next original response byte offset.
    pub bytes: u64,
}
/// Payload-free failure. Underlying storage details stay with its existing owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpArchiveError {
    /// Invalid source, retention/clock identity or limits.
    Configuration,
    /// Wrong stream/clock/scope or changed raw-read identity.
    Source,
    /// Missing, duplicated, reordered, conflicting or unaccounted source history.
    Sequence,
    /// Invalid canonical metadata, root family or direct child set.
    Metadata,
    /// Existing publisher is poisoned/broken, or a required root is not durable.
    NotDurable,
    /// Current source/spool verification failed, including vanished/corrupt bytes.
    Storage,
    /// Source bytes have been tombstoned; never reconstruct or reacquire them here.
    Tombstoned,
    /// Complete input/output/allocation/scan ceiling exceeded.
    Limit,
    /// Explicit storage-owner cancellation, including its live authorization/deadline probe.
    Cancelled,
    /// Deterministic caller work/cancellation bound failed before completion.
    Work(GeometryError),
}
impl From<GeometryError> for HttpArchiveError {
    fn from(e: GeometryError) -> Self { Self::Work(e) }
}
impl std::fmt::Display for HttpArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP source archive refused: {self:?}")
    }
}
impl std::error::Error for HttpArchiveError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry { prior: HttpWirePin, wire: HttpWireReceipt, root: ContentDigest }
impl Entry {
    fn pin(self) -> HttpWirePin {
        HttpWirePin { scope: self.prior.scope, head: self.root,
            reads: self.prior.reads + 1, bytes: self.wire.range[1] }
    }
    fn metadata(self) -> Result<Vec<u8>, HttpArchiveError> {
        let mut e = CanonicalEncoder::new(); e.text(DOMAIN);
        e.digest(self.prior.scope); e.digest(self.prior.head);
        e.u64(self.prior.reads); e.u64(self.prior.bytes);
        e.digest(sha(self.wire.basis.source)); e.u64(self.wire.basis.generation);
        e.u64(self.wire.range[0]); e.u64(self.wire.range[1]);
        e.digest(sha(self.wire.sha256)); e.u64(self.wire.admitted_ns);
        let bytes = e.finish_checked().map_err(|_| HttpArchiveError::Metadata)?;
        if bytes.len() > MAX_METADATA { return Err(HttpArchiveError::Limit); }
        Ok(bytes)
    }
    fn manifest(self) -> Result<ObjectManifest, HttpArchiveError> {
        ObjectManifest::new(HTTP_WIRE_KIND, vec![sha(self.wire.sha256)],
            Some(ContentDigest::sha256(&self.metadata()?))).map_err(|_| HttpArchiveError::Metadata)
    }
    fn decode(bytes: &[u8], root: ContentDigest) -> Result<Self, HttpArchiveError> {
        let decode = || -> Result<Self, fss_core::ContractError> {
            let mut d = CanonicalDecoder::new(bytes);
            if d.text()? != DOMAIN { return Err(fss_core::ContractError::InvalidIdentifier); }
            let prior = HttpWirePin { scope: d.digest()?, head: d.digest()?, reads: d.u64()?, bytes: d.u64()? };
            let source = d.digest()?; let generation = d.u64()?;
            let range = [d.u64()?, d.u64()?]; let digest = d.digest()?; let admitted_ns = d.u64()?;
            if [prior.scope, prior.head, source, digest, root].iter().any(|d| d.algorithm() != DigestAlgorithm::Sha256) {
                return Err(fss_core::ContractError::InvalidIdentifier);
            }
            d.ensure_finished()?;
            Ok(Self { prior, wire: HttpWireReceipt { basis: StreamBasis { source: source.bytes(), generation },
                range, sha256: digest.bytes(), admitted_ns }, root })
        };
        let entry = decode().map_err(|_| HttpArchiveError::Metadata)?;
        if entry.metadata()? != bytes { return Err(HttpArchiveError::Metadata); }
        Ok(entry)
    }
}
/// Prepared exact source publication. Keep its pin independently before I/O so a
/// lost acknowledgement can be resolved after reopening the same storage owner.
pub struct PreparedHttpWire<'a> { entry: Entry, bytes: &'a [u8], manifest: ObjectManifest, slot: SlotName }
impl PreparedHttpWire<'_> {
    /// Expected post-publication prefix; not itself a durability receipt.
    pub fn pin(&self) -> HttpWirePin { self.entry.pin() }
    /// Exact immutable root route, shared by exact retries.
    pub fn slot(&self) -> &SlotName { &self.slot }
}
impl std::fmt::Debug for PreparedHttpWire<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedHttpWire").field("pin", &self.pin()).finish_non_exhaustive()
    }
}
/// A successful current read publication. Replication/protection are not implied.
#[derive(Debug)]
pub struct HttpWirePublication {
    /// Source prefix after this read; exact retries do not increment it.
    pub pin: HttpWirePin,
    /// Original source record whose bytes were retained unchanged.
    pub wire: HttpWireReceipt,
    /// Existing publisher's reverified local durability receipt and explicit claims.
    pub local: LocalPublicationReceipt,
}
/// Bounded in-memory index of individually durable immutable original reads.
/// It owns NO filesystem, network, background worker or alternative journal.
#[derive(Debug)]
pub struct HttpWireArchive { scope: HttpWireScope, limits: HttpArchiveLimits, prefix: String, scope_digest: ContentDigest, entries: Vec<Entry> }
impl HttpWireArchive {
    /// Declare an empty prefix. Publication checks storage for namespace conflicts;
    /// an empty constructor does not assert that an existing store is empty.
    pub fn new(scope: HttpWireScope, limits: HttpArchiveLimits) -> Result<Self, HttpArchiveError> {
        limits.validate()?;
        Ok(Self { scope, limits, prefix: scope.prefix()?, scope_digest: scope.digest()?, entries: Vec::new() })
    }
    /// Exact source and retention interpretation. It is not permission to expose bytes.
    pub fn scope(&self) -> HttpWireScope { self.scope }
    /// Independently selected complete-input bounds.
    pub fn limits(&self) -> HttpArchiveLimits { self.limits }
    /// Current acknowledged in-memory prefix. Source must be reverified for fresh reads.
    pub fn pin(&self) -> HttpWirePin {
        self.entries.last().map_or_else(|| {
            // The constructor validated this fixed-size encoding and immutable scope.
            let scope = self.entries_scope();
            HttpWirePin { scope, head: scope, reads: 0, bytes: 0 }
        }, |e| e.pin())
    }
    /// Every retained read in original order, with its exact post-read prefix pin.
    pub fn reads(&self) -> impl Iterator<Item = (HttpWirePin, HttpWireReceipt)> + '_ {
        self.entries.iter().map(|e| (e.pin(), e.wire))
    }
    fn entries_scope(&self) -> ContentDigest { self.scope_digest }
    fn slot(&self, ordinal: u64) -> Result<SlotName, HttpArchiveError> {
        SlotName::parse(&format!("{}{:08x}", self.prefix, ordinal)).map_err(|_| HttpArchiveError::Metadata)
    }
    /// Verify all roots, canonical metadata, order, receive times and original bytes
    /// for EXACTLY expected. A later root is not silently followed or discarded.
    pub fn load(p: &LocalRootPublisher, scope: HttpWireScope, expected: HttpWirePin,
        limits: HttpArchiveLimits, cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>)
        -> Result<Self, HttpArchiveError> {
        let mut archive = Self::new(scope, limits)?;
        archive.ready(p)?;
        if expected.scope != scope.digest()? || expected.reads > limits.maximum_reads as u64
            || expected.bytes > limits.maximum_bytes { return Err(HttpArchiveError::Source); }
        archive.inventory(p, expected.reads, expected.reads, cancel, budget)?;
        archive.entries.try_reserve_exact(expected.reads as usize).map_err(|_| HttpArchiveError::Limit)?;
        for ordinal in 1..=expected.reads {
            let slot = archive.slot(ordinal)?;
            let root = p.root(&slot).ok_or(HttpArchiveError::NotDurable)?.root;
            let (entry, _) = archive.read_entry(p, &slot, root, cancel, budget)?;
            archive.validate_next(entry.wire)?;
            if entry.prior != archive.pin() { return Err(HttpArchiveError::Sequence); }
            archive.entries.push(entry);
        }
        if archive.pin() != expected { return Err(HttpArchiveError::Sequence); }
        budget.charge(0)?; probe(cancel)?;
        Ok(archive)
    }
    /// Prepare an actual opaque socket read without doing I/O or acknowledging it.
    pub fn prepare<'a>(&self, read: &'a HttpWireRead, budget: &mut WorkBudget<'_>)
        -> Result<PreparedHttpWire<'a>, HttpArchiveError> {
        self.prepare_bytes(read.receipt(), read.bytes(), budget)
    }
    fn prepare_bytes<'a>(&self, wire: HttpWireReceipt, bytes: &'a [u8], budget: &mut WorkBudget<'_>)
        -> Result<PreparedHttpWire<'a>, HttpArchiveError> {
        budget.charge(1024 + bytes.len() as u64 * 2)?;
        if bytes.is_empty() || bytes.len() > MAX_READ || wire.range[1].checked_sub(wire.range[0]) != Some(bytes.len() as u64)
            || ContentDigest::sha256(bytes).bytes() != wire.sha256 { return Err(HttpArchiveError::Source); }
        let mut entry = if let Some(old) = self.entries.last().filter(|e| e.wire == wire) { *old }
            else { self.validate_next(wire)?; Entry { prior: self.pin(), wire, root: self.pin().head } };
        let manifest = entry.manifest()?; entry.root = manifest.root();
        let slot = self.slot(entry.pin().reads)?;
        budget.charge(0)?;
        Ok(PreparedHttpWire { entry, bytes, manifest, slot })
    }
    fn validate_next(&self, wire: HttpWireReceipt) -> Result<(), HttpArchiveError> {
        if wire.basis != self.scope.stream || wire.sha256 == [0; 32] { return Err(HttpArchiveError::Source); }
        if wire.range[0] != self.pin().bytes || wire.range[1] <= wire.range[0]
            || self.entries.last().is_some_and(|e| wire.admitted_ns < e.wire.admitted_ns) {
            return Err(HttpArchiveError::Sequence);
        }
        if self.entries.len() == self.limits.maximum_reads || wire.range[1] > self.limits.maximum_bytes
            || wire.range[1] - wire.range[0] > MAX_READ as u64 { return Err(HttpArchiveError::Limit); }
        Ok(())
    }
    /// Stage original bytes and exact metadata, then publish through the existing
    /// root-last owner. No fallible work follows a durable result before index commit.
    /// A failed call keeps the source borrowed and index unchanged; storage may have
    /// staged/visible work. Reopen a poisoned publisher, never acknowledge on error.
    pub fn publish(&mut self, plan: &PreparedHttpWire<'_>, p: &mut LocalRootPublisher,
        cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>) -> Result<HttpWirePublication, HttpArchiveError> {
        self.ready(p)?; probe(cancel)?;
        let retry = self.entries.last() == Some(&plan.entry);
        if !retry && plan.entry.prior != self.pin() { return Err(HttpArchiveError::Sequence); }
        if plan.slot != self.slot(plan.entry.pin().reads)? || plan.entry.prior.scope != self.entries_scope() {
            return Err(HttpArchiveError::Source);
        }
        if !retry { self.validate_next(plan.entry.wire)?; }
        self.inventory(p, self.pin().reads, plan.pin().reads, cancel, budget)?;
        if let Some(root) = p.root(&plan.slot) && root.root != plan.entry.root { return Err(HttpArchiveError::Sequence); }
        // Reserve memory/work before ANY storage side effect. Metadata has fixed bounded size.
        self.entries.try_reserve(usize::from(!retry)).map_err(|_| HttpArchiveError::Limit)?;
        let metadata = plan.entry.metadata()?;
        budget.charge(4096 + plan.bytes.len() as u64 * 8)?;
        probe(cancel)?;
        if p.stage_object(plan.bytes).map_err(|_| HttpArchiveError::Storage)? != sha(plan.entry.wire.sha256) {
            return Err(HttpArchiveError::Storage);
        }
        probe(cancel)?;
        if p.stage_object(&metadata).map_err(|_| HttpArchiveError::Storage)? != ContentDigest::sha256(&metadata) {
            return Err(HttpArchiveError::Storage);
        }
        probe(cancel)?; budget.charge(0)?;
        let local = p.publish_cancellable(&plan.slot, &plan.manifest, cancel).map_err(|_| HttpArchiveError::Storage)?;
        if local.claims.local != LocalPublicationState::Durable || local.root != plan.entry.root {
            return Err(HttpArchiveError::NotDurable);
        }
        if !retry { self.entries.push(plan.entry); }
        Ok(HttpWirePublication { pin: self.pin(), wire: plan.entry.wire, local })
    }
    /// Read and rehash a bounded exact original-wire range across read boundaries.
    /// Caller supplies the authorized storage owner; this API grants no access.
    pub fn read_range(&self, p: &LocalRootPublisher, range: [u64; 2],
        cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>) -> Result<Vec<u8>, HttpArchiveError> {
        self.ready(p)?; probe(cancel)?;
        let length = range[1].checked_sub(range[0]).ok_or(HttpArchiveError::Source)?;
        if range[1] > self.pin().bytes || length > MAX_RANGE as u64 { return Err(HttpArchiveError::Limit); }
        budget.charge(length + 64)?;
        let mut output = Vec::new(); output.try_reserve_exact(length as usize).map_err(|_| HttpArchiveError::Limit)?;
        let mut cursor = range[0];
        let first = self.entries.partition_point(|e| e.wire.range[1] <= cursor);
        for entry in &self.entries[first..] {
            if cursor == range[1] { break; }
            let slot = self.slot(entry.pin().reads)?;
            let (actual, bytes) = self.read_entry(p, &slot, entry.root, cancel, budget)?;
            if actual != *entry || cursor < entry.wire.range[0] { return Err(HttpArchiveError::Sequence); }
            let end = range[1].min(entry.wire.range[1]);
            output.extend_from_slice(&bytes[(cursor - entry.wire.range[0]) as usize..(end - entry.wire.range[0]) as usize]);
            cursor = end;
        }
        if cursor != range[1] { return Err(HttpArchiveError::Sequence); }
        budget.charge(0)?; probe(cancel)?;
        Ok(output)
    }
    /// Re-read every mapped JPEG payload byte and compare with the original opaque
    /// HTTP/MIME frame. This proves payload custody NOW, not full-response completion,
    /// camera authentication, capture time, model quality or canonical event publication.
    pub fn verify_frame(&self, p: &LocalRootPublisher, frame: &HttpJpegFrame,
        cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>) -> Result<(), HttpArchiveError> {
        if frame.head().wire != self.scope.stream || frame.source_spans().is_empty()
            || frame.source_spans().len() > 65536 || frame.part().bytes().len() > MAX_RANGE {
            return Err(HttpArchiveError::Source);
        }
        let mut cursor = 0_u64; let mut wire_end = 0_u64;
        for span in frame.source_spans() {
            budget.charge(1)?;
            if span.jpeg_range[0] != cursor || span.jpeg_range[1] <= cursor
                || span.jpeg_range[1] > frame.part().bytes().len() as u64
                || span.wire_range[0] < wire_end
                || span.wire_range[1].checked_sub(span.wire_range[0]) != Some(span.jpeg_range[1] - cursor) {
                return Err(HttpArchiveError::Source);
            }
            let bytes = self.read_range(p, span.wire_range, cancel, budget)?;
            if bytes != frame.part().bytes()[cursor as usize..span.jpeg_range[1] as usize] {
                return Err(HttpArchiveError::Source);
            }
            cursor = span.jpeg_range[1]; wire_end = span.wire_range[1];
        }
        if cursor != frame.part().bytes().len() as u64 { return Err(HttpArchiveError::Source); }
        budget.charge(0)?; probe(cancel)?; Ok(())
    }
    fn ready(&self, p: &LocalRootPublisher) -> Result<(), HttpArchiveError> {
        if p.is_poisoned() { return Err(HttpArchiveError::NotDurable); }
        if p.limits().spool.max_object_bytes > self.limits.maximum_spool_object_bytes {
            return Err(HttpArchiveError::Limit);
        }
        Ok(())
    }
    fn inventory(&self, p: &LocalRootPublisher, minimum: u64, maximum: u64,
        cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>) -> Result<(), HttpArchiveError> {
        self.ready(p)?;
        let mut examined = 0_usize; let mut matching = 0_u64;
        for root in p.visible_roots() {
            probe(cancel)?; budget.charge(128)?; examined += 1;
            if examined > self.limits.maximum_scan_roots { return Err(HttpArchiveError::Limit); }
            let name = root.slot.to_string();
            if let Some(tail) = name.strip_prefix(&self.prefix) {
                let ordinal = u64::from_str_radix(tail, 16).map_err(|_| HttpArchiveError::Sequence)?;
                if ordinal == 0 || ordinal > maximum || root.slot != self.slot(ordinal)?
                    || root.state != LocalPublicationState::Durable { return Err(HttpArchiveError::Sequence); }
                matching += 1;
            }
        }
        for slot in p.broken_slots() {
            probe(cancel)?; budget.charge(128)?; examined += 1;
            if examined > self.limits.maximum_scan_roots { return Err(HttpArchiveError::Limit); }
            if slot.to_string().starts_with(&self.prefix) { return Err(HttpArchiveError::NotDurable); }
        }
        for path in &p.recovery_report().orphaned_temps {
            probe(cancel)?; budget.charge(128)?; examined += 1;
            if examined > self.limits.maximum_scan_roots { return Err(HttpArchiveError::Limit); }
            if path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(&self.prefix)) {
                return Err(HttpArchiveError::NotDurable);
            }
        }
        if matching < minimum || matching > maximum { return Err(HttpArchiveError::Sequence); }
        // Equal counts alone cannot hide a gap; every previously acknowledged slot must exist.
        for entry in &self.entries {
            probe(cancel)?; budget.charge(128)?;
            require_root(p, &self.slot(entry.pin().reads)?, entry.root)?;
        }
        Ok(())
    }
    fn read_entry(&self, p: &LocalRootPublisher, slot: &SlotName, root: ContentDigest,
        cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>) -> Result<(Entry, Vec<u8>), HttpArchiveError> {
        require_root(p, slot, root)?;
        let raw = self.read_object(p, root, MAX_MANIFEST, cancel, budget)?;
        let manifest = ObjectManifest::from_canonical_bytes(&raw).map_err(|_| HttpArchiveError::Metadata)?;
        if manifest.root() != root || manifest.kind() != HTTP_WIRE_KIND { return Err(HttpArchiveError::Metadata); }
        let metadata = self.read_object(p, manifest.metadata_digest().ok_or(HttpArchiveError::Metadata)?, MAX_METADATA, cancel, budget)?;
        let entry = Entry::decode(&metadata, root)?;
        if entry.prior.scope != self.entries_scope() || entry.wire.basis != self.scope.stream
            || entry.prior.reads >= self.limits.maximum_reads as u64
            || entry.wire.range[1] <= entry.wire.range[0]
            || entry.wire.range[1] > self.limits.maximum_bytes
            || entry.wire.range[1] - entry.wire.range[0] > MAX_READ as u64
            || entry.manifest()? != manifest { return Err(HttpArchiveError::Metadata); }
        let bytes = self.read_object(p, sha(entry.wire.sha256), MAX_READ, cancel, budget)?;
        if bytes.len() as u64 != entry.wire.range[1] - entry.wire.range[0] { return Err(HttpArchiveError::Source); }
        Ok((entry, bytes))
    }
    fn read_object(&self, p: &LocalRootPublisher, digest: ContentDigest, maximum: usize,
        cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>) -> Result<Vec<u8>, HttpArchiveError> {
        self.ready(p)?; probe(cancel)?;
        // Pay the actual owner's maximum BEFORE its allocating read, including hash work.
        budget.charge(p.limits().spool.max_object_bytes as u64 * 3 + p.limits().max_tombstones as u64 + 1)?;
        if p.tombstones().any(|d| *d == digest) { return Err(HttpArchiveError::Tombstoned); }
        let bytes = p.spool().read(digest).map_err(|_| HttpArchiveError::Storage)?;
        if bytes.len() > maximum { return Err(HttpArchiveError::Limit); }
        probe(cancel)?; budget.charge(0)?; Ok(bytes)
    }
}
fn sha(bytes: [u8; 32]) -> ContentDigest { ContentDigest::new(DigestAlgorithm::Sha256, bytes) }
fn probe(cancel: &dyn PublishCancellation) -> Result<(), HttpArchiveError> {
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) { Err(HttpArchiveError::Cancelled) } else { Ok(()) }
}
fn require_root(p: &LocalRootPublisher, slot: &SlotName, root: ContentDigest) -> Result<(), HttpArchiveError> {
    if p.is_poisoned() || p.is_broken_slot(slot) || p.root(slot).is_none_or(|r| r.root != root || r.state != LocalPublicationState::Durable) {
        return Err(HttpArchiveError::NotDurable);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
