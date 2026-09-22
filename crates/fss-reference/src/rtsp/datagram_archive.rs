#![forbid(unsafe_code)]
//! Original interleaved RTP/RTCP custody before a picture or recording is complete.
//!
//! This is a source prefix, not a recording, codec checkpoint, coverage witness or
//! remote-session receipt. RTSP control/authentication messages are NOT stored.
//! Malformed, duplicate and probation datagrams remain evidence, not silent gaps.

/// Native live capture with original-datagram publication before further media progress.
pub mod live;
/// Read-only, exact historical source selection without rewinding the capture owner.
pub mod prefix;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryError, WorkBudget};
use fss_object::{ObjectManifest, SpoolError};
use fss_publication::{LocalPublicationError, LocalPublicationReceipt, LocalPublicationState,
    LocalRootPublisher, PublishCancellation, PublishCutPoint, SlotName};
use super::avc_client::InterleavedSource;
use super::tcp::TcpBinding;

/// Independent immutable root family; it cannot stand in for an AVC recording.
pub const RTSP_DATAGRAM_KIND: &str = "rtsp_interleaved_source_v1";
/// Largest payload admitted by the existing interleaved RTSP framing.
pub const MAX_DATAGRAM_BYTES: usize = 65_535;
const DOMAIN: &str = "fss.rtsp_interleaved_source.v1";
const MAX_METADATA: usize = 512;

/// Owner-selected connection epoch and interpretation. None of these fields grants access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatagramScope {
    /// Exact route and stream key of the connection that supplies these datagrams.
    pub binding: TcpBinding,
    /// Independently selected RTP and RTCP channels, in that order.
    pub channels: (u8, u8),
    /// Parser-completion receive clock, never an inferred camera-capture clock.
    pub receive_clock: ContentDigest,
    /// Owner evidence authorizing retention of original media AND RTCP metadata.
    pub retention_evidence: ContentDigest,
}
impl DatagramScope {
    /// Complete immutable interpretation; the route is committed without storing its text.
    pub fn digest(&self) -> Result<ContentDigest> {
        if self.channels.0 == self.channels.1
            || [self.receive_clock, self.retention_evidence].iter().any(|d|
                d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32]) {
            return Err(DatagramArchiveError::Configuration);
        }
        let key = self.binding.key();
        let mut e = CanonicalEncoder::new(); e.text("fss.rtsp_datagram_scope.v1");
        e.u64((key.ingress >> 64) as u64); e.u64(key.ingress as u64);
        e.u64(key.generation); e.u32(key.ssrc);
        e.text(&self.binding.peer().to_string()); e.text(self.binding.authority());
        e.text("owner_approved_plaintext");
        e.tag(self.channels.0); e.tag(self.channels.1);
        e.digest(self.receive_clock); e.digest(self.retention_evidence);
        hash_encoder(e)
    }
    fn prefix(&self) -> Result<String> {
        let key = self.binding.key();
        let mut e = CanonicalEncoder::new(); e.text("fss.rtsp_datagram_namespace.v1");
        e.u64((key.ingress >> 64) as u64); e.u64(key.ingress as u64); e.u64(key.generation);
        let text = hash_encoder(e)?.to_text();
        // A changed route, SSRC, clock, channel or retention policy cannot evade occupied
        // slots for the same ingress/generation. Reconnect needs a new explicit epoch.
        Ok(format!("fssrd1-{}-", text.strip_prefix("sha256:").ok_or(DatagramArchiveError::Metadata)?))
    }
}

/// Independent complete-prefix limits. Stored metadata cannot raise any ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatagramArchiveLimits {
    /// Complete datagram count, including zero-byte, repeated and malformed input; at most 65536.
    pub max_datagrams: usize,
    /// Sum of original payload bytes, at most 1 GiB. No implicit rollover or eviction.
    pub max_payload_bytes: u64,
    /// All publisher root/recovery entries examined, including other namespaces; at most 262144.
    pub max_scan_roots: usize,
    /// Maximum actual spool allocation accepted before reads; 1 KiB through 32 MiB.
    pub max_spool_object_bytes: usize,
}
impl DatagramArchiveLimits {
    fn validate(self) -> Result<()> {
        if !(1..=65_536).contains(&self.max_datagrams)
            || !(1..=1_073_741_824).contains(&self.max_payload_bytes)
            || !(1..=262_144).contains(&self.max_scan_roots)
            || !(1024..=33_554_432).contains(&self.max_spool_object_bytes) {
            return Err(DatagramArchiveError::Configuration);
        }
        Ok(())
    }
}

/// A source-prefix commitment, not proof of present custody or a clean end of stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatagramPin {
    /// Exact selected scope identity.
    pub scope: ContentDigest,
    /// Last datagram root, or scope identity for an empty prefix.
    pub head: ContentDigest,
    /// Contiguous source observations, not RTP sequence numbers or pictures.
    pub datagrams: u64,
    /// Cumulative original payload bytes; identical retransmissions count separately.
    pub payload_bytes: u64,
}

/// Failures preserve typed storage uncertainty without displaying private storage paths.
pub enum DatagramArchiveError {
    /// Invalid scope or independent bounds.
    Configuration,
    /// Source channel, receive clock or byte count disagrees.
    Source,
    /// A gap, conflicting root, stale plan or missing independently pinned prefix.
    Sequence,
    /// Wrong canonical metadata, family, or exact child set.
    Metadata,
    /// A whole-input, allocation, byte, work or scan ceiling was reached.
    Limit,
    /// Publisher is poisoned, broken or does not prove the required root durable.
    NotDurable,
    /// Source or metadata has a tombstone; never reconstruct it here.
    Tombstoned,
    /// Explicit owner cancellation/deadline/revocation stopped the storage operation.
    Cancelled,
    /// Independent replay/storage deadline expired.
    Deadline,
    /// Current operation clock regressed; no source was consumed.
    ClockReversed,
    /// A prior replay error stopped this attempt.
    Stopped,
    /// Existing publisher error, including its original indeterminate outcome.
    Publication(LocalPublicationError),
    /// Original source read/verification error.
    Spool(SpoolError),
    /// Cooperative work/cancellation refusal.
    Work(GeometryError),
}
impl std::fmt::Debug for DatagramArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Publication(e) => f.debug_tuple("Publication").field(&e.code()).finish(),
            Self::Spool(_) => f.write_str("Spool"), Self::Work(e) => f.debug_tuple("Work").field(e).finish(),
            Self::Configuration => f.write_str("Configuration"), Self::Source => f.write_str("Source"),
            Self::Sequence => f.write_str("Sequence"), Self::Metadata => f.write_str("Metadata"),
            Self::Limit => f.write_str("Limit"), Self::NotDurable => f.write_str("NotDurable"),
            Self::Tombstoned => f.write_str("Tombstoned"), Self::Cancelled => f.write_str("Cancelled"),
            Self::Deadline => f.write_str("Deadline"), Self::ClockReversed => f.write_str("ClockReversed"),
            Self::Stopped => f.write_str("Stopped"),
        }
    }
}
impl std::fmt::Display for DatagramArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RTSP datagram custody refused: {self:?}")
    }
}
impl std::error::Error for DatagramArchiveError {}
impl From<GeometryError> for DatagramArchiveError {
    fn from(e: GeometryError) -> Self { Self::Work(e) }
}
type Result<T> = std::result::Result<T, DatagramArchiveError>;

/// One immutable observation; ordinal is arrival order, not a deduplicated RTP sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatagramRecord {
    /// Exact preceding source prefix.
    pub prior: DatagramPin,
    /// Exact post-observation source prefix.
    pub pin: DatagramPin,
    /// Original interleaved channel, without reclassifying payload syntax.
    pub channel: u8,
    /// Existing parser-completion receive timestamp.
    pub received_ns: u64,
    /// Original payload content identity, including headers and padding.
    pub payload_digest: ContentDigest,
    /// Original payload length. Zero-byte malformed datagrams are retained too.
    pub payload_bytes: usize,
}
impl DatagramRecord {
    fn metadata(&self) -> Result<Vec<u8>> {
        let mut e = CanonicalEncoder::new(); e.text(DOMAIN);
        e.digest(self.prior.scope); e.digest(self.prior.head);
        e.u64(self.prior.datagrams); e.u64(self.prior.payload_bytes);
        e.tag(self.channel); e.u64(self.received_ns);
        e.digest(self.payload_digest); e.u64(self.payload_bytes as u64);
        e.finish_checked().map_err(|_| DatagramArchiveError::Metadata)
    }
    fn manifest(&self) -> Result<ObjectManifest> {
        ObjectManifest::new(RTSP_DATAGRAM_KIND, [self.payload_digest],
            Some(ContentDigest::sha256(&self.metadata()?))).map_err(|_| DatagramArchiveError::Metadata)
    }
    fn decode(bytes: &[u8], root: ContentDigest) -> Result<Self> {
        let decode = || -> std::result::Result<Self, fss_core::ContractError> {
            let mut d = CanonicalDecoder::new(bytes);
            if d.text()? != DOMAIN { return Err(fss_core::ContractError::InvalidIdentifier); }
            let prior = DatagramPin { scope: d.digest()?, head: d.digest()?, datagrams: d.u64()?, payload_bytes: d.u64()? };
            let channel = d.tag()?; let received_ns = d.u64()?; let payload_digest = d.digest()?;
            let count = d.u64()?;
            let payload_bytes = usize::try_from(count).map_err(|_| fss_core::ContractError::ArithmeticOverflow)?;
            let pin = DatagramPin { scope: prior.scope, head: root,
                datagrams: prior.datagrams.checked_add(1).ok_or(fss_core::ContractError::ArithmeticOverflow)?,
                payload_bytes: prior.payload_bytes.checked_add(count).ok_or(fss_core::ContractError::ArithmeticOverflow)? };
            d.ensure_finished()?;
            Ok(Self { prior, pin, channel, received_ns, payload_digest, payload_bytes })
        };
        let record = decode().map_err(|_| DatagramArchiveError::Metadata)?;
        if record.metadata()? != bytes || [record.prior.scope, record.prior.head, record.payload_digest, root]
            .iter().any(|d| d.algorithm() != DigestAlgorithm::Sha256) { return Err(DatagramArchiveError::Metadata); }
        Ok(record)
    }
}

/// Borrowed immutable source publication. Reuse THIS plan for an exact retry.
/// Preparing another identical datagram deliberately assigns another observation ordinal.
#[must_use]
pub struct PreparedDatagram<'a> {
    record: DatagramRecord, bytes: &'a [u8], metadata: Vec<u8>, manifest: ObjectManifest, slot: SlotName,
}
impl PreparedDatagram<'_> {
    /// Candidate prefix to retain independently before attempting publication.
    pub fn pin(&self) -> DatagramPin { self.record.pin }
    /// Deterministic route, unchanged across exact retries.
    pub fn slot(&self) -> &SlotName { &self.slot }
}
/// Original protocol observation and actual local publication receipt.
#[derive(Debug)]
pub struct DatagramPublication {
    /// Complete exact original observation.
    pub record: DatagramRecord,
    /// Existing root-last receipt; other storage claims are not promoted.
    pub local: LocalPublicationReceipt,
}
/// Reverified payload from one exact observation. Debug never includes its contents.
pub struct RetainedDatagram { record: DatagramRecord, bytes: Vec<u8> }
impl RetainedDatagram {
    /// Original channel, receive timestamp, identity and prefix position.
    pub fn record(&self) -> DatagramRecord { self.record }
    /// Original datagram, not reconstructed NALs or decoded pixels.
    pub fn payload(&self) -> &[u8] { &self.bytes }
}
impl std::fmt::Debug for RetainedDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedDatagram").field("record", &self.record).finish_non_exhaustive()
    }
}

/// Source-only inventory over an explicitly supplied exclusive publisher. No payload cache,
/// recursive historical root traversal, alternate media journal or automatic source deletion.
#[derive(Debug)]
pub struct DatagramArchive {
    scope: DatagramScope, limits: DatagramArchiveLimits, empty: DatagramPin, prefix: String,
    records: Vec<DatagramRecord>,
}
impl DatagramArchive {
    /// Empty in-memory declaration; publication still checks the actual owner's namespace.
    pub fn new(scope: DatagramScope, limits: DatagramArchiveLimits) -> Result<Self> {
        limits.validate()?;
        let digest = scope.digest()?; let prefix = scope.prefix()?;
        Ok(Self { scope, limits, empty: DatagramPin { scope: digest, head: digest, datagrams: 0, payload_bytes: 0 },
            prefix, records: Vec::new() })
    }
    /// Exact source/route/retention interpretation.
    pub fn scope(&self) -> &DatagramScope { &self.scope }
    /// Complete recovered observation metadata in arrival order; not current retrieval proof.
    pub fn records(&self) -> &[DatagramRecord] { &self.records }
    /// Last acknowledged prefix. This does not assert clean EOF or complete camera coverage.
    pub fn pin(&self) -> DatagramPin { self.records.last().map_or(self.empty, |r| r.pin) }
    /// Recover the complete currently durable namespace, rehashing every source object.
    /// A minimum pin rejects rollback/forks below that exact prefix; accepted descendants
    /// are explicit. Without it, trust rests in the protected publisher's local inventory.
    /// Missing/intermediate roots, malformed slots and unresolved temporaries are not skipped.
    pub fn recover(p: &LocalRootPublisher, scope: DatagramScope, limits: DatagramArchiveLimits,
        minimum: Option<DatagramPin>, cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>) -> Result<Self> {
        let mut a = Self::new(scope, limits)?;
        let roots = a.inventory(p, cancel, budget)?;
        a.records.try_reserve_exact(roots.len()).map_err(|_| DatagramArchiveError::Limit)?;
        for (slot, root) in roots {
            let retained = a.read_root(p, &slot, root, cancel, budget)?;
            a.validate_next(retained.record)?;
            a.records.push(retained.record);
        }
        if let Some(pin) = minimum {
            let found = if pin.datagrams == 0 { Some(a.empty) }
                else { usize::try_from(pin.datagrams - 1).ok().and_then(|i| a.records.get(i)).map(|r| r.pin) };
            if found != Some(pin) { return Err(DatagramArchiveError::Sequence); }
        }
        probe(cancel)?; budget.charge(0)?; Ok(a)
    }
    /// Prepare one actual opaque interleaved source, including malformed/probation packets.
    /// Never supply authentication or RTSP control-message bytes through this interface.
    pub fn prepare<'a>(&self, source: &'a InterleavedSource, budget: &mut WorkBudget<'_>) -> Result<PreparedDatagram<'a>> {
        self.prepare_bytes(source.channel(), source.received_ns(), source.payload(), budget)
    }
    fn prepare_bytes<'a>(&self, channel: u8, received_ns: u64, bytes: &'a [u8],
        budget: &mut WorkBudget<'_>) -> Result<PreparedDatagram<'a>> {
        if bytes.len() > MAX_DATAGRAM_BYTES { return Err(DatagramArchiveError::Limit); }
        budget.charge(1024 + bytes.len() as u64 * 2)?;
        let prior = self.pin();
        let mut record = DatagramRecord { prior, pin: DatagramPin { scope: prior.scope, head: prior.head,
            datagrams: prior.datagrams + 1, payload_bytes: prior.payload_bytes + bytes.len() as u64 },
            channel, received_ns, payload_digest: ContentDigest::sha256(bytes), payload_bytes: bytes.len() };
        self.validate_next(record)?;
        let metadata = record.metadata()?; let manifest = record.manifest()?; record.pin.head = manifest.root();
        let slot = self.slot(record.pin.datagrams)?;
        budget.charge(0)?;
        Ok(PreparedDatagram { record, bytes, metadata, manifest, slot })
    }
    /// Persist original payload first, then metadata and the root. Publication uncertainty
    /// preserves the unchanged plan/index and the publisher's typed error. There is no retry
    /// on a poisoned owner. Only a successful durable receipt advances the source prefix.
    pub fn publish(&mut self, plan: &PreparedDatagram<'_>, p: &mut LocalRootPublisher,
        cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>) -> Result<DatagramPublication> {
        let retry = self.records.last() == Some(&plan.record);
        if !retry { self.validate_next(plan.record)?; }
        if plan.record.prior.scope != self.empty.scope || plan.slot != self.slot(plan.pin().datagrams)? {
            return Err(DatagramArchiveError::Source);
        }
        let roots = self.inventory(p, cancel, budget)?;
        if roots.len() < self.records.len() || roots.len() > plan.pin().datagrams as usize {
            return Err(DatagramArchiveError::Sequence);
        }
        for (i, (slot, root)) in roots.iter().enumerate() {
            let expected = self.records.get(i).unwrap_or(&plan.record);
            if *root != expected.pin.head || *slot != self.slot(expected.pin.datagrams)? {
                return Err(DatagramArchiveError::Sequence);
            }
        }
        self.records.try_reserve(usize::from(!retry)).map_err(|_| DatagramArchiveError::Limit)?;
        budget.charge(4096 + plan.bytes.len() as u64 * 8 + p.limits().max_tombstones as u64 * 3)?;
        if p.tombstones().any(|d| *d == plan.pin().head || plan.manifest.children().contains(d)) {
            return Err(DatagramArchiveError::Tombstoned);
        }
        probe(cancel)?;
        if p.stage_object(plan.bytes).map_err(DatagramArchiveError::Publication)? != plan.record.payload_digest {
            return Err(DatagramArchiveError::Metadata);
        }
        probe(cancel)?;
        if p.stage_object(&plan.metadata).map_err(DatagramArchiveError::Publication)? != ContentDigest::sha256(&plan.metadata) {
            return Err(DatagramArchiveError::Metadata);
        }
        probe(cancel)?; budget.charge(0)?;
        let local = p.publish_cancellable(&plan.slot, &plan.manifest, cancel).map_err(DatagramArchiveError::Publication)?;
        if local.root != plan.pin().head || local.claims.local != LocalPublicationState::Durable {
            return Err(DatagramArchiveError::NotDurable);
        }
        if !retry { self.records.push(plan.record); }
        Ok(DatagramPublication { record: plan.record, local })
    }
    /// Read one complete observation, revalidating its root, metadata and original bytes.
    /// Out-of-range is an error, NOT an end-of-stream or physical-absence assertion.
    pub fn read(&self, ordinal: u64, p: &LocalRootPublisher, cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>) -> Result<RetainedDatagram> {
        let i = ordinal.checked_sub(1).and_then(|n| usize::try_from(n).ok()).ok_or(DatagramArchiveError::Sequence)?;
        let expected = self.records.get(i).ok_or(DatagramArchiveError::Sequence)?;
        let retained = self.read_root(p, &self.slot(ordinal)?, expected.pin.head, cancel, budget)?;
        if retained.record != *expected { return Err(DatagramArchiveError::Metadata); }
        probe(cancel)?; budget.charge(0)?; Ok(retained)
    }
    fn validate_next(&self, r: DatagramRecord) -> Result<()> {
        if r.prior != self.pin() || r.pin.scope != self.empty.scope
            || r.pin.datagrams != r.prior.datagrams + 1
            || r.pin.payload_bytes != r.prior.payload_bytes.checked_add(r.payload_bytes as u64).ok_or(DatagramArchiveError::Limit)? {
            return Err(DatagramArchiveError::Sequence);
        }
        if ![self.scope.channels.0, self.scope.channels.1].contains(&r.channel)
            || self.records.last().is_some_and(|p| r.received_ns < p.received_ns) {
            return Err(DatagramArchiveError::Source);
        }
        if r.payload_bytes > MAX_DATAGRAM_BYTES || self.records.len() == self.limits.max_datagrams
            || r.pin.payload_bytes > self.limits.max_payload_bytes { return Err(DatagramArchiveError::Limit); }
        Ok(())
    }
    fn slot(&self, ordinal: u64) -> Result<SlotName> {
        SlotName::parse(&format!("{}{:08x}", self.prefix, ordinal)).map_err(|_| DatagramArchiveError::Metadata)
    }
    fn ready(&self, p: &LocalRootPublisher) -> Result<()> {
        if p.is_poisoned() { return Err(DatagramArchiveError::NotDurable); }
        if p.limits().spool.max_object_bytes > self.limits.max_spool_object_bytes { return Err(DatagramArchiveError::Limit); }
        Ok(())
    }
    fn inventory(&self, p: &LocalRootPublisher, cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>) -> Result<Vec<(SlotName, ContentDigest)>> {
        self.ready(p)?;
        let mut count = 0;
        let mut scan = || -> Result<()> {
            probe(cancel)?; budget.charge(128)?; count += 1;
            if count > self.limits.max_scan_roots { return Err(DatagramArchiveError::Limit); } Ok(())
        };
        let mut roots = Vec::new();
        for root in p.visible_roots() {
            scan()?;
            if let Some(tail) = root.slot.as_str().strip_prefix(&self.prefix) {
                let n = u64::from_str_radix(tail, 16).map_err(|_| DatagramArchiveError::Sequence)?;
                if n == 0 || n > self.limits.max_datagrams as u64 || root.slot != self.slot(n)?
                    || root.state != LocalPublicationState::Durable { return Err(DatagramArchiveError::Sequence); }
                if roots.len() == self.limits.max_datagrams { return Err(DatagramArchiveError::Limit); }
                roots.try_reserve(1).map_err(|_| DatagramArchiveError::Limit)?;
                roots.push((root.slot.clone(), root.root));
            }
        }
        for slot in p.broken_slots() {
            scan()?; if slot.as_str().starts_with(&self.prefix) { return Err(DatagramArchiveError::NotDurable); }
        }
        let report = p.recovery_report();
        for path in report.orphaned_temps.iter().chain(report.foreign.iter()).chain(report.broken_roots.iter().map(|b| &b.path)) {
            scan()?;
            if path.file_name().is_some_and(|n| n.as_encoded_bytes().starts_with(self.prefix.as_bytes())) {
                return Err(DatagramArchiveError::NotDurable);
            }
        }
        roots.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        for (i, (slot, _)) in roots.iter().enumerate() {
            if *slot != self.slot(i as u64 + 1)? { return Err(DatagramArchiveError::Sequence); }
        }
        Ok(roots)
    }
    fn read_root(&self, p: &LocalRootPublisher, slot: &SlotName, root: ContentDigest,
        cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>) -> Result<RetainedDatagram> {
        self.ready(p)?;
        if p.is_broken_slot(slot) || p.root(slot).is_none_or(|r| r.root != root || r.state != LocalPublicationState::Durable) {
            return Err(DatagramArchiveError::NotDurable);
        }
        let raw = self.object(p, root, 1024, cancel, budget)?;
        let manifest = ObjectManifest::from_canonical_bytes(&raw).map_err(|_| DatagramArchiveError::Metadata)?;
        if manifest.root() != root || manifest.kind() != RTSP_DATAGRAM_KIND { return Err(DatagramArchiveError::Metadata); }
        let metadata = self.object(p, manifest.metadata_digest().ok_or(DatagramArchiveError::Metadata)?, MAX_METADATA, cancel, budget)?;
        let record = DatagramRecord::decode(&metadata, root)?;
        if record.payload_bytes > MAX_DATAGRAM_BYTES || record.manifest()? != manifest
            || record.prior.scope != self.empty.scope || record.pin.datagrams > self.limits.max_datagrams as u64
            || record.pin.payload_bytes > self.limits.max_payload_bytes || *slot != self.slot(record.pin.datagrams)? {
            return Err(DatagramArchiveError::Metadata);
        }
        let bytes = self.object(p, record.payload_digest, MAX_DATAGRAM_BYTES, cancel, budget)?;
        if bytes.len() != record.payload_bytes { return Err(DatagramArchiveError::Source); }
        Ok(RetainedDatagram { record, bytes })
    }
    fn object(&self, p: &LocalRootPublisher, root: ContentDigest, maximum: usize,
        cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>) -> Result<Vec<u8>> {
        self.ready(p)?; probe(cancel)?;
        budget.charge(p.limits().spool.max_object_bytes as u64 * 3 + p.limits().max_tombstones as u64 + 1)?;
        if p.tombstones().any(|d| *d == root) { return Err(DatagramArchiveError::Tombstoned); }
        let bytes = p.spool().read(root).map_err(DatagramArchiveError::Spool)?;
        if bytes.len() > maximum { return Err(DatagramArchiveError::Limit); }
        probe(cancel)?; budget.charge(0)?; Ok(bytes)
    }
}

/// One verified source observation or explicit exhaustion of a retained prefix.
#[derive(Debug)]
#[must_use]
pub enum DatagramReplayStep {
    /// Original datagram with its original channel/time; no live network effect.
    Datagram(RetainedDatagram),
    /// All named source observations were read. This is NOT TCP/codec EOF: do not
    /// use it to flush an incomplete picture or assert complete stream coverage.
    PrefixExhausted(DatagramPin),
    /// PrefixExhausted already returned once; no repeat read or completion receipt.
    Ended,
}
/// Whole-prefix replay with independent output and storage-time bounds. Later source
/// corruption stops replay rather than returning an apparently complete prefix.
pub struct DatagramReplay<'a> {
    archive: &'a DatagramArchive, publisher: &'a LocalRootPublisher,
    next: u64, deadline_ns: u64, last_ns: u64, stopped: bool, done: bool,
}
impl<'a> DatagramReplay<'a> {
    /// Borrow one immutable recovered inventory. This does not initialize a codec or
    /// restore its SPS/PPS, grants, clocks, timing decisions, or remote session.
    pub fn new(archive: &'a DatagramArchive, publisher: &'a LocalRootPublisher,
        max_output_bytes: u64, now_ns: u64, deadline_ns: u64) -> Result<Self> {
        archive.ready(publisher)?;
        if now_ns >= deadline_ns { return Err(DatagramArchiveError::Deadline); }
        if archive.pin().payload_bytes > max_output_bytes {
            return Err(DatagramArchiveError::Limit);
        }
        Ok(Self { archive, publisher, next: 1, deadline_ns, last_ns: now_ns, stopped: false, done: false })
    }
    /// Reverify at most one original datagram. Storage/cancellation failure stops this
    /// attempt; create a newly authorized replay instead of retrying through an error.
    pub fn step(&mut self, now_ns: u64, cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>) -> Result<DatagramReplayStep> {
        if self.done { return Ok(DatagramReplayStep::Ended); }
        if self.stopped { return Err(DatagramArchiveError::Stopped); }
        if now_ns < self.last_ns { return Err(DatagramArchiveError::ClockReversed); }
        self.last_ns = now_ns;
        let result = (|| {
            if now_ns >= self.deadline_ns { return Err(DatagramArchiveError::Deadline); }
            probe(cancel)?; budget.charge(1)?;
            if self.next > self.archive.pin().datagrams {
                self.done = true;
                return Ok(DatagramReplayStep::PrefixExhausted(self.archive.pin()));
            }
            let datagram = self.archive.read(self.next, self.publisher, cancel, budget)?;
            self.next += 1;
            Ok(DatagramReplayStep::Datagram(datagram))
        })();
        if result.is_err() { self.stopped = true; }
        result
    }
}

fn hash_encoder(e: CanonicalEncoder) -> Result<ContentDigest> {
    Ok(ContentDigest::sha256(&e.finish_checked().map_err(|_| DatagramArchiveError::Metadata)?))
}
fn probe(cancel: &dyn PublishCancellation) -> Result<()> {
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) { Err(DatagramArchiveError::Cancelled) } else { Ok(()) }
}

#[cfg(test)]
mod tests;
