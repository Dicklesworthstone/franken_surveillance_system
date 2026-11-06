#![forbid(unsafe_code)]
//! Explicitly authorized, ledgered publication of prepared FLV source evidence.
//! Capture bounds must be independently established, not inferred from network
//! arrival or the camera's media clock. No implicit policy grants exist here.

use std::fmt;

use fss_core::{CanonicalDecoder, CaptureInterval, ContentDigest, DigestAlgorithm, TimestampNs};
use fss_geometry::{GeometryError, WorkBudget};
use fss_object::ObjectManifest;
use fss_packet::extended_flv::stream::SearchMode;
use fss_publication::{
    PublishCancellation, PublishCutPoint, RootLedgerReceipt, RootLedgerState, SlotName,
};

use super::{
    av_evidence::{self, AudioConfigurationOrigin, PreparedAv},
    evidence::{DOMAIN, KIND, Prepared},
};
use crate::{ReferenceDeployment, ReplayCx, reference_deployment::ReplayCancellationBridge};

/// Revalidated authority to retain original camera bytes under the exact scope.
pub trait RetainAuthority {
    /// This digest identifies a decision; the implementation must check current
    /// principal, policy, retention and capability rather than trusting the digest.
    fn permits(&self, retention: ContentDigest, root: ContentDigest) -> bool;
}

/// Current permission to disclose original camera bytes for one retained graph.
pub trait ReadAuthority {
    /// Implementations must revalidate the current principal, privacy and policy.
    fn permits(&self, retention: ContentDigest, root: ContentDigest) -> bool;
}

/// Immutable caller-retained identities needed to reopen one ledgered graph.
/// This pin is not a receipt and does not grant access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pin {
    /// Canonical manifest root.
    pub root: ContentDigest,
    /// Retention decision identity encoded into graph metadata.
    pub retention: ContentDigest,
    /// Caller-established physical capture interval encoded into graph metadata.
    pub capture: CaptureInterval,
}
impl Pin {
    /// Obtain a candidate pin only if physical capture bounds were supplied.
    pub fn from_plan(plan: &Prepared<'_>) -> Option<Self> {
        Some(Self {
            root: plan.manifest().root(),
            retention: plan.retention(),
            capture: plan.capture()?,
        })
    }
    /// Obtain an A/V graph pin only when physical capture bounds were supplied.
    pub fn from_av_plan(plan: &PreparedAv<'_>) -> Option<Self> {
        Some(Self {
            root: plan.manifest().root(),
            retention: plan.retention(),
            capture: plan.capture()?,
        })
    }
    fn slot(self) -> Result<SlotName, Error> {
        for digest in [self.root, self.retention] {
            if digest.algorithm() != DigestAlgorithm::Sha256
                || digest.is_laboratory()
                || digest.bytes() == [0; 32]
            {
                return Err(Error::Mismatch);
            }
        }
        if self.capture.earliest > self.capture.latest {
            return Err(Error::Mismatch);
        }
        slot_for_root(self.root)
    }
}

/// Payload-free publication refusal. A storage failure can be indeterminate;
/// reconcile the exact same root and slot before trying a new publication.
#[derive(Debug)]
pub enum Error {
    /// The current original-byte policy denied retention.
    Denied,
    /// No independently justified capture bounds were provided.
    UnknownCapture,
    /// A source, graph, retention or publisher limit was exceeded.
    Limit,
    /// No durable, ledgered root matches the supplied pin.
    NotCommitted,
    /// A deletion tombstone prohibits resurrection.
    Tombstoned,
    /// The operation's owner cancelled.
    Cancelled,
    /// A staged payload differed from its expected content address.
    Mismatch,
    /// Work accounting refused the operation.
    Work(GeometryError),
    /// Existing publication, ledger, or storage failure; it can be indeterminate.
    Storage(Box<dyn std::error::Error>),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Denied => "FLV original-byte retention denied",
            Self::UnknownCapture => "FLV physical capture bounds unavailable",
            Self::Limit => "FLV archive publication limit exceeded",
            Self::NotCommitted => "FLV archive root is not durably ledgered",
            Self::Tombstoned => "FLV archive object tombstoned",
            Self::Cancelled => "FLV archive owner cancelled",
            Self::Mismatch => "FLV archive content mismatch",
            Self::Work(_) => "FLV archive work budget exhausted",
            Self::Storage(_) => "FLV archive storage or publication failed",
        })
    }
}
impl std::error::Error for Error {}
impl From<GeometryError> for Error {
    fn from(e: GeometryError) -> Self {
        Self::Work(e)
    }
}
fn storage<E: std::error::Error + 'static>(error: E) -> Error {
    Error::Storage(Box::new(error))
}

/// Bounds independent of bytes stored in the prepared evidence.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum configured spool object allocation; at most 64 MiB.
    pub maximum_spool_object_bytes: usize,
    /// Maximum ledger deltas inspected; at most 262,144.
    pub maximum_ledger_deltas: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            maximum_spool_object_bytes: 64 * 1024 * 1024,
            maximum_ledger_deltas: 65_536,
        }
    }
}

/// Deterministic immutable root slot. The returned name is not a receipt.
pub fn slot(plan: &Prepared<'_>) -> Result<SlotName, Error> {
    slot_for_root(plan.manifest().root())
}
fn slot_for_root(root: ContentDigest) -> Result<SlotName, Error> {
    let hex: String = root.bytes().iter().map(|b| format!("{b:02x}")).collect();
    SlotName::parse(&format!("uflv1-{hex}")).map_err(storage)
}

/// Stage exact source objects first, then publish and ledger the prepared root.
/// Retry the same plan after an indeterminate result. A successful return is
/// the underlying publisher's actual receipt, not an assertion of decode or
/// device authenticity. Individual spool objects are not encrypted here.
pub fn publish(
    plan: &Prepared<'_>,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RootLedgerReceipt, Error> {
    publish_graph(plan, deployment, authority, limits, work, cx)
}

/// Publish an A/V evidence graph under the same retention and ledger gates.
/// This does not establish synchronization, decoding, identity or coverage.
pub fn publish_av(
    plan: &PreparedAv<'_>,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RootLedgerReceipt, Error> {
    publish_graph(plan, deployment, authority, limits, work, cx)
}

trait Graph {
    fn manifest(&self) -> &ObjectManifest;
    fn capture(&self) -> Option<CaptureInterval>;
    fn retention(&self) -> ContentDigest;
    fn payloads(&self) -> Box<dyn Iterator<Item = &[u8]> + '_>;
}
impl Graph for Prepared<'_> {
    fn manifest(&self) -> &ObjectManifest {
        self.manifest()
    }
    fn capture(&self) -> Option<CaptureInterval> {
        self.capture()
    }
    fn retention(&self) -> ContentDigest {
        self.retention()
    }
    fn payloads(&self) -> Box<dyn Iterator<Item = &[u8]> + '_> {
        Box::new(self.payloads())
    }
}
impl Graph for PreparedAv<'_> {
    fn manifest(&self) -> &ObjectManifest {
        self.manifest()
    }
    fn capture(&self) -> Option<CaptureInterval> {
        self.capture()
    }
    fn retention(&self) -> ContentDigest {
        self.retention()
    }
    fn payloads(&self) -> Box<dyn Iterator<Item = &[u8]> + '_> {
        Box::new(self.payloads())
    }
}

fn publish_graph(
    plan: &impl Graph,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RootLedgerReceipt, Error> {
    let capture = plan.capture().ok_or(Error::UnknownCapture)?;
    authorize(plan, authority, cx)?;
    if !(1024..=64 * 1024 * 1024).contains(&limits.maximum_spool_object_bytes)
        || !(1..=262_144).contains(&limits.maximum_ledger_deltas)
        || deployment.publisher().limits().spool.max_object_bytes
            > limits.maximum_spool_object_bytes
        || deployment.publisher().is_poisoned()
    {
        return Err(Error::Limit);
    }
    let mut deltas = 0usize;
    for batch in deployment.ledger().batches() {
        work.charge(1 + batch.deltas.len() as u64)?;
        deltas = deltas.checked_add(batch.deltas.len()).ok_or(Error::Limit)?;
        if deltas > limits.maximum_ledger_deltas {
            return Err(Error::Limit);
        }
    }
    work.charge(deployment.publisher().limits().spool.max_object_bytes as u64 * 4)?;
    for digest in plan
        .manifest()
        .children()
        .iter()
        .copied()
        .chain([plan.manifest().root()])
    {
        work.charge(deployment.publisher().limits().max_tombstones as u64 + 1)?;
        if deployment.publisher().tombstones().any(|v| *v == digest) {
            return Err(Error::Tombstoned);
        }
    }
    let object_ceiling = deployment.publisher().limits().spool.max_object_bytes;
    if plan.payloads().any(|bytes| bytes.len() > object_ceiling) {
        return Err(Error::Limit);
    }
    for bytes in plan.payloads() {
        authorize(plan, authority, cx)?;
        work.charge((bytes.len() as u64).checked_mul(3).ok_or(Error::Limit)?)?;
        if deployment.stage_payload(bytes).map_err(storage)? != ContentDigest::sha256(bytes) {
            return Err(Error::Mismatch);
        }
    }
    let gate = Gate {
        plan,
        authority,
        cx,
    };
    deployment
        .ledgered_publisher()
        .publish_and_commit_cancellable(
            &slot_for_root(plan.manifest().root())?,
            plan.manifest(),
            capture,
            &gate,
        )
        .map_err(storage)
}

fn authorize(plan: &impl Graph, auth: &dyn RetainAuthority, cx: &ReplayCx) -> Result<(), Error> {
    cx.checkpoint("unifi-flv-archive:authority")
        .map_err(|_| Error::Cancelled)?;
    if !auth.permits(plan.retention(), plan.manifest().root()) {
        return Err(Error::Denied);
    }
    Ok(())
}
struct Gate<'a, G> {
    plan: &'a G,
    authority: &'a dyn RetainAuthority,
    cx: &'a ReplayCx,
}
impl<G: Graph> PublishCancellation for Gate<'_, G> {
    fn cancel_requested(&self, point: PublishCutPoint) -> bool {
        ReplayCancellationBridge(self.cx).cancel_requested(point)
            || !self
                .authority
                .permits(self.plan.retention(), self.plan.manifest().root())
    }
}

/// Read one direct child of an independently pinned, durably ledgered graph.
/// The root and metadata are verified before the requested object is disclosed.
/// This does not reconstruct the segment, replay its source mappings, prove
/// capture time, or authenticate the camera. Caller-selected limits cannot
/// expand the attached spool's configured maximum object allocation.
pub fn read_object(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    object: ContentDigest,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>, Error> {
    let (manifest, _) = open_graph(deployment, pin, authority, limits, work, cx)?;
    require_child(&manifest, object, work)?;
    read_part(deployment, pin, object, authority, work, cx)
}

/// Read a child of a ledgered A/V graph. This verifies the graph's authority,
/// content addresses and prefix, but does not replay media mappings or decode.
pub fn read_av_object(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    object: ContentDigest,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>, Error> {
    let (manifest, _) = open_graph_kind(
        deployment,
        pin,
        authority,
        limits,
        work,
        cx,
        av_evidence::KIND,
        av_evidence::DOMAIN,
    )?;
    require_child(&manifest, object, work)?;
    read_part(deployment, pin, object, authority, work, cx)
}

fn require_child(
    manifest: &ObjectManifest,
    child: ContentDigest,
    work: &mut WorkBudget<'_>,
) -> Result<(), Error> {
    work.charge(u64::from(usize::BITS) + 1)?;
    if manifest.children().binary_search(&child).is_err() {
        return Err(Error::Mismatch);
    }
    Ok(())
}

/// Verified graph-local AAC configuration classification. An in-band record
/// and claimed epoch still do not authenticate the camera or shared epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvAudioConfiguration {
    /// Whether a source record was retained or the codec bytes were supplied.
    pub origin: AudioConfigurationOrigin,
    /// Content identity of the exact two configuration bytes.
    pub digest: ContentDigest,
    /// Claimed track-local epoch, present only with an in-band record.
    pub claimed_epoch: Option<u64>,
}

/// Reopen the A/V configuration classification and verify its bytes. For an
/// in-band configuration this also verifies the original FLV record and exact
/// byte range. This does not validate all mappings, identity or A/V timing.
pub fn read_av_audio_configuration(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<AvAudioConfiguration, Error> {
    use fss_packet::extended_flv::{self, Parse, Tag, aac};

    let (manifest, metadata) = open_graph_kind(
        deployment,
        pin,
        authority,
        limits,
        work,
        cx,
        av_evidence::KIND,
        av_evidence::DOMAIN,
    )?;
    work.charge(metadata.len() as u64 * 4)?;
    let mut d = CanonicalDecoder::new(&metadata);
    check_prefix_kind(&mut d, pin, av_evidence::DOMAIN)?;
    let video_root = d.digest().map_err(storage)?;
    require_child(&manifest, video_root, work)?;
    let (origin, claimed_epoch, source) = match d.u8().map_err(storage)? {
        0 => {
            let epoch = d.u64().map_err(storage)?;
            let entry = record(&mut d, limits.maximum_spool_object_bytes)?;
            let start = d.u64().map_err(storage)?;
            let end = d.u64().map_err(storage)?;
            if epoch == 0 || start >= end {
                return Err(Error::Mismatch);
            }
            require_child(&manifest, entry.digest, work)?;
            (
                AudioConfigurationOrigin::InBand,
                Some(epoch),
                Some((entry, start..end)),
            )
        }
        1 => (AudioConfigurationOrigin::SuppliedUnverified, None, None),
        _ => return Err(Error::Mismatch),
    };
    let digest = d.digest().map_err(storage)?;
    require_child(&manifest, digest, work)?;
    let bytes = read_part_bounded(deployment, pin, digest, 2, authority, work, cx)?;
    aac::Configuration::parse_explicit(&bytes).map_err(storage)?;
    if let Some((entry, range)) = source {
        let source_bytes = checked_record_bytes(deployment, pin, &entry, authority, work, cx)?;
        let (tag_offset, kind, timestamp) = entry.tag.ok_or(Error::Mismatch)?;
        let tag_bytes = source_bytes.get(tag_offset..).ok_or(Error::Mismatch)?;
        let Parse::Complete(tag) =
            Tag::parse(tag_bytes, extended_flv::Limits::default()).map_err(storage)?
        else {
            return Err(Error::Mismatch);
        };
        if kind != 8
            || tag.kind() != kind
            || tag.timestamp_ms() != timestamp
            || tag.wire_bytes().len() != tag_bytes.len()
        {
            return Err(Error::Mismatch);
        }
        let audio = aac::AudioTag::parse(tag, aac::Limits::default()).map_err(storage)?;
        if audio.packet_type() != aac::PacketType::Configuration || audio.body() != bytes {
            return Err(Error::Mismatch);
        }
        let body = audio.body_range();
        let start = entry
            .offset
            .checked_add(tag_offset as u64)
            .and_then(|offset| offset.checked_add(body.start as u64))
            .ok_or(Error::Limit)?;
        let end = entry
            .offset
            .checked_add(tag_offset as u64)
            .and_then(|offset| offset.checked_add(body.end as u64))
            .ok_or(Error::Limit)?;
        if range != (start..end) {
            return Err(Error::Mismatch);
        }
    }
    read_authorize(pin, authority, cx)?;
    Ok(AvAudioConfiguration {
        origin,
        digest,
        claimed_epoch,
    })
}

fn open_graph(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<(ObjectManifest, Vec<u8>), Error> {
    open_graph_kind(deployment, pin, authority, limits, work, cx, KIND, DOMAIN)
}

fn open_graph_kind(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    kind: &str,
    domain: &str,
) -> Result<(ObjectManifest, Vec<u8>), Error> {
    read_authorize(pin, authority, cx)?;
    if !(1024..=64 * 1024 * 1024).contains(&limits.maximum_spool_object_bytes)
        || !(1..=262_144).contains(&limits.maximum_ledger_deltas)
        || deployment.publisher().limits().spool.max_object_bytes
            > limits.maximum_spool_object_bytes
        || deployment.publisher().is_poisoned()
    {
        return Err(Error::Limit);
    }
    let mut count = 0usize;
    for batch in deployment.ledger().batches() {
        work.charge(1 + batch.deltas.len() as u64)?;
        count = count.checked_add(batch.deltas.len()).ok_or(Error::Limit)?;
        if count > limits.maximum_ledger_deltas {
            return Err(Error::Limit);
        }
    }
    work.charge(deployment.publisher().limits().spool.max_object_bytes as u64 * 4)?;
    match deployment
        .ledgered_publisher()
        .state(&pin.slot()?)
        .map_err(storage)?
    {
        RootLedgerState::Ledgered { root, .. } if root == pin.root => {}
        _ => return Err(Error::NotCommitted),
    }
    let root_bytes = read_part(deployment, pin, pin.root, authority, work, cx)?;
    let manifest = ObjectManifest::from_canonical_bytes(&root_bytes).map_err(storage)?;
    if manifest.root() != pin.root || manifest.kind() != kind {
        return Err(Error::Mismatch);
    }
    let metadata = manifest.metadata_digest().ok_or(Error::Mismatch)?;
    let metadata_bytes = read_part(deployment, pin, metadata, authority, work, cx)?;
    let mut decoder = CanonicalDecoder::new(&metadata_bytes);
    check_prefix_kind(&mut decoder, pin, domain)?;
    Ok((manifest, metadata_bytes))
}

fn check_prefix(decoder: &mut CanonicalDecoder<'_>, pin: Pin) -> Result<(), Error> {
    check_prefix_kind(decoder, pin, DOMAIN)
}
fn check_prefix_kind(
    decoder: &mut CanonicalDecoder<'_>,
    pin: Pin,
    domain: &str,
) -> Result<(), Error> {
    if decoder.text().map_err(storage)? != domain
        || decoder.digest().map_err(storage)? != pin.retention
        || !decoder.bool().map_err(storage)?
    {
        return Err(Error::Mismatch);
    }
    let capture = CaptureInterval::new(
        TimestampNs(decoder.i128().map_err(storage)?),
        TimestampNs(decoder.i128().map_err(storage)?),
    )
    .map_err(storage)?;
    if capture != pin.capture {
        return Err(Error::Mismatch);
    }
    Ok(())
}

fn read_authorize(pin: Pin, auth: &dyn ReadAuthority, cx: &ReplayCx) -> Result<(), Error> {
    cx.checkpoint("unifi-flv-archive:read-authority")
        .map_err(|_| Error::Cancelled)?;
    if !auth.permits(pin.retention, pin.root) {
        return Err(Error::Denied);
    }
    Ok(())
}
fn read_part(
    deployment: &ReferenceDeployment,
    pin: Pin,
    digest: ContentDigest,
    authority: &dyn ReadAuthority,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>, Error> {
    read_part_bounded(
        deployment,
        pin,
        digest,
        deployment.publisher().limits().spool.max_object_bytes,
        authority,
        work,
        cx,
    )
}

fn read_part_bounded(
    deployment: &ReferenceDeployment,
    pin: Pin,
    digest: ContentDigest,
    maximum_payload_bytes: usize,
    authority: &dyn ReadAuthority,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>, Error> {
    read_authorize(pin, authority, cx)?;
    if maximum_payload_bytes > deployment.publisher().limits().spool.max_object_bytes {
        return Err(Error::Limit);
    }
    work.charge(deployment.publisher().limits().max_tombstones as u64 + 1)?;
    if deployment
        .publisher()
        .tombstones()
        .any(|value| *value == digest)
    {
        return Err(Error::Tombstoned);
    }
    let read_bound = (fss_object::SPOOL_OBJECT_HEADER_LEN as u64)
        .checked_add(u64::try_from(maximum_payload_bytes).map_err(|_| Error::Limit)?)
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_mul(4))
        .ok_or(Error::Limit)?;
    work.charge(read_bound)?;
    let bytes = deployment
        .publisher()
        .spool()
        .read_bounded(digest, maximum_payload_bytes)
        .map_err(storage)?;
    if ContentDigest::sha256(&bytes) != digest {
        return Err(Error::Mismatch);
    }
    read_authorize(pin, authority, cx)?;
    Ok(bytes)
}

/// A recovered, source-checked AVC fragmented MP4. Its capture bounds are the
/// independently supplied bounds in the pin, not a clock inferred from video.
#[must_use]
pub struct RecoveredClip {
    bytes: Vec<u8>,
    capture: CaptureInterval,
    samples: usize,
}
impl RecoveredClip {
    /// Initialization segment followed by the validated media fragment.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Transfer the validated MP4 bytes to the authorized caller.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    /// Caller-supplied physical capture interval bound into the ledgered root.
    pub fn capture(&self) -> CaptureInterval {
        self.capture
    }
    /// Number of structurally validated AVC samples; not a decoder guarantee.
    pub fn samples(&self) -> usize {
        self.samples
    }
}
impl fmt::Debug for RecoveredClip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredClip")
            .field("bytes", &"<redacted>")
            .field("capture", &self.capture)
            .field("samples", &self.samples)
            .finish()
    }
}

#[derive(Clone)]
struct StoredRecord {
    offset: u64,
    length: usize,
    digest: ContentDigest,
    tag: Option<(usize, u8, u32)>,
}
struct StoredSample {
    start: usize,
    end: usize,
    decode: u64,
    composition: i128,
    duration: u32,
    idr: bool,
    first_nal: usize,
    end_nal: usize,
}
struct StoredNal {
    sample: usize,
    source_start: u64,
    source_end: u64,
    start: usize,
    end: usize,
}

fn read_size(decoder: &mut CanonicalDecoder<'_>, max: usize) -> Result<usize, Error> {
    let n = usize::try_from(decoder.u64().map_err(storage)?).map_err(|_| Error::Limit)?;
    if n > max {
        return Err(Error::Limit);
    }
    Ok(n)
}
fn record(decoder: &mut CanonicalDecoder<'_>, limit: usize) -> Result<StoredRecord, Error> {
    let offset = decoder.u64().map_err(storage)?;
    let length = read_size(decoder, limit)?;
    if length == 0 || offset.checked_add(length as u64).is_none() {
        return Err(Error::Mismatch);
    }
    let digest = decoder.digest().map_err(storage)?;
    let tag = match decoder.u8().map_err(storage)? {
        0 => None,
        1 => Some((
            0,
            decoder.u8().map_err(storage)?,
            decoder.u32().map_err(storage)?,
        )),
        2 => {
            let trailer = read_size(decoder, length)?;
            if trailer >= length {
                return Err(Error::Mismatch);
            }
            let kind = decoder.u8().map_err(storage)?;
            let timestamp = decoder.u32().map_err(storage)?;
            decoder.bool().map_err(storage)?;
            if decoder.bool().map_err(storage)? {
                return Err(Error::Mismatch);
            }
            if SearchMode::from_evidence_id(decoder.u8().map_err(storage)?).is_none() {
                return Err(Error::Mismatch);
            }
            Some((trailer, kind, timestamp))
        }
        _ => return Err(Error::Mismatch),
    };
    Ok(StoredRecord {
        offset,
        length,
        digest,
        tag,
    })
}
fn checked_record_bytes(
    deployment: &ReferenceDeployment,
    pin: Pin,
    entry: &StoredRecord,
    authority: &dyn ReadAuthority,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>, Error> {
    let bytes = read_part_bounded(
        deployment,
        pin,
        entry.digest,
        entry.length,
        authority,
        work,
        cx,
    )?;
    if bytes.len() != entry.length {
        return Err(Error::Mismatch);
    }
    Ok(bytes)
}

/// Recover one ledgered segment, rechecking the graph, its source-object hashes,
/// original-to-fragment NAL byte mappings and the generated MP4's sample table.
/// The source framer's boundaries remain heuristic, capture time and device
/// identity are not independently proven here, and successful parsing is not
/// proof that a decoder can display the pictures. No data is returned on denial.
pub fn read_clip(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredClip, Error> {
    let (manifest, metadata) = open_graph(deployment, pin, authority, limits, work, cx)?;
    recover_video_graph(
        deployment, pin, &manifest, &metadata, authority, limits, work, cx,
    )
}

/// Recover the independently source-checked video derivative nested in a
/// ledgered A/V graph. This returns video only, not the A/V fragment, and does
/// not validate audio mappings, synchronization, peer identity or capture time.
pub fn read_av_video_clip(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredClip, Error> {
    let (_, _, video, video_metadata) =
        open_av_video_graph(deployment, pin, authority, limits, work, cx)?;
    recover_video_graph(
        deployment,
        pin,
        &video,
        &video_metadata,
        authority,
        limits,
        work,
        cx,
    )
}

fn open_av_video_graph(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<(ObjectManifest, Vec<u8>, ObjectManifest, Vec<u8>), Error> {
    let (outer, metadata) = open_graph_kind(
        deployment,
        pin,
        authority,
        limits,
        work,
        cx,
        av_evidence::KIND,
        av_evidence::DOMAIN,
    )?;
    work.charge(metadata.len() as u64 * 4)?;
    let mut decoder = CanonicalDecoder::new(&metadata);
    check_prefix_kind(&mut decoder, pin, av_evidence::DOMAIN)?;
    let video_root = decoder.digest().map_err(storage)?;
    work.charge(u64::from(usize::BITS) + 1)?;
    if outer.children().binary_search(&video_root).is_err() {
        return Err(Error::Mismatch);
    }
    let bytes = read_part(deployment, pin, video_root, authority, work, cx)?;
    let video = ObjectManifest::from_canonical_bytes(&bytes).map_err(storage)?;
    work.charge(
        (video.children().len() as u64)
            .checked_mul(u64::from(usize::BITS) + 1)
            .ok_or(Error::Limit)?,
    )?;
    if video.root() != video_root
        || video.kind() != KIND
        || video
            .children()
            .iter()
            .any(|child| outer.children().binary_search(child).is_err())
    {
        return Err(Error::Mismatch);
    }
    let digest = video.metadata_digest().ok_or(Error::Mismatch)?;
    let video_metadata = read_part(deployment, pin, digest, authority, work, cx)?;
    Ok((outer, metadata, video, video_metadata))
}

/// Evidence that retained AAC bodies match the writer-profile A/V sample table.
/// This is not audio decoding, independent clock alignment, source
/// authentication, or proof of continuous coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvAudioSourceMapping {
    /// Whether the codec configuration had a retained in-band source record.
    pub configuration_origin: AudioConfigurationOrigin,
    /// Number of matching AAC bodies.
    pub frames: usize,
    /// Caller-bound AAC sample clock at the first body.
    pub first_decode_ticks: u64,
    /// Exclusive end of the contiguous caller-bound AAC sample clock.
    pub end_decode_ticks: u64,
    /// Sample rate declared by the configuration, not independently measured.
    pub sample_rate: u32,
}

/// A/V bytes recovered after source-mapping and writer-profile checks.
/// Capture, identity, codec decoding and independent synchronization remain
/// separate claims; audio configuration provenance is exposed explicitly.
#[must_use]
pub struct RecoveredAvClip {
    bytes: Vec<u8>,
    capture: CaptureInterval,
    video_samples: usize,
    audio: AvAudioSourceMapping,
}
impl RecoveredAvClip {
    /// Two-track initialization followed by its checked media fragment.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Transfer the authorized media bytes to the caller.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    /// Caller-supplied bounds encoded in the ledgered root.
    pub fn capture(&self) -> CaptureInterval {
        self.capture
    }
    /// Structurally checked video sample count, not a decode guarantee.
    pub fn video_samples(&self) -> usize {
        self.video_samples
    }
    /// Checked audio source mapping and configuration provenance.
    pub fn audio(&self) -> AvAudioSourceMapping {
        self.audio
    }
}
impl fmt::Debug for RecoveredAvClip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredAvClip")
            .field("bytes", &"<redacted>")
            .field("capture", &self.capture)
            .field("video_samples", &self.video_samples)
            .field("audio", &self.audio)
            .finish()
    }
}

struct StoredAudioMapping {
    source: std::ops::Range<u64>,
    target: std::ops::Range<usize>,
    decode_ticks: u64,
    duration_ticks: u32,
}

/// Recheck every retained audio source tag against its emitted AAC body.
/// The A/V fragment remains in private memory and no media bytes are returned.
/// The generated initialization and audio fragment table are checked against
/// the writer's supported profile. A/V sync and decodability are not checked.
pub fn verify_av_audio_source_mapping(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<AvAudioSourceMapping, Error> {
    Ok(verify_av_graph(deployment, pin, authority, limits, work, cx)?.audio)
}

struct VerifiedAvGraph {
    audio: AvAudioSourceMapping,
    video_samples: usize,
    initialization_digest: ContentDigest,
    initialization_len: usize,
    fragment_digest: ContentDigest,
    fragment_len: usize,
}

/// Recover the two-track derivative after checking its retained video, audio
/// source ranges, configuration class and the supported writer-profile table.
/// This neither decodes the samples nor authenticates or synchronizes the camera.
/// No bytes are returned after policy revocation or content mismatch.
pub fn read_av_clip(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredAvClip, Error> {
    let verified = verify_av_graph(deployment, pin, authority, limits, work, cx)?;
    let media_len = verified
        .initialization_len
        .checked_add(verified.fragment_len)
        .ok_or(Error::Limit)?;
    if media_len > 129 * 1024 * 1024 {
        return Err(Error::Limit);
    }
    let mut bytes = read_part_bounded(
        deployment,
        pin,
        verified.initialization_digest,
        verified.initialization_len,
        authority,
        work,
        cx,
    )?;
    let fragment = read_part_bounded(
        deployment,
        pin,
        verified.fragment_digest,
        verified.fragment_len,
        authority,
        work,
        cx,
    )?;
    if bytes.len() != verified.initialization_len || fragment.len() != verified.fragment_len {
        return Err(Error::Mismatch);
    }
    work.charge((media_len as u64).checked_mul(2).ok_or(Error::Limit)?)?;
    bytes
        .try_reserve_exact(fragment.len())
        .map_err(|_| Error::Limit)?;
    bytes.extend_from_slice(&fragment);
    read_authorize(pin, authority, cx)?;
    Ok(RecoveredAvClip {
        bytes,
        capture: pin.capture,
        video_samples: verified.video_samples,
        audio: verified.audio,
    })
}

fn verify_av_graph(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<VerifiedAvGraph, Error> {
    use fss_packet::extended_flv::{self, Parse, Tag, aac};

    let configuration = read_av_audio_configuration(deployment, pin, authority, limits, work, cx)?;
    let (outer, metadata, video, video_metadata) =
        open_av_video_graph(deployment, pin, authority, limits, work, cx)?;
    let verified_video = recover_video_graph(
        deployment,
        pin,
        &video,
        &video_metadata,
        authority,
        limits,
        work,
        cx,
    )?;
    work.charge(metadata.len() as u64 * 4)?;
    let mut d = CanonicalDecoder::new(&metadata);
    check_prefix_kind(&mut d, pin, av_evidence::DOMAIN)?;
    if d.digest().map_err(storage)? != video.root() {
        return Err(Error::Mismatch);
    }
    match d.u8().map_err(storage)? {
        0 if configuration.origin == AudioConfigurationOrigin::InBand => {
            if Some(d.u64().map_err(storage)?) != configuration.claimed_epoch {
                return Err(Error::Mismatch);
            }
            let _ = record(&mut d, limits.maximum_spool_object_bytes)?;
            let _ = d.u64().map_err(storage)?;
            let _ = d.u64().map_err(storage)?;
        }
        1 if configuration.origin == AudioConfigurationOrigin::SuppliedUnverified => {}
        _ => return Err(Error::Mismatch),
    }
    if d.digest().map_err(storage)? != configuration.digest {
        return Err(Error::Mismatch);
    }
    let initialization_digest = d.digest().map_err(storage)?;
    let initialization_len = read_size(&mut d, limits.maximum_spool_object_bytes)?;
    let fragment_digest = d.digest().map_err(storage)?;
    let fragment_len = read_size(&mut d, limits.maximum_spool_object_bytes)?;
    let video_shift = read_size(&mut d, fragment_len)?;
    work.charge(2 * (u64::from(usize::BITS) + 1))?;
    if initialization_len == 0
        || fragment_len == 0
        || outer
            .children()
            .binary_search(&initialization_digest)
            .is_err()
        || outer.children().binary_search(&fragment_digest).is_err()
    {
        return Err(Error::Mismatch);
    }
    let count = read_size(&mut d, 8192)?;
    if count == 0 || count > 4096 {
        return Err(Error::Mismatch);
    }
    if count.checked_mul(8).and_then(|n| n.checked_add(64)) != Some(video_shift) {
        return Err(Error::Mismatch);
    }
    let mut mappings = Vec::new();
    mappings
        .try_reserve_exact(count)
        .map_err(|_| Error::Limit)?;
    for _ in 0..count {
        let source = d.u64().map_err(storage)?..d.u64().map_err(storage)?;
        let target = read_size(&mut d, fragment_len)?..read_size(&mut d, fragment_len)?;
        let decode_ticks = d.u64().map_err(storage)?;
        let duration_ticks = d.u32().map_err(storage)?;
        if source.start >= source.end || target.start >= target.end || duration_ticks == 0 {
            return Err(Error::Mismatch);
        }
        mappings.push(StoredAudioMapping {
            source,
            target,
            decode_ticks,
            duration_ticks,
        });
    }
    d.ensure_finished().map_err(storage)?;
    let fragment = read_part_bounded(
        deployment,
        pin,
        fragment_digest,
        fragment_len,
        authority,
        work,
        cx,
    )?;
    if fragment.len() != fragment_len {
        return Err(Error::Mismatch);
    }
    let config_bytes = read_part_bounded(
        deployment,
        pin,
        configuration.digest,
        2,
        authority,
        work,
        cx,
    )?;
    let config = aac::Configuration::parse_explicit(&config_bytes).map_err(storage)?;
    let initialization = read_part_bounded(
        deployment,
        pin,
        initialization_digest,
        initialization_len,
        authority,
        work,
        cx,
    )?;
    if initialization.len() != initialization_len {
        return Err(Error::Mismatch);
    }
    let mp4_limits = fss_container::Mp4Limits {
        max_samples: 4096,
        max_nals: 65_536,
        max_source_spans: 262_144,
        max_fragment_bytes: 128 * 1024 * 1024,
        max_initialization_bytes: 1024 * 1024,
    };
    work.charge(
        (verified_video.bytes().len() as u64)
            .checked_add(initialization.len() as u64)
            .and_then(|n| n.checked_mul(4))
            .ok_or(Error::Limit)?,
    )?;
    fss_container::flv_av::verify_archived_initialization(
        verified_video.bytes(),
        &initialization,
        &config,
        mp4_limits,
    )
    .map_err(storage)?;

    work.charge(video_metadata.len() as u64 * 4)?;
    let mut source = CanonicalDecoder::new(&video_metadata);
    check_prefix(&mut source, pin)?;
    if source.u64().map_err(storage)? == 0
        || source.u64().map_err(storage)? == 0
        || source.u32().map_err(storage)? == 0
    {
        return Err(Error::Mismatch);
    }
    let _ = record(&mut source, limits.maximum_spool_object_bytes)?;
    let _ = source.digest().map_err(storage)?;
    let _ = read_size(&mut source, limits.maximum_spool_object_bytes)?;
    let video_fragment_digest = source.digest().map_err(storage)?;
    let video_fragment_len = read_size(&mut source, limits.maximum_spool_object_bytes)?;
    work.charge(u64::from(usize::BITS) + 1)?;
    if video
        .children()
        .binary_search(&video_fragment_digest)
        .is_err()
    {
        return Err(Error::Mismatch);
    }
    let video_fragment = read_part_bounded(
        deployment,
        pin,
        video_fragment_digest,
        video_fragment_len,
        authority,
        work,
        cx,
    )?;
    if video_fragment.len() != video_fragment_len {
        return Err(Error::Mismatch);
    }
    let mut container_mappings = Vec::new();
    container_mappings
        .try_reserve_exact(count)
        .map_err(|_| Error::Limit)?;
    for mapping in &mappings {
        container_mappings.push(fss_container::flv_av::AudioMapping {
            source: mapping.source.clone(),
            target: mapping.target.clone(),
            decode_ticks: mapping.decode_ticks,
            duration_ticks: u16::try_from(mapping.duration_ticks).map_err(|_| Error::Limit)?,
        });
    }
    work.charge(
        (video_fragment.len() as u64)
            .checked_add(fragment.len() as u64)
            .and_then(|n| n.checked_mul(4))
            .ok_or(Error::Limit)?,
    )?;
    fss_container::flv_av::verify_archived_fragment(
        &video_fragment,
        &fragment,
        &container_mappings,
        mp4_limits,
    )
    .map_err(storage)?;
    let source_count = read_size(&mut source, 8192)?;
    if source_count == 0 {
        return Err(Error::Mismatch);
    }
    let mut index = 0usize;
    let mut next_offset = None;
    let mut previous_target = None;
    let mut previous_tick = None;
    let mut previous_sender: Option<u32> = None;
    for _ in 0..source_count {
        let entry = record(&mut source, limits.maximum_spool_object_bytes)?;
        work.charge(u64::from(usize::BITS) + 1)?;
        if video.children().binary_search(&entry.digest).is_err()
            || next_offset.is_some_and(|offset| offset != entry.offset)
        {
            return Err(Error::Mismatch);
        }
        next_offset = Some(
            entry
                .offset
                .checked_add(entry.length as u64)
                .ok_or(Error::Limit)?,
        );
        let bytes = checked_record_bytes(deployment, pin, &entry, authority, work, cx)?;
        let Some((tag_offset, kind, timestamp)) = entry.tag else {
            let Parse::Complete(header) =
                extended_flv::Header::parse(&bytes, extended_flv::Limits::default())
                    .map_err(storage)?
            else {
                return Err(Error::Mismatch);
            };
            if header.wire_bytes().len() != bytes.len() {
                return Err(Error::Mismatch);
            }
            continue;
        };
        let tag_bytes = bytes.get(tag_offset..).ok_or(Error::Mismatch)?;
        let Parse::Complete(tag) =
            Tag::parse(tag_bytes, extended_flv::Limits::default()).map_err(storage)?
        else {
            return Err(Error::Mismatch);
        };
        if tag.wire_bytes().len() != tag_bytes.len()
            || tag.kind() != kind
            || tag.timestamp_ms() != timestamp
            || kind == 10
        {
            return Err(Error::Mismatch);
        }
        if kind != 8 {
            continue;
        }
        let audio = aac::AudioTag::parse(tag, aac::Limits::default()).map_err(storage)?;
        if audio.packet_type() != aac::PacketType::Raw {
            return Err(Error::Mismatch);
        }
        let mapping = mappings.get(index).ok_or(Error::Mismatch)?;
        let body = audio.body_range();
        let base = entry
            .offset
            .checked_add(tag_offset as u64)
            .ok_or(Error::Limit)?;
        let start = base.checked_add(body.start as u64).ok_or(Error::Limit)?;
        let end = base.checked_add(body.end as u64).ok_or(Error::Limit)?;
        if mapping.source != (start..end)
            || fragment.get(mapping.target.clone()) != Some(audio.body())
            || mapping.duration_ticks != u32::from(config.frame_samples())
            || previous_target.is_some_and(|end| end != mapping.target.start)
            || previous_tick.is_some_and(|end| end != mapping.decode_ticks)
            || previous_sender.is_some_and(|last| {
                let delta = timestamp.wrapping_sub(last);
                delta == 0 || delta >= (1 << 31)
            })
        {
            return Err(Error::Mismatch);
        }
        previous_target = Some(mapping.target.end);
        previous_tick = Some(
            mapping
                .decode_ticks
                .checked_add(u64::from(mapping.duration_ticks))
                .ok_or(Error::Limit)?,
        );
        previous_sender = Some(timestamp);
        index = index.checked_add(1).ok_or(Error::Limit)?;
    }
    if index != count {
        return Err(Error::Mismatch);
    }
    read_authorize(pin, authority, cx)?;
    Ok(VerifiedAvGraph {
        audio: AvAudioSourceMapping {
            configuration_origin: configuration.origin,
            frames: count,
            first_decode_ticks: mappings[0].decode_ticks,
            end_decode_ticks: previous_tick.ok_or(Error::Mismatch)?,
            sample_rate: config.sample_rate(),
        },
        video_samples: verified_video.samples(),
        initialization_digest,
        initialization_len,
        fragment_digest,
        fragment_len,
    })
}

fn recover_video_graph(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    manifest: &ObjectManifest,
    metadata: &[u8],
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredClip, Error> {
    use fss_container::demux::{AvcMp4, DemuxLimits};
    use std::collections::BTreeSet;
    work.charge(metadata.len() as u64 * 4)?;
    let mut d = CanonicalDecoder::new(metadata);
    check_prefix(&mut d, pin)?;
    if d.u64().map_err(storage)? == 0
        || d.u64().map_err(storage)? == 0
        || d.u32().map_err(storage)? == 0
    {
        return Err(Error::Mismatch);
    }
    let config = record(&mut d, limits.maximum_spool_object_bytes)?;
    let init_digest = d.digest().map_err(storage)?;
    let init_len = read_size(&mut d, limits.maximum_spool_object_bytes)?;
    let fragment_digest = d.digest().map_err(storage)?;
    let fragment_len = read_size(&mut d, limits.maximum_spool_object_bytes)?;
    let media_len = init_len.checked_add(fragment_len).ok_or(Error::Limit)?;
    if init_len == 0 || fragment_len == 0 || media_len > 128 * 1024 * 1024 {
        return Err(Error::Limit);
    }
    let mut children = BTreeSet::from([config.digest, init_digest, fragment_digest]);
    let source_count = read_size(&mut d, 8192)?;
    if source_count == 0 {
        return Err(Error::Mismatch);
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(source_count)
        .map_err(|_| Error::Limit)?;
    let mut total = config.length.checked_add(media_len).ok_or(Error::Limit)?;
    let mut next = None;
    for _ in 0..source_count {
        let item = record(&mut d, limits.maximum_spool_object_bytes)?;
        if next.is_some_and(|v| v != item.offset) {
            return Err(Error::Mismatch);
        }
        next = Some(
            item.offset
                .checked_add(item.length as u64)
                .ok_or(Error::Limit)?,
        );
        total = total.checked_add(item.length).ok_or(Error::Limit)?;
        children.insert(item.digest);
        records.push(item);
    }
    let witness_count = read_size(&mut d, 8192 - source_count)?;
    if witness_count == 0 {
        return Err(Error::Mismatch);
    }
    let mut witnesses = Vec::new();
    witnesses
        .try_reserve_exact(witness_count)
        .map_err(|_| Error::Limit)?;
    for _ in 0..witness_count {
        let item = record(&mut d, limits.maximum_spool_object_bytes)?;
        if next != Some(item.offset) {
            return Err(Error::Mismatch);
        }
        next = Some(
            item.offset
                .checked_add(item.length as u64)
                .ok_or(Error::Limit)?,
        );
        total = total.checked_add(item.length).ok_or(Error::Limit)?;
        children.insert(item.digest);
        witnesses.push(item);
    }
    if total > 256 * 1024 * 1024 {
        return Err(Error::Limit);
    }
    let count = read_size(&mut d, 4096)?;
    if count == 0 {
        return Err(Error::Mismatch);
    }
    let mut samples = Vec::new();
    samples.try_reserve_exact(count).map_err(|_| Error::Limit)?;
    for _ in 0..count {
        samples.push(StoredSample {
            start: read_size(&mut d, fragment_len)?,
            end: read_size(&mut d, fragment_len)?,
            decode: d.u64().map_err(storage)?,
            composition: d.i128().map_err(storage)?,
            duration: d.u32().map_err(storage)?,
            idr: d.bool().map_err(storage)?,
            first_nal: read_size(&mut d, 65_536)?,
            end_nal: read_size(&mut d, 65_536)?,
        });
    }
    let nal_count = read_size(&mut d, 65_536)?;
    if nal_count == 0 {
        return Err(Error::Mismatch);
    }
    let mut nals = Vec::new();
    nals.try_reserve_exact(nal_count)
        .map_err(|_| Error::Limit)?;
    for _ in 0..nal_count {
        nals.push(StoredNal {
            sample: read_size(&mut d, count - 1)?,
            source_start: d.u64().map_err(storage)?,
            source_end: d.u64().map_err(storage)?,
            start: read_size(&mut d, fragment_len)?,
            end: read_size(&mut d, fragment_len)?,
        });
    }
    if d.bool().map_err(storage)? {
        let start = d.u64().map_err(storage)?;
        let end = d.u64().map_err(storage)?;
        if start >= end {
            return Err(Error::Mismatch);
        }
    }
    d.ensure_finished().map_err(storage)?;
    children.insert(manifest.metadata_digest().ok_or(Error::Mismatch)?);
    if children
        .iter()
        .copied()
        .ne(manifest.children().iter().copied())
    {
        return Err(Error::Mismatch);
    }
    let config_bytes = checked_record_bytes(deployment, pin, &config, authority, work, cx)?;
    let (tag_offset, kind, timestamp) = config.tag.ok_or(Error::Mismatch)?;
    let tag_bytes = config_bytes.get(tag_offset..).ok_or(Error::Mismatch)?;
    let fss_packet::extended_flv::Parse::Complete(tag) = fss_packet::extended_flv::Tag::parse(
        tag_bytes,
        fss_packet::extended_flv::Limits::default(),
    )
    .map_err(storage)?
    else {
        return Err(Error::Mismatch);
    };
    if tag.wire_bytes().len() != tag_bytes.len()
        || tag.kind() != kind
        || tag.timestamp_ms() != timestamp
    {
        return Err(Error::Mismatch);
    }
    let source_config = fss_packet::extended_flv::avc::VideoTag::parse(tag)
        .map_err(storage)?
        .configuration(fss_packet::extended_flv::avc::Limits::default())
        .map_err(storage)?;
    let mut media = read_part_bounded(deployment, pin, init_digest, init_len, authority, work, cx)?;
    let fragment = read_part_bounded(
        deployment,
        pin,
        fragment_digest,
        fragment_len,
        authority,
        work,
        cx,
    )?;
    if media.len() != init_len || fragment.len() != fragment_len {
        return Err(Error::Mismatch);
    }
    work.charge((media_len as u64).checked_mul(4).ok_or(Error::Limit)?)?;
    media
        .try_reserve_exact(fragment_len)
        .map_err(|_| Error::Limit)?;
    media.extend_from_slice(&fragment);
    let movie = AvcMp4::parse(&media, None, DemuxLimits::default()).map_err(storage)?;
    if movie.timescale() != 1000 || movie.nal_length_bytes() != 4 || movie.samples().len() != count
    {
        return Err(Error::Mismatch);
    }
    let mut source_sets = source_config.sps().chain(source_config.pps());
    for range in movie.parameter_sets() {
        let source = source_sets.next().ok_or(Error::Mismatch)?;
        if media.get(range.clone()) != Some(source.bytes()) {
            return Err(Error::Mismatch);
        }
    }
    if source_sets.next().is_some() {
        return Err(Error::Mismatch);
    }
    let mut nal_index = 0;
    for (index, (expected, actual)) in samples.iter().zip(movie.samples()).enumerate() {
        if expected.start >= expected.end
            || expected.first_nal != nal_index
            || expected.end_nal <= expected.first_nal
            || expected.end_nal > nals.len()
            || actual.source.start != init_len.checked_add(expected.start).ok_or(Error::Limit)?
            || actual.source.end != init_len.checked_add(expected.end).ok_or(Error::Limit)?
            || actual.decode_time != expected.decode
            || i128::from(actual.composition_offset) != expected.composition
            || actual.duration != expected.duration
            || actual.sync_sample != expected.idr
            || actual.contains_idr != expected.idr
        {
            return Err(Error::Mismatch);
        }
        let mut cursor = expected.start;
        for nal in &nals[expected.first_nal..expected.end_nal] {
            let prefix_end = cursor.checked_add(4).ok_or(Error::Limit)?;
            let prefix: [u8; 4] = fragment
                .get(cursor..prefix_end)
                .ok_or(Error::Mismatch)?
                .try_into()
                .map_err(|_| Error::Mismatch)?;
            if nal.sample != index
                || nal.start != prefix_end
                || nal.start >= nal.end
                || nal.end > expected.end
                || nal.source_start >= nal.source_end
                || u32::from_be_bytes(prefix) as usize != nal.end - nal.start
                || nal.source_end - nal.source_start != (nal.end - nal.start) as u64
            {
                return Err(Error::Mismatch);
            }
            cursor = nal.end;
        }
        if cursor != expected.end {
            return Err(Error::Mismatch);
        }
        nal_index = expected.end_nal;
    }
    if nal_index != nals.len() || !samples[0].idr {
        return Err(Error::Mismatch);
    }
    let mut index = 0;
    for entry in &records {
        let bytes = checked_record_bytes(deployment, pin, entry, authority, work, cx)?;
        let end = entry
            .offset
            .checked_add(entry.length as u64)
            .ok_or(Error::Limit)?;
        while let Some(nal) = nals.get(index) {
            if nal.source_start >= end {
                break;
            }
            let start = usize::try_from(
                nal.source_start
                    .checked_sub(entry.offset)
                    .ok_or(Error::Mismatch)?,
            )
            .map_err(|_| Error::Limit)?;
            let finish = usize::try_from(
                nal.source_end
                    .checked_sub(entry.offset)
                    .ok_or(Error::Mismatch)?,
            )
            .map_err(|_| Error::Limit)?;
            if bytes.get(start..finish) != fragment.get(nal.start..nal.end)
                || bytes.get(start..finish).is_none()
            {
                return Err(Error::Mismatch);
            }
            index += 1;
        }
    }
    if index != nals.len() {
        return Err(Error::Mismatch);
    }
    for entry in &witnesses {
        let _ = checked_record_bytes(deployment, pin, entry, authority, work, cx)?;
    }
    read_authorize(pin, authority, cx)?;
    Ok(RecoveredClip {
        bytes: media,
        capture: pin.capture,
        samples: count,
    })
}

#[cfg(test)]
mod tests {
    use super::{Error, record};
    use crate::unifi_direct::evidence::encode_record;
    use fss_core::{CanonicalDecoder, CanonicalEncoder};
    use fss_packet::extended_flv::{
        Limits,
        stream::{Framer, Next, SearchMode},
    };

    #[test]
    fn archive_record_accepts_av_flag_policy_and_rejects_unknown_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        fn tag(kind: u8, timestamp: u32, body: &[u8]) -> Vec<u8> {
            let len = body.len();
            let mut out = vec![
                kind,
                (len >> 16) as u8,
                (len >> 8) as u8,
                len as u8,
                (timestamp >> 16) as u8,
                (timestamp >> 8) as u8,
                timestamp as u8,
                (timestamp >> 24) as u8,
                0,
                0,
                0,
            ];
            out.extend_from_slice(body);
            out.extend_from_slice(&(11_u32 + len as u32).to_be_bytes());
            out
        }
        let mut wire = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
        wire.extend(tag(9, 0, b"video"));
        let mut trailer = [0; 16];
        trailer[11] = 1;
        wire.extend(trailer);
        wire.extend(tag(8, 40, b"audio"));
        let mut framer = Framer::with_mode(
            Limits::default(),
            1024,
            SearchMode::StructuredTrailer16AvFlag,
        )?;
        framer.append(0, &wire)?;
        framer.take()?;
        framer.take()?;
        let Next::Record(source) = framer.take()? else {
            return Err("missing source record".into());
        };
        let mut encoder = CanonicalEncoder::new();
        encode_record(&mut encoder, &source);
        let mut bytes = encoder.finish_checked()?;
        let parsed = record(&mut CanonicalDecoder::new(&bytes), 1024)?;
        assert_eq!(parsed.offset, source.offset());
        assert_eq!(parsed.length, source.bytes().len());
        assert_eq!(parsed.tag, Some((16, 8, 40)));
        *bytes.last_mut().ok_or("empty encoded record")? = 4;
        assert!(matches!(
            record(&mut CanonicalDecoder::new(&bytes), 1024),
            Err(Error::Mismatch)
        ));
        Ok(())
    }
}
