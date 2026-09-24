#![forbid(unsafe_code)]
//! Durable, source-closed RGB inference evidence in the existing deployment spool.
//!
//! Originals are separate content-addressed objects: repeated model weights do not
//! get copied into a new envelope for every frame. A stored claim is not an executed
//! inference. Restore returns `RgbEvidence`; its native `replay` remains mandatory.

use std::collections::BTreeSet;
use std::ops::Range;

use super::rgb_evidence::{
    ReplayedRgbEvidence, RgbEvidence, RgbEvidenceBudget, RgbEvidenceError, RgbEvidenceLimits,
};
use crate::reference_deployment::ReplayCancellationBridge;
use crate::{ReferenceDeployment, ReplayCx};
use fss_core::{
    CanonicalDecoder, CanonicalEncoder, CaptureInterval, ContentDigest, DigestAlgorithm,
    TimestampNs,
};
use fss_geometry::{GeometryError, WorkBudget};
use fss_object::ObjectManifest;
use fss_publication::{
    PublishCancellation, PublishCutPoint, RootLedgerReceipt, RootLedgerState, SlotName,
};

const DOMAIN: &str = "fss.rgb-evidence-custody.reference.v1";
const KIND: &str = "rgb-evidence-custody-v1";
const INDEX_LIMIT: usize = 1024;

/// Explicit operations on ORIGINAL images, masks and model files, not just detections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RgbArchiveOperation {
    /// Requires permission to retain originals, stage/publish objects and append custody.
    RetainOriginals,
    /// Requires original-media/model disclosure permission under current privacy policy.
    ReadOriginals,
}
/// Deployment policy adapter. There is deliberately no default or permissive implementation.
/// Check current principal, retention/privacy scope and registered capabilities on EVERY call.
/// A nonzero retention-evidence digest by itself must never grant these permissions.
pub trait RgbArchiveAuthority {
    /// Revalidate this exact operation, retention decision and source-closed recipe.
    fn permits(
        &self,
        operation: RgbArchiveOperation,
        retention: ContentDigest,
        evidence: ContentDigest,
    ) -> bool;
}

/// Independent limits; stored files cannot enlarge them.
#[derive(Clone, Copy, Debug)]
pub struct RgbArchiveLimits {
    /// Complete source and per-original ceilings used by the existing evidence owner.
    pub evidence: RgbEvidenceLimits,
    /// Maximum allocation the attached spool may perform per read, at most 32 MiB.
    pub maximum_spool_object_bytes: usize,
    /// Maximum ledger deltas inspected when resolving one root, at most 262144.
    pub maximum_ledger_deltas: usize,
}
impl Default for RgbArchiveLimits {
    fn default() -> Self {
        Self {
            evidence: RgbEvidenceLimits::default(),
            maximum_spool_object_bytes: 64 * 1024 * 1024,
            maximum_ledger_deltas: 65_536,
        }
    }
}

/// Independently retain this pin before publication; it is not proof of current custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RgbArchivePin {
    /// Complete canonical object-graph root, including retention scope and capture bounds.
    pub root: ContentDigest,
    /// Existing portable recipe identity, independent of archive framing.
    pub evidence: ContentDigest,
    /// Exact owner retention decision authorizing original-byte custody.
    pub retention: ContentDigest,
    /// Original conservative source capture interval, never arrival time.
    pub capture: [u64; 2],
}
impl RgbArchivePin {
    /// Deterministic immutable slot. Another retention decision cannot overwrite this root.
    pub fn slot(self) -> Result<SlotName> {
        if ![self.root, self.evidence, self.retention]
            .iter()
            .copied()
            .all(valid_digest)
            || self.capture[0] > self.capture[1]
        {
            return Err(RgbArchiveError::Mismatch);
        }
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.digest(self.retention);
        e.digest(self.evidence);
        let d = ContentDigest::sha256(&e.finish_checked().map_err(storage)?);
        SlotName::parse(&format!("rgbe1-{}", hex(d))).map_err(storage)
    }
}

/// Storage uncertainty is preserved, never reported as a successful inference or absence.
#[derive(Debug)]
pub enum RgbArchiveError {
    /// The explicit current original-byte policy denied access.
    Denied,
    /// Invalid bounds or complete-input/work limit exceeded.
    Limit,
    /// Source, canonical graph, recipe, retention or pinned interval differs.
    Mismatch,
    /// Root is not both durable and canonically ledgered. Retry the original prepared plan.
    NotCommitted,
    /// A deletion tombstone prohibits resurrection or disclosure.
    Tombstoned,
    /// Owner cancellation before the operation's commit point.
    Cancelled,
    /// Existing source-envelope owner refused its bounded encoding or decoding.
    Evidence(RgbEvidenceError),
    /// Bounded deterministic work failed.
    Work(GeometryError),
    /// Original publisher/ledger/spool error; includes possible indeterminate publication.
    Storage(Box<dyn std::error::Error>),
}
impl std::fmt::Display for RgbArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Denied => "RGB original-custody authority denied",
            Self::Limit => "RGB original-custody limit exceeded",
            Self::Mismatch => "RGB original-custody binding mismatch",
            Self::NotCommitted => "RGB original-custody root not ledgered and durable",
            Self::Tombstoned => "RGB original-custody object deleted",
            Self::Cancelled => "RGB original-custody owner cancelled",
            Self::Evidence(_) => "RGB source envelope refused",
            Self::Work(_) => "RGB original-custody work refused",
            Self::Storage(_) => "RGB original-custody storage refused",
        })
    }
}
impl std::error::Error for RgbArchiveError {}
impl From<RgbEvidenceError> for RgbArchiveError {
    fn from(e: RgbEvidenceError) -> Self {
        Self::Evidence(e)
    }
}
impl From<GeometryError> for RgbArchiveError {
    fn from(e: GeometryError) -> Self {
        Self::Work(e)
    }
}
fn storage<E: std::error::Error + 'static>(e: E) -> RgbArchiveError {
    RgbArchiveError::Storage(Box::new(e))
}
/// Results from original-byte custody operations.
pub type Result<T> = std::result::Result<T, RgbArchiveError>;
fn valid_digest(d: ContentDigest) -> bool {
    d.algorithm() == DigestAlgorithm::Sha256 && d.bytes() != [0; 32]
}
fn hex(d: ContentDigest) -> String {
    d.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone, Copy)]
struct Part {
    digest: ContentDigest,
    bytes: usize,
}
struct Index {
    pin: RgbArchivePin,
    parts: [Part; 5],
}
impl Index {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.digest(self.pin.evidence);
        e.digest(self.pin.retention);
        for n in self.pin.capture {
            e.u64(n);
        }
        for part in self.parts {
            e.digest(part.digest);
            e.u64(part.bytes as u64);
        }
        e.finish_checked().map_err(storage)
    }
    fn manifest(&self) -> Result<ObjectManifest> {
        let metadata = ContentDigest::sha256(&self.encode()?);
        let mut children: BTreeSet<_> = self.parts.iter().map(|p| p.digest).collect();
        children.remove(&metadata);
        ObjectManifest::new(KIND, children, Some(metadata)).map_err(storage)
    }
    fn decode(bytes: &[u8], pin: RgbArchivePin) -> Result<Self> {
        let mut d = CanonicalDecoder::new(bytes);
        if d.text().map_err(storage)? != DOMAIN {
            return Err(RgbArchiveError::Mismatch);
        }
        let evidence = d.digest().map_err(storage)?;
        let retention = d.digest().map_err(storage)?;
        let capture = [d.u64().map_err(storage)?, d.u64().map_err(storage)?];
        if (evidence, retention, capture) != (pin.evidence, pin.retention, pin.capture) {
            return Err(RgbArchiveError::Mismatch);
        }
        let mut parts = [Part {
            digest: evidence,
            bytes: 0,
        }; 5];
        for part in &mut parts {
            part.digest = d.digest().map_err(storage)?;
            part.bytes =
                usize::try_from(d.u64().map_err(storage)?).map_err(|_| RgbArchiveError::Limit)?;
            if !valid_digest(part.digest) {
                return Err(RgbArchiveError::Mismatch);
            }
        }
        d.ensure_finished().map_err(storage)?;
        let index = Self { pin, parts };
        if index.parts[0].digest != evidence
            || index.encode()? != bytes
            || index.manifest()?.root() != pin.root
        {
            return Err(RgbArchiveError::Mismatch);
        }
        Ok(index)
    }
    fn size(&self, limits: RgbEvidenceLimits) -> Result<usize> {
        if !(1..=64 * 1024 * 1024).contains(&limits.maximum_bytes)
            || !(1..=16 * 1024 * 1024).contains(&limits.maximum_source_bytes)
        {
            return Err(RgbArchiveError::Limit);
        }
        let ceilings = [
            256 * 1024,
            limits.maximum_source_bytes,
            limits.maximum_source_bytes,
            limits.maximum_source_bytes,
            4_194_304,
        ];
        let mut size = 48usize;
        for (part, ceiling) in self.parts.iter().zip(ceilings) {
            if part.bytes == 0 || part.bytes > ceiling {
                return Err(RgbArchiveError::Limit);
            }
            size = size.checked_add(part.bytes).ok_or(RgbArchiveError::Limit)?;
        }
        if size > limits.maximum_bytes {
            return Err(RgbArchiveError::Limit);
        }
        Ok(size)
    }
}

/// Exact replay-verified source envelope and deterministic publication plan. No storage yet.
/// Reuse this object after a lost acknowledgement; do not create another observation identity.
pub struct PreparedRgbArchive {
    index: Index,
    envelope: Vec<u8>,
    ranges: [Range<usize>; 5],
    limits: RgbArchiveLimits,
}
impl std::fmt::Debug for PreparedRgbArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRgbArchive")
            .field("pin", &self.index.pin)
            .finish_non_exhaustive()
    }
}
impl PreparedRgbArchive {
    /// Bind originals to a real native replay, never to an unverified output digest.
    pub fn new(
        evidence: &RgbEvidence,
        replay: &ReplayedRgbEvidence,
        retention: ContentDigest,
        limits: RgbArchiveLimits,
        copy_work: &mut RgbEvidenceBudget,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<Self> {
        if !valid_digest(retention) || evidence.identity() != replay.evidence_identity() {
            return Err(RgbArchiveError::Mismatch);
        }
        let envelope = evidence.encode(limits.evidence, copy_work, cx)?;
        work.charge(envelope.len() as u64)?;
        let mut at = 8usize;
        let mut ranges = std::array::from_fn(|_| 0..0);
        let mut parts = [Part {
            digest: evidence.identity(),
            bytes: 0,
        }; 5];
        for (range, part) in ranges.iter_mut().zip(&mut parts) {
            let end = at.checked_add(8).ok_or(RgbArchiveError::Limit)?;
            let raw = envelope.get(at..end).ok_or(RgbArchiveError::Mismatch)?;
            let n = usize::try_from(u64::from_le_bytes(
                raw.try_into().map_err(|_| RgbArchiveError::Mismatch)?,
            ))
            .map_err(|_| RgbArchiveError::Limit)?;
            at = end;
            let end = at.checked_add(n).ok_or(RgbArchiveError::Limit)?;
            let bytes = envelope.get(at..end).ok_or(RgbArchiveError::Mismatch)?;
            *range = at..end;
            *part = Part {
                digest: ContentDigest::sha256(bytes),
                bytes: n,
            };
            at = end;
        }
        if at != envelope.len() || parts[0].digest != evidence.identity() {
            return Err(RgbArchiveError::Mismatch);
        }
        let mut index = Index {
            pin: RgbArchivePin {
                root: evidence.identity(),
                evidence: evidence.identity(),
                retention,
                capture: replay.admission().source().capture,
            },
            parts,
        };
        index.size(limits.evidence)?;
        index.pin.root = index.manifest()?.root();
        index.pin.slot()?;
        cx.checkpoint("rgb-archive:prepared")
            .map_err(|_| RgbArchiveError::Cancelled)?;
        Ok(Self {
            index,
            envelope,
            ranges,
            limits,
        })
    }
    /// Candidate known before disk mutation, useful for exact reconciliation after ACK loss.
    pub fn pin(&self) -> RgbArchivePin {
        self.index.pin
    }

    /// Stage originals first, then publish the root and existing canonical reachability batch.
    /// Rechecks current original-retention authority at every pre-commit root cut point.
    /// Once the existing publisher commits, its actual receipt is returned even on late cancel.
    pub fn publish(
        &self,
        deployment: &mut ReferenceDeployment,
        authority: &dyn RgbArchiveAuthority,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<RootLedgerReceipt> {
        let pin = self.pin();
        let operation = RgbArchiveOperation::RetainOriginals;
        authorize(pin, authority, operation, cx)?;
        admit(deployment, pin, self.limits, work, cx)?;
        let metadata = self.index.encode()?;
        let manifest = self.index.manifest()?;
        // Check the COMPLETE graph before writing anything; no resurrection on exact retries.
        for digest in manifest.children().iter().copied().chain([pin.root]) {
            not_deleted(deployment, digest, work)?;
        }
        for (part, range) in self.index.parts.iter().zip(&self.ranges) {
            authorize(pin, authority, operation, cx)?;
            work.charge(part.bytes as u64 * 3)?;
            if deployment
                .stage_payload(&self.envelope[range.clone()])
                .map_err(storage)?
                != part.digest
            {
                return Err(RgbArchiveError::Mismatch);
            }
        }
        authorize(pin, authority, operation, cx)?;
        work.charge(metadata.len() as u64 * 3)?;
        if deployment.stage_payload(&metadata).map_err(storage)? != ContentDigest::sha256(&metadata)
        {
            return Err(RgbArchiveError::Mismatch);
        }
        let cancel = Gate { pin, authority, cx };
        let validity = CaptureInterval::new(
            TimestampNs(i128::from(pin.capture[0])),
            TimestampNs(i128::from(pin.capture[1])),
        )
        .map_err(storage)?;
        let receipt = deployment
            .ledgered_publisher()
            .publish_and_commit_cancellable(&pin.slot()?, &manifest, validity, &cancel)
            .map_err(storage)?;
        Ok(receipt)
    }
}

/// Reopen exact originals from current durable local custody AND the canonical ledger.
/// A pending-ledger root is refused. Reading never silently completes a failed publication.
/// The returned envelope still requires native `RgbEvidence::replay` before use as inference.
pub fn restore_rgb_evidence(
    deployment: &mut ReferenceDeployment,
    pin: RgbArchivePin,
    limits: RgbArchiveLimits,
    authority: &dyn RgbArchiveAuthority,
    copy_work: &mut RgbEvidenceBudget,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RgbEvidence> {
    authorize(pin, authority, RgbArchiveOperation::ReadOriginals, cx)?;
    admit(deployment, pin, limits, work, cx)?;
    match deployment
        .ledgered_publisher()
        .state(&pin.slot()?)
        .map_err(storage)?
    {
        RootLedgerState::Ledgered { root, .. } if root == pin.root => {}
        _ => return Err(RgbArchiveError::NotCommitted),
    }
    let root_bytes = read(deployment, pin, pin.root, INDEX_LIMIT, authority, work, cx)?;
    let manifest = ObjectManifest::from_canonical_bytes(&root_bytes).map_err(storage)?;
    let metadata = manifest
        .metadata_digest()
        .ok_or(RgbArchiveError::Mismatch)?;
    let bytes = read(deployment, pin, metadata, INDEX_LIMIT, authority, work, cx)?;
    let index = Index::decode(&bytes, pin)?;
    if index.manifest()? != manifest {
        return Err(RgbArchiveError::Mismatch);
    }
    let size = index.size(limits.evidence)?;
    work.charge(size as u64)?;
    let mut envelope = Vec::new();
    envelope
        .try_reserve_exact(size)
        .map_err(|_| RgbArchiveError::Limit)?;
    envelope.extend_from_slice(b"FSSRGBE1");
    for part in index.parts {
        let bytes = read(
            deployment,
            pin,
            part.digest,
            part.bytes,
            authority,
            work,
            cx,
        )?;
        if bytes.len() != part.bytes {
            return Err(RgbArchiveError::Mismatch);
        }
        envelope.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        envelope.extend_from_slice(&bytes);
    }
    let evidence = RgbEvidence::decode(&envelope, pin.evidence, limits.evidence, copy_work, cx)?;
    authorize(pin, authority, RgbArchiveOperation::ReadOriginals, cx)?;
    Ok(evidence)
}

fn authorize(
    pin: RgbArchivePin,
    auth: &dyn RgbArchiveAuthority,
    operation: RgbArchiveOperation,
    cx: &ReplayCx,
) -> Result<()> {
    cx.checkpoint("rgb-archive:authority")
        .map_err(|_| RgbArchiveError::Cancelled)?;
    if !auth.permits(operation, pin.retention, pin.evidence) {
        return Err(RgbArchiveError::Denied);
    }
    Ok(())
}
fn admit(
    d: &ReferenceDeployment,
    pin: RgbArchivePin,
    l: RgbArchiveLimits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<()> {
    cx.checkpoint("rgb-archive:admit")
        .map_err(|_| RgbArchiveError::Cancelled)?;
    pin.slot()?;
    if !(1024..=64 * 1024 * 1024).contains(&l.maximum_spool_object_bytes)
        || !(1..=262_144).contains(&l.maximum_ledger_deltas)
        || d.publisher().limits().spool.max_object_bytes > l.maximum_spool_object_bytes
    {
        return Err(RgbArchiveError::Limit);
    }
    if d.publisher().is_poisoned() {
        return Err(RgbArchiveError::NotCommitted);
    }
    let mut count = 0usize;
    for batch in d.ledger().batches() {
        work.charge(1 + batch.deltas.len() as u64)?;
        count = count
            .checked_add(batch.deltas.len())
            .ok_or(RgbArchiveError::Limit)?;
        if count > l.maximum_ledger_deltas {
            return Err(RgbArchiveError::Limit);
        }
    }
    work.charge(d.publisher().limits().spool.max_object_bytes as u64 * 4)?;
    Ok(())
}
fn not_deleted(
    d: &ReferenceDeployment,
    digest: ContentDigest,
    work: &mut WorkBudget<'_>,
) -> Result<()> {
    work.charge(d.publisher().limits().max_tombstones as u64 + 1)?;
    if d.publisher().tombstones().any(|v| *v == digest) {
        return Err(RgbArchiveError::Tombstoned);
    }
    Ok(())
}
fn read(
    d: &ReferenceDeployment,
    pin: RgbArchivePin,
    digest: ContentDigest,
    maximum: usize,
    auth: &dyn RgbArchiveAuthority,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>> {
    authorize(pin, auth, RgbArchiveOperation::ReadOriginals, cx)?;
    not_deleted(d, digest, work)?;
    work.charge(d.publisher().limits().spool.max_object_bytes as u64 * 3)?;
    let bytes = d.publisher().spool().read(digest).map_err(storage)?;
    if bytes.len() > maximum {
        return Err(RgbArchiveError::Limit);
    }
    if ContentDigest::sha256(&bytes) != digest {
        return Err(RgbArchiveError::Mismatch);
    }
    authorize(pin, auth, RgbArchiveOperation::ReadOriginals, cx)?;
    Ok(bytes)
}
struct Gate<'a> {
    pin: RgbArchivePin,
    authority: &'a dyn RgbArchiveAuthority,
    cx: &'a ReplayCx,
}
impl PublishCancellation for Gate<'_> {
    fn cancel_requested(&self, point: PublishCutPoint) -> bool {
        ReplayCancellationBridge(self.cx).cancel_requested(point)
            || !self.authority.permits(
                RgbArchiveOperation::RetainOriginals,
                self.pin.retention,
                self.pin.evidence,
            )
    }
}
