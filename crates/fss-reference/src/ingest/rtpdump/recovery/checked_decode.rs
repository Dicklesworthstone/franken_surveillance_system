#![forbid(unsafe_code)]
//! Optional current-custody delivery over the existing frozen-snapshot RTP decoder.
//!
//! The existing decoder owns parameter selection, packet ordering, recovery, capture-time
//! uncertainty and privacy. This layer adds bounded graph readback and canonical deletion
//! denial before delivery. It does not reinterpret media or change the snapshot API.
//! Callers must authorize deployment access before entering this reference boundary.

/// Optional portable receipts jointly delivered with custody-checked frames.
pub mod receipt;

use super::decode::{
    RetainedRtpDecodeError, RetainedRtpDecodeRequest, RetainedRtpDecodeStats,
    RetainedRtpDecodeStep, RetainedRtpH264Decoder,
};
use super::{RecoveredRtpImport, RtpRecoveryState, root_hex, root_slot};
use crate::deletion::{DeletionError, DeletionIndex};
use crate::ingest::privacy_mask::{MAX_MASK_POLICY_BYTES, MaskBinding, current_mask};
use crate::{ReferenceDeployment, ReplayCx};
use fss_core::ContentDigest;
use fss_publication::LocalPublicationState;

/// Independent admission for live custody checks, in addition to native decode limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpCustodyDecodeLimits {
    /// Maximum original snapshot length (1..=256 MiB).
    pub max_source_bytes: usize,
    /// Maximum recorded inputs (1..=65,536).
    pub max_records: usize,
    /// Maximum one-object allocation (1..=64 MiB).
    pub max_object_bytes: usize,
    /// Lifetime custody-read allowance (at most 2 GiB), separate from initial recovery reads.
    pub max_read_bytes: u64,
    /// Lifetime progress calls (1..=5,000,000), not replenished by decoder recovery.
    pub max_steps: usize,
    /// Maximum candidate entries in the complete protected graph (1..=65,536).
    pub max_graph_objects: usize,
}
impl Default for RtpCustodyDecodeLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 64 * 1024 * 1024,
            max_records: 65_536,
            max_object_bytes: 64 * 1024 * 1024,
            max_read_bytes: 512 * 1024 * 1024,
            max_steps: 1_000_000,
            max_graph_objects: 65_536,
        }
    }
}

/// Refusal of this additional custody boundary, never an unmasked fallback.
#[derive(Debug)]
pub enum CheckedRtpDecodeError {
    /// Existing native decoder, source or privacy owner refused the operation.
    Native(Box<RetainedRtpDecodeError>),
    /// Inspection authority or publication root changed; reopen from a fresh inspection.
    StaleBasis,
    /// Current custody or canonical deletion authority could not be verified.
    Custody,
    /// Committed deletion denies a protected object, even before its physical unlink.
    Deleted,
    /// An independent source, graph, allocation, read or progress budget was exhausted.
    Limit,
    /// Cancellation stopped delivery and retired the owned decoder.
    Cancelled,
}
impl std::fmt::Display for CheckedRtpDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "current-custody RTP decode refused: {self:?}")
    }
}
impl std::error::Error for CheckedRtpDecodeError {}
impl From<RetainedRtpDecodeError> for CheckedRtpDecodeError {
    fn from(error: RetainedRtpDecodeError) -> Self {
        Self::Native(Box::new(error))
    }
}
impl From<DeletionError> for CheckedRtpDecodeError {
    fn from(_: DeletionError) -> Self {
        Self::Custody
    }
}
type Result<T> = std::result::Result<T, CheckedRtpDecodeError>;

struct Reads {
    object: usize,
    remaining: u64,
    used: u64,
}
impl Reads {
    fn reserve(&mut self, deployment: &ReferenceDeployment, cx: &ReplayCx) -> Result<usize> {
        checkpoint(cx)?;
        let ceiling = deployment.publisher().spool().limits().max_object_bytes;
        if ceiling > self.object || self.remaining < ceiling as u64 {
            return Err(CheckedRtpDecodeError::Limit);
        }
        self.remaining -= ceiling as u64;
        self.used += ceiling as u64;
        Ok(ceiling)
    }
    fn refund(&mut self, bytes: usize) {
        self.remaining += bytes as u64;
        self.used -= bytes as u64;
    }
    fn read(
        &mut self,
        deployment: &ReferenceDeployment,
        digest: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<Vec<u8>> {
        let ceiling = self.reserve(deployment, cx)?;
        if deployment.publisher().tombstones().any(|d| *d == digest) {
            return Err(CheckedRtpDecodeError::Deleted);
        }
        let bytes = deployment
            .publisher()
            .spool()
            .read(digest)
            .map_err(|_| CheckedRtpDecodeError::Custody)?;
        if bytes.len() > ceiling || ContentDigest::sha256(&bytes) != digest {
            return Err(CheckedRtpDecodeError::Custody);
        }
        self.refund(ceiling - bytes.len());
        Ok(bytes)
    }
}

/// The native retained decoder with an additional current-custody delivery gate.
///
/// Each delivered frame re-reads the complete graph, including reference-picture originals.
/// This conservative bounded reference profile is not a throughput optimization. Its read
/// allowance is cumulative across outputs and IDR recovery; failure drops queued output.
pub struct CheckedRetainedRtpH264Decoder<'a> {
    retained: &'a RecoveredRtpImport,
    inner: Option<RetainedRtpH264Decoder<'a>>,
    protected: Vec<ContentDigest>,
    mask: MaskBinding,
    reads: Reads,
    max_steps: usize,
    steps: usize,
    stats: RetainedRtpDecodeStats,
}
impl std::fmt::Debug for CheckedRetainedRtpH264Decoder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckedRetainedRtpH264Decoder")
            .field("root", &self.retained.root)
            .field("stats", &self.stats)
            .field("read_bytes", &self.reads.used)
            .finish_non_exhaustive()
    }
}

impl RecoveredRtpImport {
    /// Open an explicitly current-custody consumer without replacing the existing snapshot API.
    /// The initial recovery inspection and this consumer have separate, declared read budgets.
    pub fn decode_h264_checked(
        &self,
        request: RetainedRtpDecodeRequest,
        limits: RtpCustodyDecodeLimits,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<CheckedRetainedRtpH264Decoder<'_>> {
        checkpoint(cx)?;
        if !matches!(self.state, RtpRecoveryState::Complete { .. }) {
            return Err(RetainedRtpDecodeError::ImportPending.into());
        }
        if !(1..=256 * 1024 * 1024).contains(&limits.max_source_bytes)
            || !(1..=65_536).contains(&limits.max_records)
            || !(1..=64 * 1024 * 1024).contains(&limits.max_object_bytes)
            || limits.max_read_bytes < limits.max_object_bytes as u64
            || limits.max_read_bytes > 2 * 1024 * 1024 * 1024
            || !(1..=5_000_000).contains(&limits.max_steps)
            || !(1..=65_536).contains(&limits.max_graph_objects)
            || self.source.len() > limits.max_source_bytes
            || self.report.records().len() > limits.max_records
        {
            return Err(CheckedRtpDecodeError::Limit);
        }
        guard(self, deployment, cx)?;
        let mut reads = Reads {
            object: limits.max_object_bytes,
            remaining: limits.max_read_bytes,
            used: 0,
        };
        // Denials are canonical authority, not merely the publisher's physical tombstones.
        let deletions = DeletionIndex::from_batches::<CheckedRtpDecodeError>(
            deployment.ledger().batches(),
            |digest| reads.read(deployment, digest, cx),
        )?;
        if deletions.import(self.root).is_some()
            || deletions.unit_deleted(&format!("slot:rtp-{}", root_hex(self.root)))
            || deletions.object(self.root).is_some()
        {
            return Err(CheckedRtpDecodeError::Deleted);
        }
        let root = reads.read(deployment, self.root, cx)?;
        let manifest = fss_object::ObjectManifest::from_canonical_bytes(&root)
            .map_err(|_| CheckedRtpDecodeError::Custody)?;
        let count = manifest
            .children()
            .len()
            .checked_add(3)
            .ok_or(CheckedRtpDecodeError::Limit)?;
        if count > limits.max_graph_objects {
            return Err(CheckedRtpDecodeError::Limit);
        }
        let mut protected = Vec::new();
        protected
            .try_reserve_exact(count)
            .map_err(|_| CheckedRtpDecodeError::Limit)?;
        protected.push(self.root);
        protected.extend(manifest.children().iter().copied());
        protected.extend(manifest.metadata_digest());
        let ceiling = reads.reserve(deployment, cx)?;
        let mask = current_mask(deployment, &self.recipe.scope.sensor)
            .map_err(RetainedRtpDecodeError::from)?;
        let policy_charge = if mask.policy_digest().is_some() {
            ceiling.min(MAX_MASK_POLICY_BYTES)
        } else {
            0
        };
        reads.refund(ceiling - policy_charge);
        protected.extend(mask.policy_digest());
        protected.sort_unstable();
        protected.dedup();
        if protected
            .iter()
            .any(|digest| deletions.object(*digest).is_some())
        {
            return Err(CheckedRtpDecodeError::Deleted);
        }
        // Retained RTP publication is one flat manifest: its direct children include source
        // chunks, NALs, source capsules and their exact source envelopes. No nested graph is
        // invented here. Native recovery verified this manifest against its canonical recipe.
        for digest in &protected {
            reads.read(deployment, *digest, cx)?;
        }
        // The native constructor resolves the same mask once. Reserve before its possible
        // read too; conservatively charge the maximum valid policy payload on success.
        let ceiling = reads.reserve(deployment, cx)?;
        let inner = self.decode_h264(request, deployment, cx)?;
        reads.refund(ceiling - policy_charge.min(ceiling));
        guard(self, deployment, cx)?;
        Ok(CheckedRetainedRtpH264Decoder {
            retained: self,
            inner: Some(inner),
            protected,
            mask,
            reads,
            max_steps: limits.max_steps,
            steps: 0,
            stats: RetainedRtpDecodeStats::default(),
        })
    }
}

impl CheckedRetainedRtpH264Decoder<'_> {
    /// Native progress with only custody-checked, actually delivered frames counted.
    pub fn stats(&self) -> RetainedRtpDecodeStats {
        self.stats
    }
    /// Lifetime charged read bytes, including constructor reads and failed reservations.
    pub fn read_bytes(&self) -> u64 {
        self.reads.used
    }
    /// Lifetime progress calls; recovery never resets this count.
    pub fn steps(&self) -> usize {
        self.steps
    }
    /// Queued native output remains private until this layer's delivery checks pass.
    pub fn queued_pictures(&self) -> usize {
        self.inner
            .as_ref()
            .map_or(0, RetainedRtpH264Decoder::queued_pictures)
    }
    /// One bounded event or one fully masked, freshly custody-checked frame.
    /// A failed attempt is permanently fenced. Already delivered frames remain historical views.
    pub fn step(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<RetainedRtpDecodeStep> {
        if self.inner.is_none() {
            return Ok(RetainedRtpDecodeStep::Ended(self.stats));
        }
        let before = self.stats.refusals;
        let result = self.advance(deployment, cx);
        if result.is_err() {
            self.inner = None;
            if self.stats.refusals == before {
                self.stats.refusals += 1;
            }
            self.stats.ended = true;
        }
        result
    }
    fn advance(
        &mut self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<RetainedRtpDecodeStep> {
        guard(self.retained, deployment, cx)?;
        if self.steps == self.max_steps {
            return Err(CheckedRtpDecodeError::Limit);
        }
        self.steps += 1;
        let delivered = self.stats.frames;
        let inner = self
            .inner
            .as_mut()
            .ok_or(CheckedRtpDecodeError::StaleBasis)?;
        let result = inner.step(deployment, cx);
        self.stats = inner.stats();
        self.stats.frames = delivered;
        match result? {
            RetainedRtpDecodeStep::Frame(frame) => {
                if frame.root() != self.retained.root
                    || frame.source().recording != self.retained.report.input_digest()
                    || frame.mask() != &self.mask
                {
                    return Err(CheckedRtpDecodeError::StaleBasis);
                }
                // Verify every dependency, not only this picture's own coded spans. Prediction
                // and B-picture decode-ahead can depend on other source positions in the graph.
                for digest in &self.protected {
                    self.reads.read(deployment, *digest, cx)?;
                }
                guard(self.retained, deployment, cx)?;
                self.stats.frames += 1;
                Ok(RetainedRtpDecodeStep::Frame(frame))
            }
            RetainedRtpDecodeStep::Ended(_) => {
                self.inner = None;
                Ok(RetainedRtpDecodeStep::Ended(self.stats))
            }
            step => Ok(step),
        }
    }
}

fn guard(
    retained: &RecoveredRtpImport,
    deployment: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<()> {
    checkpoint(cx)?;
    let publisher = deployment.publisher();
    let slot = root_slot(retained.root).map_err(|_| CheckedRtpDecodeError::StaleBasis)?;
    if deployment.current_anchor() != &retained.basis
        || publisher.is_poisoned()
        || publisher.tombstones().any(|digest| *digest == retained.root)
        || !publisher.root(&slot).is_some_and(|root| {
            root.root == retained.root && root.state == LocalPublicationState::Durable
        })
    {
        return Err(CheckedRtpDecodeError::StaleBasis);
    }
    Ok(())
}
fn checkpoint(cx: &ReplayCx) -> Result<()> {
    cx.checkpoint("rtpdump:checked_decode")
        .map_err(|_| CheckedRtpDecodeError::Cancelled)
}
