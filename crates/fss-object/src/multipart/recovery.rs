#![forbid(unsafe_code)]
//! Bounded, inert multipart checkpoints and an explicit durable write boundary.
//!
//! A checkpoint describes knowledge and the original authority ceiling. It never
//! recreates a live runtime authority. Reopening requires an independently held
//! journal pin and a fresh, explicitly authorized object-store child.

use fss_core::{
    BudgetVector, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContextAuthority, DigestAlgorithm, OperationId, RegionTree, RuntimeGrant,
    TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::grant::GrantSet;

use super::{
    AbortReceipt, CompletionReceipt, ETag, MultipartError, MultipartPhase, PartReceipt,
    TransportOperation, UploadId, UploadIntent, valid_label,
};
use crate::planner::{ChunkPlan, ChunkPolicy, MAX_PARTS, plan_chunks};

/// Hard allocation/read bound for one full protocol checkpoint.
pub const MAX_UPLOAD_CHECKPOINT_BYTES: usize = 16 * 1024 * 1024;
/// Bound on the uploader's canonical authority/obligation metadata.
pub const MAX_UPLOAD_OWNER_METADATA_BYTES: usize = 64 * 1024;
const DOMAIN: &str = "fss.multipart_checkpoint.v1";
const MAX_AUTHORITY_BYTES: usize = 64 * 1024;

/// An independently retainable durable journal head, not a runtime capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadJournalPin {
    /// One-based committed record sequence.
    pub sequence: u64,
    /// Digest of the journal's complete committed envelope at this sequence.
    pub root: ContentDigest,
}

/// Explicit single-writer, compare-and-append checkpoint storage.
///
/// Success means the complete record and its discoverable head are durable and
/// read back. Implementations must bound recovery, reject forks/gaps/corruption,
/// enforce exclusive ownership and stop after an ambiguous write until reopen.
/// Journal I/O has a separate allowance from the provider's transport budget.
pub trait UploadJournal {
    /// Current verified durable head, or none for an empty journal.
    fn head(&self) -> Option<UploadJournalPin>;
    /// Canonical checkpoint belonging to exactly `head()`.
    fn latest(&self) -> Option<&[u8]>;
    /// Whether this exact pin occurs in the verified complete chain.
    fn contains(&self, pin: UploadJournalPin) -> bool;
    /// Append only if the current head equals `expected`.
    fn append(
        &mut self,
        expected: Option<UploadJournalPin>,
        checkpoint: &[u8],
    ) -> Result<UploadJournalPin, MultipartError>;
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct Checkpoint {
    pub plan: ChunkPlan,
    pub intent: UploadIntent,
    pub upload: Option<UploadId>,
    pub phase: MultipartPhase,
    pub intended: Vec<Option<ContentDigest>>,
    pub parts: Vec<Option<PartReceipt>>,
    pub observed_at: TimestampNs,
    pub original_authority: ContextAuthority,
    pub effective_authority: ContextAuthority,
    pub consumed: BudgetVector,
    pub grant_mask: u8,
    pub cancelled: bool,
    pub owner_metadata: Vec<u8>,
}

/// Validated recovery data. Its bytes and authority recipe remain inert.
#[derive(Clone, Debug, PartialEq)]
pub struct MultipartRecovery {
    pub(super) checkpoint: Checkpoint,
    head: UploadJournalPin,
}

impl MultipartRecovery {
    /// Read the latest canonical state only after proving the independently
    /// supplied minimum pin belongs to the current journal's complete chain.
    pub fn read(
        journal: &dyn UploadJournal,
        minimum: UploadJournalPin,
    ) -> Result<Self, MultipartError> {
        let head = journal.head().ok_or(MultipartError::RecoveryPinMismatch)?;
        if !valid_pin(minimum)
            || !valid_pin(head)
            || minimum.sequence > head.sequence
            || !journal.contains(minimum)
            || !journal.contains(head)
        {
            return Err(MultipartError::RecoveryPinMismatch);
        }
        let bytes = journal.latest().ok_or(MultipartError::InvalidCheckpoint)?;
        let checkpoint = Checkpoint::decode(bytes)?;
        Ok(Self { checkpoint, head })
    }

    /// Preflight journal identity and clock before reserving a fresh child.
    /// This is read-only and performs no provider or journal writes.
    pub fn validate_restore(
        &self,
        journal: &dyn UploadJournal,
        now: TimestampNs,
    ) -> Result<(), MultipartError> {
        if now < self.observed_at() {
            return Err(MultipartError::ClockRegression);
        }
        if journal.head() != Some(self.head)
            || !journal.contains(self.head)
            || journal.latest() != Some(self.checkpoint.encode()?.as_slice())
        {
            return Err(MultipartError::RecoveryPinMismatch);
        }
        Ok(())
    }

    /// Validate an inert proposed fresh child before runtime reservation. The
    /// caller still has to create and present a genuine live ObjectStore child.
    pub(crate) fn validate_authority(
        &self,
        canonical: &ContextAuthority,
        grants: &GrantSet,
    ) -> Result<(), MultipartError> {
        let mut canonical = canonical.clone();
        canonical.cancellation_reason = None;
        validate_context_narrowing(&canonical, &self.checkpoint.effective_authority)?;
        let mask = [
            RuntimeGrant::ObjectStage,
            RuntimeGrant::ObjectPublish,
            RuntimeGrant::AdapterNet,
        ]
        .into_iter()
        .enumerate()
        .fold(0, |mask, (index, grant)| {
            mask | (u8::from(
                grants
                    .require_grant_for(grant, self.intent().resource())
                    .is_ok(),
            ) << index)
        });
        if canonical.budgets != self.remaining_budget() || mask & !self.checkpoint.grant_mask != 0 {
            return Err(MultipartError::OwnerMismatch);
        }
        Ok(())
    }

    /// Exact canonical chunk layout, including its cost row.
    #[must_use]
    pub fn plan(&self) -> &ChunkPlan {
        &self.checkpoint.plan
    }
    /// Stable original provider idempotency intent.
    #[must_use]
    pub fn intent(&self) -> &UploadIntent {
        &self.checkpoint.intent
    }
    /// Last durably acknowledged provider knowledge.
    #[must_use]
    pub const fn phase(&self) -> MultipartPhase {
        self.checkpoint.phase
    }
    /// Latest durably observed time; recovery may not move it backwards.
    #[must_use]
    pub const fn observed_at(&self) -> TimestampNs {
        self.checkpoint.observed_at
    }
    /// Original immutable workflow budget ceiling.
    #[must_use]
    pub const fn original_budget(&self) -> BudgetVector {
        self.checkpoint.original_authority.budgets
    }
    /// Cumulative consumption across every previous execution epoch.
    #[must_use]
    pub const fn consumed(&self) -> BudgetVector {
        self.checkpoint.consumed
    }
    /// Only this remaining allowance may be reserved in a fresh parent.
    #[must_use]
    pub fn remaining_budget(&self) -> BudgetVector {
        // Decoding proves consumption fits the original ceiling.
        self.original_budget()
            .checked_sub(&self.consumed())
            .unwrap_or(BudgetVector::ZERO)
    }
    /// Preserved deadline, including any subsequently narrowed deadline.
    #[must_use]
    pub const fn deadline(&self) -> Option<TimestampNs> {
        self.checkpoint.effective_authority.deadline
    }
    /// Original inert canonical scope recipe, never an AuthorityCx.
    #[must_use]
    pub fn original_authority(&self) -> &ContextAuthority {
        &self.checkpoint.original_authority
    }
    /// Latest canonical restriction recipe, also inert.
    #[must_use]
    pub fn effective_authority(&self) -> &ContextAuthority {
        &self.checkpoint.effective_authority
    }
    /// Cancellation observed at any persisted boundary cannot be forgotten.
    #[must_use]
    pub const fn cancelled(&self) -> bool {
        self.checkpoint.cancelled
    }
    /// Empty for a protocol-only session; otherwise canonical StagedUpload metadata.
    #[must_use]
    pub fn owner_metadata(&self) -> &[u8] {
        &self.checkpoint.owner_metadata
    }
    /// Exact head validated by this recovery object.
    #[must_use]
    pub const fn head(&self) -> UploadJournalPin {
        self.head
    }
    /// Already established completion proof, with no provider I/O.
    pub fn completion_receipt(&self) -> Result<CompletionReceipt, MultipartError> {
        if self.phase() != MultipartPhase::Completed {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(CompletionReceipt {
            intent_digest: self.checkpoint.intent.digest,
            upload: self
                .checkpoint
                .upload
                .clone()
                .ok_or(MultipartError::InvalidCheckpoint)?,
            parts: self.checkpoint.parts.iter().flatten().cloned().collect(),
            manifest_root: self.checkpoint.intent.manifest_root,
        })
    }
    /// Already established abort proof, with no provider I/O.
    pub fn abort_receipt(&self) -> Result<AbortReceipt, MultipartError> {
        if self.phase() != MultipartPhase::Aborted {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(AbortReceipt {
            intent_digest: self.checkpoint.intent.digest,
            upload: self.checkpoint.upload.clone(),
            confirmed_parts: self.checkpoint.parts.iter().flatten().count(),
        })
    }
}

/// Validate canonical bytes and monotone protocol/owner evolution. A storage
/// backend must call this both on append and for every record during cold open.
pub fn validate_checkpoint_transition(
    previous: Option<&[u8]>,
    next: &[u8],
) -> Result<(), MultipartError> {
    let next = Checkpoint::decode(next)?;
    let previous = previous.map(Checkpoint::decode).transpose()?;
    validate_transition(previous.as_ref(), &next)
}

fn validate_transition(
    previous: Option<&Checkpoint>,
    next: &Checkpoint,
) -> Result<(), MultipartError> {
    next.validate()?;
    crate::uploader::validate_recovery_owner_transition(
        previous.map(|state| state.owner_metadata.as_slice()),
        &next.owner_metadata,
    )?;
    let Some(previous) = previous else {
        if next.phase != MultipartPhase::Prepared
            || next.upload.is_some()
            || next.intended.iter().any(Option::is_some)
            || next.parts.iter().any(Option::is_some)
            || next.original_authority != next.effective_authority
        {
            return Err(MultipartError::InvalidCheckpoint);
        }
        return Ok(());
    };
    if previous.plan != next.plan
        || previous.intent != next.intent
        || previous.original_authority != next.original_authority
        || previous.observed_at > next.observed_at
        || !previous.consumed.fits_within(next.consumed)
        || (previous.cancelled && !next.cancelled)
        || next.grant_mask & !previous.grant_mask != 0
        || previous
            .upload
            .as_ref()
            .is_some_and(|upload| next.upload.as_ref() != Some(upload))
    {
        return Err(MultipartError::InvalidCheckpoint);
    }
    validate_context_narrowing(&next.effective_authority, &previous.effective_authority)?;
    if !legal_phase_transition(previous.phase, next.phase) {
        return Err(MultipartError::InvalidCheckpoint);
    }
    let mut new_intents = 0;
    let mut new_receipts = 0;
    for index in 0..next.parts.len() {
        if previous.intended[index].is_some() && previous.intended[index] != next.intended[index]
            || previous.parts[index].is_some() && previous.parts[index] != next.parts[index]
        {
            return Err(MultipartError::InvalidCheckpoint);
        }
        new_intents +=
            usize::from(previous.intended[index].is_none() && next.intended[index].is_some());
        new_receipts += usize::from(previous.parts[index].is_none() && next.parts[index].is_some());
    }
    if new_intents > 0
        && (new_intents != 1
            || previous.phase != MultipartPhase::Uploading
            || next.phase != MultipartPhase::Uncertain(TransportOperation::UploadPart))
        || new_receipts > 0 && !matches!(previous.phase, MultipartPhase::Uncertain(_))
    {
        return Err(MultipartError::InvalidCheckpoint);
    }
    // Entering uncertainty is the write-ahead admission of one real request.
    if previous.phase != next.phase
        && matches!(next.phase, MultipartPhase::Uncertain(_))
        && next.consumed.storage_operations <= previous.consumed.storage_operations
    {
        return Err(MultipartError::InvalidCheckpoint);
    }
    Ok(())
}

fn legal_phase_transition(previous: MultipartPhase, next: MultipartPhase) -> bool {
    use MultipartPhase::{Aborted, Completed, Prepared, Uncertain, Uploading};
    use TransportOperation::{Abort, Complete, Initiate, UploadPart};
    previous == next
        || matches!(
            (previous, next),
            (Prepared, Uncertain(Initiate) | Aborted)
                | (Uploading, Uncertain(UploadPart | Complete | Abort))
                | (Uncertain(Initiate), Prepared | Uploading)
                | (Uncertain(UploadPart), Uploading)
                | (Uncertain(Complete), Uploading | Completed)
                | (Uncertain(Abort), Uploading | Aborted)
        )
}

pub(super) fn validate_context_narrowing(
    next: &ContextAuthority,
    previous: &ContextAuthority,
) -> Result<(), MultipartError> {
    next.verify_narrowing_of(previous)
        .map_err(|_| MultipartError::OwnerMismatch)?;
    if next.operation_id != previous.operation_id
        || next.privacy_scope != previous.privacy_scope
        || next.retention_scope != previous.retention_scope
        || next.lease_fence != previous.lease_fence
        || next.idempotency_key != previous.idempotency_key
        || next.lab_controls != previous.lab_controls
    {
        return Err(MultipartError::OwnerMismatch);
    }
    Ok(())
}

pub(super) fn context(
    authority: &AuthorityCx,
    tree: &RegionTree,
) -> Result<ContextAuthority, MultipartError> {
    let mut context = tree
        .get(authority.region())
        .map_err(|error| MultipartError::Authority(error.to_string()))?
        .authority
        .clone();
    // Cancellation is independently monotone; a fresh live region may have a
    // different diagnostic reason for the same inherited cancellation.
    context.cancellation_reason = None;
    if context.budgets != *authority.budget().limit() {
        return Err(MultipartError::OwnerMismatch);
    }
    context
        .validate()
        .map_err(|_| MultipartError::InvalidCheckpoint)?;
    Ok(context)
}

pub(super) fn grant_mask(authority: &AuthorityCx, resource: &str) -> u8 {
    [
        RuntimeGrant::ObjectStage,
        RuntimeGrant::ObjectPublish,
        RuntimeGrant::AdapterNet,
    ]
    .into_iter()
    .enumerate()
    .fold(0, |mask, (index, grant)| {
        mask | (u8::from(authority.require_grant_for(grant, resource).is_ok()) << index)
    })
}

fn valid_pin(pin: UploadJournalPin) -> bool {
    pin.sequence != 0 && valid_digest(pin.root)
}
fn valid_digest(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256
        && digest.bytes() != [0; 32]
        && !digest.is_laboratory()
}
fn invalid<T>(_: T) -> MultipartError {
    MultipartError::InvalidCheckpoint
}

impl Checkpoint {
    pub(super) fn validate(&self) -> Result<(), MultipartError> {
        let canonical = plan_chunks(
            self.plan.object_bytes,
            ChunkPolicy {
                part_size: self.plan.part_size,
            },
        )
        .map_err(invalid)?;
        if canonical != self.plan
            || self.intent.plan_digest != self.plan.digest()
            || !valid_label(self.intent.resource())
            || !valid_digest(self.intent.manifest_root)
            || self.intended.len() != self.plan.chunks.len()
            || self.parts.len() != self.plan.chunks.len()
            || self.owner_metadata.len() > MAX_UPLOAD_OWNER_METADATA_BYTES
            || self.grant_mask & !7 != 0
            || !self.consumed.fits_within(self.original_authority.budgets)
            || self.consumed.privacy_exposure() != 0.0
            || self.consumed.operator_attention_seconds() != 0.0
            || self.original_authority.operation_id != self.intent.operation
            || self.effective_authority.operation_id != self.intent.operation
            || self.original_authority.cancellation_reason.is_some()
            || self.effective_authority.cancellation_reason.is_some()
        {
            return Err(MultipartError::InvalidCheckpoint);
        }
        self.original_authority.validate().map_err(invalid)?;
        self.effective_authority.validate().map_err(invalid)?;
        validate_context_narrowing(&self.effective_authority, &self.original_authority)?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.multipart_intent.v2");
        encoder.text(self.intent.operation.as_str());
        encoder.text(&self.intent.resource);
        encoder.digest(self.intent.plan_digest);
        encoder.digest(self.intent.manifest_root);
        if self.intent.digest != ContentDigest::sha256(&encoder.finish())
            || self
                .upload
                .as_ref()
                .is_some_and(|upload| !valid_label(&upload.0))
        {
            return Err(MultipartError::InvalidCheckpoint);
        }
        for (index, (intended, receipt)) in self.intended.iter().zip(&self.parts).enumerate() {
            if intended.is_some_and(|digest| !valid_digest(digest)) {
                return Err(MultipartError::InvalidCheckpoint);
            }
            if let Some(receipt) = receipt
                && (receipt.index != index as u64
                    || Some(receipt.content_digest) != *intended
                    || !valid_label(&receipt.etag.0))
            {
                return Err(MultipartError::InvalidCheckpoint);
            }
        }
        match self.phase {
            MultipartPhase::Prepared | MultipartPhase::Uncertain(TransportOperation::Initiate) => {
                if self.upload.is_some()
                    || self.intended.iter().any(Option::is_some)
                    || self.parts.iter().any(Option::is_some)
                {
                    return Err(MultipartError::InvalidCheckpoint);
                }
            }
            MultipartPhase::Uploading
            | MultipartPhase::Uncertain(
                TransportOperation::UploadPart | TransportOperation::Abort,
            ) => {
                if self.upload.is_none() {
                    return Err(MultipartError::InvalidCheckpoint);
                }
            }
            MultipartPhase::Completed | MultipartPhase::Uncertain(TransportOperation::Complete) => {
                if self.upload.is_none() || self.parts.iter().any(Option::is_none) {
                    return Err(MultipartError::InvalidCheckpoint);
                }
            }
            MultipartPhase::Aborted => {
                if self.upload.is_none()
                    && (self.intended.iter().any(Option::is_some)
                        || self.parts.iter().any(Option::is_some))
                {
                    return Err(MultipartError::InvalidCheckpoint);
                }
            }
            MultipartPhase::Uncertain(TransportOperation::Reconcile) => {
                return Err(MultipartError::InvalidCheckpoint);
            }
        }
        Ok(())
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, MultipartError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.u64(self.plan.object_bytes);
        e.u64(self.plan.part_size);
        e.u64(self.plan.wire_bytes);
        e.u64(self.plan.transfer_work);
        e.digest(self.intent.plan_digest);
        e.text(self.intent.operation.as_str());
        e.text(&self.intent.resource);
        e.digest(self.intent.manifest_root);
        e.digest(self.intent.digest);
        e.bool(self.upload.is_some());
        if let Some(upload) = &self.upload {
            e.text(&upload.0);
        }
        e.tag(phase_tag(self.phase)?);
        e.u64(self.parts.len() as u64);
        for (intended, receipt) in self.intended.iter().zip(&self.parts) {
            e.bool(intended.is_some());
            if let Some(digest) = intended {
                e.digest(*digest);
            }
            e.bool(receipt.is_some());
            if let Some(receipt) = receipt {
                e.u64(receipt.index);
                e.digest(receipt.content_digest);
                e.text(&receipt.etag.0);
            }
        }
        e.i128(self.observed_at.0);
        encode_authority(&mut e, &self.original_authority)?;
        encode_authority(&mut e, &self.effective_authority)?;
        self.consumed.encode_canonical(&mut e);
        e.tag(self.grant_mask);
        e.bool(self.cancelled);
        e.bytes(&self.owner_metadata);
        let bytes = e.finish_checked().map_err(invalid)?;
        if bytes.len() > MAX_UPLOAD_CHECKPOINT_BYTES {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, MultipartError> {
        if bytes.is_empty() || bytes.len() > MAX_UPLOAD_CHECKPOINT_BYTES {
            return Err(MultipartError::InvalidCheckpoint);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text().map_err(invalid)? != DOMAIN {
            return Err(MultipartError::InvalidCheckpoint);
        }
        let object_bytes = d.u64().map_err(invalid)?;
        let part_size = d.u64().map_err(invalid)?;
        let plan = plan_chunks(object_bytes, ChunkPolicy { part_size }).map_err(invalid)?;
        if d.u64().map_err(invalid)? != plan.wire_bytes
            || d.u64().map_err(invalid)? != plan.transfer_work
        {
            return Err(MultipartError::InvalidCheckpoint);
        }
        let plan_digest = d.digest().map_err(invalid)?;
        let operation = OperationId::parse(d.text().map_err(invalid)?).map_err(invalid)?;
        let resource = label(&mut d)?;
        let manifest_root = d.digest().map_err(invalid)?;
        let digest = d.digest().map_err(invalid)?;
        let intent = UploadIntent {
            operation,
            resource,
            plan_digest,
            manifest_root,
            digest,
        };
        let upload = if d.bool().map_err(invalid)? {
            Some(UploadId(label(&mut d)?))
        } else {
            None
        };
        let phase = decode_phase(d.tag().map_err(invalid)?)?;
        let count = d.u64().map_err(invalid)?;
        if count > MAX_PARTS || count != plan.chunks.len() as u64 {
            return Err(MultipartError::InvalidCheckpoint);
        }
        let mut intended = Vec::with_capacity(count as usize);
        let mut parts = Vec::with_capacity(count as usize);
        for _ in 0..count {
            intended.push(if d.bool().map_err(invalid)? {
                Some(d.digest().map_err(invalid)?)
            } else {
                None
            });
            parts.push(if d.bool().map_err(invalid)? {
                Some(PartReceipt {
                    index: d.u64().map_err(invalid)?,
                    content_digest: d.digest().map_err(invalid)?,
                    etag: ETag(label(&mut d)?),
                })
            } else {
                None
            });
        }
        let observed_at = TimestampNs(d.i128().map_err(invalid)?);
        let original_authority = decode_authority(&mut d)?;
        let effective_authority = decode_authority(&mut d)?;
        let consumed =
            <BudgetVector as CanonicalDecode>::decode_canonical(&mut d).map_err(invalid)?;
        let grant_mask = d.tag().map_err(invalid)?;
        let cancelled = d.bool().map_err(invalid)?;
        let owner_bytes = d.bytes().map_err(invalid)?;
        if owner_bytes.len() > MAX_UPLOAD_OWNER_METADATA_BYTES {
            return Err(MultipartError::InvalidCheckpoint);
        }
        let owner_metadata = owner_bytes.to_vec();
        d.ensure_finished().map_err(invalid)?;
        let checkpoint = Self {
            plan,
            intent,
            upload,
            phase,
            intended,
            parts,
            observed_at,
            original_authority,
            effective_authority,
            consumed,
            grant_mask,
            cancelled,
            owner_metadata,
        };
        checkpoint.validate()?;
        crate::uploader::validate_recovery_owner_transition(None, &checkpoint.owner_metadata)?;
        if checkpoint.encode()?.as_slice() != bytes {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(checkpoint)
    }
}

fn label(decoder: &mut CanonicalDecoder<'_>) -> Result<String, MultipartError> {
    let value = decoder.text().map_err(invalid)?;
    if !valid_label(value) {
        return Err(MultipartError::InvalidCheckpoint);
    }
    Ok(value.to_owned())
}
fn encode_authority(
    e: &mut CanonicalEncoder,
    authority: &ContextAuthority,
) -> Result<(), MultipartError> {
    let mut inner = CanonicalEncoder::new();
    authority.encode_canonical(&mut inner);
    let bytes = inner.finish_checked().map_err(invalid)?;
    if bytes.len() > MAX_AUTHORITY_BYTES {
        return Err(MultipartError::InvalidCheckpoint);
    }
    e.bytes(&bytes);
    Ok(())
}
fn decode_authority(d: &mut CanonicalDecoder<'_>) -> Result<ContextAuthority, MultipartError> {
    let bytes = d.bytes().map_err(invalid)?;
    if bytes.len() > MAX_AUTHORITY_BYTES {
        return Err(MultipartError::InvalidCheckpoint);
    }
    let mut inner = CanonicalDecoder::new(bytes);
    let authority = ContextAuthority::decode_canonical(&mut inner).map_err(invalid)?;
    inner.ensure_finished().map_err(invalid)?;
    Ok(authority)
}
fn phase_tag(phase: MultipartPhase) -> Result<u8, MultipartError> {
    match phase {
        MultipartPhase::Prepared => Ok(0),
        MultipartPhase::Uploading => Ok(1),
        MultipartPhase::Uncertain(TransportOperation::Initiate) => Ok(2),
        MultipartPhase::Uncertain(TransportOperation::UploadPart) => Ok(3),
        MultipartPhase::Uncertain(TransportOperation::Complete) => Ok(4),
        MultipartPhase::Uncertain(TransportOperation::Abort) => Ok(5),
        MultipartPhase::Completed => Ok(6),
        MultipartPhase::Aborted => Ok(7),
        MultipartPhase::Uncertain(TransportOperation::Reconcile) => {
            Err(MultipartError::InvalidCheckpoint)
        }
    }
}
fn decode_phase(tag: u8) -> Result<MultipartPhase, MultipartError> {
    match tag {
        0 => Ok(MultipartPhase::Prepared),
        1 => Ok(MultipartPhase::Uploading),
        2 => Ok(MultipartPhase::Uncertain(TransportOperation::Initiate)),
        3 => Ok(MultipartPhase::Uncertain(TransportOperation::UploadPart)),
        4 => Ok(MultipartPhase::Uncertain(TransportOperation::Complete)),
        5 => Ok(MultipartPhase::Uncertain(TransportOperation::Abort)),
        6 => Ok(MultipartPhase::Completed),
        7 => Ok(MultipartPhase::Aborted),
        _ => Err(MultipartError::InvalidCheckpoint),
    }
}

pub(super) struct DurableState<'a> {
    pub journal: &'a mut dyn UploadJournal,
    pub expected: Option<UploadJournalPin>,
    pub historical_consumed: BudgetVector,
    pub last: Checkpoint,
    pub poisoned: bool,
}

impl DurableState<'_> {
    pub(super) fn ensure_ready(&self) -> Result<(), MultipartError> {
        if self.poisoned {
            return Err(MultipartError::DurabilityFailed);
        }
        if self.journal.head() != self.expected {
            return Err(MultipartError::RecoveryPinMismatch);
        }
        Ok(())
    }

    pub(super) fn cumulative(&self, current: BudgetVector) -> Result<BudgetVector, MultipartError> {
        let consumed = self
            .historical_consumed
            .checked_add(&current)
            .map_err(invalid)?;
        if !consumed.fits_within(self.last.original_authority.budgets) {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(consumed)
    }

    pub(super) fn persist(
        &mut self,
        checkpoint: Checkpoint,
    ) -> Result<UploadJournalPin, MultipartError> {
        self.ensure_ready()?;
        let result = (|| {
            let bytes = checkpoint.encode()?;
            validate_checkpoint_transition(self.journal.latest(), &bytes)?;
            if self.journal.latest() == Some(bytes.as_slice()) {
                return self.expected.ok_or(MultipartError::InvalidCheckpoint);
            }
            let next_sequence = self
                .expected
                .map_or(Some(1), |pin| pin.sequence.checked_add(1))
                .ok_or(MultipartError::InvalidCheckpoint)?;
            let pin = self.journal.append(self.expected, &bytes)?;
            if !valid_pin(pin)
                || pin.sequence != next_sequence
                || self.journal.head() != Some(pin)
                || !self.journal.contains(pin)
                || self.journal.latest() != Some(bytes.as_slice())
            {
                return Err(MultipartError::RecoveryPinMismatch);
            }
            Ok(pin)
        })();
        match result {
            Ok(pin) => {
                self.expected = Some(pin);
                self.last = checkpoint;
                Ok(pin)
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
}

/// Private effect-boundary hook; adapters cannot replace or remove it.
pub(super) trait TransportPersistence {
    fn record(
        &mut self,
        consumed: BudgetVector,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<(), MultipartError>;
}

pub(super) struct DispatchJournal<'call, 'journal> {
    pub durable: &'call mut DurableState<'journal>,
    pub checkpoint: Checkpoint,
}
impl TransportPersistence for DispatchJournal<'_, '_> {
    fn record(
        &mut self,
        consumed: BudgetVector,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<(), MultipartError> {
        self.checkpoint.consumed = self.durable.cumulative(consumed)?;
        self.checkpoint.observed_at = now;
        self.checkpoint.cancelled |= cancelled;
        self.durable.persist(self.checkpoint.clone())?;
        Ok(())
    }
}
