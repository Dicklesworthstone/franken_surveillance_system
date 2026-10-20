#![forbid(unsafe_code)]
//! Owned multipart protocol, with explicit authority at every transport call.
//!
//! This is an injected protocol boundary, not an HTTP client or proof of archive
//! retrievability. Provider ETags are opaque. Independent part checksums bind the
//! bytes; a complete receipt binds the exact intent, plan, root and ordered parts.
//! An acknowledgement lost after dispatch leaves the session owned and uncertain.
//! Only a conclusive, intent-bound provider reconciliation permits further work.

mod authority;
pub mod recovery;

pub use authority::{TransportCx, UploadIo};
pub use recovery::{
    MultipartRecovery, UploadJournal, UploadJournalPin, validate_checkpoint_transition,
};

use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, DigestAlgorithm, OperationId, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;

use recovery::{Checkpoint, DispatchJournal, DurableState, TransportPersistence};

use crate::planner::{ChunkPlan, ChunkPolicy, PlannedChunk, plan_chunks};

/// Bound on provider identifiers, opaque ETags and the exact target resource.
pub const MAX_TRANSPORT_LABEL_BYTES: usize = 1024;

/// Provider-issued multipart identity; never an authority token.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UploadId(pub String);

/// Opaque provider ETag. It is never interpreted as a content digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ETag(pub String);

/// The immutable, idempotent identity supplied on initiation and reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadIntent {
    operation: OperationId,
    resource: String,
    plan_digest: ContentDigest,
    manifest_root: ContentDigest,
    digest: ContentDigest,
}

impl UploadIntent {
    /// Exact operator resource, used by scoped network and object grants.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }
    /// Owner operation, not a new identity minted for each retry.
    #[must_use]
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }
    /// Idempotency key binding operation, target, plan and manifest root.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Exact chunk plan identity.
    #[must_use]
    pub const fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }
    /// Root intended for publication after all parts are confirmed.
    #[must_use]
    pub const fn manifest_root(&self) -> ContentDigest {
        self.manifest_root
    }
}

/// One provider-confirmed part, with independent checksum and opaque ETag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartReceipt {
    /// Zero-based canonical plan index.
    pub index: u64,
    /// Independently reported checksum of the exact uploaded bytes.
    pub content_digest: ContentDigest,
    /// Provider token carried unchanged into completion.
    pub etag: ETag,
}

/// External operation whose acknowledgement can be uncertain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportOperation {
    /// Create or locate the exact idempotent upload intent.
    Initiate,
    /// Upload one exact planned part.
    UploadPart,
    /// Publish the bound root with all confirmed part tokens.
    Complete,
    /// Abort this upload's uncommitted staging only.
    Abort,
    /// Observe the outcome of an already dispatched operation.
    Reconcile,
}

/// Honest local protocol state. Uncertain is neither completed nor aborted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultipartPhase {
    /// No transport call has occurred.
    Prepared,
    /// A provider upload exists; only its intended parts may be uploaded.
    Uploading,
    /// A dispatched call lacked a conclusive valid acknowledgement.
    Uncertain(TransportOperation),
    /// Provider completion was acknowledged or conclusively reconciled.
    Completed,
    /// Local preparation or remote staging was conclusively aborted.
    Aborted,
}

/// A conclusive provider observation for one immutable upload intent.
///
/// `Active` must be a complete, consistent part inventory that also rules out
/// outstanding completion/abort dispatches. An eventually consistent listing,
/// timeout, missing object, or partial listing must be `Unknown` instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderUploadState {
    /// The provider cannot yet establish the operation's outcome.
    Unknown,
    /// The exact initiation was conclusively never accepted; safe to initiate again.
    NotStarted,
    /// Exact upload is active and neither completed nor aborted.
    Active {
        /// The provider upload identity.
        upload: UploadId,
        /// Complete inventory, ordered by canonical part index.
        parts: Vec<PartReceipt>,
    },
    /// The exact complete operation committed this root and part inventory.
    Completed {
        /// Provider identity of the completed upload.
        upload: UploadId,
        /// Observed root, independently checked against the intent.
        manifest_root: ContentDigest,
        /// Every committed part in canonical plan order.
        parts: Vec<PartReceipt>,
    },
    /// Provider conclusively aborted the exact upload without root publication.
    Aborted {
        /// Provider identity of the aborted upload.
        upload: UploadId,
    },
}

/// Reconciliation response bound to the original idempotency key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reconciliation {
    /// Exact intent queried, not only an upload ID or object name.
    pub intent_digest: ContentDigest,
    /// Provider observation; unknown observations retain the pending owner.
    pub state: ProviderUploadState,
}

/// Injected transport. Each call receives the actual admitted child authority.
///
/// The implementation must preserve intent idempotency, enforce the part digest,
/// and use `cx` at its I/O boundary. Errors after dispatch are treated as unknown,
/// including initiation errors. There is no implicit retry or transport in this crate.
pub trait MultipartTransport {
    /// Initiate exactly once per intent key, or return the same existing upload.
    fn initiate(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<UploadId, String>;
    /// Upload only these plan-exact bytes, with an independent digest precondition.
    fn upload_part(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        chunk: &PlannedChunk,
        bytes: &[u8],
        content_digest: ContentDigest,
    ) -> Result<PartReceipt, String>;
    /// Complete only this intent and full ordered confirmed part list.
    fn complete(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        intent: &UploadIntent,
        parts: &[PartReceipt],
    ) -> Result<(), String>;
    /// Abort only this owned staging upload, never a committed object.
    fn abort(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        intent: &UploadIntent,
    ) -> Result<(), String>;
    /// Query this exact intent. A partial listing or missing ACK is not a terminal result.
    fn reconcile(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<Reconciliation, String>;
}

/// Typed refusal; every method retains the session so cleanup remains possible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MultipartError {
    /// Authority, scope, capability or budget refused before transport dispatch.
    Authority(String),
    /// The explicit durable journal refused or could not confirm a write.
    Persistence(String),
    /// Checkpoint bytes or their monotone state transition are invalid.
    InvalidCheckpoint,
    /// The independently retained head is absent, stale or belongs to another chain.
    RecoveryPinMismatch,
    /// A previous persistence failure requires a cold journal/session reopen.
    DurabilityFailed,
    /// Canonical chunk layout, bounds, root or target is invalid.
    InvalidIntent,
    /// Another owner attempted to use an already-bound session.
    OwnerMismatch,
    /// Supplied time moved backwards; no transport call occurred.
    ClockRegression,
    /// Authority expired; only bounded cleanup and reconciliation remain admissible.
    Deadline,
    /// Cancellation requested; staging still needs explicit drain.
    CancellationRequested,
    /// New work would consume the last operation reserved for cleanup.
    CleanupReserve,
    /// This transition is not legal in the current state.
    WrongState {
        /// Transition the caller attempted.
        operation: TransportOperation,
        /// Current knowledge of the upload's provider state.
        state: MultipartPhase,
    },
    /// A previous dispatch must be conclusively reconciled first.
    RequiresReconciliation {
        /// Original dispatch whose outcome remains uncertain.
        operation: TransportOperation,
    },
    /// Another plan was supplied, including a changed cost row.
    StalePlan {
        /// Plan bound at preparation.
        bound: ContentDigest,
        /// Plan supplied by the refused call.
        presented: ContentDigest,
    },
    /// Completion tried to replace the root bound at preparation.
    StaleRoot {
        /// Root bound at preparation.
        bound: ContentDigest,
        /// Replacement root supplied by the refused call.
        presented: ContentDigest,
    },
    /// No such canonical part index exists.
    UnknownPart {
        /// Refused zero-based index.
        index: u64,
    },
    /// Part length or bytes conflict with this part's first dispatched intent.
    PartConflict {
        /// Canonical index of the conflicting part.
        index: u64,
    },
    /// Provider acknowledgement does not attest the intended checksum/index/token.
    InvalidPartReceipt {
        /// Intended part whose acknowledgement was invalid.
        index: u64,
    },
    /// Completion is refused before every part has been confirmed.
    Incomplete {
        /// Checksum-confirmed parts currently owned.
        confirmed: usize,
        /// Complete canonical plan's part count.
        required: usize,
    },
    /// Dispatch has an unknown outcome; the session is retained and must reconcile.
    Transport {
        /// Dispatched operation, distinct from its unknown provider outcome.
        operation: TransportOperation,
        /// Adapter error; transport implementations must omit secrets and media.
        detail: String,
    },
    /// Provider reconciliation contradicts the original intent or accepted work.
    ReconciliationMismatch,
}

impl std::fmt::Display for MultipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "multipart refusal: {self:?}")
    }
}
impl std::error::Error for MultipartError {}

/// Completion acknowledgement, not an independent retrievability witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionReceipt {
    /// Exact immutable intent that was completed.
    pub intent_digest: ContentDigest,
    /// Provider upload identity.
    pub upload: UploadId,
    /// Ordered independent checksum and provider token for every part.
    pub parts: Vec<PartReceipt>,
    /// Root acknowledged after its parts.
    pub manifest_root: ContentDigest,
}
impl CompletionReceipt {
    /// Proof identity includes part bytes and provider tokens, not just the requested root.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text("fss.multipart_completion.v2");
        e.digest(self.intent_digest);
        e.text(&self.upload.0);
        e.digest(self.manifest_root);
        e.u64(self.parts.len() as u64);
        for part in &self.parts {
            e.u64(part.index);
            e.digest(part.content_digest);
            e.text(&part.etag.0);
        }
        ContentDigest::sha256(&e.finish())
    }
}

/// Conclusive local or provider abort acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbortReceipt {
    /// Exact intent whose staging was released.
    pub intent_digest: ContentDigest,
    /// Absent only when initiation was never dispatched or conclusively never accepted.
    pub upload: Option<UploadId>,
    /// Parts confirmed before the abort, not a claim of committed data.
    pub confirmed_parts: usize,
}
impl AbortReceipt {
    /// Proof identity of this exact abort.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text("fss.multipart_abort.v2");
        e.digest(self.intent_digest);
        e.bool(self.upload.is_some());
        if let Some(upload) = &self.upload {
            e.text(&upload.0);
        }
        e.u64(self.confirmed_parts as u64);
        ContentDigest::sha256(&e.finish())
    }
}

/// Single owner of a prepared, active, uncertain or terminal protocol session.
#[must_use = "a nonterminal upload requires explicit completion, abort or reconciliation"]
pub struct MultipartSession<'a, T: MultipartTransport> {
    transport: &'a mut T,
    plan: ChunkPlan,
    intent: UploadIntent,
    upload: Option<UploadId>,
    phase: MultipartPhase,
    intended: Vec<Option<ContentDigest>>,
    parts: Vec<Option<PartReceipt>>,
    owner: Option<(fss_core::RegionTreeIdentity, fss_core::RegionId)>,
    observed_at: TimestampNs,
    durable: Option<DurableState<'a>>,
}

fn valid_label(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_TRANSPORT_LABEL_BYTES
        && !value.chars().any(char::is_control)
}

impl<'a, T: MultipartTransport> MultipartSession<'a, T> {
    /// Pure preparation. No provider mutation occurs until `start` is admitted.
    pub fn prepare(
        transport: &'a mut T,
        plan: &ChunkPlan,
        manifest_root: ContentDigest,
        operation: OperationId,
        resource: &str,
        now: TimestampNs,
    ) -> Result<MultipartSession<'a, T>, MultipartError> {
        let canonical = plan_chunks(
            plan.object_bytes,
            ChunkPolicy {
                part_size: plan.part_size,
            },
        )
        .map_err(|_| MultipartError::InvalidIntent)?;
        if *plan != canonical
            || !valid_label(resource)
            || manifest_root.algorithm() != DigestAlgorithm::Sha256
            || manifest_root.bytes() == [0; 32]
        {
            return Err(MultipartError::InvalidIntent);
        }
        let plan_digest = plan.digest();
        let mut e = CanonicalEncoder::new();
        e.text("fss.multipart_intent.v2");
        e.text(operation.as_str());
        e.text(resource);
        e.digest(plan_digest);
        e.digest(manifest_root);
        let intent = UploadIntent {
            operation,
            resource: resource.to_owned(),
            plan_digest,
            manifest_root,
            digest: ContentDigest::sha256(&e.finish()),
        };
        Ok(MultipartSession {
            transport,
            plan: canonical,
            intent,
            upload: None,
            phase: MultipartPhase::Prepared,
            intended: vec![None; plan.chunks.len()],
            parts: vec![None; plan.chunks.len()],
            owner: None,
            observed_at: now,
            durable: None,
        })
    }

    /// Attach an empty, exclusively owned journal before the first dispatch.
    /// Initial persistence is mandatory. Failure retains the live owner and
    /// attached journal but blocks further effects until cold recovery.
    /// `owner_metadata` is empty for protocol-only use or canonical StagedUpload
    /// metadata; it cannot be replaced by an unrelated ownership format later.
    pub fn attach_journal(
        &mut self,
        journal: &'a mut dyn UploadJournal,
        io: UploadIo<'_>,
        owner_metadata: Vec<u8>,
    ) -> Result<UploadJournalPin, MultipartError> {
        if self.durable.is_some()
            || self.phase != MultipartPhase::Prepared
            || journal.head().is_some()
            || journal.latest().is_some()
        {
            return Err(MultipartError::InvalidCheckpoint);
        }
        authority::validate_binding(&io, &self.intent, &self.owner, self.observed_at)?;
        let context = recovery::context(io.authority, io.tree)?;
        let cancelled = io
            .authority
            .is_cancel_requested(io.tree)
            .map_err(|error| MultipartError::Authority(error.to_string()))?;
        let checkpoint = Checkpoint {
            plan: self.plan.clone(),
            intent: self.intent.clone(),
            upload: self.upload.clone(),
            phase: self.phase,
            intended: self.intended.clone(),
            parts: self.parts.clone(),
            observed_at: io.now,
            original_authority: context.clone(),
            effective_authority: context,
            consumed: *io.authority.budget().consumed(),
            grant_mask: recovery::grant_mask(io.authority, self.intent.resource()),
            cancelled,
            owner_metadata,
        };
        // Validate before storing the borrow; a malformed owner recipe has not
        // attempted persistence and must not consume the empty journal.
        checkpoint.encode()?;
        self.owner = Some((
            io.tree.owner_identity().clone(),
            io.authority.region().clone(),
        ));
        self.observed_at = io.now;
        self.durable = Some(DurableState {
            journal,
            expected: None,
            historical_consumed: BudgetVector::ZERO,
            last: checkpoint.clone(),
            poisoned: false,
        });
        self.durable
            .as_mut()
            .ok_or(MultipartError::InvalidCheckpoint)?
            .persist(checkpoint)
    }

    /// Rebind inert recovery data to a fresh explicitly authorized child. Only
    /// the remaining allowance is reserved; historical spending is not charged
    /// a second time to this parent. This method performs no persistence or I/O.
    pub fn restore(
        transport: &'a mut T,
        journal: &'a mut dyn UploadJournal,
        recovery: &MultipartRecovery,
        io: UploadIo<'_>,
    ) -> Result<Self, MultipartError> {
        // Uploader-owned journals must return through their obligation-aware
        // constructor, including a retained indeterminate terminal settlement.
        if !recovery.owner_metadata().is_empty() {
            return Err(MultipartError::OwnerMismatch);
        }
        recovery.validate_restore(journal, io.now)?;
        authority::validate_binding(&io, recovery.intent(), &None, recovery.observed_at())?;
        let context = recovery::context(io.authority, io.tree)?;
        recovery.validate_authority(&context, io.authority.grants())?;
        if *io.authority.budget().consumed() != BudgetVector::ZERO
            || recovery.cancelled()
                && !io
                    .authority
                    .is_cancel_requested(io.tree)
                    .map_err(|error| MultipartError::Authority(error.to_string()))?
        {
            return Err(MultipartError::OwnerMismatch);
        }
        Ok(Self::restore_prevalidated(transport, journal, recovery, io))
    }

    /// The owning uploader validates the complete recipe before reserving its
    /// fresh child. Construction afterward cannot fail and strand that child.
    pub(crate) fn restore_prevalidated(
        transport: &'a mut T,
        journal: &'a mut dyn UploadJournal,
        recovery: &MultipartRecovery,
        io: UploadIo<'_>,
    ) -> Self {
        let state = &recovery.checkpoint;
        Self {
            transport,
            plan: state.plan.clone(),
            intent: state.intent.clone(),
            upload: state.upload.clone(),
            phase: state.phase,
            intended: state.intended.clone(),
            parts: state.parts.clone(),
            owner: Some((
                io.tree.owner_identity().clone(),
                io.authority.region().clone(),
            )),
            observed_at: state.observed_at,
            durable: Some(DurableState {
                journal,
                expected: Some(recovery.head()),
                historical_consumed: state.consumed,
                last: state.clone(),
                poisoned: false,
            }),
        }
    }

    /// Persist canonical owner restrictions or terminal settlement before the
    /// runtime owner can close/refund its child. An ambiguous failure is sticky.
    pub fn persist_owner(
        &mut self,
        io: UploadIo<'_>,
        owner_metadata: Vec<u8>,
    ) -> Result<UploadJournalPin, MultipartError> {
        self.ensure_durable_ready()?;
        authority::validate_binding(&io, &self.intent, &self.owner, self.observed_at)?;
        let mut checkpoint = self
            .checkpoint(io.authority, io.tree, io.now)?
            .ok_or(MultipartError::InvalidCheckpoint)?;
        checkpoint.owner_metadata = owner_metadata;
        self.observed_at = io.now;
        self.durable
            .as_mut()
            .ok_or(MultipartError::InvalidCheckpoint)?
            .persist(checkpoint)
    }

    /// Independently retain this pin outside the journal to detect rollback.
    #[must_use]
    pub fn journal_pin(&self) -> Option<UploadJournalPin> {
        self.durable.as_ref().and_then(|durable| durable.expected)
    }
    /// Whether write-ahead persistence is mandatory for this session.
    #[must_use]
    pub const fn is_durable(&self) -> bool {
        self.durable.is_some()
    }
    /// A failed append blocks every subsequent effect until cold reopen.
    #[must_use]
    pub fn durability_failed(&self) -> bool {
        self.durable
            .as_ref()
            .is_some_and(|durable| durable.poisoned)
    }
    /// Historical plus current-epoch consumption, without double charging it.
    pub fn cumulative_consumed(
        &self,
        authority: &AuthorityCx,
    ) -> Result<BudgetVector, MultipartError> {
        self.durable
            .as_ref()
            .map_or(Ok(*authority.budget().consumed()), |durable| {
                durable.cumulative(*authority.budget().consumed())
            })
    }

    fn ensure_durable_ready(&self) -> Result<(), MultipartError> {
        if let Some(durable) = &self.durable {
            durable.ensure_ready()?;
        }
        Ok(())
    }

    fn checkpoint(
        &self,
        authority: &AuthorityCx,
        tree: &fss_core::RegionTree,
        now: TimestampNs,
    ) -> Result<Option<Checkpoint>, MultipartError> {
        let Some(durable) = &self.durable else {
            return Ok(None);
        };
        let mut checkpoint = durable.last.clone();
        checkpoint.upload = self.upload.clone();
        checkpoint.phase = self.phase;
        checkpoint.intended = self.intended.clone();
        checkpoint.parts = self.parts.clone();
        checkpoint.observed_at = now;
        checkpoint.effective_authority = recovery::context(authority, tree)?;
        checkpoint.consumed = durable.cumulative(*authority.budget().consumed())?;
        checkpoint.grant_mask = recovery::grant_mask(authority, self.intent.resource());
        checkpoint.cancelled |= authority
            .is_cancel_requested(tree)
            .map_err(|error| MultipartError::Authority(error.to_string()))?;
        Ok(Some(checkpoint))
    }

    fn persist_local(&mut self, io: &UploadIo<'_>) -> Result<(), MultipartError> {
        if let Some(checkpoint) = self.checkpoint(io.authority, io.tree, io.now)? {
            self.durable
                .as_mut()
                .ok_or(MultipartError::InvalidCheckpoint)?
                .persist(checkpoint)?;
            self.observed_at = io.now;
        }
        Ok(())
    }

    /// The bound intent, including its stable reconciliation key.
    #[must_use]
    pub const fn intent(&self) -> &UploadIntent {
        &self.intent
    }
    /// Current local knowledge of provider state.
    #[must_use]
    pub const fn phase(&self) -> MultipartPhase {
        self.phase
    }
    /// Number of independently checksum-confirmed parts (never a count of attempts).
    #[must_use]
    pub fn confirmed_parts(&self) -> usize {
        self.parts.iter().filter(|p| p.is_some()).count()
    }
    /// One acknowledged part, if any; used to resume without re-reading confirmed payloads.
    #[must_use]
    pub fn confirmed_part(&self, index: u64) -> Option<&PartReceipt> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.parts.get(index))
            .and_then(Option::as_ref)
    }
    /// Most recent admitted call time, for caller-side source access checks.
    #[must_use]
    pub const fn observed_at(&self) -> TimestampNs {
        self.observed_at
    }

    fn require_plan(&self, plan: &ChunkPlan) -> Result<(), MultipartError> {
        if plan != &self.plan {
            return Err(MultipartError::StalePlan {
                bound: self.intent.plan_digest,
                presented: plan.digest(),
            });
        }
        Ok(())
    }
    fn require_phase(
        &self,
        operation: TransportOperation,
        expected: MultipartPhase,
    ) -> Result<(), MultipartError> {
        self.ensure_durable_ready()?;
        if let MultipartPhase::Uncertain(operation) = self.phase {
            return Err(MultipartError::RequiresReconciliation { operation });
        }
        if self.phase != expected {
            return Err(MultipartError::WrongState {
                operation,
                state: self.phase,
            });
        }
        Ok(())
    }
    fn parts(&self) -> Vec<PartReceipt> {
        self.parts.iter().flatten().cloned().collect()
    }

    /// One mandatory write-ahead boundary shared by every provider operation.
    /// Reconciliation retains the original uncertain operation, so a crash in
    /// the observation call never manufactures a new effect identity.
    #[allow(clippy::too_many_arguments)]
    fn dispatch<R, O>(
        &mut self,
        io: UploadIo<'_>,
        operation: TransportOperation,
        payload_bytes: u64,
        intended_part: Option<(usize, ContentDigest)>,
        invoke: impl FnOnce(
            &mut T,
            &mut TransportCx<'_>,
            &UploadIntent,
            Option<&UploadId>,
        ) -> Result<R, String>,
        observe: impl FnOnce(&mut Self, R) -> Result<O, MultipartError>,
    ) -> Result<O, MultipartError> {
        self.ensure_durable_ready()?;
        if self
            .durable
            .as_ref()
            .is_some_and(|durable| durable.last.cancelled)
            && !matches!(
                operation,
                TransportOperation::Abort | TransportOperation::Reconcile
            )
        {
            return Err(MultipartError::CancellationRequested);
        }
        let cx = authority::admit(
            io,
            &self.intent,
            operation,
            payload_bytes,
            &mut self.owner,
            &mut self.observed_at,
        )?;
        if let Some((index, digest)) = intended_part {
            self.intended[index] = Some(digest);
        }
        if operation != TransportOperation::Reconcile {
            self.phase = MultipartPhase::Uncertain(operation);
        }
        let pending = self.checkpoint(cx.authority(), cx.tree(), cx.now())?;
        let (result, observed_at, consumed, cancelled) = {
            let mut writer = match (&mut self.durable, &pending) {
                (Some(durable), Some(checkpoint)) => Some(DispatchJournal {
                    durable,
                    checkpoint: checkpoint.clone(),
                }),
                _ => None,
            };
            if let Some(writer) = &mut writer {
                // The first-dispatched part digest, uncertain operation and its
                // entire cost are durable before the adapter sees any context.
                writer.record(
                    *cx.authority().budget().consumed(),
                    cx.now(),
                    cx.cancelled(),
                )?;
            }
            let persistence = writer
                .as_mut()
                .map(|writer| writer as &mut dyn TransportPersistence);
            let mut cx = cx.with_persistence(persistence);
            let result = invoke(self.transport, &mut cx, &self.intent, self.upload.as_ref());
            (
                result,
                cx.now(),
                *cx.authority().budget().consumed(),
                cx.cancelled(),
            )
        };
        self.observed_at = observed_at;
        // Even an adapter that catches a failed dynamic charge cannot return a
        // success which would erase the failed durable admission.
        if self.durability_failed() {
            return Err(MultipartError::DurabilityFailed);
        }
        let result = match result {
            Ok(response) => observe(self, response),
            Err(detail) => Err(MultipartError::Transport { operation, detail }),
        };
        if let Some(durable) = &mut self.durable {
            let mut checkpoint = durable.last.clone();
            checkpoint.upload = self.upload.clone();
            checkpoint.phase = self.phase;
            checkpoint.intended = self.intended.clone();
            checkpoint.parts = self.parts.clone();
            checkpoint.observed_at = observed_at;
            checkpoint.consumed = durable.cumulative(consumed)?;
            checkpoint.cancelled |= cancelled;
            if let Err(error) = durable.persist(checkpoint) {
                // Withhold unpersisted knowledge and never allow terminal
                // settlement/refund from an acknowledgement lost at this cut.
                if let Some(pending) = pending {
                    self.upload = pending.upload;
                    self.phase = pending.phase;
                    self.intended = pending.intended;
                    self.parts = pending.parts;
                }
                return Err(error);
            }
        }
        result
    }

    /// Start the stable intent. Lost initiation ACKs remain reconcilable by its key.
    pub fn start(&mut self, io: UploadIo<'_>) -> Result<UploadId, MultipartError> {
        self.require_phase(TransportOperation::Initiate, MultipartPhase::Prepared)?;
        self.dispatch(
            io,
            TransportOperation::Initiate,
            0,
            None,
            |transport, cx, intent, _| transport.initiate(cx, intent),
            |session, upload| {
                if !valid_label(&upload.0) {
                    return Err(MultipartError::ReconciliationMismatch);
                }
                session.upload = Some(upload.clone());
                session.phase = MultipartPhase::Uploading;
                Ok(upload)
            },
        )
    }

    /// Upload one exact part. Identical confirmed replay has no transport traffic.
    pub fn upload_part(
        &mut self,
        io: UploadIo<'_>,
        plan: &ChunkPlan,
        index: u64,
        bytes: &[u8],
    ) -> Result<PartReceipt, MultipartError> {
        self.require_plan(plan)?;
        self.require_phase(TransportOperation::UploadPart, MultipartPhase::Uploading)?;
        authority::validate_owner(
            &io,
            &self.intent,
            TransportOperation::UploadPart,
            &self.owner,
            self.observed_at,
        )?;
        let position = usize::try_from(index).map_err(|_| MultipartError::UnknownPart { index })?;
        let chunk = *self
            .plan
            .chunks
            .get(position)
            .ok_or(MultipartError::UnknownPart { index })?;
        if u64::try_from(bytes.len()).ok() != Some(chunk.len) {
            return Err(MultipartError::PartConflict { index });
        }
        let digest = ContentDigest::sha256(bytes);
        if self.intended[position].is_some_and(|original| original != digest) {
            return Err(MultipartError::PartConflict { index });
        }
        if let Some(receipt) = &self.parts[position] {
            let receipt = receipt.clone();
            self.persist_local(&io)?;
            return Ok(receipt);
        }
        self.dispatch(
            io,
            TransportOperation::UploadPart,
            chunk.len,
            Some((position, digest)),
            |transport, cx, _, upload| {
                transport.upload_part(
                    cx,
                    upload.ok_or_else(|| "missing owned upload identity".to_owned())?,
                    &chunk,
                    bytes,
                    digest,
                )
            },
            |session, receipt| {
                if receipt.index != index
                    || receipt.content_digest != digest
                    || !valid_label(&receipt.etag.0)
                {
                    return Err(MultipartError::InvalidPartReceipt { index });
                }
                session.parts[position] = Some(receipt.clone());
                session.phase = MultipartPhase::Uploading;
                Ok(receipt)
            },
        )
    }

    /// Complete the bound root. Any failure keeps this owner and its part inventory.
    pub fn complete(
        &mut self,
        io: UploadIo<'_>,
        plan: &ChunkPlan,
        manifest_root: ContentDigest,
    ) -> Result<CompletionReceipt, MultipartError> {
        self.ensure_durable_ready()?;
        self.require_plan(plan)?;
        if manifest_root != self.intent.manifest_root {
            return Err(MultipartError::StaleRoot {
                bound: self.intent.manifest_root,
                presented: manifest_root,
            });
        }
        if self.phase == MultipartPhase::Completed {
            authority::validate_binding(&io, &self.intent, &self.owner, self.observed_at)?;
            return self.completion_receipt();
        }
        self.require_phase(TransportOperation::Complete, MultipartPhase::Uploading)?;
        let confirmed = self.confirmed_parts();
        if confirmed != self.plan.chunks.len() {
            return Err(MultipartError::Incomplete {
                confirmed,
                required: self.plan.chunks.len(),
            });
        }
        let parts = self.parts();
        self.dispatch(
            io,
            TransportOperation::Complete,
            0,
            None,
            |transport, cx, intent, upload| {
                transport.complete(
                    cx,
                    upload.ok_or_else(|| "missing owned upload identity".to_owned())?,
                    intent,
                    &parts,
                )
            },
            |session, ()| {
                session.phase = MultipartPhase::Completed;
                session.completion_receipt()
            },
        )
    }

    /// Abort known uncommitted staging. Uncertain completion must be reconciled first.
    pub fn abort(&mut self, io: UploadIo<'_>) -> Result<AbortReceipt, MultipartError> {
        self.ensure_durable_ready()?;
        authority::validate_binding(&io, &self.intent, &self.owner, self.observed_at)?;
        if matches!(
            self.phase,
            MultipartPhase::Prepared | MultipartPhase::Aborted
        ) {
            let previous_phase = self.phase;
            if previous_phase == MultipartPhase::Prepared {
                // A local no-dispatch abort is still an owner-bound outcome. It must not
                // become a reusable receipt for another region with the same operation ID.
                self.owner = Some((
                    io.tree.owner_identity().clone(),
                    io.authority.region().clone(),
                ));
                self.observed_at = io.now;
            }
            self.phase = MultipartPhase::Aborted;
            if previous_phase == MultipartPhase::Prepared
                && let Err(error) = self.persist_local(&io)
            {
                self.phase = previous_phase;
                return Err(error);
            }
            return Ok(self.abort_receipt());
        }
        self.require_phase(TransportOperation::Abort, MultipartPhase::Uploading)?;
        self.dispatch(
            io,
            TransportOperation::Abort,
            0,
            None,
            |transport, cx, intent, upload| {
                transport.abort(
                    cx,
                    upload.ok_or_else(|| "missing owned upload identity".to_owned())?,
                    intent,
                )
            },
            |session, ()| {
                session.phase = MultipartPhase::Aborted;
                Ok(session.abort_receipt())
            },
        )
    }

    /// Observe an uncertain dispatch without retrying it or manufacturing a terminal result.
    pub fn reconcile(&mut self, io: UploadIo<'_>) -> Result<MultipartPhase, MultipartError> {
        self.ensure_durable_ready()?;
        if !matches!(self.phase, MultipartPhase::Uncertain(_)) {
            return Err(MultipartError::WrongState {
                operation: TransportOperation::Reconcile,
                state: self.phase,
            });
        }
        self.dispatch(
            io,
            TransportOperation::Reconcile,
            0,
            None,
            |transport, cx, intent, _| transport.reconcile(cx, intent),
            Self::observe_reconciliation,
        )
    }

    fn observe_reconciliation(
        &mut self,
        response: Reconciliation,
    ) -> Result<MultipartPhase, MultipartError> {
        if response.intent_digest != self.intent.digest {
            return Err(MultipartError::ReconciliationMismatch);
        }
        match response.state {
            ProviderUploadState::Unknown => {}
            ProviderUploadState::NotStarted => {
                if self.phase != MultipartPhase::Uncertain(TransportOperation::Initiate)
                    || self.upload.is_some()
                {
                    return Err(MultipartError::ReconciliationMismatch);
                }
                self.phase = MultipartPhase::Prepared;
            }
            ProviderUploadState::Active { upload, parts } => {
                self.validate_inventory(&upload, &parts, false)?;
                for part in parts {
                    let index = part.index as usize;
                    self.parts[index] = Some(part);
                }
                self.upload = Some(upload);
                self.phase = MultipartPhase::Uploading;
            }
            ProviderUploadState::Completed {
                upload,
                manifest_root,
                parts,
            } => {
                if manifest_root != self.intent.manifest_root {
                    return Err(MultipartError::ReconciliationMismatch);
                }
                // Completion is only credible after this owner actually dispatched it.
                if self.phase != MultipartPhase::Uncertain(TransportOperation::Complete) {
                    return Err(MultipartError::ReconciliationMismatch);
                }
                self.validate_inventory(&upload, &parts, true)?;
                for part in parts {
                    let index = part.index as usize;
                    self.parts[index] = Some(part);
                }
                self.upload = Some(upload);
                self.phase = MultipartPhase::Completed;
            }
            ProviderUploadState::Aborted { upload } => {
                if self.phase != MultipartPhase::Uncertain(TransportOperation::Abort)
                    || self.upload.as_ref() != Some(&upload)
                {
                    return Err(MultipartError::ReconciliationMismatch);
                }
                self.phase = MultipartPhase::Aborted;
            }
        }
        Ok(self.phase)
    }

    fn validate_inventory(
        &self,
        upload: &UploadId,
        parts: &[PartReceipt],
        complete: bool,
    ) -> Result<(), MultipartError> {
        if !valid_label(&upload.0)
            || self
                .upload
                .as_ref()
                .is_some_and(|expected| expected != upload)
            || parts.len() > self.parts.len()
            || (complete && parts.len() != self.parts.len())
        {
            return Err(MultipartError::ReconciliationMismatch);
        }
        let mut previous = None;
        for part in parts {
            let index =
                usize::try_from(part.index).map_err(|_| MultipartError::ReconciliationMismatch)?;
            if previous.is_some_and(|old| old >= part.index)
                || self.intended.get(index).copied().flatten() != Some(part.content_digest)
                || !valid_label(&part.etag.0)
                || self.parts[index].as_ref().is_some_and(|old| old != part)
            {
                return Err(MultipartError::ReconciliationMismatch);
            }
            previous = Some(part.index);
        }
        // A supposedly complete inventory cannot silently lose an acknowledged part.
        for known in self.parts.iter().flatten() {
            if parts
                .binary_search_by_key(&known.index, |part| part.index)
                .ok()
                .and_then(|index| parts.get(index))
                != Some(known)
            {
                return Err(MultipartError::ReconciliationMismatch);
            }
        }
        Ok(())
    }

    /// Return the already terminal completion without provider I/O.
    pub fn completion_receipt(&self) -> Result<CompletionReceipt, MultipartError> {
        self.require_phase(TransportOperation::Complete, MultipartPhase::Completed)?;
        Ok(CompletionReceipt {
            intent_digest: self.intent.digest,
            upload: self
                .upload
                .clone()
                .ok_or(MultipartError::ReconciliationMismatch)?,
            parts: self.parts(),
            manifest_root: self.intent.manifest_root,
        })
    }
    fn abort_receipt(&self) -> AbortReceipt {
        AbortReceipt {
            intent_digest: self.intent.digest,
            upload: self.upload.clone(),
            confirmed_parts: self.confirmed_parts(),
        }
    }
}
