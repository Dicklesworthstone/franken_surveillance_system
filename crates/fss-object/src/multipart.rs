#![forbid(unsafe_code)]
//! Owned multipart protocol, with explicit authority at every transport call.
//!
//! This is an injected protocol boundary, not an HTTP client or proof of archive
//! retrievability. Provider ETags are opaque. Independent part checksums bind the
//! bytes; a complete receipt binds the exact intent, plan, root and ordered parts.
//! An acknowledgement lost after dispatch leaves the session owned and uncertain.
//! Only a conclusive, intent-bound provider reconciliation permits further work.

mod authority;

pub use authority::{TransportCx, UploadIo};

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, OperationId, TimestampNs};

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
}

fn valid_label(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_TRANSPORT_LABEL_BYTES
        && !value.chars().any(char::is_control)
}

impl<T: MultipartTransport> MultipartSession<'_, T> {
    /// Pure preparation. No provider mutation occurs until `start` is admitted.
    pub fn prepare<'a>(
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
        })
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

    /// Start the stable intent. Lost initiation ACKs remain reconcilable by its key.
    pub fn start(&mut self, io: UploadIo<'_>) -> Result<UploadId, MultipartError> {
        self.require_phase(TransportOperation::Initiate, MultipartPhase::Prepared)?;
        let mut cx = authority::admit(
            io,
            &self.intent,
            TransportOperation::Initiate,
            0,
            &mut self.owner,
            &mut self.observed_at,
        )?;
        self.phase = MultipartPhase::Uncertain(TransportOperation::Initiate);
        let result = self.transport.initiate(&mut cx, &self.intent);
        self.observed_at = cx.now();
        let upload = result.map_err(|detail| MultipartError::Transport {
            operation: TransportOperation::Initiate,
            detail,
        })?;
        if !valid_label(&upload.0) {
            return Err(MultipartError::ReconciliationMismatch);
        }
        self.upload = Some(upload.clone());
        self.phase = MultipartPhase::Uploading;
        Ok(upload)
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
            return Ok(receipt.clone());
        }
        let mut cx = authority::admit(
            io,
            &self.intent,
            TransportOperation::UploadPart,
            chunk.len,
            &mut self.owner,
            &mut self.observed_at,
        )?;
        self.intended[position] = Some(digest);
        self.phase = MultipartPhase::Uncertain(TransportOperation::UploadPart);
        let upload = self
            .upload
            .as_ref()
            .ok_or(MultipartError::ReconciliationMismatch)?;
        let result = self
            .transport
            .upload_part(&mut cx, upload, &chunk, bytes, digest);
        self.observed_at = cx.now();
        let receipt = result.map_err(|detail| MultipartError::Transport {
            operation: TransportOperation::UploadPart,
            detail,
        })?;
        if receipt.index != index
            || receipt.content_digest != digest
            || !valid_label(&receipt.etag.0)
        {
            return Err(MultipartError::InvalidPartReceipt { index });
        }
        self.parts[position] = Some(receipt.clone());
        self.phase = MultipartPhase::Uploading;
        Ok(receipt)
    }

    /// Complete the bound root. Any failure keeps this owner and its part inventory.
    pub fn complete(
        &mut self,
        io: UploadIo<'_>,
        plan: &ChunkPlan,
        manifest_root: ContentDigest,
    ) -> Result<CompletionReceipt, MultipartError> {
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
        let mut cx = authority::admit(
            io,
            &self.intent,
            TransportOperation::Complete,
            0,
            &mut self.owner,
            &mut self.observed_at,
        )?;
        self.phase = MultipartPhase::Uncertain(TransportOperation::Complete);
        let result = self.transport.complete(
            &mut cx,
            self.upload
                .as_ref()
                .ok_or(MultipartError::ReconciliationMismatch)?,
            &self.intent,
            &parts,
        );
        self.observed_at = cx.now();
        result.map_err(|detail| MultipartError::Transport {
            operation: TransportOperation::Complete,
            detail,
        })?;
        self.phase = MultipartPhase::Completed;
        self.completion_receipt()
    }

    /// Abort known uncommitted staging. Uncertain completion must be reconciled first.
    pub fn abort(&mut self, io: UploadIo<'_>) -> Result<AbortReceipt, MultipartError> {
        authority::validate_binding(&io, &self.intent, &self.owner, self.observed_at)?;
        if matches!(
            self.phase,
            MultipartPhase::Prepared | MultipartPhase::Aborted
        ) {
            if self.phase == MultipartPhase::Prepared {
                // A local no-dispatch abort is still an owner-bound outcome. It must not
                // become a reusable receipt for another region with the same operation ID.
                self.owner = Some((
                    io.tree.owner_identity().clone(),
                    io.authority.region().clone(),
                ));
                self.observed_at = io.now;
            }
            self.phase = MultipartPhase::Aborted;
            return Ok(self.abort_receipt());
        }
        self.require_phase(TransportOperation::Abort, MultipartPhase::Uploading)?;
        let mut cx = authority::admit(
            io,
            &self.intent,
            TransportOperation::Abort,
            0,
            &mut self.owner,
            &mut self.observed_at,
        )?;
        self.phase = MultipartPhase::Uncertain(TransportOperation::Abort);
        let result = self.transport.abort(
            &mut cx,
            self.upload
                .as_ref()
                .ok_or(MultipartError::ReconciliationMismatch)?,
            &self.intent,
        );
        self.observed_at = cx.now();
        result.map_err(|detail| MultipartError::Transport {
            operation: TransportOperation::Abort,
            detail,
        })?;
        self.phase = MultipartPhase::Aborted;
        Ok(self.abort_receipt())
    }

    /// Observe an uncertain dispatch without retrying it or manufacturing a terminal result.
    pub fn reconcile(&mut self, io: UploadIo<'_>) -> Result<MultipartPhase, MultipartError> {
        if !matches!(self.phase, MultipartPhase::Uncertain(_)) {
            return Err(MultipartError::WrongState {
                operation: TransportOperation::Reconcile,
                state: self.phase,
            });
        }
        let mut cx = authority::admit(
            io,
            &self.intent,
            TransportOperation::Reconcile,
            0,
            &mut self.owner,
            &mut self.observed_at,
        )?;
        let result = self.transport.reconcile(&mut cx, &self.intent);
        self.observed_at = cx.now();
        let response = result.map_err(|detail| MultipartError::Transport {
            operation: TransportOperation::Reconcile,
            detail,
        })?;
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
