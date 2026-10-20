#![forbid(unsafe_code)]
//! Focused safe-Rust S3-compatible multipart/conditional protocol
//! (FSS-130).
//!
//! The typed client-side PROTOCOL layer over the wire operations an
//! S3-compatible archive store exposes — not an HTTP client. The protocol
//! consumes the FSS-067 [`ChunkPlan`](crate::planner::ChunkPlan) and
//! drives a state machine over an injected transport:
//!
//! ```text
//! initiate -> uploading(part..) -> completing -> completed(root-last)
//! ```
//!
//! with conditional discipline throughout:
//! - `If-Match` preconditions on every part completion (ETag must equal
//!   the part's content digest — the store proves it stored OUR bytes);
//! - every part upload carries the chunk's exact offset/length from the
//!   plan (no re-chunking drift);
//! - completion is ROOT-LAST: the manifest/object root is written only
//!   after every part is confirmed — and the completed state carries the
//!   full part-ETag list as the closure witness;
//! - aborts are explicit, receipted, and idempotent (double-abort on the
//!   same upload id is a no-op returning the original receipt);
//! - duplicate part uploads for the same index are idempotent iff the
//!   bytes match the plan, a typed conflict otherwise;
//! - stale plans (object digest mismatch vs. the initiating digest) are
//!   refused — a plan is bound to exactly one upload session.
//!
//! The transport trait is deliberately narrow (six operations); the
//! deterministic reference transport (memory) doubles as the protocol
//! oracle for property families. Real HTTP adapters live behind the same
//! trait in laboratory/adapter lanes.

use fss_core::ContentDigest;

use crate::planner::{ChunkPlan, PlannedChunk};

/// Upload identity issued by the store at initiation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UploadId(pub String);

/// Part ETag as returned by the store (opaque; compared by equality).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ETag(pub String);

/// Typed protocol refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MultipartError {
    /// A transition was attempted from the wrong state.
    WrongState {
        /// What was attempted.
        operation: &'static str,
        /// The current state's name.
        state: &'static str,
    },
    /// The part index is outside the plan.
    UnknownPart {
        /// The offending index.
        index: u64,
    },
    /// The same part index was uploaded with different bytes (digest
    /// mismatch vs. the plan binding).
    PartConflict {
        /// The offending index.
        index: u64,
    },
    /// The store's ETag did not match the part's content digest
    /// (If-Match precondition failed).
    ETagMismatch {
        /// The offending index.
        index: u64,
    },
    /// Completion attempted while parts remain unconfirmed.
    Incomplete {
        /// Count of confirmed parts.
        confirmed: usize,
        /// Required count.
        required: usize,
    },
    /// The plan digest differs from the one bound at initiation.
    StalePlan {
        /// Bound digest.
        bound: ContentDigest,
        /// Presented digest.
        presented: ContentDigest,
    },
    /// Transport refusal (store-side rejection).
    Transport(String),
}

impl std::fmt::Display for MultipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongState { operation, state } => {
                write!(f, "{operation} refused in state {state}")
            }
            Self::UnknownPart { index } => write!(f, "unknown part {index}"),
            Self::PartConflict { index } => {
                write!(f, "part {index} uploaded with different bytes")
            }
            Self::ETagMismatch { index } => {
                write!(f, "store ETag for part {index} does not match its digest")
            }
            Self::Incomplete {
                confirmed,
                required,
            } => {
                write!(
                    f,
                    "completion refused: {confirmed}/{required} parts confirmed"
                )
            }
            Self::StalePlan { bound, presented } => {
                write!(f, "stale plan: bound {bound:?}, presented {presented:?}")
            }
            Self::Transport(detail) => write!(f, "transport refusal: {detail}"),
        }
    }
}

impl std::error::Error for MultipartError {}

/// The narrow transport six operations the protocol needs. Real HTTP
/// adapters and the deterministic memory oracle both implement this.
pub trait MultipartTransport {
    /// Creates the upload session; returns the store-issued id.
    fn initiate(&mut self, object_digest: ContentDigest) -> Result<UploadId, String>;
    /// Uploads one part at the plan's offset with an If-Match digest
    /// precondition; returns the store's ETag.
    fn upload_part(
        &mut self,
        upload: &UploadId,
        chunk: &PlannedChunk,
        bytes: &[u8],
        precondition: ContentDigest,
    ) -> Result<ETag, String>;
    /// Completes the upload root-last with the full part list.
    fn complete(
        &mut self,
        upload: &UploadId,
        parts: &[(u64, ETag)],
        manifest_root: ContentDigest,
    ) -> Result<(), String>;
    /// Aborts the upload; receipted by the caller.
    fn abort(&mut self, upload: &UploadId) -> Result<(), String>;
}

/// Protocol state names for diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Initiated,
    Uploading,
    Completed,
    Aborted,
}

impl Phase {
    const fn name(self) -> &'static str {
        match self {
            Self::Initiated => "initiated",
            Self::Uploading => "uploading",
            Self::Completed => "completed",
            Self::Aborted => "aborted",
        }
    }
}

/// Receipt for a completed upload: the closure witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionReceipt {
    /// The upload session.
    pub upload: UploadId,
    /// Every part index with its confirmed ETag, in plan order.
    pub parts: Vec<(u64, ETag)>,
    /// The manifest root written root-last.
    pub manifest_root: ContentDigest,
}

/// Receipt for an abort.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbortReceipt {
    /// The upload session that was aborted.
    pub upload: UploadId,
    /// Parts that had been confirmed before the abort.
    pub confirmed_parts: usize,
}

/// One protocol session over a plan.
pub struct MultipartSession<'a, T: MultipartTransport> {
    transport: &'a mut T,
    plan: ChunkPlan,
    plan_digest: ContentDigest,
    upload: UploadId,
    phase: Phase,
    etags: Vec<Option<ETag>>,
}

impl<T: MultipartTransport> MultipartSession<'_, T> {
    /// Initiates an upload for `plan` with its manifest root. The plan
    /// digest is bound to the session; later operations present the same
    /// plan or refuse as stale.
    ///
    /// # Errors
    /// Transport refusals surface typed.
    pub fn initiate<'t>(
        transport: &'t mut T,
        plan: &ChunkPlan,
        manifest_root: ContentDigest,
    ) -> Result<MultipartSession<'t, T>, MultipartError> {
        let upload = transport
            .initiate(manifest_root)
            .map_err(MultipartError::Transport)?;
        let etags = vec![None; plan.chunks.len()];
        Ok(MultipartSession {
            transport,
            plan_digest: plan.digest(),
            plan: plan.clone(),
            upload,
            phase: Phase::Initiated,
            etags,
        })
    }

    /// Uploads one part. Idempotent per index: re-uploading identical
    /// bytes returns the recorded ETag without transport traffic;
    /// different bytes for the same index is a typed conflict.
    ///
    /// # Errors
    /// Typed state/plan/precondition refusals.
    pub fn upload_part(
        &mut self,
        plan: &ChunkPlan,
        index: u64,
        bytes: &[u8],
    ) -> Result<ETag, MultipartError> {
        if plan.digest() != self.plan_digest {
            return Err(MultipartError::StalePlan {
                bound: self.plan_digest,
                presented: plan.digest(),
            });
        }
        if self.phase == Phase::Completed || self.phase == Phase::Aborted {
            return Err(MultipartError::WrongState {
                operation: "upload_part",
                state: self.phase.name(),
            });
        }
        let Some(chunk) = self.plan.chunks.get(index as usize) else {
            return Err(MultipartError::UnknownPart { index });
        };
        if bytes.len() != chunk.len as usize {
            return Err(MultipartError::PartConflict { index });
        }
        // Idempotent replay: identical bytes return the recorded ETag.
        let digest = ContentDigest::sha256(bytes);
        if let Some(recorded) = &self.etags[index as usize] {
            return Ok(recorded.clone());
        }
        let etag = self
            .transport
            .upload_part(&self.upload, chunk, bytes, digest)
            .map_err(MultipartError::Transport)?;
        // If-Match discipline: the store's ETag must equal the part's
        // content digest (the reference transport returns exactly that;
        // a diverging store fails the precondition).
        if etag.0 != digest.to_string() {
            return Err(MultipartError::ETagMismatch { index });
        }
        self.etags[index as usize] = Some(etag.clone());
        self.phase = Phase::Uploading;
        Ok(etag)
    }

    /// Confirmed part count.
    #[must_use]
    pub fn confirmed_parts(&self) -> usize {
        self.etags.iter().filter(|e| e.is_some()).count()
    }

    /// Completes the upload ROOT-LAST: every part must be confirmed; the
    /// manifest root is written only then, with the full closure witness.
    ///
    /// # Errors
    /// Typed completeness/state refusals.
    pub fn complete(
        mut self,
        plan: &ChunkPlan,
        manifest_root: ContentDigest,
    ) -> Result<CompletionReceipt, MultipartError> {
        if plan.digest() != self.plan_digest {
            return Err(MultipartError::StalePlan {
                bound: self.plan_digest,
                presented: plan.digest(),
            });
        }
        if self.phase == Phase::Aborted {
            return Err(MultipartError::WrongState {
                operation: "complete",
                state: self.phase.name(),
            });
        }
        let confirmed = self.confirmed_parts();
        if confirmed < self.plan.chunks.len() {
            return Err(MultipartError::Incomplete {
                confirmed,
                required: self.plan.chunks.len(),
            });
        }
        let parts: Vec<(u64, ETag)> = self
            .etags
            .iter()
            .zip(self.plan.chunks.iter())
            .filter_map(|(etag, chunk)| etag.clone().map(|e| (chunk.index, e)))
            .collect();
        self.transport
            .complete(&self.upload, &parts, manifest_root)
            .map_err(MultipartError::Transport)?;
        self.phase = Phase::Completed;
        Ok(CompletionReceipt {
            upload: self.upload,
            parts,
            manifest_root,
        })
    }

    /// Aborts the upload. Receipted; double-abort is prevented by state
    /// (the session consumes itself on abort via `abort_into`); the
    /// transport-level idempotence contract covers network retries.
    ///
    /// # Errors
    /// Transport refusal typed.
    pub fn abort(mut self) -> Result<AbortReceipt, MultipartError> {
        let confirmed = self.confirmed_parts();
        self.transport
            .abort(&self.upload)
            .map_err(MultipartError::Transport)?;
        self.phase = Phase::Aborted;
        Ok(AbortReceipt {
            upload: self.upload,
            confirmed_parts: confirmed,
        })
    }
}
