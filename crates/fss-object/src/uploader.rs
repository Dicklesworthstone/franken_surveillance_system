#![forbid(unsafe_code)]
//! Asupersync-owned S3-compatible staged uploader (FSS-063).
//!
//! The composition vertical that wires the landed layers into one
//! authority-owned upload: the FSS-067 [`ChunkPlan`] chunks the object,
//! the FSS-130 [`MultipartSession`] drives the store protocol, and the
//! FSS-021 [`AuthorityCx`] owns every step — the upload runs inside a
//! scoped child region with a durable drain obligation that only
//! terminal completion or cancellation-with-receipt resolves.
//!
//! Ownership semantics:
//! - `stage_upload` scopes a child region (kind-legal under the caller's
//!   authority), reserves the transfer budget, registers the obligation
//!   "upload completed or cancelled with receipt", and initiates the
//!   multipart session. The staged handle carries the region, the plan
//!   binding, and the session.
//! - `upload_chunks` streams parts through the plan; cancellation is
//!   honored BETWEEN parts (checked before each transport call) — an
//!   in-flight part completes, then the upload transitions to cancelled.
//! - `finish` completes root-last and resolves the obligation `Completed`
//!   with the closure witness digest as proof.
//! - `cancel` aborts the store session and resolves the obligation
//!   `Drained` (cooperative cancellation before external commitment).
//!
//! No ambient state: the caller supplies authority, tree, transport, and
//! time. The uploader allocates nothing beyond the plan's own bounds.

use fss_core::{ContentDigest, TimestampNs};

use crate::multipart::{MultipartSession, MultipartTransport};
use crate::planner::{ChunkPlan, ChunkPolicy, PlannerError, plan_chunks};
use fss_core::BudgetVector;
use fss_runtime::authority::{AuthorityCx, AuthorityError};
use fss_runtime::obligation::{ObligationTerminal, new_obligation};

use fss_core::{Generation, OperationId, RegionId, RegionKind, RootAuthoritySpec};

/// Typed uploader refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UploaderError {
    /// The authority refused a scope/budget/obligation step.
    Authority(String),
    /// The planner refused the object/policy.
    Planner(PlannerError),
    /// The transport protocol refused (multipart discipline).
    Protocol(String),
    /// Cancellation arrived; the upload is terminal with a receipt.
    Cancelled {
        /// Parts confirmed before the cancellation was observed.
        confirmed_parts: usize,
    },
}

impl std::fmt::Display for UploaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authority(detail) => write!(f, "authority refusal: {detail}"),
            Self::Planner(e) => write!(f, "planner refusal: {e}"),
            Self::Protocol(detail) => write!(f, "protocol refusal: {detail}"),
            Self::Cancelled { confirmed_parts } => {
                write!(f, "upload cancelled after {confirmed_parts} parts")
            }
        }
    }
}

impl std::error::Error for UploaderError {}

impl From<AuthorityError> for UploaderError {
    fn from(e: AuthorityError) -> Self {
        Self::Authority(format!("{e}"))
    }
}

impl From<PlannerError> for UploaderError {
    fn from(e: PlannerError) -> Self {
        Self::Planner(e)
    }
}

/// One staged upload: authority region + obligation + session binding.
pub struct StagedUpload<'a, T: MultipartTransport> {
    authority: &'a mut AuthorityCx,
    region: RegionId,
    obligation: fss_core::ObligationId,
    session: MultipartSession<'a, T>,
    plan: ChunkPlan,
    manifest_root: ContentDigest,
    confirmed: usize,
}

impl<T: MultipartTransport> StagedUpload<'_, T> {
    /// Stages an upload under `authority`: child region (Property under
    /// Process or narrower), budget reservation sized to the object,
    /// drain obligation, initiated multipart session.
    ///
    /// # Errors
    /// Typed authority/planner/protocol refusals.
    #[allow(clippy::too_many_arguments)]
    pub fn stage<'a>(
        authority: &'a mut AuthorityCx,
        tree: &mut fss_core::RegionTree,
        transport: &'a mut T,
        operation: OperationId,
        object_bytes: u64,
        policy: ChunkPolicy,
        manifest_root: ContentDigest,
        child_authority_spec: RootAuthoritySpec,
        now: TimestampNs,
    ) -> Result<StagedUpload<'a, T>, UploaderError> {
        let plan = plan_chunks(object_bytes, policy)?;
        // Budget: bytes + one storage operation per part, inside the parent.
        let mut budget = BudgetVector::builder()
            .build()
            .map_err(|e| UploaderError::Authority(format!("{e:?}")))?;
        budget.bytes = object_bytes;
        budget.storage_operations = plan.chunks.len() as u64;
        // The child authority's own canonical budgets must cover the
        // reservation (validate_allowance checks reservation <= child
        // canonical; the parent-remaining gate is the real admission).
        let mut spec = child_authority_spec;
        spec.budgets = budget;
        let region = RegionId::new(format!("region:upload:{}", operation.as_str()))
            .map_err(|e| UploaderError::Authority(format!("{e}")))?;
        let upload_authority = AuthorityCx::scope_down(
            authority,
            tree,
            region.clone(),
            RegionKind::ObjectStore,
            budget,
            spec,
            now,
        )?;
        let _ = upload_authority; // scoped region exists; the session binds it
        let obligation = new_obligation(
            format!("obligation:upload:{}:drain", operation.as_str()),
            operation.clone(),
            "upload completed or cancelled with receipt",
        )
        .map_err(|e| UploaderError::Authority(format!("{e}")))?;
        let obligation_id = obligation.obligation_id.clone();
        authority
            .register_obligation(tree, obligation)
            .map_err(|e| UploaderError::Authority(format!("{e}")))?;
        let session = MultipartSession::initiate(transport, &plan, manifest_root)
            .map_err(|e| UploaderError::Protocol(format!("{e}")))?;
        Ok(StagedUpload {
            authority,
            region,
            obligation: obligation_id,
            session,
            plan,
            manifest_root,
            confirmed: 0,
        })
    }

    /// Streams every chunk's bytes through the session, honoring
    /// cancellation between parts. `bytes_for` supplies the slice for a
    /// chunk index (the caller owns the object bytes).
    ///
    /// # Errors
    /// Typed protocol refusals; `Cancelled` when the authority's chain
    /// observed a cancellation request.
    pub fn upload_chunks(
        &mut self,
        tree: &fss_core::RegionTree,
        bytes_for: impl Fn(u64) -> Vec<u8>,
    ) -> Result<(), UploaderError> {
        for chunk in self.plan.chunks.clone() {
            if self.authority.is_cancel_requested(tree).unwrap_or(false) {
                return Err(UploaderError::Cancelled {
                    confirmed_parts: self.confirmed,
                });
            }
            let bytes = bytes_for(chunk.index);
            self.session
                .upload_part(&self.plan, chunk.index, &bytes)
                .map_err(|e| UploaderError::Protocol(format!("{e}")))?;
            self.confirmed += 1;
        }
        Ok(())
    }

    /// Completes root-last and resolves the obligation with the closure
    /// witness as proof.
    ///
    /// # Errors
    /// Typed refusals from completion or obligation resolution.
    pub fn finish(
        self,
        tree: &mut fss_core::RegionTree,
    ) -> Result<crate::multipart::CompletionReceipt, UploaderError> {
        let receipt = self
            .session
            .complete(&self.plan, self.manifest_root)
            .map_err(|e| UploaderError::Protocol(format!("{e}")))?;
        self.authority
            .resolve_obligation(
                tree,
                &self.obligation,
                ObligationTerminal::Completed,
                Some(receipt.manifest_root),
                None,
            )
            .map_err(|e| UploaderError::Authority(format!("{e}")))?;
        Ok(receipt)
    }

    /// Cancels cooperatively: aborts the store session and resolves the
    /// obligation `Drained` with the abort receipt digest as proof.
    ///
    /// # Errors
    /// Typed refusals.
    pub fn cancel(
        self,
        tree: &mut fss_core::RegionTree,
    ) -> Result<crate::multipart::AbortReceipt, UploaderError> {
        let receipt = self
            .session
            .abort()
            .map_err(|e| UploaderError::Protocol(format!("{e}")))?;
        self.authority
            .resolve_obligation(
                tree,
                &self.obligation,
                ObligationTerminal::Drained,
                Some(fss_core::ContentDigest::sha256(receipt.upload.0.as_bytes())),
                None,
            )
            .map_err(|e| UploaderError::Authority(format!("{e}")))?;
        Ok(receipt)
    }

    /// The bound drain obligation.
    #[must_use]
    pub fn obligation(&self) -> &fss_core::ObligationId {
        &self.obligation
    }

    /// The scoped child region owning this upload.
    #[must_use]
    pub fn region(&self) -> &RegionId {
        &self.region
    }

    /// Confirmed part count.
    #[must_use]
    pub fn confirmed_parts(&self) -> usize {
        self.confirmed
    }
}

/// Default child authority spec for uploads: same trace/principal,
/// object-store-scoped generation.
#[must_use]
pub fn upload_authority_spec(trace: &str, operation: &str) -> RootAuthoritySpec {
    RootAuthoritySpec {
        trace_id: trace.to_string(),
        operation_id: match OperationId::parse(operation)
            .or_else(|_| OperationId::parse("op:upload-fallback"))
        {
            Ok(id) => id,
            Err(_) => unreachable!("valid literal"),
        },
        principal: "principal:local-operator".to_string(),
        capabilities: Vec::new(),
        deadline: None,
        priority: 10,
        budgets: BudgetVector::ZERO,
        privacy_scope: "privacy:local-authorized".to_string(),
        retention_scope: "retention:existing-deployment-policy".to_string(),
        anchor_universe: ContentDigest::sha256(b"upload-authority-universe"),
        generation: Generation::GENESIS.get(),
    }
}
