#![forbid(unsafe_code)]
//! Borrowed cancellation of an already owned transport request.

/// A probe of the request owner's existing cancellation state.
///
/// This grants no read, session, clock, or effect authority and creates no independent
/// cancellation tree. The owner keeps the probe alive until native execution has joined.
/// A probe must remain cancelled after it first returns `true`. Native readers consult it
/// at their existing bounded checkpoints; a started effect retains its own durable owner.
#[derive(Clone, Copy)]
pub struct RequestControl<'a> {
    cancelled: &'a (dyn Fn() -> bool + Sync),
}

impl<'a> RequestControl<'a> {
    /// Borrow the cancellation probe of the transport's existing request owner.
    #[must_use]
    pub const fn new(cancelled: &'a (dyn Fn() -> bool + Sync)) -> Self {
        Self { cancelled }
    }

    /// Preserve the original synchronous CLI behavior, without a cancellation source.
    #[must_use]
    pub fn uncancelled() -> Self {
        Self::new(&never_cancelled)
    }

    /// Observe the owner's cancellation without changing any native effect or receipt.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        (self.cancelled)()
    }
}

fn never_cancelled() -> bool {
    false
}

/// Refuse an interrupted read before a complete verified snapshot exists.
///
/// No deployment is reread to manufacture an anchor or diagnose cancellation. The registered
/// diagnostic distinguishes the owner's cancellation from missing/corrupt retained state.
pub(crate) fn cancelled_read(
    command: &str,
    root: &std::path::Path,
) -> (String, crate::error::ExitIdentity) {
    let exit = crate::error::ExitIdentity::AGENT_REFUSED;
    (
        crate::orient_cmd::execution_diagnostic(
            command,
            root,
            crate::error::ERR_CLI_READ_CANCELLED,
            exit,
        ),
        exit,
    )
}

/// Exact identity and output contract of an interrupted snapshot-only read.
pub(crate) struct CancelledRead<'a> {
    pub(crate) command: &'static str,
    pub(crate) operation: &'static str,
    pub(crate) root: &'a std::path::Path,
    pub(crate) request_digest: fss_core::ContentDigest,
    pub(crate) principal: &'a fss_core::PrincipalId,
    pub(crate) view: fss_core::AgentView,
    pub(crate) capability: &'static str,
    pub(crate) payload_schema: &'static str,
}

/// Render cancellation solely from an already verified snapshot, without further I/O.
/// The retained anchor describes completed verification, not a fresh post-cancellation head.
pub(crate) fn cancelled_snapshot_read(
    read: CancelledRead<'_>,
    snapshot: &fss_reference::agent_orient::DeploymentSnapshot,
) -> (String, crate::error::ExitIdentity) {
    cancelled_anchored_read(read, &snapshot.anchor, snapshot.latest_evidence_time.0)
}

/// Render from a completed immutable owner's verified authority observation alone.
/// The caller must never construct this anchor by reopening storage after cancellation.
pub(crate) fn cancelled_anchored_read(
    read: CancelledRead<'_>,
    anchor: &fss_core::LedgerAnchor,
    observed_at_ns: i128,
) -> (String, crate::error::ExitIdentity) {
    cancelled_anchored_read_with_boundary(
        read,
        anchor,
        observed_at_ns,
        crate::orient_cmd::read_only_boundary(
            "Observed caller cancellation after complete snapshot verification.".to_owned(),
        ),
    )
}

/// Preserve any completed session-clock admission while discarding a private read's output.
/// The supplied boundary and verified anchor require no new storage read or session lock.
pub(crate) fn cancelled_anchored_read_with_boundary(
    read: CancelledRead<'_>,
    anchor: &fss_core::LedgerAnchor,
    observed_at_ns: i128,
    boundary: fss_core::ExecutionBoundary,
) -> (String, crate::error::ExitIdentity) {
    use fss_core::{
        BudgetVector, Completeness, KnowledgeState, ResponseOutcome, ResponseSafeRetry,
    };

    use crate::orient_cmd::{ResponseParts, build_response, rendered};

    rendered(
        build_response(ResponseParts {
            operation: read.operation,
            request_digest: read.request_digest,
            principal: read.principal.clone(),
            session_id: None,
            mission_id: None,
            anchor: anchor.clone(),
            view: read.view,
            capability: read.capability,
            outcome: ResponseOutcome::Cancelled,
            error_id: None,
            payload_schema: read.payload_schema,
            payload_json: "null".to_owned(),
            epistemic_state: KnowledgeState::Unknown,
            completeness: Completeness::Partial,
            warnings: Vec::new(),
            contradictions: Vec::new(),
            degradation: vec![
                "The request owner cancelled this read. No result, empty-match claim, \
                 continuation or affordance is delivered. The anchor is the last completely \
                 verified snapshot; no storage was reread to render cancellation."
                    .to_owned(),
                "Interrupted work is not fully metered. Zero budget placeholders do not \
                 claim zero work. A new read requires a fresh request owner."
                    .to_owned(),
            ],
            budgets_json: crate::agent_json::budget_summary(
                &BudgetVector::ZERO,
                &BudgetVector::ZERO,
            ),
            proof_pointers: vec![anchor.state_root.to_text()],
            affordances: Vec::new(),
            affordance_objects: Vec::new(),
            decision_fingerprint: read.request_digest,
            compression_receipt_id: None,
            continuation: None,
            recovery_class: "operator_action_required",
            safe_retry: ResponseSafeRetry::No,
            boundary,
            created_at_ns: observed_at_ns,
            workspace_revision: None,
            idempotency_key: None,
        }),
        crate::error::ExitIdentity::AGENT_REFUSED,
        read.command,
        read.root,
    )
}

#[cfg(test)]
mod tests;
