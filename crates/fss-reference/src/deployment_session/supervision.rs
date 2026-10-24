#![forbid(unsafe_code)]
//! Session-owned delivery of bounded, historical retained-supervision reports.
//!
//! The existing session journal owns registration, charged attempts, pending bytes and explicit
//! ACK/discard. An admitted evaluator owns native cognition and current source verification.
//! A report is never made current by redelivery, and source validation never grants an effect.

use std::fmt;
use std::path::Path;

use fss_core::{AgentSession, ContentDigest, DigestAlgorithm, LedgerAnchor, PrincipalId, TimestampNs};

use super::{DeploymentSessionError, SessionJournal};
use crate::agent_orient::{DeploymentHistory, OrientLimits};
use crate::agent_session::checkpoint::journal::supervision::{
    DurableSupervisionError, PendingSupervisionDelivery, SupervisionRegistration,
    SupervisionSourcePin, SupervisionSubscription,
};

/// Exactly one action is committed by a command. ACK never evaluates a successor implicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisionAction {
    /// Produce a fresh pending report, or revalidate and redeliver the existing one.
    Poll,
    /// Acknowledge the exact pending receipt, or retry the most recent committed ACK.
    Acknowledge(ContentDigest),
    /// Explicitly abandon one pending report without claiming its delivery was acknowledged.
    Discard(ContentDigest),
}

/// Immutable registration plus the explicitly expected current authority for this command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionSessionRequest {
    /// Exact configuration bytes, session-local label and cumulative attempt ceilings.
    pub registration: SupervisionRegistration,
    /// Current root supplied for this invocation; never inferred by silently rebasing a request.
    pub expected_authority_root: ContentDigest,
    /// Poll, exact ACK, or exact discard.
    pub action: SupervisionAction,
}

/// Complete scope presented to the caller's authority at every work boundary.
pub struct SupervisionSessionBinding<'a> {
    root: &'a Path,
    principal: &'a PrincipalId,
    request: &'a SupervisionSessionRequest,
    limits: &'a OrientLimits,
}

impl<'a> SupervisionSessionBinding<'a> {
    /// Deployment namespace.
    pub const fn root(&self) -> &'a Path { self.root }
    /// Authenticated caller.
    pub const fn principal(&self) -> &'a PrincipalId { self.principal }
    /// Exact original command.
    pub const fn request(&self) -> &'a SupervisionSessionRequest { self.request }
    /// Bounded history observations.
    pub const fn limits(&self) -> &'a OrientLimits { self.limits }
}

/// No owner work, lock, source evaluation or response is admitted implicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisionSessionBoundary {
    /// Before a bounded current deployment-history read.
    ReadHistory,
    /// Before acquiring the existing exclusive session-journal writer.
    OpenJournal,
    /// Before admitting the live session and immutable registration.
    ReadSubscription,
    /// Before durably reserving the complete native read ceilings.
    ReserveRead,
    /// Before fresh native discovery and supervision.
    Evaluate,
    /// Before current verification of all retained metadata/native source pins.
    RevalidateSources,
    /// Before comparing current history against this command's admitted head.
    RevalidateHistory,
    /// Before storing the complete pending result.
    PublishDelivery,
    /// Before durably consuming validation and exposing the exact pending bytes.
    ReleasePayload,
    /// Before the explicit acknowledgement.
    Acknowledge,
    /// Before explicit abandonment, which never claims a source verification or ACK.
    Discard,
    /// Before releasing a complete result whose journal changes are already pinned.
    Deliver,
}

/// Evaluators preserve their owning stable diagnostic without importing a cognition engine here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionAdapterError {
    /// Stable source-owner or runtime diagnostic.
    pub identity: &'static str,
    /// Bounded operation description; never a partial successful payload.
    pub reason: String,
}

impl fmt::Display for SupervisionAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.identity, self.reason)
    }
}
impl std::error::Error for SupervisionAdapterError {}

/// Caller-owned cancellation/deadline/capability admission, with no permissive implementation.
pub trait SupervisionSessionControl {
    /// Admit exactly the immutable binding and named operation boundary.
    fn admit_session(
        &mut self,
        binding: &SupervisionSessionBinding<'_>,
        boundary: SupervisionSessionBoundary,
    ) -> Result<(), SupervisionAdapterError>;
}

/// A private fresh computation; it is not released until durable pending publication succeeds.
#[derive(Debug)]
pub struct SupervisionEvaluation {
    /// Exact admitted current anchor under which the native evaluator completed.
    pub basis: LedgerAnchor,
    /// Complete historical report bytes, without a transport-added newline.
    pub payload: Vec<u8>,
    /// Native report's own receipt.
    pub report_receipt: ContentDigest,
    /// Every metadata candidate, distinguishing sources that were verified natively.
    pub sources: Vec<SupervisionSourcePin>,
}

/// Current verification of a historical report's complete source inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionValidation {
    /// Current authority, not the historical report's original authority.
    pub basis: LedgerAnchor,
    /// Receipt binding the current source validation and its complete inventory.
    pub receipt: ContentDigest,
    /// Actual conservative source envelope reservations in this validation.
    pub reserved_bytes: u64,
    /// Actual indexed source reads in this validation.
    pub read_attempts: u64,
}

/// Trusted native adapter; the journal stores derived reports and does not manufacture evidence.
pub trait SupervisionEvaluator: SupervisionSessionControl {
    /// Run discovery under the explicitly admitted current root and the registered read caps.
    fn evaluate(
        &mut self,
        binding: &SupervisionSessionBinding<'_>,
        anchor: &LedgerAnchor,
    ) -> Result<SupervisionEvaluation, SupervisionAdapterError>;

    /// Verify all stored metadata/native pins before any historical payload release or new ACK.
    fn revalidate(
        &mut self,
        binding: &SupervisionSessionBinding<'_>,
        anchor: &LedgerAnchor,
        pending: &PendingSupervisionDelivery,
    ) -> Result<SupervisionValidation, SupervisionAdapterError>;
}

/// Exact bounded deployment history observed for this command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionSessionHead {
    /// Current complete authority anchor.
    pub anchor: LedgerAnchor,
    /// Exact canonical ledger journal root.
    pub ledger_root: ContentDigest,
    /// Exact effect journal root; observing it never authorizes an effect.
    pub effect_root: ContentDigest,
    /// Existing deployment evidence-clock watermark, never an invented wall-clock time.
    pub observed_at: TimestampNs,
}

/// One complete result. Acknowledgement and discard commands never also return a successor.
#[derive(Debug)]
pub enum SupervisionSessionOutcome {
    /// Historical pending bytes released only after admitted native verification.
    Report {
        /// Exact historical report bytes.
        payload: Vec<u8>,
        /// Durable descriptor and exact ACK/discard receipt.
        pending: PendingSupervisionDelivery,
        /// True when this payload was already pending before the command.
        replayed: bool,
        /// Separate current validation for historical redelivery; fresh evaluation is its own proof.
        validation: Option<SupervisionValidation>,
    },
    /// One receipt was acknowledged, including its exact idempotent retry.
    Acknowledged {
        /// Exact acknowledged delivery receipt.
        receipt: ContentDigest,
        /// Current validation for a new ACK; an exact last-ACK retry performs no fresh source work.
        validation: Option<SupervisionValidation>,
    },
    /// One receipt was explicitly abandoned, including its exact idempotent retry.
    Discarded(ContentDigest),
}

/// Complete delivery context; journal counters never reset when a process restarts.
#[derive(Debug)]
pub struct SupervisionSessionDelivery {
    /// Live admitted session, with its original grants and lease.
    pub session: AgentSession,
    /// Current history separately reported from historical payload authority.
    pub head: SupervisionSessionHead,
    /// Complete updated subscription state, without a private payload accessor.
    pub subscription: SupervisionSubscription,
    /// Pinned journal containing this command's committed changes.
    pub journal_root: ContentDigest,
    /// Exactly one committed outcome.
    pub outcome: SupervisionSessionOutcome,
}

/// No refusal is represented as an empty successful report.
#[derive(Debug)]
pub enum SupervisionSessionError {
    /// Request syntax or a finite bound failed before work admission.
    InvalidRequest,
    /// Existing session, lock or journal owner refused.
    Session(DeploymentSessionError),
    /// Durable CAS, scope, reservation, pending receipt or ACK/discard refused.
    Store(DurableSupervisionError),
    /// Caller authority stopped work.
    Denied(SupervisionAdapterError),
    /// Native evaluation or current source verification refused.
    Evaluation(SupervisionAdapterError),
    /// Authority, ledger/effect history or the evaluator's exact basis changed.
    ChangedAuthority,
    /// Current generation authority differs from the session's interpretation basis.
    StaleAuthority,
}

impl fmt::Display for SupervisionSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => f.write_str("invalid bounded supervision session request"),
            Self::Session(error) => write!(f, "{error}"),
            Self::Store(error) => write!(f, "{error}"),
            Self::Denied(error) | Self::Evaluation(error) => write!(f, "{error}"),
            Self::ChangedAuthority => f.write_str(
                "supervision authority changed; complete delivery withheld",
            ),
            Self::StaleAuthority => f.write_str(
                "supervision session authority generation is stale; explicit fresh session required",
            ),
        }
    }
}
impl std::error::Error for SupervisionSessionError {}

/// Durable progress is reported even when source checks, pinning or final output later fail.
#[derive(Debug)]
pub struct SupervisionSessionFailure {
    /// Owning typed refusal.
    pub error: SupervisionSessionError,
    /// Current verified deployment head, when available.
    pub head: Option<SupervisionSessionHead>,
    /// Reservation count definitely committed before the failure.
    pub attempts_reserved: u32,
    /// Exact ACK definitely committed before a later failure.
    pub acknowledged: Option<ContentDigest>,
    /// Exact discard definitely committed before a later failure.
    pub discarded: Option<ContentDigest>,
    /// Session clock, registration, reservation or delivery may already have changed durably.
    pub journal_may_have_changed: bool,
}
impl fmt::Display for SupervisionSessionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.error.fmt(f) }
}
impl std::error::Error for SupervisionSessionFailure {}

fn observe_head(history: &DeploymentHistory) -> Result<SupervisionSessionHead, SupervisionSessionError> {
    let (anchor, ledger_root, effect_root) = history
        .roots_at(history.head())
        .ok_or(SupervisionSessionError::ChangedAuthority)?;
    let observed_at = history
        .batches_through_head()
        .iter()
        .flat_map(|batch| &batch.deltas)
        .map(|delta| delta.validity.latest.0)
        .max()
        .unwrap_or(0)
        .max(0);
    Ok(SupervisionSessionHead {
        anchor,
        ledger_root,
        effect_root,
        observed_at: TimestampNs(observed_at),
    })
}

fn same_generations(left: &LedgerAnchor, right: &LedgerAnchor) -> bool {
    left.site_lineage == right.site_lineage
        && left.ledger_epoch == right.ledger_epoch
        && left.adapter_registry_epoch == right.adapter_registry_epoch
        && left.schema_epoch == right.schema_epoch
        && left.policy_epoch == right.policy_epoch
        && left.privacy_epoch == right.privacy_epoch
}

fn admit(
    control: &mut impl SupervisionEvaluator,
    binding: &SupervisionSessionBinding<'_>,
    boundary: SupervisionSessionBoundary,
) -> Result<(), SupervisionSessionError> {
    control
        .admit_session(binding, boundary)
        .map_err(SupervisionSessionError::Denied)
}

fn revalidate_history(
    binding: &SupervisionSessionBinding<'_>,
    head: &SupervisionSessionHead,
    session: &AgentSession,
    control: &mut impl SupervisionEvaluator,
    progress: &mut SupervisionSessionFailure,
) -> Result<(), SupervisionSessionError> {
    admit(control, binding, SupervisionSessionBoundary::RevalidateHistory)?;
    let history = DeploymentHistory::read(binding.root, binding.limits)
        .map_err(|error| SupervisionSessionError::Session(error.into()))?;
    let current = observe_head(&history)?;
    progress.head = Some(current.clone());
    if &current != head || !same_generations(&session.current_anchor, &current.anchor) {
        return Err(SupervisionSessionError::ChangedAuthority);
    }
    Ok(())
}

/// Executes one finite poll/ACK/discard. All source work has a prior durable full-cap reservation.
pub fn supervise_session(
    root: &Path,
    principal: &PrincipalId,
    request: &SupervisionSessionRequest,
    limits: &OrientLimits,
    control: &mut impl SupervisionEvaluator,
) -> Result<SupervisionSessionDelivery, Box<SupervisionSessionFailure>> {
    let mut progress = SupervisionSessionFailure {
        error: SupervisionSessionError::InvalidRequest,
        head: None,
        attempts_reserved: 0,
        acknowledged: None,
        discarded: None,
        journal_may_have_changed: false,
    };
    match execute(root, principal, request, limits, control, &mut progress) {
        Ok(delivery) => Ok(delivery),
        Err(error) => {
            progress.error = error;
            Err(Box::new(progress))
        }
    }
}

fn execute(
    root: &Path,
    principal: &PrincipalId,
    request: &SupervisionSessionRequest,
    limits: &OrientLimits,
    control: &mut impl SupervisionEvaluator,
    progress: &mut SupervisionSessionFailure,
) -> Result<SupervisionSessionDelivery, SupervisionSessionError> {
    request.registration.validate().map_err(SupervisionSessionError::Store)?;
    let defaults = OrientLimits::default();
    if root.as_os_str().is_empty()
        || request.expected_authority_root.algorithm() != DigestAlgorithm::Sha256
        || request.expected_authority_root.bytes() == [0; 32]
        || matches!(
            request.action,
            SupervisionAction::Acknowledge(digest) | SupervisionAction::Discard(digest)
                if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32]
        )
        || limits.max_journal_bytes == 0
        || limits.max_journal_bytes > 32 * 1024 * 1024
        || [
            (limits.max_layout_bytes, defaults.max_layout_bytes),
            (limits.max_object_bytes, defaults.max_object_bytes),
            (limits.max_events, defaults.max_events),
            (limits.max_revisions_per_event, defaults.max_revisions_per_event),
        ].into_iter().any(|(value, ceiling)| value == 0 || value > ceiling)
    {
        return Err(SupervisionSessionError::InvalidRequest);
    }
    let binding = SupervisionSessionBinding { root, principal, request, limits };
    admit(control, &binding, SupervisionSessionBoundary::ReadHistory)?;
    let history = DeploymentHistory::read(root, limits)
        .map_err(|error| SupervisionSessionError::Session(error.into()))?;
    let head = observe_head(&history)?;
    progress.head = Some(head.clone());
    if head.anchor.state_root != request.expected_authority_root {
        return Err(SupervisionSessionError::ChangedAuthority);
    }
    admit(control, &binding, SupervisionSessionBoundary::OpenJournal)?;
    progress.journal_may_have_changed = true;
    let mut journal = SessionJournal::open(root).map_err(SupervisionSessionError::Session)?;
    admit(control, &binding, SupervisionSessionBoundary::ReadSubscription)?;
    let session = journal.store
        .session(principal, &request.registration.session_id, head.observed_at)
        .map_err(|error| SupervisionSessionError::Session(error.into()))?;
    if !same_generations(&session.current_anchor, &head.anchor) {
        return Err(SupervisionSessionError::StaleAuthority);
    }
    let mut state = journal.store
        .register_supervision(principal, request.registration.clone(), head.observed_at)
        .map_err(SupervisionSessionError::Store)?;
    journal.commit_pin().map_err(SupervisionSessionError::Session)?;
    progress.attempts_reserved = state.attempts_reserved();

    let outcome = match request.action {
        SupervisionAction::Discard(receipt) => {
            revalidate_history(&binding, &head, &session, control, progress)?;
            admit(control, &binding, SupervisionSessionBoundary::Discard)?;
            state = journal.store.discard_supervision(
                principal, &state, receipt, &head.anchor, head.observed_at,
            ).map_err(SupervisionSessionError::Store)?;
            progress.discarded = Some(receipt);
            journal.commit_pin().map_err(SupervisionSessionError::Session)?;
            SupervisionSessionOutcome::Discarded(receipt)
        }
        SupervisionAction::Acknowledge(receipt)
            if state.last_acknowledged() == Some(receipt) =>
        {
            revalidate_history(&binding, &head, &session, control, progress)?;
            admit(control, &binding, SupervisionSessionBoundary::Acknowledge)?;
            state = journal.store.acknowledge_supervision(
                principal, &state, None, receipt, &head.anchor, head.observed_at,
            ).map_err(SupervisionSessionError::Store)?;
            progress.acknowledged = Some(receipt);
            journal.commit_pin().map_err(SupervisionSessionError::Session)?;
            SupervisionSessionOutcome::Acknowledged { receipt, validation: None }
        }
        action => {
            let pending = state.pending().cloned();
            if let SupervisionAction::Acknowledge(receipt) = action {
                if pending.as_ref().is_none_or(|pending| pending.receipt() != receipt) {
                    return Err(SupervisionSessionError::InvalidRequest);
                }
            }
            admit(control, &binding, SupervisionSessionBoundary::ReserveRead)?;
            state = journal.store.reserve_supervision(
                principal, &state, &head.anchor, head.observed_at,
            ).map_err(SupervisionSessionError::Store)?;
            progress.attempts_reserved = state.attempts_reserved();
            journal.commit_pin().map_err(SupervisionSessionError::Session)?;
            let reservation = state.reservation().cloned()
                .ok_or(SupervisionSessionError::InvalidRequest)?;
            if let Some(pending) = pending {
                admit(control, &binding, SupervisionSessionBoundary::RevalidateSources)?;
                let validation = control.revalidate(&binding, &head.anchor, &pending)
                    .map_err(SupervisionSessionError::Evaluation)?;
                if validation.basis != head.anchor
                    || validation.receipt.algorithm() != DigestAlgorithm::Sha256
                    || validation.receipt.bytes() == [0; 32]
                    || validation.reserved_bytes > state.registration().max_read_bytes
                    || validation.read_attempts > state.registration().max_read_attempts
                {
                    return Err(SupervisionSessionError::ChangedAuthority);
                }
                revalidate_history(&binding, &head, &session, control, progress)?;
                if let SupervisionAction::Acknowledge(receipt) = action {
                    admit(control, &binding, SupervisionSessionBoundary::Acknowledge)?;
                    state = journal.store.acknowledge_supervision(
                        principal, &state, Some(&reservation), receipt, &head.anchor, head.observed_at,
                    ).map_err(SupervisionSessionError::Store)?;
                    progress.acknowledged = Some(receipt);
                    journal.commit_pin().map_err(SupervisionSessionError::Session)?;
                    SupervisionSessionOutcome::Acknowledged { receipt, validation: Some(validation) }
                } else {
                    admit(control, &binding, SupervisionSessionBoundary::ReleasePayload)?;
                    let (updated, payload) = journal.store.release_supervision_payload(
                        principal, &state, &reservation, pending.receipt(), head.observed_at,
                    ).map_err(SupervisionSessionError::Store)?;
                    state = updated;
                    journal.commit_pin().map_err(SupervisionSessionError::Session)?;
                    SupervisionSessionOutcome::Report {
                        payload, pending, replayed: true, validation: Some(validation),
                    }
                }
            } else {
                admit(control, &binding, SupervisionSessionBoundary::Evaluate)?;
                let evaluation = control.evaluate(&binding, &head.anchor)
                    .map_err(SupervisionSessionError::Evaluation)?;
                if evaluation.basis != head.anchor {
                    return Err(SupervisionSessionError::ChangedAuthority);
                }
                revalidate_history(&binding, &head, &session, control, progress)?;
                admit(control, &binding, SupervisionSessionBoundary::PublishDelivery)?;
                state = journal.store.publish_supervision(
                    principal, &state, &reservation, evaluation.payload.clone(),
                    evaluation.sources, evaluation.report_receipt, head.observed_at,
                ).map_err(SupervisionSessionError::Store)?;
                journal.commit_pin().map_err(SupervisionSessionError::Session)?;
                let pending = state.pending().cloned()
                    .ok_or(SupervisionSessionError::InvalidRequest)?;
                SupervisionSessionOutcome::Report {
                    payload: evaluation.payload, pending, replayed: false, validation: None,
                }
            }
        }
    };
    revalidate_history(&binding, &head, &session, control, progress)?;
    admit(control, &binding, SupervisionSessionBoundary::Deliver)?;
    Ok(SupervisionSessionDelivery {
        session, head, subscription: state, journal_root: journal.store.committed_root(), outcome,
    })
}
