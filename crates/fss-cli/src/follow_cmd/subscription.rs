#![forbid(unsafe_code)]
//! Explicit, session-owned follow delivery and acknowledgement.

use std::path::Path;
use std::time::{Duration, Instant};

use fss_core::{
    BudgetVector, Completeness, ContentDigest, KnowledgeState, PrincipalId, ResponseOutcome,
    ResponseSafeRetry, SessionId,
};
use fss_reference::agent_follow::replay::{
    ReplayBinding, ReplayBoundary, ReplayControl, ReplayDenial, ReplayError,
};
use fss_reference::agent_follow::wait::{
    FOLLOW_WAIT_POLL_MS, FollowWaitBinding, FollowWaitBoundary, FollowWaitControl,
    FollowWaitDenial, FollowWaitProgress, MAX_FOLLOW_WAIT_READS,
};
use fss_reference::agent_session::checkpoint::journal::follow::DurableFollowError;
use fss_reference::deployment_session::DeploymentSessionError;
use fss_reference::deployment_session::follow::wait::{
    FollowSessionWaitBinding, follow_session_wait,
};
use fss_reference::deployment_session::follow::{
    FollowSessionBinding, FollowSessionBoundary, FollowSessionControl, FollowSessionDelivery,
    FollowSessionError, FollowSessionFailure, FollowSessionRequest, follow_session,
};

use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{
    ResponseParts, build_response, build_response_with_resnapshot, execution_diagnostic,
    internal_failure, rendered, take,
};
use crate::session_cmd;

use super::{FollowArgs, FollowError, OrientError, OrientLimits};

const ACK_CONTINUATION_PREFIX: &str = "continuation:follow-ack:";
const ERR_RESNAPSHOT: &str = "ERR-AGENT-RESNAPSHOT-001";

/// Durable follow scope. Acknowledgements name an exact previously delivered page receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowSubscriptionArgs {
    /// Existing durable session that owns the cursor and its original grants.
    pub session_id: SessionId,
    /// Stable identity scoped to this session; never a path or effect authority.
    pub subscription_id: String,
    /// Exact receipt to acknowledge before requesting the next page.
    pub acknowledge: Option<ContentDigest>,
}

pub(super) fn parse(
    values: &[(String, String, usize)],
    has_continuation: bool,
    _has_wait: bool,
) -> Result<Option<FollowSubscriptionArgs>, CliError> {
    let session = take(values, "--session");
    let subscription = take(values, "--subscription");
    let acknowledgement = take(values, "--acknowledge");
    if session.is_none() && subscription.is_none() && acknowledgement.is_none() {
        return Ok(None);
    }
    let required = |option: &str| CliError::MissingValue {
        option: option.to_owned(),
        command: Some("follow".to_owned()),
        expected: "both --session and --subscription for durable follow delivery".to_owned(),
    };
    let (_, raw_session, session_index) = session.ok_or_else(|| required("--session"))?;
    let (_, subscription_id, subscription_index) =
        subscription.ok_or_else(|| required("--subscription"))?;
    if has_continuation {
        return Err(super::malformed(
            "--subscription",
            subscription_id,
            "durable follow owns its page cursor; --continuation cannot be combined with --subscription",
            *subscription_index,
        ));
    }
    let session_id = SessionId::parse(raw_session).map_err(|_| {
        super::malformed(
            "--session",
            raw_session,
            "session must be a canonical stable identifier of at most 128 ASCII bytes",
            *session_index,
        )
    })?;
    fss_core::validate_id(subscription_id).map_err(|_| {
        super::malformed(
            "--subscription",
            subscription_id,
            "subscription must be a canonical stable identifier of at most 128 ASCII bytes",
            *subscription_index,
        )
    })?;
    let acknowledge = acknowledgement
        .map(|(_, value, index)| {
            ContentDigest::parse(value).map_err(|_| {
                super::malformed(
                    "--acknowledge",
                    value,
                    "acknowledgement must be the exact sha256 receipt returned by a durable follow delivery",
                    *index,
                )
            })
        })
        .transpose()?;
    Ok(Some(FollowSubscriptionArgs {
        session_id,
        subscription_id: subscription_id.clone(),
        acknowledge,
    }))
}

/// The launching OS account and the explicit root provide local access. Durable session
/// admission separately checks principal, grants, privacy, lease and immutable subscription
/// scope. This adapter never authenticates remote credentials or executes an effect.
struct LocalControl<'a> {
    root: &'a Path,
    principal: &'a PrincipalId,
    request: &'a FollowSessionRequest,
    limits: OrientLimits,
    session_boundaries: u32,
    replay_boundaries: u32,
    replay: Option<ReplayBinding>,
    wait: Option<FollowWaitBinding>,
    started: Instant,
}

impl FollowSessionControl for LocalControl<'_> {
    fn admit_session(
        &mut self,
        binding: &FollowSessionBinding<'_>,
        _: FollowSessionBoundary,
    ) -> Result<(), ReplayDenial> {
        if binding.root() != self.root
            || binding.principal() != self.principal
            || binding.request() != self.request
            || binding.limits() != &self.limits
        {
            return Err(ReplayDenial::Unauthorized);
        }
        self.session_boundaries = self
            .session_boundaries
            .checked_add(1)
            .ok_or(ReplayDenial::Budget)?;
        let maximum = self
            .wait
            .as_ref()
            .map_or(16, |scope| scope.max_reads() * 16);
        if self.session_boundaries > maximum {
            return Err(ReplayDenial::Budget);
        }
        Ok(())
    }
}

impl ReplayControl for LocalControl<'_> {
    fn admit(
        &mut self,
        binding: &ReplayBinding,
        boundary: ReplayBoundary,
    ) -> Result<(), ReplayDenial> {
        if binding.objects_root() != self.root.join("objects")
            || binding.request().principal != *self.principal
            || binding.request().view != self.request.view
            || binding.request().max_entries != self.request.max_entries
            || binding.read_limits() != self.limits
            || binding
                .session()
                .is_none_or(|session| session.session_id != self.request.session_id)
        {
            return Err(ReplayDenial::Unauthorized);
        }
        if boundary == ReplayBoundary::BasisSnapshot {
            self.replay = Some(binding.clone());
        } else if self.replay.as_ref() != Some(binding) {
            return Err(ReplayDenial::Unauthorized);
        }
        self.replay_boundaries = self
            .replay_boundaries
            .checked_add(1)
            .ok_or(ReplayDenial::Budget)?;
        // An ACK may reverify the pending page before reconstructing its successor. Each native
        // replay has exactly four admitted boundaries and at most two bounded snapshots.
        let maximum = self.wait.as_ref().map_or(8, |scope| scope.max_reads() * 8);
        if self.replay_boundaries > maximum {
            return Err(ReplayDenial::Budget);
        }
        Ok(())
    }
}

impl FollowWaitControl for LocalControl<'_> {
    fn checkpoint(
        &mut self,
        binding: &FollowWaitBinding,
        _: FollowWaitBoundary,
    ) -> Result<u64, FollowWaitDenial> {
        if self.wait.as_ref() != Some(binding) {
            return Err(FollowWaitDenial::Unauthorized);
        }
        u64::try_from(self.started.elapsed().as_millis())
            .map_err(|_| FollowWaitDenial::ClockUnavailable)
    }

    fn park(&mut self, binding: &FollowWaitBinding, delay_ms: u64) -> Result<(), FollowWaitDenial> {
        let now = self.checkpoint(binding, FollowWaitBoundary::Park)?;
        if delay_ms == 0 || delay_ms > FOLLOW_WAIT_POLL_MS {
            return Err(FollowWaitDenial::Unauthorized);
        }
        let remaining = binding.wait_ms().saturating_sub(now);
        if remaining > 0 {
            std::thread::sleep(Duration::from_millis(delay_ms.min(remaining)));
        }
        Ok(())
    }
}

pub(super) fn execute(args: &FollowArgs) -> (String, ExitIdentity) {
    let Some(scope) = &args.subscription else {
        return internal_failure("follow", &args.root);
    };
    if args.continuation.is_some() {
        return (
            execution_diagnostic(
                "follow",
                &args.root,
                session_cmd::ERR_PRECONDITION_STALE,
                ExitIdentity::AGENT_REFUSED,
            ),
            ExitIdentity::AGENT_REFUSED,
        );
    }
    let request = FollowSessionRequest {
        session_id: scope.session_id.clone(),
        subscription_id: scope.subscription_id.clone(),
        since: args.since.clone(),
        view: args.view,
        max_entries: args.max_entries,
        acknowledge: scope.acknowledge,
    };
    let limits = OrientLimits::default();
    let wait = match args
        .wait_ms
        .map(|milliseconds| {
            FollowSessionWaitBinding::new(
                &args.root,
                args.principal.clone(),
                request.clone(),
                limits,
                milliseconds,
                MAX_FOLLOW_WAIT_READS,
            )
        })
        .transpose()
    {
        Ok(wait) => wait,
        Err(_) => {
            return (
                execution_diagnostic(
                    "follow",
                    &args.root,
                    crate::ERR_CLI_MALFORMED_VALUE,
                    ExitIdentity::AGENT_REFUSED,
                ),
                ExitIdentity::AGENT_REFUSED,
            );
        }
    };
    let mut control = LocalControl {
        root: &args.root,
        principal: &args.principal,
        request: &request,
        limits,
        session_boundaries: 0,
        replay_boundaries: 0,
        replay: None,
        wait: wait.as_ref().map(|binding| binding.read_scope().clone()),
        started: Instant::now(),
    };
    if let Some(wait) = wait {
        return match follow_session_wait(&wait, &mut control) {
            Ok(result) => rendered(
                delivery_response(args, &result.delivery, Some(&result.progress)),
                ExitIdentity::SUCCESS,
                "follow",
                &args.root,
            ),
            Err(failure) => failure_response_with_wait(
                args,
                &failure.failure,
                Some((&failure.progress, failure.last_follow.as_ref())),
            ),
        };
    }
    match follow_session(&args.root, &args.principal, &request, &limits, &mut control) {
        Ok(delivery) => rendered(
            delivery_response(args, &delivery, None),
            ExitIdentity::SUCCESS,
            "follow",
            &args.root,
        ),
        Err(failure) => failure_response(args, &failure),
    }
}

fn delivery_response(
    args: &FollowArgs,
    delivery: &FollowSessionDelivery,
    wait: Option<&FollowWaitProgress>,
) -> Result<String, Box<dyn std::error::Error>> {
    let capsule = delivery.follow.result.capsule();
    if capsule.session_id != delivery.session.session_id
        || capsule.mission_id != delivery.session.mission_id
        || capsule.principal_id != delivery.session.principal_id
    {
        return Err(
            crate::orient_cmd::RenderError("durable follow publication session binding").into(),
        );
    }
    let request_digest = super::request_digest(args, &capsule.anchor);
    let mut parts = super::follow_response_parts(&delivery.follow, request_digest)?;
    let receipt = delivery.delivery_receipt.to_text();
    let continuation = format!("{ACK_CONTINUATION_PREFIX}{receipt}");
    parts.payload_json = super::meaningful_delta_json(
        &delivery.follow.delta,
        &delivery.follow.page_items,
        &continuation,
        &delivery.follow.result,
    );
    parts.continuation = Some(continuation);
    parts.recovery_class = "resume_from_continuation";
    parts.idempotency_key = Some(session_cmd::idempotency_key(delivery.delivery_receipt));
    parts.proof_pointers.extend([
        format!("follow-delivery:{receipt}"),
        format!("follow-journal:{}", delivery.journal_root.to_text()),
        format!("follow-subscription:{}", delivery.subscription_id),
        format!("follow-horizon:{}", delivery.horizon_anchor.as_str()),
        delivery.horizon_anchor.as_str().to_owned(),
    ]);
    if let Some(ack) = delivery.acknowledged {
        parts
            .proof_pointers
            .push(format!("follow-acknowledged:{}", ack.to_text()));
    }
    parts
        .degradation
        .retain(|line| !line.contains("through the envelope continuation (the same --since"));
    parts.degradation.extend([
        format!(
            "Durable subscription {}: {} pending page. Repeat the same request without a new acknowledgement to redeliver it; use --acknowledge {receipt} with the original --since, session, subscription, view and page size to acknowledge this exact page and request its successor.",
            delivery.subscription_id, if delivery.replayed { "reconstructed the existing" } else { "retained a new" },
        ),
        format!(
            "This adjacent transition runs from {} to {} within frozen horizon {}. It reaches that horizon: {}. Every remaining item page still requires explicit acknowledgement.",
            delivery.since_anchor.as_str(), delivery.result_anchor.as_str(),
            delivery.horizon_anchor.as_str(), delivery.horizon_reached,
        ),
        "Only exact deployment-ledger or effect-journal prefix transitions are replayed. Mixed-journal interleaving and changing agent case, plan, finding or workspace history require explicit resnapshot; this adapter cannot claim their complete subscription history.".to_owned(),
        "Budget counters cover the returned native comparison. Session-journal verification/publication, history revalidation and an acknowledged prior page's reconstruction are additional bounded work and are not claimed to be zero-cost. The command admits at most two native comparisons; it does not renew an evidence clock, lease or grant.".to_owned(),
    ]);
    parts.boundary = session_cmd::agent_plane_boundary(
        format!(
            "Durably retained delivery receipt {receipt} before response release; acknowledged {}.",
            delivery
                .acknowledged
                .map_or_else(|| "no new page".to_owned(), |ack| ack.to_text())
        ),
        Vec::new(),
    );
    if let Some(progress) = wait {
        parts.budgets_json = wait_budget(args, progress);
        parts.degradation.retain(|line| {
            !line.starts_with("Budget counters cover the returned native comparison.")
        });
        parts.degradation.extend(wait_accounting(args, progress));
    }
    build_response(parts)
}

fn wait_budget(args: &FollowArgs, progress: &FollowWaitProgress) -> String {
    let mut requested = progress.requested;
    let mut consumed = progress.consumed;
    requested.latency_ms = args.wait_ms.unwrap_or(0);
    consumed.latency_ms = progress.elapsed_ms;
    crate::agent_json::budget_summary(&requested, &consumed)
}

fn wait_accounting(args: &FollowArgs, progress: &FollowWaitProgress) -> Vec<String> {
    vec![
        format!(
            "Durable bounded wait: {} ms admission deadline; {} ms last observed elapsed; {} of {} history reads, including revalidations; {} completed comparisons; {} completed parks. Lock acquisitions and semantic scans are bounded by these read admissions; no journal lock is held while parked.",
            args.wait_ms.unwrap_or(0), progress.elapsed_ms, progress.admitted_reads,
            MAX_FOLLOW_WAIT_READS, progress.completed_comparisons, progress.completed_parks,
        ),
        "Pending pages and every actual adjacent transition return immediately. Only newly computed certified quiet at the exact acknowledged head can park. Quiet probes create no pending delivery and never acknowledge a page. Wall waiting does not renew an evidence clock, session, grant or coverage interval.".to_owned(),
        format!(
            "Fresh source custody across all polls: {} read admissions; {} verified reads; {} payload bytes; {} publication-metadata bytes; {} requested envelope bytes; {} of {} charged envelope bytes. Failed reads retain their reservation. The allowance and accounting never reset between polls.",
            progress.source_read_attempts, progress.verified_source_reads,
            progress.source_payload_bytes, progress.source_metadata_bytes,
            progress.source_requested_bytes, progress.source_reserved_bytes,
            fss_reference::agent_follow::wait::MAX_FOLLOW_WAIT_SOURCE_ENVELOPE_BYTES,
        ),
        "Budgets include every completed native comparison (including ACK reconstruction), the extra source-audit snapshot and returned source-custody counters. Session-journal replay, publication and history-only revalidation are bounded additional work that is not fully metered or claimed free. Source envelope charges are allowances, not exact consumed bytes. An admitted read can finish after the deadline.".to_owned(),
    ]
}

struct FailureClass {
    error: Option<&'static str>,
    outcome: ResponseOutcome,
    resnapshot: bool,
    retry: ResponseSafeRetry,
    recovery: &'static str,
}

fn classify(error: &FollowSessionError) -> FailureClass {
    let mut class = FailureClass {
        error: Some(session_cmd::ERR_PRECONDITION_STALE),
        outcome: ResponseOutcome::Refused,
        resnapshot: false,
        retry: ResponseSafeRetry::YesAfterRefresh,
        recovery: "rebase_required",
    };
    match error {
        FollowSessionError::Replay(
            ReplayError::AmbiguousOrder | ReplayError::UnsupportedSessionFacets,
        )
        | FollowSessionError::ChangedDelivery => {
            class.error = Some(ERR_RESNAPSHOT);
            class.outcome = ResponseOutcome::Partial;
            class.resnapshot = true;
        }
        FollowSessionError::StaleAuthority
        | FollowSessionError::Store(DurableFollowError::StaleScope)
        | FollowSessionError::Session(DeploymentSessionError::SessionStale(_)) => {
            class.error = Some(session_cmd::ERR_AGENT_SESSION_STALE);
            class.resnapshot = true;
        }
        FollowSessionError::Denied(reason)
        | FollowSessionError::Replay(ReplayError::Denied(reason)) => {
            class.retry = ResponseSafeRetry::YesSameRequest;
            class.recovery = "safe_read_retry";
            match reason {
                ReplayDenial::Cancelled => {
                    class.error = None;
                    class.outcome = ResponseOutcome::Cancelled;
                }
                ReplayDenial::Unauthorized => {
                    class.error = Some(session_cmd::ERR_AUTH_DENIED);
                    class.retry = ResponseSafeRetry::No;
                    class.recovery = "operator_action_required";
                }
                ReplayDenial::Deadline => {
                    class.error = Some(session_cmd::ERR_OP_TIMEOUT);
                    class.outcome = ResponseOutcome::Partial;
                }
                ReplayDenial::Budget => {
                    class.error = Some(session_cmd::ERR_BUDGET_EXHAUSTED);
                    class.outcome = ResponseOutcome::Partial;
                }
                ReplayDenial::Unavailable => {
                    class.error = Some(session_cmd::ERR_CLOCK_UNCERTAIN);
                }
            }
        }
        FollowSessionError::Store(DurableFollowError::CapacityExceeded) => {
            class.error = Some(session_cmd::ERR_BUDGET_EXHAUSTED);
            class.retry = ResponseSafeRetry::No;
            class.recovery = "operator_action_required";
        }
        FollowSessionError::Session(DeploymentSessionError::SessionUnknown) => {
            class.error = Some(session_cmd::ERR_AGENT_SESSION_NOT_FOUND);
            class.retry = ResponseSafeRetry::No;
            class.recovery = "operator_action_required";
        }
        FollowSessionError::Session(DeploymentSessionError::StoreLocked) => {
            class.error = Some(session_cmd::ERR_AGENT_SESSION_STORE_LOCKED);
            class.retry = ResponseSafeRetry::YesSameRequest;
            class.recovery = "backoff";
        }
        FollowSessionError::Session(DeploymentSessionError::StoreInvalid(_))
        | FollowSessionError::Store(DurableFollowError::Session(_)) => {
            class.error = Some(session_cmd::ERR_AGENT_SESSION_STORE_INVALID);
            class.retry = ResponseSafeRetry::No;
            class.recovery = "operator_action_required";
        }
        FollowSessionError::Replay(ReplayError::Follow(FollowError::Anchor(reason))) => {
            class.error = Some(match reason {
                super::AnchorRefusal::Foreign => super::ERR_AGENT_FOLLOW_ANCHOR_FOREIGN,
                super::AnchorRefusal::Ahead => super::ERR_AGENT_FOLLOW_ANCHOR_AHEAD,
                super::AnchorRefusal::Unknown => super::ERR_AGENT_FOLLOW_ANCHOR_UNKNOWN,
            });
        }
        FollowSessionError::Replay(ReplayError::Follow(FollowError::Orient(
            OrientError::ContextBudgetExceeded { .. } | OrientError::TooManyEvents { .. },
        ))) => {
            class.error = Some(super::ERR_AGENT_CONTEXT_INCOMPLETE);
        }
        FollowSessionError::Replay(ReplayError::Follow(FollowError::Read(_)))
        | FollowSessionError::Session(DeploymentSessionError::Read(_)) => {
            class.error = Some(session_cmd::ERR_EVIDENCE_MISSING);
            class.retry = ResponseSafeRetry::No;
            class.recovery = "operator_action_required";
        }
        _ => {}
    }
    class
}

fn failure_response(args: &FollowArgs, failure: &FollowSessionFailure) -> (String, ExitIdentity) {
    failure_response_with_wait(args, failure, None)
}

fn failure_response_with_wait(
    args: &FollowArgs,
    failure: &FollowSessionFailure,
    wait: Option<(&FollowWaitProgress, Option<&super::DeploymentFollow>)>,
) -> (String, ExitIdentity) {
    let class = classify(&failure.error);
    let Some(head) = &failure.head else {
        return (
            execution_diagnostic(
                "follow",
                &args.root,
                class.error.unwrap_or(crate::ERR_CLI_RUNTIME_FAILURE),
                ExitIdentity::AGENT_REFUSED,
            ),
            ExitIdentity::AGENT_REFUSED,
        );
    };
    let digest = super::request_digest(args, &head.anchor);
    let mut pointers = vec![head.token.as_str().to_owned()];
    for anchor in [&failure.since_anchor, &failure.horizon_anchor]
        .into_iter()
        .flatten()
    {
        if !pointers.iter().any(|p| p == anchor.as_str()) {
            pointers.push(anchor.as_str().to_owned());
        }
    }
    if let Some(ack) = failure.acknowledged {
        pointers.push(format!("follow-acknowledged:{}", ack.to_text()));
    }
    let mut completed = vec![format!(
        "Verified committed deployment head {}.",
        head.token.as_str()
    )];
    if let Some(ack) = failure.acknowledged {
        completed.push(format!(
            "Confirmed durable acknowledgement {}.",
            ack.to_text()
        ));
    }
    let mut parts = ResponseParts {
        operation: "session.follow", request_digest: digest, principal: args.principal.clone(),
        session_id: failure.since_anchor.as_ref().and_then(|_| args.subscription.as_ref().map(|s| s.session_id.as_str().to_owned())),
        mission_id: None, anchor: head.anchor.clone(), view: args.view,
        capability: super::CAPABILITY_SITUATION_READ, outcome: class.outcome, error_id: class.error,
        payload_schema: super::FOLLOW_PAYLOAD_SCHEMA, payload_json: "null".to_owned(),
        epistemic_state: KnowledgeState::Unknown, completeness: Completeness::Partial,
        warnings: Vec::new(), contradictions: Vec::new(),
        degradation: vec![
            failure.error.to_string(),
            "No page is returned and no unobserved interval is certified. For a resnapshot refusal, read the owned session with `fss session orient --json --root DEPLOYMENT --session SESSION`. This read neither acknowledges the old stream nor repairs missing historical session ordering. Register a new subscription only when native history admission permits it; never splice the gap into the old stream. Other failures may safely repeat the exact ACK only when safeRetry admits it.".to_owned(),
            "Completed failed-call I/O and any preceding page reconstruction are not fully metered; zero budget placeholders are not a claim of zero work.".to_owned(),
        ],
        budgets_json: crate::agent_json::budget_summary(&BudgetVector::ZERO, &BudgetVector::ZERO),
        proof_pointers: pointers, affordances: Vec::new(), affordance_objects: Vec::new(),
        decision_fingerprint: digest, compression_receipt_id: None, continuation: None,
        recovery_class: class.recovery, safe_retry: class.retry,
        boundary: fss_core::ExecutionBoundary {
            completed,
            not_started: vec!["Release of a follow payload for this failed call.".to_owned()],
            possibly_occurred: if failure.journal_may_have_changed {
                vec!["Agent-journal admission, registration, acknowledgement or pending-delivery records may already be durable. A failed response does not roll them back; exact retries consult committed state.".to_owned()]
            } else { Vec::new() },
            preserved_truth: vec!["No authority-ledger batch, effect-journal record or source spool object was written.".to_owned()],
            invalidated: Vec::new(),
        },
        created_at_ns: head.observed_at.0, workspace_revision: None,
        idempotency_key: args.subscription.as_ref().and_then(|s| s.acknowledge.map(session_cmd::idempotency_key)),
    };
    if let Some((progress, last)) = wait {
        parts.budgets_json = wait_budget(args, progress);
        parts
            .degradation
            .retain(|line| !line.starts_with("Completed failed-call I/O"));
        parts.degradation.extend(wait_accounting(args, progress));
        if let Some(last) = last {
            parts.proof_pointers.extend([
                last.basis.publication.publication_digest.to_text(),
                last.result.publication.publication_digest.to_text(),
                last.delta.selection_witness.to_text(),
            ]);
        }
    }
    rendered(
        build_response_with_resnapshot(parts, class.resnapshot),
        ExitIdentity::AGENT_REFUSED,
        "follow",
        &args.root,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(items: &[(&str, &str)]) -> Vec<(String, String, usize)> {
        items
            .iter()
            .enumerate()
            .map(|(index, (name, value))| (name.to_string(), value.to_string(), index))
            .collect()
    }

    #[test]
    fn durable_scope_requires_both_ids_and_owns_continuation()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse(&[], false, false)?, None);
        for items in [
            vec![("--session", "session:owner")],
            vec![("--subscription", "overnight")],
            vec![("--acknowledge", "sha256:invalid")],
        ] {
            assert!(parse(&options(&items), false, false).is_err());
        }
        let values = options(&[
            ("--session", "session:owner"),
            ("--subscription", "overnight"),
        ]);
        assert!(parse(&values, true, false).is_err());
        assert_eq!(parse(&values, false, true)?, parse(&values, false, false)?);
        let scope = parse(&values, false, false)?.ok_or("missing subscription")?;
        assert_eq!(scope.session_id.as_str(), "session:owner");
        assert_eq!(scope.subscription_id, "overnight");
        assert_eq!(scope.acknowledge, None);
        Ok(())
    }

    #[test]
    fn exact_receipt_and_portable_ids_are_checked_before_io()
    -> Result<(), Box<dyn std::error::Error>> {
        let receipt = ContentDigest::sha256(b"exact delivered page");
        let receipt_text = receipt.to_text();
        let values = options(&[
            ("--session", "session:owner"),
            ("--subscription", "overnight"),
            ("--acknowledge", &receipt_text),
        ]);
        assert_eq!(
            parse(&values, false, false)?
                .ok_or("missing subscription")?
                .acknowledge,
            Some(receipt)
        );
        for invalid in ["../cursor", "cursor/other", "", "cursor with spaces"] {
            let values = options(&[("--session", "session:owner"), ("--subscription", invalid)]);
            assert!(parse(&values, false, false).is_err());
        }
        Ok(())
    }

    #[test]
    fn wait_refusals_preserve_committed_ack_and_cumulative_cost_without_a_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        use fss_reference::deployment_session::follow::FollowSessionHead;

        let token = fss_reference::agent_follow::AnchorToken::parse(
            "anchor:0123456789abcdef:3:e2:abababababababababababababababababababababababababababababababab",
        ).ok_or("synthetic renderer anchor")?;
        let ack = ContentDigest::sha256(b"explicit already committed acknowledgement");
        let args = FollowArgs {
            root: "/unopened-durable-follow-render-fixture".into(),
            since: token.clone(),
            view: fss_core::AgentView::Brief,
            principal: PrincipalId::parse("principal:wait-render")?,
            max_entries: 64,
            continuation: None,
            wait_ms: Some(500),
            subscription: Some(FollowSubscriptionArgs {
                session_id: SessionId::parse("session:wait-render")?,
                subscription_id: "watch".to_owned(),
                acknowledge: Some(ack),
            }),
        };
        let mut progress = FollowWaitProgress::default();
        progress.admitted_reads = 4;
        progress.completed_comparisons = 2;
        progress.completed_parks = 1;
        progress.elapsed_ms = 500;
        progress.consumed.bytes = 42;
        progress.source_reserved_bytes = 71;
        for (denial, outcome, error) in [
            (
                ReplayDenial::Deadline,
                "partial",
                Some(session_cmd::ERR_OP_TIMEOUT),
            ),
            (ReplayDenial::Cancelled, "cancelled", None),
            (
                ReplayDenial::Budget,
                "partial",
                Some(session_cmd::ERR_BUDGET_EXHAUSTED),
            ),
        ] {
            let failure = FollowSessionFailure {
                error: FollowSessionError::Denied(denial),
                head: Some(FollowSessionHead {
                    anchor: fss_core::LedgerAnchor::genesis("site:wait-render"),
                    token: token.clone(),
                    observed_at: fss_core::TimestampNs::ZERO,
                }),
                since_anchor: Some(token.clone()),
                horizon_anchor: Some(token.clone()),
                acknowledged: Some(ack),
                journal_may_have_changed: true,
            };
            let (body, exit) = failure_response_with_wait(&args, &failure, Some((&progress, None)));
            assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
            let parsed = crate::json_input::parse(&body)?;
            let fields = parsed.object().ok_or("response object")?;
            assert_eq!(
                fields
                    .get("outcome")
                    .and_then(crate::json_input::Value::text),
                Some(outcome)
            );
            assert_eq!(
                fields
                    .get("errorId")
                    .and_then(crate::json_input::Value::text),
                error
            );
            assert_eq!(fields.get("payload"), Some(&crate::json_input::Value::Null));
            assert_eq!(
                fields.get("continuation"),
                Some(&crate::json_input::Value::Null)
            );
            assert!(body.contains(&format!("follow-acknowledged:{ack}")));
            assert!(body.contains(&format!("Confirmed durable acknowledgement {ack}")));
            assert!(body.contains("4 of 41 history reads"));
            assert!(body.contains("2 completed comparisons; 1 completed parks"));
            assert!(body.contains("71 of 67108864 charged envelope bytes"));
            assert!(!body.contains("zero budget placeholders"));
        }
        Ok(())
    }
}
