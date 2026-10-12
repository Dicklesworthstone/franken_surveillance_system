#![forbid(unsafe_code)]
//! Operator-local synchronous authority/clock adapter and truthful bounded-wait envelopes.

use std::time::{Duration, Instant};

use fss_reference::agent_follow::wait::{
    FollowWaitBinding, FollowWaitBoundary, FollowWaitControl, FollowWaitDenial, FollowWaitError,
    FollowWaitFailure, FollowWaitHead, FollowWaitProgress, FollowWaitResult, FollowWaitWake,
    MAX_FOLLOW_WAIT_READS, follow_deployment_wait,
};

use super::*;
use crate::orient_cmd::{build_response_with_resnapshot, execution_diagnostic};

const ERR_RESNAPSHOT: &str = "ERR-AGENT-RESNAPSHOT-001";
const ERR_TIMEOUT: &str = "ERR-OP-TIMEOUT-001";
const ERR_BUDGET: &str = "ERR-BUDGET-EXHAUSTED-001";
const ERR_AUTH: &str = "ERR-AUTH-DENIED-001";

/// The CLI invocation is the local operator's explicit read/wait scope, not authentication or
/// a durable AgentSession grant. Every boundary compares that full scope. Process termination
/// owns CLI cancellation; callers needing cooperative cancellation supply their own control.
struct LocalControl {
    admitted: FollowWaitBinding,
    started: Instant,
}

impl FollowWaitControl for LocalControl {
    fn checkpoint(
        &mut self,
        binding: &FollowWaitBinding,
        _: FollowWaitBoundary,
    ) -> Result<u64, FollowWaitDenial> {
        if binding != &self.admitted {
            return Err(FollowWaitDenial::Unauthorized);
        }
        u64::try_from(self.started.elapsed().as_millis())
            .map_err(|_| FollowWaitDenial::ClockUnavailable)
    }

    fn park(&mut self, binding: &FollowWaitBinding, delay_ms: u64) -> Result<(), FollowWaitDenial> {
        let now = self.checkpoint(binding, FollowWaitBoundary::Park)?;
        if delay_ms == 0 || delay_ms > fss_reference::agent_follow::wait::FOLLOW_WAIT_POLL_MS {
            return Err(FollowWaitDenial::Unauthorized);
        }
        // Time may advance between the engine's checkpoint and this boundary. Shorten only
        // toward the already fixed deadline; never restart or extend the requested wait.
        let remaining = binding.wait_ms().saturating_sub(now);
        if remaining > 0 {
            std::thread::sleep(Duration::from_millis(delay_ms.min(remaining)));
        }
        Ok(())
    }
}

fn binding(args: &FollowArgs) -> Result<FollowWaitBinding, ()> {
    if args.subscription.is_some() {
        return Err(());
    }
    FollowWaitBinding::new(
        &args.root,
        args.since.clone(),
        FollowRequest {
            view: args.view,
            principal: args.principal.clone(),
            max_entries: args.max_entries,
            continuation: args.continuation.clone(),
        },
        OrientLimits::default(),
        args.wait_ms.ok_or(())?,
        MAX_FOLLOW_WAIT_READS,
    )
    .map_err(|_| ())
}

pub(super) fn execute(args: &FollowArgs) -> (String, ExitIdentity) {
    let admitted = match binding(args) {
        Ok(binding) => binding,
        Err(_) => return internal_failure("follow", &args.root),
    };
    let mut control = LocalControl {
        admitted,
        started: Instant::now(),
    };
    execute_with_control(args, &mut control)
}

pub(super) fn execute_with_control(
    args: &FollowArgs,
    control: &mut dyn FollowWaitControl,
) -> (String, ExitIdentity) {
    let binding = match binding(args) {
        Ok(binding) => binding,
        Err(_) => return internal_failure("follow", &args.root),
    };
    match follow_deployment_wait(&binding, control) {
        Ok(result) => {
            let exit = if result.wake == FollowWaitWake::Ready {
                ExitIdentity::SUCCESS
            } else {
                ExitIdentity::AGENT_REFUSED
            };
            rendered(result_response(args, &result), exit, "follow", &args.root)
        }
        Err(failure) => {
            if failure.last_follow.is_none() {
                return match &failure.error {
                    FollowWaitError::Follow(FollowError::Read(error)) => {
                        read_refusal("follow", &args.root, error)
                    }
                    error => {
                        let error_id = match error {
                            FollowWaitError::Follow(FollowError::Anchor(reason)) => {
                                anchor_refusal(*reason, &args.since).error_id
                            }
                            FollowWaitError::DeadlineBeforeObservation
                            | FollowWaitError::SourceDeadlineReached => ERR_TIMEOUT,
                            FollowWaitError::Denied(FollowWaitDenial::Unauthorized) => ERR_AUTH,
                            FollowWaitError::Follow(FollowError::Orient(
                                OrientError::ContextBudgetExceeded { .. }
                                | OrientError::TooManyEvents { .. },
                            )) => ERR_AGENT_CONTEXT_INCOMPLETE,
                            FollowWaitError::AccountingOverflow
                            | FollowWaitError::SourceBudgetExhausted => ERR_BUDGET,
                            _ => crate::ERR_CLI_RUNTIME_FAILURE,
                        };
                        (
                            execution_diagnostic(
                                "follow",
                                &args.root,
                                error_id,
                                ExitIdentity::AGENT_REFUSED,
                            ),
                            ExitIdentity::AGENT_REFUSED,
                        )
                    }
                };
            }
            rendered(
                failure_response(args, &failure),
                ExitIdentity::AGENT_REFUSED,
                "follow",
                &args.root,
            )
        }
    }
}

fn budget(args: &FollowArgs, progress: &FollowWaitProgress) -> String {
    let mut requested = progress.requested;
    let mut consumed = progress.consumed;
    requested.latency_ms = args.wait_ms.unwrap_or(0);
    consumed.latency_ms = progress.elapsed_ms;
    agent_json::budget_summary(&requested, &consumed)
}

fn accounting(args: &FollowArgs, progress: &FollowWaitProgress) -> Vec<String> {
    vec![
        format!("Bounded wait: {} ms admission deadline; {} ms last observed monotonic elapsed; {} of {} native deployment reads admitted; {} complete comparisons; {} completed caller-owned parks.",
            args.wait_ms.unwrap_or(0), progress.elapsed_ms, progress.admitted_reads,
            MAX_FOLLOW_WAIT_READS, progress.completed_comparisons, progress.completed_parks),
        "Budgets accumulate every completed native comparison's two snapshot/projection counters. Doctor inspection, history-only wake verification and failed reads' unreturned work are not measured here and are not claimed to cost zero. A read admitted before the deadline can finish later.".to_owned(),
        format!("Fresh source custody: {} of {} whole-call read admissions; {} verified reads; {} verified spool payload bytes; {} verified publication metadata bytes; {} gross requested envelope bytes; {} of {} net charged envelope bytes. Each read reserves its bounded envelope before I/O; unused allowance is released only after verified success, and a failed read retains its full reservation. Selected objects are deduplicated only within one comparison and reverified after every park.",
            progress.source_read_attempts, fss_reference::agent_follow::wait::MAX_FOLLOW_WAIT_SOURCE_READS,
            progress.verified_source_reads, progress.source_payload_bytes, progress.source_metadata_bytes,
            progress.source_requested_bytes, progress.source_reserved_bytes,
            fss_reference::agent_follow::wait::MAX_FOLLOW_WAIT_SOURCE_ENVELOPE_BYTES),
        "Consumed bytes include successfully verified custody payload/metadata bytes; storage operations include custody read admissions. Charged source envelopes separately bound header/probe overhead and failed-read uncertainty; they are not claimed as exact consumed bytes or an atomic filesystem snapshot.".to_owned(),
        "Wall waiting neither extends a retained coverage interval nor advances evidence time, renews a cursor/session lease, or proves that intermediate protected transitions were absent. This call owns no subscription or detached work.".to_owned(),
    ]
}

fn result_response(
    args: &FollowArgs,
    result: &FollowWaitResult,
) -> Result<String, Box<dyn std::error::Error>> {
    let digest = request_digest(args, &result.observed_head.anchor);
    if result.wake == FollowWaitWake::Ready {
        let mut parts = follow_response_parts(&result.last_follow, digest)?;
        parts.budgets_json = budget(args, &result.progress);
        for note in &mut parts.degradation {
            if note.starts_with("Latency and CPU time are not metered by this reference path;") {
                *note = "Native snapshot/projection stage latency and CPU are not metered. This wait adapter additionally reports measured monotonic elapsed wall time in consumed.latencyMs.".to_owned();
            }
        }
        parts.degradation.extend(accounting(args, &result.progress));
        return build_response(parts);
    }
    let (error_id, reason, recovery, retry, resnapshot) = match result.wake {
        FollowWaitWake::ResnapshotRequired => (
            ERR_RESNAPSHOT,
            "The exact authority/effect anchor advanced. Intervening protected transitions have not been enumerated; no endpoint delta or no-change interval is returned. Obtain a fresh orientation and follow from its exact anchor.",
            "rebase_required",
            ResponseSafeRetry::YesAfterRefresh,
            true,
        ),
        FollowWaitWake::DeadlineReached => (
            ERR_TIMEOUT,
            "The monotonic deadline ended new read admissions. Only the last completed retained-evidence comparison is known; no current or wall-interval silence claim is returned.",
            "safe_read_retry",
            ResponseSafeRetry::YesSameRequest,
            false,
        ),
        FollowWaitWake::ReadLimitReached => (
            ERR_BUDGET,
            "The fixed read-admission budget is exhausted. No further read or park was started, and no unobserved interval is certified.",
            "safe_read_retry",
            ResponseSafeRetry::YesSameRequest,
            false,
        ),
        FollowWaitWake::Ready => {
            return Err(RenderError("ready wait reached stopped renderer").into());
        }
    };
    stopped_response(
        args,
        &result.observed_head,
        Some(&result.last_follow),
        &result.progress,
        ResponseOutcome::Partial,
        Some(error_id),
        reason.to_owned(),
        recovery,
        retry,
        resnapshot,
    )
}

fn failure_response(
    args: &FollowArgs,
    failure: &FollowWaitFailure,
) -> Result<String, Box<dyn std::error::Error>> {
    let head = failure
        .observed_head
        .as_ref()
        .ok_or(RenderError("wait failure has no verified head"))?;
    let (outcome, error_id, recovery, retry, resnapshot) = match &failure.error {
        FollowWaitError::Denied(FollowWaitDenial::Cancelled) => (
            ResponseOutcome::Cancelled,
            None,
            "safe_read_retry",
            ResponseSafeRetry::YesSameRequest,
            false,
        ),
        FollowWaitError::Denied(FollowWaitDenial::Unauthorized) => (
            ResponseOutcome::Refused,
            Some(ERR_AUTH),
            "operator_action_required",
            ResponseSafeRetry::No,
            false,
        ),
        FollowWaitError::DeadlineBeforeObservation | FollowWaitError::SourceDeadlineReached => (
            ResponseOutcome::Partial,
            Some(ERR_TIMEOUT),
            "safe_read_retry",
            ResponseSafeRetry::YesSameRequest,
            false,
        ),
        FollowWaitError::Follow(FollowError::Anchor(reason)) => {
            let refusal = anchor_refusal(*reason, &args.since);
            (
                ResponseOutcome::Refused,
                Some(refusal.error_id),
                "rebase_required",
                ResponseSafeRetry::YesAfterRefresh,
                true,
            )
        }
        FollowWaitError::Follow(FollowError::Orient(
            OrientError::ContextBudgetExceeded { .. } | OrientError::TooManyEvents { .. },
        )) => (
            ResponseOutcome::Refused,
            Some(ERR_AGENT_CONTEXT_INCOMPLETE),
            "never_unchanged",
            ResponseSafeRetry::No,
            false,
        ),
        FollowWaitError::AccountingOverflow | FollowWaitError::SourceBudgetExhausted => (
            ResponseOutcome::Refused,
            Some(ERR_BUDGET),
            "operator_action_required",
            ResponseSafeRetry::No,
            false,
        ),
        _ => (
            ResponseOutcome::Refused,
            Some(crate::ERR_CLI_RUNTIME_FAILURE),
            "refresh_and_retry",
            ResponseSafeRetry::YesAfterRefresh,
            true,
        ),
    };
    stopped_response(
        args,
        head,
        failure.last_follow.as_ref(),
        &failure.progress,
        outcome,
        error_id,
        format!(
            "{}; verification stopped. Earlier observations are retained as proof pointers only and are not served as current truth.",
            failure.error
        ),
        recovery,
        retry,
        resnapshot,
    )
}

#[allow(clippy::too_many_arguments)] // one explicit rendering decision, no hidden mutable state
fn stopped_response(
    args: &FollowArgs,
    head: &FollowWaitHead,
    last: Option<&DeploymentFollow>,
    progress: &FollowWaitProgress,
    outcome: ResponseOutcome,
    error_id: Option<&'static str>,
    reason: String,
    recovery_class: &'static str,
    safe_retry: ResponseSafeRetry,
    resnapshot_required: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let digest = request_digest(args, &head.anchor);
    let mut pointers = vec![
        args.since.as_str().to_owned(),
        head.token.as_str().to_owned(),
        head.anchor.state_root.to_text(),
    ];
    if let Some(last) = last {
        pointers.extend([
            last.basis.publication.publication_digest.to_text(),
            last.result.publication.publication_digest.to_text(),
            last.delta.selection_witness.to_text(),
        ]);
        if let Some(certificate) = &last.delta.silence_certificate {
            pointers.push(certificate.certificate_digest().to_text());
        }
    }
    pointers.sort();
    pointers.dedup();
    let mut degradation = vec![reason];
    degradation.extend(accounting(args, progress));
    let last = last.ok_or(RenderError(
        "no full observation exists for a wait envelope",
    ))?;
    let mut boundary = read_only_boundary(format!(
        "Bounded follow stopped after {} admitted native read(s); no interval delta was published.",
        progress.admitted_reads
    ));
    if resnapshot_required {
        boundary.invalidated.push("The original exact follow basis cannot be advanced as an uninterrupted stream; request a fresh situation capsule.".to_owned());
    }
    build_response_with_resnapshot(
        ResponseParts {
            operation: "session.follow",
            request_digest: digest,
            principal: args.principal.clone(),
            session_id: None,
            mission_id: None,
            anchor: head.anchor.clone(),
            view: args.view,
            capability: CAPABILITY_SITUATION_READ,
            outcome,
            error_id,
            payload_schema: FOLLOW_PAYLOAD_SCHEMA,
            payload_json: "null".to_owned(),
            epistemic_state: KnowledgeState::Unknown,
            completeness: Completeness::Partial,
            warnings: Vec::new(),
            contradictions: Vec::new(),
            degradation,
            budgets_json: budget(args, progress),
            proof_pointers: pointers,
            affordances: Vec::new(),
            affordance_objects: Vec::new(),
            decision_fingerprint: digest,
            compression_receipt_id: None,
            continuation: None,
            recovery_class,
            safe_retry,
            boundary,
            created_at_ns: last.result.capsule().created_at.0,
            workspace_revision: None,
            idempotency_key: None,
        },
        resnapshot_required,
    )
}

#[cfg(test)]
mod tests;
