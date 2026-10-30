#![forbid(unsafe_code)]
//! Bounded, request-owned waiting on the existing durable follow cursor.
//!
//! Pending deliveries and every actual adjacent history transition return immediately. Only
//! a new certified-quiet comparison at the exact acknowledged head may park, without publishing
//! an undisclosed page or acknowledging it. Each poll reacquires live session authority and the
//! unchanged semantic baseline. The writer is dropped before sleep, and a real advance is read
//! through adjacent replay rather than endpoint coalescing.

use fss_core::BudgetVector;

use super::*;
use crate::agent_follow::wait::{
    self as bounded, FOLLOW_WAIT_POLL_MS, FollowWaitBinding, FollowWaitBoundary, FollowWaitControl,
    FollowWaitDenial, FollowWaitError, FollowWaitProgress,
};

#[cfg(test)]
mod tests;

/// Immutable session request and bounded read/time/custody scope for one invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowSessionWaitBinding {
    request: FollowSessionRequest,
    read_scope: FollowWaitBinding,
}

impl FollowSessionWaitBinding {
    /// Admit bounds before opening any file. Native ceilings may be narrowed, never widened.
    pub fn new(
        root: impl Into<std::path::PathBuf>,
        principal: PrincipalId,
        request: FollowSessionRequest,
        limits: OrientLimits,
        wait_ms: u64,
        max_history_reads: u32,
    ) -> Result<Self, FollowWaitError> {
        request
            .registration(ContentDigest::sha256(&[]))
            .validate()
            .map_err(|_| FollowWaitError::InvalidBounds)?;
        let read_scope = FollowWaitBinding::new(
            root,
            request.since.clone(),
            FollowRequest {
                view: request.view,
                principal,
                max_entries: request.max_entries,
                continuation: None,
            },
            limits,
            wait_ms,
            max_history_reads,
        )?;
        Ok(Self {
            request,
            read_scope,
        })
    }

    /// Reduce whole-invocation source allowances without reducing the selected evidence scope.
    pub fn with_source_limits(
        mut self,
        max_reads: u32,
        max_envelope_bytes: u64,
    ) -> Result<Self, FollowWaitError> {
        self.read_scope = self
            .read_scope
            .with_source_limits(max_reads, max_envelope_bytes)?;
        Ok(self)
    }

    /// Original subscription, explicit ACK, and immutable page settings.
    #[must_use]
    pub const fn request(&self) -> &FollowSessionRequest {
        &self.request
    }

    /// Exact read/clock/custody binding offered to the caller's wait control.
    #[must_use]
    pub const fn read_scope(&self) -> &FollowWaitBinding {
        &self.read_scope
    }
}

/// An ordinary durable page, with all returned work accumulated across this wait.
#[derive(Debug)]
pub struct FollowSessionWaitDelivery {
    /// Same pending receipt and native payload as an immediate call at this admitted position.
    pub delivery: FollowSessionDelivery,
    /// Includes ACK reconstruction, repeated quiet probes, and fresh source audits.
    pub progress: FollowWaitProgress,
}

/// No page is released on timeout, cancellation, changed authority or failed custody.
#[derive(Debug)]
pub struct FollowSessionWaitFailure {
    /// Existing refusal plus any registration or explicit ACK already committed.
    pub failure: FollowSessionFailure,
    /// Last actual comparison is historical diagnostic context only, never current truth.
    pub last_follow: Option<DeploymentFollow>,
    /// Nonrefillable whole-call admissions and known consumed work, including failed attempts.
    pub progress: FollowWaitProgress,
}

impl fmt::Display for FollowSessionWaitFailure {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.failure.fmt(output)
    }
}

impl std::error::Error for FollowSessionWaitFailure {}

fn wait_error(error: FollowWaitError) -> FollowSessionError {
    match error {
        FollowWaitError::Follow(error) => FollowSessionError::Replay(ReplayError::Follow(error)),
        FollowWaitError::Denied(FollowWaitDenial::Unauthorized) => {
            FollowSessionError::Denied(ReplayDenial::Unauthorized)
        }
        FollowWaitError::Denied(FollowWaitDenial::Cancelled) => {
            FollowSessionError::Denied(ReplayDenial::Cancelled)
        }
        FollowWaitError::Denied(FollowWaitDenial::ClockUnavailable)
        | FollowWaitError::InvalidClock => FollowSessionError::Denied(ReplayDenial::Unavailable),
        FollowWaitError::DeadlineBeforeObservation | FollowWaitError::SourceDeadlineReached => {
            FollowSessionError::Denied(ReplayDenial::Deadline)
        }
        FollowWaitError::AccountingOverflow | FollowWaitError::SourceBudgetExhausted => {
            FollowSessionError::Denied(ReplayDenial::Budget)
        }
        FollowWaitError::InvalidBounds | FollowWaitError::ContinuationNotAllowed => {
            FollowSessionError::InvalidRequest
        }
    }
}

struct Waiting<'a> {
    binding: &'a FollowWaitBinding,
    progress: FollowWaitProgress,
    last_follow: Option<DeploymentFollow>,
}

impl Waiting<'_> {
    fn checkpoint(
        &mut self,
        control: &mut impl FollowWaitControl,
        boundary: FollowWaitBoundary,
    ) -> Result<(), FollowSessionError> {
        bounded::checkpoint(self.binding, control, boundary, &mut self.progress).map_err(wait_error)
    }

    fn admit_more(&self) -> Result<(), FollowSessionError> {
        if self.progress.elapsed_ms >= self.binding.wait_ms() {
            return Err(FollowSessionError::Denied(ReplayDenial::Deadline));
        }
        if self.progress.admitted_reads >= self.binding.max_reads() {
            return Err(FollowSessionError::Denied(ReplayDenial::Budget));
        }
        Ok(())
    }
}

impl<C: FollowSessionControl + FollowWaitControl> DeliveryPolicy<C> for Waiting<'_> {
    fn before_history(&mut self, control: &mut C) -> Result<(), FollowSessionError> {
        self.checkpoint(control, FollowWaitBoundary::Read)?;
        self.admit_more()?;
        // Count both initial reads and under-lock revalidations. Therefore lock acquisitions,
        // registrations and semantic-journal scans are bounded by this same finite ceiling.
        self.progress.admitted_reads = self
            .progress
            .admitted_reads
            .checked_add(1)
            .ok_or(FollowSessionError::Denied(ReplayDenial::Budget))?;
        Ok(())
    }

    fn compared(&mut self, step: &ReplayStep) -> Result<(), FollowSessionError> {
        bounded::account(&mut self.progress, &step.follow).map_err(wait_error)?;
        self.last_follow = Some(step.follow.clone());
        Ok(())
    }

    fn defer(
        &mut self,
        history: &DeploymentHistory,
        step: &ReplayStep,
        control: &mut C,
    ) -> Result<bool, FollowSessionError> {
        if !bounded::certified_quiet(&step.follow) {
            return Ok(false);
        }
        self.checkpoint(control, FollowWaitBoundary::Hydrate)?;
        self.admit_more()?;
        let position = resolve_anchor(history, &step.result_anchor)
            .map_err(|error| ReplayError::Follow(FollowError::Anchor(error)))?;
        // Native replay owns its two snapshots. Reopen the exact result for the existing
        // custody auditor; account its returned read counters in addition to the comparison.
        let snapshot = history
            .snapshot_at(position)
            .map_err(|error| ReplayError::Follow(FollowError::Read(error)))?;
        let read_cost = BudgetVector::builder()
            .bytes(snapshot.bytes_read)
            .storage_operations(snapshot.files_read)
            .build()
            .map_err(|_| FollowSessionError::Denied(ReplayDenial::Budget))?;
        self.progress.consumed = self
            .progress
            .consumed
            .checked_add(&read_cost)
            .map_err(|_| FollowSessionError::Denied(ReplayDenial::Budget))?;
        let witnesses = step
            .follow
            .result
            .coverage
            .as_ref()
            .map(|coverage| coverage.witness_digests().into_iter().collect())
            .unwrap_or_default();
        bounded::custody::verify(
            history,
            &snapshot,
            &witnesses,
            self.binding,
            control,
            &mut self.progress,
        )
        .map_err(wait_error)?;
        Ok(true)
    }

    fn before_release(&mut self, control: &mut C) -> Result<(), FollowSessionError> {
        // An already admitted read may finish after its deadline. Cancellation still withholds
        // release; the synchronized pending receipt then survives for an explicit retry.
        self.checkpoint(control, FollowWaitBoundary::Observe)
    }
}

/// Wait after explicit ACK without holding a journal lock, inventing a lease, or skipping a page.
///
/// The control must admit both the existing session/replay boundaries and the exact wait binding.
/// No default permissive control is supplied. A pending page is never parked, and even a harmless
/// real history transition must be delivered and explicitly acknowledged. Only identical-anchor,
/// source-verified quiet probes can repeat. Timeout/cancellation retains an already committed ACK
/// but publishes no quiet page, manufactures no silence interval, and refunds no session budget.
///
/// The history-read bound counts revalidation reads too. At most one lock acquisition occurs per
/// initial read, and no caller-owned park retains that lock or any native history/source cache.
pub fn follow_session_wait<C: FollowSessionControl + FollowWaitControl>(
    binding: &FollowSessionWaitBinding,
    control: &mut C,
) -> Result<FollowSessionWaitDelivery, Box<FollowSessionWaitFailure>> {
    let mut durable = initial_progress();
    let mut policy = Waiting {
        binding: &binding.read_scope,
        progress: FollowWaitProgress::default(),
        last_follow: None,
    };
    let attempt = (|| {
        loop {
            let result = execute(
                binding.read_scope.root(),
                binding.read_scope.principal(),
                &binding.request,
                &binding.read_scope.read_limits(),
                control,
                &mut durable,
                &mut policy,
            )?;
            if let Some(delivery) = result {
                return Ok(delivery);
            }
            // execute returned and dropped its journal owner before this boundary.
            policy.checkpoint(control, FollowWaitBoundary::Park)?;
            policy.admit_more()?;
            let delay =
                FOLLOW_WAIT_POLL_MS.min(binding.read_scope.wait_ms() - policy.progress.elapsed_ms);
            let earliest = policy
                .progress
                .elapsed_ms
                .checked_add(delay)
                .ok_or(FollowSessionError::Denied(ReplayDenial::Budget))?;
            control
                .park(&binding.read_scope, delay)
                .map_err(|error| wait_error(FollowWaitError::Denied(error)))?;
            policy.progress.completed_parks = policy
                .progress
                .completed_parks
                .checked_add(1)
                .ok_or(FollowSessionError::Denied(ReplayDenial::Budget))?;
            policy.checkpoint(control, FollowWaitBoundary::Observe)?;
            if policy.progress.elapsed_ms < earliest {
                return Err(FollowSessionError::Denied(ReplayDenial::Unavailable));
            }
        }
    })();
    match attempt {
        Ok(delivery) => Ok(FollowSessionWaitDelivery {
            delivery,
            progress: policy.progress,
        }),
        Err(error) => {
            durable.error = error;
            Err(Box::new(FollowSessionWaitFailure {
                failure: durable,
                last_follow: policy.last_follow,
                progress: policy.progress,
            }))
        }
    }
}
