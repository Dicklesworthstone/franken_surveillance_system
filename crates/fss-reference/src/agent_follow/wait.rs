#![forbid(unsafe_code)]
//! A bounded, caller-owned wait for an exact follow basis.
//!
//! Only a validated, certified `no_meaningful_change` may park. Every subsequent admission
//! reopens the deployment and verifies its committed history. Any full anchor advance ends the
//! wait with a resnapshot requirement: endpoint comparison cannot prove that an intermediate
//! protected transition did not occur. Unchanged anchors are rehydrated and reclassified; a
//! cached silence certificate never substitutes for current source verification.
//!
//! This is synchronous read/wait work, not a subscription or a durable session lease. The owning
//! [`FollowWaitControl`] admits every read, clock and park boundary. There are no spawned tasks,
//! locks held over a park, effects, or lease renewals. Wall time bounds new work admissions; a
//! bounded filesystem read already admitted can finish after the deadline. The evidence clock
//! and the existing continuation lifetime remain unchanged.

use std::path::{Path, PathBuf};

use fss_core::{AgentView, BudgetVector, LedgerAnchor, MeaningfulDeltaClass, PrincipalId};

use super::{AnchorToken, DeploymentFollow, FollowError, FollowRequest, MAX_FOLLOW_ENTRIES};
use crate::agent_orient::{DeploymentHistory, OrientLimits};

pub(crate) mod custody;

/// Largest wall wait admitted by this reference implementation.
pub const MAX_FOLLOW_WAIT_MS: u64 = 10_000;
/// Minimum spacing between new follow read admissions after a quiet comparison.
pub const FOLLOW_WAIT_POLL_MS: u64 = 250;
/// Fixed upper bound on all attempted deployment reads, including the initial read and failures.
pub const MAX_FOLLOW_WAIT_READS: u32 = 41;
/// Whole-invocation ceiling for source custody reads, including exact publication metadata.
pub const MAX_FOLLOW_WAIT_SOURCE_READS: u32 = 4096;
/// Whole-invocation envelope-byte allowance, including a failed read's reserved maximum.
pub const MAX_FOLLOW_WAIT_SOURCE_ENVELOPE_BYTES: u64 = 64 * 1024 * 1024;

/// The complete immutable scope offered to the caller's authority at every boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowWaitBinding {
    root: PathBuf,
    since: AnchorToken,
    request: FollowRequest,
    read_limits: OrientLimits,
    wait_ms: u64,
    max_reads: u32,
    max_source_reads: u32,
    max_source_envelope_bytes: u64,
}

impl FollowWaitBinding {
    /// Validates an explicit read-only wait scope before any I/O or clock access.
    ///
    /// `max_reads` may reduce the fixed ceiling, never increase it. Native per-read limits may
    /// likewise be narrowed but not widened. Continuations must be drained without waiting.
    pub fn new(
        root: impl Into<PathBuf>,
        since: AnchorToken,
        request: FollowRequest,
        read_limits: OrientLimits,
        wait_ms: u64,
        max_reads: u32,
    ) -> Result<Self, FollowWaitError> {
        let root = root.into();
        let defaults = OrientLimits::default();
        if root.as_os_str().is_empty()
            || !(1..=MAX_FOLLOW_WAIT_MS).contains(&wait_ms)
            || !(1..=MAX_FOLLOW_WAIT_READS).contains(&max_reads)
            || !(1..=MAX_FOLLOW_ENTRIES).contains(&request.max_entries)
            || !matches!(request.view, AgentView::Pulse | AgentView::Brief)
            || [
                (read_limits.max_layout_bytes, defaults.max_layout_bytes),
                (read_limits.max_journal_bytes, defaults.max_journal_bytes),
                (read_limits.max_object_bytes, defaults.max_object_bytes),
                (read_limits.max_events, defaults.max_events),
                (
                    read_limits.max_revisions_per_event,
                    defaults.max_revisions_per_event,
                ),
            ]
            .into_iter()
            .any(|(value, maximum)| value == 0 || value > maximum)
        {
            return Err(FollowWaitError::InvalidBounds);
        }
        if request.continuation.is_some() {
            return Err(FollowWaitError::ContinuationNotAllowed);
        }
        Ok(Self {
            root,
            since,
            request,
            read_limits,
            wait_ms,
            max_reads,
            max_source_reads: MAX_FOLLOW_WAIT_SOURCE_READS,
            max_source_envelope_bytes: MAX_FOLLOW_WAIT_SOURCE_ENVELOPE_BYTES,
        })
    }

    /// Narrows the immutable whole-call source-custody allowance before admission. Every
    /// selected source must still verify; a smaller allowance never shrinks the evidence scope.
    pub fn with_source_limits(
        mut self,
        max_reads: u32,
        max_envelope_bytes: u64,
    ) -> Result<Self, FollowWaitError> {
        if !(1..=MAX_FOLLOW_WAIT_SOURCE_READS).contains(&max_reads)
            || !(1..=MAX_FOLLOW_WAIT_SOURCE_ENVELOPE_BYTES).contains(&max_envelope_bytes)
        {
            return Err(FollowWaitError::InvalidBounds);
        }
        self.max_source_reads = max_reads;
        self.max_source_envelope_bytes = max_envelope_bytes;
        Ok(self)
    }

    /// Exact operator-supplied root; the wait never selects another root.
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Exact original anchor; a wake never rebases it automatically.
    pub fn since(&self) -> &AnchorToken {
        &self.since
    }
    /// Principal audit label. This label itself grants no authority.
    pub fn principal(&self) -> &PrincipalId {
        &self.request.principal
    }
    /// Exact view/page request offered to the caller's authority.
    pub fn request(&self) -> &FollowRequest {
        &self.request
    }
    /// Native bounds of every admitted deployment read.
    pub const fn read_limits(&self) -> OrientLimits {
        self.read_limits
    }
    /// Deadline in the caller's monotonic elapsed-millisecond epoch, starting at this invocation.
    pub const fn wait_ms(&self) -> u64 {
        self.wait_ms
    }
    /// Maximum attempted native reads, including a read that later fails.
    pub const fn max_reads(&self) -> u32 {
        self.max_reads
    }
    /// Whole-call source-object/publication-metadata read admission limit.
    pub const fn max_source_reads(&self) -> u32 {
        self.max_source_reads
    }
    /// Nonrefillable whole-call source envelope allowance. Successful short reads release only
    /// their unused reservation; the actual envelope remains charged across all comparisons.
    pub const fn max_source_envelope_bytes(&self) -> u64 {
        self.max_source_envelope_bytes
    }
}

/// A boundary the owner must admit under the same fixed scope and live cancellation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FollowWaitBoundary {
    /// Before opening or verifying any deployment file.
    Read,
    /// Before the native as-of/head spool hydration and orientation comparison.
    Hydrate,
    /// Before a selected source object or its exact custody metadata is inspected/read.
    Source,
    /// Before a caller-owned synchronous park.
    Park,
    /// After an admitted read or park, before returning data or admitting further work.
    Observe,
}

/// A live authority/clock refusal. No permissive implementation is supplied by the library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FollowWaitDenial {
    /// The caller no longer permits this exact root/principal/read/wait scope.
    Unauthorized,
    /// Cancellation was requested; this call owns no outstanding asynchronous work to drain.
    Cancelled,
    /// The owner cannot supply a current monotonic time in this invocation's epoch.
    ClockUnavailable,
}

/// Explicit equivalent of a Cx at read, time and park boundaries.
///
/// Implement this with the owning runtime's authority and cancellation state. `checkpoint`
/// must validate the exact binding and return live monotonic elapsed milliseconds; it must not
/// substitute retained evidence timestamps. `park` must recheck live authority/cancellation,
/// sleep for at most the requested remaining interval, and own that work until it returns.
/// It must not launch detached work. The engine checks time again before another read and
/// refuses regressing clocks or an early return that did not advance the requested interval.
pub trait FollowWaitControl {
    /// Admit a boundary and read the current operation clock.
    fn checkpoint(
        &mut self,
        binding: &FollowWaitBinding,
        boundary: FollowWaitBoundary,
    ) -> Result<u64, FollowWaitDenial>;
    /// Perform one bounded synchronous park under the same authority.
    fn park(&mut self, binding: &FollowWaitBinding, delay_ms: u64) -> Result<(), FollowWaitDenial>;
}

/// Verified authority/effect head, including the complete content-bound token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowWaitHead {
    /// Full authority anchor, not only its commit sequence.
    pub anchor: LedgerAnchor,
    /// Includes ledger prefix, effect prefix/presence and every authority epoch.
    pub token: AnchorToken,
}

/// Cumulative accounting of this invocation; all additions are checked.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FollowWaitProgress {
    /// Attempted complete deployment reads, including the last read if it failed.
    pub admitted_reads: u32,
    /// Follow comparisons that returned native cost counters successfully.
    pub completed_comparisons: u32,
    /// Caller-owned parks that returned successfully.
    pub completed_parks: u32,
    /// Attempted source object or exact publication-record reads, including the failing attempt.
    pub source_read_attempts: u32,
    /// Source object/publication-record reads whose bytes and expected identities verified.
    pub verified_source_reads: u32,
    /// Verified spool payload bytes; envelope/header reservations are reported separately.
    pub source_payload_bytes: u64,
    /// Verified exact local publication-record bytes, separate from spool payload bytes.
    pub source_metadata_bytes: u64,
    /// Sum of every attempted source read's maximum reservation before successful unused
    /// allowance is released. Unlike net charged envelopes, this is not the 64 MiB ceiling.
    pub source_requested_bytes: u64,
    /// Charged source envelope bytes: successful verified envelopes and the full maximum
    /// reserved for a failed/incomplete read. This is an allowance charge, not measured CPU/RAM.
    pub source_reserved_bytes: u64,
    /// Latest observed monotonic elapsed milliseconds, not evidence time.
    pub elapsed_ms: u64,
    /// The two orientations' requested vectors plus admitted source-custody reservations.
    pub requested: BudgetVector,
    /// The two orientations' consumed vectors plus successful custody bytes and custody read
    /// attempts. A failed read's unknown byte count is held in `source_reserved_bytes`.
    ///
    /// These are native admitted snapshot/projection counters. Doctor inspection, history-only
    /// wake checks, and a failed read's unreturned costs are not measured and are not zero claims.
    pub consumed: BudgetVector,
}

/// Why a successfully observed bounded wait returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FollowWaitWake {
    /// Existing material/protected context was returned before any unsafe suppression.
    Ready,
    /// An authority/effect head advanced; refresh is mandatory and no interval delta is claimed.
    ResnapshotRequired,
    /// The monotonic admission deadline was reached with no new admitted observation.
    DeadlineReached,
    /// The explicit read-admission budget was exhausted.
    ReadLimitReached,
}

/// A completed bounded observation, with the last full comparison and latest verified head.
#[derive(Debug)]
pub struct FollowWaitResult {
    /// Typed terminal reason, not a fabricated semantic delta.
    pub wake: FollowWaitWake,
    /// Last full native comparison. On resnapshot this is the earlier comparison, not a claim
    /// about the newly observed head or everything that happened while the caller parked.
    pub last_follow: DeploymentFollow,
    /// Latest verified authority/effect head. May be newer than `last_follow` on resnapshot.
    pub observed_head: FollowWaitHead,
    /// Cumulative known costs and bounded work admissions.
    pub progress: FollowWaitProgress,
}

/// An explicit refusal, preserving completed observations and accounting without serving them
/// as current truth after failed verification or cancellation.
#[derive(Debug)]
pub struct FollowWaitFailure {
    /// Exact native or authority failure.
    pub error: FollowWaitError,
    /// Last successfully completed comparison, if any.
    pub last_follow: Option<DeploymentFollow>,
    /// Most recently verified journal head, if any; not a replacement for failed source reads.
    pub observed_head: Option<FollowWaitHead>,
    /// Includes attempted failing read admissions and all returned costs.
    pub progress: FollowWaitProgress,
}

/// Why a bounded follow wait could not safely continue.
#[derive(Debug)]
pub enum FollowWaitError {
    /// Bounds were absent, zero, outside the native limits, or requested an unsupported view.
    InvalidBounds,
    /// Waiting cannot be mixed with an immutable page continuation.
    ContinuationNotAllowed,
    /// Caller authority/cancellation/time boundary refused the operation.
    Denied(FollowWaitDenial),
    /// A live clock regressed or a completed park returned before its requested interval.
    InvalidClock,
    /// A deadline elapsed before any complete native comparison could be observed.
    DeadlineBeforeObservation,
    /// The fixed admission deadline expired during the additional source-custody audit.
    SourceDeadlineReached,
    /// The immutable whole-call source read or envelope-byte allowance was exhausted.
    SourceBudgetExhausted,
    /// Checked cumulative counters could not represent the next completed cost.
    AccountingOverflow,
    /// The native follow verifier/reader refused the root or exact basis.
    Follow(FollowError),
}

impl std::fmt::Display for FollowWaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBounds => f.write_str("follow wait bounds are invalid"),
            Self::ContinuationNotAllowed => f.write_str("drain exact continuations before waiting"),
            Self::Denied(reason) => write!(f, "follow wait boundary refused: {reason:?}"),
            Self::InvalidClock => f.write_str("follow wait clock did not advance monotonically"),
            Self::DeadlineBeforeObservation => {
                f.write_str("follow wait deadline reached before an observation")
            }
            Self::SourceDeadlineReached => {
                f.write_str("follow wait deadline reached during source-custody verification")
            }
            Self::SourceBudgetExhausted => {
                f.write_str("follow wait source-custody budget is exhausted")
            }
            Self::AccountingOverflow => f.write_str("follow wait cumulative accounting overflow"),
            Self::Follow(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for FollowWaitError {}

pub(crate) fn checkpoint(
    binding: &FollowWaitBinding,
    control: &mut dyn FollowWaitControl,
    boundary: FollowWaitBoundary,
    progress: &mut FollowWaitProgress,
) -> Result<(), FollowWaitError> {
    let now = control
        .checkpoint(binding, boundary)
        .map_err(FollowWaitError::Denied)?;
    if now < progress.elapsed_ms {
        return Err(FollowWaitError::InvalidClock);
    }
    progress.elapsed_ms = now;
    Ok(())
}

pub(crate) fn account(
    progress: &mut FollowWaitProgress,
    follow: &DeploymentFollow,
) -> Result<(), FollowWaitError> {
    let requested = follow
        .basis
        .requested
        .checked_add(&follow.result.requested)
        .and_then(|cost| progress.requested.checked_add(&cost))
        .map_err(|_| FollowWaitError::AccountingOverflow)?;
    let consumed = follow
        .basis
        .consumed
        .checked_add(&follow.result.consumed)
        .and_then(|cost| progress.consumed.checked_add(&cost))
        .map_err(|_| FollowWaitError::AccountingOverflow)?;
    let comparisons = progress
        .completed_comparisons
        .checked_add(1)
        .ok_or(FollowWaitError::AccountingOverflow)?;
    progress.requested = requested;
    progress.consumed = consumed;
    progress.completed_comparisons = comparisons;
    Ok(())
}

pub(crate) fn certified_quiet(follow: &DeploymentFollow) -> bool {
    follow.delta.classes.len() == 1
        && follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::NoMeaningfulChange)
        && follow.delta.silence_certificate.is_some()
        && follow.delta.validate().is_ok()
}

/// Waits synchronously under one immutable caller-admitted scope.
///
/// The initial existing material/protected delta is returned normally. Initial harmless anchor
/// advances and every advance after a park require resnapshot. Quiet timeouts return only the
/// last actual retained-evidence comparison; they never extend its coverage window, synthesize
/// a new publication, renew a cursor, or claim to have observed an unbroken live interval.
pub fn follow_deployment_wait(
    binding: &FollowWaitBinding,
    control: &mut dyn FollowWaitControl,
) -> Result<FollowWaitResult, FollowWaitFailure> {
    let mut progress = FollowWaitProgress::default();
    let mut last_follow: Option<DeploymentFollow> = None;
    let mut observed_head: Option<FollowWaitHead> = None;
    let attempt =
        (|| -> Result<FollowWaitWake, FollowWaitError> {
            loop {
                checkpoint(binding, control, FollowWaitBoundary::Read, &mut progress)?;
                if progress.elapsed_ms >= binding.wait_ms {
                    return if last_follow.is_some() {
                        Ok(FollowWaitWake::DeadlineReached)
                    } else {
                        Err(FollowWaitError::DeadlineBeforeObservation)
                    };
                }
                if progress.admitted_reads >= binding.max_reads {
                    return Ok(FollowWaitWake::ReadLimitReached);
                }
                progress.admitted_reads = progress
                    .admitted_reads
                    .checked_add(1)
                    .ok_or(FollowWaitError::AccountingOverflow)?;
                let history = DeploymentHistory::read(&binding.root, &binding.read_limits)
                    .map_err(|error| FollowWaitError::Follow(FollowError::Read(error)))?;
                let position = history.head();
                let (anchor, ledger_root, effect_root) = history.roots_at(position).ok_or(
                    FollowWaitError::Follow(FollowError::Anchor(super::AnchorRefusal::Unknown)),
                )?;
                let token = AnchorToken::parse(&super::render_token(
                    history.site_lineage(),
                    position,
                    &anchor,
                    ledger_root,
                    effect_root,
                ))
                .ok_or(FollowWaitError::Follow(FollowError::Anchor(
                    super::AnchorRefusal::Unknown,
                )))?;
                observed_head = Some(FollowWaitHead {
                    anchor,
                    token: token.clone(),
                });
                let basis_position = super::resolve_anchor(&history, &binding.since)
                    .map_err(|error| FollowWaitError::Follow(FollowError::Anchor(error)))?;
                if last_follow.is_some() && token != binding.since {
                    // Journal roots alone prove that exact continuity must be reconsidered. Do not
                    // hydrate or compare endpoints and accidentally hide an intermediate transition.
                    checkpoint(binding, control, FollowWaitBoundary::Observe, &mut progress)?;
                    return Ok(FollowWaitWake::ResnapshotRequired);
                }
                checkpoint(binding, control, FollowWaitBoundary::Hydrate, &mut progress)?;
                if progress.elapsed_ms >= binding.wait_ms {
                    return if last_follow.is_some() {
                        Ok(FollowWaitWake::DeadlineReached)
                    } else {
                        Err(FollowWaitError::DeadlineBeforeObservation)
                    };
                }
                let basis_snapshot = history
                    .snapshot_at(basis_position)
                    .map_err(custody::read_error)?;
                let result_snapshot = history.snapshot_at(position).map_err(custody::read_error)?;
                let follow = super::follow_snapshots(
                    &history,
                    &basis_snapshot,
                    &result_snapshot,
                    &binding.request,
                )
                .map_err(FollowWaitError::Follow)?;
                account(&mut progress, &follow)?;
                let quiet = certified_quiet(&follow);
                let witnesses = follow
                    .result
                    .coverage
                    .as_ref()
                    .map(|coverage| coverage.witness_digests().into_iter().collect())
                    .unwrap_or_default();
                last_follow = Some(follow);
                drop(basis_snapshot);
                checkpoint(binding, control, FollowWaitBoundary::Observe, &mut progress)?;
                if !quiet {
                    return Ok(FollowWaitWake::Ready);
                }
                if token != binding.since {
                    return Ok(FollowWaitWake::ResnapshotRequired);
                }
                if progress.elapsed_ms >= binding.wait_ms {
                    return Ok(FollowWaitWake::DeadlineReached);
                }
                if progress.admitted_reads >= binding.max_reads {
                    return Ok(FollowWaitWake::ReadLimitReached);
                }
                custody::verify(
                    &history,
                    &result_snapshot,
                    &witnesses,
                    binding,
                    control,
                    &mut progress,
                )?;
                // Drop native history and the bounded per-comparison source cache before any
                // park. Neither metadata custody nor a former source read survives as a lease.
                drop(result_snapshot);
                drop(history);
                checkpoint(binding, control, FollowWaitBoundary::Park, &mut progress)?;
                if progress.elapsed_ms >= binding.wait_ms {
                    return Ok(FollowWaitWake::DeadlineReached);
                }
                let delay = FOLLOW_WAIT_POLL_MS.min(binding.wait_ms - progress.elapsed_ms);
                let earliest = progress
                    .elapsed_ms
                    .checked_add(delay)
                    .ok_or(FollowWaitError::AccountingOverflow)?;
                control
                    .park(binding, delay)
                    .map_err(FollowWaitError::Denied)?;
                progress.completed_parks = progress
                    .completed_parks
                    .checked_add(1)
                    .ok_or(FollowWaitError::AccountingOverflow)?;
                checkpoint(binding, control, FollowWaitBoundary::Observe, &mut progress)?;
                if progress.elapsed_ms < earliest {
                    return Err(FollowWaitError::InvalidClock);
                }
            }
        })();
    match attempt {
        Ok(wake) => match (last_follow, observed_head) {
            (Some(last_follow), Some(observed_head)) => Ok(FollowWaitResult {
                wake,
                last_follow,
                observed_head,
                progress,
            }),
            (last_follow, observed_head) => Err(FollowWaitFailure {
                error: FollowWaitError::DeadlineBeforeObservation,
                last_follow,
                observed_head,
                progress,
            }),
        },
        Err(error) => Err(FollowWaitFailure {
            error,
            last_follow,
            observed_head,
            progress,
        }),
    }
}

#[cfg(test)]
mod tests;
