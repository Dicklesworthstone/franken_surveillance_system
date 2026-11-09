#![forbid(unsafe_code)]
//! Coordinate session steps with publication of separately returned sources.
//!
//! The caller owns the session guard, task authority and every returned event.
//! This owner starts one attempt per accepted source; a refused or uncertain
//! attempt is never retried without a separate caller decision.

use std::time::Duration;

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_container::flv_avc::SourceKey;
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_runtime::execution::TaskCx;

use super::{
    av_unknown_worker_guard::{Guard, SessionEvent, SourceAdvance},
    av_worker, conversation,
    metered::MeteredClock,
    source_handoff, source_worker,
};

/// One bounded session, source transfer, or archival decision.
#[must_use]
pub enum Step {
    /// A session decision which was not a separately returned source.
    Session(SessionEvent),
    /// Source transfer was attempted; any refusal retains the original event.
    SourceOffered(source_handoff::Result),
    /// The accepted source's first or explicitly authorized attempt started.
    SourceStarted,
    /// Attempt admission failed; the source remains held and retry is disarmed.
    SourceStartRefused(av_worker::StartError),
    /// Control and any source completion remain owned by the caller.
    SourceArchive(source_handoff::Drive),
    /// A source remains pending and requires an explicit retry decision.
    SourceRetryRequired,
    /// A source owner needs reconciliation before further media is read.
    SourceFenced,
    /// Source custody was unavailable for inspection.
    SourceUnavailable,
    /// The session owner, task, or clock did not match.
    Context,
    /// Cancellation drained the separate attempt; the A/V guard remains owned.
    Cancelled(Option<source_worker::Completion>),
}

/// Explicit retry authorization could not be applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryError {
    /// There is no idle pending source, or an attempt is already armed.
    NotPending,
}

/// Resource and metered cost for one archive owner.
#[derive(Clone, Copy)]
pub struct ArchiveAdmission<'a> {
    /// Exact resource scoped by the owning task's grants.
    pub resource: &'a str,
    /// Cost to debit if this particular owner starts an attempt.
    pub cost: &'a BudgetVector,
}

/// An owner for one separate-source worker and its caller-bound source claims.
#[must_use = "drain or recover the worker and account for each returned event"]
pub struct Coordinator {
    worker: source_worker::Worker,
    key: SourceKey,
    camera_claim: ContentDigest,
    start_armed: bool,
}

impl Coordinator {
    /// Attach a worker without starting or retrying existing work.
    pub fn new(worker: source_worker::Worker, key: SourceKey, camera_claim: ContentDigest) -> Self {
        Self {
            worker,
            key,
            camera_claim,
            start_armed: false,
        }
    }

    /// Transfer an event if it contains a separate source, returning all other
    /// events and all refusals intact. Only a newly accepted source arms its
    /// first attempt.
    pub fn offer(&mut self, event: SessionEvent) -> source_handoff::Result {
        let result = source_handoff::offer(&mut self.worker, event, self.key, self.camera_claim);
        if matches!(&result, source_handoff::Result::Accepted { .. }) {
            self.start_armed = true;
        }
        result
    }

    /// Permit one further attempt at an already retained source.
    pub fn authorize_retry(&mut self) -> Result<(), RetryError> {
        if self.start_armed || self.worker.status() != source_worker::Status::Pending {
            return Err(RetryError::NotPending);
        }
        self.start_armed = true;
        Ok(())
    }

    /// Return the exact worker and its retained work to the session owner.
    pub fn into_worker(self) -> source_worker::Worker {
        self.worker
    }

    /// Advance one session or source-archive operation within the owning task.
    pub async fn step<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        guard: &mut Guard<'scope, 'task, IO>,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        operation: &OperationId,
        wait: Duration,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        av_archive: ArchiveAdmission<'_>,
        source_archive: ArchiveAdmission<'_>,
    ) -> Step {
        match guard
            .advance_with_source(
                &mut self.worker,
                owner,
                operation,
                wait,
                task,
                cx,
                clock,
                av_archive.resource,
                av_archive.cost,
            )
            .await
        {
            SourceAdvance::Context => Step::Context,
            SourceAdvance::Session(advance) => match self.offer(SessionEvent::Advance(advance)) {
                source_handoff::Result::Unhandled(event) => Step::Session(event),
                result => Step::SourceOffered(result),
            },
            SourceAdvance::SourceArchive(drive) => Step::SourceArchive(drive),
            SourceAdvance::SourcePending if self.start_armed => {
                self.start_armed = false;
                match self.worker.start(
                    task,
                    cx,
                    clock,
                    source_archive.resource,
                    source_archive.cost,
                ) {
                    Ok(()) => Step::SourceStarted,
                    Err(error) => Step::SourceStartRefused(error),
                }
            }
            SourceAdvance::SourcePending => Step::SourceRetryRequired,
            SourceAdvance::SourceFenced => Step::SourceFenced,
            SourceAdvance::SourceUnavailable => Step::SourceUnavailable,
            SourceAdvance::Cancelled(completion) => {
                self.start_armed = false;
                Step::Cancelled(completion)
            }
        }
    }
}
