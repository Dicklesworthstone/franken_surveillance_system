#![forbid(unsafe_code)]
//! Source-preserving video-only session around an already admitted supervisor.
//!
//! The caller constructs both idle archive workers, binds the video sink to an
//! exact configuration, and accounts for every returned control or completion.
//! This does not discover, authenticate, adopt, reconnect or claim audio coverage.

use std::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
    time::Duration,
};

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_container::flv_avc::SourceKey;
use fss_core::{ContentDigest, OperationId};
use fss_runtime::execution::TaskCx;

use super::{
    av_worker, conversation, metered::MeteredClock, pipeline, recording, retirement_source,
    source_coordinator::ArchiveAdmission, source_worker, supervisor, video_worker,
};

/// One complete control, custody, admission or archive outcome.
#[must_use]
pub enum Step {
    /// An unrelated supervisor event remains caller-owned.
    Supervisor(supervisor::Step),
    /// A separate original source was transferred, but not yet published.
    SourceOffered(recording::SourceDisposition),
    /// The unchanged source was refused; the session is halted.
    SourceRefused(source_worker::OfferRefusal),
    /// The video segment was transferred, but not yet published.
    VideoOffered,
    /// The unchanged segment was refused; the session is halted.
    VideoRefused(video_worker::OfferRefusal),
    /// A separate source publication started.
    SourceStarted,
    /// Source admission failed; the caller must explicitly authorize retry.
    SourceStartRefused(av_worker::StartError),
    /// A video publication started.
    VideoStarted,
    /// Video admission failed; the caller must explicitly authorize retry.
    VideoStartRefused(av_worker::StartError),
    /// Control and any drained source completion remain caller-owned.
    SourceArchive {
        /// A controller result, when the bounded control step was polled.
        control: Option<supervisor::Step>,
        /// Drained source outcome, when available.
        completion: Option<source_worker::Completion>,
    },
    /// Control and any drained video completion remain caller-owned.
    VideoArchive {
        /// A controller result, when the bounded control step was polled.
        control: Option<supervisor::Step>,
        /// Drained video outcome, when available.
        completion: Option<video_worker::Completion>,
    },
    /// A retained source needs an explicit retry; controller traffic was serviced.
    SourceRetryRequired(supervisor::Step),
    /// A retained segment needs an explicit retry; controller traffic was serviced.
    VideoRetryRequired(supervisor::Step),
    /// Source custody is fenced or cannot be inspected.
    SourceUnavailable,
    /// Video custody is fenced or cannot be inspected.
    VideoUnavailable,
    /// The supervisor, task or clock does not match.
    Context,
    /// The bounded wait is invalid; no work or effects were started.
    Configuration,
    /// Cancellation or an earlier untransferred refusal stopped admission.
    Halted,
}

/// All unchanged owners after an attach refusal or a drained stop.
#[must_use]
pub struct Parts<'scope, 'task, IO> {
    /// Admitted controller and source pipeline.
    pub supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    /// Dedicated video archive worker.
    pub video: video_worker::Worker,
    /// Dedicated separately returned source worker.
    pub source: source_worker::Worker,
    /// Caller-bound source connection and generation claim.
    pub key: SourceKey,
    /// Caller-bound camera claim, not independent device identity.
    pub camera_claim: ContentDigest,
    /// Whether a first or explicitly authorized video attempt is armed.
    pub video_armed: bool,
    /// Whether a first or explicitly authorized source attempt is armed.
    pub source_armed: bool,
    /// New work was stopped; pending owners still require reconciliation.
    pub halted: bool,
}

/// Quiescent recording owners after the controller and media pipeline retire.
/// Tail records still need to be driven to a terminal publication or retained.
#[must_use = "reconcile controller facts and drain or recover the tail and video owners"]
pub struct Retired {
    /// Outstanding controller facts, not proof that remote effects were undone.
    pub controller: super::Retirement,
    /// A clock-reply attempt that may still require reconciliation.
    pub time_sync: Option<conversation::TimeSyncTrace>,
    /// Non-running video worker and its archive custody, including any pending segment.
    pub video: video_worker::Worker,
    /// Driver holding the original unfinished media and source archive worker.
    pub tail: retirement_source::Driver,
    /// Whether admission had already been stopped by the session owner.
    pub halted: bool,
}

/// Ownership-preserving refusal to prepare a retired video session.
#[must_use = "retain or reconcile all returned owners and controller facts"]
pub enum RetirementRefusal<'scope, 'task, IO> {
    /// An attempt, admission flag, or source worker is not ready; no owner was retired.
    NotDrained(Parts<'scope, 'task, IO>),
    /// Media ranges could not be planned; every retired owner is returned.
    TailPlan {
        /// Outstanding controller protocol facts.
        controller: super::Retirement,
        /// A clock-reply attempt retained by the supervisor.
        time_sync: Option<conversation::TimeSyncTrace>,
        /// Non-running video archive worker and any pending segment.
        video: video_worker::Worker,
        /// Drained separate-source archive worker.
        source: source_worker::Worker,
        /// Caller-bound connection and generation claim.
        key: SourceKey,
        /// Caller-bound camera claim.
        camera_claim: ContentDigest,
        /// Whether the session had stopped admission.
        halted: bool,
        /// Reason and complete unchanged pipeline retirement.
        refusal: retirement_source::Refusal,
    },
    /// Tail planning succeeded but the worker could not be joined to it.
    TailDriver {
        /// Outstanding controller protocol facts.
        controller: super::Retirement,
        /// A clock-reply attempt retained by the supervisor.
        time_sync: Option<conversation::TimeSyncTrace>,
        /// Non-running video archive worker and any pending segment.
        video: video_worker::Worker,
        /// Whether the session had stopped admission.
        halted: bool,
        /// The unchanged source worker, plan, and source claims.
        parts: retirement_source::DriverParts,
    },
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> Parts<'scope, 'task, IO> {
    /// Retire a quiescent session and prepare its held source for archival.
    ///
    /// This does not start publication, reconcile controller effects, infer a
    /// capture time, or account for bytes not received from the socket. On
    /// A pending video segment remains in the returned video worker; it is not
    /// retried or published. On refusal all original owners remain available.
    pub fn prepare_retirement(self) -> Result<Retired, RetirementRefusal<'scope, 'task, IO>> {
        if self.video_armed
            || self.source_armed
            || !matches!(
                self.video.status(),
                video_worker::Status::Idle | video_worker::Status::Pending
            )
            || self.source.status() != source_worker::Status::Idle
        {
            return Err(RetirementRefusal::NotDrained(self));
        }
        let Parts {
            supervisor,
            video,
            source,
            key,
            camera_claim,
            halted,
            ..
        } = self;
        let supervisor::Retirement {
            controller,
            media,
            time_sync,
        } = supervisor.retire();
        let plan = match retirement_source::Plan::new(media) {
            Ok(plan) => plan,
            Err(refusal) => {
                return Err(RetirementRefusal::TailPlan {
                    controller,
                    time_sync,
                    video,
                    source,
                    key,
                    camera_claim,
                    halted,
                    refusal,
                });
            }
        };
        let tail = match retirement_source::Driver::begin(source, plan, key, camera_claim) {
            Ok(tail) => tail,
            Err(parts) => {
                return Err(RetirementRefusal::TailDriver {
                    controller,
                    time_sync,
                    video,
                    halted,
                    parts,
                });
            }
        };
        Ok(Retired {
            controller,
            time_sync,
            video,
            tail,
            halted,
        })
    }
}

/// Single session owner. At most one original record or segment is in flight.
#[must_use = "abort and join active workers before recovering all owners"]
pub struct Session<'scope, 'task, IO> {
    parts: Parts<'scope, 'task, IO>,
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> Session<'scope, 'task, IO> {
    /// Pause a pending video segment and retain the controller across an
    /// explicitly supplied rollover. Refusal returns the unchanged owners.
    pub fn begin_rollover(
        self,
        supplies: super::av_rollover_worker::Supplies,
    ) -> Result<Rollover<'scope, 'task, IO>, (Self, super::av_rollover_worker::Supplies)> {
        if self.parts.halted
            || self.parts.video_armed
            || self.parts.source_armed
            || self.parts.video.status() != video_worker::Status::Pending
            || self.parts.source.status() != source_worker::Status::Idle
        {
            return Err((self, supplies));
        }
        let Parts {
            supervisor,
            video,
            source,
            key,
            camera_claim,
            video_armed,
            source_armed,
            halted,
        } = self.parts;
        let retirement = match video.retire() {
            Ok(retirement) => retirement,
            Err(video) => {
                return Err((
                    Self {
                        parts: Parts {
                            supervisor,
                            video,
                            source,
                            key,
                            camera_claim,
                            video_armed,
                            source_armed,
                            halted,
                        },
                    },
                    supplies,
                ));
            }
        };
        Ok(Rollover {
            parts: RolloverParts {
                supervisor,
                source,
                key,
                camera_claim,
                supplies: Some(supplies),
                cancelled: false,
                state: RolloverState::Preflight(super::video_rollover_preflight::Worker::new(
                    retirement,
                )),
            },
        })
    }
    /// Attach idle workers to a supervisor whose audio tracker is disabled.
    /// The sink and recorder source keys must match; the caller must still
    /// bind the configuration to the same connection.
    pub fn attach(
        supervisor: supervisor::Supervisor<'scope, 'task, IO>,
        video: video_worker::Worker,
        source: source_worker::Worker,
        key: SourceKey,
        camera_claim: ContentDigest,
    ) -> Result<Self, Parts<'scope, 'task, IO>> {
        let parts = Parts {
            supervisor,
            video,
            source,
            key,
            camera_claim,
            video_armed: false,
            source_armed: false,
            halted: false,
        };
        if parts.supervisor.audio_tracking_active()
            || parts.supervisor.has_pending_audio()
            || parts.video.status() != video_worker::Status::Idle
            || parts.video.source_key() != Some(key)
            || parts.supervisor.source_key() != key
            || parts.source.status() != source_worker::Status::Idle
            || key.connection == 0
            || key.generation == 0
        {
            return Err(parts);
        }
        Ok(Self { parts })
    }

    /// Borrow the admitted controller without transferring either archive owner.
    pub fn control(&mut self) -> Option<super::recording_session::Control<'_, 'scope, 'task, IO>> {
        if self.parts.halted {
            None
        } else {
            Some(super::recording_session::Control::from_supervisor(
                &mut self.parts.supervisor,
            ))
        }
    }

    /// Explicitly authorize another attempt at the same retained video source.
    pub fn authorize_video_retry(&mut self) -> bool {
        if !self.parts.halted
            && !self.parts.video_armed
            && self.parts.video.status() == video_worker::Status::Pending
        {
            self.parts.video_armed = true;
            true
        } else {
            false
        }
    }

    /// Explicitly authorize another attempt at the same retained separate source.
    pub fn authorize_source_retry(&mut self) -> bool {
        if !self.parts.halted
            && !self.parts.source_armed
            && self.parts.source.status() == source_worker::Status::Pending
        {
            self.parts.source_armed = true;
            true
        } else {
            false
        }
    }

    /// Stop admission and request cancellation; active attempts must be joined.
    pub fn abort(&mut self) {
        self.parts.halted = true;
        self.parts.source_armed = false;
        self.parts.video_armed = false;
        self.parts.source.abort();
        self.parts.video.abort();
    }

    /// Join an active video attempt and return its exact completion.
    pub async fn join_video(&mut self) -> Option<video_worker::Completion> {
        self.parts.video.join().await
    }

    /// Join an active separate-source attempt and return its exact completion.
    pub async fn join_source(&mut self) -> Option<source_worker::Completion> {
        self.parts.source.join().await
    }

    /// Recover all owners after active attempts have drained.
    pub fn into_parts(self) -> Result<Parts<'scope, 'task, IO>, Self> {
        if self.parts.video.is_running() || self.parts.source.is_running() {
            Err(self)
        } else {
            Ok(self.parts)
        }
    }

    /// Drive one bounded decision. A retained source pauses media polling while
    /// control traffic continues; failures are never silently retried.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        operation: &OperationId,
        wait: Duration,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        video_archive: ArchiveAdmission<'_>,
        source_archive: ArchiveAdmission<'_>,
    ) -> Step {
        if self.parts.halted {
            return Step::Halted;
        }
        if wait.is_zero() || wait > Duration::from_secs(30) {
            return Step::Configuration;
        }
        if !owner.clock.matches(owner.task, owner.cx)
            || !owner.clock.matches(task, cx)
            || !clock.matches(task, cx)
            || !self.parts.supervisor.matches_clock(&owner.clock)
            || !self.parts.supervisor.matches_clock(&clock)
        {
            return Step::Context;
        }
        if owner.cx.checkpoint().is_err() {
            self.abort();
            return Step::Halted;
        }

        match self.parts.source.status() {
            source_worker::Status::Running => {
                if let Some(completion) = poll_source(&mut self.parts.source).await {
                    return Step::SourceArchive {
                        control: None,
                        completion: Some(completion),
                    };
                }
                let control = self
                    .parts
                    .supervisor
                    .step_control(owner, operation, wait)
                    .await;
                let completion = poll_source(&mut self.parts.source).await;
                return Step::SourceArchive {
                    control: Some(control),
                    completion,
                };
            }
            source_worker::Status::Pending if self.parts.source_armed => {
                self.parts.source_armed = false;
                return match self.parts.source.start(
                    task,
                    cx,
                    clock,
                    source_archive.resource,
                    source_archive.cost,
                ) {
                    Ok(()) => Step::SourceStarted,
                    Err(error) => Step::SourceStartRefused(error),
                };
            }
            source_worker::Status::Pending => {
                return Step::SourceRetryRequired(
                    self.parts
                        .supervisor
                        .step_control(owner, operation, wait)
                        .await,
                );
            }
            source_worker::Status::Fenced | source_worker::Status::Unavailable => {
                return Step::SourceUnavailable;
            }
            source_worker::Status::Idle => (),
        }
        match self.parts.video.status() {
            video_worker::Status::Running => {
                if let Some(completion) = poll_video(&mut self.parts.video).await {
                    return Step::VideoArchive {
                        control: None,
                        completion: Some(completion),
                    };
                }
                let control = self
                    .parts
                    .supervisor
                    .step_control(owner, operation, wait)
                    .await;
                let completion = poll_video(&mut self.parts.video).await;
                return Step::VideoArchive {
                    control: Some(control),
                    completion,
                };
            }
            video_worker::Status::Pending if self.parts.video_armed => {
                self.parts.video_armed = false;
                return match self.parts.video.start(
                    task,
                    cx,
                    clock,
                    video_archive.resource,
                    video_archive.cost,
                ) {
                    Ok(()) => Step::VideoStarted,
                    Err(error) => Step::VideoStartRefused(error),
                };
            }
            video_worker::Status::Pending => {
                return Step::VideoRetryRequired(
                    self.parts
                        .supervisor
                        .step_control(owner, operation, wait)
                        .await,
                );
            }
            video_worker::Status::Fenced | video_worker::Status::Unavailable => {
                return Step::VideoUnavailable;
            }
            video_worker::Status::Idle => (),
        }
        match self.parts.supervisor.step(owner, operation, wait).await {
            supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Source {
                record,
                disposition,
            })) => {
                match self.parts.source.offer(source_worker::Input::Original {
                    record,
                    key: self.parts.key,
                    disposition,
                    camera_claim: self.parts.camera_claim,
                }) {
                    Ok(()) => {
                        self.parts.source_armed = true;
                        Step::SourceOffered(disposition)
                    }
                    Err(refusal) => {
                        self.parts.halted = true;
                        Step::SourceRefused(refusal)
                    }
                }
            }
            supervisor::Step::Media(pipeline::Step::Recording(recording::Push::Segment(
                segment,
            ))) => match self.parts.video.offer(segment) {
                Ok(()) => {
                    self.parts.video_armed = true;
                    Step::VideoOffered
                }
                Err(refusal) => {
                    self.parts.halted = true;
                    Step::VideoRefused(refusal)
                }
            },
            event => Step::Supervisor(event),
        }
    }
}

pub(super) async fn poll_source(
    worker: &mut source_worker::Worker,
) -> Option<source_worker::Completion> {
    poll_fn(|cx| {
        let mut join = pin!(worker.join());
        Poll::Ready(match join.as_mut().poll(cx) {
            Poll::Ready(result) => result,
            Poll::Pending => None,
        })
    })
    .await
}

async fn poll_video(worker: &mut video_worker::Worker) -> Option<video_worker::Completion> {
    poll_fn(|cx| {
        let mut join = pin!(worker.join());
        Poll::Ready(match join.as_mut().poll(cx) {
            Poll::Ready(result) => result,
            Poll::Pending => None,
        })
    })
    .await
}

/// All owners while video publication is paused for an explicit rollover.
#[must_use = "retain or reconcile every returned owner"]
pub struct RolloverParts<'scope, 'task, IO> {
    /// Camera controller and media pipeline; media polling remains paused.
    pub supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    /// Separately archived source worker.
    pub source: source_worker::Worker,
    /// Caller-bound source connection and generation.
    pub key: SourceKey,
    /// Caller-bound camera claim, not independently verified identity.
    pub camera_claim: ContentDigest,
    /// Unused successor stores until preflight succeeds.
    pub supplies: Option<super::av_rollover_worker::Supplies>,
    /// Cancellation was requested; a successor must not resume.
    pub cancelled: bool,
    /// Exact transition owner or stopped outcome.
    pub state: RolloverState,
}

/// The exact worker or outcome held during video rollover.
#[must_use = "retain or reconcile the transition state"]
pub enum RolloverState {
    /// Pending predecessor check.
    Preflight(super::video_rollover_preflight::Worker),
    /// Pending successor switch and root verification.
    Transition(super::video_rollover_worker::Worker),
    /// Preflight finished but the worker could not be retired.
    PreflightUnretired {
        /// The unrecovered worker.
        worker: super::video_rollover_preflight::Worker,
        /// Its drained completion.
        completion: super::video_rollover_preflight::Completion,
    },
    /// Preflight refused or its runtime did not finish successfully.
    PreflightStopped {
        /// Original pending source owner.
        retirement: super::video_rollover_preflight::Retirement,
        /// Runtime and preflight results.
        completion: super::video_rollover_preflight::Completion,
    },
    /// The verified predecessor could not be transferred.
    PreflightTransferRefused(super::video_rollover_preflight::Retirement),
    /// Supplies were missing; both detached owners remain held.
    SuppliesMissing {
        /// Pending source and archive resources.
        resources: video_worker::RolloverResources,
        /// Exact predecessor journal and keeper.
        previous: super::archive::journal::rollover::Previous,
    },
    /// Transition finished but the worker could not be retired.
    TransitionUnretired {
        /// The unrecovered transition worker.
        worker: super::video_rollover_worker::Worker,
        /// Its drained completion.
        completion: super::video_rollover_worker::Completion,
    },
    /// The switch or replay needs reconciliation.
    TransitionStopped {
        /// Pending source resources and any unconsumed supplies.
        retirement: super::video_rollover_worker::Retirement,
        /// Actual switch and replay outcome.
        completion: super::video_rollover_worker::Completion,
    },
    /// The verified successor could not be attached.
    AttachRefused {
        /// Both original resources and the checked successor.
        refusal: super::video_rollover_worker::AttachRefusal,
        /// Confirmed replay receipt.
        receipt: fss_publication::RootLedgerReceipt,
    },
    /// The original pending video is attached to the checked successor.
    Ready {
        /// The original pending video worker, now on the successor.
        video: video_worker::Worker,
        /// Confirmed replay receipt.
        receipt: fss_publication::RootLedgerReceipt,
    },
    /// Internal transfer sentinel; never a successful completion.
    Unavailable,
}

/// Admission refusal keeps the rollover and all its owners intact.
#[derive(Debug)]
pub enum RolloverStartError {
    /// Preflight admission refused.
    Preflight(super::video_rollover_preflight::StartError),
    /// Transition admission refused.
    Transition(super::video_rollover_worker::StartError),
    /// The transition has already stopped or completed.
    Unavailable,
    /// Cancellation was requested; drain and recover the owners.
    Cancelled,
}

/// One bounded control or transition decision.
#[must_use]
pub enum RolloverStep {
    /// Controller traffic serviced while media remains paused.
    Control(supervisor::Step),
    /// Preflight succeeded; start the successor transition explicitly.
    PreflightReady,
    /// Successor verified and ready to resume the original session.
    Ready,
    /// An outcome requires reconciliation; all owners remain held.
    Stopped,
    /// Cancellation was requested and active work is still draining.
    Draining,
    /// The task, clock, or wait bound was invalid.
    Context,
}

/// Owns the controller and both archive lineages across a video transition.
#[must_use = "drain active work and recover the session or all stopped owners"]
pub struct Rollover<'scope, 'task, IO> {
    parts: RolloverParts<'scope, 'task, IO>,
}

/// Automatic stage admission around one already-owned rollover.
#[must_use = "drain or recover the owned rollover"]
pub struct AutomaticRollover<'scope, 'task, IO> {
    rollover: Rollover<'scope, 'task, IO>,
    armed: bool,
    refused: bool,
}

/// A bounded automatic admission, control, or transition result.
#[must_use]
pub enum AutomaticRolloverStep {
    /// A preflight or transition task was admitted.
    Started,
    /// Admission refused; explicit retry authorization is required.
    StartRefused(RolloverStartError),
    /// A controller result or drained transition outcome.
    Rollover(RolloverStep),
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> AutomaticRollover<'scope, 'task, IO> {
    /// Own a new, not-yet-started rollover and arm its preflight once.
    pub fn new(rollover: Rollover<'scope, 'task, IO>) -> Result<Self, Rollover<'scope, 'task, IO>> {
        if rollover.parts.cancelled
            || !matches!(&rollover.parts.state, RolloverState::Preflight(worker) if !worker.is_running())
        {
            return Err(rollover);
        }
        Ok(Self {
            rollover,
            armed: true,
            refused: false,
        })
    }

    /// Access the same controller while the rollover is running.
    pub fn control(&mut self) -> Option<super::recording_session::Control<'_, 'scope, 'task, IO>> {
        self.rollover.control()
    }

    /// Re-arm one admission after a reported refusal.
    pub fn authorize_retry(&mut self) -> bool {
        if self.refused && !self.rollover.parts.cancelled {
            self.refused = false;
            self.armed = true;
            true
        } else {
            false
        }
    }

    /// Request cancellation and prevent further automatic admission.
    pub fn abort(&mut self) {
        self.armed = false;
        self.refused = false;
        self.rollover.abort();
    }

    /// Drain a cancelled stage, preserving its outcome in the rollover.
    pub async fn join_cancelled(&mut self) -> bool {
        self.rollover.join_cancelled().await
    }

    /// Automatically start each stage once, while returning every control and
    /// refusal result to the caller. Failed admission is never retried silently.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        operation: &OperationId,
        wait: Duration,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        admission: ArchiveAdmission<'_>,
    ) -> AutomaticRolloverStep {
        if wait.is_zero()
            || wait > Duration::from_secs(30)
            || !owner.clock.matches(owner.task, owner.cx)
            || !owner.clock.matches(task, cx)
            || !clock.matches(task, cx)
            || !self.rollover.parts.supervisor.matches_clock(&owner.clock)
            || !self.rollover.parts.supervisor.matches_clock(&clock)
        {
            return AutomaticRolloverStep::Rollover(RolloverStep::Context);
        }
        if owner.cx.checkpoint().is_err() {
            self.abort();
        }
        if self.armed {
            self.armed = false;
            return match self
                .rollover
                .start(task, cx, clock, admission.resource, admission.cost)
            {
                Ok(()) => AutomaticRolloverStep::Started,
                Err(error) => {
                    self.refused = true;
                    AutomaticRolloverStep::StartRefused(error)
                }
            };
        }
        let result = self
            .rollover
            .step(owner, operation, wait, task, cx, clock)
            .await;
        if matches!(result, RolloverStep::PreflightReady) {
            self.armed = true;
        }
        AutomaticRolloverStep::Rollover(result)
    }

    /// Recover the exact transition owner for resumption or reconciliation.
    pub fn into_rollover(self) -> Rollover<'scope, 'task, IO> {
        self.rollover
    }
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> Rollover<'scope, 'task, IO> {
    /// Borrow the original controller while a transition is underway.
    pub fn control(&mut self) -> Option<super::recording_session::Control<'_, 'scope, 'task, IO>> {
        if !self.parts.cancelled
            && matches!(
                self.parts.state,
                RolloverState::Preflight(_) | RolloverState::Transition(_)
            )
        {
            Some(super::recording_session::Control::from_supervisor(
                &mut self.parts.supervisor,
            ))
        } else {
            None
        }
    }

    /// Admit the current stage to a region-owned blocking worker.
    pub fn start(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &str,
        cost: &fss_core::BudgetVector,
    ) -> Result<(), RolloverStartError> {
        if self.parts.cancelled {
            return Err(RolloverStartError::Cancelled);
        }
        match &mut self.parts.state {
            RolloverState::Preflight(worker) => worker
                .start(task, cx, clock, resource, cost)
                .map_err(RolloverStartError::Preflight),
            RolloverState::Transition(worker) => worker
                .start(task, cx, clock, resource, cost)
                .map_err(RolloverStartError::Transition),
            _ => Err(RolloverStartError::Unavailable),
        }
    }

    /// Request cancellation; the active stage must still be joined by `step`.
    pub fn abort(&mut self) {
        self.parts.cancelled = true;
        match &self.parts.state {
            RolloverState::Preflight(worker) => worker.abort(),
            RolloverState::Transition(worker) => worker.abort(),
            _ => (),
        }
    }

    /// Drain a cancelled transition without polling camera control. The exact
    /// outcome and all owners remain in this rollover for reconciliation.
    pub async fn join_cancelled(&mut self) -> bool {
        if !self.parts.cancelled {
            return false;
        }
        let preflight = match &mut self.parts.state {
            RolloverState::Preflight(worker) if worker.is_running() => worker.join().await,
            _ => None,
        };
        if let Some(completion) = preflight {
            let state = std::mem::replace(&mut self.parts.state, RolloverState::Unavailable);
            self.parts.state = match state {
                RolloverState::Preflight(worker) => match worker.retire() {
                    Ok(retirement) => RolloverState::PreflightStopped {
                        retirement,
                        completion,
                    },
                    Err(worker) => RolloverState::PreflightUnretired { worker, completion },
                },
                state => state,
            };
            return true;
        }
        let transition = match &mut self.parts.state {
            RolloverState::Transition(worker) if worker.is_running() => worker.join().await,
            _ => None,
        };
        if let Some(completion) = transition {
            let state = std::mem::replace(&mut self.parts.state, RolloverState::Unavailable);
            self.parts.state = match state {
                RolloverState::Transition(worker) => match worker.retire() {
                    Ok(retirement) => RolloverState::TransitionStopped {
                        retirement,
                        completion,
                    },
                    Err(worker) => RolloverState::TransitionUnretired { worker, completion },
                },
                state => state,
            };
            return true;
        }
        false
    }

    /// Service control or advance a completed transition without polling media.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        operation: &OperationId,
        wait: Duration,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
    ) -> RolloverStep {
        if wait.is_zero()
            || wait > Duration::from_secs(30)
            || !owner.clock.matches(owner.task, owner.cx)
            || !owner.clock.matches(task, cx)
            || !clock.matches(task, cx)
            || !self.parts.supervisor.matches_clock(&owner.clock)
            || !self.parts.supervisor.matches_clock(&clock)
        {
            return RolloverStep::Context;
        }
        if owner.cx.checkpoint().is_err() {
            self.abort();
        }
        let mut preflight = None;
        let mut transition = None;
        match &mut self.parts.state {
            RolloverState::Preflight(worker) if worker.is_running() => {
                preflight = poll_fn(|cx| {
                    let mut join = pin!(worker.join());
                    Poll::Ready(match join.as_mut().poll(cx) {
                        Poll::Ready(value) => value,
                        Poll::Pending => None,
                    })
                })
                .await;
            }
            RolloverState::Transition(worker) if worker.is_running() => {
                transition = poll_fn(|cx| {
                    let mut join = pin!(worker.join());
                    Poll::Ready(match join.as_mut().poll(cx) {
                        Poll::Ready(value) => value,
                        Poll::Pending => None,
                    })
                })
                .await;
            }
            RolloverState::Preflight(_) | RolloverState::Transition(_) => {}
            RolloverState::Ready { .. } => {
                return if self.parts.cancelled {
                    RolloverStep::Stopped
                } else {
                    RolloverStep::Ready
                };
            }
            _ => return RolloverStep::Stopped,
        }
        if let Some(completion) = preflight {
            let worker = match std::mem::replace(&mut self.parts.state, RolloverState::Unavailable)
            {
                RolloverState::Preflight(worker) => worker,
                state => {
                    self.parts.state = state;
                    return RolloverStep::Stopped;
                }
            };
            let retirement = match worker.retire() {
                Ok(retirement) => retirement,
                Err(worker) => {
                    self.parts.state = RolloverState::PreflightUnretired { worker, completion };
                    return RolloverStep::Stopped;
                }
            };
            let super::video_rollover_preflight::Completion { runtime, outcome } = completion;
            let proof = match (runtime, outcome) {
                (Ok(()), super::video_rollover_preflight::Outcome::Verified(proof))
                    if !self.parts.cancelled =>
                {
                    proof
                }
                (runtime, outcome) => {
                    self.parts.state = RolloverState::PreflightStopped {
                        retirement,
                        completion: super::video_rollover_preflight::Completion {
                            runtime,
                            outcome,
                        },
                    };
                    return RolloverStep::Stopped;
                }
            };
            let (resources, previous) = match retirement.into_rollover(proof) {
                Ok(owners) => owners,
                Err(retirement) => {
                    self.parts.state = RolloverState::PreflightTransferRefused(retirement);
                    return RolloverStep::Stopped;
                }
            };
            let Some(supplies) = self.parts.supplies.take() else {
                self.parts.state = RolloverState::SuppliesMissing {
                    resources,
                    previous,
                };
                return RolloverStep::Stopped;
            };
            self.parts.state = RolloverState::Transition(
                super::video_rollover_worker::Worker::new(resources, supplies.bind(previous)),
            );
            return RolloverStep::PreflightReady;
        }
        if let Some(completion) = transition {
            let worker = match std::mem::replace(&mut self.parts.state, RolloverState::Unavailable)
            {
                RolloverState::Transition(worker) => worker,
                state => {
                    self.parts.state = state;
                    return RolloverStep::Stopped;
                }
            };
            let retirement = match worker.retire() {
                Ok(retirement) => retirement,
                Err(worker) => {
                    self.parts.state = RolloverState::TransitionUnretired { worker, completion };
                    return RolloverStep::Stopped;
                }
            };
            let super::video_rollover_worker::Completion { runtime, outcome } = completion;
            let (attachment, receipt) = match (runtime, outcome) {
                (
                    Ok(()),
                    super::video_rollover_worker::Outcome::Prepared {
                        attachment,
                        receipt,
                    },
                ) if !self.parts.cancelled => (attachment, receipt),
                (runtime, outcome) => {
                    self.parts.state = RolloverState::TransitionStopped {
                        retirement,
                        completion: super::video_rollover_worker::Completion { runtime, outcome },
                    };
                    return RolloverStep::Stopped;
                }
            };
            self.parts.state = match retirement.attach(attachment) {
                Ok(video) => RolloverState::Ready { video, receipt },
                Err(refusal) => RolloverState::AttachRefused { refusal, receipt },
            };
            return if matches!(self.parts.state, RolloverState::Ready { .. }) {
                RolloverStep::Ready
            } else {
                RolloverStep::Stopped
            };
        }
        if self.parts.cancelled {
            let running = match &self.parts.state {
                RolloverState::Preflight(worker) => worker.is_running(),
                RolloverState::Transition(worker) => worker.is_running(),
                _ => false,
            };
            return if running {
                RolloverStep::Draining
            } else {
                RolloverStep::Stopped
            };
        }
        RolloverStep::Control(
            self.parts
                .supervisor
                .step_control(owner, operation, wait)
                .await,
        )
    }

    /// Recover the original session only after successful successor attachment.
    pub fn resume(
        self,
    ) -> Result<
        (
            Session<'scope, 'task, IO>,
            fss_publication::RootLedgerReceipt,
        ),
        Self,
    > {
        if self.parts.cancelled || !matches!(self.parts.state, RolloverState::Ready { .. }) {
            return Err(self);
        }
        let RolloverParts {
            supervisor,
            source,
            key,
            camera_claim,
            supplies,
            cancelled,
            state,
        } = self.parts;
        let (video, receipt) = match state {
            RolloverState::Ready { video, receipt } => (video, receipt),
            state => {
                return Err(Self {
                    parts: RolloverParts {
                        supervisor,
                        source,
                        key,
                        camera_claim,
                        supplies,
                        cancelled,
                        state,
                    },
                });
            }
        };
        if supplies.is_some()
            || video.status() != video_worker::Status::Pending
            || video.source_key() != Some(key)
        {
            return Err(Self {
                parts: RolloverParts {
                    supervisor,
                    source,
                    key,
                    camera_claim,
                    supplies,
                    cancelled,
                    state: RolloverState::Ready { video, receipt },
                },
            });
        }
        Ok((
            Session {
                parts: Parts {
                    supervisor,
                    video,
                    source,
                    key,
                    camera_claim,
                    video_armed: false,
                    source_armed: false,
                    halted: false,
                },
            },
            receipt,
        ))
    }

    /// Recover all owners after the active stage has drained.
    pub fn into_parts(self) -> Result<RolloverParts<'scope, 'task, IO>, Self> {
        let running = match &self.parts.state {
            RolloverState::Preflight(worker) => worker.is_running(),
            RolloverState::Transition(worker) => worker.is_running(),
            _ => false,
        };
        if running { Err(self) } else { Ok(self.parts) }
    }
}

/// The recording session or exact rollover owner held by a managed session.
#[must_use = "drain or reconcile the returned owner"]
pub enum ManagedOwner<'scope, 'task, IO> {
    /// Normal source-preserving session.
    Recording(Box<Session<'scope, 'task, IO>>),
    /// Automatic rollover retaining controller and archive custody.
    Rollover(Box<AutomaticRollover<'scope, 'task, IO>>),
    /// A verified transition could not return to the session.
    Halted(Box<Rollover<'scope, 'task, IO>>),
}

/// All owners and capacity state returned by a managed session.
#[must_use = "retain or reconcile all returned owners"]
pub struct ManagedParts<'scope, 'task, IO> {
    /// Recording or transition owner.
    pub owner: Option<ManagedOwner<'scope, 'task, IO>>,
    /// Fresh supplies, if not yet consumed.
    pub supplies: Option<super::av_rollover_worker::Supplies>,
    /// Candidate held at a reported capacity boundary.
    pub capacity: Option<super::archive::UnknownTimePin>,
    /// True if an invariant or transition requires reconciliation.
    pub halted: bool,
}

/// One recording, control, rollover, or recovery decision.
#[must_use]
pub enum ManagedStep {
    /// An ordinary session result; its owners remain caller-accountable.
    Session(Step),
    /// A pending candidate needs fresh successor supplies.
    SuppliesRequired(Step),
    /// The exact pending candidate was transferred to rollover ownership.
    RolloverBeginning,
    /// The automatic transition's control or admission result.
    Rollover(AutomaticRolloverStep),
    /// A verified successor resumed the original pending candidate.
    Resumed(fss_publication::RootLedgerReceipt),
    /// All owners remain held but require explicit reconciliation.
    Halted,
    /// Wait, clock, or task context did not match; no transition started.
    Context,
}

/// Session-level automatic rollover with caller-provisioned successor stores.
#[must_use = "abort and drain or recover the managed owners"]
pub struct ManagedSession<'scope, 'task, IO> {
    parts: ManagedParts<'scope, 'task, IO>,
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> ManagedSession<'scope, 'task, IO> {
    /// Check clock binding without polling the camera or storage.
    pub(super) fn clocks_match(
        &mut self,
        owner: &MeteredClock<'_, '_>,
        clock: &MeteredClock<'_, '_>,
    ) -> bool {
        match self.parts.owner.as_mut() {
            Some(ManagedOwner::Recording(session)) => {
                session.parts.supervisor.matches_clock(owner)
                    && session.parts.supervisor.matches_clock(clock)
            }
            Some(ManagedOwner::Rollover(rollover)) => {
                rollover.rollover.parts.supervisor.matches_clock(owner)
                    && rollover.rollover.parts.supervisor.matches_clock(clock)
            }
            _ => false,
        }
    }

    /// Drain a cancelled rollover while retaining its transition owner.
    pub async fn join_rollover(&mut self) -> bool {
        match self.parts.owner.as_mut() {
            Some(ManagedOwner::Rollover(rollover)) => rollover.join_cancelled().await,
            _ => false,
        }
    }
    /// Own an existing recording session and observe later capacity outcomes.
    pub fn new(session: Session<'scope, 'task, IO>) -> Self {
        Self {
            parts: ManagedParts {
                owner: Some(ManagedOwner::Recording(Box::new(session))),
                supplies: None,
                capacity: None,
                halted: false,
            },
        }
    }

    /// Resume management at an explicitly reported pending-candidate boundary.
    /// A mismatch returns the unchanged session.
    pub fn at_capacity(
        session: Session<'scope, 'task, IO>,
        candidate: super::archive::UnknownTimePin,
    ) -> Result<Self, Session<'scope, 'task, IO>> {
        if session.parts.halted
            || session.parts.video_armed
            || session.parts.source_armed
            || session.parts.video.status() != video_worker::Status::Pending
            || session.parts.video.pending_pin() != Some(candidate)
            || session.parts.source.status() != source_worker::Status::Idle
        {
            return Err(session);
        }
        Ok(Self {
            parts: ManagedParts {
                owner: Some(ManagedOwner::Recording(Box::new(session))),
                supplies: None,
                capacity: Some(candidate),
                halted: false,
            },
        })
    }

    /// Install exactly one fresh successor without overwriting retained supplies.
    pub fn provide(
        &mut self,
        supplies: super::av_rollover_worker::Supplies,
    ) -> Result<(), super::av_rollover_worker::Supplies> {
        if self.parts.halted || self.parts.supplies.is_some() || self.parts.owner.is_none() {
            return Err(supplies);
        }
        self.parts.supplies = Some(supplies);
        Ok(())
    }

    /// Borrow the admitted controller during recording or an active rollover.
    pub fn control(&mut self) -> Option<super::recording_session::Control<'_, 'scope, 'task, IO>> {
        if self.parts.halted {
            return None;
        }
        match self.parts.owner.as_mut()? {
            ManagedOwner::Recording(session) => session.control(),
            ManagedOwner::Rollover(rollover) => rollover.control(),
            ManagedOwner::Halted(_) => None,
        }
    }

    /// Authorize one retry after an automatic stage admission refusal.
    pub fn authorize_rollover_retry(&mut self) -> bool {
        if self.parts.halted {
            return false;
        }
        match self.parts.owner.as_mut() {
            Some(ManagedOwner::Rollover(rollover)) => rollover.authorize_retry(),
            _ => false,
        }
    }

    /// Authorize one retry of a retained source while ordinary recording owns
    /// the session. Rollover, shutdown, and other states refuse unchanged.
    pub fn authorize_source_retry(&mut self) -> bool {
        if self.parts.halted {
            return false;
        }
        match self.parts.owner.as_mut() {
            Some(ManagedOwner::Recording(session)) => session.authorize_source_retry(),
            _ => false,
        }
    }

    /// Authorize one retry of a retained video segment while ordinary
    /// recording owns the session. A reported capacity boundary must be
    /// rolled over first. No publication starts in this call.
    pub fn authorize_video_retry(&mut self) -> bool {
        if self.parts.halted || self.parts.capacity.is_some() {
            return false;
        }
        match self.parts.owner.as_mut() {
            Some(ManagedOwner::Recording(session)) => session.authorize_video_retry(),
            _ => false,
        }
    }

    /// Stop admission and request cooperative cancellation of active work.
    pub fn abort(&mut self) {
        self.parts.halted = true;
        match self.parts.owner.as_mut() {
            Some(ManagedOwner::Recording(session)) => session.abort(),
            Some(ManagedOwner::Rollover(rollover)) => rollover.abort(),
            _ => (),
        }
    }

    /// Advance one bounded operation. Capacity is acted on only on a later
    /// call, after the original completion has been returned to the caller.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        operation: &OperationId,
        wait: Duration,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        video_archive: ArchiveAdmission<'_>,
        source_archive: ArchiveAdmission<'_>,
    ) -> ManagedStep {
        if self.parts.halted {
            return ManagedStep::Halted;
        }
        let Some(current) = self.parts.owner.as_mut() else {
            self.parts.halted = true;
            return ManagedStep::Halted;
        };
        if wait.is_zero()
            || wait > Duration::from_secs(30)
            || !owner.clock.matches(owner.task, owner.cx)
            || !owner.clock.matches(task, cx)
            || !clock.matches(task, cx)
        {
            return ManagedStep::Context;
        }
        let matches = match current {
            ManagedOwner::Recording(session) => {
                session.parts.supervisor.matches_clock(&owner.clock)
                    && session.parts.supervisor.matches_clock(&clock)
            }
            ManagedOwner::Rollover(rollover) => {
                rollover
                    .rollover
                    .parts
                    .supervisor
                    .matches_clock(&owner.clock)
                    && rollover.rollover.parts.supervisor.matches_clock(&clock)
            }
            ManagedOwner::Halted(_) => false,
        };
        if !matches {
            return ManagedStep::Context;
        }
        if owner.cx.checkpoint().is_err() {
            self.abort();
            return ManagedStep::Halted;
        }

        if let Some(candidate) = self.parts.capacity {
            if self.parts.supplies.is_none() {
                let Some(ManagedOwner::Recording(session)) = self.parts.owner.as_mut() else {
                    self.parts.halted = true;
                    return ManagedStep::Halted;
                };
                let step = session
                    .step(
                        owner,
                        operation,
                        wait,
                        task,
                        cx,
                        clock,
                        video_archive,
                        source_archive,
                    )
                    .await;
                return ManagedStep::SuppliesRequired(step);
            }
            let session = match self.parts.owner.take() {
                Some(ManagedOwner::Recording(session)) => session,
                owner => {
                    self.parts.owner = owner;
                    self.parts.halted = true;
                    return ManagedStep::Halted;
                }
            };
            if session.parts.video.pending_pin() != Some(candidate) {
                self.parts.owner = Some(ManagedOwner::Recording(session));
                self.parts.halted = true;
                return ManagedStep::Halted;
            }
            let Some(supplies) = self.parts.supplies.take() else {
                self.parts.owner = Some(ManagedOwner::Recording(session));
                self.parts.halted = true;
                return ManagedStep::Halted;
            };
            let rollover = match session.begin_rollover(supplies) {
                Ok(rollover) => rollover,
                Err((session, supplies)) => {
                    self.parts.owner = Some(ManagedOwner::Recording(Box::new(session)));
                    self.parts.supplies = Some(supplies);
                    self.parts.halted = true;
                    return ManagedStep::Halted;
                }
            };
            match AutomaticRollover::new(rollover) {
                Ok(rollover) => self.parts.owner = Some(ManagedOwner::Rollover(Box::new(rollover))),
                Err(rollover) => {
                    self.parts.owner = Some(ManagedOwner::Halted(Box::new(rollover)));
                    self.parts.halted = true;
                    return ManagedStep::Halted;
                }
            }
            self.parts.capacity = None;
            return ManagedStep::RolloverBeginning;
        }
        match self.parts.owner.as_mut() {
            Some(ManagedOwner::Recording(session)) => {
                let step = session
                    .step(
                        owner,
                        operation,
                        wait,
                        task,
                        cx,
                        clock,
                        video_archive,
                        source_archive,
                    )
                    .await;
                if let Step::VideoArchive {
                    completion: Some(completion),
                    ..
                } = &step
                {
                    if completion.runtime.is_ok() {
                        if let video_worker::Outcome::Publication(
                            video_worker::Publication::Refused {
                                pending: Some(pin),
                                reason:
                                    video_worker::Refusal::BeforePublication(
                                        av_worker::FailureReason::JournalCapacity,
                                    ),
                            },
                        ) = &completion.outcome
                        {
                            self.parts.capacity = Some(*pin);
                        }
                    }
                }
                ManagedStep::Session(step)
            }
            Some(ManagedOwner::Rollover(rollover)) => {
                let step = rollover
                    .step(owner, operation, wait, task, cx, clock, video_archive)
                    .await;
                if matches!(step, AutomaticRolloverStep::Rollover(RolloverStep::Ready)) {
                    let rollover = match self.parts.owner.take() {
                        Some(ManagedOwner::Rollover(rollover)) => rollover,
                        owner => {
                            self.parts.owner = owner;
                            self.parts.halted = true;
                            return ManagedStep::Halted;
                        }
                    };
                    let rollover = rollover.into_rollover();
                    match rollover.resume() {
                        Ok((mut session, receipt)) => {
                            if !session.authorize_video_retry() {
                                self.parts.owner = Some(ManagedOwner::Recording(Box::new(session)));
                                self.parts.halted = true;
                                return ManagedStep::Halted;
                            }
                            self.parts.owner = Some(ManagedOwner::Recording(Box::new(session)));
                            ManagedStep::Resumed(receipt)
                        }
                        Err(rollover) => {
                            self.parts.owner = Some(ManagedOwner::Halted(Box::new(rollover)));
                            self.parts.halted = true;
                            ManagedStep::Halted
                        }
                    }
                } else {
                    if matches!(step, AutomaticRolloverStep::Rollover(RolloverStep::Stopped)) {
                        self.parts.halted = true;
                    }
                    ManagedStep::Rollover(step)
                }
            }
            _ => {
                self.parts.halted = true;
                ManagedStep::Halted
            }
        }
    }

    /// Return the exact owners and any unconsumed supplies for drain or recovery.
    pub fn into_parts(self) -> ManagedParts<'scope, 'task, IO> {
        self.parts
    }
}
