#![forbid(unsafe_code)]
//! Bounded archive scheduling after HTTP A/V bootstrap.
//!
//! Bootstrap-forwarded records must be offered in order and individually
//! accounted for before the caller seals the prefix. Capture time, camera
//! authentication, reconnection and a retention duration remain external.

use std::time::Duration;

use asupersync::{Cx, time::timeout_at};
use fss_container::flv_avc::SourceKey;
use fss_core::{BudgetVector, ContentDigest};
use fss_runtime::{effect::CommittedEffect, execution::TaskCx};

use super::{media, media_av_bootstrap};
use crate::unifi_direct::{
    av_recording, av_rollover_preflight, av_rollover_worker, av_worker,
    metered::MeteredClock,
    pipeline, recording, retirement_source,
    source_coordinator::{ArchiveAdmission, Coordinator},
    source_worker,
};

/// Transfer refusal preserves the connected stream, first segment and archives.
#[must_use]
pub struct AttachRefusal {
    /// Validated HTTP A/V bootstrap and its archive worker.
    pub handoff: media_av_bootstrap::ArchiveHandoff,
    /// Exclusive standalone-source archive owner.
    pub source: Coordinator,
}

/// HTTP media and source custody retained while A/V history is switched.
#[must_use = "retain the live stream, source worker and pending media"]
pub struct Paused {
    /// Original connected camera stream and unresolved startup effect.
    pub connected: media::Connected,
    /// Separate-source archive owner.
    pub source: source_worker::Worker,
    /// Bootstrap segment, if still owned outside the A/V worker.
    pub first_segment: Option<recording::Segment>,
    /// Existing sender-clock hypothesis.
    pub origin: av_recording::SenderClockOrigin,
    /// Source key held by this exact connection.
    pub key: SourceKey,
    /// Caller-supplied camera claim.
    pub camera_claim: ContentDigest,
    /// Original capacity observation.
    pub need: av_worker::RolloverNeed,
}

impl Paused {
    fn resume(
        self,
        av: av_worker::UnknownTimeWorker,
        state: ArchiveState,
        need: Option<av_worker::RolloverNeed>,
    ) -> Driver {
        Driver {
            parts: Parts {
                connected: self.connected,
                source: self.source,
                av,
                first_segment: self.first_segment,
                origin: self.origin,
                key: self.key,
                camera_claim: self.camera_claim,
                source_armed: false,
                av_state: state,
                rollover_need: need,
                prefix_sealed: true,
                halted: false,
            },
        }
    }
}

/// A capacity rollover refusal retains the unchanged driver and supplies.
#[must_use]
pub struct RolloverPrepareRefusal {
    /// Original HTTP recording owner.
    pub driver: Driver,
    /// Unused successor stores.
    pub supplies: av_rollover_worker::Supplies,
}

/// A paused HTTP stream and task-owned predecessor custody check.
#[must_use = "drain the preflight and retain all owners"]
pub struct RolloverPreflight {
    paused: Paused,
    worker: av_rollover_preflight::Worker,
    completion: Option<av_rollover_preflight::Completion>,
    supplies: av_rollover_worker::Supplies,
}

struct BoxedPreflightRetirement {
    paused: Paused,
    supplies: av_rollover_worker::Supplies,
    completion: av_rollover_preflight::Completion,
    retired: Box<av_rollover_preflight::Retirement>,
}

/// Exact reason a drained HTTP rollover preflight could not continue.
#[derive(Debug)]
pub enum RolloverPreflightReason {
    /// Existing archive custody failed verification.
    Refused(av_worker::RolloverPauseError),
    /// Work did not begin or was cancelled before a usable proof.
    NotCompleted,
    /// Runtime failure, panic, or inconsistent state needs reconciliation.
    Indeterminate,
    /// The verified observation no longer matched its original owner.
    ProofMismatch,
}

/// Result of the first rollover stage; all owners remain explicit.
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum RolloverPreflightResult {
    /// The predecessor was verified and the successor worker is ready.
    Ready(Rollover),
    /// The exact predecessor and unused supplies need inspection.
    Unresolved {
        /// Paused HTTP stream and source custody.
        paused: Paused,
        /// Original A/V worker retirement.
        original: av_worker::UnknownTimeRetirement,
        /// Original successor stores.
        supplies: av_rollover_worker::Supplies,
        /// Why automatic continuation stopped.
        reason: RolloverPreflightReason,
        /// Runtime outcome, independent of the storage result.
        runtime: Result<(), asupersync::runtime::JoinError>,
        /// Whether the worker itself became fenced.
        fenced: bool,
    },
}

impl RolloverPreflight {
    /// Whether the admitted preflight still requires joining.
    pub fn is_running(&self) -> bool {
        self.worker.is_running()
    }

    pub(super) fn bound_to_task(&self, task: &TaskCx<'_>) -> bool {
        self.paused.connected.pipeline.is_bound_to_task(task)
    }
    /// Pause only a settled capacity refusal, without storage I/O or camera writes.
    pub fn prepare(
        driver: Driver,
        supplies: av_rollover_worker::Supplies,
    ) -> Result<Self, Box<RolloverPrepareRefusal>> {
        let p = &driver.parts;
        let Some(need) = p.rollover_need else {
            return Err(Box::new(RolloverPrepareRefusal { driver, supplies }));
        };
        if p.halted
            || !p.prefix_sealed
            || p.source_armed
            || p.source.status() != source_worker::Status::Idle
            || p.av_state != ArchiveState::Retry
            || p.connected.pipeline.has_pending_audio()
            || p.first_segment.is_some()
        {
            return Err(Box::new(RolloverPrepareRefusal { driver, supplies }));
        }
        let Parts {
            connected,
            source,
            av,
            first_segment,
            origin,
            key,
            camera_claim,
            source_armed,
            av_state,
            rollover_need,
            prefix_sealed,
            halted,
        } = driver.parts;
        let _ = rollover_need;
        let paused = Paused {
            connected,
            source,
            first_segment,
            origin,
            key,
            camera_claim,
            need,
        };
        let original = match av.retire() {
            Ok(original) => original,
            Err(av) => {
                let driver = Driver {
                    parts: Parts {
                        connected: paused.connected,
                        source: paused.source,
                        av,
                        first_segment: paused.first_segment,
                        origin: paused.origin,
                        key: paused.key,
                        camera_claim: paused.camera_claim,
                        source_armed,
                        av_state,
                        rollover_need: Some(need),
                        prefix_sealed,
                        halted,
                    },
                };
                return Err(Box::new(RolloverPrepareRefusal { driver, supplies }));
            }
        };
        if original.fenced
            || original.parts.journal.confirmed() != Some(need.confirmed)
            || original.parts.journal.anchor() != need.journal
            || original.parts.keeper.anchor() != need.keeper
        {
            let av = av_worker::UnknownTimeWorker::from_retirement(original);
            return Err(Box::new(RolloverPrepareRefusal {
                driver: paused.resume(av, av_state, Some(need)),
                supplies,
            }));
        }
        Ok(Self {
            paused,
            worker: av_rollover_preflight::Worker::new(original),
            completion: None,
            supplies,
        })
    }

    /// Admit the predecessor check to the task-owned blocking pool.
    pub fn start<'scope, 'task>(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &str,
        cost: &BudgetVector,
    ) -> Result<(), av_rollover_worker::StartError> {
        if self.completion.is_some() {
            return Err(av_rollover_worker::StartError::Fenced);
        }
        if !self.paused.connected.pipeline.is_bound_to_task(task) {
            return Err(av_rollover_worker::StartError::Context);
        }
        self.worker
            .start(task, cx, clock, resource, cost)
            .map_err(|error| match error {
                av_rollover_preflight::StartError::Running => {
                    av_rollover_worker::StartError::Running
                }
                av_rollover_preflight::StartError::Fenced => av_rollover_worker::StartError::Fenced,
                av_rollover_preflight::StartError::Context => {
                    av_rollover_worker::StartError::Context
                }
                av_rollover_preflight::StartError::Clock => av_rollover_worker::StartError::Clock,
                av_rollover_preflight::StartError::Task(error) => {
                    av_rollover_worker::StartError::Task(error)
                }
                av_rollover_preflight::StartError::Runtime(error) => {
                    av_rollover_worker::StartError::Runtime(error)
                }
            })
    }
    /// Request cancellation; joining is still required.
    pub fn abort(&self) {
        self.worker.abort();
    }
    /// Join the exact preflight without losing its result.
    pub async fn join(&mut self) -> bool {
        if self.completion.is_some() {
            return true;
        }
        if let Some(completion) = self.worker.join().await {
            self.completion = Some(completion);
            true
        } else {
            false
        }
    }
    /// Recover the unchanged recording and stores if no check was admitted.
    #[allow(clippy::result_large_err)]
    pub fn into_unstarted(self) -> Result<(Driver, av_rollover_worker::Supplies), Self> {
        if self.completion.is_some() || self.worker.is_running() {
            return Err(self);
        }
        let Self {
            paused,
            worker,
            completion,
            supplies,
        } = self;
        match worker.retire() {
            Ok(retired) if !retired.fenced => {
                let need = paused.need;
                Ok((
                    paused.resume(
                        av_worker::UnknownTimeWorker::from_retirement(retired.original),
                        ArchiveState::Retry,
                        Some(need),
                    ),
                    supplies,
                ))
            }
            Ok(retired) => Err(Self {
                paused,
                worker: av_rollover_preflight::Worker::from_retirement(retired),
                completion,
                supplies,
            }),
            Err(worker) => Err(Self {
                paused,
                worker,
                completion,
                supplies,
            }),
        }
    }
    /// Convert a drained proof into a successor worker, or retain all failures.
    #[allow(clippy::result_large_err)]
    pub fn finish(self) -> Result<RolloverPreflightResult, Self> {
        Self::finish_boxed(Box::new(self))
            .map(|result| *result)
            .map_err(|owner| *owner)
    }

    /// Move a drained preflight through heap-owned stages without placing its
    /// full retirement and successor owners in the async caller's frame.
    #[inline(never)]
    pub fn finish_boxed(self: Box<Self>) -> Result<Box<RolloverPreflightResult>, Box<Self>> {
        let stage = Self::boxed_retire(self)?;
        Ok(Self::boxed_finish(stage))
    }

    #[inline(never)]
    fn boxed_retire(mut this: Box<Self>) -> Result<Box<BoxedPreflightRetirement>, Box<Self>> {
        let Some(completion) = this.completion.take() else {
            return Err(this);
        };
        let Self {
            paused,
            worker,
            supplies,
            ..
        } = *this;
        match worker.retire() {
            Ok(retired) => Ok(Box::new(BoxedPreflightRetirement {
                paused,
                supplies,
                completion,
                retired: Box::new(retired),
            })),
            Err(worker) => Err(Box::new(Self {
                paused,
                worker,
                completion: Some(completion),
                supplies,
            })),
        }
    }

    #[inline(never)]
    fn boxed_finish(stage: Box<BoxedPreflightRetirement>) -> Box<RolloverPreflightResult> {
        let BoxedPreflightRetirement {
            paused,
            supplies,
            completion,
            retired,
        } = *stage;
        let retired = *retired;
        let (original, reason, runtime) = match (completion.runtime, completion.outcome) {
            (Ok(()), av_rollover_preflight::Outcome::Verified(proof)) if !retired.fenced => {
                match retired.original.into_rollover_verified(proof) {
                    Ok((resources, previous)) => {
                        return Box::new(RolloverPreflightResult::Ready(Rollover {
                            paused,
                            worker: av_rollover_worker::Worker::new(
                                resources,
                                supplies.bind(previous),
                            ),
                            completion: None,
                        }));
                    }
                    Err(original) => (original, RolloverPreflightReason::ProofMismatch, Ok(())),
                }
            }
            (runtime, outcome) => {
                let reason = if runtime.is_err() {
                    RolloverPreflightReason::Indeterminate
                } else {
                    match outcome {
                        av_rollover_preflight::Outcome::Refused(error) => {
                            RolloverPreflightReason::Refused(error)
                        }
                        av_rollover_preflight::Outcome::Cancelled
                        | av_rollover_preflight::Outcome::NotStarted => {
                            RolloverPreflightReason::NotCompleted
                        }
                        _ => RolloverPreflightReason::Indeterminate,
                    }
                };
                (retired.original, reason, runtime)
            }
        };
        Box::new(RolloverPreflightResult::Unresolved {
            paused,
            original,
            supplies,
            reason,
            runtime,
            fenced: retired.fenced,
        })
    }
}

/// Task-owned successor switch while the HTTP source remains paused.
#[must_use = "drain the switch and reconcile every returned owner"]
pub struct Rollover {
    paused: Paused,
    worker: av_rollover_worker::Worker,
    completion: Option<av_rollover_worker::Completion>,
}

struct BoxedSwitchRetirement {
    paused: Paused,
    completion: av_rollover_worker::Completion,
    retired: Box<av_rollover_worker::Retirement>,
}

/// Exact outcome of the successor transition.
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum RolloverResult {
    /// The matching successor owns the pending media; the caller may resume.
    Resumed {
        /// Original HTTP stream with its pending A/V segment armed.
        driver: Driver,
        /// Confirmed predecessor replay receipt.
        receipt: fss_publication::RootLedgerReceipt,
    },
    /// The transition stopped; no owner or observed outcome is discarded.
    Unresolved {
        /// Paused stream and source worker.
        paused: Paused,
        /// Pending media and any unconsumed inputs.
        retirement: av_rollover_worker::Retirement,
        /// Exact runtime and transition result.
        completion: av_rollover_worker::Completion,
    },
    /// A prepared successor could not be reattached to its original media.
    AttachRefused {
        /// Paused stream and source worker.
        paused: Paused,
        /// Original resources and prepared successor.
        refusal: av_worker::PreparedUnknownTimeAttachRefusal,
        /// Actual predecessor replay receipt.
        receipt: fss_publication::RootLedgerReceipt,
    },
}

/// Recovery of a successor transition that never started.
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum RolloverUnstarted {
    /// The exact predecessor and unused successor stores were recovered.
    Restored {
        /// Original HTTP stream and pending segment.
        driver: Driver,
        /// Unused successor stores.
        supplies: av_rollover_worker::Supplies,
    },
    /// The predecessor did not match; all owners remain available.
    Refused {
        /// Paused HTTP stream and source worker.
        paused: Paused,
        /// Original media and predecessor that could not be restored.
        refusal: av_worker::UnknownTimeRolloverRestoreRefusal,
        /// Unused successor stores.
        supplies: av_rollover_worker::Supplies,
    },
}

impl Rollover {
    /// Whether the admitted rollover still requires joining.
    pub fn is_running(&self) -> bool {
        self.worker.is_running()
    }

    pub(super) fn bound_to_task(&self, task: &TaskCx<'_>) -> bool {
        self.paused.connected.pipeline.is_bound_to_task(task)
    }
    /// Start the switch under current task authority.
    pub fn start<'scope, 'task>(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &str,
        cost: &BudgetVector,
    ) -> Result<(), av_rollover_worker::StartError> {
        if self.completion.is_some() {
            return Err(av_rollover_worker::StartError::Fenced);
        }
        if !self.paused.connected.pipeline.is_bound_to_task(task) {
            return Err(av_rollover_worker::StartError::Context);
        }
        self.worker.start(task, cx, clock, resource, cost)
    }
    /// Request cancellation; joining is still required.
    pub fn abort(&self) {
        self.worker.abort();
    }
    /// Join the exact transition without discarding its outcome.
    pub async fn join(&mut self) -> bool {
        if self.completion.is_some() {
            return true;
        }
        if let Some(completion) = self.worker.join().await {
            self.completion = Some(completion);
            true
        } else {
            false
        }
    }
    /// Restore the predecessor if the successor worker was never admitted.
    #[allow(clippy::result_large_err)]
    pub fn into_unstarted(self) -> Result<RolloverUnstarted, Self> {
        if self.completion.is_some() {
            return Err(self);
        }
        let Self {
            paused,
            worker,
            completion,
        } = self;
        let (resources, inputs) = match worker.into_unstarted() {
            Ok(owners) => owners,
            Err(worker) => {
                return Err(Self {
                    paused,
                    worker,
                    completion,
                });
            }
        };
        let (previous, supplies) = inputs.into_parts();
        Ok(match resources.restore(previous) {
            Ok(original) => {
                let need = paused.need;
                RolloverUnstarted::Restored {
                    driver: paused.resume(
                        av_worker::UnknownTimeWorker::from_retirement(original),
                        ArchiveState::Retry,
                        Some(need),
                    ),
                    supplies,
                }
            }
            Err(refusal) => RolloverUnstarted::Refused {
                paused,
                refusal,
                supplies,
            },
        })
    }
    /// Reattach only a fully replayed, unfenced successor.
    #[allow(clippy::result_large_err)]
    pub fn finish(self) -> Result<RolloverResult, Self> {
        Self::finish_boxed(Box::new(self))
            .map(|result| *result)
            .map_err(|owner| *owner)
    }

    /// Transfer a drained switch through heap-owned stages.
    #[inline(never)]
    pub fn finish_boxed(self: Box<Self>) -> Result<Box<RolloverResult>, Box<Self>> {
        let stage = Self::boxed_retire(self)?;
        Ok(Self::boxed_finish(stage))
    }

    #[inline(never)]
    fn boxed_retire(mut this: Box<Self>) -> Result<Box<BoxedSwitchRetirement>, Box<Self>> {
        let Some(completion) = this.completion.take() else {
            return Err(this);
        };
        let Self { paused, worker, .. } = *this;
        match worker.retire() {
            Ok(retired) => Ok(Box::new(BoxedSwitchRetirement {
                paused,
                completion,
                retired: Box::new(retired),
            })),
            Err(worker) => Err(Box::new(Self {
                paused,
                worker,
                completion: Some(completion),
            })),
        }
    }

    #[inline(never)]
    fn boxed_finish(stage: Box<BoxedSwitchRetirement>) -> Box<RolloverResult> {
        let BoxedSwitchRetirement {
            paused,
            completion,
            retired,
        } = *stage;
        let retired = *retired;
        if completion.runtime.is_ok()
            && !retired.fenced
            && retired.inputs.is_none()
            && let av_rollover_worker::Outcome::Prepared {
                attachment,
                receipt,
            } = completion.outcome
        {
            return Box::new(match retired.resources.attach_prepared(attachment) {
                Ok(av) => RolloverResult::Resumed {
                    driver: paused.resume(av, ArchiveState::Armed, None),
                    receipt,
                },
                Err(refusal) => RolloverResult::AttachRefused {
                    paused,
                    refusal,
                    receipt,
                },
            });
        }
        Box::new(RolloverResult::Unresolved {
            paused,
            retirement: retired,
            completion,
        })
    }
}

/// Explicit state of the A/V publication attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveState {
    /// No segment or attempt is pending.
    Idle,
    /// An accepted segment is awaiting its first or explicitly retried attempt.
    Armed,
    /// A region-owned attempt must be joined.
    Running,
    /// An accepted segment needs explicit retry authorization.
    Retry,
    /// An uncertain completion requires reconciliation.
    Fenced,
}

/// Exact owners retained by this driver. Prefix events remain caller-owned.
#[must_use = "drain both archive workers and reconcile the camera effect"]
pub struct Parts {
    /// Source, readback, and committed camera-start effect.
    pub connected: media::Connected,
    /// Exclusive separate-source archive owner.
    pub source: source_worker::Worker,
    /// Exclusive A/V archive owner.
    pub av: av_worker::UnknownTimeWorker,
    /// First segment until it is offered to the A/V worker.
    pub first_segment: Option<recording::Segment>,
    /// Sender-clock hypothesis, not an observed capture time.
    pub origin: av_recording::SenderClockOrigin,
    /// Caller-supplied connection and generation claim.
    pub key: SourceKey,
    /// Caller-supplied camera claim, not independent identity evidence.
    pub camera_claim: ContentDigest,
    /// A first or explicitly retried standalone-source attempt is armed.
    pub source_armed: bool,
    /// A/V worker scheduling state.
    pub av_state: ArchiveState,
    /// Settled predecessor requiring a successor, if capacity stopped publication.
    pub rollover_need: Option<av_worker::RolloverNeed>,
    /// The caller has accounted for every forwarded bootstrap event.
    pub prefix_sealed: bool,
    /// Further media admission has been stopped.
    pub halted: bool,
}

impl Parts {
    /// Stop further admission and request cancellation of both archive paths.
    pub fn abort(&mut self) {
        self.halted = true;
        self.source_armed = false;
        self.source.abort();
        self.av.abort();
    }

    /// Join the exact A/V attempt and update its retained scheduling state.
    pub async fn join_av(&mut self) -> Option<av_worker::UnknownTimeCompletion> {
        let result = self.av.join().await?;
        self.rollover_need = if result.runtime.is_ok() {
            match &result.outcome {
                av_worker::UnknownTimeOutcome::Publication(
                    av_worker::UnknownTimePublication::Refused {
                        stage: av_worker::UnknownTimeFailureStage::BeforePublication,
                        reason: av_worker::FailureReason::JournalCapacity,
                        pending: None,
                        receipt: None,
                        rollover: Some(need),
                    },
                ) => Some(*need),
                _ => None,
            }
        } else {
            None
        };
        self.av_state = if result.runtime.is_err() {
            ArchiveState::Fenced
        } else {
            match &result.outcome {
                av_worker::UnknownTimeOutcome::Publication(
                    av_worker::UnknownTimePublication::Published(_),
                ) => ArchiveState::Idle,
                av_worker::UnknownTimeOutcome::NotStarted
                | av_worker::UnknownTimeOutcome::Publication(
                    av_worker::UnknownTimePublication::Refused { .. },
                ) => ArchiveState::Retry,
                _ => ArchiveState::Fenced,
            }
        };
        Some(result)
    }
}

/// Camera effect and A/V owners retained separately from the retired source tail.
/// None of these fields establishes effect settlement or camera identity.
#[must_use = "reconcile the camera effect and retain all A/V owners"]
pub struct RetirementAssets {
    /// Caller-supplied camera claim.
    pub camera_claim: ContentDigest,
    /// Committed camera-start effect requiring reconciliation.
    pub permit: CommittedEffect,
    /// Full private serializer readback.
    pub readback: crate::unifi_direct::camera_api::VideoSerializers,
    /// Redacted readback comparison.
    pub comparison: super::ReadbackObservation,
    /// A/V archive worker, including any pending segment.
    pub av: av_worker::UnknownTimeWorker,
    /// First segment if it was not offered to the A/V worker.
    pub first_segment: Option<recording::Segment>,
    /// Unverified sender-clock hypothesis.
    pub origin: av_recording::SenderClockOrigin,
    /// A/V worker scheduling state at retirement.
    pub av_state: ArchiveState,
    /// Outstanding capacity transition, if any.
    pub rollover_need: Option<av_worker::RolloverNeed>,
}

/// Retired camera effect, A/V worker and source-tail archival owner.
#[must_use = "reconcile the camera effect and drain or retain the tail"]
pub struct Retired {
    /// Camera and A/V ownership that remains outside the tail driver.
    pub assets: RetirementAssets,
    /// Ordered unfinished source and its exclusive archive worker.
    pub tail: retirement_source::Driver,
}

/// A retirement refusal preserves the exact owners at the failed stage.
#[must_use = "retain or reconcile all returned owners"]
#[allow(clippy::large_enum_variant)]
pub enum RetirementRefusal {
    /// The source has not stopped or its archive workers are not ready.
    NotDrained(Parts),
    /// Tail range validation refused the complete pipeline retirement.
    TailPlan {
        /// Camera and A/V owners.
        assets: RetirementAssets,
        /// Original source archive worker.
        source: source_worker::Worker,
        /// The full pipeline retirement and validation reason.
        refusal: retirement_source::Refusal,
    },
    /// Tail planning succeeded but attachment was refused.
    TailDriver {
        /// Camera and A/V owners.
        assets: RetirementAssets,
        /// Source worker, exact tail plan, and source claims.
        parts: retirement_source::DriverParts,
    },
}

impl Parts {
    /// Prepare archival of bytes retained after a stopped HTTP stream.
    /// This performs no I/O, does not finalize the unfinished GOP, and does
    /// not settle the camera effect or establish physical capture time.
    #[allow(clippy::result_large_err)]
    pub fn prepare_retirement(self) -> Result<Retired, RetirementRefusal> {
        if !self.halted
            || !self.prefix_sealed
            || self.source_armed
            || self.source.status() != source_worker::Status::Idle
            || !matches!(self.av_state, ArchiveState::Idle | ArchiveState::Retry)
            || self.connected.pipeline.source_key() != self.key
            || self.connected.camera_claim() != self.camera_claim
        {
            return Err(RetirementRefusal::NotDrained(self));
        }
        let Parts {
            connected,
            source,
            av,
            first_segment,
            origin,
            key,
            camera_claim,
            av_state,
            rollover_need,
            ..
        } = self;
        let detached = connected.into_parts();
        let assets = RetirementAssets {
            camera_claim: detached.camera_claim,
            permit: detached.permit,
            readback: detached.readback,
            comparison: detached.comparison,
            av,
            first_segment,
            origin,
            av_state,
            rollover_need,
        };
        let plan = match retirement_source::Plan::new(detached.pipeline.retire()) {
            Ok(plan) => plan,
            Err(refusal) => {
                return Err(RetirementRefusal::TailPlan {
                    assets,
                    source,
                    refusal,
                });
            }
        };
        let tail = match retirement_source::Driver::begin(source, plan, key, camera_claim) {
            Ok(tail) => tail,
            Err(parts) => return Err(RetirementRefusal::TailDriver { assets, parts }),
        };
        Ok(Retired { assets, tail })
    }
}

/// A paired input was either transferred or returned without losing custody.
#[must_use]
pub enum Offer {
    /// A separate source record entered its archive worker.
    Source {
        /// Why the original source was returned separately.
        disposition: recording::SourceDisposition,
        /// Same-step audio observation, still caller-owned.
        audio: Option<pipeline::AudioEvent>,
    },
    /// The recorder retains the source in its pending segment.
    Buffered(Option<pipeline::AudioEvent>),
    /// A segment entered the A/V worker.
    Segment(Option<pipeline::AudioEvent>),
    /// Source publication refused the unchanged source and paired audio.
    SourceRefused {
        /// Original worker refusal.
        refusal: source_worker::OfferRefusal,
        /// Same-step audio observation.
        audio: Option<pipeline::AudioEvent>,
    },
    /// A/V publication refused the unchanged segment and paired audio.
    SegmentRefused {
        /// Original worker refusal.
        refusal: av_worker::UnknownTimeOfferRefusal,
        /// Same-step audio observation.
        audio: Option<pipeline::AudioEvent>,
    },
    /// The input could not be transferred and remains caller-owned.
    Returned {
        /// Exact recorder result.
        push: recording::Push,
        /// Same-step audio observation.
        audio: Option<pipeline::AudioEvent>,
    },
}

/// One bounded source, media, or archive scheduling decision.
#[must_use]
pub enum Step {
    /// A complete paired media input was processed or returned.
    Offer(Offer),
    /// A source attempt started.
    SourceStarted,
    /// An A/V attempt started.
    AvStarted,
    /// The exact drained source completion remains caller-owned.
    SourceCompleted(source_worker::Completion),
    /// The exact drained A/V completion remains caller-owned.
    AvCompleted(av_worker::UnknownTimeCompletion),
    /// Worker admission refused; its original input remains held.
    StartRefused(av_worker::StartError),
    /// A source attempt remains running after the bounded wait.
    SourceRunning,
    /// An A/V attempt remains running after the bounded wait.
    AvRunning,
    /// A source requires explicit retry authorization.
    SourceRetryRequired,
    /// An A/V segment requires explicit retry authorization.
    AvRetryRequired,
    /// The pending segment requires a fresh journal successor before retry.
    RolloverRequired(av_worker::RolloverNeed),
    /// An archive owner is fenced or unavailable.
    ArchiveUnavailable,
    /// The caller has not yet sealed the forwarded bootstrap prefix.
    PrefixOpen,
    /// A media result that did not emit a recorder result.
    Media(pipeline::Step),
    /// A pipeline failure; any pending audio remains in the connected owner.
    MediaError(pipeline::Error),
    /// Bounded waiting elapsed without a media result.
    Idle,
    /// Invalid task, clock or wait bounds; no work was polled.
    Configuration,
    /// Cancellation or an earlier refusal stopped further admission.
    Halted,
}

impl Step {
    /// Whether this stop left the source tail in the pipeline, without an
    /// additional unaccepted source record carried by this event. The caller
    /// must still stop admission, join workers, and validate retirement.
    /// This does not authorize a camera write or claim durable source bytes.
    pub fn has_retirable_tail(&self) -> bool {
        matches!(
            self,
            Self::Media(pipeline::Step::Eof | pipeline::Step::LimitReached)
                | Self::MediaError(pipeline::Error::Ingress(
                    crate::unifi_direct::ingress::Error::Source(
                        fss_runtime::tcp_ingress::IngressError::BudgetExhausted
                    )
                ))
                | Self::MediaError(pipeline::Error::Ingress(
                    crate::unifi_direct::ingress::Error::Framing(
                        fss_packet::extended_flv::stream::Error::TrailerPolicyMismatch
                    )
                ))
        )
    }
}

/// One recording decision under an explicit finite AAC renewal allowance.
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum AllowanceStep {
    /// The normal driver decision, including any retained media or worker result.
    Recording(Step),
    /// The existing AAC epoch was extended; no media or archive work was polled.
    Renewed {
        /// Remaining frames before the extension.
        before: u64,
        /// Remaining frames after the extension.
        after: u64,
        /// Unspent caller-authorized frames.
        budget: u64,
    },
    /// The policy cannot restore its minimum with its remaining budget.
    Exhausted {
        /// Current remaining frames.
        remaining: u64,
        /// Unspent caller-authorized frames.
        budget: u64,
    },
    /// The task clock or task authority refused; no media or archive work was polled.
    Authority,
    /// The archive worker refused inspection or renewal; media was not polled.
    Refused(av_worker::AudioAllowanceError),
}

/// Owns both archive workers and the HTTP-started source.
#[must_use = "drain or recover the source and both archive owners"]
pub struct Driver {
    parts: Parts,
}

impl Driver {
    /// Whether the source archive attempt still requires joining.
    pub fn is_source_running(&self) -> bool {
        self.parts.source.is_running()
    }

    /// Whether the A/V archive attempt still requires joining.
    pub fn is_av_running(&self) -> bool {
        self.parts.av.is_running()
    }

    pub(super) fn bound_to_task(&self, task: &TaskCx<'_>) -> bool {
        self.parts.connected.pipeline.is_bound_to_task(task)
    }

    pub(super) fn source_claim(&self) -> (SourceKey, ContentDigest) {
        (self.parts.key, self.parts.camera_claim)
    }

    pub(super) fn matches_listener(
        &self,
        listener: &crate::unifi_direct::listener::Listener<'_, '_, '_>,
    ) -> bool {
        self.parts.connected.listener_addr == listener.local_addr()
            && listener.owns_pipeline_task(&self.parts.connected.pipeline)
    }

    /// Whether this source has stopped admitting recording work.
    /// This does not imply that its workers have drained or that the camera
    /// effect has been reconciled.
    pub(super) fn is_halted(&self) -> bool {
        self.parts.halted
    }

    /// Current capacity observation, if publication is waiting for a successor.
    pub fn rollover_need(&self) -> Option<av_worker::RolloverNeed> {
        self.parts.rollover_need
    }

    /// Renew the existing AAC epoch only while both archive workers are idle
    /// and under a caller-supplied finite allowance. A renewal never retries a
    /// failed publication, changes codec configuration, or reads media.
    #[allow(clippy::too_many_arguments)]
    pub async fn step_with_audio_allowance<'scope, 'task>(
        &mut self,
        policy: &mut crate::unifi_direct::recording_session::AudioAllowancePolicy,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        wait: Duration,
        source_archive: ArchiveAdmission<'_>,
        av_archive: ArchiveAdmission<'_>,
    ) -> AllowanceStep {
        let eligible = !self.parts.halted
            && self.parts.prefix_sealed
            && !wait.is_zero()
            && wait <= Duration::from_secs(30)
            && clock.matches(task, cx)
            && self.parts.connected.pipeline.is_bound_to_task(task)
            && cx.checkpoint().is_ok()
            && self.parts.source.status() == source_worker::Status::Idle
            && matches!(
                self.parts.av_state,
                ArchiveState::Idle | ArchiveState::Armed
            );
        if eligible {
            let Ok(now) = clock.now() else {
                return AllowanceStep::Authority;
            };
            if task.checkpoint(now, &BudgetVector::ZERO).is_err() {
                return AllowanceStep::Authority;
            }
            match self.parts.av.remaining_audio_frames() {
                Ok(before) if before < policy.minimum => {
                    if policy.remaining_budget < policy.minimum - before {
                        return AllowanceStep::Exhausted {
                            remaining: before,
                            budget: policy.remaining_budget,
                        };
                    }
                    let additional = policy.chunk.min(policy.remaining_budget);
                    return match self.parts.av.extend_audio_limit(additional) {
                        Ok(after) => {
                            policy.remaining_budget -= additional;
                            AllowanceStep::Renewed {
                                before,
                                after,
                                budget: policy.remaining_budget,
                            }
                        }
                        Err(error) => AllowanceStep::Refused(error),
                    };
                }
                Err(error) => return AllowanceStep::Refused(error),
                Ok(_) => (),
            }
        }
        AllowanceStep::Recording(
            self.step(task, cx, clock, wait, source_archive, av_archive)
                .await,
        )
    }

    /// Bind idle archive owners to one caller-claimed camera and source.
    pub fn attach(
        handoff: media_av_bootstrap::ArchiveHandoff,
        source: Coordinator,
    ) -> Result<Self, Box<AttachRefusal>> {
        let key = handoff.connected.pipeline.source_key();
        let camera_claim = handoff.connected.camera_claim();
        if key.connection == 0
            || key.generation == 0
            || key != handoff.first_segment.fragment().key()
            || !handoff.connected.pipeline.audio_tracking_active()
            || handoff.connected.pipeline.has_pending_audio()
            || !handoff.worker.is_idle()
            || !source.matches_binding(key, camera_claim)
            || source.source_status() != source_worker::Status::Idle
        {
            return Err(Box::new(AttachRefusal { handoff, source }));
        }
        Ok(Self {
            parts: Parts {
                connected: handoff.connected,
                source: source.into_worker(),
                av: handoff.worker,
                first_segment: Some(handoff.first_segment),
                origin: handoff.origin,
                key,
                camera_claim,
                source_armed: false,
                av_state: ArchiveState::Idle,
                rollover_need: None,
                prefix_sealed: false,
                halted: false,
            },
        })
    }

    /// Offer one original bootstrap-forwarded pair in source order.
    /// The caller must drive and account for each source completion before
    /// offering another record, and must not omit any forwarded event.
    pub fn offer_prefix(
        &mut self,
        push: recording::Push,
        audio: Option<pipeline::AudioEvent>,
    ) -> Offer {
        if self.parts.halted
            || self.parts.prefix_sealed
            || self.parts.source.status() != source_worker::Status::Idle
        {
            return Offer::Returned { push, audio };
        }
        self.offer_pair(push, audio, false)
    }

    /// Assert that all forwarded bootstrap events have been accounted for.
    /// This assertion is caller-supplied; it is not verified source continuity.
    pub fn seal_prefix(&mut self) -> bool {
        if self.parts.halted
            || self.parts.prefix_sealed
            || self.parts.source.status() != source_worker::Status::Idle
        {
            return false;
        }
        self.parts.prefix_sealed = true;
        true
    }

    /// Authorize one more attempt for a retained standalone source.
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

    /// Authorize one more attempt for the retained A/V segment.
    pub fn authorize_av_retry(&mut self) -> bool {
        if !self.parts.halted
            && self.parts.av_state == ArchiveState::Retry
            && self.parts.rollover_need.is_none()
        {
            self.parts.av_state = ArchiveState::Armed;
            true
        } else {
            false
        }
    }

    /// Stop new admission and request cancellation of both archive attempts.
    pub fn abort(&mut self) {
        self.parts.abort();
    }

    /// Join a source attempt without discarding its result.
    pub async fn join_source(&mut self) -> Option<source_worker::Completion> {
        self.parts.source.join().await
    }

    /// Join the exact A/V attempt and preserve its publication outcome.
    pub async fn join_av(&mut self) -> Option<av_worker::UnknownTimeCompletion> {
        self.parts.join_av().await
    }

    /// Recover all owners only once running attempts have been joined.
    #[allow(clippy::result_large_err)]
    pub fn into_parts(self) -> Result<Parts, Self> {
        if self.parts.source.is_running() || self.parts.av_state == ArchiveState::Running {
            Err(self)
        } else {
            Ok(self.parts)
        }
    }

    /// Run one bounded decision. Archive backpressure stops further media reads.
    pub async fn step<'scope, 'task>(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        wait: Duration,
        source_archive: ArchiveAdmission<'_>,
        av_archive: ArchiveAdmission<'_>,
    ) -> Step {
        if self.parts.halted {
            return Step::Halted;
        }
        if wait.is_zero()
            || wait > Duration::from_secs(30)
            || !clock.matches(task, cx)
            || !self.parts.connected.pipeline.is_bound_to_task(task)
        {
            return Step::Configuration;
        }
        if cx.checkpoint().is_err() {
            self.abort();
            return Step::Halted;
        }
        match self.parts.source.status() {
            source_worker::Status::Running => {
                return match timeout_at(cx.now() + wait, self.parts.source.join()).await {
                    Ok(Some(done)) => Step::SourceCompleted(done),
                    Ok(None) => Step::ArchiveUnavailable,
                    Err(_) => Step::SourceRunning,
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
                    Err(error) => Step::StartRefused(error),
                };
            }
            source_worker::Status::Pending => return Step::SourceRetryRequired,
            source_worker::Status::Fenced | source_worker::Status::Unavailable => {
                return Step::ArchiveUnavailable;
            }
            source_worker::Status::Idle => (),
        }
        if !self.parts.prefix_sealed {
            return Step::PrefixOpen;
        }
        match self.parts.av_state {
            ArchiveState::Running => {
                return match timeout_at(cx.now() + wait, self.join_av()).await {
                    Ok(Some(done)) => Step::AvCompleted(done),
                    Ok(None) => Step::ArchiveUnavailable,
                    Err(_) => Step::AvRunning,
                };
            }
            ArchiveState::Armed => {
                self.parts.av_state = ArchiveState::Retry;
                return match self.parts.av.start(
                    task,
                    cx,
                    clock,
                    av_archive.resource,
                    av_archive.cost,
                ) {
                    Ok(()) => {
                        self.parts.av_state = ArchiveState::Running;
                        Step::AvStarted
                    }
                    Err(error) => Step::StartRefused(error),
                };
            }
            ArchiveState::Retry => {
                return match self.parts.rollover_need {
                    Some(need) => Step::RolloverRequired(need),
                    None => Step::AvRetryRequired,
                };
            }
            ArchiveState::Fenced => return Step::ArchiveUnavailable,
            ArchiveState::Idle => (),
        }
        if let Some(segment) = self.parts.first_segment.take() {
            return Step::Offer(self.offer_pair(recording::Push::Segment(segment), None, true));
        }
        if !self.parts.connected.pipeline.audio_tracking_active()
            || self.parts.connected.pipeline.has_pending_audio()
        {
            self.parts.halted = true;
            return Step::ArchiveUnavailable;
        }
        let now = match clock.now() {
            Ok(now) => now,
            Err(_) => return Step::Configuration,
        };
        match timeout_at(
            cx.now() + wait,
            self.parts.connected.pipeline.step(task, cx, now),
        )
        .await
        {
            Err(_) => Step::Idle,
            Ok(Err(error)) => {
                self.parts.halted = true;
                Step::MediaError(error)
            }
            Ok(Ok(pipeline::Step::Recording(push))) => {
                let audio = self.parts.connected.pipeline.take_audio_event();
                Step::Offer(self.offer_pair(push, audio, true))
            }
            Ok(Ok(other)) => {
                if matches!(other, pipeline::Step::Eof | pipeline::Step::LimitReached) {
                    self.parts.halted = true;
                }
                Step::Media(other)
            }
        }
    }

    fn offer_pair(
        &mut self,
        push: recording::Push,
        audio: Option<pipeline::AudioEvent>,
        allow_segment: bool,
    ) -> Offer {
        if matches!(
            &push,
            recording::Push::Source {
                disposition: recording::SourceDisposition::Configuration,
                ..
            }
        ) || matches!(
            audio.as_ref(),
            Some(pipeline::AudioEvent::Fenced(_))
                | Some(pipeline::AudioEvent::Observed(
                    fss_packet::extended_flv::aac_track::Observation::Configuration { .. }
                ))
        ) {
            self.parts.halted = true;
            return Offer::Returned { push, audio };
        }
        match push {
            recording::Push::Source {
                record,
                disposition,
            } => {
                match self.parts.source.offer(source_worker::Input::Original {
                    record,
                    key: self.parts.key,
                    disposition,
                    camera_claim: self.parts.camera_claim,
                }) {
                    Ok(()) => {
                        self.parts.source_armed = true;
                        Offer::Source { disposition, audio }
                    }
                    Err(refusal) => {
                        self.parts.halted = true;
                        Offer::SourceRefused { refusal, audio }
                    }
                }
            }
            recording::Push::Buffered => Offer::Buffered(audio),
            recording::Push::Segment(segment) if allow_segment => {
                match self.parts.av.offer(segment) {
                    Ok(()) => {
                        self.parts.av_state = ArchiveState::Armed;
                        Offer::Segment(audio)
                    }
                    Err(refusal) => {
                        self.parts.halted = true;
                        Offer::SegmentRefused { refusal, audio }
                    }
                }
            }
            push => Offer::Returned { push, audio },
        }
    }
}
