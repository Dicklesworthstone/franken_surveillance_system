#![forbid(unsafe_code)]
//! Task-admitted archive-to-still work with retained source and drained cancellation.

use std::sync::{Arc, Mutex};

use asupersync::{Cx, runtime::JoinError};
use fss_core::{BudgetVector, RuntimeGrant};
use fss_runtime::{
    drained_blocking::{self, Drained, StartFailure, WorkOutcome},
    execution::{ExecutionError, TaskCx},
};

use super::{archive, metered::MeteredClock, video_owned_sink, video_still};

/// Original source retained while one still is produced.
pub enum Source {
    /// Source and mappings were checked by an archive read.
    Recovered(archive::RecoveredUnknownTimeVideoClip),
    /// Original segment and sealed confirmed publication, not a fresh readback.
    Published(video_owned_sink::PublishedStillSource),
}
impl Source {
    /// Exact root and retention identity; this grants no read permission.
    pub fn pin(&self) -> archive::UnknownTimePin {
        match self {
            Self::Recovered(value) => value.pin(),
            Self::Published(value) => value.pin(),
        }
    }
    /// Return the original recovered clip or the unchanged alternate source.
    pub fn into_recovered(self) -> Result<archive::RecoveredUnknownTimeVideoClip, Self> {
        match self {
            Self::Recovered(value) => Ok(value),
            other => Err(other),
        }
    }
    /// Return the original publication or the unchanged alternate source.
    pub fn into_published(self) -> Result<video_owned_sink::Published, Self> {
        match self {
            Self::Published(value) => Ok(value.into_publication()),
            other => Err(other),
        }
    }
}

/// The source and explicit bounded rendering policy owned by one attempt.
pub struct Parts {
    /// Previously source-checked recording; this does not grant future reads.
    pub source: Source,
    /// Current read/privacy policy, checked before, during and after work.
    pub read: Arc<dyn archive::ReadAuthority + Send + Sync>,
    /// Explicit declared color interpretation.
    pub color: video_still::Color,
    /// JPEG quality in 1..=100.
    pub quality: u8,
    /// Independent image and output limits.
    pub limits: fss_codec_jpeg_encode::EncodeLimits,
    /// Maximum pixels converted in this attempt.
    pub pixel_work_limit: u64,
    /// Maximum JPEG encoder work units in this attempt.
    pub encode_work_limit: u64,
}

/// Why a still attempt could not be started or completed.
#[derive(Debug)]
pub enum Refusal {
    /// Current read/privacy policy denied the exact archive root.
    Denied,
    /// The owner requested cancellation; no still is returned.
    Cancelled,
    /// Bounded demux, decode, conversion or encoding refused.
    Still(video_still::Error),
}

/// Runtime admission errors; the source remains owned by the worker.
#[derive(Debug)]
pub enum StartError {
    /// An earlier attempt is still running.
    Running,
    /// Cancellation, a prior attempt, or an uncertain result fenced the owner.
    Fenced,
    /// The clock belongs to a different task or context.
    Context,
    /// The bound clock was unavailable.
    Clock,
    /// Current policy refused the archive root.
    Denied,
    /// Task, grant, time or budget admission refused.
    Task(ExecutionError),
    /// Runtime or region admission refused.
    Runtime(StartFailure),
}

/// Semantic result after the blocking work drained.
#[must_use]
pub enum Outcome {
    /// Work was not started; source remains in the worker.
    NotStarted,
    /// Work returned, with a still only if current policy permitted it.
    Finished(Result<video_still::ArchivedStill, Refusal>),
    /// The closure panicked and must be inspected.
    Panicked,
    /// Completion could not be established.
    Indeterminate,
}

/// The independent runtime and semantic outcomes.
#[must_use]
pub struct Completion {
    /// Runtime classification after draining.
    pub runtime: Result<(), JoinError>,
    /// Semantic outcome, including any returned still.
    pub outcome: Outcome,
}

/// Every owner remaining after the worker has drained.
#[must_use]
pub struct Retirement {
    /// Original source and policy, retained even on refusal.
    pub parts: Parts,
    /// A result not transferred by `join`.
    pub report: Option<Result<video_still::ArchivedStill, Refusal>>,
    /// Panic, poison, cancellation or uncertainty fenced this worker.
    pub fenced: bool,
}

struct State {
    parts: Parts,
    report: Option<Result<video_still::ArchivedStill, Refusal>>,
}
type Job = Box<dyn FnOnce(Cx) + Send + 'static>;

/// One non-retrying worker. Join before retirement after every admission.
pub struct Worker {
    state: Arc<Mutex<State>>,
    running: Option<Drained<Job, ()>>,
    started: bool,
    fenced: bool,
    aborted: bool,
}
impl Worker {
    /// Bind source and bounded policy without I/O; refusal returns all owners.
    pub fn new(parts: Parts) -> Result<Self, Parts> {
        if parts.limits.validate().is_err()
            || !(1..=100).contains(&parts.quality)
            || !(1..=fss_codec_jpeg_encode::MAX_PIXELS as u64).contains(&parts.pixel_work_limit)
            || !(1..=100_000_000_000).contains(&parts.encode_work_limit)
        {
            return Err(parts);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                parts,
                report: None,
            })),
            running: None,
            started: false,
            fenced: false,
            aborted: false,
        })
    }

    /// Admit one blocking decode under current read and media-decode grants.
    pub fn start<'scope, 'task>(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &str,
        cost: &BudgetVector,
    ) -> Result<(), StartError> {
        if self.running.is_some() {
            return Err(StartError::Running);
        }
        if self.fenced || self.aborted || self.started {
            return Err(StartError::Fenced);
        }
        if !clock.matches(task, cx) {
            return Err(StartError::Context);
        }
        let now = clock.now().map_err(|_| StartError::Clock)?;
        {
            let state = self.state.try_lock().map_err(|_| StartError::Fenced)?;
            let pin = state.parts.source.pin();
            if !state.parts.read.permits(pin.retention, pin.root) {
                return Err(StartError::Denied);
            }
        }
        task.checkpoint_for(RuntimeGrant::ReadMedia, resource, now, &BudgetVector::ZERO)
            .map_err(StartError::Task)?;
        task.checkpoint_for(RuntimeGrant::MediaDecode, resource, now, cost)
            .map_err(StartError::Task)?;
        let state = Arc::clone(&self.state);
        let work: Job = Box::new(move |child| {
            let Ok(mut state) = state.lock() else {
                return;
            };
            let pin = state.parts.source.pin();
            let read = Arc::clone(&state.parts.read);
            let permitted = || read.permits(pin.retention, pin.root);
            let cancelled = || child.is_cancel_requested() || !permitted();
            let result = if !permitted() {
                Err(Refusal::Denied)
            } else if child.is_cancel_requested() {
                Err(Refusal::Cancelled)
            } else {
                let p = &state.parts;
                let result = match &p.source {
                    Source::Recovered(clip) => video_still::from_archive_with_probe(
                        clip,
                        p.color,
                        p.quality,
                        &p.limits,
                        p.pixel_work_limit,
                        p.encode_work_limit,
                        &cancelled,
                    ),
                    Source::Published(source) => video_still::from_published_with_probe(
                        source,
                        p.color,
                        p.quality,
                        &p.limits,
                        p.pixel_work_limit,
                        p.encode_work_limit,
                        &cancelled,
                    ),
                };
                if !permitted() {
                    Err(Refusal::Denied)
                } else if child.is_cancel_requested() {
                    Err(Refusal::Cancelled)
                } else {
                    result.map_err(Refusal::Still)
                }
            };
            state.report = Some(result);
        });
        match drained_blocking::start(cx, work) {
            Ok(running) => {
                self.running = Some(running);
                self.started = true;
                Ok(())
            }
            Err(refusal) => Err(StartError::Runtime(refusal.reason)),
        }
    }

    /// Latch cancellation and request interruption of an admitted attempt.
    pub fn abort(&mut self) {
        self.aborted = true;
        if let Some(running) = &self.running {
            running.abort();
        }
    }

    /// Drain one admitted attempt, retaining both runtime and semantic outcomes.
    pub async fn join(&mut self) -> Option<Completion> {
        let receipt = self.running.as_mut()?.join().await?;
        self.running.take();
        let outcome = match receipt.work {
            WorkOutcome::NotStarted(work) => {
                drop(work);
                Outcome::NotStarted
            }
            WorkOutcome::Finished(()) => match self.state.try_lock() {
                Ok(mut state) => match state.report.take() {
                    Some(report) => {
                        let pin = state.parts.source.pin();
                        if !state.parts.read.permits(pin.retention, pin.root) {
                            Outcome::Finished(Err(Refusal::Denied))
                        } else if self.aborted {
                            Outcome::Finished(Err(Refusal::Cancelled))
                        } else {
                            Outcome::Finished(report)
                        }
                    }
                    None => {
                        self.fenced = true;
                        Outcome::Indeterminate
                    }
                },
                Err(_) => {
                    self.fenced = true;
                    Outcome::Indeterminate
                }
            },
            WorkOutcome::Panicked => {
                self.fenced = true;
                Outcome::Panicked
            }
            WorkOutcome::Indeterminate => {
                self.fenced = true;
                Outcome::Indeterminate
            }
        };
        if receipt.runtime.is_err() {
            self.fenced = true;
        }
        Some(Completion {
            runtime: receipt.runtime,
            outcome,
        })
    }

    /// Recover the source only after the original attempt has drained.
    pub fn retire(self) -> Result<Retirement, Self> {
        let Self {
            state,
            running,
            started,
            fenced,
            aborted,
        } = self;
        if running.is_some() {
            return Err(Self {
                state,
                running,
                started,
                fenced,
                aborted,
            });
        }
        match Arc::try_unwrap(state) {
            Ok(state) => {
                let poisoned = state.is_poisoned();
                let state = state
                    .into_inner()
                    .unwrap_or_else(|error| error.into_inner());
                Ok(Retirement {
                    parts: state.parts,
                    report: state.report,
                    fenced: fenced || aborted || poisoned,
                })
            }
            Err(state) => Err(Self {
                state,
                running,
                started,
                fenced,
                aborted,
            }),
        }
    }
}
