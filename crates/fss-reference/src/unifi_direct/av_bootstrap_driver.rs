#![forbid(unsafe_code)]
//! A bounded supervisor driver pairing each media result with its audio event.
//!
//! The owner does not authorize cameras, infer capture time, start archive
//! tasks or reconnect. Control can be serviced while an event is withheld;
//! all outstanding source custody can be recovered through `into_parts`.

use std::time::Duration;

use asupersync::io::{AsyncRead, AsyncWrite};
use fss_core::OperationId;

use super::{
    av_bootstrap, av_owned_sink, conversation, metered::MeteredClock, pipeline, recording,
    supervisor,
};

/// One bounded driver result. Every returned source or event remains caller-owned.
#[must_use]
#[derive(Debug)]
pub enum Step {
    /// A source record or first segment was retained by the collector.
    Retained,
    /// A result and its audio interpretation were not needed for bootstrap.
    Forward {
        /// The complete original recorder result.
        push: recording::Push,
        /// Its corresponding audio event, if any.
        audio: Option<pipeline::AudioEvent>,
    },
    /// A previously pending audio event could not be paired with a returned
    /// recorder result, for example after a recording refusal.
    Audio(pipeline::AudioEvent),
    /// Admission or cancellation withheld the pending event; no more media was read.
    AudioWithheld,
    /// An audio fence or unconsumed configuration requires reconciliation.
    /// No further media is polled; recover all components with `into_parts`.
    Fenced,
    /// An unrelated supervisor observation, control result, or failure.
    Supervisor(supervisor::Step),
    /// All bootstrap inputs are retained; media polling is stopped.
    Ready,
}

/// Task-owned components, returned intact when attachment is refused.
#[must_use]
pub struct Parts<'scope, 'task, IO> {
    /// Original controller and media owner.
    pub supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    /// Inputs already retained for bootstrap.
    pub collector: av_bootstrap::Collector,
    /// A recorder result awaiting its corresponding audio event, if any.
    pub pending: Option<recording::Push>,
    /// Audio interpretation requires explicit reconciliation before resuming.
    pub fenced: bool,
}

/// At most one recorder result can wait for an audio-event transfer.
#[must_use = "recover the supervisor and source custody with into_parts"]
pub struct Driver<'scope, 'task, IO> {
    parts: Parts<'scope, 'task, IO>,
}

/// Completed bootstrap and the still-owned camera supervisor.
#[must_use]
pub struct Handoff<'scope, 'task, IO> {
    /// Camera controller and media owner, ready for a separately supervised guard.
    pub supervisor: supervisor::Supervisor<'scope, 'task, IO>,
    /// Idle archive sink, original first segment and sender-clock hypothesis.
    pub bootstrap: av_owned_sink::Bootstrap,
}

/// Failed handoff retaining all original source and controller custody.
#[must_use]
pub enum HandoffRefusal<'scope, 'task, IO> {
    /// The collector is incomplete, audio is pending, or reconciliation is required.
    NotReady(Driver<'scope, 'task, IO>),
    /// Source validation failed; the sink refusal retains all original inputs.
    Bootstrap {
        /// Original controller and media owner.
        supervisor: supervisor::Supervisor<'scope, 'task, IO>,
        /// Exact original inputs and payload-free reason for refusal.
        refusal: av_owned_sink::BootstrapRefusal,
    },
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> Driver<'scope, 'task, IO> {
    pub(super) fn matches_clock(&self, clock: &MeteredClock<'_, '_>) -> bool {
        self.parts.supervisor.matches_clock(clock)
    }

    pub(super) fn ready_for_handoff(&self) -> bool {
        self.parts.pending.is_none()
            && !self.parts.fenced
            && !self.parts.supervisor.has_pending_audio()
            && self.parts.collector.ready()
    }

    /// Attach only to an active audio interpreter with no unmatched event.
    /// On refusal the supervisor and collector are returned unchanged.
    pub fn attach(
        supervisor: supervisor::Supervisor<'scope, 'task, IO>,
        collector: av_bootstrap::Collector,
    ) -> Result<Self, Parts<'scope, 'task, IO>> {
        let parts = Parts {
            supervisor,
            collector,
            pending: None,
            fenced: false,
        };
        if !parts.supervisor.audio_tracking_active() || parts.supervisor.has_pending_audio() {
            return Err(parts);
        }
        Ok(Self { parts })
    }

    /// Return the original owners, including a result whose event was withheld.
    pub fn into_parts(self) -> Parts<'scope, 'task, IO> {
        self.parts
    }

    /// Derive the idle archive sink and transfer the original first segment.
    /// No I/O, capture-time inference or camera authorization is performed.
    /// An incomplete or fenced driver is returned intact; a validation refusal
    /// returns both the supervisor and every original bootstrap input.
    pub fn bootstrap(
        self,
    ) -> Result<Handoff<'scope, 'task, IO>, HandoffRefusal<'scope, 'task, IO>> {
        if !self.ready_for_handoff() {
            return Err(HandoffRefusal::NotReady(self));
        }
        let Parts {
            supervisor,
            collector,
            pending,
            fenced,
        } = self.parts;
        let inputs = match collector.into_inputs() {
            Ok(inputs) => inputs,
            Err(av_bootstrap::Incomplete(collector)) => {
                return Err(HandoffRefusal::NotReady(Self {
                    parts: Parts {
                        supervisor,
                        collector,
                        pending,
                        fenced,
                    },
                }));
            }
        };
        match av_owned_sink::OwnedSink::bootstrap(inputs) {
            Ok(bootstrap) => Ok(Handoff {
                supervisor,
                bootstrap,
            }),
            Err(refusal) => Err(HandoffRefusal::Bootstrap {
                supervisor,
                refusal,
            }),
        }
    }

    /// Service controller input without consuming media or a pending audio event.
    pub async fn service_control(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> supervisor::Step {
        self.parts
            .supervisor
            .step_control(owner, operation, wait)
            .await
    }

    /// Drive one supervisor result or one pending-event transfer. If admission
    /// is withdrawn, the source result remains owned until transfer or retirement.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, '_, '_>,
        operation: &OperationId,
        wait: Duration,
    ) -> Step {
        if self.parts.pending.is_some() || self.parts.supervisor.has_pending_audio() {
            let Some(audio) = self.parts.supervisor.take_audio_event(owner) else {
                return Step::AudioWithheld;
            };
            return match self.parts.pending.take() {
                Some(push) => self.collect(push, Some(audio)),
                None => {
                    self.parts.fenced |= requires_reconciliation(&audio);
                    Step::Audio(audio)
                }
            };
        }
        if self.parts.fenced {
            return Step::Fenced;
        }
        if self.parts.collector.ready() {
            return Step::Ready;
        }
        match self.parts.supervisor.step(owner, operation, wait).await {
            supervisor::Step::Media(pipeline::Step::Recording(push)) => {
                if self.parts.supervisor.has_pending_audio() {
                    match self.parts.supervisor.take_audio_event(owner) {
                        Some(audio) => self.collect(push, Some(audio)),
                        None => {
                            self.parts.pending = Some(push);
                            Step::AudioWithheld
                        }
                    }
                } else {
                    self.collect(push, None)
                }
            }
            other => Step::Supervisor(other),
        }
    }

    fn collect(&mut self, push: recording::Push, audio: Option<pipeline::AudioEvent>) -> Step {
        match self.parts.collector.collect(push, audio) {
            av_bootstrap::Collected::Retained => Step::Retained,
            av_bootstrap::Collected::Forward { push, audio } => {
                self.parts.fenced |= audio.as_ref().is_some_and(requires_reconciliation);
                Step::Forward { push, audio }
            }
        }
    }
}

fn requires_reconciliation(audio: &pipeline::AudioEvent) -> bool {
    matches!(
        audio,
        pipeline::AudioEvent::Fenced(_)
            | pipeline::AudioEvent::Observed(
                fss_packet::extended_flv::aac_track::Observation::Configuration { .. }
            )
    )
}
