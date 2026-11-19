#![forbid(unsafe_code)]
//! Separate every A/V supervisor phase from its scoped listener and clocks.
//!
//! The custody transfer and optional explicit worker drain do not authorize a
//! retry, settle an effect, prove physical identity, or survive a process crash.

use super::{
    media, media_av_archive as archive, media_av_managed as managed,
    media_av_reconnect as reconnect, media_av_startup as startup,
    media_av_supervisor as supervisor, media_reaccept,
};
use crate::unifi_direct::{
    av_owned_sink, av_recording, av_recovered_startup, av_worker, listener, media_reconnect,
    metered::MeteredClock, retirement_source, source_coordinator::Coordinator, source_worker,
};
use fss_container::flv_avc::SourceKey;
use fss_core::ContentDigest;
use std::collections::VecDeque;

/// Scoped bindings returned intact; neither listener is implicitly closed.
#[must_use = "account for both listener slots and their clock bindings"]
pub struct Scope<'scope, 'task, 'policy> {
    /// Listener held separately by the supervisor, if any.
    pub supervisor_listener: Option<listener::Listener<'scope, 'task, 'policy>>,
    /// Listener held inside the phase or its refusal, if any.
    pub phase_listener: Option<listener::Listener<'scope, 'task, 'policy>>,
    /// Original supervisor clock.
    pub clock: MeteredClock<'scope, 'task>,
    /// Original parked manager clock, if a manager was parked.
    pub parked_clock: Option<MeteredClock<'scope, 'task>>,
}

/// Original bridge-creation refusal with its listener removed.
#[must_use = "retain the connected source or rejected tail and effect"]
pub enum BridgeRefusal {
    /// Original connected source and effect.
    NotStopped(Box<media::Connected>),
    /// Original retired source and effect.
    Bounded(
        Option<media_reconnect::Retired>,
        media_reaccept::EffectCustody,
    ),
}

/// Original reconnect-begin refusal with its listener removed.
#[must_use = "retain every source, archive and effect owner"]
pub enum BeginRefusal {
    /// Recording was not ready.
    NotReady(Box<archive::Parts>),
    /// Bridge creation refused.
    Bridge(Box<(BridgeRefusal, source_worker::Worker, reconnect::Previous)>),
    /// Tail planning refused.
    TailPlan(
        Box<(
            media_reaccept::Detached,
            source_worker::Worker,
            reconnect::Previous,
            retirement_source::Refusal,
        )>,
    ),
    /// Tail driver attachment refused.
    TailDriver(
        Box<(
            media_reaccept::Detached,
            retirement_source::DriverParts,
            reconnect::Previous,
        )>,
    ),
    /// The expected original tail was missing.
    TailMissing(
        Box<(
            media_reaccept::Detached,
            source_worker::Worker,
            reconnect::Previous,
        )>,
    ),
}

/// Original in-progress transition, including its tail state.
#[must_use = "drain workers and reconcile the effect and source"]
pub struct Transition {
    /// Original effect, live candidate and retained media tails.
    pub bridge: media_reaccept::Detached,
    /// Old source-tail driver.
    pub tail: retirement_source::Driver,
    /// Previous A/V worker and claims.
    pub previous: reconnect::Previous,
    /// Tail completion was observed.
    pub tail_finished: bool,
    /// Tail publication was fenced.
    pub tail_fenced: bool,
}

/// Original verification phase, including its potentially running worker.
#[must_use = "drain the worker and reconcile all source and effect owners"]
pub struct Verification {
    /// Original effect, candidate and media tails.
    pub bridge: media_reaccept::Detached,
    /// Previous source archive and plan.
    pub tail: retirement_source::DriverParts,
    /// Previous connection's finished muxer.
    pub sink: av_owned_sink::UnknownTimeOwnedSink,
    /// Sender-clock hypothesis.
    pub origin: av_recording::SenderClockOrigin,
    /// Previous source claim.
    pub key: SourceKey,
    /// Previous camera claim.
    pub camera_claim: ContentDigest,
    /// Exact verification worker, possibly running.
    pub worker: av_recovered_startup::Worker,
    /// Worker admission succeeded.
    pub started: bool,
    /// Worker admission was refused.
    pub start_refused: bool,
    /// Verification succeeded.
    pub verified: bool,
    /// Verification stopped and requires reconciliation.
    pub stopped: bool,
}

/// Original archive-reuse refusal with its listener removed.
#[must_use = "retain all source, archive and effect owners"]
pub enum ReuseRefusal {
    /// Transition was not ready.
    NotReady(Box<Transition>),
    /// Source-tail worker was busy.
    TailBusy(
        Box<(
            media_reaccept::Detached,
            retirement_source::Driver,
            reconnect::Previous,
        )>,
    ),
    /// Source archive was not settled.
    SourceUnsettled(
        Box<(
            media_reaccept::Detached,
            retirement_source::DriverParts,
            reconnect::Previous,
        )>,
    ),
    /// A/V worker was busy.
    AvBusy(
        Box<(
            media_reaccept::Detached,
            retirement_source::DriverParts,
            reconnect::Previous,
        )>,
    ),
    /// A/V archive or custody was not settled.
    AvUnsettled(
        Box<(
            media_reaccept::Detached,
            retirement_source::DriverParts,
            Box<av_worker::UnknownTimeRetirement>,
            av_recording::SenderClockOrigin,
            SourceKey,
            ContentDigest,
        )>,
    ),
    /// Bridge transfer failed after archive retirement.
    Bridge(
        Box<(
            media_reaccept::Detached,
            retirement_source::DriverParts,
            Box<av_worker::UnknownTimeRetirement>,
            av_recording::SenderClockOrigin,
            SourceKey,
            ContentDigest,
        )>,
    ),
    /// Successor attachment refused.
    Attach(
        Box<(
            Box<startup::AttachRefusal>,
            reconnect::ReusedPrevious,
            VecDeque<media_reconnect::Retired>,
            usize,
            usize,
            Option<SourceKey>,
        )>,
    ),
}

/// Original verification-finish refusal.
#[must_use = "retain the verification or exact reuse refusal"]
pub enum VerifyFinishRefusal {
    /// Verification was not ready.
    NotReady(Box<Verification>),
    /// Verified resources could not be reused.
    Reuse(Box<ReuseRefusal>),
}

/// Original supervisor phase without any listener lifetime.
#[must_use = "drain and reconcile every retained phase owner"]
pub enum Phase {
    /// Managed recorder.
    Recording(Box<managed::Managed>),
    /// Tail archival or successor acceptance.
    Reconnecting(Box<Transition>),
    /// Custody verification.
    Verifying(Box<Verification>),
    /// Successor bootstrap.
    Starting(Box<startup::Driver>),
    /// Reconnect setup refusal.
    BeginStopped(Box<BeginRefusal>),
    /// Recording detached without an available listener.
    Detached(Box<archive::Parts>),
    /// Archive reuse refusal.
    ReuseStopped(Box<ReuseRefusal>),
    /// Verification finish refusal.
    VerificationStopped(Box<VerifyFinishRefusal>),
    /// Bootstrap transition refusal.
    StartupStopped(Box<startup::TransitionRefusal>),
    /// Successor management attachment refusal.
    ResumeStopped(Box<archive::Driver>),
}

/// Exact supervisor decision flags at the time of transfer.
#[derive(Clone, Copy, Debug)]
pub struct Flags {
    /// EOF was reported.
    pub eof_seen: bool,
    /// Successor readiness was reported.
    pub accepted_ready: bool,
    /// Bootstrap readiness was reported.
    pub bootstrap_ready: bool,
    /// Verification readiness was reported.
    pub verification_ready: bool,
    /// Verification requires explicit action.
    pub verification_blocked: bool,
    /// Reconnection requires explicit action.
    pub reconnect_blocked: bool,
    /// Reconnection was eligible for explicit retry.
    pub reconnect_retryable: bool,
    /// Startup requires explicit action.
    pub startup_blocked: bool,
    /// Parking was refused.
    pub park_stopped: bool,
}

/// All non-scoped supervisor owners and decisions.
#[must_use = "drain workers, preserve source evidence and reconcile the effect"]
pub struct Recovery {
    /// Original phase, including exact refusals.
    pub phase: Option<Phase>,
    /// Parked management policy and workers, if present.
    pub parked: Option<Box<managed::DetachedParked>>,
    /// Previous generation awaiting transfer.
    pub boundary: Option<Box<supervisor::Boundary>>,
    /// Original finite policy.
    pub config: supervisor::Config,
    /// Original decision flags.
    pub flags: Flags,
}

/// Result of one joined worker; absence does not establish quiescence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JoinResult {
    /// An exact completion is retained in the drain owner.
    Retained,
    /// No completion was returned; the owner must still be inspected.
    NoCompletion,
}

/// Observations from one pass over all supported worker slots.
/// `NoCompletion` does not imply that a slot is quiescent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainReport {
    /// Parked manager creator.
    pub parked_creator: JoinResult,
    /// Recording manager creator.
    pub recording_creator: JoinResult,
    /// Recording manager rollover worker.
    pub rollover: JoinResult,
    /// Source or old-tail worker.
    pub source: JoinResult,
    /// A/V worker.
    pub av: JoinResult,
    /// Rollover-custody verifier.
    pub verification: JoinResult,
}

/// Whether each retained worker class still has an admitted attempt to join.
/// This says nothing about live sockets, unresolved effects or durability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunningWorkers {
    /// Source or old-tail worker.
    pub source: bool,
    /// A/V worker.
    pub av: bool,
    /// Rollover-custody verifier.
    pub verification: bool,
    /// Recording manager creator or rollover worker.
    pub recording_background: bool,
    /// Parked manager creator.
    pub parked_creator: bool,
}

/// Exact worker completions returned when a drain owner is separated.
#[must_use = "reconcile every returned worker completion"]
#[derive(Default)]
pub struct DrainReceipts {
    /// Original source or retired-tail publication completion.
    pub source: Option<source_worker::Completion>,
    /// Original A/V publication completion.
    pub av: Option<av_worker::UnknownTimeCompletion>,
    /// Rollover-custody verification completion.
    pub verification: Option<av_recovered_startup::Completion>,
}

enum SourceSlot<'a> {
    Managed(&'a mut managed::Managed),
    Archive(&'a mut archive::Driver),
    ArchiveParts(&'a mut archive::Parts),
    Startup(&'a mut startup::Driver),
    Tail(&'a mut retirement_source::Driver),
    TailParts(&'a mut retirement_source::DriverParts),
    Worker(&'a mut source_worker::Worker),
    Coordinator(&'a mut Coordinator),
}

impl SourceSlot<'_> {
    fn is_running(&self) -> bool {
        match self {
            Self::Managed(v) => v.is_recording_source_running(),
            Self::Archive(v) => v.is_source_running(),
            Self::ArchiveParts(v) => v.source.is_running(),
            Self::Startup(v) => v.is_source_running(),
            Self::Tail(v) => v.is_running(),
            Self::TailParts(v) => v.worker.is_running(),
            Self::Worker(v) => v.is_running(),
            Self::Coordinator(v) => v.is_running(),
        }
    }

    fn abort(&mut self) {
        match self {
            Self::Managed(v) => v.abort(),
            Self::Archive(v) => v.abort(),
            Self::ArchiveParts(v) => v.abort(),
            Self::Startup(v) => v.abort(),
            Self::Tail(v) => v.abort(),
            Self::TailParts(v) => {
                v.halted = true;
                v.armed = false;
                v.worker.abort();
            }
            Self::Worker(v) => v.abort(),
            Self::Coordinator(v) => v.abort(),
        }
    }
    async fn join(&mut self) -> Option<source_worker::Completion> {
        match self {
            Self::Managed(v) => v.join_recording_source().await,
            Self::Archive(v) => v.join_source().await,
            Self::ArchiveParts(v) => v.source.join().await,
            Self::Startup(v) => v.join_source().await,
            Self::Tail(v) => v.join().await,
            Self::TailParts(v) => v.worker.join().await,
            Self::Worker(v) => v.join().await,
            Self::Coordinator(v) => v.join_source().await,
        }
    }
}

enum AvSlot<'a> {
    Managed(&'a mut managed::Managed),
    Archive(&'a mut archive::Driver),
    ArchiveParts(&'a mut archive::Parts),
    Worker(&'a mut av_worker::UnknownTimeWorker),
    None,
}

impl AvSlot<'_> {
    fn is_running(&self) -> bool {
        match self {
            Self::Managed(v) => v.is_recording_av_running(),
            Self::Archive(v) => v.is_av_running(),
            Self::ArchiveParts(v) => v.av.is_running(),
            Self::Worker(v) => v.is_running(),
            Self::None => false,
        }
    }

    fn abort(&mut self) {
        match self {
            Self::Managed(v) => v.abort(),
            Self::Archive(v) => v.abort(),
            Self::ArchiveParts(v) => v.abort(),
            Self::Worker(v) => v.abort(),
            Self::None => (),
        }
    }
    async fn join(&mut self) -> Option<av_worker::UnknownTimeCompletion> {
        match self {
            Self::Managed(v) => v.join_recording_av().await,
            Self::Archive(v) => v.join_av().await,
            Self::ArchiveParts(v) => v.join_av().await,
            Self::Worker(v) => v.join().await,
            Self::None => None,
        }
    }
}

fn reuse_source(v: &mut ReuseRefusal) -> SourceSlot<'_> {
    match v {
        ReuseRefusal::NotReady(v) => SourceSlot::Tail(&mut v.tail),
        ReuseRefusal::TailBusy(v) => SourceSlot::Tail(&mut v.1),
        ReuseRefusal::SourceUnsettled(v) | ReuseRefusal::AvBusy(v) => {
            SourceSlot::TailParts(&mut v.1)
        }
        ReuseRefusal::AvUnsettled(v) | ReuseRefusal::Bridge(v) => SourceSlot::TailParts(&mut v.1),
        ReuseRefusal::Attach(v) => SourceSlot::Coordinator(&mut v.0.storage.coordinator),
    }
}

fn reuse_av(v: &mut ReuseRefusal) -> AvSlot<'_> {
    match v {
        ReuseRefusal::NotReady(v) => AvSlot::Worker(&mut v.previous.av),
        ReuseRefusal::TailBusy(v) => AvSlot::Worker(&mut v.2.av),
        ReuseRefusal::SourceUnsettled(v) | ReuseRefusal::AvBusy(v) => AvSlot::Worker(&mut v.2.av),
        ReuseRefusal::AvUnsettled(_) | ReuseRefusal::Bridge(_) | ReuseRefusal::Attach(_) => {
            AvSlot::None
        }
    }
}

fn phase_source(v: &mut Phase) -> SourceSlot<'_> {
    match v {
        Phase::Recording(v) => SourceSlot::Managed(v),
        Phase::Reconnecting(v) => SourceSlot::Tail(&mut v.tail),
        Phase::Verifying(v) => SourceSlot::TailParts(&mut v.tail),
        Phase::Starting(v) => SourceSlot::Startup(v),
        Phase::BeginStopped(v) => match &mut **v {
            BeginRefusal::NotReady(v) => SourceSlot::ArchiveParts(v),
            BeginRefusal::Bridge(v) => SourceSlot::Worker(&mut v.1),
            BeginRefusal::TailPlan(v) => SourceSlot::Worker(&mut v.1),
            BeginRefusal::TailDriver(v) => SourceSlot::TailParts(&mut v.1),
            BeginRefusal::TailMissing(v) => SourceSlot::Worker(&mut v.1),
        },
        Phase::Detached(v) => SourceSlot::ArchiveParts(v),
        Phase::ReuseStopped(v) => reuse_source(v),
        Phase::VerificationStopped(v) => match &mut **v {
            VerifyFinishRefusal::NotReady(v) => SourceSlot::TailParts(&mut v.tail),
            VerifyFinishRefusal::Reuse(v) => reuse_source(v),
        },
        Phase::StartupStopped(v) => match &mut **v {
            startup::TransitionRefusal::NotReady(v) => SourceSlot::Startup(v),
            startup::TransitionRefusal::Bootstrap { source, .. }
            | startup::TransitionRefusal::Archive { source, .. } => SourceSlot::Worker(source),
            startup::TransitionRefusal::Attach(v) => SourceSlot::Coordinator(&mut v.source),
            startup::TransitionRefusal::Seal(v) => SourceSlot::Archive(v),
        },
        Phase::ResumeStopped(v) => SourceSlot::Archive(v),
    }
}

fn phase_av(v: &mut Phase) -> AvSlot<'_> {
    match v {
        Phase::Recording(v) => AvSlot::Managed(v),
        Phase::Reconnecting(v) => AvSlot::Worker(&mut v.previous.av),
        Phase::Verifying(_) | Phase::Starting(_) => AvSlot::None,
        Phase::BeginStopped(v) => match &mut **v {
            BeginRefusal::NotReady(v) => AvSlot::ArchiveParts(v),
            BeginRefusal::Bridge(v) => AvSlot::Worker(&mut v.2.av),
            BeginRefusal::TailPlan(v) => AvSlot::Worker(&mut v.2.av),
            BeginRefusal::TailDriver(v) => AvSlot::Worker(&mut v.2.av),
            BeginRefusal::TailMissing(v) => AvSlot::Worker(&mut v.2.av),
        },
        Phase::Detached(v) => AvSlot::ArchiveParts(v),
        Phase::ReuseStopped(v) => reuse_av(v),
        Phase::VerificationStopped(v) => match &mut **v {
            VerifyFinishRefusal::NotReady(_) => AvSlot::None,
            VerifyFinishRefusal::Reuse(v) => reuse_av(v),
        },
        Phase::StartupStopped(v) => match &mut **v {
            startup::TransitionRefusal::Attach(v) => AvSlot::Worker(&mut v.handoff.worker),
            startup::TransitionRefusal::Seal(v) => AvSlot::Archive(v),
            _ => AvSlot::None,
        },
        Phase::ResumeStopped(v) => AvSlot::Archive(v),
    }
}

fn phase_verifier(v: &mut Phase) -> Option<&mut av_recovered_startup::Worker> {
    match v {
        Phase::Verifying(v) => Some(&mut v.worker),
        Phase::VerificationStopped(v) => match &mut **v {
            VerifyFinishRefusal::NotReady(v) => Some(&mut v.worker),
            VerifyFinishRefusal::Reuse(_) => None,
        },
        _ => None,
    }
}

/// Owns cancellation and one-at-a-time joins for retained supervisor phases.
/// A dropped pending join leaves both this owner and its earlier receipts intact.
#[must_use = "finish draining and reconcile all retained owners and receipts"]
pub struct Drain {
    recovery: Box<Recovery>,
    receipts: DrainReceipts,
}

impl Drain {
    /// Request cancellation without relinquishing any owner. Missing phases
    /// and inconsistent parked ownership are returned unchanged.
    pub fn begin(mut recovery: Box<Recovery>) -> Result<Box<Self>, Box<Recovery>> {
        if recovery
            .parked
            .as_ref()
            .is_some_and(|p| p.parts.owner.is_some())
            || recovery.phase.is_none()
        {
            return Err(recovery);
        }
        if let Some(parked) = recovery.parked.as_mut() {
            parked.abort();
        }
        let phase = recovery
            .phase
            .as_mut()
            .expect("phase checked before mutation");
        phase_source(phase).abort();
        phase_av(phase).abort();
        if let Some(worker) = phase_verifier(phase) {
            worker.abort();
        }
        Ok(Box::new(Self {
            recovery,
            receipts: DrainReceipts::default(),
        }))
    }

    /// Inspect all original owners while they remain held by this drain.
    pub fn recovery(&self) -> &Recovery {
        &self.recovery
    }

    /// Inspect worker handles without treating an absent completion as proof.
    pub fn running_workers(&mut self) -> RunningWorkers {
        let phase = self
            .recovery
            .phase
            .as_mut()
            .expect("drain requires a phase");
        let source = phase_source(phase).is_running();
        let av = phase_av(phase).is_running();
        let verification = phase_verifier(phase).is_some_and(|worker| worker.is_running());
        let recording_background =
            matches!(phase, Phase::Recording(owner) if owner.is_background_running());
        let parked_creator = self
            .recovery
            .parked
            .as_ref()
            .and_then(|parked| parked.parts.creator.as_ref())
            .is_some_and(|worker| worker.is_running());
        RunningWorkers {
            source,
            av,
            verification,
            recording_background,
            parked_creator,
        }
    }

    /// Return ownership only if every known admitted worker has been joined.
    /// Success does not settle effects, close sockets or establish durability.
    pub fn finish_if_drained(
        mut self: Box<Self>,
    ) -> Result<(Box<Recovery>, DrainReceipts), Box<Self>> {
        let running = self.running_workers();
        if running.source
            || running.av
            || running.verification
            || running.recording_background
            || running.parked_creator
        {
            return Err(self);
        }
        Ok((self.recovery, self.receipts))
    }

    /// Join a source attempt and retain its completion before returning.
    pub async fn join_source(&mut self) -> JoinResult {
        if self.receipts.source.is_some() {
            return JoinResult::Retained;
        }
        let completion = match self.recovery.phase.as_mut() {
            Some(phase) => phase_source(phase).join().await,
            None => None,
        };
        if let Some(completion) = completion {
            self.receipts.source = Some(completion);
            JoinResult::Retained
        } else {
            JoinResult::NoCompletion
        }
    }

    /// Join an A/V attempt and retain its completion before returning.
    pub async fn join_av(&mut self) -> JoinResult {
        if self.receipts.av.is_some() {
            return JoinResult::Retained;
        }
        let completion = match self.recovery.phase.as_mut() {
            Some(phase) => phase_av(phase).join().await,
            None => None,
        };
        if let Some(completion) = completion {
            self.receipts.av = Some(completion);
            JoinResult::Retained
        } else {
            JoinResult::NoCompletion
        }
    }

    /// Join a custody check and retain its completion before returning.
    pub async fn join_verification(&mut self) -> JoinResult {
        if self.receipts.verification.is_some() {
            return JoinResult::Retained;
        }
        let completion = match self.recovery.phase.as_mut().and_then(phase_verifier) {
            Some(worker) => worker.join().await,
            None => None,
        };
        if let Some(completion) = completion {
            self.receipts.verification = Some(completion);
            JoinResult::Retained
        } else {
            JoinResult::NoCompletion
        }
    }

    /// Join the parked creator; its completion remains in parked custody.
    pub async fn join_parked_creator(&mut self) -> JoinResult {
        if let Some(parked) = self.recovery.parked.as_mut() {
            if parked.join_creator().await {
                return JoinResult::Retained;
            }
        }
        JoinResult::NoCompletion
    }

    /// Join the recording manager's creator; it retains its own completion.
    pub async fn join_recording_creator(&mut self) -> JoinResult {
        if let Some(Phase::Recording(owner)) = self.recovery.phase.as_mut() {
            if owner.join_creator().await {
                return JoinResult::Retained;
            }
        }
        JoinResult::NoCompletion
    }

    /// Join a recording manager's rollover worker; its owner retains the result.
    pub async fn join_rollover(&mut self) -> JoinResult {
        if let Some(Phase::Recording(owner)) = self.recovery.phase.as_mut() {
            if owner.join_rollover().await {
                return JoinResult::Retained;
            }
        }
        JoinResult::NoCompletion
    }

    /// Join each supported worker slot once. Earlier completions remain held
    /// if this future is dropped while waiting on a later slot. This may wait
    /// for admitted blocking work and does not claim a complete shutdown.
    pub async fn join_available(&mut self) -> DrainReport {
        let parked_creator = self.join_parked_creator().await;
        let recording_creator = self.join_recording_creator().await;
        let rollover = self.join_rollover().await;
        let source = self.join_source().await;
        let av = self.join_av().await;
        let verification = self.join_verification().await;
        DrainReport {
            parked_creator,
            recording_creator,
            rollover,
            source,
            av,
            verification,
        }
    }

    /// Return custody and exact completions, even when drainage is incomplete.
    pub fn into_parts(self: Box<Self>) -> (Box<Recovery>, DrainReceipts) {
        (self.recovery, self.receipts)
    }
}

type Bound<'s, 't, 'p> = listener::Listener<'s, 't, 'p>;

fn bridge<'s, 't, 'p>(
    value: media_reaccept::Reaccept<'s, 't, 'p>,
) -> (Bound<'s, 't, 'p>, media_reaccept::Detached) {
    value.into_parts().split_listener()
}

fn transition<'s, 't, 'p>(
    value: Box<reconnect::Transition<'s, 't, 'p>>,
) -> (Bound<'s, 't, 'p>, Box<Transition>) {
    let reconnect::Parts {
        bridge: source,
        tail,
        previous,
        tail_finished,
        tail_fenced,
    } = (*value).into_parts();
    let (listener, bridge) = bridge(source);
    (
        listener,
        Box::new(Transition {
            bridge,
            tail,
            previous,
            tail_finished,
            tail_fenced,
        }),
    )
}

fn verification<'s, 't, 'p>(
    value: Box<reconnect::ReuseVerification<'s, 't, 'p>>,
) -> (Bound<'s, 't, 'p>, Box<Verification>) {
    let reconnect::VerificationParts {
        bridge: source,
        tail,
        sink,
        origin,
        key,
        camera_claim,
        worker,
        started,
        start_refused,
        verified,
        stopped,
    } = value.into_parts();
    let (listener, bridge) = bridge(source);
    (
        listener,
        Box::new(Verification {
            bridge,
            tail,
            sink,
            origin,
            key,
            camera_claim,
            worker,
            started,
            start_refused,
            verified,
            stopped,
        }),
    )
}

fn begin<'s, 't, 'p>(
    value: Box<reconnect::BeginRefusal<'s, 't, 'p>>,
) -> (Bound<'s, 't, 'p>, Box<BeginRefusal>) {
    use reconnect::BeginRefusal as B;
    match *value {
        B::NotReady { parts, listener } => {
            (listener, Box::new(BeginRefusal::NotReady(Box::new(parts))))
        }
        B::Bridge {
            refusal,
            source,
            previous,
        } => {
            let (listener, refusal) = match refusal {
                media_reaccept::CreateRefusal::NotStoppedOrBound {
                    listener,
                    connected,
                } => (listener, BridgeRefusal::NotStopped(Box::new(connected))),
                media_reaccept::CreateRefusal::Bounded { refusal, effect } => (
                    refusal.listener,
                    BridgeRefusal::Bounded(refusal.previous, effect),
                ),
            };
            (
                listener,
                Box::new(BeginRefusal::Bridge(Box::new((refusal, source, previous)))),
            )
        }
        B::TailPlan {
            bridge: b,
            source,
            previous,
            refusal,
        } => {
            let (l, b) = bridge(b);
            (
                l,
                Box::new(BeginRefusal::TailPlan(Box::new((
                    b, source, previous, refusal,
                )))),
            )
        }
        B::TailDriver {
            bridge: b,
            parts,
            previous,
        } => {
            let (l, b) = bridge(b);
            (
                l,
                Box::new(BeginRefusal::TailDriver(Box::new((b, parts, previous)))),
            )
        }
        B::TailMissing {
            bridge: b,
            source,
            previous,
        } => {
            let (l, b) = bridge(b);
            (
                l,
                Box::new(BeginRefusal::TailMissing(Box::new((b, source, previous)))),
            )
        }
    }
}

fn reuse<'s, 't, 'p>(
    value: Box<reconnect::ReuseRefusal<'s, 't, 'p>>,
) -> (Bound<'s, 't, 'p>, Box<ReuseRefusal>) {
    use reconnect::ReuseRefusal as R;
    match *value {
        R::NotReady(t) => {
            let (l, t) = transition(t);
            (l, Box::new(ReuseRefusal::NotReady(t)))
        }
        R::TailBusy {
            bridge: b,
            tail,
            previous,
        } => {
            let (l, b) = bridge(b);
            (
                l,
                Box::new(ReuseRefusal::TailBusy(Box::new((b, tail, previous)))),
            )
        }
        R::SourceUnsettled {
            bridge: b,
            tail,
            previous,
        } => {
            let (l, b) = bridge(b);
            (
                l,
                Box::new(ReuseRefusal::SourceUnsettled(Box::new((b, tail, previous)))),
            )
        }
        R::AvBusy {
            bridge: b,
            tail,
            previous,
        } => {
            let (l, b) = bridge(b);
            (
                l,
                Box::new(ReuseRefusal::AvBusy(Box::new((b, tail, previous)))),
            )
        }
        R::AvUnsettled {
            bridge: b,
            tail,
            av,
            origin,
            key,
            camera_claim,
        } => {
            let (l, b) = bridge(b);
            (
                l,
                Box::new(ReuseRefusal::AvUnsettled(Box::new((
                    b,
                    tail,
                    av,
                    origin,
                    key,
                    camera_claim,
                )))),
            )
        }
        R::Bridge {
            bridge: b,
            tail,
            av,
            origin,
            key,
            camera_claim,
        } => {
            let (l, b) = bridge(b);
            (
                l,
                Box::new(ReuseRefusal::Bridge(Box::new((
                    b,
                    tail,
                    av,
                    origin,
                    key,
                    camera_claim,
                )))),
            )
        }
        R::Attach {
            refusal,
            listener,
            previous,
            retired,
            attempts,
            max_attempts,
            last,
        } => (
            listener,
            Box::new(ReuseRefusal::Attach(Box::new((
                refusal,
                previous,
                retired,
                attempts,
                max_attempts,
                last,
            )))),
        ),
    }
}

/// Split every phase, including stopped refusals, without polling or dropping owners.
/// The returned recovery owner is independent of the runtime scope but is not
/// durable. Previously returned events and receipts remain caller-owned.
#[inline(never)]
pub fn detach<'s, 't, 'p>(
    value: Box<supervisor::Supervisor<'s, 't, 'p>>,
) -> (Scope<'s, 't, 'p>, Box<Recovery>) {
    let supervisor::Parts {
        phase,
        listener: supervisor_listener,
        parked,
        boundary,
        config,
        clock,
        eof_seen,
        accepted_ready,
        bootstrap_ready,
        verification_ready,
        verification_blocked,
        reconnect_blocked,
        reconnect_retryable,
        startup_blocked,
        park_stopped,
    } = value.into_parts();
    let (phase_listener, phase) = match phase {
        None => (None, None),
        Some(supervisor::Phase::Recording(v)) => (None, Some(Phase::Recording(v))),
        Some(supervisor::Phase::Reconnecting(v)) => {
            let (l, v) = transition(v);
            (Some(l), Some(Phase::Reconnecting(v)))
        }
        Some(supervisor::Phase::Verifying(v)) => {
            let (l, v) = verification(v);
            (Some(l), Some(Phase::Verifying(v)))
        }
        Some(supervisor::Phase::Starting(v)) => (None, Some(Phase::Starting(v))),
        Some(supervisor::Phase::BeginStopped(v)) => {
            let (l, v) = begin(v);
            (Some(l), Some(Phase::BeginStopped(v)))
        }
        Some(supervisor::Phase::Detached(v)) => (None, Some(Phase::Detached(v))),
        Some(supervisor::Phase::ReuseStopped(v)) => {
            let (l, v) = reuse(v);
            (Some(l), Some(Phase::ReuseStopped(v)))
        }
        Some(supervisor::Phase::VerificationStopped(v)) => match *v {
            reconnect::VerifyFinishRefusal::NotReady(v) => {
                let (l, v) = verification(v);
                (
                    Some(l),
                    Some(Phase::VerificationStopped(Box::new(
                        VerifyFinishRefusal::NotReady(v),
                    ))),
                )
            }
            reconnect::VerifyFinishRefusal::Reuse(v) => {
                let (l, v) = reuse(v);
                (
                    Some(l),
                    Some(Phase::VerificationStopped(Box::new(
                        VerifyFinishRefusal::Reuse(v),
                    ))),
                )
            }
        },
        Some(supervisor::Phase::StartupStopped(v)) => (None, Some(Phase::StartupStopped(v))),
        Some(supervisor::Phase::ResumeStopped(v)) => (None, Some(Phase::ResumeStopped(v))),
    };
    let (parked_clock, parked) = match parked {
        Some(value) => {
            let (clock, value) = value.split_scope();
            (Some(clock), Some(value))
        }
        None => (None, None),
    };
    let flags = Flags {
        eof_seen,
        accepted_ready,
        bootstrap_ready,
        verification_ready,
        verification_blocked,
        reconnect_blocked,
        reconnect_retryable,
        startup_blocked,
        park_stopped,
    };
    (
        Scope {
            supervisor_listener,
            phase_listener,
            clock,
            parked_clock,
        },
        Box::new(Recovery {
            phase,
            parked,
            boundary,
            config,
            flags,
        }),
    )
}
