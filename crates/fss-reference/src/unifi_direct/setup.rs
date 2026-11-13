#![forbid(unsafe_code)]
//! Experimental one-candidate discovery-to-controller handoff orchestration.
//!
//! The candidate remains untrusted. The caller supplies an already admitted
//! camera transport, credentials, a current independent identity/lease policy,
//! an existing effect journal, and an authorized controller destination. This
//! module does not perform Wi-Fi provisioning, establish TLS identity, run the
//! controller, settle the effect, or guarantee recording continuity. Journal
//! operations are synchronous and unsuitable for a latency-sensitive reactor.

use super::{
    camera_api, camera_http, controller_listener, conversation, discovery, handoff,
    metered::MeteredClock,
};
use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, DigestAlgorithm, IdempotencyKey, OperationId,
    RuntimeGrant,
};
use fss_object::{SpoolObjectState, StagingSpool};
use fss_runtime::{
    effect::{CommittedEffect, EffectCoordinator, PrepareSpec, PreparedEffect},
    effect_journal::EffectJournalPin,
    execution::TaskCx,
    lease::LeaseRegistry,
};
use std::{
    cell::RefCell,
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

const MAX_WAIT: Duration = Duration::from_secs(30);
const DEADLINE_EVIDENCE_DOMAIN: &str = "fss.unifi-direct.setup-precommit-deadline.v1";

/// Nonblocking independent policy binding this untrusted candidate to the
/// operator-authorized camera, admitted transport, and live lease.
pub trait Admission {
    /// Revalidate the candidate and supplied camera claims at each setup stage.
    fn permits(
        &self,
        candidate: &discovery::CameraCandidate,
        camera: ContentDigest,
        peer_admission: ContentDigest,
        generation: u64,
        fence: u64,
    ) -> bool;
}

/// Inputs for one setup attempt. Credential bytes are never logged or retained.
pub struct Config<'a> {
    /// Completed bounded discovery window containing the candidate.
    pub report: &'a discovery::Report,
    /// Index into the exact report, not a durable device identity.
    pub index: usize,
    /// Independently established camera identity claim.
    pub camera: ContentDigest,
    /// Current independently established peer-admission decision.
    pub peer_admission: ContentDigest,
    /// Nonzero camera-local session generation.
    pub generation: u64,
    /// Current nonzero lease fence.
    pub fence: u64,
    /// Authorized new controller IPv4 address.
    pub destination: Ipv4Addr,
    /// Exact one-use journal operation identity.
    pub operation: &'a OperationId,
    /// Caller-owned camera-local credential bytes.
    pub credential: &'a [u8],
    /// Single total deadline covering network stages, at most 30 seconds.
    pub wait: Duration,
}

/// Payload-free refusal before a dispatch permit was returned. A failed
/// preparation or commit may leave a journaled obligation; inspect the journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Discovery, identity, task, session, or time parameters are invalid.
    Configuration,
    /// Untrusted discovery claims conflict or the window was incomplete.
    Claims,
    /// The two camera settings observations did not agree.
    Changed,
    /// No complete camera-reported video profile met the preflight limits.
    VideoProfileUnavailable,
    /// The expected controller socket is absent, mismatched or no longer admitted.
    ControllerUnavailable,
    /// Camera status did not report the listener's nonzero controller port.
    ControllerPort,
    /// Current admission or runtime authority refused setup.
    Denied,
    /// The bounded total deadline elapsed.
    Deadline,
    /// Camera-local login, status or settings failed.
    Camera(camera_http::Error),
    /// A safe handoff plan could not be prepared.
    Plan(handoff::Error),
    /// Journal preparation, policy approval, or commit was refused.
    Effect,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi setup stopped: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Stage at which a committed effect needs independent reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Indeterminate {
    /// The write was partial or its outcome is unknown.
    Write,
    /// Current policy or the total deadline prevented further observation.
    AuthorityOrDeadline,
    /// The handoff HTTP reply was unavailable or refused.
    Response,
    /// The follow-up settings observation was unavailable or unbound.
    Readback,
}

/// Caller-owned custody for an interrupted setup attempt. A dispatched permit
/// may be inside the dropped write future; the journal then remains the source
/// of the unresolved obligation. A retained permit never authorizes replay.
#[derive(Default, Debug)]
#[must_use = "reconcile any started setup effect and retain its journal"]
pub struct Trace {
    started: bool,
    operation: Option<OperationId>,
    dispatch_started: bool,
    preparation_cancelled: bool,
    deadline_witness: Option<DeadlineWitness>,
    permit: Option<CommittedEffect>,
    response: Option<camera_api::HandoffResponseObservation>,
    profile: Option<Box<ProfilePreflight>>,
    listener_refusal: Option<controller_listener::ReadinessRefusal>,
}

#[derive(Clone, Debug)]
struct DeadlineWitness {
    task: fss_core::TaskId,
    region: fss_core::RegionId,
    preparation: ContentDigest,
    journal: EffectJournalPin,
    deadline: u64,
    observed: u64,
    stage: u8,
}

/// A refused evidence retention or cancellation. The digest identifies the
/// attempted content when it may have been staged; it is not a success receipt.
#[derive(Debug)]
pub struct DeadlineCancellationError {
    /// Exact payload-free failure category.
    pub reason: DeadlineCancellationFailure,
    /// Digest of bytes that may have been staged before refusal.
    pub evidence: Option<ContentDigest>,
}

/// Failure before a verified setup cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadlineCancellationFailure {
    /// The trace, prepared effect or journal head no longer matches.
    Stale,
    /// Task authority, clock or the storage capability refused the work.
    Authority,
    /// Encoding, staging, durable verification or byte comparison failed.
    Storage,
    /// The journal refused cancellation or its result is uncertain.
    Cancellation,
}
impl fmt::Display for DeadlineCancellationError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "setup deadline cancellation: {:?}", self.reason)
    }
}
impl std::error::Error for DeadlineCancellationError {}

#[derive(Debug)]
struct ProfilePreflight {
    limits: camera_api::VideoProfileLimits,
    selection: Option<camera_api::VideoProfileSelection>,
}
impl Trace {
    /// Most recent pre-effect listener readiness refusal for this unstarted
    /// trace. This is a local diagnostic and does not authenticate a camera.
    pub fn listener_refusal(&self) -> Option<controller_listener::ReadinessRefusal> {
        self.listener_refusal
    }
    /// Require a usable reported profile before preparing a handoff. The
    /// selection is a camera claim, not authority or proof of video delivery.
    /// Configure once, before a setup attempt starts; use a fresh trace for a
    /// separately authorized retry.
    pub fn require_reported_video(
        &mut self,
        limits: camera_api::VideoProfileLimits,
    ) -> Result<(), Error> {
        if self.started || self.profile.is_some() {
            return Err(Error::Configuration);
        }
        let missing = camera_api::VideoProfile {
            width: camera_api::VideoMetric::NotReported,
            height: camera_api::VideoMetric::NotReported,
            fps: camera_api::VideoMetric::NotReported,
        };
        camera_api::select_reported_video_profile([missing; 3], limits)
            .map_err(|_| Error::Configuration)?;
        self.profile = Some(Box::new(ProfilePreflight {
            limits,
            selection: None,
        }));
        Ok(())
    }
    /// Retained pre-effect ranking from the two consistent settings reads.
    pub fn preflight_video(&self) -> Option<camera_api::VideoProfileSelection> {
        self.profile.as_ref().and_then(|profile| profile.selection)
    }
    /// Whether a returned setup outcome still reports the same chosen profile.
    /// An unconfigured trace preserves the caller's existing routing policy.
    /// This comparison does not reconcile a handoff or establish identity.
    pub fn reported_video_matches(&self, outcome: &Outcome) -> bool {
        match &self.profile {
            None => true,
            Some(profile) => profile.selection.is_some_and(|before| {
                before.selected.is_some()
                    && outcome
                        .select_reported_video(profile.limits)
                        .ok()
                        .flatten()
                        .is_some_and(|after| after.selected == before.selected)
            }),
        }
    }
    /// The operation being prepared or committed, if setup reached that point.
    pub fn operation(&self) -> Option<&OperationId> {
        self.operation.as_ref()
    }
    /// Whether handoff dispatch was entered; it does not prove any bytes were sent.
    pub fn dispatch_started(&self) -> bool {
        self.dispatch_started
    }
    /// Whether this owner durably cancelled the exact preparation.
    pub fn preparation_cancelled(&self) -> bool {
        self.preparation_cancelled
    }
    /// Whether this attempt retained a durable pre-commit deadline observation.
    pub fn has_precommit_deadline(&self) -> bool {
        self.deadline_witness.is_some()
    }
    /// Retained committed permit, if it has not moved into an in-flight write.
    pub fn take_permit(&mut self) -> Option<CommittedEffect> {
        self.permit.take()
    }
    /// Payload-free response shape retained after the response was read.
    pub fn response(&self) -> Option<camera_api::HandoffResponseObservation> {
        self.response
    }
}

/// Setup results. A returned committed effect remains caller-owned and unsettled.
#[must_use]
#[derive(Debug)]
pub enum Outcome {
    /// The camera reported the requested address before any effect was prepared.
    /// This untrusted observation does not establish controller adoption.
    AlreadyAssociated {
        /// Original untrusted status shape.
        status: camera_api::StatusShape,
        /// Session-bound observation of the reported address.
        observation: camera_api::SettingsObservation,
    },
    /// A committed permit was refused before a dispatch attempt.
    Refused {
        /// Exact claimed refusal; it does not settle the journaled effect.
        reason: camera_api::HandoffError,
        /// Original permit retained for reconciliation.
        permit: CommittedEffect,
    },
    /// A write or observation was interrupted; never resend automatically.
    Indeterminate {
        /// Boundary at which the operation stopped.
        stage: Indeterminate,
        /// Untrusted response shape, when read before the interruption.
        response: Option<camera_api::HandoffResponseObservation>,
        /// Permit retained for independent reconciliation.
        permit: CommittedEffect,
    },
    /// The camera returned a readback claim, not authenticated adoption proof.
    Observed {
        /// Original untrusted status shape.
        status: camera_api::StatusShape,
        /// Untrusted response shape, not proof of the camera effect.
        response: camera_api::HandoffResponseObservation,
        /// Locally bound readback comparison.
        readback: handoff::Readback,
        /// Original readback claim; it does not settle the effect.
        observation: camera_api::SettingsObservation,
        /// Permit retained for independent reconciliation.
        permit: CommittedEffect,
    },
}

impl Outcome {
    /// Rank the video profiles in this outcome's camera-reported settings.
    /// Outcomes without a settings observation return `None`. A selection is
    /// only an untrusted claim: it does not settle a handoff permit, establish
    /// adoption, authenticate the camera, or authorize a stream request.
    pub fn select_reported_video(
        &self,
        limits: camera_api::VideoProfileLimits,
    ) -> Result<Option<camera_api::VideoProfileSelection>, camera_api::Error> {
        let observation = match self {
            Self::AlreadyAssociated { observation, .. } | Self::Observed { observation, .. } => {
                observation
            }
            Self::Refused { .. } | Self::Indeterminate { .. } => return Ok(None),
        };
        camera_api::select_reported_video_profile(observation.video_profiles, limits).map(Some)
    }
}

/// Caller-owned setup and accept state. A returned setup outcome remains here
/// even if accepting the connection times out or its future is dropped.
#[derive(Default, Debug)]
#[must_use = "retain the setup outcome and reconcile any committed effect"]
pub struct AcceptTrace {
    started: bool,
    setup: Trace,
    outcome: Option<Outcome>,
    accept_started: bool,
}
impl AcceptTrace {
    /// Require a complete in-bounds camera-reported video profile before any
    /// handoff effect is prepared. This untrusted claim does not grant stream
    /// authority or establish camera identity, codec support, or delivery.
    /// Configure this once, before entering setup; a used trace cannot be rearmed.
    pub fn require_reported_video(
        &mut self,
        limits: camera_api::VideoProfileLimits,
    ) -> Result<(), Error> {
        if self.started {
            return Err(Error::Configuration);
        }
        self.setup.require_reported_video(limits)
    }
    /// The pre-effect ranking, if two consistent settings reads reached it.
    /// A returned selection remains a camera claim, not proof of media.
    pub fn preflight_video(&self) -> Option<camera_api::VideoProfileSelection> {
        self.setup.preflight_video()
    }
    /// The tracked setup attempt, including any retained permit.
    pub fn setup_mut(&mut self) -> &mut Trace {
        &mut self.setup
    }
    /// Whether controller accept was entered, not proof of connection.
    pub fn accept_started(&self) -> bool {
        self.accept_started
    }
    /// The untrusted setup outcome, retained even after accept failure.
    pub fn outcome(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }
    /// Transfer the original outcome and its permit for reconciliation.
    pub fn take_outcome(&mut self) -> Option<Outcome> {
        self.outcome.take()
    }
}

/// A peer socket, subject to the same listener policy on every I/O poll.
/// A caller must still perform TLS and independently verify identity.
pub struct Accepted<'scope, 'task, 'policy> {
    /// Metered, guarded raw socket. This is not an authenticated session.
    pub io: super::metered::MeteredIo<
        'scope,
        'task,
        controller_listener::GuardedIo<'policy, TcpStream>,
    >,
    /// Apply this same connection gate above TLS before reading or writing.
    pub gate: controller_listener::AdmissionGate<'policy>,
}

/// Failure to complete the setup-to-accept transition.
#[derive(Debug)]
pub enum AcceptError {
    /// Invalid accept bounds or a previously used trace.
    Configuration,
    /// Setup stopped; trace retains any interrupted setup state.
    Setup(Error),
    /// The response or settings do not permit even an untrusted accept attempt.
    Unconfirmed,
    /// Listener acceptance failed; the setup outcome remains in the trace.
    Listener(super::listener::Error),
    /// Accepted source differed from the selected discovery claim.
    PeerMismatch,
}

/// Two matching read-only observations of one discovered camera.
///
/// The camera's claims and discovery identity remain untrusted; this does not
/// prove adoption, authorize a handoff, or settle any previous effect.
#[derive(Debug)]
pub struct Observation {
    /// The camera's status response shape.
    pub status: camera_api::StatusShape,
    /// The matching camera-local controller claim and session binding.
    pub settings: camera_api::SettingsObservation,
}

/// Task resources and policies for the setup attempt.
pub struct Owner<'a, 'scope, 'task> {
    /// Runtime context and canonical registered task.
    pub cx: &'scope Cx,
    /// Same task that owns the camera transport.
    pub task: &'scope TaskCx<'task>,
    /// Shared task-bound monotonic clock.
    pub clock: MeteredClock<'scope, 'task>,
    /// Durable effect coordinator. Calls may synchronously block.
    pub effects: &'a mut EffectCoordinator,
    /// Live lease registry for preparation and commit.
    pub leases: &'a RefCell<LeaseRegistry>,
    /// Current approval for the exact prepared effect.
    pub approval: &'a dyn conversation::Approval,
    /// Independent candidate and identity admission.
    pub admission: &'a dyn Admission,
    /// Live handoff authority, rechecked on every write poll.
    pub handoff_authority: &'a dyn camera_api::HandoffAuthority,
}

impl Owner<'_, '_, '_> {
    fn precommit_remaining(
        &self,
        trace: &mut Trace,
        prepared: &PreparedEffect,
        deadline: u64,
        stage: u8,
    ) -> Result<(), Error> {
        self.cx.checkpoint().map_err(|_| Error::Denied)?;
        let observed = self.cx.now().as_nanos();
        if observed < deadline {
            return Ok(());
        }
        if !self.effects.persistence_needs_recovery()
            && let Some(journal) = self.effects.durable_pin()
        {
            trace.deadline_witness = Some(DeadlineWitness {
                task: self.task.task_id().clone(),
                region: self.task.region().clone(),
                preparation: prepared.digest(),
                journal,
                deadline,
                observed,
                stage,
            });
        }
        Err(Error::Deadline)
    }

    /// Retain and verify a locally observed pre-commit deadline, then cancel
    /// its exact prepared handoff. This does not prove independent custody or
    /// authorize retry. Both storage and journal I/O may synchronously block.
    pub fn retain_and_cancel_deadline(
        &mut self,
        trace: &mut Trace,
        spool: &mut StagingSpool,
        storage_resource: &str,
    ) -> Result<ContentDigest, DeadlineCancellationError> {
        let fail = |reason, evidence| DeadlineCancellationError { reason, evidence };
        let witness = trace
            .deadline_witness
            .as_ref()
            .ok_or_else(|| fail(DeadlineCancellationFailure::Stale, None))?;
        let operation = trace
            .operation
            .as_ref()
            .ok_or_else(|| fail(DeadlineCancellationFailure::Stale, None))?;
        let prepared = self
            .effects
            .prepared(operation)
            .ok_or_else(|| fail(DeadlineCancellationFailure::Stale, None))?;
        if !trace.started
            || !self.clock.matches(self.task, self.cx)
            || &witness.task != self.task.task_id()
            || &witness.region != self.task.region()
            || trace.preparation_cancelled
            || trace.dispatch_started
            || trace.permit.is_some()
            || self.effects.persistence_needs_recovery()
            || self.effects.durable_pin() != Some(witness.journal)
            || prepared.digest() != witness.preparation
            || self.effects.state(&prepared).ok() != Some(fss_core::EffectState::Prepared)
            || witness.observed < witness.deadline
        {
            return Err(fail(DeadlineCancellationFailure::Stale, None));
        }
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DEADLINE_EVIDENCE_DOMAIN);
        encoder.text(operation.as_str());
        encoder.text(witness.task.as_str());
        encoder.text(witness.region.as_str());
        encoder.digest(witness.preparation);
        encoder.u64(witness.journal.sequence);
        encoder.digest(witness.journal.root);
        encoder.u64(witness.deadline);
        encoder.u64(witness.observed);
        encoder.u8(witness.stage);
        let bytes = encoder
            .finish_checked()
            .map_err(|_| fail(DeadlineCancellationFailure::Storage, None))?;
        let digest = ContentDigest::sha256(&bytes);
        let now = self
            .clock
            .now()
            .map_err(|_| fail(DeadlineCancellationFailure::Authority, None))?;
        let mut cost = BudgetVector::ZERO;
        cost.bytes = u64::try_from(bytes.len())
            .map_err(|_| fail(DeadlineCancellationFailure::Storage, None))?;
        self.task
            .checkpoint_for(RuntimeGrant::ObjectStage, storage_resource, now, &cost)
            .map_err(|_| fail(DeadlineCancellationFailure::Authority, None))?;
        let receipt = spool
            .stage(digest, &bytes)
            .map_err(|_| fail(DeadlineCancellationFailure::Storage, Some(digest)))?;
        if receipt.digest != digest {
            return Err(fail(DeadlineCancellationFailure::Storage, Some(digest)));
        }
        let (state, readback) = spool
            .verify_and_read(digest)
            .map_err(|_| fail(DeadlineCancellationFailure::Storage, Some(digest)))?;
        if state != SpoolObjectState::Verified || readback != bytes {
            return Err(fail(DeadlineCancellationFailure::Storage, Some(digest)));
        }
        self.cancel_prepared_effect(trace, digest)
            .map_err(|_| fail(DeadlineCancellationFailure::Cancellation, Some(digest)))?;
        Ok(digest)
    }

    /// Cancel this task's undispatched setup preparation using retained evidence.
    ///
    /// A committed or dispatched handoff cannot be cancelled through this
    /// method. The caller must retain and validate the evidence, dispose of
    /// the camera session, and independently decide whether another attempt
    /// is authorized. This operation may synchronously block on storage.
    pub fn cancel_prepared_effect(
        &mut self,
        trace: &mut Trace,
        evidence: ContentDigest,
    ) -> Result<(), Error> {
        if !trace.started
            || trace.dispatch_started
            || trace.preparation_cancelled
            || trace.permit.is_some()
            || trace.response.is_some()
            || !self.clock.matches(self.task, self.cx)
        {
            return Err(Error::Configuration);
        }
        let operation = trace.operation.as_ref().ok_or(Error::Configuration)?;
        let prepared = self.effects.prepared(operation).ok_or(Error::Effect)?;
        let now = self.clock.now().map_err(|_| Error::Denied)?;
        self.task
            .cancel_prepared_effect(self.cx, self.effects, prepared, evidence, now)
            .map_err(|_| Error::Effect)?;
        trace.preparation_cancelled = true;
        Ok(())
    }
}

struct ReadyAdmission<'a, 'listener_scope, 'listener_task, 'policy, 'scope, 'task> {
    inner: &'a dyn Admission,
    listener: &'a controller_listener::Listener<'listener_scope, 'listener_task, 'policy>,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    resource: &'a str,
    endpoint: SocketAddrV4,
}
impl Admission for ReadyAdmission<'_, '_, '_, '_, '_, '_> {
    fn permits(
        &self,
        candidate: &discovery::CameraCandidate,
        camera: ContentDigest,
        peer_admission: ContentDigest,
        generation: u64,
        fence: u64,
    ) -> bool {
        self.listener.ready_for(
            self.task,
            self.cx,
            &self.clock,
            self.resource,
            self.endpoint,
            *candidate.source().ip(),
        ) && self
            .inner
            .permits(candidate, camera, peer_admission, generation, fence)
    }
}

struct Guard<'a> {
    admission: &'a dyn Admission,
    inner: &'a dyn camera_api::HandoffAuthority,
    candidate: &'a discovery::CameraCandidate,
    camera: ContentDigest,
    peer_admission: ContentDigest,
    generation: u64,
    fence: u64,
}
impl Guard<'_> {
    fn current(&self) -> bool {
        self.admission.permits(
            self.candidate,
            self.camera,
            self.peer_admission,
            self.generation,
            self.fence,
        )
    }
}
impl camera_api::HandoffAuthority for Guard<'_> {
    fn permits(
        &self,
        plan: &handoff::Plan,
        current: handoff::Preconditions,
        permit: &CommittedEffect,
    ) -> bool {
        self.current() && self.inner.permits(plan, current, permit)
    }
}
fn remaining(cx: &Cx, deadline: u64) -> Result<Duration, Error> {
    cx.checkpoint().map_err(|_| Error::Denied)?;
    let ns = deadline
        .checked_sub(cx.now().as_nanos())
        .filter(|v| *v > 0)
        .ok_or(Error::Deadline)?;
    Ok(Duration::from_nanos(ns))
}
fn valid_destination(ip: Ipv4Addr) -> bool {
    (ip.is_private() || ip.is_link_local())
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
}
fn valid_digest(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256
        && !digest.is_laboratory()
        && digest.bytes() != [0; 32]
}
fn valid_claims(report: &discovery::Report, index: usize) -> bool {
    report.valid_completed()
        && report
            .assess_claims(index)
            .is_some_and(|v| v == discovery::ClaimAssessment::default())
}

impl Owner<'_, '_, '_> {
    /// Set up an admitted candidate and accept its controller connection on
    /// the same pre-bound listener. This does not authenticate the accepted
    /// peer, drive TLS or WebSocket, settle the effect, or retry a handoff.
    /// A caller-owned trace preserves the result across an interrupted accept.
    /// A previous-controller readback permits waiting for a connection, but
    /// the committed handoff remains unresolved and must be reconciled.
    pub async fn setup_and_accept<'scope, 'task, 'policy, IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        listener: &mut controller_listener::Listener<'scope, 'task, 'policy>,
        expected_port: u16,
        camera: &mut camera_http::Owner<'_, '_, '_, IO>,
        cfg: &Config<'_>,
        framing: handoff::Framing,
        max_poll: usize,
        accept_wait: Duration,
        trace: &mut AcceptTrace,
    ) -> Result<Accepted<'scope, 'task, 'policy>, AcceptError> {
        if trace.started
            || !(1..=super::metered::MAX_POLL_BYTES).contains(&max_poll)
            || accept_wait.is_zero()
            || accept_wait > MAX_WAIT
        {
            return Err(AcceptError::Configuration);
        }
        trace.started = true;
        let outcome = self
            .run_when_listening_tracked(
                listener,
                expected_port,
                camera,
                cfg,
                framing,
                &mut trace.setup,
            )
            .await
            .map_err(AcceptError::Setup)?;
        let eligible_for_accept = match &outcome {
            Outcome::AlreadyAssociated { .. } => true,
            Outcome::Observed {
                readback: handoff::Readback::Requested | handoff::Readback::Previous,
                response,
                ..
            } => !matches!(
                response,
                camera_api::HandoffResponseObservation::Object {
                    success: Some(false),
                    ..
                }
            ),
            _ => false,
        };
        trace.outcome = Some(outcome);
        if !eligible_for_accept {
            return Err(AcceptError::Unconfirmed);
        }
        trace.accept_started = true;
        let (io, gate) = listener
            .accept_next(max_poll, accept_wait)
            .await
            .map_err(AcceptError::Listener)?;
        if cfg
            .report
            .cameras
            .get(cfg.index)
            .is_none_or(|candidate| candidate.source().ip() != gate.source().ip())
        {
            return Err(AcceptError::PeerMismatch);
        }
        Ok(Accepted { io, gate })
    }

    /// Observe one admitted discovered camera without preparing or sending a
    /// management effect. Settings are read twice and must agree.
    pub async fn observe<IO: AsyncRead + AsyncWrite + Unpin>(
        &self,
        camera: &mut camera_http::Owner<'_, '_, '_, IO>,
        cfg: &Config<'_>,
    ) -> Result<Observation, Error> {
        if cfg.wait.is_zero()
            || cfg.wait > MAX_WAIT
            || cfg.generation == 0
            || cfg.fence == 0
            || !valid_digest(cfg.camera)
            || !valid_digest(cfg.peer_admission)
            || !self.clock.matches(self.task, self.cx)
            || camera.phase() != camera_api::Phase::Login
        {
            return Err(Error::Configuration);
        }
        let candidate = cfg
            .report
            .cameras
            .get(cfg.index)
            .ok_or(Error::Configuration)?;
        if !valid_claims(cfg.report, cfg.index) {
            return Err(Error::Claims);
        }
        let resource = format!("camera:{}", cfg.camera.to_text());
        if !camera.matches_setup(
            self.task,
            self.cx,
            self.clock,
            *candidate.source().ip(),
            cfg.generation,
            &resource,
        ) {
            return Err(Error::Configuration);
        }
        let admitted = || {
            self.admission.permits(
                candidate,
                cfg.camera,
                cfg.peer_admission,
                cfg.generation,
                cfg.fence,
            )
        };
        if !admitted() {
            return Err(Error::Denied);
        }
        let deadline = self
            .cx
            .now()
            .as_nanos()
            .checked_add(u64::try_from(cfg.wait.as_nanos()).map_err(|_| Error::Configuration)?)
            .ok_or(Error::Configuration)?;
        camera
            .login(cfg.credential, remaining(self.cx, deadline)?)
            .await
            .map_err(Error::Camera)?;
        if !admitted() {
            return Err(Error::Denied);
        }
        let status = camera
            .status(remaining(self.cx, deadline)?)
            .await
            .map_err(Error::Camera)?;
        if !admitted() {
            return Err(Error::Denied);
        }
        let settings = camera
            .settings(remaining(self.cx, deadline)?)
            .await
            .map_err(Error::Camera)?;
        if !admitted() {
            return Err(Error::Denied);
        }
        let fresh = camera
            .settings(remaining(self.cx, deadline)?)
            .await
            .map_err(Error::Camera)?;
        if !admitted() {
            return Err(Error::Denied);
        }
        if fresh != settings {
            return Err(Error::Changed);
        }
        let binding = camera_api::controller_binding(
            settings.controller,
            *candidate.source().ip(),
            cfg.generation,
        )
        .map_err(|_| Error::Configuration)?;
        if settings.binding != binding {
            return Err(Error::Configuration);
        }
        Ok(Observation { status, settings })
    }

    /// Orchestrate one explicitly authorized candidate through journaled
    /// handoff and readback. No retry is performed after an indeterminate write.
    /// Dropping this future after preparation or commit leaves durable journal
    /// obligations for reconciliation, even if no outcome is returned.
    /// This entry point does not check that a listener exists or that its port
    /// matches the camera's status claim; use [`Self::run_when_listening`] when
    /// the caller owns the target listener.
    pub async fn run<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        camera: &mut camera_http::Owner<'_, '_, '_, IO>,
        cfg: &Config<'_>,
    ) -> Result<Outcome, Error> {
        self.run_with_framing(camera, cfg, handoff::Framing::ContentLength)
            .await
    }

    /// Run one setup attempt while retaining the already-bound controller
    /// listener. The caller supplies the camera's expected controller port;
    /// the exact task, clock, resource, destination and live listener policy
    /// are rechecked throughout the handoff and every dispatch poll. The
    /// camera's untrusted status must report that port before a write is
    /// prepared. This observation can become stale; keeping the socket bound
    /// does not establish peer identity or reachability.
    /// The borrowed listener remains caller-owned on every return or drop.
    pub async fn run_when_listening<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        listener: &controller_listener::Listener<'_, '_, '_>,
        expected_port: u16,
        camera: &mut camera_http::Owner<'_, '_, '_, IO>,
        cfg: &Config<'_>,
        framing: handoff::Framing,
    ) -> Result<Outcome, Error> {
        let mut trace = Trace::default();
        self.run_when_listening_tracked(listener, expected_port, camera, cfg, framing, &mut trace)
            .await
    }

    /// Listener-bound setup with caller-owned custody across cancellation.
    /// A trace is single-use and must outlive the future.
    pub async fn run_when_listening_tracked<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        listener: &controller_listener::Listener<'_, '_, '_>,
        expected_port: u16,
        camera: &mut camera_http::Owner<'_, '_, '_, IO>,
        cfg: &Config<'_>,
        framing: handoff::Framing,
        trace: &mut Trace,
    ) -> Result<Outcome, Error> {
        let resource = format!("camera:{}", cfg.camera.to_text());
        let endpoint = SocketAddrV4::new(cfg.destination, expected_port);
        let peer = *cfg
            .report
            .cameras
            .get(cfg.index)
            .ok_or(Error::Configuration)?
            .source()
            .ip();
        let readiness =
            listener.readiness(self.task, self.cx, &self.clock, &resource, endpoint, peer);
        if !trace.started {
            trace.listener_refusal = readiness.err();
        }
        if readiness.is_err() {
            return Err(Error::ControllerUnavailable);
        }
        let admitted = ReadyAdmission {
            inner: self.admission,
            listener,
            task: self.task,
            cx: self.cx,
            clock: self.clock,
            resource: &resource,
            endpoint,
        };
        let mut owner = Owner {
            cx: self.cx,
            task: self.task,
            clock: self.clock,
            effects: &mut *self.effects,
            leases: self.leases,
            approval: self.approval,
            admission: &admitted,
            handoff_authority: self.handoff_authority,
        };
        owner
            .run_inner(camera, cfg, framing, Some(expected_port), trace)
            .await
    }

    /// Run setup with an explicit framing choice bound to the prepared effect.
    /// An indeterminate write is never retried using another framing mode.
    /// This lower-level entry point does not validate a controller listener
    /// or compare its port with camera status.
    pub async fn run_with_framing<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        camera: &mut camera_http::Owner<'_, '_, '_, IO>,
        cfg: &Config<'_>,
        framing: handoff::Framing,
    ) -> Result<Outcome, Error> {
        let mut trace = Trace::default();
        self.run_with_framing_tracked(camera, cfg, framing, &mut trace)
            .await
    }

    /// Lower-level setup with caller-owned custody across cancellation.
    /// This does not check a controller listener or port.
    pub async fn run_with_framing_tracked<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        camera: &mut camera_http::Owner<'_, '_, '_, IO>,
        cfg: &Config<'_>,
        framing: handoff::Framing,
        trace: &mut Trace,
    ) -> Result<Outcome, Error> {
        self.run_inner(camera, cfg, framing, None, trace).await
    }

    async fn run_inner<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        camera: &mut camera_http::Owner<'_, '_, '_, IO>,
        cfg: &Config<'_>,
        framing: handoff::Framing,
        expected_port: Option<u16>,
        trace: &mut Trace,
    ) -> Result<Outcome, Error> {
        if trace.started
            || trace.operation.is_some()
            || cfg.wait.is_zero()
            || cfg.wait > MAX_WAIT
            || cfg.generation == 0
            || cfg.fence == 0
            || !valid_digest(cfg.camera)
            || !valid_digest(cfg.peer_admission)
            || !valid_destination(cfg.destination)
            || !self.clock.matches(self.task, self.cx)
            || camera.phase() != camera_api::Phase::Login
        {
            return Err(Error::Configuration);
        }
        trace.started = true;
        let candidate = cfg
            .report
            .cameras
            .get(cfg.index)
            .ok_or(Error::Configuration)?;
        if !valid_claims(cfg.report, cfg.index) {
            return Err(Error::Claims);
        }
        let resource = format!("camera:{}", cfg.camera.to_text());
        if !camera.matches_setup(
            self.task,
            self.cx,
            self.clock,
            *candidate.source().ip(),
            cfg.generation,
            &resource,
        ) {
            return Err(Error::Configuration);
        }
        let guard = Guard {
            admission: self.admission,
            inner: self.handoff_authority,
            candidate,
            camera: cfg.camera,
            peer_admission: cfg.peer_admission,
            generation: cfg.generation,
            fence: cfg.fence,
        };
        if !guard.current() {
            return Err(Error::Denied);
        }
        let deadline = self
            .cx
            .now()
            .as_nanos()
            .checked_add(u64::try_from(cfg.wait.as_nanos()).map_err(|_| Error::Configuration)?)
            .ok_or(Error::Configuration)?;
        camera
            .login(cfg.credential, remaining(self.cx, deadline)?)
            .await
            .map_err(Error::Camera)?;
        if !guard.current() {
            return Err(Error::Denied);
        }
        let status = camera
            .status(remaining(self.cx, deadline)?)
            .await
            .map_err(Error::Camera)?;
        if !guard.current() {
            return Err(Error::Denied);
        }
        if expected_port.is_some_and(|port| {
            status.controller_port != camera_api::ControllerPort::Reported(port)
        }) {
            return Err(Error::ControllerPort);
        }
        let before = camera
            .settings(remaining(self.cx, deadline)?)
            .await
            .map_err(Error::Camera)?;
        if !guard.current() {
            return Err(Error::Denied);
        }
        let fresh = camera
            .settings(remaining(self.cx, deadline)?)
            .await
            .map_err(Error::Camera)?;
        if !guard.current() {
            return Err(Error::Denied);
        }
        if fresh != before {
            return Err(Error::Changed);
        }
        if let Some(profile) = &mut trace.profile {
            let selection =
                camera_api::select_reported_video_profile(before.video_profiles, profile.limits)
                    .map_err(|_| Error::Configuration)?;
            profile.selection = Some(selection);
            if selection.selected.is_none() {
                return Err(Error::VideoProfileUnavailable);
            }
        }
        if before.controller == camera_api::ControllerAddress::Reported(cfg.destination) {
            let expected = camera_api::controller_binding(
                before.controller,
                *candidate.source().ip(),
                cfg.generation,
            )
            .map_err(|_| Error::Configuration)?;
            if expected.is_none() || before.binding != expected {
                return Err(Error::Configuration);
            }
            return Ok(Outcome::AlreadyAssociated {
                status,
                observation: before,
            });
        }
        let conditions = handoff::Preconditions {
            camera: cfg.camera,
            peer_admission: cfg.peer_admission,
            session_generation: cfg.generation,
            lease_fence: cfg.fence,
            settings: before,
        };
        let mut plan = handoff::Plan::new_with_framing(
            *candidate.source().ip(),
            cfg.destination,
            conditions,
            framing,
        )
        .map_err(Error::Plan)?;
        if let Some(port) = expected_port {
            plan = plan
                .bind_reported_controller_port(status, port)
                .map_err(Error::Plan)?;
        }
        let key =
            IdempotencyKey::parse(cfg.operation.as_str()).map_err(|_| Error::Configuration)?;
        trace.operation = Some(cfg.operation.clone());
        remaining(self.cx, deadline)?;
        let now = self.clock.now().map_err(|_| Error::Denied)?;
        let prepared = self
            .task
            .prepare_effect(
                self.cx,
                self.effects,
                &mut self.leases.borrow_mut(),
                PrepareSpec {
                    operation: cfg.operation,
                    idempotency_key: key,
                    request_digest: plan.request_digest(),
                    precondition_digest: plan.precondition_digest(),
                    resource: &resource,
                    fence: cfg.fence,
                    prepare_grant: RuntimeGrant::CameraManagementPrepare,
                    commit_grant: RuntimeGrant::CameraManagementCommit,
                    terminal_predicate: "independent association observation or reconciliation",
                },
                now,
            )
            .map_err(|_| Error::Effect)?;
        self.precommit_remaining(trace, &prepared, deadline, 1)?;
        let approval = self.approval.approve(&prepared).ok_or(Error::Effect)?;
        if !guard.current() {
            return Err(Error::Denied);
        }
        self.precommit_remaining(trace, &prepared, deadline, 2)?;
        let now = self.clock.now().map_err(|_| Error::Denied)?;
        self.precommit_remaining(trace, &prepared, deadline, 3)?;
        let permit = self
            .task
            .commit_effect(
                self.cx,
                self.effects,
                &mut self.leases.borrow_mut(),
                prepared,
                now,
                approval,
            )
            .map_err(|_| Error::Effect)?;
        trace.permit = Some(permit);
        let wait = match remaining(self.cx, deadline) {
            Ok(wait) if guard.current() => wait,
            _ => {
                return Ok(Outcome::Indeterminate {
                    stage: Indeterminate::AuthorityOrDeadline,
                    response: None,
                    permit: trace.permit.take().ok_or(Error::Effect)?,
                });
            }
        };
        trace.dispatch_started = true;
        let permit = trace.permit.take().ok_or(Error::Effect)?;
        let permit = match camera
            .dispatch_handoff(&plan, conditions, permit, &guard, wait)
            .await
        {
            Err(refusal) => {
                return Ok(Outcome::Refused {
                    reason: refusal.reason,
                    permit: refusal.permit,
                });
            }
            Ok(camera_api::HandoffWrite::Indeterminate { permit }) => {
                return Ok(Outcome::Indeterminate {
                    stage: Indeterminate::Write,
                    response: None,
                    permit,
                });
            }
            Ok(camera_api::HandoffWrite::Written { permit }) => permit,
        };
        trace.permit = Some(permit);
        let wait = match remaining(self.cx, deadline) {
            Ok(wait) if guard.current() => wait,
            _ => {
                return Ok(Outcome::Indeterminate {
                    stage: Indeterminate::AuthorityOrDeadline,
                    response: None,
                    permit: trace.permit.take().ok_or(Error::Effect)?,
                });
            }
        };
        let response = match camera
            .read_handoff_response_observed(trace.permit.as_ref().ok_or(Error::Effect)?, wait)
            .await
        {
            Ok(response) => response,
            Err(_) => {
                return Ok(Outcome::Indeterminate {
                    stage: Indeterminate::Response,
                    response: None,
                    permit: trace.permit.take().ok_or(Error::Effect)?,
                });
            }
        };
        trace.response = Some(response);
        let wait = match remaining(self.cx, deadline) {
            Ok(wait) if guard.current() => wait,
            _ => {
                return Ok(Outcome::Indeterminate {
                    stage: Indeterminate::AuthorityOrDeadline,
                    response: Some(response),
                    permit: trace.permit.take().ok_or(Error::Effect)?,
                });
            }
        };
        let observation = match camera.settings(wait).await {
            Ok(value) => value,
            Err(_) => {
                return Ok(Outcome::Indeterminate {
                    stage: Indeterminate::Readback,
                    response: Some(response),
                    permit: trace.permit.take().ok_or(Error::Effect)?,
                });
            }
        };
        if !guard.current() {
            return Ok(Outcome::Indeterminate {
                stage: Indeterminate::AuthorityOrDeadline,
                response: Some(response),
                permit: trace.permit.take().ok_or(Error::Effect)?,
            });
        }
        let readback = match plan.classify_readback(observation) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Outcome::Indeterminate {
                    stage: Indeterminate::Readback,
                    response: Some(response),
                    permit: trace.permit.take().ok_or(Error::Effect)?,
                });
            }
        };
        Ok(Outcome::Observed {
            status,
            response,
            readback,
            observation,
            permit: trace.permit.take().ok_or(Error::Effect)?,
        })
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    use camera_api::{
        ControllerAddress, ControllerPort, SettingsObservation, StatusShape, VideoDestinationShape,
        VideoMetric, VideoProfile,
    };

    #[test]
    fn preflight_match_fences_changed_or_missing_readback() {
        let limits = camera_api::VideoProfileLimits {
            max_width: 4096,
            max_height: 2304,
            min_fps: 1,
            max_fps: 60,
            max_pixels_per_second: 4096 * 2304 * 60,
        };
        let missing = VideoProfile {
            width: VideoMetric::NotReported,
            height: VideoMetric::NotReported,
            fps: VideoMetric::NotReported,
        };
        let high = VideoProfile {
            width: VideoMetric::Reported(2688),
            height: VideoMetric::Reported(1512),
            fps: VideoMetric::Reported(30),
        };
        let low = VideoProfile {
            width: VideoMetric::Reported(1280),
            height: VideoMetric::Reported(720),
            fps: VideoMetric::Reported(30),
        };
        let observation = SettingsObservation {
            controller: ControllerAddress::Missing,
            binding: None,
            video_destinations: [VideoDestinationShape::NotReported; 3],
            video_profiles: [high, low, missing],
            snapshot_profile: missing,
        };
        let status = StatusShape {
            board: true,
            firmware: true,
            controller: true,
            controller_port: ControllerPort::Reported(7442),
        };
        let outcome = Outcome::AlreadyAssociated {
            status,
            observation,
        };
        let mut trace = Trace::default();
        assert!(trace.reported_video_matches(&outcome));
        trace.require_reported_video(limits).unwrap();
        assert!(!trace.reported_video_matches(&outcome));
        trace.profile.as_mut().unwrap().selection = Some(
            camera_api::select_reported_video_profile(observation.video_profiles, limits).unwrap(),
        );
        assert!(trace.reported_video_matches(&outcome));
        let changed = Outcome::AlreadyAssociated {
            status,
            observation: SettingsObservation {
                video_profiles: [low, low, missing],
                ..observation
            },
        };
        assert!(!trace.reported_video_matches(&changed));
        let absent = Outcome::AlreadyAssociated {
            status,
            observation: SettingsObservation {
                video_profiles: [missing; 3],
                ..observation
            },
        };
        assert!(!trace.reported_video_matches(&absent));
        trace.started = true;
        assert!(matches!(
            trace.require_reported_video(limits),
            Err(Error::Configuration)
        ));
    }
}
