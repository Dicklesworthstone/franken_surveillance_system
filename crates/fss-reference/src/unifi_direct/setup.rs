#![forbid(unsafe_code)]
//! Experimental one-candidate discovery-to-controller handoff orchestration.
//!
//! The candidate remains untrusted. The caller supplies an already admitted
//! camera transport, credentials, a current independent identity/lease policy,
//! an existing effect journal, and an authorized controller destination. This
//! module does not perform Wi-Fi provisioning, establish TLS identity, run the
//! controller, settle the effect, or guarantee recording continuity. Journal
//! operations are synchronous and unsuitable for a latency-sensitive reactor.

use super::{camera_api, camera_http, conversation, discovery, handoff, metered::MeteredClock};
use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_core::{ContentDigest, DigestAlgorithm, IdempotencyKey, OperationId, RuntimeGrant};
use fss_runtime::{
    effect::{CommittedEffect, EffectCoordinator, PrepareSpec},
    execution::TaskCx,
    lease::LeaseRegistry,
};
use std::{cell::RefCell, fmt, net::Ipv4Addr, time::Duration};

const MAX_WAIT: Duration = Duration::from_secs(30);

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
    report.stop == discovery::Stop::WindowElapsed
        && report
            .assess_claims(index)
            .is_some_and(|v| v == discovery::ClaimAssessment::default())
}

impl Owner<'_, '_, '_> {
    /// Orchestrate one explicitly authorized candidate through journaled
    /// handoff and readback. No retry is performed after an indeterminate write.
    /// Dropping this future after preparation or commit leaves durable journal
    /// obligations for reconciliation, even if no outcome is returned.
    pub async fn run<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        camera: &mut camera_http::Owner<'_, '_, '_, IO>,
        cfg: &Config<'_>,
    ) -> Result<Outcome, Error> {
        if cfg.wait.is_zero()
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
        let before = camera
            .settings(remaining(self.cx, deadline)?)
            .await
            .map_err(Error::Camera)?;
        if !guard.current() {
            return Err(Error::Denied);
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
        let plan = handoff::Plan::new(*candidate.source().ip(), cfg.destination, conditions)
            .map_err(Error::Plan)?;
        let key =
            IdempotencyKey::parse(cfg.operation.as_str()).map_err(|_| Error::Configuration)?;
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
        let approval = self.approval.approve(&prepared).ok_or(Error::Effect)?;
        if !guard.current() {
            return Err(Error::Denied);
        }
        remaining(self.cx, deadline)?;
        let now = self.clock.now().map_err(|_| Error::Denied)?;
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
        let wait = match remaining(self.cx, deadline) {
            Ok(wait) if guard.current() => wait,
            _ => {
                return Ok(Outcome::Indeterminate {
                    stage: Indeterminate::AuthorityOrDeadline,
                    response: None,
                    permit,
                });
            }
        };
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
        let wait = match remaining(self.cx, deadline) {
            Ok(wait) if guard.current() => wait,
            _ => {
                return Ok(Outcome::Indeterminate {
                    stage: Indeterminate::AuthorityOrDeadline,
                    response: None,
                    permit,
                });
            }
        };
        let response = match camera.read_handoff_response_observed(&permit, wait).await {
            Ok(response) => response,
            Err(_) => {
                return Ok(Outcome::Indeterminate {
                    stage: Indeterminate::Response,
                    response: None,
                    permit,
                });
            }
        };
        let wait = match remaining(self.cx, deadline) {
            Ok(wait) if guard.current() => wait,
            _ => {
                return Ok(Outcome::Indeterminate {
                    stage: Indeterminate::AuthorityOrDeadline,
                    response: Some(response),
                    permit,
                });
            }
        };
        let observation = match camera.settings(wait).await {
            Ok(value) => value,
            Err(_) => {
                return Ok(Outcome::Indeterminate {
                    stage: Indeterminate::Readback,
                    response: Some(response),
                    permit,
                });
            }
        };
        if !guard.current() {
            return Ok(Outcome::Indeterminate {
                stage: Indeterminate::AuthorityOrDeadline,
                response: Some(response),
                permit,
            });
        }
        let readback = match plan.classify_readback(observation) {
            Ok(value) => value,
            Err(_) => {
                return Ok(Outcome::Indeterminate {
                    stage: Indeterminate::Readback,
                    response: Some(response),
                    permit,
                });
            }
        };
        Ok(Outcome::Observed {
            status,
            response,
            readback,
            observation,
            permit,
        })
    }
}
