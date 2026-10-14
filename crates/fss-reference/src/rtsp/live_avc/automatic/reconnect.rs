#![forbid(unsafe_code)]
//! Owner-driven reconnects around the existing native automatic AVC connection.
//!
//! No socket, request, password or recorder is shared across attempts. The owner
//! supplies each new configuration after retaining the previous terminal output.
//! Waiting is a timer/readiness contract, not a sleeping thread. A successful
//! connect/PLAY is not a freshness, continuity, capture-time or custody receipt.

/// Native HEVC recording supervision with distinct source-end and EOF semantics.
pub mod hevc;
/// The same reconnect grant composed with loss-aware recording and explicit timing.
pub mod recording;
/// Atomic whole-run reservations; connection retirement never replenishes capacity.
pub mod resources;

use resources::ReservationLedger;
pub use resources::{
    ReconnectBudget, ReconnectBudgetDimension, ReconnectBudgetRefusal, ReconnectBudgetState,
};
use std::fmt;
use std::io::ErrorKind;

use super::{AutomaticAvcConnection, AutomaticAvcStep};
use crate::rtsp::avc_client::AvcClientError;
use crate::rtsp::live_avc::{
    DigestAvcPoll, DigestCredentials, LiveAvcConfig, LiveAvcConnectFailure, LiveAvcError,
    LiveAvcRetirement, LiveAvcStep, SocketReadiness,
};
use crate::rtsp::tcp::{TcpAuthority, TcpBinding, TcpDenial, TcpError, TcpOperation};
use fss_packet::StreamKey;

/// Explicit finite supervision grant, independent of each connection's limits.
/// Native byte/call/work maxima are reserved across attempts. The authority must
/// still enforce live permission and actual elapsed time: an admission timestamp
/// is not a post-syscall clock observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconnectPolicy {
    /// Includes the first connection attempt; accepted range is 1..=1024.
    pub max_attempts: u32,
    /// Positive delay after the first recoverable terminal observation.
    pub initial_backoff_ns: u64,
    /// Positive ceiling on doubling backoff. Success never resets the budget.
    pub max_backoff_ns: u64,
    /// One absolute lease shared by every attempt and every backoff.
    pub deadline_ns: u64,
    /// Total connect/poll admissions, including idle polls, across all attempts.
    pub max_steps: u64,
}

/// Terminal supervision reasons; none authorizes another connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnectStop {
    /// Explicit local stop, including while no socket exists.
    Cancelled,
    /// Absolute lease expired or the next backoff cannot finish within it.
    Deadline,
    /// All explicitly allowed connection attempts were consumed.
    Attempts,
    /// Supervisor-wide work ceiling was exhausted.
    WorkBudget,
    /// Live owner denied admission. There is no retry through a denial.
    Denied(TcpDenial),
    /// Non-transient protocol, authentication, configuration or transport fault.
    PermanentFailure,
    /// Native bitstream end after capture draining; not an outage or permission to retry.
    SourceEnded,
}

/// Scheduling state only. Active never asserts that a camera is delivering frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnectStatus {
    /// Supply an exact new-generation configuration at/after this owner-clock time.
    Waiting {
        /// Fresh expected stream identity; the owner must grant this generation.
        key: StreamKey,
        /// Absolute timer; the owner must also honor earlier cancellation/revocation.
        retry_at_ns: u64,
    },
    /// Original terminal ownership was returned. The owner must retain it and
    /// acknowledge with a fresh clock observation before any backoff is scheduled.
    Retired(StreamKey),
    /// Exactly one connection owns this generation.
    Active(StreamKey),
    /// Irreversible for this supervisor. Constructing a new one needs a new grant.
    Stopped(ReconnectStop),
}

/// Safe refusal or irreversible local stop. Contains no route or credential text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconnectRefusal {
    /// Invalid finite grant or generation range would overflow.
    Configuration,
    /// Owner time regressed; existing ownership and budgets remain unchanged.
    ClockReversed,
    /// A connection still owns the previous generation.
    Active,
    /// Backoff has not elapsed; no connection was attempted.
    NotReady,
    /// Retain the original terminal output and acknowledge retirement first.
    AwaitingRetirement,
    /// There is no terminal generation to acknowledge.
    NoRetirement,
    /// Changed route, generation, presentation, realm, media profile or widened ceilings.
    Scope,
    /// The proposed complete connection allowance could not be reserved.
    /// No socket or attempt was admitted and previous reservations are unchanged.
    Resources(ReconnectBudgetRefusal),
    /// This supervisor may no longer admit effects.
    Stopped(ReconnectStop),
}
impl fmt::Display for ReconnectRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RTSP reconnect refusal: {self:?}")
    }
}
impl std::error::Error for ReconnectRefusal {}

/// One attempted generation. Times are owner observations, not footage coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconnectAttempt {
    /// New generation, including attempts that never reach PLAY.
    pub key: StreamKey,
    /// One-based attempt number, never reset after a successful connection.
    pub ordinal: u32,
    /// Admission time, not a remote connection/PLAY acknowledgement timestamp.
    pub admitted_ns: u64,
    /// Prior generation and retirement acknowledgement, if any. This explicitly
    /// breaks continuity; a picture receipt is still needed to establish resumption.
    pub previous: Option<(StreamKey, u64)>,
}

#[derive(Debug)]
struct Schedule {
    policy: ReconnectPolicy,
    binding: TcpBinding,
    status: ReconnectStatus,
    attempts: u32,
    delay_ns: u64,
    remaining_steps: u64,
    last_ns: u64,
    previous: Option<(StreamKey, u64)>,
    resources: ReservationLedger,
}
impl Schedule {
    fn new(
        binding: TcpBinding,
        policy: ReconnectPolicy,
        now: u64,
    ) -> Result<Self, ReconnectRefusal> {
        if !(1..=1024).contains(&policy.max_attempts)
            || policy.initial_backoff_ns == 0
            || policy.initial_backoff_ns > policy.max_backoff_ns
            || policy.max_steps == 0
            || now >= policy.deadline_ns
            || binding
                .key()
                .generation
                .checked_add(u64::from(policy.max_attempts - 1))
                .is_none()
        {
            return Err(ReconnectRefusal::Configuration);
        }
        Ok(Self {
            status: ReconnectStatus::Waiting {
                key: binding.key(),
                retry_at_ns: now,
            },
            binding,
            policy,
            attempts: 0,
            delay_ns: policy.initial_backoff_ns,
            remaining_steps: policy.max_steps,
            last_ns: now,
            previous: None,
            resources: ReservationLedger::automatic(),
        })
    }

    fn stop(&mut self, reason: ReconnectStop) -> ReconnectRefusal {
        self.status = ReconnectStatus::Stopped(reason);
        ReconnectRefusal::Stopped(reason)
    }

    fn admit(&mut self, now: u64, authority: &dyn TcpAuthority) -> Result<(), ReconnectRefusal> {
        if let ReconnectStatus::Stopped(reason) = self.status {
            return Err(ReconnectRefusal::Stopped(reason));
        }
        if now < self.last_ns {
            return Err(ReconnectRefusal::ClockReversed);
        }
        self.last_ns = now;
        if now >= self.policy.deadline_ns {
            return Err(self.stop(ReconnectStop::Deadline));
        }
        if self.remaining_steps == 0 {
            return Err(self.stop(ReconnectStop::WorkBudget));
        }
        self.remaining_steps -= 1;
        if let Err(denial) = authority.checkpoint(
            &self.binding,
            TcpOperation::Poll,
            now,
            self.policy.deadline_ns,
        ) {
            return Err(self.stop(ReconnectStop::Denied(denial)));
        }
        Ok(())
    }

    fn ready(&self, now: u64) -> Result<(), ReconnectRefusal> {
        match self.status {
            ReconnectStatus::Waiting { retry_at_ns, .. } if now < retry_at_ns => {
                Err(ReconnectRefusal::NotReady)
            }
            ReconnectStatus::Waiting { .. } => Ok(()),
            ReconnectStatus::Active(_) => Err(ReconnectRefusal::Active),
            ReconnectStatus::Retired(_) => Err(ReconnectRefusal::AwaitingRetirement),
            ReconnectStatus::Stopped(reason) => Err(ReconnectRefusal::Stopped(reason)),
        }
    }

    fn begin(&mut self, now: u64) -> Result<ReconnectAttempt, ReconnectRefusal> {
        self.ready(now)?;
        self.attempts += 1;
        self.status = ReconnectStatus::Active(self.binding.key());
        Ok(ReconnectAttempt {
            key: self.binding.key(),
            ordinal: self.attempts,
            admitted_ns: now,
            previous: self.previous,
        })
    }

    fn begin_connection(
        &mut self,
        config: &LiveAvcConfig,
        now: u64,
    ) -> Result<ReconnectAttempt, ReconnectRefusal> {
        self.begin_native_connection(config.transport, config.max_steps, now)
    }

    fn begin_native_connection(
        &mut self,
        transport: crate::rtsp::tcp::TcpLimits,
        connection_steps: u64,
        now: u64,
    ) -> Result<ReconnectAttempt, ReconnectRefusal> {
        // Ordering matters: an early reconnect or a still-owned retirement must
        // not reserve resources or pin the first profile. No I/O occurs here.
        self.ready(now)?;
        let cost = ReconnectBudget::connection(transport, connection_steps)
            .map_err(ReconnectRefusal::Resources)?;
        self.resources
            .reserve(cost, self.policy.max_attempts)
            .map_err(ReconnectRefusal::Resources)?;
        self.begin(now)
    }

    fn ended(&mut self, retry: bool) {
        if retry {
            self.status = ReconnectStatus::Retired(self.binding.key());
        } else {
            self.stop(ReconnectStop::PermanentFailure);
        }
    }

    fn finish(&mut self, retry: bool, now: u64) {
        if !retry || !matches!(self.status, ReconnectStatus::Retired(_)) {
            self.stop(ReconnectStop::PermanentFailure);
            return;
        }
        if self.attempts >= self.policy.max_attempts {
            self.stop(ReconnectStop::Attempts);
            return;
        }
        let Some(at) = now
            .checked_add(self.delay_ns)
            .filter(|at| *at < self.policy.deadline_ns)
        else {
            self.stop(ReconnectStop::Deadline);
            return;
        };
        let old = self.binding.key();
        // The complete generation range was checked before any connection attempt.
        let key = StreamKey {
            generation: old.generation + 1,
            ..old
        };
        let Ok(binding) = TcpBinding::new(
            key,
            self.binding.peer(),
            self.binding.authority(),
            self.binding.security(),
        ) else {
            self.stop(ReconnectStop::PermanentFailure);
            return;
        };
        self.previous = Some((old, now));
        self.binding = binding;
        self.delay_ns = self
            .delay_ns
            .saturating_mul(2)
            .min(self.policy.max_backoff_ns);
        self.status = ReconnectStatus::Waiting {
            key,
            retry_at_ns: at,
        };
    }
}

// Deliberately not Debug: realm and URI are sensitive metadata even without passwords.
struct Profile {
    protocol: crate::rtsp::client::ClientConfig,
    realm: String,
    digest: crate::rtsp::authentication::DigestPolicy,
    limits: crate::rtsp::tcp::TcpLimits,
    media: fss_packet::avc::AvcReceiveLimits,
    steps: u64,
}
impl Profile {
    fn new(config: &LiveAvcConfig) -> Self {
        Self {
            protocol: config.protocol.clone(),
            realm: config.realm.clone(),
            digest: config.digest_policy,
            limits: config.transport,
            media: config.media,
            steps: config.max_steps,
        }
    }

    fn permits(&self, config: &LiveAvcConfig) -> bool {
        let limits = config.transport;
        self.protocol == config.protocol
            && self.realm == config.realm
            && self.digest == config.digest_policy
            && self.media == config.media
            && config.max_steps <= self.steps
            && limits.max_received_bytes <= self.limits.max_received_bytes
            && limits.max_sent_bytes <= self.limits.max_sent_bytes
            && limits.max_io_calls <= self.limits.max_io_calls
            && limits.max_request_bytes <= self.limits.max_request_bytes
            && limits.chunk_bytes <= self.limits.chunk_bytes
            && limits.connect_timeout_ns <= self.limits.connect_timeout_ns
    }
}

/// Payload-free cause; original ownership accompanies a fatal poll failure.
#[derive(Debug)]
pub enum SupervisedAvcError {
    /// Supervision refused before further native work.
    Supervisor(ReconnectRefusal),
    /// Original connect failure, including whether a TCP attempt actually occurred.
    Connect(LiveAvcConnectFailure),
    /// Unmodified live connection failure category.
    Live(LiveAvcError),
}

/// Failed admission or native step, preserving exact terminal ownership.
#[must_use]
#[derive(Debug)]
pub struct SupervisedAvcFailure {
    /// Generation to which any returned retirement belongs, not the next attempt.
    pub key: StreamKey,
    /// Payload-free reason; inspect status separately for retry scheduling.
    pub reason: SupervisedAvcError,
    /// Exact original ownership, including unread bytes and partially sent requests.
    pub retirement: Option<Box<LiveAvcRetirement>>,
}
impl fmt::Display for SupervisedAvcFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "supervised AVC refusal: {:?}", self.reason)
    }
}
impl std::error::Error for SupervisedAvcFailure {}

/// A wait or one original output. Retain terminal ownership before reconnecting.
#[must_use]
#[derive(Debug)]
pub enum SupervisedAvcStep {
    /// No socket exists. Poll still checks authority and the fixed work/lease budget.
    Waiting {
        /// Expected generation.
        key: StreamKey,
        /// Earliest permitted connection admission.
        retry_at_ns: u64,
    },
    /// No socket exists; retain the previous output and acknowledge retirement.
    Retired(StreamKey),
    /// Original output tagged with the generation that produced it.
    Connection {
        /// Generation that produced the original output.
        key: StreamKey,
        /// Unmodified source, protocol, media or retirement output.
        output: AutomaticAvcStep,
    },
}

/// Finite, explicitly granted reconnection of the existing native AVC owner.
///
/// Call connect with expected_binding() at/after the scheduled timer, then poll
/// normally. After retaining a retriable terminal output, call
/// acknowledge_retirement with a fresh owner-clock observation; only then does
/// backoff begin (a blocking connect timeout cannot consume the backoff).
/// Every retry begins DESCRIBE on a new native connection and generation;
/// it never replays the previous prepared request or adopts its codec state. EOF
/// must drain before retry; malformed/authentication/scope failures fail closed.
/// The owner retains all original outputs and independently decides their custody.
#[must_use]
pub struct SupervisedAvcConnection {
    schedule: Schedule,
    profile: Option<Profile>,
    active: Option<AutomaticAvcConnection>,
}
impl fmt::Debug for SupervisedAvcConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SupervisedAvcConnection")
            .field("status", &self.schedule.status)
            .field("attempts", &self.schedule.attempts)
            .field("remaining_steps", &self.schedule.remaining_steps)
            .field("resources", &self.schedule.resources.state())
            .finish_non_exhaustive()
    }
}
impl SupervisedAvcConnection {
    /// Validate a finite grant without creating any socket or borrowing credentials.
    /// The first admitted native profile prices a checked aggregate of its maxima
    /// times max_attempts. Use new_with_budget for a separately constrained total.
    pub fn new(
        binding: TcpBinding,
        policy: ReconnectPolicy,
        now: u64,
    ) -> Result<Self, ReconnectRefusal> {
        Ok(Self {
            schedule: Schedule::new(binding, policy, now)?,
            profile: None,
            active: None,
        })
    }

    /// Constrain all attempts with one explicit non-replenishing resource grant.
    /// Complete native maxima reserve before connect, even if that attempt later
    /// fails. A rejected reservation opens no socket and consumes no attempt.
    pub fn new_with_budget(
        binding: TcpBinding,
        policy: ReconnectPolicy,
        budget: ReconnectBudget,
        now: u64,
    ) -> Result<Self, ReconnectRefusal> {
        let mut owner = Self::new(binding, policy, now)?;
        owner.schedule.resources =
            ReservationLedger::bounded(budget).map_err(ReconnectRefusal::Resources)?;
        Ok(owner)
    }

    /// Fixed ceiling, admitted maxima and remaining assignable capacity.
    /// These are reservations, not actual traffic or source-custody observations.
    pub fn resource_budget(&self) -> ReconnectBudgetState {
        self.schedule.resources.state()
    }

    /// Scheduling only, not camera/recording health.
    pub fn status(&self) -> ReconnectStatus {
        self.schedule.status
    }

    /// Exact route and generation the owner must authorize for the next attempt.
    pub fn expected_binding(&self) -> &TcpBinding {
        &self.schedule.binding
    }

    /// Earliest useful native wake or reconnect timer, bounded by the original lease.
    pub fn next_wake_ns(&self) -> Option<u64> {
        match self.schedule.status {
            ReconnectStatus::Waiting { retry_at_ns, .. } => Some(retry_at_ns),
            ReconnectStatus::Active(_) => Some(
                self.active
                    .as_ref()
                    .and_then(AutomaticAvcConnection::next_wake_ns)
                    .unwrap_or(self.schedule.policy.deadline_ns)
                    .min(self.schedule.policy.deadline_ns),
            ),
            ReconnectStatus::Retired(_) => Some(self.schedule.policy.deadline_ns),
            ReconnectStatus::Stopped(_) => None,
        }
    }

    /// Whether the native owner needs fresh credential borrowing on the next poll.
    pub fn needs_credentials(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(AutomaticAvcConnection::needs_credentials)
    }

    /// Connect exactly once, never during backoff or while an old owner is active.
    /// All attempts share the original deadline and cannot change pinned media.
    /// Complete declared native allowances reserve before any connection effect.
    pub fn connect(
        &mut self,
        config: LiveAvcConfig,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<ReconnectAttempt, SupervisedAvcFailure> {
        self.admit(now, authority)?;
        if config.binding != self.schedule.binding
            || config.deadline_ns != self.schedule.policy.deadline_ns
            || self.profile.as_ref().is_some_and(|p| !p.permits(&config))
        {
            return Err(self.refusal(ReconnectRefusal::Scope));
        }
        let attempt = self
            .schedule
            .begin_connection(&config, now)
            .map_err(|e| self.refusal(e))?;
        if self.profile.is_none() {
            self.profile = Some(Profile::new(&config));
        }
        match AutomaticAvcConnection::connect(config, now, authority) {
            Ok(connection) => {
                self.active = Some(connection);
                Ok(attempt)
            }
            Err(failure) => {
                self.schedule.ended(retryable(&failure.reason));
                Err(SupervisedAvcFailure {
                    key: attempt.key,
                    reason: SupervisedAvcError::Connect(failure),
                    retirement: None,
                })
            }
        }
    }

    /// Perform one original native step. No terminal source, tail or retirement is hidden.
    pub fn poll(
        &mut self,
        readiness: SocketReadiness,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<SupervisedAvcStep, SupervisedAvcFailure> {
        self.admit(now, authority)?;
        if let ReconnectStatus::Waiting { key, retry_at_ns } = self.schedule.status {
            return Ok(SupervisedAvcStep::Waiting { key, retry_at_ns });
        }
        if let ReconnectStatus::Retired(key) = self.schedule.status {
            return Ok(SupervisedAvcStep::Retired(key));
        }
        let key = self.schedule.binding.key();
        let Some(connection) = self.active.as_mut() else {
            return Err(self.refusal(ReconnectRefusal::Active));
        };
        match connection.poll(readiness, credentials, cnonce, now, authority) {
            Ok(output) => {
                if let AutomaticAvcStep::Live(LiveAvcStep::Protocol {
                    event,
                    transport: Some(transport),
                }) = &output
                {
                    let retry = terminal_retryable(event, transport.totals.peer_eof);
                    self.active = None;
                    self.schedule.ended(retry);
                }
                Ok(SupervisedAvcStep::Connection { key, output })
            }
            Err(failure) => {
                if failure.retirement.is_some() {
                    self.active = None;
                    self.schedule.ended(retryable(&failure.reason));
                }
                Err(SupervisedAvcFailure {
                    key,
                    reason: SupervisedAvcError::Live(failure.reason),
                    retirement: failure.retirement,
                })
            }
        }
    }

    /// Acknowledge retention/explicit omission of the original terminal output.
    /// This is an owner assertion, NOT a durable-publication receipt or resource
    /// refund. Supply a fresh observation after the failed syscall/drain; it
    /// starts the backoff. The old generation must still be granted here; the new
    /// one is independently checked when connected. This performs no network I/O.
    pub fn acknowledge_retirement(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<ReconnectStatus, SupervisedAvcFailure> {
        self.admit(now, authority)?;
        if !matches!(self.schedule.status, ReconnectStatus::Retired(_)) {
            return Err(self.refusal(ReconnectRefusal::NoRetirement));
        }
        self.schedule.finish(true, now);
        Ok(self.schedule.status)
    }

    /// Irreversible local stop, even during backoff or after permission revocation.
    /// Sends nothing. Original retirement is returned once with its generation.
    /// Previously reserved capacity is never refunded by cancellation.
    pub fn cancel(&mut self) -> Option<(StreamKey, LiveAvcRetirement)> {
        self.schedule.stop(ReconnectStop::Cancelled);
        let key = self.schedule.binding.key();
        self.active
            .take()
            .and_then(|mut connection| connection.cancel())
            .map(|retirement| (key, retirement))
    }

    fn refusal(&self, reason: ReconnectRefusal) -> SupervisedAvcFailure {
        SupervisedAvcFailure {
            key: self.schedule.binding.key(),
            reason: SupervisedAvcError::Supervisor(reason),
            retirement: None,
        }
    }

    fn admit(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<(), SupervisedAvcFailure> {
        if let Err(reason) = self.schedule.admit(now, authority) {
            let mut failure = self.refusal(reason);
            if matches!(self.schedule.status, ReconnectStatus::Stopped(_)) {
                failure.retirement = self
                    .active
                    .take()
                    .and_then(|mut connection| connection.cancel())
                    .map(Box::new);
            }
            return Err(failure);
        }
        Ok(())
    }
}

fn retryable(reason: &LiveAvcError) -> bool {
    matches!(reason, LiveAvcError::Transport(error) if retryable_transport(error))
}

// Shared wire-failure classification, without an AVC/HEVC error conversion or fallback.
fn retryable_transport(error: &TcpError) -> bool {
    matches!(
        error,
        TcpError::Io {
            operation: TcpOperation::Connect | TcpOperation::Read | TcpOperation::Write,
            kind: ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::NotConnected
                | ErrorKind::BrokenPipe
                | ErrorKind::TimedOut
                | ErrorKind::UnexpectedEof,
        } | TcpError::WriteZero
    )
}

fn terminal_retryable(event: &DigestAvcPoll, eof: bool) -> bool {
    use crate::rtsp::avc_client::AvcClientPoll;
    match event {
        DigestAvcPoll::Client { event, .. } => match event.as_ref() {
            AvcClientPoll::Ended {
                retirement: Some(_),
                ..
            } => eof,
            AvcClientPoll::Fault {
                reason: AvcClientError::Truncated,
                ..
            } => eof,
            AvcClientPoll::Rtp {
                retirement: Some(_),
                ..
            } => true,
            _ => false,
        },
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtsp::tcp::TcpSecurityPolicy;
    use std::cell::Cell;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct Authority {
        binding: TcpBinding,
        denial: Cell<Option<TcpDenial>>,
    }
    impl TcpAuthority for Authority {
        fn checkpoint(
            &self,
            binding: &TcpBinding,
            _: TcpOperation,
            now: u64,
            deadline: u64,
        ) -> Result<(), TcpDenial> {
            if let Some(denial) = self.denial.get() {
                return Err(denial);
            }
            if binding != &self.binding {
                return Err(TcpDenial::Unauthorized);
            }
            if now >= deadline {
                return Err(TcpDenial::Deadline);
            }
            Ok(())
        }
    }

    fn binding(generation: u64) -> Result<TcpBinding, TcpError> {
        TcpBinding::new(
            StreamKey {
                ingress: 71,
                generation,
                ssrc: 7,
            },
            SocketAddr::from((Ipv4Addr::LOCALHOST, 8554)),
            "camera.local",
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )
    }

    fn policy() -> ReconnectPolicy {
        ReconnectPolicy {
            max_attempts: 4,
            initial_backoff_ns: 10,
            max_backoff_ns: 25,
            deadline_ns: 1_000,
            max_steps: 100,
        }
    }

    fn authority(binding: TcpBinding) -> Authority {
        Authority {
            binding,
            denial: Cell::new(None),
        }
    }

    #[test]
    fn backoff_is_capped_and_each_attempt_breaks_generation_continuity() -> TestResult {
        let mut schedule = Schedule::new(binding(1)?, policy(), 0)?;
        for (now, next) in [(0, 10), (10, 30), (30, 55)] {
            let auth = authority(schedule.binding.clone());
            schedule.admit(now, &auth)?;
            let old = schedule.begin(now)?;
            schedule.ended(true);
            assert_eq!(
                schedule.begin(now),
                Err(ReconnectRefusal::AwaitingRetirement)
            );
            schedule.finish(true, now);
            assert_eq!(
                schedule.status,
                ReconnectStatus::Waiting {
                    key: StreamKey {
                        generation: old.key.generation + 1,
                        ..old.key
                    },
                    retry_at_ns: next,
                }
            );
            assert_eq!(schedule.previous, Some((old.key, now)));
            assert_eq!(schedule.begin(next - 1), Err(ReconnectRefusal::NotReady));
        }
        let auth = authority(schedule.binding.clone());
        schedule.admit(55, &auth)?;
        assert_eq!(schedule.begin(55)?.ordinal, 4);
        schedule.ended(true);
        schedule.finish(true, 55);
        assert_eq!(
            schedule.status,
            ReconnectStatus::Stopped(ReconnectStop::Attempts)
        );
        Ok(())
    }

    #[test]
    fn overflow_and_empty_grants_fail_before_io() -> TestResult {
        assert!(Schedule::new(binding(u64::MAX)?, policy(), 0).is_err());
        let mut p = policy();
        p.max_attempts = 0;
        assert!(Schedule::new(binding(1)?, p, 0).is_err());
        p = policy();
        p.initial_backoff_ns = 0;
        assert!(Schedule::new(binding(1)?, p, 0).is_err());
        p = policy();
        p.deadline_ns = 0;
        assert!(Schedule::new(binding(1)?, p, 0).is_err());
        Ok(())
    }

    #[test]
    fn clock_reversal_is_safe_but_work_and_lease_exhaustion_are_terminal() -> TestResult {
        let mut p = policy();
        p.max_steps = 1;
        let mut schedule = Schedule::new(binding(1)?, p, 10)?;
        let auth = authority(schedule.binding.clone());
        assert_eq!(
            schedule.admit(9, &auth),
            Err(ReconnectRefusal::ClockReversed)
        );
        assert_eq!(schedule.remaining_steps, 1);
        schedule.admit(10, &auth)?;
        assert_eq!(
            schedule.admit(11, &auth),
            Err(ReconnectRefusal::Stopped(ReconnectStop::WorkBudget))
        );
        let mut schedule = Schedule::new(binding(1)?, policy(), 0)?;
        schedule.begin(995)?;
        schedule.ended(true);
        schedule.finish(true, 995);
        assert_eq!(
            schedule.status,
            ReconnectStatus::Stopped(ReconnectStop::Deadline)
        );
        Ok(())
    }

    #[test]
    fn denial_during_backoff_is_not_a_retriable_connection_failure() -> TestResult {
        let mut schedule = Schedule::new(binding(1)?, policy(), 0)?;
        schedule.begin(0)?;
        schedule.ended(true);
        schedule.finish(true, 0);
        let auth = authority(schedule.binding.clone());
        auth.denial.set(Some(TcpDenial::Revoked));
        assert_eq!(
            schedule.admit(1, &auth),
            Err(ReconnectRefusal::Stopped(ReconnectStop::Denied(
                TcpDenial::Revoked
            )))
        );
        auth.denial.set(None);
        assert!(schedule.admit(10, &auth).is_err());
        Ok(())
    }

    #[test]
    fn only_explicit_transport_faults_are_retried() {
        assert!(retryable(&LiveAvcError::Transport(TcpError::Io {
            operation: TcpOperation::Read,
            kind: ErrorKind::ConnectionReset,
        })));
        for reason in [
            LiveAvcError::Configuration,
            LiveAvcError::WorkBudget,
            LiveAvcError::Transport(TcpError::Denied(TcpDenial::Budget)),
            LiveAvcError::Transport(TcpError::PeerMismatch),
            LiveAvcError::Transport(TcpError::Io {
                operation: TcpOperation::Configure,
                kind: ErrorKind::TimedOut,
            }),
        ] {
            assert!(!retryable(&reason));
        }
    }

    #[test]
    fn native_stop_returns_unsent_request_once_and_never_reconnects() -> TestResult {
        use crate::rtsp::live_avc::tests::{credentials, scope};
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (config, auth) = scope(listener.local_addr()?)?;
        let mut p = policy();
        p.deadline_ns = config.deadline_ns;
        let mut owner = SupervisedAvcConnection::new(config.binding.clone(), p, 0)?;
        assert_eq!(owner.connect(config, 0, &auth)?.ordinal, 1);
        let (_peer, _) = listener.accept()?;
        assert!(matches!(
            owner.poll(
                SocketReadiness::default(),
                &credentials()?,
                [1; 16],
                0,
                &auth
            )?,
            SupervisedAvcStep::Connection {
                output: AutomaticAvcStep::Queued(_),
                ..
            }
        ));
        let reserved = owner.resource_budget();
        let (key, retirement) = owner.cancel().ok_or("missing retirement")?;
        assert_eq!(owner.resource_budget(), reserved);
        assert_eq!(key.generation, 1);
        assert!(retirement.transport.request.is_some());
        assert_eq!(retirement.transport.request_sent_bytes, 0);
        assert_eq!(
            owner.status(),
            ReconnectStatus::Stopped(ReconnectStop::Cancelled)
        );
        assert!(owner.cancel().is_none());
        assert_eq!(owner.next_wake_ns(), None);
        assert!(
            owner
                .poll(
                    SocketReadiness::default(),
                    &credentials()?,
                    [2; 16],
                    1,
                    &auth
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn native_eof_drains_before_acknowledged_backoff_and_a_fresh_describe() -> TestResult {
        use crate::rtsp::client::ClientCommand;
        use crate::rtsp::live_avc::tests::{credentials, scope};
        use crate::rtsp::tcp::TcpWriteStep;
        use std::io::Read;
        use std::net::Shutdown;
        use std::time::Duration;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let (config, first_authority) = scope(address)?;
        let one = ReconnectBudget::for_attempts(config.transport, config.max_steps, 1)?;
        let two = ReconnectBudget::for_attempts(config.transport, config.max_steps, 2)?;
        let mut p = policy();
        p.deadline_ns = config.deadline_ns;
        p.max_steps = 100_000;
        let mut owner = SupervisedAvcConnection::new(config.binding.clone(), p, 0)?;
        let first = owner.connect(config, 0, &first_authority)?;
        assert_eq!(owner.resource_budget().reserved(), one);
        let (mut peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        let queued = match owner.poll(
            SocketReadiness::default(),
            &credentials()?,
            [1; 16],
            0,
            &first_authority,
        )? {
            SupervisedAvcStep::Connection {
                output: AutomaticAvcStep::Queued(queued),
                ..
            } => queued,
            _ => return Err("missing initial DESCRIBE".into()),
        };
        let mut sent = false;
        for _ in 0..32_768 {
            if matches!(
                owner.poll(
                    SocketReadiness {
                        readable: false,
                        writable: true
                    },
                    &credentials()?,
                    [2; 16],
                    0,
                    &first_authority
                )?,
                SupervisedAvcStep::Connection {
                    output: AutomaticAvcStep::Live(LiveAvcStep::Write(TcpWriteStep::Sent { .. })),
                    ..
                }
            ) {
                sent = true;
                break;
            }
        }
        assert!(sent, "bounded DESCRIBE write did not complete");
        let mut original_request = vec![0; queued.bytes];
        peer.read_exact(&mut original_request)?;
        assert!(original_request.starts_with(b"DESCRIBE "));
        peer.shutdown(Shutdown::Write)?;
        let mut saw_input_end = false;
        let mut terminal = None;
        for _ in 0..32_768 {
            match owner.poll(
                SocketReadiness {
                    readable: true,
                    writable: false,
                },
                &credentials()?,
                [3; 16],
                1,
                &first_authority,
            )? {
                SupervisedAvcStep::Connection {
                    output: AutomaticAvcStep::Live(LiveAvcStep::InputEnded),
                    ..
                } => {
                    saw_input_end = true;
                    assert_eq!(owner.status(), ReconnectStatus::Active(first.key));
                }
                SupervisedAvcStep::Connection {
                    output:
                        AutomaticAvcStep::Live(
                            step @ LiveAvcStep::Protocol {
                                transport: Some(_), ..
                            },
                        ),
                    ..
                } => {
                    terminal = Some(step);
                    break;
                }
                _ => std::thread::yield_now(),
            }
        }
        assert!(saw_input_end);
        assert!(terminal.is_some(), "EOF retirement was not transferred");
        assert_eq!(owner.status(), ReconnectStatus::Retired(first.key));
        assert_eq!(owner.resource_budget().reserved(), one);
        let (config, _) = scope(address)?;
        let refusal = owner
            .connect(config, 2, &first_authority)
            .err()
            .ok_or("retry preceded acknowledgement")?;
        assert!(matches!(
            refusal.reason,
            SupervisedAvcError::Supervisor(ReconnectRefusal::AwaitingRetirement)
        ));
        owner.acknowledge_retirement(100, &first_authority)?;
        assert_eq!(owner.resource_budget().reserved(), one);
        let next = owner.expected_binding().clone();
        assert_eq!(next.key().generation, first.key.generation + 1);
        assert_eq!(owner.next_wake_ns(), Some(110));
        let next_authority = authority(next.clone());
        let (mut config, _) = scope(address)?;
        config.binding = next.clone();
        let refusal = owner
            .connect(config, 109, &next_authority)
            .err()
            .ok_or("backoff was bypassed")?;
        assert!(matches!(
            refusal.reason,
            SupervisedAvcError::Supervisor(ReconnectRefusal::NotReady)
        ));
        listener.set_nonblocking(true)?;
        assert_eq!(
            listener
                .accept()
                .err()
                .ok_or("early retry opened a socket")?
                .kind(),
            ErrorKind::WouldBlock
        );
        let (mut changed, _) = scope(address)?;
        changed.binding = next.clone();
        changed.media.syntax.max_width += 1;
        let refused = owner
            .connect(changed, 110, &next_authority)
            .err()
            .ok_or("media profile changed")?;
        assert!(matches!(
            refused.reason,
            SupervisedAvcError::Supervisor(ReconnectRefusal::Scope)
        ));
        assert_eq!(owner.resource_budget().reserved(), one);
        assert_eq!(
            listener
                .accept()
                .err()
                .ok_or("media drift opened a socket")?
                .kind(),
            ErrorKind::WouldBlock
        );
        let (mut config, _) = scope(address)?;
        config.binding = next;
        let second = owner.connect(config, 110, &next_authority)?;
        let (_second_peer, _) = listener.accept()?;
        assert_eq!(second.ordinal, 2);
        assert_eq!(second.previous, Some((first.key, 100)));
        assert_eq!(owner.resource_budget().reserved(), two);
        match owner.poll(
            SocketReadiness::default(),
            &credentials()?,
            [4; 16],
            110,
            &next_authority,
        )? {
            SupervisedAvcStep::Connection {
                key,
                output: AutomaticAvcStep::Queued(queued),
            } => {
                assert_eq!(key, second.key);
                assert_eq!(queued.command, ClientCommand::Describe);
                assert_eq!(queued.cseq, 1);
            }
            _ => return Err("new generation did not start fresh negotiation".into()),
        }
        assert!(owner.cancel().is_some());
        assert_eq!(owner.resource_budget().reserved(), two);
        // Old terminal ownership is never adopted as new-generation continuity.
        drop(terminal);
        Ok(())
    }

    #[test]
    fn insufficient_whole_run_budget_refuses_before_native_connect_and_allows_correction()
    -> TestResult {
        use crate::rtsp::live_avc::tests::scope;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let (config, auth) = scope(address)?;
        let mut budget = ReconnectBudget::for_attempts(config.transport, config.max_steps, 1)?;
        budget.sent_bytes -= 1;
        let mut p = policy();
        p.deadline_ns = config.deadline_ns;
        let mut owner =
            SupervisedAvcConnection::new_with_budget(config.binding.clone(), p, budget, 0)?;
        let before = owner.resource_budget();
        let failure = owner
            .connect(config, 0, &auth)
            .err()
            .ok_or("excess reservation connected")?;
        assert!(matches!(
            failure.reason,
            SupervisedAvcError::Supervisor(ReconnectRefusal::Resources(
                ReconnectBudgetRefusal::Exhausted(ReconnectBudgetDimension::SentBytes)
            ))
        ));
        assert!(failure.retirement.is_none());
        assert_eq!(owner.resource_budget(), before);
        assert_eq!(
            listener
                .accept()
                .err()
                .ok_or("refused reservation opened a socket")?
                .kind(),
            ErrorKind::WouldBlock
        );
        let (mut corrected, _) = scope(address)?;
        corrected.transport.max_sent_bytes = budget.sent_bytes;
        assert_eq!(owner.connect(corrected, 0, &auth)?.ordinal, 1);
        let (_peer, _) = listener.accept()?;
        assert_eq!(owner.resource_budget().reserved(), budget);
        assert_eq!(owner.resource_budget().admitted_attempts(), 1);
        assert!(owner.cancel().is_some());
        assert_eq!(owner.resource_budget().reserved(), budget);
        Ok(())
    }

    #[test]
    fn retired_attempt_does_not_replenish_shared_connection_reservations() -> TestResult {
        use crate::rtsp::live_avc::tests::scope;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (config, _) = scope(listener.local_addr()?)?;
        let budget = ReconnectBudget::for_attempts(config.transport, config.max_steps, 1)?;
        let mut schedule = Schedule::new(config.binding.clone(), policy(), 0)?;
        schedule.resources = ReservationLedger::bounded(budget)?;
        let first = schedule.begin_connection(&config, 0)?;
        schedule.ended(true);
        schedule.finish(true, 0);
        let before = schedule.resources.state();
        let waiting = schedule.status;
        assert!(matches!(
            schedule.begin_connection(&config, 10),
            Err(ReconnectRefusal::Resources(
                ReconnectBudgetRefusal::Exhausted(_)
            ))
        ));
        assert_eq!(schedule.resources.state(), before);
        assert_eq!(schedule.status, waiting);
        assert_eq!(schedule.attempts, first.ordinal);
        Ok(())
    }
}
