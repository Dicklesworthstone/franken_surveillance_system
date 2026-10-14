#![forbid(unsafe_code)]
//! Reconnection of the existing native recording owner without bypassing capture
//! draining, explicit timing, source custody or root-last publication. This uses
//! the same finite scheduler, resource reservations and transport classification
//! as live supervision. A recording retirement never refunds native capacity.

use std::fmt;

use super::{
    Profile, ReconnectAttempt, ReconnectBudget, ReconnectBudgetState, ReconnectPolicy,
    ReconnectRefusal, ReconnectStatus, ReconnectStop, ReservationLedger, Schedule, retryable,
    terminal_retryable,
};
use crate::rtsp::authentication::DigestCredentials;
use crate::rtsp::live_avc::automatic::{AutomaticAvcRecording, AutomaticRecordingStep};
use crate::rtsp::live_avc::recording::{
    LiveRecordingConfig, LiveRecordingConnectFailure, LiveRecordingError,
    LiveRecordingFailure, LiveRecordingRetirement, LiveRecordingStep,
};
use crate::rtsp::live_avc::{LiveAvcConfig, LiveAvcStep, SocketReadiness};
use crate::rtsp::recording::RecordingScope;
use crate::rtsp::recording_capture::{CapturePoll, TimedCapture};
use crate::rtsp::recording_collector::{RecordingCollector, RecordingTiming};
use crate::rtsp::tcp::{TcpAuthority, TcpBinding};
use fss_packet::StreamKey;

/// Failure classification without source bytes, URI, credentials or server text.
#[derive(Debug)]
pub enum SupervisedRecordingError {
    /// Supervision rejected further native effects.
    Supervisor(ReconnectRefusal),
    /// Original recording/native connection refusal.
    Connect(LiveRecordingConnectFailure),
    /// Original live recording or capture refusal.
    Recording(LiveRecordingError),
}

/// A failed operation retains every original terminal layer exactly once.
#[must_use]
#[derive(Debug)]
pub struct SupervisedRecordingFailure {
    /// Generation of the returned work, never the next retry generation.
    pub key: StreamKey,
    /// Payload-free failure; status independently reports retry eligibility.
    pub reason: SupervisedRecordingError,
    /// Original prepared, unsealed, untimed, network and unoffered ownership.
    pub retirement: Option<Box<LiveRecordingRetirement>>,
}
impl fmt::Display for SupervisedRecordingFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "supervised recording refusal: {:?}", self.reason)
    }
}
impl std::error::Error for SupervisedRecordingFailure {}

/// A scheduling observation or one original recording output.
#[must_use]
#[derive(Debug)]
pub enum SupervisedRecordingStep {
    /// No native owner exists; the fixed lease and authority still apply.
    Waiting {
        /// Expected fresh stream generation.
        key: StreamKey,
        /// Absolute earliest connection admission.
        retry_at_ns: u64,
    },
    /// Preserve the previous terminal output and acknowledge with a fresh clock.
    Retired(StreamKey),
    /// Original live recording output, including timing requests and prepared windows.
    Recording {
        /// Exact generation that produced the output.
        key: StreamKey,
        /// Original output, not a publication or continuity certificate.
        output: AutomaticRecordingStep,
    },
}

/// One finite reconnect owner for recording, not a fleet scheduler or publisher.
///
/// The template fixes camera identity, RTP mapping, media tick rate and collection
/// limits. Each attempt needs an explicitly supplied RecordingScope with the new
/// generation and owner-provided anchor/clock provenance. These are never guessed.
/// A TCP EOF alone cannot advance this owner: queued recording work must drain,
/// and the caller must retain the terminal output before acknowledging retirement.
#[must_use]
pub struct SupervisedAvcRecording {
    schedule: Schedule,
    profile: Option<Profile>,
    template: LiveRecordingConfig,
    active: Option<AutomaticAvcRecording>,
    draining_eof: bool,
}
impl fmt::Debug for SupervisedAvcRecording {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SupervisedAvcRecording")
            .field("status", &self.schedule.status)
            .field("attempts", &self.schedule.attempts)
            .field("draining_eof", &self.draining_eof)
            .field("resources", &self.schedule.resources.state())
            .finish_non_exhaustive()
    }
}
impl SupervisedAvcRecording {
    /// Validate the finite grant without opening a socket or borrowing credentials.
    /// The first admitted native profile establishes a checked maximum aggregate
    /// over max_attempts. The recording owner still validates collection before I/O.
    pub fn new(
        binding: TcpBinding,
        template: LiveRecordingConfig,
        policy: ReconnectPolicy,
        now: u64,
    ) -> Result<Self, ReconnectRefusal> {
        if template.scope.generation != binding.key().generation {
            return Err(ReconnectRefusal::Configuration);
        }
        Ok(Self {
            schedule: Schedule::new(binding, policy, now)?,
            profile: None,
            template,
            active: None,
            draining_eof: false,
        })
    }

    /// Bind one explicit whole-run native resource budget before any connection.
    /// Reserving a new generation never refunds the previous generation's maxima,
    /// even after its recording and source ownership have completely drained.
    /// Storage/publication allowances remain with their separate existing owners.
    pub fn new_with_budget(
        binding: TcpBinding,
        template: LiveRecordingConfig,
        policy: ReconnectPolicy,
        budget: ReconnectBudget,
        now: u64,
    ) -> Result<Self, ReconnectRefusal> {
        let mut owner = Self::new(binding, template, policy, now)?;
        owner.schedule.resources =
            ReservationLedger::bounded(budget).map_err(ReconnectRefusal::Resources)?;
        Ok(owner)
    }

    /// Fixed native ceiling and irreversibly admitted maxima across generations.
    /// This is not measured traffic, stored media size or a publication receipt.
    pub fn resource_budget(&self) -> ReconnectBudgetState {
        self.schedule.resources.state()
    }

    /// Scheduling state, not evidence of recorded footage or camera health.
    pub fn status(&self) -> ReconnectStatus {
        self.schedule.status
    }

    /// The new generation must be separately granted by the live authority.
    pub fn expected_binding(&self) -> &TcpBinding {
        &self.schedule.binding
    }

    /// Include capture deadlines even while an EOF tail or timing request is held.
    pub fn next_wake_ns(&self) -> Option<u64> {
        match self.schedule.status {
            ReconnectStatus::Waiting { retry_at_ns, .. } => Some(retry_at_ns),
            ReconnectStatus::Active(_) => Some(
                self.active
                    .as_ref()
                    .and_then(AutomaticAvcRecording::next_wake_ns)
                    .unwrap_or(self.schedule.policy.deadline_ns)
                    .min(self.schedule.policy.deadline_ns),
            ),
            ReconnectStatus::Retired(_) => Some(self.schedule.policy.deadline_ns),
            ReconnectStatus::Stopped(_) => None,
        }
    }

    /// Whether the original automatic control owner needs fresh credential borrowing.
    pub fn needs_credentials(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(AutomaticAvcRecording::needs_credentials)
    }

    /// Read-only collection accounting for the currently active generation.
    pub fn collector(&self) -> Option<&RecordingCollector> {
        self.active.as_ref().map(AutomaticAvcRecording::collector)
    }

    /// Open one exact new-generation recording attempt, retaining the fixed template
    /// and complete native media profile. Scope and whole-run budget refusals happen
    /// before any socket opens; resource refusals do not consume an attempt ordinal.
    pub fn connect(
        &mut self,
        config: LiveAvcConfig,
        scope: RecordingScope,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<ReconnectAttempt, SupervisedRecordingFailure> {
        self.admit(now, authority)?;
        if config.binding != self.schedule.binding
            || config.deadline_ns != self.schedule.policy.deadline_ns
            || scope.generation != self.schedule.binding.key().generation
            || scope.sensor != self.template.scope.sensor
            || scope.stream != self.template.scope.stream
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
        let mut recording = self.template.clone();
        recording.scope = scope;
        match AutomaticAvcRecording::connect(config, recording, now, authority) {
            Ok(recording) => {
                self.active = Some(recording);
                self.draining_eof = false;
                Ok(attempt)
            }
            Err(failure) => {
                self.schedule.ended(recording_retryable(&failure.reason));
                Err(SupervisedRecordingFailure {
                    key: attempt.key,
                    reason: SupervisedRecordingError::Connect(failure),
                    retirement: None,
                })
            }
        }
    }

    /// Drive original capture before network reads. A prepared window remains an
    /// unchanged caller-owned plan requiring the existing publication protocol.
    pub fn poll(
        &mut self,
        readiness: SocketReadiness,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<SupervisedRecordingStep, SupervisedRecordingFailure> {
        self.admit(now, authority)?;
        match self.schedule.status {
            ReconnectStatus::Waiting { key, retry_at_ns } => {
                return Ok(SupervisedRecordingStep::Waiting { key, retry_at_ns });
            }
            ReconnectStatus::Retired(key) => return Ok(SupervisedRecordingStep::Retired(key)),
            _ => {}
        }
        let key = self.schedule.binding.key();
        let Some(recording) = self.active.as_mut() else {
            return Err(self.refusal(ReconnectRefusal::Active));
        };
        let result = recording.poll(readiness, credentials, cnonce, now, authority);
        let output = self.settle(result)?;
        if let AutomaticRecordingStep::Recording(step) = &output {
            let terminal = match step {
                LiveRecordingStep::Network(step @ LiveAvcStep::Protocol { transport: Some(_), .. }) => {
                    // The existing owner moved real receiver EOF into capture before
                    // emitting this event. Keep the owner alive until capture drains.
                    self.draining_eof = step_retryable(step);
                    None
                }
                LiveRecordingStep::Stopped { trigger, .. } => Some(step_retryable(trigger)),
                LiveRecordingStep::Capture { event, .. } => match event.as_ref() {
                    CapturePoll::Ended { .. } => Some(self.draining_eof),
                    CapturePoll::Stopped { .. } => Some(false),
                    _ => None,
                },
                LiveRecordingStep::Ended => Some(false),
                _ => None,
            };
            if let Some(retry) = terminal {
                self.active = None;
                self.schedule.ended(retry);
            }
        }
        Ok(SupervisedRecordingStep::Recording { key, output })
    }

    /// The timing request's exact key is mandatory. Late timing from an old
    /// generation cannot be applied to a new generation's held picture.
    pub fn supply_timing(
        &mut self,
        key: StreamKey,
        timing: RecordingTiming,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<TimedCapture, SupervisedRecordingFailure> {
        self.admit_generation(key, now, authority)?;
        let Some(recording) = self.active.as_mut() else {
            return Err(self.refusal(ReconnectRefusal::Active));
        };
        let result = recording.supply_timing(timing, now, authority);
        self.settle(result)
    }

    /// Seal only the requested active generation, without guessing timing or
    /// claiming publication. Poll for the unchanged prepared recording window.
    pub fn seal(
        &mut self,
        key: StreamKey,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<bool, SupervisedRecordingFailure> {
        self.admit_generation(key, now, authority)?;
        let Some(recording) = self.active.as_mut() else {
            return Err(self.refusal(ReconnectRefusal::Active));
        };
        let result = recording.seal(now, authority);
        self.settle(result)
    }

    /// Owner assertion that original terminal work was retained or explicitly
    /// accounted for, not proof of durable publication or unused native capacity.
    /// Only this fresh clock observation starts backoff, after recording retirement.
    pub fn acknowledge_retirement(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<ReconnectStatus, SupervisedRecordingFailure> {
        self.admit(now, authority)?;
        if !matches!(self.schedule.status, ReconnectStatus::Retired(_)) {
            return Err(self.refusal(ReconnectRefusal::NoRetirement));
        }
        self.schedule.finish(true, now);
        Ok(self.schedule.status)
    }

    /// Cancel even after revocation or during EOF draining. Return all prepared,
    /// unsealed and untimed work exactly once; never send a teardown or publish.
    /// The complete admitted resource maxima remain reserved after cancellation.
    pub fn cancel(&mut self) -> Option<(StreamKey, LiveRecordingRetirement)> {
        self.schedule.stop(ReconnectStop::Cancelled);
        let key = self.schedule.binding.key();
        self.active
            .take()
            .and_then(|mut recording| recording.cancel())
            .map(|retirement| (key, retirement))
    }

    fn refusal(&self, reason: ReconnectRefusal) -> SupervisedRecordingFailure {
        SupervisedRecordingFailure {
            key: self.schedule.binding.key(),
            reason: SupervisedRecordingError::Supervisor(reason),
            retirement: None,
        }
    }

    fn admit(&mut self, now: u64, authority: &dyn TcpAuthority) -> Result<(), SupervisedRecordingFailure> {
        if let Err(reason) = self.schedule.admit(now, authority) {
            let mut failure = self.refusal(reason);
            if matches!(self.schedule.status, ReconnectStatus::Stopped(_)) {
                failure.retirement = self
                    .active
                    .take()
                    .and_then(|mut recording| recording.cancel())
                    .map(Box::new);
            }
            return Err(failure);
        }
        Ok(())
    }

    fn admit_generation(
        &mut self, key: StreamKey, now: u64, authority: &dyn TcpAuthority,
    ) -> Result<(), SupervisedRecordingFailure> {
        self.admit(now, authority)?;
        if self.schedule.status != ReconnectStatus::Active(key) {
            return Err(self.refusal(ReconnectRefusal::Scope));
        }
        Ok(())
    }

    fn settle<T>(
        &mut self, result: Result<T, LiveRecordingFailure>,
    ) -> Result<T, SupervisedRecordingFailure> {
        result.map_err(|failure| {
            let key = self.schedule.binding.key();
            if failure.retirement.is_some() {
                self.active = None;
                self.schedule.ended(recording_retryable(&failure.reason));
            }
            SupervisedRecordingFailure {
                key,
                reason: SupervisedRecordingError::Recording(failure.reason),
                retirement: failure.retirement,
            }
        })
    }
}

fn recording_retryable(reason: &LiveRecordingError) -> bool {
    matches!(reason, LiveRecordingError::Network(reason) if retryable(reason))
}

fn step_retryable(step: &LiveAvcStep) -> bool {
    match step {
        LiveAvcStep::Protocol { event, transport: Some(transport) } => {
            terminal_retryable(event, transport.totals.peer_eof)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtsp::live_avc::automatic::reconnect::{
        ReconnectBudgetDimension, ReconnectBudgetRefusal,
    };
    use crate::rtsp::live_avc::tests::{KEY, credentials, scope};
    use crate::rtsp::recording_collector::CollectorLimits;
    use fss_core::{ContentDigest, SensorId, StreamId};
    use std::io::ErrorKind;
    use std::net::{Ipv4Addr, TcpListener};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn template() -> TestResult<LiveRecordingConfig> {
        Ok(LiveRecordingConfig {
            scope: RecordingScope {
                sensor: SensorId::parse("sensor:supervised-recording")?,
                stream: StreamId::parse("stream:supervised-recording")?,
                generation: KEY.generation,
                anchor: ContentDigest::sha256(b"supervised source anchor"),
                receive_clock: ContentDigest::sha256(b"supervised receive clock"),
            },
            payload_type: 96,
            time_scale: 90_000,
            limits: CollectorLimits::default(),
        })
    }

    fn policy(deadline_ns: u64) -> ReconnectPolicy {
        ReconnectPolicy {
            max_attempts: 3,
            initial_backoff_ns: 10,
            max_backoff_ns: 100,
            deadline_ns,
            max_steps: 10_000,
        }
    }

    #[test]
    fn stale_recording_scope_never_opens_a_camera_connection() -> TestResult {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let (config, authority) = scope(listener.local_addr()?)?;
        let template = template()?;
        let mut stale = template.scope.clone();
        stale.generation += 1;
        let mut owner = SupervisedAvcRecording::new(
            config.binding.clone(), template, policy(config.deadline_ns), 0,
        )?;
        let before = owner.resource_budget();
        let failure = owner.connect(config, stale, 0, &authority)
            .err().ok_or("stale recording scope connected")?;
        assert!(matches!(failure.reason,
            SupervisedRecordingError::Supervisor(ReconnectRefusal::Scope)));
        assert!(failure.retirement.is_none());
        assert_eq!(owner.resource_budget(), before);
        assert_eq!(listener.accept().err().ok_or("stale scope opened a socket")?.kind(), ErrorKind::WouldBlock);
        Ok(())
    }

    #[test]
    fn late_generation_commands_cannot_seal_new_recording_and_cancel_preserves_all_layers() -> TestResult {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (config, authority) = scope(listener.local_addr()?)?;
        let template = template()?;
        let recording_scope = template.scope.clone();
        let budget = ReconnectBudget::for_attempts(config.transport, config.max_steps, 1)?;
        let mut owner = SupervisedAvcRecording::new_with_budget(
            config.binding.clone(), template, policy(config.deadline_ns), budget, 0,
        )?;
        let attempt = owner.connect(config, recording_scope, 0, &authority)?;
        let (_peer, _) = listener.accept()?;
        assert_eq!(owner.resource_budget().reserved(), budget);
        assert_eq!(owner.resource_budget().admitted_attempts(), 1);
        let failure = owner.seal(StreamKey { generation: attempt.key.generation + 1, ..attempt.key }, 0, &authority)
            .err().ok_or("wrong generation sealed recording")?;
        assert!(failure.retirement.is_none());
        assert_eq!(owner.status(), ReconnectStatus::Active(attempt.key));
        assert!(matches!(owner.poll(SocketReadiness::default(), &credentials()?, [1; 16], 0, &authority)?,
            SupervisedRecordingStep::Recording { output: AutomaticRecordingStep::Queued(_), .. }));
        let (key, retirement) = owner.cancel().ok_or("missing capture retirement")?;
        assert_eq!(owner.resource_budget().reserved(), budget);
        assert_eq!(key, attempt.key);
        let connection = retirement.connection.ok_or("missing native retirement")?;
        assert!(connection.transport.request.is_some());
        assert_eq!(connection.transport.request_sent_bytes, 0);
        assert!(owner.cancel().is_none());
        assert!(owner.collector().is_none());
        assert_eq!(owner.next_wake_ns(), None);
        Ok(())
    }

    #[test]
    fn recording_cannot_bypass_whole_run_budget_and_a_smaller_native_profile_can_be_admitted()
    -> TestResult {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let (config, authority) = scope(address)?;
        let template = template()?;
        let recording_scope = template.scope.clone();
        let mut budget = ReconnectBudget::for_attempts(config.transport, config.max_steps, 1)?;
        budget.connection_steps -= 1;
        let mut owner = SupervisedAvcRecording::new_with_budget(
            config.binding.clone(), template, policy(config.deadline_ns), budget, 0,
        )?;
        let before = owner.resource_budget();
        let failure = owner.connect(config, recording_scope.clone(), 0, &authority)
            .err().ok_or("recording bypassed native resource grant")?;
        assert!(matches!(failure.reason, SupervisedRecordingError::Supervisor(
            ReconnectRefusal::Resources(ReconnectBudgetRefusal::Exhausted(
                ReconnectBudgetDimension::ConnectionSteps
            ))
        )));
        assert!(failure.retirement.is_none());
        assert_eq!(owner.resource_budget(), before);
        assert_eq!(listener.accept().err().ok_or("budget refusal opened camera")?.kind(), ErrorKind::WouldBlock);
        let (mut corrected, _) = scope(address)?;
        corrected.max_steps = budget.connection_steps;
        assert_eq!(owner.connect(corrected, recording_scope, 0, &authority)?.ordinal, 1);
        let (_peer, _) = listener.accept()?;
        assert_eq!(owner.resource_budget().reserved(), budget);
        assert!(owner.cancel().is_some());
        assert_eq!(owner.resource_budget().reserved(), budget);
        Ok(())
    }

    #[test]
    fn revocation_retires_recording_once_without_refunding_the_native_grant() -> TestResult {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (config, authority) = scope(listener.local_addr()?)?;
        let template = template()?;
        let recording_scope = template.scope.clone();
        let mut owner = SupervisedAvcRecording::new(
            config.binding.clone(), template, policy(config.deadline_ns), 0,
        )?;
        owner.connect(config, recording_scope, 0, &authority)?;
        let (_peer, _) = listener.accept()?;
        owner.poll(SocketReadiness::default(), &credentials()?, [1; 16], 0, &authority)?;
        let reserved = owner.resource_budget();
        authority.revoked.set(true);
        let failure = owner.poll(SocketReadiness::default(), &credentials()?, [2; 16], 1, &authority)
            .err().ok_or("revoked recording continued")?;
        assert!(failure.retirement.is_some());
        assert_eq!(owner.resource_budget(), reserved);
        assert!(owner.cancel().is_none());
        assert_eq!(owner.resource_budget(), reserved);
        Ok(())
    }
}
