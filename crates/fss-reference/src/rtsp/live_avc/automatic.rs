#![forbid(unsafe_code)]
//! Opt-in automatic control of one explicitly authorized live AVC connection.
//!
//! A call either prepares one request or returns one unchanged live output. It never
//! hides source bytes, retries an uncertain write, reconnects, extends a lease, or
//! retains credentials. Owners still schedule readiness/deadlines and retain every
//! wire/media/retirement output before polling again.

mod control;
/// Separately granted, finite reconnection using fresh native owners and generations.
pub mod reconnect;

use super::recording::{
    LiveAvcRecording, LiveRecordingConfig, LiveRecordingConnectFailure, LiveRecordingError,
    LiveRecordingFailure, LiveRecordingRetirement, LiveRecordingStep,
};
use super::*;
#[cfg(test)]
use crate::rtsp::client::ClientProgress;
use crate::rtsp::recording_capture::{CapturePoll, TimedCapture};
use crate::rtsp::recording_collector::{RecordingCollector, RecordingTiming};
use control::{Action, ControlDriver};

/// An automatically prepared request or the complete original live output.
/// A queue receipt is not proof of socket delivery or camera acknowledgement.
#[must_use]
#[derive(Debug)]
pub enum AutomaticAvcStep {
    /// Exactly one request was prepared and queued; poll again to drive its write.
    Queued(QueuedAvcRequest),
    /// Unmodified wire, protocol, media, pending, EOF, or terminal ownership.
    Live(LiveAvcStep),
}

/// DESCRIBE -> SETUP -> PLAY, Digest responses, and session keepalives under the
/// original connection's authority, lifetime, byte ceilings and work budget.
///
/// Construction alone does not start capture: the first poll queues DESCRIBE.
/// Transitions are driven by accepted responses, not by repeatedly inspecting a
/// state that may already have an outstanding request. Informational responses
/// do not trigger follow-up commands. Fatal outcomes never cause a resend.
#[must_use]
#[derive(Debug)]
pub struct AutomaticAvcConnection {
    connection: LiveAvcConnection,
    control: ControlDriver,
}
impl AutomaticAvcConnection {
    /// Validate the same explicit route, policy and budgets as the manual owner.
    /// This makes one authorized TCP attempt; it does not resolve or discover peers.
    pub fn connect(
        config: LiveAvcConfig,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<Self, LiveAvcConnectFailure> {
        Ok(Self {
            connection: LiveAvcConnection::connect(config, now, authority)?,
            control: ControlDriver::new(now),
        })
    }
    /// Negotiation state only, never a frame, continuity or publication receipt.
    pub fn state(&self) -> ClientState {
        self.connection.state()
    }
    /// Whether the next poll will attempt a credential-borrowing preparation.
    /// A deferred command drains native input before borrowing credentials again.
    pub fn needs_credentials(&self) -> bool {
        self.control.action().is_some()
    }
    /// Immediate local control work or the original earliest hard/useful deadline.
    /// Honor this timer even without socket readiness, including during keepalives.
    pub fn next_wake_ns(&self) -> Option<u64> {
        self.control.wake(self.connection.next_wake_ns())
    }
    /// Original live transport accounting, absent after terminal transfer.
    pub fn totals(&self) -> Option<TcpTotals> {
        self.connection.totals()
    }
    /// Remaining connection-wide work admissions; automatic control adds no budget.
    pub fn remaining_steps(&self) -> u64 {
        self.connection.remaining_steps()
    }
    /// Perform one request preparation OR one existing live step, never both.
    /// Safe backpressure preserves the unsent intent and makes the next call drain
    /// native input. It never retries a prepared or partially dispatched request.
    /// Supply a fresh owner-generated cnonce for each admitted preparation.
    pub fn poll(
        &mut self,
        readiness: SocketReadiness,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<AutomaticAvcStep, LiveAvcFailure> {
        if let Some(action) = self.control.action() {
            let result = match action {
                Action::Request(command) => {
                    self.connection
                        .request(command, credentials, cnonce, now, authority)
                }
                Action::Respond => self.connection.respond(credentials, cnonce, now, authority),
            };
            return match result {
                Ok(receipt) => {
                    self.control.clear();
                    Ok(AutomaticAvcStep::Queued(receipt))
                }
                Err(failure) => {
                    self.control
                        .refused(&failure.reason, failure.retirement.is_some());
                    Err(failure)
                }
            };
        }
        let step = self
            .connection
            .poll(readiness, now, authority)
            .map_err(|failure| {
                self.control
                    .refused(&failure.reason, failure.retirement.is_some());
                failure
            })?;
        // A native wait can still contain a partial exact frame. Do not busy-retry
        // preparation until that same input has drained, or a semantic event arrives.
        let control_ready = self.connection.active.as_ref().is_some_and(|active| {
            active.protocol.buffered_wire_bytes() == 0 && !active.transport.has_pending_request()
        });
        if !matches!(&step, LiveAvcStep::Pending(_)) || control_ready {
            self.control.observe(&step, now);
        }
        Ok(AutomaticAvcStep::Live(step))
    }
    /// Cancel without sending TEARDOWN, even after permission was revoked.
    /// Return every retained layer exactly once; no remote completion is asserted.
    pub fn cancel(&mut self) -> Option<LiveAvcRetirement> {
        self.control.clear();
        self.connection.cancel()
    }
}

/// An automatic control receipt or the complete existing recording output.
/// Prepared windows still require the original root-last publication procedure.
#[must_use]
#[derive(Debug)]
pub enum AutomaticRecordingStep {
    /// One command prepared under the recording owner's live authority.
    Queued(QueuedAvcRequest),
    /// Original network, timing, collection, backpressure or terminal ownership.
    Recording(LiveRecordingStep),
}

/// Automatic camera control composed with the existing loss-aware recording owner.
///
/// Recording still drains before network reads. Picture timing, sealing, source
/// custody and publication remain explicit: neither arrival time nor a successful
/// PLAY response can manufacture recording timestamps or a durable recording.
/// This wrapper stores no additional media and creates no read-ahead queue.
#[must_use]
#[derive(Debug)]
pub struct AutomaticAvcRecording {
    recording: LiveAvcRecording,
    control: ControlDriver,
}
impl AutomaticAvcRecording {
    /// Validate recording scope before opening the one authorized connection.
    pub fn connect(
        config: LiveAvcConfig,
        recording: LiveRecordingConfig,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<Self, LiveRecordingConnectFailure> {
        Ok(Self {
            recording: LiveAvcRecording::connect(config, recording, now, authority)?,
            control: ControlDriver::new(now),
        })
    }
    /// Negotiation state only; not evidence of stored media.
    pub fn state(&self) -> ClientState {
        self.recording.state()
    }
    /// Read-only accounting from the original recording collector.
    pub fn collector(&self) -> &RecordingCollector {
        self.recording.collector()
    }
    /// Original live transport accounting; final totals transfer with retirement.
    pub fn totals(&self) -> Option<TcpTotals> {
        self.recording.totals()
    }
    /// Whether the next poll will prepare an automatic request or Digest answer.
    pub fn needs_credentials(&self) -> bool {
        self.control.action().is_some()
    }
    /// Include local control work without masking capture or network deadlines.
    pub fn next_wake_ns(&self) -> Option<u64> {
        self.control.wake(self.recording.next_wake_ns())
    }
    /// Prepare one request OR drive one original recording step. Every returned
    /// source chunk, capture event and retirement remains caller-owned unchanged.
    /// Safe command backpressure selects native drainage on the following call.
    pub fn poll(
        &mut self,
        readiness: SocketReadiness,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<AutomaticRecordingStep, LiveRecordingFailure> {
        if let Some(action) = self.control.action() {
            let result = match action {
                Action::Request(command) => {
                    self.recording
                        .request(command, credentials, cnonce, now, authority)
                }
                Action::Respond => self.recording.respond(credentials, cnonce, now, authority),
            };
            let receipt = self.settle(result)?;
            self.control.clear();
            return Ok(AutomaticRecordingStep::Queued(receipt));
        }
        let result = self.recording.poll(readiness, now, authority);
        let step = self.settle(result)?;
        if let LiveRecordingStep::Network(event) = &step {
            self.control.observe(event, now);
        } else if matches!(
            &step,
            LiveRecordingStep::Stopped { .. } | LiveRecordingStep::Ended
        ) || matches!(
            step.capture_event(),
            Some(CapturePoll::Stopped { .. } | CapturePoll::Ended { .. })
        ) {
            self.control.clear();
        }
        Ok(AutomaticRecordingStep::Recording(step))
    }
    /// Supply explicit media timing to the same retained picture. Safe timing
    /// refusals preserve the picture for correction; fatal errors retire all layers.
    pub fn supply_timing(
        &mut self,
        timing: RecordingTiming,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<TimedCapture, LiveRecordingFailure> {
        let result = self.recording.supply_timing(timing, now, authority);
        self.settle(result)
    }
    /// Seal a completed prefix under live authority to relieve collector pressure.
    /// Poll to obtain its prepared window; this method does not publish it.
    pub fn seal(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<bool, LiveRecordingFailure> {
        let result = self.recording.seal(now, authority);
        self.settle(result)
    }
    /// Stop without network I/O and transfer prepared, unsealed, untimed and
    /// protocol work exactly once, including after live authority revocation.
    pub fn cancel(&mut self) -> Option<LiveRecordingRetirement> {
        self.control.clear();
        self.recording.cancel()
    }
    fn settle<T>(
        &mut self,
        result: Result<T, LiveRecordingFailure>,
    ) -> Result<T, LiveRecordingFailure> {
        if let Err(failure) = &result {
            if let LiveRecordingError::Network(reason) = &failure.reason {
                self.control.refused(reason, failure.retirement.is_some());
            } else if failure.retirement.is_some() {
                self.control.clear();
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progress(progress: ClientProgress) -> LiveAvcStep {
        LiveAvcStep::Protocol {
            event: DigestAvcPoll::Client {
                event: Box::new(AvcClientPoll::Control(progress)),
                wire_retirement: None,
            },
            transport: None,
        }
    }

    #[test]
    fn starts_once_and_wakes_before_network_deadlines() {
        let mut driver = ControlDriver::new(7);
        assert_eq!(driver.next, Some(Action::Request(ClientCommand::Describe)));
        assert_eq!(driver.wake(Some(100)), Some(7));
        assert_eq!(driver.wake(None), Some(7));
        driver.next = None;
        assert_eq!(driver.wake(Some(100)), Some(100));
        assert_eq!(driver.wake(None), None);
    }

    #[test]
    fn advances_only_after_accepted_negotiation_responses() {
        let mut driver = ControlDriver::new(0);
        driver.next = None;
        driver.observe(&progress(ClientProgress::Interim), 1);
        assert_eq!(driver.next, None);
        driver.observe(
            &progress(ClientProgress::Accepted(ClientState::Described)),
            2,
        );
        assert_eq!(driver.next, Some(Action::Request(ClientCommand::Setup)));
        assert_eq!(driver.wake(Some(100)), Some(2));
        driver.next = None;
        driver.observe(&progress(ClientProgress::Accepted(ClientState::Ready)), 3);
        assert_eq!(driver.next, Some(Action::Request(ClientCommand::Play)));
        driver.next = None;
        driver.observe(&progress(ClientProgress::Accepted(ClientState::Playing)), 4);
        assert_eq!(driver.next, None);
    }

    #[test]
    fn keepalive_uses_the_existing_due_event_not_an_invented_timer() {
        let mut driver = ControlDriver::new(0);
        driver.next = None;
        driver.observe(&progress(ClientProgress::Pending), 10);
        assert_eq!(driver.next, None);
        driver.observe(&progress(ClientProgress::KeepAliveDue), 11);
        assert_eq!(driver.next, Some(Action::Request(ClientCommand::KeepAlive)));
        driver.next = None;
        driver.observe(
            &progress(ClientProgress::Accepted(ClientState::Playing)),
            12,
        );
        assert_eq!(driver.next, None);
    }

    #[test]
    fn eof_and_local_closure_never_reconnect_or_restart_play() {
        let mut driver = ControlDriver::new(0);
        driver.observe(&LiveAvcStep::InputEnded, 1);
        assert_eq!(driver.next, None);
        driver.observe(&progress(ClientProgress::Accepted(ClientState::Closed)), 2);
        assert_eq!(driver.next, None);
        driver.observe(&LiveAvcStep::Ended, 3);
        assert_eq!(driver.next, None);
        assert_eq!(driver.wake(None), None);
    }
}

#[cfg(test)]
mod recording_tests {
    use super::*;
    use crate::rtsp::live_avc::tests::{KEY, credentials, scope};
    use crate::rtsp::recording::RecordingScope;
    use crate::rtsp::recording_collector::CollectorLimits;
    use fss_core::{ContentDigest, SensorId, StreamId};
    use std::net::{Ipv4Addr, TcpListener};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn recording() -> TestResult<LiveRecordingConfig> {
        Ok(LiveRecordingConfig {
            scope: RecordingScope {
                sensor: SensorId::parse("sensor:automatic-fixture")?,
                stream: StreamId::parse("stream:automatic-fixture")?,
                generation: KEY.generation,
                anchor: ContentDigest::sha256(b"automatic recording anchor"),
                receive_clock: ContentDigest::sha256(b"automatic recording clock"),
            },
            payload_type: 96,
            time_scale: 90_000,
            limits: CollectorLimits::default(),
        })
    }

    #[test]
    fn invalid_recording_scope_does_not_open_a_camera_connection() -> TestResult {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (config, authority) = scope(listener.local_addr()?)?;
        let mut recording = recording()?;
        recording.time_scale = 0;
        let failure = AutomaticAvcRecording::connect(config, recording, 0, &authority)
            .err()
            .ok_or("invalid recording unexpectedly connected")?;
        assert!(!failure.connection_attempted);
        Ok(())
    }

    #[test]
    fn automatic_recording_cancel_preserves_queued_request_and_capture_ownership() -> TestResult {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (config, authority) = scope(listener.local_addr()?)?;
        let mut driver = AutomaticAvcRecording::connect(config, recording()?, 0, &authority)?;
        let (_peer, _) = listener.accept()?;
        assert_eq!(driver.next_wake_ns(), Some(0));
        let step = driver.poll(
            SocketReadiness::default(),
            &credentials()?,
            [1; 16],
            0,
            &authority,
        )?;
        let AutomaticRecordingStep::Queued(queued) = step else {
            return Err("missing initial recording command".into());
        };
        assert_eq!(queued.command, ClientCommand::Describe);
        assert_eq!(driver.totals().ok_or("missing totals")?.sent_bytes, 0);
        let retirement = driver.cancel().ok_or("missing recording retirement")?;
        let connection = retirement
            .connection
            .ok_or("missing connection ownership")?;
        let request = connection.transport.request.ok_or("lost queued request")?;
        assert_eq!(request.cseq(), queued.cseq);
        assert_eq!(connection.transport.request_sent_bytes, 0);
        assert!(!driver.needs_credentials());
        assert_eq!(driver.next_wake_ns(), None);
        assert!(driver.cancel().is_none());
        assert!(matches!(
            driver.poll(
                SocketReadiness::default(),
                &credentials()?,
                [2; 16],
                1,
                &authority
            )?,
            AutomaticRecordingStep::Recording(LiveRecordingStep::Ended)
        ));
        Ok(())
    }
}

#[cfg(test)]
mod reconnect_boundary_tests {
    use super::reconnect::{
        ReconnectPolicy, ReconnectRefusal, ReconnectStatus, ReconnectStop, SupervisedAvcConnection,
        SupervisedAvcError, SupervisedAvcStep,
    };
    use super::*;
    use crate::rtsp::live_avc::tests::{credentials, scope};
    use crate::rtsp::tcp::TcpDenial;
    use std::io::ErrorKind;
    use std::net::{Ipv4Addr, TcpListener};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

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
    fn reconnect_cannot_extend_the_owner_lease_or_consume_an_attempt_by_scope_error() -> TestResult
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let (mut config, authority) = scope(listener.local_addr()?)?;
        let mut owner =
            SupervisedAvcConnection::new(config.binding.clone(), policy(config.deadline_ns), 0)?;
        config.deadline_ns += 1;
        let failure = owner
            .connect(config, 0, &authority)
            .err()
            .ok_or("extended lease connected")?;
        assert!(matches!(
            failure.reason,
            SupervisedAvcError::Supervisor(ReconnectRefusal::Scope)
        ));
        assert!(failure.retirement.is_none());
        assert_eq!(
            listener
                .accept()
                .err()
                .ok_or("scope error opened a socket")?
                .kind(),
            ErrorKind::WouldBlock
        );
        let (config, authority) = scope(listener.local_addr()?)?;
        assert_eq!(owner.connect(config, 0, &authority)?.ordinal, 1);
        let (_peer, _) = listener.accept()?;
        assert!(owner.cancel().is_some());
        Ok(())
    }

    #[test]
    fn revoked_supervisor_returns_queued_native_work_once_without_sending_or_retrying() -> TestResult
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (config, authority) = scope(listener.local_addr()?)?;
        let mut owner =
            SupervisedAvcConnection::new(config.binding.clone(), policy(config.deadline_ns), 0)?;
        let attempt = owner.connect(config, 0, &authority)?;
        let (_peer, _) = listener.accept()?;
        assert!(matches!(
            owner.poll(
                SocketReadiness::default(),
                &credentials()?,
                [1; 16],
                0,
                &authority
            )?,
            SupervisedAvcStep::Connection {
                output: AutomaticAvcStep::Queued(_),
                ..
            }
        ));
        authority.revoked.set(true);
        let failure = owner
            .poll(
                SocketReadiness {
                    readable: true,
                    writable: true,
                },
                &credentials()?,
                [2; 16],
                1,
                &authority,
            )
            .err()
            .ok_or("revoked owner made progress")?;
        assert_eq!(failure.key, attempt.key);
        let retirement = failure.retirement.ok_or("lost queued native ownership")?;
        assert!(retirement.transport.request.is_some());
        assert_eq!(retirement.transport.request_sent_bytes, 0);
        assert_eq!(retirement.transport.totals.sent_bytes, 0);
        assert_eq!(
            owner.status(),
            ReconnectStatus::Stopped(ReconnectStop::Denied(TcpDenial::Revoked))
        );
        authority.revoked.set(false);
        let failure = owner
            .poll(
                SocketReadiness::default(),
                &credentials()?,
                [3; 16],
                2,
                &authority,
            )
            .err()
            .ok_or("revived a terminal supervisor")?;
        assert!(failure.retirement.is_none());
        assert!(owner.cancel().is_none());
        assert_eq!(owner.next_wake_ns(), None);
        Ok(())
    }
}
