#![forbid(unsafe_code)]
//! Opt-in automatic control of one explicitly authorized live AVC connection.
//!
//! A call either prepares one request or returns one unchanged live output. It never
//! hides source bytes, retries an uncertain write, reconnects, extends a lease, or
//! retains credentials. Owners still schedule readiness/deadlines and retain every
//! wire/media/retirement output before polling again.

use super::*;
use crate::rtsp::client::ClientProgress;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    Request(ClientCommand),
    Respond,
}

/// Shared sequencing only; protocol validation and effect authority remain with
/// the existing live owner. State names alone never authorize another request.
#[derive(Debug)]
struct ControlDriver {
    next: Option<Action>,
    ready_at_ns: u64,
}
impl ControlDriver {
    fn new(now: u64) -> Self {
        Self {
            next: Some(Action::Request(ClientCommand::Describe)),
            ready_at_ns: now,
        }
    }

    fn wake(&self, underlying: Option<u64>) -> Option<u64> {
        if self.next.is_some() {
            earlier(Some(self.ready_at_ns), underlying)
        } else {
            underlying
        }
    }

    fn observe(&mut self, step: &LiveAvcStep, now: u64) {
        self.next = match step {
            LiveAvcStep::Protocol {
                event: DigestAvcPoll::AuthenticationRequired { .. },
                transport: None,
            } => Some(Action::Respond),
            LiveAvcStep::Protocol {
                event:
                    DigestAvcPoll::Client {
                        event,
                        wire_retirement: None,
                    },
                transport: None,
            } => match event.as_ref() {
                AvcClientPoll::Control(ClientProgress::Accepted(ClientState::Described)) => {
                    Some(Action::Request(ClientCommand::Setup))
                }
                AvcClientPoll::Control(ClientProgress::Accepted(ClientState::Ready)) => {
                    Some(Action::Request(ClientCommand::Play))
                }
                AvcClientPoll::Control(ClientProgress::KeepAliveDue) => {
                    Some(Action::Request(ClientCommand::KeepAlive))
                }
                _ => None,
            },
            _ => None,
        };
        self.ready_at_ns = now;
    }
}

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
    /// Credentials are never retained by this owner, even while a write is pending.
    pub fn needs_credentials(&self) -> bool {
        self.control.next.is_some()
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
    /// Supply a fresh owner-generated cnonce for each admitted preparation. On
    /// other calls it is unused. A safe refusal leaves the scheduled action intact;
    /// a fatal refusal transfers the original retirement and stops sequencing.
    pub fn poll(
        &mut self,
        readiness: SocketReadiness,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<AutomaticAvcStep, LiveAvcFailure> {
        if let Some(action) = self.control.next {
            let result = match action {
                Action::Request(command) => {
                    self.connection.request(command, credentials, cnonce, now, authority)
                }
                Action::Respond => self.connection.respond(credentials, cnonce, now, authority),
            };
            return match result {
                Ok(receipt) => {
                    self.control.next = None;
                    Ok(AutomaticAvcStep::Queued(receipt))
                }
                Err(failure) => {
                    if failure.retirement.is_some() {
                        self.control.next = None;
                    }
                    Err(failure)
                }
            };
        }
        let step = self.connection.poll(readiness, now, authority)?;
        self.control.observe(&step, now);
        Ok(AutomaticAvcStep::Live(step))
    }

    /// Cancel without sending TEARDOWN, even after permission was revoked.
    /// Return every retained layer exactly once; no remote completion is asserted.
    pub fn cancel(&mut self) -> Option<LiveAvcRetirement> {
        self.control.next = None;
        self.connection.cancel()
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
        driver.observe(&progress(ClientProgress::Accepted(ClientState::Described)), 2);
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
        driver.observe(&progress(ClientProgress::Accepted(ClientState::Playing)), 12);
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
