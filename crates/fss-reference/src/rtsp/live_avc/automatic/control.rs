#![forbid(unsafe_code)]
//! Pure sequencing for the existing explicitly authorized AVC owners.
//! This state machine performs no I/O, stores no credentials and grants no effects.

use crate::rtsp::avc_client::{AvcClientError, AvcClientPoll};
use crate::rtsp::avc_client::authenticated::{DigestAvcError, DigestAvcPoll};
use crate::rtsp::client::{ClientCommand, ClientProgress, ClientState};
use crate::rtsp::live_avc::{LiveAvcError, LiveAvcStep};
use crate::rtsp::tcp::TcpError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Action {
    Request(ClientCommand),
    Respond,
}

/// An unsent intent is different from a prepared request. Only the former may wait
/// for protocol drainage; this owner never replays a prepared or partially sent request.
#[derive(Debug)]
pub(super) struct ControlDriver {
    pub(super) next: Option<Action>,
    ready_at_ns: u64,
    draining: bool,
}
impl ControlDriver {
    pub(super) fn new(now: u64) -> Self {
        Self { next: Some(Action::Request(ClientCommand::Describe)), ready_at_ns: now, draining: false }
    }

    pub(super) fn action(&self) -> Option<Action> {
        self.next.filter(|_| !self.draining)
    }

    pub(super) fn wake(&self, underlying: Option<u64>) -> Option<u64> {
        match (self.action(), underlying) {
            (Some(_), Some(at)) => Some(at.min(self.ready_at_ns)),
            (Some(_), None) => Some(self.ready_at_ns),
            (None, at) => at,
        }
    }

    pub(super) fn clear(&mut self) {
        self.next = None;
        self.draining = false;
    }

    pub(super) fn refused(&mut self, reason: &LiveAvcError, retired: bool) {
        if retired || matches!(reason, LiveAvcError::Closed) {
            self.clear();
        } else if self.next.is_some() && backpressured(reason) {
            // Repeating request() cannot drain the input which made request() refuse.
            // The next call must enter the original native poll, not borrow credentials again.
            self.draining = true;
        }
        // Clock and other safe correction refusals change neither intent nor drain state.
    }

    pub(super) fn observe(&mut self, step: &LiveAvcStep, now: u64) {
        if terminal(step) {
            self.clear();
            return;
        }
        let action = match step {
            LiveAvcStep::Protocol {
                event: DigestAvcPoll::AuthenticationRequired { .. }, transport: None,
            } => Some(Action::Respond),
            LiveAvcStep::Protocol {
                event: DigestAvcPoll::Client { event, wire_retirement: None }, transport: None,
            } => match event.as_ref() {
                AvcClientPoll::Control(ClientProgress::Accepted(ClientState::Described)) =>
                    Some(Action::Request(ClientCommand::Setup)),
                AvcClientPoll::Control(ClientProgress::Accepted(ClientState::Ready)) =>
                    Some(Action::Request(ClientCommand::Play)),
                AvcClientPoll::Control(ClientProgress::KeepAliveDue) =>
                    Some(Action::Request(ClientCommand::KeepAlive)),
                _ => None,
            },
            _ => None,
        };
        if let Some(action) = action {
            self.next = Some(action);
            self.draining = false;
            self.ready_at_ns = now;
        } else if matches!(step, LiveAvcStep::Pending(_)) && self.draining {
            // The original native owner reached a wait. A partial frame may still refuse
            // preparation; another bounded drain turn then resumes its exact suffix.
            self.draining = false;
            self.ready_at_ns = now;
        }
        // Original wire, RTP/RTCP, interim replies and parser/media work never erase an
        // outstanding unsent intent. No source output is swallowed to advance control.
    }
}

fn backpressured(reason: &LiveAvcError) -> bool {
    matches!(reason,
        LiveAvcError::Backpressure
        | LiveAvcError::Transport(TcpError::Backpressure)
        | LiveAvcError::Protocol(DigestAvcError::Backpressure)
        | LiveAvcError::Protocol(DigestAvcError::Client(AvcClientError::Backpressure)))
}
fn terminal(step: &LiveAvcStep) -> bool {
    match step {
        LiveAvcStep::InputEnded | LiveAvcStep::Ended => true,
        LiveAvcStep::Protocol { transport: Some(_), .. }
        | LiveAvcStep::Protocol { event: DigestAvcPoll::Fault { .. }, .. } => true,
        LiveAvcStep::Protocol {
            event: DigestAvcPoll::Client { event, wire_retirement }, ..
        } => wire_retirement.is_some() || matches!(event.as_ref(),
            AvcClientPoll::Fault { .. } | AvcClientPoll::Ended { .. }
            | AvcClientPoll::Rtp { retirement: Some(_), .. }
            | AvcClientPoll::Control(ClientProgress::Accepted(ClientState::Closed | ClientState::Failed))),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtsp::live_avc::LiveAvcWait;

    fn progress(progress: ClientProgress) -> LiveAvcStep {
        LiveAvcStep::Protocol {
            event: DigestAvcPoll::Client {
                event: Box::new(AvcClientPoll::Control(progress)), wire_retirement: None,
            },
            transport: None,
        }
    }
    fn pending(at: u64) -> LiveAvcStep {
        LiveAvcStep::Pending(LiveAvcWait { readable: true, writable: false, wake_at_ns: Some(at) })
    }

    #[test]
    fn safe_backpressure_drains_instead_of_repeating_preparation() {
        let mut c = ControlDriver::new(0);
        c.clear();
        c.observe(&progress(ClientProgress::Accepted(ClientState::Described)), 1);
        c.refused(&LiveAvcError::Protocol(DigestAvcError::Backpressure), false);
        assert_eq!(c.next, Some(Action::Request(ClientCommand::Setup)));
        assert_eq!(c.action(), None);
        assert_eq!(c.wake(Some(50)), Some(50));
        c.observe(&progress(ClientProgress::Interim), 2);
        assert_eq!(c.next, Some(Action::Request(ClientCommand::Setup)));
        assert_eq!(c.action(), None);
        c.observe(&pending(50), 3);
        assert_eq!(c.action(), Some(Action::Request(ClientCommand::Setup)));
        assert_eq!(c.wake(Some(50)), Some(3));
    }

    #[test]
    fn clock_refusal_does_not_rearm_a_blocked_preparation() {
        let mut c = ControlDriver::new(10);
        c.refused(&LiveAvcError::Backpressure, false);
        c.refused(&LiveAvcError::ClockReversed, false);
        assert_eq!(c.action(), None);
        assert_eq!(c.wake(Some(90)), Some(90));
        c.observe(&pending(90), 11);
        assert_eq!(c.wake(Some(90)), Some(11));
    }

    #[test]
    fn held_challenge_is_answerable_without_another_drain_loop() {
        let mut c = ControlDriver::new(0);
        c.refused(&LiveAvcError::Backpressure, false);
        c.observe(&LiveAvcStep::Protocol {
            event: DigestAvcPoll::AuthenticationRequired { cseq: 1, wake_at_ns: Some(40) },
            transport: None,
        }, 2);
        assert_eq!(c.action(), Some(Action::Respond));
        assert_eq!(c.wake(Some(40)), Some(2));
    }

    #[test]
    fn terminal_or_fatal_progress_never_rearms_a_deferred_command() {
        for terminal in [LiveAvcStep::InputEnded, LiveAvcStep::Ended,
            progress(ClientProgress::Accepted(ClientState::Closed))]
        {
            let mut c = ControlDriver::new(0);
            c.refused(&LiveAvcError::Backpressure, false);
            c.observe(&terminal, 1);
            assert_eq!(c.action(), None);
            assert_eq!(c.next, None);
            assert_eq!(c.wake(None), None);
        }
        let mut c = ControlDriver::new(0);
        c.refused(&LiveAvcError::Backpressure, true);
        assert_eq!(c.next, None);
        c.observe(&pending(20), 1);
        assert_eq!(c.action(), None);
    }

    #[test]
    fn repeated_partial_input_refusals_preserve_the_same_unsent_command() {
        let mut c = ControlDriver::new(0);
        for now in 1..32 {
            c.refused(&LiveAvcError::Protocol(DigestAvcError::Backpressure), false);
            assert_eq!(c.action(), None);
            c.observe(&pending(100), now);
            assert_eq!(c.action(), Some(Action::Request(ClientCommand::Describe)));
        }
        c.clear(); // exact successful queue admission, not remote acknowledgement
        c.observe(&pending(100), 32);
        assert_eq!(c.action(), None);
    }
}
