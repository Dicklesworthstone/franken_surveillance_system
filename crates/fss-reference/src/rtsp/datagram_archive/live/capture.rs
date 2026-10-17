#![forbid(unsafe_code)]
//! Native AVC capture whose original interleaved source crosses custody before release.
//! No bare capture escape, control-message retention, source queue, guessed timing or reconnect.

use super::*;
use crate::rtsp::authentication::DigestCredentials;
use crate::rtsp::avc_client::AvcClientPoll;
use crate::rtsp::avc_client::authenticated::DigestAvcPoll;
use crate::rtsp::client::{ClientCommand, ClientState};
use crate::rtsp::live_avc::recording::{
    LiveAvcRecording, LiveRecordingConfig, LiveRecordingError, LiveRecordingFailure,
    LiveRecordingRetirement, LiveRecordingStep,
};
use crate::rtsp::live_avc::{LiveAvcConfig, LiveAvcStep, QueuedAvcRequest, SocketReadiness};
use crate::rtsp::recording_capture::{CapturePoll, TimedCapture};
use crate::rtsp::recording_collector::RecordingTiming;
use crate::rtsp::tcp::{TcpAuthority, TcpDenial, TcpOperation, TcpTotals};
use std::path::PathBuf;

/// Original errors keep their storage/network/capture distinction and private payloads separate.
#[derive(Debug)]
pub enum RetainedRecordingError {
    /// Inconsistent source/recording/transport scope, owner path or initial lease.
    Configuration,
    /// The epoch already has source observations; reconstruct it, do not silently append a new connection.
    ExistingSource,
    /// Original capture failure, including safe correction and fatal network outcomes.
    Capture(LiveRecordingError),
    /// Original typed custody failure, including uncertain root publication.
    Custody(DatagramArchiveError),
    /// Exact live network authority refused progress, including after a storage syscall.
    Authority(TcpDenial),
    /// The trusted operation clock regressed without consuming source or renewing a budget.
    ClockReversed,
    /// The independent complete-owner command/poll budget was exhausted.
    WorkBudget,
    /// Terminal ownership has already transferred.
    Closed,
}
impl std::fmt::Display for RetainedRecordingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "retained AVC recording refused: {self:?}")
    }
}
impl std::error::Error for RetainedRecordingError {}
/// Construction performs read-only source recovery before a single native connection attempt.
#[derive(Debug)]
pub struct RetainedRecordingConnectFailure {
    /// Typed configuration/storage/network failure.
    pub reason: RetainedRecordingError,
    /// The peer may have observed a TCP attempt, not an RTSP acknowledgement.
    pub connection_attempted: bool,
}
impl std::fmt::Display for RetainedRecordingConnectFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for RetainedRecordingConnectFailure {}

/// Every unfinished source is transferred, never deleted or called durably retained on failure.
#[derive(Debug)]
#[must_use]
pub struct RetainedRecordingRetirement {
    /// Original capture/network retirement; a terminal trigger may already own it instead.
    pub capture: Option<LiveRecordingRetirement>,
    /// Original event withheld by a custody failure, including its intact source datagram.
    pub trigger: Option<Box<LiveRecordingStep>>,
    /// Last locally acknowledged source prefix; not a complete-recording claim.
    pub prefix: DatagramPin,
    /// Prepared candidate when publication was attempted; may already be durable after an error.
    pub candidate: Option<DatagramPin>,
    /// Actual completed publication withheld by post-I/O authority/cancellation failure.
    pub publication: Option<DatagramPublication>,
}
/// Safe corrections have no retirement. Every fatal refusal closes the native capture owner.
#[derive(Debug)]
pub struct RetainedRecordingFailure {
    /// Typed cause; no input bytes, credentials or private paths are displayed.
    pub reason: RetainedRecordingError,
    /// Remaining exact input and recovery identities when the owner stopped.
    pub retirement: Option<Box<RetainedRecordingRetirement>>,
}
impl std::fmt::Display for RetainedRecordingFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for RetainedRecordingFailure {}
/// An unchanged capture event, with a current durable receipt only for original interleaved source.
#[derive(Debug)]
#[must_use]
pub struct RetainedRecordingStep {
    /// Existing wire/control/source/timing/window/terminal result. Prepared windows still need publication.
    pub event: LiveRecordingStep,
    /// Original RTP/RTCP source root published before this event or any later picture is released.
    /// None for TCP/control bytes, derived media, prepared windows and EOF.
    pub datagram: Option<DatagramPublication>,
}

/// Source-retaining native recording owner. The publisher is explicitly supplied to each poll,
/// allowing the caller to publish returned windows with the SAME owner between polls. Its exact
/// root directory and source scope cannot change. No mutable inner capture API is exposed.
#[must_use]
pub struct RetainedAvcRecording {
    capture: LiveAvcRecording,
    archive: DatagramArchive,
    publisher_root: PathBuf,
    deadline_ns: u64,
    last_ns: u64,
    remaining_steps: u64,
    closed: bool,
}
impl std::fmt::Debug for RetainedAvcRecording {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedAvcRecording")
            .field("prefix", &self.archive.pin())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}
impl RetainedAvcRecording {
    /// Validate all cross-owner identities and an empty source namespace before connecting.
    /// Recovery reads use the supplied custody capability; no source/root is published here.
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        live: LiveAvcConfig,
        recording: LiveRecordingConfig,
        scope: DatagramScope,
        limits: DatagramArchiveLimits,
        publisher: &LocalRootPublisher,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> std::result::Result<Self, RetainedRecordingConnectFailure> {
        let refused = |reason| RetainedRecordingConnectFailure {
            reason,
            connection_attempted: false,
        };
        if scope.binding != live.binding
            || scope.channels != live.protocol.channels
            || scope.receive_clock != recording.scope.receive_clock
            || now >= live.deadline_ns
            || live.max_steps == 0
        {
            return Err(refused(RetainedRecordingError::Configuration));
        }
        let archive = DatagramArchive::recover(publisher, scope, limits, None, cancel, budget)
            .map_err(|e| refused(RetainedRecordingError::Custody(e)))?;
        if archive.pin().datagrams != 0 {
            return Err(refused(RetainedRecordingError::ExistingSource));
        }
        let deadline_ns = live.deadline_ns;
        let remaining_steps = live.max_steps;
        let publisher_root = publisher.root_dir().to_path_buf();
        let capture = LiveAvcRecording::connect(live, recording, now, authority).map_err(|e| {
            RetainedRecordingConnectFailure {
                reason: RetainedRecordingError::Capture(e.reason),
                connection_attempted: e.connection_attempted,
            }
        })?;
        Ok(Self {
            capture,
            archive,
            publisher_root,
            deadline_ns,
            last_ns: now,
            remaining_steps,
            closed: false,
        })
    }
    /// Last acknowledged original-source prefix, not complete capture or current whole-prefix custody.
    pub fn pin(&self) -> DatagramPin {
        self.archive.pin()
    }
    /// Immutable source interpretation, for later independently authorized recovery.
    pub fn scope(&self) -> &DatagramScope {
        self.archive.scope()
    }
    /// Existing local protocol state, not recording/coverage status.
    pub fn state(&self) -> ClientState {
        self.capture.state()
    }
    /// Live transport counts. Terminal values remain in the original retirement.
    pub fn totals(&self) -> Option<TcpTotals> {
        self.capture.totals()
    }
    /// Existing media/partial-input deadlines are never reset by source storage.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.closed {
            None
        } else {
            self.capture.next_wake_ns()
        }
    }
    /// Prepare one existing RTSP command with borrowed credentials, without an automatic effect.
    pub fn request(
        &mut self,
        command: ClientCommand,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> std::result::Result<QueuedAvcRequest, RetainedRecordingFailure> {
        self.admit(now, authority, cancel)?;
        let out = self
            .capture
            .request(command, credentials, cnonce, now, authority);
        out.map_err(|e| self.capture_failure(e))
    }
    /// Answer only the existing held challenge; no credentials are retained in source storage.
    pub fn respond(
        &mut self,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> std::result::Result<QueuedAvcRequest, RetainedRecordingFailure> {
        self.admit(now, authority, cancel)?;
        let out = self.capture.respond(credentials, cnonce, now, authority);
        out.map_err(|e| self.capture_failure(e))
    }
    /// Independent DTS/duration/composition offset. Invalid timing preserves the same pending picture.
    pub fn supply_timing(
        &mut self,
        timing: RecordingTiming,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> std::result::Result<TimedCapture, RetainedRecordingFailure> {
        self.admit(now, authority, cancel)?;
        let out = self.capture.supply_timing(timing, now, authority);
        out.map_err(|e| self.capture_failure(e))
    }
    /// Seal only an actual completed picture prefix. This does not publish a recording root.
    pub fn seal(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> std::result::Result<bool, RetainedRecordingFailure> {
        self.admit(now, authority, cancel)?;
        let out = self.capture.seal(now, authority);
        out.map_err(|e| self.capture_failure(e))
    }
    /// One existing capture step. Any original datagram, including terminal admission failures,
    /// is synchronously rooted before release. Such protocol-output steps do no socket I/O;
    /// no later media/timing/window event can bypass this source-publication barrier.
    #[allow(clippy::too_many_arguments)]
    pub fn poll(
        &mut self,
        readiness: SocketReadiness,
        now: u64,
        authority: &dyn TcpAuthority,
        publisher: &mut LocalRootPublisher,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> std::result::Result<RetainedRecordingStep, RetainedRecordingFailure> {
        if self.closed {
            return Ok(RetainedRecordingStep {
                event: LiveRecordingStep::Ended,
                datagram: None,
            });
        }
        self.admit(now, authority, cancel)?;
        if publisher.root_dir() != self.publisher_root.as_path() {
            return Err(self.fail(RetainedRecordingError::Configuration, None, None, None));
        }
        if let Err(e) = self
            .archive
            .ready(publisher)
            .and_then(|()| budget.charge(1).map_err(Into::into))
        {
            return Err(self.fail(RetainedRecordingError::Custody(e), None, None, None));
        }
        let step = self
            .capture
            .poll(readiness, now, authority)
            .map_err(|e| self.capture_failure(e))?;
        let mut candidate = None;
        let stored = (|| {
            let Some(source) = source(&step) else {
                return Ok(None);
            };
            let plan = self.archive.prepare(source, budget)?;
            candidate = Some(plan.pin());
            // Both owner capabilities are checked inside existing publication cut points.
            // The live probe, not `now`, is responsible for actual elapsed syscall time.
            let guard = SourceGuard {
                authority,
                cancel,
                binding: self.archive.scope.binding.clone(),
                now,
                deadline: self.deadline_ns,
            };
            self.archive
                .publish(&plan, publisher, &guard, budget)
                .map(Some)
        })();
        let datagram = match stored {
            Ok(receipt) => receipt,
            Err(error) => {
                return Err(self.fail(
                    RetainedRecordingError::Custody(error),
                    Some(step),
                    candidate,
                    None,
                ));
            }
        };
        if let Err(reason) = self.check_live(now, authority, cancel) {
            return Err(self.fail(reason, Some(step), candidate, datagram));
        }
        if matches!(
            &step,
            LiveRecordingStep::Stopped { .. } | LiveRecordingStep::Ended
        ) || matches!(
            step.capture_event(),
            Some(CapturePoll::Stopped { .. } | CapturePoll::Ended { .. })
        ) {
            self.closed = true;
        }
        Ok(RetainedRecordingStep {
            event: step,
            datagram,
        })
    }
    /// Close capture and transfer unfinished work without publication, deletion or implicit teardown.
    pub fn cancel(&mut self) -> Option<RetainedRecordingRetirement> {
        if self.closed {
            return None;
        }
        self.closed = true;
        Some(RetainedRecordingRetirement {
            capture: self.capture.cancel(),
            trigger: None,
            prefix: self.pin(),
            candidate: None,
            publication: None,
        })
    }
    fn check_live(
        &self,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> std::result::Result<(), RetainedRecordingError> {
        if now >= self.deadline_ns {
            return Err(RetainedRecordingError::Authority(TcpDenial::Deadline));
        }
        probe(cancel).map_err(RetainedRecordingError::Custody)?;
        authority
            .checkpoint(
                &self.archive.scope.binding,
                TcpOperation::Poll,
                now,
                self.deadline_ns,
            )
            .map_err(RetainedRecordingError::Authority)
    }
    fn admit(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation,
    ) -> std::result::Result<(), RetainedRecordingFailure> {
        if self.closed {
            return Err(safe(RetainedRecordingError::Closed));
        }
        if now < self.last_ns {
            return Err(safe(RetainedRecordingError::ClockReversed));
        }
        if self.remaining_steps == 0 {
            return Err(self.fail(RetainedRecordingError::WorkBudget, None, None, None));
        }
        self.last_ns = now;
        self.remaining_steps -= 1;
        self.check_live(now, authority, cancel)
            .map_err(|e| self.fail(e, None, None, None))
    }
    fn capture_failure(&mut self, e: LiveRecordingFailure) -> RetainedRecordingFailure {
        let retirement = e.retirement.map(|r| {
            self.closed = true;
            Box::new(RetainedRecordingRetirement {
                capture: Some(*r),
                trigger: None,
                prefix: self.pin(),
                candidate: None,
                publication: None,
            })
        });
        RetainedRecordingFailure {
            reason: RetainedRecordingError::Capture(e.reason),
            retirement,
        }
    }
    fn fail(
        &mut self,
        reason: RetainedRecordingError,
        trigger: Option<LiveRecordingStep>,
        candidate: Option<DatagramPin>,
        publication: Option<DatagramPublication>,
    ) -> RetainedRecordingFailure {
        self.closed = true;
        RetainedRecordingFailure {
            reason,
            retirement: Some(Box::new(RetainedRecordingRetirement {
                capture: self.capture.cancel(),
                trigger: trigger.map(Box::new),
                prefix: self.pin(),
                candidate,
                publication,
            })),
        }
    }
}
fn safe(reason: RetainedRecordingError) -> RetainedRecordingFailure {
    RetainedRecordingFailure {
        reason,
        retirement: None,
    }
}
fn source(step: &LiveRecordingStep) -> Option<&InterleavedSource> {
    let network = match step {
        LiveRecordingStep::Network(network) => network,
        LiveRecordingStep::Stopped { trigger, .. } => trigger.as_ref(),
        _ => return None,
    };
    let LiveAvcStep::Protocol {
        event: DigestAvcPoll::Client { event, .. },
        ..
    } = network
    else {
        return None;
    };
    match event.as_ref() {
        AvcClientPoll::Rtp { source, .. }
        | AvcClientPoll::Rtcp { source, .. }
        | AvcClientPoll::Fault {
            source: Some(source),
            ..
        } => Some(source),
        _ => None,
    }
}
struct SourceGuard<'a> {
    authority: &'a dyn TcpAuthority,
    cancel: &'a dyn PublishCancellation,
    binding: TcpBinding,
    now: u64,
    deadline: u64,
}
impl PublishCancellation for SourceGuard<'_> {
    fn cancel_requested(&self, cut: PublishCutPoint) -> bool {
        self.cancel.cancel_requested(cut)
            || self
                .authority
                .checkpoint(&self.binding, TcpOperation::Poll, self.now, self.deadline)
                .is_err()
    }
}
