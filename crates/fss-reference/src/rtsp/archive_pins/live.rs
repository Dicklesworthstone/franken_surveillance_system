#![forbid(unsafe_code)]
//! Actual native live capture with independent pin-journal commits, not auto-acknowledged memory.
use super::*;
use crate::rtsp::authentication::DigestCredentials;
use crate::rtsp::client::{ClientCommand, ClientState};
use crate::rtsp::live_avc::{LiveAvcConfig, QueuedAvcRequest, SocketReadiness};
use crate::rtsp::live_avc::recording::{LiveRecordingConfig, LiveRecordingRetirement, LiveRecordingStep};
use crate::rtsp::live_archive::{LiveArchiveConfig, LiveArchiveError, LiveArchiveStep};
use crate::rtsp::live_archive::checkpointed::{CheckpointedLiveArchiveFailure,
    CheckpointedLiveArchiveRetirement, CheckpointedLiveArchiveStep, CheckpointedLiveAvcArchive};
use crate::rtsp::recording::PreparedRecording;
use crate::rtsp::recording_archive::ArchiveSnapshot;
use crate::rtsp::recording_archive::checkpoint::write_ahead::CheckpointedArchiveProgress;
use crate::rtsp::recording_capture::TimedCapture;
use crate::rtsp::recording_collector::RecordingTiming;
use crate::rtsp::tcp::{TcpAuthority, TcpTotals};

/// Typed source versus independent metadata failure. Neither implies that all writes failed.
#[derive(Debug)]
pub enum JournaledLiveArchiveError {
    /// Existing camera/capture/archive failure or safe request/timing refusal.
    Live(LiveArchiveError),
    /// Independent recovery-reference persistence or integrity failure.
    Pins(ArchivePinError),
}
impl fmt::Display for JournaledLiveArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::Live(e) => fmt::Display::fmt(e, f), Self::Pins(e) => fmt::Display::fmt(e, f) }
    }
}
impl std::error::Error for JournaledLiveArchiveError {}
/// Failed preflight never starts a camera connection; actual connection failures say otherwise.
#[derive(Debug)]
pub struct JournaledLiveConnectFailure {
    /// Payload-free classification, not authorization to retry an effect.
    pub reason: JournaledLiveArchiveError,
    /// True only if the existing transport attempted a connection.
    pub connection_attempted: bool,
}
impl fmt::Display for JournaledLiveConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.reason, f) }
}
impl std::error::Error for JournaledLiveConnectFailure {}
/// Terminal ownership across camera, archive and independent metadata boundaries.
#[must_use]
#[derive(Debug)]
pub struct JournaledLiveRetirement {
    /// All original network/source/archive state from the existing exclusive owner.
    pub live: CheckpointedLiveArchiveRetirement,
    /// Work committed when its journal confirmation failed, if any.
    pub unrecorded_confirmation: Option<UnrecordedWorkConfirmation>,
    /// Last acknowledged metadata prefix, not a denial that an uncertain append exists.
    pub journal_anchor: ArchivePinAnchor,
    /// Both candidate and predecessor from that acknowledged prefix.
    pub pins: ArchivePinState,
}
/// Safe input correction leaves retirement absent; pin failures always stop native capture.
#[derive(Debug)]
pub struct JournaledLiveFailure {
    /// Existing failure or independent pin failure.
    pub reason: JournaledLiveArchiveError,
    /// Remaining ownership transferred exactly once on a fatal failure.
    pub retirement: Option<Box<JournaledLiveRetirement>>,
}
impl fmt::Display for JournaledLiveFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.reason, f) }
}
impl std::error::Error for JournaledLiveFailure {}
/// No new effect dialect: ordinary outputs are unchanged; independent metadata has its own receipt.
#[must_use]
#[derive(Debug)]
pub enum JournaledLiveArchiveStep {
    /// Existing wire/timing/archive/completion output; raw source custody is still explicit.
    Live(LiveArchiveStep),
    /// Candidate synchronization or work+confirmation synchronization, never PinRequired.
    Checkpoint(Box<JournaledArchiveProgress>),
    /// Original source failure without fabricated EOF or successful finalization.
    Stopped {
        /// Existing exact source/protocol/capture trigger.
        trigger: Box<LiveRecordingStep>,
        /// All still-owned source plus independent journal state.
        retained: Box<JournaledLiveRetirement>,
    },
}
/// Opt-in live owner whose acknowledgements follow actual independent journal synchronization.
/// No caller acknowledgement, mutable inner writer, background task or extra source queue.
/// A metadata error closes the socket before another normal archive publication can occur.
#[must_use]
pub struct JournaledLiveAvcArchive<'a, 'p> {
    inner: Option<CheckpointedLiveAvcArchive<'a>>,
    pins: &'p mut ArchivePinJournal,
    last_ns: u64,
    finished: bool,
}
impl fmt::Debug for JournaledLiveAvcArchive<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JournaledLiveAvcArchive").field("finished", &self.finished).finish_non_exhaustive()
    }
}
impl<'a, 'p> JournaledLiveAvcArchive<'a, 'p> {
    /// Validate journal namespace and settled prior work BEFORE connecting. The caller already
    /// owns each separately opened storage capability and its independent protection policy.
    #[allow(clippy::too_many_arguments)]
    pub fn connect(live: LiveAvcConfig, recording: LiveRecordingConfig, archive: LiveArchiveConfig,
        work: ArchiveWorkLimits, publisher: &'a mut LocalRootPublisher, pins: &'p mut ArchivePinJournal,
        now: u64, authority: &dyn TcpAuthority, cancel: &dyn PublishCancellation)
        -> Result<Self, JournaledLiveConnectFailure> {
        if pins.scope().archive_namespace != archive.namespace.digest() {
            return Err(JournaledLiveConnectFailure { reason: JournaledLiveArchiveError::Pins(ArchivePinError::Scope),
                connection_attempted: false });
        }
        pins.require_settled(publisher, work, cancel).map_err(|e| JournaledLiveConnectFailure {
            reason: JournaledLiveArchiveError::Pins(e), connection_attempted: false })?;
        let inner = CheckpointedLiveAvcArchive::connect(live, recording, archive, work, publisher, now, authority, cancel)
            .map_err(|e| JournaledLiveConnectFailure {
                reason: JournaledLiveArchiveError::Live(e.reason), connection_attempted: e.connection_attempted })?;
        Ok(Self { inner: Some(inner), pins, last_ns: now, finished: false })
    }
    /// Normal acknowledged archive inventory, not auxiliary work or pin records.
    pub fn snapshot(&self) -> Option<&ArchiveSnapshot> { self.inner.as_ref().and_then(|i| i.snapshot()) }
    /// Exact original pending recording; no source payload is copied by this owner.
    pub fn pending(&self) -> Option<&PreparedRecording> { self.inner.as_ref().and_then(|i| i.pending()) }
    /// Native protocol state, never physical coverage or complete capture.
    pub fn state(&self) -> ClientState { self.inner.as_ref().map_or(ClientState::Closed, |i| i.state()) }
    /// Actual socket observations while the underlying owner is still live.
    pub fn totals(&self) -> Option<TcpTotals> { self.inner.as_ref().and_then(|i| i.totals()) }
    /// Existing fixed deadlines; internal pin acknowledgement cannot extend a lease or pause.
    pub fn next_wake_ns(&self) -> Option<u64> {
        if self.finished { None } else { self.inner.as_ref().and_then(|i| i.next_wake_ns()) }
    }
    /// Last acknowledged independent journal prefix.
    pub fn journal_anchor(&self) -> ArchivePinAnchor { self.pins.anchor() }
    /// Read-only independent candidate/predecessor state.
    pub fn pin_state(&self) -> &ArchivePinState { self.pins.state() }
    /// Explicit protocol request with borrowed credentials; no automatic camera commands.
    #[allow(clippy::too_many_arguments)]
    pub fn request(&mut self, command: ClientCommand, credentials: &DigestCredentials<'_>, cnonce: [u8;16],
        now: u64, authority: &dyn TcpAuthority, cancel: &dyn PublishCancellation) -> Result<QueuedAvcRequest, JournaledLiveFailure> {
        self.admit(now, cancel)?;
        let result = self.inner.as_mut().ok_or_else(closed)?.request(command, credentials, cnonce, now, authority);
        result.map_err(|e| self.live_failure(e))
    }
    /// Answer only the existing held authentication challenge, without credential retention.
    pub fn respond(&mut self, credentials: &DigestCredentials<'_>, cnonce: [u8;16], now: u64,
        authority: &dyn TcpAuthority, cancel: &dyn PublishCancellation) -> Result<QueuedAvcRequest, JournaledLiveFailure> {
        self.admit(now, cancel)?;
        let result = self.inner.as_mut().ok_or_else(closed)?.respond(credentials, cnonce, now, authority);
        result.map_err(|e| self.live_failure(e))
    }
    /// Supply actual owner media timing; a safe refusal keeps the held picture intact.
    pub fn supply_timing(&mut self, timing: RecordingTiming, now: u64, authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation) -> Result<TimedCapture, JournaledLiveFailure> {
        self.admit(now, cancel)?;
        let result = self.inner.as_mut().ok_or_else(closed)?.supply_timing(timing, now, authority);
        result.map_err(|e| self.live_failure(e))
    }
    /// Prepare only a completed prefix; every resulting window still crosses both barriers.
    pub fn seal(&mut self, now: u64, authority: &dyn TcpAuthority, cancel: &dyn PublishCancellation) -> Result<bool, JournaledLiveFailure> {
        self.admit(now, cancel)?;
        let result = self.inner.as_mut().ok_or_else(closed)?.seal(now, authority);
        result.map_err(|e| self.live_failure(e))
    }
    /// Request a page through its independently persisted checkpoint, without ending capture.
    pub fn flush(&mut self, now: u64, authority: &dyn TcpAuthority, cancel: &dyn PublishCancellation) -> Result<(), JournaledLiveFailure> {
        self.admit(now, cancel)?;
        let result = self.inner.as_mut().ok_or_else(closed)?.flush(now, authority);
        result.map_err(|e| self.live_failure(e))
    }
    /// Explicitly stop input and transfer unsealed/untimed work; accepted windows drain separately.
    pub fn finish_capture(&mut self, now: u64, authority: &dyn TcpAuthority, cancel: &dyn PublishCancellation)
        -> Result<Option<LiveRecordingRetirement>, JournaledLiveFailure> {
        self.admit(now, cancel)?;
        let result = self.inner.as_mut().ok_or_else(closed)?.finish_capture(now, authority);
        result.map_err(|e| self.live_failure(e))
    }
    /// One existing live/storage step plus a bounded independent pin append when required.
    /// Pin preparation may read source metadata, but its append precedes work publication.
    /// Work confirmation appends after work commits and before any normal archive write.
    /// No socket operation accompanies either metadata append; no failed append is auto-retried.
    pub fn poll(&mut self, readiness: SocketReadiness, now: u64, authority: &dyn TcpAuthority,
        cancel: &dyn PublishCancellation) -> Result<JournaledLiveArchiveStep, JournaledLiveFailure> {
        if self.finished || self.inner.is_none() { return Ok(JournaledLiveArchiveStep::Live(LiveArchiveStep::Ended)); }
        self.admit(now, cancel)?;
        let step = self.inner.as_mut().ok_or_else(closed)?.poll(readiness, now, authority, cancel)
            .map_err(|e| self.live_failure(e))?;
        match step {
            CheckpointedLiveArchiveStep::Checkpoint(CheckpointedArchiveProgress::PinRequired(checkpoint)) => {
                let receipt = self.pins.persist_candidate(&checkpoint, cancel).map_err(|e| self.pin_failure(e, None))?;
                self.inner.as_mut().ok_or_else(closed)?.acknowledge_checkpoint(&checkpoint, now, authority, cancel)
                    .map_err(|e| self.live_failure(e))?;
                Ok(JournaledLiveArchiveStep::Checkpoint(Box::new(JournaledArchiveProgress::PinPersisted { checkpoint, receipt })))
            }
            CheckpointedLiveArchiveStep::Checkpoint(CheckpointedArchiveProgress::WorkDurable { checkpoint, receipt }) => {
                match self.pins.confirm_receipt(&checkpoint, &receipt, cancel) {
                    Ok(pin_receipt) => Ok(JournaledLiveArchiveStep::Checkpoint(Box::new(JournaledArchiveProgress::WorkConfirmed {
                        checkpoint, work_receipt: receipt, pin_receipt }))),
                    Err(e) => Err(self.pin_failure(e, Some(UnrecordedWorkConfirmation { checkpoint, receipt }))),
                }
            }
            CheckpointedLiveArchiveStep::Checkpoint(CheckpointedArchiveProgress::Archive(progress)) => {
                Ok(JournaledLiveArchiveStep::Live(LiveArchiveStep::Archive(progress)))
            }
            CheckpointedLiveArchiveStep::Live(step) => {
                if matches!(&step, LiveArchiveStep::Finished { .. } | LiveArchiveStep::Ended) { self.finished = true; }
                Ok(JournaledLiveArchiveStep::Live(step))
            }
            CheckpointedLiveArchiveStep::Stopped { trigger, retained } => {
                self.finished = true; self.inner = None;
                Ok(JournaledLiveArchiveStep::Stopped { trigger, retained: Box::new(self.retirement(*retained, None)) })
            }
        }
    }
    /// Stop without writing, forgetting source, or claiming remote teardown. Metadata remains on disk.
    pub fn cancel(&mut self) -> Option<JournaledLiveRetirement> {
        self.finished = true;
        self.inner.take().and_then(|mut inner| inner.cancel()).map(|r| self.retirement(r, None))
    }
    fn admit(&mut self, now: u64, cancel: &dyn PublishCancellation) -> Result<(), JournaledLiveFailure> {
        if self.finished || self.inner.is_none() { return Err(closed()); }
        if now < self.last_ns {
            return Err(JournaledLiveFailure { reason: JournaledLiveArchiveError::Live(LiveArchiveError::ClockReversed), retirement: None });
        }
        self.last_ns = now;
        self.pins.verify_tip(cancel).map_err(|e| self.pin_failure(e, None))
    }
    fn retirement(&self, live: CheckpointedLiveArchiveRetirement, unrecorded: Option<UnrecordedWorkConfirmation>) -> JournaledLiveRetirement {
        JournaledLiveRetirement { live, unrecorded_confirmation: unrecorded,
            journal_anchor: self.pins.anchor(), pins: self.pins.state().clone() }
    }
    fn pin_failure(&mut self, error: ArchivePinError, unrecorded: Option<UnrecordedWorkConfirmation>) -> JournaledLiveFailure {
        self.finished = true;
        let retirement = self.inner.take().and_then(|mut inner| inner.cancel())
            .map(|r| Box::new(self.retirement(r, unrecorded)));
        JournaledLiveFailure { reason: JournaledLiveArchiveError::Pins(error), retirement }
    }
    fn live_failure(&mut self, error: CheckpointedLiveArchiveFailure) -> JournaledLiveFailure {
        let retirement = error.retirement.map(|r| {
            self.finished = true; self.inner = None; Box::new(self.retirement(*r, None))
        });
        JournaledLiveFailure { reason: JournaledLiveArchiveError::Live(error.reason), retirement }
    }
}
fn closed() -> JournaledLiveFailure {
    JournaledLiveFailure { reason: JournaledLiveArchiveError::Live(LiveArchiveError::Closed), retirement: None }
}
