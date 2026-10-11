#![forbid(unsafe_code)]
//! One approved native AVC attempt, with durable original-window custody and independent pins.
//! Selected original RTP datagrams are archived. Raw TCP/control/RTCP, startup pictures,
//! and unsealed terminal work are explicitly accounted for, never called durable recordings.

use std::cell::Cell;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fss_cli::agent_json::{object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_publication::{
    LocalPublicationState, LocalRootPublisher, PublishCancellation, PublishCutPoint,
};
use fss_reference::ReplayCx;
use fss_reference::rtsp::archive_pins::live::{
    JournaledLiveArchiveError, JournaledLiveArchiveStep, JournaledLiveAvcArchive,
    JournaledLiveFailure,
};
use fss_reference::rtsp::archive_pins::{ArchivePinJournal, JournaledArchiveProgress};
use fss_reference::rtsp::authentication::DigestCredentials;
use fss_reference::rtsp::avc_client::AvcClientPoll;
use fss_reference::rtsp::avc_client::authenticated::DigestAvcPoll;
use fss_reference::rtsp::client::{ClientCommand, ClientProgress, ClientState};
use fss_reference::rtsp::live_archive::{LiveArchiveCompletion, LiveArchiveError, LiveArchiveStep};
use fss_reference::rtsp::live_avc::recording::{LiveRecordingError, LiveRecordingStep};
use fss_reference::rtsp::live_avc::{LiveAvcError, LiveAvcStep, SocketReadiness};
use fss_reference::rtsp::recording_archive::ArchiveWriteProgress;
use fss_reference::rtsp::recording_capture::{CaptureError, CapturePoll, TimedCapture};
use fss_reference::rtsp::recording_collector::CollectorError;
use fss_reference::rtsp::tcp::{TcpAuthority, TcpBinding, TcpDenial, TcpError, TcpOperation};

use super::plan::Options;
use super::timing::FixedTiming;

#[path = "report.rs"]
mod report;
use report::{
    Statistics, Transcript, anchor_json, pin_json, receipt_json, scope_json, source_bytes, terminal,
};
const STORAGE_CAPS: [&str; 4] = [
    "CAP-READ-MEDIA-001",
    "CAP-OBJECT-STAGE-001",
    "CAP-OBJECT-PUBLISH-001",
    "CAP-RETENTION-COMMIT-001",
];

#[derive(Clone, Copy, Debug)]
enum Failure {
    Configuration,
    Approval,
    Root,
    Storage,
    Connect,
    Authentication,
    Protocol,
    Timing,
    Deadline,
    Authority,
    WorkBudget,
    State,
    Shortfall,
    Output,
}
impl Failure {
    fn code(self) -> &'static str {
        match self {
            Self::Configuration => "ERR-CAPTURE-RTSP-CONFIG-001",
            Self::Approval => "ERR-CAPTURE-RTSP-APPROVAL-001",
            Self::Root => "ERR-CAPTURE-RTSP-ROOT-001",
            Self::Storage => "ERR-CAPTURE-RTSP-STORAGE-001",
            Self::Connect => "ERR-CAPTURE-RTSP-CONNECT-001",
            Self::Authentication => "ERR-CAPTURE-RTSP-AUTH-UNSUPPORTED-001",
            Self::Protocol => "ERR-CAPTURE-RTSP-SOURCE-001",
            Self::Timing => "ERR-CAPTURE-RTSP-TIMING-001",
            Self::Deadline => "ERR-CAPTURE-RTSP-DEADLINE-001",
            Self::Authority => "ERR-CAPTURE-RTSP-AUTHORITY-001",
            Self::WorkBudget => "ERR-CAPTURE-RTSP-WORK-001",
            Self::State => "ERR-CAPTURE-RTSP-STATE-001",
            Self::Shortfall => "ERR-CAPTURE-RTSP-SHORTFALL-001",
            Self::Output => "ERR-CAPTURE-RTSP-OUTPUT-001",
        }
    }
    fn cause(self) -> &'static str {
        match self {
            Self::Authentication => "authentication_required",
            Self::Timing => "timing_refused",
            Self::Deadline => "deadline",
            Self::WorkBudget => "work_budget",
            Self::Shortfall => "input_ended_before_target",
            Self::Output => "output_failure",
            Self::Root | Self::Storage => "storage_failure",
            Self::Authority | Self::Approval => "authority_refused",
            Self::Connect => "connection_failure",
            Self::Configuration | Self::State => "configuration_or_state_refused",
            Self::Protocol => "protocol_failure",
        }
    }
}

fn elapsed(start: Instant) -> Result<u64, Failure> {
    u64::try_from(start.elapsed().as_nanos()).map_err(|_| Failure::Deadline)
}
fn context_check(
    authority: &ContextAuthority,
    start: Instant,
    deadline: u64,
) -> Result<u64, Failure> {
    if authority.cancellation_reason.is_some()
        || !STORAGE_CAPS.iter().all(|cap| authority.has_capability(cap))
    {
        return Err(Failure::Authority);
    }
    let now = elapsed(start)?;
    if now >= deadline {
        return Err(Failure::Deadline);
    }
    Ok(now)
}
struct Owner<'a> {
    cx: &'a ReplayCx,
    authority: &'a ContextAuthority,
    binding: TcpBinding,
    start: Instant,
    live_deadline: u64,
    storage_deadline: u64,
    drain_timeout: u64,
    drain_deadline: Cell<Option<u64>>,
}
impl Owner<'_> {
    fn now(&self) -> Result<u64, Failure> {
        self.cx
            .checkpoint("capture_rtsp:owner")
            .map_err(|_| Failure::Authority)?;
        context_check(
            self.authority,
            self.start,
            self.drain_deadline.get().unwrap_or(self.storage_deadline),
        )
    }
    fn begin_drain(&self) -> Result<(), Failure> {
        let now = self.now()?;
        if self.drain_deadline.get().is_none() {
            let deadline = now
                .checked_add(self.drain_timeout)
                .ok_or(Failure::Deadline)?;
            self.drain_deadline
                .set(Some(deadline.min(self.storage_deadline)));
        }
        Ok(())
    }
    fn pause(&self, wake: Option<u64>) -> Result<(), Failure> {
        let now = self.now()?;
        if now >= self.live_deadline {
            return Err(Failure::Deadline);
        }
        let delay = wake
            .map_or(1_000_000, |at| at.saturating_sub(now))
            .min(1_000_000)
            .min(self.live_deadline - now);
        if delay != 0 {
            // One explicit owner-clock wait, only following a Pending network poll.
            self.cx
                .checkpoint("capture_rtsp:wait")
                .map_err(|_| Failure::Authority)?;
            std::thread::sleep(Duration::from_nanos(delay));
        }
        self.now()?;
        Ok(())
    }
}
impl TcpAuthority for Owner<'_> {
    fn checkpoint(
        &self,
        binding: &TcpBinding,
        _: TcpOperation,
        now: u64,
        deadline: u64,
    ) -> Result<(), TcpDenial> {
        self.cx
            .checkpoint("capture_rtsp:network")
            .map_err(|_| TcpDenial::Cancelled)?;
        if self.authority.cancellation_reason.is_some() {
            return Err(TcpDenial::Cancelled);
        }
        if binding != &self.binding
            || deadline != self.live_deadline
            || !self.authority.has_capability("CAP-ADAPTER-NET-001")
            || !STORAGE_CAPS
                .iter()
                .all(|cap| self.authority.has_capability(cap))
        {
            return Err(TcpDenial::Unauthorized);
        }
        // Re-read the actual clock at every native pre/post-syscall probe. A caller's
        // old admission timestamp cannot extend network authority during storage/output.
        if now >= deadline || elapsed(self.start).map_err(|_| TcpDenial::Deadline)? >= deadline {
            return Err(TcpDenial::Deadline);
        }
        Ok(())
    }
}
impl PublishCancellation for Owner<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.now().is_err()
    }
}

fn failure(error: JournaledLiveFailure, stats: &mut Statistics) -> Failure {
    if let Some(retired) = &error.retirement {
        stats.retirement(retired);
    }
    match error.reason {
        JournaledLiveArchiveError::Pins(_) => Failure::Storage,
        JournaledLiveArchiveError::Live(error) => match error {
            LiveArchiveError::Deadline
            | LiveArchiveError::StoragePauseExpired
            | LiveArchiveError::Authority(TcpDenial::Deadline) => Failure::Deadline,
            LiveArchiveError::WorkBudget => Failure::WorkBudget,
            LiveArchiveError::Authority(_) => Failure::Authority,
            LiveArchiveError::Archive(_) => Failure::Storage,
            LiveArchiveError::Recording(error) => match *error {
                LiveRecordingError::Network(LiveAvcError::Transport(
                    TcpError::Deadline
                    | TcpError::ReadDeadline
                    | TcpError::Denied(TcpDenial::Deadline),
                ))
                | LiveRecordingError::Capture(CaptureError::Collection(CollectorError::Deadline)) => {
                    Failure::Deadline
                }
                LiveRecordingError::Network(LiveAvcError::Transport(TcpError::Denied(_))) => {
                    Failure::Authority
                }
                LiveRecordingError::Network(LiveAvcError::WorkBudget)
                | LiveRecordingError::Network(LiveAvcError::Transport(
                    TcpError::WorkBudget | TcpError::RequestBudget,
                )) => Failure::WorkBudget,
                _ => Failure::Protocol,
            },
            _ => Failure::State,
        },
    }
}
fn backpressure(error: &JournaledLiveFailure) -> bool {
    if error.retirement.is_some() {
        return false;
    }
    matches!(
        &error.reason,
        JournaledLiveArchiveError::Live(LiveArchiveError::Backpressure)
    ) || matches!(
        &error.reason,
        JournaledLiveArchiveError::Live(LiveArchiveError::Recording(error))
        if matches!(
            error.as_ref(),
            LiveRecordingError::Network(LiveAvcError::Backpressure)
            | LiveRecordingError::Capture(CaptureError::Backpressure)
            | LiveRecordingError::Capture(CaptureError::Collection(CollectorError::Backpressure))
        )
    )
}

fn command_name(command: ClientCommand) -> &'static str {
    match command {
        ClientCommand::Options => "OPTIONS",
        ClientCommand::Describe => "DESCRIBE",
        ClientCommand::Setup => "SETUP",
        ClientCommand::Play => "PLAY",
        ClientCommand::KeepAlive => "KEEPALIVE",
        ClientCommand::Teardown => "TEARDOWN",
    }
}
fn state_name(state: ClientState) -> &'static str {
    match state {
        ClientState::Idle => "idle",
        ClientState::Described => "described",
        ClientState::Ready => "ready",
        ClientState::Playing => "playing",
        ClientState::Closing => "closing",
        ClientState::Closed => "closed",
        ClientState::Failed => "failed",
    }
}
fn observe_network_retirement(step: &LiveAvcStep, stats: &mut Statistics) {
    if let LiveAvcStep::Protocol { event, transport } = step {
        if let Some(transport) = transport {
            stats.totals = transport.totals;
            stats.pending_request |= transport.request.is_some();
        }
        match event {
            DigestAvcPoll::Fault { retirement, .. } => stats.client_retirement(&retirement.client),
            DigestAvcPoll::Client { event, .. } => match event.as_ref() {
                AvcClientPoll::Rtp {
                    retirement: Some(retired),
                    ..
                }
                | AvcClientPoll::Ended {
                    retirement: Some(retired),
                    ..
                }
                | AvcClientPoll::Fault {
                    retirement: retired,
                    ..
                } => stats.client_retirement(retired),
                _ => {}
            },
            _ => {}
        }
    }
}
fn observe_stopped(step: &LiveRecordingStep, stats: &mut Statistics) {
    match step {
        LiveRecordingStep::Network(step) => observe_network_retirement(step, stats),
        LiveRecordingStep::Stopped { trigger, retained } => {
            observe_network_retirement(trigger, stats);
            stats.capture_retirement(retained);
        }
        LiveRecordingStep::Capture { event, connection } => {
            if let Some(connection) = connection {
                stats.connection_retirement(connection);
            }
            match event.as_ref() {
                CapturePoll::Stopped { retained, .. } => stats.capture_retirement(retained),
                CapturePoll::Ended {
                    trailing: Some(trailing),
                } => stats.unsealed(trailing),
                CapturePoll::Window(window) => stats.prepared(window),
                _ => {}
            }
        }
        _ => {}
    }
}

/// Some(wake) is a real Pending output; None means more bounded local work can run.
fn network_step<W: Write>(
    step: LiveAvcStep,
    stats: &mut Statistics,
    next_command: &mut Option<ClientCommand>,
    log: &mut Transcript<'_, W>,
) -> Result<Option<Option<u64>>, Failure> {
    observe_network_retirement(&step, stats);
    match step {
        LiveAvcStep::Wire(_) | LiveAvcStep::Write(_) => {}
        LiveAvcStep::InputEnded => {
            stats.input_ended = true;
            log.emit(
                "network_input_ended",
                object(&[("capture_drained", "false".into())]),
                false,
            )?;
        }
        LiveAvcStep::Pending(wait) => return Ok(Some(wait.wake_at_ns)),
        LiveAvcStep::Ended => return Err(Failure::Protocol),
        LiveAvcStep::Protocol { event, .. } => match event {
            // This is a deliberate terminal refusal. There is no respond(), credential
            // lookup, Authorization construction, or authenticated request retry here.
            DigestAvcPoll::AuthenticationRequired { .. } => return Err(Failure::Authentication),
            DigestAvcPoll::Fault { .. } => return Err(Failure::Protocol),
            DigestAvcPoll::Client { event, .. } => match *event {
                AvcClientPoll::Control(ClientProgress::Accepted(state)) => {
                    *next_command = match state {
                        ClientState::Described => Some(ClientCommand::Setup),
                        ClientState::Ready => Some(ClientCommand::Play),
                        _ => None,
                    };
                    log.emit(
                        "protocol",
                        object(&[("state", string(state_name(state)))]),
                        false,
                    )?;
                }
                AvcClientPoll::Control(ClientProgress::KeepAliveDue) => {
                    *next_command = Some(ClientCommand::KeepAlive);
                }
                AvcClientPoll::Rtp {
                    retirement: Some(_),
                    ..
                }
                | AvcClientPoll::Fault { .. } => return Err(Failure::Protocol),
                AvcClientPoll::Ended { .. } => stats.input_ended = true,
                AvcClientPoll::Pending { wake_at_ns }
                | AvcClientPoll::Backpressure { wake_at_ns } => return Ok(Some(wake_at_ns)),
                // Original receiver events are normally intercepted by LiveAvcRecording.
                // Do not reinterpret a surprising bypass as a captured picture.
                AvcClientPoll::Media(_) => {
                    stats.unpublished_receiver_state = true;
                    return Err(Failure::State);
                }
                _ => {}
            },
        },
    }
    Ok(None)
}

fn archive_progress<W: Write>(
    progress: ArchiveWriteProgress,
    capture: &JournaledLiveAvcArchive<'_, '_>,
    namespace: ContentDigest,
    stats: &mut Statistics,
    ready: &mut bool,
    log: &mut Transcript<'_, W>,
) -> Result<(), Failure> {
    match progress {
        ArchiveWriteProgress::Ready {
            durable_windows,
            indexed_windows,
        } => {
            stats.durable_windows = durable_windows;
            stats.indexed_windows = indexed_windows;
            *ready = true;
        }
        ArchiveWriteProgress::WindowDurable { ordinal, receipt } => {
            if receipt.claims.local != LocalPublicationState::Durable {
                return Err(Failure::State);
            }
            let snapshot = capture.snapshot().ok_or(Failure::State)?;
            let entry = snapshot.windows().get(ordinal).ok_or(Failure::State)?;
            if entry.slot() != &receipt.slot || entry.root() != receipt.root {
                return Err(Failure::State);
            }
            let (pending_root, source_bytes) = stats.pending_window.take().ok_or(Failure::State)?;
            if pending_root != receipt.root {
                return Err(Failure::State);
            }
            stats.durable_source_object_bytes += source_bytes;
            stats.snapshot(snapshot);
            let interval = entry.decode_interval();
            log.emit(
                "window_durable",
                object(&[
                    ("ordinal", ordinal.to_string()),
                    ("slot", string(receipt.slot.as_str())),
                    ("root", string(&receipt.root.to_text())),
                    ("archive_namespace", string(&namespace.to_text())),
                    (
                        "source",
                        scope_json(&snapshot.namespace().scope().recording),
                    ),
                    ("pictures", entry.samples().to_string()),
                    ("decode_start", interval.start.to_string()),
                    ("decode_end", interval.end.to_string()),
                    (
                        "decode_clock",
                        string(&snapshot.namespace().scope().decode_clock.to_text()),
                    ),
                    (
                        "time_scale",
                        snapshot.namespace().scope().time_scale.to_string(),
                    ),
                    ("source_object_bytes", source_bytes.to_string()),
                    ("codec", string("avc")),
                    ("pixel_decode", "false".into()),
                    ("catalog_indexed", "false".into()),
                    ("record_digest", string(&receipt.record_digest.to_text())),
                ]),
                false,
            )?;
        }
        ArchiveWriteProgress::CatalogPublished {
            first_ordinal,
            windows,
            receipt,
        } => {
            if receipt.claims.local != LocalPublicationState::Durable {
                return Err(Failure::State);
            }
            let snapshot = capture.snapshot().ok_or(Failure::State)?;
            let page = snapshot
                .pages()
                .iter()
                .find(|page| page.first_ordinal() == first_ordinal)
                .ok_or(Failure::State)?;
            let catalog = page.catalog();
            let scope = snapshot.namespace().scope();
            if page.slot() != &receipt.slot
                || catalog.manifest().root() != receipt.root
                || catalog.entries().len() != windows
                || catalog.scope() != scope
            {
                return Err(Failure::State);
            }
            stats.indexed_windows = first_ordinal + windows;
            log.emit(
                "catalog_published",
                object(&[
                    ("first_ordinal", first_ordinal.to_string()),
                    ("windows", windows.to_string()),
                    ("slot", string(receipt.slot.as_str())),
                    ("root", string(&receipt.root.to_text())),
                    ("archive_namespace", string(&namespace.to_text())),
                    ("source", scope_json(&scope.recording)),
                    ("decode_clock", string(&scope.decode_clock.to_text())),
                    ("time_scale", scope.time_scale.to_string()),
                    ("codec", string("avc")),
                    ("receipt", receipt_json(&receipt)),
                ]),
                false,
            )?;
        }
        ArchiveWriteProgress::Finished {
            snapshot_digest,
            windows,
            ..
        } => {
            stats.snapshot_digest = Some(snapshot_digest);
            stats.durable_windows = windows;
        }
        ArchiveWriteProgress::Exhausted => return Err(Failure::State),
        _ => {}
    }
    Ok(())
}

fn begin_archive_drain(
    capture: &mut JournaledLiveAvcArchive<'_, '_>,
    owner: &Owner<'_>,
    stats: &mut Statistics,
) -> Result<(), Failure> {
    let retired = capture
        .finish_capture(owner.now()?, owner, owner)
        .map_err(|e| failure(e, stats))?;
    if let Some(retired) = &retired {
        stats.recording_retirement(retired);
    }
    // Close input without a synthetic EOF or TEARDOWN. Already-admitted windows and the
    // final catalog retain their ordinary checkpoint barriers and storage drain deadline.
    owner.begin_drain()
}

fn drive<W: Write>(
    options: &Options,
    capture: &mut JournaledLiveAvcArchive<'_, '_>,
    owner: &Owner<'_>,
    stats: &mut Statistics,
    log: &mut Transcript<'_, W>,
) -> Result<(), Failure> {
    let namespace = options.pin_scope().archive_namespace;
    let mut timing = FixedTiming::new(options.frame_duration).map_err(|_| Failure::Timing)?;
    let mut next_command = Some(ClientCommand::Describe);
    let mut ready = false;
    let mut sealing = false;
    let mut sealed = false;
    let mut draining = false;
    // The native API borrows these arguments even before a challenge has been accepted.
    // They are nonsecret placeholders and are NEVER used to authenticate: only respond()
    // installs a challenge in DigestState, and that method is absent from this driver.
    let unsigned = DigestCredentials::new("unused", "").map_err(|_| Failure::Configuration)?;

    loop {
        if stats.steps >= options.max_steps {
            return Err(Failure::WorkBudget);
        }
        stats.steps += 1;
        stats.observe(capture);
        let now = owner.now()?;
        if !draining && now >= owner.live_deadline {
            return Err(Failure::Deadline);
        }
        if stats.collected_pictures == options.stop_after_pictures && !draining {
            sealing = true;
            next_command = None;
        }

        if sealing && ready && !sealed {
            match capture.seal(now, owner, owner) {
                Ok(true) => {
                    // Sealing only prepares a window. Its WindowAccepted event transfers
                    // the final prefix to storage before input can be stopped.
                    sealed = true;
                    ready = false;
                }
                Ok(false) if stats.durable_pictures == stats.collected_pictures => sealed = true,
                Ok(false) => return Err(Failure::State),
                Err(error) if backpressure(&error) => ready = false,
                Err(error) => return Err(failure(error, stats)),
            }
        }
        if sealing && sealed && ready && !draining {
            if stats.durable_pictures != stats.collected_pictures {
                return Err(Failure::State);
            }
            begin_archive_drain(capture, owner, stats)?;
            draining = true;
            ready = false;
        }
        if !sealing && !draining && ready {
            if let Some(command) = next_command {
                match capture.request(command, &unsigned, [0; 16], owner.now()?, owner, owner) {
                    Ok(request) => {
                        next_command = None;
                        log.emit(
                            "request_queued",
                            object(&[
                                ("command", string(command_name(request.command))),
                                ("cseq", request.cseq.to_string()),
                                ("bytes", request.bytes.to_string()),
                                ("authentication", string("none")),
                            ]),
                            false,
                        )?;
                    }
                    Err(error) if backpressure(&error) => {}
                    Err(error) => return Err(failure(error, stats)),
                }
            }
        }

        // Once the requested count is consumed, no additional socket operation is enabled.
        // Buffered native work may drain only far enough to publish the sealed prefix.
        let readiness = SocketReadiness {
            readable: !sealing && !draining,
            writable: !sealing && !draining,
        };
        let step = capture
            .poll(readiness, owner.now()?, owner, owner)
            .map_err(|e| failure(e, stats))?;
        match step {
            JournaledLiveArchiveStep::Checkpoint(progress) => match *progress {
                JournaledArchiveProgress::PinPersisted { receipt, .. } => {
                    stats.observe(capture);
                    log.emit(
                        "checkpoint_candidate",
                        object(&[
                            ("pin", pin_json(receipt.pin())),
                            ("journal_anchor", anchor_json(receipt.anchor())),
                            ("work_durable", "false".into()),
                        ]),
                        false,
                    )?;
                }
                JournaledArchiveProgress::WorkConfirmed {
                    work_receipt,
                    pin_receipt,
                    ..
                } => {
                    stats.observe(capture);
                    log.emit(
                        "checkpoint_durable",
                        object(&[
                            ("pin", pin_json(pin_receipt.pin())),
                            ("journal_anchor", anchor_json(pin_receipt.anchor())),
                            ("work_receipt", receipt_json(&work_receipt)),
                            ("normal_window_durable", "false".into()),
                        ]),
                        false,
                    )?;
                }
                JournaledArchiveProgress::Archive(progress) => {
                    archive_progress(progress, capture, namespace, stats, &mut ready, log)?;
                }
            },
            JournaledLiveArchiveStep::Live(LiveArchiveStep::WindowAccepted(admission)) => {
                let pending = capture.pending().ok_or(Failure::State)?;
                if pending.manifest().root() != admission.root || stats.pending_window.is_some() {
                    return Err(Failure::State);
                }
                stats.pending_window =
                    Some((admission.root, pending.objects().source.len() as u64));
                ready = false;
                if sealing && sealed && !draining {
                    // This is the final explicitly sealed window, not an earlier IDR cut.
                    // Close the socket before preparing its first checkpoint, so publication
                    // can use the drain allowance even when the live deadline is near.
                    begin_archive_drain(capture, owner, stats)?;
                    draining = true;
                }
                log.emit(
                    "window_accepted",
                    object(&[
                        ("ordinal", admission.ordinal.to_string()),
                        ("slot", string(admission.slot.as_str())),
                        ("root", string(&admission.root.to_text())),
                        ("durable", "false".into()),
                    ]),
                    false,
                )?;
            }
            JournaledLiveArchiveStep::Live(LiveArchiveStep::Archive(progress)) => {
                archive_progress(progress, capture, namespace, stats, &mut ready, log)?;
            }
            JournaledLiveArchiveStep::Live(LiveArchiveStep::Finished { archive, cause }) => {
                archive_progress(archive, capture, namespace, stats, &mut ready, log)?;
                stats.observe(capture);
                return if cause == LiveArchiveCompletion::OwnerStopped
                    && stats.collected_pictures == options.stop_after_pictures
                    && stats.durable_pictures == stats.collected_pictures
                    && stats.indexed_windows == stats.durable_windows
                {
                    Ok(())
                } else {
                    Err(Failure::Shortfall)
                };
            }
            JournaledLiveArchiveStep::Live(LiveArchiveStep::Recording(step)) => match *step {
                LiveRecordingStep::Network(step) => {
                    if let Some(wake) = network_step(step, stats, &mut next_command, log)? {
                        owner.pause(wake)?;
                    }
                }
                LiveRecordingStep::Capture { event, connection } => {
                    if let Some(connection) = &connection {
                        stats.connection_retirement(connection);
                    }
                    match *event {
                        CapturePoll::TimingRequired(request) => {
                            if sealing || draining {
                                // Cancellation below accounts for the still-held picture once.
                                return Err(Failure::State);
                            }
                            let selected_timing =
                                timing.observe(request).map_err(|_| Failure::Timing)?;
                            let timed = capture
                                .supply_timing(selected_timing, owner.now()?, owner, owner)
                                .map_err(|e| failure(e, stats))?;
                            match timed {
                                TimedCapture::Collected { unselected, .. } => {
                                    stats.unselected_rtp_bytes += source_bytes(&unselected);
                                    stats.collected_pictures += 1;
                                    log.emit(
                                        "picture_collected",
                                        object(&[
                                            ("picture", stats.collected_pictures.to_string()),
                                            ("rtp_timestamp", request.rtp_timestamp.to_string()),
                                            (
                                                "decode_time",
                                                selected_timing.decode_time.to_string(),
                                            ),
                                            ("duration", selected_timing.duration.to_string()),
                                            ("composition_offset", "0".into()),
                                            ("durable", "false".into()),
                                        ]),
                                        false,
                                    )?;
                                }
                                TimedCapture::AwaitingIdr { unselected, .. } => {
                                    stats.unselected_rtp_bytes += source_bytes(&unselected);
                                    stats.skipped_pictures += 1;
                                }
                            }
                        }
                        CapturePoll::Ended { trailing } => {
                            if let Some(trailing) = &trailing {
                                stats.unsealed(trailing);
                            }
                            stats.input_ended = true;
                            next_command = None;
                            owner.begin_drain()?;
                            draining = true;
                            ready = false;
                        }
                        CapturePoll::InputEnded => stats.input_ended = true,
                        CapturePoll::Stopped { retained, .. } => {
                            stats.capture_retirement(&retained);
                            return Err(Failure::Protocol);
                        }
                        CapturePoll::Backpressure(_) => return Err(Failure::Protocol),
                        CapturePoll::Tail(_) => stats.receiver_tail = true,
                        CapturePoll::Window(window) => {
                            stats.prepared(&window);
                            return Err(Failure::State);
                        }
                        CapturePoll::Receiver(_) | CapturePoll::Pending { .. } => {}
                    }
                }
                LiveRecordingStep::Stopped { trigger, retained } => {
                    observe_network_retirement(&trigger, stats);
                    stats.capture_retirement(&retained);
                    return Err(Failure::Protocol);
                }
                LiveRecordingStep::Ended => return Err(Failure::Protocol),
                LiveRecordingStep::MediaQueued => {}
            },
            JournaledLiveArchiveStep::Stopped { trigger, retained } => {
                observe_stopped(&trigger, stats);
                stats.retirement(&retained);
                return Err(Failure::Protocol);
            }
            JournaledLiveArchiveStep::Live(LiveArchiveStep::Stopped { trigger, retained }) => {
                observe_stopped(&trigger, stats);
                stats.archive_retirement(&retained);
                return Err(Failure::Protocol);
            }
            JournaledLiveArchiveStep::Live(LiveArchiveStep::Ended) => return Err(Failure::State),
        }
    }
}

/// Refuse any existing path before creating either owner, including symlinks and old attempts.
fn require_new(path: &Path) -> Result<(), Failure> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(Failure::Root),
    }
}

/// Bind both outputs to their existing canonical parents before creating either owner.
/// Lexically different paths may otherwise alias through a symlinked ancestor.
fn resolve_new_parent(
    path: &Path,
    authority: &ContextAuthority,
    start: Instant,
    deadline: u64,
) -> Result<PathBuf, Failure> {
    context_check(authority, start, deadline)?;
    let parent =
        std::fs::canonicalize(path.parent().ok_or(Failure::Root)?).map_err(|_| Failure::Root)?;
    context_check(authority, start, deadline)?;
    if !std::fs::metadata(&parent)
        .map_err(|_| Failure::Root)?
        .is_dir()
    {
        return Err(Failure::Root);
    }
    context_check(authority, start, deadline)?;
    let resolved = parent.join(path.file_name().ok_or(Failure::Root)?);
    require_new(&resolved)?;
    context_check(authority, start, deadline)?;
    Ok(resolved)
}

fn create_root(path: &Path) -> Result<(), Failure> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    // Exclusive creation closes the check/create race at the final path component.
    // Parent directories must already exist; no hidden ancestor creation or repair.
    builder.create(path).map_err(|_| Failure::Root)?;
    std::fs::File::open(path.parent().ok_or(Failure::Root)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| Failure::Root)
}

fn run_owned<W: Write>(
    options: &Options,
    authority: &ContextAuthority,
    start: Instant,
    stats: &mut Statistics,
    log: &mut Transcript<'_, W>,
) -> Result<(), Failure> {
    let storage_deadline = options
        .timeout_ns
        .checked_add(options.drain_timeout_ns)
        .ok_or(Failure::Configuration)?;
    context_check(authority, start, options.timeout_ns)?;
    require_new(&options.root)?;
    context_check(authority, start, options.timeout_ns)?;
    require_new(&options.pins)?;
    let root = resolve_new_parent(&options.root, authority, start, options.timeout_ns)?;
    let pin_root = resolve_new_parent(&options.pins, authority, start, options.timeout_ns)?;
    if root.starts_with(&pin_root) || pin_root.starts_with(&root) {
        return Err(Failure::Root);
    }
    context_check(authority, start, options.timeout_ns)?;
    create_root(&root)?;
    context_check(authority, start, options.timeout_ns)?;
    let cx =
        ReplayCx::from_context_authority(authority, root.clone()).map_err(|_| Failure::Root)?;
    let owner = Owner {
        cx: &cx,
        authority,
        binding: options.live_config().binding,
        start,
        live_deadline: options.timeout_ns,
        storage_deadline,
        drain_timeout: options.drain_timeout_ns,
        drain_deadline: Cell::new(None),
    };
    let result = (|| {
        owner.now()?;
        let mut publisher = LocalRootPublisher::open(&root, options.publication_limits())
            .map_err(|_| Failure::Storage)?;
        owner.now()?;
        let mut pins =
            ArchivePinJournal::create(&pin_root, options.pin_scope(), options.pin_limits(), &owner)
                .map_err(|_| Failure::Storage)?;
        stats.journal_anchor = Some(pins.anchor());
        stats.pins = pins.state().clone();
        let mut capture = JournaledLiveAvcArchive::connect(
            options.live_config(),
            options.recording_config(),
            options.archive_config(),
            options.work_limits(),
            &mut publisher,
            &mut pins,
            owner.now()?,
            &owner,
            &owner,
        )
        .map_err(|error| {
            stats.connection_attempted = error.connection_attempted;
            match error.reason {
                JournaledLiveArchiveError::Pins(_) => Failure::Storage,
                _ => Failure::Connect,
            }
        })?;
        stats.connection_attempted = true;
        let result = drive(options, &mut capture, &owner, stats, log);
        stats.observe(&capture);
        // Close the socket and transfer all remaining ownership BEFORE terminal sink output.
        // No retry, deletion, publication, or synthetic EOF occurs in cancellation.
        if let Some(retired) = capture.cancel() {
            stats.retirement(&retired);
        }
        result
    })();
    cx.drain_and_finalize();
    result
}

pub(super) fn execute(options: &Options) -> Result<(), &'static str> {
    let approval = options.digest()?;
    if options.approve != Some(approval) {
        return Err(Failure::Approval.code());
    }
    let publication = options.publication_limits();
    let byte_budget = publication
        .spool
        .max_total_bytes
        .checked_add(options.live_config().transport.max_received_bytes)
        .ok_or(Failure::Configuration.code())?;
    let mut capabilities: Vec<String> = STORAGE_CAPS.iter().map(|cap| (*cap).into()).collect();
    capabilities.extend(["ADP-REPLAY-001".into(), "CAP-ADAPTER-NET-001".into()]);
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-capture".into(),
        operation_id: OperationId::parse("operation:rtsp-capture")
            .map_err(|_| Failure::Configuration.code())?,
        principal: options.principal.clone(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(byte_budget)
            .storage_operations(options.max_steps.saturating_mul(64))
            .build()
            .map_err(|_| Failure::Configuration.code())?,
        privacy_scope: "privacy:owner-original-rtsp-custody".into(),
        retention_scope: "retention:explicit-original-rtsp-scope".into(),
        anchor_universe: approval,
        generation: options.recording_config().scope.generation,
    })
    .map_err(|_| Failure::Configuration.code())?;
    authority
        .validate()
        .map_err(|_| Failure::Configuration.code())?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut log = Transcript {
        out: &mut out,
        used: 0,
        maximum: options.max_report_bytes,
        sequence: 0,
        io_failed: false,
    };
    // A refused output sink cannot leave an archive or start a TCP connection.
    log.emit(
        "started",
        object(&[
            ("approval_digest", string(&approval.to_text())),
            (
                "archive_namespace",
                string(&options.pin_scope().archive_namespace.to_text()),
            ),
            (
                "journal_id",
                string(&options.pin_scope().journal_id.to_text()),
            ),
            ("source", scope_json(&options.recording_config().scope)),
            (
                "requested_pictures",
                options.stop_after_pictures.to_string(),
            ),
            ("frame_duration_ticks", options.frame_duration.to_string()),
            (
                "decode_clock",
                string(
                    &options
                        .archive_config()
                        .namespace
                        .scope()
                        .decode_clock
                        .to_text(),
                ),
            ),
            ("time_scale", options.time_scale.to_string()),
            ("codec", string("avc")),
            ("authentication", string("unsupported")),
            ("capture_time", string("unknown")),
        ]),
        false,
    )
    .map_err(Failure::code)?;
    let start = Instant::now();
    let mut stats = Statistics::default();
    let result = run_owned(options, &authority, start, &mut stats, &mut log);
    log.emit("terminal", terminal(options, &stats, &result), true)
        .map_err(Failure::code)?;
    result.map_err(Failure::code)
}
