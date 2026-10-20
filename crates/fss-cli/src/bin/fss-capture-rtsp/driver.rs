#![forbid(unsafe_code)]
//! One approved native capture attempt, with original-window custody and independent pins.
//! Selected original RTP datagrams are archived. Raw TCP/control/RTCP, startup pictures,
//! and unsealed terminal work are explicitly accounted for, never called durable recordings.

use std::cell::{Cell, RefCell};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fss_cli::agent_json::{object, string};
use fss_core::{ContentDigest, TimestampNs};
use fss_publication::{
    LocalPublicationState, LocalRootPublisher, PublishCancellation, PublishCutPoint,
};
use fss_reference::rtsp::archive_pins::live::{
    JournaledLiveArchiveError, JournaledLiveArchiveStep, JournaledLiveAvcArchive,
    JournaledLiveFailure,
};
use fss_reference::rtsp::archive_pins::{ArchivePinJournal, JournaledArchiveProgress};
use fss_reference::rtsp::authentication::DigestCredentials;
use fss_reference::rtsp::avc_client::authenticated::{DigestAvcError, DigestAvcPoll};
use fss_reference::rtsp::avc_client::{AvcClientError, AvcClientPoll};
use fss_reference::rtsp::client::{ClientCommand, ClientProgress, ClientState};
use fss_reference::rtsp::live_archive::{LiveArchiveCompletion, LiveArchiveError, LiveArchiveStep};
use fss_reference::rtsp::live_avc::recording::{LiveRecordingError, LiveRecordingStep};
use fss_reference::rtsp::live_avc::{LiveAvcError, LiveAvcStep, SocketReadiness};
use fss_reference::rtsp::preview::{PreviewAuthority, PreviewCodec, PreviewError, PreviewScope};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording_archive::{
    ArchiveCodec, ArchiveWriteProgress, CodecArchiveSnapshot,
};
use fss_reference::rtsp::recording_capture::{CaptureError, CapturePoll, TimedCapture};
use fss_reference::rtsp::recording_collector::CollectorError;
use fss_reference::rtsp::tcp::{TcpAuthority, TcpBinding, TcpDenial, TcpError, TcpOperation};
use fss_runtime::execution::TaskCx;

use super::authentication::{CredentialLease, Entropy, MAX_CREDENTIAL_BYTES, SecretError};
use super::plan::Options;
use super::timing::FixedTiming;

#[path = "attempt.rs"]
mod attempt;
#[cfg(test)]
#[path = "read_interruption_tests.rs"]
mod read_interruption_tests;
pub(super) use attempt::{AttemptOutcome, RetryReason};
#[path = "progress.rs"]
mod progress;
pub(super) use progress::Supervision;
use progress::{RecordingProgress, Stall, StopCause};
#[path = "hevc_driver.rs"]
mod hevc;
#[path = "report.rs"]
mod report;
use report::{
    Statistics, Transcript, anchor_json, pin_json, receipt_json, scope_json, source_bytes, terminal,
};
#[path = "source_retention.rs"]
mod source_retention;
use super::source_mode::SourceConfig;
use source_retention::SourceCustody;

#[path = "preview.rs"]
mod preview;
use preview::{Gateway, GatewayAuthority};
#[path = "runtime.rs"]
mod runtime;
use runtime::{CaptureRuntime, Resources, TaskClock};

#[derive(Clone, Copy, Debug)]
enum Failure {
    Configuration,
    Approval,
    Root,
    Storage,
    Connect,
    ConnectionUnavailable,
    ReadInterrupted,
    ProgressStalled,
    EmptyCapture,
    Authentication,
    AuthenticationRefused,
    Credentials,
    Entropy,
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
            Self::Connect | Self::ConnectionUnavailable => "ERR-CAPTURE-RTSP-CONNECT-001",
            Self::Authentication => "ERR-CAPTURE-RTSP-AUTH-UNSUPPORTED-001",
            Self::AuthenticationRefused => "ERR-CAPTURE-RTSP-AUTH-REFUSED-001",
            Self::Credentials => "ERR-CAPTURE-RTSP-CREDENTIAL-001",
            Self::Entropy => "ERR-CAPTURE-RTSP-ENTROPY-001",
            // Keep the original source failure visible even when a separately
            // approved controller may start a new, independent recording.
            Self::Protocol | Self::ReadInterrupted => "ERR-CAPTURE-RTSP-SOURCE-001",
            Self::Timing => "ERR-CAPTURE-RTSP-TIMING-001",
            Self::Deadline => "ERR-CAPTURE-RTSP-DEADLINE-001",
            Self::ProgressStalled => "ERR-CAPTURE-RTSP-PROGRESS-001",
            Self::EmptyCapture => "ERR-CAPTURE-RTSP-EMPTY-DURATION-001",
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
            Self::AuthenticationRefused => "authentication_refused",
            Self::Credentials => "credential_refused",
            Self::Entropy => "entropy_unavailable",
            Self::Timing => "timing_refused",
            Self::Deadline => "deadline",
            Self::WorkBudget => "work_budget",
            Self::Shortfall => "input_ended_before_target",
            Self::ProgressStalled => "recording_progress_stalled",
            Self::EmptyCapture => "capture_duration_without_pictures",
            Self::Output => "output_failure",
            Self::Root | Self::Storage => "storage_failure",
            Self::Authority | Self::Approval => "authority_refused",
            Self::Connect | Self::ConnectionUnavailable => "connection_failure",
            Self::Configuration | Self::State => "configuration_or_state_refused",
            Self::Protocol | Self::ReadInterrupted => "protocol_failure",
        }
    }
}

fn secret_failure(error: SecretError) -> Failure {
    match error {
        SecretError::Credentials => Failure::Credentials,
        SecretError::Revoked | SecretError::Authority => Failure::Authority,
        SecretError::Entropy => Failure::Entropy,
        SecretError::Deadline => Failure::Deadline,
    }
}

struct Owner<'a, 'task> {
    task: &'a TaskCx<'task>,
    clock: &'a TaskClock,
    resources: &'a Resources,
    binding: TcpBinding,
    live_deadline: u64,
    storage_deadline: u64,
    drain_timeout: u64,
    drain_deadline: Cell<Option<u64>>,
    credentials: Option<&'a CredentialLease>,
    supervision: Option<Supervision>,
    preview_scope: Option<PreviewScope>,
    preview: RefCell<Option<Gateway>>,
}

struct NativeContext<'a, 'task> {
    task: &'a TaskCx<'task>,
    clock: &'a TaskClock,
    resources: &'a Resources,
}
impl Owner<'_, '_> {
    fn preview_stage(&self, recording: &PreparedRecording) {
        if let Ok(mut preview) = self.preview.try_borrow_mut()
            && let Some(gateway) = preview.as_mut()
        {
            gateway.stage(recording, &PreviewOwner(self));
        }
    }

    fn preview_publish(&self, root: ContentDigest) {
        if let Ok(mut preview) = self.preview.try_borrow_mut()
            && let Some(gateway) = preview.as_mut()
        {
            gateway.publish(root, &PreviewOwner(self));
        }
    }

    fn preview_pump(&self) {
        if let Ok(mut preview) = self.preview.try_borrow_mut()
            && let Some(gateway) = preview.as_mut()
        {
            gateway.pump(&PreviewOwner(self));
        }
    }

    fn close_preview(&self) -> Option<String> {
        let Ok(mut preview) = self.preview.try_borrow_mut() else {
            return None;
        };
        preview.as_mut().map(|gateway| {
            gateway.close();
            gateway.report()
        })
    }

    fn start_preview(&self, options: &Options, stats: &mut Statistics) {
        let Some(plan) = &options.live_preview else {
            return;
        };
        let Some(scope) = self.preview_scope.clone() else {
            return;
        };
        let result = Gateway::open(plan, scope, &PreviewOwner(self)).and_then(|gateway| {
            // Disclosure is bounded and happens before camera input starts. The fragment
            // capability is deliberately absent from the JSONL/evidence transcript.
            GatewayAuthority::now(&PreviewOwner(self)).map_err(PreviewError::as_str)?;
            writeln!(
                io::stderr().lock(),
                "FSS live preview: {}",
                gateway.operator_url()
            )
            .map_err(|_| "preview_operator_sink_unavailable")?;
            GatewayAuthority::now(&PreviewOwner(self)).map_err(PreviewError::as_str)?;
            self.preview
                .try_borrow_mut()
                .map_err(|_| "preview_owner_busy")?
                .replace(gateway);
            Ok(())
        });
        if let Err(reason) = result {
            stats.live_preview = Some(object(&[
                ("enabled", "true".into()),
                ("listening", "false".into()),
                ("last_refusal", string(reason)),
            ]));
        }
    }

    fn admit_stall<W: Write>(
        &self,
        stall: Stall,
        authentication_pending: bool,
        log: &mut Transcript<'_, W>,
    ) -> Result<(), Failure> {
        // Neither a progress timeout nor a planned stop can hide a revoked credential
        // or live network grant, or turn an unresolved authentication request into success.
        let now = self.now()?;
        self.checkpoint(&self.binding, TcpOperation::Poll, now, self.live_deadline)
            .map_err(|denial| match denial {
                TcpDenial::Deadline => Failure::Deadline,
                _ => Failure::Authority,
            })?;
        if authentication_pending {
            return Err(Failure::AuthenticationRefused);
        }
        let policy = self.supervision.ok_or(Failure::State)?;
        let kind = match stall.cause {
            StopCause::ProgressStalled => "recording_stalled",
            StopCause::CaptureDuration => "capture_duration_elapsed",
        };
        log.emit(kind, stall.report(policy), false)
    }

    fn now(&self) -> Result<u64, Failure> {
        let now = self
            .clock
            .now(self.task, self.drain_deadline.get().is_some())?;
        self.check_storage_deadline(now)?;
        Ok(now)
    }
    fn check_storage_deadline(&self, now: u64) -> Result<(), Failure> {
        if now >= self.drain_deadline.get().unwrap_or(self.storage_deadline) {
            Err(Failure::Deadline)
        } else {
            Ok(())
        }
    }
    fn storage_check(&self) -> Result<u64, Failure> {
        let now = self.clock.storage(
            self.task,
            self.resources,
            self.drain_deadline.get().is_some(),
        )?;
        self.check_storage_deadline(now)?;
        Ok(now)
    }
    fn startup_check(&self) -> Result<(), Failure> {
        let now = self.storage_check()?;
        if now >= self.live_deadline {
            return Err(Failure::Deadline);
        }
        Ok(())
    }
    fn secret_check(&self) -> Result<(), SecretError> {
        let now = self
            .clock
            .secret(self.task, self.resources)
            .map_err(|error| {
                if matches!(error, Failure::Deadline) {
                    SecretError::Deadline
                } else {
                    SecretError::Authority
                }
            })?;
        if now >= self.live_deadline {
            return Err(SecretError::Deadline);
        }
        Ok(())
    }
    fn begin_drain(&self) -> Result<(), Failure> {
        // A viewer cannot prolong capture or admit new network work during drain.
        self.close_preview();
        let now = self.clock.metadata_now(self.task)?;
        if self.drain_deadline.get().is_none() {
            let deadline = now
                .checked_add(self.drain_timeout)
                .ok_or(Failure::Deadline)?;
            self.task
                .begin_drain(TimestampNs(i128::from(now)))
                .map_err(|error| runtime::failure(&error))?;
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
            self.clock.network(self.task, self.resources)?;
            std::thread::sleep(Duration::from_nanos(delay));
        }
        self.now()?;
        Ok(())
    }

    fn authentication(
        &self,
        entropy: &mut Entropy,
    ) -> Result<(DigestCredentials<'_>, [u8; 16]), Failure> {
        let check = || self.secret_check();
        let lease = self.credentials.ok_or(Failure::Authentication)?;
        lease.revalidate(&check).map_err(secret_failure)?;
        let nonce = entropy.next(&check).map_err(secret_failure)?;
        let credentials = lease.credentials().map_err(secret_failure)?;
        Ok((credentials, nonce))
    }
}

struct PreviewOwner<'a, 'b, 'task>(&'a Owner<'b, 'task>);

impl GatewayAuthority for PreviewOwner<'_, '_, '_> {
    fn now(&self) -> Result<u64, PreviewError> {
        if self.0.drain_deadline.get().is_some() {
            return Err(PreviewError::Cancelled);
        }
        let scope = self
            .0
            .preview_scope
            .as_ref()
            .ok_or(PreviewError::Unauthorized)?;
        let now = self
            .0
            .clock
            .preview(self.0.task, self.0.resources)
            .map_err(|_| PreviewError::Unauthorized)?;
        if now >= scope.expires_at_ns {
            return Err(PreviewError::Expired);
        }
        Ok(now)
    }

    fn secret(&self) -> Result<(), SecretError> {
        if self.0.preview_scope.is_none() || self.0.drain_deadline.get().is_some() {
            return Err(SecretError::Authority);
        }
        let now = self
            .0
            .clock
            .preview_secret(self.0.task, self.0.resources)
            .map_err(|_| SecretError::Authority)?;
        if now >= self.0.live_deadline {
            return Err(SecretError::Deadline);
        }
        Ok(())
    }
}

impl PreviewAuthority for PreviewOwner<'_, '_, '_> {
    fn checkpoint(&self, scope: &PreviewScope, observed: u64) -> Result<(), PreviewError> {
        if self.0.preview_scope.as_ref() != Some(scope) {
            return Err(PreviewError::Scope);
        }
        let now = GatewayAuthority::now(self)?;
        if now < observed {
            return Err(PreviewError::ClockRegression);
        }
        Ok(())
    }
}

impl TcpAuthority for Owner<'_, '_> {
    fn checkpoint(
        &self,
        binding: &TcpBinding,
        _: TcpOperation,
        now: u64,
        deadline: u64,
    ) -> Result<(), TcpDenial> {
        if binding != &self.binding || deadline != self.live_deadline {
            return Err(TcpDenial::Unauthorized);
        }
        if self.drain_deadline.get().is_some() {
            return Err(TcpDenial::Cancelled);
        }
        if self
            .task
            .is_cancel_requested()
            .map_err(|_| TcpDenial::Unauthorized)?
        {
            return Err(TcpDenial::Cancelled);
        }
        let denial = |error| match error {
            Failure::Deadline => TcpDenial::Deadline,
            Failure::WorkBudget => TcpDenial::Budget,
            _ => TcpDenial::Unauthorized,
        };
        self.clock
            .network(self.task, self.resources)
            .map_err(denial)?;
        if let Some(lease) = self.credentials {
            let check = || self.secret_check();
            lease.revalidate(&check).map_err(|error| match error {
                SecretError::Deadline => TcpDenial::Deadline,
                SecretError::Revoked | SecretError::Credentials => TcpDenial::Revoked,
                _ => TcpDenial::Unauthorized,
            })?;
        }
        // Re-read the actual clock at every native pre/post-syscall probe. A caller's
        // old admission timestamp cannot extend network authority during storage/output.
        let observed = self
            .clock
            .network(self.task, self.resources)
            .map_err(denial)?;
        if now >= deadline || observed >= deadline {
            return Err(TcpDenial::Deadline);
        }
        Ok(())
    }
}
impl PublishCancellation for Owner<'_, '_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.storage_check().is_err()
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
                LiveRecordingError::Network(LiveAvcError::Protocol(
                    DigestAvcError::Authentication(_) | DigestAvcError::AuthenticationAtEof,
                )) => Failure::AuthenticationRefused,
                LiveRecordingError::Network(LiveAvcError::Transport(error))
                    if abrupt_read_failure(&error) =>
                {
                    Failure::ReadInterrupted
                }
                _ => Failure::Protocol,
            },
            _ => Failure::State,
        },
    }
}
// Keep this classification as narrow as the native prefix-preservation owners.
// Poll/write/connect errors and temporary read conditions cannot authorize a new
// recording. A positive classification is still subject to final custody checks.
fn abrupt_read_failure(error: &TcpError) -> bool {
    matches!(
        error,
        TcpError::Io {
            operation: TcpOperation::Read,
            kind: io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::NotConnected,
        }
    )
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
            | LiveRecordingError::Network(LiveAvcError::Protocol(DigestAvcError::Backpressure))
            | LiveRecordingError::Network(LiveAvcError::Protocol(DigestAvcError::Client(
                AvcClientError::Backpressure
            )))
            | LiveRecordingError::Capture(CaptureError::Backpressure)
            | LiveRecordingError::Capture(CaptureError::Collection(CollectorError::Backpressure))
        )
    )
}

fn command_name(command: ClientCommand) -> &'static str {
    if command.is_keepalive() {
        "KEEPALIVE"
    } else {
        command.wire_method()
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

fn network_stop_failure(step: &LiveAvcStep) -> Failure {
    match step {
        LiveAvcStep::Protocol {
            event:
                DigestAvcPoll::Fault {
                    reason: DigestAvcError::Authentication(_) | DigestAvcError::AuthenticationAtEof,
                    ..
                },
            ..
        } => Failure::AuthenticationRefused,
        _ => Failure::Protocol,
    }
}

fn recording_stop_failure(step: &LiveRecordingStep) -> Failure {
    match step {
        LiveRecordingStep::Network(step) => network_stop_failure(step),
        LiveRecordingStep::Stopped { trigger, .. } => network_stop_failure(trigger),
        _ => Failure::Protocol,
    }
}

/// Some(wake) is a real Pending output; None means more bounded local work can run.
fn network_step<W: Write>(
    step: LiveAvcStep,
    stats: &mut Statistics,
    next_command: &mut Option<ClientCommand>,
    challenge: &mut Option<u32>,
    authentication_allowed: bool,
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
            DigestAvcPoll::AuthenticationRequired { cseq, .. } => {
                if !authentication_allowed {
                    return Err(Failure::Authentication);
                }
                if challenge.is_some_and(|pending| pending != cseq) {
                    return Err(Failure::State);
                }
                if challenge.replace(cseq).is_none() {
                    stats.authentication_challenges += 1;
                }
            }
            DigestAvcPoll::Fault { reason, .. } => {
                return Err(match reason {
                    DigestAvcError::Authentication(_) | DigestAvcError::AuthenticationAtEof => {
                        Failure::AuthenticationRefused
                    }
                    _ => Failure::Protocol,
                });
            }
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

struct ArchiveOutput<'a, 'b, 'task> {
    namespace: ContentDigest,
    codec: &'static str,
    owner: &'a Owner<'b, 'task>,
}

fn archive_progress<C: ArchiveCodec, W: Write>(
    progress: ArchiveWriteProgress,
    snapshot: Option<&CodecArchiveSnapshot<C>>,
    output: &ArchiveOutput<'_, '_, '_>,
    stats: &mut Statistics,
    ready: &mut bool,
    log: &mut Transcript<'_, W>,
) -> Result<(), Failure> {
    let ArchiveOutput {
        namespace,
        codec,
        owner,
    } = output;
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
            let snapshot = snapshot.ok_or(Failure::State)?;
            let entry = snapshot.windows().get(ordinal).ok_or(Failure::State)?;
            if entry.slot() != &receipt.slot || entry.root() != receipt.root {
                return Err(Failure::State);
            }
            let (pending_root, source_bytes) = stats.pending_window.take().ok_or(Failure::State)?;
            if pending_root != receipt.root {
                return Err(Failure::State);
            }
            stats.durable_source_object_bytes += source_bytes;
            let source_only_nals = std::mem::take(&mut stats.pending_source_only_nals);
            stats.durable_source_only_nals += source_only_nals;
            stats.snapshot(snapshot);
            owner.preview_publish(receipt.root);
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
                    ("source_only_nals", source_only_nals.to_string()),
                    ("codec", string(codec)),
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
            let snapshot = snapshot.ok_or(Failure::State)?;
            let page = snapshot
                .pages()
                .iter()
                .find(|page| page.first_ordinal() == first_ordinal)
                .ok_or(Failure::State)?;
            let catalog = page.catalog();
            let scope = snapshot.namespace().scope();
            if page.slot() != &receipt.slot
                || C::manifest(catalog).root() != receipt.root
                || C::entries(catalog).len() != windows
                || C::scope(catalog) != scope
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
                    ("codec", string(codec)),
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
    owner: &Owner<'_, '_>,
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

/// Completion is evaluated only after the native archive emits Finished. A duration
/// observation does not bypass picture, index, or observed-final-snapshot barriers.
fn finished_result(
    cause: LiveArchiveCompletion,
    stop: Option<StopCause>,
    stats: &Statistics,
    target: u64,
) -> Result<(), Failure> {
    if cause != LiveArchiveCompletion::OwnerStopped
        || stats.durable_pictures != stats.collected_pictures
        || stats.indexed_windows != stats.durable_windows
        || stats.snapshot_digest.is_none()
    {
        return Err(Failure::Shortfall);
    }
    // Reuse the native custody classification rather than maintaining a second, weaker
    // list of pending-window, work-pin and unconfirmed-publication barriers here.
    // Pending remote control is deliberately separate from archive completion.
    if AttemptOutcome::new(Ok(()), stats).recovery_required {
        return Err(Failure::Storage);
    }
    match stop {
        Some(StopCause::ProgressStalled) => Err(Failure::ProgressStalled),
        Some(StopCause::CaptureDuration) if stats.durable_pictures == 0 => {
            Err(Failure::EmptyCapture)
        }
        Some(StopCause::CaptureDuration) if stats.collected_pictures <= target => Ok(()),
        None if stats.collected_pictures == target => Ok(()),
        _ => Err(Failure::Shortfall),
    }
}

fn finish_attempt<W: Write>(
    cause: LiveArchiveCompletion,
    stop: Option<StopCause>,
    stats: &Statistics,
    target: u64,
    log: &mut Transcript<'_, W>,
) -> Result<(), Failure> {
    finished_result(cause, stop, stats, target)?;
    if stop == Some(StopCause::CaptureDuration) {
        // This receipt follows publication, unlike the earlier timer observation. It
        // asserts only an owner-timed, nonempty durable prefix, never scene coverage.
        log.emit(
            "capture_duration_complete",
            object(&[
                ("durable_pictures", stats.durable_pictures.to_string()),
                ("picture_ceiling", target.to_string()),
                (
                    "picture_ceiling_reached",
                    (stats.durable_pictures == target).to_string(),
                ),
                ("archive_drained", "true".into()),
                ("source_eof_asserted", "false".into()),
                ("camera_time_asserted", "false".into()),
                ("absence_certifiable", "false".into()),
            ]),
            false,
        )?;
    }
    Ok(())
}

fn drive<W: Write>(
    options: &Options,
    source: &mut Option<SourceCustody>,
    capture: &mut JournaledLiveAvcArchive<'_, '_>,
    owner: &Owner<'_, '_>,
    mut entropy: Option<&mut Entropy>,
    stats: &mut Statistics,
    log: &mut Transcript<'_, W>,
) -> Result<(), Failure> {
    let namespace = options.pin_scope().archive_namespace;
    let output = ArchiveOutput {
        namespace,
        codec: "avc",
        owner,
    };
    let mut timing =
        FixedTiming::with_reorder(options.frame_duration, options.max_reorder_pictures)
            .map_err(|_| Failure::Timing)?;
    let mut next_command = Some(ClientCommand::Describe);
    let mut challenge = None;
    let mut ready = false;
    let mut sealing = false;
    let mut sealed = false;
    let mut draining = false;
    let mut stop_cause = None;
    let mut progress = RecordingProgress::new(owner.supervision);
    // Before a challenge is accepted the existing native API needs only nonsecret
    // placeholders. The owner's private lease is borrowed solely for signed requests.
    let unsigned = DigestCredentials::new("unused", "").map_err(|_| Failure::Configuration)?;

    loop {
        if stats.steps >= options.max_steps {
            return Err(Failure::WorkBudget);
        }
        stats.steps += 1;
        stats.observe(capture);
        let now = owner.now()?;
        owner.preview_pump();
        if !draining && capture.interruption().is_some() {
            // A source-verified archive prefix is not proof of a closed display
            // group. Preserve unresolved presentation timing as a fatal failure.
            timing.finish().map_err(|_| Failure::Timing)?;
            // The native owner has already retired the socket and admitted only
            // an original-source-verified prefix. Do not prepare another command,
            // borrow credentials, synthesize an owner stop, or reset its resource
            // ceilings. The original source failure remains terminal after drain.
            next_command = None;
            sealing = false;
            ready = false;
            draining = true;
            owner.begin_drain()?;
            log.emit(
                "source_interrupted",
                object(&[
                    ("error_id", string(Failure::Protocol.code())),
                    ("verified_prefix_admitted", "true".into()),
                    ("archive_drained", "false".into()),
                    ("source_eof_asserted", "false".into()),
                    ("capture_complete", "false".into()),
                    ("reconnect_admitted", "false".into()),
                ]),
                false,
            )?;
        }
        if !draining && now >= owner.live_deadline {
            return Err(Failure::Deadline);
        }
        if !sealing
            && !draining
            && !stats.input_ended
            && let Some(stall) = progress
                .observe(
                    now,
                    capture.state() == ClientState::Playing,
                    ready,
                    stats.collected_pictures,
                )
                .map_err(|_| Failure::State)?
        {
            if stats.collected_pictures != 0 {
                timing.finish().map_err(|_| Failure::Timing)?;
            }
            owner.admit_stall(stall, challenge.is_some(), log)?;
            // Stop socket readiness immediately. Only already-collected pictures may
            // enter the existing explicit seal and independently journaled final drain.
            stop_cause = Some(stall.cause);
            sealing = true;
            next_command = None;
        }
        if stats.collected_pictures == options.stop_after_pictures && !draining {
            // Do not label a prefix complete while future display positions remain unresolved.
            // The approved picture ceiling never grows implicitly to close a reorder group.
            timing.finish().map_err(|_| Failure::Timing)?;
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
        if !sealing && !draining && ready && challenge.is_some() {
            let (credentials, nonce) =
                owner.authentication(entropy.as_deref_mut().ok_or(Failure::Authentication)?)?;
            match capture.respond(&credentials, nonce, owner.now()?, owner, owner) {
                Ok(request) => {
                    challenge = None;
                    stats.authentication_responses += 1;
                    stats.digest_requests += 1;
                    log.emit(
                        "request_queued",
                        object(&[
                            ("command", string(command_name(request.command))),
                            ("method", string(request.command.wire_method())),
                            ("cseq", request.cseq.to_string()),
                            ("bytes", request.bytes.to_string()),
                            ("authentication", string("digest")),
                            ("challenge_response", "true".into()),
                        ]),
                        false,
                    )?;
                }
                Err(error) if backpressure(&error) => {}
                Err(error) => return Err(failure(error, stats)),
            }
        } else if !sealing
            && !draining
            && ready
            && let Some(command) = next_command
        {
            // Only an UNSENT keepalive intent is selected here. A held challenge's
            // response keeps the original chosen method, URI, CSeq and deadline owner.
            let command = if command == ClientCommand::KeepAlive {
                options.keepalive
            } else {
                command
            };
            let authenticated = if stats.authentication_responses != 0 {
                Some(owner.authentication(entropy.as_deref_mut().ok_or(Failure::Authentication)?)?)
            } else {
                None
            };
            let (credentials, nonce) = authenticated
                .as_ref()
                .map_or((&unsigned, [0; 16]), |(credentials, nonce)| {
                    (credentials, *nonce)
                });
            match capture.request(command, credentials, nonce, owner.now()?, owner, owner) {
                Ok(request) => {
                    next_command = None;
                    if authenticated.is_some() {
                        stats.digest_requests += 1;
                    }
                    log.emit(
                        "request_queued",
                        object(&[
                            ("command", string(command_name(request.command))),
                            ("method", string(request.command.wire_method())),
                            ("cseq", request.cseq.to_string()),
                            ("bytes", request.bytes.to_string()),
                            (
                                "authentication",
                                string(if authenticated.is_some() {
                                    "digest"
                                } else {
                                    "none"
                                }),
                            ),
                        ]),
                        false,
                    )?;
                }
                Err(error) if backpressure(&error) => {}
                Err(error) => return Err(failure(error, stats)),
            }
        }

        // Once either approved stop condition is observed, no additional socket operation
        // is enabled. Buffered work may drain only to publish the already-collected prefix.
        let readiness = SocketReadiness {
            readable: !sealing && !draining,
            writable: !sealing && !draining,
        };
        let step = capture
            .poll(readiness, owner.now()?, owner, owner)
            .map_err(|e| failure(e, stats))?;
        source_retention::observe_avc(source, &step, owner, stats, log)?;
        source_retention::account_pause(
            source,
            &mut progress,
            capture.state() == ClientState::Playing,
            ready,
            stats.collected_pictures,
        )?;
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
                    archive_progress(
                        progress,
                        capture.snapshot(),
                        &output,
                        stats,
                        &mut ready,
                        log,
                    )?;
                }
            },
            JournaledLiveArchiveStep::Live(LiveArchiveStep::WindowAccepted(admission)) => {
                let pending = capture.pending().ok_or(Failure::State)?;
                if pending.manifest().root() != admission.root || stats.pending_window.is_some() {
                    return Err(Failure::State);
                }
                stats.pending_window =
                    Some((admission.root, pending.objects().source.len() as u64));
                owner.preview_stage(pending);
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
                archive_progress(
                    progress,
                    capture.snapshot(),
                    &output,
                    stats,
                    &mut ready,
                    log,
                )?;
            }
            JournaledLiveArchiveStep::Live(LiveArchiveStep::Finished { archive, cause }) => {
                archive_progress(archive, capture.snapshot(), &output, stats, &mut ready, log)?;
                stats.observe(capture);
                if stats.collected_pictures != 0 {
                    timing.finish().map_err(|_| Failure::Timing)?;
                }
                return finish_attempt(cause, stop_cause, stats, options.stop_after_pictures, log);
            }
            JournaledLiveArchiveStep::Live(LiveArchiveStep::Recording(step)) => match *step {
                LiveRecordingStep::Network(step) => {
                    if let Some(wake) = network_step(
                        step,
                        stats,
                        &mut next_command,
                        &mut challenge,
                        options.authentication.is_some(),
                        log,
                    )? {
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
                                            (
                                                "composition_offset",
                                                selected_timing.composition_offset.to_string(),
                                            ),
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
                    return Err(network_stop_failure(&trigger));
                }
                LiveRecordingStep::Ended => return Err(Failure::Protocol),
                LiveRecordingStep::MediaQueued => {}
            },
            JournaledLiveArchiveStep::Stopped { trigger, retained } => {
                observe_stopped(&trigger, stats);
                stats.retirement(&retained);
                return Err(recording_stop_failure(&trigger));
            }
            JournaledLiveArchiveStep::Live(LiveArchiveStep::Stopped { trigger, retained }) => {
                observe_stopped(&trigger, stats);
                stats.archive_retirement(&retained);
                return Err(recording_stop_failure(&trigger));
            }
            JournaledLiveArchiveStep::Live(LiveArchiveStep::Ended) => return Err(Failure::State),
        }
        if owner.supervision.is_some() && !sealing && !draining && !stats.input_ended {
            let _ = progress
                .observe(
                    owner.now()?,
                    capture.state() == ClientState::Playing,
                    ready,
                    stats.collected_pictures,
                )
                .map_err(|_| Failure::State)?;
        }
    }
}

/// Refuse any existing path before creating either owner, including symlinks and old attempts.
fn require_new(path: &Path, owner: &Owner<'_, '_>) -> Result<(), Failure> {
    owner.startup_check()?;
    let result = match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(Failure::Root),
    };
    owner.startup_check()?;
    result
}

/// Bind both outputs to their existing canonical parents before creating either owner.
/// Lexically different paths may otherwise alias through a symlinked ancestor.
fn resolve_new_parent(path: &Path, owner: &Owner<'_, '_>) -> Result<PathBuf, Failure> {
    owner.startup_check()?;
    let parent =
        std::fs::canonicalize(path.parent().ok_or(Failure::Root)?).map_err(|_| Failure::Root)?;
    owner.startup_check()?;
    if !std::fs::metadata(&parent)
        .map_err(|_| Failure::Root)?
        .is_dir()
    {
        return Err(Failure::Root);
    }
    owner.startup_check()?;
    let resolved = parent.join(path.file_name().ok_or(Failure::Root)?);
    require_new(&resolved, owner)?;
    Ok(resolved)
}

fn create_root(path: &Path, owner: &Owner<'_, '_>) -> Result<(), Failure> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    // Exclusive creation closes the check/create race at the final path component.
    // Parent directories must already exist; no hidden ancestor creation or repair.
    owner.startup_check()?;
    builder.create(path).map_err(|_| Failure::Root)?;
    owner.startup_check()?;
    let parent =
        std::fs::File::open(path.parent().ok_or(Failure::Root)?).map_err(|_| Failure::Root)?;
    owner.startup_check()?;
    parent.sync_all().map_err(|_| Failure::Root)?;
    owner.startup_check()
}

fn run_owned<W: Write>(
    options: &Options,
    source_config: Option<&SourceConfig>,
    context: NativeContext<'_, '_>,
    stats: &mut Statistics,
    log: &mut Transcript<'_, W>,
    supervision: Option<Supervision>,
) -> Result<(), Failure> {
    let storage_deadline = options
        .timeout_ns
        .checked_add(options.drain_timeout_ns)
        .ok_or(Failure::Configuration)?;
    let mut owner = Owner {
        task: context.task,
        clock: context.clock,
        resources: context.resources,
        binding: options.binding(),
        live_deadline: options.timeout_ns,
        storage_deadline,
        drain_timeout: options.drain_timeout_ns,
        drain_deadline: Cell::new(None),
        credentials: None,
        supervision,
        preview_scope: if options.live_preview.is_some() {
            Some(PreviewScope {
                recording: options.recording_config().scope,
                codec: if options.codec() == "hevc" {
                    PreviewCodec::Hevc
                } else {
                    PreviewCodec::Avc
                },
                time_scale: options.time_scale,
                decode_clock: options.catalog_scope().decode_clock,
                privacy_binding: options.digest().map_err(|_| Failure::Configuration)?,
                expires_at_ns: options.timeout_ns,
            })
        } else {
            None
        },
        preview: RefCell::new(None),
    };
    let check_secret = || owner.secret_check();
    let credentials = options
        .authentication
        .as_ref()
        .map(|auth| CredentialLease::load(&auth.credential_file, &check_secret))
        .transpose()
        .map_err(secret_failure)?;
    let mut entropy = if credentials.is_some() {
        Some(Entropy::open(&check_secret).map_err(secret_failure)?)
    } else {
        None
    };
    owner.credentials = credentials.as_ref();
    require_new(&options.root, &owner)?;
    require_new(&options.pins, &owner)?;
    let root = resolve_new_parent(&options.root, &owner)?;
    let pin_root = resolve_new_parent(&options.pins, &owner)?;
    if root.starts_with(&pin_root) || pin_root.starts_with(&root) {
        return Err(Failure::Root);
    }
    let source_root = source_config
        .map(|config| {
            require_new(&config.root, &owner)?;
            let path = resolve_new_parent(&config.root, &owner)?;
            if [&root, &pin_root]
                .iter()
                .any(|other| path.starts_with(other) || other.starts_with(&path))
            {
                return Err(Failure::Root);
            }
            Ok(path)
        })
        .transpose()?;
    create_root(&root, &owner)?;
    owner.start_preview(options, stats);
    let result = (|| {
        owner.storage_check()?;
        let mut publisher = LocalRootPublisher::open(&root, options.publication_limits())
            .map_err(|_| Failure::Storage)?;
        owner.storage_check()?;
        let mut source = source_config
            .zip(source_root.as_ref())
            .map(|(config, path)| SourceCustody::open(config, path, &owner))
            .transpose()?;
        if let Some(custody) = &source {
            stats.source_custody = Some(custody.summary());
        }
        let capture_result = (|| {
            if options.codec() == "hevc" {
                return hevc::run(
                    options,
                    &pin_root,
                    &mut publisher,
                    &owner,
                    entropy.as_mut(),
                    stats,
                    log,
                    &mut source,
                );
            }
            let mut pins = ArchivePinJournal::create(
                &pin_root,
                options.pin_scope(),
                options.pin_limits(),
                &owner,
            )
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
                    JournaledLiveArchiveError::Live(LiveArchiveError::Recording(error))
                        if matches!(
                            error.as_ref(),
                            LiveRecordingError::Network(LiveAvcError::Transport(TcpError::Io {
                                operation: TcpOperation::Connect,
                                kind: io::ErrorKind::ConnectionRefused
                                    | io::ErrorKind::ConnectionReset
                                    | io::ErrorKind::ConnectionAborted
                                    | io::ErrorKind::TimedOut,
                            }))
                        ) =>
                    {
                        Failure::ConnectionUnavailable
                    }
                    _ => Failure::Connect,
                }
            })?;
            stats.connection_attempted = true;
            let result = drive(
                options,
                &mut source,
                &mut capture,
                &owner,
                entropy.as_mut(),
                stats,
                log,
            );
            stats.observe(&capture);
            // Close the socket and transfer all remaining ownership BEFORE terminal sink output.
            // No retry, deletion, publication, or synthetic EOF occurs in cancellation.
            if let Some(retired) = capture.cancel() {
                stats.retirement(&retired);
            }
            result
        })();
        if let Some(custody) = &source {
            stats.source_custody = Some(custody.summary());
        }
        capture_result
    })();
    if let Some(report) = owner.close_preview() {
        stats.live_preview = Some(report);
    }
    result
}

pub(super) fn execute(options: &Options) -> Result<(), &'static str> {
    execute_attempt(options)?.result
}

/// Only returns a retry observation after closing the socket, transferring retirements,
/// finalizing the attempt context and successfully flushing the complete terminal report.
pub(super) fn execute_attempt(options: &Options) -> Result<AttemptOutcome, &'static str> {
    execute_supervised_attempt(options, None)
}

/// The caller binds this additional stop/retry policy in its exact outer approval.
/// A single-attempt approval does not authorize an automatic successor attempt.
pub(super) fn execute_supervised_attempt(
    options: &Options,
    supervision: Option<Supervision>,
) -> Result<AttemptOutcome, &'static str> {
    execute_owned_attempt(options, supervision, None)
}

pub(super) fn execute_retained(
    options: &Options,
    source: &SourceConfig,
) -> Result<(), &'static str> {
    execute_owned_attempt(options, None, Some(source))?.result
}

fn execute_owned_attempt(
    options: &Options,
    supervision: Option<Supervision>,
    source: Option<&SourceConfig>,
) -> Result<AttemptOutcome, &'static str> {
    let approval = match source {
        Some(source) => source.digest(options)?,
        None => options.digest()?,
    };
    if options.approve != Some(approval) {
        return Err(Failure::Approval.code());
    }
    let mut runtime = CaptureRuntime::new(options, source, approval).map_err(Failure::code)?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut log = Transcript {
        out: &mut out,
        used: 0,
        maximum: options.max_report_bytes,
        sequence: 0,
        io_failed: false,
    };
    let mut stats = Statistics::default();
    let execution = runtime.run(&mut stats, |task, clock, resources, stats| {
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
                    string(&options.catalog_scope().decode_clock.to_text()),
                ),
                ("time_scale", options.time_scale.to_string()),
                ("codec", string(options.codec())),
                ("keepalive_method", string(options.keepalive.wire_method())),
                ("keepalive_fallback", "false".into()),
                ("authentication", string(options.authentication_mode())),
                ("server_identity_verified", "false".into()),
                ("transport_encrypted", "false".into()),
                ("capture_time", string("unknown")),
            ]),
            false,
        )?;
        if let Some(source) = source {
            log.emit("source_custody_started", source.report(), false)?;
        }
        if let Some(policy) = supervision {
            log.emit("recording_supervision", policy.report(), false)?;
        }
        run_owned(
            options,
            source,
            NativeContext {
                task,
                clock,
                resources,
            },
            stats,
            &mut log,
            supervision,
        )
    });
    stats.runtime = Some(execution.report);
    let result = execution.result;
    log.emit("terminal", terminal(options, &stats, &result), true)
        .map_err(Failure::code)?;
    let mut outcome = AttemptOutcome::new(result, &stats);
    if execution.closure_failed {
        // No successor may bypass canonical task/custody recovery merely because
        // the native protocol result would otherwise permit a new generation.
        outcome.retry = None;
        outcome.recovery_required = true;
    }
    Ok(outcome)
}

#[cfg(test)]
mod completion_tests {
    use super::*;

    fn settled() -> Statistics {
        Statistics {
            collected_pictures: 3,
            durable_pictures: 3,
            durable_windows: 1,
            indexed_windows: 1,
            snapshot_digest: Some(ContentDigest::sha256(b"finished archive")),
            ..Statistics::default()
        }
    }

    #[test]
    fn timed_nonempty_prefix_can_finish_before_the_approved_picture_ceiling() {
        let stats = settled();
        assert!(
            finished_result(
                LiveArchiveCompletion::OwnerStopped,
                Some(StopCause::CaptureDuration),
                &stats,
                10,
            )
            .is_ok()
        );
        assert!(finished_result(LiveArchiveCompletion::OwnerStopped, None, &stats, 10).is_err());
        assert!(finished_result(LiveArchiveCompletion::OwnerStopped, None, &stats, 3).is_ok());
        assert!(
            finished_result(
                LiveArchiveCompletion::OwnerStopped,
                Some(StopCause::CaptureDuration),
                &stats,
                2,
            )
            .is_err()
        );
    }

    #[test]
    fn a_progress_failure_is_not_promoted_to_timed_capture_success() {
        assert!(matches!(
            finished_result(
                LiveArchiveCompletion::OwnerStopped,
                Some(StopCause::ProgressStalled),
                &settled(),
                3,
            ),
            Err(Failure::ProgressStalled)
        ));
    }

    #[test]
    fn duration_cannot_skip_picture_index_or_final_snapshot_barriers() {
        for condition in 0..3 {
            let mut stats = settled();
            match condition {
                0 => stats.collected_pictures += 1,
                1 => stats.indexed_windows = 0,
                _ => stats.snapshot_digest = None,
            }
            assert!(
                finished_result(
                    LiveArchiveCompletion::OwnerStopped,
                    Some(StopCause::CaptureDuration),
                    &stats,
                    10,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn pending_custody_cannot_be_hidden_by_equal_picture_and_index_totals() {
        for condition in 0..5 {
            let mut stats = settled();
            match condition {
                0 => stats.pending_window = Some((ContentDigest::sha256(b"pending"), 1)),
                1 => stats.unrecorded_work_receipt = Some("unconfirmed receipt".into()),
                2 => stats.unpublished_prepared_pictures = 1,
                3 => stats.unpublished_prepared_bytes = 1,
                _ => stats.pending_source_only_nals = 1,
            }
            assert!(matches!(
                finished_result(
                    LiveArchiveCompletion::OwnerStopped,
                    Some(StopCause::CaptureDuration),
                    &stats,
                    10,
                ),
                Err(Failure::Storage)
            ));
        }
    }

    #[test]
    fn empty_duration_is_neither_success_nor_source_eof_nor_retry_permission() {
        let stats = Statistics {
            snapshot_digest: Some(ContentDigest::sha256(b"empty finished archive")),
            ..Statistics::default()
        };
        let result = finished_result(
            LiveArchiveCompletion::OwnerStopped,
            Some(StopCause::CaptureDuration),
            &stats,
            10,
        );
        assert!(matches!(result, Err(Failure::EmptyCapture)));
        assert!(!stats.input_ended);
        let outcome = AttemptOutcome::new(result, &stats);
        assert!(outcome.result.is_err());
        assert!(outcome.retry.is_none());
        assert!(!outcome.recovery_required);
    }

    #[test]
    fn publication_receipt_distinguishes_timed_success_from_reaching_picture_target() {
        let mut bytes = Vec::new();
        let mut log = Transcript {
            out: &mut bytes,
            used: 0,
            maximum: 65_536,
            sequence: 0,
            io_failed: false,
        };
        finish_attempt(
            LiveArchiveCompletion::OwnerStopped,
            Some(StopCause::CaptureDuration),
            &settled(),
            10,
            &mut log,
        )
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for expected in [
            "\"kind\":\"capture_duration_complete\"",
            "\"picture_ceiling_reached\":false",
            "\"archive_drained\":true",
            "\"source_eof_asserted\":false",
            "\"camera_time_asserted\":false",
            "\"absence_certifiable\":false",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
    }

    #[test]
    fn failed_output_cannot_report_a_successful_timed_attempt() {
        struct Refused;
        impl Write for Refused {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut sink = Refused;
        let mut log = Transcript {
            out: &mut sink,
            used: 0,
            maximum: 65_536,
            sequence: 0,
            io_failed: false,
        };
        assert!(matches!(
            finish_attempt(
                LiveArchiveCompletion::OwnerStopped,
                Some(StopCause::CaptureDuration),
                &settled(),
                10,
                &mut log,
            ),
            Err(Failure::Output)
        ));
    }
}
