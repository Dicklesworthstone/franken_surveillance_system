#![forbid(unsafe_code)]
//! Finite owner-authorized native RTSP metadata acquisition with durable prefix receipts.

use std::ffi::OsString;
use std::fmt::Write as _;

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    RuntimeGrant, TimestampNs,
};
use fss_packet::OnvifMetadataReceivePoll;
use fss_reference::onvif::metadata::rtp::{self, RetainedRtpMetadata};
use fss_reference::rtsp::RtspEvent;
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::authenticated::DigestClientError;
use fss_reference::rtsp::client::{ClientCommand, ClientError, ClientProgress, ClientState};
use fss_reference::rtsp::framed::{MAX_WIRE_CHUNK, RtspWireFrame, WireIntakeError};
use fss_reference::rtsp::live_metadata::{
    LiveMetadataConfig, LiveMetadataConnection, LiveMetadataError, LiveMetadataFailure,
    LiveMetadataRetirement, LiveMetadataStep, QueuedMetadataRequest, SocketReadiness,
};
use fss_reference::rtsp::metadata_client::{
    MetadataClientError, MetadataClientPoll, MetadataClientRetirement,
};
use fss_reference::rtsp::metadata_source::{
    NativeMetadataConfig, NativeMetadataSource, NativeMetadataSourceError,
    NativeMetadataStop as Stop,
};
use fss_reference::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpError, TcpLimits, TcpOperation, TcpTotals,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::authentication::{CredentialLease, Entropy, SecretError};
use super::{
    CUSTODY_ERROR, CommandOutput, INPUT_ERROR, LIMIT_ERROR, REPORT_LIMIT, admission, runtime,
};

#[path = "capture_rtp/plan.rs"]
mod plan;
use plan::Options;

const AUTHORITY_ERROR: &str = "ERR-ONVIF-AUTHORITY-001";
const DEADLINE_ERROR: &str = "ERR-ONVIF-DEADLINE-001";
const BUDGET_ERROR: &str = "ERR-ONVIF-BUDGET-001";
const CANCELLED_ERROR: &str = "ERR-ONVIF-CANCELLED-001";
const STORAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const STORAGE_OPERATIONS: u64 = 4 * (super::STORAGE_CHECKPOINT_ALLOWANCE + 16 * 16_384 + 32 * 64);
const MAX_SENT_BYTES: u64 = 256 * 1024;
const MAX_STEPS: u64 = 200_000;
const CLEANUP_NS: u64 = 2_000_000_000;

fn secret_code(error: SecretError) -> &'static str {
    match error {
        SecretError::Deadline => DEADLINE_ERROR,
        SecretError::Authority | SecretError::Revoked => AUTHORITY_ERROR,
        SecretError::Credentials | SecretError::Entropy => INPUT_ERROR,
    }
}
fn secret_check(scope: &runtime::Scope<'_, '_>) -> Result<(), SecretError> {
    super::capture::secret_check(scope)
}
fn denial(code: &'static str) -> TcpDenial {
    match code {
        CANCELLED_ERROR => TcpDenial::Cancelled,
        DEADLINE_ERROR => TcpDenial::Deadline,
        BUDGET_ERROR => TcpDenial::Budget,
        _ => TcpDenial::Unauthorized,
    }
}
fn stop_for_owner(code: &'static str) -> Stop {
    match code {
        CANCELLED_ERROR => Stop::Cancelled,
        DEADLINE_ERROR => Stop::Timeout,
        BUDGET_ERROR | LIMIT_ERROR => Stop::InputLimit,
        _ => Stop::Authority,
    }
}
fn stop_for_transport(error: &LiveMetadataError) -> Stop {
    match error {
        LiveMetadataError::Transport(TcpError::Denied(TcpDenial::Cancelled)) => Stop::Cancelled,
        LiveMetadataError::Transport(
            TcpError::Deadline | TcpError::ReadDeadline | TcpError::Denied(TcpDenial::Deadline),
        )
        | LiveMetadataError::Protocol(
            MetadataClientError::Session(
                ClientError::ResponseTimeout | ClientError::SessionExpired,
            )
            | MetadataClientError::Authentication(DigestClientError::Session(
                ClientError::ResponseTimeout | ClientError::SessionExpired,
            ))
            | MetadataClientError::Wire(WireIntakeError::Deadline),
        ) => Stop::Timeout,
        LiveMetadataError::WorkBudget
        | LiveMetadataError::Transport(
            TcpError::WorkBudget | TcpError::RequestBudget | TcpError::Denied(TcpDenial::Budget),
        )
        | LiveMetadataError::Protocol(
            MetadataClientError::InputLimit
            | MetadataClientError::Wire(WireIntakeError::Limit | WireIntakeError::Allocation),
        ) => Stop::InputLimit,
        LiveMetadataError::Transport(TcpError::Denied(_)) => Stop::Authority,
        LiveMetadataError::Protocol(
            MetadataClientError::Authentication(_) | MetadataClientError::AuthenticationAtEof,
        ) => Stop::Authentication,
        LiveMetadataError::Transport(_) => Stop::Transport,
        _ => Stop::Protocol,
    }
}

fn source_failure(error: NativeMetadataSourceError) -> (Stop, &'static str) {
    match error {
        NativeMetadataSourceError::Limit
        | NativeMetadataSourceError::Allocation
        | NativeMetadataSourceError::Exhausted => (Stop::InputLimit, LIMIT_ERROR),
        _ => (Stop::Protocol, INPUT_ERROR),
    }
}

fn safe_backpressure(failure: &LiveMetadataFailure) -> bool {
    failure.retirement.is_none()
        && matches!(
            failure.reason,
            LiveMetadataError::Backpressure
                | LiveMetadataError::Protocol(MetadataClientError::Backpressure)
        )
}

/// A timer becoming due between the admission check and the wait is ordinary progress.
/// A failed owner checkpoint still remains a refusal; no expired request is revived.
fn wait_for_progress(scope: &runtime::Scope<'_, '_>, until: u64) -> Result<(), &'static str> {
    if scope.now()? >= until {
        return Ok(());
    }
    match scope.wait(until) {
        Err(DEADLINE_ERROR) if scope.now().is_ok_and(|now| now >= until) => Ok(()),
        result => result,
    }
}

struct Network<'a, 'clock, 'task> {
    scope: &'a runtime::Scope<'clock, 'task>,
    binding: &'a TcpBinding,
    credentials: Option<&'a CredentialLease>,
    deadline_ns: u64,
}
impl TcpAuthority for Network<'_, '_, '_> {
    fn checkpoint(
        &self,
        binding: &TcpBinding,
        _: TcpOperation,
        now: u64,
        deadline: u64,
    ) -> Result<(), TcpDenial> {
        if binding != self.binding || deadline != self.deadline_ns || now >= deadline {
            return Err(TcpDenial::Unauthorized);
        }
        let current = self
            .scope
            .admit(RuntimeGrant::AdapterNet, false)
            .map_err(denial)?;
        if current < now || current >= deadline {
            return Err(TcpDenial::Deadline);
        }
        if let Some(credentials) = self.credentials {
            credentials
                .revalidate(&|| secret_check(self.scope))
                .map_err(|error| match error {
                    SecretError::Deadline => TcpDenial::Deadline,
                    SecretError::Revoked | SecretError::Credentials => TcpDenial::Revoked,
                    _ => TcpDenial::Unauthorized,
                })?;
        }
        // Secret-file checks also consume time; never extend the network lease through them.
        if self.scope.now().map_err(denial)? >= deadline {
            return Err(TcpDenial::Deadline);
        }
        Ok(())
    }
}

struct Receipt {
    kind: &'static str,
    identity: ContentDigest,
    root: ContentDigest,
    native_source: ContentDigest,
}
struct Capture {
    source: NativeMetadataSource,
    totals: TcpTotals,
    accounted_network_bytes: u64,
    documents: usize,
    stop: Stop,
    error: Option<&'static str>,
    remote_session_may_exist: bool,
    teardown_acknowledged: bool,
    pending_request: bool,
    receipts: Vec<Receipt>,
    retained: Option<RetainedRtpMetadata>,
    final_published: bool,
}
impl Capture {
    fn source_error(&mut self, error: NativeMetadataSourceError) {
        let (stop, code) = source_failure(error);
        self.stop = stop;
        self.error.get_or_insert(code);
    }
    fn observe_rejected(&mut self, frame: &RtspWireFrame) {
        if self.source.omitted_observations() != 0 {
            return;
        }
        let result = match frame.event() {
            RtspEvent::Response(_) | RtspEvent::AuthRequired { .. } => {
                self.source.observe_rejected_control(frame)
            }
            RtspEvent::Interleaved { .. } => self.source.observe_interleaved(frame),
            _ => return,
        };
        if let Err(error) = result {
            self.source_error(error);
        }
    }
    fn retire_protocol(&mut self, retired: MetadataClientRetirement) {
        self.remote_session_may_exist = retired.session.remote_session_may_exist;
        // Held frames have not been emitted by the protocol owner before this transfer.
        if let Some(frame) = retired.challenge {
            self.observe_rejected(&frame);
        }
        if let Some(frame) = retired.retry {
            self.observe_rejected(&frame);
        }
        // Disjoint remaining wire is accounted by the final byte conservation check.
    }
    fn retire(&mut self, retired: LiveMetadataRetirement) {
        self.totals = retired.transport.totals;
        if let Some(frame) = retired.answered_challenge {
            self.observe_rejected(&frame);
        }
        self.retire_protocol(retired.protocol);
    }
    fn failure(&mut self, failure: LiveMetadataFailure) {
        self.stop = stop_for_transport(&failure.reason);
        self.error.get_or_insert(INPUT_ERROR);
        if let Some(retired) = failure.retirement {
            self.retire(*retired);
        }
    }
    fn queued(&mut self, queued: QueuedMetadataRequest) {
        self.pending_request = true;
        if let Some(frame) = queued.challenge {
            self.observe_rejected(&frame);
        }
    }
    fn account(&mut self, scope: &runtime::Scope<'_, '_>) -> Result<(), &'static str> {
        let total = self
            .totals
            .received_bytes
            .checked_add(self.totals.sent_bytes)
            .ok_or(LIMIT_ERROR)?;
        let delta = total
            .checked_sub(self.accounted_network_bytes)
            .ok_or(CUSTODY_ERROR)?;
        if delta != 0 {
            scope.network_bytes(delta)?;
            self.accounted_network_bytes = total;
        }
        Ok(())
    }
    fn seal(&mut self, ended_ns: u64) -> Result<(), &'static str> {
        let retained = self
            .source
            .controls()
            .iter()
            .try_fold(0u64, |n, c| n.checked_add(c.wire_bytes() as u64))
            .and_then(|n| {
                self.source
                    .records()
                    .iter()
                    .try_fold(n, |n, r| n.checked_add(r.expose_wire().len() as u64))
            })
            .and_then(|n| n.checked_add(self.source.omitted_bytes()))
            .ok_or(CUSTODY_ERROR)?;
        let remainder = self
            .totals
            .received_bytes
            .checked_sub(retained)
            .ok_or(CUSTODY_ERROR)?;
        self.source
            .record_unprocessed_wire(usize::try_from(remainder).map_err(|_| LIMIT_ERROR)?)
            .map_err(|_| CUSTODY_ERROR)?;
        self.source
            .finish(ended_ns, self.stop)
            .map_err(|_| CUSTODY_ERROR)
    }
    fn publish(
        &mut self,
        kind: &'static str,
        ended_ns: u64,
        publish: &mut impl FnMut(&NativeMetadataSource) -> Result<RetainedRtpMetadata, &'static str>,
    ) -> Result<(), &'static str> {
        // Three fixed milestones plus the terminal source. Work never scales with packet count.
        if self.receipts.len() >= 4 {
            return Err(LIMIT_ERROR);
        }
        let mut prefix;
        let source = if kind == "final" {
            &self.source
        } else {
            prefix = self.source.clone();
            prefix
                .finish(ended_ns, Stop::Checkpoint)
                .map_err(|_| CUSTODY_ERROR)?;
            &prefix
        };
        let retained = publish(source)?;
        let native_source = retained.native_source_digest().ok_or(CUSTODY_ERROR)?;
        self.receipts.push(Receipt {
            kind,
            identity: retained.identity(),
            root: retained.publication_root(),
            native_source,
        });
        self.retained = Some(retained);
        self.final_published = kind == "final";
        Ok(())
    }
}

fn nonce(
    entropy: &mut Option<Entropy>,
    scope: &runtime::Scope<'_, '_>,
) -> Result<[u8; 16], &'static str> {
    match entropy {
        Some(entropy) => entropy.next(&|| secret_check(scope)).map_err(secret_code),
        // An unauthenticated owner never answers a challenge or emits Authorization.
        None => Ok([0; 16]),
    }
}

fn acquire(
    options: &Options,
    scope: &runtime::Scope<'_, '_>,
    publish: &mut impl FnMut(&NativeMetadataSource) -> Result<RetainedRtpMetadata, &'static str>,
) -> Result<Capture, &'static str> {
    let credentials = options
        .auth
        .as_ref()
        .map(|auth| CredentialLease::load(&auth.credential_file, &|| secret_check(scope)))
        .transpose()
        .map_err(secret_code)?;
    let mut entropy = if credentials.is_some() {
        Some(Entropy::open(&|| secret_check(scope)).map_err(secret_code)?)
    } else {
        None
    };
    let digest = match &credentials {
        Some(lease) => lease.credentials().map_err(secret_code)?,
        None => DigestCredentials::new("anonymous", "").map_err(|_| INPUT_ERROR)?,
    };
    let started_ns = scope.now()?;
    let target_ns = started_ns
        .checked_add(options.capture_ns)
        .ok_or(LIMIT_ERROR)?;
    let deadline_ns = target_ns.checked_add(CLEANUP_NS).ok_or(LIMIT_ERROR)?;
    // Storage setup and secret resolution consumed the same request clock. Never borrow
    // their time from the explicit final-publication reserve.
    if deadline_ns
        .checked_add(2_000_000_000)
        .is_none_or(|at| at >= options.timeout_ns)
    {
        return Err(DEADLINE_ERROR);
    }
    let source = NativeMetadataSource::new(NativeMetadataConfig {
        approval: options.approval,
        protocol: options.protocol.clone(),
        binding: options.tcp.clone(),
        payload_type: options.payload_type,
        receive_origin_ns: options.receive_origin_ns,
        started_ns,
        max_source_bytes: options.max_source_bytes,
        max_records: options.max_records,
    })
    .map_err(|_| LIMIT_ERROR)?;
    let network = Network {
        scope,
        binding: &options.tcp,
        credentials: credentials.as_ref(),
        deadline_ns,
    };
    let config = LiveMetadataConfig {
        protocol: options.protocol.clone(),
        binding: options.tcp.clone(),
        transport: TcpLimits {
            max_received_bytes: options.max_source_bytes as u64 + 256 * 1024,
            max_sent_bytes: MAX_SENT_BYTES,
            max_io_calls: 100_000,
            max_request_bytes: 32 * 1024,
            chunk_bytes: MAX_WIRE_CHUNK,
            connect_timeout_ns: options.capture_ns.min(2_000_000_000),
        },
        reorder: options.config.reorder,
        payload_type: options.payload_type,
        metadata: options.config.metadata,
        realm: options
            .auth
            .as_ref()
            .map_or("owner-approved-anonymous", |auth| &auth.realm)
            .to_owned(),
        digest_policy: options
            .auth
            .as_ref()
            .map_or(DigestPolicy::default(), |auth| auth.policy),
        deadline_ns,
        max_steps: MAX_STEPS,
    };
    let mut capture = Capture {
        source,
        totals: TcpTotals::default(),
        accounted_network_bytes: 0,
        documents: 0,
        stop: Stop::Transport,
        error: None,
        remote_session_may_exist: false,
        teardown_acknowledged: false,
        pending_request: false,
        receipts: Vec::with_capacity(4),
        retained: None,
        final_published: false,
    };
    let mut connection = match LiveMetadataConnection::connect(config, started_ns, &network) {
        Ok(connection) => Some(connection),
        Err(failure) => {
            capture.stop = stop_for_transport(&failure.reason);
            capture.error = Some(INPUT_ERROR);
            None
        }
    };
    if let Some(connection) = &mut connection {
        let result = nonce(&mut entropy, scope).and_then(|cnonce| {
            let now = scope.now()?;
            match connection.request(ClientCommand::Describe, &digest, cnonce, now, &network) {
                Ok(queued) => {
                    capture.queued(queued);
                    Ok(())
                }
                Err(failure) => {
                    capture.failure(failure);
                    Err(INPUT_ERROR)
                }
            }
        });
        if let Err(error) = result {
            capture.error.get_or_insert(error);
        }
        let mut want_stop = false;
        let mut first_packet = false;
        let mut first_document = false;
        let mut terminal = false;
        while capture.error.is_none() && !terminal {
            let now = match scope.now() {
                Ok(now) => now,
                Err(error) => {
                    capture.stop = stop_for_owner(error);
                    capture.error = Some(error);
                    break;
                }
            };
            if now >= target_ns {
                want_stop = true;
            }
            if want_stop && !capture.pending_request {
                match connection.state() {
                    ClientState::Ready | ClientState::Playing => {
                        let cnonce = match nonce(&mut entropy, scope) {
                            Ok(nonce) => nonce,
                            Err(error) => {
                                capture.stop = Stop::Authentication;
                                capture.error = Some(error);
                                break;
                            }
                        };
                        match connection.request(
                            ClientCommand::Teardown,
                            &digest,
                            cnonce,
                            now,
                            &network,
                        ) {
                            Ok(queued) => {
                                capture.stop = Stop::TargetReached;
                                capture.queued(queued);
                            }
                            // A complete frame, partial frame or retained RTP retry must
                            // drain first. This refusal consumed no CSeq or wire bytes.
                            Err(failure) if safe_backpressure(&failure) => {}
                            Err(failure) => {
                                capture.failure(failure);
                                break;
                            }
                        }
                    }
                    ClientState::Idle | ClientState::Described => {
                        capture.stop = Stop::Timeout;
                        capture.error = Some(DEADLINE_ERROR);
                        break;
                    }
                    _ => {}
                }
            }
            let step = connection.poll(
                SocketReadiness {
                    readable: true,
                    writable: true,
                },
                now,
                &network,
            );
            if let Some(totals) = connection.totals() {
                capture.totals = totals;
            }
            let mut command = None;
            let mut milestone = None;
            let mut wake = None;
            match step {
                Err(failure) => capture.failure(failure),
                Ok(
                    LiveMetadataStep::Wire(_)
                    | LiveMetadataStep::Write(_)
                    | LiveMetadataStep::InputEnded,
                ) => {}
                Ok(LiveMetadataStep::Ended) => {
                    terminal = true;
                }
                Ok(LiveMetadataStep::Pending(wait)) => {
                    wake = Some(wait.wake_at_ns.unwrap_or(deadline_ns));
                }
                Ok(LiveMetadataStep::Protocol { event, transport }) => {
                    if let Some(retired) = transport {
                        capture.totals = retired.totals;
                    }
                    match event {
                        MetadataClientPoll::Control { progress, source } => {
                            if let Err(error) = capture.source.observe_control(&progress, &source) {
                                capture.source_error(error);
                            }
                            if let ClientProgress::Accepted(state) = progress {
                                capture.pending_request = false;
                                match state {
                                    ClientState::Described => {
                                        milestone = Some("description");
                                        if !want_stop {
                                            command = Some(ClientCommand::Setup);
                                        }
                                    }
                                    ClientState::Ready => {
                                        if !want_stop {
                                            command = Some(ClientCommand::Play);
                                        }
                                    }
                                    ClientState::Closed => {
                                        capture.teardown_acknowledged = true;
                                        capture.remote_session_may_exist = false;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        MetadataClientPoll::Rtp {
                            source, retirement, ..
                        } => {
                            if let Err(error) = capture.source.observe_interleaved(&source) {
                                capture.source_error(error);
                            }
                            if !first_packet {
                                first_packet = true;
                                milestone = Some("first_packet");
                            }
                            if let Some(retired) = retirement {
                                capture.stop = Stop::Protocol;
                                capture.error = Some(INPUT_ERROR);
                                capture.retire_protocol(*retired);
                                terminal = true;
                            }
                        }
                        MetadataClientPoll::Rtcp { source, .. } => {
                            if let Err(error) = capture.source.observe_interleaved(&source) {
                                capture.source_error(error);
                            }
                        }
                        MetadataClientPoll::Metadata(event) => {
                            if let OnvifMetadataReceivePoll::Packet {
                                reconstruction: Ok(output),
                                ..
                            } = event
                            {
                                if output.document.is_some() {
                                    capture.documents += 1;
                                    if !first_document {
                                        first_document = true;
                                        milestone = Some("first_document");
                                    }
                                    if capture.documents >= options.max_documents {
                                        want_stop = true;
                                    }
                                }
                            }
                        }
                        MetadataClientPoll::AuthenticationRequired { .. } => {
                            if credentials.is_none() {
                                capture.stop = Stop::Authentication;
                                capture.error = Some(AUTHORITY_ERROR);
                            } else {
                                match nonce(&mut entropy, scope) {
                                    Err(error) => {
                                        capture.stop = Stop::Authentication;
                                        capture.error = Some(error);
                                    }
                                    Ok(cnonce) => {
                                        match connection.respond(&digest, cnonce, now, &network) {
                                            Ok(queued) => capture.queued(queued),
                                            Err(failure) => capture.failure(failure),
                                        }
                                    }
                                }
                            }
                        }
                        MetadataClientPoll::KeepAliveDue => {
                            if !want_stop {
                                command = Some(ClientCommand::KeepAliveGetParameter);
                            }
                        }
                        MetadataClientPoll::Pending { wake_at_ns }
                        | MetadataClientPoll::Backpressure { wake_at_ns } => {
                            wake = Some(wake_at_ns.unwrap_or(deadline_ns));
                        }
                        MetadataClientPoll::Fault {
                            reason,
                            retirement,
                            source,
                        } => {
                            capture.stop = stop_for_transport(&LiveMetadataError::Protocol(reason));
                            capture.error = Some(INPUT_ERROR);
                            if let Some(frame) = source {
                                capture.observe_rejected(&frame);
                            }
                            capture.retire_protocol(*retirement);
                            terminal = true;
                        }
                        MetadataClientPoll::Ended { retirement, .. } => {
                            if let Some(retired) = retirement {
                                capture.retire_protocol(*retired);
                            }
                            if !capture.teardown_acknowledged {
                                capture.stop = Stop::Eof;
                            }
                            terminal = true;
                        }
                    }
                }
            }
            if let Err(error) = capture.account(scope) {
                capture.stop = stop_for_owner(error);
                capture.error.get_or_insert(error);
            }
            if capture.error.is_none() {
                if let Some(kind) = milestone {
                    let result = scope
                        .now()
                        .and_then(|now| capture.publish(kind, now, publish));
                    if let Err(error) = result {
                        capture.stop = Stop::Storage;
                        capture.error = Some(error);
                    }
                }
            }
            if capture.error.is_none() && !terminal {
                if let Some(command) = command {
                    let result = nonce(&mut entropy, scope).and_then(|cnonce| {
                        let now = scope.now()?;
                        match connection.request(command, &digest, cnonce, now, &network) {
                            Ok(queued) => {
                                capture.queued(queued);
                                Ok(())
                            }
                            Err(failure) => {
                                capture.failure(failure);
                                Err(INPUT_ERROR)
                            }
                        }
                    });
                    if let Err(error) = result {
                        capture.error.get_or_insert(error);
                    }
                } else if let Some(wake) = wake {
                    let until = if want_stop {
                        deadline_ns
                    } else {
                        target_ns.min(deadline_ns)
                    }
                    .min(wake);
                    if until > scope.observed_ns() {
                        if let Err(error) = wait_for_progress(scope, until) {
                            capture.stop = stop_for_owner(error);
                            capture.error = Some(error);
                        }
                    }
                }
            }
        }
        if let Some(retired) = connection.cancel() {
            capture.retire(retired);
        }
    }
    // Releasing the owned socket is local cleanup, independent of remote TEARDOWN proof.
    // The last admitted time is available even after cancellation, without another clock effect.
    if let Err(error) = capture.account(scope) {
        capture.error.get_or_insert(error);
    }
    let seal = capture.seal(scope.observed_ns().max(started_ns));
    if let Err(error) = seal {
        capture.error.get_or_insert(error);
    } else if let Err(error) = capture.publish("final", scope.observed_ns(), publish) {
        capture.error.get_or_insert(error);
    }
    // An earlier successful publication is never erased by a later storage/cancellation failure.
    if capture.receipts.is_empty() {
        return Err(capture.error.unwrap_or(CUSTODY_ERROR));
    }
    Ok(capture)
}

fn run(options: Options) -> Result<(CommandOutput, bool), &'static str> {
    let request = runtime::Request {
        approval: options.approval,
        principal: options.principal.clone(),
        timeout_ns: options.timeout_ns,
        bytes: STORAGE_BYTES,
        network_bytes: options.max_source_bytes as u64 + 256 * 1024 + MAX_SENT_BYTES,
        storage_operations: STORAGE_OPERATIONS,
        network: true,
        write: true,
        secrets: options.auth.is_some(),
    };
    let completed = runtime::run_committing(request, |scope| {
        scope.input()?;
        match std::fs::symlink_metadata(&options.root) {
            Ok(metadata) if !metadata.file_type().is_dir() => return Err(INPUT_ERROR),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(INPUT_ERROR),
        }
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:onvif-native-rtp-metadata".into(),
            operation_id: OperationId::parse("operation:onvif-native-rtp-metadata")
                .map_err(|_| CUSTODY_ERROR)?,
            principal: options.principal.clone(),
            capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(STORAGE_BYTES)
                .storage_operations(STORAGE_OPERATIONS)
                .build()
                .map_err(|_| LIMIT_ERROR)?,
            privacy_scope: "privacy:owner-private-vendor-metadata".into(),
            retention_scope: "retention:explicit-native-rtp-metadata".into(),
            anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
            generation: 1,
        })
        .map_err(|_| CUSTODY_ERROR)?;
        let cx = ReplayCx::from_context_authority_read_only(&authority, options.root.clone())
            .map_err(|_| CUSTODY_ERROR)?
            .with_admission(|_| admission::check(scope));
        let result = (|| {
            scope.output()?;
            let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)
                .map_err(|_| CUSTODY_ERROR)?;
            acquire(&options, scope, &mut |source| {
                let mut binding = options.binding.clone();
                let origin = source.config().receive_origin_ns;
                binding.receive_interval = CaptureInterval::new(
                    TimestampNs(
                        origin
                            .checked_add(i128::from(source.started_ns()))
                            .ok_or(LIMIT_ERROR)?,
                    ),
                    TimestampNs(
                        origin
                            .checked_add(i128::from(source.ended_ns().ok_or(CUSTODY_ERROR)?))
                            .ok_or(LIMIT_ERROR)?,
                    ),
                )
                .map_err(|_| CUSTODY_ERROR)?;
                rtp::retain_native(&mut deployment, source, binding, options.config, &cx).map_err(
                    |error| {
                        cx.admission_refusal()
                            .map(admission::code)
                            .unwrap_or(error.code())
                    },
                )
            })
        })();
        let owner_error = cx.admission_refusal().map(admission::code);
        cx.drain_and_finalize();
        match result {
            Ok(mut capture) => {
                capture.error = capture.error.or(owner_error);
                Ok(runtime::Committed::new(capture))
            }
            Err(error) => Err(owner_error.unwrap_or(error)),
        }
    })?;
    let capture = completed.value;
    let error = capture
        .error
        .or(completed.post_commit_error)
        .or(completed.finalization_error);
    let mut custody = format!(
        "operation=capture-rtp\napproval={}\nsource_mode=native_rtsp_tcp\ndurable_publications={}\n",
        options.approval,
        capture.receipts.len()
    );
    for (index, receipt) in capture.receipts.iter().enumerate() {
        writeln!(custody, "publication.{index}.kind={}\npublication.{index}.import_identity={}\npublication.{index}.root={}\npublication.{index}.native_source_sha256={}", receipt.kind, receipt.identity, receipt.root, receipt.native_source).map_err(|_| LIMIT_ERROR)?;
    }
    custody.push_str("durable_publication=true\nsafe_next=verify_rtp_exact_import\n");
    let retained = capture.retained.as_ref().ok_or(CUSTODY_ERROR)?;
    let mut report = custody.clone();
    writeln!(report, "final_source_published={}\nacquisition_stop={}\nerror={}\npost_commit_error={}\nfinalization_error={}\nremote_session_may_exist={}\nteardown_acknowledged={}\nsocket_received_bytes={}\nsocket_sent_bytes={}\naccounted_network_bytes={}\nnetwork_budget_reserved={}\nnetwork_budget_mode=prepaid_ceiling\nraw_tcp_transcript_retained=false\nauthentication_headers_retained=false\ntransport_encrypted=false\nserver_identity_verified=false\nvalues_disclosed=false", capture.final_published, capture.stop.code(), error.unwrap_or("none"), completed.post_commit_error.unwrap_or("none"), completed.finalization_error.unwrap_or("none"), capture.remote_session_may_exist, capture.teardown_acknowledged, capture.totals.received_bytes, capture.totals.sent_bytes, capture.accounted_network_bytes, options.max_source_bytes as u64 + 256 * 1024 + MAX_SENT_BYTES).map_err(|_| LIMIT_ERROR)?;
    let detail = super::rtp::report(retained, "capture-rtp", false, None);
    let detail_ok = match detail {
        Ok(detail) if report.len().saturating_add(detail.len()) <= REPORT_LIMIT => {
            report.push_str(&detail);
            true
        }
        _ => {
            report.push_str("detail_available=false\nsafe_next=inspect_rtp_exact_import\n");
            false
        }
    };
    let complete = error.is_none()
        && detail_ok
        && capture.final_published
        && retained.processing_complete()
        && !capture.remote_session_may_exist;
    Ok((
        CommandOutput {
            report,
            custody_receipt: Some(custody),
        },
        complete,
    ))
}

pub(super) fn run_args(args: &[OsString]) -> Result<(CommandOutput, bool), &'static str> {
    match plan::parse(args)? {
        None => Ok((
            CommandOutput {
                report: plan::HELP.to_owned(),
                custody_receipt: None,
            },
            true,
        )),
        Some(options) => run(options),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_digest_and_partial_wire_deadlines_preserve_timeout_outcome() {
        for error in [
            MetadataClientError::Session(ClientError::ResponseTimeout),
            MetadataClientError::Session(ClientError::SessionExpired),
            MetadataClientError::Authentication(DigestClientError::Session(
                ClientError::ResponseTimeout,
            )),
            MetadataClientError::Authentication(DigestClientError::Session(
                ClientError::SessionExpired,
            )),
            MetadataClientError::Wire(WireIntakeError::Deadline),
        ] {
            assert_eq!(
                stop_for_transport(&LiveMetadataError::Protocol(error)),
                Stop::Timeout
            );
        }
        assert_eq!(
            stop_for_transport(&LiveMetadataError::Protocol(
                MetadataClientError::AuthenticationAtEof
            )),
            Stop::Authentication,
        );
    }

    #[test]
    fn source_and_wire_limits_are_distinct_from_invalid_protocol_evidence() {
        for error in [
            MetadataClientError::InputLimit,
            MetadataClientError::Wire(WireIntakeError::Limit),
            MetadataClientError::Wire(WireIntakeError::Allocation),
        ] {
            assert_eq!(
                stop_for_transport(&LiveMetadataError::Protocol(error)),
                Stop::InputLimit
            );
        }
        for error in [
            NativeMetadataSourceError::Limit,
            NativeMetadataSourceError::Allocation,
            NativeMetadataSourceError::Exhausted,
        ] {
            assert_eq!(source_failure(error), (Stop::InputLimit, LIMIT_ERROR));
        }
        for error in [
            NativeMetadataSourceError::Control,
            NativeMetadataSourceError::Description,
            NativeMetadataSourceError::Clock,
        ] {
            assert_eq!(source_failure(error), (Stop::Protocol, INPUT_ERROR));
        }
    }
}
