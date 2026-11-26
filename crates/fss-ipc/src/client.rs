#![forbid(unsafe_code)]
//! Owner-authenticated local IPC client and streaming delta subscription iterator.

use std::io::{self, BufReader};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fss_core::{CanonicalDecode, CanonicalEncode, ContentDigest, ContractBasis, PrincipalId};

pub use crate::deployment::{DeploymentChannel, DeploymentClient};
use crate::error::IpcError;
use crate::protocol::{
    BoundedControlOp, HandshakeAccepted, HandshakeRequest, HandshakeResponse, IpcRequest,
    IpcResponse, StreamEndReason,
};
use crate::security::{
    default_run_dir, default_socket_path, deployment_root_digest, validate_capabilities,
    validate_socket_for_client,
};
use crate::trace::{IpcTraceEvent, format_trace_jsonl};
use crate::transport::{
    FrameFlags, IPC_PROTOCOL_VERSION, MAX_REQUEST_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES,
    read_frame, write_frame,
};

/// Client connection configuration pinning deployment identity, contract basis, and principal.
#[derive(Clone, Debug)]
pub struct IpcClientConfig {
    /// Deployment root directory (`<deployment>`).
    pub deployment_root: PathBuf,
    /// Expected deployment identifier pinned in the handshake.
    pub deployment_id: String,
    /// Expected canonical `ContractBasis::basis_digest()` pinned in the handshake.
    pub contract_basis_digest: ContentDigest,
    /// Authenticated local principal identifier.
    pub principal: PrincipalId,
    /// Requested opaque capability identifiers (zero raw secrets).
    pub capabilities: Vec<String>,
    /// Bounded read/write timeout for IPC operations (default `10s`).
    pub io_timeout: Duration,
}

impl IpcClientConfig {
    /// Builds a client configuration directly from a [`ContractBasis`].
    #[must_use]
    pub fn from_contract_basis(
        deployment_root: impl Into<PathBuf>,
        deployment_id: impl Into<String>,
        contract_basis: &ContractBasis,
        principal: PrincipalId,
        capabilities: Vec<String>,
    ) -> Self {
        Self {
            deployment_root: deployment_root.into(),
            deployment_id: deployment_id.into(),
            contract_basis_digest: contract_basis.basis_digest(),
            principal,
            capabilities,
            io_timeout: Duration::from_secs(10),
        }
    }
}

/// Authenticated client connection to a live local FSS supervisor daemon.
pub struct IpcClient {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    handshake: HandshakeAccepted,
    next_request_id: u64,
    traces: Vec<IpcTraceEvent>,
}

impl IpcClient {
    /// Validates local socket security, connects, and completes the pinned mutual handshake.
    pub fn connect(config: IpcClientConfig) -> Result<Self, IpcError> {
        validate_capabilities(&config.capabilities)?;
        let run_dir = default_run_dir(&config.deployment_root);
        let socket_path = default_socket_path(&config.deployment_root);
        validate_socket_for_client(&config.deployment_root, &run_dir, &socket_path)?;

        let started = Instant::now();
        let mut stream = UnixStream::connect(&socket_path).map_err(|err| {
            if matches!(
                err.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) {
                IpcError::daemon_offline(
                    &config.deployment_root,
                    &socket_path,
                    "daemon socket refused connection (stale or stopped daemon)",
                )
            } else {
                IpcError::io("connect_unix_socket", err)
            }
        })?;
        stream
            .set_read_timeout(Some(config.io_timeout))
            .map_err(|err| IpcError::io("set_client_read_timeout", err))?;
        stream
            .set_write_timeout(Some(config.io_timeout))
            .map_err(|err| IpcError::io("set_client_write_timeout", err))?;

        let expected_root_digest = deployment_root_digest(&config.deployment_root);
        let req = HandshakeRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            deployment_id: config.deployment_id.clone(),
            deployment_root_digest: expected_root_digest,
            contract_basis_digest: config.contract_basis_digest,
            principal: config.principal,
            capabilities: config.capabilities,
        };
        req.validate()?;
        let req_bytes = req.try_canonical_bytes()?;
        let sent_bytes = write_frame(
            &mut stream,
            FrameFlags::HANDSHAKE,
            &req_bytes,
            MAX_REQUEST_FRAME_BYTES,
        )?;
        let frame = read_frame(&mut stream, MAX_RESPONSE_FRAME_BYTES)?;
        if !frame.flags.contains(FrameFlags::HANDSHAKE) {
            return Err(IpcError::HandshakeMismatch {
                reason: "daemon handshake reply lacked HANDSHAKE wire flag".to_owned(),
            });
        }
        let accepted = match HandshakeResponse::from_canonical_bytes(&frame.payload)? {
            HandshakeResponse::Accepted(accepted) => accepted,
            HandshakeResponse::Rejected(rejected) => {
                return Err(IpcError::HandshakeRejected {
                    error_id: rejected.error_id,
                    reason: rejected.reason,
                    expected_protocol_version: rejected.expected_protocol_version,
                });
            }
        };
        if accepted.protocol_version != IPC_PROTOCOL_VERSION
            || accepted.deployment_id != config.deployment_id
            || accepted.deployment_root_digest != expected_root_digest
            || accepted.contract_basis_digest != config.contract_basis_digest
        {
            return Err(IpcError::HandshakeMismatch {
                reason: "daemon handshake acceptance disagreed with client pinned deployment or contract basis".to_owned(),
            });
        }

        let traces = vec![IpcTraceEvent {
            req_id: 0,
            op: "handshake".to_owned(),
            frame_bytes: sent_bytes.saturating_add(frame.total_wire_bytes),
            rtt_us: elapsed_us(started),
            outcome: "ok".to_owned(),
            fallback_used: false,
        }];

        let read_stream = stream
            .try_clone()
            .map_err(|err| IpcError::io("clone_client_stream", err))?;
        Ok(Self {
            reader: BufReader::with_capacity(8192, read_stream),
            writer: stream,
            handshake: accepted,
            next_request_id: 1,
            traces,
        })
    }

    /// Returns the mutually verified handshake acceptance record.
    #[must_use]
    pub const fn handshake(&self) -> &HandshakeAccepted {
        &self.handshake
    }

    /// Allocates the next client-local monotonic request identifier.
    pub fn next_request_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        id
    }

    /// Sends a single canonical request frame without awaiting its response.
    pub fn send_request_frame(&mut self, request: &IpcRequest) -> Result<usize, IpcError> {
        let payload = request.try_canonical_bytes()?;
        write_frame(
            &mut self.writer,
            FrameFlags::REQUEST,
            &payload,
            MAX_REQUEST_FRAME_BYTES,
        )
    }

    /// Receives one canonical response frame and returns `(response, total_wire_bytes)`.
    pub fn recv_response_frame(&mut self) -> Result<(IpcResponse, usize), IpcError> {
        let frame = read_frame(&mut self.reader, MAX_RESPONSE_FRAME_BYTES)?;
        if !frame.flags.contains(FrameFlags::RESPONSE) {
            return Err(IpcError::InvalidFrame {
                reason: "daemon frame lacked RESPONSE wire flag".to_owned(),
            });
        }
        let response = IpcResponse::from_canonical_bytes(&frame.payload)?;
        Ok((response, frame.total_wire_bytes))
    }

    /// Sends a unary request, awaits its correlated response, and records an [`IpcTraceEvent`].
    pub fn request(&mut self, request: &IpcRequest) -> Result<IpcResponse, IpcError> {
        let started = Instant::now();
        let req_id = request.request_id();
        let op = request.op_name();
        let sent_bytes = match self.send_request_frame(request) {
            Ok(bytes) => bytes,
            Err(err) => {
                self.record_trace(req_id, op, 0, elapsed_us(started), err.error_id(), false);
                return Err(err);
            }
        };
        match self.recv_response_frame() {
            Ok((response, recv_bytes)) => {
                let outcome = response_outcome_label(&response);
                self.record_trace(
                    req_id,
                    op,
                    sent_bytes.saturating_add(recv_bytes),
                    elapsed_us(started),
                    outcome,
                    false,
                );
                Ok(response)
            }
            Err(err) => {
                self.record_trace(
                    req_id,
                    op,
                    sent_bytes,
                    elapsed_us(started),
                    err.error_id(),
                    false,
                );
                Err(err)
            }
        }
    }

    /// Submits an `EvidenceDeltaBatch` write to the local owning daemon.
    pub fn submit_delta_batch(
        &mut self,
        request_id: u64,
        idempotency_key: ContentDigest,
        batch_bytes: Vec<u8>,
        approval_digest: Option<ContentDigest>,
    ) -> Result<IpcResponse, IpcError> {
        self.request(&IpcRequest::SubmitDeltaBatch {
            request_id,
            idempotency_key,
            batch_bytes,
            approval_digest,
        })
    }

    /// Queries live telemetry from the local daemon.
    pub fn query_live_status(
        &mut self,
        request_id: u64,
        include_cameras: bool,
        include_ring: bool,
    ) -> Result<IpcResponse, IpcError> {
        self.request(&IpcRequest::QueryLiveStatus {
            request_id,
            include_cameras,
            include_ring,
        })
    }

    /// Submits a closed-enum bounded supervisor control operation.
    pub fn submit_bounded_control(
        &mut self,
        request_id: u64,
        op: BoundedControlOp,
        target_camera_id: Option<String>,
        approval_digest: ContentDigest,
    ) -> Result<IpcResponse, IpcError> {
        self.request(&IpcRequest::SubmitBoundedControl {
            request_id,
            op,
            target_camera_id,
            approval_digest,
        })
    }

    /// Sends a cooperative `CancelRequest` for `target_request_id`.
    pub fn cancel_request(&mut self, target_request_id: u64) -> Result<IpcResponse, IpcError> {
        self.request(&IpcRequest::CancelRequest { target_request_id })
    }

    /// Opens a streaming `SubscribeDeltas` iterator over this connection.
    pub fn subscribe_deltas(
        &mut self,
        request_id: u64,
        since_commit_seq: u64,
        max_batch: u32,
    ) -> Result<DeltaSubscription<'_>, IpcError> {
        let started = Instant::now();
        let req = IpcRequest::SubscribeDeltas {
            request_id,
            since_commit_seq,
            max_batch,
        };
        let sent_bytes = self.send_request_frame(&req)?;
        Ok(DeltaSubscription {
            client: self,
            request_id,
            started,
            total_bytes: sent_bytes,
            finished: false,
        })
    }

    /// Returns all structured trace records collected on this client connection.
    #[must_use]
    pub fn trace_events(&self) -> &[IpcTraceEvent] {
        &self.traces
    }

    /// Formats all recorded trace events as newline-delimited JSONL.
    #[must_use]
    pub fn trace_jsonl(&self) -> String {
        format_trace_jsonl(&self.traces)
    }

    fn record_trace(
        &mut self,
        req_id: u64,
        op: &str,
        frame_bytes: usize,
        rtt_us: u64,
        outcome: &str,
        fallback_used: bool,
    ) {
        self.traces.push(IpcTraceEvent {
            req_id,
            op: op.to_owned(),
            frame_bytes,
            rtt_us,
            outcome: outcome.to_owned(),
            fallback_used,
        });
    }
}

/// Item yielded by [`DeltaSubscription`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeltaSubscriptionItem {
    /// One committed delta event frame.
    Event {
        /// Correlated subscription request identifier.
        request_id: u64,
        /// Commit sequence of the delta.
        commit_sequence: u64,
        /// Digest of the committed delta batch.
        delta_digest: ContentDigest,
        /// Canonical summary payload bytes.
        summary_canonical: Vec<u8>,
    },
    /// Terminal end-of-stream marker.
    End {
        /// Correlated subscription request identifier.
        request_id: u64,
        /// Terminal reason closing the stream.
        reason: StreamEndReason,
    },
}

/// Streaming iterator consuming `DeltaEvent` frames until `StreamEnd`.
pub struct DeltaSubscription<'a> {
    client: &'a mut IpcClient,
    request_id: u64,
    started: Instant,
    total_bytes: usize,
    finished: bool,
}

impl Iterator for DeltaSubscription<'_> {
    type Item = Result<DeltaSubscriptionItem, IpcError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match self.client.recv_response_frame() {
            Ok((response, wire_bytes)) => {
                self.total_bytes = self.total_bytes.saturating_add(wire_bytes);
                match response {
                    IpcResponse::DeltaEvent {
                        request_id,
                        commit_sequence,
                        delta_digest,
                        summary_canonical,
                    } => Some(Ok(DeltaSubscriptionItem::Event {
                        request_id,
                        commit_sequence,
                        delta_digest,
                        summary_canonical,
                    })),
                    IpcResponse::StreamEnd { request_id, reason } => {
                        self.finished = true;
                        self.client.record_trace(
                            self.request_id,
                            "subscribe_deltas",
                            self.total_bytes,
                            elapsed_us(self.started),
                            reason.as_str(),
                            false,
                        );
                        Some(Ok(DeltaSubscriptionItem::End { request_id, reason }))
                    }
                    IpcResponse::Refused {
                        request_id,
                        error_id,
                        reason,
                        retryable,
                    } => {
                        self.finished = true;
                        let err = IpcError::Refused {
                            request_id,
                            error_id,
                            reason,
                            retryable,
                        };
                        self.client.record_trace(
                            self.request_id,
                            "subscribe_deltas",
                            self.total_bytes,
                            elapsed_us(self.started),
                            err.error_id(),
                            false,
                        );
                        Some(Err(err))
                    }
                    IpcResponse::Cancelled { request_id } => {
                        self.finished = true;
                        self.client.record_trace(
                            self.request_id,
                            "subscribe_deltas",
                            self.total_bytes,
                            elapsed_us(self.started),
                            "cancelled",
                            false,
                        );
                        Some(Ok(DeltaSubscriptionItem::End {
                            request_id,
                            reason: StreamEndReason::Cancelled,
                        }))
                    }
                    other => {
                        self.finished = true;
                        Some(Err(IpcError::InvalidFrame {
                            reason: format!(
                                "unexpected response variant during SubscribeDeltas stream: req_id={}",
                                other.request_id()
                            ),
                        }))
                    }
                }
            }
            Err(err) => {
                self.finished = true;
                self.client.record_trace(
                    self.request_id,
                    "subscribe_deltas",
                    self.total_bytes,
                    elapsed_us(self.started),
                    err.error_id(),
                    false,
                );
                Some(Err(err))
            }
        }
    }
}

fn response_outcome_label(response: &IpcResponse) -> &str {
    match response {
        IpcResponse::DeltaBatchCommitted { .. }
        | IpcResponse::RetentionForecast { .. }
        | IpcResponse::LiveStatus(_)
        | IpcResponse::DeltaEvent { .. }
        | IpcResponse::ControlAccepted { .. } => "ok",
        IpcResponse::StreamEnd { reason, .. } => reason.as_str(),
        IpcResponse::Cancelled { .. } => "cancelled",
        IpcResponse::Refused { error_id, .. } => error_id.as_str(),
    }
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}
