#![forbid(unsafe_code)]
//! Per-connection handshake, buffered reader loop, and bounded request executor for `IpcServer`.

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use fss_core::{CanonicalDecode, CanonicalEncode, PrincipalId};

use crate::cancel::{CancelReason, ConnectionCancelSlot, RequestCancelToken};
use crate::error::{
    ERR_IPC_CANCELLED_001, ERR_IPC_CAPABILITY_DENIED_001, ERR_IPC_CONNECTION_LIMIT_001,
    ERR_IPC_FRAME_TOO_LARGE_001, ERR_IPC_HANDSHAKE_MISMATCH_001, ERR_IPC_SERVER_SHUTDOWN_001,
    ERR_IPC_WIRE_CORRUPT_001, IpcError, parse_error_id,
};
use crate::protocol::{
    HandshakeAccepted, HandshakeRejected, HandshakeRequest, HandshakeResponse, IpcRequest,
    IpcResponse, StreamEndReason,
};
use crate::security::validate_capabilities;
use crate::server::{DeltaStreamSink, RequestContext, SharedServerState};
use crate::transport::{
    FrameFlags, IPC_PROTOCOL_VERSION, MAX_REQUEST_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES, PollFrame,
    poll_read_frame, read_frame, write_frame,
};

const READER_POLL_INTERVAL: Duration = Duration::from_millis(25);
const PER_CONNECTION_QUEUE_DEPTH: usize = 8;
const CONNECTION_READ_BUF_BYTES: usize = 8192;

struct DispatchedWork {
    request: IpcRequest,
    token: RequestCancelToken,
}

#[derive(Clone)]
struct AuthenticatedSession {
    principal: PrincipalId,
    granted_capabilities: Vec<String>,
}

pub(crate) fn reject_connection_limit(mut stream: UnixStream, limit: usize) {
    let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
    if let Ok(error_id) = parse_error_id(ERR_IPC_CONNECTION_LIMIT_001) {
        let rejected = HandshakeResponse::Rejected(HandshakeRejected {
            error_id,
            reason: format!("daemon reached bounded max_connections={limit}"),
            expected_protocol_version: IPC_PROTOCOL_VERSION,
        });
        if let Ok(payload) = rejected.try_canonical_bytes() {
            let _ = write_frame(
                &mut stream,
                FrameFlags::HANDSHAKE,
                &payload,
                MAX_RESPONSE_FRAME_BYTES,
            );
        }
    }
}

pub(crate) fn handle_connection(
    conn_id: u64,
    mut stream: UnixStream,
    shared: &Arc<SharedServerState>,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(shared.config.handshake_timeout));
    let _ = stream.set_write_timeout(Some(shared.config.io_timeout));

    let Some(session) = perform_server_handshake(&mut stream, shared) else {
        return;
    };

    let Ok(write_stream) = stream.try_clone() else {
        return;
    };
    let cancel_slot = shared
        .cancel_registry
        .register_connection(conn_id, session.principal.clone());
    let writer = Arc::new(Mutex::new(write_stream));
    let (tx, rx) = mpsc::sync_channel::<DispatchedWork>(PER_CONNECTION_QUEUE_DEPTH);
    let in_flight = Arc::new(AtomicUsize::new(0));

    let _ = stream.set_read_timeout(Some(READER_POLL_INTERVAL));
    let mut reader = BufReader::with_capacity(CONNECTION_READ_BUF_BYTES, stream);
    let mut last_activity = Instant::now();

    std::thread::scope(|scope| {
        let exec_shared = Arc::clone(shared);
        let exec_writer = Arc::clone(&writer);
        let exec_in_flight = Arc::clone(&in_flight);
        let exec_slot = Arc::clone(&cancel_slot);
        let exec_session = session.clone();
        let _executor = scope.spawn(move || {
            run_connection_executor(
                conn_id,
                rx,
                exec_session,
                exec_slot,
                exec_writer,
                exec_in_flight,
                &exec_shared,
            );
        });

        loop {
            if shared.shutdown.load(Ordering::Acquire) {
                cancel_slot.cancel_all(CancelReason::ServerShutdown);
                break;
            }
            match poll_read_frame(&mut reader, MAX_REQUEST_FRAME_BYTES) {
                Ok(PollFrame::IdleTimeout) => {
                    if in_flight.load(Ordering::Acquire) == 0
                        && last_activity.elapsed() >= shared.config.idle_timeout
                    {
                        break;
                    }
                }
                Ok(PollFrame::Closed) => {
                    cancel_slot.cancel_all(CancelReason::PeerDisconnected);
                    break;
                }
                Ok(PollFrame::Frame(frame)) => {
                    last_activity = Instant::now();
                    if !dispatch_frame(
                        frame.flags,
                        &frame.payload,
                        &session,
                        &cancel_slot,
                        &writer,
                        &tx,
                        &in_flight,
                        shared,
                    ) {
                        break;
                    }
                }
                Err(IpcError::FrameTooLarge { actual, limit }) => {
                    send_refused(
                        &writer,
                        0,
                        ERR_IPC_FRAME_TOO_LARGE_001,
                        &format!("request frame {actual} bytes exceeds hard limit {limit} bytes"),
                        false,
                    );
                    cancel_slot.cancel_all(CancelReason::PeerDisconnected);
                    break;
                }
                Err(_) => {
                    cancel_slot.cancel_all(CancelReason::PeerDisconnected);
                    break;
                }
            }
        }

        drop(tx);
    });

    cancel_slot.cancel_all(CancelReason::PeerDisconnected);
    shared.cancel_registry.remove_connection(conn_id);
}

#[allow(clippy::too_many_arguments)]
fn dispatch_frame(
    flags: FrameFlags,
    payload: &[u8],
    session: &AuthenticatedSession,
    cancel_slot: &ConnectionCancelSlot,
    writer: &Arc<Mutex<UnixStream>>,
    tx: &mpsc::SyncSender<DispatchedWork>,
    in_flight: &AtomicUsize,
    shared: &SharedServerState,
) -> bool {
    if !flags.contains(FrameFlags::REQUEST) {
        send_refused(
            writer,
            0,
            ERR_IPC_WIRE_CORRUPT_001,
            "expected REQUEST wire frame flag after handshake",
            false,
        );
        cancel_slot.cancel_all(CancelReason::PeerDisconnected);
        return false;
    }
    let request = match IpcRequest::from_canonical_bytes(payload) {
        Ok(req) => req,
        Err(err) => {
            send_refused(
                writer,
                0,
                ERR_IPC_WIRE_CORRUPT_001,
                &format!("malformed canonical request: {err}"),
                false,
            );
            cancel_slot.cancel_all(CancelReason::PeerDisconnected);
            return false;
        }
    };
    match request {
        IpcRequest::CancelRequest { target_request_id } => {
            let _ = cancel_slot
                .cancel_request(target_request_id, CancelReason::ClientCancelRequest)
                || shared.cancel_registry.cancel_for_principal(
                    &session.principal,
                    target_request_id,
                    CancelReason::ClientCancelRequest,
                );
            let resp = IpcResponse::Cancelled {
                request_id: target_request_id,
            };
            send_response(writer, FrameFlags::RESPONSE, &resp).is_ok()
        }
        other => {
            let req_id = other.request_id();
            let token = RequestCancelToken::new();
            cancel_slot.register(req_id, token.clone());
            in_flight.fetch_add(1, Ordering::AcqRel);
            if tx
                .try_send(DispatchedWork {
                    request: other,
                    token,
                })
                .is_err()
            {
                in_flight.fetch_sub(1, Ordering::AcqRel);
                cancel_slot.remove(req_id);
                send_refused(
                    writer,
                    req_id,
                    ERR_IPC_CONNECTION_LIMIT_001,
                    "per-connection request queue is full; retry after in-flight work completes",
                    true,
                );
            }
            true
        }
    }
}

fn perform_server_handshake(
    stream: &mut UnixStream,
    shared: &SharedServerState,
) -> Option<AuthenticatedSession> {
    let frame = match read_frame(stream, MAX_REQUEST_FRAME_BYTES) {
        Ok(frame) => frame,
        Err(IpcError::ConnectionClosed) => return None,
        Err(err) => {
            send_handshake_rejection(stream, err.error_id(), &err.to_string());
            return None;
        }
    };
    if !frame.flags.contains(FrameFlags::HANDSHAKE) {
        send_handshake_rejection(
            stream,
            ERR_IPC_HANDSHAKE_MISMATCH_001,
            "first frame on IPC connection must carry HANDSHAKE flag",
        );
        return None;
    }
    let req = match HandshakeRequest::from_canonical_bytes(&frame.payload) {
        Ok(req) => req,
        Err(err) => {
            send_handshake_rejection(
                stream,
                ERR_IPC_WIRE_CORRUPT_001,
                &format!("invalid canonical handshake payload: {err}"),
            );
            return None;
        }
    };
    if let Err(err) = req.validate() {
        send_handshake_rejection(stream, err.error_id(), &err.to_string());
        return None;
    }
    if req.protocol_version != IPC_PROTOCOL_VERSION {
        send_handshake_rejection(
            stream,
            ERR_IPC_HANDSHAKE_MISMATCH_001,
            &format!(
                "protocol version {} does not match server version {}",
                req.protocol_version, IPC_PROTOCOL_VERSION
            ),
        );
        return None;
    }
    if req.deployment_id != shared.config.deployment_id
        || req.deployment_root_digest != shared.deployment_root_digest
    {
        send_handshake_rejection(
            stream,
            ERR_IPC_HANDSHAKE_MISMATCH_001,
            "deployment_id or deployment_root_digest does not match local daemon",
        );
        return None;
    }
    if req.contract_basis_digest != shared.config.contract_basis_digest {
        send_handshake_rejection(
            stream,
            ERR_IPC_HANDSHAKE_MISMATCH_001,
            "contract_basis_digest does not match local daemon",
        );
        return None;
    }
    if shared.shutdown.load(Ordering::Acquire) {
        send_handshake_rejection(
            stream,
            ERR_IPC_SERVER_SHUTDOWN_001,
            "daemon is shutting down",
        );
        return None;
    }

    let granted_capabilities = match shared.handler.authorize_handshake(&req) {
        Ok(caps) => {
            if let Err(err) = validate_capabilities(&caps) {
                send_handshake_rejection(stream, ERR_IPC_CAPABILITY_DENIED_001, &err.to_string());
                return None;
            }
            caps
        }
        Err((error_id, reason)) => {
            send_handshake_rejection(stream, error_id.as_str(), &reason);
            return None;
        }
    };

    let accepted = HandshakeResponse::Accepted(HandshakeAccepted {
        protocol_version: IPC_PROTOCOL_VERSION,
        deployment_id: shared.config.deployment_id.clone(),
        deployment_root_digest: shared.deployment_root_digest,
        contract_basis_digest: shared.config.contract_basis_digest,
        daemon_instance_id: shared.config.daemon_instance_id.clone(),
        granted_capabilities: granted_capabilities.clone(),
        head_commit_sequence: shared.handler.head_commit_sequence(),
    });
    let Ok(payload) = accepted.try_canonical_bytes() else {
        return None;
    };
    if write_frame(
        stream,
        FrameFlags::HANDSHAKE,
        &payload,
        MAX_RESPONSE_FRAME_BYTES,
    )
    .is_err()
    {
        return None;
    }
    Some(AuthenticatedSession {
        principal: req.principal,
        granted_capabilities,
    })
}

fn send_handshake_rejection(stream: &mut UnixStream, error_id_str: &str, reason: &str) {
    let error_id = match parse_error_id(error_id_str)
        .or_else(|_| parse_error_id(ERR_IPC_HANDSHAKE_MISMATCH_001))
    {
        Ok(id) => id,
        Err(_) => return,
    };
    let rejected = HandshakeResponse::Rejected(HandshakeRejected {
        error_id,
        reason: reason.to_owned(),
        expected_protocol_version: IPC_PROTOCOL_VERSION,
    });
    if let Ok(payload) = rejected.try_canonical_bytes() {
        let _ = write_frame(
            stream,
            FrameFlags::HANDSHAKE,
            &payload,
            MAX_RESPONSE_FRAME_BYTES,
        );
    }
}

fn run_connection_executor(
    conn_id: u64,
    rx: mpsc::Receiver<DispatchedWork>,
    session: AuthenticatedSession,
    cancel_slot: Arc<ConnectionCancelSlot>,
    writer: Arc<Mutex<UnixStream>>,
    in_flight: Arc<AtomicUsize>,
    shared: &SharedServerState,
) {
    for work in rx {
        let req_id = work.request.request_id();
        let ctx = RequestContext {
            connection_id: conn_id,
            request_id: req_id,
            deployment_id: shared.config.deployment_id.clone(),
            contract_basis_digest: shared.config.contract_basis_digest,
            principal: session.principal.clone(),
            granted_capabilities: session.granted_capabilities.clone(),
            cancel: work.token.clone(),
        };

        let write_result = execute_one(&ctx, work.request, &writer, shared);
        cancel_slot.remove(req_id);
        in_flight.fetch_sub(1, Ordering::AcqRel);
        if write_result.is_err() {
            cancel_slot.cancel_all(CancelReason::PeerDisconnected);
            break;
        }
    }
}

fn execute_one(
    ctx: &RequestContext,
    request: IpcRequest,
    writer: &Mutex<UnixStream>,
    shared: &SharedServerState,
) -> Result<(), IpcError> {
    let req_id = ctx.request_id;
    if ctx.is_cancelled() {
        return match request {
            IpcRequest::SubscribeDeltas { .. } => send_response(
                writer,
                FrameFlags::RESPONSE.union(FrameFlags::STREAM),
                &IpcResponse::StreamEnd {
                    request_id: req_id,
                    reason: StreamEndReason::Cancelled,
                },
            ),
            _ => send_response(
                writer,
                FrameFlags::RESPONSE,
                &IpcResponse::Cancelled { request_id: req_id },
            ),
        };
    }

    match request {
        IpcRequest::SubmitDeltaBatch {
            idempotency_key,
            batch_bytes,
            approval_digest,
            ..
        } => {
            let resp = shared.handler.submit_delta_batch(
                ctx,
                idempotency_key,
                &batch_bytes,
                approval_digest,
            );
            send_response(writer, FrameFlags::RESPONSE, &resp)
        }
        IpcRequest::QueryRetentionForecast { camera_id, .. } => {
            let resp = shared.handler.query_retention_forecast(ctx, &camera_id);
            send_response(writer, FrameFlags::RESPONSE, &resp)
        }
        IpcRequest::QueryLiveStatus {
            include_cameras,
            include_ring,
            ..
        } => {
            let resp = shared
                .handler
                .query_live_status(ctx, include_cameras, include_ring);
            send_response(writer, FrameFlags::RESPONSE, &resp)
        }
        IpcRequest::SubscribeDeltas {
            since_commit_seq,
            max_batch,
            ..
        } => {
            let mut sink = DeltaStreamSink::new(req_id, writer, &ctx.cancel, max_batch);
            let reason =
                shared
                    .handler
                    .subscribe_deltas(ctx, since_commit_seq, max_batch, &mut sink);
            let final_reason = if ctx.is_cancelled() {
                StreamEndReason::Cancelled
            } else {
                reason
            };
            send_response(
                writer,
                FrameFlags::RESPONSE.union(FrameFlags::STREAM),
                &IpcResponse::StreamEnd {
                    request_id: req_id,
                    reason: final_reason,
                },
            )
        }
        IpcRequest::SubmitBoundedControl {
            op,
            target_camera_id,
            approval_digest,
            ..
        } => {
            let resp = if op.requires_camera_id() && target_camera_id.is_none() {
                make_refused(
                    req_id,
                    ERR_IPC_WIRE_CORRUPT_001,
                    &format!(
                        "bounded control op {} requires target_camera_id",
                        op.as_str()
                    ),
                    false,
                )
            } else {
                shared.handler.submit_bounded_control(
                    ctx,
                    op,
                    target_camera_id.as_deref(),
                    approval_digest,
                )
            };
            send_response(writer, FrameFlags::RESPONSE, &resp)
        }
        IpcRequest::CancelRequest { target_request_id } => send_response(
            writer,
            FrameFlags::RESPONSE,
            &IpcResponse::Cancelled {
                request_id: target_request_id,
            },
        ),
    }
}

fn send_response(
    writer: &Mutex<UnixStream>,
    flags: FrameFlags,
    response: &IpcResponse,
) -> Result<(), IpcError> {
    let payload = response.try_canonical_bytes()?;
    let mut guard = writer.lock().map_err(|_| IpcError::ConnectionClosed)?;
    let _ = write_frame(&mut *guard, flags, &payload, MAX_RESPONSE_FRAME_BYTES)?;
    Ok(())
}

fn send_refused(
    writer: &Mutex<UnixStream>,
    request_id: u64,
    error_id_str: &str,
    reason: &str,
    retryable: bool,
) {
    let resp = make_refused(request_id, error_id_str, reason, retryable);
    let _ = send_response(writer, FrameFlags::RESPONSE, &resp);
}

pub(crate) fn make_refused(
    request_id: u64,
    error_id_str: &str,
    reason: &str,
    retryable: bool,
) -> IpcResponse {
    match parse_error_id(error_id_str).or_else(|_| parse_error_id(ERR_IPC_CANCELLED_001)) {
        Ok(error_id) => IpcResponse::Refused {
            request_id,
            error_id,
            reason: reason.to_owned(),
            retryable,
        },
        Err(_) => IpcResponse::Cancelled { request_id },
    }
}
