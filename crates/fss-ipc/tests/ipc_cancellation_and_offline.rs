#![forbid(unsafe_code)]
//! Cooperative cancellation, peer-disconnect cancellation, and offline fallback tests for `fss-ipc`.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use fss_core::{
    CanonicalEncode, ContentDigest, ContractBasis, DeltaPriority, MeaningfulDeltaClass,
    OperationId, PrincipalId, reference_contract_basis,
};
use fss_ipc::{
    ActiveScrubStatus, BoundedControlOp, CancelReason, ControlOperationState, DaemonIpcHandler,
    DeltaEventSummary, DeltaStreamSink, DeltaSubscriptionItem, DeploymentChannel, DeploymentClient,
    ERR_DAEMON_OFFLINE_001, IpcClient, IpcClientConfig, IpcError, IpcRequest, IpcResponse,
    IpcServer, IpcServerConfig, LiveDaemonStatus, RequestContext, StreamEndReason,
};

type TestResult = Result<(), Box<dyn Error>>;
static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempDeployment {
    root: PathBuf,
}

impl TempDeployment {
    fn new(tag: &str) -> Result<Self, Box<dyn Error>> {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("fss-ipc-c-{}-{tag}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for TempDeployment {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct BlockingHandler {
    head_seq: AtomicU64,
    block_on_delta: AtomicBool,
    block_on_control: AtomicBool,
    cancel_tx: Mutex<Option<mpsc::Sender<Option<CancelReason>>>>,
    started_tx: Mutex<Option<mpsc::Sender<u64>>>,
}

impl BlockingHandler {
    fn new() -> Self {
        Self {
            head_seq: AtomicU64::new(10),
            block_on_delta: AtomicBool::new(false),
            block_on_control: AtomicBool::new(false),
            cancel_tx: Mutex::new(None),
            started_tx: Mutex::new(None),
        }
    }

    fn wait_for_cancel(&self, ctx: &RequestContext) -> Option<CancelReason> {
        if let Ok(guard) = self.started_tx.lock()
            && let Some(tx) = guard.as_ref()
        {
            let _ = tx.send(ctx.request_id);
        }
        for _ in 0..200 {
            if ctx.is_cancelled() && ctx.cancel.asupersync_cx().is_cancelled() {
                let reason = ctx.cancel.reason();
                if let Ok(guard) = self.cancel_tx.lock()
                    && let Some(tx) = guard.as_ref()
                {
                    let _ = tx.send(reason);
                }
                return reason;
            }
            thread::sleep(Duration::from_millis(5));
        }
        None
    }
}

impl DaemonIpcHandler for BlockingHandler {
    fn head_commit_sequence(&self) -> u64 {
        self.head_seq.load(Ordering::Acquire)
    }

    fn submit_delta_batch(
        &self,
        ctx: &RequestContext,
        idempotency_key: ContentDigest,
        batch_bytes: &[u8],
        _approval_digest: Option<ContentDigest>,
    ) -> IpcResponse {
        if self.block_on_delta.load(Ordering::Acquire) {
            let _ = self.wait_for_cancel(ctx);
            return IpcResponse::Cancelled {
                request_id: ctx.request_id,
            };
        }
        let seq = self.head_seq.fetch_add(1, Ordering::AcqRel) + 1;
        IpcResponse::DeltaBatchCommitted {
            request_id: ctx.request_id,
            commit_sequence: seq,
            history_root: ContentDigest::sha256(batch_bytes),
            state_root: idempotency_key,
        }
    }

    fn query_live_status(
        &self,
        ctx: &RequestContext,
        _include_cameras: bool,
        _include_ring: bool,
    ) -> IpcResponse {
        IpcResponse::LiveStatus(LiveDaemonStatus {
            request_id: ctx.request_id,
            daemon_uptime_ms: 1000,
            head_commit_sequence: self.head_seq.load(Ordering::Acquire),
            history_root: ContentDigest::sha256(b"h"),
            state_root: ContentDigest::sha256(b"s"),
            active_connections: 1,
            cameras: Vec::new(),
            ring: None,
            scrub: ActiveScrubStatus::Idle,
        })
    }

    fn subscribe_deltas(
        &self,
        ctx: &RequestContext,
        since_commit_seq: u64,
        max_batch: u32,
        sink: &mut DeltaStreamSink<'_>,
    ) -> StreamEndReason {
        let head = self.head_seq.load(Ordering::Acquire);
        for seq in (since_commit_seq + 1)..=head {
            if ctx.is_cancelled() {
                return StreamEndReason::Cancelled;
            }
            if sink.emitted() >= max_batch {
                return StreamEndReason::BatchLimitReached;
            }
            let summary = DeltaEventSummary {
                delta_class: MeaningfulDeltaClass::MaterialState,
                priority: DeltaPriority::Normal,
                summary: format!("commit-{seq}"),
            };
            if sink
                .emit_delta(
                    seq,
                    ContentDigest::sha256(&seq.to_be_bytes()),
                    summary.canonical_bytes(),
                )
                .is_err()
            {
                return StreamEndReason::Cancelled;
            }
        }
        StreamEndReason::Completed
    }

    fn submit_bounded_control(
        &self,
        ctx: &RequestContext,
        op: BoundedControlOp,
        _target_camera_id: Option<&str>,
        _approval_digest: ContentDigest,
    ) -> IpcResponse {
        if self.block_on_control.load(Ordering::Acquire) {
            let _ = self.wait_for_cancel(ctx);
            return IpcResponse::Cancelled {
                request_id: ctx.request_id,
            };
        }
        match OperationId::parse(format!("op:{}:{}", op.as_str(), ctx.request_id)) {
            Ok(operation_id) => IpcResponse::ControlAccepted {
                request_id: ctx.request_id,
                operation_id,
                state: ControlOperationState::Accepted,
            },
            Err(_) => IpcResponse::Cancelled {
                request_id: ctx.request_id,
            },
        }
    }
}

fn test_basis() -> ContractBasis {
    reference_contract_basis()
}

fn test_principal() -> Result<PrincipalId, Box<dyn Error>> {
    Ok(PrincipalId::parse("principal:local-operator")?)
}

#[test]
fn mid_request_client_disconnect_triggers_cooperative_cancellation() -> TestResult {
    let tmp = TempDeployment::new("disc")?;
    let basis = test_basis();
    let handler = Arc::new(BlockingHandler::new());
    handler.block_on_delta.store(true, Ordering::Release);
    let (started_tx, started_rx) = mpsc::channel();
    let (cancel_tx, cancel_rx) = mpsc::channel();
    if let Ok(mut guard) = handler.started_tx.lock() {
        *guard = Some(started_tx);
    }
    if let Ok(mut guard) = handler.cancel_tx.lock() {
        *guard = Some(cancel_tx);
    }

    let server = IpcServer::bind(
        IpcServerConfig::new(tmp.path(), "site:disc", basis.basis_digest(), "d1"),
        Arc::clone(&handler) as Arc<dyn DaemonIpcHandler>,
    )?;
    let mut client = IpcClient::connect(IpcClientConfig::from_contract_basis(
        tmp.path(),
        "site:disc",
        &basis,
        test_principal()?,
        vec!["cap.ledger.append".to_owned()],
    ))?;
    let _ = client.send_request_frame(&IpcRequest::SubmitDeltaBatch {
        request_id: 77,
        idempotency_key: ContentDigest::sha256(b"k77"),
        batch_bytes: b"payload".to_vec(),
        approval_digest: None,
    })?;

    assert_eq!(started_rx.recv_timeout(Duration::from_secs(2))?, 77);
    drop(client);
    assert_eq!(
        cancel_rx.recv_timeout(Duration::from_secs(2))?,
        Some(CancelReason::PeerDisconnected)
    );
    server.shutdown()?;
    Ok(())
}

#[test]
fn cancel_request_works_cross_connection_and_pipelined_same_connection() -> TestResult {
    let tmp = TempDeployment::new("cancel")?;
    let basis = test_basis();
    let handler = Arc::new(BlockingHandler::new());
    handler.block_on_control.store(true, Ordering::Release);
    let (started_tx, started_rx) = mpsc::channel();
    let (cancel_tx, cancel_rx) = mpsc::channel();
    if let Ok(mut guard) = handler.started_tx.lock() {
        *guard = Some(started_tx);
    }
    if let Ok(mut guard) = handler.cancel_tx.lock() {
        *guard = Some(cancel_tx);
    }

    let server = IpcServer::bind(
        IpcServerConfig::new(tmp.path(), "site:cancel", basis.basis_digest(), "d1"),
        Arc::clone(&handler) as Arc<dyn DaemonIpcHandler>,
    )?;
    let mut client1 = IpcClient::connect(IpcClientConfig::from_contract_basis(
        tmp.path(),
        "site:cancel",
        &basis,
        test_principal()?,
        vec!["cap.device.control".to_owned()],
    ))?;
    let mut client2 = IpcClient::connect(IpcClientConfig::from_contract_basis(
        tmp.path(),
        "site:cancel",
        &basis,
        test_principal()?,
        vec!["cap.device.control".to_owned()],
    ))?;

    // Cross-connection CancelRequest.
    let _ = client1.send_request_frame(&IpcRequest::SubmitBoundedControl {
        request_id: 909,
        op: BoundedControlOp::TriggerScrub,
        target_camera_id: None,
        approval_digest: ContentDigest::sha256(b"approve-909"),
    })?;
    assert_eq!(started_rx.recv_timeout(Duration::from_secs(2))?, 909);
    assert_eq!(
        client2.cancel_request(909)?,
        IpcResponse::Cancelled { request_id: 909 }
    );
    assert_eq!(
        cancel_rx.recv_timeout(Duration::from_secs(2))?,
        Some(CancelReason::ClientCancelRequest)
    );
    let (client1_reply, _) = client1.recv_response_frame()?;
    assert_eq!(client1_reply, IpcResponse::Cancelled { request_id: 909 });

    // Same-connection pipelined CancelRequest.
    let _ = client1.send_request_frame(&IpcRequest::SubmitBoundedControl {
        request_id: 910,
        op: BoundedControlOp::ProbeDetect,
        target_camera_id: None,
        approval_digest: ContentDigest::sha256(b"approve-910"),
    })?;
    assert_eq!(started_rx.recv_timeout(Duration::from_secs(2))?, 910);
    let _ = client1.send_request_frame(&IpcRequest::CancelRequest {
        target_request_id: 910,
    })?;
    assert_eq!(
        cancel_rx.recv_timeout(Duration::from_secs(2))?,
        Some(CancelReason::ClientCancelRequest)
    );
    let (resp_a, _) = client1.recv_response_frame()?;
    let (resp_b, _) = client1.recv_response_frame()?;
    assert_eq!(resp_a, IpcResponse::Cancelled { request_id: 910 });
    assert_eq!(resp_b, IpcResponse::Cancelled { request_id: 910 });

    server.shutdown()?;
    Ok(())
}

#[test]
fn offline_direct_fallback_and_daemon_offline_refusal_guidance() -> TestResult {
    let tmp = TempDeployment::new("offline")?;
    let basis = test_basis();

    let mut channel =
        DeploymentClient::connect_or_direct(tmp.path(), "site:offline", &basis, test_principal()?)?;
    match &channel {
        DeploymentChannel::OfflineDirect {
            root,
            fallback_reason,
        } => {
            assert_eq!(root, tmp.path());
            assert!(!fallback_reason.is_empty());
        }
        DeploymentChannel::LiveDaemon(_) => {
            return Err("expected OfflineDirect when no daemon is running".into());
        }
    }

    let expected_guidance = format!(
        "Start the local supervisor with: fss site run --root {}",
        tmp.path().display()
    );
    match channel.submit_bounded_control(
        1,
        BoundedControlOp::ReloadManifest,
        None,
        ContentDigest::sha256(b"approval"),
    ) {
        Err(ref offline_err @ IpcError::DaemonOffline { ref guidance, .. }) => {
            assert_eq!(offline_err.error_id(), ERR_DAEMON_OFFLINE_001);
            assert_eq!(guidance, &expected_guidance);
            assert!(offline_err.to_string().contains(&expected_guidance));
        }
        other => return Err(format!("expected DaemonOffline error, got {other:?}").into()),
    }

    let refusal = DeploymentChannel::offline_refusal_response(1, tmp.path(), "socket missing")?;
    match refusal {
        IpcResponse::Refused {
            request_id,
            error_id,
            reason,
            retryable,
        } => {
            assert_eq!(request_id, 1);
            assert_eq!(error_id.as_str(), ERR_DAEMON_OFFLINE_001);
            assert!(retryable);
            assert!(reason.contains(&expected_guidance));
        }
        other => return Err(format!("expected Refused response, got {other:?}").into()),
    }

    let trace = DeploymentChannel::offline_trace_event(1, "submit_bounded_control").to_jsonl_line();
    assert!(trace.contains("\"fallback_used\":true"));
    assert!(trace.contains(ERR_DAEMON_OFFLINE_001));

    let server = IpcServer::bind(
        IpcServerConfig::new(tmp.path(), "site:offline", basis.basis_digest(), "d-live"),
        Arc::new(BlockingHandler::new()),
    )?;
    let live_channel =
        DeploymentClient::connect_or_direct(tmp.path(), "site:offline", &basis, test_principal()?)?;
    assert!(live_channel.is_live());
    if let DeploymentChannel::LiveDaemon(mut client) = live_channel {
        let mut sub = client.subscribe_deltas(55, 8, 10)?;
        let mut events = Vec::new();
        let mut ended = None;
        for item in &mut sub {
            match item? {
                DeltaSubscriptionItem::Event {
                    commit_sequence, ..
                } => events.push(commit_sequence),
                DeltaSubscriptionItem::End { reason, .. } => ended = Some(reason),
            }
        }
        assert_eq!(events, vec![9, 10]);
        assert_eq!(ended, Some(StreamEndReason::Completed));
    }
    server.shutdown()?;
    Ok(())
}
