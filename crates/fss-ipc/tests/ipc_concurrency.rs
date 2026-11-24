#![forbid(unsafe_code)]
//! 16-client concurrency and p99 RTT verification for `fss-ipc`.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use fss_core::{
    CanonicalEncode, ContentDigest, DeltaPriority, MeaningfulDeltaClass, OperationId, PrincipalId,
    reference_contract_basis,
};
use fss_ipc::{
    ActiveScrubStatus, BoundedControlOp, CameraLiveStatus, ControlOperationState, DaemonIpcHandler,
    DeltaEventSummary, DeltaStreamSink, DeltaSubscriptionItem, IpcClient, IpcClientConfig,
    IpcResponse, IpcServer, IpcServerConfig, IpcTraceEvent, LiveDaemonStatus, RequestContext,
    RingWatermarkStatus, StreamEndReason, format_trace_jsonl,
};

type TestResult = Result<(), Box<dyn Error>>;

const CLIENT_COUNT: usize = 16;
const ROUNDS_PER_CLIENT: usize = 20;
const P99_LIMIT_US: u64 = 2_000;

struct BenchHandler {
    commit_seq: AtomicU64,
    history_root: ContentDigest,
    state_root: ContentDigest,
    summary_bytes: Vec<u8>,
}

impl BenchHandler {
    fn new() -> Self {
        let summary = DeltaEventSummary {
            delta_class: MeaningfulDeltaClass::MaterialState,
            priority: DeltaPriority::Normal,
            summary: "steady-state-delta".to_owned(),
        };
        Self {
            commit_seq: AtomicU64::new(1),
            history_root: ContentDigest::sha256(b"bench-history"),
            state_root: ContentDigest::sha256(b"bench-state"),
            summary_bytes: summary.canonical_bytes(),
        }
    }
}

impl DaemonIpcHandler for BenchHandler {
    fn head_commit_sequence(&self) -> u64 {
        self.commit_seq.load(Ordering::Acquire)
    }

    fn submit_delta_batch(
        &self,
        ctx: &RequestContext,
        idempotency_key: ContentDigest,
        _batch_bytes: &[u8],
        _approval_digest: Option<ContentDigest>,
    ) -> IpcResponse {
        let seq = self.commit_seq.fetch_add(1, Ordering::AcqRel) + 1;
        IpcResponse::DeltaBatchCommitted {
            request_id: ctx.request_id,
            commit_sequence: seq,
            history_root: self.history_root,
            state_root: idempotency_key,
        }
    }

    fn query_live_status(
        &self,
        ctx: &RequestContext,
        include_cameras: bool,
        include_ring: bool,
    ) -> IpcResponse {
        let cameras = if include_cameras {
            vec![CameraLiveStatus {
                camera_id: "cam-01".to_owned(),
                running: true,
                fps_milli: 30_000,
                reconnect_count: 0,
                queue_depth: 1,
                frames_ingested: 100_000,
            }]
        } else {
            Vec::new()
        };
        let ring = include_ring.then_some(RingWatermarkStatus {
            used_bytes: 256 * 1024 * 1024,
            capacity_bytes: 1024 * 1024 * 1024,
            watermark_percent: 25,
        });
        IpcResponse::LiveStatus(LiveDaemonStatus {
            request_id: ctx.request_id,
            daemon_uptime_ms: 10_000,
            head_commit_sequence: self.commit_seq.load(Ordering::Acquire),
            history_root: self.history_root,
            state_root: self.state_root,
            active_connections: CLIENT_COUNT as u32,
            cameras,
            ring,
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
        let head = self.commit_seq.load(Ordering::Acquire);
        if since_commit_seq > head {
            return StreamEndReason::CursorStale;
        }
        let end = head.min(since_commit_seq.saturating_add(u64::from(max_batch)));
        for seq in (since_commit_seq + 1)..=end {
            if ctx.is_cancelled() {
                return StreamEndReason::Cancelled;
            }
            if sink
                .emit_delta(seq, self.history_root, self.summary_bytes.clone())
                .is_err()
            {
                return StreamEndReason::Cancelled;
            }
        }
        if end < head {
            StreamEndReason::BatchLimitReached
        } else {
            StreamEndReason::Completed
        }
    }

    fn submit_bounded_control(
        &self,
        ctx: &RequestContext,
        op: BoundedControlOp,
        _target_camera_id: Option<&str>,
        _approval_digest: ContentDigest,
    ) -> IpcResponse {
        match OperationId::parse(format!("op:bench:{}:{}", op.as_str(), ctx.request_id)) {
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

struct TempRoot(PathBuf);

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn sixteen_concurrent_clients_zero_errors_under_2ms_p99() -> TestResult {
    let root_path = std::env::temp_dir().join(format!("fss-ipc-conc-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root_path);
    fs::create_dir_all(&root_path)?;
    let _cleanup = TempRoot(root_path.clone());

    let basis = reference_contract_basis();
    let handler = Arc::new(BenchHandler::new());
    let server = IpcServer::bind(
        IpcServerConfig::new(&root_path, "site:conc16", basis.basis_digest(), "d-conc"),
        handler,
    )?;

    let barrier = Arc::new(Barrier::new(CLIENT_COUNT));
    let mut handles = Vec::with_capacity(CLIENT_COUNT);

    for idx in 0..CLIENT_COUNT {
        let root = root_path.clone();
        let basis_clone = basis.clone();
        let start_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(
            move || -> Result<Vec<IpcTraceEvent>, String> {
                let principal = PrincipalId::parse(format!("principal:client-{idx}"))
                    .map_err(|e| e.to_string())?;
                let mut client = IpcClient::connect(IpcClientConfig::from_contract_basis(
                    root,
                    "site:conc16",
                    &basis_clone,
                    principal,
                    vec![
                        "cap.observe.status".to_owned(),
                        "cap.ledger.append".to_owned(),
                    ],
                ))
                .map_err(|e| e.to_string())?;

                // Warm one round before synchronized timed burst to avoid cold OS thread scheduling skew.
                let warm_id = client.next_request_id();
                let _ = client
                    .query_live_status(warm_id, true, true)
                    .map_err(|e| e.to_string())?;

                start_barrier.wait();

                let mut cursor = 1_u64;
                for round in 0..ROUNDS_PER_CLIENT {
                    let status_req = client.next_request_id();
                    match client
                        .query_live_status(status_req, true, true)
                        .map_err(|e| e.to_string())?
                    {
                        IpcResponse::LiveStatus(st) if st.request_id == status_req => {}
                        other => return Err(format!("unexpected status response: {other:?}")),
                    }

                    let batch_req = client.next_request_id();
                    let key = ContentDigest::sha256(format!("c{idx}-r{round}").as_bytes());
                    match client
                        .submit_delta_batch(
                            batch_req,
                            key,
                            vec![idx as u8, round as u8, 0xAA, 0x55],
                            None,
                        )
                        .map_err(|e| e.to_string())?
                    {
                        IpcResponse::DeltaBatchCommitted {
                            request_id,
                            commit_sequence,
                            ..
                        } if request_id == batch_req && commit_sequence > 1 => {}
                        other => return Err(format!("unexpected batch response: {other:?}")),
                    }

                    let sub_req = client.next_request_id();
                    let mut saw_end = false;
                    let mut sub = client
                        .subscribe_deltas(sub_req, cursor, 4)
                        .map_err(|e| e.to_string())?;
                    for item in &mut sub {
                        match item.map_err(|e| e.to_string())? {
                            DeltaSubscriptionItem::Event {
                                request_id,
                                commit_sequence,
                                ..
                            } if request_id == sub_req => {
                                cursor = cursor.max(commit_sequence);
                            }
                            DeltaSubscriptionItem::End { request_id, reason }
                                if request_id == sub_req
                                    && matches!(
                                        reason,
                                        StreamEndReason::Completed
                                            | StreamEndReason::BatchLimitReached
                                    ) =>
                            {
                                saw_end = true;
                            }
                            other => return Err(format!("unexpected stream item: {other:?}")),
                        }
                    }
                    if !saw_end {
                        return Err("subscribe_deltas closed without StreamEnd".to_owned());
                    }
                }
                Ok(client.trace_events().to_vec())
            },
        ));
    }

    let mut all_traces = Vec::new();
    let mut op_rtts_us = Vec::new();
    for handle in handles {
        let client_traces = handle
            .join()
            .map_err(|_| "client worker thread panicked")??;
        // Skip handshake + warmup (first 2 events) when computing steady-state concurrent RTTs.
        for event in client_traces.iter().skip(2) {
            op_rtts_us.push(event.rtt_us);
        }
        all_traces.extend(client_traces);
    }

    assert_eq!(op_rtts_us.len(), CLIENT_COUNT * ROUNDS_PER_CLIENT * 3);
    op_rtts_us.sort_unstable();
    let p50_us = percentile(&op_rtts_us, 50);
    let p95_us = percentile(&op_rtts_us, 95);
    let p99_us = percentile(&op_rtts_us, 99);
    let max_us = op_rtts_us.last().copied().unwrap_or(0);

    // Verify JSONL trace formatting produces valid one-line-per-event output.
    let sample_jsonl = format_trace_jsonl(&all_traces[..all_traces.len().min(6)]);
    assert_eq!(sample_jsonl.lines().count(), all_traces.len().min(6));
    for line in sample_jsonl.lines() {
        assert!(line.starts_with("{\"req_id\":"));
        assert!(line.ends_with('}'));
        assert!(line.contains("\"fallback_used\":false"));
    }

    println!(
        "{{\"event\":\"ipc_concurrency_summary\",\"clients\":{CLIENT_COUNT},\"ops\":{},\"errors\":0,\"p50_us\":{p50_us},\"p95_us\":{p95_us},\"p99_us\":{p99_us},\"max_us\":{max_us}}}",
        op_rtts_us.len()
    );
    println!("{sample_jsonl}");

    assert!(
        p99_us < P99_LIMIT_US,
        "p99 RTT {p99_us} us exceeded {P99_LIMIT_US} us ceiling (p50={p50_us} us, p95={p95_us} us, max={max_us} us)"
    );

    let sock_path = server.socket_path().to_path_buf();
    server.shutdown()?;
    assert!(fs::symlink_metadata(&sock_path).is_err());
    Ok(())
}

fn percentile(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) * pct) / 100;
    sorted[idx]
}
