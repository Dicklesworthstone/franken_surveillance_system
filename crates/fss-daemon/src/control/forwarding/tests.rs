#![forbid(unsafe_code)]
//! Forwarding must never turn a retry, cancellation, or lost receipt into another write.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::Duration;

use fss_core::PrincipalId;
use fss_core::contract_basis::reference_contract_basis;
use fss_ipc::{
    ActiveScrubStatus, CancelReason, DaemonIpcHandler, IpcError, RequestCancelToken,
    RingWatermarkStatus, parse_error_id,
};

use super::super::{ControlStatusSnapshot, DaemonIpcHandlerAdapter, ForwardBatchWriter};
use super::*;
use crate::error::DaemonError;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn handler(writer: Arc<dyn ForwardBatchWriter>) -> DaemonIpcHandlerAdapter {
    DaemonIpcHandlerAdapter {
        shared: ControlPlaneShared::new(
            "site-forward",
            ContentDigest::sha256(b"deployment-root"),
            Vec::new(),
            ControlStatusSnapshot {
                head_commit_sequence: 0,
                history_root: ContentDigest::sha256(b"initial-history"),
                state_root: ContentDigest::sha256(b"initial-state"),
                cameras: Vec::new(),
                ring: RingWatermarkStatus {
                    used_bytes: 0,
                    capacity_bytes: 1024,
                    watermark_percent: 0,
                },
                scrub: ActiveScrubStatus::Idle,
            },
            writer,
        ),
    }
}

fn context() -> Result<RequestContext, fss_core::ContractError> {
    Ok(RequestContext {
        connection_id: 1,
        request_id: 7,
        deployment_id: "site-forward".to_owned(),
        contract_basis_digest: reference_contract_basis().basis_digest(),
        principal: PrincipalId::parse("principal:owner")?,
        granted_capabilities: vec!["CAP-AGENT-CAMERA-CONTROL-001".to_owned()],
        cancel: RequestCancelToken::new(),
    })
}

fn receipt(commit_sequence: u64) -> ForwardBatchReceipt {
    ForwardBatchReceipt {
        commit_sequence,
        history_root: ContentDigest::sha256(format!("history-{commit_sequence}").as_bytes()),
        state_root: ContentDigest::sha256(format!("state-{commit_sequence}").as_bytes()),
        replayed: false,
    }
}

fn assert_committed(response: IpcResponse, request_id: u64, sequence: u64) {
    assert_eq!(response, committed(request_id, receipt(sequence)));
}

fn assert_refused(response: IpcResponse, expected: &str, retryable: bool) {
    assert!(
        matches!(
            &response,
            IpcResponse::Refused { error_id, retryable: actual, .. }
                if error_id.as_str() == expected && *actual == retryable
        ),
        "expected {expected} (retryable={retryable}), got {response:?}"
    );
    assert!(
        !format!("{response:?}").contains("FORWARD_SECRET_CANARY"),
        "refusals must not disclose batch bytes or storage error detail"
    );
}

fn summary_count(handler: &DaemonIpcHandlerAdapter) -> usize {
    let log = handler.shared.delta_log.lock().expect("delta log");
    let cursor = log
        .start(0, handler.head_commit_sequence())
        .expect("retained cursor");
    log.read_after(cursor, u32::MAX)
        .expect("retained summaries")
        .events
        .len()
}

#[derive(Default)]
struct CountingWriter {
    calls: AtomicU64,
}

impl ForwardBatchWriter for CountingWriter {
    fn forward_delta_batch(
        &self,
        _batch_bytes: &[u8],
    ) -> Result<(u64, ContentDigest, ContentDigest), DaemonError> {
        let receipt = receipt(self.calls.fetch_add(1, Ordering::AcqRel) + 1);
        Ok((
            receipt.commit_sequence,
            receipt.history_root,
            receipt.state_root,
        ))
    }
}

#[test]
fn exact_retry_returns_original_receipt_under_new_connection_and_request_ids() -> TestResult {
    let writer = Arc::new(CountingWriter::default());
    let handler = handler(writer.clone());
    let mut ctx = context()?;
    let key = ContentDigest::sha256(b"stable-key");
    let approval = Some(ContentDigest::sha256(b"approval"));
    assert_committed(
        handler.submit_delta_batch(&ctx, key, b"exact-batch", approval),
        7,
        1,
    );
    ctx.connection_id = 99;
    ctx.request_id = 100;
    assert_committed(
        handler.submit_delta_batch(&ctx, key, b"exact-batch", approval),
        100,
        1,
    );
    assert_eq!(writer.calls.load(Ordering::Acquire), 1);
    assert_eq!(summary_count(&handler), 1);
    Ok(())
}

#[test]
fn key_binds_exact_bytes_approval_principal_deployment_basis_and_grants() -> TestResult {
    let writer = Arc::new(CountingWriter::default());
    let handler = handler(writer.clone());
    let ctx = context()?;
    let key = ContentDigest::sha256(b"bound-key");
    let approval = Some(ContentDigest::sha256(b"approval"));
    assert_committed(
        handler.submit_delta_batch(&ctx, key, b"original-batch", approval),
        7,
        1,
    );
    for (bytes, changed_approval) in [
        (b"FORWARD_SECRET_CANARY".as_slice(), approval),
        (b"original-batch".as_slice(), None),
        (
            b"original-batch".as_slice(),
            Some(ContentDigest::sha256(b"changed-approval")),
        ),
    ] {
        assert_refused(
            handler.submit_delta_batch(&ctx, key, bytes, changed_approval),
            ERR_IDEMPOTENCY_CONFLICT,
            false,
        );
    }
    let mut changed = context()?;
    changed.principal = PrincipalId::parse("principal:another-owner")?;
    assert_refused(
        handler.submit_delta_batch(&changed, key, b"original-batch", approval),
        ERR_IDEMPOTENCY_CONFLICT,
        false,
    );
    changed = context()?;
    changed.deployment_id = "site-another".to_owned();
    assert_refused(
        handler.submit_delta_batch(&changed, key, b"original-batch", approval),
        ERR_IDEMPOTENCY_CONFLICT,
        false,
    );
    changed = context()?;
    changed.contract_basis_digest = ContentDigest::sha256(b"another-basis");
    assert_refused(
        handler.submit_delta_batch(&changed, key, b"original-batch", approval),
        ERR_IDEMPOTENCY_CONFLICT,
        false,
    );
    changed = context()?;
    changed.granted_capabilities.clear();
    assert_refused(
        handler.submit_delta_batch(&changed, key, b"original-batch", approval),
        ERR_IDEMPOTENCY_CONFLICT,
        false,
    );
    assert_eq!(writer.calls.load(Ordering::Acquire), 1);
    assert_eq!(summary_count(&handler), 1);
    Ok(())
}

#[test]
fn capability_order_and_duplicates_do_not_change_the_authenticated_set() -> TestResult {
    let writer = Arc::new(CountingWriter::default());
    let handler = handler(writer.clone());
    let mut ctx = context()?;
    ctx.granted_capabilities.push("CAP-AGENT-HYDRATE-H3-001".to_owned());
    let key = ContentDigest::sha256(b"grant-set");
    assert_committed(handler.submit_delta_batch(&ctx, key, b"batch", None), 7, 1);
    ctx.granted_capabilities.reverse();
    ctx.granted_capabilities.push(ctx.granted_capabilities[0].clone());
    assert_committed(handler.submit_delta_batch(&ctx, key, b"batch", None), 7, 1);
    assert_eq!(writer.calls.load(Ordering::Acquire), 1);
    Ok(())
}

struct BlockingWriter {
    calls: AtomicU64,
    started: SyncSender<()>,
    release: Mutex<Receiver<()>>,
}

impl ForwardBatchWriter for BlockingWriter {
    fn forward_delta_batch(
        &self,
        _batch_bytes: &[u8],
    ) -> Result<(u64, ContentDigest, ContentDigest), DaemonError> {
        let sequence = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        if sequence == 1 {
            self.started.send(()).expect("observe first dispatch");
            self.release
                .lock()
                .expect("release receiver")
                .recv_timeout(Duration::from_secs(10))
                .expect("test releases first dispatch");
        }
        let receipt = receipt(sequence);
        Ok((
            receipt.commit_sequence,
            receipt.history_root,
            receipt.state_root,
        ))
    }
}

#[test]
fn concurrent_duplicates_do_not_dispatch_and_other_keys_progress_during_io() -> TestResult {
    let (started_tx, started_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let writer = Arc::new(BlockingWriter {
        calls: AtomicU64::new(0),
        started: started_tx,
        release: Mutex::new(release_rx),
    });
    let handler = Arc::new(handler(writer.clone()));
    let first_handler = handler.clone();
    let first_ctx = context()?;
    let key = ContentDigest::sha256(b"in-flight");
    let first = std::thread::spawn(move || {
        first_handler.submit_delta_batch(&first_ctx, key, b"first", None)
    });
    started_rx.recv_timeout(Duration::from_secs(10))?;
    let ctx = context()?;
    assert_refused(
        handler.submit_delta_batch(&ctx, key, b"first", None),
        ERR_OP_RECONCILIATION_REQUIRED_001,
        true,
    );
    assert_refused(
        handler.submit_delta_batch(&ctx, key, b"changed", None),
        ERR_IDEMPOTENCY_CONFLICT,
        false,
    );
    assert_committed(
        handler.submit_delta_batch(&ctx, ContentDigest::sha256(b"independent"), b"second", None),
        7,
        2,
    );
    release_tx.send(())?;
    assert_committed(first.join().expect("first worker"), 7, 1);
    assert_committed(handler.submit_delta_batch(&ctx, key, b"first", None), 7, 1);
    assert_eq!(writer.calls.load(Ordering::Acquire), 2);
    assert_eq!(summary_count(&handler), 2);
    Ok(())
}

struct UncertainWriter {
    calls: AtomicU64,
    panics: bool,
}

impl ForwardBatchWriter for UncertainWriter {
    fn forward_delta_batch(
        &self,
        _batch_bytes: &[u8],
    ) -> Result<(u64, ContentDigest, ContentDigest), DaemonError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        assert!(!self.panics, "injected post-dispatch panic");
        Err(DaemonError::Io {
            operation: "forwarded test commit",
            detail: "FORWARD_SECRET_CANARY".to_owned(),
        })
    }
}

#[test]
fn storage_failure_or_unwind_without_receipt_never_allows_blind_redispatch() -> TestResult {
    for panics in [false, true] {
        let writer = Arc::new(UncertainWriter {
            calls: AtomicU64::new(0),
            panics,
        });
        let handler = handler(writer.clone());
        let ctx = context()?;
        let key = ContentDigest::sha256(b"uncertain");
        let first = catch_unwind(AssertUnwindSafe(|| {
            handler.submit_delta_batch(&ctx, key, b"batch", None)
        }));
        if panics {
            assert!(first.is_err());
        } else {
            assert_refused(
                first.expect("writer returns an error"),
                ERR_OP_RECONCILIATION_REQUIRED_001,
                false,
            );
        }
        assert!(handler.shared.forwarded_batches.entries.lock().is_ok());
        assert_refused(
            handler.submit_delta_batch(&ctx, key, b"batch", None),
            ERR_OP_RECONCILIATION_REQUIRED_001,
            false,
        );
        assert_refused(
            handler.submit_delta_batch(&ctx, key, b"changed", None),
            ERR_IDEMPOTENCY_CONFLICT,
            false,
        );
        assert_eq!(writer.calls.load(Ordering::Acquire), 1);
        assert_eq!(summary_count(&handler), 0);
    }
    Ok(())
}

struct CancellingWriter {
    calls: AtomicU64,
    cancel: RequestCancelToken,
}

impl ForwardBatchWriter for CancellingWriter {
    fn forward_delta_batch(
        &self,
        _batch_bytes: &[u8],
    ) -> Result<(u64, ContentDigest, ContentDigest), DaemonError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.cancel.cancel(CancelReason::ClientCancelRequest);
        let receipt = receipt(1);
        Ok((
            receipt.commit_sequence,
            receipt.history_root,
            receipt.state_root,
        ))
    }
}

#[test]
fn cancellation_before_dispatch_does_not_reserve_but_after_commit_keeps_receipt() -> TestResult {
    let before = Arc::new(CountingWriter::default());
    let before_handler = handler(before.clone());
    let cancelled = context()?;
    cancelled.cancel.cancel(CancelReason::ClientCancelRequest);
    let key = ContentDigest::sha256(b"cancelled");
    assert_eq!(
        before_handler.submit_delta_batch(&cancelled, key, b"batch", None),
        IpcResponse::Cancelled { request_id: 7 }
    );
    assert_eq!(before.calls.load(Ordering::Acquire), 0);
    assert!(before_handler.shared.forwarded_batches.entries.lock().expect("cache").is_empty());
    assert_committed(
        before_handler.submit_delta_batch(&context()?, key, b"batch", None),
        7,
        1,
    );

    let ctx = context()?;
    let after = Arc::new(CancellingWriter {
        calls: AtomicU64::new(0),
        cancel: ctx.cancel.clone(),
    });
    let after_handler = handler(after.clone());
    assert_committed(after_handler.submit_delta_batch(&ctx, key, b"batch", None), 7, 1);
    assert!(ctx.is_cancelled());
    assert_committed(
        after_handler.submit_delta_batch(&context()?, key, b"batch", None),
        7,
        1,
    );
    assert_eq!(after.calls.load(Ordering::Acquire), 1);
    assert_eq!(summary_count(&after_handler), 1);
    Ok(())
}

#[test]
fn unavailable_cache_fails_closed_without_forwarding() -> TestResult {
    let writer = Arc::new(CountingWriter::default());
    let handler = handler(writer.clone());
    let poisoned = catch_unwind(AssertUnwindSafe(|| {
        let _guard = handler.shared.forwarded_batches.entries.lock().expect("cache");
        panic!("injected cache poison");
    }));
    assert!(poisoned.is_err());
    assert_refused(
        handler.submit_delta_batch(&context()?, ContentDigest::sha256(b"key"), b"batch", None),
        ERR_OP_RECONCILIATION_REQUIRED_001,
        false,
    );
    assert_eq!(writer.calls.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn shutdown_still_returns_retained_receipts_but_refuses_new_writes() -> TestResult {
    let writer = Arc::new(CountingWriter::default());
    let handler = handler(writer.clone());
    let ctx = context()?;
    let key = ContentDigest::sha256(b"before-shutdown");
    assert_committed(handler.submit_delta_batch(&ctx, key, b"batch", None), 7, 1);
    handler.shared.request_shutdown();
    assert_committed(handler.submit_delta_batch(&ctx, key, b"batch", None), 7, 1);
    assert_refused(
        handler.submit_delta_batch(&ctx, key, b"changed", None),
        ERR_IDEMPOTENCY_CONFLICT,
        false,
    );
    assert_refused(
        handler.submit_delta_batch(&ctx, ContentDigest::sha256(b"after-shutdown"), b"batch", None),
        ERR_IPC_SERVER_SHUTDOWN_001,
        true,
    );
    assert_eq!(writer.calls.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn oversized_batch_and_unencodable_context_never_admit_a_write() -> TestResult {
    let writer = Arc::new(CountingWriter::default());
    let handler = handler(writer.clone());
    let mut ctx = context()?;
    let key = ContentDigest::sha256(b"overbound");
    assert_refused(
        handler.submit_delta_batch(&ctx, key, &vec![0; MAX_REQUEST_PAYLOAD_BYTES + 1], None),
        ERR_IPC_FRAME_TOO_LARGE_001,
        false,
    );
    ctx.deployment_id = "x".repeat(65_537);
    assert_refused(
        handler.submit_delta_batch(&ctx, key, b"batch", None),
        ERR_IPC_WIRE_CORRUPT_001,
        false,
    );
    assert_eq!(writer.calls.load(Ordering::Acquire), 0);
    assert!(handler.shared.forwarded_batches.entries.lock().expect("cache").is_empty());
    assert_committed(handler.submit_delta_batch(&context()?, key, b"batch", None), 7, 1);
    Ok(())
}

#[derive(Default)]
struct DurableWriter {
    mutations: AtomicU64,
    records: Mutex<BTreeMap<ContentDigest, (ContentDigest, ForwardBatchReceipt)>>,
}

impl ForwardBatchWriter for DurableWriter {
    fn forward_delta_batch(
        &self,
        _batch_bytes: &[u8],
    ) -> Result<(u64, ContentDigest, ContentDigest), DaemonError> {
        panic!("durable forwarding must use the key and request binding");
    }

    fn forward_delta_batch_idempotent(
        &self,
        key: ContentDigest,
        request_digest: ContentDigest,
        _batch_bytes: &[u8],
    ) -> Result<ForwardBatchReceipt, DaemonError> {
        let mut records = self.records.lock().expect("durable records");
        if let Some(&(previous, mut receipt)) = records.get(&key) {
            if previous != request_digest {
                return Err(DaemonError::Ipc(IpcError::Refused {
                    request_id: 0,
                    error_id: parse_error_id(ERR_IDEMPOTENCY_CONFLICT).expect("registered error"),
                    reason: "conflicting durable request".to_owned(),
                    retryable: false,
                }));
            }
            receipt.replayed = true;
            return Ok(receipt);
        }
        let receipt = receipt(self.mutations.fetch_add(1, Ordering::AcqRel) + 1);
        records.insert(key, (request_digest, receipt));
        Ok(receipt)
    }

    fn supports_durable_idempotency(&self) -> bool {
        true
    }
}

#[test]
fn durable_receipts_outlive_hot_cache_without_a_lifetime_write_limit() -> TestResult {
    let writer = Arc::new(DurableWriter::default());
    let handler = handler(writer.clone());
    let ctx = context()?;
    let mut requests = Vec::new();
    for index in 0..=MAX_FORWARDED_BATCHES {
        let batch = format!("batch-{index}").into_bytes();
        let key = ContentDigest::sha256(&batch);
        let sequence = u64::try_from(index)? + 1;
        assert_committed(handler.submit_delta_batch(&ctx, key, &batch, None), 7, sequence);
        requests.push((key, batch, sequence));
    }
    let (evicted_key, evicted_batch, evicted_sequence) = {
        let cache = handler.shared.forwarded_batches.entries.lock().expect("cache");
        assert_eq!(cache.len(), MAX_FORWARDED_BATCHES);
        requests
            .iter()
            .find(|(key, _, _)| !cache.contains_key(key))
            .cloned()
            .expect("a settled hot record was evicted")
    };
    assert_refused(
        handler.submit_delta_batch(&ctx, evicted_key, b"FORWARD_SECRET_CANARY", None),
        ERR_IDEMPOTENCY_CONFLICT,
        false,
    );
    // A conflict observed only by the durable backend must not poison the original key.
    assert_committed(
        handler.submit_delta_batch(&ctx, evicted_key, &evicted_batch, None),
        7,
        evicted_sequence,
    );
    assert_eq!(writer.mutations.load(Ordering::Acquire), u64::try_from(requests.len())?);
    assert_eq!(summary_count(&handler), requests.len());

    let reopened = self::handler(writer.clone());
    let mut new_ctx = context()?;
    new_ctx.request_id = 80;
    new_ctx.connection_id = 90;
    assert_committed(
        reopened.submit_delta_batch(&new_ctx, evicted_key, &evicted_batch, None),
        80,
        evicted_sequence,
    );
    assert_eq!(writer.mutations.load(Ordering::Acquire), u64::try_from(requests.len())?);
    assert_eq!(summary_count(&reopened), 0);
    Ok(())
}

#[test]
fn legacy_writer_capacity_retains_every_acknowledged_replay_record() -> TestResult {
    let writer = Arc::new(CountingWriter::default());
    let handler = handler(writer.clone());
    let ctx = context()?;
    for index in 0..MAX_FORWARDED_BATCHES {
        let batch = format!("batch-{index}");
        assert_committed(
            handler.submit_delta_batch(
                &ctx,
                ContentDigest::sha256(batch.as_bytes()),
                batch.as_bytes(),
                None,
            ),
            7,
            u64::try_from(index)? + 1,
        );
    }
    assert_refused(
        handler.submit_delta_batch(&ctx, ContentDigest::sha256(b"overflow"), b"overflow", None),
        "ERR-BUDGET-EXHAUSTED-001",
        false,
    );
    assert_committed(
        handler.submit_delta_batch(&ctx, ContentDigest::sha256(b"batch-0"), b"batch-0", None),
        7,
        1,
    );
    assert_eq!(writer.calls.load(Ordering::Acquire), u64::try_from(MAX_FORWARDED_BATCHES)?);
    Ok(())
}
