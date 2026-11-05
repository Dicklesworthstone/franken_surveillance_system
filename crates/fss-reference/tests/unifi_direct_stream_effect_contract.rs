#![forbid(unsafe_code)]
#![cfg(unix)]
//! Journal-backed, one-use synthetic camera stream-setting dispatch.

use asupersync::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    runtime::RuntimeBuilder,
};
use fss_core::{
    BudgetVector, ContentDigest, IdempotencyKey, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_object::{
    HostSpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal},
};
use fss_reference::unifi_direct::{
    AGREEMENT_DELAY_NS, AudioCodec, Controller, Dispatch, Identity, StreamStart, VideoChannel,
    VideoCodec,
    intent::{Intent, Preconditions},
    metered::MeteredIo,
    receive::{Error as ReceiveError, Session, Step, Stop, StreamAuthority, StreamWrite},
    upgrade::{PreparedUpgrade, ProtocolPolicy},
};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PrepareSpec},
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    lease::LeaseRegistry,
};
use std::{
    cell::RefCell,
    error::Error,
    future::{Future, poll_fn},
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

type Test = Result<(), Box<dyn Error>>;
const HEAD: &str = "GET / HTTP/1.1\r\nHost: camera.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCamera-Mac: 001122aabbcc\r\nSec-WebSocket-Protocol: secure_transfer\r\n\r\n";
const TIME: &str = "2026-11-05T10:00:00.000Z";

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Sink(Rc<RefCell<Vec<u8>>>);
impl AsyncRead for Sink {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
struct PartialSink(Rc<RefCell<Vec<u8>>>);
impl AsyncRead for PartialSink {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for PartialSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !self.0.borrow().is_empty() {
            return Poll::Pending;
        }
        let count = bytes.len().min(1);
        self.0.borrow_mut().extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
struct Guard(bool);
impl StreamAuthority for Guard {
    fn permits(&self, mac: [u8; 6], _: Intent, _: &CommittedEffect) -> bool {
        self.0 && mac == [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]
    }
}
fn message(function: &str, id: u64, response_to: u64) -> Vec<u8> {
    format!("{{\"from\":\"ubnt_avclient\",\"to\":\"UniFiVideo\",\"functionName\":\"{function}\",\"messageId\":{id},\"inResponseTo\":{response_to},\"payload\":{{}}}}").into_bytes()
}
fn ready(
    request: &StreamStart,
    conditions: Preconditions,
) -> Result<(Controller, Intent), Box<dyn Error>> {
    let mut controller = Controller::new(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
    )?;
    controller.observe(&message("ubnt_avclient_hello", 7, 0))?;
    controller.prepare_hello(TIME)?;
    controller.finish_dispatch(1, Dispatch::Written)?;
    controller.prepare_agreement(TIME, AGREEMENT_DELAY_NS)?;
    controller.finish_dispatch(2, Dispatch::Written)?;
    controller.observe(&message("ubnt_avclient_paramAgreement", 8, 2))?;
    let intent = Intent::new(controller.prepare_stream_start(request, TIME)?, conditions)?;
    Ok((controller, intent))
}

#[test]
fn journaled_stream_effect_checks_intent_and_uses_permit_once() -> Test {
    let parent = std::fs::canonicalize(std::env::temp_dir())?;
    let path = parent.join(format!("fss-unifi-stream-effect-{}", std::process::id()));
    std::fs::create_dir(&path)?;
    let temp = Temp(path);
    let store = FileEffectJournal::create(
        temp.0.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut effects = EffectCoordinator::with_journal(Box::new(store))?;
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-effect-test".into(),
            operation_id: OperationId::parse("operation:unifi-effect-owner")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::CameraSettingCommit.as_str().into(),
                RuntimeGrant::CameraSettingPrepare.as_str().into(),
            ],
            deadline: Some(TimestampNs(600_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"unifi effect fixture"),
            generation: 1,
        },
        RegionId::new("region:unifi-effect")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let camera = ContentDigest::sha256(b"verified fixture camera");
    let resource = format!("camera:{}", camera.to_text());
    let mut leases = LeaseRegistry::new();
    let lease = leases.acquire(&resource, authority.region().as_str(), None, TimestampNs(2))?;
    let conditions = Preconditions {
        camera,
        peer_admission: ContentDigest::sha256(b"fixture peer admission"),
        stream_generation: 2,
        previous_settings: Some(ContentDigest::sha256(b"fixture prior settings")),
        lease_fence: lease.fence,
    };
    let request = StreamStart::new(
        VideoChannel::Video2,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 17551),
        VideoCodec::H264,
        AudioCodec::Aac,
        "0123456789abcdef",
    )?;
    let (controller, intent) = ready(&request, conditions)?;
    assert_eq!(intent.resource(), resource);
    let operation = OperationId::parse("operation:unifi-stream-effect")?;
    let prepared = effects.prepare(
        &authority,
        &mut tree,
        &mut leases,
        PrepareSpec {
            operation: &operation,
            idempotency_key: IdempotencyKey::parse(operation.as_str())?,
            request_digest: intent.request_digest(),
            precondition_digest: intent.precondition_digest(),
            resource: &resource,
            fence: lease.fence,
            prepare_grant: RuntimeGrant::CameraSettingPrepare,
            commit_grant: RuntimeGrant::CameraSettingCommit,
            terminal_predicate: "settings readback and stream generation rollover",
        },
        TimestampNs(3),
    )?;
    let approval = CommitApproval {
        prepared_digest: prepared.digest(),
        current_precondition_digest: intent.precondition_digest(),
    };
    let permit = effects.commit(
        &authority,
        &tree,
        &mut leases,
        prepared,
        TimestampNs(4),
        approval,
    )?;
    assert!(permit.journal_backed());
    assert_eq!(
        permit.prepared().effect_class(),
        "EFFECT-CAMERA-SETTING-001"
    );
    let runtime = RuntimeBuilder::current_thread().build()?;
    let mut permit = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:unifi-stream-effect")?,
                started_at: TimestampNs(5),
            },
            &cx,
            async |task, cx| {
                let output: Result<CommittedEffect, Box<dyn Error>> = async {
                    let start = cx.now().as_nanos();
                    let written = Rc::new(RefCell::new(Vec::new()));
                    let io = MeteredIo::new(
                        Sink(written.clone()),
                        task,
                        cx,
                        TimestampNs(6),
                        "fixture:camera",
                        4096,
                    )?;
                    let upgrade =
                        PreparedUpgrade::parse(HEAD.as_bytes(), ProtocolPolicy::RequireOffer)?;
                    let mut session =
                        Session::from_upgrade(upgrade, io, Dispatch::Written, controller)?;
                    let refused = session
                        .dispatch_stream(
                            intent,
                            conditions,
                            permit,
                            &Guard(false),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("policy denial");
                    assert_eq!(refused.reason, ReceiveError::Denied);
                    let changed = Preconditions {
                        stream_generation: conditions.stream_generation + 1,
                        ..conditions
                    };
                    let refused = session
                        .dispatch_stream(
                            intent,
                            changed,
                            refused.permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("stale preconditions");
                    assert!(matches!(refused.reason, ReceiveError::Intent(_)));
                    assert!(written.borrow().is_empty());
                    let outcome = session
                        .dispatch_stream(
                            intent,
                            conditions,
                            refused.permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .map_err(|_| "unexpected refusal")?;
                    let permit = match outcome {
                        StreamWrite::Written { permit } => permit,
                        _ => return Err("indeterminate fixture write".into()),
                    };
                    assert_eq!(written.borrow().first().copied(), Some(0x82));
                    drop(session);
                    let (duplicate_controller, duplicate_intent) = ready(&request, conditions)?;
                    assert_eq!(duplicate_intent, intent);
                    let now =
                        TimestampNs(6 + i128::from(cx.now().as_nanos().saturating_sub(start)));
                    let io = MeteredIo::new(
                        Sink(Rc::new(RefCell::new(Vec::new()))),
                        task,
                        cx,
                        now,
                        "fixture:camera",
                        4096,
                    )?;
                    let upgrade =
                        PreparedUpgrade::parse(HEAD.as_bytes(), ProtocolPolicy::RequireOffer)?;
                    let mut duplicate = Session::from_upgrade(
                        upgrade,
                        io,
                        Dispatch::Written,
                        duplicate_controller,
                    )?;
                    let refused = duplicate
                        .dispatch_stream(
                            intent,
                            conditions,
                            permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("claimed permit must not be reused");
                    assert_eq!(refused.reason, ReceiveError::PermitUsed);
                    Ok(refused.permit)
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("stream effect fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })?;
    effects.adapter_accepted(&mut permit, None, TimestampNs(59_100_000_000))?;
    let proof = ContentDigest::sha256(b"fixture settings readback and rollover");
    effects.observed(&mut permit, proof, TimestampNs(59_200_000_000))?;
    effects.verified(
        &mut tree,
        &authority,
        permit,
        proof,
        TimestampNs(59_300_000_000),
    )?;
    assert!(authority.finalize_report(&tree)?.is_empty());

    // Drop a future after one actual byte was sent. The committed journal entry
    // must remain available after cold restart and cannot mint another permit.
    let (controller, second_intent) = ready(&request, conditions)?;
    let second_operation = OperationId::parse("operation:unifi-stream-interrupted")?;
    let prepared = effects.prepare(
        &authority,
        &mut tree,
        &mut leases,
        PrepareSpec {
            operation: &second_operation,
            idempotency_key: IdempotencyKey::parse(second_operation.as_str())?,
            request_digest: second_intent.request_digest(),
            precondition_digest: second_intent.precondition_digest(),
            resource: &resource,
            fence: lease.fence,
            prepare_grant: RuntimeGrant::CameraSettingPrepare,
            commit_grant: RuntimeGrant::CameraSettingCommit,
            terminal_predicate: "settings readback and stream generation rollover",
        },
        TimestampNs(60_000_000_000),
    )?;
    let approval = CommitApproval {
        prepared_digest: prepared.digest(),
        current_precondition_digest: second_intent.precondition_digest(),
    };
    let permit = effects.commit(
        &authority,
        &tree,
        &mut leases,
        prepared,
        TimestampNs(61_000_000_000),
        approval,
    )?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:unifi-stream-interrupted")?,
                started_at: TimestampNs(62_000_000_000),
            },
            &cx,
            async |task, cx| {
                let output: Result<(), Box<dyn Error>> = async {
                    let sent = Rc::new(RefCell::new(Vec::new()));
                    let io = MeteredIo::new(
                        PartialSink(sent.clone()),
                        task,
                        cx,
                        TimestampNs(62_000_000_001),
                        "fixture:camera",
                        4096,
                    )?;
                    let upgrade =
                        PreparedUpgrade::parse(HEAD.as_bytes(), ProtocolPolicy::RequireOffer)?;
                    let mut session =
                        Session::from_upgrade(upgrade, io, Dispatch::Written, controller)?;
                    let guard = Guard(true);
                    let mut write = Box::pin(session.dispatch_stream(
                        second_intent,
                        conditions,
                        permit,
                        &guard,
                        Duration::from_secs(1),
                    ));
                    poll_fn(|cx| match write.as_mut().poll(cx) {
                        Poll::Pending => Poll::Ready(()),
                        Poll::Ready(_) => panic!("partial write fixture must suspend"),
                    })
                    .await;
                    drop(write);
                    assert_eq!(sent.borrow().len(), 1);
                    assert!(
                        matches!(session.next(Duration::from_secs(1)).await?, Step::Retired {
                    reason: Stop::IndeterminateWrite, controller,
                } if controller.previous_phase == fss_reference::unifi_direct::Phase::Indeterminate)
                    );
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("interrupted stream fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(63_000_000_000),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output
    })?;
    assert_eq!(
        effects
            .journal()
            .operation(&second_operation)
            .ok_or("missing interrupted operation")?
            .state,
        fss_core::EffectState::Committed
    );
    let pin = effects.durable_pin().ok_or("missing durable effect pin")?;
    drop(effects);
    let store = FileEffectJournal::open(
        temp.0.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        pin,
    )?;
    let recovered = EffectCoordinator::recover(Box::new(store), pin)?;
    assert!(recovered.is_reconciliation_only());
    assert_eq!(
        recovered
            .journal()
            .operation(&second_operation)
            .ok_or("missing recovered operation")?
            .state,
        fss_core::EffectState::Committed
    );
    Ok(())
}
