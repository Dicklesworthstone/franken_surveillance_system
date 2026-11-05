#![forbid(unsafe_code)]
#![cfg(unix)]
//! Durable one-use management effects over a synthetic connection.
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
    Controller, Dispatch, Identity,
    management::{Intent, Preconditions},
    metered::{MeteredClock, MeteredIo},
    receive::{Error as ReceiveError, ManagementAuthority, ManagementWrite, Session},
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
    path::PathBuf,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

type Test = Result<(), Box<dyn Error>>;
const HEAD: &str = "GET / HTTP/1.1\r\nHost: camera.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCamera-Mac: 001122aabbcc\r\nSec-WebSocket-Protocol: secure_transfer\r\n\r\n";
const HELLO: &[u8] = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_hello","messageId":7,"payload":{}}"#;
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
struct Guard(bool);
impl ManagementAuthority for Guard {
    fn permits(&self, mac: [u8; 6], _: Intent, _: &CommittedEffect) -> bool {
        self.0 && mac == [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]
    }
}
fn prepared(conditions: Preconditions) -> Result<(Controller, Intent), Box<dyn Error>> {
    let mut controller = Controller::new(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
    )?;
    controller.observe(HELLO)?;
    let intent = Intent::new(
        controller.prepare_hello("2026-11-05T10:00:00.000Z")?,
        conditions,
    )?;
    Ok((controller, intent))
}
#[test]
fn management_dispatch_requires_exact_durable_single_use_effect() -> Test {
    let parent = std::fs::canonicalize(std::env::temp_dir())?;
    let path = parent.join(format!(
        "fss-unifi-management-effect-{}",
        std::process::id()
    ));
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
            trace_id: "trace:unifi-management".into(),
            operation_id: OperationId::parse("operation:unifi-management-owner")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::CameraManagementCommit.as_str().into(),
                RuntimeGrant::CameraManagementPrepare.as_str().into(),
            ],
            deadline: Some(TimestampNs(600_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"unifi management fixture"),
            generation: 1,
        },
        RegionId::new("region:unifi-management")?,
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
        peer_admission: ContentDigest::sha256(b"fixture peer"),
        session_generation: 1,
        previous_association: Some(ContentDigest::sha256(b"old association")),
        previous_clock: None,
        lease_fence: lease.fence,
    };
    let (controller, intent) = prepared(conditions)?;
    assert_eq!(intent.resource(), resource);
    let operation = OperationId::parse("operation:unifi-management")?;
    let prepared_effect = effects.prepare(
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
            prepare_grant: RuntimeGrant::CameraManagementPrepare,
            commit_grant: RuntimeGrant::CameraManagementCommit,
            terminal_predicate: "independent association observation or reconciliation",
        },
        TimestampNs(3),
    )?;
    let approval = CommitApproval {
        prepared_digest: prepared_effect.digest(),
        current_precondition_digest: intent.precondition_digest(),
    };
    let permit = effects.commit(
        &authority,
        &tree,
        &mut leases,
        prepared_effect,
        TimestampNs(4),
        approval,
    )?;
    assert!(permit.journal_backed());
    assert_eq!(
        permit.prepared().effect_class(),
        "EFFECT-CAMERA-MANAGEMENT-001"
    );
    let runtime = RuntimeBuilder::current_thread().build()?;
    let mut permit = runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:unifi-management")?,
                started_at: TimestampNs(5),
            },
            &cx,
            async |task, cx| {
                let output: Result<CommittedEffect, Box<dyn Error>> = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(6))?;
                    let written = Rc::new(RefCell::new(Vec::new()));
                    let io = MeteredIo::with_clock(
                        Sink(written.clone()),
                        clock,
                        "fixture:camera",
                        4096,
                    )?;
                    let upgrade =
                        PreparedUpgrade::parse(HEAD.as_bytes(), ProtocolPolicy::RequireOffer)?;
                    let mut session =
                        Session::from_upgrade(upgrade, io, Dispatch::Written, controller)?;
                    assert_eq!(session.management_intent(conditions)?, intent);
                    let refused = session
                        .dispatch_management(
                            intent,
                            conditions,
                            permit,
                            &Guard(false),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("denied policy");
                    assert_eq!(refused.reason, ReceiveError::Denied);
                    let stale = Preconditions {
                        session_generation: 2,
                        ..conditions
                    };
                    let refused = session
                        .dispatch_management(
                            intent,
                            stale,
                            refused.permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("stale preconditions");
                    assert!(matches!(refused.reason, ReceiveError::ManagementIntent(_)));
                    assert!(written.borrow().is_empty());
                    let result = session
                        .dispatch_management(
                            intent,
                            conditions,
                            refused.permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .map_err(|_| "dispatch refused")?;
                    let permit = match result {
                        ManagementWrite::Written { permit } => permit,
                        _ => return Err("unexpected indeterminate write".into()),
                    };
                    assert_eq!(written.borrow().first().copied(), Some(0x82));
                    drop(session);
                    let (controller, duplicate_intent) = prepared(conditions)?;
                    let io = MeteredIo::with_clock(
                        Sink(Rc::new(RefCell::new(Vec::new()))),
                        clock,
                        "fixture:camera",
                        4096,
                    )?;
                    let upgrade =
                        PreparedUpgrade::parse(HEAD.as_bytes(), ProtocolPolicy::RequireOffer)?;
                    let mut duplicate =
                        Session::from_upgrade(upgrade, io, Dispatch::Written, controller)?;
                    let refused = duplicate
                        .dispatch_management(
                            duplicate_intent,
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
                    TaskOutcome::Failed("management effect fixture failed".into())
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
    let proof = ContentDigest::sha256(b"fixture association observation");
    effects.observed(&mut permit, proof, TimestampNs(59_200_000_000))?;
    effects.verified(
        &mut tree,
        &authority,
        permit,
        proof,
        TimestampNs(59_300_000_000),
    )?;
    assert!(authority.finalize_report(&tree)?.is_empty());
    Ok(())
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

#[test]
fn interrupted_management_write_recovers_for_reconciliation_only() -> Test {
    use fss_reference::unifi_direct::{
        Phase,
        receive::{Step, Stop},
    };
    use std::future::{Future, poll_fn};
    let parent = std::fs::canonicalize(std::env::temp_dir())?;
    let path = parent.join(format!(
        "fss-unifi-management-interrupted-{}",
        std::process::id()
    ));
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
            trace_id: "trace:unifi-management-interrupted".into(),
            operation_id: OperationId::parse("operation:unifi-management-interrupted-owner")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::CameraManagementCommit.as_str().into(),
                RuntimeGrant::CameraManagementPrepare.as_str().into(),
            ],
            deadline: Some(TimestampNs(600_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"unifi interrupted management fixture"),
            generation: 1,
        },
        RegionId::new("region:unifi-management-interrupted")?,
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
        peer_admission: ContentDigest::sha256(b"fixture peer"),
        session_generation: 1,
        previous_association: None,
        previous_clock: None,
        lease_fence: lease.fence,
    };
    let (controller, intent) = prepared(conditions)?;
    let operation = OperationId::parse("operation:unifi-management-interrupted")?;
    let effect = effects.prepare(
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
            prepare_grant: RuntimeGrant::CameraManagementPrepare,
            commit_grant: RuntimeGrant::CameraManagementCommit,
            terminal_predicate: "independent association observation or reconciliation",
        },
        TimestampNs(3),
    )?;
    let approval = CommitApproval {
        prepared_digest: effect.digest(),
        current_precondition_digest: intent.precondition_digest(),
    };
    let permit = effects.commit(
        &authority,
        &tree,
        &mut leases,
        effect,
        TimestampNs(4),
        approval,
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:management-interrupted")?,started_at:TimestampNs(5)},&cx,async |task,cx| {
            let output:Test=async {
                let sent=Rc::new(RefCell::new(Vec::new()));
                let io=MeteredIo::new(PartialSink(sent.clone()),task,cx,TimestampNs(6),"fixture:camera",4096)?;
                let upgrade=PreparedUpgrade::parse(HEAD.as_bytes(),ProtocolPolicy::RequireOffer)?;
                let mut session=Session::from_upgrade(upgrade,io,Dispatch::Written,controller)?;
                let guard=Guard(true);
                let mut write=Box::pin(session.dispatch_management(intent,conditions,permit,&guard,Duration::from_secs(1)));
                poll_fn(|cx| match write.as_mut().poll(cx) { Poll::Pending=>Poll::Ready(()), Poll::Ready(_)=>panic!("partial write fixture must suspend") }).await;
                drop(write);assert_eq!(sent.borrow().len(),1);
                assert!(matches!(session.next(Duration::from_secs(1)).await?,Step::Retired {reason:Stop::IndeterminateWrite,controller} if controller.previous_phase==Phase::Indeterminate));
                Ok(())
            }.await;
            let outcome=if output.is_ok(){TaskOutcome::Success}else{TaskOutcome::Failed("interrupted management fixture failed".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(59_000_000_000)}
        }).await?;
        result.receipt?;result.output
    })?;
    assert_eq!(
        effects
            .journal()
            .operation(&operation)
            .ok_or("missing operation")?
            .state,
        fss_core::EffectState::Committed
    );
    let pin = effects.durable_pin().ok_or("missing journal pin")?;
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
            .operation(&operation)
            .ok_or("missing recovered operation")?
            .state,
        fss_core::EffectState::Committed
    );
    Ok(())
}

#[test]
fn management_intents_bind_operation_and_current_preconditions() -> Test {
    use fss_reference::unifi_direct::{AGREEMENT_DELAY_NS, MessageKind};
    let conditions = Preconditions {
        camera: ContentDigest::sha256(b"camera"),
        peer_admission: ContentDigest::sha256(b"admission"),
        session_generation: 1,
        previous_association: None,
        previous_clock: None,
        lease_fence: 1,
    };
    let (mut hello, hello_intent) = prepared(conditions)?;
    assert_eq!(hello_intent.kind(), MessageKind::HelloReply);
    hello.finish_dispatch(hello_intent.message_id(), Dispatch::Written)?;
    let agreement = Intent::new(
        hello.prepare_agreement("2026-11-05T10:00:00.000Z", AGREEMENT_DELAY_NS)?,
        conditions,
    )?;
    assert_eq!(agreement.kind(), MessageKind::AgreementRequest);
    assert_ne!(agreement.request_digest(), hello_intent.request_digest());
    assert_eq!(
        agreement.precondition_digest(),
        hello_intent.precondition_digest()
    );
    assert!(
        agreement
            .check_preconditions(Preconditions {
                session_generation: 2,
                ..conditions
            })
            .is_err()
    );
    assert!(
        agreement
            .check_message(hello.prepared().ok_or("prepared agreement")?)
            .is_ok()
    );
    assert!(
        hello_intent
            .check_message(hello.prepared().ok_or("prepared agreement")?)
            .is_err()
    );
    let mut clock = Controller::new(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
    )?;
    clock.observe(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":8,"payload":{}}"#)?;
    let time = Intent::new(
        clock.prepare_time_sync(1_762_340_000_000, "2026-11-05T10:00:00.000Z")?,
        conditions,
    )?;
    assert_eq!(time.kind(), MessageKind::TimeSyncReply);
    assert_ne!(time.request_digest(), agreement.request_digest());
    assert!(
        Intent::new(
            clock.prepared().ok_or("prepared clock reply")?,
            Preconditions {
                lease_fence: 0,
                ..conditions
            }
        )
        .is_err()
    );
    Ok(())
}
