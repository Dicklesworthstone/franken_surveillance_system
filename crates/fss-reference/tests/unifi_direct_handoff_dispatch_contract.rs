#![forbid(unsafe_code)]
#![cfg(unix)]
//! Journal-authorized HTTP controller handoff, partial writes and reconciliation.
use asupersync::{
    http::h1::Response, io::AsyncWrite, net::TcpListener, runtime::RuntimeBuilder, time::timeout,
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
    camera_api::{
        ControllerAddress, HandoffAuthority, HandoffError, HandoffWrite, Phase, Session,
        WriteOutcome,
    },
    camera_http,
    handoff::{Plan, Preconditions},
    metered::{MeteredClock, MeteredIo},
};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PrepareSpec},
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    lease::LeaseRegistry,
};
use std::future::{Future, poll_fn};
use std::{
    cell::{Cell, RefCell},
    error::Error,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

type Test = Result<(), Box<dyn Error>>;
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Sink {
    bytes: Rc<RefCell<Vec<u8>>>,
    partial: bool,
    polled: Rc<Cell<bool>>,
}
impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.polled.set(true);
        if self.partial && !self.bytes.borrow().is_empty() {
            return Poll::Pending;
        }
        let n = if self.partial {
            bytes.len().min(1)
        } else {
            bytes.len()
        };
        self.bytes.borrow_mut().extend_from_slice(&bytes[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
struct Guard(bool);
impl HandoffAuthority for Guard {
    fn permits(&self, _: &Plan, _: Preconditions, _: &CommittedEffect) -> bool {
        self.0
    }
}
struct RevokingGuard(Cell<u32>);
impl HandoffAuthority for RevokingGuard {
    fn permits(&self, _: &Plan, _: Preconditions, _: &CommittedEffect) -> bool {
        let calls = self.0.get();
        self.0.set(calls + 1);
        calls < 2
    }
}

struct Harness {
    _temp: Temp,
    authority: AuthorityCx,
    tree: fss_core::RegionTree,
    effects: EffectCoordinator,
    session: Session,
    plan: Plan,
    conditions: Preconditions,
    permit: CommittedEffect,
}
fn harness(suffix: &str) -> Result<Harness, Box<dyn Error>> {
    let path = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
        "fss-unifi-handoff-dispatch-{}-{suffix}",
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
    let (authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:handoff-dispatch".into(),
            operation_id: OperationId::parse("operation:handoff-owner")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::AdapterAuth.as_str().into(),
                RuntimeGrant::ObserveStatus.as_str().into(),
                RuntimeGrant::CameraManagementPrepare.as_str().into(),
                RuntimeGrant::CameraManagementCommit.as_str().into(),
            ],
            deadline: Some(TimestampNs(600_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"fixture"),
            generation: 1,
        },
        RegionId::new("region:handoff-dispatch")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let peer = Ipv4Addr::new(192, 168, 1, 30);
    let mut session = Session::new(peer, 1)?;
    let r = session.prepare_login(br#"{"username":"fixture","password":"synthetic"}"#)?;
    session.finish_write(r, WriteOutcome::Written)?;
    session.accept_login(
        Response::new(200, "OK", Vec::new()).with_header("Set-Cookie", "authId=synthetic-cookie"),
    )?;
    let r = session.prepare_status()?;
    session.finish_write(r, WriteOutcome::Written)?;
    session.accept_status(Response::new(200, "OK", b"{}".to_vec()))?;
    let r = session.prepare_settings()?;
    session.finish_write(r, WriteOutcome::Written)?;
    let settings = session.accept_settings(Response::new(
        200,
        "OK",
        br#"{"controller":{"addr":"192.168.1.10"}}"#.to_vec(),
    ))?;
    let camera = ContentDigest::sha256(b"fixture camera");
    let resource = format!("camera:{}", camera.to_text());
    let mut leases = LeaseRegistry::new();
    let fence = leases
        .acquire(&resource, authority.region().as_str(), None, TimestampNs(2))?
        .fence;
    let conditions = Preconditions {
        camera,
        peer_admission: ContentDigest::sha256(b"fixture peer"),
        session_generation: 1,
        lease_fence: fence,
        settings,
    };
    let plan = Plan::new(peer, Ipv4Addr::new(192, 168, 1, 40), conditions)?;
    let op = OperationId::parse("operation:handoff-dispatch")?;
    let prepared = effects.prepare(
        &authority,
        &mut tree,
        &mut leases,
        PrepareSpec {
            operation: &op,
            idempotency_key: IdempotencyKey::parse(op.as_str())?,
            request_digest: plan.request_digest(),
            precondition_digest: plan.precondition_digest(),
            resource: &resource,
            fence,
            prepare_grant: RuntimeGrant::CameraManagementPrepare,
            commit_grant: RuntimeGrant::CameraManagementCommit,
            terminal_predicate: "independent association observation or reconciliation",
        },
        TimestampNs(3),
    )?;
    let approval = CommitApproval {
        prepared_digest: prepared.digest(),
        current_precondition_digest: plan.precondition_digest(),
    };
    let permit = effects.commit(
        &authority,
        &tree,
        &mut leases,
        prepared,
        TimestampNs(4),
        approval,
    )?;
    Ok(Harness {
        _temp: temp,
        authority,
        tree,
        effects,
        session,
        plan,
        conditions,
        permit,
    })
}

#[test]
fn denied_stale_then_written_requires_fresh_readback() -> Test {
    let Harness {
        _temp,
        mut authority,
        mut tree,
        effects,
        mut session,
        plan,
        conditions,
        permit,
    } = harness("written")?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:handoff-dispatch")?,
                started_at: TimestampNs(5),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(6))?;
                    let bytes = Rc::new(RefCell::new(Vec::new()));
                    let mut io = MeteredIo::with_clock(
                        Sink {
                            bytes: bytes.clone(),
                            partial: false,
                            polled: Rc::new(Cell::new(false)),
                        },
                        clock,
                        "fixture:camera",
                        4096,
                    )?;
                    let other = Plan::new(
                        Ipv4Addr::new(192, 168, 1, 30),
                        Ipv4Addr::new(192, 168, 1, 41),
                        conditions,
                    )?;
                    let refusal = session
                        .dispatch_handoff(
                            cx,
                            &mut io,
                            &other,
                            conditions,
                            permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("different plan must deny");
                    assert_eq!(refusal.reason, HandoffError::PermitMismatch);
                    assert!(bytes.borrow().is_empty());
                    let refusal = session
                        .dispatch_handoff(
                            cx,
                            &mut io,
                            &plan,
                            conditions,
                            refusal.permit,
                            &Guard(false),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("policy must deny");
                    assert_eq!(refusal.reason, HandoffError::Denied);
                    assert!(bytes.borrow().is_empty());
                    let stale = Preconditions {
                        lease_fence: conditions.lease_fence + 1,
                        ..conditions
                    };
                    let refusal = session
                        .dispatch_handoff(
                            cx,
                            &mut io,
                            &plan,
                            stale,
                            refusal.permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("stale lease must deny");
                    assert_eq!(refusal.reason, HandoffError::Stale);
                    assert!(bytes.borrow().is_empty());
                    let result = session
                        .dispatch_handoff(
                            cx,
                            &mut io,
                            &plan,
                            conditions,
                            refusal.permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .map_err(|_| "write refused")?;
                    let mut permit = match result {
                        HandoffWrite::Written { permit } => permit,
                        _ => return Err("unexpected interruption".into()),
                    };
                    assert!(!permit.try_claim_dispatch());
                    let wire = bytes.borrow();
                    assert!(wire.starts_with(b"PUT /api/1.1/settings HTTP/1.1\r\n"));
                    assert!(wire.ends_with(br#"{"controller":{"addr":"192.168.1.40"}}"#));
                    drop(wire);
                    assert_eq!(session.phase(), Phase::AwaitHandoff);
                    session.accept_handoff_response(Response::new(200, "OK", b"{}".to_vec()))?;
                    assert_eq!(session.phase(), Phase::ReconcileSettings);
                    assert!(session.prepare_snapshot().is_err());
                    let readback = session.prepare_settings()?;
                    session.finish_write(readback, WriteOutcome::NotWritten)?;
                    assert_eq!(session.phase(), Phase::ReconcileSettings);
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
    })?;
    assert!(!authority.finalize_report(&tree)?.is_empty());
    assert_eq!(
        effects
            .journal()
            .operation(&OperationId::parse("operation:handoff-dispatch")?)
            .ok_or("missing journal")?
            .state,
        fss_core::EffectState::Committed
    );
    Ok(())
}

#[test]
fn revoked_authority_stops_a_partial_write_and_fences_the_session() -> Test {
    let Harness {
        _temp,
        mut authority,
        mut tree,
        effects,
        mut session,
        plan,
        conditions,
        permit,
    } = harness("revoked")?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:handoff-revoked")?,
                started_at: TimestampNs(5),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(6))?;
                    let bytes = Rc::new(RefCell::new(Vec::new()));
                    let mut io = MeteredIo::with_clock(
                        Sink {
                            bytes: bytes.clone(),
                            partial: true,
                            polled: Rc::new(Cell::new(false)),
                        },
                        clock,
                        "fixture:camera",
                        4096,
                    )?;
                    let guard = RevokingGuard(Cell::new(0));
                    let result = session
                        .dispatch_handoff(
                            cx,
                            &mut io,
                            &plan,
                            conditions,
                            permit,
                            &guard,
                            Duration::from_secs(1),
                        )
                        .await
                        .map_err(|_| "write refused too early")?;
                    assert!(matches!(result, HandoffWrite::Indeterminate { .. }));
                    assert_eq!(guard.0.get(), 3);
                    assert_eq!(bytes.borrow().len(), 1);
                    assert_eq!(session.phase(), Phase::Fenced);
                    assert!(session.prepare_settings().is_err());
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
    })?;
    assert!(!authority.finalize_report(&tree)?.is_empty());
    assert_eq!(
        effects
            .journal()
            .operation(&OperationId::parse("operation:handoff-dispatch")?)
            .ok_or("missing journal")?
            .state,
        fss_core::EffectState::Committed
    );
    Ok(())
}

#[test]
fn dropped_partial_write_fences_session_and_keeps_committed_obligation() -> Test {
    let Harness {
        _temp: temp,
        mut authority,
        mut tree,
        effects,
        mut session,
        plan,
        conditions,
        permit,
    } = harness("partial")?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:handoff-partial")?,
                started_at: TimestampNs(5),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(6))?;
                    let bytes = Rc::new(RefCell::new(Vec::new()));
                    let polled = Rc::new(Cell::new(false));
                    let mut io = MeteredIo::with_clock(
                        Sink {
                            bytes: bytes.clone(),
                            partial: true,
                            polled: polled.clone(),
                        },
                        clock,
                        "fixture:camera",
                        4096,
                    )?;
                    let guard = Guard(true);
                    let mut future = Box::pin(session.dispatch_handoff(
                        cx,
                        &mut io,
                        &plan,
                        conditions,
                        permit,
                        &guard,
                        Duration::from_secs(2),
                    ));
                    poll_fn(|context| match future.as_mut().poll(context) {
                        Poll::Pending => Poll::Ready(()),
                        Poll::Ready(_) => panic!("write should park"),
                    })
                    .await;
                    assert!(polled.get());
                    assert_eq!(bytes.borrow().len(), 1);
                    drop(future);
                    assert_eq!(session.phase(), Phase::Fenced);
                    assert!(session.prepare_settings().is_err());
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(59_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
    })?;
    assert!(!authority.finalize_report(&tree)?.is_empty());
    assert_eq!(
        effects
            .journal()
            .operation(&OperationId::parse("operation:handoff-dispatch")?)
            .ok_or("missing journal")?
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
            .operation(&OperationId::parse("operation:handoff-dispatch")?)
            .ok_or("missing recovered operation")?
            .state,
        fss_core::EffectState::Committed
    );
    Ok(())
}

struct HttpAccess;
impl camera_http::Authority for HttpAccess {
    fn permits(&self, peer: Ipv4Addr, generation: u64, _: camera_http::Operation) -> bool {
        peer == Ipv4Addr::new(192, 168, 1, 30) && generation == 1
    }
}
fn http_request(socket: &mut std::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut one = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut one)?;
        head.push(one[0]);
        if head.len() > 8192 {
            return Err(std::io::Error::other("fixture header limit"));
        }
    }
    let text = std::str::from_utf8(&head).map_err(std::io::Error::other)?;
    let len = text
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .map_or(Ok(0), str::parse::<usize>)
        .map_err(std::io::Error::other)?;
    if len > 4096 {
        return Err(std::io::Error::other("fixture body limit"));
    }
    let end = head.len() + len;
    head.resize(end, 0);
    socket.read_exact(&mut head[end - len..])?;
    Ok(head)
}
fn http_fixture(address: SocketAddr, cancel_reply: bool) -> std::io::Result<()> {
    let mut socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    socket.set_read_timeout(Some(Duration::from_secs(8)))?;
    let routes = [
        "POST /api/1.1/login ",
        "GET /api/1.1/status ",
        "GET /api/1.1/settings ",
        "PUT /api/1.1/settings ",
        "GET /api/1.1/settings ",
    ];
    for (index, route) in routes.iter().enumerate() {
        let request = http_request(&mut socket)?;
        if !request.starts_with(route.as_bytes()) {
            return Err(std::io::Error::other("fixture unexpected route"));
        }
        if index > 0
            && !request
                .windows(b"Cookie: authId=fixture-cookie".len())
                .any(|window| window == b"Cookie: authId=fixture-cookie")
        {
            return Err(std::io::Error::other("fixture cookie missing"));
        }
        if index == 3 && !request.ends_with(br#"{"controller":{"addr":"192.168.1.40"}}"#) {
            return Err(std::io::Error::other("fixture handoff mismatch"));
        }
        if index == 3 && cancel_reply {
            let mut b = [0u8; 1];
            return if socket.read(&mut b)? == 0 {
                Ok(())
            } else {
                Err(std::io::Error::other("fixture expected closure"))
            };
        }
        let body: &[u8] = match index {
            2 => br#"{"controller":{"addr":"192.168.1.10"}}"#,
            4 => br#"{"controller":{"addr":"192.168.1.40"}}"#,
            _ => b"{}",
        };
        let cookie = if index == 0 {
            "Set-Cookie: authId=fixture-cookie\r\n"
        } else {
            ""
        };
        let header = format!(
            "HTTP/1.1 200 OK\r\n{cookie}Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            body.len()
        );
        socket.write_all(header.as_bytes())?;
        socket.write_all(body)?;
    }
    Ok(())
}
fn owned_http_handoff(cancel_reply: bool) -> Test {
    let suffix = if cancel_reply {
        "http-cancel"
    } else {
        "http-success"
    };
    let Harness {
        _temp,
        mut authority,
        mut tree,
        effects,
        session: _,
        plan,
        conditions,
        permit,
    } = harness(suffix)?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime context")?;
        let result = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:owned-handoff-http")?,
                started_at: TimestampNs(5),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let peer = std::thread::spawn(move || http_fixture(address, cancel_reply));
                    let (socket, _) =
                        timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                    let clock = MeteredClock::new(task, cx, TimestampNs(6))?;
                    let resource = plan.resource();
                    let io = MeteredIo::with_clock(socket, clock, &resource, 4096)?;
                    let mut owner = camera_http::Owner::new(
                        io,
                        task,
                        cx,
                        clock,
                        &HttpAccess,
                        Ipv4Addr::new(192, 168, 1, 30),
                        1,
                        &resource,
                    )?;
                    owner
                        .login(
                            br#"{"username":"fixture","password":"synthetic"}"#,
                            Duration::from_secs(5),
                        )
                        .await?;
                    owner.status(Duration::from_secs(5)).await?;
                    let observed = owner.settings(Duration::from_secs(5)).await?;
                    assert_eq!(observed, conditions.settings);
                    let stale = Preconditions {
                        lease_fence: conditions.lease_fence + 1,
                        ..conditions
                    };
                    let refused = owner
                        .dispatch_handoff(
                            &plan,
                            stale,
                            permit,
                            &Guard(true),
                            Duration::from_secs(5),
                        )
                        .await
                        .expect_err("stale handoff must refuse");
                    assert_eq!(refused.reason, HandoffError::Stale);
                    assert_eq!(owner.phase(), Phase::Snapshot);
                    let denied = owner
                        .dispatch_handoff(
                            &plan,
                            conditions,
                            refused.permit,
                            &Guard(false),
                            Duration::from_secs(5),
                        )
                        .await
                        .expect_err("policy must refuse");
                    assert_eq!(denied.reason, HandoffError::Denied);
                    let mut permit = match owner
                        .dispatch_handoff(
                            &plan,
                            conditions,
                            denied.permit,
                            &Guard(true),
                            Duration::from_secs(5),
                        )
                        .await
                        .map_err(|_| "handoff refused")?
                    {
                        HandoffWrite::Written { permit } => permit,
                        HandoffWrite::Indeterminate { .. } => {
                            return Err("unexpected indeterminate write".into());
                        }
                    };
                    assert!(!permit.try_claim_dispatch());
                    assert_eq!(owner.phase(), Phase::AwaitHandoff);
                    if cancel_reply {
                        let mut reply =
                            Box::pin(owner.read_handoff_response(&permit, Duration::from_secs(5)));
                        poll_fn(|context| match reply.as_mut().poll(context) {
                            Poll::Pending => Poll::Ready(()),
                            Poll::Ready(_) => panic!("reply should wait"),
                        })
                        .await;
                        drop(reply);
                        assert_eq!(owner.phase(), Phase::Fenced);
                    } else {
                        owner
                            .read_handoff_response(&permit, Duration::from_secs(5))
                            .await?;
                        assert_eq!(owner.phase(), Phase::ReconcileSettings);
                        let after = owner.settings(Duration::from_secs(5)).await?;
                        assert_eq!(
                            after.controller,
                            ControllerAddress::Reported(Ipv4Addr::new(192, 168, 1, 40))
                        );
                        assert_eq!(
                            plan.classify_readback(after)?,
                            fss_reference::unifi_direct::handoff::Readback::Requested
                        );
                        assert_eq!(owner.phase(), Phase::Snapshot);
                    }
                    drop(owner);
                    peer.join().map_err(|_| "fixture peer panic")??;
                    Ok(())
                }
                .await;
                // The task completed its fixture work; the separately journaled
                // camera effect remains committed and unreconciled below.
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("HTTP handoff fixture failed".into())
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
    assert_eq!(
        effects
            .journal()
            .operation(&OperationId::parse("operation:handoff-dispatch")?)
            .ok_or("missing operation")?
            .state,
        fss_core::EffectState::Committed
    );
    Ok(())
}
#[test]
fn owned_http_handoff_requires_success_and_readback() -> Test {
    owned_http_handoff(false)
}
#[test]
fn cancelled_owned_http_handoff_reply_fences_session() -> Test {
    owned_http_handoff(true)
}
