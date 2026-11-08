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
        ControllerAddress, HandoffAuthority, HandoffError, HandoffResponseObservation,
        HandoffWrite, Phase, Session, WriteOutcome,
    },
    camera_http,
    handoff::{Framing, Plan, Preconditions},
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
    harness_with_framing(suffix, Framing::ContentLength)
}
fn harness_with_framing(suffix: &str, framing: Framing) -> Result<Harness, Box<dyn Error>> {
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
    let plan = Plan::new_with_framing(peer, Ipv4Addr::new(192, 168, 1, 40), conditions, framing)?;
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
    exercise_framing(Framing::ContentLength)
}
#[test]
fn chunked_write_is_bound_to_its_own_permit_and_has_exact_wire_framing() -> Test {
    exercise_framing(Framing::Chunked)
}
fn exercise_framing(framing: Framing) -> Test {
    let Harness {
        _temp,
        mut authority,
        mut tree,
        effects,
        mut session,
        plan,
        conditions,
        permit,
    } = harness_with_framing(
        if framing == Framing::Chunked {
            "chunked"
        } else {
            "written"
        },
        framing,
    )?;
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
                    let wrong_framing = Plan::new_with_framing(
                        Ipv4Addr::new(192, 168, 1, 30),
                        Ipv4Addr::new(192, 168, 1, 40),
                        conditions,
                        if framing == Framing::Chunked {
                            Framing::ContentLength
                        } else {
                            Framing::Chunked
                        },
                    )?;
                    let refusal = session
                        .dispatch_handoff(
                            cx,
                            &mut io,
                            &wrong_framing,
                            conditions,
                            refusal.permit,
                            &Guard(true),
                            Duration::from_secs(1),
                        )
                        .await
                        .expect_err("permit must bind framing");
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
                    let body = br#"{"controller":{"addr":"192.168.1.40"}}"#;
                    let wire_text = std::str::from_utf8(&wire)?;
                    match framing {
                        Framing::ContentLength => {
                            assert!(
                                wire_text
                                    .contains(&format!("\r\nContent-Length: {}\r\n", body.len()))
                            );
                            assert!(!wire_text.contains("Transfer-Encoding:"));
                            assert!(wire.ends_with(body));
                        }
                        Framing::Chunked => {
                            assert!(wire_text.contains("\r\nTransfer-Encoding: chunked\r\n"));
                            assert!(!wire_text.contains("Content-Length:"));
                            assert!(wire_text.ends_with(&format!(
                                "\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                                body.len(),
                                std::str::from_utf8(body)?
                            )));
                        }
                    }
                    drop(wire);
                    assert_eq!(session.phase(), Phase::AwaitHandoff);
                    let observed = session.accept_handoff_response_observed(Response::new(
                        200,
                        "OK",
                        br#"{"success":false,"statusCode":17,"password":"fixture-secret"}"#
                            .to_vec(),
                    ))?;
                    assert_eq!(
                        observed,
                        HandoffResponseObservation::Object {
                            success: Some(false),
                            status_code: Some(17)
                        }
                    );
                    assert!(!format!("{observed:?}").contains("fixture-secret"));
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

struct HttpAccess {
    handoff: Cell<bool>,
}
impl camera_http::Authority for HttpAccess {
    fn permits(&self, peer: Ipv4Addr, generation: u64, operation: camera_http::Operation) -> bool {
        peer == Ipv4Addr::new(192, 168, 1, 30)
            && generation == 1
            && (operation != camera_http::Operation::Handoff || self.handoff.get())
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
    let chunked = text
        .lines()
        .any(|line| line == "Transfer-Encoding: chunked");
    if chunked {
        if text.lines().any(|line| line.starts_with("Content-Length:")) {
            return Err(std::io::Error::other("ambiguous fixture framing"));
        }
        let mut length = Vec::new();
        while !length.ends_with(b"\r\n") {
            socket.read_exact(&mut one)?;
            length.push(one[0]);
            if length.len() > 10 {
                return Err(std::io::Error::other("fixture chunk size limit"));
            }
        }
        let len = usize::from_str_radix(
            std::str::from_utf8(&length[..length.len() - 2]).map_err(std::io::Error::other)?,
            16,
        )
        .map_err(std::io::Error::other)?;
        if len == 0 || len > 4096 {
            return Err(std::io::Error::other("fixture chunk body limit"));
        }
        let start = head.len();
        head.resize(start + len, 0);
        socket.read_exact(&mut head[start..])?;
        let mut end = [0u8; 7];
        socket.read_exact(&mut end)?;
        if &end != b"\r\n0\r\n\r\n" {
            return Err(std::io::Error::other("fixture chunk terminator"));
        }
        return Ok(head);
    }
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
fn http_fixture(
    address: SocketAddr,
    cancel_reply: bool,
    already: bool,
    fail_readback: bool,
    framing: Framing,
    observe: bool,
    changed: bool,
    setup_preflight: bool,
    destination: Ipv4Addr,
    revoke: Option<Arc<std::sync::atomic::AtomicBool>>,
    reported_port: Option<(Arc<std::sync::atomic::AtomicU16>, u8)>,
    handoff_success: bool,
    readback_mode: u8,
) -> std::io::Result<()> {
    let target_body = format!(r#"{{"controller":{{"addr":"{destination}"}}}}"#);
    let mut socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    socket.set_read_timeout(Some(Duration::from_secs(8)))?;
    let handoff_routes = [
        "POST /api/1.1/login ",
        "GET /api/1.1/status ",
        "GET /api/1.1/settings ",
        "PUT /api/1.1/settings ",
        "GET /api/1.1/settings ",
    ];
    let observe_routes = [
        "POST /api/1.1/login ",
        "GET /api/1.1/status ",
        "GET /api/1.1/settings ",
        "GET /api/1.1/settings ",
    ];
    let setup_routes = [
        "POST /api/1.1/login ",
        "GET /api/1.1/status ",
        "GET /api/1.1/settings ",
        "GET /api/1.1/settings ",
        "PUT /api/1.1/settings ",
        "GET /api/1.1/settings ",
    ];
    let double_read = observe || setup_preflight;
    let handoff_index = if setup_preflight { 4 } else { 3 };
    let routes: &[&str] = if observe {
        &observe_routes
    } else if setup_preflight {
        &setup_routes
    } else {
        &handoff_routes
    };
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
        if index == handoff_index && !observe && !request.ends_with(target_body.as_bytes()) {
            return Err(std::io::Error::other("fixture handoff mismatch"));
        }
        if index == handoff_index && !observe {
            let chunked = request
                .windows(b"\r\nTransfer-Encoding: chunked\r\n".len())
                .any(|window| window == b"\r\nTransfer-Encoding: chunked\r\n");
            if chunked != (framing == Framing::Chunked) {
                return Err(std::io::Error::other("fixture wrong handoff framing"));
            }
        }
        if index == handoff_index && !observe && cancel_reply {
            let mut b = [0u8; 1];
            return if socket.read(&mut b)? == 0 {
                Ok(())
            } else {
                Err(std::io::Error::other("fixture expected closure"))
            };
        }
        if index == handoff_index + 1 && fail_readback {
            return Ok(());
        }
        let status_body = reported_port.as_ref().map(|(port, mode)| {
            let port = port.load(std::sync::atomic::Ordering::Acquire);
            match mode {
                1 => format!(
                    r#"{{"controller":{{"port":{}}}}}"#,
                    if port == u16::MAX { port - 1 } else { port + 1 }
                ),
                2 => "{}".to_owned(),
                _ => format!(r#"{{"controller":{{"port":{port}}}}}"#),
            }
        });
        let body: &[u8] = match index {
            1 if status_body.is_some() => status_body.as_deref().unwrap_or("{}").as_bytes(),
            2 if already => target_body.as_bytes(),
            2 => br#"{"controller":{"addr":"192.168.1.10"}}"#,
            3 if double_read && changed => br#"{"controller":{"addr":"192.168.1.99"}}"#,
            3 if double_read && already => target_body.as_bytes(),
            3 if double_read => br#"{"controller":{"addr":"192.168.1.10"}}"#,
            i if i == handoff_index && handoff_success => br#"{"success":true}"#,
            i if i == handoff_index => {
                br#"{"success":false,"statusCode":17,"secret":"fixture-private"}"#
            }
            i if i == handoff_index + 1 && readback_mode == 1 => {
                br#"{"controller":{"addr":"192.168.1.10"}}"#
            }
            i if i == handoff_index + 1 && readback_mode == 2 => {
                br#"{"controller":{"addr":"192.168.1.99"}}"#
            }
            i if i == handoff_index + 1 => target_body.as_bytes(),
            _ => b"{}",
        };
        let cookie = if index == 0 {
            "Set-Cookie: authId=fixture-cookie\r\n"
        } else {
            ""
        };
        if index == 3 && double_read {
            if let Some(policy) = &revoke {
                policy.store(false, std::sync::atomic::Ordering::Release);
            }
        }
        let header = format!(
            "HTTP/1.1 200 OK\r\n{cookie}Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            body.len()
        );
        socket.write_all(header.as_bytes())?;
        socket.write_all(body)?;
        if index == 1 && reported_port.as_ref().is_some_and(|(_, mode)| *mode != 0) {
            let mut byte = [0u8; 1];
            return if socket.read(&mut byte)? == 0 {
                Ok(())
            } else {
                Err(std::io::Error::other(
                    "port mismatch allowed another request",
                ))
            };
        }
        if index == 2 && already && !double_read {
            return Ok(());
        }
        if index == 3 && double_read && revoke.is_some() {
            let mut byte = [0u8; 1];
            return if socket.read(&mut byte)? == 0 {
                Ok(())
            } else {
                Err(std::io::Error::other("revoked listener allowed a write"))
            };
        }
        if index == 3 && double_read && (already || changed) {
            if changed && setup_preflight && !observe {
                let mut byte = [0u8; 1];
                return if socket.read(&mut byte)? == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::other(
                        "changing settings caused an unexpected write",
                    ))
                };
            }
            return Ok(());
        }
    }
    Ok(())
}
fn owned_http_handoff(cancel_reply: bool, framing: Framing) -> Test {
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
    } = harness_with_framing(
        if framing == Framing::Chunked {
            "http-chunked"
        } else {
            suffix
        },
        framing,
    )?;
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
                    let peer = std::thread::spawn(move || {
                        http_fixture(
                            address,
                            cancel_reply,
                            false,
                            false,
                            framing,
                            false,
                            false,
                            false,
                            Ipv4Addr::new(192, 168, 1, 40),
                            None,
                            None,
                            false,
                            0,
                        )
                    });
                    let (socket, _) =
                        timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                    let clock = MeteredClock::new(task, cx, TimestampNs(6))?;
                    let resource = plan.resource();
                    let io = MeteredIo::with_clock(socket, clock, &resource, 4096)?;
                    let http_access = HttpAccess {
                        handoff: Cell::new(true),
                    };
                    let mut owner = camera_http::Owner::new(
                        io,
                        task,
                        cx,
                        clock,
                        &http_access,
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
                    http_access.handoff.set(false);
                    let denied_by_owner = owner
                        .dispatch_handoff(
                            &plan,
                            conditions,
                            denied.permit,
                            &Guard(true),
                            Duration::from_secs(5),
                        )
                        .await
                        .expect_err("HTTP owner policy must refuse");
                    assert_eq!(denied_by_owner.reason, HandoffError::Denied);
                    http_access.handoff.set(true);
                    let mut permit = match owner
                        .dispatch_handoff(
                            &plan,
                            conditions,
                            denied_by_owner.permit,
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
    owned_http_handoff(false, Framing::ContentLength)
}
#[test]
fn cancelled_owned_http_handoff_reply_fences_session() -> Test {
    owned_http_handoff(true, Framing::ContentLength)
}
#[test]
fn owned_http_handoff_uses_chunked_framing_end_to_end() -> Test {
    owned_http_handoff(false, Framing::Chunked)
}

struct SetupAdmission {
    allowed: Cell<bool>,
    camera: ContentDigest,
    admission: ContentDigest,
    fence: u64,
}
impl fss_reference::unifi_direct::setup::Admission for SetupAdmission {
    fn permits(
        &self,
        candidate: &fss_reference::unifi_direct::discovery::CameraCandidate,
        camera: ContentDigest,
        peer_admission: ContentDigest,
        generation: u64,
        fence: u64,
    ) -> bool {
        self.allowed.get()
            && candidate.platform() == "UVC G4 Instant"
            && candidate.source().ip().is_loopback()
            && camera == self.camera
            && peer_admission == self.admission
            && generation == 1
            && fence == self.fence
    }
}
struct SetupHttpAccess;
impl camera_http::Authority for SetupHttpAccess {
    fn permits(&self, peer: Ipv4Addr, generation: u64, _: camera_http::Operation) -> bool {
        peer.is_loopback() && generation == 1
    }
}
struct SetupApproval;
impl fss_reference::unifi_direct::conversation::Approval for SetupApproval {
    fn approve(&self, prepared: &fss_runtime::effect::PreparedEffect) -> Option<CommitApproval> {
        Some(CommitApproval {
            prepared_digest: prepared.digest(),
            current_precondition_digest: prepared.precondition_digest(),
        })
    }
}
fn discovery_packet() -> Vec<u8> {
    let mac = [0x10u8, 2, 3, 4, 5, 6];
    let address = [0x10u8, 2, 3, 4, 5, 6, 127, 0, 0, 1];
    let mut body = Vec::new();
    for (kind, value) in [
        (1, mac.as_slice()),
        (2, address.as_slice()),
        (3, b"UVC.fixture".as_slice()),
        (12, b"UVC G4 Instant".as_slice()),
    ] {
        body.push(kind);
        body.extend_from_slice(&(value.len() as u16).to_be_bytes());
        body.extend_from_slice(value);
    }
    let mut packet = vec![1, 0];
    packet.extend_from_slice(&(body.len() as u16).to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}
fn run_discovered_setup(
    cancel_reply: bool,
    already: bool,
    fail_readback: bool,
    framing: Framing,
    observe: bool,
    changed: bool,
) -> Test {
    run_discovered_setup_with_listener(
        cancel_reply,
        already,
        fail_readback,
        framing,
        observe,
        changed,
        None,
        0,
        false,
        0,
    )
}

struct ReadyPolicy(Arc<std::sync::atomic::AtomicBool>);
impl fss_reference::unifi_direct::listener::Admission for ReadyPolicy {
    fn listener(&self, _: std::net::SocketAddrV4, _: Option<std::net::SocketAddrV4>) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
    fn peer(&self, _: std::net::SocketAddrV4, _: std::net::SocketAddrV4) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
}

fn run_discovered_setup_with_listener(
    cancel_reply: bool,
    already: bool,
    fail_readback: bool,
    framing: Framing,
    observe: bool,
    changed: bool,
    ready: Option<(Ipv4Addr, bool)>,
    port_mode: u8,
    drop_future: bool,
    integrated_mode: u8,
) -> Test {
    use fss_reference::unifi_direct::{controller_listener, discovery, setup};
    static SETUP_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let destination = ready.map_or(Ipv4Addr::new(192, 168, 1, 40), |value| value.0);
    let revoked = ready.is_some_and(|value| value.1);
    let live = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let advertised_port = Arc::new(std::sync::atomic::AtomicU16::new(0));
    let path = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
        "fss-unifi-setup-{}-{cancel_reply}-{already}-{fail_readback}-{framing:?}-{observe}-{changed}-{}",
        std::process::id(),
        SETUP_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir(&path)?;
    let _temp = Temp(path.clone());
    let store = FileEffectJournal::create(
        path.join("journal"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
    )?;
    let mut effects = EffectCoordinator::with_journal(Box::new(store))?;
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 2_000_000;
    budget.bytes = 2_000_000;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:setup-fixture".into(),
            operation_id: OperationId::parse("operation:setup-owner")?,
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
            anchor_universe: ContentDigest::sha256(b"setup fixture"),
            generation: 1,
        },
        RegionId::new("region:setup-fixture")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let camera = ContentDigest::sha256(b"verified synthetic camera");
    let peer_admission = ContentDigest::sha256(b"fixture admission");
    let resource = format!("camera:{}", camera.to_text());
    let mut leases = LeaseRegistry::new();
    let fence = leases
        .acquire(&resource, authority.region().as_str(), None, TimestampNs(2))?
        .fence;
    let leases = RefCell::new(leases);
    let operation = OperationId::parse("operation:setup-fixture")?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime context")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:setup-fixture")?,
                started_at: TimestampNs(3),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let udp = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
                    udp.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let address = match udp.local_addr()? {
                        SocketAddr::V4(v) => v,
                        _ => return Err("fixture is not IPv4".into()),
                    };
                    let sender = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut input = [0u8; 32];
                        let (_, peer) = udp.recv_from(&mut input)?;
                        udp.send_to(&discovery_packet(), peer)?;
                        Ok(())
                    });
                    let clock = MeteredClock::new(task, cx, TimestampNs(4))?;
                    let config = discovery::Config::new(
                        Ipv4Addr::LOCALHOST,
                        8,
                        address,
                        "fixture:discovery",
                        Duration::from_millis(120),
                        8,
                    )?;
                    let mut report = discovery::discover(task, cx, clock.now()?, &config).await?;
                    sender.join().map_err(|_| "discovery fixture panic")??;
                    assert_eq!(report.cameras.len(), 1);
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let revoke_policy = revoked.then(|| Arc::clone(&live));
                    let port_claim = ready.map(|_| (Arc::clone(&advertised_port), port_mode));
                    let peer = std::thread::spawn(move || {
                        http_fixture(
                            address,
                            cancel_reply,
                            already,
                            fail_readback,
                            framing,
                            observe,
                            changed,
                            true,
                            destination,
                            revoke_policy,
                            port_claim,
                            matches!(integrated_mode, 5 | 6 | 8 | 9),
                            if integrated_mode == 8 { 1 } else if integrated_mode == 9 { 2 } else { 0 },
                        )
                    });
                    let (socket, _) =
                        timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                    let io = MeteredIo::with_clock(socket, clock, &resource, 4096)?;
                    let mut http = camera_http::Owner::new(
                        io,
                        task,
                        cx,
                        clock,
                        &SetupHttpAccess,
                        Ipv4Addr::LOCALHOST,
                        1,
                        &resource,
                    )?;
                    let admission = SetupAdmission {
                        allowed: Cell::new(false),
                        camera,
                        admission: peer_admission,
                        fence,
                    };
                    let mut owner = setup::Owner {
                        cx,
                        task,
                        clock,
                        effects: &mut effects,
                        leases: &leases,
                        approval: &SetupApproval,
                        admission: &admission,
                        handoff_authority: &Guard(true),
                    };
                    macro_rules! config {
                        ($report:expr) => {
                            setup::Config {
                                report: $report,
                                index: 0,
                                camera,
                                peer_admission,
                                generation: 1,
                                fence,
                                destination,
                                operation: &operation,
                                credential: br#"{"username":"fixture","password":"synthetic"}"#,
                                wait: Duration::from_secs(5),
                            }
                        };
                    }
                    assert!(matches!(
                        owner.run(&mut http, &config!(&report)).await,
                        Err(setup::Error::Denied)
                    ));
                    if observe {
                        assert!(matches!(
                            owner.observe(&mut http, &config!(&report)).await,
                            Err(setup::Error::Denied)
                        ));
                    }
                    assert_eq!(http.phase(), Phase::Login);
                    admission.allowed.set(true);
                    report.stop = discovery::Stop::PacketLimit;
                    assert!(matches!(
                        owner.run(&mut http, &config!(&report)).await,
                        Err(setup::Error::Claims)
                    ));
                    if observe {
                        assert!(matches!(
                            owner.observe(&mut http, &config!(&report)).await,
                            Err(setup::Error::Claims)
                        ));
                    }
                    assert_eq!(http.phase(), Phase::Login);
                    report.stop = discovery::Stop::WindowElapsed;
                    if drop_future {
                        let mut trace = setup::Trace::default();
                        let cfg = config!(&report);
                        let result = timeout(
                            cx.now(),
                            Duration::from_millis(1000),
                            owner.run_with_framing_tracked(&mut http, &cfg, framing, &mut trace),
                        )
                        .await;
                        assert!(
                            result.is_err(),
                            "fixture should withhold the handoff response"
                        );
                        assert_eq!(trace.operation(), Some(&operation));
                        assert!(trace.dispatch_started());
                        assert_eq!(trace.response(), None);
                        let permit = trace
                            .take_permit()
                            .ok_or("cancelled setup lost its permit")?;
                        assert_eq!(permit.operation(), &operation);
                        assert_eq!(http.phase(), Phase::Fenced);
                        drop(http);
                        peer.join().map_err(|_| "HTTP fixture panic")??;
                        return Ok(());
                    }
                    if observe {
                        let result = owner.observe(&mut http, &config!(&report)).await;
                        if changed {
                            assert!(matches!(result, Err(setup::Error::Changed)));
                        } else {
                            let observed = result?;
                            let expected = if already { 40 } else { 10 };
                            assert_eq!(
                                observed.settings.controller,
                                ControllerAddress::Reported(Ipv4Addr::new(192, 168, 1, expected))
                            );
                        }
                        drop(http);
                        peer.join().map_err(|_| "HTTP fixture panic")??;
                        return Ok(());
                    }
                    let result = if ready.is_some() {
                        let policy = ReadyPolicy(Arc::clone(&live));
                        let mut control = controller_listener::Listener::bind(
                            task,
                            cx,
                            clock,
                            &policy,
                            std::net::SocketAddrV4::new(destination, 0),
                            &resource,
                            Duration::from_secs(5),
                        )
                        .await
                        .map_err(|error| format!("controller listener bind: {error:?}"))?;
                        let port = control.local_addr().port();
                        advertised_port.store(port, std::sync::atomic::Ordering::Release);
                        assert!(matches!(
                            owner
                                .run_when_listening(
                                    &control,
                                    0,
                                    &mut http,
                                    &config!(&report),
                                    framing
                                )
                                .await,
                            Err(setup::Error::ControllerUnavailable)
                        ));
                        let wrong_port = if port == u16::MAX { port - 1 } else { port + 1 };
                        assert!(matches!(
                            owner
                                .run_when_listening(
                                    &control,
                                    wrong_port,
                                    &mut http,
                                    &config!(&report),
                                    framing
                                )
                                .await,
                            Err(setup::Error::ControllerUnavailable)
                        ));
                        let wrong_destination = setup::Config {
                            destination: Ipv4Addr::LOCALHOST,
                            ..config!(&report)
                        };
                        assert!(matches!(
                            owner
                                .run_when_listening(
                                    &control,
                                    port,
                                    &mut http,
                                    &wrong_destination,
                                    framing
                                )
                                .await,
                            Err(setup::Error::ControllerUnavailable)
                        ));
                        assert_eq!(http.phase(), Phase::Login);
                        live.store(false, std::sync::atomic::Ordering::Release);
                        assert!(matches!(
                            owner
                                .run_when_listening(
                                    &control,
                                    port,
                                    &mut http,
                                    &config!(&report),
                                    framing
                                )
                                .await,
                            Err(setup::Error::ControllerUnavailable)
                        ));
                        assert_eq!(http.phase(), Phase::Login);
                        live.store(true, std::sync::atomic::Ordering::Release);
                        if integrated_mode != 0 {
                            let mut trace = setup::AcceptTrace::default();
                            let client = if matches!(integrated_mode, 1 | 4 | 6 | 8) {
                                let socket = asupersync::net::TcpSocket::new_v4()?;
                                let source = if integrated_mode == 4 { Ipv4Addr::new(127, 0, 0, 2) } else { Ipv4Addr::LOCALHOST };
                                socket.bind(SocketAddr::V4(std::net::SocketAddrV4::new(source, 0)))?;
                                Some(
                                    timeout(
                                        cx.now(),
                                        Duration::from_secs(5),
                                        socket.connect(SocketAddr::V4(control.local_addr())),
                                    )
                                    .await??,
                                )
                            } else {
                                None
                            };
                            let cfg = config!(&report);
                            if integrated_mode == 7 {
                                let interrupted = timeout(
                                    cx.now(), Duration::from_secs(1),
                                    owner.setup_and_accept(
                                        &mut control, port, &mut http, &cfg, framing, 4096,
                                        Duration::from_secs(5), &mut trace,
                                    ),
                                ).await;
                                assert!(interrupted.is_err(), "fixture should withhold the handoff response");
                                assert!(!trace.accept_started());
                                assert!(trace.outcome().is_none());
                                let setup_trace = trace.setup_mut();
                                assert!(setup_trace.dispatch_started());
                                let permit = setup_trace.take_permit().ok_or("cancelled setup lost its permit")?;
                                assert_eq!(permit.operation(), &operation);
                                drop(interrupted);
                                assert_eq!(http.phase(), Phase::Fenced);
                                drop(http);
                                peer.join().map_err(|_| "HTTP fixture panic")??;
                                return Ok(());
                            }
                            if integrated_mode == 5 {
                                let interrupted = timeout(
                                    cx.now(), Duration::from_secs(1),
                                    owner.setup_and_accept(
                                        &mut control, port, &mut http, &cfg, framing, 4096,
                                        Duration::from_secs(5), &mut trace,
                                    ),
                                ).await;
                                assert!(interrupted.is_err(), "fixture should cancel during accept");
                                assert!(trace.accept_started());
                                match trace.take_outcome() {
                                    Some(setup::Outcome::Observed { permit, readback, .. }) => {
                                        assert_eq!(permit.operation(), &operation);
                                        assert_eq!(readback, fss_reference::unifi_direct::handoff::Readback::Requested);
                                    }
                                    _ => return Err("cancelled accept lost committed handoff".into()),
                                }
                                drop(interrupted);
                                drop(http);
                                peer.join().map_err(|_| "HTTP fixture panic")??;
                                return Ok(());
                            }
                            let result = owner
                                .setup_and_accept(
                                    &mut control,
                                    port,
                                    &mut http,
                                    &cfg,
                                    framing,
                                    4096,
                                    if integrated_mode == 3 {
                                        Duration::from_millis(100)
                                    } else {
                                        Duration::from_secs(5)
                                    },
                                    &mut trace,
                                )
                                .await;
                            match integrated_mode {
                                1 => {
                                    let accepted =
                                        result.map_err(|e| format!("integrated accept: {e:?}"))?;
                                    assert_eq!(*accepted.gate.source().ip(), Ipv4Addr::LOCALHOST);
                                    assert!(trace.accept_started());
                                    assert!(matches!(
                                        trace.take_outcome(),
                                        Some(setup::Outcome::AlreadyAssociated { .. })
                                    ));
                                    drop(accepted);
                                }
                                2 => {
                                    assert!(matches!(result, Err(setup::AcceptError::Unconfirmed)));
                                    assert!(!trace.accept_started());
                                    assert!(matches!(
                                        trace.take_outcome(),
                                        Some(setup::Outcome::Observed {
                                            response: HandoffResponseObservation::Object {
                                                success: Some(false),
                                                ..
                                            },
                                            ..
                                        })
                                    ));
                                }
                                3 => {
                                    assert!(matches!(result, Err(setup::AcceptError::Listener(_))));
                                    assert!(trace.accept_started());
                                    assert!(matches!(
                                        trace.take_outcome(),
                                        Some(setup::Outcome::AlreadyAssociated { .. })
                                    ));
                                }
                                4 => {
                                    assert!(matches!(result, Err(setup::AcceptError::PeerMismatch)));
                                    assert!(trace.accept_started());
                                    assert!(matches!(trace.take_outcome(), Some(setup::Outcome::AlreadyAssociated { .. })));
                                }
                                6 => {
                                    let accepted = result.map_err(|e| format!("integrated handoff accept: {e:?}"))?;
                                    assert_eq!(*accepted.gate.source().ip(), Ipv4Addr::LOCALHOST);
                                    assert!(trace.accept_started());
                                    match trace.take_outcome() {
                                        Some(setup::Outcome::Observed { permit, readback, .. }) => {
                                            assert_eq!(permit.operation(), &operation);
                                            assert_eq!(readback, fss_reference::unifi_direct::handoff::Readback::Requested);
                                        }
                                        _ => return Err("successful accept lost committed handoff".into()),
                                    }
                                    drop(accepted);
                                }
                                8 => {
                                    let accepted = result.map_err(|e| format!("previous-readback accept: {e:?}"))?;
                                    assert_eq!(*accepted.gate.source().ip(), Ipv4Addr::LOCALHOST);
                                    assert!(trace.accept_started());
                                    match trace.take_outcome() {
                                        Some(setup::Outcome::Observed { permit, readback, .. }) => {
                                            assert_eq!(permit.operation(), &operation);
                                            assert_eq!(readback, fss_reference::unifi_direct::handoff::Readback::Previous);
                                        }
                                        _ => return Err("previous-readback accept lost its unresolved handoff".into()),
                                    }
                                    drop(accepted);
                                }
                                9 => {
                                    assert!(matches!(result, Err(setup::AcceptError::Unconfirmed)));
                                    assert!(!trace.accept_started());
                                    match trace.take_outcome() {
                                        Some(setup::Outcome::Observed { permit, readback, .. }) => {
                                            assert_eq!(permit.operation(), &operation);
                                            assert_eq!(readback, fss_reference::unifi_direct::handoff::Readback::Different);
                                        }
                                        _ => return Err("different readback lost its unresolved handoff".into()),
                                    }
                                }
                                _ => return Err("unknown integrated test mode".into()),
                            }
                            drop(client);
                            drop(http);
                            peer.join().map_err(|_| "HTTP fixture panic")??;
                            return Ok(());
                        }
                        let outcome = owner
                            .run_when_listening(
                                &control,
                                port,
                                &mut http,
                                &config!(&report),
                                framing,
                            )
                            .await;
                        if port_mode != 0 {
                            assert!(matches!(outcome, Err(setup::Error::ControllerPort)));
                            drop(http);
                            peer.join().map_err(|_| "HTTP fixture panic")??;
                            return Ok(());
                        }
                        if !revoked {
                            if let Err(error) = &outcome {
                                return Err(format!("listener-bound setup: {error:?}").into());
                            }
                            let address = SocketAddr::V4(control.local_addr());
                            let client = asupersync::net::TcpSocket::new_v4()?;
                            client.bind(SocketAddr::V4(std::net::SocketAddrV4::new(
                                Ipv4Addr::LOCALHOST,
                                0,
                            )))?;
                            let client =
                                timeout(cx.now(), Duration::from_secs(5), client.connect(address))
                                    .await??;
                            let source = client.local_addr()?;
                            let source_is_local = match source {
                                SocketAddr::V4(addr) => {
                                    addr.ip().is_private()
                                        || addr.ip().is_loopback()
                                        || addr.ip().is_link_local()
                                }
                                _ => false,
                            };
                            assert!(
                                source_is_local,
                                "fixture source is not a permitted local address"
                            );
                            assert!(
                                live.load(std::sync::atomic::Ordering::Acquire),
                                "listener policy revoked before accept"
                            );
                            let (_accepted, _gate) = control
                                .accept_next(4096, Duration::from_secs(5))
                                .await
                                .map_err(|error| {
                                    format!("controller listener accept: {error:?}")
                                })?;
                            drop(client);
                        }
                        outcome
                    } else {
                        owner
                            .run_with_framing(&mut http, &config!(&report), framing)
                            .await
                    };
                    if revoked {
                        assert!(matches!(result, Err(setup::Error::Denied)));
                        drop(http);
                        peer.join().map_err(|_| "HTTP fixture panic")??;
                        return Ok(());
                    }
                    if changed {
                        assert!(matches!(result, Err(setup::Error::Changed)));
                        drop(http);
                        peer.join().map_err(|_| "HTTP fixture panic")??;
                        return Ok(());
                    }
                    let outcome = result?;
                    match outcome {
                        setup::Outcome::AlreadyAssociated { observation, .. } if already => {
                            assert_eq!(
                                observation.controller,
                                ControllerAddress::Reported(destination)
                            );
                            assert_eq!(http.phase(), Phase::Snapshot);
                        }
                        setup::Outcome::Observed {
                            readback,
                            response,
                            permit,
                            ..
                        } if !cancel_reply && !already && !fail_readback => {
                            assert_eq!(
                                readback,
                                fss_reference::unifi_direct::handoff::Readback::Requested
                            );
                            assert_eq!(
                                response,
                                HandoffResponseObservation::Object {
                                    success: Some(false),
                                    status_code: Some(17)
                                }
                            );
                            assert_eq!(permit.operation(), &operation);
                        }
                        setup::Outcome::Indeterminate {
                            stage,
                            response,
                            permit,
                        } if cancel_reply => {
                            assert_eq!(stage, setup::Indeterminate::Response);
                            assert_eq!(response, None);
                            assert_eq!(permit.operation(), &operation);
                            assert_eq!(http.phase(), Phase::Fenced);
                        }
                        setup::Outcome::Indeterminate {
                            stage,
                            response,
                            permit,
                        } if fail_readback => {
                            assert_eq!(stage, setup::Indeterminate::Readback);
                            assert_eq!(
                                response,
                                Some(HandoffResponseObservation::Object {
                                    success: Some(false),
                                    status_code: Some(17)
                                })
                            );
                            assert_eq!(permit.operation(), &operation);
                            assert_eq!(http.phase(), Phase::Fenced);
                        }
                        _ => return Err("unexpected setup outcome".into()),
                    }
                    drop(http);
                    peer.join().map_err(|_| "HTTP fixture panic")??;
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok()
                    && (already || observe || changed || revoked || port_mode != 0)
                {
                    TaskOutcome::Success
                } else if output.is_ok() {
                    TaskOutcome::Indeterminate("effect requires reconciliation".into())
                } else {
                    TaskOutcome::Failed("setup fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(599_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
    })?;
    let journal_entry = effects.journal().operation(&operation);
    if already || observe || changed || revoked || port_mode != 0 {
        assert!(journal_entry.is_none());
    } else {
        assert_eq!(
            journal_entry.ok_or("missing journal operation")?.state,
            fss_core::EffectState::Committed
        );
    }
    Ok(())
}

#[test]
fn cancelled_setup_response_retains_permit_in_caller_trace() -> Test {
    run_discovered_setup_with_listener(
        true,
        false,
        false,
        Framing::ContentLength,
        false,
        false,
        None,
        0,
        true,
        0,
    )
}
#[test]
fn discovered_candidate_runs_owned_setup_through_journal_and_readback() -> Test {
    run_discovered_setup(false, false, false, Framing::ContentLength, false, false)
}
#[test]
fn discovered_setup_uses_authorized_chunked_handoff() -> Test {
    run_discovered_setup(false, false, false, Framing::Chunked, false, false)
}
#[test]
fn discovered_setup_reply_timeout_preserves_committed_obligation() -> Test {
    run_discovered_setup(true, false, false, Framing::ContentLength, false, false)
}

#[test]
fn discovered_setup_already_associated_does_not_prepare_an_effect() -> Test {
    run_discovered_setup(false, true, false, Framing::ContentLength, false, false)
}

#[test]
fn discovered_setup_retains_response_if_readback_is_interrupted() -> Test {
    run_discovered_setup(false, false, true, Framing::ContentLength, false, false)
}

#[test]
fn discovered_camera_observation_never_writes_for_either_controller() -> Test {
    run_discovered_setup(false, false, false, Framing::ContentLength, true, false)?;
    run_discovered_setup(false, true, false, Framing::ContentLength, true, false)
}

#[test]
fn discovered_camera_observation_refuses_changing_settings_without_effect() -> Test {
    run_discovered_setup(false, false, false, Framing::ContentLength, true, true)
}

#[test]
fn discovered_setup_refuses_changed_controller_before_effect_or_write() -> Test {
    run_discovered_setup(false, false, false, Framing::ContentLength, false, true)?;
    run_discovered_setup(false, true, false, Framing::ContentLength, false, true)
}

/// Requires a private IPv4 address assigned to an isolated test worker.
#[test]
#[ignore = "requires FSS_TEST_CONTROLLER_BIND_IP on the test worker"]
fn discovered_setup_requires_current_bound_controller_listener() -> Test {
    let ip: Ipv4Addr = std::env::var("FSS_TEST_CONTROLLER_BIND_IP")?.parse()?;
    if !(ip.is_private() || ip.is_link_local()) || ip == Ipv4Addr::new(192, 168, 1, 10) {
        return Err("test controller interface is not a suitable private address".into());
    }
    run_discovered_setup_with_listener(
        false,
        false,
        false,
        Framing::ContentLength,
        false,
        false,
        Some((ip, false)),
        0,
        false,
        0,
    )?;
    run_discovered_setup_with_listener(
        false,
        false,
        false,
        Framing::ContentLength,
        false,
        false,
        Some((ip, true)),
        0,
        false,
        0,
    )?;
    for mode in [1, 2] {
        run_discovered_setup_with_listener(
            false,
            false,
            false,
            Framing::ContentLength,
            false,
            false,
            Some((ip, false)),
            mode,
            false,
            0,
        )?;
    }
    Ok(())
}

/// Exercises the full setup-to-accept boundary on an isolated worker.
#[test]
#[ignore = "requires FSS_TEST_CONTROLLER_BIND_IP on the test worker"]
fn setup_accept_retains_outcome_across_handoff_and_accept_boundaries() -> Test {
    let ip: Ipv4Addr = std::env::var("FSS_TEST_CONTROLLER_BIND_IP")?.parse()?;
    if !(ip.is_private() || ip.is_link_local())
        || ip == Ipv4Addr::new(192, 168, 1, 10)
        || ip == Ipv4Addr::new(192, 168, 1, 99)
    {
        return Err("test controller interface is not a suitable private address".into());
    }
    for mode in 1..=9 {
        run_discovered_setup_with_listener(
            mode == 7,
            !matches!(mode, 2 | 5 | 6 | 7 | 8 | 9),
            false,
            Framing::ContentLength,
            false,
            false,
            Some((ip, false)),
            0,
            false,
            mode,
        )?;
    }
    Ok(())
}
