#![forbid(unsafe_code)]
//! Owned native socket and management-observation contracts.

use asupersync::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    runtime::RuntimeBuilder,
    time::timeout,
};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::{
    Controller, Dispatch, Identity, Observation, Phase,
    metered::{MeteredClock, MeteredIo},
    receive::{Error as ReceiveError, Session, Step, Stop, TransportFailure},
    upgrade::{PreparedUpgrade, ProtocolPolicy},
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use std::{
    error::Error,
    io::{Cursor, Read, Write},
    sync::mpsc,
    time::Duration,
};

type TestResult = Result<(), Box<dyn Error>>;
const HEAD: &str = "GET / HTTP/1.1\r\nHost: camera.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCamera-Mac: 001122aabbcc\r\nSec-WebSocket-Protocol: secure_transfer\r\n\r\n";

fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mask = [1_u8, 2, 3, 4];
    let mut result = vec![0x80 | opcode, 0x80 | payload.len() as u8];
    result.extend_from_slice(&mask);
    result.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    result
}

fn root() -> Result<(AuthorityCx, fss_core::RegionTree), Box<dyn Error>> {
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    let spec = RootAuthoritySpec {
        trace_id: "trace:receive".into(),
        operation_id: OperationId::parse("operation:receive")?,
        principal: "principal:fixture".into(),
        capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
        deadline: Some(TimestampNs(60_000_000_000)),
        priority: 10,
        budgets: budget,
        privacy_scope: "privacy:local".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"receive fixture"),
        generation: 1,
    };
    Ok(AuthorityCx::root(
        spec,
        RegionId::new("region:receive")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?)
}

#[test]
fn native_camera_hello_idle_and_close_preserve_unresolved_state() -> TestResult {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut owner, mut tree) = root()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(&mut owner, &mut tree, TaskSpec { task_id: TaskId::new("task:receive")?, started_at: TimestampNs(2) }, &cx, async |task, cx| {
            let output: Result<(), Box<dyn Error>> = async {
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let address = listener.local_addr()?;
                let (release, wait) = mpsc::channel();
                let client = std::thread::spawn(move || -> std::io::Result<()> {
                    let mut stream = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut request = HEAD.as_bytes().to_vec();
                    request.extend(frame(9, b"ok"));
                    request.extend(frame(2, br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_hello","messageId":7,"payload":{}}"#));
                    stream.write_all(&request)?;
                    let mut reply = Vec::new();
                    let mut chunk = [0_u8; 512];
                    loop {
                        let n = stream.read(&mut chunk)?;
                        if n == 0 || reply.len() + n > 2048 { return Err(std::io::Error::other("incomplete fixture response")); }
                        reply.extend_from_slice(&chunk[..n]);
                        if let Some(end) = reply.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
                            && reply.len() >= end + 4 {
                            if !reply.starts_with(b"HTTP/1.1 101 ") || reply[end..end + 4] != [0x8a, 2, b'o', b'k'] {
                                return Err(std::io::Error::other("missing upgrade response or pong"));
                            }
                            break;
                        }
                    }
                    wait.recv_timeout(Duration::from_secs(5)).map_err(std::io::Error::other)?;
                    stream.write_all(&frame(2, br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_timeSync","messageId":8,"payload":{}}"#))?;
                    Ok(())
                });
                let (stream, _) = timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                let mut io = MeteredIo::new(stream, task, cx, TimestampNs(3), "fixture:camera", 4096)?;
                let mut request = Vec::new();
                let mut buf = [0_u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = timeout(cx.now(), Duration::from_secs(5), io.read(&mut buf)).await??;
                    if n == 0 || request.len() + n > 4096 { return Err("incomplete request".into()); }
                    request.extend_from_slice(&buf[..n]);
                }
                let prepared = PreparedUpgrade::parse(&request, ProtocolPolicy::RequireOffer)?;
                timeout(cx.now(), Duration::from_secs(5), io.write_all(prepared.response_bytes())).await??;
                let controller = Controller::new(Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?, 1)?;
                let mut session = Session::from_upgrade(prepared, io, Dispatch::Written, controller)?;
                assert_eq!(session.claimed_mac(), [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]);
                assert_eq!(session.next(Duration::ZERO).await, Err(ReceiveError::WaitLimit));
                assert_eq!(session.next(Duration::from_secs(2)).await?, Step::Observation(Observation::Hello));
                assert_eq!(session.phase(), Phase::HelloObserved);
                assert_eq!(session.next(Duration::from_millis(50)).await?, Step::WaitElapsed);
                release.send(())?;
                assert_eq!(session.next(Duration::from_secs(2)).await?, Step::Observation(Observation::TimeSyncRequested));
                let stopped = session.next(Duration::from_secs(2)).await?;
                match stopped {
                    Step::Retired { reason: Stop::PeerClosed, controller } => {
                        assert_eq!(controller.previous_phase, Phase::HelloObserved);
                        assert_eq!(controller.hello_request_id, Some(7));
                        assert_eq!(controller.time_sync_request_id, Some(8));
                    }
                    _ => return Err("expected peer close and unresolved hello".into()),
                }
                assert_eq!(session.next(Duration::from_millis(1)).await, Err(ReceiveError::Retired));
                client.join().map_err(|_| "fixture client panicked")??;
                Ok(())
            }.await;
            let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("receive fixture failed".into()) };
            TaskCompletion { output, outcome, completed_at: TimestampNs(59_000_000_000) }
        }).await?;
        result.receipt?;
        result.output
    })
}

#[test]
fn malformed_management_data_retires_without_reflecting_payload() -> TestResult {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut owner, mut tree) = root()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:receive-invalid")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Result<(), Box<dyn Error>> = async {
                    let mut request = HEAD.as_bytes().to_vec();
                    request.extend(frame(2, b"PRIVATE_CAMERA_VALUE is not JSON"));
                    let prepared = PreparedUpgrade::parse(&request, ProtocolPolicy::RequireOffer)?;
                    let io = MeteredIo::new(
                        Cursor::new(Vec::new()),
                        task,
                        cx,
                        TimestampNs(3),
                        "fixture:camera",
                        4096,
                    )?;
                    let controller = Controller::new(
                        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
                        1,
                    )?;
                    let mut session =
                        Session::from_upgrade(prepared, io, Dispatch::Written, controller)?;
                    let step = session.next(Duration::from_secs(1)).await?;
                    assert!(matches!(
                        step,
                        Step::Retired {
                            reason: Stop::Protocol(fss_reference::unifi_direct::Error::InvalidJson),
                            ..
                        }
                    ));
                    assert!(!format!("{step:?} {session:?}").contains("PRIVATE_CAMERA_VALUE"));
                    assert_eq!(
                        session.next(Duration::from_millis(1)).await,
                        Err(ReceiveError::Retired)
                    );
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("invalid fixture failed".into())
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
    })
}

#[test]
fn transport_retirement_distinguishes_wire_errors_without_leaking_details() -> TestResult {
    use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    struct ResetIo;
    impl AsyncRead for ResetIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "PRIVATE_TRANSPORT_DETAIL",
            )))
        }
    }
    impl AsyncWrite for ResetIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut owner, mut tree) = root()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:receive-wire-failures")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Result<(), Box<dyn Error>> = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    for (unmasked, expected) in [
                        (true, TransportFailure::UnmaskedClientFrame),
                        (false, TransportFailure::Io(io::ErrorKind::ConnectionReset)),
                    ] {
                        let mut request = HEAD.as_bytes().to_vec();
                        if unmasked {
                            request.extend_from_slice(&[0x82, 1, b'x']);
                        }
                        let prepared =
                            PreparedUpgrade::parse(&request, ProtocolPolicy::RequireOffer)?;
                        let io = MeteredIo::with_clock(ResetIo, clock, "fixture:camera", 4096)?;
                        let controller = Controller::new(
                            Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
                            1,
                        )?;
                        let mut session =
                            Session::from_upgrade(prepared, io, Dispatch::Written, controller)?;
                        let step = session.next(Duration::from_secs(1)).await?;
                        match step {
                            Step::Retired {
                                reason: Stop::TransportDetail(actual),
                                controller,
                            } => {
                                assert_eq!(actual, expected);
                                assert_eq!(controller.previous_phase, Phase::AwaitHello);
                            }
                            other => return Err(format!("unexpected retirement: {other:?}").into()),
                        }
                        assert!(
                            !format!("{step:?} {session:?}").contains("PRIVATE_TRANSPORT_DETAIL")
                        );
                        assert_eq!(
                            session.next(Duration::from_millis(1)).await,
                            Err(ReceiveError::Retired)
                        );
                    }
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("transport failure fixture failed".into())
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
    })
}

#[test]
fn permitless_management_dispatch_is_refused_without_writing() -> TestResult {
    use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
    use fss_reference::unifi_direct::{MessageKind, receive::DispatchAuthority};
    use std::{
        cell::RefCell,
        pin::Pin,
        rc::Rc,
        task::{Context, Poll},
    };
    struct Allow;
    impl DispatchAuthority for Allow {
        fn permits(&self, _: [u8; 6], _: u64, _: MessageKind) -> bool {
            true
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
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut owner, mut tree) = root()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(&mut owner,&mut tree,TaskSpec {task_id:TaskId::new("task:permitless-refused")?,started_at:TimestampNs(2)},&cx,async |task,cx| {
            let output:TestResult=async {
                let bytes=Rc::new(RefCell::new(Vec::new()));
                let io=MeteredIo::new(Sink(bytes.clone()),task,cx,TimestampNs(3),"fixture:camera",4096)?;
                let upgrade=PreparedUpgrade::parse(HEAD.as_bytes(),ProtocolPolicy::RequireOffer)?;
                let mut controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
                controller.observe(br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_hello","messageId":7,"payload":{}}"#)?;
                let mut session=Session::from_upgrade(upgrade,io,Dispatch::Written,controller)?;
                session.prepare_hello("2026-11-05T10:00:00.000Z")?;
                assert_eq!(session.dispatch(&Allow,Duration::from_secs(1)).await,Err(ReceiveError::JournalRequired));
                assert!(bytes.borrow().is_empty());
                assert_eq!(session.phase(),Phase::HelloObserved);
                Ok(())
            }.await;
            let outcome=if output.is_ok(){TaskOutcome::Success}else{TaskOutcome::Failed("permitless fixture failed".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(59_000_000_000)}
        }).await?;
        result.receipt?;result.output
    })
}

#[test]
fn permitless_management_stays_silent_on_loopback() -> TestResult {
    use fss_reference::unifi_direct::{
        MessageKind,
        owner::{self, PeerAdmission},
        receive::DispatchAuthority,
    };
    struct Allow;
    impl DispatchAuthority for Allow {
        fn permits(&self, _: [u8; 6], _: u64, _: MessageKind) -> bool {
            true
        }
    }
    impl PeerAdmission for Allow {
        fn permits(&self, _: [u8; 6]) -> bool {
            true
        }
    }
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut owner_context, mut tree) = root()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut owner_context,&mut tree,TaskSpec {task_id:TaskId::new("task:permitless-loopback")?,started_at:TimestampNs(2)},&cx,async |task,cx| {
            let output:TestResult=async {
                let listener=TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
                let client=std::thread::spawn(move || -> std::io::Result<()> {
                    let mut stream=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut request=HEAD.as_bytes().to_vec();request.extend(frame(2,br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_hello","messageId":7,"payload":{}}"#));
                    stream.write_all(&request)?;let mut response=Vec::new();let mut one=[0_u8;1];
                    while !response.ends_with(b"\r\n\r\n") { stream.read_exact(&mut one)?; response.push(one[0]);if response.len()>4096{return Err(std::io::Error::other("oversized upgrade"));} }
                    if !response.starts_with(b"HTTP/1.1 101 "){return Err(std::io::Error::other("upgrade failed"));}
                    if stream.read(&mut one)? != 0 {return Err(std::io::Error::other("unexpected management bytes"));}
                    Ok(())
                });
                let (stream,_)=timeout(cx.now(),Duration::from_secs(5),listener.accept()).await??;
                let io=MeteredIo::new(stream,task,cx,TimestampNs(3),"fixture:camera",4096)?;
                let controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
                let mut session=owner::accept(io,ProtocolPolicy::RequireOffer,&Allow,controller,Duration::from_secs(5)).await?;
                assert_eq!(session.next(Duration::from_secs(2)).await?,Step::Observation(Observation::Hello));
                session.prepare_hello("2026-11-05T10:00:00.000Z")?;
                assert_eq!(session.dispatch(&Allow,Duration::from_secs(2)).await,Err(ReceiveError::JournalRequired));
                let retirement=session.retire();assert_eq!(retirement.previous_phase,Phase::HelloObserved);client.join().map_err(|_|"fixture client panic")??;
                Ok(())
            }.await;
            let outcome=if output.is_ok(){TaskOutcome::Success}else{TaskOutcome::Failed("permitless loopback failed".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(59_000_000_000)}
        }).await?;
        result.receipt?;result.output
    })
}

#[test]
fn startup_event_backpressure_preserves_sources_after_retirement() -> TestResult {
    use fss_reference::unifi_direct::{
        MAX_MESSAGE_BYTES, events,
        owner::{self, PeerAdmission},
    };
    struct Allow;
    impl PeerAdmission for Allow {
        fn permits(&self, _: [u8; 6]) -> bool {
            true
        }
    }
    const FIRST:&[u8]=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventSmartMotion","messageId":8}"#;
    const SECOND:&[u8]=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"EventAnalytics","messageId":9}"#;
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut owner_context, mut tree) = root()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner_context,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:startup-inbox")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: TestResult = async {
                    let inbox = events::StartupInbox::new(1, MAX_MESSAGE_BYTES)?;
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let client = std::thread::spawn(move || -> std::io::Result<()> {
                        let mut stream =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                        let mut request = HEAD.as_bytes().to_vec();
                        request.extend(frame(2, FIRST));
                        request.extend(frame(2, SECOND));
                        stream.write_all(&request)?;
                        let mut response = Vec::new();
                        let mut one = [0u8; 1];
                        while !response.ends_with(b"\r\n\r\n") {
                            stream.read_exact(&mut one)?;
                            response.push(one[0]);
                            if response.len() > 4096 {
                                return Err(std::io::Error::other("upgrade limit"));
                            }
                        }
                        match stream.read(&mut one) {
                            Ok(0) => Ok(()),
                            other => {
                                Err(std::io::Error::other(format!("expected close: {other:?}")))
                            }
                        }
                    });
                    let (stream, _) =
                        timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                    let io =
                        MeteredIo::new(stream, task, cx, TimestampNs(3), "fixture:camera", 4096)?;
                    let controller = Controller::new(
                        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
                        1,
                    )?;
                    let mut session = owner::accept(
                        io,
                        ProtocolPolicy::RequireOffer,
                        &Allow,
                        controller,
                        Duration::from_secs(5),
                    )
                    .await?;
                    session.bind_startup_events(&inbox)?;
                    assert_eq!(
                        session.bind_startup_events(&inbox),
                        Err(ReceiveError::Denied)
                    );
                    assert_eq!(
                        session.next(Duration::from_secs(2)).await?,
                        Step::Observation(Observation::Other)
                    );
                    assert_eq!(inbox.len(), 1);
                    assert_eq!(
                        session.next(Duration::from_secs(2)).await?,
                        Step::StartupEventBackpressure
                    );
                    let first = inbox.take().ok_or("first event missing")?;
                    assert_eq!(first.source(), FIRST);
                    assert_eq!(
                        session.next(Duration::from_secs(2)).await?,
                        Step::Observation(Observation::Other)
                    );
                    assert_eq!(inbox.len(), 1);
                    let _ = session.retire();
                    let second = inbox.take().ok_or("second event missing after retire")?;
                    assert_eq!(second.source(), SECOND);
                    assert!(inbox.is_empty());
                    client.join().map_err(|_| "fixture client panicked")??;
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("startup inbox fixture failed".into())
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
    })
}
