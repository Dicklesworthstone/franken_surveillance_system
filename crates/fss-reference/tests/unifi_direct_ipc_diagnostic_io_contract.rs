#![forbid(unsafe_code)]
//! Native loopback and cancellation checks for experimental diagnostic I/O.

use asupersync::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    runtime::RuntimeBuilder,
    time::timeout,
};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::{
    camera_http, ipc_diagnostic, ipc_diagnostic_io,
    metered::{MeteredClock, MeteredIo},
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use std::{
    cell::{Cell, RefCell},
    error::Error,
    future::{Future, poll_fn},
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};

type Test = Result<(), Box<dyn Error>>;
const RESOURCE: &str = "fixture:diagnostic";
const RESPONSE: &[u8] = br#"{"from":"ubnt_streamer","functionName":"__response__","requestId":123,"statusCode":0,"to":"fss_fixture","payload":{"synthetic":true}}"#;

struct Access(bool);
impl camera_http::Authority for Access {
    fn permits(&self, peer: Ipv4Addr, generation: u64, operation: camera_http::Operation) -> bool {
        self.0
            && peer.is_loopback()
            && generation == 1
            && operation == camera_http::Operation::SettingsSerializers
    }
}

struct RevokeOnThirdPoll(Cell<usize>);
impl camera_http::Authority for RevokeOnThirdPoll {
    fn permits(&self, _: Ipv4Addr, _: u64, _: camera_http::Operation) -> bool {
        let next = self.0.get() + 1;
        self.0.set(next);
        next < 3
    }
}

struct OversizedHeader {
    offset: usize,
}
impl AsyncRead for OversizedHeader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let header = u32::MAX.to_be_bytes();
        let n = (header.len() - self.offset).min(out.remaining());
        out.put_slice(&header[self.offset..self.offset + n]);
        self.offset += n;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for OversizedHeader {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct PendingSocket {
    written: Rc<RefCell<Vec<u8>>>,
}
impl AsyncRead for PendingSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for PendingSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written.borrow_mut().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn request() -> Result<ipc_diagnostic::Request, ipc_diagnostic::Error> {
    ipc_diagnostic::Request::new("fss_fixture", 123, "2026-11-16T03:14:22Z")
}

fn server(address: SocketAddr, expected: Vec<u8>) -> io::Result<()> {
    let mut stream = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut actual = vec![0; expected.len()];
    stream.read_exact(&mut actual)?;
    if actual != expected {
        return Err(io::Error::other("unexpected request"));
    }
    let mut frame = (RESPONSE.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(RESPONSE);
    for part in frame.chunks(3) {
        stream.write_all(part)?;
    }
    Ok(())
}

#[test]
fn native_exchange_authority_and_cancel_fence() -> Test {
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1024 * 1024;
    let (mut root, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:diagnostic-io".into(),
            operation_id: OperationId::parse("operation:diagnostic-io")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::ObserveStatus.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"diagnostic fixture"),
            generation: 1,
        },
        RegionId::new("region:diagnostic-io")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("runtime context")?;
        let result = run_owned_async(
            &mut root,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:diagnostic-io")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let expected = request()?.bytes().to_vec();
                    let peer = std::thread::spawn(move || server(address, expected));
                    let (socket, _) =
                        timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                    let io = MeteredIo::with_clock(socket, clock, RESOURCE, 4096)?;
                    let allowed = Access(true);
                    let mut owner = ipc_diagnostic_io::Owner::new(
                        io,
                        task,
                        cx,
                        clock,
                        &allowed,
                        Ipv4Addr::LOCALHOST,
                        1,
                        RESOURCE,
                    )?;
                    let response = owner.observe(&request()?, Duration::from_secs(5)).await?;
                    assert_eq!(response.status(), 0);
                    assert!(owner.is_spent());
                    assert!(matches!(
                        owner.observe(&request()?, Duration::from_secs(5)).await,
                        Err(ipc_diagnostic_io::Error::Spent)
                    ));
                    peer.join().map_err(|_| "fixture thread panicked")??;
                    drop(owner);

                    let written = Rc::new(RefCell::new(Vec::new()));
                    let io = MeteredIo::with_clock(
                        PendingSocket {
                            written: written.clone(),
                        },
                        clock,
                        RESOURCE,
                        4096,
                    )?;
                    let denied = Access(false);
                    let mut owner = ipc_diagnostic_io::Owner::new(
                        io,
                        task,
                        cx,
                        clock,
                        &denied,
                        Ipv4Addr::LOCALHOST,
                        1,
                        RESOURCE,
                    )?;
                    assert!(matches!(
                        owner.observe(&request()?, Duration::from_secs(5)).await,
                        Err(ipc_diagnostic_io::Error::Denied)
                    ));
                    assert!(written.borrow().is_empty());
                    assert!(owner.is_spent());
                    drop(owner);

                    let written = Rc::new(RefCell::new(Vec::new()));
                    let io = MeteredIo::with_clock(
                        PendingSocket {
                            written: written.clone(),
                        },
                        clock,
                        RESOURCE,
                        4,
                    )?;
                    let revoke = RevokeOnThirdPoll(Cell::new(0));
                    let mut owner = ipc_diagnostic_io::Owner::new(
                        io,
                        task,
                        cx,
                        clock,
                        &revoke,
                        Ipv4Addr::LOCALHOST,
                        1,
                        RESOURCE,
                    )?;
                    assert!(matches!(
                        owner.observe(&request()?, Duration::from_secs(5)).await,
                        Err(ipc_diagnostic_io::Error::Denied)
                    ));
                    assert_eq!(written.borrow().len(), 4);
                    assert!(owner.is_spent());
                    drop(owner);

                    let io = MeteredIo::with_clock(
                        OversizedHeader { offset: 0 },
                        clock,
                        RESOURCE,
                        4096,
                    )?;
                    let mut owner = ipc_diagnostic_io::Owner::new(
                        io,
                        task,
                        cx,
                        clock,
                        &allowed,
                        Ipv4Addr::LOCALHOST,
                        1,
                        RESOURCE,
                    )?;
                    assert!(matches!(
                        owner.observe(&request()?, Duration::from_secs(5)).await,
                        Err(ipc_diagnostic_io::Error::Protocol(
                            ipc_diagnostic::Error::InvalidInput
                        ))
                    ));
                    assert!(owner.is_spent());
                    drop(owner);

                    let written = Rc::new(RefCell::new(Vec::new()));
                    let io = MeteredIo::with_clock(
                        PendingSocket {
                            written: written.clone(),
                        },
                        clock,
                        RESOURCE,
                        4096,
                    )?;
                    let mut owner = ipc_diagnostic_io::Owner::new(
                        io,
                        task,
                        cx,
                        clock,
                        &allowed,
                        Ipv4Addr::LOCALHOST,
                        1,
                        RESOURCE,
                    )?;
                    let pending_request = request()?;
                    let mut pending =
                        Box::pin(owner.observe(&pending_request, Duration::from_secs(5)));
                    poll_fn(|context| {
                        assert!(pending.as_mut().poll(context).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    drop(pending);
                    assert!(!written.borrow().is_empty());
                    assert!(owner.is_spent());
                    assert!(matches!(
                        owner.observe(&request()?, Duration::from_secs(5)).await,
                        Err(ipc_diagnostic_io::Error::Spent)
                    ));
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("diagnostic fixture".into())
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
