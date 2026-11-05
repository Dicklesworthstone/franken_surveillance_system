#![forbid(unsafe_code)]
//! Task-owned camera HTTP over actual loopback and interruption controls.
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
    camera_api::{ControllerAddress, Phase},
    camera_http::{self, Operation},
    metered::{MeteredClock, MeteredIo},
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskCx, TaskSpec, run_owned_async},
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
const CREDENTIAL: &[u8] = br#"{"username":"fixture-user","password":"fixture-secret"}"#;
struct Access {
    calls: Cell<usize>,
    deny_at: Cell<usize>,
}
impl camera_http::Authority for Access {
    fn permits(&self, peer: Ipv4Addr, generation: u64, _: Operation) -> bool {
        let n = self.calls.get() + 1;
        self.calls.set(n);
        peer.is_loopback() && generation == 1 && n < self.deny_at.get()
    }
}
struct ClockedAccess<'scope, 'task> {
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
}
impl camera_http::Authority for ClockedAccess<'_, '_> {
    fn permits(&self, peer: Ipv4Addr, generation: u64, _: Operation) -> bool {
        peer.is_loopback()
            && generation == 1
            && self.clock.now().ok().is_some_and(|now| {
                self.task
                    .checkpoint_for(
                        RuntimeGrant::AdapterNet,
                        "fixture:camera",
                        now,
                        &BudgetVector::ZERO,
                    )
                    .is_ok()
            })
    }
}
fn read_request(socket: &mut std::net::TcpStream) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut byte = [0u8; 1];
    while !data.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut byte)?;
        data.push(byte[0]);
        if data.len() > 8192 {
            return Err(io::Error::other("request header too large"));
        }
    }
    let text = std::str::from_utf8(&data).map_err(io::Error::other)?;
    let length = text
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .map_or(Ok(0), str::parse::<usize>)
        .map_err(io::Error::other)?;
    if length > 4096 {
        return Err(io::Error::other("request body too large"));
    }
    let end = data.len() + length;
    data.resize(end, 0);
    socket.read_exact(&mut data[end - length..])?;
    Ok(data)
}
fn fixture(address: SocketAddr) -> io::Result<()> {
    let mut socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    for (index, (path, body)) in [
        ("POST /api/1.1/login ", b"{}".as_slice()),
        (
            "GET /api/1.1/status ",
            br#"{"board":{},"fw":{},"controller":{}}"#.as_slice(),
        ),
        (
            "GET /api/1.1/settings ",
            br#"{"controller":{"addr":"127.0.0.1"}}"#.as_slice(),
        ),
        ("GET /snap.jpeg ", [0xff, 0xd8, 0xff, 0xd9].as_slice()),
    ]
    .iter()
    .enumerate()
    {
        let request = read_request(&mut socket)?;
        if !request.starts_with(path.as_bytes()) {
            return Err(io::Error::other("unexpected request"));
        }
        if index == 0 && !request.ends_with(CREDENTIAL) {
            return Err(io::Error::other("unexpected credential"));
        }
        if index > 0
            && !request
                .windows(b"Cookie: authId=fixture-cookie".len())
                .any(|w| w == b"Cookie: authId=fixture-cookie")
        {
            return Err(io::Error::other("missing fixture cookie"));
        }
        let cookie = if index == 0 {
            "Set-Cookie: authId=fixture-cookie; Path=/\r\n"
        } else {
            ""
        };
        let mut response = format!(
            "HTTP/1.1 200 OK\r\n{cookie}Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        for part in response.chunks(13) {
            socket.write_all(part)?;
        }
    }
    Ok(())
}
struct FixedSocket {
    response: Vec<u8>,
    offset: usize,
}
impl AsyncRead for FixedSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = (self.response.len() - self.offset).min(out.remaining());
        out.put_slice(&self.response[self.offset..self.offset + n]);
        self.offset += n;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for FixedSocket {
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
    writes: Rc<RefCell<Vec<u8>>>,
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
        self.writes.borrow_mut().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[test]
fn owned_camera_http_sequences_and_fences_interruption() -> Test {
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 16 * 1024 * 1024;
    let (mut root, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:camera-http".into(),
            operation_id: OperationId::parse("operation:camera-http")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::AdapterAuth.as_str().into(),
                RuntimeGrant::ObserveStatus.as_str().into(),
                RuntimeGrant::ReadMedia.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"camera http fixture"),
            generation: 1,
        },
        RegionId::new("region:camera-http")?,
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
                task_id: TaskId::new("task:camera-http")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let peer = std::thread::spawn(move || fixture(address));
                    let (socket, _) =
                        timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let io = MeteredIo::with_clock(socket, clock, "fixture:camera", 4096)?;
                    let access = Access {
                        calls: Cell::new(0),
                        deny_at: Cell::new(usize::MAX),
                    };
                    let clocked_access = ClockedAccess { task, clock };
                    let mut owner = camera_http::Owner::new(
                        io,
                        task,
                        cx,
                        clock,
                        &clocked_access,
                        Ipv4Addr::LOCALHOST,
                        1,
                        "fixture:camera",
                    )?;
                    owner.login(CREDENTIAL, Duration::from_secs(5)).await?;
                    let status = owner.status(Duration::from_secs(5)).await?;
                    assert!(status.board && status.firmware && status.controller);
                    let settings = owner.settings(Duration::from_secs(5)).await?;
                    assert_eq!(
                        settings.controller,
                        ControllerAddress::Reported(Ipv4Addr::LOCALHOST)
                    );
                    let snapshot = owner.snapshot(Duration::from_secs(5)).await?;
                    assert_eq!(snapshot.bytes(), [0xff, 0xd8, 0xff, 0xd9]);
                    assert_eq!(owner.phase(), Phase::Snapshot);
                    peer.join().map_err(|_| "fixture peer panicked")??;
                    drop(owner);
                    let writes = Rc::new(RefCell::new(Vec::new()));
                    let io = MeteredIo::with_clock(
                        PendingSocket {
                            writes: writes.clone(),
                        },
                        clock,
                        "fixture:camera",
                        4096,
                    )?;
                    let mut owner = camera_http::Owner::new(
                        io,
                        task,
                        cx,
                        clock,
                        &access,
                        Ipv4Addr::LOCALHOST,
                        1,
                        "fixture:camera",
                    )?;
                    let unpolled = owner.login(CREDENTIAL, Duration::from_secs(5));
                    drop(unpolled);
                    assert!(writes.borrow().is_empty());
                    assert_eq!(owner.phase(), Phase::Login);
                    let mut login = Box::pin(owner.login(CREDENTIAL, Duration::from_secs(5)));
                    poll_fn(|cx| match login.as_mut().poll(cx) {
                        Poll::Pending => Poll::Ready(()),
                        Poll::Ready(_) => panic!("login should await response"),
                    })
                    .await;
                    drop(login);
                    assert!(writes.borrow().ends_with(CREDENTIAL));
                    assert_eq!(owner.phase(), Phase::Fenced);
                    assert!(matches!(
                        owner.status(Duration::from_secs(5)).await,
                        Err(camera_http::Error::Fenced)
                    ));
                    drop(owner);
                    let writes = Rc::new(RefCell::new(Vec::new()));
                    let io = MeteredIo::with_clock(
                        PendingSocket {
                            writes: writes.clone(),
                        },
                        clock,
                        "fixture:camera",
                        4096,
                    )?;
                    access.calls.set(0);
                    access.deny_at.set(3);
                    let mut owner = camera_http::Owner::new(
                        io,
                        task,
                        cx,
                        clock,
                        &access,
                        Ipv4Addr::LOCALHOST,
                        1,
                        "fixture:camera",
                    )?;
                    assert!(matches!(
                        owner.login(CREDENTIAL, Duration::from_secs(5)).await,
                        Err(camera_http::Error::Denied)
                    ));
                    assert!(!writes.borrow().is_empty());
                    assert_eq!(owner.phase(), Phase::Fenced);
                    drop(owner);
                    access.deny_at.set(usize::MAX);
                    for response in [
                        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".as_slice(),
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: authId=fixture-cookie\r\n\r\nextra".as_slice(),
                    ] {
                        let socket=FixedSocket { response:response.to_vec(),offset:0 };
                        let io=MeteredIo::with_clock(socket,clock,"fixture:camera",4096)?;
                        let mut owner=camera_http::Owner::new(io,task,cx,clock,&access,Ipv4Addr::LOCALHOST,1,"fixture:camera")?;
                        assert!(matches!(owner.login(CREDENTIAL,Duration::from_secs(5)).await,Err(camera_http::Error::Protocol)));
                        assert_eq!(owner.phase(),Phase::Fenced);
                    }
                    access.calls.set(0);access.deny_at.set(1);
                    let writes=Rc::new(RefCell::new(Vec::new()));
                    let io=MeteredIo::with_clock(PendingSocket {writes:writes.clone()},clock,"fixture:camera",4096)?;
                    let mut owner=camera_http::Owner::new(io,task,cx,clock,&access,Ipv4Addr::LOCALHOST,1,"fixture:camera")?;
                    assert!(matches!(owner.login(CREDENTIAL,Duration::from_secs(5)).await,Err(camera_http::Error::Denied)));
                    assert!(writes.borrow().is_empty());
                    assert_eq!(owner.phase(),Phase::Fenced);
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("camera http fixture".into())
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
