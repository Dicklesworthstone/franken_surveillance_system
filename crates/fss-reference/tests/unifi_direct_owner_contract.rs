#![forbid(unsafe_code)]
//! Bounded owned HTTP upgrade and refusal behavior.

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
    Controller, Identity, Observation,
    metered::{MeteredClock, MeteredIo},
    owner::{self, Error, PeerAdmission},
    receive::Step,
    upgrade::ProtocolPolicy,
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use std::{
    cell::Cell,
    error::Error as StdError,
    future::{Future, poll_fn},
    io::{self, Read, Write},
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};

type TestResult = Result<(), Box<dyn StdError>>;
const HEAD: &str = "GET / HTTP/1.1\r\nHost: camera.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCamera-Mac: 001122aabbcc\r\nSec-WebSocket-Protocol: secure_transfer\r\n\r\n";
const HELLO: &[u8] = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_hello","messageId":7,"payload":{}}"#;

struct Policy(bool);
impl PeerAdmission for Policy {
    fn permits(&self, claim: [u8; 6]) -> bool {
        self.0 && claim == [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]
    }
}
fn controller() -> Result<Controller, Box<dyn StdError>> {
    Ok(Controller::new(
        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
        1,
    )?)
}
fn root() -> Result<(AuthorityCx, fss_core::RegionTree), Box<dyn StdError>> {
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    Ok(AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:owner-upgrade".into(),
            operation_id: OperationId::parse("operation:owner-upgrade")?,
            principal: "principal:fixture".into(),
            capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"upgrade owner fixture"),
            generation: 1,
        },
        RegionId::new("region:owner-upgrade")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?)
}
fn frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mask = [1_u8, 2, 3, 4];
    let mut out = vec![0x82, 0x80 | payload.len() as u8];
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

#[test]
fn native_upgrade_preserves_pipelined_hello() -> TestResult {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut owner, mut tree) = root()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:owner-upgrade")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: TestResult = async {
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let client = std::thread::spawn(move || -> io::Result<()> {
                        let mut socket =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                        socket.write_all(&HEAD.as_bytes()[..19])?;
                        let mut rest = HEAD.as_bytes()[19..].to_vec();
                        rest.extend(frame(HELLO));
                        socket.write_all(&rest)?;
                        let mut response = Vec::new();
                        let mut buffer = [0_u8; 512];
                        while !response.windows(4).any(|w| w == b"\r\n\r\n") {
                            let count = socket.read(&mut buffer)?;
                            if count == 0 || response.len() + count > 4096 {
                                return Err(io::Error::other("incomplete response"));
                            }
                            response.extend_from_slice(&buffer[..count]);
                        }
                        if !response.starts_with(b"HTTP/1.1 101 ") {
                            return Err(io::Error::other("bad response"));
                        }
                        Ok(())
                    });
                    let (socket, _) =
                        timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                    let io =
                        MeteredIo::new(socket, task, cx, TimestampNs(3), "fixture:camera", 4096)?;
                    let mut session = owner::accept(
                        io,
                        ProtocolPolicy::RequireOffer,
                        &Policy(true),
                        controller()?,
                        Duration::from_secs(5),
                    )
                    .await?;
                    assert_eq!(
                        session.next(Duration::from_secs(3)).await?,
                        Step::Observation(Observation::Hello)
                    );
                    client.join().map_err(|_| "fixture client panic")??;
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("upgrade fixture failed".into())
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

struct Fixture {
    bytes: Vec<u8>,
    offset: usize,
    writes: Rc<Cell<usize>>,
    dropped: Rc<Cell<bool>>,
    stall_write: bool,
    stall_read: bool,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.dropped.set(true);
    }
}
impl AsyncRead for Fixture {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.stall_read {
            return Poll::Pending;
        }
        let count = out.remaining().min(self.bytes.len() - self.offset);
        out.put_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Fixture {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.stall_write && self.writes.get() > 0 {
            return Poll::Pending;
        }
        let count = if self.stall_write {
            input.len().min(1)
        } else {
            input.len()
        };
        self.writes.set(self.writes.get() + count);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn denied_invalid_timeout_and_cancel_retire_without_reuse() -> TestResult {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let (mut owner, mut tree) = root()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:owner-refusals")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: TestResult = async {
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    for (bytes, permit, stall_write, stall_read, expected) in [
                        (
                            HEAD.as_bytes().to_vec(),
                            false,
                            false,
                            false,
                            Error::PeerDenied,
                        ),
                        (
                            vec![b'x'; 16 * 1024],
                            true,
                            false,
                            false,
                            Error::Request(
                                fss_reference::unifi_direct::upgrade::Error::InvalidRequest,
                            ),
                        ),
                        (Vec::new(), true, false, true, Error::RequestTimeout),
                        (
                            HEAD.as_bytes().to_vec(),
                            true,
                            true,
                            false,
                            Error::ResponseIndeterminate,
                        ),
                    ] {
                        let writes = Rc::new(Cell::new(0));
                        let dropped = Rc::new(Cell::new(false));
                        let fixture = Fixture {
                            bytes,
                            offset: 0,
                            writes: writes.clone(),
                            dropped: dropped.clone(),
                            stall_write,
                            stall_read,
                        };
                        let io = MeteredIo::with_clock(fixture, clock, "fixture:camera", 4096)?;
                        let result = owner::accept(
                            io,
                            ProtocolPolicy::RequireOffer,
                            &Policy(permit),
                            controller()?,
                            Duration::from_millis(30),
                        )
                        .await;
                        assert!(matches!(result, Err(error) if error == expected));
                        assert!(dropped.get());
                        assert_eq!(writes.get(), usize::from(stall_write));
                    }
                    let writes = Rc::new(Cell::new(0));
                    let dropped = Rc::new(Cell::new(false));
                    let fixture = Fixture {
                        bytes: HEAD.as_bytes().to_vec(),
                        offset: 0,
                        writes: writes.clone(),
                        dropped: dropped.clone(),
                        stall_write: true,
                        stall_read: false,
                    };
                    let io = MeteredIo::with_clock(fixture, clock, "fixture:camera", 4096)?;
                    let policy = Policy(true);
                    let mut future = Box::pin(owner::accept(
                        io,
                        ProtocolPolicy::RequireOffer,
                        &policy,
                        controller()?,
                        Duration::from_secs(5),
                    ));
                    poll_fn(|cx| {
                        assert!(matches!(future.as_mut().poll(cx), Poll::Pending));
                        Poll::Ready(())
                    })
                    .await;
                    assert_eq!(writes.get(), 1);
                    drop(future);
                    assert!(dropped.get());
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("upgrade refusal fixture failed".into())
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
