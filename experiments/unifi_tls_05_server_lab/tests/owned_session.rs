#![forbid(unsafe_code)]
#![cfg(unix)]
//! Observe a fixture hello, then durably prepare its response inside the task.
//! The journal calls here are synchronous, not a production async store.
use asupersync::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    runtime::RuntimeBuilder,
    time::timeout,
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
    Controller, Identity, Observation,
    management::{Intent, Preconditions},
    metered::{MeteredClock, MeteredIo},
    owner::{self, PeerAdmission},
    receive::{ManagementAuthority, ManagementWrite, Step},
    upgrade::ProtocolPolicy,
};
use fss_runtime::{
    authority::AuthorityCx,
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PrepareSpec},
    execution::{TaskCompletion, TaskSpec, run_owned_async},
    lease::LeaseRegistry,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use std::{
    cell::{Cell, RefCell},
    error::Error,
    future::{Future, poll_fn},
    io::{self, Read, Write},
    path::PathBuf,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use unifi_tls_05_server_lab::server::Server;

type Test = Result<(), Box<dyn Error>>;
const HEAD: &str = "GET / HTTP/1.1\r\nHost: camera.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCamera-Mac: 001122aabbcc\r\nSec-WebSocket-Protocol: secure_transfer\r\n\r\n";
const HELLO:&[u8]=br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_hello","messageId":7,"payload":{}}"#;
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct FixtureAdmission;
impl PeerAdmission for FixtureAdmission {
    fn permits(&self, claim: [u8; 6]) -> bool {
        claim == [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]
    }
}
struct Gate<IO> {
    inner: IO,
    armed: Rc<Cell<bool>>,
    wrote: Rc<Cell<bool>>,
}
impl<IO: AsyncRead + Unpin> AsyncRead for Gate<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}
impl<IO: AsyncWrite + Unpin> AsyncWrite for Gate<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.armed.get() && self.wrote.get() {
            return Poll::Pending;
        }
        let gated = self.armed.get();
        let input = if gated {
            &input[..input.len().min(1)]
        } else {
            input
        };
        let result = Pin::new(&mut self.inner).poll_write(cx, input);
        if gated && matches!(result,Poll::Ready(Ok(n)) if n>0) {
            self.wrote.set(true);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
struct Guard<'a, 'scope, 'task> {
    leases: &'a RefCell<LeaseRegistry>,
    clock: MeteredClock<'scope, 'task>,
}
impl ManagementAuthority for Guard<'_, '_, '_> {
    fn permits(&self, mac: [u8; 6], intent: Intent, permit: &CommittedEffect) -> bool {
        let Ok(now) = self.clock.now() else {
            return false;
        };
        mac == [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]
            && permit.fence() == intent.fence()
            && self
                .leases
                .borrow_mut()
                .check_fence(&intent.resource(), intent.fence(), now)
                .is_ok()
    }
}
fn frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mask = [1, 2, 3, 4];
    let mut bytes = vec![0x82, 0x80 | payload.len() as u8];
    bytes.extend_from_slice(&mask);
    bytes.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    bytes
}

fn observed_hello_case(interrupt: bool) -> Test {
    let cert = std::fs::read(std::env::var("FSS_LAB_CERT_DER")?)?;
    let key = std::fs::read(std::env::var("FSS_LAB_KEY_DER")?)?;
    if cert.is_empty() || cert.len() > 8192 || key.is_empty() || key.len() > 8192 {
        return Err("invalid fixture sizes".into());
    }
    let provider = Arc::new(rustls_pure::provider());
    let server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert))?;
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let path = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
        "fss-unifi-task-effect-{}-{interrupt}",
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
            trace_id: "trace:task-unifi".into(),
            operation_id: OperationId::parse("operation:camera-task-owner")?,
            principal: "principal:fixture".into(),
            capabilities: vec![
                RuntimeGrant::AdapterNet.as_str().into(),
                RuntimeGrant::CameraManagementCommit.as_str().into(),
                RuntimeGrant::CameraManagementPrepare.as_str().into(),
            ],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"fixture"),
            generation: 1,
        },
        RegionId::new("region:task-unifi")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let camera = ContentDigest::sha256(b"verified fixture camera");
    let resource = format!("camera:{}", camera.to_text());
    let mut leases = LeaseRegistry::new();
    let fence = leases
        .acquire(&resource, authority.region().as_str(), None, TimestampNs(2))?
        .fence;
    let leases = Rc::new(RefCell::new(leases));
    let conditions = Preconditions {
        camera,
        peer_admission: ContentDigest::sha256(b"fixture admission"),
        session_generation: 1,
        previous_association: None,
        previous_clock: None,
        lease_fence: fence,
    };
    let operation = OperationId::parse("operation:fixture-observed-hello")?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx=asupersync::Cx::current().ok_or("missing runtime")?;
        let result=run_owned_async(&mut authority,&mut tree,TaskSpec {task_id:TaskId::new("task:unifi-live-fixture")?,started_at:TimestampNs(3)},&cx,async |task,cx| {
            let output:Test=async {
                let listener=TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
                let peer=std::thread::spawn(move || -> io::Result<()> {
                    let raw=std::net::TcpStream::connect_timeout(&address,Duration::from_secs(5))?;raw.set_read_timeout(Some(Duration::from_secs(5)))?;raw.set_write_timeout(Some(Duration::from_secs(5)))?;
                    let connection=ClientConnection::new(Arc::new(client_config),ServerName::try_from("localhost").map_err(io::Error::other)?).map_err(io::Error::other)?;
                    let mut socket=StreamOwned::new(connection,raw);
                    let mut request=HEAD.as_bytes().to_vec();request.extend(frame(HELLO));socket.write_all(&request)?;socket.flush()?;
                    let mut header=Vec::new();let mut byte=[0_u8;1];
                    while !header.ends_with(b"\r\n\r\n") {socket.read_exact(&mut byte)?;header.push(byte[0]);if header.len()>4096{return Err(io::Error::other("upgrade limit"));}}
                    if !header.starts_with(b"HTTP/1.1 101 "){return Err(io::Error::other("upgrade refused"));}
                    if interrupt {
                        let mut h=[0_u8;2];
                        return match socket.read_exact(&mut h) {
                            Err(error) if error.kind()==io::ErrorKind::UnexpectedEof=>Ok(()),
                            _=>Err(io::Error::other("interrupted TLS frame was delivered")),
                        };
                    }
                    let mut h=[0_u8;2];socket.read_exact(&mut h)?;if h[0]!=0x82||h[1]&0x80!=0{return Err(io::Error::other("not binary"));}
                    let len=match h[1] { n@0..=125=>usize::from(n),126=>{let mut x=[0_u8;2];socket.read_exact(&mut x)?;usize::from(u16::from_be_bytes(x))},_=>return Err(io::Error::other("frame size"))};
                    if len>4096{return Err(io::Error::other("message bound"));}let mut payload=vec![0;len];socket.read_exact(&mut payload)?;
                    if !payload.windows(b"ubnt_avclient_hello".len()).any(|w|w==b"ubnt_avclient_hello"){return Err(io::Error::other("wrong message"));}
                    Ok(())
                });
                let (socket,_)=timeout(cx.now(),Duration::from_secs(5),listener.accept()).await??;
                let clock=MeteredClock::new(task,cx,TimestampNs(4))?;
                let raw=MeteredIo::with_clock(socket,clock,"fixture:camera",37)?;
                let armed=Rc::new(Cell::new(false));let wrote=Rc::new(Cell::new(false));
                let gate=Gate {inner:raw,armed:armed.clone(),wrote:wrote.clone()};
                let tls=timeout(cx.now(),Duration::from_secs(5),Server::new(ServerConnection::new(Arc::new(server_config))?,gate).handshake(cx)).await??;
                let io=MeteredIo::with_clock(tls,clock,"fixture:camera",4096)?;
                let controller=Controller::new(Identity::new("FSS","12345678-1234-4abc-9abc-123456789abc","1.20.0")?,1)?;
                let mut session=owner::accept(io,ProtocolPolicy::RequireOffer,&FixtureAdmission,controller,Duration::from_secs(5)).await?;
                assert_eq!(session.next(Duration::from_secs(3)).await?,Step::Observation(Observation::Hello));
                session.prepare_hello("2026-11-05T10:00:00.000Z")?;
                let intent=session.management_intent(conditions)?;
                let prepared=task.prepare_effect(cx,&mut effects,&mut leases.borrow_mut(),PrepareSpec {
                    operation:&operation,idempotency_key:IdempotencyKey::parse(operation.as_str())?,request_digest:intent.request_digest(),precondition_digest:intent.precondition_digest(),resource:&resource,fence,
                    prepare_grant:RuntimeGrant::CameraManagementPrepare,commit_grant:RuntimeGrant::CameraManagementCommit,terminal_predicate:"independent association observation or reconciliation",
                },clock.now()?)?;
                let approval=CommitApproval {prepared_digest:prepared.digest(),current_precondition_digest:intent.precondition_digest()};
                let permit=task.commit_effect(cx,&mut effects,&mut leases.borrow_mut(),prepared,clock.now()?,approval)?;
                assert!(permit.journal_backed());
                let guard=Guard {leases:&leases,clock};
                if interrupt {
                    armed.set(true);
                    let mut write=Box::pin(session.dispatch_management(intent,conditions,permit,&guard,Duration::from_secs(3)));
                    timeout(cx.now(),Duration::from_secs(5),poll_fn(|context| match write.as_mut().poll(context) {Poll::Pending if wrote.get()=>Poll::Ready(()),Poll::Pending=>Poll::Pending,Poll::Ready(_)=>panic!("ciphertext write should park")})).await?;
                    assert!(wrote.get());
                    drop(write);
                    assert_eq!(session.phase(),fss_reference::unifi_direct::Phase::Indeterminate);
                    assert!(matches!(session.next(Duration::from_secs(1)).await?,Step::Retired {reason:fss_reference::unifi_direct::receive::Stop::IndeterminateWrite,..}));
                    peer.join().map_err(|_|"fixture peer panic")??;
                    return Ok(());
                }
                let result=session.dispatch_management(intent,conditions,permit,&guard,Duration::from_secs(3)).await.map_err(|_|"management dispatch refused")?;
                assert!(matches!(result,ManagementWrite::Written {..}));
                peer.join().map_err(|_|"fixture peer panic")??;
                let retirement=session.retire();assert_eq!(retirement.previous_phase,fss_reference::unifi_direct::Phase::AwaitAgreementPreparation);
                Ok(())
            }.await;
            let outcome=if output.is_ok(){TaskOutcome::Indeterminate("fixture association needs reconciliation".into())}else{TaskOutcome::Failed("task effect fixture failed".into())};
            TaskCompletion {output,outcome,completed_at:TimestampNs(59_000_000_000)}
        }).await?;
        result.receipt?;result.output
    })?;
    assert_eq!(
        effects
            .journal()
            .operation(&operation)
            .ok_or("missing journal operation")?
            .state,
        fss_core::EffectState::Committed
    );
    assert!(!authority.finalize_report(&tree)?.is_empty());
    Ok(())
}

#[test]
#[ignore = "requires disposable cert and key fixture paths"]
fn observed_hello_gets_its_own_durable_permit_inside_task() -> Test {
    observed_hello_case(false)
}

#[test]
#[ignore = "requires disposable cert and key fixture paths"]
fn interrupted_ciphertext_write_fences_the_session() -> Test {
    observed_hello_case(true)
}

#[test]
#[ignore = "requires disposable cert and key fixture paths"]
fn silent_peer_timeout_drops_the_owned_tls_transport() -> Test {
    let cert = std::fs::read(std::env::var("FSS_LAB_CERT_DER")?)?;
    let key = std::fs::read(std::env::var("FSS_LAB_KEY_DER")?)?;
    let provider = Arc::new(rustls_pure::provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )?;
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:tls-timeout-fixture".into(),
            operation_id: OperationId::parse("operation:tls-timeout-fixture")?,
            principal: "principal:fixture".into(),
            capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
            deadline: Some(TimestampNs(30_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"fixture"),
            generation: 1,
        },
        RegionId::new("region:tls-timeout-fixture")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:tls-timeout")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let peer = std::thread::spawn(move || -> io::Result<()> {
                        let mut socket =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
                        let mut byte = [0u8; 1];
                        if socket.read(&mut byte)? != 0 {
                            return Err(io::Error::other("expected EOF"));
                        }
                        Ok(())
                    });
                    let (socket, _) =
                        timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let raw = MeteredIo::with_clock(socket, clock, "fixture:camera", 37)?;
                    let handshake =
                        Server::new(ServerConnection::new(Arc::new(config))?, raw).handshake(cx);
                    if timeout(cx.now(), Duration::from_millis(150), handshake)
                        .await
                        .is_ok()
                    {
                        return Err("silent peer handshake did not time out".into());
                    }
                    peer.join().map_err(|_| "silent peer panic")??;
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("timeout fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(29_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
    })
}

#[test]
#[ignore = "requires disposable cert and key fixture paths"]
fn untrusted_server_certificate_never_opens_the_session() -> Test {
    let cert = std::fs::read(std::env::var("FSS_LAB_CERT_DER")?)?;
    let key = std::fs::read(std::env::var("FSS_LAB_KEY_DER")?)?;
    let provider = Arc::new(rustls_pure::provider());
    let config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )?;
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:tls-untrusted-fixture".into(),
            operation_id: OperationId::parse("operation:tls-untrusted-fixture")?,
            principal: "principal:fixture".into(),
            capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
            deadline: Some(TimestampNs(30_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"fixture"),
            generation: 1,
        },
        RegionId::new("region:tls-untrusted-fixture")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:tls-untrusted")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let peer = std::thread::spawn(move || -> io::Result<()> {
                        let raw =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                        raw.set_read_timeout(Some(Duration::from_secs(5)))?;
                        raw.set_write_timeout(Some(Duration::from_secs(5)))?;
                        let connection = ClientConnection::new(
                            Arc::new(client),
                            ServerName::try_from("localhost").map_err(io::Error::other)?,
                        )
                        .map_err(io::Error::other)?;
                        let mut tls = StreamOwned::new(connection, raw);
                        if tls.write_all(b"must-not-reach-server").is_ok() {
                            return Err(io::Error::other("untrusted certificate was accepted"));
                        }
                        Ok(())
                    });
                    let (socket, _) =
                        timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let raw = MeteredIo::with_clock(socket, clock, "fixture:camera", 37)?;
                    let handshake =
                        Server::new(ServerConnection::new(Arc::new(config))?, raw).handshake(cx);
                    if timeout(cx.now(), Duration::from_secs(5), handshake)
                        .await?
                        .is_ok()
                    {
                        return Err("untrusted session opened".into());
                    }
                    peer.join().map_err(|_| "untrusted peer panic")??;
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("untrusted certificate fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: TimestampNs(29_000_000_000),
                }
            },
        )
        .await?;
        run.receipt?;
        run.output
    })
}
