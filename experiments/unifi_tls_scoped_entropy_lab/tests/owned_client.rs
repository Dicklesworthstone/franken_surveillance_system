#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
//! Task-owned client using local disposable TLS peer, not a physical camera.
use asupersync::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    runtime::RuntimeBuilder,
    time::timeout,
};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::metered::{MeteredClock, MeteredIo};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use fss_unifi_scoped_tls_entropy_lab::owned::client::Session;
use rustls::{
    ClientConfig, NamedGroup, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    crypto::{ActiveKeyExchange, GetRandomFailed, SecureRandom, SupportedKxGroup},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use std::{
    error::Error,
    io::{self, Read, Write},
    sync::Arc,
    time::Duration,
};
type Test = Result<(), Box<dyn Error>>;
#[derive(Debug)]
struct ForbiddenRandom;
impl SecureRandom for ForbiddenRandom {
    fn fill(&self, _: &mut [u8]) -> Result<(), GetRandomFailed> {
        panic!("ambient client randomness used")
    }
}
#[derive(Debug)]
struct ForbiddenKx;
impl SupportedKxGroup for ForbiddenKx {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        panic!("ambient client key exchange used")
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}
static NO_RANDOM: ForbiddenRandom = ForbiddenRandom;
static NO_KX: ForbiddenKx = ForbiddenKx;
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new("tests/fixtures").join(name)).unwrap()
}
fn client_config() -> ClientConfig {
    let mut provider = rustls_pure::provider();
    provider.secure_random = &NO_RANDOM;
    provider.kx_groups = vec![&NO_KX];
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(fixture("ca.der"))).unwrap();
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}
fn peer(listener: std::net::TcpListener, has_auth: bool) -> io::Result<()> {
    let (socket, _) = listener.accept()?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(rustls_pure::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(fixture("cert.der"))],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture("key.der"))),
        )
        .unwrap();
    config.send_tls13_tickets = 0;
    let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), socket);
    let mut input = [0; 4];
    let read = tls.read_exact(&mut input);
    if !has_auth {
        return if read.is_err() {
            Ok(())
        } else {
            Err(io::Error::other("unauthorized client sent plaintext"))
        };
    }
    read?;
    if &input != b"PING" {
        return Err(io::Error::other("unexpected plaintext"));
    }
    tls.write_all(b"PONG")?;
    tls.flush()
}
fn run(has_auth: bool, offloaded: bool) -> Test {
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    budget.bytes = 1_000_000;
    let mut caps = vec![RuntimeGrant::AdapterNet.as_str().into()];
    if has_auth {
        caps.push(RuntimeGrant::AdapterAuth.as_str().into());
    }
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:owned-client".into(),
            operation_id: OperationId::parse("operation:owned-client")?,
            principal: "principal:fixture".into(),
            capabilities: caps,
            deadline: Some(TimestampNs(30_000_000_000)),
            priority: 1,
            budgets: budget,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(b"fixture"),
            generation: 1,
        },
        RegionId::new("region:owned-client")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    RuntimeBuilder::current_thread()
        .blocking_threads(1, 1)
        .build()?
        .block_on(async {
            let cx = asupersync::Cx::current().ok_or("missing runtime")?;
            let run = run_owned_async(
                &mut authority,
                &mut tree,
                TaskSpec {
                    task_id: TaskId::new("task:owned-client")?,
                    started_at: TimestampNs(2),
                },
                &cx,
                async |task, cx| {
                    let output: Test = async {
                        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
                        let address = listener.local_addr()?;
                        let peer = std::thread::spawn(move || peer(listener, has_auth));
                        let socket = timeout(
                            cx.now(),
                            Duration::from_secs(5),
                            TcpStream::connect(address),
                        )
                        .await??;
                        let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                        let raw =
                            MeteredIo::with_clock(socket, clock, "fixture:owned-client", 4096)?;
                        let name = ServerName::try_from("localhost")?.to_owned();
                        let result = if offloaded {
                            use fss_unifi_scoped_tls_entropy_lab::owned::offload::Acquisition;
                            match Acquisition::begin(task, cx, clock, "fixture:owned-client", 128) {
                                Ok(mut owner) => {
                                    match timeout(cx.now(), Duration::from_secs(5), owner.join())
                                        .await
                                    {
                                        Ok(Ok(lease)) => {
                                            timeout(
                                                cx.now(),
                                                Duration::from_secs(5),
                                                Session::connect_with_lease(
                                                    client_config(),
                                                    name,
                                                    raw,
                                                    lease,
                                                ),
                                            )
                                            .await?
                                        }
                                        Ok(Err(error)) => {
                                            drop(raw);
                                            Err(error)
                                        }
                                        Err(_) => {
                                            owner.abort();
                                            let _ = owner.join().await;
                                            drop(raw);
                                            return Err("entropy drain timed out".into());
                                        }
                                    }
                                }
                                Err(error) => {
                                    drop(raw);
                                    Err(error)
                                }
                            }
                        } else {
                            timeout(
                                cx.now(),
                                Duration::from_secs(5),
                                Session::connect(
                                    client_config(),
                                    name,
                                    raw,
                                    task,
                                    cx,
                                    clock,
                                    "fixture:owned-client",
                                    128,
                                ),
                            )
                            .await?
                        };
                        if !has_auth {
                            match result {
                                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => (),
                                _ => return Err("missing auth was not denied".into()),
                            }
                            peer.join().map_err(|_| "peer panic")??;
                            return Ok(());
                        }
                        let mut tls = result?;
                        timeout(cx.now(), Duration::from_secs(5), tls.write_all(b"PING")).await??;
                        timeout(cx.now(), Duration::from_secs(5), tls.flush()).await??;
                        let mut reply = [0; 4];
                        timeout(cx.now(), Duration::from_secs(5), tls.read_exact(&mut reply))
                            .await??;
                        assert_eq!(&reply, b"PONG");
                        peer.join().map_err(|_| "peer panic")??;
                        tls.request_stop();
                        assert_eq!(
                            tls.write_all(b"NO").await.unwrap_err().kind(),
                            io::ErrorKind::Interrupted
                        );
                        assert_eq!(
                            tls.read_exact(&mut reply).await.unwrap_err().kind(),
                            io::ErrorKind::Interrupted
                        );
                        Ok(())
                    }
                    .await;
                    let outcome = if output.is_ok() {
                        TaskOutcome::Success
                    } else {
                        TaskOutcome::Failed("owned client fixture failed".into())
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
fn task_owned_client_uses_metered_transport() -> Test {
    run(true, false)
}
#[test]
fn missing_auth_fails_before_client_handshake() -> Test {
    run(false, false)
}

#[test]
fn offloaded_client_entropy_completes_loopback() -> Test {
    run(true, true)
}
#[test]
fn offloaded_client_entropy_requires_authority() -> Test {
    run(false, true)
}
