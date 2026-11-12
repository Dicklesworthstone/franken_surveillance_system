#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
//! Loopback-only task-bound TLS experiment; no camera or production credentials.

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
use fss_reference::unifi_direct::metered::{MeteredClock, MeteredIo};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use fss_unifi_scoped_tls_entropy_lab::owned::Session;
use rustls::{
    ClientConfig, ClientConnection, NamedGroup, RootCertStore, ServerConfig, StreamOwned,
    crypto::{ActiveKeyExchange, GetRandomFailed, SecureRandom, SupportedKxGroup},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use std::{
    error::Error,
    io::{self, Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

type Test = Result<(), Box<dyn Error>>;
#[derive(Debug)]
struct ForbiddenRandom;
impl SecureRandom for ForbiddenRandom {
    fn fill(&self, _: &mut [u8]) -> Result<(), GetRandomFailed> {
        panic!("ambient server randomness used")
    }
}
#[derive(Debug)]
struct ForbiddenKx;
impl SupportedKxGroup for ForbiddenKx {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        panic!("ambient server key exchange used")
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}
static NO_RANDOM: ForbiddenRandom = ForbiddenRandom;
static NO_KX: ForbiddenKx = ForbiddenKx;
#[derive(Debug)]
struct ForbiddenP256;
impl SupportedKxGroup for ForbiddenP256 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        panic!("ambient server P-256 key exchange used")
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}
static NO_P256: ForbiddenP256 = ForbiddenP256;
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new("tests/fixtures").join(name)).unwrap()
}
fn server_config(p256: bool) -> ServerConfig {
    let mut provider = rustls_pure::provider();
    provider.secure_random = &NO_RANDOM;
    provider.kx_groups = if p256 { vec![&NO_P256] } else { vec![&NO_KX] };
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(fixture("cert.der"))],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture("key.der"))),
        )
        .unwrap();
    config.send_tls13_tickets = 0;
    config
}
fn peer(address: std::net::SocketAddr, p256: bool) -> io::Result<()> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(fixture("ca.der"))).unwrap();
    let mut provider = rustls_pure::provider();
    if p256 {
        provider
            .kx_groups
            .retain(|group| group.name() == NamedGroup::secp256r1);
    }
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connection = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("localhost").unwrap().to_owned(),
    )
    .unwrap();
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut tls = StreamOwned::new(connection, socket);
    tls.write_all(b"PING")?;
    tls.flush()?;
    let mut reply = [0; 4];
    tls.read_exact(&mut reply)?;
    if &reply != b"PONG" {
        return Err(io::Error::other("unexpected reply"));
    }
    Ok(())
}
fn independent_p256_peer(address: std::net::SocketAddr) -> io::Result<()> {
    let script = r#"import socket,ssl,sys
c=ssl.create_default_context(cafile='tests/fixtures/ca.pem')
c.minimum_version=ssl.TLSVersion.TLSv1_3
c.maximum_version=ssl.TLSVersion.TLSv1_3
c.set_ecdh_curve('prime256v1')
with socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=5) as s:
    with c.wrap_socket(s,server_hostname='localhost') as t:
        t.settimeout(5)
        t.sendall(b'PING')
        data=b''
        while len(data)<4:
            part=t.recv(4-len(data))
            if not part: raise RuntimeError('early EOF')
            data+=part
        assert data==b'PONG'
"#;
    let status = std::process::Command::new("python3")
        .args(["-c", script, &address.port().to_string()])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("independent P-256 peer failed"))
    }
}
fn run(has_auth: bool, offloaded: bool, p256: bool, independent: bool) -> Test {
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    budget.bytes = 1_000_000;
    let mut caps = vec![RuntimeGrant::AdapterNet.as_str().into()];
    if has_auth {
        caps.push(RuntimeGrant::AdapterAuth.as_str().into());
    }
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:owned-tls".into(),
            operation_id: OperationId::parse("operation:owned-tls")?,
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
        RegionId::new("region:owned-tls")?,
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
                    task_id: TaskId::new("task:owned-tls")?,
                    started_at: TimestampNs(2),
                },
                &cx,
                async |task, cx| {
                    let output: Test = async {
                        let listener = TcpListener::bind("127.0.0.1:0").await?;
                        let address = listener.local_addr()?;
                        let client = std::thread::spawn(move || {
                            if has_auth && independent {
                                independent_p256_peer(address)
                            } else if has_auth {
                                peer(address, p256)
                            } else {
                                TcpStream::connect_timeout(&address, Duration::from_secs(5))
                                    .map(|_| ())
                            }
                        });
                        let (socket, _) =
                            timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                        let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                        if has_auth {
                            use fss_unifi_scoped_tls_entropy_lab::fleet_transport::FleetTls;
                            let resources = vec![
                                "fixture:owned-tls".to_owned(),
                                "fixture:other-camera".to_owned(),
                            ];
                            assert!(
                                FleetTls::new(server_config(p256), task, &resources, 128).is_ok()
                            );
                            assert!(
                                FleetTls::new(server_config(p256), task, &resources, 63).is_err()
                            );
                            let duplicate = vec![
                                "fixture:owned-tls".to_owned(),
                                "fixture:owned-tls".to_owned(),
                            ];
                            assert!(
                                FleetTls::new(server_config(p256), task, &duplicate, 128).is_err()
                            );
                            let mut with_tickets = server_config(p256);
                            with_tickets.send_tls13_tickets = 1;
                            assert!(FleetTls::new(with_tickets, task, &resources, 128).is_err());
                        }
                        let raw = MeteredIo::with_clock(socket, clock, "fixture:owned-tls", 4096)?;
                        let result = if offloaded {
                            use fss_unifi_scoped_tls_entropy_lab::owned::offload::Acquisition;
                            match Acquisition::begin(task, cx, clock, "fixture:owned-tls", 128) {
                                Ok(mut owner) => {
                                    match timeout(cx.now(), Duration::from_secs(5), owner.join())
                                        .await
                                    {
                                        Ok(Ok(lease)) => {
                                            timeout(
                                                cx.now(),
                                                Duration::from_secs(5),
                                                Session::accept_with_lease(
                                                    server_config(p256),
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
                                Session::accept(
                                    server_config(p256),
                                    raw,
                                    task,
                                    cx,
                                    clock,
                                    "fixture:owned-tls",
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
                            client.join().map_err(|_| "client panic")??;
                            return Ok(());
                        }
                        let mut tls = result?;
                        let mut bytes = [0; 4];
                        timeout(cx.now(), Duration::from_secs(5), tls.read_exact(&mut bytes))
                            .await??;
                        assert_eq!(&bytes, b"PING");
                        timeout(cx.now(), Duration::from_secs(5), tls.write_all(b"PONG")).await??;
                        timeout(cx.now(), Duration::from_secs(5), tls.flush()).await??;
                        client.join().map_err(|_| "client panic")??;
                        tls.request_stop();
                        assert_eq!(
                            tls.write_all(b"NO").await.unwrap_err().kind(),
                            io::ErrorKind::Interrupted
                        );
                        assert_eq!(
                            tls.read_exact(&mut bytes).await.unwrap_err().kind(),
                            io::ErrorKind::Interrupted
                        );
                        Ok(())
                    }
                    .await;
                    let outcome = if output.is_ok() {
                        TaskOutcome::Success
                    } else {
                        TaskOutcome::Failed("owned TLS fixture failed".into())
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
fn task_owned_entropy_and_metered_transport_complete_loopback() -> Test {
    run(true, false, false, false)
}
#[test]
fn missing_auth_is_denied_before_handshake() -> Test {
    run(false, false, false, false)
}

#[test]
fn offloaded_server_entropy_completes_loopback() -> Test {
    run(true, true, false, false)
}
#[test]
fn offloaded_server_entropy_requires_authority() -> Test {
    run(false, true, false, false)
}

#[test]
fn p256_server_completes_loopback_with_owned_entropy() -> Test {
    run(true, false, true, false)
}

#[test]
fn p256_server_completes_loopback_with_offloaded_entropy() -> Test {
    run(true, true, true, false)
}

#[test]
fn p256_server_accepts_independent_openssl_peer() -> Test {
    run(true, true, true, true)
}
