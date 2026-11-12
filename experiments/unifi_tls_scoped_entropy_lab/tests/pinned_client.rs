#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
//! Synthetic pinned camera HTTPS: a wrong pin must stop before plaintext.
use asupersync::{
    io::{AsyncReadExt, AsyncWriteExt},
    runtime::RuntimeBuilder,
    time::timeout,
};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::metered::MeteredClock;
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use fss_unifi_scoped_tls_entropy_lab::camera_tls_owned;
use rustls::{
    NamedGroup, ServerConfig, ServerConnection, StreamOwned,
    crypto::{ActiveKeyExchange, GetRandomFailed, SecureRandom, SupportedKxGroup},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{
    error::Error,
    io::{self, Read, Write},
    net::SocketAddr,
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
#[derive(Debug)]
struct ForbiddenP256;
impl SupportedKxGroup for ForbiddenP256 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        panic!("ambient client P-256 key exchange used")
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}
static NO_P256: ForbiddenP256 = ForbiddenP256;
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new("tests/fixtures").join(name)).unwrap()
}
fn peer(listener: std::net::TcpListener, valid_pin: bool) -> io::Result<()> {
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
    if !valid_pin {
        return if read.is_err() {
            Ok(())
        } else {
            Err(io::Error::other("wrong-pin session sent plaintext"))
        };
    }
    read?;
    if &input != b"PING" {
        return Err(io::Error::other("unexpected plaintext"));
    }
    tls.write_all(b"PONG")?;
    tls.flush()
}
fn run(valid_pin: bool, p256: bool) -> Test {
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    budget.bytes = 1_000_000;
    let caps = [RuntimeGrant::AdapterNet, RuntimeGrant::AdapterAuth]
        .iter()
        .map(|g| g.as_str().into())
        .collect();
    let (mut authority, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:pinned-client".into(),
            operation_id: OperationId::parse("operation:pinned-client")?,
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
        RegionId::new("region:pinned-client")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    RuntimeBuilder::current_thread().build()?.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime")?;
        let run = run_owned_async(
            &mut authority,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:pinned-client")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
                    let SocketAddr::V4(address) = listener.local_addr()? else {
                        return Err("IPv4 required".into());
                    };
                    let peer = std::thread::spawn(move || peer(listener, valid_pin));
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let pin = fixture(if valid_pin { "cert.der" } else { "ca.der" });
                    let mut provider = rustls_pure::provider();
                    provider.secure_random = &NO_RANDOM;
                    provider.kx_groups = if p256 { vec![&NO_P256] } else { vec![&NO_KX] };
                    let result = camera_tls_owned::connect(
                        cx,
                        task,
                        clock,
                        address,
                        &pin,
                        "fixture:pinned-client",
                        Duration::from_secs(5),
                        Arc::new(provider),
                    )
                    .await;
                    if !valid_pin {
                        if !matches!(result, Err(camera_tls_owned::Error::Handshake)) {
                            return Err("wrong pin was not refused".into());
                        }
                        peer.join().map_err(|_| "peer panic")??;
                        return Ok(());
                    }
                    let mut tls = result?;
                    timeout(cx.now(), Duration::from_secs(5), tls.write_all(b"PING")).await??;
                    timeout(cx.now(), Duration::from_secs(5), tls.flush()).await??;
                    let mut reply = [0; 4];
                    timeout(cx.now(), Duration::from_secs(5), tls.read_exact(&mut reply)).await??;
                    assert_eq!(&reply, b"PONG");
                    peer.join().map_err(|_| "peer panic")??;
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("pinned-client fixture failed".into())
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
fn correct_pin_exchanges_task_owned_tls() -> Test {
    run(true, false)
}
#[test]
fn wrong_pin_refuses_before_plaintext() -> Test {
    run(false, false)
}

#[test]
fn p256_correct_pin_exchanges_task_owned_tls() -> Test {
    run(true, true)
}

#[test]
fn p256_wrong_pin_refuses_before_plaintext() -> Test {
    run(false, true)
}
