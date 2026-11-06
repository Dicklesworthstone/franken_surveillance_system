#![forbid(unsafe_code)]
//! Fixture-only composition of FSS owned task, TLS, metered transport and UniFi WebSocket.
use asupersync::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    runtime::RuntimeBuilder,
    time::timeout,
    tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder},
};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_reference::unifi_direct::{
    Controller, Dispatch, Identity, Observation,
    metered::{MeteredClock, MeteredIo},
    receive::{Session, Step},
    upgrade::{PreparedUpgrade, ProtocolPolicy},
};
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, ServerName},
};
use std::{
    error::Error,
    fs,
    io::{Read, Write},
    sync::Arc,
    time::Duration,
};

type TestResult = Result<(), Box<dyn Error>>;
fn observed(cx: &asupersync::Cx, base: u64) -> TimestampNs {
    let elapsed = cx
        .now()
        .as_nanos()
        .checked_sub(base)
        .expect("fixture runtime clock regressed");
    TimestampNs(10 + i128::from(elapsed))
}
const HEAD: &str = "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCamera-Mac: 001122aabbcc\r\nSec-WebSocket-Protocol: secure_transfer\r\n\r\n";
const HELLO: &[u8] = br#"{"from":"ubnt_avclient","to":"UniFiVideo","functionName":"ubnt_avclient_hello","messageId":7,"payload":{}}"#;
fn masked(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mask = [1_u8, 2, 3, 4];
    let mut frame = vec![0x82, 0x80 | payload.len() as u8];
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    frame
}

#[test]
#[ignore = "requires disposable cert and key fixture paths"]
fn owned_tls_websocket_hello() -> TestResult {
    let cert = fs::read(std::env::var("FSS_LAB_CERT_DER")?)?;
    let key = fs::read(std::env::var("FSS_LAB_KEY_DER")?)?;
    if cert.is_empty() || cert.len() > 8192 || key.is_empty() || key.len() > 8192 {
        return Err("invalid fixture sizes".into());
    }
    let provider = Arc::new(rustls_pure::provider());
    let acceptor = TlsAcceptorBuilder::new(
        CertificateChain::from_cert(Certificate::from_der(cert.clone())),
        PrivateKey::from_pkcs8_der(key),
    )
    .crypto_provider(provider.clone())
    .min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
    .build()?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert))?;
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    let (mut owner, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:tls-session-fixture".into(),
            operation_id: OperationId::parse("operation:tls-session-fixture")?,
            principal: "principal:fixture".into(),
            capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
            deadline: Some(TimestampNs(60_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:lab".into(),
            anchor_universe: ContentDigest::sha256(b"tls session fixture").with_laboratory(true),
            generation: 1,
        },
        RegionId::new("region:tls-session-fixture")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let base = cx.now().as_nanos();
        let result = run_owned_async(
            &mut owner,
            &mut tree,
            TaskSpec {
                task_id: TaskId::new("task:tls-session-fixture")?,
                started_at: observed(&cx, base),
            },
            &cx,
            async |task, cx| {
                let output: TestResult = async {
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let client = std::thread::spawn(move || -> Result<(), String> {
                        let socket =
                            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))
                                .map_err(|e| e.to_string())?;
                        socket
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .map_err(|e| e.to_string())?;
                        socket
                            .set_write_timeout(Some(Duration::from_secs(5)))
                            .map_err(|e| e.to_string())?;
                        let connection = ClientConnection::new(
                            Arc::new(client_config),
                            ServerName::try_from("localhost").map_err(|e| e.to_string())?,
                        )
                        .map_err(|e| e.to_string())?;
                        let mut tls = StreamOwned::new(connection, socket);
                        let mut request = HEAD.as_bytes().to_vec();
                        request.extend(masked(HELLO));
                        tls.write_all(&request).map_err(|e| e.to_string())?;
                        tls.flush().map_err(|e| e.to_string())?;
                        let mut reply = Vec::new();
                        let mut buf = [0_u8; 1024];
                        while !reply.windows(4).any(|b| b == b"\r\n\r\n") {
                            let n = tls.read(&mut buf).map_err(|e| e.to_string())?;
                            if n == 0 || reply.len() + n > 4096 {
                                return Err("incomplete response".into());
                            }
                            reply.extend_from_slice(&buf[..n]);
                        }
                        if !reply.starts_with(b"HTTP/1.1 101 ") {
                            return Err("unexpected upgrade response".into());
                        }
                        Ok(())
                    });
                    let (socket, _) =
                        timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                    let clock = MeteredClock::new(task, cx, observed(&cx, base))?;
                    let raw = MeteredIo::with_clock(socket, clock, "fixture:camera", 4096)?;
                    let tls = timeout(
                        cx.now(),
                        Duration::from_secs(5),
                        acceptor.accept_with_cx(cx, raw),
                    )
                    .await??;
                    // This owner conservatively charges plaintext as well as encrypted traffic.
                    let mut io = MeteredIo::with_clock(tls, clock, "fixture:camera", 4096)?;
                    let mut request = Vec::new();
                    let mut buf = [0_u8; 1024];
                    while !request.windows(4).any(|b| b == b"\r\n\r\n") {
                        let n =
                            timeout(cx.now(), Duration::from_secs(5), io.read(&mut buf)).await??;
                        if n == 0 || request.len() + n > 4096 {
                            return Err("incomplete request".into());
                        }
                        request.extend_from_slice(&buf[..n]);
                    }
                    let upgrade = PreparedUpgrade::parse(&request, ProtocolPolicy::RequireOffer)?;
                    timeout(
                        cx.now(),
                        Duration::from_secs(5),
                        io.write_all(upgrade.response_bytes()),
                    )
                    .await??;
                    let controller = Controller::new(
                        Identity::new("FSS", "12345678-1234-4abc-9abc-123456789abc", "1.20.0")?,
                        1,
                    )?;
                    let mut session =
                        Session::from_upgrade(upgrade, io, Dispatch::Written, controller)?;
                    assert_eq!(session.claimed_mac(), [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]);
                    assert_eq!(
                        session.next(Duration::from_secs(3)).await?,
                        Step::Observation(Observation::Hello)
                    );
                    client
                        .join()
                        .map_err(|_| "client panic")?
                        .map_err(|_| "client failed")?;
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("TLS session fixture failed".into())
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at: observed(&cx, base),
                }
            },
        )
        .await?;
        result.receipt?;
        result.output?;
        println!("owned_tls_websocket_hello=ok fixture=disposable claim=unauthenticated");
        Ok::<(), Box<dyn Error>>(())
    })
}
