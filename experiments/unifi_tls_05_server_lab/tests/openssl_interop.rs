#![forbid(unsafe_code)]
//! Disposable independent OpenSSL client against the experimental TLS server.
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
use rustls::{
    ServerConfig, ServerConnection,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{
    error::Error,
    io::{self, Read, Write},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
use unifi_tls_05_server_lab::server::Server;

type Test = Result<(), Box<dyn Error>>;
fn exchange(trusted: bool) -> Test {
    let cert = std::fs::read(std::env::var("FSS_LAB_CERT_DER")?)?;
    let key = std::fs::read(std::env::var("FSS_LAB_KEY_DER")?)?;
    let ca = std::env::var(if trusted {
        "FSS_LAB_CERT_PEM"
    } else {
        "FSS_LAB_BAD_CERT_PEM"
    })?;
    let config = ServerConfig::builder_with_provider(Arc::new(rustls_pure::provider()))
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
            trace_id: "trace:openssl-tls-fixture".into(),
            operation_id: OperationId::parse("operation:openssl-tls-fixture")?,
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
        RegionId::new("region:openssl-tls-fixture")?,
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
                task_id: TaskId::new("task:openssl-tls")?,
                started_at: TimestampNs(2),
            },
            &cx,
            async |task, cx| {
                let output: Test = async {
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let peer = std::thread::spawn(move || -> io::Result<()> {
                        let mut child = Command::new("/usr/bin/timeout")
                            .args([
                                "8",
                                "/usr/bin/openssl",
                                "s_client",
                                "-quiet",
                                "-tls1_3",
                                "-verify_return_error",
                                "-verify_hostname",
                                "localhost",
                                "-CAfile",
                                &ca,
                                "-connect",
                                &address.to_string(),
                            ])
                            .stdin(Stdio::piped())
                            .stdout(Stdio::piped())
                            .stderr(Stdio::piped())
                            .spawn()?;
                        let mut input = child
                            .stdin
                            .take()
                            .ok_or_else(|| io::Error::other("missing stdin"))?;
                        input.write_all(b"PING")?;
                        input.flush()?;
                        drop(input);
                        if trusted {
                            let result = (|| {
                                let mut bytes = [0u8; 4];
                                child
                                    .stdout
                                    .as_mut()
                                    .ok_or_else(|| io::Error::other("missing stdout"))?
                                    .read_exact(&mut bytes)?;
                                if &bytes != b"PONG" {
                                    return Err(io::Error::other("unexpected plaintext"));
                                }
                                Ok(())
                            })();
                            let _ = child.kill();
                            let _ = child.wait();
                            result
                        } else {
                            let output = child.wait_with_output()?;
                            if output.status.success()
                                || !String::from_utf8_lossy(&output.stderr)
                                    .contains("certificate verify failed")
                            {
                                return Err(io::Error::other("wrong CA was not refused"));
                            }
                            Ok(())
                        }
                    });
                    let (socket, _) =
                        timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                    let clock = MeteredClock::new(task, cx, TimestampNs(3))?;
                    let raw = MeteredIo::with_clock(socket, clock, "fixture:camera", 37)?;
                    let handshake = timeout(
                        cx.now(),
                        Duration::from_secs(5),
                        Server::new(ServerConnection::new(Arc::new(config))?, raw).handshake(cx),
                    )
                    .await?;
                    if trusted {
                        let mut tls = handshake?;
                        let mut bytes = [0u8; 4];
                        timeout(cx.now(), Duration::from_secs(5), tls.read_exact(&mut bytes))
                            .await??;
                        if &bytes != b"PING" {
                            return Err("unexpected client plaintext".into());
                        }
                        timeout(cx.now(), Duration::from_secs(5), tls.write_all(b"PONG")).await??;
                        timeout(cx.now(), Duration::from_secs(5), tls.flush()).await??;
                    } else if handshake.is_ok() {
                        return Err("wrong-CA session opened".into());
                    }
                    peer.join().map_err(|_| "OpenSSL peer panic")??;
                    Ok(())
                }
                .await;
                let outcome = if output.is_ok() {
                    TaskOutcome::Success
                } else {
                    TaskOutcome::Failed("OpenSSL fixture failed".into())
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
#[ignore = "requires disposable PEM and DER fixture certificates"]
fn independent_openssl_client_accepts_trusted_server() -> Test {
    exchange(true)
}
#[test]
#[ignore = "requires disposable PEM and DER fixture certificates"]
fn independent_openssl_client_refuses_wrong_ca() -> Test {
    exchange(false)
}
