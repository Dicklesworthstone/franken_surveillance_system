#![forbid(unsafe_code)]
//! Isolated, credential-free interoperability experiment. NOT a production verifier.
//! The same-network observed certificate is not independent proof of device identity.
use asupersync::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    runtime::RuntimeBuilder,
    time::timeout,
};
#[path = "../../../crates/fss-reference/src/unifi_direct/metered.rs"]
mod fss_metered;
use fss_core::{
    BudgetVector, ContentDigest, DigestAlgorithm, OperationId, RegionId, RegionKind,
    RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_metered::MeteredIo;
use fss_runtime::{
    authority::AuthorityCx,
    execution::{TaskCompletion, TaskSpec, run_owned_async},
};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key},
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
};
use std::collections::BTreeSet;
use std::{
    error::Error,
    fs,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

struct ObservedPin {
    cert: Vec<u8>,
    spki: SubjectPublicKeyInfoDer<'static>,
    algorithms: WebPkiSupportedAlgorithms,
}
impl std::fmt::Debug for ObservedPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObservedPin(<redacted>)")
    }
}
impl ObservedPin {
    fn verify_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if cert.as_ref() != self.cert || signature.scheme != SignatureScheme::ECDSA_NISTP256_SHA256
        {
            return Err(rustls::Error::General("LAB_SIGNATURE_REJECTED".into()));
        }
        verify_tls13_signature_with_raw_key(msg, &self.spki, signature, &self.algorithms)
            .map_err(|_| rustls::Error::General("LAB_SIGNATURE_REJECTED".into()))
    }
}
impl ServerCertVerifier for ObservedPin {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end.as_ref() == self.cert {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("LAB_PIN_MISMATCH".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(msg, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(msg, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}
fn observed(start: Instant) -> TimestampNs {
    TimestampNs(
        i128::try_from(start.elapsed().as_nanos())
            .unwrap_or(i128::MAX)
            .saturating_add(1),
    )
}

fn main() -> Result<(), Box<dyn Error>> {
    run(std::env::args().skip(1).collect())
}

fn run(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    if args.len() != 6 || args[5] != "--owner-authorized" {
        return Err("expected certificate path, private IPv4 address, tls13, match|mismatch|bad-key, scope-sha256, --owner-authorized".into());
    }
    let mut cert = fs::read(&args[0])?;
    if cert.is_empty() || cert.len() > 8192 {
        return Err("invalid certificate size".into());
    }
    let parsed = Certificate::from_der(&cert)?;
    let mut spki = parsed.tbs_certificate.subject_public_key_info.to_der()?;
    let expected_failure = match args[3].as_str() {
        "match" => None,
        "mismatch" => {
            cert[0] ^= 1;
            Some("LAB_PIN_MISMATCH")
        }
        "bad-key" => {
            // Public, valid P-256 generator point (not a generated secret).
            let point: [u8; 65] = [
                0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
                0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
                0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
                0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
                0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
            ];
            if spki.len() != 91 || spki[26] != 4 || spki[26..] == point {
                return Err("unexpected public-key shape".into());
            }
            spki[26..].copy_from_slice(&point);
            Some("LAB_SIGNATURE_REJECTED")
        }
        _ => return Err("invalid pin case".into()),
    };
    let version = match args[2].as_str() {
        "tls13" => &rustls::version::TLS13,
        _ => return Err("invalid TLS version".into()),
    };
    let provider = Arc::new(rustls_pure::provider());
    let verifier = Arc::new(ObservedPin {
        cert,
        spki: spki.into(),
        algorithms: provider.signature_verification_algorithms,
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let ip: IpAddr = args[1].parse()?;
    if !matches!(ip, IpAddr::V4(v4) if v4.is_private() || v4.is_loopback() || v4.is_link_local()) {
        return Err("private or loopback IPv4 required".into());
    }
    let address = SocketAddr::new(ip, 443);
    let scope = ContentDigest::parse(&args[4])?;
    if scope.algorithm() != DigestAlgorithm::Sha256 || scope.bytes() == [0; 32] {
        return Err("a nonzero SHA-256 scope digest is required".into());
    }
    let start = Instant::now();
    let resource = format!("unifi-owned-lab:{ip}");
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    let (mut owner, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:unifi-owned-lab".into(),
            operation_id: OperationId::parse("operation:unifi-owned-lab")?,
            principal: "principal:owner".into(),
            capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
            deadline: Some(TimestampNs(30_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:local".into(),
            retention_scope: "retention:lab".into(),
            anchor_universe: scope.with_laboratory(true),
            generation: 1,
        },
        RegionId::new("region:unifi-owned-lab")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    owner.narrow_grants(
        owner
            .grants()
            .clone()
            .with_scope(RuntimeGrant::AdapterNet, BTreeSet::from([resource.clone()])),
    )?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let result = run_owned_async(&mut owner, &mut tree,
            TaskSpec { task_id: TaskId::new("task:unifi-owned-lab")?, started_at: observed(start) },
            &cx,
            async |task, cx| {
        let output: Result<String, Box<dyn Error>> = async {
        task.checkpoint_for(RuntimeGrant::AdapterNet, &resource, observed(start), &BudgetVector::ZERO)?;
        let raw = timeout(cx.now(), Duration::from_secs(5), TcpStream::connect(address)).await??;
        let mut stream = MeteredIo::new(raw, task, cx, observed(start), &resource, 4096)?;
        let mut connection = ClientConnection::new(Arc::new(config), ServerName::IpAddress(ip.into()))?;
        let handshake = async {
            let mut sent = 0_usize;
            let mut received = 0_usize;
            let mut input = [0_u8; 4096];
            for _ in 0..128 {
                cx.checkpoint().map_err(|_| "runtime cancelled")?;
                while connection.wants_write() {
                    let mut output = Vec::new();
                    let written = connection.write_tls(&mut output)?;
                    if written == 0 || output.len() > 65_536 || sent.saturating_add(output.len()) > 262_144 {
                        return Err("outbound handshake limit".into());
                    }
                    stream.write_all(&output).await?;
                    sent += output.len();
                }
                if !connection.is_handshaking() { return Ok::<bool, Box<dyn Error>>(true); }
                if !connection.wants_read() { return Err("TLS handshake made no progress".into()); }
                let count = stream.read(&mut input).await?;
                if count == 0 || received.saturating_add(count) > 262_144 { return Err("EOF or inbound handshake limit".into()); }
                received += count;
                let mut source = std::io::Cursor::new(&input[..count]);
                while source.position() < count as u64 {
                    if connection.read_tls(&mut source)? == 0 { return Err("TLS read made no progress".into()); }
                }
                if let Err(error) = connection.process_new_packets() {
                    if expected_failure.is_some_and(|expected| error.to_string().contains(expected)) {
                        return Ok(false);
                    }
                    return Err(error.into());
                }
            }
            Err("handshake iteration limit".into())
        };
        let accepted = timeout(cx.now(), Duration::from_secs(10), handshake).await??;
        if !accepted { return Ok(format!("{}=rejected", args[3])); }
        if expected_failure.is_some() { return Err("invalid pin or public key was accepted".into()); }
        let outcome = format!("observed_pin=matched signature=verified tls={:?} cipher={:?} application_data=none runtime=asupersync transport=fss_metered", connection.protocol_version(), connection.negotiated_cipher_suite().map(|s| s.suite()));
        connection.send_close_notify();
        let mut close = Vec::new();
        connection.write_tls(&mut close)?;
        timeout(cx.now(), Duration::from_secs(5), stream.write_all(&close)).await??;
        Ok(outcome)
        }.await;
        let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("credential-free TLS probe failed".into()) };
        TaskCompletion { output, outcome, completed_at: observed(start) }
            },
        ).await?;
        result.receipt?;
        println!("{} task_receipt=completed", result.output?);
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
#[ignore = "owner-authorized credential-free camera TLS laboratory"]
fn owner_camera_tls13() -> Result<(), Box<dyn Error>> {
    let args = vec![
        std::env::var("FSS_G4_CERT_PATH")?,
        std::env::var("FSS_G4_ADDRESS")?,
        "tls13".to_owned(),
        std::env::var("FSS_G4_PIN_CASE")?,
        std::env::var("FSS_G4_SCOPE_DIGEST")?,
        "--owner-authorized".to_owned(),
    ];
    run(args)
}

#[test]
#[ignore = "synthetic loopback TLS server laboratory with disposable key"]
fn loopback_tls13_server() -> Result<(), Box<dyn Error>> {
    use asupersync::net::TcpListener;
    use rustls::{
        RootCertStore, ServerConfig, ServerConnection, StreamOwned,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use std::io::{Read, Write};
    let cert = fs::read(std::env::var("FSS_LAB_CERT_DER")?)?;
    let key = fs::read(std::env::var("FSS_LAB_KEY_DER")?)?;
    if cert.is_empty() || cert.len() > 8192 || key.is_empty() || key.len() > 8192 {
        return Err("invalid bounded disposable fixture".into());
    }
    let cert = CertificateDer::from(cert);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key));
    let provider = Arc::new(rustls_pure::provider());
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)?;
    let mut roots = RootCertStore::empty();
    roots.add(cert)?;
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let start = Instant::now();
    let mut budget = BudgetVector::ZERO;
    budget.network_bytes = 1_000_000;
    let (mut owner, mut tree) = AuthorityCx::root(
        RootAuthoritySpec {
            trace_id: "trace:pure-tls-server-fixture".into(),
            operation_id: OperationId::parse("operation:pure-tls-server-fixture")?,
            principal: "principal:fixture".into(),
            capabilities: vec![RuntimeGrant::AdapterNet.as_str().into()],
            deadline: Some(TimestampNs(30_000_000_000)),
            priority: 10,
            budgets: budget,
            privacy_scope: "privacy:fixture".into(),
            retention_scope: "retention:lab".into(),
            anchor_universe: ContentDigest::sha256(b"synthetic loopback tls server")
                .with_laboratory(true),
            generation: 1,
        },
        RegionId::new("region:pure-tls-server-fixture")?,
        RegionKind::Process,
        budget,
        TimestampNs(1),
    )?;
    owner.narrow_grants(owner.grants().clone().with_scope(
        RuntimeGrant::AdapterNet,
        BTreeSet::from(["fixture:tls-loopback".to_owned()]),
    ))?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let result = run_owned_async(&mut owner, &mut tree, TaskSpec {
            task_id: TaskId::new("task:pure-tls-server-fixture")?, started_at: observed(start),
        }, &cx, async |task, cx| {
            let output: Result<(), Box<dyn Error>> = async {
                task.checkpoint_for(RuntimeGrant::AdapterNet, "fixture:tls-loopback", observed(start), &BudgetVector::ZERO)?;
                let listener = timeout(cx.now(), Duration::from_secs(5), TcpListener::bind("127.0.0.1:0")).await??;
                let address = listener.local_addr()?;
                let client = std::thread::spawn(move || -> Result<(), String> {
                    let socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5)).map_err(|e| e.to_string())?;
                    socket.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
                    socket.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
                    let connection = ClientConnection::new(Arc::new(client), ServerName::try_from("localhost").map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
                    let mut stream = StreamOwned::new(connection, socket);
                    stream.write_all(b"fixture-client").map_err(|e| e.to_string())?;
                    stream.flush().map_err(|e| e.to_string())?;
                    let mut received = [0_u8; 14];
                    stream.read_exact(&mut received).map_err(|e| e.to_string())?;
                    if &received != b"fixture-server" { return Err("unexpected server response".into()); }
                    Ok(())
                });
                let (raw, _) = timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
                let mut stream = MeteredIo::new(raw, task, cx, observed(start), "fixture:tls-loopback", 4096)?;
                let mut server = ServerConnection::new(Arc::new(server))?;
                let exchange = async {
                    let mut network = [0_u8; 4096];
                    let mut application = [0_u8; 14];
                    let mut total = 0_usize;
                    for _ in 0..128 {
                        while server.wants_write() {
                            let mut wire = Vec::new();
                            server.write_tls(&mut wire)?;
                            if wire.is_empty() || wire.len() > 262_144 { return Err("bad bounded TLS output".into()); }
                            stream.write_all(&wire).await?;
                        }
                        if !server.is_handshaking() {
                            match server.reader().read(&mut application[total..]) {
                                Ok(n) => total += n,
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                                Err(e) => return Err(Box::<dyn Error>::from(e)),
                            }
                            if total == application.len() {
                                if &application != b"fixture-client" { return Err("unexpected client data".into()); }
                                server.writer().write_all(b"fixture-server")?;
                                server.send_close_notify();
                                while server.wants_write() {
                                    let mut wire = Vec::new();
                                    server.write_tls(&mut wire)?;
                                    if wire.is_empty() || wire.len() > 262_144 { return Err("bad bounded TLS output".into()); }
                                    stream.write_all(&wire).await?;
                                }
                                return Ok(());
                            }
                        }
                        let n = stream.read(&mut network).await?;
                        if n == 0 { return Err("early TLS EOF".into()); }
                        let mut source = std::io::Cursor::new(&network[..n]);
                        while source.position() < n as u64 {
                            if server.read_tls(&mut source)? == 0 { return Err("TLS read made no progress".into()); }
                        }
                        server.process_new_packets()?;
                    }
                    Err("TLS iteration limit".into())
                };
                timeout(cx.now(), Duration::from_secs(10), exchange).await??;
                client.join().map_err(|_| "fixture client panicked")?.map_err(|_| "fixture client failed")?;
                if server.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) { return Err("unexpected TLS version".into()); }
                Ok(())
            }.await;
            let outcome = if output.is_ok() { TaskOutcome::Success } else { TaskOutcome::Failed("TLS server fixture failed".into()) };
            TaskCompletion { output, outcome, completed_at: observed(start) }
        }).await?;
        result.receipt?;
        result.output?;
        println!("loopback_tls13_server=ok provider=rustls-pure client=same_provider transport=asupersync_metered task_receipt=completed fixture_only=yes");
        Ok::<(), Box<dyn Error>>(())
    })
}
