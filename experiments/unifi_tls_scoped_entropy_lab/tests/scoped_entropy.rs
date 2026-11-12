#![forbid(unsafe_code)]
//! Synthetic API experiment. Deterministic bytes here are never production entropy.

use rustls::{
    ClientConfig, ClientConnection, NamedGroup, RootCertStore, ServerConfig, ServerConnection,
    crypto::{
        ActiveKeyExchange, CompletedKeyExchange, GetRandomFailed, ScopedServerKx, SecureRandom,
        SharedSecret, SupportedKxGroup,
    },
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use std::{
    io::{Cursor, Read, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Debug)]
struct FixtureRandom {
    remaining: Mutex<(usize, u8, usize)>,
    active: AtomicBool,
}
impl FixtureRandom {
    fn new(seed: u8, budget: usize) -> Self {
        Self {
            remaining: Mutex::new((budget, seed, 0)),
            active: AtomicBool::new(true),
        }
    }
    fn consumed(&self) -> usize {
        self.remaining.lock().unwrap().2
    }
}
impl SecureRandom for FixtureRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), GetRandomFailed> {
        if !self.active.load(Ordering::Acquire) {
            return Err(GetRandomFailed);
        }
        let mut state = self.remaining.try_lock().map_err(|_| GetRandomFailed)?;
        if output.len() > state.0 {
            return Err(GetRandomFailed);
        }
        for byte in output.iter_mut() {
            state.1 = state.1.wrapping_mul(73).wrapping_add(41);
            *byte = state.1;
        }
        state.0 -= output.len();
        state.2 += output.len();
        Ok(())
    }
}

#[derive(Debug)]
struct X25519;
impl ScopedServerKx for X25519 {
    fn start_and_complete(
        &self,
        group: NamedGroup,
        peer: &[u8],
        random: &dyn SecureRandom,
    ) -> Result<CompletedKeyExchange, rustls::Error> {
        if group != NamedGroup::X25519 {
            return Err(rustls::Error::General("unsupported group".into()));
        }
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::General("bad peer key".into()))?;
        let mut bytes = Zeroizing::new([0u8; 32]);
        random
            .fill(&mut *bytes)
            .map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
        let secret = StaticSecret::from(*bytes);
        let public = PublicKey::from(&secret);
        let shared = secret.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(rustls::Error::General("invalid shared secret".into()));
        }
        Ok(CompletedKeyExchange {
            group,
            pub_key: public.as_bytes().to_vec(),
            secret: SharedSecret::from(shared.as_bytes().as_slice()),
        })
    }
}

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
static FORBIDDEN_RANDOM: ForbiddenRandom = ForbiddenRandom;
static FORBIDDEN_KX: ForbiddenKx = ForbiddenKx;

fn fixture(name: &str) -> Vec<u8> {
    let base = std::env::var_os("FSS_LAB_TLS_FIXTURE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "tests/fixtures".into());
    std::fs::read(base.join(name)).expect("disposable test certificate fixture")
}

fn server(entropy: Arc<FixtureRandom>) -> ServerConfig {
    let mut provider = rustls_pure::provider();
    provider.secure_random = &FORBIDDEN_RANDOM;
    provider.kx_groups = vec![&FORBIDDEN_KX];
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(fixture("cert.der"))],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture("key.der"))),
        )
        .unwrap();
    config.scoped_random = Some(entropy);
    config.scoped_kx = Some(Arc::new(X25519));
    config.send_tls13_tickets = 0;
    config
}

fn client() -> ClientConnection {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(fixture("ca.der"))).unwrap();
    let config = ClientConfig::builder_with_provider(Arc::new(rustls_pure::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("localhost").unwrap().to_owned(),
    )
    .unwrap()
}

fn c2s(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), rustls::Error> {
    let mut wire = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut wire).unwrap();
    }
    if !wire.is_empty() {
        server.read_tls(&mut Cursor::new(wire)).unwrap();
        server.process_new_packets()?;
    }
    Ok(())
}
fn s2c(server: &mut ServerConnection, client: &mut ClientConnection) -> Result<(), rustls::Error> {
    let mut wire = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut wire).unwrap();
    }
    if !wire.is_empty() {
        client.read_tls(&mut Cursor::new(wire)).unwrap();
        client.process_new_packets()?;
    }
    Ok(())
}

#[test]
fn two_interleaved_sessions_use_separate_scoped_sources() {
    let first = Arc::new(FixtureRandom::new(1, 128));
    let second = Arc::new(FixtureRandom::new(2, 128));
    let mut s1 = ServerConnection::new(Arc::new(server(first.clone()))).unwrap();
    let mut s2 = ServerConnection::new(Arc::new(server(second.clone()))).unwrap();
    let mut c1 = client();
    let mut c2 = client();
    for _ in 0..8 {
        c2s(&mut c1, &mut s1).unwrap();
        c2s(&mut c2, &mut s2).unwrap();
        s2c(&mut s2, &mut c2).unwrap();
        s2c(&mut s1, &mut c1).unwrap();
        if !s1.is_handshaking() && !s2.is_handshaking() {
            break;
        }
    }
    assert!(!s1.is_handshaking() && !s2.is_handshaking());
    assert_eq!(first.consumed(), 64);
    assert_eq!(second.consumed(), 64);
    c1.writer().write_all(b"first").unwrap();
    c2s(&mut c1, &mut s1).unwrap();
    let mut data = [0; 5];
    s1.reader().read_exact(&mut data).unwrap();
    assert_eq!(&data, b"first");
    c2.writer().write_all(b"other").unwrap();
    c2s(&mut c2, &mut s2).unwrap();
    s2.reader().read_exact(&mut data).unwrap();
    assert_eq!(&data, b"other");
}

#[test]
fn exhaustion_and_revocation_fail_without_ambient_fallback() {
    for (seed, budget, revoked, expected) in
        [(3, 31, false, 0), (4, 32, false, 32), (5, 128, true, 0)]
    {
        let entropy = Arc::new(FixtureRandom::new(seed, budget));
        if revoked {
            entropy.active.store(false, Ordering::Release);
        }
        let mut server = ServerConnection::new(Arc::new(server(entropy.clone()))).unwrap();
        let mut client = client();
        assert!(matches!(
            c2s(&mut client, &mut server),
            Err(rustls::Error::FailedToGetRandomBytes)
        ));
        assert_eq!(entropy.consumed(), expected);
    }
}

#[test]
fn incomplete_scope_and_invalid_peer_are_rejected() {
    let entropy = Arc::new(FixtureRandom::new(5, 128));
    let mut config = server(entropy.clone());
    config.scoped_kx = None;
    assert!(ServerConnection::new(Arc::new(config)).is_err());
    let mut config = server(entropy.clone());
    config.scoped_random = None;
    assert!(ServerConnection::new(Arc::new(config)).is_err());
    assert!(
        X25519
            .start_and_complete(NamedGroup::X25519, &[0; 32], entropy.as_ref())
            .is_err()
    );
}

#[test]
fn independent_openssl_client_uses_scoped_server_entropy() {
    use std::{
        net::TcpListener,
        process::{Command, Stdio},
        time::Duration,
    };
    let base = std::env::var_os("FSS_LAB_TLS_FIXTURE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "tests/fixtures".into());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut child = Command::new("timeout")
        .args([
            "15",
            "openssl",
            "s_client",
            "-quiet",
            "-tls1_3",
            "-groups",
            "X25519",
            "-verify_return_error",
            "-verify_hostname",
            "localhost",
            "-CAfile",
        ])
        .arg(base.join("ca.pem"))
        .arg("-connect")
        .arg(address.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"PING").unwrap();
    drop(child.stdin.take());
    listener.set_nonblocking(true).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let (socket, _) = loop {
        match listener.accept() {
            Ok(socket) => break socket,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("independent client did not connect: {error}"),
        }
    };
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let entropy = Arc::new(FixtureRandom::new(7, 128));
    let connection = ServerConnection::new(Arc::new(server(entropy.clone()))).unwrap();
    let mut tls = rustls::StreamOwned::new(connection, socket);
    let mut input = [0; 4];
    tls.read_exact(&mut input).unwrap();
    assert_eq!(&input, b"PING");
    tls.write_all(b"PONG").unwrap();
    tls.flush().unwrap();
    tls.conn.send_close_notify();
    tls.flush().unwrap();
    drop(tls);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "independent TLS client failed");
    assert!(output.stdout.windows(4).any(|part| part == b"PONG"));
    assert_eq!(entropy.consumed(), 64);
}
