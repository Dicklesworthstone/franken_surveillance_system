#![forbid(unsafe_code)]
//! Synthetic client-side Rustls API experiment; fixture bytes are predictable.
use rustls::{
    ClientConfig, ClientConnection, NamedGroup, RootCertStore, ServerConfig, ServerConnection,
    crypto::{
        ActiveKeyExchange, GetRandomFailed, ScopedClientKx, SecureRandom, SharedSecret,
        SupportedKxGroup,
    },
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use std::{
    io::{Cursor, Read, Write},
    sync::{Arc, Mutex},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Debug)]
struct FixtureRandom(Mutex<(usize, u8, usize)>);
impl FixtureRandom {
    fn new(seed: u8, budget: usize) -> Self {
        Self(Mutex::new((budget, seed, 0)))
    }
    fn used(&self) -> usize {
        self.0.lock().unwrap().2
    }
}
impl SecureRandom for FixtureRandom {
    fn fill(&self, out: &mut [u8]) -> Result<(), GetRandomFailed> {
        let mut state = self.0.try_lock().map_err(|_| GetRandomFailed)?;
        if state.0 < out.len() {
            return Err(GetRandomFailed);
        }
        for byte in out.iter_mut() {
            state.1 = state.1.wrapping_mul(73).wrapping_add(41);
            *byte = state.1;
        }
        state.0 -= out.len();
        state.2 += out.len();
        Ok(())
    }
}
#[derive(Debug)]
struct ForbiddenRandom;
impl SecureRandom for ForbiddenRandom {
    fn fill(&self, _: &mut [u8]) -> Result<(), GetRandomFailed> {
        panic!("ambient client random")
    }
}
#[derive(Debug)]
struct ForbiddenKx;
impl SupportedKxGroup for ForbiddenKx {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        panic!("ambient client key exchange")
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
        panic!("ambient retry key exchange")
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}
static NO_P256: ForbiddenP256 = ForbiddenP256;
#[derive(Debug)]
struct X25519;
struct Exchange {
    secret: StaticSecret,
    public: [u8; 32],
}
impl ScopedClientKx for X25519 {
    fn start(
        &self,
        group: NamedGroup,
        random: &dyn SecureRandom,
    ) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        if group != NamedGroup::X25519 {
            return Err(rustls::Error::General("unsupported group".into()));
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        random
            .fill(&mut *bytes)
            .map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
        let secret = StaticSecret::from(*bytes);
        let public = *PublicKey::from(&secret).as_bytes();
        Ok(Box::new(Exchange { secret, public }))
    }
}
impl ActiveKeyExchange for Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::General("bad peer".into()))?;
        let secret = self.secret.diffie_hellman(&PublicKey::from(peer));
        if !secret.was_contributory() {
            return Err(rustls::Error::General("invalid shared secret".into()));
        }
        Ok(SharedSecret::from(secret.as_bytes().as_slice()))
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new("tests/fixtures").join(name)).unwrap()
}
fn client_config(source: Arc<FixtureRandom>) -> ClientConfig {
    client_config_groups(source, false)
}
fn client_config_groups(source: Arc<FixtureRandom>, retry_group: bool) -> ClientConfig {
    let mut provider = rustls_pure::provider();
    provider.secure_random = &NO_RANDOM;
    provider.kx_groups = if retry_group {
        vec![&NO_KX, &NO_P256]
    } else {
        vec![&NO_KX]
    };
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(fixture("ca.der"))).unwrap();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.scoped_random = Some(source);
    config.scoped_kx = Some(Arc::new(X25519));
    config
}
fn client(config: ClientConfig) -> Result<ClientConnection, rustls::Error> {
    ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("localhost").unwrap().to_owned(),
    )
}
fn server() -> ServerConnection {
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
    ServerConnection::new(Arc::new(config)).unwrap()
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
fn independent_clients_use_only_their_scoped_sources() {
    let first = Arc::new(FixtureRandom::new(1, 256));
    let second = Arc::new(FixtureRandom::new(2, 256));
    let mut c1 = client(client_config(first.clone())).unwrap();
    let mut c2 = client(client_config(second.clone())).unwrap();
    let mut s1 = server();
    let mut s2 = server();
    for _ in 0..8 {
        c2s(&mut c1, &mut s1).unwrap();
        c2s(&mut c2, &mut s2).unwrap();
        s2c(&mut s2, &mut c2).unwrap();
        s2c(&mut s1, &mut c1).unwrap();
        if !c1.is_handshaking()
            && !c2.is_handshaking()
            && !s1.is_handshaking()
            && !s2.is_handshaking()
        {
            break;
        }
    }
    assert!(
        !c1.is_handshaking()
            && !c2.is_handshaking()
            && !s1.is_handshaking()
            && !s2.is_handshaking()
    );
    assert!(first.used() >= 98 && second.used() >= 98);
    assert_eq!(first.used(), second.used());
    c1.writer().write_all(b"first").unwrap();
    c2.writer().write_all(b"other").unwrap();
    c2s(&mut c1, &mut s1).unwrap();
    c2s(&mut c2, &mut s2).unwrap();
    let mut out = [0; 5];
    s1.reader().read_exact(&mut out).unwrap();
    assert_eq!(&out, b"first");
    s2.reader().read_exact(&mut out).unwrap();
    assert_eq!(&out, b"other");
}
#[test]
fn client_refuses_exhaustion_incomplete_scope_and_early_data() {
    let low = Arc::new(FixtureRandom::new(4, 97));
    assert!(matches!(
        client(client_config(low)),
        Err(rustls::Error::FailedToGetRandomBytes)
    ));
    let source = Arc::new(FixtureRandom::new(5, 256));
    let mut a = client_config(source.clone());
    a.scoped_kx = None;
    assert!(client(a).is_err());
    let mut b = client_config(source.clone());
    b.scoped_random = None;
    assert!(client(b).is_err());
    let mut c = client_config(source);
    c.enable_early_data = true;
    assert!(client(c).is_err());
    assert!(
        X25519
            .start(NamedGroup::X25519, &FixtureRandom::new(9, 32))
            .unwrap()
            .complete(&[0; 32])
            .is_err()
    );
}

#[test]
fn retry_with_unsupported_group_refuses_without_provider_fallback() {
    let source = Arc::new(FixtureRandom::new(11, 256));
    let mut client = client(client_config_groups(source.clone(), true)).unwrap();
    let mut provider = rustls_pure::provider();
    provider
        .kx_groups
        .retain(|group| group.name() == NamedGroup::secp256r1);
    assert_eq!(provider.kx_groups.len(), 1);
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
    let mut server = ServerConnection::new(Arc::new(config)).unwrap();
    c2s(&mut client, &mut server).unwrap();
    assert!(
        matches!(s2c(&mut server, &mut client), Err(rustls::Error::General(reason)) if reason == "unsupported group")
    );
    assert_eq!(source.used(), 98);
}

#[test]
fn independent_openssl_server_accepts_scoped_client() {
    use std::{
        net::{TcpListener, TcpStream},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    struct Guard(Child);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let child = Command::new("openssl")
        .args([
            "s_server",
            "-quiet",
            "-www",
            "-tls1_3",
            "-groups",
            "X25519",
            "-no_ticket",
            "-accept",
        ])
        .arg(address.to_string())
        .arg("-cert")
        .arg("tests/fixtures/cert.pem")
        .arg("-key")
        .arg("tests/fixtures/key.pem")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut child = Guard(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    let socket = loop {
        if let Ok(socket) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            break socket;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "OpenSSL exited before accepting"
        );
        assert!(Instant::now() < deadline, "OpenSSL did not accept");
        std::thread::sleep(Duration::from_millis(10));
    };
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let source = Arc::new(FixtureRandom::new(12, 256));
    let mut tls = rustls::StreamOwned::new(client(client_config(source.clone())).unwrap(), socket);
    tls.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .unwrap();
    tls.flush().unwrap();
    let mut response = [0u8; 64];
    let n = tls.read(&mut response).unwrap();
    assert!(response[..n].starts_with(b"HTTP/1.0 200"));
    assert!(source.used() >= 98);
}
