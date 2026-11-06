#![forbid(unsafe_code)]
//! Disposable loopback experiment, not an admitted camera controller.
use asupersync::{
    net::TcpListener,
    runtime::RuntimeBuilder,
    tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder},
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

fn main() -> Result<(), Box<dyn Error>> {
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
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let client = std::thread::spawn(move || -> Result<(), String> {
            let socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5)).map_err(|e| e.to_string())?;
            socket.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
            socket.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
            let connection = ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            let mut stream = StreamOwned::new(connection, socket);
            stream.write_all(b"fixture-client").map_err(|e| e.to_string())?;
            stream.flush().map_err(|e| e.to_string())?;
            let mut reply = [0_u8; 14];
            stream.read_exact(&mut reply).map_err(|e| e.to_string())?;
            if &reply != b"fixture-server" { return Err("unexpected fixture response".into()); }
            Ok(())
        });
        let (socket, _) = listener.accept().await?;
        let mut tls = acceptor.accept_with_cx(&cx, socket).await?;
        let mut request = [0_u8; 14];
        let mut read = 0;
        while read < request.len() {
            let count = tls.read_with_cx(&cx, &mut request[read..]).await?;
            if count == 0 { return Err("fixture EOF".into()); }
            read += count;
        }
        if &request != b"fixture-client" { return Err("unexpected fixture request".into()); }
        let mut written = 0;
        while written < 14 {
            let count = tls.write_with_cx(&cx, &b"fixture-server"[written..]).await?;
            if count == 0 { return Err("fixture write made no progress".into()); }
            written += count;
        }
        tls.flush_with_cx(&cx).await?;
        client.join().map_err(|_| "fixture client panic")?.map_err(|_| "fixture client failed")?;
        println!("loopback_asupersync_acceptor=ok tls=1.3 provider=rustls-pure peer=same-provider fixture=disposable");
        Ok::<(), Box<dyn Error>>(())
    })
}

#[cfg(test)]
#[test]
#[ignore = "requires disposable certificate fixture paths"]
fn loopback_exchange() {
    main().expect("disposable TLS loopback exchange");
}

#[cfg(test)]
mod openssl_interop;

#[cfg(test)]
mod cancel_handshake;
