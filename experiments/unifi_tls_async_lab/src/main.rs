#![forbid(unsafe_code)]
//! Isolated, credential-free interoperability experiment. NOT a production verifier.
//! The same-network observed certificate is not independent proof of device identity.
use asupersync::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    runtime::RuntimeBuilder,
    time::timeout,
};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key},
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
};
use std::{
    error::Error,
    fs,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
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
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 5 || args[4] != "--owner-authorized" {
        return Err("expected certificate path, private IPv4 address, tls12|tls13, match|mismatch|bad-key, --owner-authorized".into());
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
        "tls12" => &rustls::version::TLS12,
        "tls13" => &rustls::version::TLS13,
        _ => return Err("invalid TLS version".into()),
    };
    let provider = Arc::new(rustls_rustcrypto::provider());
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
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let mut stream = timeout(cx.now(), Duration::from_secs(5), TcpStream::connect(address)).await??;
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
        if !accepted { println!("{}=rejected", args[3]); return Ok::<(), Box<dyn Error>>(()); }
        if expected_failure.is_some() { return Err("invalid pin or public key was accepted".into()); }
        println!("observed_pin=matched signature=verified tls={:?} cipher={:?} application_data=none runtime=asupersync", connection.protocol_version(), connection.negotiated_cipher_suite().map(|s| s.suite()));
        connection.send_close_notify();
        let mut close = Vec::new();
        connection.write_tls(&mut close)?;
        timeout(cx.now(), Duration::from_secs(5), stream.write_all(&close)).await??;
        Ok(())
    })
}
