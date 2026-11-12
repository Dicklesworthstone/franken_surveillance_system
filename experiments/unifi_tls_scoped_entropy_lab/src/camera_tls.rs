#![forbid(unsafe_code)]
//! Experimental, explicitly pinned camera-side HTTPS transport.
//!
//! A caller-supplied certificate pin is only as trustworthy as its independent
//! provisioning. This laboratory adapter does not validate a chain, hostname,
//! certificate dates, provider entropy, or physical camera identity.

use crate::camera_tls_client::Client;
use asupersync::{
    Cx,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout_at,
};
use fss_core::{BudgetVector, RuntimeGrant};
use fss_reference::unifi_direct::metered::{MeteredClock, MeteredIo};
use fss_runtime::execution::TaskCx;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key},
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
};
use std::{fmt, io, net::SocketAddrV4, sync::Arc, time::Duration};
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

const MAX_CERT: usize = 8192;
const MAX_HANDSHAKE: usize = 262_144;
const MAX_WAIT: Duration = Duration::from_secs(30);

/// Payload-free connection refusal.
#[derive(Debug)]
pub enum Error {
    /// Invalid bounds, scoped address, or certificate.
    Configuration,
    /// Task or runtime authority refused the operation.
    Authority,
    /// TCP or TLS did not finish inside the deadline.
    Deadline,
    /// Socket or TLS transport failed.
    Transport(io::ErrorKind),
    /// Pin, handshake signature, or protocol validation failed.
    Handshake,
    /// TLS exceeded the bounded handshake work or byte limit.
    Limit,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "experimental pinned camera TLS refused: {self:?}")
    }
}
impl std::error::Error for Error {}

struct Pin {
    cert: Vec<u8>,
    spki: SubjectPublicKeyInfoDer<'static>,
    algorithms: WebPkiSupportedAlgorithms,
}
impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pin(<redacted>)")
    }
}
impl Pin {
    fn signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if cert.as_ref() != self.cert || signature.scheme != SignatureScheme::ECDSA_NISTP256_SHA256
        {
            return Err(rustls::Error::General("PIN_SIGNATURE_REJECTED".into()));
        }
        verify_tls13_signature_with_raw_key(msg, &self.spki, signature, &self.algorithms)
            .map_err(|_| rustls::Error::General("PIN_SIGNATURE_REJECTED".into()))
    }
}
impl ServerCertVerifier for Pin {
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
            Err(rustls::Error::General("PIN_MISMATCH".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signature(msg, cert, sig)
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signature(msg, cert, sig)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// TLS client over the same task-metered TCP connection used in its handshake.
pub type Transport<'scope, 'task> = Client<MeteredIo<'scope, 'task, TcpStream>>;

/// Connect to one explicitly scoped peer using an independently supplied DER pin.
/// The caller must meter plaintext, revalidate the peer's authority on each
/// camera HTTP operation, and separately authorize all credentials and effects.
pub async fn connect<'scope, 'task>(
    cx: &'scope Cx,
    task: &'scope TaskCx<'task>,
    clock: MeteredClock<'scope, 'task>,
    peer: SocketAddrV4,
    cert: &[u8],
    resource: &str,
    wait: Duration,
) -> Result<Transport<'scope, 'task>, Error> {
    if cert.is_empty()
        || cert.len() > MAX_CERT
        || resource.is_empty()
        || wait.is_zero()
        || wait > MAX_WAIT
        || peer.port() == 0
        || !(peer.ip().is_private() || peer.ip().is_loopback() || peer.ip().is_link_local())
        || !clock.matches(task, cx)
    {
        return Err(Error::Configuration);
    }
    let parsed = Certificate::from_der(cert).map_err(|_| Error::Configuration)?;
    let spki = parsed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| Error::Configuration)?;
    let provider = Arc::new(rustls_pure::provider());
    let verifier = Arc::new(Pin {
        cert: cert.to_vec(),
        spki: spki.into(),
        algorithms: provider.signature_verification_algorithms,
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Configuration)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    task.checkpoint_for(
        RuntimeGrant::AdapterNet,
        resource,
        clock.now().map_err(|_| Error::Authority)?,
        &BudgetVector::ZERO,
    )
    .map_err(|_| Error::Authority)?;
    let deadline = cx.now() + wait;
    let work = async {
        let raw = TcpStream::connect(peer)
            .await
            .map_err(|e| Error::Transport(e.kind()))?;
        let mut stream = MeteredIo::with_clock(raw, clock, resource, 4096)
            .map_err(|e| Error::Transport(e.kind()))?;
        let mut tls =
            ClientConnection::new(Arc::new(config), ServerName::IpAddress((*peer.ip()).into()))
                .map_err(|_| Error::Configuration)?;
        let (mut sent, mut received) = (0usize, 0usize);
        let mut input = [0u8; 4096];
        for _ in 0..128 {
            cx.checkpoint().map_err(|_| Error::Authority)?;
            while tls.wants_write() {
                let mut output = Vec::new();
                let written = tls
                    .write_tls(&mut output)
                    .map_err(|e| Error::Transport(e.kind()))?;
                if written == 0
                    || output.len() > 65_536
                    || sent.saturating_add(output.len()) > MAX_HANDSHAKE
                {
                    return Err(Error::Limit);
                }
                stream
                    .write_all(&output)
                    .await
                    .map_err(|e| Error::Transport(e.kind()))?;
                sent += output.len();
            }
            if !tls.is_handshaking() {
                return Ok(Client::new(tls, stream));
            }
            if !tls.wants_read() {
                return Err(Error::Handshake);
            }
            let n = stream
                .read(&mut input)
                .await
                .map_err(|e| Error::Transport(e.kind()))?;
            if n == 0 || received.saturating_add(n) > MAX_HANDSHAKE {
                return Err(Error::Limit);
            }
            received += n;
            let mut source = io::Cursor::new(&input[..n]);
            while source.position() < n as u64 {
                if tls
                    .read_tls(&mut source)
                    .map_err(|e| Error::Transport(e.kind()))?
                    == 0
                {
                    return Err(Error::Handshake);
                }
                tls.process_new_packets().map_err(|_| Error::Handshake)?;
            }
        }
        Err(Error::Limit)
    };
    timeout_at(deadline, work)
        .await
        .map_err(|_| Error::Deadline)?
}
