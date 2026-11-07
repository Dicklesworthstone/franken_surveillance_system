#![forbid(unsafe_code)]
//! TLS handshake over an independently bounded buffered transport.
#![cfg(unix)]

use asupersync::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpListener,
    runtime::RuntimeBuilder,
    time::timeout,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use std::{
    cell::Cell,
    error::Error,
    io::{self, Read, Write},
    pin::Pin,
    process::{Command, Stdio},
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use unifi_tls_05_server_lab::server::Server;

/// A valid buffered writer which needs an explicit flush to make room.
struct Buffered<IO> {
    inner: IO,
    pending: Vec<u8>,
    offset: usize,
    limit: usize,
    blocked: Rc<Cell<usize>>,
    flushes: Rc<Cell<usize>>,
    waiter: Option<Waker>,
}
impl<IO: AsyncRead + Unpin> AsyncRead for Buffered<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}
impl<IO: AsyncWrite + Unpin> AsyncWrite for Buffered<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending.len() == self.limit {
            self.blocked.set(self.blocked.get() + 1);
            self.waiter = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let count = bytes.len().min(self.limit - self.pending.len());
        self.pending.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.offset < this.pending.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.pending[this.offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => this.offset += n,
            }
        }
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let progressed = !this.pending.is_empty();
                if progressed {
                    this.flushes.set(this.flushes.get() + 1);
                }
                this.pending.clear();
                this.offset = 0;
                if progressed {
                    if let Some(waiter) = this.waiter.take() {
                        waiter.wake();
                    }
                }
                Poll::Ready(Ok(()))
            }
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

fn buffered_case(permanently_blocked: bool, independent_peer: bool) -> Result<(), Box<dyn Error>> {
    let cert = std::fs::read(std::env::var("FSS_LAB_CERT_DER")?)?;
    let key = std::fs::read(std::env::var("FSS_LAB_KEY_DER")?)?;
    let provider = Arc::new(rustls_pure::provider());
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert))?;
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let ca = if independent_peer {
        Some(std::env::var("FSS_LAB_CERT_PEM")?)
    } else {
        None
    };
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing context")?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let peer = std::thread::spawn(move || -> io::Result<()> {
            if let Some(ca) = ca {
                let mut child = Command::new("/usr/bin/timeout")
                    .args([
                        "5",
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
                let result = (|| {
                    let mut stdin = child
                        .stdin
                        .take()
                        .ok_or_else(|| io::Error::other("missing peer input"))?;
                    stdin.write_all(b"client payload")?;
                    stdin.flush()?;
                    drop(stdin);
                    let mut response = [0; 14];
                    child
                        .stdout
                        .as_mut()
                        .ok_or_else(|| io::Error::other("missing peer output"))?
                        .read_exact(&mut response)?;
                    if &response != b"server payload" {
                        return Err(io::Error::other("bad server payload"));
                    }
                    Ok(())
                })();
                let waited = child.wait();
                result?;
                waited?;
                return Ok(());
            }
            let socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
            socket.set_read_timeout(Some(Duration::from_secs(3)))?;
            socket.set_write_timeout(Some(Duration::from_secs(3)))?;
            let name = ServerName::try_from("localhost").map_err(io::Error::other)?;
            let mut tls = StreamOwned::new(
                ClientConnection::new(Arc::new(client), name).map_err(io::Error::other)?,
                socket,
            );
            tls.write_all(b"client payload")?;
            tls.flush()?;
            let mut response = [0; 14];
            tls.read_exact(&mut response)?;
            if &response != b"server payload" {
                return Err(io::Error::other("bad server payload"));
            }
            Ok(())
        });
        let blocked = Rc::new(Cell::new(0));
        let flushes = Rc::new(Cell::new(0));
        let server_result: Result<(), Box<dyn Error>> = async {
            let (socket, _) =
                timeout(cx.now(), Duration::from_secs(2), listener.accept()).await??;
            let buffered = Buffered {
                inner: socket,
                pending: Vec::with_capacity(32),
                offset: 0,
                limit: if permanently_blocked { 0 } else { 32 },
                blocked: blocked.clone(),
                flushes: flushes.clone(),
                waiter: None,
            };
            let handshake = timeout(
                cx.now(),
                Duration::from_millis(700),
                Server::new(ServerConnection::new(Arc::new(server))?, buffered).handshake(&cx),
            )
            .await;
            if permanently_blocked {
                if handshake.is_ok() {
                    return Err("blocked handshake unexpectedly completed".into());
                }
                return Ok(());
            }
            let mut tls = handshake??;
            let mut input = [0; 14];
            timeout(cx.now(), Duration::from_secs(2), tls.read_exact(&mut input)).await??;
            if &input != b"client payload" {
                return Err("bad client payload".into());
            }
            tls.write_all(b"server payload").await?;
            timeout(cx.now(), Duration::from_secs(2), tls.flush()).await??;
            Ok(())
        }
        .await;
        let peer_result = peer.join().map_err(|_| "peer panic")?;
        eprintln!(
            "buffered_fixture blocked_polls={} completed_flushes={}",
            blocked.get(),
            flushes.get()
        );
        server_result?;
        if permanently_blocked {
            assert!(
                blocked.get() >= 2,
                "the blocked writer must be retried after flush"
            );
            assert!(
                blocked.get() <= 8,
                "a ready flush without progress must not spin"
            );
            return Ok(());
        }
        peer_result?;
        assert!(blocked.get() > 0, "the fixture must exercise a full buffer");
        assert!(
            flushes.get() > 0,
            "ciphertext must actually pass through flush"
        );
        Ok(())
    })
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn handshake_and_application_data_cross_full_buffer() -> Result<(), Box<dyn Error>> {
    buffered_case(false, false)
}

#[test]
#[ignore = "requires disposable TLS certificate and key"]
fn permanently_blocked_writer_does_not_spin() -> Result<(), Box<dyn Error>> {
    buffered_case(true, false)
}

#[test]
#[ignore = "requires disposable TLS certificate and key and OpenSSL"]
fn independent_openssl_crosses_full_buffer() -> Result<(), Box<dyn Error>> {
    buffered_case(false, true)
}
