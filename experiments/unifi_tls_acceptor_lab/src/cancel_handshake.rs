#![forbid(unsafe_code)]
//! Native parked-handshake cancellation with disposable fixture keys.
use super::*;
use asupersync::{tls::TlsError, types::CancelKind};
use std::{
    future::{Future, poll_fn},
    io,
    pin::pin,
    sync::mpsc,
    task::Poll,
};

#[test]
#[ignore = "requires disposable certificate fixture paths"]
fn parked_handshake_cancellation_closes_socket() {
    let cert = fs::read(std::env::var("FSS_LAB_CERT_DER").unwrap()).unwrap();
    let key = fs::read(std::env::var("FSS_LAB_KEY_DER").unwrap()).unwrap();
    let acceptor = TlsAcceptorBuilder::new(
        CertificateChain::from_cert(Certificate::from_der(cert)),
        PrivateKey::from_pkcs8_der(key),
    )
    .crypto_provider(Arc::new(rustls_pure::provider()))
    .min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
    .build()
    .unwrap();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = asupersync::Cx::current().expect("runtime context");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (parked_tx, parked_rx) = mpsc::sync_channel::<()>(1);
        let peer_cx = cx.clone();
        let peer = std::thread::spawn(move || -> io::Result<()> {
            let mut socket =
                std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            parked_rx
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| io::Error::other("handshake never parked"))?;
            peer_cx.cancel_with(CancelKind::User, Some("fixture cancellation"));
            let mut byte = [0_u8; 1];
            match socket.read(&mut byte)? {
                0 => Ok(()),
                _ => Err(io::Error::other("unexpected server data")),
            }
        });
        let (socket, _) = listener.accept().await.unwrap();
        let mut handshake = pin!(acceptor.accept_with_cx(&cx, socket));
        let mut parked = false;
        let result = poll_fn(|task| match handshake.as_mut().poll(task) {
            Poll::Pending => {
                if !parked {
                    parked = true;
                    parked_tx.send(()).expect("peer waits for parked handshake");
                }
                Poll::Pending
            }
            ready => ready,
        })
        .await;
        assert!(
            parked,
            "must observe a pending handshake before cancellation"
        );
        assert!(
            matches!(result, Err(TlsError::Io(ref e)) if e.kind() == io::ErrorKind::Interrupted)
        );
        peer.join()
            .expect("peer thread")
            .expect("socket closed after cancellation");
        println!("parked_tls_handshake=cancelled transport=closed fixture=disposable");
    });
}
