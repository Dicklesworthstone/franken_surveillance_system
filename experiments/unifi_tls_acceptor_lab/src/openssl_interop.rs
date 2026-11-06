#![forbid(unsafe_code)]
//! Independent OpenSSL fixture client; no camera or production credentials.
use super::*;
use asupersync::time::timeout;
use std::process::{Command, Stdio};

fn exercise(trusted: bool) -> Result<(), Box<dyn Error>> {
    let cert = fs::read(std::env::var("FSS_LAB_CERT_DER")?)?;
    let key = fs::read(std::env::var("FSS_LAB_KEY_DER")?)?;
    let ca = std::env::var(if trusted {
        "FSS_LAB_CERT_PEM"
    } else {
        "FSS_LAB_OTHER_CA_PEM"
    })?;
    if cert.is_empty() || cert.len() > 8192 || key.is_empty() || key.len() > 8192 {
        return Err("invalid fixture sizes".into());
    }
    let acceptor = TlsAcceptorBuilder::new(
        CertificateChain::from_cert(Certificate::from_der(cert)),
        PrivateKey::from_pkcs8_der(key),
    )
    .crypto_provider(Arc::new(rustls_pure::provider()))
    .min_protocol_version(rustls::ProtocolVersion::TLSv1_3)
    .build()?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let peer = std::thread::spawn(move || -> Result<(), String> {
            let mut child = Command::new("timeout")
                .args([
                    "12s",
                    "openssl",
                    "s_client",
                    "-quiet",
                    "-no_ign_eof",
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
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| e.to_string())?;
            let mut input = child.stdin.take().ok_or("missing peer stdin")?;
            let mut output = child.stdout.take().ok_or("missing peer stdout")?;
            let exchange = (|| -> Result<(), String> {
                input
                    .write_all(b"fixture-client")
                    .map_err(|e| e.to_string())?;
                input.flush().map_err(|e| e.to_string())?;
                let mut bytes = [0_u8; 14];
                output.read_exact(&mut bytes).map_err(|e| e.to_string())?;
                if &bytes != b"fixture-server" {
                    return Err("wrong peer response".into());
                }
                Ok(())
            })();
            drop(input);
            drop(output);
            let status = child.wait().map_err(|e| e.to_string())?;
            if trusted {
                exchange?;
                if !status.success() {
                    return Err(format!("trusted peer exit {status}"));
                }
            } else if exchange.is_ok() || status.success() {
                return Err("wrong CA unexpectedly succeeded".into());
            }
            Ok(())
        });
        let (socket, _) = timeout(cx.now(), Duration::from_secs(10), listener.accept()).await??;
        let handshake = timeout(
            cx.now(),
            Duration::from_secs(10),
            acceptor.accept_with_cx(&cx, socket),
        )
        .await?;
        if trusted {
            let mut tls = handshake?;
            let mut request = [0_u8; 14];
            let mut offset = 0;
            while offset < request.len() {
                let n = timeout(
                    cx.now(),
                    Duration::from_secs(10),
                    tls.read_with_cx(&cx, &mut request[offset..]),
                )
                .await??;
                if n == 0 {
                    return Err("peer EOF".into());
                }
                offset += n;
            }
            if &request != b"fixture-client" {
                return Err("wrong peer request".into());
            }
            let mut offset = 0;
            while offset < 14 {
                let n = timeout(
                    cx.now(),
                    Duration::from_secs(10),
                    tls.write_with_cx(&cx, &b"fixture-server"[offset..]),
                )
                .await??;
                if n == 0 {
                    return Err("zero progress".into());
                }
                offset += n;
            }
            timeout(cx.now(), Duration::from_secs(10), tls.flush_with_cx(&cx)).await??;
            timeout(cx.now(), Duration::from_secs(10), tls.shutdown_with_cx(&cx)).await??;
        } else if handshake.is_ok() {
            return Err("untrusted peer completed handshake".into());
        }
        peer.join()
            .map_err(|_| "peer panic")?
            .map_err(|_| "peer verification failed")?;
        println!(
            "independent_openssl_tls13={} fixture=disposable",
            if trusted {
                "accepted"
            } else {
                "wrong_ca_rejected"
            }
        );
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
#[ignore = "requires disposable certificate fixtures and OpenSSL"]
fn openssl_trusted() {
    exercise(true).expect("trusted independent peer");
}

#[test]
#[ignore = "requires disposable certificate fixtures and OpenSSL"]
fn openssl_wrong_ca() {
    exercise(false).expect("wrong CA rejection");
}
