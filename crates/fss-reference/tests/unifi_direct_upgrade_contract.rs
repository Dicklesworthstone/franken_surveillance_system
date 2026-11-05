#![forbid(unsafe_code)]
//! UniFi WebSocket upgrade preparation and pipelined frame contracts.

use asupersync::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, websocket::Message},
    runtime::RuntimeBuilder,
    time::timeout,
};
use fss_reference::unifi_direct::{
    Dispatch,
    upgrade::{Error, MAX_HEADER_BYTES, MAX_READ_AHEAD, PreparedUpgrade, ProtocolPolicy},
};
use std::{
    error::Error as StdError,
    io::{Cursor, Read, Write},
    time::Duration,
};

type TestResult = Result<(), Box<dyn StdError>>;
const BASE: &str = "GET / HTTP/1.1\r\nHost: camera.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCamera-Mac: 001122aAbBcC\r\n";
fn request(extra: &str) -> Vec<u8> {
    format!("{BASE}{extra}\r\n").into_bytes()
}

#[test]
fn offered_protocol_and_claim_are_validated_without_authentication() -> TestResult {
    let prepared = PreparedUpgrade::parse(
        &request("Sec-WebSocket-Protocol: other, secure_transfer\r\n"),
        ProtocolPolicy::RequireOffer,
    )?;
    assert_eq!(prepared.claimed_mac(), [0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]);
    assert!(prepared.protocol_offered());
    let response = std::str::from_utf8(prepared.response_bytes())?;
    assert!(response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    assert!(response.contains("Sec-WebSocket-Protocol: secure_transfer\r\n"));
    assert!(!format!("{prepared:?}").contains("001122"));
    Ok(())
}

#[test]
fn nonstandard_selection_is_explicit_and_bad_http_is_rejected() {
    assert!(matches!(
        PreparedUpgrade::parse(&request(""), ProtocolPolicy::RequireOffer),
        Err(Error::MissingSubprotocol)
    ));
    let compatible = PreparedUpgrade::parse(&request(""), ProtocolPolicy::ReferenceCompatibility)
        .expect("compatibility accepted");
    assert!(!compatible.protocol_offered());
    assert!(
        String::from_utf8_lossy(compatible.response_bytes())
            .contains("Sec-WebSocket-Protocol: secure_transfer")
    );
    for bad in [
        request("Camera-Mac: 001122aabbcc\r\n"),
        request("Content-Length: 1\r\n"),
        request("Transfer-Encoding: chunked\r\n"),
        request("not-a-header\r\n"),
        request("X-Test: a\nInjected: yes\r\n"),
        format!("{}\r\n", BASE.replace("GET / HTTP/1.1", "GET /")).into_bytes(),
        request(&format!("X-Fill: {}\r\n", "x".repeat(MAX_HEADER_BYTES))),
    ] {
        assert!(matches!(
            PreparedUpgrade::parse(&bad, ProtocolPolicy::ReferenceCompatibility),
            Err(Error::InvalidRequest)
        ));
    }
    let mut oversized = request("Sec-WebSocket-Protocol: secure_transfer\r\n");
    oversized.resize(oversized.len() + MAX_READ_AHEAD + 1, 0);
    assert!(matches!(
        PreparedUpgrade::parse(&oversized, ProtocolPolicy::RequireOffer),
        Err(Error::InvalidRequest)
    ));
    assert!(matches!(
        PreparedUpgrade::parse(
            &vec![b'x'; MAX_HEADER_BYTES + MAX_READ_AHEAD + 1],
            ProtocolPolicy::RequireOffer
        ),
        Err(Error::InvalidRequest)
    ));
}

#[test]
fn read_ahead_reaches_asupersync_websocket_and_uncertain_writes_retire() -> TestResult {
    let mut wire = request("Sec-WebSocket-Protocol: secure_transfer\r\n");
    // A masked client binary frame containing 'hi' arrived with the header.
    wire.extend_from_slice(&[0x82, 0x82, b'a', b'b', b'c', b'd', b'h' ^ b'a', b'i' ^ b'b']);
    let prepared = PreparedUpgrade::parse(&wire, ProtocolPolicy::RequireOffer)?;
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let mut socket = prepared.finish(Cursor::new(Vec::new()), Dispatch::Written)?;
        match socket.recv(&cx).await? {
            Some(Message::Binary(bytes)) if bytes.as_ref() == b"hi" => {
                Ok::<(), Box<dyn StdError>>(())
            }
            _ => Err("read-ahead frame was lost or altered".into()),
        }
    })?;
    for (dispatch, expected) in [
        (Dispatch::NotWritten, Error::ResponseNotWritten),
        (Dispatch::Indeterminate, Error::ResponseIndeterminate),
    ] {
        let prepared = PreparedUpgrade::parse(&wire, ProtocolPolicy::RequireOffer)?;
        assert!(
            matches!(prepared.finish(Cursor::new(Vec::new()), dispatch), Err(e) if e == expected)
        );
    }
    Ok(())
}

#[test]
fn native_loopback_upgrade_and_binary_frame() -> TestResult {
    let runtime = RuntimeBuilder::current_thread().build()?;
    runtime.block_on(async {
        let cx = asupersync::Cx::current().ok_or("missing runtime context")?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let client = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let mut stream =
                std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut wire = request("Sec-WebSocket-Protocol: secure_transfer\r\n");
            wire.extend_from_slice(&[0x82, 0x82, b'a', b'b', b'c', b'd', b'h' ^ b'a', b'i' ^ b'b']);
            stream.write_all(&wire)?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response)?;
            Ok(response)
        });
        let (mut stream, _) =
            timeout(cx.now(), Duration::from_secs(5), listener.accept()).await??;
        let mut input = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !input.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = timeout(cx.now(), Duration::from_secs(5), stream.read(&mut buffer)).await??;
            if n == 0 || input.len() + n > MAX_HEADER_BYTES + MAX_READ_AHEAD {
                return Err("incomplete fixture request".into());
            }
            input.extend_from_slice(&buffer[..n]);
        }
        let prepared = PreparedUpgrade::parse(&input, ProtocolPolicy::RequireOffer)?;
        timeout(
            cx.now(),
            Duration::from_secs(5),
            stream.write_all(prepared.response_bytes()),
        )
        .await??;
        let mut socket = prepared.finish(stream, Dispatch::Written)?;
        let message = timeout(cx.now(), Duration::from_secs(5), socket.recv(&cx)).await??;
        if !matches!(message, Some(Message::Binary(bytes)) if bytes.as_ref() == b"hi") {
            return Err("fixture frame was lost or altered".into());
        }
        drop(socket);
        let response = client.join().map_err(|_| "fixture client panicked")??;
        if !response.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n") {
            return Err("fixture response not observed".into());
        }
        Ok::<(), Box<dyn StdError>>(())
    })
}
