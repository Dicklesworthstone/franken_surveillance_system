#![forbid(unsafe_code)]
//! Deterministic partial-I/O and authority faults through a private socket seam.

use super::super::wire::get_capabilities_request;
use super::*;
use crate::rtsp::authentication::{DigestChallenge, DigestCredentials, DigestPolicy};
use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn snapshot_routes_preserve_the_approved_origin_and_hide_tokens() -> TestResult {
    let media = route()?;
    let snapshot = media.snapshot("http://camera.invalid:8080/private.jpg?token=PRIVATE-TOKEN")?;
    assert_eq!(snapshot.peer(), media.peer());
    assert_eq!(snapshot.authority(), media.authority());
    assert_eq!(snapshot.generation(), media.generation());
    assert_eq!(snapshot.plaintext_approval(), media.plaintext_approval());
    assert_ne!(snapshot.digest(), media.digest());
    assert!(!format!("{snapshot:?}").contains("PRIVATE"));
    assert_eq!(
        snapshot.with_target("/onvif/media").err(),
        Some(HttpError::Configuration)
    );
    assert!(
        snapshot
            .snapshot("http://camera.invalid:8080/another.jpg")
            .is_err()
    );
    for uri in [
        "http://other.invalid:8080/image.jpg",
        "http://127.0.0.1:8080/image.jpg",
        "http://camera.invalid:80/image.jpg",
        "https://camera.invalid:8080/image.jpg",
        "http://user@camera.invalid:8080/image.jpg",
        "http://camera.invalid:8080//other.invalid/image.jpg",
        "http://camera.invalid:8080/a/../image.jpg",
        "http://camera.invalid:8080/a/%2E%2e/image.jpg",
        "http://camera.invalid:8080/image.jpg?token=%GG",
        "http://camera.invalid:8080/image.jpg#fragment",
        "http://camera.invalid:8080/image.jpg?token=a b",
        "http://camera.invalid:8080/image.jpg\r\nAuthorization: forged",
        "http://camera.invalid:8080/a\\image.jpg",
    ] {
        assert_eq!(media.snapshot(uri).err(), Some(HttpError::Configuration));
    }
    let limits = HttpLimits {
        body_bytes: 4 * 1024 * 1024,
        wire_bytes: 8 * 1024 * 1024,
        ..HttpLimits::default()
    };
    assert_eq!(limits.validate(), Err(HttpError::Configuration));
    assert_eq!(limits.validate_profile(true), Ok(()));
    assert_eq!(
        make_request(&snapshot, &get_capabilities_request(), None, 32768).err(),
        Some(HttpError::Configuration),
    );
    assert_eq!(
        HttpExchange::connect(
            snapshot,
            &get_capabilities_request(),
            None,
            HttpLimits::default(),
            0,
            100,
            &Permit
        )
        .err(),
        Some(HttpError::Configuration),
    );
    assert_eq!(
        HttpExchange::connect_snapshot(media, limits, 0, 100, &Permit).err(),
        Some(HttpError::Configuration),
    );
    Ok(())
}

fn route() -> Result<HttpRoute, HttpError> {
    HttpRoute::new(
        SocketAddr::from(([127, 0, 0, 1], 8080)),
        "camera.invalid:8080",
        "/onvif/device_service",
        7,
        ContentDigest::sha256(b"test-only-plaintext-approval"),
    )
}

struct Permit;
impl HttpAuthority for Permit {
    fn checkpoint(
        &self,
        route: &HttpRoute,
        _: HttpOperation,
        _: u64,
        _: u64,
    ) -> Result<(), HttpDenial> {
        if route.generation() == 7 && route.authority() == "camera.invalid:8080" {
            Ok(())
        } else {
            Err(HttpDenial::Unauthorized)
        }
    }
}

struct DenyAt {
    operation: HttpOperation,
    occurrence: usize,
    seen: Cell<usize>,
}
impl HttpAuthority for DenyAt {
    fn checkpoint(
        &self,
        _: &HttpRoute,
        operation: HttpOperation,
        _: u64,
        _: u64,
    ) -> Result<(), HttpDenial> {
        if operation == self.operation {
            let seen = self.seen.get() + 1;
            self.seen.set(seen);
            if seen >= self.occurrence {
                return Err(HttpDenial::Revoked);
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct Script {
    reads: VecDeque<io::Result<Vec<u8>>>,
    write_errors: VecDeque<io::ErrorKind>,
    max_write: Option<usize>,
    written: Arc<Mutex<Vec<u8>>>,
}
impl Read for Script {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let bytes = self
            .reads
            .pop_front()
            .unwrap_or_else(|| Err(io::ErrorKind::WouldBlock.into()))?;
        let count = out.len().min(bytes.len());
        out[..count].copy_from_slice(&bytes[..count]);
        if count < bytes.len() {
            self.reads.push_front(Ok(bytes[count..].to_vec()));
        }
        Ok(count)
    }
}
impl Write for Script {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(kind) = self.write_errors.pop_front() {
            return Err(kind.into());
        }
        let count = self.max_write.unwrap_or(bytes.len()).min(bytes.len());
        self.written
            .lock()
            .map_err(|_| io::ErrorKind::Other)?
            .extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl HttpSocket for Script {}

fn exchange(script: Script, limits: HttpLimits) -> Result<HttpExchange, HttpError> {
    limits.validate()?;
    let route = route()?;
    let request = make_request(
        &route,
        &get_capabilities_request(),
        None,
        limits.request_bytes,
    )?;
    Ok(HttpExchange {
        route,
        limits,
        deadline_ns: 10_000,
        last_ns: 0,
        socket: Some(Box::new(script)),
        request,
        written: 0,
        pending: None,
        eof: false,
        decoder: framing::Decoder::new(limits),
        totals: HttpTotals::default(),
        failure: None,
        interruptions: 0,
        taken: false,
    })
}

fn decode(bytes: &[u8], split: usize, eof: bool) -> Result<HttpResponse, HttpError> {
    let mut decoder = framing::Decoder::new(HttpLimits::default());
    decoder.push(&bytes[..split])?;
    decoder.push(&bytes[split..])?;
    if eof {
        decoder.finish()?;
    }
    decoder.take_response()
}

#[test]
fn pinned_routes_refuse_cross_origin_and_secret_targets() -> TestResult {
    let good = route()?;
    assert_eq!(good.generation(), 7);
    assert_ne!(good.digest(), good.with_target("/onvif/media")?.digest());
    assert_eq!(good.peer(), good.with_target("/onvif/media")?.peer());
    assert_eq!(good.plaintext_approval(), good.clone().plaintext_approval());
    for target in [
        "//other.invalid/media",
        "/onvif/../admin",
        "/onvif/./media",
        "/onvif/%2e%2e/admin",
        "/onvif/media?password=test",
        "/onvif/media#fragment",
        "/onvif/media\r\nAuthorization: forged",
    ] {
        assert_eq!(
            good.with_target(target).err(),
            Some(HttpError::Configuration)
        );
    }
    for authority in [
        "camera.invalid",
        "camera.invalid:80",
        "camera.invalid:08080",
        "other@camera.invalid:8080",
        "192.0.2.9:8080",
        "bad..host:8080",
        "-host:8080",
        "camera.invalid:8080\r\nForged: yes",
    ] {
        assert_eq!(
            HttpRoute::new(
                good.peer(),
                authority,
                good.target(),
                7,
                good.plaintext_approval()
            )
            .err(),
            Some(HttpError::Configuration)
        );
    }
    assert!(!format!("{good:?}").contains("camera.invalid"));
    assert!(!format!("{good:?}").contains("device_service"));
    Ok(())
}

#[test]
fn content_length_and_chunked_are_split_invariant() -> TestResult {
    let fixed = b"HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: 7\r\n\r\n<test/>";
    let chunked = b"HTTP/1.1 103 Early Hints\r\nX-Info: ignored\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nTransfer-Encoding: chunked\r\n\r\n2;tag=\"test;quoted\"\r\n<t\r\n5\r\nest/>\r\n0\r\nX-Checksum: uninterpreted\r\n\r\n";
    for bytes in [fixed.as_slice(), chunked.as_slice()] {
        for split in 0..=bytes.len() {
            let response = decode(bytes, split, false)?;
            assert_eq!(response.status(), 200);
            assert_eq!(response.body(), b"<test/>");
            assert!(response.content_type().is_some());
        }
        let mut decoder = framing::Decoder::new(HttpLimits::default());
        for byte in bytes {
            decoder.push(&[*byte])?;
        }
        assert_eq!(decoder.take_response()?.body(), b"<test/>");
    }
    Ok(())
}

#[test]
fn close_delimited_requires_explicit_owner_eof() -> TestResult {
    let bytes = b"HTTP/1.0 200 OK\r\nContent-Type: application/soap+xml\r\n\r\n<test/>";
    assert_eq!(decode(bytes, 15, false).err(), Some(HttpError::NotComplete));
    assert_eq!(decode(bytes, 15, true)?.body(), b"<test/>");
    Ok(())
}

#[test]
fn ambiguous_truncated_and_extra_responses_never_release() {
    for bytes in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1, 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\n Folded: refused\r\n\r\n",
        b"HTTP/1.1 200 OK\nHeader: value\r\n\r\n",
        b"HTTP/1.1 200 O\0K\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nWWW-Authenticate: Digest realm=\"injected\"\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nxXX0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;bad=\"unterminated\r\nx\r\n0\r\n\r\n",
    ] {
        assert_eq!(decode(bytes, 0, true).err(), Some(HttpError::Malformed));
    }
    for bytes in [
        b"HTTP/1.1 101 Switching Protocols\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"ignored\"\r\nContent-Length: 0\r\n\r\n",
    ] {
        assert_eq!(decode(bytes, 0, true).err(), Some(HttpError::Unsupported));
    }
    for bytes in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\npart".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\n",
    ] {
        assert_eq!(decode(bytes, 0, true).err(), Some(HttpError::Truncated));
    }
    assert_eq!(
        decode(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nextra",
            0,
            false
        )
        .err(),
        Some(HttpError::TrailingResponse)
    );
}

#[test]
fn digest_challenge_is_single_bounded_and_redacted() -> TestResult {
    let challenge = "Digest realm=\"test-realm\", nonce=\"private-test-nonce\", algorithm=SHA-256, qop=\"auth\"";
    let bytes = format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: {challenge}\r\nContent-Length: 0\r\n\r\n"
    );
    let response = decode(bytes.as_bytes(), 20, false)?;
    assert_eq!(response.status(), 401);
    assert_eq!(response.digest_challenge(), Some(challenge));
    assert!(!format!("{response:?}").contains("private-test-nonce"));
    let duplicated = format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: {challenge}\r\nwww-authenticate: {challenge}\r\nContent-Length: 0\r\n\r\n"
    );
    assert_eq!(
        decode(duplicated.as_bytes(), 0, false).err(),
        Some(HttpError::Malformed)
    );
    let oversized = format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest {}\r\nContent-Length: 0\r\n\r\n",
        "x".repeat(2048)
    );
    assert_eq!(
        decode(oversized.as_bytes(), 0, false).err(),
        Some(HttpError::Limit)
    );
    Ok(())
}

#[test]
fn request_reuses_digest_for_exact_post_target() -> TestResult {
    let challenge = DigestChallenge::parse(
        "Digest realm=\"test-realm\", nonce=\"test-nonce\", algorithm=SHA-256, qop=\"auth\"",
        "test-realm",
        DigestPolicy::default(),
    )?;
    let credentials = DigestCredentials::new("test-user", "test-password")?;
    let route = route()?;
    let authorization = challenge.authorize("POST", route.target(), &credentials, [9; 16], 1)?;
    let request = make_request(
        &route,
        &get_capabilities_request(),
        Some(&authorization),
        32768,
    )?;
    let request = std::str::from_utf8(&request)?;
    assert!(
        request.starts_with("POST /onvif/device_service HTTP/1.1\r\nHost: camera.invalid:8080\r\n")
    );
    assert!(request.contains("Authorization: Digest "));
    assert!(request.contains("uri=\"/onvif/device_service\""));
    assert!(request.contains("nc=00000001"));
    assert!(request.contains("Connection: close\r\n"));
    assert!(!request.contains("test-password"));
    assert_eq!(
        make_request(
            &route,
            &get_capabilities_request(),
            Some(&authorization),
            64
        )
        .err(),
        Some(HttpError::Configuration)
    );
    Ok(())
}

#[test]
fn native_connect_checks_configuration_and_authority_before_io() -> TestResult {
    let deny = DenyAt {
        operation: HttpOperation::Connect,
        occurrence: 1,
        seen: Cell::new(0),
    };
    let request = get_capabilities_request();
    assert_eq!(
        HttpExchange::connect(route()?, &request, None, HttpLimits::default(), 0, 0, &deny,).err(),
        Some(HttpError::Configuration)
    );
    assert_eq!(deny.seen.get(), 0);
    assert_eq!(
        HttpExchange::connect(
            route()?,
            &request,
            None,
            HttpLimits::default(),
            0,
            10_000,
            &deny,
        )
        .err(),
        Some(HttpError::Denied(HttpDenial::Revoked))
    );
    assert_eq!(deny.seen.get(), 1);
    Ok(())
}

#[test]
fn headers_body_wire_and_chunk_work_have_hard_ceilings() {
    for bytes in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999999\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
    ] {
        assert_eq!(decode(bytes, 0, false).err(), Some(HttpError::Limit));
    }
    let mut decoder = framing::Decoder::new(HttpLimits {
        header_bytes: 20,
        ..HttpLimits::default()
    });
    assert_eq!(
        decoder.push(b"HTTP/1.1 200 OK\r\nX-Long: too large\r\n\r\n"),
        Err(HttpError::Limit)
    );
    let mut decoder = framing::Decoder::new(HttpLimits {
        body_bytes: 2,
        ..HttpLimits::default()
    });
    assert_eq!(
        decoder.push(b"HTTP/1.1 200 OK\r\n\r\nabc"),
        Err(HttpError::Limit)
    );
    let mut decoder = framing::Decoder::new(HttpLimits {
        wire_bytes: 16,
        ..HttpLimits::default()
    });
    assert_eq!(
        decoder.push(b"HTTP/1.1 200 OK\r\n\r\n"),
        Err(HttpError::Limit)
    );
    let mut excessive = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for _ in 0..4097 {
        excessive.extend_from_slice(b"1\r\nx\r\n");
    }
    assert_eq!(decode(&excessive, 0, false).err(), Some(HttpError::Limit));
    let informational = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(9);
    assert_eq!(
        decode(&informational, 0, false).err(),
        Some(HttpError::Limit)
    );
}

#[test]
fn partial_writes_and_would_block_complete_once_without_replay() -> TestResult {
    let written = Arc::new(Mutex::new(Vec::new()));
    let script = Script {
        reads: VecDeque::from([
            Err(io::ErrorKind::WouldBlock.into()),
            Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n<test/>".to_vec()),
        ]),
        write_errors: VecDeque::from([io::ErrorKind::Interrupted, io::ErrorKind::WouldBlock]),
        max_write: Some(7),
        written: written.clone(),
    };
    let mut owner = exchange(script, HttpLimits::default())?;
    let expected = owner.request.clone();
    let mut complete = false;
    for now in 0..1000 {
        let before = owner.totals.io_calls;
        if owner.step(now, &Permit)? == HttpProgress::Complete {
            complete = true;
            break;
        }
        assert!(owner.totals.io_calls - before <= 1);
    }
    assert!(complete);
    assert_eq!(
        *written.lock().map_err(|_| "test mutex poisoned")?,
        expected
    );
    assert_eq!(owner.take_response(1000, &Permit)?.body(), b"<test/>");
    assert_eq!(
        owner.take_response(1001, &Permit).err(),
        Some(HttpError::Closed)
    );
    assert!(owner.socket.is_none());
    Ok(())
}

#[test]
fn revocation_after_read_preserves_accounting_and_prevents_release() -> TestResult {
    let bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n<test/>";
    let mut owner = exchange(
        Script {
            reads: VecDeque::from([Ok(bytes.to_vec())]),
            ..Script::default()
        },
        HttpLimits::default(),
    )?;
    let deny = DenyAt {
        operation: HttpOperation::Read,
        occurrence: 2,
        seen: Cell::new(0),
    };
    owner.step(0, &deny)?;
    assert_eq!(
        owner.step(1, &deny),
        Err(HttpError::Denied(HttpDenial::Revoked))
    );
    assert_eq!(owner.totals().received_bytes, bytes.len() as u64);
    assert!(owner.pending.is_some());
    assert!(owner.socket.is_none());
    assert_eq!(
        owner.take_response(2, &Permit).err(),
        Some(HttpError::Denied(HttpDenial::Revoked))
    );
    assert_eq!(
        owner.step(2, &Permit),
        Err(HttpError::Denied(HttpDenial::Revoked))
    );
    Ok(())
}

#[test]
fn post_write_revocation_keeps_exact_sent_prefix_and_never_retries() -> TestResult {
    let mut owner = exchange(
        Script {
            max_write: Some(13),
            ..Script::default()
        },
        HttpLimits::default(),
    )?;
    let deny = DenyAt {
        operation: HttpOperation::Write,
        occurrence: 2,
        seen: Cell::new(0),
    };
    assert_eq!(
        owner.step(0, &deny),
        Err(HttpError::Denied(HttpDenial::Revoked))
    );
    assert_eq!(owner.totals().sent_bytes, 13);
    assert_eq!(owner.totals().write_calls, 1);
    assert_eq!(
        owner.step(1, &Permit),
        Err(HttpError::Denied(HttpDenial::Revoked))
    );
    assert_eq!(owner.totals().write_calls, 1);
    Ok(())
}

#[test]
fn release_rechecks_authority_even_after_complete_response() -> TestResult {
    let mut owner = exchange(
        Script {
            reads: VecDeque::from([Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec())]),
            ..Script::default()
        },
        HttpLimits::default(),
    )?;
    owner.step(0, &Permit)?;
    owner.step(1, &Permit)?;
    assert_eq!(owner.step(2, &Permit)?, HttpProgress::Complete);
    let deny = DenyAt {
        operation: HttpOperation::Release,
        occurrence: 1,
        seen: Cell::new(0),
    };
    assert_eq!(
        owner.take_response(3, &deny).err(),
        Some(HttpError::Denied(HttpDenial::Revoked))
    );
    assert_eq!(
        owner.take_response(4, &Permit).err(),
        Some(HttpError::Denied(HttpDenial::Revoked))
    );
    Ok(())
}

#[test]
fn deadlines_clock_regression_and_network_budget_fence_without_more_io() -> TestResult {
    let mut owner = exchange(Script::default(), HttpLimits::default())?;
    assert_eq!(owner.step(10000, &Permit), Err(HttpError::Deadline));
    assert_eq!(owner.totals().io_calls, 0);
    let mut owner = exchange(Script::default(), HttpLimits::default())?;
    owner.step(10, &Permit)?;
    assert_eq!(owner.step(9, &Permit), Err(HttpError::ClockReversed));
    assert_eq!(owner.totals().io_calls, 1);
    let mut owner = exchange(
        Script::default(),
        HttpLimits {
            io_calls: 1,
            ..HttpLimits::default()
        },
    )?;
    owner.step(0, &Permit)?;
    assert_eq!(owner.step(1, &Permit), Err(HttpError::Limit));
    assert_eq!(owner.totals().io_calls, 1);
    let mut owner = exchange(
        Script {
            write_errors: VecDeque::from([io::ErrorKind::Interrupted; 8]),
            ..Script::default()
        },
        HttpLimits::default(),
    )?;
    for now in 0..7 {
        assert_eq!(owner.step(now, &Permit)?, HttpProgress::Pending);
    }
    assert_eq!(owner.step(7, &Permit), Err(HttpError::Interrupted));
    assert_eq!(owner.totals().io_calls, 8);
    Ok(())
}
