#![forbid(unsafe_code)]
//! Scripted I/O tests isolate failure cuts; the final test uses native loopback TCP.
use super::*;
use fss_codec_mjpeg::multipart::MultipartError;
use fss_codec_mjpeg::{ComponentInterpretation, DecodeError, DecodeLimits};
use std::cell::Cell;
use std::io::Cursor;
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Instant;

type Test = Result<(), Box<dyn std::error::Error>>;
const JPEG: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fss-codec-mjpeg/tests/fixtures/gray.jpg"
));
fn budget() -> DecodeBudget<'static> {
    DecodeBudget::new(100_000_000)
}
fn route() -> Result<HttpCameraRoute, HttpCameraError> {
    HttpCameraRoute::new(
        StreamBasis {
            source: [7; 32],
            generation: 3,
        },
        SocketAddr::from(([127, 0, 0, 1], 12345)),
        "camera.invalid",
        "/video",
        HttpCameraSecurity::OwnerApprovedPlaintext,
    )
}
struct Authority {
    route: HttpCameraRoute,
    deny: Option<(HttpCameraOperation, usize)>,
    seen: Cell<usize>,
}
impl Authority {
    fn new(route: &HttpCameraRoute) -> Self {
        Self {
            route: route.clone(),
            deny: None,
            seen: Cell::new(0),
        }
    }
    fn deny(route: &HttpCameraRoute, op: HttpCameraOperation, occurrence: usize) -> Self {
        Self {
            route: route.clone(),
            deny: Some((op, occurrence)),
            seen: Cell::new(0),
        }
    }
}
impl HttpCameraAuthority for Authority {
    fn checkpoint(
        &self,
        route: &HttpCameraRoute,
        op: HttpCameraOperation,
        now: u64,
        deadline: u64,
    ) -> Result<(), HttpCameraDenial> {
        if route != &self.route {
            return Err(HttpCameraDenial::Unauthorized);
        }
        if now >= deadline {
            return Err(HttpCameraDenial::Deadline);
        }
        if let Some((operation, nth)) = self.deny
            && operation == op
        {
            self.seen.set(self.seen.get() + 1);
            if self.seen.get() >= nth {
                return Err(HttpCameraDenial::Revoked);
            }
        }
        Ok(())
    }
}
struct Socket {
    input: Cursor<Vec<u8>>,
    read_limit: usize,
    write_limit: usize,
    read_error: Option<io::ErrorKind>,
}
impl Read for Socket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if let Some(kind) = self.read_error {
            return Err(io::Error::from(kind));
        }
        let n = bytes.len().min(self.read_limit);
        self.input.read(&mut bytes[..n])
    }
}
impl Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len().min(self.write_limit))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn camera(
    bytes: &[u8],
    read_limit: usize,
    limits: HttpCameraLimits,
) -> Result<HttpCamera, HttpCameraError> {
    let route = route()?;
    let http = limits.validate(route.basis)?;
    Ok(HttpCamera {
        route,
        limits,
        deadline: 100_000,
        clock: 10,
        socket: Some(Box::new(Socket {
            input: Cursor::new(bytes.to_vec()),
            read_limit,
            write_limit: usize::MAX,
            read_error: None,
        })),
        request: b"GET /video HTTP/1.1\r\nHost: camera.invalid\r\n\r\n".to_vec(),
        sent: 0,
        http,
        multipart: None,
        head: None,
        wire: None,
        entity: None,
        frame: None,
        end: None,
        complete: None,
        totals: HttpCameraTotals::default(),
        failure: None,
        interruptions: 0,
    })
}
fn response(chunked: bool, close_delimited: bool, count: usize) -> Vec<u8> {
    let mut body = Vec::new();
    for _ in 0..count {
        body.extend_from_slice(
            format!(
                "--fss\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
                JPEG.len()
            )
            .as_bytes(),
        );
        body.extend_from_slice(JPEG);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--fss--\r\n");
    let mut wire =
        b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=fss\r\n".to_vec();
    if chunked {
        wire.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
        for chunk in body.chunks(13) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
    } else {
        if !close_delimited {
            wire.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(&body);
    }
    wire
}
fn wire_ready(
    c: &mut HttpCamera,
    a: &dyn HttpCameraAuthority,
) -> Result<HttpWireReceipt, HttpCameraError> {
    for _ in 0..100 {
        if let HttpCameraStep::WireReady(r) = c.step(11, a, &mut budget())? {
            return Ok(r);
        }
    }
    Err(HttpCameraError::NetworkLimit)
}
fn run(
    c: &mut HttpCamera,
    a: &dyn HttpCameraAuthority,
    saved: &mut Vec<u8>,
    frames: &mut Vec<HttpJpegFrame>,
) -> Result<(), HttpCameraError> {
    let mut b = budget();
    for _ in 0..50_000 {
        match c.step(12, a, &mut b)? {
            HttpCameraStep::WireReady(r) => {
                assert_eq!(saved.len() as u64, r.range[0]);
                saved.extend_from_slice(
                    c.pending_wire()
                        .ok_or(HttpCameraError::ReceiptMismatch)?
                        .bytes(),
                );
                c.acknowledge_wire(r, 12, a)?;
            }
            HttpCameraStep::FrameReady => {
                let r = c
                    .pending_frame()
                    .ok_or(HttpCameraError::ReceiptMismatch)?
                    .part()
                    .receipt();
                frames.push(c.take_frame(r.ordinal, r.encoded_sha256, 12, a)?);
            }
            HttpCameraStep::Complete => return Ok(()),
            HttpCameraStep::Pending | HttpCameraStep::Advanced => {}
        }
    }
    Err(HttpCameraError::NetworkLimit)
}
#[test]
fn exact_identity_length_chunked_and_close_delimited_source_maps_reach_native_decoder() -> Test {
    for (chunked, close) in [(false, false), (true, false), (false, true)] {
        for n in [1, 7, 4096] {
            let source = response(chunked, close, 2);
            let mut c = camera(&source, n, HttpCameraLimits::default())?;
            let a = Authority::new(c.route());
            let mut saved = Vec::new();
            let mut frames = Vec::new();
            run(&mut c, &a, &mut saved, &mut frames)?;
            assert_eq!(saved, source);
            assert_eq!(frames.len(), 2);
            assert_eq!(
                c.completion().ok_or("missing completion")?.multipart.frames,
                2
            );
            assert_eq!(c.totals().peer_eof, close);
            for (i, f) in frames.iter().enumerate() {
                assert_eq!(f.part().receipt().ordinal, i as u64 + 1);
                assert_eq!(f.head().wire, c.route().basis());
                let mut rebuilt = Vec::new();
                for span in f.source_spans() {
                    assert_eq!(span.jpeg_range[0], rebuilt.len() as u64);
                    rebuilt.extend_from_slice(
                        &saved[span.wire_range[0] as usize..span.wire_range[1] as usize],
                    );
                }
                assert_eq!(rebuilt, JPEG);
                assert_eq!(f.part().bytes(), JPEG);
                assert_eq!(
                    f.decode(
                        ComponentInterpretation::Grayscale,
                        DecodeLimits::default(),
                        &mut budget()
                    )?
                    .dimensions(),
                    [17, 13]
                );
            }
            assert_eq!(
                c.step(12, &a, &mut DecodeBudget::new(0))?,
                HttpCameraStep::Complete
            );
        }
    }
    Ok(())
}
#[test]
fn raw_and_frame_backpressure_prevent_overwrite_or_extra_reads() -> Test {
    let mut c = camera(
        &response(false, false, 2),
        4096,
        HttpCameraLimits::default(),
    )?;
    let a = Authority::new(c.route());
    let r = wire_ready(&mut c, &a)?;
    let counts = c.totals();
    let raw = c.pending_wire().ok_or("missing wire")?.bytes().to_vec();
    for _ in 0..3 {
        assert_eq!(c.step(11, &a, &mut budget())?, HttpCameraStep::WireReady(r));
    }
    assert_eq!(c.totals(), counts);
    assert_eq!(c.http.next_offset(), 0);
    let bad = HttpWireReceipt {
        sha256: [8; 32],
        ..r
    };
    assert_eq!(
        c.acknowledge_wire(bad, 11, &a),
        Err(HttpCameraError::ReceiptMismatch)
    );
    c.acknowledge_wire(r, 11, &a)?;
    c.acknowledge_wire(r, 11, &a)?;
    for _ in 0..100 {
        if c.step(11, &a, &mut budget())? == HttpCameraStep::FrameReady {
            break;
        }
    }
    let f = c.pending_frame().ok_or("missing frame")?.part().receipt();
    let counts = c.totals();
    for _ in 0..3 {
        assert_eq!(c.step(11, &a, &mut budget())?, HttpCameraStep::FrameReady);
    }
    assert_eq!(c.totals(), counts);
    assert_eq!(c.pending_wire().ok_or("wire lost")?.bytes(), raw);
    assert!(matches!(
        c.take_frame(f.ordinal + 1, f.encoded_sha256, 11, &a),
        Err(HttpCameraError::ReceiptMismatch)
    ));
    assert_eq!(
        c.take_frame(f.ordinal, f.encoded_sha256, 11, &a)?
            .part()
            .bytes(),
        JPEG
    );
    Ok(())
}
#[test]
fn post_read_revocation_preserves_all_bytes_before_fencing() -> Test {
    let input = response(false, false, 1);
    let mut c = camera(&input, 4096, HttpCameraLimits::default())?;
    let a = Authority::deny(c.route(), HttpCameraOperation::Read, 2);
    assert_eq!(
        wire_ready(&mut c, &a),
        Err(HttpCameraError::Denied(HttpCameraDenial::Revoked))
    );
    assert_eq!(c.totals().received_bytes, input.len() as u64);
    assert_eq!(c.http.next_offset(), 0);
    let stopped = c.retire();
    assert_eq!(stopped.wire.ok_or("source disappeared")?.bytes(), input);
    assert!(stopped.frame.is_none());
    assert!(stopped.complete.is_none());
    Ok(())
}
#[test]
fn post_write_revocation_retains_the_exact_sent_prefix() -> Test {
    let mut c = camera(&[], 1, HttpCameraLimits::default())?;
    c.socket = Some(Box::new(Socket {
        input: Cursor::new(Vec::new()),
        read_limit: 1,
        write_limit: 3,
        read_error: None,
    }));
    let a = Authority::deny(c.route(), HttpCameraOperation::Write, 2);
    assert_eq!(
        c.step(11, &a, &mut budget()),
        Err(HttpCameraError::Denied(HttpCameraDenial::Revoked))
    );
    let retired = c.retire();
    assert_eq!(retired.request_sent, 3);
    assert_eq!(retired.totals.sent_bytes, 3);
    assert_eq!(&retired.request[..3], b"GET");
    assert_eq!(retired.totals.read_calls, 0);
    Ok(())
}
#[test]
fn framing_budget_refusal_is_terminal_and_raw_input_survives() -> Test {
    let input = response(false, false, 1);
    let mut c = camera(&input, 4096, HttpCameraLimits::default())?;
    let a = Authority::new(c.route());
    let r = wire_ready(&mut c, &a)?;
    c.acknowledge_wire(r, 11, &a)?;
    let expected = HttpCameraError::Http(HttpError::Work(DecodeError::BudgetExhausted));
    assert_eq!(c.step(11, &a, &mut DecodeBudget::new(0)), Err(expected));
    assert_eq!(c.step(11, &a, &mut budget()), Err(expected));
    assert_eq!(c.retire().wire.ok_or("raw source lost")?.bytes(), input);
    Ok(())
}
#[test]
fn truncated_mime_keeps_prior_frames_and_http_end_without_claiming_completion() -> Test {
    let source = response(false, true, 2);
    let mut source = source[..source.len() - 9].to_vec();
    source.extend_from_slice(b"x");
    let mut c = camera(&source, 79, HttpCameraLimits::default())?;
    let a = Authority::new(c.route());
    let mut saved = Vec::new();
    let mut frames = Vec::new();
    assert_eq!(
        run(&mut c, &a, &mut saved, &mut frames),
        Err(HttpCameraError::Multipart(HttpMjpegError::Multipart(
            MultipartError::Truncated
        )))
    );
    assert_eq!(frames.len(), 1);
    assert_eq!(saved, source);
    assert!(c.completion().is_none());
    let r = c.retire();
    assert!(r.end.is_some());
    assert!(r.multipart.is_some());
    assert!(r.complete.is_none());
    Ok(())
}
#[test]
fn limits_never_become_peer_eof_or_success_and_keep_unparsed_suffixes() -> Test {
    let source = response(false, false, 2);
    for limits in [
        HttpCameraLimits {
            frames: 1,
            ..HttpCameraLimits::default()
        },
        HttpCameraLimits {
            http: HttpLimits {
                wire_bytes: 80,
                ..HttpLimits::default()
            },
            ..HttpCameraLimits::default()
        },
        HttpCameraLimits {
            io_calls: 1,
            ..HttpCameraLimits::default()
        },
    ] {
        let mut c = camera(&source, 4096, limits)?;
        let a = Authority::new(c.route());
        let mut saved = Vec::new();
        let mut frames = Vec::new();
        let err = run(&mut c, &a, &mut saved, &mut frames)
            .err()
            .ok_or("limit was treated as success")?;
        assert!(matches!(
            err,
            HttpCameraError::NetworkLimit | HttpCameraError::FrameLimit
        ));
        assert!(!c.totals().peer_eof);
        assert!(c.completion().is_none());
        if limits.frames == 1 {
            assert_eq!(frames.len(), 1);
            let r = c.retire();
            assert!(r.wire.is_some() || r.entity.is_some());
        }
    }
    Ok(())
}
#[test]
fn interrupted_and_would_block_attempts_are_bounded_and_never_busy_loop() -> Test {
    for (kind, attempts, terminal) in [
        (io::ErrorKind::Interrupted, 8, HttpCameraError::Interrupted),
        (io::ErrorKind::WouldBlock, 9, HttpCameraError::NetworkLimit),
    ] {
        let mut c = camera(
            &[],
            1,
            HttpCameraLimits {
                io_calls: 10,
                ..HttpCameraLimits::default()
            },
        )?;
        c.socket = Some(Box::new(Socket {
            input: Cursor::new(Vec::new()),
            read_limit: 1,
            write_limit: usize::MAX,
            read_error: Some(kind),
        }));
        let a = Authority::new(c.route());
        assert_eq!(c.step(11, &a, &mut budget())?, HttpCameraStep::Advanced);
        for n in 1..=attempts {
            let result = c.step(11, &a, &mut budget());
            if kind == io::ErrorKind::Interrupted && n == attempts {
                assert_eq!(result, Err(terminal));
            } else {
                assert_eq!(result, Ok(HttpCameraStep::Pending));
            }
            assert_eq!(c.totals().read_calls, n);
        }
        assert_eq!(c.step(11, &a, &mut budget()), Err(terminal));
        assert!(!c.totals().peer_eof);
    }
    Ok(())
}
#[test]
fn invalid_routes_and_denied_connect_never_attempt_the_network() -> Test {
    let r = route()?;
    for path in [
        "/stream?token=secret",
        "//other/stream",
        "/a%0d%0aX",
        "/x\r\nY",
        "http://other",
        "/a#fragment",
    ] {
        assert!(
            HttpCameraRoute::new(r.basis(), r.peer(), r.authority(), path, r.security()).is_err()
        );
    }
    let a = Authority::deny(&r, HttpCameraOperation::Connect, 1);
    let fail = HttpCamera::connect(r.clone(), HttpCameraLimits::default(), 0, 100, &a)
        .err()
        .ok_or("connect unexpectedly succeeded")?;
    assert!(!fail.attempted);
    assert_eq!(
        fail.reason,
        HttpCameraError::Denied(HttpCameraDenial::Revoked)
    );
    let fail = HttpCamera::connect(
        r,
        HttpCameraLimits {
            frames: 0,
            ..HttpCameraLimits::default()
        },
        0,
        100,
        &a,
    )
    .err()
    .ok_or("invalid configuration succeeded")?;
    assert!(!fail.attempted);
    Ok(())
}
#[test]
fn clock_regression_does_not_consume_source_and_debug_redacts_route() -> Test {
    let mut c = camera(
        &response(false, false, 1),
        4096,
        HttpCameraLimits::default(),
    )?;
    let a = Authority::new(c.route());
    let r = wire_ready(&mut c, &a)?;
    let counts = c.totals();
    assert_eq!(
        c.acknowledge_wire(r, 9, &a),
        Err(HttpCameraError::ClockReversed)
    );
    assert_eq!(
        c.step(9, &a, &mut budget()),
        Err(HttpCameraError::ClockReversed)
    );
    assert_eq!(c.totals(), counts);
    assert!(c.failure().is_none());
    assert!(!format!("{c:?}").contains("camera.invalid"));
    c.acknowledge_wire(r, 11, &a)?;
    assert_eq!(
        c.step(100_000, &a, &mut budget()),
        Err(HttpCameraError::Deadline)
    );
    let retired = c.retire();
    assert!(!format!("{retired:?}").contains("camera.invalid"));
    assert!(retired.wire.is_some());
    Ok(())
}
#[test]
fn redirect_response_is_not_followed_and_wire_is_retained() -> Test {
    let source =
        b"HTTP/1.1 302 Found\r\nLocation: http://other/private\r\nContent-Length: 0\r\n\r\n";
    let mut c = camera(source, 4096, HttpCameraLimits::default())?;
    let a = Authority::new(c.route());
    let mut saved = Vec::new();
    let mut frames = Vec::new();
    assert_eq!(
        run(&mut c, &a, &mut saved, &mut frames),
        Err(HttpCameraError::Http(HttpError::Status(302)))
    );
    assert_eq!(saved, source);
    assert_eq!(frames.len(), 0);
    assert_eq!(c.totals().write_calls, 1);
    assert!(!format!("{:?}", c.failure()).contains("private"));
    Ok(())
}
#[test]
fn real_loopback_tcp_get_reaches_source_mapped_decodable_frames() -> Test {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let peer = listener.local_addr()?;
    let source = response(true, false, 2);
    let original = source.clone();
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || -> io::Result<()> {
        let until = Instant::now() + Duration::from_secs(5);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(e) => return Err(e),
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut request = Vec::new();
        while request.len() < 4096 && !request.ends_with(b"\r\n\r\n") {
            let mut b = [0; 1];
            socket.read_exact(&mut b)?;
            request.push(b[0]);
        }
        if !request.starts_with(b"GET /video HTTP/1.1\r\n") {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        socket.write_all(&source)?;
        tx.send(())
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(())
    });
    let route = HttpCameraRoute::new(
        StreamBasis {
            source: [3; 32],
            generation: 1,
        },
        peer,
        "localhost",
        "/video",
        HttpCameraSecurity::OwnerApprovedPlaintext,
    )?;
    let a = Authority::new(&route);
    let mut c = HttpCamera::connect(route, HttpCameraLimits::default(), 0, 10_000_000_000, &a)?;
    let until = Instant::now() + Duration::from_secs(4);
    let mut saved = Vec::new();
    let mut frames = Vec::new();
    let mut b = budget();
    let mut done = false;
    while Instant::now() < until {
        match c.step(1, &a, &mut b)? {
            HttpCameraStep::WireReady(r) => {
                saved.extend_from_slice(c.pending_wire().ok_or("raw read missing")?.bytes());
                c.acknowledge_wire(r, 1, &a)?;
            }
            HttpCameraStep::FrameReady => {
                let r = c.pending_frame().ok_or("frame missing")?.part().receipt();
                frames.push(c.take_frame(r.ordinal, r.encoded_sha256, 1, &a)?);
            }
            HttpCameraStep::Complete => {
                done = true;
                break;
            }
            HttpCameraStep::Pending => std::thread::sleep(Duration::from_millis(1)),
            HttpCameraStep::Advanced => {}
        }
    }
    assert!(done);
    assert_eq!(saved, original);
    assert_eq!(frames.len(), 2);
    rx.recv_timeout(Duration::from_secs(1))?;
    handle.join().map_err(|_| "server thread failed")??;
    for frame in frames {
        assert_eq!(
            frame
                .decode(
                    ComponentInterpretation::Grayscale,
                    DecodeLimits::default(),
                    &mut budget()
                )?
                .dimensions(),
            [17, 13]
        );
    }
    Ok(())
}
#[test]
fn parser_cancellation_preserves_the_unconsumed_original_read() -> Test {
    let source = response(false, false, 1);
    let mut c = camera(&source, 4096, HttpCameraLimits::default())?;
    let a = Authority::new(c.route());
    let r = wire_ready(&mut c, &a)?;
    c.acknowledge_wire(r, 11, &a)?;
    let flag = std::sync::atomic::AtomicBool::new(true);
    let mut cancelled = DecodeBudget::cancellable(100_000_000, &flag);
    assert_eq!(
        c.step(11, &a, &mut cancelled),
        Err(HttpCameraError::Http(HttpError::Work(
            DecodeError::Cancelled
        )))
    );
    assert_eq!(
        c.retire().wire.ok_or("cancelled read disappeared")?.bytes(),
        source
    );
    Ok(())
}
#[test]
fn explicit_length_finishes_at_exact_wire_ceiling_but_close_delimited_does_not_invent_eof() -> Test
{
    for close in [false, true] {
        let source = response(false, close, 1);
        let limits = HttpCameraLimits {
            http: HttpLimits {
                wire_bytes: source.len() as u64,
                ..HttpLimits::default()
            },
            ..HttpCameraLimits::default()
        };
        let mut c = camera(&source, 4096, limits)?;
        let a = Authority::new(c.route());
        let mut saved = Vec::new();
        let mut frames = Vec::new();
        let result = run(&mut c, &a, &mut saved, &mut frames);
        if close {
            assert_eq!(result, Err(HttpCameraError::NetworkLimit));
            assert!(c.completion().is_none());
        } else {
            result?;
            assert!(c.completion().is_some());
        }
        assert!(!c.totals().peer_eof);
        assert_eq!(saved, source);
        assert_eq!(frames.len(), 1);
    }
    Ok(())
}
#[test]
fn returned_trailing_response_bytes_cannot_be_silently_discarded() -> Test {
    let mut source = response(false, false, 1);
    source.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
    let mut c = camera(&source, 4096, HttpCameraLimits::default())?;
    let a = Authority::new(c.route());
    let mut saved = Vec::new();
    let mut frames = Vec::new();
    assert_eq!(
        run(&mut c, &a, &mut saved, &mut frames),
        Err(HttpCameraError::TrailingResponse)
    );
    assert_eq!(saved, source);
    assert_eq!(frames.len(), 1);
    assert!(c.completion().is_none());
    let r = c.retire();
    let raw = r.wire.ok_or("trailing source was lost")?;
    assert!(raw.parsed_bytes() < raw.bytes().len());
    Ok(())
}

mod learned;
