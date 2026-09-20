#![forbid(unsafe_code)]
//! Deterministic faults use the private socket seam; the public constructor owns real TCP only.

use super::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use crate::rtsp::client::{ClientCommand, ClientConfig, RtspClientSession};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey { ingress: 1, generation: 1, ssrc: 7 };

struct Permit;
impl TcpAuthority for Permit {
    fn checkpoint(&self, binding: &TcpBinding, _: TcpOperation, _: u64, _: u64) -> Result<(), TcpDenial> {
        if binding.key == KEY && binding.authority == "camera.local" { Ok(()) }
        else { Err(TcpDenial::Unauthorized) }
    }
}
struct Deny;
impl TcpAuthority for Deny {
    fn checkpoint(&self, _: &TcpBinding, _: TcpOperation, _: u64, _: u64) -> Result<(), TcpDenial> {
        Err(TcpDenial::Revoked)
    }
}
struct DenyAt(std::sync::atomic::AtomicUsize, usize);
impl TcpAuthority for DenyAt {
    fn checkpoint(&self, _: &TcpBinding, _: TcpOperation, _: u64, _: u64) -> Result<(), TcpDenial> {
        if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == self.1 { Err(TcpDenial::Cancelled) }
        else { Ok(()) }
    }
}

#[derive(Default)]
struct Script {
    reads: VecDeque<io::Result<Vec<u8>>>,
    writes: VecDeque<io::Result<usize>>,
    sent: Arc<Mutex<Vec<u8>>>,
}
impl Read for Script {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let bytes = self.reads.pop_front().unwrap_or_else(|| Err(io::ErrorKind::WouldBlock.into()))?;
        let n = out.len().min(bytes.len());
        out[..n].copy_from_slice(&bytes[..n]);
        if n < bytes.len() { self.reads.push_front(Ok(bytes[n..].to_vec())); }
        Ok(n)
    }
}
impl Write for Script {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.writes.pop_front().unwrap_or(Ok(bytes.len()))?.min(bytes.len());
        self.sent.lock().map_err(|_| io::ErrorKind::Other)?.extend_from_slice(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
fn binding() -> Result<TcpBinding, TcpError> {
    TcpBinding::new(KEY, SocketAddr::from(([127, 0, 0, 1], 8554)), "camera.local", TcpSecurityPolicy::OwnerApprovedPlaintext)
}
fn make_link(script: Script, limits: TcpLimits) -> Result<RtspTcpLink, TcpError> {
    limits.validate()?;
    Ok(RtspTcpLink { socket: Some(Box::new(script)), binding: binding()?, limits,
        deadline_ns: 60_000_000_000, last_ns: 0, totals: TcpTotals::default(),
        request: None, read: None, interrupted_read: 0, interrupted_write: 0 })
}
fn request() -> Result<ClientRequest, crate::rtsp::client::ClientError> {
    RtspClientSession::new(ClientConfig {
        presentation_uri: "rtsp://camera.local/live/".into(),
        control_root_uri: "rtsp://camera.local/live".into(), media_index: 0, channels: (0, 1),
        response_timeout_ns: 10_000_000_000, default_session_timeout_seconds: 60,
    })?.request(ClientCommand::Describe, 0)
}

#[test]
fn short_writes_wouldblock_and_interruption_send_only_the_original_suffix() -> TestResult {
    let script = Script { writes: [Ok(3), Err(io::ErrorKind::WouldBlock.into()),
        Err(io::ErrorKind::Interrupted.into()), Ok(2)].into(), ..Script::default() };
    let sent = Arc::clone(&script.sent);
    let mut link = make_link(script, TcpLimits { chunk_bytes: 11, ..TcpLimits::default() })?;
    let request = request()?;
    let original = request.bytes().to_vec();
    link.queue_request(request, 0, &Permit)?;
    for now in 1..100 {
        if matches!(link.write_step(now, &Permit)?, TcpWriteStep::Sent { cseq: 1, .. }) { break; }
    }
    assert!(!link.has_pending_request());
    assert_eq!(*sent.lock().map_err(|_| "test lock poisoned")?, original);
    assert_eq!(link.totals().sent_bytes as usize, original.len());
    assert_eq!(link.totals().last_sent_cseq, Some(1));
    assert!(link.retire().request.is_none());
    Ok(())
}

#[test]
fn partial_write_error_retains_exact_command_and_accepted_prefix() -> TestResult {
    let script = Script { writes: [Ok(7), Err(io::ErrorKind::ConnectionReset.into())].into(), ..Script::default() };
    let mut link = make_link(script, TcpLimits::default())?;
    let request = request()?; let original = request.bytes().to_vec();
    link.queue_request(request, 0, &Permit)?;
    assert!(matches!(link.write_step(1, &Permit)?, TcpWriteStep::Advanced { sent: 7, .. }));
    assert_eq!(link.write_step(2, &Permit), Err(TcpError::Io { operation: TcpOperation::Write, kind: io::ErrorKind::ConnectionReset }));
    assert_eq!(link.write_step(3, &Permit), Err(TcpError::Closed));
    let retired = link.retire();
    assert_eq!(retired.request_sent_bytes, 7);
    assert_eq!(retired.request.ok_or("lost partial request")?.bytes(), original);
    assert_eq!(retired.totals.sent_bytes, 7);
    assert_eq!(retired.totals.last_sent_cseq, None);
    Ok(())
}

#[test]
fn post_write_cancellation_preserves_even_a_fully_accepted_unacknowledged_request() -> TestResult {
    let mut link = make_link(Script::default(), TcpLimits::default())?;
    let req = request()?; let len = req.bytes().len();
    link.queue_request(req, 0, &Permit)?;
    let cancel = DenyAt(std::sync::atomic::AtomicUsize::new(0), 1);
    assert_eq!(link.write_step(1, &cancel), Err(TcpError::Denied(TcpDenial::Cancelled)));
    let retired = link.retire();
    assert_eq!(retired.request_sent_bytes, len);
    assert_eq!(retired.request.ok_or("dispatch uncertainty disappeared")?.bytes().len(), len);
    assert_eq!(retired.totals.last_sent_cseq, None);
    Ok(())
}

#[test]
fn bounded_read_never_consumes_another_chunk_before_acknowledgement() -> TestResult {
    let script = Script { reads: [Ok(b"abcdef".to_vec())].into(), ..Script::default() };
    let mut link = make_link(script, TcpLimits { chunk_bytes: 3, ..TcpLimits::default() })?;
    assert_eq!(link.read_step(1, &Permit)?, TcpReadStep::Buffered);
    assert_eq!(link.pending_read().ok_or("read missing")?.expose(), b"abc");
    assert_eq!(link.read_step(2, &Permit), Err(TcpError::Backpressure));
    assert_eq!(link.totals().read_calls, 1);
    let chunk = link.acknowledge_read().ok_or("read ownership missing")?;
    assert_eq!(chunk.admitted_ns(), 1);
    assert_eq!(link.read_step(3, &Permit)?, TcpReadStep::Buffered);
    assert_eq!(link.retire().unread.ok_or("remaining source lost")?.expose(), b"def");
    Ok(())
}

#[test]
fn post_read_revocation_keeps_exact_bytes_without_returning_a_successful_read() -> TestResult {
    let script = Script { reads: [Ok(b"private-response".to_vec())].into(), ..Script::default() };
    let mut link = make_link(script, TcpLimits::default())?;
    let cancel = DenyAt(std::sync::atomic::AtomicUsize::new(0), 1);
    assert_eq!(link.read_step(1, &cancel), Err(TcpError::Denied(TcpDenial::Cancelled)));
    let retired = link.retire();
    assert_eq!(retired.totals.received_bytes, 16);
    assert_eq!(retired.unread.ok_or("revoked source lost")?.expose(), b"private-response");
    Ok(())
}

#[test]
fn budgets_are_not_eof_and_wouldblock_attempts_consume_work() -> TestResult {
    let mut read = make_link(Script { reads: [Ok(b"abcd".to_vec())].into(), ..Script::default() },
        TcpLimits { max_received_bytes: 3, ..TcpLimits::default() })?;
    read.read_step(1, &Permit)?; let _ = read.acknowledge_read();
    assert_eq!(read.read_step(2, &Permit), Err(TcpError::WorkBudget));
    assert!(!read.totals().peer_eof);
    assert_eq!(read.totals().received_bytes, 3);
    let mut work = make_link(Script::default(), TcpLimits { max_io_calls: 2, ..TcpLimits::default() })?;
    assert_eq!(work.read_step(1, &Permit)?, TcpReadStep::Pending);
    assert_eq!(work.read_step(2, &Permit)?, TcpReadStep::Pending);
    assert_eq!(work.read_step(3, &Permit), Err(TcpError::WorkBudget));
    assert_eq!(work.totals().read_calls, 2);
    Ok(())
}

#[test]
fn whole_request_budget_and_queue_pressure_refuse_without_consuming_the_request() -> TestResult {
    let mut small = make_link(Script::default(), TcpLimits { max_sent_bytes: 3, ..TcpLimits::default() })?;
    let request_a = request()?; let original = request_a.bytes().to_vec();
    let refused = small.queue_request(request_a, 1, &Permit).err().ok_or("send budget ignored")?;
    assert_eq!(refused.reason, TcpError::RequestBudget);
    assert_eq!(refused.request.bytes(), original);
    assert_eq!(small.totals().write_calls, 0);
    let mut busy = make_link(Script::default(), TcpLimits::default())?;
    busy.queue_request(request()?, 0, &Permit)?;
    let refused = busy.queue_request(request()?, 1, &Permit).err().ok_or("queue widened")?;
    assert_eq!(refused.reason, TcpError::Backpressure);
    assert_eq!(busy.retire().request_sent_bytes, 0);
    Ok(())
}

#[test]
fn eight_interruptions_fail_without_an_unbounded_retry_loop() -> TestResult {
    let mut script = Script::default();
    for _ in 0..8 { script.reads.push_back(Err(io::ErrorKind::Interrupted.into())); }
    let mut link = make_link(script, TcpLimits::default())?;
    for now in 0..7 { assert_eq!(link.read_step(now, &Permit)?, TcpReadStep::Pending); }
    assert_eq!(link.read_step(7, &Permit), Err(TcpError::Interrupted));
    assert_eq!(link.totals().read_calls, 8);
    Ok(())
}

#[test]
fn zero_write_and_true_eof_have_different_receipts() -> TestResult {
    let mut writer = make_link(Script { writes: [Ok(0)].into(), ..Script::default() }, TcpLimits::default())?;
    writer.queue_request(request()?, 0, &Permit)?;
    assert_eq!(writer.write_step(1, &Permit), Err(TcpError::WriteZero));
    assert!(!writer.totals().peer_eof);
    let mut reader = make_link(Script { reads: [Ok(Vec::new())].into(), ..Script::default() }, TcpLimits::default())?;
    assert_eq!(reader.read_step(1, &Permit)?, TcpReadStep::Eof);
    assert!(reader.totals().peer_eof);
    assert_eq!(reader.next_deadline_ns(), None);
    Ok(())
}

#[test]
fn reversed_time_is_retryable_but_expiry_and_revocation_close_without_io() -> TestResult {
    let mut link = make_link(Script::default(), TcpLimits::default())?;
    link.check(5, &Permit)?;
    assert_eq!(link.check(4, &Permit), Err(TcpError::ClockReversed));
    link.check(6, &Permit)?;
    assert_eq!(link.read_step(7, &Deny), Err(TcpError::Denied(TcpDenial::Revoked)));
    assert_eq!(link.totals().read_calls, 0);
    let mut expired = make_link(Script::default(), TcpLimits::default())?;
    assert_eq!(expired.check(60_000_000_000, &Permit), Err(TcpError::Deadline));
    assert_eq!(expired.totals(), TcpTotals::default());
    Ok(())
}

#[test]
fn buffered_source_retains_original_age_and_debug_does_not_print_routes_or_payloads() -> TestResult {
    let mut link = make_link(Script { reads: [Ok(b"private-media".to_vec())].into(), ..Script::default() }, TcpLimits::default())?;
    link.queue_request(request()?, 0, &Permit)?;
    link.read_step(1, &Permit)?;
    assert_eq!(link.next_deadline_ns(), Some(1 + WIRE_LIFETIME_NS));
    let debug = format!("{link:?}");
    for secret in ["private-media", "camera.local", "127.0.0.1", "DESCRIBE"] { assert!(!debug.contains(secret)); }
    assert_eq!(link.check(1 + WIRE_LIFETIME_NS, &Permit), Err(TcpError::ReadDeadline));
    assert_eq!(link.retire().unread.ok_or("expired source missing")?.expose(), b"private-media");
    Ok(())
}

#[test]
fn invalid_configuration_and_denied_connect_make_no_connection_attempt() -> TestResult {
    for limits in [TcpLimits { chunk_bytes: 0, ..TcpLimits::default() },
        TcpLimits { chunk_bytes: MAX_WIRE_CHUNK + 1, ..TcpLimits::default() },
        TcpLimits { connect_timeout_ns: 0, ..TcpLimits::default() },
        TcpLimits { max_io_calls: 0, ..TcpLimits::default() }] {
        assert!(!RtspTcpLink::connect(binding()?, limits, 0, 100, &Permit)
            .err().ok_or("invalid limits accepted")?.connection_attempted);
    }
    let denied = RtspTcpLink::connect(binding()?, TcpLimits::default(), 0, 100, &Deny)
        .err().ok_or("denied route connected")?;
    assert_eq!(denied.reason, TcpError::Denied(TcpDenial::Revoked));
    assert!(!denied.connection_attempted);
    assert!(TcpBinding::new(KEY, SocketAddr::from(([0, 0, 0, 0], 8554)), "camera", TcpSecurityPolicy::OwnerApprovedPlaintext).is_err());
    assert!(TcpBinding::new(KEY, SocketAddr::from(([127, 0, 0, 1], 8554)), "user:secret@camera", TcpSecurityPolicy::OwnerApprovedPlaintext).is_err());
    Ok(())
}

#[test]
fn actual_loopback_socket_uses_exact_route_and_transfers_native_bytes() -> TestResult {
    let listener = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    listener.set_nonblocking(true)?;
    let route = TcpBinding::new(KEY, listener.local_addr()?, "camera.local", TcpSecurityPolicy::OwnerApprovedPlaintext)?;
    let mut link = RtspTcpLink::connect(route, TcpLimits::default(), 0, 60_000_000_000, &Permit)?;
    let (mut peer, _) = listener.accept()?;
    peer.set_read_timeout(Some(Duration::from_secs(1)))?;
    peer.set_write_timeout(Some(Duration::from_secs(1)))?;
    let request = request()?; let original = request.bytes().to_vec();
    link.queue_request(request, 0, &Permit)?;
    for now in 1..100 {
        if matches!(link.write_step(now, &Permit)?, TcpWriteStep::Sent { .. }) { break; }
    }
    assert!(!link.has_pending_request());
    let mut received = vec![0; original.len()];
    peer.read_exact(&mut received)?;
    assert_eq!(received, original);
    peer.write_all(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")?;
    let mut combined = Vec::new();
    for now in 100..200 {
        match link.read_step(now, &Permit)? {
            TcpReadStep::Buffered => combined.extend_from_slice(link.acknowledge_read().ok_or("missing native read")?.expose()),
            TcpReadStep::Pending => std::thread::sleep(Duration::from_millis(1)),
            TcpReadStep::Eof => return Err("unexpected loopback EOF".into()),
        }
        if combined.ends_with(b"\r\n\r\n") { break; }
    }
    assert_eq!(combined, b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n");
    let retired = link.retire();
    assert!(retired.request.is_none());
    assert!(retired.unread.is_none());
    Ok(())
}
