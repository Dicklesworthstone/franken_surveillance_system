#![forbid(unsafe_code)]
//! Real bounded loopback acquisition; no camera, external service or detached task.

use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::rtsp::authentication::{DigestCredentials, DigestPolicy};
use crate::rtsp::client::{ClientCommand, ClientConfig, ClientState};
use crate::rtsp::jpeg_client::JpegClientPoll;
use crate::rtsp::live_jpeg::{
    LiveJpegConfig, LiveJpegConnection, LiveJpegError, LiveJpegStep, LiveJpegWait,
    QueuedJpegRequest, SocketReadiness,
};
use crate::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpError, TcpLimits, TcpOperation, TcpSecurityPolicy,
    TcpWriteStep,
};
use fss_packet::ReorderLimits;
use fss_packet::jpeg::{JpegLimits, JpegReceivePoll};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const KEY: fss_packet::StreamKey = super::KEY;
const LEASE: u64 = 100_000_000_000;
const RESPONSE_TIMEOUT: u64 = 10_000_000_000;
const READ: SocketReadiness = SocketReadiness {
    readable: true,
    writable: false,
};
const WRITE: SocketReadiness = SocketReadiness {
    readable: false,
    writable: true,
};

struct Authority {
    binding: TcpBinding,
    revoked: Cell<bool>,
    reject_queue: Cell<bool>,
    deny_second_read_check: Cell<bool>,
    read_checks: Cell<usize>,
    checks: Cell<usize>,
}
impl TcpAuthority for Authority {
    fn checkpoint(
        &self,
        binding: &TcpBinding,
        operation: TcpOperation,
        now: u64,
        deadline: u64,
    ) -> Result<(), TcpDenial> {
        self.checks.set(self.checks.get() + 1);
        if binding != &self.binding {
            return Err(TcpDenial::Unauthorized);
        }
        if self.revoked.get() {
            return Err(TcpDenial::Revoked);
        }
        if deadline != LEASE || now >= deadline {
            return Err(TcpDenial::Deadline);
        }
        if self.reject_queue.get() && operation == TcpOperation::QueueRequest {
            return Err(TcpDenial::Budget);
        }
        if operation == TcpOperation::Read {
            self.read_checks.set(self.read_checks.get() + 1);
            if self.deny_second_read_check.get() && self.read_checks.get() == 2 {
                return Err(TcpDenial::Revoked);
            }
        }
        Ok(())
    }
}

fn scope(peer: SocketAddr) -> Test<(LiveJpegConfig, Authority)> {
    let binding = TcpBinding::new(
        KEY,
        peer,
        "camera.local",
        TcpSecurityPolicy::OwnerApprovedPlaintext,
    )?;
    let authority = Authority {
        binding: binding.clone(),
        revoked: Cell::new(false),
        reject_queue: Cell::new(false),
        deny_second_read_check: Cell::new(false),
        read_checks: Cell::new(0),
        checks: Cell::new(0),
    };
    Ok((
        LiveJpegConfig {
            protocol: ClientConfig {
                presentation_uri: "rtsp://camera.local/live/".into(),
                control_root_uri: "rtsp://camera.local/live".into(),
                media_index: 1,
                channels: (6, 7),
                response_timeout_ns: RESPONSE_TIMEOUT,
                default_session_timeout_seconds: 60,
            },
            binding,
            transport: TcpLimits::default(),
            payload_type: 26,
            reorder: ReorderLimits::default(),
            jpeg: JpegLimits::default(),
            realm: "fixture-camera".into(),
            digest_policy: DigestPolicy::default(),
            deadline_ns: LEASE,
            max_steps: 100_000,
        },
        authority,
    ))
}
fn credentials() -> Test<DigestCredentials<'static>> {
    Ok(DigestCredentials::new("camera-user", "camera-password")?)
}
fn response(cseq: u32, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
    .into_bytes()
}
fn challenge(cseq: u32) -> Vec<u8> {
    format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"fixture-camera\", nonce=\"private-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n").into_bytes()
}
fn description() -> &'static str {
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=audio 0 RTP/AVP 0\r\na=control:audio\r\nm=video 0 RTP/AVP 26\r\na=control:jpeg\r\n"
}
fn packet(sequence: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 26 | if marker { 0x80 } else { 0 }];
    bytes.extend(sequence.to_be_bytes());
    bytes.extend(timestamp.to_be_bytes());
    bytes.extend(KEY.ssrc.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 50, 4, 3]);
    bytes.extend_from_slice(payload);
    bytes
}
fn interleaved(channel: u8, packet: &[u8]) -> Vec<u8> {
    let mut wire = vec![b'$', channel];
    wire.extend((packet.len() as u16).to_be_bytes());
    wire.extend_from_slice(packet);
    wire
}

struct Fixture {
    connection: LiveJpegConnection,
    peer: TcpStream,
    authority: Authority,
}
impl Fixture {
    fn new(chunk: usize) -> Test<Self> {
        Self::configured(|config| config.transport.chunk_bytes = chunk)
    }
    fn configured(change: impl FnOnce(&mut LiveJpegConfig)) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (mut config, authority) = scope(listener.local_addr()?)?;
        change(&mut config);
        let connection = LiveJpegConnection::connect(config, 0, &authority)?;
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        Ok(Self {
            connection,
            peer,
            authority,
        })
    }
    fn flush(&mut self, queued: &QueuedJpegRequest, now: u64) -> Test<Vec<u8>> {
        for _ in 0..32_768 {
            match self.connection.poll(WRITE, now, &self.authority)? {
                LiveJpegStep::Write(TcpWriteStep::Sent { cseq, bytes }) => {
                    assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                    let mut received = vec![0; bytes];
                    self.peer.read_exact(&mut received)?;
                    return Ok(received);
                }
                LiveJpegStep::Write(TcpWriteStep::Advanced { .. }) | LiveJpegStep::Pending(_) => {}
                step => return Err(format!("unexpected flush step: {step:?}").into()),
            }
        }
        Err("bounded request flush did not finish".into())
    }
    fn command(&mut self, command: ClientCommand, now: u64) -> Test<(QueuedJpegRequest, Vec<u8>)> {
        let queued = self.connection.request(
            command,
            &credentials()?,
            [now as u8 + 1; 16],
            now,
            &self.authority,
        )?;
        let bytes = self.flush(&queued, now)?;
        Ok((queued, bytes))
    }
    fn receive(&mut self, bytes: &[u8], now: u64) -> Test<Vec<JpegClientPoll>> {
        self.peer.write_all(bytes)?;
        let mut original = Vec::new();
        let mut interpreted = Vec::new();
        let mut events = Vec::new();
        for _ in 0..32_768 {
            match self.connection.poll(READ, now, &self.authority)? {
                LiveJpegStep::Wire(chunk) => {
                    assert_eq!(chunk.admitted_ns(), now);
                    original.extend_from_slice(chunk.expose());
                }
                LiveJpegStep::Protocol { event, transport } => {
                    match event.as_ref() {
                        JpegClientPoll::Control { source, .. }
                        | JpegClientPoll::Rtp { source, .. }
                        | JpegClientPoll::Rtcp { source, .. } => {
                            interpreted.extend_from_slice(source.expose_wire());
                            assert!(
                                original.starts_with(&interpreted),
                                "original wire must transfer before interpretation"
                            );
                        }
                        _ => {}
                    }
                    let stop = transport.is_some()
                        || matches!(
                            event.as_ref(),
                            JpegClientPoll::AuthenticationRequired { .. }
                        );
                    events.push(*event);
                    if stop {
                        assert_eq!(original, bytes);
                        return Ok(events);
                    }
                }
                LiveJpegStep::Pending(wait) => {
                    if original.len() == bytes.len()
                        && wait.wake_at_ns.is_none_or(|wake| wake > now)
                    {
                        assert_eq!(original, bytes);
                        return Ok(events);
                    }
                    std::thread::yield_now();
                }
                step => return Err(format!("unexpected receive step: {step:?}").into()),
            }
        }
        Err("bounded response receive did not finish".into())
    }
    fn playing(&mut self) -> Test {
        for (command, now, headers, body) in [
            (
                ClientCommand::Describe,
                0,
                "Content-Type: application/sdp\r\n",
                description(),
            ),
            (
                ClientCommand::Setup,
                1,
                "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=6-7;ssrc=00000007\r\n",
                "",
            ),
            (ClientCommand::Play, 2, "Session: fixture\r\n", ""),
        ] {
            let (queued, bytes) = self.command(command, now)?;
            if command == ClientCommand::Setup {
                assert!(
                    std::str::from_utf8(&bytes)?
                        .starts_with("SETUP rtsp://camera.local/live/jpeg RTSP/1.0\r\n")
                );
            }
            let events = self.receive(&response(queued.cseq, headers, body), now)?;
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event, JpegClientPoll::Control { .. }))
            );
        }
        assert_eq!(self.connection.state(), ClientState::Playing);
        assert_eq!(
            self.connection
                .media()
                .ok_or("missing selection")?
                .payload_type(),
            26
        );
        Ok(())
    }
}

#[test]
fn route_and_payload_are_validated_before_any_connection_effect() -> Test {
    for bad_route in [true, false] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (mut config, authority) = scope(listener.local_addr()?)?;
        if bad_route {
            config.protocol.presentation_uri = "rtsp://other-camera/live/".into();
        } else {
            config.payload_type = 95;
        }
        let error = LiveJpegConnection::connect(config, 0, &authority)
            .err()
            .ok_or("unexpected connect")?;
        assert!(!error.connection_attempted);
        assert_eq!(authority.checks.get(), 0);
    }
    Ok(())
}

#[test]
fn short_writes_require_readiness_and_do_not_claim_remote_acceptance() -> Test {
    let mut f = Fixture::new(3)?;
    let queued = f.connection.request(
        ClientCommand::Describe,
        &credentials()?,
        [1; 16],
        0,
        &f.authority,
    )?;
    assert!(matches!(
        f.connection
            .poll(SocketReadiness::default(), 0, &f.authority)?,
        LiveJpegStep::Pending(LiveJpegWait {
            readable: false,
            writable: true,
            ..
        })
    ));
    assert_eq!(
        f.connection.totals().ok_or("missing totals")?.write_calls,
        0
    );
    let bytes = f.flush(&queued, 0)?;
    assert!(
        std::str::from_utf8(&bytes)?.starts_with("DESCRIBE rtsp://camera.local/live/ RTSP/1.0\r\n")
    );
    assert!(!std::str::from_utf8(&bytes)?.contains("Authorization:"));
    let totals = f.connection.totals().ok_or("missing totals")?;
    assert_eq!(totals.sent_bytes, bytes.len() as u64);
    assert!(totals.write_calls > 1);
    assert_eq!(f.connection.state(), ClientState::Idle);
    assert!(f.connection.cancel().is_some());
    assert!(f.connection.cancel().is_none());
    Ok(())
}

#[test]
fn digest_response_queue_refusal_returns_the_original_challenge_and_unsent_request() -> Test {
    let mut f = Fixture::new(4096)?;
    let (queued, _) = f.command(ClientCommand::Describe, 0)?;
    let original = challenge(queued.cseq);
    let events = f.receive(&original, 1)?;
    assert!(
        events
            .iter()
            .any(|event| matches!(event, JpegClientPoll::AuthenticationRequired { .. }))
    );
    f.authority.reject_queue.set(true);
    let failure = f
        .connection
        .respond(&credentials()?, [9; 16], 2, &f.authority)
        .err()
        .ok_or("unexpected queued answer")?;
    assert_eq!(
        failure.reason,
        LiveJpegError::Transport(TcpError::Denied(TcpDenial::Budget))
    );
    let retired = failure.retirement.ok_or("missing fatal retirement")?;
    assert_eq!(
        retired
            .answered_challenge
            .as_ref()
            .ok_or("lost challenge")?
            .expose_wire(),
        original
    );
    let request = retired
        .unqueued_request
        .as_ref()
        .ok_or("lost prepared request")?;
    assert_eq!(request.cseq(), queued.cseq + 1);
    assert!(std::str::from_utf8(request.bytes())?.contains("Authorization: Digest"));
    assert_eq!(retired.transport.request_sent_bytes, 0);
    assert!(!format!("{retired:?}").contains("private-nonce"));
    assert!(!format!("{retired:?}").contains("camera-password"));
    assert!(f.connection.cancel().is_none());
    Ok(())
}

#[test]
fn real_loopback_socket_reassembles_and_decodes_camera_jpeg_with_original_wire_first() -> Test {
    for chunk in [1, 17, 4096] {
        let mut f = Fixture::new(chunk)?;
        f.playing()?;
        let entropy = super::scan()?;
        let probation = packet(1, 0, true, entropy);
        let image = packet(2, 90_000, true, entropy);
        let mut wire = interleaved(6, &probation);
        wire.extend_from_slice(&interleaved(6, &image));
        let events = f.receive(&wire, 3)?;
        let originals: Vec<_> = events
            .iter()
            .filter_map(|event| {
                if let JpegClientPoll::Rtp { source, .. } = event {
                    Some(source.expose_wire().to_vec())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            originals,
            [interleaved(6, &probation), interleaved(6, &image)]
        );
        let mut frames = Vec::new();
        for event in events {
            if let JpegClientPoll::Jpeg(JpegReceivePoll::Packet { reconstruction, .. }) = event
                && let Some(frame) = reconstruction?.frame
            {
                frames.push(*frame);
            }
        }
        assert_eq!(frames.len(), 1);
        super::assert_luma(frames.pop().ok_or("no socket JPEG")?)?;
        assert!(f.authority.read_checks.get() > 0);
        let totals = f.connection.totals().ok_or("missing live accounting")?;
        assert!(totals.received_bytes >= wire.len() as u64);
        assert!(f.connection.cancel().is_some());
    }
    Ok(())
}

#[test]
fn real_loopback_eof_drains_accepted_jpeg_before_one_terminal_retirement() -> Test {
    let mut f = Fixture::new(31)?;
    f.playing()?;
    let entropy = super::scan()?;
    let mut wire = interleaved(6, &packet(1, 0, true, entropy));
    wire.extend_from_slice(&interleaved(6, &packet(2, 90_000, true, entropy)));
    f.peer.write_all(&wire)?;
    f.peer.shutdown(Shutdown::Write)?;
    let mut originals = Vec::new();
    let mut images = 0;
    let mut terminal = 0;
    let mut eof = 0;
    let mut ended = false;
    let mut last_wait = None;
    let started = Instant::now();
    for _ in 0..32768 {
        if started.elapsed() >= Duration::from_secs(2) {
            break;
        }
        let now = 3 + u64::try_from(started.elapsed().as_nanos())?;
        let step = f.connection.poll(READ, now, &f.authority)?;
        match step {
            LiveJpegStep::Wire(chunk) => originals.extend_from_slice(chunk.expose()),
            LiveJpegStep::Protocol { event, transport } => {
                if let Some(transport) = transport {
                    assert!(transport.totals.peer_eof);
                    assert!(matches!(
                        event.as_ref(),
                        JpegClientPoll::Ended {
                            media: Some(JpegReceivePoll::Ended { discarded: None }),
                            retirement: Some(_),
                        }
                    ));
                    terminal += 1;
                }
                if let JpegClientPoll::Jpeg(JpegReceivePoll::Packet { reconstruction, .. }) = *event
                    && let Some(frame) = reconstruction?.frame
                {
                    super::assert_luma(*frame)?;
                    images += 1;
                }
            }
            LiveJpegStep::InputEnded => eof += 1,
            LiveJpegStep::Pending(wait) => {
                last_wait = Some(wait);
                // Readiness is advisory: FIN delivery runs on kernel time. Keep
                // the owner clock advancing and bound actual waiting, not just
                // the number of frozen-clock WouldBlock polls.
                std::thread::sleep(Duration::from_millis(1));
            }
            LiveJpegStep::Ended => {
                ended = true;
                break;
            }
            step => return Err(format!("unexpected EOF progress: {step:?}").into()),
        }
    }
    assert!(
        ended,
        "wire={}, images={images}, terminal={terminal}, last={last_wait:?}",
        originals.len()
    );
    assert_eq!(originals, wire);
    assert_eq!((images, terminal, eof), (1, 1, 1));
    assert!(f.connection.cancel().is_none());
    Ok(())
}
