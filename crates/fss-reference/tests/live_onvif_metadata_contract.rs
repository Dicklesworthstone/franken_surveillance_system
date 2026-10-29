#![forbid(unsafe_code)]
//! Real bounded loopback acquisition; no camera, external service or detached task.

use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use fss_packet::{OnvifMetadataLimits, OnvifMetadataReceivePoll, ReorderLimits, StreamKey};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientError, ClientState};
use fss_reference::rtsp::framed::WireIntakeError;
use fss_reference::rtsp::live_metadata::{
    LiveMetadataConfig, LiveMetadataConnection, LiveMetadataError, LiveMetadataStep,
    LiveMetadataWait, QueuedMetadataRequest, SocketReadiness,
};
use fss_reference::rtsp::metadata_client::{MetadataClientError, MetadataClientPoll};
use fss_reference::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpError, TcpLimits, TcpOperation, TcpSecurityPolicy,
    TcpWriteStep,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey {
    ingress: 810,
    generation: 3,
    ssrc: 7,
};
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

fn scope(peer: SocketAddr) -> Test<(LiveMetadataConfig, Authority)> {
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
        LiveMetadataConfig {
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
            payload_type: 107,
            reorder: ReorderLimits::default(),
            metadata: OnvifMetadataLimits::default(),
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
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:video\r\nm=application 0 RTP/AVP 107\r\na=rtpmap:107 vnd.onvif.metadata/90000\r\na=control:metadata\r\n"
}
fn packet(sequence: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 107 | if marker { 0x80 } else { 0 }];
    bytes.extend(sequence.to_be_bytes());
    bytes.extend(timestamp.to_be_bytes());
    bytes.extend(KEY.ssrc.to_be_bytes());
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
    connection: LiveMetadataConnection,
    peer: TcpStream,
    authority: Authority,
}
impl Fixture {
    fn new(chunk: usize) -> Test<Self> {
        Self::configured(|config| config.transport.chunk_bytes = chunk)
    }
    fn configured(change: impl FnOnce(&mut LiveMetadataConfig)) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let (mut config, authority) = scope(listener.local_addr()?)?;
        change(&mut config);
        let connection = LiveMetadataConnection::connect(config, 0, &authority)?;
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
    fn flush(&mut self, queued: &QueuedMetadataRequest, now: u64) -> Test<Vec<u8>> {
        for _ in 0..32_768 {
            match self.connection.poll(WRITE, now, &self.authority)? {
                LiveMetadataStep::Write(TcpWriteStep::Sent { cseq, bytes }) => {
                    assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                    let mut received = vec![0; bytes];
                    self.peer.read_exact(&mut received)?;
                    return Ok(received);
                }
                LiveMetadataStep::Write(TcpWriteStep::Advanced { .. })
                | LiveMetadataStep::Pending(_) => {}
                step => return Err(format!("unexpected flush step: {step:?}").into()),
            }
        }
        Err("bounded request flush did not finish".into())
    }
    fn command(
        &mut self,
        command: ClientCommand,
        now: u64,
    ) -> Test<(QueuedMetadataRequest, Vec<u8>)> {
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
    fn receive(&mut self, bytes: &[u8], now: u64) -> Test<Vec<MetadataClientPoll>> {
        self.peer.write_all(bytes)?;
        let mut original = Vec::new();
        let mut interpreted = Vec::new();
        let mut events = Vec::new();
        for _ in 0..32_768 {
            match self.connection.poll(READ, now, &self.authority)? {
                LiveMetadataStep::Wire(chunk) => {
                    assert_eq!(chunk.admitted_ns(), now);
                    original.extend_from_slice(chunk.expose());
                }
                LiveMetadataStep::Protocol { event, transport } => {
                    match &event {
                        MetadataClientPoll::Control { source, .. }
                        | MetadataClientPoll::Rtp { source, .. }
                        | MetadataClientPoll::Rtcp { source, .. } => {
                            interpreted.extend_from_slice(source.expose_wire());
                            assert!(
                                original.starts_with(&interpreted),
                                "original wire must transfer before interpretation"
                            );
                        }
                        _ => {}
                    }
                    let stop = transport.is_some()
                        || matches!(event, MetadataClientPoll::AuthenticationRequired { .. });
                    events.push(event);
                    if stop {
                        assert_eq!(original, bytes);
                        return Ok(events);
                    }
                }
                LiveMetadataStep::Pending(wait) => {
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
                        .starts_with("SETUP rtsp://camera.local/live/metadata RTSP/1.0\r\n")
                );
            }
            let events = self.receive(&response(queued.cseq, headers, body), now)?;
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event, MetadataClientPoll::Control { .. }))
            );
        }
        assert_eq!(self.connection.state(), ClientState::Playing);
        assert_eq!(
            self.connection
                .media()
                .ok_or("missing selection")?
                .payload_type(),
            107
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
        let error = LiveMetadataConnection::connect(config, 0, &authority)
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
        LiveMetadataStep::Pending(LiveMetadataWait {
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
fn live_negotiation_short_reads_and_timestamp_changing_document_preserve_sources() -> Test {
    let mut f = Fixture::new(7)?;
    f.playing()?;
    let xml = b"<tt:MetadataStream xmlns:tt=\"http://www.onvif.org/ver10/schema\"><tt:VideoAnalytics/></tt:MetadataStream>";
    let split = xml.len() / 2;
    let packets = [
        packet(1, 1, false, b"unknown-start"),
        packet(2, 2, true, b"old-document-end"),
        packet(3, 3, false, &xml[..split]),
        packet(4, 4, true, &xml[split..]),
    ];
    let mut wire = Vec::new();
    for packet in &packets {
        wire.extend(interleaved(6, packet));
    }
    wire.extend(interleaved(7, b"malformed-rtcp-retained"));
    let events = f.receive(&wire, 3)?;
    let sources: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            MetadataClientPoll::Rtp { source, .. } => Some(source.expose_wire()),
            _ => None,
        })
        .collect();
    assert_eq!(sources.len(), packets.len());
    for (source, packet) in sources.into_iter().zip(&packets) {
        assert_eq!(source, interleaved(6, packet));
    }
    let documents: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            MetadataClientPoll::Metadata(OnvifMetadataReceivePoll::Packet {
                reconstruction: Ok(output),
                ..
            }) => output.document.as_ref(),
            _ => None,
        })
        .collect();
    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0].bytes(), xml);
    assert_eq!(documents[0].boundary().sequence, 2);
    assert_eq!(documents[0].sources().len(), 2);
    assert_eq!(documents[0].sources()[0].timestamp, 3);
    assert_eq!(documents[0].sources()[1].timestamp, 4);
    assert!(events.iter().any(|event| matches!(
        event,
        MetadataClientPoll::Rtcp {
            validation: Err(_),
            ..
        }
    )));
    let retired = f.connection.cancel().ok_or("missing retirement")?;
    assert!(retired.protocol.session.remote_session_may_exist);
    assert!(retired.transport.request.is_none());
    assert!(matches!(
        f.connection.poll(READ, 4, &f.authority)?,
        LiveMetadataStep::Ended
    ));
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
            .any(|event| matches!(event, MetadataClientPoll::AuthenticationRequired { .. }))
    );
    f.authority.reject_queue.set(true);
    let failure = f
        .connection
        .respond(&credentials()?, [9; 16], 2, &f.authority)
        .err()
        .ok_or("unexpected queued answer")?;
    assert_eq!(
        failure.reason,
        LiveMetadataError::Transport(TcpError::Denied(TcpDenial::Budget))
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
fn post_read_revocation_preserves_uninterpreted_original_bytes() -> Test {
    let mut f = Fixture::new(4096)?;
    let (queued, _) = f.command(ClientCommand::Describe, 0)?;
    let original = response(
        queued.cseq,
        "Content-Type: application/sdp\r\n",
        description(),
    );
    f.peer.write_all(&original)?;
    f.authority.deny_second_read_check.set(true);
    let failure = f
        .connection
        .poll(READ, 1, &f.authority)
        .err()
        .ok_or("post-read revocation was ignored")?;
    assert_eq!(
        failure.reason,
        LiveMetadataError::Transport(TcpError::Denied(TcpDenial::Revoked))
    );
    let retired = failure.retirement.ok_or("missing retirement")?;
    assert_eq!(
        retired
            .transport
            .unread
            .as_ref()
            .ok_or("lost original read")?
            .expose(),
        original
    );
    assert!(retired.protocol.wire.is_empty());
    assert!(retired.protocol.metadata.is_none());
    assert_eq!(retired.transport.totals.read_calls, 1);
    assert_eq!(
        retired.transport.totals.received_bytes,
        original.len() as u64
    );
    Ok(())
}

#[test]
fn silent_response_deadline_closes_without_an_extra_socket_operation() -> Test {
    let mut f = Fixture::new(4096)?;
    let (_queued, _request) = f.command(ClientCommand::Describe, 0)?;
    let before = f.connection.totals().ok_or("missing totals")?;
    let LiveMetadataStep::Protocol {
        event: MetadataClientPoll::Fault {
            reason, retirement, ..
        },
        transport: Some(transport),
    } = f
        .connection
        .poll(SocketReadiness::default(), RESPONSE_TIMEOUT, &f.authority)?
    else {
        return Err("silent response timeout did not close the connection".into());
    };
    assert_eq!(
        reason,
        MetadataClientError::Session(ClientError::ResponseTimeout)
    );
    assert!(retirement.session.pending_cseq.is_some());
    assert_eq!(transport.totals.read_calls, before.read_calls);
    assert_eq!(transport.totals.write_calls, before.write_calls);
    assert!(f.connection.cancel().is_none());
    Ok(())
}

#[test]
fn eof_inside_a_frame_retains_its_exact_suffix_and_closes_once() -> Test {
    let mut f = Fixture::new(4096)?;
    let (_queued, _request) = f.command(ClientCommand::Describe, 0)?;
    let suffix = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Len";
    f.receive(suffix, 1)?;
    f.peer.shutdown(Shutdown::Write)?;
    let mut eof = false;
    for _ in 0..128 {
        match f.connection.poll(READ, 2, &f.authority)? {
            LiveMetadataStep::InputEnded => eof = true,
            LiveMetadataStep::Protocol {
                event:
                    MetadataClientPoll::Fault {
                        reason, retirement, ..
                    },
                transport: Some(transport),
            } => {
                assert!(eof);
                assert_eq!(
                    reason,
                    MetadataClientError::Wire(WireIntakeError::Truncated)
                );
                assert_eq!(retirement.wire.expose(), suffix);
                assert!(transport.totals.peer_eof);
                assert!(matches!(
                    f.connection.poll(READ, 3, &f.authority)?,
                    LiveMetadataStep::Ended
                ));
                assert!(f.connection.cancel().is_none());
                return Ok(());
            }
            LiveMetadataStep::Pending(_) => std::thread::yield_now(),
            step => return Err(format!("unexpected EOF step: {step:?}").into()),
        }
    }
    Err("bounded EOF did not drain".into())
}

#[test]
fn work_budget_and_clock_regression_preserve_distinct_retirement_semantics() -> Test {
    let mut f = Fixture::configured(|config| config.max_steps = 1)?;
    let queued = f.connection.request(
        ClientCommand::Describe,
        &credentials()?,
        [1; 16],
        0,
        &f.authority,
    )?;
    let failure = f
        .connection
        .poll(WRITE, 0, &f.authority)
        .err()
        .ok_or("budget not enforced")?;
    assert_eq!(failure.reason, LiveMetadataError::WorkBudget);
    let retired = failure.retirement.ok_or("lost queued request")?;
    assert_eq!(
        retired
            .transport
            .request
            .as_ref()
            .ok_or("missing request")?
            .cseq(),
        queued.cseq
    );
    assert_eq!(retired.transport.request_sent_bytes, 0);
    assert_eq!(retired.transport.totals.write_calls, 0);

    let mut f = Fixture::new(4096)?;
    assert!(matches!(
        f.connection
            .poll(SocketReadiness::default(), 5, &f.authority)?,
        LiveMetadataStep::Pending(_)
    ));
    let remaining = f.connection.remaining_steps();
    let checks = f.authority.checks.get();
    let failure = f
        .connection
        .poll(READ, 4, &f.authority)
        .err()
        .ok_or("reversed clock accepted")?;
    assert_eq!(failure.reason, LiveMetadataError::ClockReversed);
    assert!(failure.retirement.is_none());
    assert_eq!(f.connection.remaining_steps(), remaining);
    assert_eq!(f.authority.checks.get(), checks);
    f.authority.revoked.set(true);
    let retired = f
        .connection
        .cancel()
        .ok_or("cancellation requires revoked permission")?;
    assert_eq!(retired.transport.totals.sent_bytes, 0);
    Ok(())
}
