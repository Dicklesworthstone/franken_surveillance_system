#![forbid(unsafe_code)]
//! Real native negotiation must agree with recording selection before any SETUP.
//! Loopback and owner-supplied fixture configuration only; no external camera access.

mod hevc_recording_support;

use std::cell::Cell;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::Duration;

use fss_packet::StreamKey;
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientProgress, ClientState};
use fss_reference::rtsp::hevc_client::HevcClientPoll;
use fss_reference::rtsp::hevc_client::pictures::HevcPictureClientPoll as Event;
use fss_reference::rtsp::hevc_recording_capture::live::{
    AutomaticHevcRecordingStep as Step, AutomaticLiveHevcRecording, LiveHevcRecordingConfig,
    LiveHevcRecordingError, LiveHevcRecordingFailure,
};
use fss_reference::rtsp::hevc_recording_capture::{CaptureError, HevcCapturePoll};
use fss_reference::rtsp::live_hevc::{
    LiveHevcConfig, LiveHevcError, LiveHevcStep, QueuedHevcRequest, SocketReadiness,
};
use fss_reference::rtsp::recording_collector::CollectorError;
use fss_reference::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpError, TcpLimits, TcpOperation, TcpSecurityPolicy,
    TcpWriteStep,
};
use hevc_recording_support::{Error, SSRC, configuration, nals, packet, scope};

type Test<T = ()> = Result<T, Error>;
const LEASE: u64 = 100_000_000_000;
const LOOP_BOUND: usize = 32_768;
const PRIVATE_SDP: &str = "PRIVATE_SDP_SENTINEL";

struct Authority {
    binding: TcpBinding,
    revoked: Cell<bool>,
}
impl TcpAuthority for Authority {
    fn checkpoint(
        &self,
        binding: &TcpBinding,
        _: TcpOperation,
        now: u64,
        until: u64,
    ) -> Result<(), TcpDenial> {
        if binding != &self.binding {
            return Err(TcpDenial::Unauthorized);
        }
        if self.revoked.get() {
            return Err(TcpDenial::Revoked);
        }
        if until != LEASE || now >= until {
            return Err(TcpDenial::Deadline);
        }
        Ok(())
    }
}

fn credentials() -> Test<DigestCredentials<'static>> {
    Ok(DigestCredentials::new(
        "selection-user",
        "selection-password",
    )?)
}
fn response(cseq: u32, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len(),
    )
    .into_bytes()
}
fn description(payloads: &[u8]) -> String {
    let mut sdp =
        format!("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns={PRIVATE_SDP}\r\nt=0 0\r\na=control:*\r\n");
    for (index, payload) in payloads.iter().enumerate() {
        sdp.push_str(&format!(
            "m=video 0 RTP/AVP {payload}\r\na=rtpmap:{payload} H265/90000\r\na=control:track-{index}\r\n"
        ));
    }
    sdp
}

struct Fixture {
    driver: AutomaticLiveHevcRecording,
    peer: TcpStream,
    authority: Authority,
    credentials: DigestCredentials<'static>,
    raw: Vec<u8>,
    nonce: u128,
}
impl Fixture {
    fn new(chunk: usize, payload: u8, media_index: usize) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let binding = TcpBinding::new(
            StreamKey {
                ingress: 1,
                generation: 1,
                ssrc: SSRC,
            },
            listener.local_addr()?,
            "fixture.local",
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )?;
        let authority = Authority {
            binding: binding.clone(),
            revoked: Cell::new(false),
        };
        let live = LiveHevcConfig {
            protocol: ClientConfig {
                presentation_uri: "rtsp://fixture.local/live/".into(),
                control_root_uri: "rtsp://fixture.local/live".into(),
                media_index,
                channels: (0, 1),
                response_timeout_ns: 10_000_000_000,
                default_session_timeout_seconds: 60,
            },
            binding,
            transport: TcpLimits {
                chunk_bytes: chunk,
                ..TcpLimits::default()
            },
            reorder: Default::default(),
            reconstruction: Default::default(),
            assembly: Default::default(),
            realm: "selection-realm".into(),
            digest_policy: DigestPolicy::default(),
            deadline_ns: LEASE,
            max_steps: 200_000,
        };
        let recording = LiveHevcRecordingConfig {
            scope: scope()?,
            payload_type: payload,
            configuration: configuration()?,
            time_scale: 90_000,
            limits: Default::default(),
        };
        let driver = AutomaticLiveHevcRecording::connect(live, recording, 0, &authority)?;
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        Ok(Self {
            driver,
            peer,
            authority,
            credentials: credentials()?,
            raw: Vec::new(),
            nonce: 0,
        })
    }

    fn poll(
        &mut self,
        readable: bool,
        writable: bool,
        now: u64,
    ) -> Result<Step, LiveHevcRecordingFailure> {
        self.nonce += 1; // The finite fixture loop bound is far below u128 exhaustion.
        self.driver.poll(
            SocketReadiness { readable, writable },
            &self.credentials,
            self.nonce.to_be_bytes(),
            now,
            &self.authority,
        )
    }

    fn command(&mut self, now: u64) -> Test<(QueuedHevcRequest, Vec<u8>)> {
        let Step::Queued(queued) = self.poll(false, false, now)? else {
            return Err("missing automatic command".into());
        };
        for _ in 0..LOOP_BOUND {
            match self.poll(false, true, now)? {
                Step::Network(LiveHevcStep::Write(TcpWriteStep::Sent { cseq, bytes })) => {
                    assert_eq!((cseq, bytes), (queued.cseq, queued.bytes));
                    let mut wire = vec![0; bytes];
                    self.peer.read_exact(&mut wire)?;
                    return Ok((queued, wire));
                }
                Step::Network(
                    LiveHevcStep::Write(TcpWriteStep::Advanced { .. }) | LiveHevcStep::Pending(_),
                ) => {}
                _ => return Err("unexpected automatic command output".into()),
            }
        }
        Err("bounded command dispatch did not finish".into())
    }

    fn receiver(&mut self, bytes: &[u8], now: u64) -> Test<Box<Event>> {
        self.peer.write_all(bytes)?;
        for _ in 0..LOOP_BOUND {
            match self.poll(true, false, now)? {
                Step::Network(LiveHevcStep::Wire(chunk)) => {
                    self.raw.extend_from_slice(chunk.expose())
                }
                Step::Network(LiveHevcStep::Pending(_)) => std::thread::yield_now(),
                Step::ProtocolQueued { transport: None } => {}
                Step::Capture {
                    event,
                    connection: None,
                } => {
                    if let HevcCapturePoll::Receiver(source) = *event {
                        return Ok(source);
                    }
                    return Err("description became a media or terminal result".into());
                }
                _ => return Err("unexpected description output".into()),
            }
        }
        Err("bounded reply intake did not finish".into())
    }

    fn describe(&mut self, digest: bool) -> Test<u32> {
        let (describe, wire) = self.command(0)?;
        assert_eq!(describe.command, ClientCommand::Describe);
        assert!(!std::str::from_utf8(&wire)?.contains("Authorization:"));
        if !digest {
            return Ok(describe.cseq);
        }
        let challenge = format!(
            "RTSP/1.0 401 Unauthorized\r\nCSeq: {}\r\nWWW-Authenticate: Digest realm=\"selection-realm\", nonce=\"selection-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n",
            describe.cseq,
        );
        let source = self.receiver(challenge.as_bytes(), 1)?;
        assert!(
            matches!(source.as_ref(), Event::Client { event, work: None }
            if matches!(event.as_ref(), HevcClientPoll::AuthenticationRequired { .. }))
        );
        let (answer, wire) = self.command(2)?;
        assert_eq!(answer.command, ClientCommand::Describe);
        assert_eq!(
            answer
                .challenge
                .as_ref()
                .ok_or("missing challenge")?
                .expose_wire(),
            challenge.as_bytes()
        );
        let text = std::str::from_utf8(&wire)?;
        assert!(text.contains("Authorization: Digest "));
        assert!(!text.contains("selection-password"));
        Ok(answer.cseq)
    }

    fn refuse(&mut self, bytes: &[u8], now: u64) -> Test<LiveHevcRecordingFailure> {
        self.peer.write_all(bytes)?;
        for _ in 0..LOOP_BOUND {
            match self.poll(true, true, now) {
                Err(failure) => return Ok(failure),
                Ok(Step::Network(LiveHevcStep::Wire(chunk))) => {
                    self.raw.extend_from_slice(chunk.expose());
                }
                Ok(Step::Network(LiveHevcStep::Pending(_))) => std::thread::yield_now(),
                // Prior to the fix this path reaches the capture receiver, then arms SETUP.
                Ok(_) => {
                    return Err(
                        "mismatched selected payload was not fenced before capture/SETUP".into(),
                    );
                }
            }
        }
        Err("bounded payload-refusal intake did not finish".into())
    }
}

#[test]
fn wrong_selected_payload_refuses_before_setup_plain_short_io() -> Test {
    for chunk in [1, 7, 4096] {
        refuse_selected(chunk, false, 0, &[99], &[])?;
    }
    Ok(())
}

#[test]
fn wrong_selected_payload_refuses_before_setup_digest_short_io() -> Test {
    for chunk in [1, 7, 4096] {
        refuse_selected(chunk, true, 0, &[99], &[])?;
    }
    Ok(())
}

#[test]
fn matching_other_media_section_cannot_repair_the_selected_offer() -> Test {
    for digest in [false, true] {
        refuse_selected(7, digest, 1, &[98, 99], &[])?;
    }
    Ok(())
}

#[test]
fn refused_description_keeps_any_already_read_media_lookahead() -> Test {
    let data = nals()?;
    let nal = data.get(3).ok_or("fixture IDR missing")?;
    let packet = packet(1, 0, true, nal);
    let mut suffix = vec![b'$', 0];
    suffix.extend_from_slice(&u16::try_from(packet.bytes.len())?.to_be_bytes());
    suffix.extend_from_slice(&packet.bytes);
    refuse_selected(4096, true, 0, &[99], &suffix)
}

fn refuse_selected(
    chunk: usize,
    digest: bool,
    media_index: usize,
    payloads: &[u8],
    suffix: &[u8],
) -> Test {
    let mut f = Fixture::new(chunk, 98, media_index)?;
    let cseq = f.describe(digest)?;
    let before = f.driver.totals().ok_or("missing live accounting")?;
    let original = response(
        cseq,
        "Content-Type: application/sdp\r\n",
        &description(payloads),
    );
    let mut wire = original.clone();
    wire.extend_from_slice(suffix);
    let raw_start = f.raw.len();
    let failure = f.refuse(&wire, 3)?;
    assert_eq!(
        failure.reason,
        LiveHevcRecordingError::Capture(CaptureError::Collection(CollectorError::StreamMismatch,))
    );
    assert!(!format!("{failure:?}").contains(PRIVATE_SDP));
    let retired = failure
        .retirement
        .ok_or("refusal lost original ownership")?;
    let Event::Client { event, work: None } =
        *retired.unoffered_event.ok_or("lost selected response")?
    else {
        return Err("wrong original event in refusal".into());
    };
    let HevcClientPoll::Control { source, progress } = *event else {
        return Err("selected response was replaced".into());
    };
    assert_eq!(progress, ClientProgress::Accepted(ClientState::Described));
    assert_eq!(source.expose_wire(), original);
    let connection = retired.connection.ok_or("missing native retirement")?;
    assert_eq!(connection.transport.totals.sent_bytes, before.sent_bytes);
    assert_eq!(connection.transport.totals.write_calls, before.write_calls);
    assert!(connection.transport.request.is_none());
    assert!(!connection.protocol.client.session.remote_session_may_exist);
    assert!(retired.capture.collection.sources.is_empty());
    assert!(retired.capture.collection.pictures.is_empty());
    assert!(retired.capture.collection.ready.is_none());
    assert!(retired.capture.event.is_none());
    assert!(retired.terminal_transport.is_none());
    let acquired = &f.raw[raw_start..];
    assert!(acquired.starts_with(&original));
    assert_eq!(
        connection.protocol.client.wire.expose(),
        &acquired[original.len()..]
    );
    assert!(wire.starts_with(acquired));
    assert_eq!(f.driver.state(), ClientState::Closed);
    assert!(!f.driver.needs_credentials());
    assert_eq!(f.driver.next_wake_ns(), None);
    assert!(f.driver.cancel().is_none());
    assert!(matches!(f.poll(true, true, 4)?, Step::Ended));
    let mut unexpected = [0_u8; 64];
    match f.peer.read(&mut unexpected) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof
            ) => {}
        _ => return Err("a command followed the refused description".into()),
    }
    Ok(())
}

#[test]
fn exact_nondefault_payload_uses_only_the_requested_media_section() -> Test {
    for expected in [96, 98, 127] {
        for digest in [false, true] {
            let mut f = Fixture::new(7, expected, 1)?;
            let cseq = f.describe(digest)?;
            let sdp = description(&[99, expected]);
            let source = f.receiver(
                &response(cseq, "Content-Type: application/sdp\r\n", &sdp),
                3,
            )?;
            assert!(
                matches!(source.as_ref(), Event::Client { event, work: None }
                if matches!(event.as_ref(), HevcClientPoll::Control {
                    progress: ClientProgress::Accepted(ClientState::Described), ..
                }))
            );
            let (setup, wire) = f.command(4)?;
            assert_eq!(setup.command, ClientCommand::Setup);
            assert!(wire.starts_with(b"SETUP rtsp://fixture.local/live/track-1 RTSP/1.0\r\n"));
            let retired = f.driver.cancel().ok_or("missing native ownership")?;
            assert!(retired.capture.collection.pictures.is_empty());
        }
    }
    Ok(())
}

#[test]
fn interim_response_neither_requires_media_nor_arms_setup() -> Test {
    let mut f = Fixture::new(7, 98, 0)?;
    let cseq = f.describe(false)?;
    let interim = format!("RTSP/1.0 100 Continue\r\nCSeq: {cseq}\r\nContent-Length: 0\r\n\r\n");
    let source = f.receiver(interim.as_bytes(), 1)?;
    assert!(
        matches!(source.as_ref(), Event::Client { event, work: None }
        if matches!(event.as_ref(), HevcClientPoll::Control { progress: ClientProgress::Interim, .. }))
    );
    assert!(!f.driver.needs_credentials());
    let original = response(
        cseq,
        "Content-Type: application/sdp\r\n",
        &description(&[98]),
    );
    let _source = f.receiver(&original, 2)?;
    let (setup, _) = f.command(3)?;
    assert_eq!(setup.command, ClientCommand::Setup);
    let _retired = f.driver.cancel().ok_or("missing native ownership")?;
    Ok(())
}

#[test]
fn revocation_precedes_reading_or_reclassifying_a_wrong_payload() -> Test {
    let mut f = Fixture::new(4096, 98, 0)?;
    let cseq = f.describe(false)?;
    let before = f.driver.totals().ok_or("missing totals")?;
    f.peer.write_all(&response(
        cseq,
        "Content-Type: application/sdp\r\n",
        &description(&[99]),
    ))?;
    f.authority.revoked.set(true);
    let failure = f
        .poll(true, true, 1)
        .err()
        .ok_or("revocation was bypassed")?;
    assert_eq!(
        failure.reason,
        LiveHevcRecordingError::Network(LiveHevcError::Transport(TcpError::Denied(
            TcpDenial::Revoked
        ),))
    );
    let retired = failure.retirement.ok_or("missing revoked ownership")?;
    assert_eq!(
        retired
            .connection
            .ok_or("missing native ownership")?
            .transport
            .totals,
        before
    );
    assert!(retired.unoffered_event.is_none());
    assert!(f.driver.cancel().is_none());
    Ok(())
}
