#![forbid(unsafe_code)]
//! Native HEVC selection through owned loopback sockets, not a synthetic session shortcut.
//! Original SDP and RTP frames remain source-owned even though negotiation uses a projection.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use fss_packet::hevc::HevcAssemblyLimits;
use fss_packet::{H265Limits, ReorderLimits, StreamKey};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientProgress, ClientState};
use fss_reference::rtsp::hevc_client::HevcClientPoll;
use fss_reference::rtsp::hevc_client::pictures::HevcPictureClientPoll;
use fss_reference::rtsp::live_hevc::{
    LiveHevcConfig, LiveHevcConnection, LiveHevcStep, QueuedHevcRequest, SocketReadiness,
};
use fss_reference::rtsp::tcp::{
    TcpAuthority, TcpBinding, TcpDenial, TcpLimits, TcpOperation, TcpSecurityPolicy, TcpWriteStep,
};

// Complete immutable parameter NALs from the existing native Main8 capture fixture.
const VPS: &str = "QAEMAf//AWAAAAMAkAAAAwAAAwAeugJA";
const SPS: &str = "QgEBAWAAAAMAkAAAAwAAAwAeoCCDHVZbpKTC8BaAgAAAAwCAAAADAoQ=";
const PPS: &str = "RAHAc8CJ";
const LEASE: u64 = 100_000_000_000;
const KEY: StreamKey = StreamKey {
    ingress: 71,
    generation: 1,
    ssrc: 7,
};
const REALM: &str = "selection-fixture";
const PASSWORD: &str = "selection-password-canary";
type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Authority(TcpBinding);
impl TcpAuthority for Authority {
    fn checkpoint(
        &self,
        binding: &TcpBinding,
        _: TcpOperation,
        now: u64,
        until: u64,
    ) -> Result<(), TcpDenial> {
        if binding != &self.0 {
            return Err(TcpDenial::Unauthorized);
        }
        if until != LEASE || now >= until {
            return Err(TcpDenial::Deadline);
        }
        Ok(())
    }
}

fn credentials() -> Test<DigestCredentials<'static>> {
    Ok(DigestCredentials::new("selection-user", PASSWORD)?)
}

fn mixed_offer(avc_first: bool) -> String {
    let payloads = if avc_first { "96 98" } else { "98 96" };
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\n\
         m=video 0 RTP/AVP {payloads}\r\n\
         a=rtpmap:96 H264/90000\r\n\
         a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0IAHw==,aAA=\r\n\
         a=rtpmap:98 H265/90000\r\n\
         a=fmtp:98 sprop-vps={VPS};sprop-sps={SPS};sprop-pps={PPS}\r\n\
         a=control:trackID=0\r\n"
    )
}

fn hevc_alternatives() -> String {
    mixed_offer(true)
        .replace("RTP/AVP 96 98", "RTP/AVP 99 98")
        .replace("a=rtpmap:96 H264/90000", "a=rtpmap:99 H265/90000")
        .replace(
            "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0IAHw==,aAA=",
            "a=fmtp:99 sprop-vps=QAEBAg==;sprop-sps=QgECAw==;sprop-pps=RAEDBA==",
        )
}

fn response(cseq: u32, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len(),
    )
    .into_bytes()
}

struct Fixture {
    connection: LiveHevcConnection,
    peer: TcpStream,
    authority: Authority,
    now: u64,
}
impl Fixture {
    fn new(chunk: usize, media_index: usize) -> Test<Self> {
        Self::with_selection(chunk, media_index, None, false)
    }

    fn with_selection(
        chunk: usize,
        media_index: usize,
        payload_type: Option<u8>,
        auto_ssrc: bool,
    ) -> Test<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let peer: SocketAddr = listener.local_addr()?;
        let binding = TcpBinding::new(
            KEY,
            peer,
            "camera.local",
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )?;
        let binding = if auto_ssrc {
            binding.with_auto_ssrc()
        } else {
            binding
        };
        let authority = Authority(binding.clone());
        let config = LiveHevcConfig {
            protocol: ClientConfig {
                presentation_uri: "rtsp://camera.local/live/".into(),
                control_root_uri: "rtsp://camera.local/live".into(),
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
            reorder: ReorderLimits::default(),
            reconstruction: H265Limits::default(),
            assembly: HevcAssemblyLimits::default(),
            realm: REALM.into(),
            digest_policy: DigestPolicy::default(),
            deadline_ns: LEASE,
            max_steps: 200_000,
        };
        let connection = match payload_type {
            Some(payload_type) => {
                LiveHevcConnection::connect_with_payload_type(config, payload_type, 0, &authority)
            }
            None => LiveHevcConnection::connect(config, 0, &authority),
        }?;
        let (peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.set_nodelay(true)?;
        Ok(Self {
            connection,
            peer,
            authority,
            now: 0,
        })
    }

    fn tick(&mut self) -> Test<u64> {
        self.now = self.now.checked_add(1).ok_or("fixture clock exhausted")?;
        Ok(self.now)
    }

    fn poll(&mut self, readable: bool, writable: bool) -> Test<LiveHevcStep> {
        let now = self.tick()?;
        Ok(self
            .connection
            .poll(SocketReadiness { readable, writable }, now, &self.authority)?)
    }

    fn flush(&mut self, queued: &QueuedHevcRequest) -> Test<Vec<u8>> {
        for _ in 0..32_768 {
            match self.poll(false, true)? {
                LiveHevcStep::Write(TcpWriteStep::Sent { cseq, bytes }) => {
                    assert_eq!(cseq, queued.cseq);
                    assert_eq!(bytes, queued.bytes);
                    let mut wire = vec![0; bytes];
                    self.peer.read_exact(&mut wire)?;
                    return Ok(wire);
                }
                LiveHevcStep::Write(TcpWriteStep::Advanced { .. }) | LiveHevcStep::Pending(_) => {}
                _ => return Err("unexpected event during bounded request write".into()),
            }
        }
        Err("native request write exceeded fixture work bound".into())
    }

    fn command(&mut self, command: ClientCommand) -> Test<(u32, Vec<u8>)> {
        let now = self.tick()?;
        let nonce = u128::from(now).to_be_bytes();
        let queued =
            self.connection
                .request(command, &credentials()?, nonce, now, &self.authority)?;
        let wire = self.flush(&queued)?;
        Ok((queued.cseq, wire))
    }

    fn reply(&mut self, bytes: &[u8]) -> Test<LiveHevcStep> {
        self.peer.write_all(bytes)?;
        let mut original = Vec::new();
        for _ in 0..32_768 {
            match self.poll(true, false)? {
                LiveHevcStep::Wire(chunk) => original.extend_from_slice(chunk.expose()),
                step @ LiveHevcStep::Protocol { .. } => {
                    let significant = match &step {
                        LiveHevcStep::Protocol {
                            event: HevcPictureClientPoll::Client { event, .. },
                            transport,
                        } => {
                            transport.is_some()
                                || matches!(
                                    event.as_ref(),
                                    HevcClientPoll::Control { .. }
                                        | HevcClientPoll::AuthenticationRequired { .. }
                                        | HevcClientPoll::Fault { .. }
                                        | HevcClientPoll::Rtp { .. }
                                )
                        }
                        LiveHevcStep::Protocol {
                            transport: Some(_), ..
                        } => true,
                        _ => false,
                    };
                    if significant {
                        assert_eq!(original, bytes, "original native intake was not preserved");
                        return Ok(step);
                    }
                }
                LiveHevcStep::Pending(_) => std::thread::yield_now(),
                _ => return Err("unexpected native reply event".into()),
            }
        }
        Err("native reply exceeded fixture work bound".into())
    }
}

fn accepted(step: LiveHevcStep, state: ClientState, original: &[u8]) -> Test {
    let LiveHevcStep::Protocol {
        event: HevcPictureClientPoll::Client { event, work: None },
        transport: None,
    } = step
    else {
        return Err("missing accepted native response".into());
    };
    let HevcClientPoll::Control { progress, source } = *event else {
        return Err("native event was not a control response".into());
    };
    assert_eq!(progress, ClientProgress::Accepted(state));
    assert_eq!(source.expose_wire(), original);
    Ok(())
}

#[test]
fn mixed_offers_negotiate_over_short_io_and_preserve_original_rtp() -> Test {
    for (chunk, avc_first) in [(1, true), (7, false), (4096, true)] {
        let mut f = Fixture::new(chunk, 0)?;
        let (seq, _) = f.command(ClientCommand::Describe)?;
        let original = response(
            seq,
            "Content-Type: application/sdp\r\n",
            &mixed_offer(avc_first),
        );
        accepted(f.reply(&original)?, ClientState::Described, &original)?;
        let media = f.connection.media().ok_or("missing selected HEVC media")?;
        assert_eq!(media.payload_type(), 98);
        assert_eq!(media.vps(), &[fss_reference::rtsp::decode_base64(VPS)?]);
        assert_eq!(media.sps(), &[fss_reference::rtsp::decode_base64(SPS)?]);
        assert_eq!(media.pps(), &[fss_reference::rtsp::decode_base64(PPS)?]);
        // Negotiation retains the original mixed response, not just the projection.
        assert!(std::str::from_utf8(&original)?.contains("a=rtpmap:96 H264/90000"));
        let (seq, setup) = f.command(ClientCommand::Setup)?;
        assert!(setup.starts_with(b"SETUP rtsp://camera.local/live/trackID=0 RTSP/1.0\r\n"));
        let original = response(
            seq,
            "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
            "",
        );
        accepted(f.reply(&original)?, ClientState::Ready, &original)?;
        let (seq, _) = f.command(ClientCommand::Play)?;
        let original = response(seq, "Session: fixture\r\n", "");
        accepted(f.reply(&original)?, ClientState::Playing, &original)?;
        for sequence in [1_u16, 2] {
            let mut packet = vec![0x80, 98];
            packet.extend_from_slice(&sequence.to_be_bytes());
            packet.extend_from_slice(&0_u32.to_be_bytes());
            packet.extend_from_slice(&KEY.ssrc.to_be_bytes());
            packet.extend_from_slice(&fss_reference::rtsp::decode_base64(VPS)?);
            let mut wire = vec![b'$', 0];
            wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
            wire.extend_from_slice(&packet);
            let LiveHevcStep::Protocol {
                event: HevcPictureClientPoll::Client { event, work: None },
                transport: None,
            } = f.reply(&wire)?
            else {
                return Err("native RTP admission missing".into());
            };
            let HevcClientPoll::Rtp {
                source,
                retirement: None,
                ..
            } = *event
            else {
                return Err("selected RTP was not admitted to the HEVC owner".into());
            };
            assert_eq!(source.expose_wire(), wire);
        }
        let retired = f.connection.cancel().ok_or("lost native retirement")?;
        assert!(retired.protocol.client.session.remote_session_may_exist);
        assert!(f.connection.cancel().is_none());
    }
    Ok(())
}

#[test]
fn digest_selected_description_keeps_original_challenge_and_scope() -> Test {
    let mut f = Fixture::with_selection(7, 0, Some(98), true)?;
    let (seq, unsigned) = f.command(ClientCommand::Describe)?;
    assert!(!std::str::from_utf8(&unsigned)?.contains("Authorization:"));
    let challenge = format!(
        "RTSP/1.0 401 Unauthorized\r\nCSeq: {seq}\r\nWWW-Authenticate: Digest realm=\"{REALM}\", nonce=\"selection-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n"
    );
    let LiveHevcStep::Protocol {
        event: HevcPictureClientPoll::Client { event, work: None },
        transport: None,
    } = f.reply(challenge.as_bytes())?
    else {
        return Err("matching Digest challenge not surfaced".into());
    };
    assert!(matches!(*event, HevcClientPoll::AuthenticationRequired { cseq, .. } if cseq == seq));
    let now = f.tick()?;
    let queued = f
        .connection
        .respond(&credentials()?, [42; 16], now, &f.authority)?;
    assert_eq!(
        queued
            .challenge
            .as_ref()
            .ok_or("lost challenge")?
            .expose_wire(),
        challenge.as_bytes()
    );
    let signed = f.flush(&queued)?;
    let signed = std::str::from_utf8(&signed)?;
    assert!(signed.contains("Authorization: Digest "));
    assert!(!signed.contains(PASSWORD));
    let original = response(
        queued.cseq,
        "Content-Type: application/sdp\r\n",
        &hevc_alternatives(),
    );
    accepted(f.reply(&original)?, ClientState::Described, &original)?;
    assert_eq!(
        f.connection.media().ok_or("missing media")?.payload_type(),
        98
    );
    let (_, setup) = f.command(ClientCommand::Setup)?;
    let setup = std::str::from_utf8(&setup)?;
    assert!(setup.starts_with("SETUP rtsp://camera.local/live/trackID=0 RTSP/1.0\r\n"));
    assert!(setup.contains("Authorization: Digest "));
    assert!(!setup.contains(PASSWORD));
    let _retirement = f.connection.cancel().ok_or("missing retirement")?;
    Ok(())
}

#[test]
fn exact_native_hevc_payload_selects_its_own_sets_and_coexists_with_auto_ssrc() -> Test {
    for (payload_type, auto_ssrc) in [(98, false), (99, false), (98, true), (99, true)] {
        let mut f = Fixture::with_selection(7, 0, Some(payload_type), auto_ssrc)?;
        let (seq, _) = f.command(ClientCommand::Describe)?;
        let original = response(
            seq,
            "Content-Type: application/sdp\r\n",
            &hevc_alternatives(),
        );
        accepted(f.reply(&original)?, ClientState::Described, &original)?;
        let media = f.connection.media().ok_or("exact HEVC payload missing")?;
        assert_eq!(media.payload_type(), payload_type);
        let expected = if payload_type == 98 {
            [VPS, SPS, PPS]
        } else {
            // Distinct header-screening sets prove no borrowing from payload 98.
            // This second offer does not claim decodable parameter syntax.
            ["QAEBAg==", "QgECAw==", "RAEDBA=="]
        };
        for (actual, expected) in [media.vps(), media.sps(), media.pps()]
            .into_iter()
            .zip(expected)
        {
            assert_eq!(actual, &[fss_reference::rtsp::decode_base64(expected)?]);
        }
        let (seq, setup) = f.command(ClientCommand::Setup)?;
        assert!(setup.starts_with(b"SETUP rtsp://camera.local/live/trackID=0 RTSP/1.0\r\n"));
        let original = response(
            seq,
            "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n",
            "",
        );
        accepted(f.reply(&original)?, ClientState::Ready, &original)?;
        assert_eq!(f.connection.bound_key(), (!auto_ssrc).then_some(KEY));
        let (seq, _) = f.command(ClientCommand::Play)?;
        let original = response(seq, "Session: fixture\r\n", "");
        accepted(f.reply(&original)?, ClientState::Playing, &original)?;
        let ssrc = if auto_ssrc { 0x91a0_0042 } else { KEY.ssrc };
        let actual_key = StreamKey { ssrc, ..KEY };
        let mut final_packet = Vec::new();
        for sequence in [1_u16, 2] {
            let mut packet = vec![0x80, payload_type];
            packet.extend_from_slice(&sequence.to_be_bytes());
            packet.extend_from_slice(&0_u32.to_be_bytes());
            packet.extend_from_slice(&ssrc.to_be_bytes());
            packet.extend_from_slice(&fss_reference::rtsp::decode_base64(expected[0])?);
            let mut wire = vec![b'$', 0];
            wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
            wire.extend_from_slice(&packet);
            let LiveHevcStep::Protocol {
                event: HevcPictureClientPoll::Client { event, work: None },
                transport: None,
            } = f.reply(&wire)?
            else {
                return Err("exact RTP admission missing".into());
            };
            let HevcClientPoll::Rtp {
                source,
                retirement: None,
                ..
            } = *event
            else {
                return Err("selected RTP rejected".into());
            };
            assert_eq!(source.expose_wire(), wire);
            assert_eq!(f.connection.bound_key(), Some(actual_key));
            final_packet = packet;
        }
        let mut observed_source = false;
        for _ in 0..32 {
            if let LiveHevcStep::Protocol {
                event: HevcPictureClientPoll::Source { source, .. },
                transport: None,
            } = f.poll(false, false)?
            {
                assert_eq!(source.key(), actual_key);
                assert_eq!(source.bytes(), final_packet);
                observed_source = true;
                break;
            }
        }
        assert!(
            observed_source,
            "selected payload did not preserve ordered original source"
        );
        let retired = f.connection.cancel().ok_or("missing native retirement")?;
        assert_eq!(retired.protocol.client.source_key, Some(actual_key));
    }
    Ok(())
}

#[test]
fn exact_native_hevc_payload_refuses_absent_unsupported_and_wrong_clock_without_fallback() -> Test {
    let alternatives = hevc_alternatives();
    let cases = [
        (97, alternatives.clone()),
        (96, mixed_offer(true)),
        (
            98,
            alternatives.replace("a=rtpmap:98 H265/90000", "a=rtpmap:98 H265/8000"),
        ),
        (98, alternatives.replace("a=rtpmap:98 H265/90000\r\n", "")),
        (
            98,
            alternatives.replace("a=fmtp:98 ", "a=fmtp:98 sprop-max-don-diff=1;"),
        ),
    ];
    for (payload_type, body) in cases {
        let mut f = Fixture::with_selection(7, 0, Some(payload_type), true)?;
        let (seq, describe) = f.command(ClientCommand::Describe)?;
        let original = response(seq, "Content-Type: application/sdp\r\n", &body);
        let LiveHevcStep::Protocol {
            transport: Some(retired),
            ..
        } = f.reply(&original)?
        else {
            return Err("unsupported exact selection did not close native owner".into());
        };
        assert_eq!(retired.totals.sent_bytes, u64::try_from(describe.len())?);
        assert!(f.connection.media().is_none());
        assert!(f.command(ClientCommand::Setup).is_err());
    }
    Ok(())
}

#[test]
fn selected_hevc_missing_sets_remain_empty_even_when_an_alternative_has_them() -> Test {
    let mut f = Fixture::with_selection(7, 0, Some(99), false)?;
    let body = hevc_alternatives().replace(
        "a=fmtp:99 sprop-vps=QAEBAg==;sprop-sps=QgECAw==;sprop-pps=RAEDBA==\r\n",
        "",
    );
    let (seq, _) = f.command(ClientCommand::Describe)?;
    let original = response(seq, "Content-Type: application/sdp\r\n", &body);
    accepted(f.reply(&original)?, ClientState::Described, &original)?;
    let media = f.connection.media().ok_or("selected HEVC missing")?;
    assert_eq!(media.payload_type(), 99);
    assert!(media.vps().is_empty());
    assert!(media.sps().is_empty());
    assert!(media.pps().is_empty());
    let _retirement = f.connection.cancel().ok_or("missing retirement")?;
    Ok(())
}

#[test]
fn ambiguous_or_unsupported_selected_sdp_never_sends_setup() -> Test {
    let body = mixed_offer(true);
    let ambiguous = body.replace("96 98", "96 98 99") + "a=rtpmap:99 H265/90000\r\n";
    for rejected in [
        ambiguous,
        body.replace("H265/90000", "H265/8000"),
        body.replace("sprop-vps=", "sprop-max-don-diff=1;sprop-vps="),
        body.replace(
            "a=control:trackID=0",
            "a=control:rtsp://other.local/live/video",
        ),
    ] {
        let mut f = Fixture::new(7, 0)?;
        let (seq, describe) = f.command(ClientCommand::Describe)?;
        let original = response(seq, "Content-Type: application/sdp\r\n", &rejected);
        let LiveHevcStep::Protocol {
            transport: Some(retired),
            ..
        } = f.reply(&original)?
        else {
            return Err("unsupported SDP did not retire native connection".into());
        };
        assert_eq!(retired.totals.sent_bytes, u64::try_from(describe.len())?);
        assert!(f.connection.media().is_none());
        assert!(f.command(ClientCommand::Setup).is_err());
        assert!(f.connection.cancel().is_none());
    }
    Ok(())
}

#[test]
fn native_selection_preserves_video_index_after_audio() -> Test {
    let mut f = Fixture::new(7, 1)?;
    let body = mixed_offer(true).replace(
        "m=video",
        "m=audio 0 RTP/AVP 0\r\na=control:audio\r\nm=video",
    );
    let (seq, _) = f.command(ClientCommand::Describe)?;
    let original = response(seq, "Content-Type: application/sdp\r\n", &body);
    accepted(f.reply(&original)?, ClientState::Described, &original)?;
    assert_eq!(
        f.connection.media().ok_or("missing video")?.payload_type(),
        98
    );
    let (_, setup) = f.command(ClientCommand::Setup)?;
    assert!(setup.starts_with(b"SETUP rtsp://camera.local/live/trackID=0 RTSP/1.0\r\n"));
    let _retirement = f.connection.cancel().ok_or("lost native owner")?;
    Ok(())
}
