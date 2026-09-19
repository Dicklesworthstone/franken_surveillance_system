#![forbid(unsafe_code)]
//! Public streaming APIs, actual RTSP framing, Digest, and source-linked RTP.

use fss_packet::{StreamKey, avc::AvcReceiveLimits};
use fss_reference::rtsp::{
    authentication::{DigestCredentials, DigestPolicy},
    avc_client::{
        AvcClientError, AvcClientPoll, RtspAvcClient,
        authenticated::{DigestAvcClient, DigestAvcPoll},
    },
    client::{ClientCommand, ClientConfig, ClientError, ClientState},
};

type Error = Box<dyn std::error::Error>;
type TestResult = Result<(), Error>;
const KEY: StreamKey = StreamKey { ingress: 71, generation: 1, ssrc: 7 };
const SPS: &str = "Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=";
const PPS: &str = "aM4PLIA=";
// Exact decoded SPS from the existing encoded baseline fixture.
const SPS_NAL: &[u8] = &[0x67, 0x42, 0xc0, 0x0b, 0xda, 0x0a, 0x11, 0xb0, 0x11, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x32, 0x0f, 0x14, 0x2a, 0xa0];
const SETUP: &str = "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n";

fn config() -> ClientConfig {
    ClientConfig {
        presentation_uri: "rtsp://camera.local/live/".into(),
        control_root_uri: "rtsp://camera.local/live".into(),
        media_index: 0,
        channels: (0, 1),
        response_timeout_ns: 10_000_000_000,
        default_session_timeout_seconds: 60,
    }
}

fn offer(multiple_h264: bool) -> String {
    let first_codec = if multiple_h264 { "H264" } else { "H265" };
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\n\
         m=video 0 RTP/AVP 96 97\r\na=control:trackID=0\r\n\
         a=rtpmap:96 {first_codec}/90000\r\n\
         a=fmtp:96 packetization-mode=0;sprop-parameter-sets={SPS},{PPS}\r\n\
         a=rtpmap:97 H264/90000\r\n\
         a=fmtp:97 packetization-mode=1;sprop-parameter-sets={SPS},{PPS}\r\n"
    )
}

fn response(cseq: u32, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len(),
    ).into_bytes()
}

fn challenge() -> Vec<u8> {
    b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"fixture-camera\", nonce=\"selection-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n".to_vec()
}

fn packet(payload_type: u8, sequence: u16) -> Vec<u8> {
    let mut packet = vec![0x80, payload_type];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&90_000_u32.to_be_bytes());
    packet.extend_from_slice(&KEY.ssrc.to_be_bytes());
    packet.extend_from_slice(SPS_NAL);
    packet
}

fn interleaved(packet: &[u8]) -> Result<Vec<u8>, Error> {
    let mut wire = vec![b'$', 0];
    wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
    wire.extend_from_slice(packet);
    Ok(wire)
}

fn plain_drain(client: &mut RtspAvcClient, now: u64) -> Result<Vec<AvcClientPoll>, Error> {
    let mut out = Vec::new();
    for _ in 0..256 {
        let event = client.poll(now)?;
        match &event {
            AvcClientPoll::Pending { wake_at_ns } if wake_at_ns.is_none_or(|at| at > now) => return Ok(out),
            AvcClientPoll::Fault { .. } | AvcClientPoll::Ended { .. } => {
                out.push(event);
                return Ok(out);
            }
            _ => out.push(event),
        }
    }
    Err("plain client did not yield within the fixture budget".into())
}

fn digest_drain(client: &mut DigestAvcClient, now: u64) -> Result<Vec<DigestAvcPoll>, Error> {
    let mut out = Vec::new();
    for _ in 0..256 {
        let event = client.poll(now)?;
        match &event {
            DigestAvcPoll::Client { event, .. } => match event.as_ref() {
                AvcClientPoll::Pending { wake_at_ns } if wake_at_ns.is_none_or(|at| at > now) => return Ok(out),
                AvcClientPoll::Fault { .. } | AvcClientPoll::Ended { .. } => {
                    return Err("unexpected terminal event while draining selected Digest client".into());
                }
                _ => {},
            },
            DigestAvcPoll::AuthenticationRequired { .. } | DigestAvcPoll::Fault { .. } => {
                out.push(event);
                return Ok(out);
            }
        }
        out.push(event);
    }
    Err("Digest client did not yield within the fixture budget".into())
}

fn digest_send(client: &mut DigestAvcClient, wire: &[u8], chunk_size: usize, now: u64)
    -> Result<Vec<DigestAvcPoll>, Error>
{
    let mut out = Vec::new();
    for chunk in wire.chunks(chunk_size) {
        client.ingest(chunk, now)?;
        out.extend(digest_drain(client, now)?);
    }
    Ok(out)
}

fn plain_playing(mut client: RtspAvcClient, body: &str, chunk_size: usize) -> Result<RtspAvcClient, Error> {
    let describe = client.request(ClientCommand::Describe, 0)?;
    let wire = response(describe.cseq(), "Content-Type: application/sdp\r\n", body);
    for chunk in wire.chunks(chunk_size) {
        client.ingest(chunk, 1)?;
        plain_drain(&mut client, 1)?;
    }
    assert_eq!(client.state(), ClientState::Described);
    let setup = client.request(ClientCommand::Setup, 2)?;
    assert!(setup.bytes().starts_with(b"SETUP rtsp://camera.local/live/trackID=0 RTSP/1.0\r\n"));
    client.ingest(&response(setup.cseq(), SETUP, ""), 3)?;
    plain_drain(&mut client, 3)?;
    assert_eq!(client.state(), ClientState::Ready);
    let play = client.request(ClientCommand::Play, 4)?;
    client.ingest(&response(play.cseq(), "Session: fixture\r\n", ""), 5)?;
    plain_drain(&mut client, 5)?;
    assert_eq!(client.state(), ClientState::Playing);
    Ok(client)
}

fn assert_plain_sources(client: &mut RtspAvcClient, payload_type: u8) -> TestResult {
    let original = [packet(payload_type, 0), packet(payload_type, 1)];
    let mut returned = Vec::new();
    for packet in &original {
        client.ingest(&interleaved(packet)?, 6)?;
        for event in plain_drain(client, 6)? {
            if let AvcClientPoll::Rtp { source, retirement: None, .. } = event {
                returned.push(source.payload().to_vec());
            }
        }
    }
    assert_eq!(returned.as_slice(), original.as_slice());
    assert_eq!(client.state(), ClientState::Playing);
    Ok(())
}

#[test]
fn exact_payload_reaches_real_receiver_for_both_offered_modes() -> TestResult {
    for payload_type in [96, 97] {
        for chunk_size in [1, 7, 4096] {
            let client = RtspAvcClient::new_with_payload_type(config(), KEY, AvcReceiveLimits::default(), payload_type)?;
            let mut client = plain_playing(client, &offer(true), chunk_size)?;
            assert_plain_sources(&mut client, payload_type)?;
        }
    }
    Ok(())
}

#[test]
fn default_pump_selects_the_only_h264_without_switching_to_hevc() -> TestResult {
    let client = RtspAvcClient::new(config(), KEY, AvcReceiveLimits::default())?;
    let mut client = plain_playing(client, &offer(false), 3)?;
    assert_plain_sources(&mut client, 97)
}

#[test]
fn ambiguous_and_absent_selections_close_before_setup() -> TestResult {
    let clients = [
        RtspAvcClient::new(config(), KEY, AvcReceiveLimits::default())?,
        RtspAvcClient::new_with_payload_type(config(), KEY, AvcReceiveLimits::default(), 99)?,
    ];
    for mut client in clients {
        client.request(ClientCommand::Describe, 0)?;
        client.ingest(&response(1, "Content-Type: application/sdp\r\n", &offer(true)), 1)?;
        let events = plain_drain(&mut client, 1)?;
        assert!(events.iter().any(|event| matches!(event,
            AvcClientPoll::Fault { reason: AvcClientError::Session(ClientError::Description), .. })));
        assert_eq!(client.state(), ClientState::Closed);
        assert!(client.request(ClientCommand::Setup, 2).is_err());
    }
    Ok(())
}

#[test]
fn authenticated_selection_survives_fragmented_challenge_and_preserves_rtp() -> TestResult {
    for chunk_size in [1, 7, 4096] {
        let mut client = DigestAvcClient::new_with_payload_type(
            config(), KEY, AvcReceiveLimits::default(), 97, "fixture-camera", DigestPolicy::default(),
        )?;
        let credentials = DigestCredentials::new("camera-user", "camera-password")?;
        let first = client.request(ClientCommand::Describe, &credentials, [0; 16], 0)?;
        assert_eq!(first.cseq(), 1);
        assert!(!std::str::from_utf8(first.bytes())?.contains("Authorization"));
        let challenged = digest_send(&mut client, &challenge(), chunk_size, 1)?;
        assert!(matches!(challenged.last(), Some(DigestAvcPoll::AuthenticationRequired { cseq: 1, .. })));
        let retry = client.respond(&credentials, [17; 16], 2)?;
        assert_eq!(retry.cseq(), 2);
        assert_eq!(client.next_wake_ns(), Some(10_000_000_000));
        digest_drain(&mut client, 2)?;
        digest_send(&mut client, &response(2, "Content-Type: application/sdp\r\n", &offer(true)), chunk_size, 3)?;
        assert_eq!(client.state(), ClientState::Described);
        let setup = client.request(ClientCommand::Setup, &credentials, [18; 16], 4)?;
        let setup_wire = std::str::from_utf8(setup.bytes())?;
        assert!(setup_wire.starts_with("SETUP rtsp://camera.local/live/trackID=0 RTSP/1.0\r\n"));
        assert!(setup_wire.contains("Authorization: Digest"));
        assert!(setup_wire.contains("uri=\"rtsp://camera.local/live/trackID=0\""));
        digest_send(&mut client, &response(setup.cseq(), SETUP, ""), chunk_size, 5)?;
        assert_eq!(client.state(), ClientState::Ready);
        let play = client.request(ClientCommand::Play, &credentials, [19; 16], 6)?;
        digest_send(&mut client, &response(play.cseq(), "Session: fixture\r\n", ""), chunk_size, 7)?;
        assert_eq!(client.state(), ClientState::Playing);
        let original = [packet(97, 0), packet(97, 1)];
        let mut returned = Vec::new();
        for packet in &original {
            for event in digest_send(&mut client, &interleaved(packet)?, chunk_size, 8)? {
                if let DigestAvcPoll::Client { event, .. } = event
                    && let AvcClientPoll::Rtp { source, retirement: None, .. } = event.as_ref()
                {
                    returned.push(source.payload().to_vec());
                }
            }
        }
        assert_eq!(returned.as_slice(), original.as_slice());
        assert!(!format!("{client:?} {retry:?} {setup:?}").contains("camera-password"));
    }
    Ok(())
}

#[test]
fn selected_authenticated_client_retains_original_challenge_on_cancel() -> TestResult {
    let mut client = DigestAvcClient::new_with_payload_type(
        config(), KEY, AvcReceiveLimits::default(), 97, "fixture-camera", DigestPolicy::default(),
    )?;
    let credentials = DigestCredentials::new("camera-user", "camera-password")?;
    client.request(ClientCommand::Describe, &credentials, [0; 16], 0)?;
    let wire = challenge();
    digest_send(&mut client, &wire, 7, 1)?;
    let retirement = client.cancel();
    assert_eq!(retirement.wire.challenge.ok_or("missing retained challenge")?.expose_wire(), wire);
    assert!(retirement.wire.pending.is_empty());
    assert_eq!(retirement.client.session.pending_cseq, Some(1));
    assert!(!retirement.client.session.remote_session_may_exist);
    assert_eq!(client.state(), ClientState::Closed);
    Ok(())
}

#[test]
fn payload_selection_cannot_reset_the_digest_retry_deadline() -> TestResult {
    let mut cfg = config();
    cfg.response_timeout_ns = 100;
    let mut client = DigestAvcClient::new_with_payload_type(
        cfg, KEY, AvcReceiveLimits::default(), 97, "fixture-camera", DigestPolicy::default(),
    )?;
    let credentials = DigestCredentials::new("camera-user", "camera-password")?;
    client.request(ClientCommand::Describe, &credentials, [0; 16], 0)?;
    digest_send(&mut client, &challenge(), 4096, 10)?;
    client.respond(&credentials, [17; 16], 90)?;
    assert_eq!(client.next_wake_ns(), Some(100));
    let event = client.poll(100)?;
    let DigestAvcPoll::Client { event, wire_retirement: Some(_) } = event else {
        return Err("selected client did not retire on its original deadline".into());
    };
    assert!(matches!(event.as_ref(), AvcClientPoll::Fault {
        reason: AvcClientError::Session(ClientError::ResponseTimeout), .. }));
    Ok(())
}

#[test]
fn constructors_preserve_scope_stream_and_payload_validation() {
    for payload_type in [128, 255] {
        assert!(RtspAvcClient::new_with_payload_type(config(), KEY, AvcReceiveLimits::default(), payload_type).is_err());
        assert!(DigestAvcClient::new_with_payload_type(config(), KEY, AvcReceiveLimits::default(), payload_type,
            "fixture-camera", DigestPolicy::default()).is_err());
    }
    let mut invalid_key = KEY;
    invalid_key.generation = 0;
    assert!(RtspAvcClient::new_with_payload_type(config(), invalid_key, AvcReceiveLimits::default(), 97).is_err());
    let mut invalid_scope = config();
    invalid_scope.presentation_uri = "rtsp://outside/live/".into();
    assert!(DigestAvcClient::new_with_payload_type(invalid_scope, KEY, AvcReceiveLimits::default(), 97,
        "fixture-camera", DigestPolicy::default()).is_err());
}
