#![forbid(unsafe_code)]
#![allow(dead_code)]
use fss_packet::StreamKey;
use fss_packet::avc::AvcReceiveLimits;
use fss_reference::rtsp::{authentication::{DigestCredentials, DigestPolicy},
    avc_client::{AvcClientPoll, authenticated::{DigestAvcClient, DigestAvcPoll}},
    client::{ClientCommand, ClientConfig, ClientProgress, ClientState}};
pub type Error = Box<dyn std::error::Error>;
pub type TestResult = Result<(), Error>;
pub const KEY: StreamKey = StreamKey { ingress: 71, generation: 1, ssrc: 7 };
pub fn config() -> ClientConfig {
    ClientConfig { presentation_uri: "rtsp://camera.local/live/".into(), control_root_uri: "rtsp://camera.local/live".into(),
        media_index: 0, channels: (0, 1), response_timeout_ns: 10_000_000_000, default_session_timeout_seconds: 60 }
}
pub fn credentials() -> Result<DigestCredentials<'static>, Error> {
    Ok(DigestCredentials::new("camera-user", "camera-password")?)
}
pub fn new_client() -> Result<DigestAvcClient, Error> {
    Ok(DigestAvcClient::new(config(), KEY, AvcReceiveLimits::default(), "fixture-camera", DigestPolicy::default())?)
}
pub fn response(seq: u32, headers: &str, body: &str) -> Vec<u8> {
    format!("RTSP/1.0 200 OK\r\nCSeq: {seq}\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).into_bytes()
}
pub fn challenge(seq: u32, nonce: &str, stale: bool) -> Vec<u8> {
    format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {seq}\r\nWWW-Authenticate: Digest realm=\"fixture-camera\", nonce=\"{nonce}\", algorithm=SHA-256, qop=\"auth\", stale={stale}\r\nContent-Length: 0\r\n\r\n").into_bytes()
}
pub fn description() -> String {
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n".into()
}
pub fn drain(c: &mut DigestAvcClient, now: u64, out: &mut Vec<DigestAvcPoll>) -> TestResult {
    for _ in 0..2048 {
        let event = c.poll(now)?;
        match &event {
            DigestAvcPoll::Client { event: AvcClientPoll::Pending { wake_at_ns }, .. } if wake_at_ns.is_none_or(|at| at > now) => return Ok(()),
            DigestAvcPoll::Client { event: AvcClientPoll::Pending { .. }, .. } => {},
            DigestAvcPoll::Client { event: AvcClientPoll::Backpressure { .. } | AvcClientPoll::Ended { .. }
                | AvcClientPoll::Fault { .. } | AvcClientPoll::Control(ClientProgress::KeepAliveDue), .. }
            | DigestAvcPoll::AuthenticationRequired { .. } | DigestAvcPoll::Fault { .. } => {
                out.push(event); return Ok(());
            }
            _ => out.push(event),
        }
    }
    Err("bounded authenticated client did not yield".into())
}
pub fn send(c: &mut DigestAvcClient, bytes: &[u8], chunk: usize, now: u64, out: &mut Vec<DigestAvcPoll>) -> TestResult {
    for part in bytes.chunks(chunk) { c.ingest(part, now)?; drain(c, now, out)?; }
    Ok(())
}
pub fn playing() -> Result<DigestAvcClient, Error> {
    let mut c = new_client()?; let creds = credentials()?; let mut out = Vec::new();
    assert_eq!(c.request(ClientCommand::Describe, &creds, [0;16], 0)?.cseq(), 1);
    send(&mut c, &challenge(1, "server-nonce-1", false), 3, 1, &mut out)?;
    assert!(matches!(out.last(), Some(DigestAvcPoll::AuthenticationRequired { cseq: 1, .. })));
    assert_eq!(c.respond(&creds, [17;16], 2)?.cseq(), 2); drain(&mut c, 2, &mut out)?;
    send(&mut c, &response(2, "Content-Type: application/sdp\r\n", &description()), 7, 3, &mut out)?;
    assert_eq!(c.state(), ClientState::Described);
    assert_eq!(c.request(ClientCommand::Setup, &creds, [18;16], 4)?.cseq(), 3);
    send(&mut c, &response(3, "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""), 7, 5, &mut out)?;
    assert_eq!(c.state(), ClientState::Ready);
    assert_eq!(c.request(ClientCommand::Play, &creds, [19;16], 6)?.cseq(), 4);
    send(&mut c, &response(4, "Session: fixture\r\n", ""), 7, 7, &mut out)?;
    assert_eq!(c.state(), ClientState::Playing);
    Ok(c)
}
pub fn packet(seq: u16, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x80, 96]; wire.extend_from_slice(&seq.to_be_bytes());
    wire.extend_from_slice(&timestamp.to_be_bytes()); wire.extend_from_slice(&KEY.ssrc.to_be_bytes());
    wire.extend_from_slice(payload); wire
}
pub fn interleaved(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![b'$', channel]; wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    wire.extend_from_slice(payload); wire
}
pub fn nals() -> Vec<&'static [u8]> {
    let bytes: &'static [u8] = include_bytes!("../../../fss-packet/tests/fixtures/avc/baseline.264");
    let mut starts = Vec::new(); let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0,0,0,1]) { 4 }
            else if bytes[at..at + 3] == [0,0,1] { 3 } else { 0 };
        if prefix == 0 { at += 1; } else { starts.push((at, at + prefix)); at += prefix; }
    }
    starts.iter().enumerate().map(|(i, (_, start))| {
        let mut end = starts.get(i + 1).map_or(bytes.len(), |next| next.0);
        while end > *start && bytes[end - 1] == 0 { end -= 1; }
        &bytes[*start..end]
    }).collect()
}
