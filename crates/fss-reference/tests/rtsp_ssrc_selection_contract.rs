#![forbid(unsafe_code)]
//! Sender selection crosses the actual session, RTP validation and ordered-source owners.

use fss_packet::avc::{AvcReceiveLimits, AvcReceivePoll};
use fss_packet::{H265Limits, H265ReceivePoll, ReorderLimits, StreamKey};
use fss_reference::rtsp::avc_client::{AvcClientPoll, RtspAvcClient};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientState};
use fss_reference::rtsp::hevc_client::{HevcClientPoll, RtspHevcClient};
use fss_reference::rtsp::tcp::SsrcPolicy;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey {
    ingress: 71,
    generation: 3,
    ssrc: 7,
};

#[derive(Clone, Copy, Debug)]
enum Codec {
    Avc,
    Hevc,
}
impl Codec {
    fn payload(self) -> u8 {
        match self {
            Self::Avc => 96,
            Self::Hevc => 98,
        }
    }
    fn sdp(self) -> String {
        let media = match self {
            Self::Avc => {
                "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\n"
            }
            Self::Hevc => {
                "m=video 0 RTP/AVP 98\r\na=rtpmap:98 H265/90000\r\na=fmtp:98 sprop-vps=QAEBAg==;sprop-sps=QgECAw==;sprop-pps=RAEDBA==\r\n"
            }
        };
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\n{media}a=control:trackID=0\r\n"
        )
    }
    fn packet(self, ssrc: u32, sequence: u16) -> Vec<u8> {
        let mut bytes = vec![0x80, self.payload()];
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&90_000_u32.to_be_bytes());
        bytes.extend_from_slice(&ssrc.to_be_bytes());
        bytes.extend_from_slice(match self {
            Self::Avc => &[0x09, 0xf0],
            Self::Hevc => &[0x46, 0x01, 0x50],
        });
        bytes
    }
}

enum Client {
    Avc(RtspAvcClient),
    Hevc(RtspHevcClient),
}
#[derive(Debug)]
enum Observation {
    Other,
    Source(StreamKey, Vec<u8>),
    Refused,
    Pending,
}
impl Client {
    fn new(codec: Codec, key: StreamKey, policy: SsrcPolicy) -> Result<Self> {
        let config = ClientConfig {
            presentation_uri: "rtsp://camera.local/live/".into(),
            control_root_uri: "rtsp://camera.local/live".into(),
            media_index: 0,
            channels: (0, 1),
            response_timeout_ns: 1_000_000_000,
            default_session_timeout_seconds: 60,
        };
        Ok(match codec {
            Codec::Avc => Self::Avc(RtspAvcClient::new_with_ssrc_policy(
                config,
                key,
                AvcReceiveLimits::default(),
                policy,
            )?),
            Codec::Hevc => Self::Hevc(RtspHevcClient::new_with_ssrc_policy(
                config,
                key,
                ReorderLimits::default(),
                H265Limits::default(),
                policy,
            )?),
        })
    }
    fn key(&self) -> Option<StreamKey> {
        match self {
            Self::Avc(c) => c.bound_key(),
            Self::Hevc(c) => c.bound_key(),
        }
    }
    fn state(&self) -> ClientState {
        match self {
            Self::Avc(c) => c.state(),
            Self::Hevc(c) => c.state(),
        }
    }
    fn request(&mut self, command: ClientCommand, now: u64) -> Result {
        match self {
            Self::Avc(c) => {
                c.request(command, now)?;
            }
            Self::Hevc(c) => {
                c.request(command, now)?;
            }
        }
        Ok(())
    }
    fn feed(&mut self, wire: &[u8], now: u64) -> Result<Vec<Observation>> {
        match self {
            Self::Avc(c) => c.ingest(wire, now)?,
            Self::Hevc(c) => c.ingest(wire, now)?,
        }
        let mut events = Vec::new();
        for _ in 0..64 {
            let event = match self {
                Self::Avc(c) => match c.poll(now)? {
                    AvcClientPoll::Media(AvcReceivePoll::Source { source, .. }) => {
                        Observation::Source(source.key(), source.bytes().to_vec())
                    }
                    AvcClientPoll::Fault { .. }
                    | AvcClientPoll::Rtp {
                        retirement: Some(_),
                        ..
                    } => Observation::Refused,
                    AvcClientPoll::Pending { .. } => Observation::Pending,
                    _ => Observation::Other,
                },
                Self::Hevc(c) => match c.poll(now)? {
                    HevcClientPoll::Media(H265ReceivePoll::Packet { source, .. }) => {
                        Observation::Source(source.key(), source.bytes().to_vec())
                    }
                    HevcClientPoll::Fault { .. }
                    | HevcClientPoll::Rtp {
                        retirement: Some(_),
                        ..
                    } => Observation::Refused,
                    HevcClientPoll::Pending { .. } => Observation::Pending,
                    _ => Observation::Other,
                },
            };
            let stop = matches!(event, Observation::Refused | Observation::Pending);
            events.push(event);
            if stop {
                return Ok(events);
            }
        }
        Err("protocol did not reach a bounded wait or refusal".into())
    }
}

fn response(cseq: u32, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
    .into_bytes()
}
fn interleaved(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![b'$', channel];
    wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}
fn playing(
    codec: Codec,
    key: StreamKey,
    policy: SsrcPolicy,
    advertised: Option<u32>,
) -> Result<Client> {
    let mut client = Client::new(codec, key, policy)?;
    client.request(ClientCommand::Describe, 0)?;
    client.feed(
        &response(1, "Content-Type: application/sdp\r\n", &codec.sdp()),
        1,
    )?;
    assert_eq!(client.state(), ClientState::Described);
    client.request(ClientCommand::Setup, 2)?;
    let ssrc = advertised.map_or_else(String::new, |ssrc| format!(";ssrc={ssrc:08X}"));
    client.feed(&response(2, &format!("Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1{ssrc}\r\n"), ""), 3)?;
    assert_eq!(client.state(), ClientState::Ready);
    client.request(ClientCommand::Play, 4)?;
    client.feed(&response(3, "Session: fixture\r\n", ""), 5)?;
    assert_eq!(client.state(), ClientState::Playing);
    Ok(client)
}

#[test]
fn auto_binds_advertised_or_first_valid_sender_and_preserves_real_ordered_source() -> Result {
    for codec in [Codec::Avc, Codec::Hevc] {
        for advertised in [None, Some(0), Some(0x1020_3040)] {
            let ssrc = advertised.unwrap_or(0xfeed_1234);
            let mut client = playing(codec, KEY, SsrcPolicy::LearnOnce, advertised)?;
            assert_eq!(client.key().map(|key| key.ssrc), advertised);
            let first = codec.packet(ssrc, 1);
            let second = codec.packet(ssrc, 2);
            let mut observed = client.feed(&interleaved(0, &first), 6)?;
            observed.extend(client.feed(&interleaved(0, &second), 7)?);
            assert_eq!(client.key(), Some(StreamKey { ssrc, ..KEY }));
            assert!(
                !observed
                    .iter()
                    .any(|event| matches!(event, Observation::Refused))
            );
            assert!(observed.iter().any(|event| matches!(event, Observation::Source(key, bytes) if *key == (StreamKey { ssrc, ..KEY }) && bytes == &second)));
        }
    }
    Ok(())
}

#[test]
fn unbound_sender_requires_complete_rtp_header_selected_payload_and_channel() -> Result {
    for codec in [Codec::Avc, Codec::Hevc] {
        let valid = codec.packet(91, 1);
        let mut version = valid.clone();
        version[0] = 0x40;
        let mut csrc = valid.clone();
        csrc[0] = 0x8f;
        let mut extension = valid.clone();
        extension[0] = 0x90;
        let mut padding = valid.clone();
        padding[0] = 0xa0;
        *padding.last_mut().ok_or("payload")? = 0;
        let mut payload = valid.clone();
        payload[1] = 99;
        for invalid in [
            version,
            csrc,
            extension,
            padding,
            payload,
            valid[..12].to_vec(),
        ] {
            let mut client = playing(codec, KEY, SsrcPolicy::LearnOnce, None)?;
            let events = client.feed(&interleaved(0, &invalid), 6)?;
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event, Observation::Refused))
            );
            assert_eq!(client.key(), None);
        }
        let mut client = playing(codec, KEY, SsrcPolicy::LearnOnce, None)?;
        // A datagram on RTCP may be invalid RTCP, but cannot establish RTP sender identity.
        client.feed(&interleaved(1, &valid), 6)?;
        assert_eq!(client.key(), None);
        let events = client.feed(&interleaved(2, &valid), 7)?;
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Observation::Refused))
        );
        assert_eq!(client.key(), None);
    }
    Ok(())
}

#[test]
fn auto_never_changes_an_advertised_or_previously_observed_sender() -> Result {
    for codec in [Codec::Avc, Codec::Hevc] {
        for advertised in [Some(44), None] {
            let mut client = playing(codec, KEY, SsrcPolicy::LearnOnce, advertised)?;
            client.feed(&interleaved(0, &codec.packet(44, 1)), 6)?;
            let events = client.feed(&interleaved(0, &codec.packet(45, 2)), 7)?;
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event, Observation::Refused))
            );
            assert_eq!(client.key().map(|key| key.ssrc), Some(44));
        }
        let mut restarted = playing(
            codec,
            StreamKey {
                generation: 4,
                ..KEY
            },
            SsrcPolicy::LearnOnce,
            None,
        )?;
        assert_eq!(restarted.key(), None);
        restarted.feed(&interleaved(0, &codec.packet(45, 1)), 6)?;
        assert_eq!(
            restarted.key(),
            Some(StreamKey {
                generation: 4,
                ssrc: 45,
                ..KEY
            })
        );
    }
    Ok(())
}

#[test]
fn numeric_zero_remains_an_exact_pin_and_auto_setup_cannot_override_it() -> Result {
    for codec in [Codec::Avc, Codec::Hevc] {
        let mut client = playing(
            codec,
            StreamKey { ssrc: 0, ..KEY },
            SsrcPolicy::Pinned,
            None,
        )?;
        assert_eq!(client.key().map(|key| key.ssrc), Some(0));
        let events = client.feed(&interleaved(0, &codec.packet(9, 1)), 6)?;
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Observation::Refused))
        );
        assert_eq!(client.key().map(|key| key.ssrc), Some(0));
        let mut client = Client::new(codec, StreamKey { ssrc: 0, ..KEY }, SsrcPolicy::Pinned)?;
        client.request(ClientCommand::Describe, 0)?;
        client.feed(
            &response(1, "Content-Type: application/sdp\r\n", &codec.sdp()),
            1,
        )?;
        client.request(ClientCommand::Setup, 2)?;
        let events = client.feed(&response(2, "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=9\r\n", ""), 3)?;
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Observation::Refused))
        );
        assert_eq!(client.key().map(|key| key.ssrc), Some(0));
    }
    Ok(())
}
