#![forbid(unsafe_code)]
//! Canonical native source preserves exact complete frames and separate clock meanings.

use fss_core::ContentDigest;
use fss_packet::{OnvifMetadataLimits, ReorderLimits, StreamKey};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientProgress, ClientState};
use fss_reference::rtsp::framed::{MAX_WIRE_CHUNK, RtspWireFrame, RtspWireIntake};
use fss_reference::rtsp::metadata_client::{MetadataClientPoll, RtspMetadataClient};
use fss_reference::rtsp::metadata_source::{
    MAX_SOURCE_BYTES, NativeMetadataConfig, NativeMetadataProjection, NativeMetadataSource,
    NativeMetadataSourceError as E, NativeMetadataStop as Stop,
};
use fss_reference::rtsp::tcp::{TcpBinding, TcpSecurityPolicy};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const START: u64 = 10_000_000_123;
const ORIGIN: i128 = 1_700_000_000_000_000_000;
const KEY: StreamKey = StreamKey {
    ingress: 11,
    generation: 7,
    ssrc: 19,
};

fn config() -> Test<NativeMetadataConfig> {
    Ok(NativeMetadataConfig {
        approval: ContentDigest::sha256(b"explicit owner approval"),
        protocol: ClientConfig {
            presentation_uri: "rtsp://camera.local/live/".into(),
            control_root_uri: "rtsp://camera.local/live".into(),
            media_index: 1,
            channels: (4, 5),
            response_timeout_ns: 1_000_000_000,
            default_session_timeout_seconds: 60,
        },
        binding: TcpBinding::new(
            KEY,
            "127.0.0.1:554".parse()?,
            "camera.local",
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )?,
        payload_type: 107,
        receive_origin_ns: ORIGIN,
        started_ns: START,
        max_source_bytes: MAX_SOURCE_BYTES,
        max_records: 16_384,
    })
}
fn sdp() -> Vec<u8> {
    b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=private-title\r\nt=0 0\r\na=control:*\r\n\
      m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:video\r\n\
      m=application 0 RTP/AVP 107\r\na=rtpmap:107 vnd.onvif.metadata/90000\r\na=control:metadata\r\n".to_vec()
}
fn response(cseq: u32, status: u16, fields: &str, body: &[u8]) -> Vec<u8> {
    let mut wire = format!(
        "RTSP/1.0 {status} Private reason\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{fields}\r\n",
        body.len()
    )
    .into_bytes();
    wire.extend_from_slice(body);
    wire
}
fn interleaved(channel: u8, bytes: &[u8]) -> Vec<u8> {
    let mut wire = vec![b'$', channel];
    wire.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    wire.extend_from_slice(bytes);
    wire
}
fn rtp(seq: u16, marker: bool, bytes: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x80, 107 | if marker { 128 } else { 0 }];
    wire.extend_from_slice(&seq.to_be_bytes());
    wire.extend_from_slice(&90_000_u32.to_be_bytes());
    wire.extend_from_slice(&KEY.ssrc.to_be_bytes());
    wire.extend_from_slice(bytes);
    wire
}
fn frame(wire: &[u8], now: u64) -> Test<RtspWireFrame> {
    let mut intake = RtspWireIntake::new();
    let mut found = None;
    for chunk in wire.chunks(MAX_WIRE_CHUNK) {
        intake.ingest(chunk, now)?;
        while let Some(value) = intake.poll(now)? {
            if found.replace(value).is_some() {
                return Err("fixture has multiple frames".into());
            }
        }
    }
    found.ok_or_else(|| "fixture incomplete".into())
}
fn accept(
    client: &mut RtspMetadataClient,
    source: &mut NativeMetadataSource,
    wire: &[u8],
    now: u64,
) -> Test {
    for chunk in wire.chunks(MAX_WIRE_CHUNK) {
        client.ingest(chunk, now)?;
        for _ in 0..32 {
            match client.poll(now)? {
                MetadataClientPoll::Control {
                    progress,
                    source: frame,
                } => source.observe_control(&progress, &frame)?,
                MetadataClientPoll::Pending { .. } => break,
                _ => return Err("fixture negotiation failed".into()),
            }
        }
    }
    Ok(())
}
fn playing(config: NativeMetadataConfig) -> Test<NativeMetadataSource> {
    let mut source = NativeMetadataSource::new(config.clone())?;
    let mut client = RtspMetadataClient::new(
        config.protocol,
        KEY,
        107,
        ReorderLimits::default(),
        OnvifMetadataLimits::default(),
    )?;
    client.request(ClientCommand::Describe, START)?;
    accept(
        &mut client,
        &mut source,
        &response(
            1,
            200,
            "Content-Type: application/sdp\r\nContent-Base: rtsp://camera.local/live/\r\n",
            &sdp(),
        ),
        START + 1,
    )?;
    client.request(ClientCommand::Setup, START + 2)?;
    accept(
        &mut client,
        &mut source,
        &response(
            2,
            200,
            "Session: private-session-token;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=4-5;ssrc=00000013\r\n",
            &[],
        ),
        START + 3,
    )?;
    client.request(ClientCommand::Play, START + 4)?;
    accept(
        &mut client,
        &mut source,
        &response(3, 200, "Session: private-session-token\r\n", &[]),
        START + 5,
    )?;
    Ok(source)
}
fn finished() -> Test<NativeMetadataSource> {
    let mut source = playing(config()?)?;
    for (sequence, at) in [
        (0, START + 1_000_111),
        (1, START + 1_999_999),
        (2, START + 2_000_000),
    ] {
        source.observe_interleaved(&frame(
            &interleaved(4, &rtp(sequence, true, b"<metadata/>")),
            at,
        )?)?;
    }
    source.finish(START + 3_000_001, Stop::TargetReached)?;
    Ok(source)
}

#[test]
fn canonical_roundtrip_keeps_exact_original_sdp_frames_route_and_nanoseconds() -> Test {
    let source = finished()?;
    let bytes = source.canonical_bytes()?;
    let decoded = NativeMetadataSource::decode(&bytes)?;
    assert_eq!(decoded.canonical_bytes()?, bytes);
    assert_eq!(decoded.config(), source.config());
    assert_eq!(decoded.description().ok_or("missing SDP")?.bytes(), sdp());
    assert_eq!(decoded.records(), source.records());
    assert_eq!(decoded.controls(), source.controls());
    assert_eq!(decoded.records()[0].received_ns(), START + 1_000_111);
    assert_eq!(decoded.records()[1].received_ns(), START + 1_999_999);
    assert_eq!(decoded.started_ns(), START);
    assert_eq!(decoded.ended_ns(), Some(START + 3_000_001));
    assert_eq!(decoded.config().receive_origin_ns, ORIGIN);
    assert_eq!(decoded.source_mode(), "native_rtsp_tcp");
    assert!(decoded.processing_complete());
    Ok(())
}

#[test]
fn rtpdump_is_a_deterministic_millisecond_projection_with_exact_datagrams() -> Test {
    let mut source = playing(config()?)?;
    let first = rtp(0, true, b"<metadata/>");
    let rtcp = [0x80, 201, 0, 1, 0, 0, 0, 19];
    source.observe_interleaved(&frame(&interleaved(4, &first), START + 1_999_999)?)?;
    source.observe_interleaved(&frame(&interleaved(5, &rtcp), START + 2_123_456)?)?;
    source.finish(START + 3_000_000, Stop::Eof)?;
    let dump = source.rtpdump()?;
    let start = dump
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or("missing dump header")?
        + 1;
    assert_eq!(&dump[start..start + 16], &[0; 16]);
    let first_at = start + 16;
    assert_eq!(
        u16::from_be_bytes(dump[first_at..first_at + 2].try_into()?),
        (first.len() + 8) as u16
    );
    assert_eq!(
        u16::from_be_bytes(dump[first_at + 2..first_at + 4].try_into()?),
        first.len() as u16
    );
    assert_eq!(
        u32::from_be_bytes(dump[first_at + 4..first_at + 8].try_into()?),
        1
    );
    assert_eq!(&dump[first_at + 8..first_at + 8 + first.len()], first);
    let second_at = first_at + 8 + first.len();
    assert_eq!(
        u16::from_be_bytes(dump[second_at + 2..second_at + 4].try_into()?),
        0
    );
    assert_eq!(
        u32::from_be_bytes(dump[second_at + 4..second_at + 8].try_into()?),
        2
    );
    assert_eq!(&dump[second_at + 8..], &rtcp);
    assert_eq!(source.records()[0].received_ns(), START + 1_999_999);
    Ok(())
}

#[test]
fn wrong_channels_oversized_frames_and_empty_rtp_stay_original_with_explicit_omissions() -> Test {
    let mut source = playing(config()?)?;
    let wrong = interleaved(9, b"unselected channel");
    let large = interleaved(4, &vec![7; 65_535]);
    let empty = interleaved(4, &[]);
    for (index, wire) in [&wrong, &large, &empty].into_iter().enumerate() {
        source.observe_interleaved(&frame(wire, START + 10 + index as u64)?)?;
    }
    source.finish(START + 20, Stop::Protocol)?;
    assert_eq!(source.records()[0].expose_wire(), wrong);
    assert_eq!(source.records()[1].expose_wire(), large);
    assert_eq!(source.records()[2].expose_wire(), empty);
    assert_eq!(
        source.records()[0].projection(source.config()),
        NativeMetadataProjection::WrongChannel
    );
    assert_eq!(
        source.records()[1].projection(source.config()),
        NativeMetadataProjection::PacketTooLarge
    );
    assert_eq!(
        source.records()[2].projection(source.config()),
        NativeMetadataProjection::EmptyRtp
    );
    assert_eq!(source.projection_omissions(), 3);
    assert!(!source.processing_complete());
    let dump = source.rtpdump()?;
    assert_eq!(
        dump.iter()
            .position(|byte| *byte == b'\n')
            .ok_or("missing header")?
            + 1
            + 16,
        dump.len()
    );
    let decoded = NativeMetadataSource::decode(&source.canonical_bytes()?)?;
    assert_eq!(decoded.records(), source.records());
    assert_eq!(decoded.projection_omissions(), 3);
    Ok(())
}

#[test]
fn unrepresentable_replay_time_remains_in_the_nanosecond_source() -> Test {
    let mut source = playing(config()?)?;
    let at = START + (u64::from(u32::MAX) + 1) * 1_000_000;
    source.observe_interleaved(&frame(&interleaved(4, &rtp(0, true, b"<metadata/>")), at)?)?;
    source.finish(at, Stop::TargetReached)?;
    assert_eq!(source.records()[0].received_ns(), at);
    assert_eq!(
        source.records()[0].projection(source.config()),
        NativeMetadataProjection::TimeOverflow
    );
    assert_eq!(source.projection_omissions(), 1);
    assert!(!source.processing_complete());
    assert_eq!(
        NativeMetadataSource::decode(&source.canonical_bytes()?)?.records()[0].received_ns(),
        at
    );
    Ok(())
}

#[test]
fn byte_and_record_caps_retain_a_sealed_prefix_and_stop_source_admission() -> Test {
    for record_limit in [false, true] {
        let mut config = config()?;
        if record_limit {
            config.max_records = 1;
        } else {
            config.max_source_bytes = 1800;
        }
        let mut source = playing(config)?;
        let accepted = interleaved(4, &rtp(0, true, b"<metadata/>"));
        source.observe_interleaved(&frame(&accepted, START + 10)?)?;
        let refused = interleaved(4, &vec![3; 2000]);
        assert_eq!(
            source.observe_interleaved(&frame(&refused, START + 11)?),
            Err(E::Limit)
        );
        assert_eq!(source.omitted_observations(), 1);
        assert_eq!(source.omitted_bytes(), refused.len() as u64);
        assert_eq!(source.omitted_received_ns(), Some(START + 11));
        assert_eq!(source.finish(START + 10, Stop::InputLimit), Err(E::Clock));
        assert_eq!(source.stop(), None);
        assert_eq!(
            source.observe_interleaved(&frame(&accepted, START + 12)?),
            Err(E::State)
        );
        source.finish(START + 12, Stop::InputLimit)?;
        let bytes = source.canonical_bytes()?;
        assert!(bytes.len() <= source.config().max_source_bytes);
        let decoded = NativeMetadataSource::decode(&bytes)?;
        assert_eq!(decoded.records().len(), 1);
        assert_eq!(decoded.records()[0].expose_wire(), accepted);
        assert_eq!(decoded.omitted_observations(), 1);
        assert_eq!(decoded.omitted_received_ns(), Some(START + 11));
        assert!(!decoded.processing_complete());
    }
    Ok(())
}

#[test]
fn checkpoints_are_independent_clones_and_never_completed_captures() -> Test {
    let mut live = playing(config()?)?;
    live.observe_interleaved(&frame(
        &interleaved(4, &rtp(0, true, b"<first/>")),
        START + 10,
    )?)?;
    let mut prefix = live.clone();
    prefix.finish(START + 11, Stop::Checkpoint)?;
    let bytes = prefix.canonical_bytes()?;
    assert_eq!(prefix.stop(), Some(Stop::Checkpoint));
    assert!(!prefix.processing_complete());
    live.observe_interleaved(&frame(
        &interleaved(4, &rtp(1, true, b"<second/>")),
        START + 12,
    )?)?;
    live.finish(START + 13, Stop::TargetReached)?;
    assert_eq!(prefix.canonical_bytes()?, bytes);
    assert_eq!(prefix.records().len(), 1);
    assert_eq!(live.records().len(), 2);
    assert!(live.processing_complete());
    assert!(!NativeMetadataSource::decode(&bytes)?.processing_complete());
    Ok(())
}

#[test]
fn control_hashes_keep_correlation_without_retaining_authentication_or_session_tokens() -> Test {
    let mut source = NativeMetadataSource::new(config()?)?;
    let challenge = response(
        1,
        401,
        "WWW-Authenticate: Digest realm=\"owner\", nonce=\"secret-nonce-canary\", algorithm=SHA-256, qop=\"auth\"\r\nSession: secret-session-canary\r\n",
        &[],
    );
    source.observe_rejected_control(&frame(&challenge, START + 1)?)?;
    source.finish(START + 2, Stop::Authentication)?;
    let bytes = source.canonical_bytes()?;
    assert_eq!(
        source.controls()[0].wire_digest(),
        ContentDigest::sha256(&challenge)
    );
    assert_eq!(source.controls()[0].wire_bytes(), challenge.len());
    assert_eq!(source.controls()[0].status(), 401);
    assert_eq!(source.controls()[0].cseq(), Some(1));
    assert_eq!(source.controls()[0].progress(), None);
    for secret in [
        b"secret-nonce-canary".as_slice(),
        b"secret-session-canary".as_slice(),
    ] {
        assert!(!bytes.windows(secret.len()).any(|window| window == secret));
    }
    let valid = finished()?.canonical_bytes()?;
    assert!(
        !valid
            .windows(b"private-session-token".len())
            .any(|window| window == b"private-session-token")
    );
    assert!(!source.processing_complete());
    Ok(())
}

#[test]
fn wrong_sdp_selection_and_control_redirect_are_rejected_without_source_mutation() -> Test {
    for (body, fields) in [
        (
            String::from_utf8(sdp())?
                .replace("vnd.onvif.metadata/90000", "vnd.onvif.metadata+gzip/90000"),
            "Content-Type: application/sdp\r\n",
        ),
        (
            String::from_utf8(sdp())?,
            "Content-Type: application/sdp\r\nContent-Base: rtsp://other.local/live/\r\n",
        ),
    ] {
        let mut source = NativeMetadataSource::new(config()?)?;
        let wire = response(1, 200, fields, body.as_bytes());
        assert_eq!(
            source.observe_control(
                &ClientProgress::Accepted(ClientState::Described),
                &frame(&wire, START + 1)?
            ),
            Err(E::Description)
        );
        assert!(source.description().is_none());
        assert!(source.controls().is_empty());
        source.finish(START + 2, Stop::Protocol)?;
        assert!(!source.processing_complete());
        NativeMetadataSource::decode(&source.canonical_bytes()?)?;
    }
    Ok(())
}

#[test]
fn all_non_success_stops_and_unprocessed_suffixes_remain_incomplete() -> Test {
    for stop in [
        Stop::InputLimit,
        Stop::Timeout,
        Stop::Protocol,
        Stop::Authentication,
        Stop::Authority,
        Stop::Storage,
        Stop::Cancelled,
        Stop::Transport,
        Stop::Checkpoint,
    ] {
        let mut source = playing(config()?)?;
        source.observe_interleaved(&frame(
            &interleaved(4, &rtp(0, true, b"<metadata/>")),
            START + 10,
        )?)?;
        source.finish(START + 11, stop)?;
        assert!(!source.processing_complete());
        assert_eq!(
            NativeMetadataSource::decode(&source.canonical_bytes()?)?.stop(),
            Some(stop)
        );
    }
    let mut source = playing(config()?)?;
    source.observe_interleaved(&frame(
        &interleaved(4, &rtp(0, true, b"<metadata/>")),
        START + 10,
    )?)?;
    source.record_unprocessed_wire(3)?;
    source.finish(START + 11, Stop::TargetReached)?;
    assert!(!source.processing_complete());
    assert_eq!(
        NativeMetadataSource::decode(&source.canonical_bytes()?)?.unprocessed_wire_bytes(),
        3
    );
    Ok(())
}

#[test]
fn clock_order_finish_boundaries_and_owner_receive_origin_are_checked() -> Test {
    let mut source = playing(config()?)?;
    let wire = interleaved(4, &rtp(0, true, b"<metadata/>"));
    assert_eq!(
        source.observe_interleaved(&frame(&wire, START + 4)?),
        Err(E::Clock)
    );
    assert_eq!(source.finish(START + 4, Stop::Cancelled), Err(E::Clock));
    source.observe_interleaved(&frame(&wire, START + 10)?)?;
    source.finish(START + 11, Stop::Eof)?;
    assert_eq!(source.finish(START + 12, Stop::Eof), Err(E::State));
    assert_eq!(
        source.observe_interleaved(&frame(&wire, START + 12)?),
        Err(E::State)
    );
    let mut config = config()?;
    config.receive_origin_ns = i128::MAX - i128::from(START);
    let mut overflow = NativeMetadataSource::new(config)?;
    assert_eq!(overflow.finish(START + 1, Stop::Cancelled), Err(E::Clock));
    assert_eq!(overflow.stop(), None);
    Ok(())
}

#[test]
fn an_unrepresentable_initial_receive_clock_is_refused_before_acquisition() -> Test {
    let mut config = config()?;
    config.receive_origin_ns = i128::MAX - i128::from(START) + 1;
    assert_eq!(config.validate(), Err(E::Clock));
    assert!(matches!(NativeMetadataSource::new(config), Err(E::Clock)));
    Ok(())
}

#[test]
fn corruption_truncation_and_trailing_bytes_cannot_become_a_valid_source() -> Test {
    let bytes = finished()?.canonical_bytes()?;
    for at in [0, 12, bytes.len() / 2, bytes.len() - 1] {
        let mut corrupt = bytes.clone();
        corrupt[at] ^= 1;
        assert!(NativeMetadataSource::decode(&corrupt).is_err());
    }
    for end in [0, 1, 32, bytes.len() / 2, bytes.len() - 1] {
        assert!(NativeMetadataSource::decode(&bytes[..end]).is_err());
    }
    let mut appended = bytes;
    appended.push(0);
    assert!(NativeMetadataSource::decode(&appended).is_err());
    Ok(())
}

#[test]
fn debug_hides_original_sdp_private_payload_and_network_location() -> Test {
    let mut source = playing(config()?)?;
    source.observe_interleaved(&frame(
        &interleaved(4, &rtp(0, true, b"private-payload-canary")),
        START + 10,
    )?)?;
    source.finish(START + 11, Stop::TargetReached)?;
    let rendered = format!(
        "{source:?} {:?} {:?}",
        source.description(),
        source.records()
    );
    for secret in [
        "private-title",
        "private-payload-canary",
        "private-session-token",
        "camera.local",
        "127.0.0.1",
    ] {
        assert!(!rendered.contains(secret));
    }
    Ok(())
}

#[test]
fn canonical_stream_ingress_preserves_all_128_identity_bits() -> Test {
    let mut config = config()?;
    let key = StreamKey {
        ingress: u128::from(u64::MAX) + 3,
        ..KEY
    };
    config.binding = TcpBinding::new(
        key,
        "127.0.0.1:554".parse()?,
        "camera.local",
        TcpSecurityPolicy::OwnerApprovedPlaintext,
    )?;
    let mut source = NativeMetadataSource::new(config)?;
    source.finish(START, Stop::Cancelled)?;
    let bytes = source.canonical_bytes()?;
    let decoded = NativeMetadataSource::decode(&bytes)?;
    assert_eq!(decoded.config().binding.key(), key);
    assert_eq!(decoded.canonical_bytes()?, bytes);
    Ok(())
}

#[test]
fn accepted_control_status_is_exactly_the_real_session_success_code() -> Test {
    let mut source = NativeMetadataSource::new(config()?)?;
    let wire = response(1, 201, "Content-Type: application/sdp\r\n", &sdp());
    let source_frame = frame(&wire, START + 1)?;
    assert_eq!(
        source.observe_control(
            &ClientProgress::Accepted(ClientState::Described),
            &source_frame
        ),
        Err(E::Control)
    );
    assert!(source.controls().is_empty());
    source.observe_rejected_control(&source_frame)?;
    source.finish(START + 2, Stop::Protocol)?;
    let decoded = NativeMetadataSource::decode(&source.canonical_bytes()?)?;
    assert_eq!(decoded.controls()[0].status(), 201);
    assert_eq!(decoded.controls()[0].progress(), None);
    assert!(!decoded.processing_complete());
    Ok(())
}
