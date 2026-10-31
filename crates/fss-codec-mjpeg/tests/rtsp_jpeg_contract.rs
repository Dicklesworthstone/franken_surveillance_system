#![forbid(unsafe_code)]
//! Actual RTSP negotiation/framing/reordering -> RFC 2435 -> complete native pixels.

extern crate self as fss_reference;

#[path = "rtsp_support/mod.rs"]
pub mod rtsp;

use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{
    ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits, decode_luma,
};
use fss_core::ContentDigest;
use fss_packet::jpeg::{JpegError, JpegFrame, JpegLimits, JpegReceiveError, JpegReceivePoll};
use fss_packet::{ReorderLimits, StreamKey};
use rtsp::authentication::{DigestCredentials, DigestPolicy};
use rtsp::client::{
    ClientCodec, ClientCommand as C, ClientConfig, ClientError, ClientState, RtspClientSession,
};
use rtsp::jpeg_client::pictures::{decode_luma_frame, decode_rgb_frame};
use rtsp::jpeg_client::{JpegClientError as E, JpegClientPoll as P, RtspJpegClient};
use rtsp::selection::{SelectionError, select_jpeg_description};
use std::sync::atomic::AtomicBool;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey {
    ingress: 11,
    generation: 8,
    ssrc: 7,
};
const JPEG: &[u8] = include_bytes!("fixtures/rtp_jpeg/422_32x24_q50_rst0.jpg");
const ORACLE: &[u8] = include_bytes!("fixtures/rtp_jpeg/422_32x24_q50_rst0.ffmpeg.luma");

fn config() -> ClientConfig {
    ClientConfig {
        presentation_uri: "rtsp://camera.local/live/".into(),
        control_root_uri: "rtsp://camera.local/live".into(),
        media_index: 1,
        channels: (0, 1),
        response_timeout_ns: 10_000_000_000,
        default_session_timeout_seconds: 60,
    }
}
fn description(payload: u8, reduced: bool) -> Vec<u8> {
    let mapping = if payload == 26 {
        String::new()
    } else {
        format!("a=rtpmap:{payload} JPEG/90000\r\n")
    };
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\n\
         m=audio 0 RTP/AVP 0\r\na=control:audio\r\n\
         m=video 0 RTP/AVP {payload}\r\n{mapping}a=control:video\r\n{}",
        if reduced { "a=rtcp-rsize\r\n" } else { "" }
    )
    .into_bytes()
}
fn response(cseq: u32, status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut wire = format!(
        "RTSP/1.0 {status} Fixture\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        wire.push_str(&format!("{name}: {value}\r\n"));
    }
    wire.push_str("\r\n");
    let mut out = wire.into_bytes();
    out.extend_from_slice(body);
    out
}
fn interleaved(channel: u8, packet: &[u8]) -> Vec<u8> {
    let mut wire = vec![b'$', channel];
    wire.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    wire.extend_from_slice(packet);
    wire
}
fn scan() -> Test<&'static [u8]> {
    let mut at = 2;
    while at < JPEG.len() {
        let marker = JPEG.get(at..at + 4).ok_or("short fixture marker")?;
        let end = at + 2 + usize::from(u16::from_be_bytes([marker[2], marker[3]]));
        JPEG.get(at..end).ok_or("short fixture segment")?;
        if marker[1] == 0xda {
            return Ok(&JPEG[end..]);
        }
        at = end;
    }
    Err("fixture missing scan".into())
}
fn packet(
    payload: u8,
    sequence: u16,
    range: std::ops::Range<usize>,
    marker: bool,
) -> Test<Vec<u8>> {
    let mut bytes = vec![0x80, payload | if marker { 0x80 } else { 0 }];
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&90_000_u32.to_be_bytes());
    bytes.extend_from_slice(&KEY.ssrc.to_be_bytes());
    bytes.extend_from_slice(&[
        0,
        (range.start >> 16) as u8,
        (range.start >> 8) as u8,
        range.start as u8,
        0,
        50,
        4,
        3,
    ]);
    bytes.extend_from_slice(scan()?.get(range).ok_or("invalid fixture scan range")?);
    Ok(bytes)
}
fn drain(client: &mut RtspJpegClient, now: u64) -> Test<Vec<P>> {
    let mut events = Vec::new();
    for _ in 0..4096 {
        let event = client.poll(now)?;
        let stop = matches!(
            &event,
            P::Pending { .. }
                | P::Backpressure { .. }
                | P::AuthenticationRequired { .. }
                | P::KeepAliveDue
                | P::Fault { .. }
                | P::Ended { .. }
        );
        events.push(event);
        if stop {
            return Ok(events);
        }
    }
    Err("bounded client did not yield".into())
}
fn feed(client: &mut RtspJpegClient, wire: &[u8], chunk: usize, now: u64) -> Test<Vec<P>> {
    let mut out = Vec::new();
    for part in wire.chunks(chunk) {
        client.ingest(part, now)?;
        out.extend(drain(client, now)?);
    }
    Ok(out)
}
fn opened(payload: u8, reduced: bool) -> Test<RtspJpegClient> {
    let mut client = RtspJpegClient::new(
        config(),
        KEY,
        payload,
        ReorderLimits::default(),
        JpegLimits::default(),
    )?;
    for (command, headers, body, now) in [
        (
            C::Describe,
            vec![("Content-Type", "application/sdp")],
            description(payload, reduced),
            1,
        ),
        (
            C::Setup,
            vec![
                ("Session", "fixture-session;timeout=60"),
                (
                    "Transport",
                    "RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000007",
                ),
            ],
            vec![],
            2,
        ),
        (C::Play, vec![("Session", "fixture-session")], vec![], 3),
    ] {
        let request = client.request(command, now)?;
        let wire = response(request.cseq(), 200, &headers, &body);
        let events = feed(&mut client, &wire, 7, now)?;
        assert!(events.iter().any(
            |event| matches!(event, P::Control { source, .. } if source.expose_wire() == wire)
        ));
        assert!(!events.iter().any(|event| matches!(event, P::Fault { .. })));
    }
    assert_eq!(client.state(), ClientState::Playing);
    assert_eq!(
        client
            .media()
            .ok_or("missing JPEG negotiation")?
            .payload_type(),
        payload
    );
    Ok(client)
}
fn completed(events: Vec<P>) -> Test<Vec<JpegFrame>> {
    let mut out = Vec::new();
    for event in events {
        if let P::Jpeg(JpegReceivePoll::Packet { reconstruction, .. }) = event
            && let Some(frame) = reconstruction?.frame
        {
            out.push(*frame);
        }
    }
    Ok(out)
}
fn one_frame(events: Vec<P>) -> Test<JpegFrame> {
    let mut frames = completed(events)?;
    assert_eq!(frames.len(), 1);
    frames.pop().ok_or("missing complete JPEG".into())
}
fn send_full(client: &mut RtspJpegClient, payload: u8, sequence: u16, now: u64) -> Test<Vec<P>> {
    feed(
        client,
        &interleaved(0, &packet(payload, sequence, 0..scan()?.len(), true)?),
        13,
        now,
    )
}
fn assert_luma(frame: JpegFrame) -> Test {
    let expected = ContentDigest::sha256(frame.bytes()).bytes();
    let picture = decode_luma_frame(
        frame,
        expected,
        DecodeLimits::default(),
        &mut DecodeBudget::new(20_000_000),
    )?;
    assert_eq!(picture.pixels().dimensions(), [32, 24]);
    assert_eq!(picture.reconstruction().key(), KEY);
    assert_eq!(picture.pixels().receipt().encoded_sha256, expected);
    assert_eq!(picture.pixels().pixels().len(), ORACLE.len());
    assert!(
        picture
            .pixels()
            .pixels()
            .iter()
            .zip(ORACLE)
            .all(|(a, b)| a.abs_diff(*b) <= 1)
    );
    let native = decode_luma(
        JPEG,
        ContentDigest::sha256(JPEG).bytes(),
        ComponentInterpretation::YCbCr,
        DecodeLimits::default(),
        &mut DecodeBudget::new(20_000_000),
    )?;
    assert_eq!(picture.pixels().pixels(), native.pixels());
    Ok(())
}

#[test]
fn static_26_without_rtpmap_and_dynamic_jpeg_both_reach_actual_pixels() -> Test {
    for payload in [26, 107] {
        let mut client = opened(payload, false)?;
        let probation = send_full(&mut client, payload, 1, 4)?;
        assert!(completed(probation)?.is_empty());
        let events = send_full(&mut client, payload, 2, 5)?;
        let raw = interleaved(0, &packet(payload, 2, 0..scan()?.len(), true)?);
        assert!(events.iter().any(|event| matches!(event, P::Rtp { source, .. } if source.expose_wire() == raw && source.received_ns() == 5)));
        let frame = one_frame(events)?;
        assert_eq!(frame.sequence_interval(), [2, 2]);
        assert_luma(frame)?;
    }
    Ok(())
}

#[test]
fn selector_keeps_ordinals_and_pins_one_jpeg_offer_without_codec_fallback() -> Test {
    let text = String::from_utf8(description(26, false))?
        .replace("m=video 0 RTP/AVP 26", "m=video 0 RTP/AVP 96 26 107")
        .replace("a=control:video", "a=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1\r\na=rtpmap:107 jpeg/90000\r\na=control:video");
    assert_eq!(
        select_jpeg_description(text.as_bytes(), 1, None),
        Err(SelectionError::Ambiguous)
    );
    for payload in [26, 107] {
        let session = select_jpeg_description(text.as_bytes(), 1, Some(payload))?;
        assert_eq!(session.media.len(), 2);
        assert_eq!(session.media[0].media_type, "audio");
        assert_eq!(session.media[1].payload_type, payload);
        assert_eq!(session.media[1].encoding_name.as_deref(), Some("JPEG"));
    }
    assert!(select_jpeg_description(text.as_bytes(), 1, Some(96)).is_err());
    assert!(select_jpeg_description(text.as_bytes(), 0, Some(26)).is_err());
    Ok(())
}

#[test]
fn wrong_clock_static_assignment_channels_and_selected_format_are_refused() -> Test {
    for text in [
        String::from_utf8(description(107, false))?.replace("JPEG/90000", "JPEG/8000"),
        String::from_utf8(description(107, false))?.replace("JPEG/90000", "JPEG/90000/1"),
        String::from_utf8(description(107, false))?.replace("a=rtpmap:107 JPEG/90000\r\n", ""),
        String::from_utf8(description(27, false))?,
        String::from_utf8(description(26, false))? + "a=rtpmap:26 H264/90000\r\n",
        String::from_utf8(description(26, false))? + "a=fmtp:26 packetization-mode=1\r\n",
    ] {
        assert!(select_jpeg_description(text.as_bytes(), 1, None).is_err());
    }
    for payload in [0, 25, 27, 95, 128, 255] {
        assert!(
            RtspClientSession::with_codec_and_payload_type(config(), ClientCodec::Jpeg, payload)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn reordered_fragmented_tcp_frames_keep_original_datagrams_and_receive_times() -> Test {
    let mut client = opened(26, false)?;
    send_full(&mut client, 26, 1, 4)?;
    let size = scan()?.len();
    let a = size / 3;
    let b = a * 2;
    let mut all = Vec::new();
    for (sequence, range, marker, now) in [
        (2, 0..a, false, 5),
        (4, b..size, true, 6),
        (3, a..b, false, 7),
    ] {
        let raw = packet(26, sequence, range, marker)?;
        let events = feed(&mut client, &interleaved(0, &raw), 1, now)?;
        assert!(events.iter().any(|event| matches!(event, P::Rtp { source, .. } if &source.expose_wire()[4..] == raw.as_slice())));
        all.extend(events);
    }
    let positions: Vec<_> = all
        .iter()
        .filter_map(|event| {
            if let P::Jpeg(JpegReceivePoll::Packet { source, .. }) = event {
                Some((source.sequence(), source.received_ns()))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(positions, [(2, 5), (3, 7), (4, 6)]);
    assert_luma(one_frame(all)?)?;
    Ok(())
}

#[test]
fn packet_loss_retires_the_image_and_a_new_complete_frame_recovers() -> Test {
    let mut client = opened(26, false)?;
    send_full(&mut client, 26, 1, 4)?;
    let half = scan()?.len() / 2;
    let start = interleaved(0, &packet(26, 2, 0..half, false)?);
    assert!(completed(feed(&mut client, &start, 19, 5)?)?.is_empty());
    let tail = interleaved(0, &packet(26, 4, half..scan()?.len(), true)?);
    feed(&mut client, &tail, 11, 6)?;
    let events = drain(&mut client, 100_000_006)?;
    assert!(events.iter().any(|event| matches!(event, P::Jpeg(JpegReceivePoll::Gap { discarded: Some(d), .. }) if d.reason == JpegError::Gap)));
    assert!(events.iter().any(|event| matches!(event, P::Jpeg(JpegReceivePoll::Packet { reconstruction: Err(JpegReceiveError::Codec(e)), .. }) if e.reason == JpegError::MissingStart)));
    assert_eq!(client.retained_frame_bytes(), 0);
    assert_luma(one_frame(send_full(&mut client, 26, 5, 100_000_007)?)?)?;
    Ok(())
}

#[test]
fn jpeg_source_binding_rejects_changed_ssrc_without_losing_the_response() -> Test {
    let mut client = RtspJpegClient::new(
        config(),
        KEY,
        26,
        ReorderLimits::default(),
        JpegLimits::default(),
    )?;
    let describe = client.request(C::Describe, 0)?;
    feed(
        &mut client,
        &response(
            describe.cseq(),
            200,
            &[("Content-Type", "application/sdp")],
            &description(26, false),
        ),
        17,
        1,
    )?;
    let setup = client.request(C::Setup, 2)?;
    let raw = response(
        setup.cseq(),
        200,
        &[
            ("Session", "fixture-session"),
            (
                "Transport",
                "RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000008",
            ),
        ],
        &[],
    );
    let mut events = feed(&mut client, &raw, 7, 3)?;
    assert!(events.iter().any(|event| matches!(event, P::Fault { reason:E::StreamBinding, source:Some(source), .. } if source.expose_wire() == raw)));
    events.clear();
    assert_eq!(client.buffered_wire_bytes(), 0);
    Ok(())
}

#[test]
fn rtcp_failure_keeps_original_source_and_does_not_invent_a_jpeg_gap() -> Test {
    let mut client = opened(26, true)?;
    send_full(&mut client, 26, 1, 4)?;
    let raw = interleaved(1, &[0x80, 201, 0, 1, 0, 0, 0, 7]);
    assert!(feed(&mut client, &raw, 3, 5)?.iter().any(
        |event| matches!(event,P::Rtcp { source,validation:Ok(1) } if source.expose_wire()==raw)
    ));
    let invalid = interleaved(1, &[0x80, 201, 0, 4, 0]);
    assert!(feed(&mut client,&invalid,2,6)?.iter().any(|event| matches!(event,P::Rtcp { source,validation:Err(_) } if source.expose_wire()==invalid)));
    assert_luma(one_frame(send_full(&mut client, 26, 2, 7)?)?)?;
    Ok(())
}

#[test]
fn cancellation_returns_exact_unprocessed_tcp_and_retired_incomplete_image() -> Test {
    let mut client = opened(26, false)?;
    send_full(&mut client, 26, 1, 4)?;
    let start = interleaved(0, &packet(26, 2, 0..scan()?.len() / 2, false)?);
    feed(&mut client, &start, 23, 5)?;
    assert!(client.retained_frame_bytes() > 0);
    let unfinished = &[b'$', 0, 0, 80, 0x80, 26];
    client.ingest(unfinished, 6)?;
    drain(&mut client, 6)?;
    let retirement = client.cancel();
    assert_eq!(retirement.wire.expose(), unfinished);
    assert_eq!(
        retirement
            .jpeg
            .ok_or("missing JPEG retirement")?
            .fragment
            .ok_or("missing partial image")?
            .reason,
        JpegError::Cancelled
    );
    assert_eq!(client.retained_frame_bytes(), 0);
    assert!(matches!(
        client.poll(6)?,
        P::Ended {
            media: None,
            retirement: None
        }
    ));
    Ok(())
}

#[test]
fn native_rgb_and_failed_decode_both_keep_the_reconstruction_lineage() -> Test {
    let mut client = opened(26, false)?;
    send_full(&mut client, 26, 1, 4)?;
    let frame = one_frame(send_full(&mut client, 26, 2, 5)?)?;
    let digest = ContentDigest::sha256(frame.bytes()).bytes();
    let rgb = decode_rgb_frame(
        frame,
        digest,
        RgbDecodeLimits::default(),
        &mut DecodeBudget::new(20_000_000),
    )?;
    let expected = decode_rgb(
        JPEG,
        ContentDigest::sha256(JPEG).bytes(),
        ComponentInterpretation::YCbCr,
        RgbDecodeLimits::default(),
        &mut DecodeBudget::new(20_000_000),
    )?;
    assert_eq!(rgb.pixels().pixels(), expected.pixels());
    assert_eq!(rgb.reconstruction().sequence_interval(), [2, 2]);
    let (frame, _) = rgb.into_parts();
    let refusal = decode_luma_frame(
        frame,
        [0; 32],
        DecodeLimits::default(),
        &mut DecodeBudget::new(20_000_000),
    )
    .err()
    .ok_or("wrong derivative digest accepted")?;
    assert_eq!(refusal.reason, DecodeError::SourceMismatch);
    let flag = AtomicBool::new(true);
    let failure = decode_luma_frame(
        *refusal.reconstruction,
        digest,
        DecodeLimits::default(),
        &mut DecodeBudget::cancellable(20_000_000, &flag),
    )
    .err()
    .ok_or("cancelled pixels published")?;
    assert_eq!(failure.reason, DecodeError::Cancelled);
    assert_eq!(failure.reconstruction.sequence_interval(), [2, 2]);
    Ok(())
}

#[test]
fn digest_challenge_uses_the_shared_session_and_returns_exact_original_bytes() -> Test {
    let credentials = DigestCredentials::new("fixture-user", "fixture-password")?;
    let mut client = RtspJpegClient::with_digest(
        config(),
        KEY,
        26,
        ReorderLimits::default(),
        JpegLimits::default(),
        "fixture-realm",
        DigestPolicy::default(),
    )?;
    assert_eq!(
        credentials.username_token_parts(),
        ("fixture-user", "fixture-password")
    );
    let first = client.request_digest(C::Describe, &credentials, [1; 16], 0)?;
    let challenge = response(
        first.cseq(),
        401,
        &[(
            "WWW-Authenticate",
            "Digest realm=\"fixture-realm\", nonce=\"fixture-nonce\", algorithm=SHA-256, qop=\"auth\"",
        )],
        &[],
    );
    let events = feed(&mut client, &challenge, 1, 1)?;
    assert!(
        events.iter().any(
            |event| matches!(event,P::AuthenticationRequired {cseq,..} if *cseq==first.cseq())
        )
    );
    let retry = client.respond_digest(&credentials, [2; 16], 2)?;
    assert_eq!(retry.source.expose_wire(), challenge);
    assert!(retry.request.cseq() > first.cseq());
    assert!(String::from_utf8_lossy(retry.request.bytes()).contains("Authorization: Digest"));
    // The held response has been consumed; let the shared intake report that its
    // accepted lookahead is drained before supplying another TCP chunk.
    drain(&mut client, 2)?;
    let description = response(
        retry.request.cseq(),
        200,
        &[("Content-Type", "application/sdp")],
        &description(26, false),
    );
    feed(&mut client, &description, 5, 3)?;
    assert_eq!(client.state(), ClientState::Described);
    assert!(!format!("{client:?}").contains("fixture-password"));
    let wrong = client
        .request(C::Setup, 4)
        .err()
        .ok_or("plain bypass of Digest accepted")?;
    assert!(matches!(
        wrong.reason,
        E::Session(ClientError::Authentication(_))
    ));
    Ok(())
}

#[path = "rtsp_jpeg_live/mod.rs"]
mod live;

#[path = "rtsp_jpeg_retained/mod.rs"]
mod retained;

// Run the original metadata selection contracts against the exact same production
// session modules, rather than introducing a second test implementation.
#[path = "../../fss-reference/tests/rtsp_metadata_selection_contract.rs"]
mod metadata_selection_regression;
