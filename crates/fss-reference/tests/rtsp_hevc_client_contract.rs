#![forbid(unsafe_code)]
//! Public TCP-to-HEVC reception, authentication, provenance and failure contracts.

use fss_packet::{
    H265Error, H265Limits, H265ReceiveError, H265ReceivePoll, ReorderDisposition,
    ReorderLimits, StreamKey,
};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::{
    ClientCommand as C, ClientConfig, ClientError, ClientProgress, ClientState,
};
use fss_reference::rtsp::framed::{MAX_WIRE_CHUNK, RtspWireFrame, WIRE_LIFETIME_NS, WireIntakeError};
use fss_reference::rtsp::hevc_client::{
    HevcClientError as E, HevcClientPoll as P, HevcClientRetirement, RtspHevcClient,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fault = (E, Box<HevcClientRetirement>, Option<RtspWireFrame>);
const KEY: StreamKey = StreamKey { ingress: 1, generation: 1, ssrc: 7 };

fn config() -> ClientConfig {
    ClientConfig {
        presentation_uri: "rtsp://camera.local/live/".into(),
        control_root_uri: "rtsp://camera.local/live".into(),
        media_index: 0, channels: (0, 1), response_timeout_ns: 10_000_000_000,
        default_session_timeout_seconds: 60,
    }
}
fn sdp(reduced: bool) -> Vec<u8> {
    // Synthetic header-screening fixtures; these are NOT decodable parameter sets.
    format!("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\n\
        m=video 0 RTP/AVP 98\r\na=rtpmap:98 H265/90000\r\n\
        a=fmtp:98 sprop-vps=QAEBAg==;sprop-sps=QgECAw==;sprop-pps=RAEDBA==\r\n\
        a=control:trackID=0\r\n{}", if reduced { "a=rtcp-rsize\r\n" } else { "" }).into_bytes()
}
fn response(cseq: u32, status: u16, fields: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut wire = format!("RTSP/1.0 {status} Fixture\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n", body.len());
    for (key, value) in fields { wire.push_str(&format!("{key}: {value}\r\n")); }
    wire.push_str("\r\n");
    let mut wire = wire.into_bytes();
    wire.extend_from_slice(body);
    wire
}
fn challenge(cseq: u32) -> Vec<u8> {
    response(cseq, 401, &[("WWW-Authenticate",
        "Digest realm=\"owner-realm\", nonce=\"private-nonce\", algorithm=SHA-256, qop=\"auth\"")], &[])
}
fn interleaved(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![b'$', channel];
    wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}
fn rtp(sequence: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x80, 98 | if marker { 128 } else { 0 }];
    wire.extend_from_slice(&sequence.to_be_bytes());
    wire.extend_from_slice(&90_000_u32.to_be_bytes());
    wire.extend_from_slice(&KEY.ssrc.to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}
fn packet(sequence: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    interleaved(0, &rtp(sequence, marker, payload))
}
fn drain(client: &mut RtspHevcClient, now: u64) -> Result<Vec<P>, Box<dyn std::error::Error>> {
    let mut events = Vec::new();
    for _ in 0..1024 {
        let event = client.poll(now)?;
        let stop = matches!(&event, P::Pending { .. } | P::Backpressure { .. }
            | P::AuthenticationRequired { .. } | P::KeepAliveDue | P::Fault { .. } | P::Ended { .. });
        events.push(event);
        if stop { return Ok(events); }
    }
    Err("client failed to reach a bounded wait/terminal state".into())
}
fn feed(client: &mut RtspHevcClient, wire: &[u8], now: u64)
    -> Result<Vec<P>, Box<dyn std::error::Error>>
{
    let mut output = Vec::new();
    for chunk in wire.chunks(MAX_WIRE_CHUNK) {
        client.ingest(chunk, now)?;
        output.extend(drain(client, now)?);
    }
    Ok(output)
}
fn nals(events: &[P]) -> Vec<Vec<u8>> {
    let mut output = Vec::new();
    for event in events {
        if let P::Media(H265ReceivePoll::Packet { reconstruction: Ok(result), .. }) = event {
            output.extend(result.nals.iter().map(|nal| nal.bytes().to_vec()));
        }
    }
    output
}
fn fault(events: Vec<P>) -> Result<Fault, Box<dyn std::error::Error>> {
    for event in events {
        if let P::Fault { reason, retirement, source } = event {
            return Ok((reason, retirement, source));
        }
    }
    Err("expected explicit client fault".into())
}
fn ready(client: &mut RtspHevcClient, reduced: bool, timeout: &str) -> TestResult {
    client.request(C::Describe, 0)?;
    feed(client, &response(1, 200, &[("Content-Type", "application/sdp")], &sdp(reduced)), 1)?;
    assert_eq!(client.state(), ClientState::Described);
    client.request(C::Setup, 2)?;
    feed(client, &response(2, 200, &[("Session", timeout),
        ("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000007")], &[]), 3)?;
    assert_eq!(client.state(), ClientState::Ready);
    Ok(())
}
fn playing(reorder: ReorderLimits, codec: H265Limits, reduced: bool)
    -> Result<RtspHevcClient, Box<dyn std::error::Error>>
{
    let mut client = RtspHevcClient::new(config(), KEY, reorder, codec)?;
    ready(&mut client, reduced, "private-session;timeout=60")?;
    client.request(C::Play, 4)?;
    feed(&mut client, &response(3, 200, &[("Session", "private-session")], &[]), 5)?;
    assert_eq!(client.state(), ClientState::Playing);
    Ok(client)
}
fn prime(client: &mut RtspHevcClient) -> TestResult {
    for seq in 0..4 {
        feed(client, &packet(seq, true, &[0x40, 1, 1]), 10 + u64::from(seq))?;
    }
    assert_eq!(client.queued_rtp_bytes(), 0);
    Ok(())
}
fn primed(reorder: ReorderLimits, codec: H265Limits)
    -> Result<RtspHevcClient, Box<dyn std::error::Error>>
{
    let mut client = playing(reorder, codec, false)?;
    prime(&mut client)?;
    Ok(client)
}
fn authenticated(codec: H265Limits) -> Result<RtspHevcClient, Box<dyn std::error::Error>> {
    let credentials = DigestCredentials::new("private-user", "private-password")?;
    let mut client = RtspHevcClient::with_digest(config(), KEY, ReorderLimits::default(), codec,
        "owner-realm", DigestPolicy::default())?;
    client.request_digest(C::Describe, &credentials, [1; 16], 0)?;
    let output = feed(&mut client, &challenge(1), 1)?;
    assert!(matches!(output.last(), Some(P::AuthenticationRequired { cseq: 1, .. })));
    let answered = client.respond_digest(&credentials, [2; 16], 2)?;
    assert_eq!(answered.request.cseq(), 2);
    assert_eq!(answered.source.expose_wire(), challenge(1));
    drain(&mut client, 2)?;
    feed(&mut client, &response(2, 200, &[("Content-Type", "application/sdp")], &sdp(false)), 3)?;
    client.request_digest(C::Setup, &credentials, [3; 16], 4)?;
    feed(&mut client, &response(3, 200, &[("Session", "private-session;timeout=60"),
        ("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000007")], &[]), 5)?;
    client.request_digest(C::Play, &credentials, [4; 16], 6)?;
    feed(&mut client, &response(4, 200, &[("Session", "private-session")], &[]), 7)?;
    assert_eq!(client.state(), ClientState::Playing);
    prime(&mut client)?;
    Ok(client)
}

#[test]
fn every_tcp_description_split_preserves_exact_control_source_and_selected_codec() -> TestResult {
    let wire = response(1, 200, &[("Content-Type", "application/sdp")], &sdp(false));
    for split in 1..wire.len() {
        let mut client = RtspHevcClient::new(config(), KEY, ReorderLimits::default(), H265Limits::default())?;
        client.request(C::Describe, 0)?;
        let before = feed(&mut client, &wire[..split], 1)?;
        assert!(before.iter().all(|p| matches!(p, P::Pending { .. })));
        let after = feed(&mut client, &wire[split..], 2)?;
        let P::Control { progress, source } = &after[0] else { return Err("missing control source".into()); };
        assert_eq!(*progress, ClientProgress::Accepted(ClientState::Described));
        assert_eq!(source.expose_wire(), wire);
        assert_eq!(source.received_ns(), 2);
        assert_eq!(client.media().ok_or("missing HEVC negotiation")?.payload_type(), 98);
    }
    Ok(())
}

#[test]
fn play_ack_and_first_rtp_coalesced_in_one_tcp_chunk_are_processed_in_order() -> TestResult {
    let mut client = RtspHevcClient::new(config(), KEY, ReorderLimits::default(), H265Limits::default())?;
    ready(&mut client, false, "private-session;timeout=60")?;
    client.request(C::Play, 4)?;
    let ack = response(3, 200, &[("Session", "private-session")], &[]);
    let wire = packet(0, true, &[0x26, 1, 1]);
    let combined = [ack.as_slice(), wire.as_slice()].concat();
    let events = feed(&mut client, &combined, 5)?;
    assert!(matches!(&events[0], P::Control { progress: ClientProgress::Accepted(ClientState::Playing), source }
        if source.expose_wire() == ack));
    assert!(matches!(&events[1], P::Rtp { source, .. } if source.expose_wire() == wire));
    assert_eq!(client.state(), ClientState::Playing);
    Ok(())
}

#[test]
fn fragmented_hevc_reorders_without_losing_wire_envelopes_or_nal_provenance() -> TestResult {
    let mut client = primed(ReorderLimits::default(), H265Limits::default())?;
    let start = packet(4, false, &[0x62, 1, 0x93, 1]);
    let middle = packet(5, false, &[0x62, 1, 0x13, 2]);
    let end = packet(6, true, &[0x62, 1, 0x53, 3]);
    let mut events = feed(&mut client, &start, 20)?;
    events.extend(feed(&mut client, &end, 21)?);
    events.extend(feed(&mut client, &middle, 22)?);
    assert_eq!(nals(&events), vec![vec![0x26, 1, 1, 2, 3]]);
    let sources: Vec<_> = events.iter().filter_map(|event| match event {
        P::Rtp { source, .. } => Some(source.expose_wire().to_vec()), _ => None,
    }).collect();
    assert_eq!(sources, vec![start.clone(), end.clone(), middle.clone()]);
    let nal = events.iter().find_map(|event| match event {
        P::Media(H265ReceivePoll::Packet { reconstruction: Ok(result), .. }) => result.nals.first(),
        _ => None,
    }).ok_or("missing reconstructed NAL")?;
    for (index, wire) in [&start, &middle, &end].into_iter().enumerate() {
        let span = &nal.sources()[index];
        assert_eq!(span.sequence, index as u64 + 4);
        assert_eq!(&wire[4 + span.wire_range.start..4 + span.wire_range.end], &nal.bytes()[span.nal_range.clone()]);
        assert_eq!(span.fragment_header_range, Some(12..15));
    }
    assert_eq!(client.retained_nal_bytes(), 0);
    assert_eq!(client.queued_rtp_bytes(), 0);
    Ok(())
}

#[test]
fn media_before_play_or_on_wrong_channel_is_returned_intact_and_fenced() -> TestResult {
    for early in [true, false] {
        let mut client = RtspHevcClient::new(config(), KEY, ReorderLimits::default(), H265Limits::default())?;
        ready(&mut client, false, "private-session;timeout=60")?;
        if !early {
            client.request(C::Play, 4)?;
            feed(&mut client, &response(3, 200, &[("Session", "private-session")], &[]), 5)?;
        }
        let wire = interleaved(if early { 0 } else { 2 }, &rtp(0, true, &[0x26, 1, 1]));
        let (error, retired, source) = fault(feed(&mut client, &wire, 6)?)?;
        assert_eq!(error, E::Session(ClientError::MediaNotAdmitted));
        assert_eq!(source.ok_or("refused media disappeared")?.expose_wire(), wire);
        assert!(retired.session.remote_session_may_exist);
        assert_eq!(client.state(), ClientState::Closed);
    }
    Ok(())
}

#[test]
fn setup_ssrc_mismatch_is_rejected_before_media_configuration() -> TestResult {
    let mut client = RtspHevcClient::new(config(), KEY, ReorderLimits::default(), H265Limits::default())?;
    client.request(C::Describe, 0)?;
    feed(&mut client, &response(1, 200, &[("Content-Type", "application/sdp")], &sdp(false)), 1)?;
    client.request(C::Setup, 2)?;
    let wire = response(2, 200, &[("Session", "private-session"),
        ("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000009")], &[]);
    let (error, retired, source) = fault(feed(&mut client, &wire, 3)?)?;
    assert_eq!(error, E::StreamBinding);
    assert!(retired.video.is_none());
    assert!(retired.session.remote_session_may_exist);
    assert_eq!(source.ok_or("setup evidence missing")?.expose_wire(), wire);
    Ok(())
}

#[test]
fn wrong_rtp_payload_type_or_ssrc_fails_with_the_original_datagram() -> TestResult {
    for offset in [1, 11] {
        let mut client = primed(ReorderLimits::default(), H265Limits::default())?;
        let mut payload = rtp(4, true, &[0x26, 1, 1]);
        payload[offset] ^= 1;
        let wire = interleaved(0, &payload);
        let (error, _, source) = fault(feed(&mut client, &wire, 20)?)?;
        assert!(matches!(error, E::Video(H265ReceiveError::Transport(_))));
        assert_eq!(source.ok_or("rejected RTP lost")?.expose_wire(), wire);
        assert_eq!(client.next_wake_ns(), None);
    }
    Ok(())
}

#[test]
fn codec_refusal_keeps_both_original_views_and_does_not_invent_stream_failure() -> TestResult {
    let mut client = primed(ReorderLimits::default(), H265Limits::default())?;
    let raw = rtp(4, true, &[0x62, 1, 0xd3, 99]);
    let wire = interleaved(0, &raw);
    let events = feed(&mut client, &wire, 20)?;
    assert!(events.iter().any(|p| matches!(p, P::Rtp { source, .. } if source.expose_wire() == wire)));
    assert!(events.iter().any(|p| matches!(p,
        P::Media(H265ReceivePoll::Packet { source, reconstruction: Err(H265ReceiveError::Codec(failure)) })
        if source.bytes() == raw && failure.reason == H265Error::Malformed)));
    assert_eq!(client.state(), ClientState::Playing);
    assert_eq!(nals(&feed(&mut client, &packet(5, true, &[0x26, 1, 8]), 21)?), vec![vec![0x26, 1, 8]]);
    Ok(())
}

#[test]
fn compound_and_reduced_rtcp_are_negotiated_not_inferred_from_invalid_input() -> TestResult {
    let rr = vec![0x80, 201, 0, 1, 0, 0, 0, 7];
    for reduced in [false, true] {
        let mut client = playing(ReorderLimits::default(), H265Limits::default(), reduced)?;
        let wire = interleaved(1, &rr);
        let events = feed(&mut client, &wire, 6)?;
        let P::Rtcp { source, validation } = &events[0] else { return Err("missing RTCP result".into()); };
        assert_eq!(source.expose_wire(), wire);
        assert_eq!(validation.is_ok(), reduced);
        assert_eq!(client.state(), ClientState::Playing);
    }
    let cname = [0x81, 202, 0, 2, 0, 0, 0, 7, 1, 1, b'x', 0];
    let compound = [rr.as_slice(), cname.as_slice()].concat();
    let mut client = playing(ReorderLimits::default(), H265Limits::default(), false)?;
    assert!(matches!(&feed(&mut client, &interleaved(1, &compound), 6)?[0], P::Rtcp { validation: Ok(2), .. }));
    let damaged = [compound.as_slice(), &[0x80, 201, 0]].concat();
    assert!(matches!(&feed(&mut client, &interleaved(1, &damaged), 7)?[0], P::Rtcp { validation: Err(_), .. }));
    assert_eq!(client.state(), ClientState::Playing);
    Ok(())
}

#[test]
fn delivery_gap_and_late_recovery_cannot_resurrect_a_hevc_fragment_chain() -> TestResult {
    let reorder = ReorderLimits { max_delay_ns: 10, ..ReorderLimits::default() };
    let mut client = primed(reorder, H265Limits::default())?;
    feed(&mut client, &packet(4, false, &[0x62, 1, 0x93, 1]), 20)?;
    feed(&mut client, &packet(6, true, &[0x62, 1, 0x53, 3]), 21)?;
    assert_eq!(client.next_wake_ns(), Some(31));
    let events = drain(&mut client, 31)?;
    assert!(matches!(&events[0], P::Media(H265ReceivePoll::Gap { gap, discarded: Some(discard) })
        if gap.first_sequence == 5 && gap.last_sequence == 5 && discard.reason == H265Error::Gap));
    assert!(events.iter().any(|p| matches!(p,
        P::Media(H265ReceivePoll::Packet { reconstruction: Err(H265ReceiveError::Codec(failure)), .. })
        if failure.reason == H265Error::MissingStart)));
    let late = feed(&mut client, &packet(5, false, &[0x62, 1, 0x13, 2]), 32)?;
    assert!(matches!(&late[0], P::Rtp { admission, .. } if admission.transport.disposition == ReorderDisposition::TooLate));
    assert!(nals(&events).is_empty());
    assert!(nals(&late).is_empty());
    assert_eq!(client.retained_nal_bytes(), 0);
    Ok(())
}

#[test]
fn full_queue_retains_one_exact_retry_then_admits_it_once_after_timer_progress() -> TestResult {
    let reorder = ReorderLimits { max_packets: 1, max_delay_ns: 10, ..ReorderLimits::default() };
    let mut client = primed(reorder, H265Limits::default())?;
    feed(&mut client, &packet(5, true, &[0x26, 1, 5]), 20)?;
    let waiting = packet(6, true, &[0x26, 1, 6]);
    let events = feed(&mut client, &waiting, 21)?;
    assert!(matches!(events.last(), Some(P::Backpressure { wake_at_ns: Some(30) })));
    assert_eq!(client.buffered_wire_bytes(), waiting.len());
    let rejected = client.ingest(&packet(7, true, &[0x26, 1, 7]), 22).err().ok_or("backpressure ignored")?;
    assert_eq!(rejected.reason, E::Backpressure);
    assert!(rejected.retirement.is_none());
    let events = drain(&mut client, 30)?;
    let sources: Vec<_> = events.iter().filter_map(|p| match p {
        P::Rtp { source, admission, .. } => Some((source, admission)), _ => None,
    }).collect();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].0.expose_wire(), waiting);
    assert_eq!(sources[0].0.received_ns(), 21);
    assert_eq!(sources[0].1.transport.disposition, ReorderDisposition::Buffered);
    assert!(events.iter().any(|p| matches!(p, P::Media(H265ReceivePoll::Packet { source, .. })
        if source.sequence() == 6 && source.received_ns() == 30)));
    assert_eq!(nals(&events), vec![vec![0x26, 1, 5], vec![0x26, 1, 6]]);
    assert_eq!(client.buffered_wire_bytes(), 0);
    Ok(())
}

#[test]
fn held_retry_cannot_outlive_its_original_wire_residence_deadline() -> TestResult {
    let reorder = ReorderLimits { max_packets: 1, max_delay_ns: 60_000_000_000, ..ReorderLimits::default() };
    let mut client = primed(reorder, H265Limits::default())?;
    feed(&mut client, &packet(5, true, &[0x26, 1, 5]), 20)?;
    let waiting = packet(6, true, &[0x26, 1, 6]);
    feed(&mut client, &waiting, 21)?;
    assert_eq!(client.next_wake_ns(), Some(WIRE_LIFETIME_NS + 21));
    let (error, retired, source) = fault(drain(&mut client, WIRE_LIFETIME_NS + 21)?)?;
    assert_eq!(error, E::Wire(WireIntakeError::Deadline));
    assert!(source.is_none());
    assert_eq!(retired.retry.ok_or("held frame disappeared")?.expose_wire(), waiting);
    assert_eq!(retired.video.ok_or("RTP retirement missing")?.queue.packets, 1);
    assert!(retired.wire.is_empty());
    Ok(())
}

#[test]
fn impossible_single_datagram_budget_refuses_instead_of_waiting_forever() -> TestResult {
    let reorder = ReorderLimits { max_bytes: 15, ..ReorderLimits::default() };
    let mut client = primed(reorder, H265Limits::default())?;
    let oversized = packet(4, true, &[0x26, 1, 1, 2]);
    let (error, _, source) = fault(feed(&mut client, &oversized, 20)?)?;
    assert_eq!(error, E::InputLimit);
    assert_eq!(source.ok_or("oversized datagram lost")?.expose_wire(), oversized);
    assert_eq!(client.next_wake_ns(), None);
    Ok(())
}

#[test]
fn blocked_partial_wire_waits_for_hard_expiry_not_a_busy_keepalive_loop() -> TestResult {
    let mut client = RtspHevcClient::new(config(), KEY, ReorderLimits::default(), H265Limits::default())?;
    ready(&mut client, false, "private-session;timeout=2")?;
    client.request(C::Play, 4)?;
    feed(&mut client, &response(3, 200, &[("Session", "private-session")], &[]), 5)?;
    feed(&mut client, b"$\0", 20)?;
    assert_eq!(client.next_wake_ns(), Some(2_000_000_004));
    assert!(matches!(client.poll(1_000_000_004)?, P::Pending { wake_at_ns: Some(2_000_000_004) }));
    let (error, retired, _) = fault(drain(&mut client, 2_000_000_004)?)?;
    assert_eq!(error, E::Session(ClientError::SessionExpired));
    assert_eq!(retired.wire.expose(), b"$\0");
    assert!(retired.session.remote_session_may_exist);
    Ok(())
}

#[test]
fn fragment_expiry_runs_without_network_and_before_consuming_new_wire() -> TestResult {
    let codec = H265Limits { max_pending_age_ns: 10, ..H265Limits::default() };
    let mut client = primed(ReorderLimits::default(), codec)?;
    feed(&mut client, &packet(4, false, &[0x62, 1, 0x93, 1]), 20)?;
    assert_eq!(client.next_wake_ns(), Some(30));
    let clean = packet(5, true, &[0x26, 1, 9]);
    client.ingest(&clean, 30)?;
    assert!(matches!(client.poll(30)?, P::Media(H265ReceivePoll::FragmentDiscarded(discard))
        if discard.reason == H265Error::Deadline && discard.first_sequence == 4));
    assert_eq!(client.buffered_wire_bytes(), clean.len());
    let events = drain(&mut client, 30)?;
    assert_eq!(nals(&events), vec![vec![0x26, 1, 9]]);
    Ok(())
}

#[test]
fn late_final_byte_cannot_erase_partial_frame_expiry() -> TestResult {
    let mut client = primed(ReorderLimits::default(), H265Limits::default())?;
    let wire = packet(4, true, &[0x26, 1, 9]);
    feed(&mut client, &wire[..wire.len() - 1], 20)?;
    let failure = client.ingest(&wire[wire.len() - 1..], WIRE_LIFETIME_NS + 20)
        .err().ok_or("expired partial frame accepted")?;
    assert_eq!(failure.reason, E::Wire(WireIntakeError::Deadline));
    assert_eq!(failure.retirement.ok_or("missing retirement")?.wire.expose(), &wire[..wire.len() - 1]);
    assert_eq!(client.state(), ClientState::Closed);
    Ok(())
}

#[test]
fn malformed_suffix_keeps_preceding_valid_packet_and_exact_unprocessed_suffix() -> TestResult {
    let mut client = primed(ReorderLimits::default(), H265Limits::default())?;
    let prefix = packet(4, true, &[0x26, 1, 9]);
    let suffix = b"INVALID\n";
    let combined = [prefix.as_slice(), suffix].concat();
    let events = feed(&mut client, &combined, 20)?;
    assert!(matches!(&events[0], P::Rtp { source, .. } if source.expose_wire() == prefix));
    assert_eq!(nals(&events), vec![vec![0x26, 1, 9]]);
    let (error, retired, source) = fault(events)?;
    assert_eq!(error, E::Wire(WireIntakeError::Framing));
    assert_eq!(retired.wire.expose(), suffix);
    assert!(source.is_none());
    Ok(())
}

#[test]
fn eof_drains_complete_frames_and_never_labels_a_truncated_suffix_successful() -> TestResult {
    for truncated in [false, true] {
        let mut client = primed(ReorderLimits::default(), H265Limits::default())?;
        let start = packet(4, false, &[0x62, 1, 0x93, 1]);
        let end = packet(5, true, &[0x62, 1, 0x53, 2]);
        let mut combined = [start.as_slice(), end.as_slice()].concat();
        if truncated { combined.push(b'$'); }
        client.ingest(&combined, 20)?;
        client.finish();
        let mut events = drain(&mut client, 20)?;
        if matches!(events.last(), Some(P::Pending { wake_at_ns: Some(20) })) {
            events.extend(drain(&mut client, 20)?);
        }
        assert_eq!(nals(&events), vec![vec![0x26, 1, 1, 2]]);
        if truncated {
            let (error, retired, _) = fault(events)?;
            assert_eq!(error, E::Wire(WireIntakeError::Truncated));
            assert_eq!(retired.wire.expose(), b"$");
        } else {
            assert!(matches!(events.last(), Some(P::Ended { media: Some(H265ReceivePoll::Ended { discarded: None }), retirement: Some(_) })));
        }
        assert!(matches!(client.poll(21)?, P::Ended { media: None, retirement: None }));
    }
    Ok(())
}

#[test]
fn eof_incomplete_fragment_is_retired_exactly_once_without_a_complete_nal() -> TestResult {
    let mut client = primed(ReorderLimits::default(), H265Limits::default())?;
    feed(&mut client, &packet(4, false, &[0x62, 1, 0x93, 1]), 20)?;
    client.finish();
    drain(&mut client, 20)?;
    let P::Ended { media: Some(H265ReceivePoll::Ended { discarded: Some(discard) }), retirement: Some(retired) } = client.poll(20)?
        else { return Err("missing incomplete EOF retirement".into()); };
    assert_eq!(discard.reason, H265Error::EndOfInput);
    assert_eq!(discard.byte_len, 3);
    assert!(retired.video.ok_or("missing video accounting")?.fragment.is_none());
    assert!(retired.session.remote_session_may_exist);
    assert!(matches!(client.poll(20)?, P::Ended { media: None, retirement: None }));
    Ok(())
}

#[test]
fn teardown_ack_stops_admission_and_returns_lookahead_in_terminal_custody() -> TestResult {
    let mut client = primed(ReorderLimits::default(), H265Limits::default())?;
    feed(&mut client, &packet(4, false, &[0x62, 1, 0x93, 1]), 20)?;
    client.request(C::Teardown, 21)?;
    let ack = response(4, 200, &[("Session", "private-session")], &[]);
    let after = packet(5, true, &[0x62, 1, 0x53, 2]);
    client.ingest(&[ack.as_slice(), after.as_slice()].concat(), 22)?;
    assert!(matches!(client.poll(22)?, P::Control { progress: ClientProgress::Accepted(ClientState::Closed), .. }));
    let P::Ended { media: Some(H265ReceivePoll::Ended { discarded: Some(discard) }), retirement: Some(retired) } = client.poll(22)?
        else { return Err("teardown did not finalize accepted codec state".into()); };
    assert_eq!(discard.reason, H265Error::EndOfInput);
    assert_eq!(retired.wire.expose(), after);
    assert!(!retired.session.remote_session_may_exist);
    assert!(client.ingest(&after, 23).is_err());
    Ok(())
}

#[test]
fn cancellation_accounts_for_queue_fragment_and_partial_tcp_without_duplicate_receipts() -> TestResult {
    let mut client = primed(ReorderLimits::default(), H265Limits::default())?;
    feed(&mut client, &packet(4, false, &[0x62, 1, 0x93, 1]), 20)?;
    feed(&mut client, &packet(6, true, &[0x62, 1, 0x53, 3]), 21)?;
    feed(&mut client, b"$\0", 22)?;
    let retired = client.cancel();
    let video = retired.video.ok_or("missing video retirement")?;
    assert_eq!(video.queue.packets, 1);
    assert_eq!(video.fragment.ok_or("missing fragment retirement")?.reason, H265Error::Cancelled);
    assert_eq!(retired.wire.expose(), b"$\0");
    assert!(retired.session.remote_session_may_exist);
    assert_eq!(client.queued_rtp_bytes(), 0);
    assert_eq!(client.retained_nal_bytes(), 0);
    assert_eq!(client.buffered_wire_bytes(), 0);
    assert_eq!(client.next_wake_ns(), None);
    let repeated = client.cancel();
    assert!(repeated.video.is_none());
    assert!(repeated.wire.is_empty());
    assert!(matches!(client.poll(22)?, P::Ended { retirement: None, .. }));
    Ok(())
}

#[test]
fn confirmed_source_restart_closes_connection_and_preserves_both_retirement_layers() -> TestResult {
    let mut client = primed(ReorderLimits::default(), H265Limits::default())?;
    feed(&mut client, &packet(4, false, &[0x62, 1, 0x93, 1]), 20)?;
    feed(&mut client, &packet(6, true, &[0x26, 1, 6]), 21)?;
    feed(&mut client, &packet(40_000, true, &[0x26, 1, 7]), 22)?;
    let events = feed(&mut client, &packet(40_001, true, &[0x26, 1, 8]), 23)?;
    let P::Rtp { admission, retirement: Some(retired), .. } = &events[0]
        else { return Err("confirmed restart was not terminal".into()); };
    assert_eq!(admission.transport.disposition, ReorderDisposition::RestartRequired);
    assert_eq!(admission.transport.discarded.ok_or("missing queue retirement")?.packets, 1);
    assert_eq!(admission.discarded.as_ref().ok_or("missing FU retirement")?.reason, H265Error::Gap);
    assert!(retired.session.remote_session_may_exist);
    assert_eq!(client.state(), ClientState::Closed);
    assert_eq!(client.next_wake_ns(), None);
    Ok(())
}

#[test]
fn digest_authentication_reuses_shared_session_and_returns_consumed_raw_challenge() -> TestResult {
    let mut client = authenticated(H265Limits::default())?;
    let events = feed(&mut client, &packet(4, true, &[0x26, 1, 7]), 20)?;
    assert_eq!(nals(&events), vec![vec![0x26, 1, 7]]);
    let plain = client.request(C::KeepAlive, 21).err().ok_or("Digest bypass was permitted")?;
    assert!(matches!(plain.reason, E::Session(ClientError::Authentication(_))));
    assert!(plain.retirement.is_none());
    let credentials = DigestCredentials::new("private-user", "private-password")?;
    let request = client.request_digest(C::Teardown, &credentials, [5; 16], 22)?;
    assert_eq!(request.cseq(), 5);
    assert!(std::str::from_utf8(request.bytes())?.contains("Authorization: Digest "));
    let debug = format!("{client:?} {request:?} {events:?}");
    for secret in ["private-user", "private-password", "private-nonce", "private-session", "camera.local"] {
        assert!(!debug.contains(secret));
    }
    Ok(())
}

#[test]
fn unsupported_or_unsolicited_challenges_are_not_presented_as_credential_requests() -> TestResult {
    for wire in [
        challenge(9),
        response(1, 401, &[("WWW-Authenticate", "Basic realm=\"owner-realm\"")], &[]),
        response(1, 407, &[("Proxy-Authenticate", "Digest realm=\"owner-realm\"")], &[]),
    ] {
        let mut client = RtspHevcClient::with_digest(config(), KEY, ReorderLimits::default(), H265Limits::default(),
            "owner-realm", DigestPolicy::default())?;
        let credentials = DigestCredentials::new("private-user", "private-password")?;
        client.request_digest(C::Describe, &credentials, [1; 16], 0)?;
        let (error, retired, source) = fault(feed(&mut client, &wire, 1)?)?;
        assert!(matches!(error, E::Session(ClientError::CseqMismatch) | E::Authentication(_)));
        assert!(source.is_none());
        assert_eq!(retired.challenge.ok_or("challenge evidence disappeared")?.expose_wire(), wire);
        assert_eq!(client.state(), ClientState::Closed);
    }
    Ok(())
}

#[test]
fn rejected_digest_realm_preserves_the_challenge_and_unprocessed_lookahead() -> TestResult {
    let mut client = RtspHevcClient::with_digest(config(), KEY, ReorderLimits::default(), H265Limits::default(),
        "different-pinned-realm", DigestPolicy::default())?;
    let credentials = DigestCredentials::new("private-user", "private-password")?;
    client.request_digest(C::Describe, &credentials, [1; 16], 0)?;
    let wire = challenge(1);
    let suffix = b"$\0";
    let events = feed(&mut client, &[wire.as_slice(), suffix].concat(), 1)?;
    assert!(matches!(events.last(), Some(P::AuthenticationRequired { cseq: 1, .. })));
    let failure = client.respond_digest(&credentials, [2; 16], 2).err().ok_or("realm mismatch accepted")?;
    assert!(matches!(failure.reason, E::Authentication(_)));
    let retired = failure.retirement.ok_or("missing retirement")?;
    assert_eq!(retired.challenge.ok_or("missing challenge")?.expose_wire(), wire);
    assert_eq!(retired.wire.expose(), suffix);
    Ok(())
}

#[test]
fn original_request_deadline_and_wire_age_survive_held_digest_challenges() -> TestResult {
    let credentials = DigestCredentials::new("private-user", "private-password")?;
    for request_expires_first in [true, false] {
        let mut cfg = config();
        if request_expires_first { cfg.response_timeout_ns = 100; }
        let mut client = RtspHevcClient::with_digest(cfg, KEY, ReorderLimits::default(), H265Limits::default(),
            "owner-realm", DigestPolicy::default())?;
        client.request_digest(C::Describe, &credentials, [1; 16], 0)?;
        let wire = challenge(1);
        feed(&mut client, &wire[..8], 20)?;
        feed(&mut client, &wire[8..], 50)?;
        let deadline = if request_expires_first { 100 } else { WIRE_LIFETIME_NS + 20 };
        assert_eq!(client.next_wake_ns(), Some(deadline));
        assert!(matches!(client.poll(deadline - 1)?, P::AuthenticationRequired { cseq: 1, .. }));
        let failure = client.respond_digest(&credentials, [2; 16], deadline).err().ok_or("expired challenge responded")?;
        let expected = if request_expires_first { E::Session(ClientError::ResponseTimeout) }
            else { E::Wire(WireIntakeError::Deadline) };
        assert_eq!(failure.reason, expected);
        assert_eq!(failure.retirement.ok_or("missing retirement")?.challenge.ok_or("challenge lost")?.expose_wire(), wire);
    }
    Ok(())
}

#[test]
fn codec_timers_keep_running_while_digest_keepalive_waits_for_credentials() -> TestResult {
    let codec = H265Limits { max_pending_age_ns: 10, ..H265Limits::default() };
    let mut client = authenticated(codec)?;
    let credentials = DigestCredentials::new("private-user", "private-password")?;
    feed(&mut client, &packet(4, false, &[0x62, 1, 0x93, 1]), 20)?;
    let keepalive = client.request_digest(C::KeepAlive, &credentials, [5; 16], 21)?;
    let events = feed(&mut client, &challenge(keepalive.cseq()), 22)?;
    assert!(matches!(events.last(), Some(P::AuthenticationRequired { wake_at_ns: Some(30), .. })));
    assert!(matches!(client.poll(30)?, P::Media(H265ReceivePoll::FragmentDiscarded(discard))
        if discard.reason == H265Error::Deadline));
    assert!(matches!(client.poll(30)?, P::AuthenticationRequired { .. }));
    client.finish();
    let (error, retired, _) = fault(drain(&mut client, 31)?)?;
    assert_eq!(error, E::AuthenticationAtEof);
    assert!(retired.challenge.is_some());
    assert!(retired.video.ok_or("missing video retirement")?.fragment.is_none());
    Ok(())
}

#[test]
fn no_codec_fallback_limits_and_reversed_time_are_enforced_at_the_public_boundary() -> TestResult {
    assert!(RtspHevcClient::new(config(), StreamKey { generation: 0, ..KEY }, ReorderLimits::default(), H265Limits::default()).is_err());
    assert!(RtspHevcClient::new(config(), KEY, ReorderLimits { max_packets: 0, ..ReorderLimits::default() }, H265Limits::default()).is_err());
    let mut client = RtspHevcClient::new(config(), KEY, ReorderLimits::default(), H265Limits::default())?;
    client.request(C::Describe, 0)?;
    let failure = client.ingest(&vec![0; MAX_WIRE_CHUNK + 1], 1).err().ok_or("chunk limit ignored")?;
    assert_eq!(failure.reason, E::InputLimit);
    assert!(failure.retirement.is_none());
    assert_eq!(client.buffered_wire_bytes(), 0);
    let body = String::from_utf8(sdp(false))?.replace("H265/90000", "H264/90000");
    let (error, _, source) = fault(feed(&mut client, &response(1, 200, &[("Content-Type", "application/sdp")], body.as_bytes()), 1)?)?;
    assert_eq!(error, E::Session(ClientError::Description));
    assert!(source.is_some());
    let mut client = primed(ReorderLimits::default(), H265Limits::default())?;
    feed(&mut client, &packet(4, false, &[0x62, 1, 0x93, 1]), 20)?;
    assert_eq!(client.poll(19).err(), Some(E::Session(ClientError::ClockReversed)));
    assert_eq!(client.retained_nal_bytes(), 3);
    assert_eq!(nals(&feed(&mut client, &packet(5, true, &[0x62, 1, 0x53, 2]), 21)?), vec![vec![0x26, 1, 1, 2]]);
    Ok(())
}

#[test]
fn tcp_chunk_partitions_preserve_reconstructed_nals_and_original_frame_order() -> TestResult {
    let originals = [
        packet(4, false, &[0x62, 1, 0x93, 1]),
        packet(6, true, &[0x62, 1, 0x53, 3]),
        packet(5, false, &[0x62, 1, 0x13, 2]),
    ];
    let stream = originals.concat();
    for width in 1..=stream.len() {
        let mut client = primed(ReorderLimits::default(), H265Limits::default())?;
        let mut events = Vec::new();
        for chunk in stream.chunks(width) {
            events.extend(feed(&mut client, chunk, 20)?);
        }
        assert_eq!(nals(&events), vec![vec![0x26, 1, 1, 2, 3]]);
        let retained: Vec<_> = events.iter().filter_map(|event| match event {
            P::Rtp { source, .. } => Some(source.expose_wire().to_vec()), _ => None,
        }).collect();
        assert_eq!(retained.as_slice(), originals.as_slice());
        assert_eq!(client.buffered_wire_bytes(), 0);
        assert_eq!(client.queued_rtp_bytes(), 0);
        assert_eq!(client.retained_nal_bytes(), 0);
        assert_eq!(client.state(), ClientState::Playing);
    }
    Ok(())
}
