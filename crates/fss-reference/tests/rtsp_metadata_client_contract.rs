#![forbid(unsafe_code)]
//! Public TCP-to-ONVIF metadata reception, authentication, provenance and failure contracts.

use fss_packet::{
    OnvifMetadataDiscardReason, OnvifMetadataLimits, OnvifMetadataReceiveError,
    OnvifMetadataReceivePoll, ReorderDisposition, ReorderLimits, StreamKey,
};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::{
    ClientCommand as C, ClientConfig, ClientError, ClientProgress, ClientState,
};
use fss_reference::rtsp::framed::{
    MAX_WIRE_CHUNK, RtspWireFrame, WIRE_LIFETIME_NS, WireIntakeError,
};
use fss_reference::rtsp::metadata_client::{
    MetadataClientError as E, MetadataClientPoll as P, MetadataClientRetirement, RtspMetadataClient,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fault = (E, Box<MetadataClientRetirement>, Option<RtspWireFrame>);
const KEY: StreamKey = StreamKey {
    ingress: 1,
    generation: 1,
    ssrc: 7,
};

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
fn sdp(reduced: bool) -> Vec<u8> {
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\n\
        m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:video\r\n\
        m=application 0 RTP/AVP 106 107\r\na=rtpmap:106 vnd.onvif.metadata+gzip/90000\r\n\
        a=rtpmap:107 vnd.onvif.metadata/90000\r\na=control:metadata\r\n{}",
        if reduced { "a=rtcp-rsize\r\n" } else { "" }
    )
    .into_bytes()
}
fn response(cseq: u32, status: u16, fields: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut wire = format!(
        "RTSP/1.0 {status} Fixture\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (key, value) in fields {
        wire.push_str(&format!("{key}: {value}\r\n"));
    }
    wire.push_str("\r\n");
    let mut wire = wire.into_bytes();
    wire.extend_from_slice(body);
    wire
}
fn challenge(cseq: u32) -> Vec<u8> {
    response(
        cseq,
        401,
        &[(
            "WWW-Authenticate",
            "Digest realm=\"owner-realm\", nonce=\"private-nonce\", algorithm=SHA-256, qop=\"auth\"",
        )],
        &[],
    )
}
fn interleaved(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![b'$', channel];
    wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}
fn rtp(sequence: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x80, 107 | if marker { 128 } else { 0 }];
    wire.extend_from_slice(&sequence.to_be_bytes());
    wire.extend_from_slice(&90_000_u32.to_be_bytes());
    wire.extend_from_slice(&KEY.ssrc.to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}
fn packet(sequence: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    interleaved(0, &rtp(sequence, marker, payload))
}
fn drain(client: &mut RtspMetadataClient, now: u64) -> Result<Vec<P>, Box<dyn std::error::Error>> {
    let mut events = Vec::new();
    for _ in 0..1024 {
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
    Err("client failed to reach a bounded wait/terminal state".into())
}
fn feed(
    client: &mut RtspMetadataClient,
    wire: &[u8],
    now: u64,
) -> Result<Vec<P>, Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    for chunk in wire.chunks(MAX_WIRE_CHUNK) {
        client.ingest(chunk, now)?;
        output.extend(drain(client, now)?);
    }
    Ok(output)
}
fn documents(events: &[P]) -> Vec<Vec<u8>> {
    let mut output = Vec::new();
    for event in events {
        if let P::Metadata(OnvifMetadataReceivePoll::Packet {
            reconstruction: Ok(result),
            ..
        }) = event
        {
            output.extend(
                result
                    .document
                    .iter()
                    .map(|document| document.bytes().to_vec()),
            );
        }
    }
    output
}
fn fault(events: Vec<P>) -> Result<Fault, Box<dyn std::error::Error>> {
    for event in events {
        if let P::Fault {
            reason,
            retirement,
            source,
        } = event
        {
            return Ok((reason, retirement, source));
        }
    }
    Err("expected explicit client fault".into())
}
fn ready(client: &mut RtspMetadataClient, reduced: bool, timeout: &str) -> TestResult {
    client.request(C::Describe, 0)?;
    feed(
        client,
        &response(
            1,
            200,
            &[("Content-Type", "application/sdp")],
            &sdp(reduced),
        ),
        1,
    )?;
    assert_eq!(client.state(), ClientState::Described);
    client.request(C::Setup, 2)?;
    feed(
        client,
        &response(
            2,
            200,
            &[
                ("Session", timeout),
                (
                    "Transport",
                    "RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000007",
                ),
            ],
            &[],
        ),
        3,
    )?;
    assert_eq!(client.state(), ClientState::Ready);
    Ok(())
}
fn playing(
    reorder: ReorderLimits,
    codec: OnvifMetadataLimits,
    reduced: bool,
) -> Result<RtspMetadataClient, Box<dyn std::error::Error>> {
    let mut client = RtspMetadataClient::new(config(), KEY, 107, reorder, codec)?;
    ready(&mut client, reduced, "private-session;timeout=60")?;
    client.request(C::Play, 4)?;
    feed(
        &mut client,
        &response(3, 200, &[("Session", "private-session")], &[]),
        5,
    )?;
    assert_eq!(client.state(), ClientState::Playing);
    Ok(client)
}
fn prime(client: &mut RtspMetadataClient) -> TestResult {
    for seq in 0..4 {
        feed(
            client,
            &packet(seq, true, &[0x40, 1, 1]),
            10 + u64::from(seq),
        )?;
    }
    assert_eq!(client.queued_rtp_bytes(), 0);
    Ok(())
}
fn primed(
    reorder: ReorderLimits,
    codec: OnvifMetadataLimits,
) -> Result<RtspMetadataClient, Box<dyn std::error::Error>> {
    let mut client = playing(reorder, codec, false)?;
    prime(&mut client)?;
    Ok(client)
}
fn authenticated(
    codec: OnvifMetadataLimits,
) -> Result<RtspMetadataClient, Box<dyn std::error::Error>> {
    let credentials = DigestCredentials::new("private-user", "private-password")?;
    let mut client = RtspMetadataClient::with_digest(
        config(),
        KEY,
        107,
        ReorderLimits::default(),
        codec,
        "owner-realm",
        DigestPolicy::default(),
    )?;
    client.request_digest(C::Describe, &credentials, [1; 16], 0)?;
    let output = feed(&mut client, &challenge(1), 1)?;
    assert!(matches!(
        output.last(),
        Some(P::AuthenticationRequired { cseq: 1, .. })
    ));
    let answered = client.respond_digest(&credentials, [2; 16], 2)?;
    assert_eq!(answered.request.cseq(), 2);
    assert_eq!(answered.source.expose_wire(), challenge(1));
    drain(&mut client, 2)?;
    feed(
        &mut client,
        &response(2, 200, &[("Content-Type", "application/sdp")], &sdp(false)),
        3,
    )?;
    client.request_digest(C::Setup, &credentials, [3; 16], 4)?;
    feed(
        &mut client,
        &response(
            3,
            200,
            &[
                ("Session", "private-session;timeout=60"),
                (
                    "Transport",
                    "RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000007",
                ),
            ],
            &[],
        ),
        5,
    )?;
    client.request_digest(C::Play, &credentials, [4; 16], 6)?;
    feed(
        &mut client,
        &response(4, 200, &[("Session", "private-session")], &[]),
        7,
    )?;
    assert_eq!(client.state(), ClientState::Playing);
    prime(&mut client)?;
    Ok(client)
}

#[test]
fn every_tcp_description_split_preserves_exact_control_source_and_selected_codec() -> TestResult {
    let wire = response(1, 200, &[("Content-Type", "application/sdp")], &sdp(false));
    for split in 1..wire.len() {
        let mut client = RtspMetadataClient::new(
            config(),
            KEY,
            107,
            ReorderLimits::default(),
            OnvifMetadataLimits::default(),
        )?;
        client.request(C::Describe, 0)?;
        let before = feed(&mut client, &wire[..split], 1)?;
        assert!(before.iter().all(|p| matches!(p, P::Pending { .. })));
        let after = feed(&mut client, &wire[split..], 2)?;
        let P::Control { progress, source } = &after[0] else {
            return Err("missing control source".into());
        };
        assert_eq!(*progress, ClientProgress::Accepted(ClientState::Described));
        assert_eq!(source.expose_wire(), wire);
        assert_eq!(source.received_ns(), 2);
        assert_eq!(
            client
                .media()
                .ok_or("missing metadata negotiation")?
                .payload_type(),
            107
        );
    }
    Ok(())
}

#[test]
fn play_ack_and_first_rtp_coalesced_in_one_tcp_chunk_are_processed_in_order() -> TestResult {
    let mut client = RtspMetadataClient::new(
        config(),
        KEY,
        107,
        ReorderLimits::default(),
        OnvifMetadataLimits::default(),
    )?;
    ready(&mut client, false, "private-session;timeout=60")?;
    client.request(C::Play, 4)?;
    let ack = response(3, 200, &[("Session", "private-session")], &[]);
    let wire = packet(0, true, &[0x26, 1, 1]);
    let combined = [ack.as_slice(), wire.as_slice()].concat();
    let events = feed(&mut client, &combined, 5)?;
    assert!(
        matches!(&events[0], P::Control { progress: ClientProgress::Accepted(ClientState::Playing), source }
        if source.expose_wire() == ack)
    );
    assert!(matches!(&events[1], P::Rtp { source, .. } if source.expose_wire() == wire));
    assert_eq!(client.state(), ClientState::Playing);
    Ok(())
}

#[test]
fn media_before_play_or_on_wrong_channel_is_returned_intact_and_fenced() -> TestResult {
    for early in [true, false] {
        let mut client = RtspMetadataClient::new(
            config(),
            KEY,
            107,
            ReorderLimits::default(),
            OnvifMetadataLimits::default(),
        )?;
        ready(&mut client, false, "private-session;timeout=60")?;
        if !early {
            client.request(C::Play, 4)?;
            feed(
                &mut client,
                &response(3, 200, &[("Session", "private-session")], &[]),
                5,
            )?;
        }
        let wire = interleaved(if early { 0 } else { 2 }, &rtp(0, true, &[0x26, 1, 1]));
        let (error, retired, source) = fault(feed(&mut client, &wire, 6)?)?;
        assert_eq!(error, E::Session(ClientError::MediaNotAdmitted));
        assert_eq!(
            source.ok_or("refused media disappeared")?.expose_wire(),
            wire
        );
        assert!(retired.session.remote_session_may_exist);
        assert_eq!(client.state(), ClientState::Closed);
    }
    Ok(())
}

#[test]
fn setup_ssrc_mismatch_is_rejected_before_media_configuration() -> TestResult {
    let mut client = RtspMetadataClient::new(
        config(),
        KEY,
        107,
        ReorderLimits::default(),
        OnvifMetadataLimits::default(),
    )?;
    client.request(C::Describe, 0)?;
    feed(
        &mut client,
        &response(1, 200, &[("Content-Type", "application/sdp")], &sdp(false)),
        1,
    )?;
    client.request(C::Setup, 2)?;
    let wire = response(
        2,
        200,
        &[
            ("Session", "private-session"),
            (
                "Transport",
                "RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000009",
            ),
        ],
        &[],
    );
    let (error, retired, source) = fault(feed(&mut client, &wire, 3)?)?;
    assert_eq!(error, E::StreamBinding);
    assert!(retired.metadata.is_none());
    assert!(retired.session.remote_session_may_exist);
    assert_eq!(source.ok_or("setup evidence missing")?.expose_wire(), wire);
    Ok(())
}

#[test]
fn wrong_rtp_payload_type_or_ssrc_fails_with_the_original_datagram() -> TestResult {
    for offset in [1, 11] {
        let mut client = primed(ReorderLimits::default(), OnvifMetadataLimits::default())?;
        let mut payload = rtp(4, true, &[0x26, 1, 1]);
        payload[offset] ^= 1;
        let wire = interleaved(0, &payload);
        let (error, _, source) = fault(feed(&mut client, &wire, 20)?)?;
        assert!(matches!(
            error,
            E::Metadata(OnvifMetadataReceiveError::Transport(_))
        ));
        assert_eq!(source.ok_or("rejected RTP lost")?.expose_wire(), wire);
        assert_eq!(client.next_wake_ns(), None);
    }
    Ok(())
}

#[test]
fn compound_and_reduced_rtcp_are_negotiated_not_inferred_from_invalid_input() -> TestResult {
    let rr = vec![0x80, 201, 0, 1, 0, 0, 0, 7];
    for reduced in [false, true] {
        let mut client = playing(
            ReorderLimits::default(),
            OnvifMetadataLimits::default(),
            reduced,
        )?;
        let wire = interleaved(1, &rr);
        let events = feed(&mut client, &wire, 6)?;
        let P::Rtcp { source, validation } = &events[0] else {
            return Err("missing RTCP result".into());
        };
        assert_eq!(source.expose_wire(), wire);
        assert_eq!(validation.is_ok(), reduced);
        assert_eq!(client.state(), ClientState::Playing);
    }
    let cname = [0x81, 202, 0, 2, 0, 0, 0, 7, 1, 1, b'x', 0];
    let compound = [rr.as_slice(), cname.as_slice()].concat();
    let mut client = playing(
        ReorderLimits::default(),
        OnvifMetadataLimits::default(),
        false,
    )?;
    assert!(matches!(
        &feed(&mut client, &interleaved(1, &compound), 6)?[0],
        P::Rtcp {
            validation: Ok(2),
            ..
        }
    ));
    let damaged = [compound.as_slice(), &[0x80, 201, 0]].concat();
    assert!(matches!(
        &feed(&mut client, &interleaved(1, &damaged), 7)?[0],
        P::Rtcp {
            validation: Err(_),
            ..
        }
    ));
    assert_eq!(client.state(), ClientState::Playing);
    Ok(())
}

#[test]
fn delayed_media_poll_keeps_original_intake_time_through_metadata_reconstruction() -> TestResult {
    let mut client = primed(ReorderLimits::default(), OnvifMetadataLimits::default())?;
    let original = rtp(4, true, &[0x26, 1, 4]);
    let wire = interleaved(0, &original);
    client.ingest(&wire, 20)?;
    let events = drain(&mut client, 100)?;
    let arrivals = events
        .iter()
        .filter_map(|event| match event {
            P::Rtp { source, .. } => Some(source),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(arrivals.len(), 1);
    assert_eq!(arrivals[0].expose_wire(), wire);
    assert_eq!(arrivals[0].received_ns(), 20);
    let originals = events
        .iter()
        .filter_map(|event| match event {
            P::Metadata(OnvifMetadataReceivePoll::Packet { source, .. }) => Some(source),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(originals.len(), 1);
    assert_eq!(originals[0].bytes(), original);
    assert_eq!(originals[0].received_ns(), 20);
    assert_eq!(documents(&events), vec![vec![0x26, 1, 4]]);
    assert!(matches!(
        client.poll(99),
        Err(E::Session(ClientError::ClockReversed))
    ));
    Ok(())
}

#[test]
fn held_retry_cannot_outlive_its_original_wire_residence_deadline() -> TestResult {
    let reorder = ReorderLimits {
        max_packets: 1,
        max_delay_ns: 60_000_000_000,
        ..ReorderLimits::default()
    };
    let mut client = primed(reorder, OnvifMetadataLimits::default())?;
    feed(&mut client, &packet(5, true, &[0x26, 1, 5]), 20)?;
    let waiting = packet(6, true, &[0x26, 1, 6]);
    feed(&mut client, &waiting, 21)?;
    assert_eq!(client.next_wake_ns(), Some(WIRE_LIFETIME_NS + 21));
    let (error, retired, source) = fault(drain(&mut client, WIRE_LIFETIME_NS + 21)?)?;
    assert_eq!(error, E::Wire(WireIntakeError::Deadline));
    assert!(source.is_none());
    assert_eq!(
        retired.retry.ok_or("held frame disappeared")?.expose_wire(),
        waiting
    );
    assert_eq!(
        retired
            .metadata
            .ok_or("RTP retirement missing")?
            .queue
            .packets,
        1
    );
    assert!(retired.wire.is_empty());
    Ok(())
}

#[test]
fn impossible_single_datagram_budget_refuses_instead_of_waiting_forever() -> TestResult {
    let reorder = ReorderLimits {
        max_bytes: 15,
        ..ReorderLimits::default()
    };
    let mut client = primed(reorder, OnvifMetadataLimits::default())?;
    let oversized = packet(4, true, &[0x26, 1, 1, 2]);
    let (error, _, source) = fault(feed(&mut client, &oversized, 20)?)?;
    assert_eq!(error, E::InputLimit);
    assert_eq!(
        source.ok_or("oversized datagram lost")?.expose_wire(),
        oversized
    );
    assert_eq!(client.next_wake_ns(), None);
    Ok(())
}

#[test]
fn blocked_partial_wire_waits_for_hard_expiry_not_a_busy_keepalive_loop() -> TestResult {
    let mut client = RtspMetadataClient::new(
        config(),
        KEY,
        107,
        ReorderLimits::default(),
        OnvifMetadataLimits::default(),
    )?;
    ready(&mut client, false, "private-session;timeout=2")?;
    client.request(C::Play, 4)?;
    feed(
        &mut client,
        &response(3, 200, &[("Session", "private-session")], &[]),
        5,
    )?;
    feed(&mut client, b"$\0", 20)?;
    assert_eq!(client.next_wake_ns(), Some(2_000_000_004));
    assert!(matches!(
        client.poll(1_000_000_004)?,
        P::Pending {
            wake_at_ns: Some(2_000_000_004)
        }
    ));
    let (error, retired, _) = fault(drain(&mut client, 2_000_000_004)?)?;
    assert_eq!(error, E::Session(ClientError::SessionExpired));
    assert_eq!(retired.wire.expose(), b"$\0");
    assert!(retired.session.remote_session_may_exist);
    Ok(())
}

#[test]
fn late_final_byte_cannot_erase_partial_frame_expiry() -> TestResult {
    let mut client = primed(ReorderLimits::default(), OnvifMetadataLimits::default())?;
    let wire = packet(4, true, &[0x26, 1, 9]);
    feed(&mut client, &wire[..wire.len() - 1], 20)?;
    let failure = client
        .ingest(&wire[wire.len() - 1..], WIRE_LIFETIME_NS + 20)
        .err()
        .ok_or("expired partial frame accepted")?;
    assert_eq!(failure.reason, E::Wire(WireIntakeError::Deadline));
    assert_eq!(
        failure
            .retirement
            .ok_or("missing retirement")?
            .wire
            .expose(),
        &wire[..wire.len() - 1]
    );
    assert_eq!(client.state(), ClientState::Closed);
    Ok(())
}

#[test]
fn malformed_suffix_keeps_preceding_valid_packet_and_exact_unprocessed_suffix() -> TestResult {
    let mut client = primed(ReorderLimits::default(), OnvifMetadataLimits::default())?;
    let prefix = packet(4, true, &[0x26, 1, 9]);
    let suffix = b"INVALID\n";
    let combined = [prefix.as_slice(), suffix].concat();
    let events = feed(&mut client, &combined, 20)?;
    assert!(matches!(&events[0], P::Rtp { source, .. } if source.expose_wire() == prefix));
    assert_eq!(documents(&events), vec![vec![0x26, 1, 9]]);
    let (error, retired, source) = fault(events)?;
    assert_eq!(error, E::Wire(WireIntakeError::Framing));
    assert_eq!(retired.wire.expose(), suffix);
    assert!(source.is_none());
    Ok(())
}

#[test]
fn digest_authentication_reuses_shared_session_and_returns_consumed_raw_challenge() -> TestResult {
    let mut client = authenticated(OnvifMetadataLimits::default())?;
    let events = feed(&mut client, &packet(4, true, &[0x26, 1, 7]), 20)?;
    assert_eq!(documents(&events), vec![vec![0x26, 1, 7]]);
    let plain = client
        .request(C::KeepAlive, 21)
        .err()
        .ok_or("Digest bypass was permitted")?;
    assert!(matches!(
        plain.reason,
        E::Session(ClientError::Authentication(_))
    ));
    assert!(plain.retirement.is_none());
    let credentials = DigestCredentials::new("private-user", "private-password")?;
    let request = client.request_digest(C::Teardown, &credentials, [5; 16], 22)?;
    assert_eq!(request.cseq(), 5);
    assert!(std::str::from_utf8(request.bytes())?.contains("Authorization: Digest "));
    let debug = format!("{client:?} {request:?} {events:?}");
    for secret in [
        "private-user",
        "private-password",
        "private-nonce",
        "private-session",
        "camera.local",
    ] {
        assert!(!debug.contains(secret));
    }
    Ok(())
}

#[test]
fn unsupported_or_unsolicited_challenges_are_not_presented_as_credential_requests() -> TestResult {
    for wire in [
        challenge(9),
        response(
            1,
            401,
            &[("WWW-Authenticate", "Basic realm=\"owner-realm\"")],
            &[],
        ),
        response(
            1,
            407,
            &[("Proxy-Authenticate", "Digest realm=\"owner-realm\"")],
            &[],
        ),
    ] {
        let mut client = RtspMetadataClient::with_digest(
            config(),
            KEY,
            107,
            ReorderLimits::default(),
            OnvifMetadataLimits::default(),
            "owner-realm",
            DigestPolicy::default(),
        )?;
        let credentials = DigestCredentials::new("private-user", "private-password")?;
        client.request_digest(C::Describe, &credentials, [1; 16], 0)?;
        let (error, retired, source) = fault(feed(&mut client, &wire, 1)?)?;
        assert!(matches!(
            error,
            E::Session(ClientError::CseqMismatch) | E::Authentication(_)
        ));
        assert!(source.is_none());
        assert_eq!(
            retired
                .challenge
                .ok_or("challenge evidence disappeared")?
                .expose_wire(),
            wire
        );
        assert_eq!(client.state(), ClientState::Closed);
    }
    Ok(())
}

#[test]
fn fragmented_metadata_reorders_across_timestamp_changes_with_exact_source_spans() -> TestResult {
    let mut client = primed(ReorderLimits::default(), OnvifMetadataLimits::default())?;
    let start = packet(4, false, b"<metadata>");
    let middle = packet(5, false, b"untrusted vendor observation");
    let mut tail_rtp = rtp(6, true, b"</metadata>");
    tail_rtp[4..8].copy_from_slice(&180_000_u32.to_be_bytes());
    let end = interleaved(0, &tail_rtp);
    let mut events = feed(&mut client, &start, 20)?;
    events.extend(feed(&mut client, &end, 21)?);
    events.extend(feed(&mut client, &middle, 22)?);
    assert_eq!(
        documents(&events),
        vec![b"<metadata>untrusted vendor observation</metadata>".to_vec()]
    );
    let originals = events
        .iter()
        .filter_map(|event| match event {
            P::Rtp { source, .. } => Some(source.expose_wire().to_vec()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(originals, vec![start.clone(), end.clone(), middle.clone()]);
    let document = events
        .iter()
        .find_map(|event| match event {
            P::Metadata(OnvifMetadataReceivePoll::Packet {
                reconstruction: Ok(result),
                ..
            }) => result.document.as_ref(),
            _ => None,
        })
        .ok_or("complete metadata missing")?;
    assert_eq!(document.key(), KEY);
    assert_eq!(document.boundary().sequence, 3);
    assert_eq!(document.first_sequence(), 4);
    assert_eq!(document.last_sequence(), 6);
    for (index, wire) in [&start, &middle, &end].into_iter().enumerate() {
        let span = &document.sources()[index];
        assert_eq!(span.sequence, index as u64 + 4);
        assert_eq!(
            &wire[4 + span.wire_range.start..4 + span.wire_range.end],
            &document.bytes()[span.document_range.clone()]
        );
    }
    assert_eq!(document.sources()[1].received_ns, 22);
    assert_eq!(document.sources()[2].received_ns, 21);
    assert_eq!(document.sources()[2].timestamp, 180_000);
    assert_eq!(client.retained_document_bytes(), 0);
    assert_eq!(client.queued_rtp_bytes(), 0);
    Ok(())
}

#[test]
fn arbitrary_tcp_fragmentation_cannot_change_document_or_packet_receipt_time() -> TestResult {
    let source = packet(4, true, b"<metadata>bounded</metadata>");
    for split in 1..source.len() {
        let mut client = primed(ReorderLimits::default(), OnvifMetadataLimits::default())?;
        let first = feed(&mut client, &source[..split], 20)?;
        assert!(documents(&first).is_empty());
        let events = feed(&mut client, &source[split..], 21)?;
        assert_eq!(
            documents(&events),
            vec![b"<metadata>bounded</metadata>".to_vec()]
        );
        assert!(events.iter().any(|event| matches!(event,
            P::Metadata(OnvifMetadataReceivePoll::Packet { source, .. })
            if source.received_ns() == 21)));
    }
    Ok(())
}

#[test]
fn unknown_initial_document_is_discarded_until_a_received_marker() -> TestResult {
    let mut client = playing(
        ReorderLimits::default(),
        OnvifMetadataLimits::default(),
        false,
    )?;
    let mut events = Vec::new();
    for (seq, marker, payload) in [
        (0, false, b"unknown".as_slice()),
        (1, false, b"partial".as_slice()),
        (2, true, b"</metadata>".as_slice()),
    ] {
        events.extend(feed(
            &mut client,
            &packet(seq, marker, payload),
            10 + u64::from(seq),
        )?);
    }
    assert!(documents(&events).is_empty());
    assert!(events.iter().any(|event| matches!(event,
        P::Rtp { admission, .. } if admission.transport.disposition == ReorderDisposition::NotAdmitted)));
    let next = feed(&mut client, &packet(3, true, b"<complete/>"), 13)?;
    assert_eq!(documents(&next), vec![b"<complete/>".to_vec()]);
    Ok(())
}

#[test]
fn delivery_gap_and_late_recovery_require_a_new_marker_boundary() -> TestResult {
    let reorder = ReorderLimits {
        max_delay_ns: 10,
        ..ReorderLimits::default()
    };
    let mut client = primed(reorder, OnvifMetadataLimits::default())?;
    feed(&mut client, &packet(4, false, b"<incomplete>"), 20)?;
    feed(&mut client, &packet(6, true, b"</incomplete>"), 21)?;
    assert_eq!(client.next_wake_ns(), Some(31));
    let events = drain(&mut client, 31)?;
    assert!(
        matches!(&events[0], P::Metadata(OnvifMetadataReceivePoll::Gap { gap, discarded: Some(discard) })
        if gap.first_sequence == 5 && gap.last_sequence == 5 && discard.reason == OnvifMetadataDiscardReason::Gap)
    );
    assert!(documents(&events).is_empty());
    let late = feed(&mut client, &packet(5, false, b"missing"), 32)?;
    assert!(
        matches!(&late[0], P::Rtp { admission, .. } if admission.transport.disposition == ReorderDisposition::TooLate)
    );
    assert!(documents(&late).is_empty());
    assert_eq!(
        documents(&feed(&mut client, &packet(7, true, b"<next/>"), 33)?),
        vec![b"<next/>".to_vec()]
    );
    Ok(())
}

#[test]
fn document_expiry_runs_before_new_wire_and_requires_resynchronization() -> TestResult {
    let limits = OnvifMetadataLimits {
        max_pending_age_ns: 10,
        ..OnvifMetadataLimits::default()
    };
    let mut client = primed(ReorderLimits::default(), limits)?;
    feed(&mut client, &packet(4, false, b"<expired>"), 20)?;
    assert_eq!(client.next_wake_ns(), Some(30));
    let boundary = packet(5, true, b"</expired>");
    client.ingest(&boundary, 30)?;
    assert!(
        matches!(client.poll(30)?, P::Metadata(OnvifMetadataReceivePoll::DocumentDiscarded(discard))
        if discard.reason == OnvifMetadataDiscardReason::Deadline && discard.first_sequence == 4)
    );
    assert_eq!(client.buffered_wire_bytes(), boundary.len());
    assert!(documents(&drain(&mut client, 30)?).is_empty());
    assert_eq!(
        documents(&feed(&mut client, &packet(6, true, b"<next/>"), 31)?),
        vec![b"<next/>".to_vec()]
    );
    Ok(())
}

#[test]
fn full_reorder_queue_retains_exact_retry_without_duplicate_admission() -> TestResult {
    let reorder = ReorderLimits {
        max_packets: 1,
        max_delay_ns: 10,
        ..ReorderLimits::default()
    };
    let mut client = primed(reorder, OnvifMetadataLimits::default())?;
    feed(&mut client, &packet(5, true, b"unknown tail"), 20)?;
    let waiting = packet(6, true, b"<next/>");
    assert!(matches!(
        feed(&mut client, &waiting, 21)?.last(),
        Some(P::Backpressure {
            wake_at_ns: Some(30)
        })
    ));
    assert_eq!(client.buffered_wire_bytes(), waiting.len());
    let refused = client
        .ingest(&packet(7, true, b"<later/>"), 22)
        .err()
        .ok_or("ignored backpressure")?;
    assert_eq!(refused.reason, E::Backpressure);
    assert!(refused.retirement.is_none());
    let events = drain(&mut client, 30)?;
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, P::Rtp { .. }))
            .count(),
        1
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, P::Rtp { source, admission, .. }
        if source.expose_wire() == waiting && source.received_ns() == 21
           && admission.transport.disposition == ReorderDisposition::Buffered))
    );
    assert_eq!(documents(&events), vec![b"<next/>".to_vec()]);
    assert_eq!(client.buffered_wire_bytes(), 0);
    Ok(())
}

#[test]
fn malformed_rtp_or_conflicting_queued_duplicate_retires_document_and_source() -> TestResult {
    for conflict in [false, true] {
        let mut client = primed(ReorderLimits::default(), OnvifMetadataLimits::default())?;
        feed(&mut client, &packet(4, false, b"<pending>"), 20)?;
        let rejected = if conflict {
            feed(&mut client, &packet(6, true, b"original"), 21)?;
            packet(6, true, b"different")
        } else {
            interleaved(0, b"invalid RTP")
        };
        let (error, retired, source) = fault(feed(&mut client, &rejected, 22)?)?;
        let E::Metadata(OnvifMetadataReceiveError::Invalidated {
            retired: receiver, ..
        }) = error
        else {
            return Err("wire ambiguity did not invalidate metadata".into());
        };
        assert_eq!(
            receiver
                .document
                .ok_or("lost incomplete document retirement")?
                .reason,
            if conflict {
                OnvifMetadataDiscardReason::ConflictingPacket
            } else {
                OnvifMetadataDiscardReason::InvalidPacket
            }
        );
        assert_eq!(
            source.ok_or("lost invalid datagram")?.expose_wire(),
            rejected
        );
        assert!(retired.session.remote_session_may_exist);
        assert_eq!(client.state(), ClientState::Closed);
    }
    Ok(())
}

#[test]
fn cancellation_accounts_for_partial_tcp_queued_rtp_and_document_once() -> TestResult {
    let mut client = primed(ReorderLimits::default(), OnvifMetadataLimits::default())?;
    feed(&mut client, &packet(4, false, b"<pending>"), 20)?;
    feed(&mut client, &packet(6, true, b"</pending>"), 21)?;
    feed(&mut client, b"$\0", 22)?;
    let retired = client.cancel();
    let metadata = retired.metadata.ok_or("missing metadata retirement")?;
    assert_eq!(metadata.queue.packets, 1);
    assert_eq!(
        metadata
            .document
            .ok_or("missing document retirement")?
            .reason,
        OnvifMetadataDiscardReason::Cancelled
    );
    assert_eq!(retired.wire.expose(), b"$\0");
    assert!(retired.session.remote_session_may_exist);
    assert_eq!(client.queued_rtp_bytes(), 0);
    assert_eq!(client.retained_document_bytes(), 0);
    assert_eq!(client.buffered_wire_bytes(), 0);
    assert_eq!(client.next_wake_ns(), None);
    let repeated = client.cancel();
    assert!(repeated.metadata.is_none());
    assert!(repeated.wire.is_empty());
    assert!(matches!(
        client.poll(22)?,
        P::Ended {
            retirement: None,
            ..
        }
    ));
    Ok(())
}

#[test]
fn confirmed_source_restart_closes_generation_without_publishing_a_document() -> TestResult {
    let mut client = primed(ReorderLimits::default(), OnvifMetadataLimits::default())?;
    feed(&mut client, &packet(4, false, b"<pending>"), 20)?;
    feed(&mut client, &packet(6, true, b"</pending>"), 21)?;
    feed(&mut client, &packet(40_000, true, b"restart"), 22)?;
    let events = feed(&mut client, &packet(40_001, true, b"restart confirmed"), 23)?;
    let P::Rtp {
        admission,
        retirement: Some(retired),
        ..
    } = &events[0]
    else {
        return Err("confirmed restart did not close generation".into());
    };
    assert_eq!(
        admission.transport.disposition,
        ReorderDisposition::RestartRequired
    );
    assert_eq!(
        admission
            .transport
            .discarded
            .ok_or("missing queue retirement")?
            .packets,
        1
    );
    assert_eq!(
        admission
            .discarded
            .as_ref()
            .ok_or("missing document retirement")?
            .reason,
        OnvifMetadataDiscardReason::RestartRequired
    );
    assert!(documents(&events).is_empty());
    assert!(retired.session.remote_session_may_exist);
    assert_eq!(client.state(), ClientState::Closed);
    Ok(())
}

#[test]
fn eof_keeps_complete_documents_and_classifies_each_incomplete_layer() -> TestResult {
    for truncated in [false, true] {
        let mut client = primed(ReorderLimits::default(), OnvifMetadataLimits::default())?;
        let mut wire = [packet(4, false, b"<whole>"), packet(5, true, b"</whole>")].concat();
        if truncated {
            wire.push(b'$');
        }
        client.ingest(&wire, 20)?;
        client.finish();
        let mut events = drain(&mut client, 20)?;
        if matches!(
            events.last(),
            Some(P::Pending {
                wake_at_ns: Some(20)
            })
        ) {
            events.extend(drain(&mut client, 20)?);
        }
        assert_eq!(documents(&events), vec![b"<whole></whole>".to_vec()]);
        if truncated {
            let (error, retired, _) = fault(events)?;
            assert_eq!(error, E::Wire(WireIntakeError::Truncated));
            assert_eq!(retired.wire.expose(), b"$");
        } else {
            assert!(matches!(
                events.last(),
                Some(P::Ended {
                    media: Some(OnvifMetadataReceivePoll::Ended { discarded: None }),
                    retirement: Some(_)
                })
            ));
        }
        assert!(matches!(
            client.poll(21)?,
            P::Ended {
                media: None,
                retirement: None
            }
        ));
    }
    let mut client = primed(ReorderLimits::default(), OnvifMetadataLimits::default())?;
    feed(&mut client, &packet(4, false, b"<pending>"), 20)?;
    client.finish();
    drain(&mut client, 20)?;
    assert!(matches!(client.poll(20)?, P::Ended {
        media: Some(OnvifMetadataReceivePoll::Ended { discarded: Some(discard) }), retirement: Some(_)
    } if discard.reason == OnvifMetadataDiscardReason::EndOfInput && discard.byte_len == 9));
    Ok(())
}

#[test]
fn teardown_ack_retains_late_wire_and_cannot_finish_an_unclosed_document() -> TestResult {
    let mut client = primed(ReorderLimits::default(), OnvifMetadataLimits::default())?;
    feed(&mut client, &packet(4, false, b"<pending>"), 20)?;
    client.request(C::Teardown, 21)?;
    let ack = response(4, 200, &[("Session", "private-session")], &[]);
    let after = packet(5, true, b"</pending>");
    client.ingest(&[ack.as_slice(), after.as_slice()].concat(), 22)?;
    assert!(matches!(
        client.poll(22)?,
        P::Control {
            progress: ClientProgress::Accepted(ClientState::Closed),
            ..
        }
    ));
    let P::Ended {
        media:
            Some(OnvifMetadataReceivePoll::Ended {
                discarded: Some(discard),
            }),
        retirement: Some(retired),
    } = client.poll(22)?
    else {
        return Err("teardown did not retire incomplete document".into());
    };
    assert_eq!(discard.reason, OnvifMetadataDiscardReason::EndOfInput);
    assert_eq!(retired.wire.expose(), after);
    assert!(!retired.session.remote_session_may_exist);
    assert!(client.ingest(&after, 23).is_err());
    Ok(())
}
