#![forbid(unsafe_code)]
//! Real encoded fixture bytes cross the existing RTSP, RTP, NAL, and picture owners.

use fss_packet::avc::{AvcAssemblyStep, AvcBoundary, AvcReceiveLimits, AvcReceivePoll};
use fss_packet::{ReorderDisposition, StreamKey};
use fss_reference::rtsp::avc_client::{AvcClientError as E, AvcClientPoll as P, RtspAvcClient};
use fss_reference::rtsp::client::{
    ClientCommand as C, ClientConfig, ClientError, ClientProgress, ClientState,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey {
    ingress: 71,
    generation: 1,
    ssrc: 7,
};
const BASELINE: &[u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
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
fn description(reduced: bool) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\na=control:trackID=0\r\n{}",
        if reduced { "a=rtcp-rsize\r\n" } else { "" }
    )
}
fn response(seq: u32, extra: &str, body: &str) -> Vec<u8> {
    format!(
        "RTSP/1.0 200 OK\r\nCSeq: {seq}\r\nContent-Length: {}\r\n{extra}\r\n{body}",
        body.len()
    )
    .into_bytes()
}
fn ready(
    limits: AvcReceiveLimits,
    reduced: bool,
) -> Result<RtspAvcClient, Box<dyn std::error::Error>> {
    let mut c = RtspAvcClient::new(config(), KEY, limits)?;
    c.request(C::Describe, 0)?;
    c.ingest(
        &response(
            1,
            "Content-Type: application/sdp\r\n",
            &description(reduced),
        ),
        1,
    )?;
    assert!(matches!(
        c.poll(1)?,
        P::Control(ClientProgress::Accepted(ClientState::Described))
    ));
    c.request(C::Setup, 2)?;
    c.ingest(&response(2, "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""), 3)?;
    assert!(matches!(
        c.poll(3)?,
        P::Control(ClientProgress::Accepted(ClientState::Ready))
    ));
    Ok(c)
}
fn playing(
    limits: AvcReceiveLimits,
    reduced: bool,
) -> Result<RtspAvcClient, Box<dyn std::error::Error>> {
    let mut c = ready(limits, reduced)?;
    c.request(C::Play, 4)?;
    c.ingest(&response(3, "Session: fixture\r\n", ""), 5)?;
    assert!(matches!(
        c.poll(5)?,
        P::Control(ClientProgress::Accepted(ClientState::Playing))
    ));
    Ok(c)
}
fn packet(seq: u16, timestamp: u32, nal: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80, 96];
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&KEY.ssrc.to_be_bytes());
    out.extend_from_slice(nal);
    out
}
fn interleaved(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![b'$', channel];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
// Only fixture framing; production code uses negotiated RTP packets and exact source maps.
fn nals(bytes: &[u8]) -> Vec<&[u8]> {
    let mut output = Vec::new();
    let mut start = None;
    let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) {
            4
        } else if bytes[at..at + 3] == [0, 0, 1] {
            3
        } else {
            0
        };
        if prefix == 0 {
            at += 1;
            continue;
        }
        if let Some(begin) = start {
            let mut end = at;
            while end > begin && bytes[end - 1] == 0 {
                end -= 1;
            }
            if begin < end {
                output.push(&bytes[begin..end]);
            }
        }
        start = Some(at + prefix);
        at += prefix;
    }
    if let Some(begin) = start
        && begin < bytes.len()
    {
        output.push(&bytes[begin..]);
    }
    output
}
fn drain(c: &mut RtspAvcClient, now: u64, output: &mut Vec<P>) -> TestResult {
    for _ in 0..2_048 {
        let event = c.poll(now)?;
        match &event {
            P::Pending { wake_at_ns } if wake_at_ns.is_none_or(|at| at > now) => return Ok(()),
            P::Backpressure { .. } | P::Control(ClientProgress::KeepAliveDue) => {
                output.push(event);
                return Ok(());
            }
            P::Ended { .. } => {
                output.push(event);
                return Ok(());
            }
            P::Fault { .. } => return Err(format!("unexpected pump failure: {event:?}").into()),
            _ => output.push(event),
        }
    }
    Err("pump did not yield within its fixture budget".into())
}
fn send(c: &mut RtspAvcClient, wire: &[u8], now: u64, out: &mut Vec<P>) -> TestResult {
    c.ingest(wire, now)?;
    drain(c, now, out)
}

#[test]
fn tcp_chunking_preserves_real_source_bytes_and_all_four_picture_groups() -> TestResult {
    let nals = nals(BASELINE);
    for chunk_size in [1, 2, 3, 7, 127, 4_096] {
        let mut c = playing(AvcReceiveLimits::default(), false)?;
        let mut received = Vec::new();
        let mut wire = Vec::new();
        let mut original = Vec::new();
        original.push(packet(0, 90_000, nals[0]));
        let mut frame = 0;
        for (index, nal) in nals.iter().enumerate() {
            original.push(packet(index as u16 + 1, 90_000 + frame * 3_600, nal));
            if matches!(nal[0] & 31, 1 | 5) {
                frame += 1;
            }
        }
        for p in &original {
            wire.extend_from_slice(&interleaved(0, p));
        }
        for chunk in wire.chunks(chunk_size) {
            send(&mut c, chunk, 6, &mut received)?;
        }
        c.finish();
        drain(&mut c, 7, &mut received)?;
        let sources: Vec<&[u8]> = received
            .iter()
            .filter_map(|e| match e {
                P::Rtp {
                    source,
                    retirement: None,
                    ..
                } => Some(source.payload()),
                _ => None,
            })
            .collect();
        assert_eq!(
            sources,
            original.iter().map(Vec::as_slice).collect::<Vec<_>>()
        );
        let mut pictures = 0;
        for event in &received {
            match event {
                P::Media(AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(out))) => {
                    pictures += usize::from(out.picture.is_some())
                }
                P::Media(AvcReceivePoll::Picture(_)) => pictures += 1,
                P::Ended {
                    media:
                        Some(AvcReceivePoll::Ended {
                            tail: Some(tail), ..
                        }),
                    retirement: Some(retired),
                } => {
                    let picture = tail.picture.as_ref().ok_or("missing explicit EOF tail")?;
                    assert_eq!(picture.boundary(), AvcBoundary::EndOfInputUnverified);
                    assert!(retired.session.remote_session_may_exist);
                    pictures += 1;
                }
                P::Media(AvcReceivePoll::Assembly(AvcAssemblyStep::Refused(_))) => {
                    return Err("clean NAL refused".into());
                }
                _ => {}
            }
        }
        assert_eq!(pictures, 4);
        assert_eq!(c.retained_nal_bytes(), 0);
        assert_eq!(c.buffered_wire_bytes(), 0);
    }
    Ok(())
}

#[test]
fn media_before_play_and_unknown_channels_return_original_bytes() -> TestResult {
    for early in [true, false] {
        let mut c = if early {
            ready(AvcReceiveLimits::default(), false)?
        } else {
            playing(AvcReceiveLimits::default(), false)?
        };
        let raw = packet(1, 90_000, &[0x67, 1]);
        c.ingest(&interleaved(if early { 0 } else { 17 }, &raw), 6)?;
        let P::Fault {
            reason: E::Session(ClientError::MediaNotAdmitted),
            source: Some(source),
            retirement,
        } = c.poll(6)?
        else {
            return Err("unnegotiated media was not fenced".into());
        };
        assert_eq!(source.payload(), raw);
        assert!(retirement.session.remote_session_may_exist);
        assert_eq!(c.state(), ClientState::Closed);
    }
    Ok(())
}

#[test]
fn server_ssrc_must_match_owner_binding_before_play() -> TestResult {
    let mut c = RtspAvcClient::new(config(), KEY, AvcReceiveLimits::default())?;
    c.request(C::Describe, 0)?;
    c.ingest(
        &response(1, "Content-Type: application/sdp\r\n", &description(false)),
        1,
    )?;
    c.poll(1)?;
    c.request(C::Setup, 2)?;
    c.ingest(
        &response(
            2,
            "Session: fixture\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=8\r\n",
            "",
        ),
        3,
    )?;
    assert!(matches!(
        c.poll(3)?,
        P::Fault {
            reason: E::StreamBinding,
            ..
        }
    ));
    assert!(c.request(C::Play, 4).is_err());
    Ok(())
}

#[test]
fn sdp_parameter_bytes_reach_real_syntax_validation() -> TestResult {
    let mut c = RtspAvcClient::new(config(), KEY, AvcReceiveLimits::default())?;
    c.request(C::Describe, 0)?;
    let body = description(false).replace("Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=", "ZwAAAA==");
    c.ingest(&response(1, "Content-Type: application/sdp\r\n", &body), 1)?;
    c.poll(1)?;
    c.request(C::Setup, 2)?;
    c.ingest(
        &response(
            2,
            "Session: fixture\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n",
            "",
        ),
        3,
    )?;
    assert!(matches!(
        c.poll(3)?,
        P::Fault {
            reason: E::Syntax(_),
            ..
        }
    ));
    Ok(())
}

#[test]
fn rtcp_reduced_size_is_negotiated_and_bad_suffix_preserves_source() -> TestResult {
    for reduced in [false, true] {
        let mut c = playing(AvcReceiveLimits::default(), reduced)?;
        let rr = [0x80, 201, 0, 1, 0, 0, 0, 7];
        c.ingest(&interleaved(1, &rr), 6)?;
        let P::Rtcp { source, validation } = c.poll(6)? else {
            return Err("RTCP event missing".into());
        };
        assert_eq!(source.payload(), rr);
        assert_eq!(validation.is_ok(), reduced);
        let mut compound = rr.to_vec();
        compound.extend_from_slice(&[0x81, 202, 0, 3, 0, 0, 0, 7, 1, 3, b'f', b's', b's', 0, 0, 0]);
        c.ingest(&interleaved(1, &compound), 7)?;
        assert!(matches!(
            c.poll(7)?,
            P::Rtcp {
                validation: Ok(2),
                ..
            }
        ));
        compound.push(0);
        c.ingest(&interleaved(1, &compound), 8)?;
        let P::Rtcp {
            source,
            validation: Err(_),
        } = c.poll(8)?
        else {
            return Err("malformed RTCP accepted".into());
        };
        assert_eq!(source.payload(), compound);
        assert_eq!(c.state(), ClientState::Playing);
    }
    Ok(())
}

#[test]
fn eof_inside_framing_retires_partial_input_without_fabricating_a_tail() -> TestResult {
    let mut c = playing(AvcReceiveLimits::default(), false)?;
    c.ingest(&[b'$', 0, 0, 10, 0x80], 6)?;
    c.finish();
    let P::Fault {
        reason: E::Truncated,
        retirement,
        ..
    } = c.poll(6)?
    else {
        return Err("truncated EOF accepted".into());
    };
    assert_eq!(retirement.partial_wire_bytes, 5);
    assert_eq!(c.buffered_wire_bytes(), 0);
    Ok(())
}

#[test]
fn slow_partial_frame_and_session_deadlines_fire_without_more_input() -> TestResult {
    let mut c = playing(AvcReceiveLimits::default(), false)?;
    c.ingest(b"$", 6)?;
    assert_eq!(c.next_wake_ns(), Some(5_000_000_006));
    assert!(matches!(
        c.poll(5_000_000_006)?,
        P::Fault {
            reason: E::PartialTimeout,
            ..
        }
    ));
    let mut c = playing(AvcReceiveLimits::default(), false)?;
    assert!(matches!(
        c.poll(60_000_000_004)?,
        P::Fault {
            reason: E::Session(ClientError::SessionExpired),
            ..
        }
    ));
    Ok(())
}

#[test]
fn input_budget_and_event_backpressure_refuse_before_consumption() -> TestResult {
    let mut c = playing(AvcReceiveLimits::default(), false)?;
    assert_eq!(
        c.ingest(&vec![0; 4_097], 6)
            .err()
            .ok_or("oversize accepted")?
            .reason,
        E::InputLimit
    );
    let frame = interleaved(1, &[0x80, 201, 0, 1, 0, 0, 0, 7]);
    c.ingest(&frame, 6)?;
    assert_eq!(
        c.ingest(&frame, 6)
            .err()
            .ok_or("queued event overwritten")?
            .reason,
        E::Backpressure
    );
    assert!(matches!(c.poll(6)?, P::Rtcp { .. }));
    c.ingest(&frame, 6)?;
    assert!(matches!(c.poll(6)?, P::Rtcp { .. }));
    Ok(())
}

#[test]
fn queue_pressure_retains_one_retry_and_late_delivery_is_explicit() -> TestResult {
    let mut limits = AvcReceiveLimits::default();
    limits.reorder.max_packets = 1;
    limits.reorder.max_delay_ns = 10;
    let mut c = playing(limits, false)?;
    let mut output = Vec::new();
    for seq in [0, 1, 3] {
        send(
            &mut c,
            &interleaved(0, &packet(seq, 90_000, nals(BASELINE)[0])),
            6,
            &mut output,
        )?;
    }
    let missing = interleaved(0, &packet(2, 90_000, nals(BASELINE)[0]));
    send(&mut c, &missing, 7, &mut output)?;
    assert!(matches!(output.last(), Some(P::Backpressure { .. })));
    assert_eq!(
        c.ingest(&missing, 7)
            .err()
            .ok_or("retry overwritten")?
            .reason,
        E::Backpressure
    );
    drain(&mut c, 16, &mut output)?;
    assert!(output.iter().any(|e| matches!(e, P::Rtp { admission, .. }
        if admission.transport.transport.disposition == ReorderDisposition::TooLate)));
    assert!(
        output
            .iter()
            .any(|e| matches!(e, P::Media(AvcReceivePoll::Gap { .. })))
    );
    Ok(())
}

#[test]
fn confirmed_sequence_restart_closes_the_old_connection() -> TestResult {
    let mut c = playing(AvcReceiveLimits::default(), false)?;
    let mut output = Vec::new();
    for seq in [0, 1, 30_000, 30_001] {
        send(
            &mut c,
            &interleaved(0, &packet(seq, 90_000, nals(BASELINE)[0])),
            6,
            &mut output,
        )?;
    }
    assert!(output.iter().any(
        |e| matches!(e, P::Rtp { retirement: Some(_), admission, .. }
        if admission.transport.transport.disposition == ReorderDisposition::RestartRequired)
    ));
    assert_eq!(c.state(), ClientState::Closed);
    assert_eq!(c.retained_nal_bytes(), 0);
    Ok(())
}

#[test]
fn valid_prefix_cannot_hide_a_deferred_wire_error() -> TestResult {
    let mut c = RtspAvcClient::new(config(), KEY, AvcReceiveLimits::default())?;
    c.request(C::Options, 0)?;
    let mut wire = response(1, "", "");
    wire.extend_from_slice(b"RTSP/1.0 200 OK\r\n\r\n");
    c.ingest(&wire, 1)?;
    assert!(matches!(c.poll(1)?, P::Control(_)));
    assert!(matches!(
        c.poll(1)?,
        P::Fault {
            reason: E::Wire(_),
            ..
        }
    ));
    Ok(())
}

#[test]
fn cancellation_accounts_for_queued_media_and_redacts_debug() -> TestResult {
    let mut c = playing(AvcReceiveLimits::default(), false)?;
    let payload = b"private-video-secret";
    c.ingest(&interleaved(0, payload), 6)?;
    assert!(!format!("{c:?}").contains("private-video"));
    let retirement = c.cancel();
    assert_eq!(retirement.pending_events, 1);
    assert_eq!(retirement.pending_media_bytes, payload.len());
    assert!(retirement.session.remote_session_may_exist);
    assert_eq!(c.retained_nal_bytes(), 0);
    assert!(matches!(
        c.poll(6)?,
        P::Ended {
            retirement: None,
            ..
        }
    ));
    Ok(())
}

#[test]
fn late_final_tcp_byte_cannot_erase_a_partial_frame_deadline() -> TestResult {
    let wire = interleaved(1, &[0x80, 201, 0, 1, 0, 0, 0, 7]);
    for last_byte_time in [5_000_000_005, 5_000_000_006, 5_000_000_007] {
        let mut c = playing(AvcReceiveLimits::default(), true)?;
        c.ingest(&wire[..wire.len() - 1], 6)?;
        let result = c.ingest(&wire[wire.len() - 1..], last_byte_time);
        if last_byte_time < 5_000_000_006 {
            result?;
            assert!(matches!(
                c.poll(last_byte_time)?,
                P::Rtcp {
                    validation: Ok(1),
                    ..
                }
            ));
        } else {
            let failure = result.err().ok_or("expired framing resurrected")?;
            assert_eq!(failure.reason, E::PartialTimeout);
            assert_eq!(
                failure
                    .retirement
                    .ok_or("retirement missing")?
                    .partial_wire_bytes,
                wire.len() - 1
            );
            assert_eq!(c.state(), ClientState::Closed);
            assert_eq!(c.buffered_wire_bytes(), 0);
        }
    }
    Ok(())
}

#[test]
fn expired_partial_input_prevents_a_new_keepalive_request() -> TestResult {
    let mut c = playing(AvcReceiveLimits::default(), false)?;
    c.ingest(b"RTSP/1.0", 6)?;
    let failure = c
        .request(C::KeepAlive, 5_000_000_006)
        .err()
        .ok_or("expired framing survived request")?;
    assert_eq!(failure.reason, E::PartialTimeout);
    let retirement = failure.retirement.ok_or("missing closure")?;
    assert_eq!(retirement.session.pending_cseq, None);
    assert!(retirement.session.remote_session_may_exist);
    Ok(())
}

#[test]
fn expired_session_refuses_new_wire_before_parsing_or_admission() -> TestResult {
    let mut c = playing(AvcReceiveLimits::default(), false)?;
    let wire = interleaved(0, &packet(1, 90_000, nals(BASELINE)[0]));
    let failure = c
        .ingest(&wire, 60_000_000_004)
        .err()
        .ok_or("expired session accepted input")?;
    assert_eq!(failure.reason, E::Session(ClientError::SessionExpired));
    assert_eq!(
        failure.retirement.ok_or("missing closure")?.pending_events,
        0
    );
    assert_eq!(c.buffered_wire_bytes(), 0);
    Ok(())
}

#[test]
fn a_new_partial_frame_gets_its_own_deadline_after_a_proven_boundary() -> TestResult {
    let mut c = playing(AvcReceiveLimits::default(), true)?;
    let wire = interleaved(1, &[0x80, 201, 0, 1, 0, 0, 0, 7]);
    c.ingest(&wire[..1], 6)?;
    let mut suffix_and_next = wire[1..].to_vec();
    suffix_and_next.extend_from_slice(&wire[..1]);
    c.ingest(&suffix_and_next, 4_000_000_006)?;
    assert!(matches!(
        c.poll(4_000_000_006)?,
        P::Rtcp {
            validation: Ok(1),
            ..
        }
    ));
    assert_eq!(c.next_wake_ns(), Some(9_000_000_006));
    c.ingest(&wire[1..], 8_000_000_006)?;
    assert!(matches!(
        c.poll(8_000_000_006)?,
        P::Rtcp {
            validation: Ok(1),
            ..
        }
    ));
    Ok(())
}
