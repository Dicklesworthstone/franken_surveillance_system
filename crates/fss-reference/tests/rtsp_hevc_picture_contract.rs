#![forbid(unsafe_code)]
//! End-to-end TCP/RTSP/RTP-to-picture contracts through the real existing semantic owners.

use fss_packet::hevc::{
    HevcAssemblyError, HevcAssemblyLimits, HevcAssemblyStep as Step, HevcBoundary,
    HevcPictureGroup, HevcRetirementReason,
};
use fss_packet::{H265Error, H265Limits, ReorderLimits, StreamKey};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::{ClientCommand as C, ClientConfig, ClientError, ClientState};
use fss_reference::rtsp::hevc_client::pictures::{
    HevcPictureClientError as E, HevcPictureClientPoll as P, HevcPictureWorkReason as R,
    RtspHevcPictureClient,
};
use fss_reference::rtsp::hevc_client::{HevcClientError, HevcClientPoll as Raw};
type TestResult = Result<(), Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey {
    ingress: 1,
    generation: 1,
    ssrc: 7,
};
const FIRST: &[u8] = &[2, 1, 0xc0];
const CONT: &[u8] = &[2, 1, 0x40];
const SDP: &[u8] = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 98\r\na=rtpmap:98 H265/90000\r\na=control:trackID=0\r\n";

fn config() -> ClientConfig {
    ClientConfig {
        presentation_uri: "rtsp://camera.local/live/".into(),
        control_root_uri: "rtsp://camera.local/live".into(),
        media_index: 0,
        channels: (0, 1),
        response_timeout_ns: 100,
        default_session_timeout_seconds: 60,
    }
}
fn response(cseq: u32, fields: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut head = format!(
        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (key, val) in fields {
        head.push_str(&format!("{key}: {val}\r\n"));
    }
    head.push_str("\r\n");
    [head.as_bytes(), body].concat()
}
fn challenge(cseq: u32) -> Vec<u8> {
    format!("RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"owner\", nonce=\"private-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n").into_bytes()
}
fn rtp(seq: u16, ts: u32, bytes: &[u8], marker: bool) -> Vec<u8> {
    let mut wire = vec![0x80, 98 | if marker { 128 } else { 0 }];
    wire.extend_from_slice(&seq.to_be_bytes());
    wire.extend_from_slice(&ts.to_be_bytes());
    wire.extend_from_slice(&KEY.ssrc.to_be_bytes());
    wire.extend_from_slice(bytes);
    wire
}
fn frame(seq: u16, ts: u32, bytes: &[u8], marker: bool) -> Vec<u8> {
    let packet = rtp(seq, ts, bytes, marker);
    let mut wire = vec![b'$', 0];
    wire.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    wire.extend_from_slice(&packet);
    wire
}
fn ap(nals: &[&[u8]]) -> Vec<u8> {
    let mut bytes = vec![96, 1];
    for nal in nals {
        bytes.extend_from_slice(&(nal.len() as u16).to_be_bytes());
        bytes.extend_from_slice(nal);
    }
    bytes
}
fn drain(
    client: &mut RtspHevcPictureClient,
    now: u64,
) -> Result<Vec<P>, Box<dyn std::error::Error>> {
    let mut events = Vec::new();
    for _ in 0..2048 {
        let event = client.poll(now)?;
        let stop = match &event {
            P::Pending { wake_at_ns } => wake_at_ns.is_none_or(|at| at > now),
            P::Client { event, work } => {
                work.is_some()
                    || matches!(
                        event.as_ref(),
                        Raw::AuthenticationRequired { .. }
                            | Raw::Backpressure { .. }
                            | Raw::KeepAliveDue
                            | Raw::Fault { .. }
                    )
            }
            P::Assembly { retirement, .. } => retirement.is_some(),
            P::Fault { .. } | P::Ended { .. } => true,
            _ => false,
        };
        events.push(event);
        if stop {
            return Ok(events);
        }
    }
    Err("picture client did not reach a bounded waiting/terminal state".into())
}
fn feed(
    client: &mut RtspHevcPictureClient,
    bytes: &[u8],
    now: u64,
) -> Result<Vec<P>, Box<dyn std::error::Error>> {
    client.ingest(bytes, now)?;
    drain(client, now)
}
fn pictures(events: &[P]) -> Vec<&HevcPictureGroup> {
    events
        .iter()
        .filter_map(|e| match e {
            P::Assembly {
                step: Step::Accepted(out),
                ..
            } => out.picture.as_ref(),
            P::Ended {
                tail: Some(out), ..
            } => out.picture.as_ref(),
            _ => None,
        })
        .collect()
}
fn prime(client: &mut RtspHevcPictureClient) -> TestResult {
    // End-of-sequence markers establish sequence probation without leaving a
    // metadata prefix or falsely decoded baseline picture in the new assembler.
    for seq in 0..4 {
        feed(
            client,
            &frame(seq, 0, &[72, 1, 0x80], false),
            8 + u64::from(seq),
        )?;
    }
    assert_eq!(client.retained_nal_bytes(), 0);
    assert_eq!(client.queued_nals(), 0);
    Ok(())
}
fn open(
    reorder: ReorderLimits,
    codec: H265Limits,
    assembly: HevcAssemblyLimits,
) -> Result<RtspHevcPictureClient, Box<dyn std::error::Error>> {
    let mut client = RtspHevcPictureClient::new(config(), KEY, reorder, codec, assembly)?;
    client.request(C::Describe, 0)?;
    feed(
        &mut client,
        &response(1, &[("Content-Type", "application/sdp")], SDP),
        1,
    )?;
    client.request(C::Setup, 2)?;
    feed(
        &mut client,
        &response(
            2,
            &[
                ("Session", "private-session;timeout=60"),
                (
                    "Transport",
                    "RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000007",
                ),
            ],
            &[],
        ),
        3,
    )?;
    client.request(C::Play, 4)?;
    feed(
        &mut client,
        &response(3, &[("Session", "private-session")], &[]),
        5,
    )?;
    assert_eq!(client.state(), ClientState::Playing);
    prime(&mut client)?;
    Ok(client)
}
fn normal() -> Result<RtspHevcPictureClient, Box<dyn std::error::Error>> {
    open(
        ReorderLimits::default(),
        H265Limits::default(),
        HevcAssemblyLimits::default(),
    )
}
fn stop_after_source(client: &mut RtspHevcPictureClient, wire: &[u8], now: u64) -> TestResult {
    client.ingest(wire, now)?;
    for _ in 0..32 {
        if let P::Source { queued_nals, .. } = client.poll(now)? {
            assert!(queued_nals > 0);
            return Ok(());
        }
    }
    Err("source event was not returned before NAL assembly".into())
}

#[test]
fn marked_multislice_picture_waits_for_real_next_first_slice_and_preserves_originals() -> TestResult
{
    let mut client = normal()?;
    assert!(client.media().ok_or("missing signaling")?.sps().is_empty());
    let first = feed(&mut client, &frame(4, 100, FIRST, true), 20)?;
    assert!(pictures(&first).is_empty());
    assert!(first.iter().any(
        |e| matches!(e, P::Source { source, .. } if source.bytes() == rtp(4, 100, FIRST, true))
    ));
    assert!(pictures(&feed(&mut client, &frame(5, 100, CONT, true), 21)?).is_empty());
    let output = feed(&mut client, &frame(6, 200, FIRST, true), 22)?;
    let groups = pictures(&output);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].boundary(), HevcBoundary::NextFirstSlice);
    assert_eq!(groups[0].slice_count(), 2);
    assert_eq!(groups[0].nals()[0].bytes(), FIRST);
    assert_eq!(groups[0].nals()[1].bytes(), CONT);
    assert_eq!(groups[0].timestamp(), 100);
    assert!(groups[0].nals().iter().all(|nal| nal.marker()));
    assert!(!groups[0].discontinuity_before());
    assert_eq!(client.state(), ClientState::Playing);
    Ok(())
}

#[test]
fn fragmented_and_reordered_first_slice_retains_every_original_copy_span() -> TestResult {
    let mut client = normal()?;
    let start = &[98, 1, 0x81, 0xc0][..];
    let middle = &[98, 1, 1, 0x55][..];
    let end = &[98, 1, 0x41, 0x66][..];
    feed(&mut client, &frame(4, 100, start, false), 20)?;
    feed(&mut client, &frame(6, 100, end, true), 21)?;
    feed(&mut client, &frame(5, 100, middle, false), 22)?;
    let output = feed(&mut client, &frame(7, 200, FIRST, false), 23)?;
    let groups = pictures(&output);
    assert_eq!(groups.len(), 1);
    let nal = &groups[0].nals()[0];
    assert_eq!(nal.bytes(), [2, 1, 0xc0, 0x55, 0x66]);
    assert_eq!(nal.sources().len(), 3);
    for (index, payload) in [start, middle, end].into_iter().enumerate() {
        let source = rtp(index as u16 + 4, 100, payload, index == 2);
        let span = &nal.sources()[index];
        assert_eq!(span.sequence, index as u64 + 4);
        assert_eq!(
            &source[span.wire_range.clone()],
            &nal.bytes()[span.nal_range.clone()]
        );
        assert_eq!(span.fragment_header_range, Some(12..15));
    }
    Ok(())
}

#[test]
fn transport_gap_invalidates_picture_and_late_continuation_cannot_repair_it() -> TestResult {
    let mut client = open(
        ReorderLimits {
            max_delay_ns: 10,
            ..ReorderLimits::default()
        },
        H265Limits::default(),
        HevcAssemblyLimits::default(),
    )?;
    feed(&mut client, &frame(4, 100, FIRST, false), 20)?;
    feed(&mut client, &frame(6, 100, CONT, true), 21)?;
    assert_eq!(client.next_wake_ns(), Some(31));
    let output = drain(&mut client, 31)?;
    assert!(output.iter().any(|e| matches!(e, P::Gap { gap, picture: Some(p), .. }
        if gap.first_sequence == 5 && p.nals == 1 && p.reason == HevcRetirementReason::InputDiscontinuity)));
    assert!(
        output
            .iter()
            .any(|e| matches!(e, P::Assembly { step: Step::Refused(r), .. }
        if r.reason == HevcAssemblyError::MissingFirstSlice))
    );
    assert!(pictures(&output).is_empty());
    feed(&mut client, &frame(5, 100, CONT, false), 32)?;
    feed(&mut client, &frame(7, 200, FIRST, false), 33)?;
    client.finish();
    let terminal = drain(&mut client, 34)?;
    assert!(pictures(&terminal)[0].discontinuity_before());
    assert_eq!(pictures(&terminal)[0].timestamp(), 200);
    Ok(())
}

#[test]
fn codec_failure_returns_the_original_packet_and_retires_the_pending_picture() -> TestResult {
    let mut client = normal()?;
    feed(&mut client, &frame(4, 100, FIRST, false), 20)?;
    let bad = &[98, 1, 0xc1, 0];
    let output = feed(&mut client, &frame(5, 100, bad, true), 21)?;
    assert!(output.iter().any(
        |e| matches!(e, P::CodecRefused { source, picture: Some(p), .. }
        if source.bytes() == rtp(5, 100, bad, true) && p.nals == 1)
    ));
    assert!(pictures(&output).is_empty());
    assert_eq!(client.retained_nal_bytes(), 0);
    feed(&mut client, &frame(6, 200, FIRST, false), 22)?;
    let output = feed(&mut client, &frame(7, 300, FIRST, false), 23)?;
    assert!(pictures(&output)[0].discontinuity_before());
    Ok(())
}

#[test]
fn incomplete_fragment_eof_never_flushes_the_preceding_partial_picture() -> TestResult {
    let mut client = normal()?;
    feed(&mut client, &frame(4, 100, FIRST, false), 20)?;
    feed(&mut client, &frame(5, 100, &[98, 1, 0x81, 0x40], false), 21)?;
    client.finish();
    let output = drain(&mut client, 22)?;
    assert!(pictures(&output).is_empty());
    assert!(output.iter().any(|e| matches!(e,
        P::Ended { interrupted_picture: Some(p), tail: Some(tail), .. }
        if p.nals == 1 && tail.picture.is_none())));
    assert!(matches!(
        client.poll(23)?,
        P::Ended {
            client: None,
            tail: None,
            interrupted_picture: None
        }
    ));
    Ok(())
}

#[test]
fn fragment_expiry_propagates_without_another_network_packet_or_a_false_tail() -> TestResult {
    let mut client = open(
        ReorderLimits::default(),
        H265Limits {
            max_pending_age_ns: 10,
            ..H265Limits::default()
        },
        HevcAssemblyLimits {
            max_age_ns: 100,
            ..HevcAssemblyLimits::default()
        },
    )?;
    feed(&mut client, &frame(4, 100, FIRST, false), 20)?;
    let start = frame(5, 100, &[98, 1, 0x81, 0x40], false);
    feed(&mut client, &start, 21)?;
    feed(&mut client, &start, 29)?;
    assert_eq!(client.next_wake_ns(), Some(31));
    let output = drain(&mut client, 31)?;
    assert!(output.iter().any(
        |e| matches!(e, P::FragmentRetired { fragment, picture: Some(p) }
        if fragment.reason == H265Error::Deadline && p.nals == 1)
    ));
    assert_eq!(client.retained_nal_bytes(), 0);
    client.finish();
    assert!(pictures(&drain(&mut client, 32)?).is_empty());
    Ok(())
}

#[test]
fn picture_deadline_is_exposed_and_not_renewed_by_a_continuation_or_marker() -> TestResult {
    let mut client = open(
        ReorderLimits::default(),
        H265Limits::default(),
        HevcAssemblyLimits {
            max_age_ns: 10,
            ..HevcAssemblyLimits::default()
        },
    )?;
    feed(&mut client, &frame(4, 100, FIRST, true), 20)?;
    feed(&mut client, &frame(5, 100, CONT, true), 29)?;
    assert_eq!(client.next_wake_ns(), Some(30));
    assert!(matches!(client.poll(30)?, P::PictureRetired(p)
        if p.reason == HevcRetirementReason::Deadline && p.nals == 2));
    drain(&mut client, 30)?;
    feed(&mut client, &frame(6, 200, FIRST, false), 31)?;
    client.finish();
    let output = drain(&mut client, 32)?;
    assert_eq!(
        pictures(&output)[0].boundary(),
        HevcBoundary::EndOfInputUnverified
    );
    assert!(pictures(&output)[0].discontinuity_before());
    Ok(())
}

#[test]
fn complete_queued_nals_expire_instead_of_starting_fresh_pictures_from_aged_work() -> TestResult {
    let mut client = open(
        ReorderLimits::default(),
        H265Limits::default(),
        HevcAssemblyLimits {
            max_age_ns: 10,
            ..HevcAssemblyLimits::default()
        },
    )?;
    stop_after_source(&mut client, &frame(4, 100, &ap(&[FIRST, CONT]), true), 20)?;
    assert_eq!(client.queued_nals(), 2);
    let refusal = client
        .ingest(&frame(5, 200, FIRST, false), 21)
        .err()
        .ok_or("NAL backpressure bypassed")?;
    assert_eq!(refusal.reason, E::Backpressure);
    assert!(refusal.retirement.is_none());
    assert!(matches!(client.poll(30)?, P::QueueRetired(work)
        if work.reason == R::QueueDeadline && work.queued.nals == 2 && work.picture.is_none()));
    assert_eq!(client.queued_nals(), 0);
    drain(&mut client, 30)?;
    feed(&mut client, &frame(5, 200, FIRST, false), 31)?;
    let output = feed(&mut client, &frame(6, 300, FIRST, false), 32)?;
    assert!(pictures(&output)[0].discontinuity_before());
    assert_eq!(pictures(&output)[0].nals().len(), 1);
    Ok(())
}

#[test]
fn request_deadline_is_enforced_before_draining_queued_derivatives() -> TestResult {
    let mut client = normal()?;
    client.request(C::KeepAlive, 20)?;
    stop_after_source(&mut client, &frame(4, 100, FIRST, false), 21)?;
    let P::Client {
        event,
        work: Some(work),
    } = client.poll(120)?
    else {
        return Err("request expiry was hidden by queued NALs".into());
    };
    assert!(matches!(
        event.as_ref(),
        Raw::Fault {
            reason: HevcClientError::Session(ClientError::ResponseTimeout),
            ..
        }
    ));
    assert_eq!(work.queued.nals, 1);
    assert!(work.picture.is_none());
    assert_eq!(client.state(), ClientState::Closed);
    assert_eq!(client.next_wake_ns(), None);
    Ok(())
}

#[test]
fn cancellation_accounts_for_picture_queue_and_exact_unprocessed_tcp() -> TestResult {
    let mut client = normal()?;
    feed(&mut client, &frame(4, 100, FIRST, false), 20)?;
    let mut combined = frame(5, 100, &ap(&[CONT, CONT]), true);
    combined.extend_from_slice(b"$\0");
    stop_after_source(&mut client, &combined, 21)?;
    let retired = client.cancel();
    assert_eq!(retired.work.reason, R::Cancelled);
    assert_eq!(retired.work.queued.nals, 2);
    assert_eq!(retired.work.queued.first_sequence, Some(5));
    assert_eq!(
        retired.work.picture.ok_or("picture ownership lost")?.nals,
        1
    );
    assert_eq!(retired.client.wire.expose(), b"$\0");
    assert!(retired.client.session.remote_session_may_exist);
    assert_eq!(client.retained_nal_bytes(), 0);
    assert_eq!(client.buffered_wire_bytes(), 0);
    let again = client.cancel();
    assert_eq!(again.work.queued.nals, 0);
    assert!(again.work.picture.is_none());
    assert!(again.client.wire.is_empty());
    Ok(())
}

#[test]
fn end_of_bitstream_fences_lookahead_and_preserves_the_last_picture() -> TestResult {
    let mut client = normal()?;
    let mut combined = frame(4, 100, &ap(&[FIRST, &[74, 1, 0x80], FIRST]), true);
    combined.extend_from_slice(b"$\0");
    let output = feed(&mut client, &combined, 20)?;
    assert_eq!(pictures(&output).len(), 1);
    assert_eq!(
        pictures(&output)[0].boundary(),
        HevcBoundary::EndOfBitstream
    );
    let retired = output
        .iter()
        .find_map(|e| match e {
            P::Assembly {
                retirement: Some(retired),
                ..
            } => Some(retired),
            _ => None,
        })
        .ok_or("EOB did not retire later work")?;
    assert_eq!(retired.work.reason, R::EndOfBitstream);
    assert_eq!(retired.work.queued.nals, 1);
    assert_eq!(retired.client.wire.expose(), b"$\0");
    assert!(retired.client.session.remote_session_may_exist);
    assert_eq!(client.state(), ClientState::Closed);
    assert!(matches!(client.poll(21)?, P::Ended { client: None, .. }));
    Ok(())
}

#[test]
fn clean_eof_and_teardown_preserve_unverified_tail_and_distinct_remote_outcomes() -> TestResult {
    for teardown in [false, true] {
        let mut client = normal()?;
        feed(&mut client, &frame(4, 100, FIRST, true), 20)?;
        let output = if teardown {
            client.request(C::Teardown, 21)?;
            feed(
                &mut client,
                &response(4, &[("Session", "private-session")], &[]),
                22,
            )?
        } else {
            client.finish();
            drain(&mut client, 22)?
        };
        assert_eq!(pictures(&output).len(), 1);
        assert_eq!(
            pictures(&output)[0].boundary(),
            HevcBoundary::EndOfInputUnverified
        );
        let raw = output
            .iter()
            .find_map(|e| match e {
                P::Ended {
                    client: Some(raw), ..
                } => Some(raw.as_ref()),
                _ => None,
            })
            .ok_or("inner terminal receipt lost")?;
        assert!(matches!(raw, Raw::Ended { retirement: Some(retired), .. }
            if retired.session.remote_session_may_exist != teardown));
        assert!(matches!(
            client.poll(23)?,
            P::Ended {
                client: None,
                tail: None,
                ..
            }
        ));
    }
    Ok(())
}

#[test]
fn authenticated_keepalive_waits_preserve_challenges_and_picture_timer_wakes() -> TestResult {
    let credentials = DigestCredentials::new("private-user", "private-password")?;
    let mut client = RtspHevcPictureClient::with_digest(
        config(),
        KEY,
        ReorderLimits::default(),
        H265Limits::default(),
        HevcAssemblyLimits {
            max_age_ns: 10,
            ..HevcAssemblyLimits::default()
        },
        "owner",
        DigestPolicy::default(),
    )?;
    client.request_digest(C::Describe, &credentials, [1; 16], 0)?;
    feed(&mut client, &challenge(1), 1)?;
    let retry = client.respond_digest(&credentials, [2; 16], 2)?;
    assert_eq!(retry.source.expose_wire(), challenge(1));
    drain(&mut client, 2)?;
    feed(
        &mut client,
        &response(2, &[("Content-Type", "application/sdp")], SDP),
        3,
    )?;
    client.request_digest(C::Setup, &credentials, [3; 16], 4)?;
    feed(
        &mut client,
        &response(
            3,
            &[
                ("Session", "private-session"),
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
        &response(4, &[("Session", "private-session")], &[]),
        7,
    )?;
    prime(&mut client)?;
    feed(&mut client, &frame(4, 100, FIRST, false), 20)?;
    let keepalive = client.request_digest(C::KeepAlive, &credentials, [5; 16], 21)?;
    let held = challenge(keepalive.cseq());
    let output = feed(&mut client, &held, 22)?;
    assert!(output.iter().any(|e| matches!(e, P::Client { event, .. }
        if matches!(event.as_ref(), Raw::AuthenticationRequired { wake_at_ns: Some(30), .. }))));
    assert!(matches!(client.poll(30)?, P::PictureRetired(_)));
    let wait = client.poll(30)?;
    assert!(
        matches!(&wait, P::Client { event, .. } if matches!(event.as_ref(), Raw::AuthenticationRequired { .. }))
    );
    let debug = format!("{client:?} {retry:?} {wait:?}");
    for secret in [
        "private-user",
        "private-password",
        "private-nonce",
        "private-session",
        "camera.local",
    ] {
        assert!(!debug.contains(secret));
    }
    let retired = client.cancel();
    assert_eq!(
        retired
            .client
            .challenge
            .ok_or("challenge lost at cancellation")?
            .expose_wire(),
        held
    );
    assert!(retired.work.picture.is_none());
    Ok(())
}

#[test]
fn malformed_suffix_does_not_drop_source_or_flush_the_pending_picture_as_success() -> TestResult {
    let mut client = normal()?;
    feed(&mut client, &frame(4, 100, FIRST, false), 20)?;
    let mut wire = frame(5, 100, CONT, false);
    wire.extend_from_slice(b"INVALID\n");
    let output = feed(&mut client, &wire, 21)?;
    assert!(pictures(&output).is_empty());
    assert!(
        output
            .iter()
            .any(|e| matches!(e, P::Source { source, .. } if source.sequence() == 5))
    );
    assert!(output.iter().any(|e| matches!(e, P::Client { event, work: Some(work) }
        if work.picture.as_ref().is_some_and(|p| p.nals == 2)
        && matches!(event.as_ref(), Raw::Fault { retirement, .. } if retirement.wire.expose() == b"INVALID\n"))));
    assert_eq!(client.state(), ClientState::Closed);
    Ok(())
}

#[test]
fn fatal_request_retirement_and_source_restart_close_all_picture_work() -> TestResult {
    let mut client = normal()?;
    feed(&mut client, &frame(4, 100, FIRST, false), 20)?;
    let failure = client
        .request(C::KeepAlive, 60_000_000_004)
        .err()
        .ok_or("expired session accepted request")?;
    assert_eq!(
        failure.reason,
        E::Client(HevcClientError::Session(ClientError::SessionExpired))
    );
    assert_eq!(
        failure
            .retirement
            .ok_or("request failure lost work")?
            .work
            .picture
            .ok_or("missing picture")?
            .nals,
        1
    );
    assert_eq!(client.retained_nal_bytes(), 0);
    let mut client = normal()?;
    feed(&mut client, &frame(4, 100, FIRST, false), 20)?;
    feed(&mut client, &frame(40_000, 100, FIRST, false), 21)?;
    let output = feed(&mut client, &frame(40_001, 100, FIRST, false), 22)?;
    assert!(
        output
            .iter()
            .any(|e| matches!(e, P::Client { event, work: Some(work) }
        if work.reason == R::ClientTerminal && work.picture.as_ref().is_some_and(|p| p.nals == 1)
        && matches!(event.as_ref(), Raw::Rtp { retirement: Some(_), .. })))
    );
    assert_eq!(client.state(), ClientState::Closed);
    Ok(())
}

#[test]
fn clock_reversal_and_invalid_constructor_never_reset_a_live_picture() -> TestResult {
    assert!(
        RtspHevcPictureClient::new(
            config(),
            KEY,
            ReorderLimits::default(),
            H265Limits::default(),
            HevcAssemblyLimits {
                max_nals: 0,
                ..HevcAssemblyLimits::default()
            }
        )
        .is_err()
    );
    let mut client = normal()?;
    feed(&mut client, &frame(4, 100, FIRST, false), 20)?;
    assert_eq!(
        client.poll(19).err(),
        Some(E::Client(HevcClientError::Session(
            ClientError::ClockReversed
        )))
    );
    assert_eq!(client.retained_nal_bytes(), FIRST.len());
    let output = feed(&mut client, &frame(5, 200, FIRST, false), 21)?;
    assert_eq!(pictures(&output)[0].timestamp(), 100);
    assert!(!pictures(&output)[0].discontinuity_before());
    Ok(())
}

#[test]
fn tcp_partitioning_preserves_picture_bytes_source_order_and_boundary_classification() -> TestResult
{
    let wires = [
        frame(4, 100, FIRST, true),
        frame(5, 100, CONT, true),
        frame(6, 200, FIRST, false),
    ];
    let stream = wires.concat();
    for width in 1..=stream.len() {
        let mut client = normal()?;
        let mut events = Vec::new();
        for chunk in stream.chunks(width) {
            events.extend(feed(&mut client, chunk, 20)?);
        }
        let groups = pictures(&events);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].boundary(), HevcBoundary::NextFirstSlice);
        assert_eq!(
            groups[0]
                .nals()
                .iter()
                .map(|n| n.bytes().to_vec())
                .collect::<Vec<_>>(),
            vec![FIRST.to_vec(), CONT.to_vec()]
        );
        let sources: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                P::Source { source, .. } => Some(source.sequence()),
                _ => None,
            })
            .collect();
        assert_eq!(sources, [4, 5, 6]);
        assert_eq!(client.buffered_wire_bytes(), 0);
        assert_eq!(client.queued_nals(), 0);
    }
    Ok(())
}

#[test]
fn malformed_rtcp_remains_orthogonal_to_video_picture_assembly() -> TestResult {
    let mut client = normal()?;
    feed(&mut client, &frame(4, 100, FIRST, false), 20)?;
    let mut bad_rtcp = frame(0, 0, &[0, 0, 0], false);
    bad_rtcp[1] = 1; // Negotiated RTCP channel carrying an intentionally invalid compound.
    let output = feed(&mut client, &bad_rtcp, 21)?;
    assert!(output.iter().any(|e| matches!(e, P::Client { event, work: None }
        if matches!(event.as_ref(), Raw::Rtcp { validation: Err(_), source } if source.expose_wire() == bad_rtcp))));
    assert_eq!(client.retained_nal_bytes(), FIRST.len());
    let output = feed(&mut client, &frame(5, 200, FIRST, false), 22)?;
    assert_eq!(pictures(&output)[0].timestamp(), 100);
    assert!(!pictures(&output)[0].discontinuity_before());
    Ok(())
}

#[test]
fn assembly_refusal_preserves_the_nal_and_allows_only_explicit_discontinuous_recovery() -> TestResult
{
    let mut client = normal()?;
    feed(&mut client, &frame(4, 100, FIRST, false), 20)?;
    let wrong_pps = &[2, 1, 0x20]; // first_slice=0, ue(v) PPS identity 1.
    let output = feed(&mut client, &frame(5, 100, wrong_pps, false), 21)?;
    assert!(output.iter().any(
        |e| matches!(e, P::Assembly { step: Step::Refused(refusal), retirement: None }
        if refusal.reason == HevcAssemblyError::PictureMismatch && refusal.nal.bytes() == wrong_pps
        && refusal.retired.as_ref().is_some_and(|p| p.nals == 1))
    ));
    assert_eq!(client.state(), ClientState::Playing);
    assert_eq!(client.retained_nal_bytes(), 0);
    feed(&mut client, &frame(6, 200, FIRST, false), 22)?;
    let output = feed(&mut client, &frame(7, 300, FIRST, false), 23)?;
    assert!(pictures(&output)[0].discontinuity_before());
    Ok(())
}
