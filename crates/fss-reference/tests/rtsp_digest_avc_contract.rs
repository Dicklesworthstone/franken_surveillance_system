#![forbid(unsafe_code)]
mod digest_media_support;
use digest_media_support::*;
use fss_packet::avc::{AvcAssemblyStep, AvcBoundary, AvcReceiveLimits, AvcReceivePoll};
use fss_reference::rtsp::{authentication::{AuthenticationError, DigestPolicy},
    avc_client::{AvcClientError, AvcClientPoll, authenticated::*},
    client::{ClientCommand as C, ClientError, ClientProgress, ClientState, authenticated::DigestClientError},
    framed::WIRE_LIFETIME_NS};

#[test]
fn fragmented_challenge_signs_exact_original_target_and_new_cseq() -> TestResult {
    let mut c = new_client()?; let creds = credentials()?; let mut out = Vec::new();
    let first = c.request(C::Describe, &creds, [0;16], 0)?;
    assert!(!std::str::from_utf8(first.bytes())?.contains("Authorization"));
    send(&mut c, &challenge(1, "server-nonce-1", false), 1, 1, &mut out)?;
    assert!(matches!(out.last(), Some(DigestAvcPoll::AuthenticationRequired { cseq: 1, .. })));
    let signed = c.respond(&creds, [17;16], 2)?;
    let wire = std::str::from_utf8(signed.bytes())?;
    assert!(wire.starts_with("DESCRIBE rtsp://camera.local/live/ RTSP/1.0\r\nCSeq: 2\r\n"));
    assert!(wire.contains("response=\"f5eba878612218aea53e17a3eb4129c90ffdfdfc6de8d96b5511029dc894177b\""));
    assert!(wire.contains("qop=auth, nc=00000001, cnonce=\"11111111111111111111111111111111\""));
    assert!(!format!("{signed:?} {c:?}").contains("camera-password"));
    assert_eq!(c.next_wake_ns(), Some(10_000_000_000));
    Ok(())
}
#[test]
fn authenticated_negotiation_preserves_real_rtp_and_all_four_avc_groups() -> TestResult {
    for chunk in [1, 7, 4096] {
        let mut c = playing()?; let nals = nals();
        let mut original = vec![packet(0, 90_000, nals[0])]; let mut frame = 0;
        for (i, nal) in nals.iter().enumerate() {
            original.push(packet(i as u16 + 1, 90_000 + frame * 3600, nal));
            if matches!(nal[0] & 31, 1 | 5) { frame += 1; }
        }
        let wire: Vec<_> = original.iter().flat_map(|p| interleaved(0, p)).collect();
        let mut out = Vec::new(); send(&mut c, &wire, chunk, 8, &mut out)?;
        c.finish(); drain(&mut c, 9, &mut out)?;
        let sources: Vec<_> = out.iter().filter_map(|e| match e {
            DigestAvcPoll::Client { event: inner, .. }
                if matches!(&**inner, AvcClientPoll::Rtp { retirement: None, .. }) =>
            {
                if let AvcClientPoll::Rtp { source, retirement: None, .. } = &**inner {
                    Some(source.payload())
                } else {
                    None
                }
            }
            _ => None,
        }).collect();
        assert_eq!(sources, original.iter().map(Vec::as_slice).collect::<Vec<_>>());
        let mut pictures = 0;
        for e in &out {
            match e {
                DigestAvcPoll::Client { event: inner, .. }
                    if matches!(&**inner, AvcClientPoll::Media(AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(_)))) =>
                {
                    if let AvcClientPoll::Media(AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(o))) = &**inner {
                        pictures += usize::from(o.picture.is_some());
                    }
                }
                DigestAvcPoll::Client { event: inner, .. }
                    if matches!(&**inner, AvcClientPoll::Media(AvcReceivePoll::Picture(_))) =>
                {
                    pictures += 1;
                }
                DigestAvcPoll::Client { event: inner, wire_retirement: Some(w) }
                    if matches!(&**inner, AvcClientPoll::Ended { media: Some(AvcReceivePoll::Ended { tail: Some(_), .. }), .. }) =>
                {
                    if let AvcClientPoll::Ended { media: Some(AvcReceivePoll::Ended { tail: Some(o), .. }), .. } = &**inner {
                        assert_eq!(o.picture.as_ref().ok_or("EOF picture")?.boundary(), AvcBoundary::EndOfInputUnverified);
                        assert!(w.pending.is_empty()); assert!(w.challenge.is_none()); pictures += 1;
                    }
                }
                DigestAvcPoll::Fault { .. } => {
                    return Err("clean fixture refused".into())
                }
                DigestAvcPoll::Client { event: inner, .. }
                    if matches!(
                        &**inner,
                        AvcClientPoll::Fault { .. }
                            | AvcClientPoll::Media(AvcReceivePoll::Assembly(
                                AvcAssemblyStep::Refused(_)
                            ))
                    ) =>
                {
                    return Err("clean fixture refused".into())
                }
                _ => {},
            }
        }
        assert_eq!(pictures, 4); assert_eq!(c.retained_nal_bytes(), 0); assert_eq!(c.buffered_wire_bytes(), 0);
    }
    Ok(())
}
#[test]
fn keepalive_challenge_does_not_suspend_media_fragment_deadlines() -> TestResult {
    let mut c = playing()?; let creds = credentials()?; let mut out = Vec::new();
    send(&mut c, &interleaved(0, &packet(0, 90_000, nals()[0])), 4096, 8, &mut out)?;
    send(&mut c, &interleaved(0, &packet(1, 90_000, &[0x5c, 0x81, 0x80])), 4096, 9, &mut out)?;
    let keepalive = c.request(C::KeepAlive, &creds, [20;16], 10)?;
    assert_eq!(keepalive.cseq(), 5);
    assert!(std::str::from_utf8(keepalive.bytes())?.contains("nc=00000004"));
    send(&mut c, &challenge(5, "server-nonce-2", true), 7, 11, &mut out)?;
    drain(&mut c, 2_000_000_009, &mut out)?;
    assert!(out.iter().any(|e| matches!(e, DigestAvcPoll::Client { event, .. }
        if matches!(&**event, AvcClientPoll::Media(AvcReceivePoll::FragmentRetired { .. })))));
    assert!(matches!(out.last(), Some(DigestAvcPoll::AuthenticationRequired { cseq: 5, .. })));
    let retry = c.respond(&creds, [21;16], 2_000_000_010)?;
    assert_eq!(retry.cseq(), 6);
    assert_eq!(c.next_wake_ns(), Some(10_000_000_010));
    Ok(())
}
#[test]
fn challenge_retry_cannot_extend_the_original_response_deadline() -> TestResult {
    let mut cfg = config(); cfg.response_timeout_ns = 100;
    let mut c = DigestAvcClient::new(cfg, KEY, AvcReceiveLimits::default(), "fixture-camera", DigestPolicy::default())?;
    let creds = credentials()?; let mut out = Vec::new(); c.request(C::Describe, &creds, [0;16], 0)?;
    send(&mut c, &challenge(1, "server-nonce-1", false), 4096, 10, &mut out)?;
    c.respond(&creds, [17;16], 90)?;
    assert_eq!(c.next_wake_ns(), Some(100));
    assert!(matches!(c.poll(100)?, DigestAvcPoll::Client { event, wire_retirement: Some(_), .. }
        if matches!(&*event, AvcClientPoll::Fault {
            reason: AvcClientError::Session(ClientError::ResponseTimeout), .. })));
    Ok(())
}
#[test]
fn wrong_cseq_basic_and_proxy_challenges_never_request_credentials() -> TestResult {
    for kind in 0..3 {
        let mut c = new_client()?; let creds = credentials()?; c.request(C::Describe, &creds, [0;16], 0)?;
        let bytes = match kind {
            0 => challenge(999, "server-nonce-1", false),
            1 => b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Basic realm=\"fixture-camera\"\r\n\r\n".to_vec(),
            _ => b"RTSP/1.0 407 Proxy\r\nCSeq: 1\r\nProxy-Authenticate: Digest realm=\"fixture-camera\"\r\n\r\n".to_vec(),
        };
        c.ingest(&bytes, 1)?;
        match c.poll(1)? {
            DigestAvcPoll::Fault { retirement, .. } => assert_eq!(retirement.wire.challenge.ok_or("refused response")?.expose_wire(), bytes),
            other => return Err(format!("challenge not refused: {other:?}").into()),
        }
        assert_eq!(c.state(), ClientState::Closed);
    }
    Ok(())
}
#[test]
fn wrong_realm_and_legacy_downgrade_close_without_losing_the_challenge() -> TestResult {
    for wrong in ["realm=\"foreign\"", "algorithm=MD5"] {
        let mut c = new_client()?; let creds = credentials()?; let mut out = Vec::new();
        c.request(C::Describe, &creds, [0;16], 0)?;
        let mut bytes = String::from_utf8(challenge(1, "server-nonce-1", false))?;
        if wrong.starts_with("realm") { bytes = bytes.replace("realm=\"fixture-camera\"", wrong); }
        else { bytes = bytes.replace("algorithm=SHA-256", wrong); }
        send(&mut c, bytes.as_bytes(), 7, 1, &mut out)?;
        let failure = c.respond(&creds, [17;16], 2).err().ok_or("must refuse challenge")?;
        assert!(matches!(failure.reason, DigestAvcError::Authentication(_)));
        assert!(!format!("{failure:?}").contains("camera-password"));
        assert_eq!(failure.retirement.ok_or("retirement")?.wire.challenge.ok_or("challenge")?.expose_wire(), bytes.as_bytes());
        assert_eq!(c.state(), ClientState::Closed);
    }
    Ok(())
}
#[test]
fn wrong_password_loop_stops_on_repeated_unstale_nonce() -> TestResult {
    let mut c = new_client()?; let creds = credentials()?; let mut out = Vec::new();
    c.request(C::Describe, &creds, [0;16], 0)?;
    send(&mut c, &challenge(1, "server-nonce-1", false), 4096, 1, &mut out)?;
    c.respond(&creds, [17;16], 2)?; drain(&mut c, 2, &mut out)?;
    send(&mut c, &challenge(2, "server-nonce-1", false), 4096, 3, &mut out)?;
    let error = c.respond(&creds, [18;16], 4).err().ok_or("replayed nonce accepted")?;
    assert_eq!(error.reason, DigestAvcError::Authentication(DigestClientError::Authentication(AuthenticationError::Replay)));
    assert!(error.retirement.is_some()); assert!(c.respond(&creds, [19;16], 5).is_err());
    Ok(())
}
#[test]
fn coalesced_media_waits_for_challenge_without_rewrite_or_double_admission() -> TestResult {
    let mut c = playing()?; let creds = credentials()?; let mut out = Vec::new();
    c.request(C::KeepAlive, &creds, [20;16], 8)?;
    let packet = packet(0, 90_000, nals()[0]);
    let bytes = [challenge(5, "server-nonce-2", true), interleaved(0, &packet)].concat();
    send(&mut c, &bytes, 4096, 9, &mut out)?;
    let before = c.buffered_wire_bytes();
    assert!(matches!(c.ingest(b"unconsumed", 10), Err(DigestAvcFailure { reason: DigestAvcError::Backpressure, retirement: None })));
    assert_eq!(c.buffered_wire_bytes(), before);
    c.respond(&creds, [21;16], 10)?; drain(&mut c, 10, &mut out)?;
    let sources: Vec<_> = out.iter().filter_map(|e| match e {
        DigestAvcPoll::Client { event, .. } if matches!(&**event,
            AvcClientPoll::Rtp { .. }) => match &**event {
            AvcClientPoll::Rtp { source, .. } => Some(source), _ => None,
        }, _ => None,
    }).collect();
    assert_eq!(sources.len(), 1); assert_eq!(sources[0].payload(), packet); assert_eq!(sources[0].received_ns(), 9);
    Ok(())
}
#[test]
fn stale_pre_retry_success_cannot_complete_the_authenticated_request() -> TestResult {
    let mut c = new_client()?; let creds = credentials()?; let mut out = Vec::new();
    c.request(C::Describe, &creds, [0;16], 0)?;
    send(&mut c, &challenge(1, "server-nonce-1", false), 4096, 1, &mut out)?;
    c.respond(&creds, [17;16], 2)?; drain(&mut c, 2, &mut out)?;
    send(&mut c, &response(1, "Content-Type: application/sdp\r\n", &description()), 4096, 3, &mut out)?;
    assert!(matches!(out.last(), Some(DigestAvcPoll::Client { event, wire_retirement: Some(_), .. })
        if matches!(&**event, AvcClientPoll::Fault {
            reason: AvcClientError::Session(ClientError::CseqMismatch), .. })));
    Ok(())
}
#[test]
fn waiting_credentials_retain_the_original_frame_deadline_and_cancel_ownership() -> TestResult {
    let mut c = new_client()?; let creds = credentials()?; let mut out = Vec::new();
    c.request(C::Describe, &creds, [0;16], 0)?;
    let bytes = challenge(1, "server-nonce-1", false);
    send(&mut c, &bytes[..10], 10, 1, &mut out)?;
    send(&mut c, &bytes[10..], 4096, 100, &mut out)?;
    assert_eq!(c.next_wake_ns(), Some(1 + WIRE_LIFETIME_NS));
    match c.poll(1 + WIRE_LIFETIME_NS)? {
        DigestAvcPoll::Fault { retirement, .. } => assert_eq!(retirement.wire.challenge.ok_or("held frame")?.expose_wire(), bytes),
        other => return Err(format!("deadline missing: {other:?}").into()),
    }
    let again = c.cancel(); assert!(again.wire.pending.is_empty()); assert!(again.wire.challenge.is_none());
    Ok(())
}
#[test]
fn eof_during_challenge_cannot_release_a_new_signed_request() -> TestResult {
    let mut c = new_client()?; let creds = credentials()?; let mut out = Vec::new();
    c.request(C::Describe, &creds, [0;16], 0)?;
    send(&mut c, &challenge(1, "server-nonce-1", false), 4096, 1, &mut out)?;
    c.finish(); assert!(c.respond(&creds, [17;16], 2).is_err());
    assert!(matches!(c.poll(2)?, DigestAvcPoll::Fault { reason: DigestAvcError::AuthenticationAtEof, .. }));
    Ok(())
}
#[test]
fn authenticated_teardown_preserves_remote_and_local_retirement_receipts() -> TestResult {
    let mut c = playing()?; let creds = credentials()?; let mut out = Vec::new();
    let request = c.request(C::Teardown, &creds, [20;16], 8)?;
    assert!(std::str::from_utf8(request.bytes())?.contains("Authorization: Digest"));
    send(&mut c, &response(request.cseq(), "Session: fixture\r\n", ""), 4096, 9, &mut out)?;
    assert!(out.iter().any(|e| matches!(e, DigestAvcPoll::Client { event, .. }
        if matches!(&**event, AvcClientPoll::Control(ClientProgress::Accepted(ClientState::Closed))))));
    assert!(out.iter().any(|e| match e {
        DigestAvcPoll::Client { event, wire_retirement: Some(w) } => match &**event {
            AvcClientPoll::Ended { retirement: Some(r), .. } => {
                !r.session.remote_session_may_exist && w.pending.is_empty()
            }
            _ => false,
        },
        _ => false,
    }));
    assert_eq!(c.buffered_wire_bytes(), 0); assert_eq!(c.retained_nal_bytes(), 0);
    Ok(())
}
