#![forbid(unsafe_code)]
//! HEVC negotiation shares the real RTSP lifecycle and never substitutes AVC semantics.

use fss_reference::rtsp::{RtspHeaders, RtspResponse};
use fss_reference::rtsp::client::{ClientCodec, ClientCommand as C, ClientConfig,
    ClientError as E, ClientProgress as P, ClientState as S, RtspClientSession};
use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config() -> ClientConfig {
    ClientConfig { presentation_uri: "rtsp://camera.local/live/".into(),
        control_root_uri: "rtsp://camera.local/live".into(), media_index: 0,
        channels: (0, 1), response_timeout_ns: 10_000_000_000,
        default_session_timeout_seconds: 60 }
}
fn sdp(attributes: &str) -> String {
    format!("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\n\
        m=video 0 RTP/AVP 98\r\na=rtpmap:98 H265/90000\r\n{attributes}a=control:trackID=0\r\n")
}
fn sets() -> &'static str {
    // Header-screening fixtures only; not complete decodable HEVC parameter sets.
    "a=fmtp:98 sprop-vps=QAEBAg==;sprop-sps=QgECAw==;sprop-pps=RAEDBA==\r\n"
}
fn response(cseq: u32, fields: &[(&str, &str)], body: &[u8]) -> RtspResponse {
    let mut headers = RtspHeaders::new();
    headers.insert("CSeq", cseq.to_string());
    headers.insert("Content-Length", body.len().to_string());
    for (key, value) in fields { headers.insert(*key, *value); }
    RtspResponse { version: "RTSP/1.0".into(), status_code: 200, reason: "OK".into(),
        headers, body: body.to_vec(), auth_challenge: None }
}
fn describe(body: &str) -> Result<RtspClientSession, E> {
    let mut client = RtspClientSession::with_codec(config(), ClientCodec::H265)?;
    client.request(C::Describe, 0)?;
    client.accept(&response(1, &[("Content-Type", "application/sdp")], body.as_bytes()), 1)?;
    Ok(client)
}

#[test]
fn hevc_description_retains_exact_parameter_sets_and_cannot_be_consumed_as_avc() -> TestResult {
    let mut client = describe(&sdp(sets()))?;
    assert_eq!(client.codec(), ClientCodec::H265);
    assert_eq!(client.state(), S::Described);
    assert!(client.media().is_none());
    let media = client.hevc_media().ok_or("missing HEVC negotiation")?;
    assert_eq!(media.payload_type(), 98);
    assert_eq!(media.sprop_max_don_diff(), 0);
    assert_eq!(media.vps(), &[vec![0x40, 1, 1, 2]]);
    assert_eq!(media.sps(), &[vec![0x42, 1, 2, 3]]);
    assert_eq!(media.pps(), &[vec![0x44, 1, 3, 4]]);
    assert_eq!(media.profile_signaling().profile_id, None);
    let setup = client.request(C::Setup, 2)?;
    assert!(setup.bytes().starts_with(b"SETUP rtsp://camera.local/live/trackID=0 "));
    assert!(!format!("{client:?}").contains("QAEBAg"));
    Ok(())
}

#[test]
fn missing_parameter_sets_remain_missing_and_partial_lists_are_not_completed() -> TestResult {
    for attributes in ["", "a=fmtp:98 tx-mode=SRST\r\n", "a=fmtp:98 sprop-vps=QAEBAg==\r\n"] {
        let client = describe(&sdp(attributes))?;
        let media = client.hevc_media().ok_or("missing media")?;
        assert!(media.sps().is_empty());
        assert!(media.pps().is_empty());
        assert_eq!(media.sprop_max_don_diff(), 0);
    }
    let client = describe(&sdp("a=fmtp:98 sprop-vps=QAEBAg==,QAECAw==\r\n"))?;
    assert_eq!(client.hevc_media().ok_or("missing media")?.vps(), &[vec![0x40, 1, 1, 2], vec![0x40, 1, 2, 3]]);
    Ok(())
}

#[test]
fn original_constructor_is_still_h264_only_and_never_accepts_a_server_codec_switch() -> TestResult {
    let mut avc = RtspClientSession::new(config())?;
    assert_eq!(avc.codec(), ClientCodec::H264);
    avc.request(C::Describe, 0)?;
    assert_eq!(avc.accept(&response(1, &[("Content-Type", "application/sdp")], sdp(sets()).as_bytes()), 1), Err(E::Description));
    assert_eq!(avc.state(), S::Failed);
    let h264 = sdp("").replace("H265/90000", "H264/90000");
    assert_eq!(describe(&h264).err(), Some(E::Description));
    Ok(())
}

#[test]
fn hevc_uses_the_same_setup_play_keepalive_teardown_and_remote_uncertainty_rules() -> TestResult {
    let mut client = describe(&sdp(sets()))?;
    client.request(C::Setup, 2)?;
    client.accept(&response(2, &[("Session", "private-token;timeout=60"),
        ("Transport", "RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000007")], &[]), 3)?;
    assert_eq!(client.admit_channel(0, 3), Err(E::MediaNotAdmitted));
    client.request(C::Play, 4)?;
    assert_eq!(client.accept(&response(3, &[("Session", "private-token")], &[]), 5)?, P::Accepted(S::Playing));
    client.admit_channel(0, 5)?;
    assert_eq!(client.tick(30_000_000_004)?, P::KeepAliveDue);
    client.request(C::KeepAlive, 30_000_000_004)?;
    client.accept(&response(4, &[], &[]), 30_000_000_005)?;
    client.request(C::Teardown, 30_000_000_006)?;
    assert_eq!(client.admit_channel(0, 30_000_000_006), Err(E::MediaNotAdmitted));
    client.accept(&response(5, &[("Session", "private-token")], &[]), 30_000_000_007)?;
    assert!(!client.cancel().remote_session_may_exist);
    let mut interrupted = describe(&sdp(""))?;
    interrupted.request(C::Setup, 2)?;
    assert!(interrupted.cancel().remote_session_may_exist);
    Ok(())
}

#[test]
fn hevc_digest_retry_keeps_original_deadline_and_then_negotiates_real_hevc() -> TestResult {
    let mut client = RtspClientSession::with_codec(config(), ClientCodec::H265)?;
    client.enable_digest("owner-realm", DigestPolicy::default())?;
    let credentials = DigestCredentials::new("fixture-user", "fixture-password")?;
    client.request_digest(C::Describe, &credentials, [1; 16], 0)?;
    let challenge = b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"owner-realm\", nonce=\"fixture-nonce\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n";
    let retry = client.retry_digest_response(challenge, &credentials, [2; 16], 1)?;
    assert_eq!(retry.cseq(), 2);
    assert_eq!(client.next_wake_ns(), Some(10_000_000_000));
    assert!(std::str::from_utf8(retry.bytes())?.contains("Authorization: Digest "));
    client.accept(&response(2, &[("Content-Type", "application/sdp")], sdp(sets()).as_bytes()), 2)?;
    assert!(client.hevc_media().is_some());
    assert!(client.media().is_none());
    let debug = format!("{client:?} {retry:?}");
    for secret in ["fixture-user", "fixture-password", "fixture-nonce", "owner-realm"] {
        assert!(!debug.contains(secret));
    }
    Ok(())
}

#[test]
fn unsupported_don_multi_stream_and_unknown_requirements_never_become_defaults() -> TestResult {
    for attr in ["tx-mode=MRST", "tx-mode=MRMT", "tx-mode=SRSTx", "sprop-max-don-diff=1",
        "sprop-max-don-diff=32768", "sprop-depack-buf-nalus=1", "sprop-depack-buf-bytes=1",
        "packetization-mode=1", "sprop-parameter-sets=Z0LACw==,aAE=", "unknown-required=1",
        "sprop-max-don-diff=-1", "sprop-max-don-diff=+0", "sprop-max-don-diff=0x0"] {
        assert_eq!(describe(&sdp(&format!("a=fmtp:98 {attr}\r\n"))).err(), Some(E::Description), "{attr}");
    }
    describe(&sdp("a=fmtp:98 tx-mode=SRST;sprop-max-don-diff=0;sprop-depack-buf-nalus=0;sprop-depack-buf-bytes=0\r\n"))?;
    Ok(())
}

#[test]
fn payload_rebinding_and_ambiguous_normalized_attributes_fail_closed() -> TestResult {
    for body in [
        sdp(sets()).replace("a=fmtp:98", "a=fmtp:99"),
        sdp(sets()).replace("a=rtpmap:98", "a=rtpmap:99"),
        sdp(sets()).replace("H265/90000", "H265/90000/2"),
        sdp(sets()).replace("H265/90000", "H265/8000"),
        sdp(sets()).replace("RTP/AVP 98", "RTP/AVP 98 99"),
        sdp("a=rtpmap:98 H265/90000\r\n"),
        sdp("a= rtpmap:98 H265/90000\r\n"),
        sdp("a=fmtp:98 tx-mode=SRST\r\na= fmtp:98 sprop-max-don-diff=1\r\n"),
        sdp("a=fmtp:98 sprop-max-don-diff=0;SPROP-MAX-DON-DIFF=1\r\n"),
        sdp("a=fmtp:98 tx-mode=SRST;;profile-id=1\r\n"),
        sdp("a=control:trackID=1\r\n"),
        sdp("a= control:trackID=1\r\n"),
    ] { assert_eq!(describe(&body).err(), Some(E::Description)); }
    Ok(())
}

#[test]
fn malformed_parameter_sets_are_not_retained_or_echoed() -> TestResult {
    for attr in ["sprop-vps=", "sprop-vps=QAEBAg==,", "sprop-vps=,QAEBAg==", "sprop-vps=QAE=",
        "sprop-vps=QgECAw==", "sprop-sps=RAEDBA==", "sprop-pps=QAEBAg==",
        "sprop-vps=wAEBAg==", "sprop-vps=QAEBAh==", "sprop-vps=QAEBAg==SECRET",
        "sprop-vps=QAABAg==", "sprop-vps=QAEBAg==, QAEBAg=="] {
        let error = describe(&sdp(&format!("a=fmtp:98 {attr}\r\n"))).err().ok_or("bad sets accepted")?;
        assert_eq!(error, E::Description);
        assert!(!format!("{error:?}").contains("SECRET"));
    }
    let many = std::iter::repeat_n("QAEBAg==", 17).collect::<Vec<_>>().join(",");
    assert_eq!(describe(&sdp(&format!("a=fmtp:98 sprop-vps={many}\r\n"))).err(), Some(E::Description));
    Ok(())
}

#[test]
fn explicit_media_index_prevents_automatic_selection_of_another_track_or_audio() -> TestResult {
    let body = sdp(sets()).replace("m=video", "m=audio 0 RTP/AVP 97\r\na=rtpmap:97 OPUS/48000/2\r\na=control:audio\r\nm=video");
    assert_eq!(describe(&body).err(), Some(E::Description));
    let mut cfg = config(); cfg.media_index = 1;
    let mut client = RtspClientSession::with_codec(cfg, ClientCodec::H265)?;
    client.request(C::Describe, 0)?;
    client.accept(&response(1, &[("Content-Type", "application/sdp")], body.as_bytes()), 1)?;
    assert_eq!(client.hevc_media().ok_or("explicit video not selected")?.payload_type(), 98);
    Ok(())
}

#[test]
fn multi_stream_source_specific_and_multiplexed_rtcp_signaling_is_refused() -> TestResult {
    for attr in ["a=depend:98 lay other\r\n", "a=ssrc:7 fmtp:98 sprop-vps=QAEBAg==\r\n",
        "a=ssrc-group:FID 7 8\r\n", "a=group:BUNDLE video audio\r\n", "a=rtcp-mux\r\n", "a=rtcp-mux-only\r\n"] {
        assert_eq!(describe(&sdp(attr)).err(), Some(E::Description));
    }
    let session_group = sdp(sets()).replace("a=control:*", "a=group:DDP video other\r\na=control:*");
    assert_eq!(describe(&session_group).err(), Some(E::Description));
    Ok(())
}

#[test]
fn profile_signaling_and_reduced_rtcp_are_retained_without_a_decode_claim() -> TestResult {
    let client = describe(&sdp("a=fmtp:98 profile-space=3;profile-id=1;tier-flag=1;level-id=120;interop-constraints=A0b1C2d3E4f5\r\na=rtcp-rsize\r\n"))?;
    let media = client.hevc_media().ok_or("missing media")?;
    let profile = media.profile_signaling();
    assert_eq!(profile.profile_space, Some(3));
    assert_eq!(profile.profile_id, Some(1));
    assert_eq!(profile.tier_flag, Some(1));
    assert_eq!(profile.level_id, Some(120));
    assert_eq!(profile.interop_constraints, Some([0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5]));
    assert!(media.reduced_rtcp());
    assert!(media.vps().is_empty());
    for attr in ["profile-space=4", "profile-id=32", "tier-flag=2", "level-id=256", "interop-constraints=1234",
        "interop-constraints=Z00000000000", "level-id=+120"] {
        assert_eq!(describe(&sdp(&format!("a=fmtp:98 {attr}\r\n"))).err(), Some(E::Description));
    }
    Ok(())
}

#[test]
fn hostile_control_paths_and_content_bases_never_expand_owner_scope() -> TestResult {
    for control in ["rtsp://other.local/live/track", "../private", "rtsp://name:secret@camera.local/live/track", "/private/track"] {
        assert!(describe(&sdp(sets()).replace("trackID=0", control)).is_err());
    }
    let mut client = RtspClientSession::with_codec(config(), ClientCodec::H265)?;
    client.request(C::Describe, 0)?;
    assert_eq!(client.accept(&response(1, &[("Content-Type", "application/sdp"),
        ("Content-Base", "rtsp://other.local/live/")], sdp(sets()).as_bytes()), 1), Err(E::UriScope));
    assert!(client.hevc_media().is_none());
    assert_eq!(client.state(), S::Failed);
    Ok(())
}
