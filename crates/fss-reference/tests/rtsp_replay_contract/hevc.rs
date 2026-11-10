#![forbid(unsafe_code)]
//! Recorder replay uses the same exact session contract for AVC and HEVC.
//! The small SDP parameter sets screen signaling only; archive/CLI tests exercise decoding.

use super::*;
use fss_reference::rtsp::client::ClientCodec;

const HEVC_SDP: &str = concat!(
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=HEVC replay fixture\r\nt=0 0\r\na=control:*\r\n",
    "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\n",
    "a=fmtp:96 sprop-max-don-diff=0;sprop-vps=QAEM;sprop-sps=QgEM;sprop-pps=RAHA\r\n",
    "a=control:trackID=0\r\n"
);

fn described_codec(
    codec: ClientCodec,
    payload: u8,
    sdp: &str,
) -> Result<RtspClientSession, Box<dyn std::error::Error>> {
    let mut client = RtspClientSession::with_codec_and_payload_type(config(), codec, payload)?;
    assert_eq!(client.request(C::Describe, 0)?.cseq(), 1);
    assert_eq!(
        client.accept(&response(1, 200, "Content-Type: application/sdp\r\n", sdp)?, 1)?,
        P::Accepted(S::Described)
    );
    Ok(client)
}

fn hevc_described() -> Result<RtspClientSession, Box<dyn std::error::Error>> {
    let client = described_codec(ClientCodec::H265, 96, HEVC_SDP)?;
    assert_eq!(client.codec(), ClientCodec::H265);
    assert!(client.media().is_none());
    assert_eq!(client.hevc_media().ok_or("HEVC selection missing")?.payload_type(), 96);
    Ok(client)
}

fn hevc_ready(replay: bool) -> Result<RtspClientSession, Box<dyn std::error::Error>> {
    let mut client = hevc_described()?;
    assert_eq!(
        client.request(if replay { C::SetupReplay } else { C::Setup }, 2)?.cseq(),
        2
    );
    assert_eq!(
        client.accept(&response(2, 200, SETUP_HEADERS, "")?, 3)?,
        P::Accepted(S::Ready)
    );
    Ok(client)
}

#[test]
fn hevc_replay_keeps_exact_scoped_wire_and_requires_a_contained_acknowledgement() -> TestResult {
    let mut client = hevc_described()?;
    assert_eq!(
        client.request(C::SetupReplay, 2)?.bytes(),
        b"SETUP rtsp://recorder.local/recordings/trackID=0 RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\nRequire: onvif-replay\r\n\r\n"
    );
    client.accept(&response(2, 200, SETUP_HEADERS, "")?, 3)?;
    assert_eq!(client.server_ssrc(), Some(7));
    assert_eq!(client.admit_channel(0, 3), Err(E::MediaNotAdmitted));
    assert_eq!(client.request(C::Play, 4).err(), Some(E::State));
    let request = client.request(C::PlayReplay(window()?), 4)?;
    assert_eq!(request.cseq(), 3);
    assert_eq!(
        request.bytes(),
        b"PLAY rtsp://recorder.local/recordings/channel-1 RTSP/1.0\r\nCSeq: 3\r\nSession: recorder-session\r\nRequire: onvif-replay\r\nRange: clock=20261105T120000Z-20261105T120010Z\r\nRate-Control: no\r\n\r\n"
    );
    assert_eq!(client.admit_channel(0, 4), Err(E::MediaNotAdmitted));
    let ack = ReplayWindow::from_timestamps("20261105T120001Z", "20261105T120009Z")?;
    assert_eq!(
        client.accept(&play_response(3, &ack.to_string())?, 5)?,
        P::ReplayAccepted(ReplayAcceptance::new(3, window()?, ack)?)
    );
    assert_eq!(client.state(), S::Playing);
    assert_eq!(client.admit_channel(0, 5)?, ClientChannel::Rtp);
    assert_eq!(client.admit_channel(1, 5)?, ClientChannel::Rtcp);
    assert!(client.request(C::Play, 6).is_err());
    assert!(client.request(C::PlayReplay(window()?), 6).is_err());
    let teardown = client.request(C::Teardown, 6)?;
    assert_eq!(teardown.cseq(), 4);
    assert_eq!(
        client.accept(&response(4, 200, "Session: recorder-session\r\n", "")?, 7)?,
        P::Accepted(S::Closed)
    );
    assert!(!client.cancel().remote_session_may_exist);
    Ok(())
}

#[test]
fn hevc_live_setup_cannot_be_reinterpreted_as_replay() -> TestResult {
    let mut client = hevc_ready(false)?;
    assert_eq!(client.request(C::PlayReplay(window()?), 4).err(), Some(E::State));
    assert_eq!(
        client.request(C::Play, 4)?.bytes(),
        b"PLAY rtsp://recorder.local/recordings/channel-1 RTSP/1.0\r\nCSeq: 3\r\nSession: recorder-session\r\n\r\n"
    );
    assert_eq!(
        client.accept(&response(3, 200, "Session: recorder-session\r\n", "")?, 5)?,
        P::Accepted(S::Playing)
    );
    Ok(())
}

#[test]
fn hevc_bad_replay_acknowledgements_close_admission_without_live_fallback() -> TestResult {
    for (headers, expected) in [
        ("Session: recorder-session\r\n".to_owned(), ReplayError::MissingRange),
        (
            format!("Session: recorder-session\r\nRange: {RANGE}\r\nrange: {RANGE}\r\n"),
            ReplayError::DuplicateRange,
        ),
        (
            "Session: recorder-session\r\nRange: npt=0-10\r\n".to_owned(),
            ReplayError::Range,
        ),
        (
            "Session: recorder-session\r\nRange: clock=20261105T115959Z-20261105T120010Z\r\n"
                .to_owned(),
            ReplayError::WidenedRange,
        ),
        (
            format!("Session: recorder-session\r\nRange: {RANGE}\r\nRate-Control: yes\r\n"),
            ReplayError::ResponsePolicy,
        ),
    ] {
        let mut client = hevc_ready(true)?;
        client.request(C::PlayReplay(window()?), 4)?;
        assert_eq!(
            client.accept(&response(3, 200, &headers, "")?, 5),
            Err(E::Replay(expected))
        );
        assert_eq!(client.state(), S::Failed);
        assert!(client.admit_channel(0, 5).is_err());
        assert!(client.request(C::Play, 6).is_err());
        let retired = client.cancel();
        assert!(retired.remote_session_may_exist);
        assert_eq!(retired.pending_cseq, Some(3));
    }
    Ok(())
}

#[test]
fn hevc_recorder_status_refusals_keep_their_typed_replay_meaning() -> TestResult {
    for rejection in [
        ReplayRejection::HeaderNotValidForResource,
        ReplayRejection::RangeRejected,
        ReplayRejection::OptionNotSupported,
    ] {
        for setup in [true, false] {
            let mut client = if setup { hevc_described()? } else { hevc_ready(true)? };
            let command = if setup { C::SetupReplay } else { C::PlayReplay(window()?) };
            let cseq = client.request(command, 4)?.cseq();
            assert_eq!(
                client.accept(&response(cseq, rejection.status_code(), "", "")?, 5),
                Err(E::ReplayRejected(rejection))
            );
            assert_eq!(client.state(), S::Failed);
            assert!(client.request(C::Play, 6).is_err());
            assert!(client.admit_channel(0, 6).is_err());
        }
    }
    Ok(())
}

#[test]
fn hevc_digest_replay_preserves_intent_correlation_and_the_original_deadline() -> TestResult {
    for expire in [false, true] {
        let mut client =
            RtspClientSession::with_codec_and_payload_type(config(), ClientCodec::H265, 96)?;
        client.enable_digest("recorder", DigestPolicy::default())?;
        let credentials = DigestCredentials::new("operator", "private-fixture-password")?;
        client.request_digest(C::Describe, &credentials, [1; 16], 0)?;
        client.accept(&response(1, 200, "Content-Type: application/sdp\r\n", HEVC_SDP)?, 1)?;
        client.request_digest(C::SetupReplay, &credentials, [2; 16], 2)?;
        let setup = client.retry_digest_response(
            &challenge(2, "setup-nonce", false),
            &credentials,
            [3; 16],
            3,
        )?;
        assert_eq!(setup.cseq(), 3);
        assert_eq!(setup.command(), C::SetupReplay);
        let wire = std::str::from_utf8(setup.bytes())?;
        assert!(wire.starts_with("SETUP rtsp://recorder.local/recordings/trackID=0 "));
        assert!(wire.contains("Require: onvif-replay\r\n"));
        assert!(wire.contains("uri=\"rtsp://recorder.local/recordings/trackID=0\""));
        client.accept(&response(3, 200, SETUP_HEADERS, "")?, 4)?;
        client.request_digest(C::PlayReplay(window()?), &credentials, [4; 16], 5)?;
        let retry = client.retry_digest_response(
            &challenge(4, "play-nonce", true),
            &credentials,
            [5; 16],
            6,
        )?;
        assert_eq!(retry.cseq(), 5);
        assert_eq!(retry.command(), C::PlayReplay(window()?));
        let wire = std::str::from_utf8(retry.bytes())?;
        assert!(wire.starts_with("PLAY rtsp://recorder.local/recordings/channel-1 "));
        assert!(wire.contains("Require: onvif-replay\r\n"));
        assert!(wire.contains(&format!("Range: {RANGE}\r\n")));
        assert!(wire.contains("Rate-Control: no\r\n"));
        assert!(wire.contains("uri=\"rtsp://recorder.local/recordings/channel-1\""));
        assert!(!wire.contains("private-fixture-password"));
        assert_eq!(client.next_wake_ns(), Some(1_005));
        if expire {
            assert_eq!(
                client.accept(&play_response(5, RANGE)?, 1_005),
                Err(E::ResponseTimeout)
            );
            assert_eq!(client.state(), S::Failed);
            assert!(client.admit_channel(0, 1_005).is_err());
        } else {
            assert_eq!(client.accept(&play_response(4, RANGE)?, 7), Err(E::CseqMismatch));
            assert_eq!(
                client.accept(&play_response(5, RANGE)?, 8)?,
                P::ReplayAccepted(ReplayAcceptance::new(5, window()?, window()?)?)
            );
        }
    }
    Ok(())
}

#[test]
fn hevc_replay_support_does_not_admit_jpeg_or_metadata_replay() -> TestResult {
    for (codec, media) in [
        (ClientCodec::Jpeg, "m=video 0 RTP/AVP 96\r\na=rtpmap:96 JPEG/90000\r\n"),
        (
            ClientCodec::OnvifMetadata,
            "m=application 0 RTP/AVP 96\r\na=rtpmap:96 vnd.onvif.metadata/90000\r\n",
        ),
    ] {
        let sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=unsupported replay fixture\r\nt=0 0\r\na=control:*\r\n{media}a=control:trackID=0\r\n"
        );
        let mut client = described_codec(codec, 96, &sdp)?;
        assert_eq!(client.request(C::SetupReplay, 2).err(), Some(E::State));
        assert_eq!(client.state(), S::Described);
        assert_eq!(client.request(C::Setup, 2)?.cseq(), 2);
        client.accept(&response(2, 200, SETUP_HEADERS, "")?, 3)?;
        assert_eq!(client.request(C::PlayReplay(window()?), 4).err(), Some(E::State));
        assert_eq!(client.request(C::Play, 4)?.cseq(), 3);
    }
    Ok(())
}
