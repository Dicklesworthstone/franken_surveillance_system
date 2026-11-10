#![forbid(unsafe_code)]
//! Bounded historical playback uses the native RTSP parser, session and Digest owner.

#[path = "rtsp_replay_contract/hevc.rs"]
mod hevc;

use fss_reference::rtsp::authentication::{DigestCredentials, DigestPolicy};
use fss_reference::rtsp::client::authenticated::DigestClientError;
use fss_reference::rtsp::client::replay::{
    MAX_REPLAY_DURATION_SECONDS, ReplayAcceptance, ReplayError, ReplayRejection,
    ReplayTimestamp, ReplayWindow,
};
use fss_reference::rtsp::client::{
    ClientChannel, ClientCommand as C, ClientConfig, ClientError as E, ClientProgress as P,
    ClientState as S, RtspClientSession,
};
use fss_reference::rtsp::{RtspEvent, RtspParser, RtspResponse};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SDP: &str = concat!(
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=replay fixture\r\nt=0 0\r\na=control:*\r\n",
    "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n",
    "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=,aM4PLIA=\r\n",
    "a=control:trackID=0\r\n"
);
const START: &str = "20261105T120000Z";
const END: &str = "20261105T120010Z";
const RANGE: &str = "clock=20261105T120000Z-20261105T120010Z";
const SETUP_HEADERS: &str =
    "Session: recorder-session;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=00000007\r\n";

fn config() -> ClientConfig {
    ClientConfig {
        presentation_uri: "rtsp://recorder.local/recordings/channel-1".into(),
        control_root_uri: "rtsp://recorder.local/recordings".into(),
        media_index: 0,
        channels: (0, 1),
        response_timeout_ns: 1_000,
        default_session_timeout_seconds: 60,
    }
}

fn response(cseq: u32, status: u16, headers: &str, body: &str)
    -> Result<RtspResponse, Box<dyn std::error::Error>>
{
    let bytes = format!(
        "RTSP/1.0 {status} fixture\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    );
    let mut parsed = RtspParser::new().feed(bytes.as_bytes())?;
    match parsed.pop() {
        Some(RtspEvent::Response(value)) if parsed.is_empty() => Ok(value),
        _ => Err("expected one complete native response".into()),
    }
}

fn described() -> Result<RtspClientSession, Box<dyn std::error::Error>> {
    let mut client = RtspClientSession::new(config())?;
    assert_eq!(client.request(C::Describe, 0)?.cseq(), 1);
    assert_eq!(
        client.accept(&response(1, 200, "Content-Type: application/sdp\r\n", SDP)?, 1)?,
        P::Accepted(S::Described)
    );
    Ok(client)
}

fn ready(replay: bool) -> Result<RtspClientSession, Box<dyn std::error::Error>> {
    let mut client = described()?;
    let command = if replay { C::SetupReplay } else { C::Setup };
    assert_eq!(client.request(command, 2)?.cseq(), 2);
    assert_eq!(
        client.accept(&response(2, 200, SETUP_HEADERS, "")?, 3)?,
        P::Accepted(S::Ready)
    );
    Ok(client)
}

fn window() -> Result<ReplayWindow, ReplayError> {
    ReplayWindow::from_timestamps(START, END)
}

fn play_response(cseq: u32, range: &str)
    -> Result<RtspResponse, Box<dyn std::error::Error>>
{
    response(cseq, 200, &format!("Session: recorder-session\r\nRange: {range}\r\n"), "")
}

#[test]
fn utc_calendar_coordinates_and_canonical_fraction_are_exact() -> TestResult {
    for (input, canonical, nanos) in [
        ("19700101T000000Z", "19700101T000000Z", 0_u128),
        ("20000101T000000.000000000Z", "20000101T000000Z", 946_684_800_000_000_000),
        ("20240229T000000.120000000Z", "20240229T000000.12Z", 1_709_164_800_120_000_000),
        ("21000301T000000.000000001Z", "21000301T000000.000000001Z", 4_107_542_400_000_000_001),
        ("99991231T235959.999999999Z", "99991231T235959.999999999Z", 253_402_300_799_999_999_999),
    ] {
        let timestamp = ReplayTimestamp::parse(input)?;
        assert_eq!(timestamp.to_string(), canonical);
        assert_eq!(timestamp.unix_nanoseconds(), nanos);
        assert_eq!(ReplayTimestamp::parse(canonical)?, timestamp);
    }
    for fraction in ["1", "01", "001", "0001", "00001", "000001", "0000001", "00000001", "000000001"] {
        let source = format!("20261105T120000.{fraction}Z");
        assert_eq!(ReplayTimestamp::parse(&source)?.to_string(), source);
    }
    Ok(())
}

#[test]
fn malformed_calendar_and_time_syntax_are_never_normalized() {
    for invalid in [
        "", "19691231T235959Z", "00000101T000000Z", "100000101T000000Z",
        "20261301T000000Z", "20260001T000000Z", "20260100T000000Z",
        "20260431T000000Z", "20260229T000000Z", "21000229T000000Z",
        "20261105T240000Z", "20261105T126000Z", "20261105T120060Z",
        "20261105t120000Z", "20261105T120000z", "20261105T120000",
        "2026-11-05T12:00:00Z", "20261105T120000+0000",
        "20261105T120000.Z", "20261105T120000.1234567890Z",
        "20261105T120000.-1Z", "20261105T120000.1e2Z",
        " 20261105T120000Z", "20261105T120000Z ", "20261105T120000Z\r\nX: 1",
        "２０２６1105T120000Z",
    ] {
        assert_eq!(ReplayTimestamp::parse(invalid), Err(ReplayError::Timestamp), "{invalid}");
    }
    let source = "20261105T120000.123456789Z";
    for cut in 0..source.len() {
        assert!(ReplayTimestamp::parse(&source[..cut]).is_err());
    }
}

#[test]
fn nonempty_forward_windows_enforce_exact_seven_day_bound() -> TestResult {
    assert_eq!(MAX_REPLAY_DURATION_SECONDS, 604_800);
    let full = ReplayWindow::from_timestamps("20240228T000000.1Z", "20240306T000000.1Z")?;
    assert_eq!(full.duration_ns(), u128::from(MAX_REPLAY_DURATION_SECONDS) * 1_000_000_000);
    assert_eq!(
        ReplayWindow::from_timestamps("20240228T000000.1Z", "20240306T000000.100000001Z"),
        Err(ReplayError::DurationLimit)
    );
    assert_eq!(ReplayWindow::from_timestamps(START, START), Err(ReplayError::WindowOrder));
    assert_eq!(ReplayWindow::from_timestamps(END, START), Err(ReplayError::WindowOrder));
    let single_ns = ReplayWindow::from_timestamps(
        "20261105T120000.999999999Z", "20261105T120001Z"
    )?;
    assert_eq!(single_ns.duration_ns(), 1);
    assert_eq!(ReplayWindow::parse(&single_ns.to_string())?, single_ns);
    assert_eq!(ReplayWindow::parse("CLOCK=20261105T120000.00Z-20261105T120010.0Z")?, window()?);
    Ok(())
}

#[test]
fn open_multiple_reverse_and_scheduled_range_profiles_are_refused() {
    for invalid in [
        "npt=0-10", "clock=-20261105T120010Z", "clock=20261105T120000Z-",
        "clock=20261105T120000Z", "clock=now-20261105T120010Z",
        "clock=20261105T120010Z-20261105T120000Z",
        "clock=20261105T120000Z-20261105T120010Z;time=20261105T120020Z",
        "clock=20261105T120000Z-20261105T120010Z,20261105T120020Z-20261105T120030Z",
        " clock=20261105T120000Z-20261105T120010Z",
        "clock=20261105T120000Z-20261105T120010Z ",
        "clock=20261105T120000Z--20261105T120010Z",
    ] {
        assert!(ReplayWindow::parse(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn acceptance_requires_correlation_and_containment_to_the_nanosecond() -> TestResult {
    let requested = window()?;
    assert_eq!(ReplayAcceptance::new(0, requested, requested), Err(ReplayError::Correlation));
    let inner = ReplayWindow::from_timestamps("20261105T120000.000000001Z", "20261105T120009.999999999Z")?;
    let accepted = ReplayAcceptance::new(7, requested, inner)?;
    assert_eq!(accepted.cseq(), 7);
    assert_eq!(accepted.requested(), requested);
    assert_eq!(accepted.acknowledged(), inner);
    assert!(requested.contains(inner));
    assert!(!inner.contains(requested));
    for (start, end) in [
        ("20261105T115959.999999999Z", END),
        (START, "20261105T120010.000000001Z"),
        ("20261105T120010Z", "20261105T120020Z"),
    ] {
        assert_eq!(
            ReplayAcceptance::new(1, requested, ReplayWindow::from_timestamps(start, end)?),
            Err(ReplayError::WidenedRange)
        );
    }
    Ok(())
}

#[test]
fn live_setup_and_play_wire_bytes_remain_exactly_unchanged() -> TestResult {
    let mut client = described()?;
    assert_eq!(
        client.request(C::Setup, 2)?.bytes(),
        b"SETUP rtsp://recorder.local/recordings/trackID=0 RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n"
    );
    client.accept(&response(2, 200, SETUP_HEADERS, "")?, 3)?;
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
fn explicit_replay_wire_and_narrowed_acceptance_preserve_all_three_coordinates() -> TestResult {
    let mut client = described()?;
    assert_eq!(
        client.request(C::SetupReplay, 2)?.bytes(),
        b"SETUP rtsp://recorder.local/recordings/trackID=0 RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\nRequire: onvif-replay\r\n\r\n"
    );
    client.accept(&response(2, 200, SETUP_HEADERS, "")?, 3)?;
    assert_eq!(client.admit_channel(0, 3), Err(E::MediaNotAdmitted));
    let request = client.request(C::PlayReplay(window()?), 4)?;
    assert_eq!(request.command(), C::PlayReplay(window()?));
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
    assert!(client.request(C::PlayReplay(window()?), 6).is_err());
    assert!(client.request(C::Play, 6).is_err());
    let keepalive = client.request(C::KeepAlive, 6)?;
    assert_eq!(
        keepalive.bytes(),
        b"OPTIONS rtsp://recorder.local/recordings/channel-1 RTSP/1.0\r\nCSeq: 4\r\nSession: recorder-session\r\n\r\n"
    );
    client.accept(&response(4, 200, "", "")?, 7)?;
    client.request(C::Teardown, 8)?;
    assert_eq!(client.accept(&response(5, 200, "Session: recorder-session\r\n", "")?, 9)?, P::Accepted(S::Closed));
    assert!(!client.cancel().remote_session_may_exist);
    Ok(())
}

#[test]
fn live_and_replay_setup_cannot_authorize_each_others_play() -> TestResult {
    let mut live = ready(false)?;
    assert_eq!(live.request(C::PlayReplay(window()?), 4).err(), Some(E::State));
    assert_eq!(live.request(C::Play, 4)?.cseq(), 3);
    let mut replay = ready(true)?;
    assert_eq!(replay.request(C::Play, 4).err(), Some(E::State));
    assert_eq!(replay.request(C::PlayReplay(window()?), 4)?.cseq(), 3);
    Ok(())
}

#[test]
fn absent_duplicate_invalid_or_widened_acknowledgements_never_admit_media() -> TestResult {
    let cases = [
        ("Session: recorder-session\r\n".to_owned(), ReplayError::MissingRange),
        (format!("Session: recorder-session\r\nRange: {RANGE}\r\nrange: {RANGE}\r\n"), ReplayError::DuplicateRange),
        ("Session: recorder-session\r\nRange: npt=0-10\r\n".into(), ReplayError::Range),
        ("Session: recorder-session\r\nRange: clock=20261105T120000Z-\r\n".into(), ReplayError::Timestamp),
        ("Session: recorder-session\r\nRange: clock=20261105T120010Z-20261105T120000Z\r\n".into(), ReplayError::WindowOrder),
        ("Session: recorder-session\r\nRange: clock=20261105T115959.999999999Z-20261105T120010Z\r\n".into(), ReplayError::WidenedRange),
        ("Session: recorder-session\r\nRange: clock=20261105T120000Z-20261105T120010.000000001Z\r\n".into(), ReplayError::WidenedRange),
    ];
    for (headers, expected) in cases {
        let mut client = ready(true)?;
        client.request(C::PlayReplay(window()?), 4)?;
        assert_eq!(client.accept(&response(3, 200, &headers, "")?, 5), Err(E::Replay(expected)));
        assert_eq!(client.state(), S::Failed);
        assert!(client.admit_channel(0, 5).is_err());
        assert!(client.request(C::Play, 5).is_err());
        assert_eq!(client.cancel().pending_cseq, Some(3));
    }
    Ok(())
}

#[test]
fn matching_cseq_and_session_are_required_before_replay_acceptance() -> TestResult {
    let mut client = ready(true)?;
    client.request(C::PlayReplay(window()?), 4)?;
    assert_eq!(client.accept(&play_response(99, "invalid")?, 5), Err(E::CseqMismatch));
    assert_eq!(client.state(), S::Ready);
    assert_eq!(
        client.accept(&play_response(3, RANGE)?, 6)?,
        P::ReplayAccepted(ReplayAcceptance::new(3, window()?, window()?)?)
    );
    for session in ["", "Session: changed-session\r\n", "Session: recorder-session\r\nSession: recorder-session\r\n"] {
        let mut client = ready(true)?;
        client.request(C::PlayReplay(window()?), 4)?;
        let headers = format!("{session}Range: {RANGE}\r\n");
        assert!(client.accept(&response(3, 200, &headers, "")?, 5).is_err());
        assert_eq!(client.state(), S::Failed);
    }
    Ok(())
}

#[test]
fn optional_policy_echoes_must_agree_without_float_rounding_or_duplicates() -> TestResult {
    for policy in [
        "Rate-Control: yes\r\n",
        "Rate-Control: no\r\nrate-control: no\r\n",
        "Rate-Control: unknown\r\n",
        "Scale: -1.0\r\n",
        "Scale: 2\r\n",
        "Scale: 0\r\n",
        "Scale: 1.00000000000000001\r\n",
        "Scale: 1e0\r\n",
        "Scale: 1.0\r\nscale: 1.0\r\n",
    ] {
        let mut client = ready(true)?;
        client.request(C::PlayReplay(window()?), 4)?;
        let headers = format!("Session: recorder-session\r\nRange: {RANGE}\r\n{policy}");
        assert_eq!(
            client.accept(&response(3, 200, &headers, "")?, 5),
            Err(E::Replay(ReplayError::ResponsePolicy)),
            "{policy}"
        );
        assert_eq!(client.state(), S::Failed);
        assert!(client.admit_channel(0, 5).is_err());
    }
    for policy in [
        "",
        "Rate-Control: no\r\n",
        "Scale: 1\r\n",
        "Scale: +1.000\r\n",
        "Scale: 01.0\r\nRate-Control: no\r\n",
        "Scale: 1.\r\n",
    ] {
        let mut client = ready(true)?;
        client.request(C::PlayReplay(window()?), 4)?;
        let headers = format!("Session: recorder-session\r\nRange: {RANGE}\r\n{policy}");
        assert_eq!(
            client.accept(&response(3, 200, &headers, "")?, 5)?,
            P::ReplayAccepted(ReplayAcceptance::new(3, window()?, window()?)?)
        );
    }
    Ok(())
}

#[test]
fn replay_rejections_are_specific_and_do_not_change_live_status_handling() -> TestResult {
    for rejection in [
        ReplayRejection::HeaderNotValidForResource,
        ReplayRejection::RangeRejected,
        ReplayRejection::OptionNotSupported,
    ] {
        let status = rejection.status_code();
        for setup in [true, false] {
            let mut client = if setup { described()? } else { ready(true)? };
            let command = if setup { C::SetupReplay } else { C::PlayReplay(window()?) };
            let cseq = client.request(command, 4)?.cseq();
            assert_eq!(
                client.accept(&response(cseq, status, "", "")?, 5),
                Err(E::ReplayRejected(rejection))
            );
            assert_eq!(client.state(), S::Failed);
            assert!(client.request(C::Play, 6).is_err());
        }
        let mut live = ready(false)?;
        live.request(C::Play, 4)?;
        assert_eq!(live.accept(&response(3, status, "", "")?, 5), Err(E::Rejected(status)));
    }
    Ok(())
}

#[test]
fn replay_expiry_cancel_and_interim_never_manufacture_an_acknowledgement() -> TestResult {
    let mut client = ready(true)?;
    client.request(C::PlayReplay(window()?), 4)?;
    assert_eq!(client.accept(&response(3, 100, "", "")?, 5)?, P::Interim);
    assert_eq!(client.state(), S::Ready);
    assert_eq!(client.next_wake_ns(), Some(1_004));
    assert_eq!(client.accept(&play_response(3, RANGE)?, 1_004), Err(E::ResponseTimeout));
    assert_eq!(client.state(), S::Failed);
    let mut client = ready(true)?;
    client.request(C::PlayReplay(window()?), 4)?;
    let cancelled = client.cancel();
    assert!(cancelled.remote_session_may_exist);
    assert_eq!(cancelled.pending_cseq, Some(3));
    assert_eq!(client.accept(&play_response(3, RANGE)?, 5), Err(E::State));
    Ok(())
}

fn challenge(cseq: u32, nonce: &str, stale: bool) -> Vec<u8> {
    let extra = if stale { ", stale=true" } else { "" };
    format!(
        "RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Digest realm=\"recorder\", nonce=\"{nonce}\", algorithm=SHA-256, qop=\"auth\"{extra}\r\nContent-Length: 0\r\n\r\n"
    ).into_bytes()
}

#[test]
fn digest_replay_keeps_range_and_option_but_reports_the_successful_retry_cseq() -> TestResult {
    let mut client = RtspClientSession::new(config())?;
    client.enable_digest("recorder", DigestPolicy::default())?;
    let credentials = DigestCredentials::new("operator", "private-fixture-password")?;
    client.request_digest(C::Describe, &credentials, [1; 16], 0)?;
    client.accept(&response(1, 200, "Content-Type: application/sdp\r\n", SDP)?, 1)?;
    client.request_digest(C::SetupReplay, &credentials, [2; 16], 2)?;
    let setup = client.retry_digest_response(&challenge(2, "setup-nonce", false), &credentials, [3; 16], 3)?;
    assert_eq!(setup.cseq(), 3);
    let setup_wire = std::str::from_utf8(setup.bytes())?;
    assert!(setup_wire.starts_with("SETUP rtsp://recorder.local/recordings/trackID=0 "));
    assert!(setup_wire.contains("Require: onvif-replay\r\n"));
    assert!(setup_wire.contains("uri=\"rtsp://recorder.local/recordings/trackID=0\""));
    client.accept(&response(3, 200, SETUP_HEADERS, "")?, 4)?;
    let play = client.request_digest(C::PlayReplay(window()?), &credentials, [4; 16], 5)?;
    assert_eq!(play.cseq(), 4);
    assert_eq!(client.next_wake_ns(), Some(1_005));
    let retry = client.retry_digest_response(&challenge(4, "play-nonce", true), &credentials, [5; 16], 6)?;
    assert_eq!(retry.cseq(), 5);
    assert_eq!(retry.command(), C::PlayReplay(window()?));
    assert_eq!(client.next_wake_ns(), Some(1_005));
    for request in [&play, &retry] {
        let wire = std::str::from_utf8(request.bytes())?;
        assert!(wire.starts_with("PLAY rtsp://recorder.local/recordings/channel-1 "));
        assert!(wire.contains("Require: onvif-replay\r\n"));
        assert!(wire.contains(&format!("Range: {RANGE}\r\n")));
        assert!(wire.contains("Rate-Control: no\r\n"));
        assert!(wire.contains("uri=\"rtsp://recorder.local/recordings/channel-1\""));
        assert!(!wire.contains("private-fixture-password"));
    }
    assert_eq!(client.accept(&play_response(4, RANGE)?, 7), Err(E::CseqMismatch));
    assert_eq!(
        client.accept(&play_response(5, RANGE)?, 8)?,
        P::ReplayAccepted(ReplayAcceptance::new(5, window()?, window()?)?)
    );
    Ok(())
}

#[test]
fn digest_retry_does_not_extend_replay_response_lifetime() -> TestResult {
    let mut client = RtspClientSession::new(config())?;
    client.enable_digest("recorder", DigestPolicy::default())?;
    let credentials = DigestCredentials::new("operator", "private-fixture-password")?;
    client.request_digest(C::Describe, &credentials, [1; 16], 0)?;
    client.accept(&response(1, 200, "Content-Type: application/sdp\r\n", SDP)?, 1)?;
    client.request_digest(C::SetupReplay, &credentials, [2; 16], 2)?;
    client.accept(&response(2, 200, SETUP_HEADERS, "")?, 3)?;
    client.request_digest(C::PlayReplay(window()?), &credentials, [3; 16], 4)?;
    client.retry_digest_response(&challenge(3, "first", false), &credentials, [4; 16], 5)?;
    client.retry_digest_response(&challenge(4, "second", true), &credentials, [5; 16], 6)?;
    assert_eq!(client.next_wake_ns(), Some(1_004));
    assert!(matches!(
        client.retry_digest_response(&challenge(5, "third", true), &credentials, [6; 16], 1_004),
        Err(DigestClientError::Session(E::ResponseTimeout))
    ));
    assert_eq!(client.state(), S::Failed);
    assert!(client.admit_channel(0, 1_004).is_err());
    Ok(())
}
