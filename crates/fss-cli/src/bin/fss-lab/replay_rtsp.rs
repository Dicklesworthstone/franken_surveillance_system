#![forbid(unsafe_code)]
//! Offline replay of a recorded interleaved AVC session using the native client.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_packet::StreamKey;
use fss_packet::avc::{AvcReceiveLimits, AvcReceivePoll};
use fss_reference::ReplayCx;
use fss_reference::media_fixture::{TranscriptDirection, parse_transcript_bounded};
use fss_reference::rtsp::avc_client::{AvcClientPoll, RtspAvcClient};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientProgress, ClientState};
use fss_reference::rtsp::tcp::SsrcPolicy;
use fss_reference::rtsp::{RtspEvent, RtspMethod, RtspParser, RtspRequest};

const MAX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RECORDS: usize = 8192;
const SCHEMA: &str = "fss.lab.rtsp_replay.v1";

pub(super) fn run(input: &Path) -> Result<String, String> {
    let error = |e: &dyn std::fmt::Display| e.to_string();
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:lab:rtsp-replay".into(),
        operation_id: OperationId::parse("op:lab:rtsp-replay").map_err(|e| error(&e))?,
        principal: "operator:lab".into(),
        capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(MAX_BYTES + 1)
            .build()
            .map_err(|e| error(&e))?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:no-publication".into(),
        anchor_universe: ContentDigest::sha256(SCHEMA.as_bytes()),
        generation: 1,
    })
    .map_err(|e| error(&e))?;
    let parent = input
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|_| "cannot resolve transcript directory")?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, parent)
        .map_err(|e| error(&e))?;
    let result = (|| {
        let check = || {
            cx.checkpoint("lab:rtsp-replay")
                .map_err(|_| "replay cancelled")
        };
        check()?;
        let metadata = fs::symlink_metadata(input).map_err(|_| "cannot inspect transcript")?;
        if !metadata.is_file() || metadata.len() > MAX_BYTES {
            return Err("transcript must be a regular file of at most 8 MiB".into());
        }
        let file = File::open(input).map_err(|_| "cannot open transcript")?;
        let opened = file.metadata().map_err(|_| "cannot inspect opened transcript")?;
        if !opened.is_file() || opened.len() > MAX_BYTES {
            return Err("opened transcript exceeds regular file bounds".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "transcript read failed")?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err("transcript byte limit".into());
        }
        check()?;
        replay(&bytes, check)
    })();
    cx.drain_and_finalize();
    result
}

#[derive(Default)]
struct Summary {
    rtp: usize,
    rtcp: usize,
    invalid_rtcp: usize,
    gaps: usize,
    states: Vec<&'static str>,
    ended: bool,
}

fn request(
    cmd: &RtspRequest,
    client: &mut RtspAvcClient,
    now: u64,
    presentation: &str,
) -> Result<(), String> {
    if cmd.headers.get("Authorization").is_some()
        || cmd.headers.get("Proxy-Authorization").is_some()
    {
        return Err("recorded credentials refused".into());
    }
    for header in ["Session", "Transport", "Range"] {
        let count = cmd.headers.iter().filter(|h| h.name.eq_ignore_ascii_case(header)).count();
        if count > 1 {
            return Err("ambiguous recorded request headers".into());
        }
    }
    let method = match cmd.method {
        RtspMethod::Options if client.state() == ClientState::Playing => ClientCommand::KeepAlive,
        RtspMethod::Options => ClientCommand::Options,
        RtspMethod::Describe => ClientCommand::Describe,
        RtspMethod::Setup => ClientCommand::Setup,
        RtspMethod::Play => ClientCommand::Play,
        RtspMethod::GetParameter => ClientCommand::KeepAliveGetParameter,
        RtspMethod::Teardown => ClientCommand::Teardown,
        _ => return Err("unsupported recorded request".into()),
    };
    let prepared = client.request(method, now).map_err(|e| e.to_string())?;
    let events = RtspParser::new()
        .feed(prepared.bytes())
        .map_err(|e| e.to_string())?;
    let [RtspEvent::Request(expected)] = events.as_slice() else {
        return Err("invalid prepared request".into());
    };
    // Some single-track recorders send the presentation URI for session-wide commands.
    // Only exact byte equality to the initial presentation URI is an alias. SETUP still
    // names the negotiated track, and every request matches the native session and CSeq.
    let session_target = matches!(
        method,
        ClientCommand::Play
            | ClientCommand::KeepAlive
            | ClientCommand::KeepAliveGetParameter
            | ClientCommand::Teardown
    ) && cmd.uri == presentation;
    if (cmd.uri != expected.uri && !session_target)
        || cmd.headers.cseq().transpose().map_err(|e| e.to_string())? != Some(prepared.cseq())
        || cmd.headers.session_id() != expected.headers.session_id()
        || cmd.headers.get("Transport") != expected.headers.get("Transport")
        || !cmd.body.is_empty()
        || ["Require", "Proxy-Require", "Scale", "Speed", "Rate-Control"]
            .iter()
            .any(|h| cmd.headers.get(h).is_some())
        || cmd.headers.get("Range").is_some_and(|range| {
            method != ClientCommand::Play || range != "npt=0-"
        })
    {
        return Err("recorded request differs from the negotiated session".into());
    }
    Ok(())
}

fn state_name(state: ClientState) -> &'static str {
    match state {
        ClientState::Idle => "idle",
        ClientState::Described => "described",
        ClientState::Ready => "ready",
        ClientState::Playing => "playing",
        ClientState::Closing => "closing",
        ClientState::Closed => "closed",
        ClientState::Failed => "failed",
    }
}

impl Summary {
    fn drain(&mut self, client: &mut RtspAvcClient, now: u64) -> Result<(), String> {
        // Bounded work at the recorded offset; never advance time to manufacture admission.
        for _ in 0..8192 {
            match client.poll(now).map_err(|e| e.to_string())? {
                AvcClientPoll::Control(ClientProgress::Accepted(s)) => {
                    self.states.push(state_name(s));
                }
                AvcClientPoll::Rtp { retirement, .. } => {
                    if retirement.is_some() {
                        return Err("source epoch restarted".into());
                    }
                    self.rtp += 1;
                }
                AvcClientPoll::Rtcp { validation, .. } => {
                    self.rtcp += 1;
                    self.invalid_rtcp += usize::from(validation.is_err());
                }
                AvcClientPoll::Media(AvcReceivePoll::Gap { .. }) => self.gaps += 1,
                AvcClientPoll::Control(ClientProgress::KeepAliveDue) => return Ok(()),
                AvcClientPoll::Control(_) | AvcClientPoll::Media(_) => {}
                AvcClientPoll::Backpressure { .. } => {
                    return Err("replay backpressure at recorded timestamp".into());
                }
                AvcClientPoll::Pending { wake_at_ns: Some(at) } if at <= now => continue,
                AvcClientPoll::Pending { .. } => return Ok(()),
                AvcClientPoll::Ended { retirement, .. } => {
                    let discarded = retirement.is_some_and(|r| {
                        r.pending_events != 0 || r.partial_wire_bytes != 0
                    });
                    if discarded {
                        return Err("unconsumed input at recorded teardown".into());
                    }
                    self.ended = true;
                    return Ok(());
                }
                AvcClientPoll::Fault { reason, .. } => return Err(reason.to_string()),
            }
        }
        Err("replay exceeded per-chunk work bound".into())
    }
}

fn replay(bytes: &[u8], check: impl Fn() -> Result<(), &'static str>) -> Result<String, String> {
    let records = parse_transcript_bounded(bytes, MAX_RECORDS).map_err(|e| e.to_string())?;
    let mut presentation = String::new();
    let mut outgoing = RtspParser::new();
    let mut client: Option<RtspAvcClient> = None;
    let mut teardown: Option<RtspParser> = None;
    let mut final_response = false;
    let mut previous = 0;
    let mut summary = Summary::default();
    for record in &records {
        check()?;
        if record.offset_ms < previous {
            return Err("recorded clock reversed".into());
        }
        previous = record.offset_ms;
        let now = u64::from(previous) * 1_000_000;
        for chunk in record.bytes.chunks(4096) {
            check()?;
            if record.direction == TranscriptDirection::ServerToClient {
                let c = client.as_mut().ok_or("response precedes request")?;
                // The native client's successful retirement can discard its parser. Validate
                // all bytes following the recorded TEARDOWN separately before retirement.
                if let Some(tail) = &mut teardown {
                    if final_response {
                        return Err("server bytes after final teardown response".into());
                    }
                    for event in tail.feed(chunk).map_err(|e| e.to_string())? {
                        match event {
                            RtspEvent::Response(response) if !final_response => {
                                final_response = response.status_code >= 200;
                            }
                            _ => return Err("unexpected input during teardown".into()),
                        }
                    }
                }
                c.ingest(chunk, now).map_err(|e| e.to_string())?;
                summary.drain(c, now)?;
            } else {
                for event in outgoing.feed(chunk).map_err(|e| e.to_string())? {
                    let RtspEvent::Request(cmd) = event else {
                        return Err("client direction contains a non-request".into());
                    };
                    if client.is_none() {
                        presentation = cmd.uri.clone();
                        let config = ClientConfig {
                            presentation_uri: cmd.uri.clone(),
                            control_root_uri: cmd.uri.clone(),
                            media_index: 0,
                            channels: (0, 1),
                            response_timeout_ns: 10_000_000_000,
                            default_session_timeout_seconds: 60,
                        };
                        let key = StreamKey {
                            ingress: 1,
                            generation: 1,
                            ssrc: 0,
                        };
                        let receiver = RtspAvcClient::new_with_ssrc_policy(
                            config,
                            key,
                            AvcReceiveLimits::default(),
                            SsrcPolicy::LearnOnce,
                        )
                        .map_err(|e| e.to_string())?;
                        client = Some(receiver);
                    }
                    let active = client.as_mut().ok_or("missing session")?;
                    request(&cmd, active, now, &presentation)?;
                    if cmd.method == RtspMethod::Teardown {
                        if active.buffered_wire_bytes() != 0 {
                            return Err("partial server message at teardown request".into());
                        }
                        teardown = Some(RtspParser::new());
                    }
                }
            }
        }
    }
    // A parser may return valid events first and defer the following error to its next feed.
    if !outgoing.feed(&[]).map_err(|e| e.to_string())?.is_empty() {
        return Err("undrained outgoing request at end of transcript".into());
    }
    let mut tail = teardown.ok_or("missing recorded teardown request")?;
    if !tail.feed(&[]).map_err(|e| e.to_string())?.is_empty()
        || tail.buffered_bytes() != 0
        || !final_response
    {
        return Err("truncated or undrained teardown response".into());
    }
    let closed = client.as_ref().is_some_and(|c| {
        c.buffered_wire_bytes() == 0 && c.state() == ClientState::Closed
    });
    if outgoing.buffered_bytes() != 0
        || !closed
        || !summary.ended
        || summary.states.last() != Some(&"closed")
    {
        return Err("incomplete transcript: a matching TEARDOWN response is required".into());
    }
    check()?;
    let states = summary.states
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        concat!(
            "{{\"schema\":\"{}\",\"source_digest\":\"{}\",\"records\":{},",
            "\"last_offset_ms\":{},\"state_trace\":[{}],\"rtp_datagrams\":{},",
            "\"rtcp_datagrams\":{},\"invalid_rtcp_datagrams\":{},\"observed_reorder_gaps\":{},",
            "\"absence_certifiable\":false,\"source_retained\":false}}"
        ),
        SCHEMA,
        ContentDigest::sha256(bytes).to_text(),
        records.len(),
        previous,
        states,
        summary.rtp,
        summary.rtcp,
        summary.invalid_rtcp,
        summary.gaps
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_reference::media_fixture::{parse_transcript, serialize_transcript};
    use std::error::Error;

    fn fixture(name: &str) -> Result<Vec<u8>, std::io::Error> {
        let media = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/media/rtsp");
        fs::read(media.join(name))
    }

    #[test]
    fn recorded_sessions_reach_teardown_and_preserve_datagram_counts() -> Result<(), Box<dyn Error>> {
        for (name, rtcp) in [
            ("clean.transcript", 3),
            ("interleave_split.transcript", 3),
            ("sr_absent.transcript", 0),
            ("rtcp_rsize.transcript", 3),
            ("session_timeout_header.transcript", 3),
            ("get_parameter_keepalive.transcript", 3),
        ] {
            let bytes = fixture(name)?;
            let report = replay(&bytes, || Ok(())).map_err(|e| format!("{name}: {e}"))?;
            assert!(report.contains("\"rtp_datagrams\":15"), "{report}");
            assert!(report.contains(&format!("\"rtcp_datagrams\":{rtcp}")), "{report}");
            assert!(report.contains("\"invalid_rtcp_datagrams\":0"), "{report}");
            assert!(report.contains(&ContentDigest::sha256(&bytes).to_text()));
            assert!(report.contains("\"absence_certifiable\":false"));
        }
        Ok(())
    }

    #[test]
    fn no_success_for_unfinished_unauthorized_or_malformed_sessions() -> Result<(), Box<dyn Error>> {
        for name in ["auth_required.transcript", "bad_content_length.transcript"] {
            assert!(replay(&fixture(name)?, || Ok(())).is_err());
        }
        let input = fixture("clean.transcript")?;
        let mut records = parse_transcript(&input)?;
        for suffix in [&b"$"[..], &b"$\x00\x00\x00"[..], &b"malformed\r\n\r\n"[..]] {
            let mut extra = records.clone();
            let response = extra.last_mut().ok_or("missing teardown response")?;
            response.bytes.extend_from_slice(suffix);
            assert!(replay(&serialize_transcript(&extra), || Ok(())).is_err());
        }
        records.pop();
        assert!(replay(&serialize_transcript(&records), || Ok(())).is_err());
        assert!(parse_transcript_bounded(&input, 1).is_err());
        assert!(replay(&input, || Err("cancelled")).is_err());
        Ok(())
    }

    #[test]
    fn credentials_are_refused_without_disclosing_values() -> Result<(), Box<dyn Error>> {
        let mut records = parse_transcript(&fixture("clean.transcript")?)?;
        let message = &mut records.first_mut().ok_or("missing fixture request")?.bytes;
        message.truncate(message.len() - 2);
        message.extend_from_slice(b"Authorization: Basic private-test-sentinel\r\n\r\n");
        let refusal = replay(&serialize_transcript(&records), || Ok(()))
            .err()
            .ok_or("credential accepted")?;
        assert_eq!(refusal, "recorded credentials refused");
        Ok(())
    }
    #[test]
    fn refuses_mismatched_target_or_cseq() -> Result<(), Box<dyn Error>> {
        let bytes = fixture("clean.transcript")?;
        for replacement in [
            "PLAY rtsp://elsewhere.invalid/stream",
            "PLAY rtsp://fixture.invalid/other",
            "PLAY rtsp://user:private-test-sentinel@fixture.invalid/stream",
            "PLAY http://fixture.invalid/stream",
        ] {
            let mut records = parse_transcript(&bytes)?;
            let play = records
                .iter_mut()
                .find(|r| r.bytes.starts_with(b"PLAY "))
                .ok_or("missing PLAY")?;
            let request = std::str::from_utf8(&play.bytes)?;
            play.bytes = request
                .replacen("PLAY rtsp://fixture.invalid/stream", replacement, 1)
                .into_bytes();
            let refusal = replay(&serialize_transcript(&records), || Ok(()))
                .err()
                .ok_or("wrong target accepted")?;
            assert!(!refusal.contains("private-test-sentinel"));
        }
        let mut records = parse_transcript(&bytes)?;
        let request = &mut records.first_mut().ok_or("missing request")?.bytes;
        let at = request.windows(7)
            .position(|s| s == b"CSeq: 1")
            .ok_or("missing CSeq")?;
        request[at + 6] = b'9';
        assert!(replay(&serialize_transcript(&records), || Ok(())).is_err());
        Ok(())
    }
}
