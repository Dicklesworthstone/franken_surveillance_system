#![forbid(unsafe_code)]
//! Deterministic negotiated RTSP/TCP -> source-linked AVC replay, with no sockets.
//! Run: cargo run --locked -p fss-reference --example rtsp_avc_replay

use fss_core::ContentDigest;
use fss_packet::StreamKey;
use fss_packet::avc::{AvcAssemblyStep, AvcPictureGroup, AvcReceiveLimits, AvcReceivePoll};
use fss_reference::rtsp::avc_client::{AvcClientPoll, RtspAvcClient};
use fss_reference::rtsp::client::{ClientCommand, ClientConfig, ClientProgress};

type Error = Box<dyn std::error::Error>;
const KEY: StreamKey = StreamKey { ingress: 71, generation: 1, ssrc: 7 };
const BASELINE: &[u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
const HIGH: &[u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/high_cropped.264");

#[derive(Default)]
struct Counts { sources: usize, pictures: usize, gaps: usize }

fn main() -> Result<(), Error> {
    replay("baseline", BASELINE,
        ("Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=", "aM4PLIA="),
        &[90_000, 93_600, 97_200, 100_800])?;
    replay("high_cropped", HIGH,
        ("Z2QACqzZRH+fARAAAAMAEAAAAwMg8SJZYA==", "aOvjyyLA"),
        &[90_000, 100_800, 93_600, 97_200, 108_000, 104_400])?;
    lost_fragment()
}

fn negotiate(parameters: (&str, &str), limits: AvcReceiveLimits) -> Result<RtspAvcClient, Error> {
    let config = ClientConfig {
        presentation_uri: "rtsp://camera.invalid/live/".into(),
        control_root_uri: "rtsp://camera.invalid/live".into(),
        media_index: 0, channels: (0, 1), response_timeout_ns: 10_000_000_000,
        default_session_timeout_seconds: 60,
    };
    let mut client = RtspAvcClient::new(config, KEY, limits)?;
    let sdp = format!("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=synthetic-fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets={},{}\r\na=control:trackID=0\r\n", parameters.0, parameters.1);
    for (command, fields, body) in [
        (ClientCommand::Describe, "Content-Type: application/sdp\r\n", sdp.as_str()),
        (ClientCommand::Setup, "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n", ""),
        (ClientCommand::Play, "Session: fixture\r\n", ""),
    ] {
        let request = client.request(command, 0)?;
        println!("{{\"kind\":\"request_prepared\",\"command\":\"{:?}\",\"cseq\":{},\"bytes\":{},\"sent_to_camera\":false}}",
            request.command(), request.cseq(), request.bytes().len());
        let response = format!("RTSP/1.0 200 OK\r\nCSeq: {}\r\nContent-Length: {}\r\n{fields}\r\n{body}", request.cseq(), body.len());
        let mut counts = Counts::default();
        for chunk in response.as_bytes().chunks(7) {
            client.ingest(chunk, 0)?;
            drain(&mut client, "negotiation", 0, &mut counts, false)?;
        }
    }
    Ok(client)
}

fn replay(name: &str, bytes: &[u8], parameters: (&str, &str), timestamps: &[u32]) -> Result<(), Error> {
    let mut client = negotiate(parameters, AvcReceiveLimits::default())?;
    let nals = split_fixture(bytes);
    let first = *nals.first().ok_or("fixture missing parameter sets")?;
    let mut counts = Counts::default();
    feed(&mut client, name, 0, timestamps[0], first, 1, &mut counts)?;
    let mut frame = 0;
    for (index, nal) in nals.iter().enumerate() {
        let timestamp = *timestamps.get(frame).ok_or("more fixture pictures than expected")?;
        feed(&mut client, name, index as u16 + 1, timestamp, nal, 1, &mut counts)?;
        if matches!(nal[0] & 31, 1 | 5) { frame += 1; }
    }
    client.finish();
    drain(&mut client, name, 2, &mut counts, false)?;
    if counts.pictures != timestamps.len() || counts.sources != nals.len() + 1
        || counts.gaps != 0 || client.retained_nal_bytes() != 0 || client.buffered_wire_bytes() != 0 {
        return Err("clean replay count or quiescence mismatch".into());
    }
    println!("{{\"kind\":\"verified_replay_counts\",\"fixture\":\"{name}\",\"sources\":{},\"picture_groups\":{},\"retained_bytes\":0,\"rust_decoder\":false,\"live_camera_qualified\":false}}", counts.sources, counts.pictures);
    Ok(())
}

fn lost_fragment() -> Result<(), Error> {
    let mut limits = AvcReceiveLimits::default();
    limits.reorder.max_delay_ns = 10;
    let mut client = negotiate(("Z0LAC9oKEbARAAADAAEAAAMAMg8UKqA=", "aM4PLIA="), limits)?;
    let nals = split_fixture(BASELINE);
    let sps = *nals.first().ok_or("fixture missing SPS")?;
    let idr = *nals.iter().find(|n| n[0] & 31 == 5).ok_or("fixture missing IDR")?;
    let mut counts = Counts::default();
    feed(&mut client, "lost_fragment", 0, 90_000, sps, 1, &mut counts)?;
    feed(&mut client, "lost_fragment", 1, 90_000, sps, 1, &mut counts)?;
    let midpoint = idr.len() / 2;
    let mut start = vec![(idr[0] & 0x60) | 28, (idr[0] & 31) | 0x80];
    start.extend_from_slice(&idr[1..midpoint]);
    let mut end = vec![(idr[0] & 0x60) | 28, (idr[0] & 31) | 0x40];
    end.extend_from_slice(&idr[midpoint..]);
    feed(&mut client, "lost_fragment", 2, 90_000, &start, 2, &mut counts)?;
    feed(&mut client, "lost_fragment", 4, 90_000, &end, 3, &mut counts)?;
    drain(&mut client, "lost_fragment", 13, &mut counts, true)?;
    if counts.gaps != 1 || counts.pictures != 0 { return Err("loss was not classified".into()); }
    feed(&mut client, "lost_fragment", 5, 93_600, &start, 14, &mut counts)?;
    let retired = client.cancel();
    let video = retired.video.ok_or("codec cancellation missing")?;
    if video.transport.fragment.is_none() || client.retained_nal_bytes() != 0 {
        return Err("pending fragment was not retired".into());
    }
    println!("{{\"kind\":\"cancelled_loss_replay\",\"gaps\":1,\"fragment_retired\":true,\"remote_session_may_exist\":{},\"retained_bytes\":0}}", retired.session.remote_session_may_exist);
    Ok(())
}

fn feed(client: &mut RtspAvcClient, name: &str, sequence: u16, timestamp: u32,
    nal: &[u8], now: u64, counts: &mut Counts) -> Result<(), Error> {
    let mut packet = vec![0x80, 96];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&KEY.ssrc.to_be_bytes());
    packet.extend_from_slice(nal);
    let length = u16::try_from(packet.len())?;
    let mut frame = vec![b'$', 0]; frame.extend_from_slice(&length.to_be_bytes()); frame.extend_from_slice(&packet);
    for chunk in frame.chunks(7) {
        client.ingest(chunk, now)?;
        drain(client, name, now, counts, name == "lost_fragment")?;
    }
    Ok(())
}

fn drain(client: &mut RtspAvcClient, name: &str, now: u64, counts: &mut Counts, allow_loss: bool) -> Result<(), Error> {
    for _ in 0..4_096 {
        match client.poll(now)? {
            AvcClientPoll::Control(progress) => {
                if progress == ClientProgress::KeepAliveDue { return Err("unexpected fixture keepalive deadline".into()); }
                println!("{{\"kind\":\"control\",\"state\":\"{progress:?}\"}}");
            }
            AvcClientPoll::Rtp { source, admission, retirement: None } => {
                let digest = ContentDigest::try_sha256(source.payload())?.to_text();
                counts.sources += 1;
                println!("{{\"kind\":\"source\",\"fixture\":\"{name}\",\"digest\":\"{digest}\",\"bytes\":{},\"disposition\":\"{:?}\"}}",
                    source.payload().len(), admission.transport.transport.disposition);
            }
            AvcClientPoll::Media(AvcReceivePoll::Source { fragment, picture, gap_before, .. }) => {
                if !allow_loss && (fragment.is_some() || picture.is_some() || gap_before) { return Err("unexpected clean source discontinuity".into()); }
            }
            AvcClientPoll::Media(AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(out))) => {
                if !allow_loss && out.retired.is_some() { return Err("clean assembly retired".into()); }
                if let Some(picture) = out.picture { report(name, &picture)?; counts.pictures += 1; }
            }
            AvcClientPoll::Media(AvcReceivePoll::Picture(picture)) => { report(name, &picture)?; counts.pictures += 1; }
            AvcClientPoll::Media(AvcReceivePoll::Gap { gap, fragment, picture }) if allow_loss => {
                counts.gaps += 1;
                println!("{{\"kind\":\"delivery_gap\",\"gap\":\"{gap:?}\",\"fragment_retired\":{},\"picture_retired\":{}}}", fragment.is_some(), picture.is_some());
            }
            AvcClientPoll::Media(AvcReceivePoll::CodecRefused { error, .. }) if allow_loss => {
                println!("{{\"kind\":\"codec_refusal\",\"error\":\"{error:?}\"}}");
            }
            AvcClientPoll::Pending { wake_at_ns } if wake_at_ns.is_none_or(|at| at > now) => return Ok(()),
            AvcClientPoll::Pending { .. } => {},
            AvcClientPoll::Ended { media: Some(AvcReceivePoll::Ended { tail, fragment: None, interrupted_picture: None }), retirement: Some(retired) } => {
                if let Some(tail) = tail {
                    if tail.retired.is_some() { return Err("clean EOF retired metadata only".into()); }
                    if let Some(picture) = tail.picture { report(name, &picture)?; counts.pictures += 1; }
                }
                println!("{{\"kind\":\"local_eof\",\"fixture\":\"{name}\",\"remote_session_may_exist\":{}}}", retired.session.remote_session_may_exist);
                return Ok(());
            }
            other => return Err(format!("unexpected replay event: {other:?}").into()),
        }
    }
    Err("fixture poll ceiling exceeded".into())
}

fn report(name: &str, picture: &AvcPictureGroup) -> Result<(), Error> {
    let (width, height) = picture.sps().display_dimensions();
    println!("{{\"kind\":\"picture_group\",\"fixture\":\"{name}\",\"timestamp\":{},\"frame_num\":{},\"width\":{width},\"height\":{height},\"boundary\":\"{:?}\",\"complete_picture_certified\":false}}",
        picture.timestamp(), picture.identity().frame_num(), picture.boundary());
    for nal in picture.nals() {
        let digest = ContentDigest::try_sha256(nal.bytes())?.to_text();
        println!("{{\"kind\":\"picture_nal\",\"digest\":\"{digest}\",\"source_spans\":{}}}", nal.sources().len());
    }
    Ok(())
}

// Fixed, retained laboratory fixtures only; not a production Annex-B parser.
fn split_fixture(bytes: &[u8]) -> Vec<&[u8]> {
    let mut output = Vec::new(); let mut start = None; let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) { 4 }
            else if bytes[at..at + 3] == [0, 0, 1] { 3 } else { 0 };
        if prefix == 0 { at += 1; continue; }
        if let Some(begin) = start {
            let mut end = at; while end > begin && bytes[end - 1] == 0 { end -= 1; }
            if begin < end { output.push(&bytes[begin..end]); }
        }
        start = Some(at + prefix); at += prefix;
    }
    if let Some(begin) = start && begin < bytes.len() { output.push(&bytes[begin..]); }
    output
}
