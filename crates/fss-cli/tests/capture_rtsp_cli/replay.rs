#![forbid(unsafe_code)]
//! Native recorder playback through approved capture, durable receipts and cold AVC decode.

use super::*;
use fss_core::{SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording::local::load_recording;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_replay::{ReplayTermination, load_replay_receipt, replay_slot};
use std::collections::BTreeMap;

const REPLAY_START: &str = "20261101T120000Z";
const REPLAY_END: &str = "20261101T120100Z";
const REQUESTED_RANGE: &str = "clock=20261101T120000Z-20261101T120100Z";
const ACKNOWLEDGED_RANGE: &str = "clock=20261101T120010Z-20261101T120050Z";

#[derive(Clone, Copy)]
enum ReplayBehavior {
    Target,
    EofAfterOne,
    BadAcknowledgement(&'static str),
    Rejected(u16),
}

struct ReplayRequestWire {
    method: String,
    cseq: u32,
    wire: String,
}

struct ReplayTranscript {
    requests: Vec<ReplayRequestWire>,
    play_cseq: u32,
    source_eof: bool,
    video: Vec<u8>,
}

fn replay_args(directory: &Directory, peer: SocketAddr) -> Vec<OsString> {
    let mut arguments = args(directory, peer, 2);
    arguments.extend([
        "--replay-start".into(),
        REPLAY_START.into(),
        "--replay-end".into(),
        REPLAY_END.into(),
    ]);
    arguments
}

fn header<'a>(wire: &'a str, name: &str) -> Test<Option<&'a str>> {
    let mut values = wire.split("\r\n").filter_map(|line| {
        let (field, value) = line.split_once(':')?;
        field.eq_ignore_ascii_case(name).then_some(value.trim())
    });
    let first = values.next();
    if values.next().is_some() {
        return Err(format!("duplicate fixture request header {name}").into());
    }
    Ok(first)
}

// Retain the complete bounded request. The parent's reader deliberately returns
// only method/CSeq, which cannot establish the historical request sent on the wire.
fn replay_request(peer: &mut TcpStream) -> Test<Option<ReplayRequestWire>> {
    let mut bytes = Vec::new();
    while bytes.len() < 8192 {
        let mut byte = [0];
        match peer.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => return Err("client closed inside a replay request".into()),
            Ok(_) => bytes.push(byte[0]),
            Err(error)
                if bytes.is_empty()
                    && matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                    ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        if bytes.ends_with(b"\r\n\r\n") {
            let wire = String::from_utf8(bytes)?;
            assert!(header(&wire, "Authorization")?.is_none());
            let method = wire
                .split_ascii_whitespace()
                .next()
                .ok_or("empty replay request")?
                .to_owned();
            let cseq = header(&wire, "CSeq")?
                .ok_or("missing replay CSeq")?
                .parse()?;
            return Ok(Some(ReplayRequestWire { method, cseq, wire }));
        }
    }
    Err("replay request exceeded the fixture byte bound".into())
}

fn serve_replay(listener: TcpListener, behavior: ReplayBehavior) -> Test<ReplayTranscript> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut peer = loop {
        match listener.accept() {
            Ok((peer, _)) => break peer,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error.into()),
        }
    };
    peer.set_read_timeout(Some(Duration::from_secs(10)))?;
    peer.set_write_timeout(Some(Duration::from_secs(10)))?;
    peer.set_nodelay(true)?;

    let mut transcript = ReplayTranscript {
        requests: Vec::new(),
        play_cseq: 0,
        source_eof: false,
        video: Vec::new(),
    };
    let describe = replay_request(&mut peer)?.ok_or("no replay DESCRIBE")?;
    assert_eq!(describe.method, "DESCRIBE");
    assert!(header(&describe.wire, "Range")?.is_none());
    response(
        &mut peer,
        describe.cseq,
        "Content-Type: application/sdp\r\n",
        SDP,
    )?;
    transcript.requests.push(describe);

    let setup = replay_request(&mut peer)?.ok_or("no replay SETUP")?;
    assert_eq!(setup.method, "SETUP");
    assert_eq!(header(&setup.wire, "Require")?, Some("onvif-replay"));
    assert!(header(&setup.wire, "Range")?.is_none());
    response(
        &mut peer,
        setup.cseq,
        "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
        "",
    )?;
    transcript.requests.push(setup);

    let play = replay_request(&mut peer)?.ok_or("no replay PLAY")?;
    assert_eq!(play.method, "PLAY");
    assert_eq!(header(&play.wire, "Require")?, Some("onvif-replay"));
    assert_eq!(header(&play.wire, "Range")?, Some(REQUESTED_RANGE));
    assert_eq!(header(&play.wire, "Rate-Control")?, Some("no"));
    assert!(header(&play.wire, "Scale")?.is_none());
    transcript.play_cseq = play.cseq;
    transcript.requests.push(play);

    let refused = matches!(
        behavior,
        ReplayBehavior::BadAcknowledgement(_) | ReplayBehavior::Rejected(_)
    );
    let (status, range_headers) = match behavior {
        ReplayBehavior::Target | ReplayBehavior::EofAfterOne => {
            (200, format!("Range: {ACKNOWLEDGED_RANGE}\r\n"))
        }
        ReplayBehavior::BadAcknowledgement(headers) => (200, headers.to_owned()),
        ReplayBehavior::Rejected(status) => (status, String::new()),
    };
    let mut reply = format!(
        "RTSP/1.0 {status} recorder fixture\r\nCSeq: {}\r\nSession: fixture\r\nContent-Length: 0\r\n{range_headers}\r\n",
        transcript.play_cseq
    )
    .into_bytes();
    if !matches!(behavior, ReplayBehavior::Rejected(_)) {
        let pictures = if matches!(behavior, ReplayBehavior::EofAfterOne) {
            1
        } else {
            2
        };
        transcript.video = video(pictures, 3600, 96, false)?;
        // Invalid acknowledgements also carry real video in the same write: a
        // bad control response must fence media already waiting in native intake.
        reply.extend_from_slice(&transcript.video);
    }
    match peer.write_all(&reply) {
        Ok(()) => {}
        Err(error)
            if refused
                && matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                ) => {}
        Err(error) => return Err(error.into()),
    }
    if matches!(behavior, ReplayBehavior::EofAfterOne) {
        peer.shutdown(Shutdown::Write)?;
        transcript.source_eof = true;
    }

    // Target success keeps the recorder connection open until the owner stops.
    // Any new request after rejection would be an unintended fallback or retry.
    for _ in 0..16 {
        let Some(request) = replay_request(&mut peer)? else {
            return Ok(transcript);
        };
        if refused || transcript.source_eof {
            return Err(format!(
                "unexpected request after replay termination: {}",
                request.method
            )
            .into());
        }
        match request.method.as_str() {
            "TEARDOWN" | "GET_PARAMETER" | "OPTIONS" => {
                response(&mut peer, request.cseq, "Session: fixture\r\n", "")?;
            }
            _ => return Err("replay fixture observed a seek, second PLAY or fallback".into()),
        }
        transcript.requests.push(request);
    }
    Err("replay fixture exceeded its request allowance".into())
}

fn capture_replay(
    listener: TcpListener,
    arguments: &[OsString],
    behavior: ReplayBehavior,
) -> Test<(Output, ReplayTranscript)> {
    thread::scope(|scope| {
        let server = scope.spawn(move || serve_replay(listener, behavior));
        let output = run("capture", arguments);
        let server = server
            .join()
            .map_err(|_| "replay fixture thread panicked")?;
        match (output, server) {
            (Ok(output), Ok(transcript)) => Ok((output, transcript)),
            (Ok(output), Err(error)) => Err(format!(
                "replay fixture failed: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into()),
            (Err(error), _) => Err(error),
        }
    })
}

fn saved_rows(directory: &Directory, mut output: Output) -> Test<Vec<Value>> {
    let path = directory.0.join("replay-capture.jsonl");
    fs::write(&path, &output.stdout)?;
    output.stdout = fs::read(path)?;
    rows(&output)
}

fn bound_usize(bounds: &Value, name: &str) -> Test<usize> {
    Ok(usize::try_from(integer(bounds, name)?)?)
}

fn publication_limits(preview: &Value) -> Test<LocalPublicationLimits> {
    let bounds = value(preview, "bounds")?;
    Ok(LocalPublicationLimits::new(
        bound_usize(bounds, "publication_roots")?,
        bound_usize(bounds, "publication_children")?,
        bound_usize(bounds, "publication_tombstones")?,
        bound_usize(bounds, "publication_scan_entries")?,
        SpoolLimits::new(
            bound_usize(bounds, "spool_objects")?,
            u64::try_from(integer(bounds, "spool_total_bytes")?)?,
            bound_usize(bounds, "spool_object_bytes")?,
            bound_usize(bounds, "spool_scan_entries")?,
        ),
    )
    .validate()?)
}

fn catalog_scope(preview: &Value) -> Test<CatalogScope> {
    let bounds = value(preview, "bounds")?;
    Ok(CatalogScope {
        recording: RecordingScope {
            sensor: SensorId::parse(text(preview, "sensor")?)?,
            stream: StreamId::parse(text(preview, "stream")?)?,
            generation: u64::try_from(integer(bounds, "generation")?)?,
            anchor: ContentDigest::parse(text(preview, "anchor")?)?,
            receive_clock: ContentDigest::parse(text(preview, "receive_clock")?)?,
        },
        decode_clock: ContentDigest::parse(text(preview, "decode_clock")?)?,
        time_scale: u32::try_from(integer(bounds, "time_scale")?)?,
    })
}

fn sent_packets(video: &[u8]) -> Test<BTreeMap<u16, &[u8]>> {
    let mut packets = BTreeMap::new();
    let mut offset = 0;
    while offset < video.len() {
        let header = video
            .get(offset..offset + 4)
            .ok_or("fixture interleaved header")?;
        assert_eq!(&header[..2], &[b'$', 0]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let end = offset + 4 + length;
        let packet = video.get(offset + 4..end).ok_or("fixture RTP payload")?;
        let sequence = packet.get(2..4).ok_or("fixture RTP sequence")?;
        let sequence = u16::from_be_bytes([sequence[0], sequence[1]]);
        assert!(
            packets.insert(sequence, packet).is_none(),
            "duplicate fixture sequence"
        );
        offset = end;
    }
    assert!(!packets.is_empty());
    Ok(packets)
}

fn verify_saved_receipt(
    directory: &Directory,
    preview: &Value,
    rows: &[Value],
    transcript: &ReplayTranscript,
    termination: ReplayTermination,
    complete: bool,
    pictures: usize,
) -> Test {
    let approved = ContentDigest::parse(text(preview, "approval")?)?;
    // A watchdog plan delegates its nested native capture only after the outer
    // approval is admitted. Keep that approval while reading native scope/bounds.
    let preview = preview
        .object()
        .and_then(|fields| fields.get("capture"))
        .unwrap_or(preview);
    let accepted = detail(rows, "replay_accepted")?;
    assert_eq!(
        integer(accepted, "play_cseq")?,
        i128::from(transcript.play_cseq)
    );
    assert_eq!(text(accepted, "requested_range")?, REQUESTED_RANGE);
    assert_eq!(text(accepted, "acknowledged_range")?, ACKNOWLEDGED_RANGE);
    assert_eq!(text(accepted, "historical_frame_time")?, "unknown");
    assert!(!boolean(accepted, "complete_interval_retrieval")?);

    let published = detail(rows, "replay_receipt_published")?;
    assert!(boolean(published, "durable")?);
    assert_eq!(boolean(published, "publication_complete")?, complete);
    assert_eq!(integer(published, "windows")?, 1);
    assert_eq!(text(published, "requested_range")?, REQUESTED_RANGE);
    assert_eq!(text(published, "acknowledged_range")?, ACKNOWLEDGED_RANGE);
    assert_eq!(
        integer(published, "play_cseq")?,
        i128::from(transcript.play_cseq)
    );
    assert_eq!(text(published, "historical_frame_time")?, "unknown");
    assert!(!boolean(published, "complete_interval_retrieval")?);
    let replay = value(detail(rows, "terminal")?, "recorder_replay")?;
    assert_eq!(text(replay, "source")?, "recorder_replay");
    assert_eq!(text(replay, "receipt_state")?, "durable");
    assert_eq!(text(replay, "historical_frame_time")?, "unknown");
    assert!(!boolean(replay, "complete_interval_retrieval")?);
    assert!(!boolean(replay, "upstream_retention_known")?);
    assert!(!boolean(replay, "automatic_live_fallback")?);
    let terminal_receipt = value(replay, "receipt")?;
    assert_eq!(text(terminal_receipt, "slot")?, text(published, "slot")?);
    assert_eq!(text(terminal_receipt, "root")?, text(published, "root")?);

    let planned = value(preview, "recorder_replay")?;
    let request = ContentDigest::parse(text(planned, "request_identity")?)?;
    assert_eq!(text(published, "request_identity")?, request.to_text());
    assert_eq!(text(replay, "request_identity")?, request.to_text());
    let root = ContentDigest::parse(text(published, "root")?)?;
    let scope = catalog_scope(preview)?;
    assert_eq!(
        replay_slot(&scope, request)?.as_str(),
        text(published, "slot")?
    );
    let publisher = LocalRootPublisher::open(&directory.root(), publication_limits(preview)?)?;
    let receipt = load_replay_receipt(&publisher, root, &scope, request, &NeverCancel)?;
    assert_eq!(receipt.root(), root);
    assert_eq!(receipt.scope(), &scope);
    assert_eq!(receipt.request().digest(), request);
    assert_eq!(receipt.request().window().to_string(), REQUESTED_RANGE);
    assert_eq!(receipt.request().scope(), &scope.recording);
    assert_eq!(receipt.approval(), approved);
    assert_eq!(receipt.acceptance().cseq(), transcript.play_cseq);
    assert_eq!(
        receipt.acceptance().requested().to_string(),
        REQUESTED_RANGE
    );
    assert_eq!(
        receipt.acceptance().acknowledged().to_string(),
        ACKNOWLEDGED_RANGE
    );
    assert_eq!(receipt.termination(), termination);
    assert_eq!(receipt.publication_complete(), complete);
    assert_eq!(receipt.rate_control(), "no");
    assert_eq!(receipt.windows().len(), 1);

    let window = &receipt.windows()[0];
    let durable = detail(rows, "window_durable")?;
    assert_eq!(window.slot().as_str(), text(durable, "slot")?);
    assert_eq!(window.root(), ContentDigest::parse(text(durable, "root")?)?);
    assert_eq!(window.samples(), pictures);
    let original = load_recording(
        &publisher,
        window.slot(),
        window.root(),
        &scope.recording,
        &NeverCancel,
    )?;
    assert_eq!(original.summary().samples, pictures);
    assert_eq!(original.summary().scope, scope.recording);
    let sent = sent_packets(&transcript.video)?;
    let retained = original.packets()?;
    assert_eq!(retained.len(), window.packets());
    assert!(retained.len() >= pictures);
    for packet in retained {
        let sequence = packet.bytes.get(2..4).ok_or("retained RTP sequence")?;
        let sequence = u16::from_be_bytes([sequence[0], sequence[1]]);
        assert_eq!(
            packet.bytes,
            *sent
                .get(&sequence)
                .ok_or("retained packet absent from recorder transmission")?,
            "original recorder datagram changed"
        );
        assert!(
            packet.received_ns < u64::try_from(integer(value(preview, "bounds")?, "timeout_ns")?)?,
            "requested historical UTC was substituted for native receive time"
        );
    }
    Ok(())
}

#[test]
fn replay_preview_is_read_only_and_interval_changes_require_new_approval() -> Test {
    let directory = Directory::new("replay-preview")?;
    let listener = listener()?;
    let peer = listener.local_addr()?;
    let (live, _) = plan(&args(&directory, peer, 2))?;
    let original = replay_args(&directory, peer);
    let (preview, approval) = plan(&original)?;
    let replay = value(&preview, "recorder_replay")?;
    ContentDigest::parse(text(replay, "request_identity")?)?;
    assert_eq!(text(replay, "requested_range")?, REQUESTED_RANGE);
    for field in ["sensor", "stream", "anchor", "receive_clock"] {
        assert_eq!(text(&preview, field)?, text(&live, field)?);
    }
    assert_ne!(
        text(&preview, "decode_clock")?,
        text(&live, "decode_clock")?
    );
    assert_ne!(
        text(&preview, "archive_namespace")?,
        text(&live, "archive_namespace")?
    );
    no_connection(&listener)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());

    let mut changed = original.clone();
    replace(&mut changed, "--replay-end", "20261101T120200Z")?;
    let (changed_preview, changed_approval) = plan(&changed)?;
    assert_ne!(changed_approval, approval);
    assert_ne!(
        text(
            value(&changed_preview, "recorder_replay")?,
            "request_identity"
        )?,
        text(replay, "request_identity")?
    );
    changed.extend(["--approve".into(), approval.into()]);
    assert!(!run("capture", &changed)?.status.success());
    no_connection(&listener)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());
    Ok(())
}

#[test]
fn recorder_replay_target_stop_retains_receipt_and_cold_decodable_originals() -> Test {
    let directory = Directory::new("replay-target")?;
    let listener = listener()?;
    let arguments = replay_args(&directory, listener.local_addr()?);
    let (preview, approval) = plan(&arguments)?;
    let mut approved = arguments;
    approved.extend(["--approve".into(), approval.into()]);
    let (output, transcript) = capture_replay(listener, &approved, ReplayBehavior::Target)?;
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!transcript.source_eof);
    assert_eq!(
        transcript.requests[..3]
            .iter()
            .map(|request| request.method.as_str())
            .collect::<Vec<_>>(),
        ["DESCRIBE", "SETUP", "PLAY"]
    );
    let rows = saved_rows(&directory, output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "owner_stopped");
    assert!(!boolean(terminal, "peer_eof")?);
    assert!(!boolean(terminal, "input_end_observed")?);
    assert_eq!(integer(terminal, "durable_pictures")?, 2);
    verify_saved_receipt(
        &directory,
        &preview,
        &rows,
        &transcript,
        ReplayTermination::RequestedStop,
        true,
        2,
    )?;
    import_and_decode(&directory, &rows, 2)
}

#[test]
fn recorder_replay_supervised_receipt_retains_the_admitted_outer_approval() -> Test {
    let directory = Directory::new("replay-supervised")?;
    let listener = listener()?;
    let mut arguments = replay_args(&directory, listener.local_addr()?);
    arguments.extend(["--progress-timeout-ms".into(), "4000".into()]);
    let preview = parse(&good(run("capture", &arguments)?)?)?;
    assert_eq!(
        text(&preview, "schema")?,
        "fss.rtsp_supervised_capture_cli.v1"
    );
    assert_eq!(text(&preview, "phase")?, "planned");
    let approval = text(&preview, "approval")?.to_owned();
    let nested = value(&preview, "capture")?;
    assert_ne!(approval, text(nested, "approval")?);
    no_connection(&listener)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());

    arguments.extend(["--approve".into(), approval.into()]);
    let (output, transcript) = capture_replay(listener, &arguments, ReplayBehavior::Target)?;
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!transcript.source_eof);
    let rows = saved_rows(&directory, output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "owner_stopped");
    assert_eq!(integer(terminal, "durable_pictures")?, 2);
    verify_saved_receipt(
        &directory,
        &preview,
        &rows,
        &transcript,
        ReplayTermination::RequestedStop,
        true,
        2,
    )
}

#[test]
fn recorder_replay_early_eof_preserves_durable_prefix_without_completeness_upgrade() -> Test {
    let directory = Directory::new("replay-eof")?;
    let listener = listener()?;
    let arguments = replay_args(&directory, listener.local_addr()?);
    let (preview, approval) = plan(&arguments)?;
    let mut approved = arguments;
    approved.extend(["--approve".into(), approval.into()]);
    let (output, transcript) = capture_replay(listener, &approved, ReplayBehavior::EofAfterOne)?;
    assert!(
        !output.status.success(),
        "one historical picture met a two-picture target"
    );
    assert!(transcript.source_eof);
    let rows = saved_rows(&directory, output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "input_ended_before_target");
    assert!(boolean(terminal, "peer_eof")?);
    assert!(boolean(terminal, "input_end_observed")?);
    assert_eq!(integer(terminal, "durable_pictures")?, 1);
    verify_saved_receipt(
        &directory,
        &preview,
        &rows,
        &transcript,
        ReplayTermination::InputEnded,
        false,
        1,
    )?;
    import_and_decode(&directory, &rows, 1)
}

#[test]
fn recorder_replay_bad_acknowledgements_fence_already_offered_video() -> Test {
    for headers in [
        "",
        "Range: npt=0-60\r\n",
        "Range: clock=20261101T120000Z-20261101T120101Z\r\n",
        "Range: clock=20261101T115959Z-20261101T120100Z\r\n",
        "Range: clock=20261101T120000Z-20261101T120100Z\r\nRange: clock=20261101T120000Z-20261101T120100Z\r\n",
    ] {
        let directory = Directory::new("replay-bad-ack")?;
        let listener = listener()?;
        let approved = approve(&replay_args(&directory, listener.local_addr()?))?;
        let (output, transcript) = capture_replay(
            listener,
            &approved,
            ReplayBehavior::BadAcknowledgement(headers),
        )?;
        assert!(!output.status.success());
        assert_eq!(
            transcript.requests.len(),
            3,
            "invalid replay acknowledgement caused fallback"
        );
        assert!(
            !transcript.video.is_empty(),
            "fixture never challenged media admission"
        );
        let rows = saved_rows(&directory, output)?;
        let terminal = detail(&rows, "terminal")?;
        assert_eq!(
            text(terminal, "error_id")?,
            "ERR-CAPTURE-RTSP-REPLAY-ACK-001"
        );
        assert_eq!(
            text(terminal, "stop_cause")?,
            "replay_acknowledgement_refused"
        );
        assert_eq!(integer(terminal, "collected_pictures")?, 0);
        assert_eq!(integer(terminal, "durable_windows")?, 0);
        assert!(!boolean(terminal, "complete")?);
        let replay = value(terminal, "recorder_replay")?;
        assert_eq!(text(replay, "receipt_state")?, "not_published");
        assert_eq!(value(replay, "acknowledgement")?, &Value::Null);
        assert_eq!(value(replay, "receipt")?, &Value::Null);
        assert!(!rows.iter().any(|row| {
            text(row, "kind").is_ok_and(|kind| {
                matches!(
                    kind,
                    "replay_accepted" | "replay_receipt_published" | "window_durable"
                )
            })
        }));
    }
    Ok(())
}

#[test]
fn recorder_replay_status_refusals_are_typed_and_never_fall_back_to_live() -> Test {
    for (status, error_id, cause) in [
        (
            456,
            "ERR-CAPTURE-RTSP-REPLAY-HEADER-456",
            "replay_header_not_valid_for_resource",
        ),
        (
            457,
            "ERR-CAPTURE-RTSP-REPLAY-RANGE-457",
            "replay_range_rejected",
        ),
        (
            551,
            "ERR-CAPTURE-RTSP-REPLAY-OPTION-551",
            "replay_option_not_supported",
        ),
    ] {
        let directory = Directory::new("replay-status")?;
        let listener = listener()?;
        let approved = approve(&replay_args(&directory, listener.local_addr()?))?;
        let (output, transcript) =
            capture_replay(listener, &approved, ReplayBehavior::Rejected(status))?;
        assert!(!output.status.success());
        assert_eq!(
            transcript
                .requests
                .iter()
                .map(|request| request.method.as_str())
                .collect::<Vec<_>>(),
            ["DESCRIBE", "SETUP", "PLAY"]
        );
        assert!(transcript.video.is_empty());
        let rows = saved_rows(&directory, output)?;
        let terminal = detail(&rows, "terminal")?;
        assert_eq!(text(terminal, "error_id")?, error_id);
        assert_eq!(text(terminal, "stop_cause")?, cause);
        assert_eq!(integer(terminal, "rtsp_status")?, i128::from(status));
        assert!(!boolean(terminal, "upstream_retention_known")?);
        assert_eq!(integer(terminal, "collected_pictures")?, 0);
        assert_eq!(integer(terminal, "durable_windows")?, 0);
        assert!(!boolean(terminal, "complete")?);
        let replay = value(terminal, "recorder_replay")?;
        assert_eq!(text(replay, "receipt_state")?, "not_published");
        assert!(!boolean(replay, "automatic_live_fallback")?);
        assert!(!boolean(replay, "upstream_retention_known")?);
    }
    Ok(())
}
