#![forbid(unsafe_code)]
//! Protected recorder discovery becomes one approved historical capture and a cold-verifiable receipt.

use super::*;
use fss_cli::onvif_replay_plan::{ONVIF_REPLAY_APPROVAL_DOMAIN, ReplayHandoff};
use fss_reference::onvif::client::recording::RecordingReplay;
use fss_reference::onvif::wire::{
    AdvertisedRecordingRange, RecordingInformation, RecordingService, RecordingServices,
    RecordingSource, RecordingStatus, RecordingTrackInformation, RecordingTrackType,
    ServiceVersion,
};
use fss_reference::rtsp::client::replay::ReplayWindow;
use fss_reference::rtsp::recording_replay::ReplayCodec;
use std::fs::OpenOptions;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

const TOKEN: &str = "PRIVATE_REPLAY_RECORDING_TOKEN";
const PRIVATE_NAME: &str = "PRIVATE_REPLAY_SOURCE_NAME";
const URI_MARKER: &str = "PRIVATE_REPLAY_URI_TICKET";
const PRESENTATION: &str = "/live/?ticket=PRIVATE_REPLAY_URI_TICKET%2Bexact";

fn selection(peer: SocketAddr) -> RecordingReplay {
    let service = |name: &str| RecordingService {
        xaddr: format!("http://127.0.0.1:8000/onvif/{name}"),
        version: ServiceVersion { major: 2, minor: 0 },
    };
    RecordingReplay {
        services: RecordingServices {
            recording: Some(service("recording")),
            search: Some(service("search")),
            replay: Some(service("replay")),
            response_body_digest: ContentDigest::sha256(b"complete services observation"),
        },
        information: RecordingInformation {
            token: TOKEN.into(),
            source: RecordingSource {
                source_id: "urn:fixture:recorded-source".into(),
                name: PRIVATE_NAME.into(),
                location: "fixture".into(),
                description: "owned loopback fixture".into(),
                address: "urn:fixture:descriptive-only".into(),
                video_source_token: None,
            },
            content: "recorder metadata never chooses a codec".into(),
            range: AdvertisedRecordingRange::default(),
            tracks: vec![RecordingTrackInformation {
                token: "private-recorded-video".into(),
                kind: RecordingTrackType::Video,
                description: "explicit video family; codec unknown".into(),
                range: AdvertisedRecordingRange::default(),
            }],
            status: RecordingStatus::Recording,
            response_body_digest: ContentDigest::sha256(b"complete recording information"),
        },
        uri: format!("rtsp://{peer}{PRESENTATION}"),
        uri_response_digest: ContentDigest::sha256(b"complete replay URI observation"),
        peer,
        authority: peer.to_string(),
        exchanges: 3,
    }
}

fn handoff(selected: &RecordingReplay, hevc: bool) -> Test<String> {
    Ok(ReplayHandoff::from_selected(
        selected,
        ContentDigest::sha256(b"independently approved recording selection"),
        ReplayWindow::from_timestamps(REPLAY_START, REPLAY_END)?,
        if hevc { ReplayCodec::Hevc } else { ReplayCodec::Avc },
    )?.render()?)
}

fn write_private(path: &Path, bytes: &[u8]) -> Test {
    let mut file = OpenOptions::new().create_new(true).write(true).mode(0o600).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn source_path(directory: &Directory) -> PathBuf {
    directory.0.join("selected-replay.json")
}

fn arguments(directory: &Directory, peer: SocketAddr, hevc: bool, bytes: &[u8]) -> Test<Vec<OsString>> {
    let direct = codec_replay_args(directory, peer, hevc)?;
    let mut arguments = vec![
        "from-onvif-replay".into(),
        "--onvif-source".into(), source_path(directory).into_os_string(),
        "--onvif-digest".into(), ContentDigest::sha256(bytes).to_text().into(),
    ];
    for pair in direct.chunks_exact(2) {
        if !["--peer", "--authority", "--presentation", "--codec", "--replay-start", "--replay-end"]
            .iter().any(|flag| pair[0] == *flag)
        {
            arguments.extend_from_slice(pair);
        }
    }
    Ok(arguments)
}

fn private_preview(arguments: &[OsString]) -> Test<Value> {
    let output = run("capture", arguments)?;
    redacted(&output)?;
    let preview = parse(&good(output)?)?;
    assert_eq!(text(&preview, "schema")?, ONVIF_REPLAY_APPROVAL_DOMAIN);
    assert_eq!(text(&preview, "phase")?, "planned");
    assert_eq!(text(&preview, "uri_lifetime_basis")?, "unknown");
    assert_eq!(text(value(&preview, "native_capture")?, "schema")?, "fss.rtsp_capture_cli.v1");
    Ok(preview)
}

fn redacted(output: &Output) -> Test {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        for secret in [TOKEN, PRIVATE_NAME, URI_MARKER, PRESENTATION] {
            assert!(!text.contains(secret), "private recording selection leaked in process output");
        }
    }
    Ok(())
}

fn capture_selected(
    listener: TcpListener,
    arguments: &[OsString],
    hevc: bool,
) -> Test<(Output, ReplayTranscript)> {
    thread::scope(|scope| {
        let server = scope.spawn(move || serve_replay(listener, ReplayBehavior::Target, hevc));
        let output = run("capture", arguments);
        let server = server.join().map_err(|_| "selected replay fixture thread panicked")?;
        match (output, server) {
            (Ok(output), Ok(transcript)) => Ok((output, transcript)),
            (Ok(output), Err(error)) => Err(format!(
                "selected replay fixture failed: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)
            ).into()),
            (Err(error), _) => Err(error),
        }
    })
}

fn cold_arguments(directory: &Directory, native: &Value, rows: &[Value]) -> Test<Vec<OsString>> {
    let scope = catalog_scope(native)?;
    let published = detail(rows, "replay_receipt_published")?;
    let mut arguments = vec!["inspect-replay".into(), "--root".into(), directory.root().into_os_string()];
    for (key, value) in [
        ("--codec", text(native, "codec")?.to_owned()),
        ("--sensor", scope.recording.sensor.as_str().to_owned()),
        ("--stream", scope.recording.stream.as_str().to_owned()),
        ("--generation", scope.recording.generation.to_string()),
        ("--anchor", scope.recording.anchor.to_text()),
        ("--receive-clock", scope.recording.receive_clock.to_text()),
        ("--decode-clock", scope.decode_clock.to_text()),
        ("--time-scale", scope.time_scale.to_string()),
        ("--expected-replay-root", text(published, "root")?.to_owned()),
        ("--expected-replay-request", text(published, "request_identity")?.to_owned()),
    ] {
        arguments.extend([key.into(), value.into()]);
    }
    Ok(arguments)
}

#[test]
fn onvif_selected_avc_and_hevc_replay_preserve_outer_approval_private_source_and_cold_custody() -> Test {
    for hevc in [false, true] {
        let directory = Directory::new("onvif-replay-capture")?;
        let listener = listener()?;
        let peer = listener.local_addr()?;
        let selected = selection(peer);
        let bytes = handoff(&selected, hevc)?;
        write_private(&source_path(&directory), bytes.as_bytes())?;
        let mut arguments = arguments(&directory, peer, hevc, bytes.as_bytes())?;
        let preview = private_preview(&arguments)?;
        let native = value(&preview, "native_capture")?;
        let source = value(value(native, "recorder_replay")?, "onvif_source")?;
        assert_eq!(text(source, "handoff_digest")?, ContentDigest::sha256(bytes.as_bytes()).to_text());
        assert_eq!(text(source, "recording_token_digest")?, ContentDigest::sha256(TOKEN.as_bytes()).to_text());
        assert_eq!(text(source, "information_digest")?, selected.information.digest()?.to_text());
        assert_eq!(text(source, "services_digest")?, selected.services.digest()?.to_text());
        assert_eq!(text(source, "services_response_digest")?, selected.services.response_body_digest.to_text());
        assert_eq!(text(source, "uri_digest")?, ContentDigest::sha256(selected.uri.as_bytes()).to_text());
        assert_eq!(text(source, "uri_response_digest")?, selected.uri_response_digest.to_text());
        assert_eq!(text(source, "file_identity")?, text(&preview, "onvif_file_identity")?);
        assert!(!boolean(source, "source_coverage_asserted")?);
        assert!(!directory.root().exists());
        assert!(!directory.pins().exists());
        no_connection(&listener)?;

        // A correct nested native plan is still not permission for protected-input replay.
        let mut nested = arguments.clone();
        nested.extend(["--approve".into(), text(native, "approval")?.into()]);
        let refused = run("capture", &nested)?;
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-CAPTURE-ONVIF-REPLAY-APPROVAL-001"));
        redacted(&refused)?;
        no_connection(&listener)?;
        assert!(!directory.root().exists());
        assert!(!directory.pins().exists());

        arguments.extend(["--approve".into(), text(&preview, "approval")?.into()]);
        let (output, transcript) = capture_selected(listener, &arguments, hevc)?;
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        redacted(&output)?;
        assert!(!transcript.source_eof);
        for method in ["DESCRIBE", "PLAY"] {
            let request = transcript.requests.iter().find(|request| request.method == method)
                .ok_or("missing selected replay request")?;
            assert_eq!(request.wire.lines().next().ok_or("request line")?,
                format!("{method} {} RTSP/1.0", selected.uri));
        }
        let rows = saved_rows(&directory, output)?;
        verify_saved_receipt(&directory, &preview, &rows, &transcript,
            ReplayTermination::RequestedStop, true, 2)?;
        assert_eq!(value(value(detail(&rows, "terminal")?, "recorder_replay")?, "onvif_source")?, source);

        // Cold verification is pinned to public receipt/request/scope identities and original
        // archive custody. It does not depend on a surviving private discovery file or URI.
        fs::remove_file(source_path(&directory))?;
        let mut cold = cold_arguments(&directory, native, &rows)?;
        let output = run("archive", &cold)?;
        redacted(&output)?;
        let report = parse(&good(output)?)?;
        assert_eq!(value(&report, "onvif_source")?, source);
        assert_eq!(text(&report, "approval")?, text(&preview, "approval")?);
        assert_eq!(text(&report, "requested_range")?, REQUESTED_RANGE);
        assert_eq!(text(&report, "acknowledged_range")?, ACKNOWLEDGED_RANGE);
        assert_eq!(text(&report, "coverage_claim")?, "not_claimed");
        assert!(boolean(&report, "original_source_verified")?);
        replace(&mut cold, "--expected-replay-request", &digest("different protected selection"))?;
        let refused = run("archive", &cold)?;
        assert!(!refused.status.success());
        assert!(refused.stdout.is_empty());
    }
    Ok(())
}

#[test]
fn onvif_replay_same_bytes_new_inode_and_widened_permissions_invalidate_before_effects() -> Test {
    let directory = Directory::new("onvif-replay-substitution")?;
    let listener = listener()?;
    let peer = listener.local_addr()?;
    let bytes = handoff(&selection(peer), false)?;
    let path = source_path(&directory);
    write_private(&path, bytes.as_bytes())?;
    let arguments = arguments(&directory, peer, false, bytes.as_bytes())?;
    let original = private_preview(&arguments)?;
    let mut approved = arguments.clone();
    approved.extend(["--approve".into(), text(&original, "approval")?.into()]);
    fs::rename(&path, directory.0.join("original-private-input.json"))?;
    write_private(&path, bytes.as_bytes())?;
    let replacement = private_preview(&arguments)?;
    assert_eq!(text(&replacement, "onvif_digest")?, text(&original, "onvif_digest")?);
    assert_ne!(text(&replacement, "onvif_file_identity")?, text(&original, "onvif_file_identity")?);
    assert_ne!(text(&replacement, "approval")?, text(&original, "approval")?);
    for field in ["decode_clock", "archive_namespace"] {
        assert_ne!(text(value(&replacement, "native_capture")?, field)?,
            text(value(&original, "native_capture")?, field)?);
    }
    let refused = run("capture", &approved)?;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-CAPTURE-ONVIF-REPLAY-APPROVAL-001"));
    redacted(&refused)?;
    no_connection(&listener)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    let refused = run("capture", &arguments)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    redacted(&refused)?;
    no_connection(&listener)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());
    Ok(())
}

#[test]
fn onvif_replay_consumer_rechecks_full_observed_bounds_even_with_new_file_digest() -> Test {
    let directory = Directory::new("onvif-replay-bounds")?;
    let listener = listener()?;
    let peer = listener.local_addr()?;
    let mut selected = selection(peer);
    let window = ReplayWindow::from_timestamps(REPLAY_START, REPLAY_END)?;
    let range = AdvertisedRecordingRange {
        earliest_ns: Some(i128::try_from(window.start().unix_nanoseconds())?),
        latest_ns: Some(i128::try_from(window.end().unix_nanoseconds())?),
    };
    selected.information.range = range;
    selected.information.tracks[0].range = range;
    let valid = handoff(&selected, false)?;
    assert_eq!(ReplayHandoff::parse(valid.as_bytes())?.range_assessment()?, "within_advertised_bounds");
    let changed = valid.replace(REQUESTED_RANGE, "clock=20261101T115959Z-20261101T120100Z");
    assert_ne!(changed, valid);
    write_private(&source_path(&directory), changed.as_bytes())?;
    let arguments = arguments(&directory, peer, false, changed.as_bytes())?;
    let refused = run("capture", &arguments)?;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-ONVIF-RECORDING-RANGE-001"));
    assert!(refused.stdout.is_empty());
    redacted(&refused)?;
    no_connection(&listener)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());
    Ok(())
}

#[test]
fn onvif_replay_owned_choices_and_live_handoff_contracts_cannot_be_overridden() -> Test {
    let directory = Directory::new("onvif-replay-owned-options")?;
    let listener = listener()?;
    let peer = listener.local_addr()?;
    let bytes = handoff(&selection(peer), false)?;
    write_private(&source_path(&directory), bytes.as_bytes())?;
    let original = arguments(&directory, peer, false, bytes.as_bytes())?;
    private_preview(&original)?;
    for (key, value) in [
        ("--replay-start", REPLAY_START), ("--replay-end", REPLAY_END),
        ("--codec", "hevc"), ("--peer", "127.0.0.1:1"), ("--authority", "127.0.0.1:1"),
        ("--presentation", "/unapproved"), ("--capture-mode", "reconnect"), ("--recover", "yes"),
    ] {
        let mut changed = original.clone();
        changed.extend([key.into(), value.into()]);
        let refused = run("capture", &changed)?;
        assert!(!refused.status.success());
        assert!(refused.stdout.is_empty());
        redacted(&refused)?;
    }
    let mut legacy = original;
    legacy[0] = "from-onvif".into();
    let refused = run("capture", &legacy)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    redacted(&refused)?;
    no_connection(&listener)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());
    Ok(())
}
