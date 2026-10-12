#![forbid(unsafe_code)]
//! Real HEVC source boundaries, retained window/catalog custody, and cold native decode.
//!
//! The owned loopback camera serves the pinned Main8 fixture. RTP markers and connection EOF
//! cannot stand in for a source NAL that closes a picture. Successful fixtures keep the TCP
//! write side open until the client stops; the retained source is independently reopened before
//! import, and the capture archive is taken offline before decode. Timing is an owner assumption.

use super::{
    Directory, SENSOR, SITE, STREAM, Test, approve, boolean, detail, digest, good, integer,
    listener, no_connection, parse, plan, replace, request, response, rows, run, text, value,
};
use fss_cli::json_input::Value;
use fss_core::{ContentDigest, SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording::hevc::PreparedHevcRecording;
use fss_reference::rtsp::recording::hevc::local::load_hevc_recording;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::Output;
use std::thread;
use std::time::{Duration, Instant};

const PT: u8 = 98;
const VPS: &str = "QAEMAf//AWAAAAMAkAAAAwAAAwAeugJA";
const SPS: &str = "QgEBAWAAAAMAkAAAAwAAAwAeoCCDHVZbpKTC8BaAgAAAAwCAAAADAoQ=";
const PPS: &str = "RAHAc8CJ";

fn args(directory: &Directory, peer: SocketAddr, pictures: u64) -> Test<Vec<OsString>> {
    let mut args = super::args(directory, peer, pictures);
    replace(&mut args, "--frame-duration-ticks", "18000")?;
    replace(
        &mut args,
        "--timing-evidence",
        &digest("owner asserted fixed 5fps HEVC cadence"),
    )?;
    args.extend([
        "--codec".into(),
        "hevc".into(),
        "--payload-type".into(),
        PT.to_string().into(),
    ]);
    Ok(args)
}

fn description(payloads: &[u8]) -> String {
    let offered = payloads
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let mut sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP {offered}\r\n"
    );
    for pt in payloads {
        sdp.push_str(&format!(
            "a=rtpmap:{pt} H265/90000\r\na=fmtp:{pt} sprop-vps={VPS};sprop-sps={SPS};sprop-pps={PPS}\r\n"
        ));
    }
    sdp.push_str("a=control:trackID=0\r\n");
    sdp
}

fn nals() -> Test<Vec<Vec<u8>>> {
    let fixture = include_str!("../../../../tests/fixtures/media/hevc/remux_main8.nals.hex");
    fixture
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            if !line.is_ascii() || line.len() % 2 != 0 {
                return Err("invalid pinned HEVC hex fixture".into());
            }
            (0..line.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&line[at..at + 2], 16).map_err(Into::into))
                .collect()
        })
        .collect()
}

fn packet(sequence: u16, timestamp: u32, marker: bool, nal: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, PT | if marker { 128 } else { 0 }];
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&7_u32.to_be_bytes());
    bytes.extend_from_slice(nal);
    bytes
}

#[derive(Clone, Copy)]
enum StreamCase {
    Target,
    TwoWindows,
    EofPrefix,
    MarkerEof,
    WrongCadence,
}

struct Camera {
    description: String,
    packets: Option<Vec<Vec<u8>>>,
    source_eof: bool,
}

fn camera(case: StreamCase) -> Test<Camera> {
    let nals = nals()?;
    assert_eq!(
        nals.iter()
            .map(|nal| (nal[0] >> 1) & 63)
            .collect::<Vec<_>>(),
        [32, 33, 34, 20, 1, 32, 33, 34, 20, 1],
        "pinned Main8 fixture must contain two IDR/P pairs with real parameter prefixes"
    );
    let count = match case {
        StreamCase::Target | StreamCase::WrongCadence => 6,
        StreamCase::TwoWindows => 10,
        StreamCase::EofPrefix => 5,
        StreamCase::MarkerEof => 4,
    };
    let mut times = [0, 0, 0, 0, 18_000, 36_000, 36_000, 36_000, 36_000, 54_000];
    if matches!(case, StreamCase::WrongCadence) {
        times[4] = 18_001;
    }
    let mut packets = Vec::new();
    for (at, (nal, timestamp)) in nals.iter().zip(times).take(count).enumerate() {
        // Even parameter NALs carry markers. Only actual HEVC syntax can close a picture.
        packets.push(packet(u16::try_from(at + 1)?, timestamp, true, nal));
    }
    if matches!(case, StreamCase::TwoWindows) {
        // Actual source EOS closes the final P picture; this is not transport EOF.
        packets.push(packet(11, 54_000, true, &[0x48, 1, 0x80]));
    }
    Ok(Camera {
        description: description(&[PT]),
        packets: Some(packets),
        source_eof: matches!(case, StreamCase::EofPrefix | StreamCase::MarkerEof),
    })
}

#[derive(Debug)]
struct Transcript {
    methods: Vec<String>,
    packets: Vec<Vec<u8>>,
    source_eof: bool,
}

fn accept(listener: TcpListener) -> Test<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let peer = loop {
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
    Ok(peer)
}

fn write_media(peer: &mut TcpStream, packets: &[Vec<u8>]) -> Test {
    // Native receiver probation is a real preceding datagram, not recorded source. Keep the
    // fixture's accepted RTP sequence contiguous and preserve every accepted datagram verbatim.
    let probation = packet(0, 0, false, nals()?.first().ok_or("missing fixture VPS")?);
    let mut wire = Vec::new();
    for packet in std::iter::once(&probation).chain(packets.iter()) {
        wire.extend_from_slice(&[b'$', 0]);
        wire.extend_from_slice(&u16::try_from(packet.len())?.to_be_bytes());
        wire.extend_from_slice(packet);
    }
    peer.write_all(&wire)?;
    Ok(())
}

fn serve(listener: TcpListener, camera: Camera) -> Test<Transcript> {
    let mut peer = accept(listener)?;
    let (method, cseq) = request(&mut peer)?.ok_or("HEVC client sent no DESCRIBE")?;
    assert_eq!(method, "DESCRIBE");
    let mut transcript = Transcript {
        methods: vec![method],
        packets: Vec::new(),
        source_eof: false,
    };
    response(
        &mut peer,
        cseq,
        "Content-Type: application/sdp\r\n",
        &camera.description,
    )?;
    let Some(packets) = camera.packets else {
        assert!(
            request(&mut peer)?.is_none(),
            "unsupported HEVC description acquired a remote SETUP session"
        );
        return Ok(transcript);
    };
    let (method, cseq) = request(&mut peer)?.ok_or("HEVC client sent no SETUP")?;
    assert_eq!(method, "SETUP");
    transcript.methods.push(method);
    response(
        &mut peer,
        cseq,
        "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
        "",
    )?;
    let (method, cseq) = request(&mut peer)?.ok_or("HEVC client sent no PLAY")?;
    assert_eq!(method, "PLAY");
    transcript.methods.push(method);
    response(&mut peer, cseq, "Session: fixture\r\n", "")?;

    write_media(&mut peer, &packets)?;
    transcript.packets = packets;
    if camera.source_eof {
        peer.shutdown(Shutdown::Write)?;
        transcript.source_eof = true;
    }
    // A requested stop must happen while the source remains open. Bound control processing.
    for _ in 0..16 {
        let Some((method, cseq)) = request(&mut peer)? else {
            return Ok(transcript);
        };
        transcript.methods.push(method.clone());
        match method.as_str() {
            "TEARDOWN" | "GET_PARAMETER" | "OPTIONS" => {
                response(&mut peer, cseq, "Session: fixture\r\n", "")?;
            }
            _ => return Err("unexpected HEVC fixture operation after PLAY".into()),
        }
    }
    Err("HEVC fixture exceeded its request bound".into())
}

fn captured(
    listener: TcpListener,
    args: &[OsString],
    camera: Camera,
) -> Test<(Output, Transcript)> {
    thread::scope(|scope| {
        let server = scope.spawn(move || serve(listener, camera));
        let output = run("capture", args);
        let server = server.join().map_err(|_| "HEVC fixture thread panicked")?;
        match (output, server) {
            (Ok(output), Ok(transcript)) => Ok((output, transcript)),
            (Ok(output), Err(error)) => Err(format!(
                "HEVC fixture failed: {error}; child stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into()),
            (Err(error), _) => Err(error),
        }
    })
}

fn load_windows(directory: &Directory, rows: &[Value]) -> Test<Vec<PreparedHevcRecording>> {
    let publisher = LocalRootPublisher::open(
        directory.root(),
        LocalPublicationLimits::new(
            256,
            64,
            256,
            512,
            SpoolLimits::new(1024, 64 * 1024 * 1024, 16 * 1024 * 1024, 1024),
        ),
    )?;
    let scope = RecordingScope {
        sensor: SensorId::parse(SENSOR)?,
        stream: StreamId::parse(STREAM)?,
        generation: 1,
        anchor: ContentDigest::sha256(b"capture CLI authority anchor"),
        receive_clock: ContentDigest::sha256(b"capture CLI receive clock"),
    };
    let mut windows = Vec::new();
    for row in rows {
        if text(row, "kind")? != "window_durable" {
            continue;
        }
        let report = value(row, "detail")?;
        assert_eq!(integer(report, "ordinal")?, i128::try_from(windows.len())?);
        let root = ContentDigest::parse(text(report, "root")?)?;
        let window = load_hevc_recording(
            &publisher,
            &SlotName::parse(text(report, "slot")?)?,
            root,
            &scope,
            &NeverCancel,
        )?;
        assert_eq!(window.manifest().root(), root);
        assert_eq!(text(report, "codec")?, "hevc");
        assert_eq!(window.summary().time_scale, 90_000);
        assert_eq!(
            i128::try_from(window.source_only_nals())?,
            integer(report, "source_only_nals")?
        );
        assert_eq!(
            i128::try_from(window.objects().source.len())?,
            integer(report, "source_object_bytes")?
        );
        assert_eq!(
            i128::try_from(window.summary().samples)?,
            integer(report, "pictures")?
        );
        assert_eq!(
            i128::from(window.summary().decode_interval.start),
            integer(report, "decode_start")?
        );
        assert_eq!(
            i128::from(window.summary().decode_interval.end),
            integer(report, "decode_end")?
        );
        windows.push(window);
    }
    assert_eq!(
        integer(detail(rows, "terminal")?, "durable_source_only_nals")?,
        i128::try_from(
            windows
                .iter()
                .map(PreparedHevcRecording::source_only_nals)
                .sum::<usize>()
        )?
    );
    // All returned source is owned. Release the publisher lock before real import processes.
    Ok(windows)
}

fn exact_source(window: &PreparedHevcRecording, expected: &[Vec<u8>]) -> Test {
    let retained = window.packets()?;
    assert_eq!(retained.len(), expected.len());
    for (actual, expected) in retained.iter().zip(expected) {
        assert_eq!(actual.bytes, expected.as_slice());
        assert_eq!(
            actual.sequence,
            u64::from(u16::from_be_bytes([expected[2], expected[3]]))
        );
    }
    assert!(
        retained
            .windows(2)
            .all(|pair| pair[0].received_ns <= pair[1].received_ns)
    );
    Ok(())
}

fn no_windows(rows: &[Value]) -> Test {
    let terminal = detail(rows, "terminal")?;
    assert_eq!(integer(terminal, "durable_pictures")?, 0);
    assert_eq!(integer(terminal, "durable_windows")?, 0);
    assert_eq!(integer(terminal, "indexed_windows")?, 0);
    assert_eq!(integer(terminal, "durable_source_only_nals")?, 0);
    for row in rows {
        assert!(!matches!(
            text(row, "kind")?,
            "window_durable" | "catalog_published"
        ));
    }
    Ok(())
}

fn stopped(rows: &[Value], pictures: i128, windows: i128) -> Test {
    let started = detail(rows, "started")?;
    assert_eq!(text(started, "codec")?, "hevc");
    assert_eq!(integer(started, "time_scale")?, 90_000);
    assert_eq!(text(started, "capture_time")?, "unknown");
    let terminal = detail(rows, "terminal")?;
    assert_eq!(text(terminal, "codec")?, "hevc");
    assert!(boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "owner_stopped");
    assert_eq!(value(terminal, "error_id")?, &Value::Null);
    assert!(!boolean(terminal, "peer_eof")?);
    assert!(!boolean(terminal, "input_end_observed")?);
    assert!(!boolean(terminal, "coverage_certified")?);
    assert_eq!(integer(terminal, "collected_pictures")?, pictures);
    assert_eq!(integer(terminal, "durable_pictures")?, pictures);
    assert_eq!(integer(terminal, "durable_windows")?, windows);
    assert_eq!(integer(terminal, "indexed_windows")?, windows);
    let confirmed = value(terminal, "confirmed_pin")?;
    ContentDigest::parse(text(confirmed, "root")?)?;
    ContentDigest::parse(text(confirmed, "retirement_digest")?)?;
    assert!(!text(confirmed, "slot")?.is_empty());
    Ok(())
}

fn import_and_cold_decode(
    directory: &Directory,
    rows: &[Value],
    frames: i128,
    catalog: bool,
) -> Test {
    let selected = detail(
        rows,
        if catalog {
            "catalog_published"
        } else {
            "window_durable"
        },
    )?;
    let (slot_option, root_option) = if catalog {
        ("--catalog-slot", "--catalog-root")
    } else {
        ("--window-slot", "--window-root")
    };
    let root = directory.0.join("deployment");
    let mut args: Vec<OsString> = [
        "--archive",
        directory.root().to_str().ok_or("archive path")?,
        "--root",
        root.to_str().ok_or("deployment path")?,
        "--site",
        SITE,
        slot_option,
        text(selected, "slot")?,
        root_option,
        text(selected, "root")?,
        "--codec",
        "hevc",
        "--sensor-id",
        SENSOR,
        "--stream-id",
        STREAM,
        "--generation",
        "1",
        "--anchor",
        &digest("capture CLI authority anchor"),
        "--receive-clock",
        &digest("capture CLI receive clock"),
        "--receive-time-ns",
        "5000000000",
        "--owner-authorized",
        "yes",
        "--read-originals",
        "yes",
        "--retain-originals",
        "yes",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    if catalog {
        args.extend([
            "--decode-clock".into(),
            text(selected, "decode_clock")?.into(),
            "--time-scale".into(),
            integer(selected, "time_scale")?.to_string().into(),
        ]);
    }
    let preview = parse(&good(run("import", &args)?)?)?;
    if catalog {
        assert_eq!(
            text(&preview, "format")?,
            "fss.rtsp_catalog_import_operator.v1"
        );
        assert_eq!(text(&preview, "selection")?, "complete_catalog_page");
    }
    assert!(
        !root.exists(),
        "HEVC import preview created destination custody"
    );
    args.extend([
        "--approve".into(),
        text(&preview, "approval_digest")?.into(),
    ]);
    let imported = parse(&good(run("import", &args)?)?)?;
    assert_eq!(integer(&imported, "frames")?, frames);
    assert_eq!(text(&imported, "capture_time_label")?, "unknown");
    assert!(boolean(
        &imported,
        "destination_contains_original_recording"
    )?);
    if catalog {
        assert!(boolean(&imported, "destination_contains_complete_catalog")?);
        assert_eq!(
            integer(&imported, "windows")?,
            integer(selected, "windows")?
        );
    }
    assert!(!boolean(&imported, "reused")?);
    let identity = text(&imported, "import_identity")?.to_owned();
    let origin = text(&imported, "origin_proof")?.to_owned();
    ContentDigest::parse(&origin)?;
    let ledger = fs::read(root.join("ledger/journal.fssj"))?;
    let effects = fs::read(root.join("effects/journal.fssj"))?;
    let retried = parse(&good(run("import", &args)?)?)?;
    assert!(boolean(&retried, "reused")?);
    assert_eq!(text(&retried, "import_identity")?, identity);
    assert_eq!(text(&retried, "origin_proof")?, origin);
    assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, ledger);
    assert_eq!(fs::read(root.join("effects/journal.fssj"))?, effects);

    fs::rename(directory.root(), directory.0.join("offline-capture"))?;
    let common: Vec<OsString> = [
        "--root",
        root.to_str().ok_or("deployment path")?,
        "--site",
        SITE,
        "--import-id",
        &identity,
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let mut verify = vec!["verify".into()];
    verify.extend(common.clone());
    let verified = good(run("file", &verify)?)?;
    for expected in [
        "media_format=mp4hevc".to_owned(),
        format!("segment_count={frames}"),
        "capture_time_class=unknown".to_owned(),
        "absence_certifiable=false".to_owned(),
    ] {
        assert!(verified.lines().any(|line| line == expected), "{verified}");
    }
    let mut decode = vec!["decode".into()];
    decode.extend(common);
    decode.extend(
        [
            "--segment",
            "0",
            "--segment-count",
            &frames.to_string(),
            "--interpretation",
            "ycbcr",
            "--work-units",
            "1000000000",
        ]
        .into_iter()
        .map(OsString::from),
    );
    let decoded = good(run("file", &decode)?)?;
    for expected in [
        format!("h265_frames_decoded={frames}"),
        "h265_rasl_skipped=0".to_owned(),
        "decode_complete=true".to_owned(),
        "decode_published=false".to_owned(),
    ] {
        assert!(decoded.lines().any(|line| line == expected), "{decoded}");
    }
    assert_eq!(
        decoded
            .lines()
            .filter(|line| line.starts_with("frame_luma_sha256="))
            .count(),
        usize::try_from(frames)?,
        "every requested HEVC picture must produce a native decoded-frame digest"
    );
    assert_eq!(fs::read(root.join("ledger/journal.fssj"))?, ledger);
    assert_eq!(fs::read(root.join("effects/journal.fssj"))?, effects);
    Ok(())
}

#[test]
fn codec_selection_is_pure_and_bound_to_the_exact_capture_approval() -> Test {
    let directory = Directory::new("hevc-codec-approval")?;
    let listener = listener()?;
    let hevc = args(&directory, listener.local_addr()?, 2)?;
    let mut avc = hevc.clone();
    replace(&mut avc, "--codec", "avc")?;
    let (hevc_preview, hevc_approval) = plan(&hevc)?;
    let (avc_preview, avc_approval) = plan(&avc)?;
    assert_eq!(text(&hevc_preview, "codec")?, "hevc");
    assert_eq!(text(&avc_preview, "codec")?, "avc");
    assert_eq!(
        integer(value(&hevc_preview, "bounds")?, "payload_type")?,
        i128::from(PT)
    );
    assert_ne!(
        hevc_approval, avc_approval,
        "codec substitution preserved authority"
    );
    for (mut changed, wrong_approval) in [(hevc.clone(), avc_approval), (avc, hevc_approval)] {
        changed.extend(["--approve".into(), wrong_approval.into()]);
        assert!(!run("capture", &changed)?.status.success());
    }
    let mut unknown = hevc;
    replace(&mut unknown, "--codec", "vp9")?;
    assert!(!run("capture", &unknown)?.status.success());
    no_connection(&listener)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());
    Ok(())
}

#[test]
fn requested_stop_retains_the_real_hevc_boundary_and_cold_decodes_both_pictures() -> Test {
    let directory = Directory::new("hevc-target")?;
    let listener = listener()?;
    let args = approve(&args(&directory, listener.local_addr()?, 2)?)?;
    let (output, transcript) = captured(listener, &args, camera(StreamCase::Target)?)?;
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(&transcript.methods[..3], ["DESCRIBE", "SETUP", "PLAY"]);
    assert!(!transcript.source_eof);
    let rows = rows(&output)?;
    stopped(&rows, 2, 1)?;
    let windows = load_windows(&directory, &rows)?;
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].summary().decode_interval, 0..36_000);
    assert_eq!(windows[0].source_only_nals(), 1);
    exact_source(&windows[0], &transcript.packets)?;
    assert_eq!(
        (transcript.packets.last().ok_or("missing boundary VPS")?[12] >> 1) & 63,
        32
    );
    import_and_cold_decode(&directory, &rows, 2, false)
}

#[test]
fn two_hevc_windows_share_only_the_real_source_witness_and_import_as_one_catalog() -> Test {
    let directory = Directory::new("hevc-catalog")?;
    let listener = listener()?;
    let mut args = args(&directory, listener.local_addr()?, 4)?;
    replace(&mut args, "--max-window-pictures", "2")?;
    let (preview, approval) = plan(&args)?;
    args.extend(["--approve".into(), approval.into()]);
    let (output, transcript) = captured(listener, &args, camera(StreamCase::TwoWindows)?)?;
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!transcript.source_eof);
    let rows = rows(&output)?;
    stopped(&rows, 4, 2)?;
    let windows = load_windows(&directory, &rows)?;
    assert_eq!(windows.len(), 2);
    assert_eq!(windows[0].summary().samples, 2);
    assert_eq!(windows[1].summary().samples, 2);
    assert_eq!(windows[0].summary().decode_interval, 0..36_000);
    assert_eq!(windows[1].summary().decode_interval, 36_000..72_000);
    assert_eq!(windows[0].source_only_nals(), 1);
    assert_eq!(windows[1].source_only_nals(), 0);
    exact_source(&windows[0], &transcript.packets[..6])?;
    exact_source(&windows[1], &transcript.packets[5..])?;
    let left = windows[0].packets()?;
    let right = windows[1].packets()?;
    assert_eq!(
        left.last().ok_or("left boundary witness")?.bytes,
        right[0].bytes
    );
    let catalog = detail(&rows, "catalog_published")?;
    assert_eq!(text(catalog, "codec")?, "hevc");
    assert_eq!(integer(catalog, "windows")?, 2);
    assert_eq!(integer(catalog, "time_scale")?, 90_000);
    assert_eq!(
        text(catalog, "decode_clock")?,
        text(&preview, "decode_clock")?
    );
    assert_eq!(text(value(catalog, "source")?, "sensor_id")?, SENSOR);
    assert_eq!(text(value(catalog, "source")?, "stream_id")?, STREAM);
    import_and_cold_decode(&directory, &rows, 4, true)
}

#[test]
fn early_eof_retains_only_the_source_closed_hevc_prefix_and_reports_incomplete() -> Test {
    let directory = Directory::new("hevc-eof-prefix")?;
    let listener = listener()?;
    let args = approve(&args(&directory, listener.local_addr()?, 2)?)?;
    let (output, transcript) = captured(listener, &args, camera(StreamCase::EofPrefix)?)?;
    assert!(
        !output.status.success(),
        "EOF completed the pending P picture"
    );
    assert!(transcript.source_eof);
    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "input_ended_before_target");
    assert!(boolean(terminal, "peer_eof")?);
    assert!(boolean(terminal, "input_end_observed")?);
    assert_eq!(integer(terminal, "collected_pictures")?, 1);
    assert_eq!(integer(terminal, "durable_pictures")?, 1);
    assert_eq!(integer(terminal, "durable_windows")?, 1);
    assert_eq!(integer(terminal, "indexed_windows")?, 1);
    let windows = load_windows(&directory, &rows)?;
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].summary().decode_interval, 0..18_000);
    assert_eq!(windows[0].source_only_nals(), 1);
    exact_source(&windows[0], &transcript.packets)?;
    import_and_cold_decode(&directory, &rows, 1, false)
}

#[test]
fn marker_and_eof_cannot_fabricate_a_closed_hevc_picture() -> Test {
    let directory = Directory::new("hevc-marker-eof")?;
    let listener = listener()?;
    let args = approve(&args(&directory, listener.local_addr()?, 1)?)?;
    let (output, transcript) = captured(listener, &args, camera(StreamCase::MarkerEof)?)?;
    assert!(
        !output.status.success(),
        "marker/EOF fabricated a complete IDR"
    );
    assert!(transcript.source_eof);
    assert!(transcript.packets.iter().all(|packet| packet[1] & 128 != 0));
    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "input_ended_before_target");
    assert!(boolean(terminal, "peer_eof")?);
    assert!(boolean(terminal, "input_end_observed")?);
    assert_eq!(integer(terminal, "collected_pictures")?, 0);
    assert!(!boolean(terminal, "coverage_certified")?);
    no_windows(&rows)
}

#[test]
fn hevc_cadence_mismatch_is_refused_without_inventing_decode_timestamps() -> Test {
    let directory = Directory::new("hevc-cadence")?;
    let listener = listener()?;
    let args = approve(&args(&directory, listener.local_addr()?, 2)?)?;
    let (output, transcript) = captured(listener, &args, camera(StreamCase::WrongCadence)?)?;
    assert!(!output.status.success());
    assert!(!transcript.source_eof);
    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "timing_refused");
    assert_eq!(integer(terminal, "collected_pictures")?, 1);
    assert!(integer(terminal, "unsealed_rtp_bytes")? > 0);
    assert!(integer(terminal, "untimed_picture_bytes")? > 0);
    assert!(!boolean(terminal, "coverage_certified")?);
    assert_eq!(text(terminal, "capture_time")?, "unknown");
    no_windows(&rows)
}

#[test]
fn unsupported_hevc_payloads_and_sdp_configurations_are_refused_before_setup() -> Test {
    let valid = description(&[PT]);
    let cases = [
        ("wrong-payload", description(&[99])),
        ("ambiguous-payload", description(&[PT, 99])),
        ("wrong-codec", valid.replace("H265/90000", "H264/90000")),
        ("wrong-clock", valid.replace("H265/90000", "H265/48000")),
        (
            "missing-pps",
            valid.replace(&format!(";sprop-pps={PPS}"), ""),
        ),
        (
            "wrong-pps-kind",
            valid.replace(&format!("sprop-pps={PPS}"), &format!("sprop-pps={VPS}")),
        ),
    ];
    for (label, description) in cases {
        let directory = Directory::new(&format!("hevc-{label}"))?;
        let listener = listener()?;
        let args = approve(&args(&directory, listener.local_addr()?, 2)?)?;
        let (output, transcript) = captured(
            listener,
            &args,
            Camera {
                description,
                packets: None,
                source_eof: false,
            },
        )?;
        assert!(
            !output.status.success(),
            "unsupported SDP case accepted: {label}"
        );
        assert_eq!(transcript.methods, ["DESCRIBE"], "{label}");
        let rows = rows(&output)?;
        let terminal = detail(&rows, "terminal")?;
        assert!(!boolean(terminal, "complete")?);
        assert_eq!(integer(terminal, "collected_pictures")?, 0);
        assert!(value(terminal, "error_id")?.text().is_some());
        no_windows(&rows)?;
    }
    Ok(())
}

#[test]
fn hevc_no_auth_capture_refuses_challenges_without_retry_or_secret_disclosure() -> Test {
    let directory = Directory::new("hevc-authentication")?;
    let listener = listener()?;
    let args = approve(&args(&directory, listener.local_addr()?, 2)?)?;
    let (output, transcript) =
        super::captured(listener, &args, super::Behavior::AuthenticationRequired)?;
    assert!(!output.status.success());
    assert_eq!(transcript.methods, ["DESCRIBE"]);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for secret in [super::SECRET_REALM, super::SECRET_NONCE, "WWW-Authenticate"] {
        assert!(
            !combined.contains(secret),
            "HEVC challenge material leaked into output"
        );
    }
    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert!(!boolean(terminal, "complete")?);
    assert_eq!(text(terminal, "stop_cause")?, "authentication_required");
    assert_eq!(integer(terminal, "collected_pictures")?, 0);
    no_windows(&rows)
}

#[cfg(target_os = "linux")]
mod authenticated {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;

    // Synthetic fixture credentials only. The ordinary private-file lease is the only route
    // into the capture process; neither argv nor the camera provides credential material.
    const USER: &str = "FSS_HEVC_SYNTHETIC_USERNAME_CANARY";
    const PASSWORD: &str = "FSS_HEVC_SYNTHETIC_PASSWORD_CANARY";
    const REALM: &str = "FSS_HEVC_SYNTHETIC_REALM_CANARY";
    const NONCE: &str = "FSS_HEVC_SYNTHETIC_NONCE_CANARY";

    struct Request {
        method: String,
        target: String,
        cseq: u32,
        authorization: Option<String>,
    }

    fn read_request(peer: &mut TcpStream) -> Test<Option<Request>> {
        let mut bytes = Vec::new();
        while bytes.len() < 8192 {
            let mut byte = [0];
            match peer.read(&mut byte) {
                Ok(0) if bytes.is_empty() => return Ok(None),
                Ok(0) => return Err("HEVC client closed inside a request".into()),
                Ok(_) => bytes.push(byte[0]),
                Err(error)
                    if error.kind() == io::ErrorKind::ConnectionReset && bytes.is_empty() =>
                {
                    return Ok(None);
                }
                Err(error) => return Err(error.into()),
            }
            if !bytes.ends_with(b"\r\n\r\n") {
                continue;
            }
            let wire = String::from_utf8(bytes)?;
            assert!(
                !wire.contains(PASSWORD),
                "HEVC client sent a plaintext password"
            );
            let mut lines = wire.split("\r\n");
            let mut start = lines
                .next()
                .ok_or("missing start line")?
                .split_ascii_whitespace();
            let method = start.next().ok_or("missing method")?.to_owned();
            let target = start.next().ok_or("missing URI")?.to_owned();
            assert_eq!(start.next(), Some("RTSP/1.0"));
            assert!(start.next().is_none());
            let mut cseq = None;
            let mut authorization = None;
            for line in lines.filter(|line| !line.is_empty()) {
                let (name, value) = line.split_once(':').ok_or("invalid RTSP header")?;
                if name.eq_ignore_ascii_case("cseq") {
                    assert!(cseq.replace(value.trim().parse()?).is_none());
                }
                if name.eq_ignore_ascii_case("authorization") {
                    assert!(authorization.replace(value.trim().to_owned()).is_none());
                }
            }
            return Ok(Some(Request {
                method,
                target,
                cseq: cseq.ok_or("missing CSeq")?,
                authorization,
            }));
        }
        Err("HEVC authenticated request exceeded its fixture bound".into())
    }

    fn signed(request: &Request, count: u32) -> Test<String> {
        let header = request
            .authorization
            .as_deref()
            .ok_or("missing Authorization")?;
        let body = header
            .strip_prefix("Digest ")
            .ok_or("unexpected authentication scheme")?;
        let mut fields = BTreeMap::new();
        for directive in body.split(',') {
            let (name, value) = directive
                .trim()
                .split_once('=')
                .ok_or("invalid Digest directive")?;
            assert!(fields.insert(name, value.trim_matches('"')).is_none());
        }
        let get = |key| fields.get(key).copied().ok_or("missing Digest directive");
        assert_eq!(get("username")?, USER);
        assert_eq!(get("realm")?, REALM);
        assert_eq!(get("nonce")?, NONCE);
        assert_eq!(get("uri")?, request.target);
        assert_eq!(get("algorithm")?, "SHA-256");
        assert_eq!(get("qop")?, "auth");
        assert_eq!(get("nc")?, format!("{count:08x}"));
        let cnonce = get("cnonce")?;
        assert_eq!(cnonce.len(), 32);
        assert!(cnonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(
            cnonce, "00000000000000000000000000000000",
            "placeholder cnonce escaped"
        );
        // Independent response composition verifies actual wire method, URI and nonce count.
        // Do not use the production challenge parser or Authorization generator as its oracle.
        let hash = |text: &str| ContentDigest::sha256(text.as_bytes()).to_text()[7..].to_owned();
        let a1 = hash(&format!("{USER}:{REALM}:{PASSWORD}"));
        let a2 = hash(&format!("{}:{}", request.method, request.target));
        assert_eq!(
            get("response")?,
            hash(&format!("{a1}:{NONCE}:{count:08x}:{cnonce}:auth:{a2}"))
        );
        Ok(cnonce.to_owned())
    }

    fn serve_authenticated(listener: TcpListener) -> Test<Transcript> {
        let address = listener.local_addr()?;
        let mut peer = accept(listener)?;
        let first = read_request(&mut peer)?.ok_or("missing initial HEVC DESCRIBE")?;
        assert_eq!(first.method, "DESCRIBE");
        assert_eq!(first.target, format!("rtsp://{address}/live/"));
        assert_eq!(first.cseq, 1);
        assert!(first.authorization.is_none());
        peer.write_all(format!(
            "RTSP/1.0 401 Unauthorized\r\nCSeq: {}\r\nWWW-Authenticate: Digest realm=\"{REALM}\", nonce=\"{NONCE}\", algorithm=SHA-256, qop=\"auth\"\r\nContent-Length: 0\r\n\r\n", first.cseq
        ).as_bytes())?;
        let camera = camera(StreamCase::Target)?;
        let mut methods = vec![first.method];
        let mut cnonces = Vec::new();
        for (count, method, target, headers, body) in [
            (
                1,
                "DESCRIBE",
                first.target.clone(),
                "Content-Type: application/sdp\r\n",
                camera.description.as_str(),
            ),
            (
                2,
                "SETUP",
                format!("rtsp://{address}/live/trackID=0"),
                "Session: fixture;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=7\r\n",
                "",
            ),
            (3, "PLAY", first.target, "Session: fixture\r\n", ""),
        ] {
            let request = read_request(&mut peer)?.ok_or("missing signed HEVC request")?;
            assert_eq!(request.method, method);
            assert_eq!(request.target, target);
            assert_eq!(request.cseq, count + 1);
            let cnonce = signed(&request, count)?;
            assert!(
                !cnonces.contains(&cnonce),
                "owner reused an HEVC Digest cnonce"
            );
            cnonces.push(cnonce);
            methods.push(request.method);
            response(&mut peer, request.cseq, headers, body)?;
        }
        assert_eq!(cnonces.len(), 3);
        let packets = camera.packets.ok_or("missing authenticated media")?;
        write_media(&mut peer, &packets)?;
        // In particular, final sealing must not dispatch a placeholder-signed control request.
        assert!(
            read_request(&mut peer)?.is_none(),
            "HEVC target stop dispatched another request"
        );
        Ok(Transcript {
            methods,
            packets,
            source_eof: false,
        })
    }

    fn no_secrets(bytes: &[u8]) {
        for secret in [
            USER,
            PASSWORD,
            REALM,
            NONCE,
            "Authorization:",
            "WWW-Authenticate:",
        ] {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "authentication material entered public output or retained custody"
            );
        }
    }

    fn secret_free_custody(directory: &Directory) -> Test {
        let mut pending = vec![
            directory.root(),
            directory.pins(),
            directory.0.join("deployment"),
        ];
        let mut visited = 0;
        while let Some(path) = pending.pop() {
            if !path.exists() {
                continue;
            }
            visited += 1;
            assert!(
                visited <= 4096,
                "fixture custody traversal exceeded its bound"
            );
            if path.is_dir() {
                for child in fs::read_dir(path)? {
                    pending.push(child?.path());
                }
            } else {
                no_secrets(&fs::read(path)?);
            }
        }
        Ok(())
    }

    #[test]
    fn digest_hevc_capture_uses_fresh_cnonces_and_cold_decodes_without_secret_custody() -> Test {
        let directory = Directory::new("hevc-digest")?;
        let listener = listener()?;
        let credential = directory.0.join("credential");
        fs::write(&credential, format!("{USER}\n{PASSWORD}\n"))?;
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))?;
        let mut args = args(&directory, listener.local_addr()?, 2)?;
        args.extend([
            "--credential-file".into(),
            credential.as_os_str().to_owned(),
            "--auth-realm".into(),
            REALM.into(),
        ]);
        let args = approve(&args)?;
        let (output, transcript) = thread::scope(|scope| -> Test<(Output, Transcript)> {
            let server = scope.spawn(move || serve_authenticated(listener));
            let output = run("capture", &args)?;
            let transcript = server
                .join()
                .map_err(|_| "authenticated HEVC fixture panicked")?
                .map_err(|error| {
                    format!(
                        "{error}; child stdout={} stderr={}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    )
                })?;
            Ok((output, transcript))
        })?;
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            transcript.methods,
            ["DESCRIBE", "DESCRIBE", "SETUP", "PLAY"]
        );
        assert!(!transcript.source_eof);
        no_secrets(&output.stdout);
        no_secrets(&output.stderr);
        secret_free_custody(&directory)?;
        let rows = rows(&output)?;
        stopped(&rows, 2, 1)?;
        let terminal = detail(&rows, "terminal")?;
        assert_eq!(text(terminal, "authentication")?, "digest");
        assert_eq!(integer(terminal, "authentication_challenges")?, 1);
        assert_eq!(integer(terminal, "authentication_responses_queued")?, 1);
        assert_eq!(integer(terminal, "digest_requests_queued")?, 3);
        assert!(!boolean(terminal, "server_identity_verified")?);
        assert!(!boolean(terminal, "transport_encrypted")?);
        let windows = load_windows(&directory, &rows)?;
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].source_only_nals(), 1);
        exact_source(&windows[0], &transcript.packets)?;
        import_and_cold_decode(&directory, &rows, 2, false)?;
        secret_free_custody(&directory)
    }
}
