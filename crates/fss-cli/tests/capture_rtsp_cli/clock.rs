#![forbid(unsafe_code)]
//! Real native capture, retained clock closure, and independently pinned cold UTC lookup.

use super::*;
use std::collections::BTreeSet;
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

const OFFSET_NS: u64 = 2_000_000_000;

fn unix_now() -> Test<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    )?)
}

// Independent daemon wire encoder. It never uses the client's NTP evaluator.
fn timestamp(reply: &mut [u8; 48], at: usize, unix_ns: u64) {
    let seconds = (unix_ns / 1_000_000_000 + 2_208_988_800) as u32;
    let fraction = ((u128::from(unix_ns % 1_000_000_000) << 32) / 1_000_000_000) as u32;
    reply[at..at + 4].copy_from_slice(&seconds.to_be_bytes());
    reply[at + 4..at + 8].copy_from_slice(&fraction.to_be_bytes());
}

fn daemon(socket: UdpSocket, valid: bool) -> Test {
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut request = [0_u8; 49];
    let (length, peer) = socket.recv_from(&mut request)?;
    assert_eq!(length, 48);
    assert_eq!(request[0], 0x23);
    let received = unix_now()? + OFFSET_NS;
    let mut reply = [0_u8; 48];
    reply[0] = 0x24;
    reply[1] = 2;
    reply[2] = 6;
    reply[3] = (-20_i8) as u8;
    reply[8..12].copy_from_slice(&66_u32.to_be_bytes()); // Explicit approximately 1ms dispersion.
    reply[12..16].copy_from_slice(b"TEST");
    timestamp(&mut reply, 16, received - 1_000_000_000);
    reply[24..32].copy_from_slice(&request[40..48]);
    timestamp(&mut reply, 32, received);
    timestamp(&mut reply, 40, unix_now()? + OFFSET_NS);
    if !valid {
        reply[24] ^= 1;
    }
    assert_eq!(socket.send_to(&reply, peer)?, 48);
    Ok(())
}

fn no_datagram(socket: &UdpSocket) -> Test {
    let mut bytes = [0_u8; 49];
    match socket.recv_from(&mut bytes) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Ok(_) => Err("unapproved clock plan sent a datagram".into()),
        Err(error) => Err(error.into()),
    }
}

fn query_args(
    directory: &Directory,
    preview: &Value,
    terminal: &Value,
    index: &Value,
) -> Test<Vec<OsString>> {
    let mut args = vec![OsString::from("query-utc")];
    for (key, value) in [
        ("--root", directory.root().display().to_string()),
        ("--codec", text(preview, "codec")?.to_owned()),
        ("--sensor", text(preview, "sensor")?.to_owned()),
        ("--stream", text(preview, "stream")?.to_owned()),
        (
            "--generation",
            integer(value(preview, "bounds")?, "generation")?.to_string(),
        ),
        ("--anchor", text(preview, "anchor")?.to_owned()),
        (
            "--receive-clock",
            text(preview, "receive_clock")?.to_owned(),
        ),
        ("--decode-clock", text(preview, "decode_clock")?.to_owned()),
        ("--time-scale", "90000".to_owned()),
        (
            "--expected-snapshot",
            text(terminal, "snapshot_digest")?.to_owned(),
        ),
        ("--expected-clock-index", text(index, "root")?.to_owned()),
        ("--start-utc-ns", "0".to_owned()),
        ("--end-utc-ns", u64::MAX.to_string()),
    ] {
        args.extend([key.into(), value.into()]);
    }
    Ok(args)
}

/// Both real codec fixtures use the same producer/consumer assertions. Their
/// media helpers still own actual RTP syntax and native picture boundaries.
pub(super) fn capture_and_query(
    directory: &Directory,
    mut args: Vec<OsString>,
    capture: impl FnOnce(&[OsString]) -> Test<Output>,
) -> Test {
    let legacy = plan(&args)?.0;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = socket.local_addr()?.to_string();
    args.extend(["--clock-ntp-peer".into(), endpoint.into()]);
    let (preview, approval) = plan(&args)?;
    assert_ne!(text(&preview, "approval")?, text(&legacy, "approval")?);
    for field in ["decode_clock", "receive_clock", "archive_namespace"] {
        assert_eq!(text(&preview, field)?, text(&legacy, field)?);
    }
    assert_eq!(
        text(value(&preview, "node_clock")?, "camera_capture_time")?,
        "unknown"
    );
    args.extend(["--approve".into(), approval.into()]);
    let before = unix_now()?;
    let output = thread::scope(|scope| -> Test<Output> {
        let server = scope.spawn(move || daemon(socket, true));
        let output = capture(&args)?;
        server.join().map_err(|_| "clock daemon panicked")??;
        Ok(output)
    })?;
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let after = unix_now()?;
    let rows = rows(&output)?;
    let index = detail(&rows, "clock_index_published")?;
    let terminal = detail(&rows, "terminal")?;
    assert!(boolean(terminal, "complete")?);
    assert!(boolean(index, "durable")?);
    assert_eq!(text(terminal, "capture_time")?, "unknown");
    let clock = value(terminal, "node_clock")?;
    assert_eq!(text(clock, "state")?, "available");
    assert!(boolean(clock, "contact_attempted")?);
    assert_eq!(integer(clock, "network_bytes")?, 96);
    assert_eq!(text(value(clock, "index")?, "root")?, text(index, "root")?);

    let mut query = query_args(directory, &preview, terminal, index)?;
    // Capture has exited and its publisher/clock/runtime no longer exist.
    let report = parse(&good(run("archive", &query)?)?)?;
    assert_eq!(text(&report, "time_basis")?, "node_read_admission_bracket");
    assert_eq!(text(&report, "camera_capture_time")?, "unknown");
    assert!(!boolean(&report, "server_authenticated")?);
    assert!(!boolean(&report, "coverage_claim")?);
    assert!(!boolean(&report, "absence_claim")?);
    assert_eq!(integer(&report, "payload_bytes_emitted")?, 0);
    assert_eq!(integer(&report, "clock_unavailable_windows")?, 0);
    assert_eq!(
        integer(&report, "candidate_windows")?,
        integer(terminal, "durable_windows")?
    );
    let retained: BTreeSet<_> = rows
        .iter()
        .filter(|row| text(row, "kind").ok() == Some("window_durable"))
        .map(|row| text(value(row, "detail")?, "root").map(str::to_owned))
        .collect::<Test<_>>()?;
    let candidates = value(&report, "candidates")?
        .array()
        .ok_or("candidate array")?;
    let selected: BTreeSet<_> = candidates
        .iter()
        .map(|row| text(row, "root").map(str::to_owned))
        .collect::<Test<_>>()?;
    assert_eq!(
        retained, selected,
        "clock index must return the exact original recording roots"
    );
    let mut first = u64::MAX;
    let mut last = 0;
    for candidate in candidates {
        let interval = value(candidate, "node_admission_utc_interval_ns")?
            .array()
            .ok_or("UTC interval")?;
        let earliest = u64::try_from(interval[0].integer().ok_or("earliest integer")?)?;
        let latest = u64::try_from(interval[1].integer().ok_or("latest integer")?)?;
        assert!(earliest <= latest);
        // A +2-second daemon correction must be observable. Allow up to one
        // exchange bound plus this fixture's dispersion, sampling brackets and
        // bounded drift, without assuming symmetric path delay.
        const FIXTURE_SLACK_NS: u64 = 1_100_000_000;
        assert!(earliest > before + OFFSET_NS - FIXTURE_SLACK_NS);
        assert!(latest < after + OFFSET_NS + FIXTURE_SLACK_NS);
        first = first.min(earliest);
        last = last.max(latest);
    }
    assert!(!candidates.is_empty());
    replace(&mut query, "--end-utc-ns", &first.to_string())?;
    let before_report = parse(&good(run("archive", &query)?)?)?;
    assert_eq!(integer(&before_report, "candidate_windows")?, 0);
    assert!(!boolean(&before_report, "absence_claim")?);
    replace(&mut query, "--start-utc-ns", &last.to_string())?;
    replace(&mut query, "--end-utc-ns", &(last + 1).to_string())?;
    let boundary = parse(&good(run("archive", &query)?)?)?;
    assert!(
        integer(&boundary, "candidate_windows")? > 0,
        "closed uncertainty endpoint overlaps a half-open query"
    );
    replace(
        &mut query,
        "--expected-clock-index",
        &digest("wrong clock companion"),
    )?;
    let refused = run("archive", &query)?;
    assert!(!refused.status.success());
    assert!(
        refused.stdout.is_empty(),
        "failed exact clock pin must not leak a partial candidate result"
    );
    Ok(())
}

#[test]
fn avc_native_clock_capture_reopens_exact_originals_for_utc_queries() -> Test {
    let directory = Directory::new("clock-avc")?;
    let camera = listener()?;
    let args = args(&directory, camera.local_addr()?, 4);
    capture_and_query(&directory, args, |approved| {
        captured(camera, approved, Behavior::TwoWindows).map(|(output, _)| output)
    })
}

#[test]
fn clock_plan_and_old_approval_do_not_contact_either_endpoint() -> Test {
    let directory = Directory::new("clock-approval")?;
    let camera = listener()?;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    socket.set_nonblocking(true)?;
    let mut args = args(&directory, camera.local_addr()?, 2);
    let (_, old) = plan(&args)?;
    args.extend([
        "--clock-ntp-peer".into(),
        socket.local_addr()?.to_string().into(),
    ]);
    let _ = plan(&args)?;
    no_datagram(&socket)?;
    no_connection(&camera)?;
    args.extend(["--approve".into(), old.into()]);
    let refused = run("capture", &args)?;
    assert!(!refused.status.success());
    no_datagram(&socket)?;
    no_connection(&camera)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());
    Ok(())
}

#[test]
fn invalid_clock_reply_refuses_before_camera_connection_and_reports_actual_contact() -> Test {
    let directory = Directory::new("clock-invalid")?;
    let camera = listener()?;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let mut args = args(&directory, camera.local_addr()?, 2);
    args.extend([
        "--clock-ntp-peer".into(),
        socket.local_addr()?.to_string().into(),
    ]);
    let args = approve(&args)?;
    let output = thread::scope(|scope| -> Test<Output> {
        let server = scope.spawn(move || daemon(socket, false));
        let output = run("capture", &args)?;
        server.join().map_err(|_| "clock daemon panicked")??;
        Ok(output)
    })?;
    assert!(!output.status.success());
    let rows = rows(&output)?;
    let terminal = detail(&rows, "terminal")?;
    assert_eq!(text(terminal, "error_id")?, "ERR-CAPTURE-RTSP-CLOCK-001");
    let clock = value(terminal, "node_clock")?;
    assert_eq!(text(clock, "state")?, "clock_unavailable");
    assert!(boolean(clock, "contact_attempted")?);
    assert_eq!(integer(clock, "network_bytes")?, 96);
    assert_eq!(value(clock, "index")?, &Value::Null);
    no_connection(&camera)?;
    assert!(!directory.root().exists());
    assert!(!directory.pins().exists());
    Ok(())
}
