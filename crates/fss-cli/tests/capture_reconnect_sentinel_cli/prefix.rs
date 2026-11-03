#![forbid(unsafe_code)]
//! Requested-count analysis of an HTTP camera that does not end its response.

use super::*;

const PREFIX_FORMAT: &str = "fss.http_prefix_capture_sentinel.v1";
const PREFIX_SCHEMA: &str = "http_prefix_capture_sentinel.v1.json";
const OFFERED_FRAMES: usize = FRAMES + 2;

fn prefix_args(fixture: &Fixture, camera: &TcpListener) -> Test<Vec<OsString>> {
    let mut args = fixture.args(camera)?;
    args[0] = "sentinel-prefix".into();
    // Admit complete read-ahead originals separately from the four acknowledged source frames.
    for key in ["--max-frames", "--max-frames-per-generation"] {
        let position = args
            .iter()
            .position(|arg| arg == key)
            .ok_or("frame ceiling")?;
        args[position + 1] = "8".into();
    }
    args.extend(["--stop-after-frames".into(), FRAMES.to_string().into()]);
    args.extend(["--max-output-bytes".into(), "8388608".into()]);
    Ok(args)
}

fn approved_prefix(fixture: &Fixture, mut args: Vec<OsString>) -> Test<Vec<OsString>> {
    let output = fixture.run(&args)?;
    good(&output);
    fixture.validate_parent_rows(&output, PREFIX_FORMAT, PREFIX_SCHEMA)?;
    let rows = rows(&output)?;
    let plan = row(&rows, PREFIX_FORMAT, "plan")?;
    assert_eq!(text(plan, &["writes"])?, "none");
    assert_eq!(text(plan, &["network"])?, "none");
    let approval = text(plan, &["approval_digest"])?;
    ContentDigest::parse(approval)?;
    args.extend(["--approve".into(), approval.into()]);
    Ok(args)
}

fn option<'a>(args: &'a [String], key: &str) -> Test<&'a str> {
    let index = args
        .iter()
        .position(|arg| arg == key)
        .ok_or("continuation option")?;
    args.get(index + 1)
        .map(String::as_str)
        .ok_or("continuation value".into())
}

fn streaming_response() -> Test<Vec<u8>> {
    let mut pixels = vec![40_u8; 48 * 32];
    for y in 8..24 {
        for x in 8..24 {
            pixels[y * 48 + x] = 220;
        }
    }
    let jpeg = encode_jpeg(
        48,
        32,
        &pixels,
        &JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: vec![],
        },
    )?;
    // No Content-Length, chunk terminator, MIME terminator or peer EOF completes this source.
    let mut wire =
        b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=camera\r\n\r\n"
            .to_vec();
    for _ in 0..OFFERED_FRAMES {
        wire.extend_from_slice(
            format!(
                "--camera\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
                jpeg.len(),
            )
            .as_bytes(),
        );
        wire.extend_from_slice(&jpeg);
        wire.extend_from_slice(b"\r\n");
    }
    // Native MIME releases the final offered JPEG only after seeing the following delimiter.
    wire.extend_from_slice(b"--camera\r\n");
    Ok(wire)
}

/// Unlike the ended fixture, this server keeps the response open until the capture owner closes
/// its side at the requested frame count. It cannot make an EOF-dependent implementation pass.
struct StreamingCamera {
    cancel: Arc<AtomicBool>,
    client_closed: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<TcpListener, String>>>,
}
impl StreamingCamera {
    fn start(listener: TcpListener, bytes: Vec<u8>) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&cancel);
        let client_closed = Arc::new(AtomicBool::new(false));
        let closed = Arc::clone(&client_closed);
        let thread = thread::spawn(move || {
            let start = Instant::now();
            let mut socket = loop {
                if stopped.load(Ordering::Acquire) || start.elapsed() > Duration::from_secs(300) {
                    return Err("streaming fixture cancelled before contact".into());
                }
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => return Err(error.to_string()),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|e| e.to_string())?;
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .map_err(|e| e.to_string())?;
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                if request.len() >= 4096 {
                    return Err("streaming HTTP request bound".into());
                }
                socket.read_exact(&mut byte).map_err(|e| e.to_string())?;
                request.push(byte[0]);
            }
            if !request.starts_with(b"GET /stream HTTP/1.1\r\n") {
                return Err("unexpected streaming camera request".into());
            }
            socket.write_all(&bytes).map_err(|e| e.to_string())?;
            // Exceeds capture's 30-second bound: a camera waiting for EOF fails before this
            // fixture releases its connection. Successful requested-count capture closes first.
            socket
                .set_read_timeout(Some(Duration::from_secs(45)))
                .map_err(|e| e.to_string())?;
            match socket.read(&mut byte) {
                Ok(0) => closed.store(true, Ordering::Release),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                    // Closing with unread read-ahead bytes may reset the socket instead of FIN.
                    closed.store(true, Ordering::Release);
                }
                Ok(_) => return Err("unexpected second request on streaming connection".into()),
                Err(error) => {
                    return Err(format!("client did not stop the open response: {error}"));
                }
            }
            Ok(listener)
        });
        Self {
            cancel,
            client_closed,
            thread: Some(thread),
        }
    }
    fn finish(mut self) -> Test<TcpListener> {
        self.cancel.store(true, Ordering::Release);
        let listener = self
            .thread
            .take()
            .ok_or("streaming camera join")?
            .join()
            .map_err(|_| "streaming camera panicked")??;
        assert!(self.client_closed.load(Ordering::Acquire));
        Ok(listener)
    }
}
impl Drop for StreamingCamera {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn prefix_preview_binds_the_requested_stop_and_refuses_before_camera_io() -> Test {
    let fixture = Fixture::new("prefix-preflight")?;
    let camera = listener()?;
    let args = prefix_args(&fixture, &camera)?;
    let approved = approved_prefix(&fixture, args.clone())?;
    fixture.absent();
    assert!(!fixture.package.exists());
    no_contact(&camera)?;

    let mut changed = approved.clone();
    let position = changed
        .iter()
        .position(|arg| arg == "--stop-after-frames")
        .ok_or("stop")?;
    changed[position + 1] = "3".into();
    let refused = fixture.run(&changed)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    fixture.absent();
    no_contact(&camera)?;

    let mut missing_stop = args;
    let position = missing_stop
        .iter()
        .position(|arg| arg == "--stop-after-frames")
        .ok_or("stop")?;
    missing_stop.drain(position..position + 2);
    let refused = fixture.run(&missing_stop)?;
    assert!(!refused.status.success());
    fixture.absent();
    no_contact(&camera)?;

    fs::write(&fixture.package, b"not the approved prefix detector")?;
    let refused = fixture.run(&approved)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    fixture.absent();
    no_contact(&camera)?;
    Ok(())
}

#[test]
fn open_http_response_stops_at_approved_prefix_and_retains_exact_cold_replay() -> Test {
    let fixture = Fixture::new("prefix-retained")?;
    fs::write(&fixture.package, PACKAGE)?;
    let camera = listener()?;
    let approved = approved_prefix(&fixture, prefix_args(&fixture, &camera)?)?;
    fixture.absent();
    no_contact(&camera)?;
    let server = StreamingCamera::start(camera, streaming_response()?);
    let captured = fixture.run(&approved)?;
    let camera = server.finish();
    good(&captured);
    let camera = camera?;
    fixture.validate_parent_rows(&captured, PREFIX_FORMAT, PREFIX_SCHEMA)?;
    let captured_rows = rows(&captured)?;
    assert!(
        !captured_rows
            .iter()
            .any(|value| matches(value, CAPTURE_FORMAT, "history_durable")),
        "a requested prefix must not fabricate ended reconnect history"
    );
    let ready = row(&captured_rows, PREFIX_FORMAT, "prefix_ready")?;
    assert_eq!(
        field(ready, &["detail", "acknowledged_frames"])?.integer(),
        Some(FRAMES as i128)
    );
    let source = field(ready, &["detail", "source_prefix"])?;
    for key in [
        "source",
        "receive_clock",
        "retention_evidence",
        "prefix_root",
    ] {
        ContentDigest::parse(text(source, &[key])?)?;
    }
    assert_eq!(field(source, &["generation"])?.integer(), Some(10));
    assert!(field(source, &["reads"])?.integer().is_some_and(|n| n > 0));
    assert!(field(source, &["bytes"])?.integer().is_some_and(|n| n > 0));
    let import_args = argv(field(ready, &["detail", "offline_import_argv"])?)?;
    assert_eq!(
        import_args.first().map(String::as_str),
        Some("fss-import-http")
    );
    ContentDigest::parse(option(&import_args, "--approve")?)?;
    assert_eq!(
        option(&import_args, "--head")?,
        text(source, &["prefix_root"])?
    );
    assert_eq!(
        option(&import_args, "--source")?,
        text(source, &["source"])?
    );

    let imported = row(&captured_rows, PREFIX_FORMAT, "imported")?;
    let identity = text(imported, &["detail", "import_identity"])?;
    ContentDigest::parse(identity)?;
    let import_root = text(imported, &["detail", "import_root"])?;
    ContentDigest::parse(import_root)?;
    let imported_frames = field(imported, &["detail", "imported_frames"])?
        .integer()
        .ok_or("imported frames")?;
    let read_ahead = field(imported, &["detail", "imported_read_ahead_frames"])?
        .integer()
        .ok_or("read-ahead frames")?;
    assert!((FRAMES as i128..=OFFERED_FRAMES as i128).contains(&imported_frames));
    assert_eq!(
        field(imported, &["detail", "acknowledged_frames"])?.integer(),
        Some(FRAMES as i128)
    );
    assert_eq!(imported_frames, FRAMES as i128 + read_ahead);
    let analysis_args = argv(field(imported, &["detail", "offline_analysis_argv"])?)?;
    assert_eq!(
        analysis_args.get(1).map(String::as_str),
        Some("package-detect")
    );
    assert_eq!(option(&analysis_args, "--import-id")?, identity);
    assert_eq!(option(&analysis_args, "--stream-sentinel")?, "yes");
    assert_eq!(option(&analysis_args, "--retain")?, "yes");
    assert_eq!(option(&analysis_args, "--max-output-bytes")?, "8388608");
    assert_eq!(option(&analysis_args, "--first-segment")?, "0");
    assert_eq!(option(&analysis_args, "--frames")?, FRAMES.to_string());

    let completed = row(&captured_rows, PREFIX_FORMAT, "completed")?;
    assert_eq!(text(completed, &["detail", "import_identity"])?, identity);
    assert_eq!(
        text(completed, &["detail", "source_ending"])?,
        "pinned_prefix"
    );
    for key in [
        "source_eof_asserted",
        "ended_history_asserted",
        "event_publication_authorized",
    ] {
        assert_eq!(
            field(completed, &["detail", key])?.boolean(),
            Some(false),
            "{key}"
        );
    }
    assert_eq!(
        field(completed, &["detail", "acknowledged_frames"])?.integer(),
        Some(FRAMES as i128)
    );
    assert_eq!(
        field(completed, &["detail", "imported_read_ahead_frames"])?.integer(),
        Some(read_ahead)
    );
    let report = field(completed, &["detail", "report"])?;
    assert_eq!(
        text(report, &["schema"])?,
        "fss.long_sentinel_detection_report.v1"
    );
    assert_eq!(text(report, &["source_import"])?, identity);
    assert_eq!(text(report, &["import_root"])?, import_root);
    assert_eq!(
        field(report, &["decode_range", "first_segment"])?.integer(),
        Some(0)
    );
    assert_eq!(
        field(report, &["decode_range", "segment_count"])?.integer(),
        Some(FRAMES as i128)
    );
    assert_eq!(
        field(report, &["resource_usage", "inferences"])?.integer(),
        Some(1)
    );
    assert_eq!(
        field(report, &["resource_usage", "decoded_frames"])?.integer(),
        Some(1)
    );
    assert_eq!(
        field(report, &["sampling", "motion_independent"])?.boolean(),
        Some(true)
    );
    for key in [
        "continuous_coverage",
        "absence_certifiable",
        "effects_authorized",
    ] {
        assert_eq!(field(report, &[key])?.boolean(), Some(false), "{key}");
    }
    let replay = argv(field(
        completed,
        &["detail", "native_sentinel_replay_argv"],
    )?)?;
    assert_eq!(replay.get(1).map(String::as_str), Some("sentinel-replay"));
    ContentDigest::parse(option(&replay, "--report-digest")?)?;
    assert_eq!(option(&replay, "--max-output-bytes")?, "8388608");
    let journals = fixture.journals()?;
    let originals = archive_bytes(&fixture.archive)?;

    let duplicate = fixture.run(&approved)?;
    assert!(!duplicate.status.success());
    assert!(duplicate.stdout.is_empty());
    no_contact(&camera)?;
    assert_eq!(archive_bytes(&fixture.archive)?, originals);
    assert_eq!(fixture.journals()?, journals);

    let imported_again = Command::new(env!("CARGO_BIN_EXE_fss-import-http"))
        .args(&import_args[1..])
        .output()?;
    good(&imported_again);
    let imported_again = parse(std::str::from_utf8(&imported_again.stdout)?)?;
    assert_eq!(text(&imported_again, &["kind"])?, "imported");
    assert_eq!(text(&imported_again, &["import_identity"])?, identity);
    assert_eq!(text(&imported_again, &["import_root"])?, import_root);
    assert_eq!(
        field(&imported_again, &["frames"])?.integer(),
        Some(imported_frames)
    );
    assert_eq!(text(&imported_again, &["source_ending"])?, "pinned_prefix");
    assert_eq!(fixture.journals()?, journals);

    let analyzed_again = run_continuation(&analysis_args)?;
    good(&analyzed_again);
    assert_eq!(
        &parse(std::str::from_utf8(&analyzed_again.stdout)?)?,
        report
    );
    assert_eq!(
        fixture.journals()?,
        journals,
        "exact prefix analysis appended state"
    );
    no_contact(&camera)?;

    fs::rename(
        &fixture.archive,
        fixture.directory.join("offline streaming archive"),
    )?;
    fs::remove_file(&fixture.package)?;
    let replayed = run_continuation(&replay)?;
    good(&replayed);
    assert_eq!(&parse(std::str::from_utf8(&replayed.stdout)?)?, report);
    assert_eq!(
        fixture.journals()?,
        journals,
        "cold prefix replay changed state"
    );
    no_contact(&camera)?;
    Ok(())
}

#[test]
fn incomplete_requested_prefix_keeps_custody_without_automatic_analysis() -> Test {
    let fixture = Fixture::new("prefix-short")?;
    fs::write(&fixture.package, PACKAGE)?;
    let camera = listener()?;
    let approved = approved_prefix(&fixture, prefix_args(&fixture, &camera)?)?;
    let server = Camera::start(camera, response(true)?);
    let captured = fixture.run(&approved)?;
    let camera = server.finish()?;
    assert!(!captured.status.success());
    fixture.validate_parent_rows(&captured, PREFIX_FORMAT, PREFIX_SCHEMA)?;
    let rows = rows(&captured)?;
    for kind in ["imported", "completed"] {
        assert!(!rows.iter().any(|value| matches(value, PREFIX_FORMAT, kind)));
    }
    let history = row(&rows, CAPTURE_FORMAT, "history_durable")?;
    assert_eq!(
        text(history, &["detail", "boundary", "outcome"])?,
        "source_failed"
    );
    assert_eq!(
        field(history, &["detail", "boundary", "frames_parsed"])?.integer(),
        Some(1)
    );
    ContentDigest::parse(text(history, &["detail", "history_pin", "root"])?)?;
    assert!(fixture.archive.is_dir());
    assert!(
        !fixture.deployment.exists(),
        "an unsatisfied stop count entered perception"
    );
    no_contact(&camera)?;
    Ok(())
}
