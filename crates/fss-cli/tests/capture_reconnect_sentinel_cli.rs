#![forbid(unsafe_code)]
//! Real-process live HTTP acquisition → native stationary-image analysis → retained replay.
//! Only synthetic loopback camera bytes are used; model outputs do not certify scene absence.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const FORMAT: &str = "fss.http_capture_sentinel.v1";
const CAPTURE_FORMAT: &str = "fss.http_reconnect_capture.v1";
const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const FRAMES: usize = 4;

#[path = "capture_reconnect_sentinel_cli/prefix.rs"]
mod prefix;

fn field<'a>(value: &'a Value, path: &[&str]) -> Test<&'a Value> {
    let mut value = value;
    for key in path {
        value = value
            .object()
            .and_then(|fields| fields.get(*key))
            .ok_or_else(|| format!("missing {key}"))?;
    }
    Ok(value)
}
fn text<'a>(value: &'a Value, path: &[&str]) -> Test<&'a str> {
    field(value, path)?.text().ok_or("expected text".into())
}
fn rows(output: &Output) -> Test<Vec<Value>> {
    std::str::from_utf8(&output.stdout)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| parse(line).map_err(Into::into))
        .collect()
}
fn matches(row: &Value, format: &str, kind: &str) -> bool {
    text(row, &["format"]).ok() == Some(format) && text(row, &["kind"]).ok() == Some(kind)
}
fn row<'a>(rows: &'a [Value], format: &str, kind: &str) -> Test<&'a Value> {
    let mut found = rows.iter().filter(|value| matches(value, format, kind));
    let value = found
        .next()
        .ok_or_else(|| format!("missing {format}/{kind}"))?;
    assert!(found.next().is_none(), "duplicate {format}/{kind}");
    Ok(value)
}
fn good(output: &Output) {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
}
fn argv(value: &Value) -> Test<Vec<String>> {
    value
        .array()
        .ok_or("argv array")?
        .iter()
        .map(|arg| arg.text().map(str::to_owned).ok_or("argv string".into()))
        .collect()
}
fn run_continuation(args: &[String]) -> Test<Output> {
    // Execute only the named, compiled owner. No shell interprets the emitted argv.
    let binary = match args.first().map(String::as_str) {
        Some("fss-sentinel-http-history") => env!("CARGO_BIN_EXE_fss-sentinel-http-history"),
        Some("fss-infer") => env!("CARGO_BIN_EXE_fss-infer"),
        _ => return Err("unexpected continuation owner".into()),
    };
    Ok(Command::new(binary).args(&args[1..]).output()?)
}
fn no_contact(listener: &TcpListener) -> Test {
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Ok(_) => Err("camera contacted without an admitted acquisition".into()),
        Err(error) => Err(error.into()),
    }
}

struct Fixture {
    directory: PathBuf,
    archive: PathBuf,
    deployment: PathBuf,
    package: PathBuf,
}
impl Fixture {
    fn new(tag: &str) -> Test<Self> {
        for serial in 0..100 {
            let directory = std::env::temp_dir().join(format!(
                "fss-live-sentinel-{tag}-{}-{serial}",
                std::process::id()
            ));
            match fs::create_dir(&directory) {
                Ok(()) => {
                    return Ok(Self {
                        archive: directory.join("camera archive"),
                        deployment: directory.join("analysis deployment"),
                        package: directory.join("pinned native detector.fmpk"),
                        directory,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("owned fixture directory bound".into())
    }
    fn args(&self, listener: &TcpListener) -> Test<Vec<OsString>> {
        let source = ContentDigest::sha256(b"live-sentinel-camera").to_text();
        let clock = ContentDigest::sha256(b"live-sentinel-receive-clock").to_text();
        let retention = ContentDigest::sha256(b"live-sentinel-retention").to_text();
        let package = ContentDigest::sha256(PACKAGE).to_text();
        Ok([
            "sentinel",
            "--root",
            self.archive.to_str().ok_or("archive path")?,
            "--deployment-root",
            self.deployment.to_str().ok_or("deployment path")?,
            "--package",
            self.package.to_str().ok_or("package path")?,
            "--package-digest",
            &package,
            "--peer",
            &listener.local_addr()?.to_string(),
            "--host",
            "camera.invalid",
            "--target",
            "/stream",
            "--source",
            &source,
            "--receive-clock",
            &clock,
            "--retention-evidence",
            &retention,
            "--generations",
            "10",
            "--principal",
            "principal:live-sentinel-test",
            "--owner-authorized",
            "yes",
            "--plaintext",
            "yes",
            "--retain-originals",
            "yes",
            "--durable-history",
            "yes",
            "--after-complete",
            "yes",
            "--max-frames",
            "4",
            "--max-reads",
            "16",
            "--max-source-bytes",
            "1048576",
            "--timeout-ms",
            "30000",
            "--connect-timeout-ms",
            "5000",
            "--initial-backoff-ms",
            "1",
            "--maximum-backoff-ms",
            "2",
            "--site",
            "site:live-sentinel-test",
            "--binding",
            "10,sensor:porch,stream:porch,50000000000,0,0,10",
            "--interpretation",
            "gray",
            "--read-originals",
            "yes",
            "--read-model",
            "yes",
            "--execute-perception",
            "yes",
            "--retain-analysis",
            "yes",
            "--sentinel-every-frames",
            "2",
            "--sentinel-burst-frames",
            "1",
            "--sentinel-max-inferences",
            "1",
            "--max-frames-per-generation",
            "4",
            "--max-frame-pixels",
            "1536",
            "--analysis-timeout-ms",
            "600000",
        ]
        .into_iter()
        .map(Into::into)
        .collect())
    }
    fn run(&self, args: &[OsString]) -> Test<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_fss-capture-reconnect"))
            .args(args)
            .output()?)
    }
    fn approved(&self, mut args: Vec<OsString>) -> Test<Vec<OsString>> {
        let output = self.run(&args)?;
        good(&output);
        self.validate_parent_rows(&output, FORMAT, "http_capture_sentinel.v1.json")?;
        let rows = rows(&output)?;
        let plan = row(&rows, FORMAT, "plan")?;
        assert_eq!(text(plan, &["writes"])?, "none");
        assert_eq!(text(plan, &["network"])?, "none");
        let digest = text(plan, &["approval_digest"])?;
        ContentDigest::parse(digest)?;
        args.extend(["--approve".into(), digest.into()]);
        Ok(args)
    }
    fn validate_parent_rows(&self, output: &Output, format: &str, schema: &str) -> Test {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let instance = self.directory.join("operator-row.json");
        for line in std::str::from_utf8(&output.stdout)?.lines() {
            if line.trim().is_empty() || text(&parse(line)?, &["format"]).ok() != Some(format) {
                continue;
            }
            fs::write(&instance, line)?;
            let checked = Command::new("python3")
                .arg("-B")
                .arg(repository.join("scripts/json_instance_validate.py"))
                .arg(repository.join("schemas").join(schema))
                .arg(&instance)
                .output()?;
            good(&checked);
        }
        Ok(())
    }
    fn absent(&self) {
        assert!(!self.archive.exists(), "archive created before acquisition");
        assert!(
            !self.deployment.exists(),
            "deployment created before analysis"
        );
    }
    fn journals(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.deployment.join("ledger/journal.fssj"))?,
            fs::read(self.deployment.join("effects/journal.fssj"))?,
        ))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn response(truncated: bool) -> Test<Vec<u8>> {
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
    let mut body = Vec::new();
    let mut cut = None;
    for index in 0..FRAMES {
        body.extend_from_slice(
            format!(
                "--camera\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
                jpeg.len(),
            )
            .as_bytes(),
        );
        if index == 1 {
            cut = Some(body.len() + jpeg.len() / 2);
        }
        // Identical frames must still invoke the detector without a foreground-motion gate.
        body.extend_from_slice(&jpeg);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--camera--\r\n");
    let mut wire = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=camera\r\nContent-Length: {}\r\n\r\n",
        body.len(),
    ).into_bytes();
    if truncated {
        body.truncate(cut.ok_or("second JPEG cut")?);
    }
    wire.extend(body);
    Ok(wire)
}

/// Returns the still-listening socket after exactly one response, so later operations can be
/// checked for unexpected reacquisition. Cancellation and joining also run on an early refusal.
struct Camera {
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<TcpListener, String>>>,
}
impl Camera {
    fn start(listener: TcpListener, bytes: Vec<u8>) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&cancel);
        let thread = thread::spawn(move || {
            let start = Instant::now();
            let mut socket = loop {
                if stopped.load(Ordering::Acquire) || start.elapsed() > Duration::from_secs(300) {
                    return Err("camera fixture cancelled before contact".into());
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
                    return Err("HTTP request bound".into());
                }
                socket.read_exact(&mut byte).map_err(|e| e.to_string())?;
                request.push(byte[0]);
            }
            if !request.starts_with(b"GET /stream HTTP/1.1\r\n") {
                return Err("unexpected camera request".into());
            }
            socket.write_all(&bytes).map_err(|e| e.to_string())?;
            drop(socket);
            Ok(listener)
        });
        Self {
            cancel,
            thread: Some(thread),
        }
    }
    fn finish(mut self) -> Test<TcpListener> {
        self.cancel.store(true, Ordering::Release);
        Ok(self
            .thread
            .take()
            .ok_or("camera join")?
            .join()
            .map_err(|_| "camera panicked")??)
    }
}
impl Drop for Camera {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn listener() -> Test<TcpListener> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}
fn archive_bytes(root: &Path) -> Test<BTreeMap<PathBuf, ContentDigest>> {
    fn visit(root: &Path, files: &mut BTreeMap<PathBuf, ContentDigest>) -> Test {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                visit(&entry.path(), files)?;
            } else {
                assert!(entry.file_type()?.is_file(), "unexpected fixture link");
                files.insert(
                    entry.path(),
                    ContentDigest::sha256(&fs::read(entry.path())?),
                );
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    visit(root, &mut files)?;
    Ok(files)
}
fn history<'a>(rows: &'a [Value]) -> Test<&'a Value> {
    let ready = row(rows, FORMAT, "history_ready")?;
    let pin = field(ready, &["detail", "history_pin"])?;
    ContentDigest::parse(text(pin, &["session"])?)?;
    ContentDigest::parse(text(pin, &["root"])?)?;
    assert_eq!(field(pin, &["connections"])?.integer(), Some(1));
    let durable = row(rows, CAPTURE_FORMAT, "history_durable")?;
    assert_eq!(pin, field(durable, &["detail", "history_pin"])?);
    assert_eq!(
        field(ready, &["detail", "automatic_reacquisition_authorized"])?.boolean(),
        Some(false)
    );
    Ok(ready)
}

#[test]
fn live_http_sentinel_preview_approval_and_model_refusals_precede_io() -> Test {
    let fixture = Fixture::new("preflight")?;
    let camera = listener()?;
    let args = fixture.args(&camera)?;
    // The approved model does not yet exist: preview must remain completely pure.
    let approved = fixture.approved(args.clone())?;
    fixture.absent();
    assert!(!fixture.package.exists());
    no_contact(&camera)?;

    let mut wrong = args;
    wrong.extend([
        "--approve".into(),
        ContentDigest::sha256(b"wrong live approval")
            .to_text()
            .into(),
    ]);
    let refused = fixture.run(&wrong)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains("ERR-HTTP-CAPTURE-SENTINEL-AUTHORITY-001")
    );
    fixture.absent();
    no_contact(&camera)?;

    fs::write(&fixture.package, b"not the approved native model")?;
    let refused = fixture.run(&approved)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("ERR-HTTP-HISTORY-SENTINEL-PACKAGE-001")
    );
    fixture.absent();
    no_contact(&camera)?;
    Ok(())
}

#[test]
fn live_stationary_capture_retains_analysis_and_emits_exact_cold_continuations() -> Test {
    let fixture = Fixture::new("retained")?;
    fs::write(&fixture.package, PACKAGE)?;
    let camera = listener()?;
    let approved = fixture.approved(fixture.args(&camera)?)?;
    fixture.absent();
    no_contact(&camera)?;
    let server = Camera::start(camera, response(false)?);
    let captured = fixture.run(&approved)?;
    let camera = server.finish();
    good(&captured);
    let camera = camera?;
    fixture.validate_parent_rows(&captured, FORMAT, "http_capture_sentinel.v1.json")?;
    let captured_rows = rows(&captured)?;
    let ready = history(&captured_rows)?;
    assert_eq!(
        field(ready, &["detail", "capture_request_satisfied"])?.boolean(),
        Some(true)
    );
    assert_eq!(
        field(ready, &["detail", "requires_new_approval"])?.boolean(),
        Some(false)
    );
    let offline = argv(field(ready, &["detail", "offline_sentinel_argv"])?)?;
    assert_eq!(
        offline.first().map(String::as_str),
        Some("fss-sentinel-http-history")
    );
    assert!(offline.iter().any(|arg| arg == "--approve-import"));
    let completed = row(&captured_rows, FORMAT, "completed")?;
    let report = field(completed, &["detail", "report"])?;
    assert_eq!(
        text(report, &["format"])?,
        "fss.http_history_sentinel_report.v1"
    );
    assert_eq!(field(report, &["usage", "inferences"])?.integer(), Some(1));
    assert_eq!(
        field(report, &["usage", "decoded_frames"])?.integer(),
        Some(1)
    );
    assert_eq!(
        field(report, &["sampling", "motion_independent"])?.boolean(),
        Some(true)
    );
    for key in [
        "foreground_gate_required",
        "event_publication_authorized",
        "alert_authorized",
        "absence_certifiable",
    ] {
        assert_eq!(field(report, &[key])?.boolean(), Some(false), "{key}");
    }
    let generations = field(report, &["generations"])?
        .array()
        .ok_or("generations")?;
    assert_eq!(generations.len(), 1);
    let generation = &generations[0];
    assert_eq!(
        field(generation, &["imported_frames"])?.integer(),
        Some(FRAMES as i128)
    );
    assert_eq!(field(generation, &["generation"])?.integer(), Some(10));
    assert_eq!(text(generation, &["status"])?, "analyzed");
    assert_eq!(
        field(generation, &["allocation", "admitted_inferences"])?.integer(),
        Some(1)
    );
    let digest = text(generation, &["retained", "report_digest"])?;
    ContentDigest::parse(digest)?;
    let replay_rows = field(completed, &["detail", "native_sentinel_reruns"])?
        .array()
        .ok_or("reruns")?;
    assert_eq!(replay_rows.len(), 1);
    assert_eq!(field(&replay_rows[0], &["generation"])?.integer(), Some(10));
    let replay = argv(field(&replay_rows[0], &["argv"])?)?;
    assert_eq!(replay.first().map(String::as_str), Some("fss-infer"));
    let journals = fixture.journals()?;
    let originals = archive_bytes(&fixture.archive)?;

    let repeated_live = fixture.run(&approved)?;
    assert!(!repeated_live.status.success());
    assert!(repeated_live.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&repeated_live.stderr)
            .contains("ERR-HTTP-CAPTURE-SENTINEL-PATH-001")
    );
    no_contact(&camera)?;
    assert_eq!(fixture.journals()?, journals);
    assert_eq!(archive_bytes(&fixture.archive)?, originals);

    let repeated_offline = run_continuation(&offline)?;
    good(&repeated_offline);
    let offline_json = parse(std::str::from_utf8(&repeated_offline.stdout)?)?;
    assert_eq!(text(&offline_json, &["kind"])?, "completed");
    let offline_generation = field(&offline_json, &["report", "generations"])?
        .array()
        .ok_or("offline generations")?;
    assert_eq!(offline_generation.len(), 1);
    assert_eq!(
        field(&offline_generation[0], &["sentinel"])?,
        field(generation, &["sentinel"])?
    );
    assert_eq!(
        text(&offline_generation[0], &["retained", "report_digest"])?,
        digest
    );
    assert_eq!(
        fixture.journals()?,
        journals,
        "offline exact retry appended state"
    );
    no_contact(&camera)?;

    fs::rename(
        &fixture.archive,
        fixture.directory.join("offline camera archive"),
    )?;
    fs::remove_file(&fixture.package)?;
    let cold = run_continuation(&replay)?;
    good(&cold);
    assert_eq!(
        &parse(std::str::from_utf8(&cold.stdout)?)?,
        field(generation, &["sentinel"])?
    );
    assert_eq!(
        fixture.journals()?,
        journals,
        "retained replay changed journals"
    );
    no_contact(&camera)?;
    Ok(())
}

#[test]
fn failed_live_source_keeps_exact_history_and_requires_separate_analysis_approval() -> Test {
    let fixture = Fixture::new("source-failed")?;
    fs::write(&fixture.package, PACKAGE)?;
    let camera = listener()?;
    let approved = fixture.approved(fixture.args(&camera)?)?;
    let server = Camera::start(camera, response(true)?);
    let captured = fixture.run(&approved)?;
    let camera = server.finish()?;
    assert!(!captured.status.success());
    fixture.validate_parent_rows(&captured, FORMAT, "http_capture_sentinel.v1.json")?;
    let captured_rows = rows(&captured)?;
    assert!(
        !captured_rows
            .iter()
            .any(|value| matches(value, FORMAT, "completed"))
    );
    let ready = history(&captured_rows)?;
    assert_eq!(
        field(ready, &["detail", "capture_request_satisfied"])?.boolean(),
        Some(false)
    );
    assert_eq!(
        field(ready, &["detail", "requires_new_approval"])?.boolean(),
        Some(true)
    );
    let durable = row(&captured_rows, CAPTURE_FORMAT, "history_durable")?;
    assert_eq!(
        text(durable, &["detail", "boundary", "outcome"])?,
        "source_failed"
    );
    assert_eq!(
        field(durable, &["detail", "boundary", "frames_parsed"])?.integer(),
        Some(1)
    );
    assert!(fixture.archive.is_dir());
    assert!(
        !fixture.deployment.exists(),
        "failed source entered analysis"
    );
    let offline = argv(field(ready, &["detail", "offline_sentinel_argv"])?)?;
    assert_eq!(
        offline.first().map(String::as_str),
        Some("fss-sentinel-http-history")
    );
    assert!(!offline.iter().any(|arg| arg == "--approve-import"));
    let originals = archive_bytes(&fixture.archive)?;
    let preview = run_continuation(&offline)?;
    good(&preview);
    let preview = parse(std::str::from_utf8(&preview.stdout)?)?;
    assert_eq!(text(&preview, &["kind"])?, "plan");
    assert_eq!(text(&preview, &["writes"])?, "none");
    assert_eq!(text(&preview, &["network"])?, "none");
    ContentDigest::parse(text(&preview, &["approval_digest"])?)?;
    assert!(!fixture.deployment.exists());
    assert_eq!(archive_bytes(&fixture.archive)?, originals);
    no_contact(&camera)?;
    Ok(())
}
