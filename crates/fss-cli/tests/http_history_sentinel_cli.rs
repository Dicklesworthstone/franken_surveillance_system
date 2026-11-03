#![forbid(unsafe_code)]
//! Native capture → motion-independent trained history analysis → retained cold replay.
//! Synthetic images exercise custody and restart behavior, not real-world detection quality.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use fss_core::ContentDigest;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const FRAMES: usize = 4;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-history-sentinel-cli-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("owned test-directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn good(output: Output) -> Test<String> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
fn run(args: &[OsString]) -> Test<Output> {
    Ok(
        Command::new(env!("CARGO_BIN_EXE_fss-sentinel-http-history"))
            .args(args)
            .output()?,
    )
}
// These synthetic fixture fields contain no escaped JSON quotes. Native CLI output is also
// validated by its own bounded JSON renderer; this helper is not a general JSON parser.
fn field<'a>(text: &'a str, key: &str) -> Test<&'a str> {
    let marker = format!("\"{key}\":\"");
    let tail = text.split_once(&marker).ok_or("missing fixture field")?.1;
    Ok(tail.split_once('"').ok_or("unterminated fixture field")?.0)
}
fn digests(text: &str, key: &str) -> Test<Vec<String>> {
    let marker = format!("\"{key}\":\"");
    text.split(&marker)
        .skip(1)
        .map(|tail| {
            let value = tail.split_once('"').ok_or("unterminated fixture digest")?.0;
            ContentDigest::parse(value)?;
            Ok(value.to_owned())
        })
        .collect()
}

fn response() -> Test<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: vec![],
    };
    let mut body = Vec::new();
    for _ in 0..FRAMES {
        let mut pixels = vec![40_u8; 48 * 32];
        // Every image is identical: successful inference must not require foreground motion.
        for y in 8..24 {
            for x in 8..24 {
                pixels[y * 48 + x] = 220;
            }
        }
        let jpeg = encode_jpeg(48, 32, &pixels, &config)?;
        body.extend_from_slice(
            format!(
                "--camera\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
                jpeg.len()
            )
            .as_bytes(),
        );
        body.extend(jpeg);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--camera--\r\n");
    let mut wire=format!("HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=camera\r\nContent-Length: {}\r\n\r\n",body.len()).into_bytes();
    wire.extend(body);
    Ok(wire)
}

fn capture(directory: &Directory) -> Test<(PathBuf, String, String)> {
    let archive = directory.0.join("capture archive");
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let peer = listener.local_addr()?;
    let digest = ContentDigest::sha256(b"native-history-cli-camera").to_text();
    let mut args: Vec<OsString> = [
        "--root",
        archive.to_str().ok_or("UTF-8 archive")?,
        "--peer",
        &peer.to_string(),
        "--host",
        "camera.invalid",
        "--target",
        "/stream",
        "--source",
        &digest,
        "--generations",
        "10,20",
        "--receive-clock",
        &digest,
        "--retention-evidence",
        &digest,
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
        &FRAMES.to_string(),
        "--max-reads",
        "16",
        "--max-source-bytes",
        "1048576",
        "--timeout-ms",
        "600000",
        "--connect-timeout-ms",
        "60000",
        "--initial-backoff-ms",
        "1",
        "--maximum-backoff-ms",
        "2",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    let preview = good(
        Command::new(env!("CARGO_BIN_EXE_fss-capture-reconnect"))
            .args(&args)
            .output()?,
    )?;
    assert!(!archive.exists());
    args.extend([
        "--approve".into(),
        field(&preview, "approval_digest")?.into(),
    ]);
    let bytes = response()?;
    listener.set_nonblocking(true)?;
    let server = thread::spawn(move || -> Result<(), String> {
        let start = Instant::now();
        for _ in 0..2 {
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && start.elapsed() < Duration::from_secs(300) =>
                    {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => return Err(e.to_string()),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(60)))
                .map_err(|e| e.to_string())?;
            socket
                .set_write_timeout(Some(Duration::from_secs(60)))
                .map_err(|e| e.to_string())?;
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                if request.len() >= 4096 {
                    return Err("request bound".into());
                }
                socket.read_exact(&mut byte).map_err(|e| e.to_string())?;
                request.push(byte[0]);
            }
            socket.write_all(&bytes).map_err(|e| e.to_string())?;
        }
        Ok(())
    });
    let captured = Command::new(env!("CARGO_BIN_EXE_fss-capture-reconnect"))
        .args(&args)
        .output()?;
    // Native capture owns a finite run; on a refusal its stderr is the primary diagnostic.
    let text = good(captured)?;
    server.join().map_err(|_| "capture fixture panicked")??;
    let row = text
        .lines()
        .filter(|r| r.contains("\"kind\":\"history_durable\""))
        .next_back()
        .ok_or("durable history pin")?;
    let pin = row
        .split_once("\"history_pin\":{")
        .ok_or("exact history pin")?
        .1;
    assert!(pin.contains("\"connections\":2"));
    Ok((
        archive,
        field(pin, "session")?.into(),
        field(pin, "root")?.into(),
    ))
}

/// Parse only the shell-quoted word format emitted by the native CLI; execute the pinned binary
/// directly. No shell, command substitution or environment expansion enters the test handoff.
fn command_words(text: &str) -> Test<Vec<OsString>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => quoted = !quoted,
            '\\' if !quoted => word.push(chars.next().ok_or("dangling command escape")?),
            c if c.is_whitespace() && !quoted => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word).into());
                }
            }
            c => word.push(c),
        }
    }
    if quoted {
        return Err("unterminated command quote".into());
    }
    if !word.is_empty() {
        words.push(word.into());
    }
    if words.first().is_none_or(|w| w != "fss-infer") {
        return Err("unexpected replay binary".into());
    }
    Ok(words)
}

fn member<'a>(
    value: &'a fss_cli::json_input::Value,
    key: &str,
) -> Test<&'a fss_cli::json_input::Value> {
    value
        .object()
        .and_then(|o| o.get(key))
        .ok_or("missing JSON field".into())
}

#[test]
fn native_stationary_http_history_is_budgeted_retried_and_replayed_without_loose_inputs() -> Test {
    use fss_cli::json_input::parse;
    const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
    let directory = Directory::new()?;
    let (archive, session, history_root) = capture(&directory)?;
    let root = directory.0.join("analysis deployment");
    let package = directory.0.join("pinned native detector.fmpk");
    fs::write(&package, PACKAGE)?;
    let package_digest = ContentDigest::sha256(PACKAGE).to_text();
    let mut args: Vec<OsString> = [
        "--archive",
        archive.to_str().ok_or("UTF-8 archive")?,
        "--root",
        root.to_str().ok_or("UTF-8 root")?,
        "--site",
        "site:http-history-sentinel-cli",
        "--history-session",
        &session,
        "--history-root",
        &history_root,
        "--history-connections",
        "2",
        "--binding",
        "10,sensor:porch,stream:porch,50000000000,0,0,10",
        "--binding",
        "20,sensor:porch,stream:porch,50000000000,20000000000,0,10",
        "--interpretation",
        "gray",
        "--package",
        package.to_str().ok_or("UTF-8 package")?,
        "--package-digest",
        &package_digest,
        "--sentinel-every-frames",
        "2",
        "--sentinel-burst-frames",
        "1",
        "--sentinel-max-inferences",
        "2",
        "--retain-analysis",
        "yes",
        "--owner-authorized",
        "yes",
        "--read-originals",
        "yes",
        "--retain-originals",
        "yes",
        "--read-model",
        "yes",
        "--max-frames-per-generation",
        "4",
        "--max-frame-pixels",
        "1536",
        "--timeout-ms",
        "600000",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    let preview = good(run(&args)?)?;
    assert!(!root.exists(), "preview created a deployment");
    args.extend([
        "--approve-import".into(),
        field(&preview, "approval_digest")?.into(),
    ]);
    let processed = good(run(&args)?)?;
    let output = parse(&processed)?;
    assert_eq!(member(&output, "kind")?.text(), Some("completed"));
    let report = member(&output, "report")?;
    assert_eq!(
        member(report, "format")?.text(),
        Some("fss.http_history_sentinel_report.v1")
    );
    assert_eq!(
        member(member(report, "usage")?, "inferences")?.integer(),
        Some(2)
    );
    let generations = member(report, "generations")?
        .array()
        .ok_or("generation rows")?;
    assert_eq!(generations.len(), 2);
    for generation in generations {
        assert_eq!(member(generation, "status")?.text(), Some("analyzed"));
        assert_eq!(
            member(member(generation, "allocation")?, "admitted_inferences")?.integer(),
            Some(1)
        );
    }
    assert!(processed.contains("\"foreground_gate_required\":false"));
    assert!(processed.contains("\"tracker_continuity_across_generations\":false"));
    assert!(processed.contains("\"event_publication_authorized\":false"));
    let commands = member(&output, "native_sentinel_reruns")?
        .array()
        .ok_or("replay rows")?
        .iter()
        .map(|row| {
            member(row, "command")?
                .text()
                .map(str::to_owned)
                .ok_or("missing retained replay command".into())
        })
        .collect::<Test<Vec<String>>>()?;
    assert_eq!(commands.len(), 2);
    let snapshot = || -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(root.join("ledger/journal.fssj"))?,
            fs::read(root.join("effects/journal.fssj"))?,
        ))
    };
    let initial = snapshot()?;
    let repeated = good(run(&args)?)?;
    assert_eq!(
        digests(&repeated, "report_digest")?,
        digests(&processed, "report_digest")?
    );
    assert_eq!(
        digests(&repeated, "recipe_digest")?,
        digests(&processed, "recipe_digest")?
    );
    assert_eq!(snapshot()?, initial, "exact retry appended durable state");

    let mut changed = args.clone();
    let index = changed
        .iter()
        .position(|a| a == "--sentinel-max-inferences")
        .ok_or("inference option")?;
    changed[index + 1] = "3".into();
    let refused = run(&changed)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains("ERR-HTTP-HISTORY-SENTINEL-AUTHORITY-001")
    );
    assert_eq!(snapshot()?, initial);

    // An unavailable original archive or loose model cannot be substituted during analysis.
    // The separate retained replay owner needs only independently verified destination custody.
    fs::rename(&archive, directory.0.join("offline capture archive"))?;
    fs::remove_file(&package)?;
    for (command, generation) in commands.iter().zip(generations) {
        let words = command_words(command)?;
        let replay = good(
            Command::new(env!("CARGO_BIN_EXE_fss-infer"))
                .args(&words[1..])
                .output()?,
        )?;
        // The native replay owner checks the exact retained digest before emitting its full
        // report. It returns the original computation, not a separate success wrapper.
        assert_eq!(
            &parse(&replay)?,
            member(generation, "sentinel")?,
            "cold native computation changed after loose inputs went offline"
        );
        assert_eq!(
            snapshot()?,
            initial,
            "read-only retained replay changed journals"
        );
    }
    let missing = run(&args)?;
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("ERR-HTTP-IMPORT-SOURCE-001"));
    assert_eq!(snapshot()?, initial);
    Ok(())
}
