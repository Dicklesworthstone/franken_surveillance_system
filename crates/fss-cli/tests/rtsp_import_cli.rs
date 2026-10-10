#![forbid(unsafe_code)]
//! Native RTSP recording custody through the real import and retained-media binaries.
//! Synthetic HEVC is a custody/replay fixture, not a camera or detector qualification.

#[path = "../../fss-reference/tests/hevc_recording_support/mod.rs"]
mod hevc_recording_support;

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::recording::hevc::PreparedHevcRecording;
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-rtsp-import-cli-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
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

fn run(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-import-rtsp"))
        .args(args)
        .output()?)
}
fn good(output: Output) -> Test<String> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
// Only synthetic fixture fields without escaped quotes are read by this helper.
fn field<'a>(text: &'a str, key: &str) -> Test<&'a str> {
    let marker = format!("\"{key}\":\"");
    let value = text.split_once(&marker).ok_or("missing fixture field")?.1;
    Ok(value.split_once('"').ok_or("unterminated fixture field")?.0)
}

fn arguments(directory: &Directory, recording: &PreparedHevcRecording) -> Test<Vec<OsString>> {
    let scope = recording.summary().scope.clone();
    Ok([
        "--archive",
        directory.0.join("source archive").to_str().ok_or("UTF-8 archive")?,
        "--root",
        directory.0.join("destination").to_str().ok_or("UTF-8 destination")?,
        "--site", "site:rtsp-import-cli",
        "--window-slot", "hevc-recording-cli",
        "--window-root", &recording.manifest().root().to_text(),
        "--codec", "hevc",
        "--sensor-id", scope.sensor.as_str(),
        "--stream-id", scope.stream.as_str(),
        "--generation", &scope.generation.to_string(),
        "--anchor", &scope.anchor.to_text(),
        "--receive-clock", &scope.receive_clock.to_text(),
        "--receive-time-ns", "5000000000",
        "--owner-authorized", "yes",
        "--read-originals", "yes",
        "--retain-originals", "yes",
        "--timeout-ms", "600000",
    ]
    .into_iter()
    .map(OsString::from)
    .collect())
}

fn publish(directory: &Directory, recording: &PreparedHevcRecording) -> Test {
    let mut source = LocalRootPublisher::open(
        directory.0.join("source archive"),
        LocalPublicationLimits::new(
            8, 16, 8, 64,
            SpoolLimits::new(64, 4 * 1024 * 1024, 1024 * 1024, 64),
        ),
    )?;
    let mut job = RecordingPublication::new(
        recording.publication_plan(),
        &mut source,
        SlotName::parse("hevc-recording-cli")?,
        recording.byte_len(),
        100,
    )?;
    for now in 0..5 {
        if let RecordingProgress::Published(receipt) = job.step(now, &NeverCancel)? {
            assert_eq!(receipt.root, recording.manifest().root());
            return Ok(());
        }
    }
    Err("source recording was not published after four children and one root".into())
}

#[test]
fn cold_hevc_import_reconciles_and_decodes_without_the_source_archive() -> Test {
    let directory = Directory::new()?;
    let recording = hevc_recording_support::fixture()?;
    publish(&directory, &recording)?;
    let root = directory.0.join("destination");
    let archive = directory.0.join("source archive");
    let mut args = arguments(&directory, &recording)?;
    let preview = good(run(&args)?)?;
    assert!(!root.exists(), "preview created destination custody");
    assert!(preview.contains("\"writes\":\"none\""));
    let approval = field(&preview, "approval_digest")?.to_owned();

    let mut wrong = args.clone();
    wrong.extend([
        "--approve".into(),
        ContentDigest::sha256(b"wrong exact import approval").to_text().into(),
    ]);
    let refused = run(&wrong)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-RTSP-IMPORT-APPROVAL-001"));
    assert!(!root.exists(), "wrong approval touched destination custody");

    args.extend(["--approve".into(), approval.into()]);
    let imported = good(run(&args)?)?;
    assert!(imported.contains("\"frames\":4"));
    assert!(imported.contains("\"capture_time_label\":\"unknown\""));
    assert!(imported.contains("\"destination_contains_original_recording\":true"));
    assert!(imported.contains("\"reused\":false"));
    let identity = field(&imported, "import_identity")?.to_owned();
    let origin = field(&imported, "origin_proof")?.to_owned();
    ContentDigest::parse(&origin)?;
    let snapshot = || -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(root.join("ledger/journal.fssj"))?,
            fs::read(root.join("effects/journal.fssj"))?,
        ))
    };
    let committed = snapshot()?;
    let retried = good(run(&args)?)?;
    assert!(retried.contains("\"reused\":true"));
    assert_eq!(field(&retried, "import_identity")?, identity);
    assert_eq!(field(&retried, "origin_proof")?, origin);
    assert_eq!(snapshot()?, committed, "exact retry appended authority or effects");

    fs::rename(&archive, directory.0.join("offline archive"))?;
    let common: Vec<OsString> = [
        "--root", root.to_str().ok_or("UTF-8 root")?,
        "--site", "site:rtsp-import-cli",
        "--import-id", &identity,
    ].into_iter().map(OsString::from).collect();
    let verified = good(
        Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .arg("verify")
            .args(&common)
            .output()?,
    )?;
    assert!(verified.contains("media_format=mp4hevc"));
    assert!(verified.contains("segment_count=4"));
    assert!(verified.contains("capture_time_class=unknown"));
    assert!(verified.contains("absence_certifiable=false"));
    let decoded = good(
        Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .arg("decode")
            .args(&common)
            .args([
                "--segment", "0", "--segment-count", "4",
                "--interpretation", "ycbcr", "--work-units", "1000000000",
            ])
            .output()?,
    )?;
    assert!(!decoded.is_empty());
    assert_eq!(snapshot()?.1, committed.1, "offline import/decode dispatched an effect");
    let after_decode = snapshot()?;
    let missing = run(&args)?;
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("ERR-RTSP-IMPORT-SOURCE-001"));
    assert_eq!(snapshot()?, after_decode);
    assert!(!archive.exists(), "missing-source refusal recreated the archive");
    Ok(())
}

#[test]
fn exact_preview_and_missing_archive_refusal_do_not_create_either_store() -> Test {
    let directory = Directory::new()?;
    let recording = hevc_recording_support::fixture()?;
    let mut args = arguments(&directory, &recording)?;
    let preview = good(run(&args)?)?;
    args.extend(["--approve".into(), field(&preview, "approval_digest")?.into()]);
    let refused = run(&args)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-RTSP-IMPORT-SOURCE-001"));
    assert!(!directory.0.join("source archive").exists());
    assert!(!directory.0.join("destination").exists());
    Ok(())
}

#[test]
fn source_and_destination_preflight_refusals_never_materialize_destination_paths() -> Test {
    let directory = Directory::new()?;
    let recording = hevc_recording_support::fixture()?;
    let archive = directory.0.join("source archive");
    fs::create_dir_all(archive.join("spool"))?;
    let mut args = arguments(&directory, &recording)?;
    let preview = good(run(&args)?)?;
    args.extend(["--approve".into(), field(&preview, "approval_digest")?.into()]);
    let refused = run(&args)?;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-RTSP-IMPORT-SOURCE-001"));
    assert!(!directory.0.join("destination").exists());
    assert!(!archive.join("roots").exists(), "preflight repaired the archive");

    fs::create_dir(archive.join("roots"))?;
    fs::create_dir(archive.join("tombstones"))?;
    let mut roots = Vec::new();
    #[cfg(unix)]
    {
        let alias = directory.0.join("archive alias");
        std::os::unix::fs::symlink(&archive, &alias)?;
        roots.push(alias.join("nested destination"));
    }
    roots.push(directory.0.join("missing parent").join("destination"));
    for root in roots {
        let mut args = arguments(&directory, &recording)?;
        let root_index = args.iter().position(|arg| arg == "--root").ok_or("root argument")?;
        args[root_index + 1] = root.as_os_str().to_owned();
        let preview = good(run(&args)?)?;
        args.extend(["--approve".into(), field(&preview, "approval_digest")?.into()]);
        let refused = run(&args)?;
        assert!(!refused.status.success());
        assert!(refused.stdout.is_empty());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-RTSP-IMPORT-REQUEST-001"));
        assert!(!root.exists());
        assert!(!directory.0.join("missing parent").exists());
    }
    Ok(())
}
