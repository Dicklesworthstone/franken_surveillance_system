#![forbid(unsafe_code)]
//! Cross-process file import, retained recovery and extraction contracts.

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::ContentDigest;
use fss_reference::ingest::{FileImportManifest, RetainedReadLimits};

const JPEG: &[u8] = include_bytes!("fixtures/retained_file_8x8.jpg");
type TestResult = Result<(), Box<dyn Error>>;

struct OwnedTestDir(PathBuf);

impl OwnedTestDir {
    fn new(label: &str) -> io::Result<Self> {
        // Never claim or remove a directory we did not create: a directory left by an earlier
        // process with a reused pid is skipped, not failed on or adopted.
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir()
                .join(format!("fss-file-cli-{label}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other("test directory capacity"))
    }
}

impl Drop for OwnedTestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn command(root: &Path, action: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-file"));
    command.arg(action).arg("--root").arg(root).args(["--site", "site:file-cli-test"]);
    command
}

fn success(output: &Output) {
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
}

fn field(output: &Output, name: &str) -> Result<String, Box<dyn Error>> {
    let text = std::str::from_utf8(&output.stdout)?;
    let prefix = format!("{name}=");
    text.lines().find_map(|line| line.strip_prefix(&prefix)).map(str::to_owned)
        .ok_or_else(|| io::Error::other(format!("missing output field {name}")).into())
}

fn import(root: &Path, source: &Path, manifest: Option<&Path>) -> io::Result<Output> {
    let mut cmd = command(root, "import");
    cmd.arg("--input").arg(source).args([
        "--sensor", "sensor:file-cli-test", "--stream", "stream:file-cli-test",
        "--receive-time-ns", "1000000000", "--chunk-bytes", "64",
    ]);
    if let Some(path) = manifest { cmd.arg("--manifest-out").arg(path); }
    cmd.output()
}

#[test]
fn import_reopen_verify_and_extract_without_original_source() -> TestResult {
    let temp = OwnedTestDir::new("reopen")?;
    let root = temp.0.join("deployment");
    let source = temp.0.join("camera.mjpeg");
    let manifest_path = temp.0.join("import.manifest");
    let source_bytes = [JPEG, JPEG].concat();
    fs::write(&source, &source_bytes)?;
    let imported = import(&root, &source, Some(&manifest_path))?;
    success(&imported);
    assert_eq!(field(&imported, "segment_count")?, "2");
    assert_eq!(field(&imported, "capture_time_class")?, "unknown");
    assert_eq!(field(&imported, "absence_certifiable")?, "false");
    assert_eq!(field(&imported, "verified_source_sha256")?, ContentDigest::sha256(&source_bytes).to_text());
    let identity = field(&imported, "import_identity")?;
    let manifest_digest = ContentDigest::parse(field(&imported, "manifest_digest")?)?;
    let manifest = FileImportManifest::from_retained_bytes(
        &fs::read(&manifest_path)?, manifest_digest, RetainedReadLimits::default(),
    )?;
    fs::remove_file(&source)?;

    // Each invocation starts a different process and reopens persistent storage.
    for action in ["inspect", "verify", "verify"] {
        let output = command(&root, action).args(["--import-id", &identity]).output()?;
        success(&output);
        assert_eq!(field(&output, "authority_sequence")?, field(&imported, "authority_sequence")?);
        assert_eq!(field(&output, "manifest_digest")?, manifest_digest.to_text());
        if action == "verify" {
            assert_eq!(field(&output, "verified_source_sha256")?, manifest.input_sha256.to_text());
        }
    }
    let destination = temp.0.join("frame.jpg");
    let extracted = command(&root, "extract").args(["--import-id", &identity, "--segment", "1"])
        .arg("--output").arg(&destination).output()?;
    success(&extracted);
    let span = &manifest.segment_spans[1];
    let start = usize::try_from(span.offset)?;
    let end = usize::try_from(span.offset + span.len)?;
    assert_eq!(fs::read(&destination)?, &source_bytes[start..end]);
    assert_eq!(field(&extracted, "extracted_sha256")?, span.segment_sha256.to_text());
    Ok(())
}

#[test]
fn repeated_import_is_idempotent_and_exports_never_overwrite() -> TestResult {
    let temp = OwnedTestDir::new("idempotent")?;
    let root = temp.0.join("deployment");
    let source = temp.0.join("camera.jpg");
    fs::write(&source, JPEG)?;
    let first = import(&root, &source, None)?;
    success(&first);
    let second = import(&root, &source, None)?;
    success(&second);
    assert_eq!(field(&first, "import_identity")?, field(&second, "import_identity")?);
    assert_eq!(field(&first, "authority_sequence")?, field(&second, "authority_sequence")?);
    assert_eq!(field(&second, "operation")?, "idempotent_existing");
    let identity = field(&first, "import_identity")?;
    let destination = temp.0.join("existing-output");
    fs::write(&destination, b"operator-owned bytes")?;
    let output = command(&root, "extract").args(["--import-id", &identity, "--segment", "0"])
        .arg("--output").arg(&destination).output()?;
    assert!(!output.status.success());
    assert_eq!(fs::read(&destination)?, b"operator-owned bytes");
    let inside_root = root.join("not-an-evidence-object");
    let output = command(&root, "extract").args(["--import-id", &identity, "--segment", "0"])
        .arg("--output").arg(&inside_root).output()?;
    assert!(!output.status.success());
    assert!(!inside_root.exists());
    Ok(())
}

#[test]
fn missing_deployment_and_incomplete_arguments_do_not_initialize_storage() -> TestResult {
    let temp = OwnedTestDir::new("refusals")?;
    let root = temp.0.join("absent");
    let id = ContentDigest::sha256(b"absent import").to_text();
    let result = command(&root, "verify").args(["--import-id", &id]).output()?;
    assert!(!result.status.success());
    assert!(!root.exists());
    let result = command(&root, "import").args([
        "--input", "nonexistent.jpg", "--sensor", "sensor:test", "--stream", "stream:test",
    ]).output()?;
    assert_eq!(result.status.code(), Some(2));
    assert!(!root.exists());
    Ok(())
}
