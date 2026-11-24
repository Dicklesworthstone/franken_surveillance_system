#![forbid(unsafe_code)]
//! Cross-process file import, retained recovery and extraction contracts.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_reference::ingest::{FileImportManifest, RetainedReadLimits};
use fss_reference::{ReferenceDeployment, ReplayCx};

const JPEG: &[u8] = include_bytes!("fixtures/retained_file_8x8.jpg");
type TestResult = Result<(), Box<dyn Error>>;

struct OwnedTestDir(PathBuf);

impl OwnedTestDir {
    fn new(label: &str) -> io::Result<Self> {
        // Never claim or remove a directory we did not create: a directory left by an earlier
        // process with a reused pid is skipped, not failed on or adopted.
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-file-cli-{label}-{}-{attempt}",
                std::process::id()
            ));
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
    command
        .arg(action)
        .arg("--root")
        .arg(root)
        .args(["--site", "site:file-cli-test"]);
    command
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn field(output: &Output, name: &str) -> Result<String, Box<dyn Error>> {
    let text = std::str::from_utf8(&output.stdout)?;
    let prefix = format!("{name}=");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other(format!("missing output field {name}")).into())
}

fn import(root: &Path, source: &Path, manifest: Option<&Path>) -> io::Result<Output> {
    let mut cmd = command(root, "import");
    cmd.arg("--input").arg(source).args([
        "--sensor",
        "sensor:file-cli-test",
        "--stream",
        "stream:file-cli-test",
        "--receive-time-ns",
        "1000000000",
        "--chunk-bytes",
        "64",
    ]);
    if let Some(path) = manifest {
        cmd.arg("--manifest-out").arg(path);
    }
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
    assert_eq!(
        field(&imported, "verified_source_sha256")?,
        ContentDigest::sha256(&source_bytes).to_text()
    );
    let identity = field(&imported, "import_identity")?;
    let manifest_digest = ContentDigest::parse(field(&imported, "manifest_digest")?)?;
    let manifest = FileImportManifest::from_retained_bytes(
        &fs::read(&manifest_path)?,
        manifest_digest,
        RetainedReadLimits::default(),
    )?;
    fs::remove_file(&source)?;

    // Each invocation starts a different process and reopens persistent storage.
    for action in ["inspect", "verify", "verify"] {
        let output = command(&root, action)
            .args(["--import-id", &identity])
            .output()?;
        success(&output);
        assert_eq!(
            field(&output, "authority_sequence")?,
            field(&imported, "authority_sequence")?
        );
        assert_eq!(
            field(&output, "manifest_digest")?,
            manifest_digest.to_text()
        );
        if action == "verify" {
            assert_eq!(
                field(&output, "verified_source_sha256")?,
                manifest.input_sha256.to_text()
            );
        }
    }
    let destination = temp.0.join("frame.jpg");
    let extracted = command(&root, "extract")
        .args(["--import-id", &identity, "--segment", "1"])
        .arg("--output")
        .arg(&destination)
        .output()?;
    success(&extracted);
    let span = &manifest.segment_spans[1];
    let start = usize::try_from(span.offset)?;
    let end = usize::try_from(span.offset + span.len)?;
    assert_eq!(fs::read(&destination)?, &source_bytes[start..end]);
    assert_eq!(
        field(&extracted, "extracted_sha256")?,
        span.segment_sha256.to_text()
    );
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
    assert_eq!(
        field(&first, "import_identity")?,
        field(&second, "import_identity")?
    );
    assert_eq!(
        field(&first, "authority_sequence")?,
        field(&second, "authority_sequence")?
    );
    assert_eq!(field(&second, "operation")?, "idempotent_existing");
    let identity = field(&first, "import_identity")?;
    let destination = temp.0.join("existing-output");
    fs::write(&destination, b"operator-owned bytes")?;
    let output = command(&root, "extract")
        .args(["--import-id", &identity, "--segment", "0"])
        .arg("--output")
        .arg(&destination)
        .output()?;
    assert!(!output.status.success());
    assert_eq!(fs::read(&destination)?, b"operator-owned bytes");
    let inside_root = root.join("not-an-evidence-object");
    let output = command(&root, "extract")
        .args(["--import-id", &identity, "--segment", "0"])
        .arg("--output")
        .arg(&inside_root)
        .output()?;
    assert!(!output.status.success());
    assert!(!inside_root.exists());
    Ok(())
}

#[test]
fn missing_deployment_and_incomplete_arguments_do_not_initialize_storage() -> TestResult {
    let temp = OwnedTestDir::new("refusals")?;
    let root = temp.0.join("absent");
    let id = ContentDigest::sha256(b"absent import").to_text();
    let result = command(&root, "verify")
        .args(["--import-id", &id])
        .output()?;
    assert!(!result.status.success());
    assert!(!root.exists());
    let result = command(&root, "import")
        .args([
            "--input",
            "nonexistent.jpg",
            "--sensor",
            "sensor:test",
            "--stream",
            "stream:test",
        ])
        .output()?;
    assert_eq!(result.status.code(), Some(2));
    assert!(!root.exists());
    Ok(())
}

#[test]
fn import_and_inspect_show_the_retained_acquisition_lifecycle() -> TestResult {
    let temp = OwnedTestDir::new("acquisition")?;
    let root = temp.0.join("deployment");
    let source = temp.0.join("camera.mjpeg");
    fs::write(&source, [JPEG, JPEG].concat())?;
    let imported = import(&root, &source, None)?;
    success(&imported);
    let identity = field(&imported, "import_identity")?;
    // A separate process reopens the ledger and replays the retained history through the core.
    let inspected = command(&root, "inspect")
        .args(["--import-id", &identity])
        .output()?;
    success(&inspected);
    for output in [&imported, &inspected] {
        assert_eq!(
            field(output, "acquisition_history")?,
            "requested,authenticated,adapter_accepted,degraded,cancelled"
        );
        assert_eq!(field(output, "acquisition_terminal")?, "cancelled");
        assert_eq!(field(output, "acquisition_ending")?, "end_of_file_source");
        let refusal = field(output, "acquisition_absence_refusal")?;
        assert!(refusal.contains("cancelled"), "{refusal}");
        assert_eq!(field(output, "absence_certifiable")?, "false");
    }
    Ok(())
}

fn immutable_fixture(label: &str) -> Result<(OwnedTestDir, PathBuf, String), Box<dyn Error>> {
    let temp = OwnedTestDir::new(label)?;
    let root = temp.0.join("deployment");
    let source = temp.0.join("camera.mjpeg");
    fs::write(&source, [JPEG, JPEG].concat())?;
    let imported = import(&root, &source, None)?;
    success(&imported);
    let identity = field(&imported, "import_identity")?;
    fs::remove_file(source)?;
    Ok((temp, root, identity))
}

fn read_command(
    root: &Path,
    identity: &str,
    action: &str,
    destination: &Path,
) -> (Command, PathBuf, Option<PathBuf>) {
    let manifest = destination.with_extension("manifest");
    let mut command = command(root, action);
    command
        .args(["--import-id", identity])
        .arg("--manifest-out")
        .arg(&manifest);
    let source = if action == "extract" {
        let source = destination.with_extension("jpg");
        command
            .args(["--segment", "1"])
            .arg("--output")
            .arg(&source);
        Some(source)
    } else {
        None
    };
    (command, manifest, source)
}

type FilesystemSnapshot = BTreeMap<PathBuf, Option<Vec<u8>>>;

fn filesystem(root: &Path) -> Result<FilesystemSnapshot, Box<dyn Error>> {
    let mut pending = vec![root.to_path_buf()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        if metadata.file_type().is_dir() {
            result.insert(relative, None);
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else if metadata.file_type().is_file() {
            result.insert(relative, Some(fs::read(path)?));
        } else {
            return Err("unexpected fixture file type".into());
        }
    }
    Ok(result)
}

#[test]
fn immutable_inspect_verify_extract_match_cold_results_while_a_writer_is_open() -> TestResult {
    let (temp, root, identity) = immutable_fixture("immutable-writer")?;
    let mut expected = BTreeMap::new();
    for action in ["inspect", "verify", "extract"] {
        let (mut command, manifest, source) = read_command(
            &root,
            &identity,
            action,
            &temp.0.join(format!("cold-{action}")),
        );
        let output = command.output()?;
        success(&output);
        assert!(output.stderr.is_empty());
        assert_eq!(field(&output, "deployment_mutated")?, "false");
        if let Some(source) = source {
            assert_eq!(fs::read(source)?, JPEG);
        }
        expected.insert(action, (output.stdout, fs::read(manifest)?));
    }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:file-cli-read-writer".into(),
        operation_id: OperationId::parse("operation:file-cli-read-writer")?,
        principal: "principal:local-operator".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(1024 * 1024 * 1024).build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(b"site:file-cli-test"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let writer = ReferenceDeployment::open(&root, "site:file-cli-test", &cx)?;
    let before = filesystem(&root)?;
    for action in ["inspect", "verify", "extract"] {
        let (mut command, manifest, source) = read_command(
            &root,
            &identity,
            action,
            &temp.0.join(format!("writer-{action}")),
        );
        let output = command.output()?;
        success(&output);
        assert!(output.stderr.is_empty());
        let (expected_report, expected_manifest) = expected.get(action).ok_or("cold report")?;
        assert_eq!(
            &output.stdout, expected_report,
            "writer-held {action} changed"
        );
        assert_eq!(&fs::read(manifest)?, expected_manifest);
        if let Some(source) = source {
            assert_eq!(fs::read(source)?, JPEG);
        }
        assert_eq!(filesystem(&root)?, before);
    }
    drop(writer);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn immutable_source_read_allowances_cover_final_validation_before_any_output() -> TestResult {
    let (temp, root, identity) = immutable_fixture("immutable-allowance")?;
    let before = filesystem(&root)?;
    for action in ["inspect", "verify", "extract"] {
        let (mut baseline, _, _) = read_command(
            &root,
            &identity,
            action,
            &temp.0.join(format!("baseline-{action}")),
        );
        let baseline = baseline.output()?;
        success(&baseline);
        let bytes = field(&baseline, "payload_read_bytes")?.parse::<u64>()?;
        let reads = field(&baseline, "payload_read_attempts")?.parse::<u64>()?;
        assert!(bytes > 1 && reads > 1);
        let (mut exact, manifest, source) = read_command(
            &root,
            &identity,
            action,
            &temp.0.join(format!("exact-{action}")),
        );
        exact.args([
            "--max-read-bytes",
            &bytes.to_string(),
            "--max-read-objects",
            &reads.to_string(),
        ]);
        let output = exact.output()?;
        success(&output);
        assert_eq!(
            output.stdout, baseline.stdout,
            "exact {action} allowance changed"
        );
        assert!(manifest.exists());
        if let Some(source) = source {
            assert_eq!(fs::read(source)?, JPEG);
        }
        for (key, allowance) in [
            ("--max-read-bytes", bytes - 1),
            ("--max-read-objects", reads - 1),
        ] {
            let (mut exhausted, manifest, source) = read_command(
                &root,
                &identity,
                action,
                &temp.0.join(format!("refused-{action}-{key}")),
            );
            exhausted.args([key, &allowance.to_string()]);
            let output = exhausted.output()?;
            assert!(!output.status.success(), "renewed {action} {key}");
            assert!(
                output.stdout.is_empty(),
                "partial {action} report for {key}"
            );
            assert!(!manifest.exists(), "partial {action} manifest for {key}");
            if let Some(source) = source {
                assert!(!source.exists(), "partial {action} media for {key}");
            }
            assert_eq!(filesystem(&root)?, before);
        }
    }
    Ok(())
}

#[test]
fn immutable_source_reads_refuse_both_torn_journals_without_recovery_or_exports() -> TestResult {
    let (temp, root, identity) = immutable_fixture("immutable-tail")?;
    for (index, relative) in ["ledger/journal.fssj", "effects/journal.fssj"]
        .into_iter()
        .enumerate()
    {
        let path = root.join(relative);
        let original = fs::read(&path)?;
        let mut torn = original.clone();
        torn.extend_from_slice(&[0x46, 0x53, 0x53]);
        fs::write(&path, torn)?;
        let before = filesystem(&root)?;
        for action in ["inspect", "verify", "extract"] {
            let (mut command, manifest, source) = read_command(
                &root,
                &identity,
                action,
                &temp.0.join(format!("torn-{index}-{action}")),
            );
            let output = command.output()?;
            assert!(
                !output.status.success(),
                "accepted torn {relative} for {action}"
            );
            assert!(output.stdout.is_empty());
            assert!(!manifest.exists());
            if let Some(source) = source {
                assert!(!source.exists());
            }
            assert_eq!(filesystem(&root)?, before, "repaired {relative}");
        }
        fs::write(path, original)?;
    }
    Ok(())
}
