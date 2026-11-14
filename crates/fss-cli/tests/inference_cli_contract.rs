#![forbid(unsafe_code)]
//! Cross-process operator tests. The model fixture performs known arithmetic, not detection.

use fss_core::{CanonicalDecoder, ContentDigest};
use fss_reference::ingest::inference::RecordedModel;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const JPEG: &[u8] = include_bytes!("fixtures/retained_file_8x8.jpg");
const MODEL: &[u8] = include_bytes!("fixtures/numeric_8x8.fssmodel");
const MODEL_DIGEST: &str =
    "sha256:ce1fe0cb63c6db88ada7cb34e8d7e405e6c63de658e0b04885f9e6e47a8ca3c7";
type TestResult<T = ()> = Result<T, Box<dyn Error>>;
struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-infer-cli-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn field(output: &Output, name: &str) -> TestResult<String> {
    let text = std::str::from_utf8(&output.stdout)?;
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")).map(str::to_owned))
        .ok_or_else(|| std::io::Error::other(format!("missing field {name}")).into())
}
fn import(root: &Path, source: &Path) -> TestResult<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(root)
        .args(["--site", "site:inference-cli"])
        .arg("--input")
        .arg(source)
        .args([
            "--sensor",
            "sensor:inference-cli",
            "--stream",
            "stream:inference-cli",
            "--receive-time-ns",
            "1000000000",
        ])
        .output()?;
    success(&output);
    field(&output, "import_identity")
}
fn command(root: &Path, action: &str, import: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-infer"));
    command.arg(action).arg("--root").arg(root).args([
        "--site",
        "site:inference-cli",
        "--import-id",
        import,
        "--segment",
        "0",
        "--interpretation",
        "gray",
    ]);
    command
}
fn run(root: &Path, import: &str, model: &Path) -> Command {
    let mut c = command(root, "run", import);
    c.arg("--model")
        .arg(model)
        .args(["--model-digest", MODEL_DIGEST]);
    c
}

#[test]
fn run_read_and_replay_survive_process_restart_and_removed_input_files() -> TestResult {
    let dir = Directory::new("restart")?;
    let root = dir.0.join("deployment");
    let source = dir.0.join("source.jpg");
    let model = dir.0.join("model.bin");
    fs::write(&source, JPEG)?;
    fs::write(&model, MODEL)?;
    assert_eq!(ContentDigest::sha256(MODEL).to_text(), MODEL_DIGEST);
    RecordedModel::decode(MODEL, ContentDigest::parse(MODEL_DIGEST)?)?;
    let id = import(&root, &source)?;
    let tensors = dir.0.join("result.tensor");
    let result = run(&root, &id, &model)
        .arg("--output")
        .arg(&tensors)
        .output()?;
    success(&result);
    assert_eq!(field(&result, "model_outputs")?, "uncalibrated");
    assert_eq!(field(&result, "effects_authorized")?, "false");
    assert_eq!(field(&result, "absence_certifiable")?, "false");
    let bytes = fs::read(&tensors)?;
    let mut d = CanonicalDecoder::new(&bytes);
    assert_eq!(d.bytes()?, b"FSSRTEN1");
    assert_eq!(d.u32()?, 1);
    assert_eq!(d.u64()?, 3);
    assert_eq!(d.u64()?, 1);
    assert_eq!(d.text()?, "result");
    assert_eq!(d.u8()?, 1);
    assert_eq!(d.u64()?, 4);
    for dim in [1, 1, 8, 8] {
        assert_eq!(d.u64()?, dim);
    }
    assert_eq!(d.u64()?, 64);
    for _ in 0..64 {
        let value = f32::from_bits(d.u32()?);
        assert!(value.is_finite() && (0.25..=1.25).contains(&value));
    }
    d.ensure_finished()?;
    let run_id = field(&result, "run_identity")?;
    let retried = run(&root, &id, &model).output()?;
    success(&retried);
    assert_eq!(
        field(&retried, "authority_sequence")?,
        field(&result, "authority_sequence")?
    );
    assert_eq!(field(&retried, "run_identity")?, run_id);
    fs::remove_file(&source)?;
    fs::remove_file(&model)?;
    for action in ["read", "replay"] {
        let destination = dir.0.join(format!("{action}.tensor"));
        let restored_model = dir.0.join(format!("{action}.model"));
        let output = command(&root, action, &id)
            .args(["--run-id", &run_id])
            .arg("--output")
            .arg(&destination)
            .arg("--model-out")
            .arg(&restored_model)
            .output()?;
        success(&output);
        assert_eq!(
            field(&output, "authority_sequence")?,
            field(&result, "authority_sequence")?
        );
        assert_eq!(fs::read(destination)?, bytes);
        assert_eq!(fs::read(restored_model)?, MODEL);
    }
    Ok(())
}

#[test]
fn wrong_model_digest_is_refused_before_any_decode_commit() -> TestResult {
    let dir = Directory::new("digest")?;
    let root = dir.0.join("deployment");
    let source = dir.0.join("source.jpg");
    let model = dir.0.join("model.bin");
    fs::write(&source, JPEG)?;
    fs::write(&model, MODEL)?;
    let id = import(&root, &source)?;
    let journal = root.join("ledger/journal.fssj");
    let before = fs::read(&journal)?;
    let wrong = ContentDigest::sha256(b"wrong model").to_text();
    let output = command(&root, "run", &id)
        .arg("--model")
        .arg(&model)
        .args(["--model-digest", &wrong])
        .output()?;
    assert!(!output.status.success());
    assert_eq!(fs::read(journal)?, before);
    Ok(())
}

#[test]
fn insufficient_execution_budget_returns_failure_without_result_export() -> TestResult {
    let dir = Directory::new("budget")?;
    let root = dir.0.join("deployment");
    let source = dir.0.join("source.jpg");
    let model = dir.0.join("model.bin");
    let destination = dir.0.join("result.tensor");
    fs::write(&source, JPEG)?;
    fs::write(&model, MODEL)?;
    let id = import(&root, &source)?;
    let output = run(&root, &id, &model)
        .args(["--max-macs", "0"])
        .arg("--output")
        .arg(&destination)
        .output()?;
    assert!(!output.status.success());
    assert!(!destination.exists());
    // The successful decode is allowed to remain; a later adequate inference grant can proceed.
    let retry = run(&root, &id, &model)
        .arg("--output")
        .arg(&destination)
        .output()?;
    success(&retry);
    Ok(())
}

#[test]
fn exports_never_overwrite_and_read_does_not_create_deployments() -> TestResult {
    let dir = Directory::new("exports")?;
    let root = dir.0.join("deployment");
    let id = ContentDigest::sha256(b"absent").to_text();
    let absent = command(&root, "read", &id)
        .args(["--run-id", &id])
        .output()?;
    assert!(!absent.status.success());
    assert!(!root.exists());
    let source = dir.0.join("source.jpg");
    let model = dir.0.join("model.bin");
    let output = dir.0.join("owned");
    fs::write(&source, JPEG)?;
    fs::write(&model, MODEL)?;
    fs::write(&output, b"operator bytes")?;
    let id = import(&root, &source)?;
    let refused = run(&root, &id, &model)
        .arg("--output")
        .arg(&output)
        .output()?;
    assert!(!refused.status.success());
    assert_eq!(fs::read(&output)?, b"operator bytes");
    let within = root.join("not-an-object");
    let refused = run(&root, &id, &model)
        .arg("--output")
        .arg(&within)
        .output()?;
    assert!(!refused.status.success());
    assert!(!within.exists());
    Ok(())
}

fn inspection_fixture(name: &str) -> TestResult<(Directory, PathBuf, String, String)> {
    let dir = Directory::new(name)?;
    let root = dir.0.join("deployment");
    let source = dir.0.join("source.jpg");
    let model = dir.0.join("model.bin");
    fs::write(&source, JPEG)?;
    fs::write(&model, MODEL)?;
    let import_id = import(&root, &source)?;
    let result = run(&root, &import_id, &model).output()?;
    success(&result);
    let run_id = field(&result, "run_identity")?;
    Ok((dir, root, import_id, run_id))
}

fn deployment_bytes(root: &Path) -> TestResult<std::collections::BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(
        root: &Path,
        path: &Path,
        files: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
    ) -> TestResult {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(root)?.to_path_buf();
            if entry.file_type()?.is_dir() {
                files.insert(relative, Vec::new());
                visit(root, &path, files)?;
            } else {
                files.insert(relative, fs::read(path)?);
            }
        }
        Ok(())
    }
    let mut files = std::collections::BTreeMap::new();
    visit(root, root, &mut files)?;
    Ok(files)
}

#[test]
fn read_and_replay_coexist_with_a_writer_without_changing_deployment_bytes() -> TestResult {
    use fss_core::{BudgetVector, ContextAuthority, OperationId, RootAuthoritySpec};
    use fss_reference::{ReferenceDeployment, ReplayCx};

    let (dir, root, import_id, run_id) = inspection_fixture("concurrent-reader")?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:inspection-writer".to_owned(),
        operation_id: OperationId::parse("operation:inspection-writer")?,
        principal: "principal:inspection-test".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(1024 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(b"site:inference-cli"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let writer = ReferenceDeployment::open(&root, "site:inference-cli", &cx)?;
    let before = deployment_bytes(&root)?;
    for action in ["read", "replay"] {
        let destination = dir.0.join(format!("{action}-inspection.tensor"));
        let output = command(&root, action, &import_id)
            .args(["--run-id", &run_id])
            .arg("--output")
            .arg(&destination)
            .output()?;
        success(&output);
        assert_eq!(field(&output, "run_identity")?, run_id);
        assert_eq!(field(&output, "replay_compatible")?, "true");
        assert_eq!(
            field(&output, "executor_profile")?,
            fss_reference::ingest::inference::executor_profile_digest().to_text()
        );
        assert_eq!(field(&output, "deployment_mutated")?, "false");
        assert!(field(&output, "payload_read_bytes")?.parse::<u64>()? > 0);
        assert!(field(&output, "payload_read_attempts")?.parse::<u64>()? > 0);
        assert_eq!(
            ContentDigest::sha256(&fs::read(destination)?).to_text(),
            field(&output, "output_digest")?
        );
        assert_eq!(deployment_bytes(&root)?, before);
    }
    drop(writer);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn read_and_replay_refuse_torn_journals_without_recovery_or_export() -> TestResult {
    for (index, relative) in ["ledger/journal.fssj", "effects/journal.fssj"]
        .iter()
        .enumerate()
    {
        let (dir, root, import_id, run_id) = inspection_fixture(&format!("torn-{index}"))?;
        let path = root.join(relative);
        let mut bytes = fs::read(&path)?;
        bytes.extend_from_slice(b"uncommitted-inference-inspection-tail");
        fs::write(&path, bytes)?;
        let before = deployment_bytes(&root)?;
        for action in ["read", "replay"] {
            let destination = dir.0.join(format!("{action}-refused.tensor"));
            let output = command(&root, action, &import_id)
                .args(["--run-id", &run_id])
                .arg("--output")
                .arg(&destination)
                .output()?;
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert!(!destination.exists());
            assert_eq!(deployment_bytes(&root)?, before);
        }
    }
    Ok(())
}

#[test]
fn inference_inspection_uses_one_allowance_through_final_revalidation() -> TestResult {
    let (dir, root, import_id, run_id) = inspection_fixture("read-allowance")?;
    let before = deployment_bytes(&root)?;
    for action in ["read", "replay"] {
        let output = command(&root, action, &import_id)
            .args(["--run-id", &run_id])
            .output()?;
        success(&output);
        let bytes = field(&output, "payload_read_bytes")?.parse::<u64>()?;
        let attempts = field(&output, "payload_read_attempts")?.parse::<u64>()?;
        assert!(bytes > 1 && attempts > 1);
        // A final empty journal probe needs one remaining byte of allowance, even though
        // it returns no payload. All actual reads and rereads still share one counter.
        let byte_allowance = bytes + 1;
        let exact = command(&root, action, &import_id)
            .args([
                "--run-id",
                &run_id,
                "--max-read-bytes",
                &byte_allowance.to_string(),
                "--max-read-objects",
                &attempts.to_string(),
            ])
            .output()?;
        success(&exact);
        for (key, amount) in [
            ("--max-read-bytes", byte_allowance - 1),
            ("--max-read-objects", attempts - 1),
        ] {
            let destination = dir.0.join(format!("{action}-{key}-refused.tensor"));
            let refused = command(&root, action, &import_id)
                .args(["--run-id", &run_id, key, &amount.to_string()])
                .arg("--output")
                .arg(&destination)
                .output()?;
            assert!(!refused.status.success());
            assert!(refused.stdout.is_empty());
            assert!(!destination.exists());
            assert_eq!(deployment_bytes(&root)?, before);
        }
    }
    Ok(())
}
