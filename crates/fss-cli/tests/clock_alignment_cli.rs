#![forbid(unsafe_code)]
//! Real command boundary over explicitly synthetic, source-labelled geometry.
use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
type Test = Result<(), Box<dyn std::error::Error>>;
fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/clock-alignment/moving_feature.json")
}
fn command() -> Result<Command, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(fixture())?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-clock-align"));
    command
        .arg("--input")
        .arg(fixture())
        .arg("--input-digest")
        .arg(ContentDigest::sha256(&bytes).to_text());
    Ok(command)
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "fss-clock-cli-read-only-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn error_code(bytes: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let value = parse(std::str::from_utf8(bytes)?)?;
    Ok(value
        .object()
        .and_then(|v| v.get("code"))
        .and_then(Value::text)
        .ok_or("error code")?
        .to_owned())
}

#[test]
fn native_command_emits_complete_pinned_scan() -> Test {
    let output = command()?.output()?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = parse(std::str::from_utf8(&output.stdout)?)?;
    let report = value
        .object()
        .and_then(|v| v.get("report"))
        .and_then(Value::object)
        .ok_or("report")?;
    assert_eq!(
        report.get("hypothesis_count").and_then(Value::integer),
        Some(3)
    );
    assert_eq!(
        report.get("hypotheses_complete").and_then(Value::boolean),
        Some(true)
    );
    assert_eq!(
        report.get("clock_activated").and_then(Value::boolean),
        Some(false)
    );
    Ok(())
}

#[test]
fn relative_input_runs_in_a_read_only_directory_without_changing_files_or_report_bytes() -> Test {
    let directory = Directory::new()?;
    let original = std::fs::read(fixture())?;
    let input = directory.0.join("query.json");
    std::fs::write(&input, &original)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o400))?;
        std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o500))?;
    }
    let output = Command::new(env!("CARGO_BIN_EXE_fss-clock-align"))
        .current_dir(&directory.0)
        .args(["--input", "./query.json", "--input-digest"])
        .arg(ContentDigest::sha256(&original).to_text())
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let report = output.stdout.strip_suffix(b"\n").ok_or("report newline")?;
    assert_eq!(
        ContentDigest::sha256(report).to_text(),
        "sha256:d0636368d94526c0b4963b8dac86c8ca6a6f2372e655541a4799015a1bccdd94"
    );
    assert_eq!(std::fs::read(&input)?, original);
    let entries = std::fs::read_dir(&directory.0)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(entries, vec![std::ffi::OsString::from("query.json")]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&input)?.permissions().mode() & 0o777,
            0o400
        );
        assert_eq!(
            std::fs::metadata(&directory.0)?.permissions().mode() & 0o777,
            0o500
        );
    }
    Ok(())
}
#[test]
fn insufficient_work_is_nonzero_without_a_successful_prefix() -> Test {
    let output = command()?.args(["--work-units", "1"]).output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(error_code(&output.stderr)?, "ERR-CLOCK-ALIGNMENT-SCAN-001");
    Ok(())
}
#[test]
fn wrong_independent_digest_refuses_before_analysis() -> Test {
    let output = Command::new(env!("CARGO_BIN_EXE_fss-clock-align"))
        .arg("--input")
        .arg(fixture())
        .arg("--input-digest")
        .arg(ContentDigest::sha256(b"not the selected input").to_text())
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(error_code(&output.stderr)?, "ERR-CLOCK-ALIGNMENT-INPUT-001");
    Ok(())
}
