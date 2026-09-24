#![forbid(unsafe_code)]
//! First-party executable boundary, separate from storage-backed library contracts.
use fss_cli::{ERR_CLI_UNKNOWN_OPTION, ExitIdentity};
use std::process::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;
/// Serializes this binary's tests. Every test holds native flock owner locks in this process and
/// spawns real CLI processes. A child spawned by a concurrent test thread inherits, until its exec
/// closes it, every descriptor open at that instant, including another test's held owner lock; the
/// flock then outlives its owner's drop, and that test's next open or child sees Locked/Busy.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
#[test]
fn executable_help_exposes_both_codecs_and_explicit_export_boundary() -> TestResult {
    let _serial = serial();
    let output = Command::new(env!("CARGO_BIN_EXE_fss-archive"))
        .arg("help")
        .output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout)?;
    for required in [
        "inspect|query|verify|export",
        "--codec avc|hevc",
        "--allow-whole-windows yes",
        "--expected-snapshot",
    ] {
        assert!(help.contains(required));
    }
    Ok(())
}
#[test]
fn refused_flags_emit_no_success_stdout_and_do_not_echo_secret_values() -> TestResult {
    let _serial = serial();
    let output = Command::new(env!("CARGO_BIN_EXE_fss-archive"))
        .args(["export", "--force", "PRIVATE_PASSWORD_SENTINEL"])
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(i32::from(ExitIdentity::MALFORMED_VALUE.code))
    );
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr)?;
    assert!(error.contains(ERR_CLI_UNKNOWN_OPTION));
    assert!(!error.contains("PRIVATE_PASSWORD_SENTINEL"));
    Ok(())
}
#[test]
fn executable_inspect_does_not_create_a_misspelled_archive() -> TestResult {
    let _serial = serial();
    let missing = std::env::temp_dir().join(format!(
        "fss-archive-process-missing-{}",
        std::process::id()
    ));
    assert!(!missing.exists());
    let digest = fss_core::ContentDigest::sha256(b"explicit test scope").to_text();
    let output = Command::new(env!("CARGO_BIN_EXE_fss-archive"))
        .args(["inspect", "--root"])
        .arg(&missing)
        .args([
            "--codec",
            "hevc",
            "--sensor",
            "sensor-cli",
            "--stream",
            "stream-cli",
            "--generation",
            "1",
            "--anchor",
            &digest,
            "--receive-clock",
            &digest,
            "--decode-clock",
            &digest,
            "--time-scale",
            "90000",
        ])
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(i32::from(ExitIdentity::RUNTIME_FAILURE.code))
    );
    assert!(output.stdout.is_empty());
    assert!(!missing.exists());
    Ok(())
}
