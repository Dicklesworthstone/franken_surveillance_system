#![forbid(unsafe_code)]
//! A separate CLI process must use real original objects and native media checking.
#[path = "../../fss-reference/tests/http_check_support/mod.rs"]
mod support;
use fss_cli::ExitIdentity;
use std::process::{Command, Output};
use support::*;

fn invoke(root: &std::path::Path, f: &Fixture, extra: &[&str]) -> Test<Output> {
    let r = f.request;
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-archive"))
        .arg("check-http")
        .arg("--root")
        .arg(root)
        .args([
            "--source",
            &r.source.source.to_string(),
            "--generation",
            &r.source.generation.to_string(),
            "--receive-clock",
            &r.source.receive_clock.to_string(),
            "--retention-evidence",
            &r.source.retention_evidence.to_string(),
            "--head",
            &r.head.to_string(),
            "--reads",
            &r.reads.to_string(),
            "--bytes",
            &r.bytes.to_string(),
            "--read-originals",
            "yes",
            "--decode",
            "grayscale",
            "--timeout-ms",
            "10000",
        ])
        .args(extra)
        .output()?)
}
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
fn real_process_checks_cold_originals_and_emits_no_media_or_paths() -> Test {
    let _serial = serial();
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG, JPEG])?;
    let output = invoke(&d.0, &f, &[])?;
    assert_eq!(
        output.status.code(),
        Some(i32::from(ExitIdentity::SUCCESS.code))
    );
    let text = String::from_utf8(output.stdout)?;
    assert!(text.starts_with(
        "{\"schema\":\"fss.local_http_check.v1\",\"command\":\"check-http\",\"status\":\"complete\""
    ));
    assert!(text.ends_with("]}\n"));
    assert_eq!(text.matches("\"ordinal\":").count(), 2);
    assert!(text.contains("\"checked_frames\":2,"));
    assert_eq!(text.matches("\"dimensions\":[17,13]").count(), 2);
    assert!(text.contains("\"source_bytes_emitted\":false"));
    assert!(text.contains("\"new_roots_published\":false"));
    assert!(!text.contains("camera.invalid"));
    assert!(!text.contains(d.0.to_str().ok_or("fixture path")?));
    assert!(output.stderr.is_empty());
    assert_eq!(open(&d.0)?.visible_roots().count(), 1);
    Ok(())
}
#[test]
fn incomplete_prefix_is_a_nonzero_exit_with_a_preserved_report() -> Test {
    let _serial = serial();
    let d = Directory::new()?;
    let f = fixture(&d.0, true, &[JPEG])?;
    let output = invoke(&d.0, &f, &[])?;
    assert!(!output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("\"status\":\"prefix_exhausted\""));
    assert!(text.contains("\"checked_frames\":1,"));
    assert!(text.contains("\"termination\":null"));
    assert!(text.contains("\"completion_root\":null"));
    Ok(())
}
#[test]
fn bounded_refusal_preserves_error_class_and_never_claims_success() -> Test {
    let _serial = serial();
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG])?;
    for extra in [["--max-steps", "1"], ["--max-decode-work", "0"]] {
        let output = invoke(&d.0, &f, &extra)?;
        assert!(!output.status.success());
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains("\"status\":\"refused\""));
        assert!(text.contains("\"checked_frames\":0,"));
        assert!(!text.contains("\"error\":null"));
    }
    Ok(())
}
#[test]
fn output_limit_never_truncates_an_apparently_successful_json_object() -> Test {
    let _serial = serial();
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG, JPEG, JPEG])?;
    let output = invoke(&d.0, &f, &["--max-report-bytes", "1024"])?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)?.contains("report exceeds selected output bound"));
    Ok(())
}
#[test]
fn malformed_options_never_echo_secrets_or_create_an_archive() -> Test {
    let _serial = serial();
    let d = Directory::new()?;
    let missing = d.0.join("missing");
    let output = Command::new(env!("CARGO_BIN_EXE_fss-archive"))
        .arg("check-http")
        .arg("--root")
        .arg(&missing)
        .args(["--unknown", "CANARY-SECRET-NEVER-ECHO"])
        .output()?;
    assert!(!output.status.success());
    assert!(!missing.exists());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8(output.stderr)?.contains("CANARY-SECRET-NEVER-ECHO"));
    Ok(())
}
#[test]
fn corrupt_originals_are_not_repaired_by_the_operator_command() -> Test {
    let _serial = serial();
    let d = Directory::new()?;
    let f = fixture(&d.0, false, &[JPEG])?;
    let text = f.wire_digest.to_text();
    let path =
        d.0.join("spool/objects")
            .join(text.strip_prefix("sha256:").ok_or("algorithm")?);
    std::fs::write(&path, b"corrupt-original")?;
    let output = invoke(&d.0, &f, &[])?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(std::fs::read(path)?, b"corrupt-original");
    Ok(())
}
