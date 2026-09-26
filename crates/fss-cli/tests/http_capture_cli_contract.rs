#![forbid(unsafe_code)]
//! The real native binaries, a fixture-owned loopback peer and cold original verification.
//! Python owns only the test peer/assertions, never production capture or media semantics.
use std::error::Error;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn native_http_capture_cold_replay_privacy_and_refusals() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("python3")
        .arg(root.join("tests/fixtures/http_capture_cli.py"))
        .arg(env!("CARGO_BIN_EXE_fss-capture"))
        .arg(env!("CARGO_BIN_EXE_fss-archive"))
        .arg(env!("CARGO_BIN_EXE_fss-event"))
        .arg(root.join("../fss-codec-mjpeg/tests/fixtures/gray.jpg"))
        .output()?;
    assert!(output.status.success(), "native HTTP CLI contract failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"native_binaries_executed\": true"));
    Ok(())
}
