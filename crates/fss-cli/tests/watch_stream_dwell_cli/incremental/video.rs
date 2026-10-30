#![forbid(unsafe_code)]
//! Real native AVC/HEVC import, cold CLI continuation, publication retry and complete JSON.

use super::*;

#[test]
fn native_video_continuations_preserve_delayed_output_and_exact_event_identity() -> Test {
    let directory = Directory::new("incremental-native-video")?;
    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("python3")
        .arg("-B")
        .arg(crate_root.join("tests/fixtures/incremental_video_dwell_cli.py"))
        .arg(env!("CARGO_BIN_EXE_fss-file"))
        .arg(env!("CARGO_BIN_EXE_fss-event"))
        .arg(&directory.0)
        .arg(crate_root.join("../.."))
        .output()?;
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
