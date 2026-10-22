#![forbid(unsafe_code)]
//! Whole-recording motion-independent inference and cold numerical replay.
//! Color bars exercise native execution and custody, not recognition accuracy.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new() -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-long-sentinel-cli-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn long_sentinel_finds_static_candidates_and_replays_retained_model_after_restart() -> TestResult {
    let directory = OwnedDirectory::new()?;
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository = crate_root.join("../..");
    let output = Command::new("python3")
        .arg("-B")
        .arg(crate_root.join("tests/fixtures/long_sentinel_cli.py"))
        .arg(env!("CARGO_BIN_EXE_fss-file"))
        .arg(env!("CARGO_BIN_EXE_fss-infer"))
        .arg(env!("CARGO_BIN_EXE_fss-event"))
        .arg(repository.join("tests/fixtures/media/jpeg/rgb_64x48_colorbars_420.jpg"))
        .arg(repository.join("models/yolox-nano/yolox_nano.fmpk"))
        .arg(&directory.0)
        .output()?;
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
