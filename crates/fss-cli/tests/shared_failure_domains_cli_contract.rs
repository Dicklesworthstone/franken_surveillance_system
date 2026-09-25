#![forbid(unsafe_code)]
//! Real import -> retained coverage -> shared-failure CLI contracts.
//! Python is a test-only JSON oracle, never a production dependency.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Self, Box<dyn Error>> {
        for attempt in 0..100 {
            let root = std::env::temp_dir().join(format!(
                "fss-shared-failure-cli-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self(root)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn common_failure_reports_preserve_windows_custody_and_unknowns() -> Result<(), Box<dyn Error>> {
    let scratch = Scratch::new()?;
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    for (name, level) in [("north", 40), ("south", 60), ("east", 80)] {
        let pixels = vec![level; 96 * 48];
        let mut stream = Vec::new();
        for _ in 0..14 {
            stream.extend(encode_jpeg(96, 48, &pixels, &config)?);
        }
        fs::write(scratch.0.join(format!("{name}.mjpeg")), stream)?;
    }
    let output = Command::new("python3")
        .arg("-B")
        .arg("-c")
        .arg(include_str!("fixtures/shared_failure_domains_cli.py"))
        .arg(&scratch.0)
        .arg(env!("CARGO_BIN_EXE_fss-file"))
        .arg(env!("CARGO_BIN_EXE_fss-event"))
        .output()?;
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
