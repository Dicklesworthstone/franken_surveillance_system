#![forbid(unsafe_code)]
//! Actual import/inference/package-zone CLI contracts, including approved retention and cold read.
#[path = "../../fss-reference/tests/package_zone_support/mod.rs"]
mod package_zone_support;
use package_zone_support::Test;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for n in 0..100_u32 {
            let path = std::env::temp_dir()
                .join(format!("fss-package-zones-cli-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn native_class_zone_dwell_approval_and_cold_read_are_source_exact_across_processes() -> Test {
    let directory = Directory::new()?;
    let package = package_zone_support::package()?;
    let package_path = directory.0.join("numeric-test.fmpk");
    let source_path = directory.0.join("numeric-test.mjpeg");
    fs::write(&package_path, &package)?;
    fs::write(&source_path, package_zone_support::footage())?;
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("python3")
        .arg("-B")
        .arg(crate_root.join("tests/fixtures/package_zones_cli.py"))
        .arg(env!("CARGO_BIN_EXE_fss-file"))
        .arg(env!("CARGO_BIN_EXE_fss-infer"))
        .arg(env!("CARGO_BIN_EXE_fss-event"))
        .arg(&source_path)
        .arg(&package_path)
        .arg(fss_core::ContentDigest::sha256(&package).to_text())
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
