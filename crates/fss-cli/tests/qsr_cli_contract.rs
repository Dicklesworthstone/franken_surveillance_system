#![forbid(unsafe_code)]
//! QSR inspection across the actual fss-event process boundary with live durable obligations.

#[path = "../../fss-reference/tests/qsr_observations_support/mod.rs"]
mod support;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use fss_core::ContentDigest;
use support::{Directory, Fixture, PRINCIPAL, SITE, Test};

fn command(root: &Path, report: ContentDigest) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
    command
        .arg("qsr")
        .arg("--root")
        .arg(root)
        .args(["--site", SITE, "--principal", PRINCIPAL, "--report-digest"])
        .arg(report.to_text());
    command
}

fn refused(output: &Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn repeated_process_reads_match_native_bytes_without_reclassifying_unresolved_effects() -> Test {
    let fixture = Fixture::new("qsr-cli-existing-effects")?;
    let before = fixture.source.journals()?;
    let mut previous = None;
    for _ in 0..2 {
        let output = command(&fixture.source.root, fixture.report)
            .args(["--zone-role", "image:queue"])
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert_eq!(std::str::from_utf8(&output.stdout)?, fixture.expected_json);
        if let Some(previous) = &previous {
            assert_eq!(&output.stdout, previous);
        }
        previous = Some(output.stdout);
        assert_eq!(fixture.source.journals()?, before);
    }
    Ok(())
}

#[test]
fn refused_native_report_zone_and_corrupt_source_reads_preserve_effect_journal() -> Test {
    let fixture = Fixture::new("qsr-cli-existing-refusals")?;
    let before = fixture.source.journals()?;
    refused(
        &command(
            &fixture.source.root,
            ContentDigest::sha256(b"unknown retained zone report"),
        )
        .output()?,
    );
    assert_eq!(fixture.source.journals()?, before);
    refused(
        &command(&fixture.source.root, fixture.report)
            .args(["--zone-role", "foreign-zone:queue"])
            .output()?,
    );
    assert_eq!(fixture.source.journals()?, before);
    let mut corrupt = fs::read(&fixture.source.chunk)?;
    *corrupt.last_mut().ok_or("source object")? ^= 1;
    fs::write(&fixture.source.chunk, &corrupt)?;
    refused(&command(&fixture.source.root, fixture.report).output()?);
    assert_eq!(fs::read(&fixture.source.chunk)?, corrupt);
    assert_eq!(fixture.source.journals()?, before);
    Ok(())
}

#[test]
fn missing_or_foreign_roots_are_not_created_and_help_has_no_storage_effect() -> Test {
    let directory = Directory::new("qsr-cli-existing-missing")?;
    let root = directory.0.join("absent");
    let report = ContentDigest::sha256(b"absent report");
    refused(&command(&root, report).output()?);
    assert!(!root.exists());
    fs::create_dir(&root)?;
    fs::write(root.join("foreign-data"), b"unrelated data")?;
    refused(&command(&root, report).output()?);
    assert_eq!(fs::read(root.join("foreign-data"))?, b"unrelated data");
    assert_eq!(fs::read_dir(&root)?.count(), 1);
    let output = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["qsr", "--help"])
        .output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = std::str::from_utf8(&output.stdout)?;
    assert!(help.contains("effect states and obligations are preserved"));
    assert!(help.contains("local locked publisher recovery still runs"));
    assert_eq!(fs::read_dir(&root)?.count(), 1);
    Ok(())
}
