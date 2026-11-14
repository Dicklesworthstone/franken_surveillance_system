#![forbid(unsafe_code)]
//! Full localization custody inspection while the ingest writer remains active.

#[path = "../../fss-reference/tests/twin_localization_query_support/mod.rs"]
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_reference::agent_orient::OrientLimits;
use fss_reference::ingest::RetainedReadLimits;
use fss_reference::ingest::twin_localization::retained::RetainedLocalization;
use fss_reference::retained_source::{
    ImmutableRetainedReadLimits, ImmutableRetainedSource, RetainedReadUsage,
};
use support::{Fixture, PRINCIPAL, Record, SITE, Test};

fn pins(record: &Record) -> [ContentDigest; 3] {
    [record.identity, record.root, record.receipt]
}

fn command(root: &Path, site: &str, pins: [ContentDigest; 3]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-file"));
    command
        .arg("read-localization")
        .arg("--root")
        .arg(root)
        .args(["--site", site, "--principal", PRINCIPAL])
        .args([
            "--localization-id",
            &pins[0].to_text(),
            "--expected-root",
            &pins[1].to_text(),
            "--expected-receipt",
            &pins[2].to_text(),
        ]);
    command
}

fn read(fixture: &Fixture, record: &Record) -> Command {
    command(fixture.root(), SITE, pins(record))
}

fn export(fixture: &Fixture, name: &str) -> Test<PathBuf> {
    Ok(fixture.root().parent().ok_or("fixture parent")?.join(name))
}

fn success(output: &Output) -> Test<BTreeMap<String, String>> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (key, value) = line.split_once('=').ok_or("status field")?;
        assert!(fields.insert(key.to_owned(), value.to_owned()).is_none());
    }
    Ok(fields)
}

fn refused(output: &Output, export: &Path) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "no partial inspection status");
    assert!(!output.stderr.is_empty());
    assert!(!export.exists(), "no receipt may escape a refused read");
}

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, (bool, Vec<u8>)>> {
    let mut pending = vec![root.to_owned()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let key = path.strip_prefix(root)?.to_owned();
        if metadata.is_dir() {
            result.insert(key, (true, Vec::new()));
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            result.insert(key, (false, fs::read(path)?));
        } else {
            return Err("unexpected fixture file type".into());
        }
    }
    Ok(result)
}

fn complete_usage(fixture: &Fixture, record: &Record) -> Test<RetainedReadUsage> {
    let cx = support::context(fixture.root())?;
    let source = ImmutableRetainedSource::open(
        fixture.root(),
        ImmutableRetainedReadLimits {
            snapshot: OrientLimits::default(),
            max_read_bytes: 256 * 1024 * 1024,
            max_read_objects: 65_536,
        },
        &cx,
    )?;
    let package = RetainedLocalization::open(
        &source,
        record.identity,
        RetainedReadLimits::default(),
        &mut WorkBudget::new(2_000_000_000),
        &cx,
    )?;
    assert_eq!(package.publication_root(), record.root);
    assert_eq!(package.receipt_digest(), record.receipt);
    source.revalidate_snapshot_metadata()?;
    source.revalidate()?;
    let usage = source.usage();
    drop(source);
    cx.drain_and_finalize();
    Ok(usage)
}

#[test]
fn full_custody_read_and_create_only_export_work_with_live_ingest_and_absent_media() -> Test {
    let fixture = Fixture::new("localization-immutable-cli")?;
    let record = fixture.records.first().ok_or("native localization")?;
    fs::write(
        fixture.root().join("LAYOUT.tmp"),
        b"pending layout, do not recover",
    )?;
    let before = tree(fixture.root())?;
    let receipt_path = export(&fixture, "read.receipt")?;
    let output = read(&fixture, record)
        .arg("--receipt-out")
        .arg(&receipt_path)
        .output()?;
    let fields = success(&output)?;
    for (key, expected) in [
        ("operation", "read-localization"),
        ("native_replay_verified", "false"),
        ("calibration_activated", "false"),
        ("coverage_certifiable", "false"),
        ("jpeg_work_units", "0"),
        ("video_work_units", "0"),
    ] {
        assert_eq!(fields.get(key).map(String::as_str), Some(expected), "{key}");
    }
    assert_eq!(
        fields.get("localization_identity"),
        Some(&record.identity.to_text())
    );
    assert_eq!(
        fields.get("localization_root"),
        Some(&record.root.to_text())
    );
    assert_eq!(
        fields.get("localization_receipt"),
        Some(&record.receipt.to_text())
    );
    let receipt = fs::read(fixture.object_path(record.receipt))?;
    assert_eq!(fs::read(&receipt_path)?, receipt);
    assert_eq!(
        tree(fixture.root())?,
        before,
        "no publisher recovery or deployment writes"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&receipt_path)?.permissions().mode() & 0o777,
            0o600
        );
    }

    let existing = read(&fixture, record)
        .arg("--receipt-out")
        .arg(&receipt_path)
        .output()?;
    assert!(!existing.status.success());
    assert!(existing.stdout.is_empty());
    assert_eq!(
        fs::read(&receipt_path)?,
        receipt,
        "existing export is never overwritten"
    );
    let inside = fixture.root().join("forbidden.receipt");
    refused(
        &read(&fixture, record)
            .arg("--receipt-out")
            .arg(&inside)
            .output()?,
        &inside,
    );
    assert_eq!(tree(fixture.root())?, before);

    // Inspection retains full archive custody semantics but does not run pixel decoding.
    let media: BTreeSet<_> = fixture
        .records
        .iter()
        .flat_map(|record| [record.source_blob, record.luma_blob])
        .collect();
    for digest in media {
        fs::remove_file(fixture.object_path(digest))?;
    }
    let absent_media = tree(fixture.root())?;
    let reopened = read(&fixture, record).output()?;
    success(&reopened)?;
    assert_eq!(reopened.stdout, output.stdout);
    assert_eq!(tree(fixture.root())?, absent_media);
    Ok(())
}

#[test]
fn exact_complete_allowance_includes_final_rereads_before_status_and_receipt_export() -> Test {
    let fixture = Fixture::new("localization-immutable-cli-budget")?;
    let record = fixture.records.first().ok_or("native localization")?;
    let usage = complete_usage(&fixture, record)?;
    assert!(usage.read_bytes > 1 && usage.read_objects > 1);
    let before = tree(fixture.root())?;
    let bytes = usage.read_bytes.to_string();
    let objects = usage.read_objects.to_string();
    let exact = read(&fixture, record)
        .args(["--max-read-bytes", &bytes, "--max-read-objects", &objects])
        .output()?;
    success(&exact)?;
    for (name, bytes, objects) in [
        (
            "short-byte.receipt",
            (usage.read_bytes - 1).to_string(),
            objects.clone(),
        ),
        (
            "short-object.receipt",
            bytes.clone(),
            (usage.read_objects - 1).to_string(),
        ),
    ] {
        let path = export(&fixture, name)?;
        let output = read(&fixture, record)
            .args(["--max-read-bytes", &bytes, "--max-read-objects", &objects])
            .arg("--receipt-out")
            .arg(&path)
            .output()?;
        refused(&output, &path);
        assert_eq!(tree(fixture.root())?, before);
    }
    Ok(())
}

#[test]
fn wrong_pins_and_corrupt_or_missing_archives_refuse_without_receipt_or_partial_status() -> Test {
    let fixture = Fixture::new("localization-immutable-cli-pins")?;
    let record = fixture.records.first().ok_or("native localization")?;
    let before = tree(fixture.root())?;
    for index in 0..3 {
        let mut wrong = pins(record);
        wrong[index] = ContentDigest::sha256(b"not the retained localization pin");
        let path = export(&fixture, &format!("wrong-pin-{index}.receipt"))?;
        refused(
            &command(fixture.root(), SITE, wrong)
                .arg("--receipt-out")
                .arg(&path)
                .output()?,
            &path,
        );
    }
    assert_eq!(tree(fixture.root())?, before);
    for (name, digest) in [("twin", record.twin_blob), ("atlas", record.atlas_blob)] {
        let archive = fixture.object_path(digest);
        let original = fs::read(&archive)?;
        for corrupt in [false, true] {
            if corrupt {
                fs::write(&archive, b"corrupt retained mapping archive")?;
            } else {
                fs::remove_file(&archive)?;
            }
            let damaged = tree(fixture.root())?;
            let path = export(&fixture, &format!("{name}-{corrupt}.receipt"))?;
            refused(
                &read(&fixture, record)
                    .arg("--receipt-out")
                    .arg(&path)
                    .output()?,
                &path,
            );
            assert_eq!(tree(fixture.root())?, damaged);
            fs::write(&archive, &original)?;
        }
    }
    assert_eq!(tree(fixture.root())?, before);
    Ok(())
}

#[test]
fn site_mismatch_absent_root_and_torn_journal_never_initialize_or_recover_a_deployment() -> Test {
    let fixture = Fixture::new("localization-immutable-cli-no-recovery")?;
    let record = fixture.records.first().ok_or("native localization")?;
    let before = tree(fixture.root())?;
    let path = export(&fixture, "wrong-site.receipt")?;
    refused(
        &command(fixture.root(), "site:wrong", pins(record))
            .arg("--receipt-out")
            .arg(&path)
            .output()?,
        &path,
    );
    let absent = export(&fixture, "absent-deployment")?;
    let path = export(&fixture, "absent.receipt")?;
    refused(
        &command(&absent, SITE, pins(record))
            .arg("--receipt-out")
            .arg(&path)
            .output()?,
        &path,
    );
    assert!(!absent.exists());
    assert_eq!(tree(fixture.root())?, before);

    fs::write(
        fixture.root().join("LAYOUT.tmp"),
        b"pending layout, do not recover",
    )?;
    let journal = fixture.root().join("ledger/journal.fssj");
    OpenOptions::new()
        .append(true)
        .open(journal)?
        .write_all(&[0xff])?;
    let torn = tree(fixture.root())?;
    let path = export(&fixture, "torn.receipt")?;
    refused(
        &read(&fixture, record)
            .arg("--receipt-out")
            .arg(&path)
            .output()?,
        &path,
    );
    assert_eq!(
        tree(fixture.root())?,
        torn,
        "no tail truncation or layout cleanup"
    );
    Ok(())
}
