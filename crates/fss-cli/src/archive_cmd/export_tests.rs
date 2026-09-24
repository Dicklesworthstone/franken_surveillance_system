#![forbid(unsafe_code)]
use super::super::tests::{argv, clock, path, setup, window};
use super::*;
use std::cell::Cell;
use std::io::Cursor;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
fn exporting(
    name: &str,
) -> std::result::Result<(ArchiveOptions, LocalRootPublisher, PathBuf), Box<dyn std::error::Error>>
{
    let (mut options, publisher) = setup(name)?;
    let output = path(&format!("{name}-output"))?;
    options.action = Action::Export;
    options.query = Some(70_000..110_000);
    options.output = Some(output.clone());
    Ok((options, publisher, output))
}
fn prefix(ordinal: usize, plan: &PreparedRecording) -> String {
    format!(
        "window-{ordinal:016x}-{}",
        &plan.manifest().root().to_text()[7..]
    )
}

#[test]
fn export_requires_whole_window_approval_and_pin_before_io() -> TestResult {
    let pin = ContentDigest::sha256(b"pin").to_text();
    let range = [
        "--expected-snapshot",
        &pin,
        "--start",
        "0",
        "--end",
        "1",
        "--output-dir",
        "/unused/output",
    ];
    let mut args = argv("export", &range);
    assert!(parse_archive_args(&args).is_err());
    args.extend(["--allow-whole-windows".into(), "no".into()]);
    assert!(parse_archive_args(&args).is_err());
    *args.last_mut().ok_or("last argument")? = "yes".into();
    assert!(parse_archive_args(&args)?.is_some());
    assert!(parse_archive_args(&argv("query", &range)).is_err());
    args.extend(["--max-export-bytes".into(), "0".into()]);
    assert!(parse_archive_args(&args).is_err());
    Ok(())
}
#[test]
fn exported_mp4_and_all_provenance_objects_equal_the_verified_originals() -> TestResult {
    let (o, p, output) = exporting("exact-export")?;
    let report = execute_for::<HevcArchiveCodec>(&o, &p, &clock())?;
    assert_eq!(fs::read_to_string(output.join("COMPLETE.json"))?, report);
    assert_eq!(
        fs::read(output.join("COMPLETE.json.pending"))?,
        report.as_bytes()
    );
    assert!(report.contains("\"whole_windows_authorized\":true"));
    assert!(report.contains("\"requested_interval\":[70000,72000]"));
    for (ordinal, base) in [(0, 0), (1, 100_000)] {
        let w = window(base)?;
        let plan = w.publication_plan();
        let stem = prefix(ordinal, plan);
        for ((_, _, bytes), suffix) in
            plan.children()
                .into_iter()
                .zip(["source.bin", "init.mp4", "media.m4s", "index.bin"])
        {
            assert_eq!(fs::read(output.join(format!("{stem}.{suffix}")))?, bytes);
        }
        assert_eq!(
            fs::read(output.join(format!("{stem}.root.bin")))?,
            plan.manifest().canonical_bytes()
        );
        let playback = fs::read(output.join(format!("{stem}.playback.mp4")))?;
        assert_eq!(
            playback,
            [plan.objects().initialization, plan.objects().media].concat()
        );
        assert!(report.contains(&quoted(&ContentDigest::sha256(&playback).to_text())));
    }
    assert_eq!(fs::read_dir(&output)?.count(), 15); // 6/window + request + two completion links.
    assert_eq!(p.visible_roots().count(), 5); // Export never republishes or removes archive roots.
    Ok(())
}
#[test]
fn existing_destination_and_files_are_never_overwritten() -> TestResult {
    let (o, p, output) = exporting("no-overwrite")?;
    fs::create_dir(&output)?;
    fs::write(output.join("sentinel"), b"owner content")?;
    assert!(matches!(
        execute_for::<HevcArchiveCodec>(&o, &p, &clock()),
        Err(ArchiveCommandError::OutputExists)
    ));
    assert_eq!(fs::read(output.join("sentinel"))?, b"owner content");
    assert_eq!(fs::read_dir(output)?.count(), 1);
    Ok(())
}
#[test]
fn export_inside_archive_is_refused_before_directory_creation() -> TestResult {
    let (mut o, p, _) = exporting("inside-source")?;
    let bad = o.root.join("forbidden-export");
    o.output = Some(bad.clone());
    assert!(matches!(
        execute_for::<HevcArchiveCodec>(&o, &p, &clock()),
        Err(ArchiveCommandError::OutputScope)
    ));
    assert!(!bad.exists());
    Ok(())
}
#[cfg(unix)]
#[test]
fn parent_symlink_alias_into_archive_cannot_bypass_output_scope() -> TestResult {
    use std::os::unix::fs::symlink;
    let (mut o, p, _) = exporting("alias-source")?;
    let alias = path("alias-source-link")?;
    symlink(&o.root, &alias)?;
    o.output = Some(alias.join("forbidden-export"));
    assert!(matches!(
        execute_for::<HevcArchiveCodec>(&o, &p, &clock()),
        Err(ArchiveCommandError::OutputScope)
    ));
    assert!(!o.root.join("forbidden-export").exists());
    fs::remove_file(alias)?;
    Ok(())
}
#[test]
fn snapshot_and_export_budget_fail_before_any_output_is_created() -> TestResult {
    let (mut o, p, output) = exporting("preflight")?;
    let original = o.expected;
    o.expected = Some(ContentDigest::sha256(b"wrong snapshot"));
    assert!(matches!(
        execute_for::<HevcArchiveCodec>(&o, &p, &clock()),
        Err(ArchiveCommandError::SnapshotMismatch)
    ));
    assert!(!output.exists());
    o.expected = original;
    o.export_budget = 1;
    assert!(matches!(
        execute_for::<HevcArchiveCodec>(&o, &p, &clock()),
        Err(ArchiveCommandError::ExportBudget)
    ));
    assert!(!output.exists());
    Ok(())
}
#[test]
fn completion_link_is_create_only_even_after_payload_and_pending_receipt_exist() -> TestResult {
    let (o, _, output) = exporting("completion-conflict")?;
    let mut destination = Destination::begin(&o, o.expected.ok_or("pin")?, 0, &clock())?;
    fs::write(output.join("COMPLETE.json"), b"existing completion")?;
    assert!(
        destination
            .complete("{\"complete\":true}\n", &clock())
            .is_err()
    );
    assert_eq!(
        fs::read(output.join("COMPLETE.json"))?,
        b"existing completion"
    );
    assert!(output.join("COMPLETE.json.pending").exists());
    Ok(())
}
#[test]
fn timeout_preserves_written_payloads_without_publishing_completion() -> TestResult {
    let (o, _, output) = exporting("timeout-export")?;
    let w = window(0)?;
    let mut destination =
        Destination::begin(&o, o.expected.ok_or("pin")?, w.byte_len() as u64, &clock())?;
    destination.window(0, w.publication_plan(), &clock())?;
    struct Expired;
    impl PublishCancellation for Expired {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            true
        }
    }
    impl OperationClock for Expired {
        fn now_ns(&self) -> Result<u64> {
            Ok(100)
        }
        fn deadline_ns(&self) -> u64 {
            100
        }
    }
    assert!(
        destination
            .complete("{\"complete\":true}\n", &Expired)
            .is_err()
    );
    assert_eq!(fs::read_dir(&output)?.count(), 7);
    assert!(!output.join("COMPLETE.json").exists());
    Ok(())
}
#[test]
fn bounded_io_handles_short_writes_and_refuses_interrupt_storms_and_bad_readback() -> TestResult {
    struct Short {
        bytes: Vec<u8>,
        interrupts: usize,
        calls: usize,
    }
    impl Write for Short {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.interrupts > 0 {
                self.interrupts -= 1;
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = b.len().min(3);
            self.bytes.extend_from_slice(&b[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let original = b"exact output despite short writes";
    let mut short = Short {
        bytes: Vec::new(),
        interrupts: 7,
        calls: 0,
    };
    write_bounded(&mut short, original, &clock())?;
    assert_eq!(short.bytes, original);
    let mut storm = Short {
        bytes: Vec::new(),
        interrupts: 1000,
        calls: 0,
    };
    assert!(write_bounded(&mut storm, original, &clock()).is_err());
    assert_eq!(storm.calls, 8);
    verify_bytes(&mut Cursor::new(original), original, &clock())?;
    for corrupt in [
        original[..original.len() - 1].to_vec(),
        [original.as_slice(), b"extra"].concat(),
        b"wrong".to_vec(),
    ] {
        assert!(verify_bytes(&mut Cursor::new(corrupt), original, &clock()).is_err());
    }
    struct Interrupted(Cell<usize>);
    impl Read for Interrupted {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.0.set(self.0.get() + 1);
            Err(io::ErrorKind::Interrupted.into())
        }
    }
    let mut interrupted = Interrupted(Cell::new(0));
    assert!(verify_bytes(&mut interrupted, original, &clock()).is_err());
    assert_eq!(interrupted.0.get(), 8);
    Ok(())
}
#[test]
fn later_source_corruption_keeps_earlier_export_but_never_claims_complete() -> TestResult {
    let (o, p, output) = exporting("late-corruption")?;
    let first = window(0)?;
    let second = window(100_000)?;
    let digest = second.publication_plan().children()[2].1.to_text();
    struct CorruptAfterExport {
        trigger: PathBuf,
        corrupt: PathBuf,
        done: Cell<bool>,
    }
    impl PublishCancellation for CorruptAfterExport {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            if !self.done.get() && self.trigger.exists() {
                // Deliberate fault in a synthetic test store, never production repair logic.
                self.done.set(true);
                if fs::write(&self.corrupt, b"corrupt later media").is_err() {
                    return true;
                }
            }
            false
        }
    }
    impl OperationClock for CorruptAfterExport {
        fn now_ns(&self) -> Result<u64> {
            Ok(1)
        }
        fn deadline_ns(&self) -> u64 {
            100
        }
    }
    let trigger = output.join(format!(
        "{}.playback.mp4",
        prefix(0, first.publication_plan())
    ));
    let fault = CorruptAfterExport {
        trigger: trigger.clone(),
        corrupt: o.root.join("spool/objects").join(&digest[7..]),
        done: Cell::new(false),
    };
    assert!(matches!(
        execute_for::<HevcArchiveCodec>(&o, &p, &fault),
        Err(ArchiveCommandError::ExportIncomplete(_))
    ));
    assert!(fault.done.get());
    assert!(trigger.exists());
    assert!(!output.join("COMPLETE.json").exists());
    Ok(())
}
#[test]
fn empty_export_finishes_with_an_explicit_unindexed_receipt_not_a_fake_video() -> TestResult {
    let (mut o, p, output) = exporting("empty-export")?;
    o.query = Some(200_000..210_000);
    let report = execute_for::<HevcArchiveCodec>(&o, &p, &clock())?;
    assert!(report.contains("\"verified_windows\":0"));
    assert!(report.contains("\"unindexed\":[[200000,210000]]"));
    assert_eq!(fs::read_dir(output)?.count(), 3);
    Ok(())
}
#[cfg(unix)]
#[test]
fn exported_files_and_directory_are_private_by_default() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let (o, p, output) = exporting("private-mode")?;
    execute_for::<HevcArchiveCodec>(&o, &p, &clock())?;
    assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o077, 0);
    for entry in fs::read_dir(output)? {
        assert_eq!(entry?.metadata()?.permissions().mode() & 0o077, 0);
    }
    Ok(())
}
