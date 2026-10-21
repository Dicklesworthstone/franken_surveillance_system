#![forbid(unsafe_code)]
//! Real native journals and media, with the original writer dropped before recovery.

use super::*;
use crate::plan::Options;
use fss_reference::rtsp::archive_pins::{ArchivePinError, HevcArchivePinJournal};
use fss_reference::rtsp::recording::hevc::{
    PreparedHevcRecording, local::load_hevc_recording, prepare_hevc_recording,
};
use fss_reference::rtsp::recording_archive::checkpoint::write_ahead::{
    CheckpointedArchiveProgress, CheckpointedHevcArchiveWriter,
};
use fss_reference::rtsp::recording_archive::hevc::HevcArchiveNamespace;
use std::cell::Cell;
use std::ffi::OsString;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "../../../../fss-reference/tests/hevc_recording_support/mod.rs"]
mod source;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const TIMEOUT: u64 = 30_000_000_000;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for _ in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-reconnect-recovery-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(fs::canonicalize(path)?)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory reservation exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn args(directory: &Directory, codec: &str) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "--peer",
        "127.0.0.1:8554",
        "--authority",
        "camera.test:8554",
        "--presentation",
        "/camera/main",
        "--control-root",
        "/camera",
        "--sensor-id",
        "sensor:camera",
        "--stream-id",
        "stream:main",
        "--generation",
        "1",
        "--ingress",
        "1",
        "--ssrc",
        "7",
        "--frame-duration-ticks",
        "18000",
        "--stop-after-pictures",
        "2",
        "--owner-authorized",
        "yes",
        "--plaintext",
        "yes",
        "--retain-originals",
        "yes",
        "--max-attempts",
        "2",
        "--recover",
        "yes",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    for key in [
        "--anchor",
        "--receive-clock",
        "--timing-evidence",
        "--journal-id",
    ] {
        args.extend([
            key.into(),
            ContentDigest::sha256(key.as_bytes()).to_text().into(),
        ]);
    }
    args.extend([
        "--root".into(),
        directory.0.join("archive").into_os_string(),
        "--pins".into(),
        directory.0.join("pins").into_os_string(),
        "--codec".into(),
        codec.into(),
    ]);
    args
}

fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = args.iter().position(|arg| arg == key) {
        args[index + 1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}

fn approve(plan: &mut ReconnectPlan) -> Test<ContentDigest> {
    let preview = plan.preview()?;
    let text = preview
        .split("\"approval\":\"")
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .ok_or("missing recovery approval")?;
    let approval = ContentDigest::parse(text)?;
    assert_ne!(approval, plan.digest()?);
    plan.approve = Some(approval);
    Ok(approval)
}

fn recording(options: &Options) -> Test<PreparedHevcRecording> {
    let packets = source::packets()?;
    Ok(prepare_hevc_recording(
        options.recording_config().scope,
        &source::configuration()?,
        90_000,
        &source::timings(2),
        &source::borrowed(&packets[..6]),
    )?)
}

fn fixture(options: &Options, durable_work: bool) -> Test<ContentDigest> {
    let namespace = HevcArchiveNamespace::new(options.catalog_scope().clone())?;
    assert_eq!(namespace.digest(), options.pin_scope().archive_namespace);
    let mut publisher = LocalRootPublisher::open(&options.root, options.publication_limits())?;
    let mut pins = HevcArchivePinJournal::create(
        &options.pins,
        options.pin_scope(),
        options.pin_limits(),
        &NeverCancel,
    )?;
    let mut writer = CheckpointedHevcArchiveWriter::open(
        &mut publisher,
        namespace,
        options.work_limits().archive,
        options.work_limits(),
        256,
        0,
        1000,
        &NeverCancel,
    )?;
    let window = recording(options)?;
    let root = window.manifest().root();
    let bytes = window.byte_len();
    writer.offer(window, bytes, 0)?;
    let CheckpointedArchiveProgress::PinRequired(pin) = writer.step(0, &NeverCancel)? else {
        return Err("missing checkpoint candidate".into());
    };
    pins.persist_candidate(&pin, &NeverCancel)?;
    if durable_work {
        writer.acknowledge_checkpoint(&pin, 0, &NeverCancel)?;
        assert!(matches!(
            writer.step(0, &NeverCancel)?,
            CheckpointedArchiveProgress::WorkDurable { .. }
        ));
    }
    let _retirement = writer.retire();
    // All native owners and in-memory work are dropped on return.
    Ok(root)
}

fn journal(options: &Options) -> Test<Vec<u8>> {
    Ok(fs::read(options.pins.join("pins.journal"))?)
}

fn roots(options: &Options) -> Test<Vec<OsString>> {
    let mut names = fs::read_dir(options.root.join("roots"))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    Ok(names)
}

fn window_present(options: &Options) -> Test<bool> {
    let publisher = LocalRootPublisher::open(&options.root, options.publication_limits())?;
    let namespace = HevcArchiveNamespace::new(options.catalog_scope().clone())?;
    Ok(publisher.root(&namespace.window_slot(0)?).is_some())
}

fn cold_window(options: &Options, expected: ContentDigest) -> Test {
    let publisher = LocalRootPublisher::open(&options.root, options.publication_limits())?;
    let namespace = HevcArchiveNamespace::new(options.catalog_scope().clone())?;
    let loaded = load_hevc_recording(
        &publisher,
        &namespace.window_slot(0)?,
        expected,
        &options.recording_config().scope,
        &NeverCancel,
    )?;
    let original = recording(options)?;
    assert_eq!(loaded.manifest().root(), expected);
    assert_eq!(loaded.objects().source, original.objects().source);
    assert_eq!(loaded.objects().media, original.objects().media);
    assert_eq!(loaded.samples(), original.samples());
    assert_eq!(loaded.source_only_nals(), 1);
    assert_eq!(loaded.summary().samples, 2);
    assert!(publisher.root(&namespace.window_slot(1)?).is_none());
    Ok(())
}

fn capture_rows(plan: &ReconnectPlan) -> Test<String> {
    let mut output = Vec::new();
    execute_codec::<HevcArchiveCodec>(
        plan,
        TIMEOUT,
        |row| {
            output.extend_from_slice(row);
            Ok(())
        },
        &NeverCancel,
    )?;
    Ok(String::from_utf8(output)?)
}

#[test]
fn two_cold_candidates_restore_original_windows_and_retry_without_duplicate_authority() -> Test {
    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&args(&directory, "hevc"))?;
    let first = fixture(&plan.attempts[0], true)?;
    let second = fixture(&plan.attempts[1], true)?;
    let old = [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?];
    let approval = approve(&mut plan)?;
    assert_eq!(
        old,
        [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?]
    );
    let rows = capture_rows(&plan)?;
    assert_eq!(rows.matches("\"confirmation_recorded\":true").count(), 2);
    assert!(rows.contains("\"selected_work_restored\":2"));
    assert!(rows.contains("\"indexed_windows_in_checked_archives\":0"));
    assert!(rows.contains("\"capture_complete\":false"));
    assert!(rows.contains("\"continuity_across_attempts\":false"));
    cold_window(&plan.attempts[0], first)?;
    cold_window(&plan.attempts[1], second)?;
    assert_ne!(approve(&mut plan)?, approval);
    let saved = [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?];
    let saved_roots = [roots(&plan.attempts[0])?, roots(&plan.attempts[1])?];
    let rows = capture_rows(&plan)?;
    assert_eq!(rows.matches("\"outcome\":\"already_durable\"").count(), 2);
    assert_eq!(
        saved,
        [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?]
    );
    assert_eq!(
        saved_roots,
        [roots(&plan.attempts[0])?, roots(&plan.attempts[1])?]
    );
    Ok(())
}

#[test]
fn later_missing_work_blocks_every_confirmation_and_normal_publication() -> Test {
    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&args(&directory, "hevc"))?;
    fixture(&plan.attempts[0], true)?;
    fixture(&plan.attempts[1], false)?;
    approve(&mut plan)?;
    let old = [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?];
    let old_roots = [roots(&plan.attempts[0])?, roots(&plan.attempts[1])?];
    let mut rows = Vec::new();
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(
            &plan,
            TIMEOUT,
            |row| {
                rows.extend_from_slice(row);
                Ok(())
            },
            &NeverCancel
        ),
        Err(STORAGE)
    );
    assert!(!String::from_utf8(rows)?.contains("source_preflight_complete"));
    assert_eq!(
        old,
        [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?]
    );
    assert_eq!(
        old_roots,
        [roots(&plan.attempts[0])?, roots(&plan.attempts[1])?]
    );
    assert!(!window_present(&plan.attempts[0])?);
    assert!(!window_present(&plan.attempts[1])?);
    Ok(())
}

#[test]
fn lost_first_restoration_output_stops_the_next_attempt_and_retries_original_slots() -> Test {
    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&args(&directory, "hevc"))?;
    let first = fixture(&plan.attempts[0], true)?;
    let second = fixture(&plan.attempts[1], true)?;
    approve(&mut plan)?;
    let old_second = journal(&plan.attempts[1])?;
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(
            &plan,
            TIMEOUT,
            |row| {
                if std::str::from_utf8(row)
                    .map_err(|_| OUTPUT)?
                    .contains("\"kind\":\"attempt_recovery\"")
                {
                    Err(OUTPUT)
                } else {
                    Ok(())
                }
            },
            &NeverCancel
        ),
        Err(OUTPUT)
    );
    cold_window(&plan.attempts[0], first)?;
    assert!(!window_present(&plan.attempts[1])?);
    assert_eq!(journal(&plan.attempts[1])?, old_second);
    approve(&mut plan)?;
    capture_rows(&plan)?;
    cold_window(&plan.attempts[0], first)?;
    cold_window(&plan.attempts[1], second)?;
    Ok(())
}

#[test]
fn delegated_approval_is_checked_once_under_locks_before_any_restoration() -> Test {
    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&args(&directory, "hevc"))?;
    for attempt in &plan.attempts {
        fixture(attempt, true)?;
    }
    // Even a valid native approval cannot bypass the enclosing owner's denial.
    let expected = approve(&mut plan)?;
    let before_journals = [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?];
    let before_roots = [roots(&plan.attempts[0])?, roots(&plan.attempts[1])?];
    let calls = Cell::new(0);
    let reports = Cell::new(0);
    assert_eq!(
        execute_codec_validated::<HevcArchiveCodec>(
            &plan,
            TIMEOUT,
            |_| {
                reports.set(reports.get() + 1);
                Ok(())
            },
            &NeverCancel,
            &|observed| {
                calls.set(calls.get() + 1);
                assert_eq!(observed, expected);
                for attempt in &plan.attempts {
                    assert!(matches!(
                        HevcArchivePinJournal::open_complete(
                            &attempt.pins,
                            attempt.pin_scope(),
                            None,
                            attempt.pin_limits(),
                            &NeverCancel,
                        ),
                        Err(ArchivePinError::Busy)
                    ));
                }
                Err("ERR-CAPTURE-ONVIF-APPROVAL-001")
            },
        ),
        Err("ERR-CAPTURE-ONVIF-APPROVAL-001")
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(reports.get(), 0);
    assert_eq!(
        before_journals,
        [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?]
    );
    assert_eq!(
        before_roots,
        [roots(&plan.attempts[0])?, roots(&plan.attempts[1])?]
    );
    for attempt in &plan.attempts {
        assert!(!window_present(attempt)?);
    }
    Ok(())
}

#[test]
fn all_journal_and_selected_archive_locks_remain_owned_through_preflight() -> Test {
    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&args(&directory, "hevc"))?;
    for attempt in &plan.attempts {
        fixture(attempt, true)?;
    }
    approve(&mut plan)?;
    let mut checked = false;
    execute_codec::<HevcArchiveCodec>(
        &plan,
        TIMEOUT,
        |row| {
            if std::str::from_utf8(row)
                .map_err(|_| OUTPUT)?
                .contains("source_preflight_complete")
            {
                for attempt in &plan.attempts {
                    assert!(matches!(
                        HevcArchivePinJournal::open_complete(
                            &attempt.pins,
                            attempt.pin_scope(),
                            None,
                            attempt.pin_limits(),
                            &NeverCancel,
                        ),
                        Err(ArchivePinError::Busy)
                    ));
                    assert!(
                        LocalRootPublisher::open(&attempt.root, attempt.publication_limits())
                            .is_err()
                    );
                }
                checked = true;
            }
            Ok(())
        },
        &NeverCancel,
    )?;
    assert!(checked);
    Ok(())
}

#[test]
fn candidate_confirmation_after_preview_invalidates_old_approval_before_source_preflight() -> Test {
    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&args(&directory, "hevc"))?;
    fixture(&plan.attempts[0], true)?;
    approve(&mut plan)?;
    {
        let attempt = &plan.attempts[0];
        let publisher = LocalRootPublisher::open(&attempt.root, attempt.publication_limits())?;
        let mut pins = HevcArchivePinJournal::open_complete(
            &attempt.pins,
            attempt.pin_scope(),
            None,
            attempt.pin_limits(),
            &NeverCancel,
        )?;
        pins.confirm_recovered(&publisher, attempt.work_limits(), &NeverCancel)?;
    }
    let saved = journal(&plan.attempts[0])?;
    let mut emitted = false;
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(
            &plan,
            TIMEOUT,
            |_| {
                emitted = true;
                Ok(())
            },
            &NeverCancel
        ),
        Err(APPROVAL)
    );
    assert!(!emitted);
    assert_eq!(saved, journal(&plan.attempts[0])?);
    assert!(!window_present(&plan.attempts[0])?);
    Ok(())
}

#[test]
fn missing_pairs_are_unknown_and_neither_preview_nor_execution_reads_credentials() -> Test {
    let directory = Directory::new()?;
    for codec in ["avc", "hevc"] {
        let mut input = args(&directory, codec);
        set(
            &mut input,
            "--credential-file",
            directory.0.join("absent-secret").to_str().ok_or("path")?,
        );
        set(&mut input, "--auth-realm", "exact-realm");
        let mut plan = ReconnectPlan::parse(&input)?;
        let preview = plan.preview()?;
        assert!(preview.contains("both_stores_unobserved"));
        assert!(!preview.contains("absent-secret"));
        approve(&mut plan)?;
        let mut rows = Vec::new();
        let emit = |row: &[u8]| {
            rows.extend_from_slice(row);
            Ok(())
        };
        match codec {
            "avc" => execute_codec::<AvcArchiveCodec>(&plan, TIMEOUT, emit, &NeverCancel)?,
            _ => execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT, emit, &NeverCancel)?,
        }
        assert!(String::from_utf8(rows)?.contains("\"unobserved_attempts\":2"));
        assert_eq!(fs::read_dir(&directory.0)?.count(), 0);
    }
    Ok(())
}

#[test]
fn capture_approval_is_never_recovery_authority_and_deadline_is_bound() -> Test {
    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&args(&directory, "hevc"))?;
    plan.approve = Some(plan.digest()?);
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel),
        Err(APPROVAL)
    );
    approve(&mut plan)?;
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT + 1, |_| Ok(()), &NeverCancel),
        Err(APPROVAL)
    );
    assert_eq!(fs::read_dir(&directory.0)?.count(), 0);
    Ok(())
}

#[test]
fn partial_layout_and_replaced_parent_refuse_without_initializing_any_store() -> Test {
    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&args(&directory, "hevc"))?;
    fs::create_dir(&plan.attempts[1].pins)?;
    assert!(plan.preview().is_err());
    assert!(!plan.attempts[0].root.exists());
    assert!(!plan.attempts[1].root.exists());
    fs::rename(&plan.attempts[1].pins, directory.0.join("partial-kept"))?;
    approve(&mut plan)?;
    let parent = directory.0.join("replacement-parent");
    fs::create_dir(&parent)?;
    // An absent leaf is still tied to the original canonical parent identity.
    let original = locate(&plan.attempts[0].root)?;
    let other = locate(&parent.join(plan.attempts[0].root.file_name().ok_or("name")?))?;
    assert_ne!(original, other);
    Ok(())
}

#[test]
fn corrupt_journal_tail_is_not_repaired_or_ignored() -> Test {
    let directory = Directory::new()?;
    let plan = ReconnectPlan::parse(&args(&directory, "hevc"))?;
    fixture(&plan.attempts[0], true)?;
    let path = plan.attempts[0].pins.join("pins.journal");
    fs::OpenOptions::new()
        .append(true)
        .open(&path)?
        .write_all(&[1, 2, 3])?;
    let saved = fs::read(&path)?;
    assert!(plan.preview().is_err());
    assert_eq!(fs::read(&path)?, saved);
    assert!(!window_present(&plan.attempts[0])?);
    Ok(())
}

#[test]
fn source_preflight_cancellation_prevents_all_confirmations_and_publications() -> Test {
    struct Cancel(Cell<bool>);
    impl PublishCancellation for Cancel {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            self.0.get()
        }
    }
    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&args(&directory, "hevc"))?;
    for attempt in &plan.attempts {
        fixture(attempt, true)?;
    }
    approve(&mut plan)?;
    let old = [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?];
    let cancel = Cancel(Cell::new(false));
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(
            &plan,
            TIMEOUT,
            |row| {
                if std::str::from_utf8(row)
                    .map_err(|_| OUTPUT)?
                    .contains("source_preflight_complete")
                {
                    cancel.0.set(true);
                }
                Ok(())
            },
            &cancel
        ),
        Err(AUTHORITY)
    );
    assert_eq!(
        old,
        [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?]
    );
    for attempt in &plan.attempts {
        assert!(!window_present(attempt)?);
    }
    Ok(())
}

#[test]
fn aliases_and_new_directories_after_preview_do_not_reuse_approval() -> Test {
    let directory = Directory::new()?;
    let mut plan = ReconnectPlan::parse(&args(&directory, "hevc"))?;
    approve(&mut plan)?;
    fixture(&plan.attempts[0], true)?;
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel),
        Err(APPROVAL)
    );
    let root = locate(&plan.attempts[0].root)?;
    assert_eq!(disjoint(&[root.clone(), root]), Err(ROOT));
    std::os::unix::fs::symlink(&plan.attempts[0].root, &plan.attempts[1].root)?;
    assert_eq!(locate(&plan.attempts[1].root), Err(ROOT));
    Ok(())
}

#[test]
fn recovery_parser_rejects_ambiguous_modes_and_preserves_capture_identity() -> Test {
    let directory = Directory::new()?;
    let input = args(&directory, "hevc");
    let recovery = ReconnectPlan::parse(&input)?;
    let capture: Vec<_> = input
        .as_chunks::<2>()
        .0
        .iter()
        .filter(|pair| pair[0] != "--recover")
        .flat_map(|pair| pair.iter().cloned())
        .collect();
    let plain = ReconnectPlan::parse(&capture)?;
    assert_eq!(plain.digest()?, recovery.digest()?);
    assert!(plain.recovery_timeout_ns.is_none());
    for value in ["no", "true", "1"] {
        let mut invalid = input.clone();
        set(&mut invalid, "--recover", value);
        assert!(ReconnectPlan::parse(&invalid).is_err());
    }
    for value in ["0", "-1", "3600001", "18446744073709551616"] {
        let mut invalid = input.clone();
        set(&mut invalid, "--recovery-timeout-ms", value);
        assert!(ReconnectPlan::parse(&invalid).is_err());
    }
    let mut invalid = capture;
    set(&mut invalid, "--recovery-timeout-ms", "1000");
    assert!(ReconnectPlan::parse(&invalid).is_err());
    Ok(())
}

#[path = "source_recovery_tests.rs"]
mod source_tests;
