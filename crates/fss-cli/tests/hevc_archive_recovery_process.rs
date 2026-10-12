#![forbid(unsafe_code)]
//! Separate executable invocations recover exact HEVC originals and syntax witnesses.
#[path = "../../fss-reference/tests/hevc_recording_support/mod.rs"]
mod source;

use fss_cli::ExitIdentity;
use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::archive_pins::{
    ArchivePinAnchor, ArchivePinLimits, ArchivePinScope, HevcArchivePinJournal,
};
use fss_reference::rtsp::recording::hevc::{PreparedHevcRecording, local::load_hevc_recording};
use fss_reference::rtsp::recording_archive::checkpoint::write_ahead::{
    CheckpointedArchiveProgress, CheckpointedHevcArchiveWriter,
};
use fss_reference::rtsp::recording_archive::checkpoint::{
    ArchiveWorkLimits, PreparedHevcArchiveWork, load_hevc_archive_work,
};
use fss_reference::rtsp::recording_archive::hevc::{
    HevcArchiveNamespace, HevcArchiveSnapshot, HevcRecordingArchiveWriter,
};
use fss_reference::rtsp::recording_archive::{ArchiveLimits, ArchiveWriteProgress};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn storage() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        128,
        1024,
        128,
        1024,
        SpoolLimits::new(1024, 64 * 1024 * 1024, 1024 * 1024, 1024),
    )
}
fn limits() -> ArchiveLimits {
    ArchiveLimits {
        max_windows: 8,
        max_pages: 8,
        max_scan_roots: 256,
        windows_per_page: 2,
    }
}
fn namespace() -> Test<HevcArchiveNamespace> {
    Ok(HevcArchiveNamespace::new(CatalogScope {
        recording: source::scope()?,
        decode_clock: ContentDigest::sha256(b"CLI HEVC recovery decode clock"),
        time_scale: 90_000,
    })?)
}
fn fresh(name: &str) -> Test<PathBuf> {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!(
            "hevc_archive_recovery_process-{}",
            std::process::id()
        ))
        .join(name);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    std::fs::create_dir_all(&path)?;
    Ok(path)
}
fn recording(second: bool) -> Test<PreparedHevcRecording> {
    let packets = source::packets()?;
    if second {
        source::prepare(&packets[5..], &source::timings(4)[2..])
    } else {
        let recording = source::prepare(&packets[..6], &source::timings(2))?;
        assert_eq!(recording.source_only_nals(), 1);
        Ok(recording)
    }
}
fn roots(path: &Path) -> Test<Vec<OsString>> {
    let mut names = std::fs::read_dir(path.join("roots"))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    Ok(names)
}
fn cold_window(publisher: &LocalRootPublisher, ordinal: usize, expected: ContentDigest) -> Test {
    let loaded = load_hevc_recording(
        publisher,
        &namespace()?.window_slot(ordinal)?,
        expected,
        &source::scope()?,
        &NeverCancel,
    )?;
    // The reopened recording is reconstructed only from native durable children. These
    // fixture objects are created afterwards, solely to compare exact source/derived bytes.
    let original = recording(ordinal != 0)?;
    assert_eq!(loaded.manifest().root(), original.manifest().root());
    assert_eq!(loaded.objects().source, original.objects().source);
    assert_eq!(loaded.objects().media, original.objects().media);
    assert_eq!(loaded.samples(), original.samples());
    assert_eq!(loaded.source_only_nals(), original.source_only_nals());
    assert_eq!(loaded.summary().samples, 2);
    Ok(())
}

struct WorkFixture {
    path: PathBuf,
    slot: String,
    root: ContentDigest,
    namespace: ContentDigest,
    window: ContentDigest,
}
fn work_fixture(name: &str, page_before_window: bool) -> Test<WorkFixture> {
    let path = fresh(name)?;
    let mut publisher = LocalRootPublisher::open(&path, storage())?;
    let namespace = namespace()?;
    let identity = namespace.digest();
    let mut writer = HevcRecordingArchiveWriter::open(
        &mut publisher,
        namespace,
        limits(),
        0,
        1000,
        &NeverCancel,
    )?;
    let window = recording(false)?;
    let bytes = window.byte_len();
    writer.offer(window, bytes, 1)?;
    if page_before_window {
        assert!(matches!(
            writer.step(2, &NeverCancel)?,
            ArchiveWriteProgress::WindowDurable { .. }
        ));
        writer.flush();
        for _ in 0..3 {
            writer.step(2, &NeverCancel)?;
        }
    }
    let mut work = writer.retire();
    if page_before_window {
        assert!(work.prepared_page.is_some());
        work.pending = Some(recording(true)?);
    }
    let window = work
        .pending
        .as_ref()
        .ok_or("pending HEVC window lost")?
        .manifest()
        .root();
    let plan = PreparedHevcArchiveWork::prepare(
        &work,
        &publisher,
        ArchiveWorkLimits::default(),
        &NeverCancel,
    )?;
    let slot = plan.slot().as_str().to_owned();
    let root = plan.root();
    plan.publish(&mut publisher, 3, 1000, &NeverCancel)?;
    // No fixture owner or prepared recording survives into the child process.
    Ok(WorkFixture {
        path,
        slot,
        root,
        namespace: identity,
        window,
    })
}
fn work_args(f: &WorkFixture, restore: bool, codec: Option<&str>) -> Vec<OsString> {
    let mut args = vec![
        if restore {
            "restore-work"
        } else {
            "inspect-work"
        }
        .into(),
        "--root".into(),
        f.path.clone().into_os_string(),
        "--work-slot".into(),
        f.slot.clone().into(),
        "--work-root".into(),
        f.root.to_text().into(),
        "--expected-namespace".into(),
        f.namespace.to_text().into(),
    ];
    if let Some(codec) = codec {
        args.extend(["--codec".into(), codec.into()]);
    }
    if restore {
        args.extend(["--commit".into(), "yes".into()]);
    }
    args
}

struct PinFixture {
    path: PathBuf,
    scope: ArchivePinScope,
    anchor: ArchivePinAnchor,
    work: ContentDigest,
    window: ContentDigest,
    source: ContentDigest,
}
fn pin_fixture(name: &str, durable: bool) -> Test<PinFixture> {
    let path = fresh(name)?;
    let scope = ArchivePinScope {
        journal_id: ContentDigest::sha256(b"CLI HEVC independent journal epoch"),
        archive_namespace: namespace()?.digest(),
    };
    let mut publisher = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = HevcArchivePinJournal::create(
        path.join("pins"),
        scope,
        ArchivePinLimits::default(),
        &NeverCancel,
    )?;
    let mut writer = CheckpointedHevcArchiveWriter::open(
        &mut publisher,
        namespace()?,
        limits(),
        ArchiveWorkLimits::default(),
        256,
        0,
        1000,
        &NeverCancel,
    )?;
    let window = recording(false)?;
    let root = window.manifest().root();
    let source = ContentDigest::sha256(window.objects().source);
    let bytes = window.byte_len();
    writer.offer(window, bytes, 0)?;
    let CheckpointedArchiveProgress::PinRequired(pin) = writer.step(0, &NeverCancel)? else {
        return Err("missing HEVC checkpoint candidate".into());
    };
    pins.persist_candidate(&pin, &NeverCancel)?;
    if durable {
        writer.acknowledge_checkpoint(&pin, 0, &NeverCancel)?;
        assert!(matches!(
            writer.step(0, &NeverCancel)?,
            CheckpointedArchiveProgress::WorkDurable { .. }
        ));
    }
    let _retired = writer.retire();
    Ok(PinFixture {
        path,
        scope,
        anchor: pins.anchor(),
        work: pin.root(),
        window: root,
        source,
    })
}
fn pin_args(f: &PinFixture, restore: bool, codec: Option<&str>) -> Vec<OsString> {
    let mut args = vec![
        if restore {
            "restore-pins"
        } else {
            "inspect-pins"
        }
        .into(),
        "--pin-root".into(),
        f.path.join("pins").into_os_string(),
        "--journal-id".into(),
        f.scope.journal_id.to_text().into(),
        "--expected-namespace".into(),
        f.scope.archive_namespace.to_text().into(),
    ];
    if let Some(codec) = codec {
        args.extend(["--codec".into(), codec.into()]);
    }
    if restore {
        args.extend([
            "--root".into(),
            f.path.join("media").into_os_string(),
            "--commit".into(),
            "yes".into(),
        ]);
    }
    args
}
fn run(args: Vec<OsString>) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-archive"))
        .args(args)
        .output()?)
}
fn success(output: Output) -> Test<String> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout)?;
    for field in [
        "\"codec\":\"hevc\"",
        "\"source_bytes_emitted\":false",
        "\"capture_complete\":false",
        "\"operation_complete\":true",
    ] {
        assert!(text.contains(field), "missing report field {field}");
    }
    assert!(text.len() <= 8192);
    Ok(text)
}
fn refused(output: Output, usage: bool) -> Test {
    assert_eq!(
        output.status.code(),
        Some(i32::from(if usage {
            ExitIdentity::MALFORMED_VALUE.code
        } else {
            ExitIdentity::RUNTIME_FAILURE.code
        })),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    Ok(())
}

// Concurrent test threads must not let a spawned child inherit another native owner's
// flock descriptor until exec, keeping that unrelated owner locked after its Rust drop.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn explicit_hevc_work_reopens_original_source_and_lost_reply_retries_exact_slot() -> Test {
    let _serial = serial();
    let f = work_fixture("work_retry", false)?;
    let before = roots(&f.path)?;
    for codec in [None, Some("avc")] {
        refused(run(work_args(&f, false, codec))?, false)?;
        assert_eq!(roots(&f.path)?, before);
    }
    let inspected = success(run(work_args(&f, false, Some("hevc")))?)?;
    assert!(inspected.contains("\"publication_requested\":false"));
    assert!(inspected.contains("\"durable_windows\":0"));
    assert_eq!(roots(&f.path)?, before);
    let mut command = work_args(&f, true, Some("hevc"));
    command.truncate(command.len() - 2);
    refused(run(command)?, true)?;
    assert_eq!(roots(&f.path)?, before);
    let command = work_args(&f, true, Some("hevc"));
    assert!(success(run(command.clone())?)?.contains("\"window_result\":\"published\""));
    let after = roots(&f.path)?;
    let retry = success(run(command)?)?;
    assert!(retry.contains("\"window_result\":\"already_durable\""));
    assert!(retry.contains("\"durable_windows\":1"));
    assert!(retry.contains("\"indexed_windows\":0"));
    assert!(retry.contains("\"indexing_remaining\":true"));
    assert_eq!(roots(&f.path)?, after);
    let publisher = LocalRootPublisher::open(&f.path, storage())?;
    let snapshot = HevcArchiveSnapshot::load(&publisher, namespace()?, limits(), &NeverCancel)?;
    assert_eq!(snapshot.windows().len(), 1);
    assert!(snapshot.pages().is_empty());
    assert_eq!(snapshot.windows()[0].root(), f.window);
    cold_window(&publisher, 0, f.window)
}

#[test]
fn interrupted_hevc_page_then_window_restoration_preserves_original_catalog_and_tail() -> Test {
    let _serial = serial();
    let f = work_fixture("page_then_window", true)?;
    let page_root = {
        let mut publisher = LocalRootPublisher::open(&f.path, storage())?;
        let work = load_hevc_archive_work(
            &publisher,
            &SlotName::parse(&f.slot)?,
            f.root,
            ArchiveWorkLimits::default(),
            &NeverCancel,
        )?;
        let page = work.prepared_page.as_ref().ok_or("HEVC page lost")?;
        // Simulate loss after the first original publication but before the waiting
        // window, retaining exactly the work pin the real process was authorized to use.
        publisher.stage_object(page.index_bytes())?;
        publisher.publish_cancellable(
            &work
                .snapshot
                .namespace()
                .page_slot(work.snapshot.indexed_windows())?,
            page.manifest(),
            &NeverCancel,
        )?;
        page.manifest().root()
    };
    let command = work_args(&f, true, Some("hevc"));
    let restored = success(run(command.clone())?)?;
    assert!(restored.contains("\"catalog_result\":\"already_durable\""));
    assert!(restored.contains("\"window_result\":\"published\""));
    let after = roots(&f.path)?;
    let retry = success(run(command)?)?;
    assert!(retry.contains("\"catalog_result\":\"already_durable\""));
    assert!(retry.contains("\"window_result\":\"already_durable\""));
    assert!(retry.contains("\"durable_windows\":2"));
    assert!(retry.contains("\"indexed_windows\":1"));
    assert!(retry.contains("\"indexing_remaining\":true"));
    assert_eq!(roots(&f.path)?, after);
    let publisher = LocalRootPublisher::open(&f.path, storage())?;
    let snapshot = HevcArchiveSnapshot::load(&publisher, namespace()?, limits(), &NeverCancel)?;
    assert_eq!(snapshot.windows().len(), 2);
    assert_eq!(snapshot.pages().len(), 1);
    assert_eq!(snapshot.pages()[0].catalog().manifest().root(), page_root);
    assert_eq!(snapshot.windows()[1].root(), f.window);
    for (ordinal, entry) in snapshot.windows().iter().enumerate() {
        cold_window(&publisher, ordinal, entry.root())?;
    }
    Ok(())
}

#[test]
fn independent_hevc_pins_inspect_offline_and_confirm_source_before_idempotent_restore() -> Test {
    let _serial = serial();
    let f = pin_fixture("pins_retry", true)?;
    let journal = f.path.join("pins/pins.journal");
    let before = std::fs::read(&journal)?;
    for codec in [None, Some("avc")] {
        refused(run(pin_args(&f, false, codec))?, false)?;
        refused(run(pin_args(&f, true, codec))?, false)?;
        assert_eq!(std::fs::read(&journal)?, before);
    }
    std::fs::rename(f.path.join("media"), f.path.join("offline-media"))?;
    let inspected = success(run(pin_args(&f, false, Some("hevc")))?)?;
    assert!(inspected.contains("\"work_custody\":\"not_checked\""));
    assert!(inspected.contains("\"last_confirmed\":null"));
    assert!(inspected.contains(&f.work.to_text()));
    assert_eq!(std::fs::read(&journal)?, before);
    std::fs::rename(f.path.join("offline-media"), f.path.join("media"))?;
    let mut command = pin_args(&f, true, Some("hevc"));
    command.extend([
        "--minimum-sequence".into(),
        f.anchor.sequence.to_string().into(),
        "--minimum-root".into(),
        ContentDigest::sha256(b"wrong minimum").to_text().into(),
    ]);
    refused(run(command.clone())?, false)?;
    assert_eq!(std::fs::read(&journal)?, before);
    *command.last_mut().ok_or("minimum root missing")? = f.anchor.root.to_text().into();
    let restored = success(run(command.clone())?)?;
    assert!(restored.contains("\"minimum_prefix_supplied\":true"));
    assert!(restored.contains("\"confirmation_recorded\":true"));
    assert!(restored.contains("\"outcome\":\"published\""));
    let confirmed = std::fs::read(&journal)?;
    let after = roots(&f.path.join("media"))?;
    let retry = success(run(command)?)?;
    assert!(retry.contains("\"confirmation_recorded\":false"));
    assert!(retry.contains("\"outcome\":\"already_durable\""));
    assert!(retry.contains("\"candidate\":null"));
    assert!(retry.contains("\"work_custody\":\"verified\""));
    assert!(retry.contains("\"durable_windows\":1"));
    assert!(retry.contains("\"indexed_windows\":0"));
    assert_eq!(std::fs::read(&journal)?, confirmed);
    assert_eq!(roots(&f.path.join("media"))?, after);
    let publisher = LocalRootPublisher::open(f.path.join("media"), storage())?;
    let mut pins = HevcArchivePinJournal::open_complete(
        f.path.join("pins"),
        f.scope,
        Some(f.anchor),
        ArchivePinLimits::default(),
        &NeverCancel,
    )?;
    pins.require_settled(&publisher, ArchiveWorkLimits::default(), &NeverCancel)?;
    cold_window(&publisher, 0, f.window)
}

#[test]
fn missing_or_corrupt_hevc_candidate_cannot_be_confirmed_or_published() -> Test {
    let _serial = serial();
    for corrupt in [false, true] {
        let f = pin_fixture(
            if corrupt {
                "corrupt_source"
            } else {
                "missing_work"
            },
            corrupt,
        )?;
        let journal = f.path.join("pins/pins.journal");
        let before = std::fs::read(&journal)?;
        let original_roots = roots(&f.path.join("media"))?;
        if corrupt {
            let digest = f.source.to_text();
            let source_path = f
                .path
                .join("media/spool/objects")
                .join(digest.strip_prefix("sha256:").ok_or("source hash")?);
            let mut bytes = std::fs::read(&source_path)?;
            *bytes.last_mut().ok_or("empty original source")? ^= 1;
            std::fs::write(source_path, bytes)?;
        }
        refused(run(pin_args(&f, true, Some("hevc")))?, false)?;
        assert_eq!(std::fs::read(&journal)?, before);
        assert_eq!(roots(&f.path.join("media"))?, original_roots);
        let inspected = success(run(pin_args(&f, false, Some("hevc")))?)?;
        assert!(inspected.contains("\"last_confirmed\":null"));
        assert!(inspected.contains(&f.work.to_text()));
        assert!(inspected.contains("\"work_custody\":\"not_checked\""));
    }
    Ok(())
}

#[test]
fn unsupported_or_duplicate_codec_is_rejected_before_opening_storage() -> Test {
    let _serial = serial();
    let path = fresh("codec_arguments")?.join("never-created");
    for command in [
        "inspect-work",
        "restore-work",
        "inspect-pins",
        "restore-pins",
    ] {
        for codec in ["auto", "h265", "HEVC"] {
            let output = run(vec![
                command.into(),
                "--codec".into(),
                codec.into(),
                if command.ends_with("work") {
                    "--root"
                } else {
                    "--pin-root"
                }
                .into(),
                path.clone().into_os_string(),
            ])?;
            refused(output, true)?;
            assert!(!path.exists());
        }
        refused(
            run(vec![
                command.into(),
                "--codec".into(),
                "hevc".into(),
                "--codec".into(),
                "avc".into(),
            ])?,
            true,
        )?;
    }
    Ok(())
}
