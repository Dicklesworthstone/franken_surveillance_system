#![forbid(unsafe_code)]
//! Native HEVC custody and independent journals, reopened after the former owner retired.
use super::*;
use fss_cli::json_input::{Value, parse};
use fss_reference::rtsp::archive_pins::{ArchivePinError, HevcArchivePinJournal};
use fss_reference::rtsp::recording::hevc::prepare_hevc_recording;
use fss_reference::rtsp::recording_archive::checkpoint::write_ahead::{
    CheckpointedArchiveProgress, CheckpointedHevcArchiveWriter,
};
use std::cell::Cell;
use std::ffi::OsString;
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
                "fss-index-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(fs::canonicalize(path)?)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("directory reservation exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn plan(directory: &Directory) -> Test<ReconnectPlan> {
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
        "sensor:index",
        "--stream-id",
        "stream:index",
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
        "--codec",
        "hevc",
        "--max-attempts",
        "2",
        "--recover",
        "index",
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
        directory.0.join("media").into_os_string(),
        "--pins".into(),
        directory.0.join("pins").into_os_string(),
    ]);
    Ok(ReconnectPlan::parse(&args)?)
}
fn approve(plan: &mut ReconnectPlan) -> Test<ContentDigest> {
    let value = parse(&plan.preview()?)?;
    let approval = value
        .object()
        .and_then(|v| v.get("approval"))
        .and_then(Value::text)
        .ok_or("approval")?;
    let approval = ContentDigest::parse(approval)?;
    plan.approve = Some(approval);
    Ok(approval)
}
fn fixture(options: &crate::plan::Options, settled: bool) -> Test<ContentDigest> {
    let mut publisher = LocalRootPublisher::open(&options.root, options.publication_limits())?;
    let mut pins = HevcArchivePinJournal::create(
        &options.pins,
        options.pin_scope(),
        options.pin_limits(),
        &NeverCancel,
    )?;
    let namespace =
        CodecArchiveNamespace::<HevcArchiveCodec>::new(options.catalog_scope().clone())?;
    let packets = source::packets()?;
    let recording = prepare_hevc_recording(
        options.recording_config().scope,
        &source::configuration()?,
        90_000,
        &source::timings(2),
        &source::borrowed(&packets[..6]),
    )?;
    let root = recording.manifest().root();
    let bytes = recording.byte_len();
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
    writer.offer(recording, bytes, 0)?;
    let CheckpointedArchiveProgress::PinRequired(pin) = writer.step(0, &NeverCancel)? else {
        return Err("pin".into());
    };
    pins.persist_candidate(&pin, &NeverCancel)?;
    writer.acknowledge_checkpoint(&pin, 0, &NeverCancel)?;
    assert!(matches!(
        writer.step(0, &NeverCancel)?,
        CheckpointedArchiveProgress::WorkDurable { .. }
    ));
    let _retained = writer.retire();
    if settled {
        let _restored =
            pins.restore_work(&mut publisher, options.work_limits(), 0, 1000, &NeverCancel)?;
    }
    Ok(root)
}
fn journal(options: &crate::plan::Options) -> Test<Vec<u8>> {
    Ok(fs::read(options.pins.join("pins.journal"))?)
}
fn snapshot(options: &crate::plan::Options) -> Test<CodecArchiveSnapshot<HevcArchiveCodec>> {
    let publisher = LocalRootPublisher::open(&options.root, options.publication_limits())?;
    Ok(CodecArchiveSnapshot::load(
        &publisher,
        CodecArchiveNamespace::new(options.catalog_scope().clone())?,
        options.work_limits().archive,
        &NeverCancel,
    )?)
}
fn run(plan: &ReconnectPlan) -> Test<String> {
    let mut rows = Vec::new();
    execute_codec::<HevcArchiveCodec>(
        plan,
        TIMEOUT,
        |bytes| {
            rows.extend_from_slice(bytes);
            Ok(())
        },
        &NeverCancel,
    )?;
    Ok(String::from_utf8(rows)?)
}
#[test]
fn recovered_epochs_gain_importable_catalogs_and_repeated_indexing_is_read_only() -> Test {
    let directory = Directory::new()?;
    let mut plan = plan(&directory)?;
    let first = fixture(&plan.attempts[0], true)?;
    let second = fixture(&plan.attempts[1], true)?;
    let before = [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?];
    let old = approve(&mut plan)?;
    assert_eq!(
        before,
        [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?]
    );
    let rows = run(&plan)?;
    assert!(rows.contains("\"catalogs_published\":2"));
    assert_eq!(rows.matches("\"index_complete\":true").count(), 2);
    assert!(rows.contains("\"continuity_across_attempts\":false"));
    for (attempt, root) in plan.attempts.iter().zip([first, second]) {
        let recovered = snapshot(attempt)?;
        assert_eq!(recovered.windows().len(), 1);
        assert_eq!(recovered.windows()[0].root(), root);
        assert_eq!(recovered.indexed_windows(), 1);
        assert_eq!(recovered.pages().len(), 1);
        assert!(rows.contains(recovered.pages()[0].slot().as_str()));
        assert!(
            rows.contains(
                &HevcArchiveCodec::manifest(recovered.pages()[0].catalog())
                    .root()
                    .to_text()
            )
        );
    }
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel),
        Err(APPROVAL)
    );
    assert_ne!(approve(&mut plan)?, old);
    let before = [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?];
    let rows = run(&plan)?;
    assert!(rows.contains("\"catalogs_published\":0"));
    assert_eq!(rows.matches("\"catalogs\":[{\"slot\":").count(), 2);
    assert_eq!(
        before,
        [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?]
    );
    Ok(())
}
#[test]
fn outstanding_candidate_is_not_implicitly_restored_by_index_approval() -> Test {
    let directory = Directory::new()?;
    let mut plan = plan(&directory)?;
    fixture(&plan.attempts[0], false)?;
    let old = journal(&plan.attempts[0])?;
    assert!(plan.preview().is_err());
    assert_eq!(old, journal(&plan.attempts[0])?);
    plan.index_catalogs = false;
    approve(&mut plan)?;
    super::super::execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel)?;
    plan.index_catalogs = true;
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel),
        Err(APPROVAL)
    );
    approve(&mut plan)?;
    run(&plan)?;
    assert_eq!(snapshot(&plan.attempts[0])?.indexed_windows(), 1);
    Ok(())
}
#[test]
fn lost_confirmed_work_output_stops_other_epochs_and_the_existing_recovery_completes_it() -> Test {
    let directory = Directory::new()?;
    let mut plan = plan(&directory)?;
    for attempt in &plan.attempts {
        fixture(attempt, true)?;
    }
    approve(&mut plan)?;
    let second = journal(&plan.attempts[1])?;
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(
            &plan,
            TIMEOUT,
            |row| {
                if std::str::from_utf8(row)
                    .map_err(|_| OUTPUT)?
                    .contains("index_work_confirmed")
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
    assert_eq!(journal(&plan.attempts[1])?, second);
    assert_eq!(snapshot(&plan.attempts[0])?.pages().len(), 0);
    assert!(plan.preview().is_err());
    plan.index_catalogs = false;
    approve(&mut plan)?;
    super::super::execute_codec::<HevcArchiveCodec>(&plan, TIMEOUT, |_| Ok(()), &NeverCancel)?;
    assert_eq!(snapshot(&plan.attempts[0])?.pages().len(), 1);
    plan.index_catalogs = true;
    approve(&mut plan)?;
    assert!(run(&plan)?.contains("\"catalogs_published\":1"));
    for attempt in &plan.attempts {
        assert_eq!(snapshot(attempt)?.pages().len(), 1);
    }
    Ok(())
}
#[test]
fn all_stores_stay_locked_and_cancellation_before_publication_preserves_both_journals() -> Test {
    struct Cancel(Cell<bool>);
    impl PublishCancellation for Cancel {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            self.0.get()
        }
    }
    let directory = Directory::new()?;
    let mut plan = plan(&directory)?;
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
            |_| {
                for attempt in &plan.attempts {
                    assert!(
                        LocalRootPublisher::open(&attempt.root, attempt.publication_limits())
                            .is_err()
                    );
                    assert!(matches!(
                        HevcArchivePinJournal::open_complete(
                            &attempt.pins,
                            attempt.pin_scope(),
                            None,
                            attempt.pin_limits(),
                            &NeverCancel
                        ),
                        Err(ArchivePinError::Busy)
                    ));
                }
                cancel.0.set(true);
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
        assert_eq!(snapshot(attempt)?.pages().len(), 0);
    }
    Ok(())
}
#[test]
fn damaged_later_source_refuses_before_any_index_confirmation_or_output() -> Test {
    let directory = Directory::new()?;
    let mut plan = plan(&directory)?;
    for attempt in &plan.attempts {
        fixture(attempt, true)?;
    }
    approve(&mut plan)?;
    let old = [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?];
    let attempt = &plan.attempts[1];
    let summary = snapshot(attempt)?;
    let publisher = LocalRootPublisher::open(&attempt.root, attempt.publication_limits())?;
    let recording = HevcArchiveCodec::load_recording(
        &publisher,
        summary.windows()[0].slot(),
        summary.windows()[0].root(),
        &attempt.catalog_scope().recording,
        &NeverCancel,
    )?;
    let digest =
        ContentDigest::sha256(HevcArchiveCodec::plan(&recording).objects().source).to_text();
    drop(publisher);
    let path = attempt
        .root
        .join("spool/objects")
        .join(digest.strip_prefix("sha256:").ok_or("digest")?);
    let mut bytes = fs::read(&path)?;
    *bytes.last_mut().ok_or("source envelope")? ^= 1;
    fs::write(&path, &bytes)?;
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
        Err(STORAGE)
    );
    assert!(!emitted);
    assert_eq!(
        old,
        [journal(&plan.attempts[0])?, journal(&plan.attempts[1])?]
    );
    assert_eq!(snapshot(&plan.attempts[0])?.pages().len(), 0);
    assert_eq!(fs::read(path)?, bytes);
    Ok(())
}
#[test]
fn native_command_budget_is_quoted_before_publication_and_not_replenished() -> Test {
    let directory = Directory::new()?;
    let mut plan = plan(&directory)?;
    fixture(&plan.attempts[0], true)?;
    let old = journal(&plan.attempts[0])?;
    plan.attempts[0].max_steps = 9;
    assert_eq!(plan.preview(), Err(WORK));
    assert_eq!(old, journal(&plan.attempts[0])?);
    plan.attempts[0].max_steps = 10;
    approve(&mut plan)?;
    assert!(run(&plan)?.contains("\"catalogs_published\":1"));
    assert_eq!(snapshot(&plan.attempts[0])?.indexed_windows(), 1);
    Ok(())
}
#[test]
fn lost_complete_attempt_output_never_indexes_the_next_attempt_and_retry_is_exact() -> Test {
    let directory = Directory::new()?;
    let mut plan = plan(&directory)?;
    for attempt in &plan.attempts {
        fixture(attempt, true)?;
    }
    approve(&mut plan)?;
    let second = journal(&plan.attempts[1])?;
    assert_eq!(
        execute_codec::<HevcArchiveCodec>(
            &plan,
            TIMEOUT,
            |row| {
                if std::str::from_utf8(row)
                    .map_err(|_| OUTPUT)?
                    .contains("\"kind\":\"attempt_index\"")
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
    let first = snapshot(&plan.attempts[0])?;
    let root = HevcArchiveCodec::manifest(first.pages()[0].catalog()).root();
    assert_eq!(snapshot(&plan.attempts[1])?.pages().len(), 0);
    assert_eq!(journal(&plan.attempts[1])?, second);
    approve(&mut plan)?;
    assert!(run(&plan)?.contains("\"catalogs_published\":1"));
    let first = snapshot(&plan.attempts[0])?;
    assert_eq!(first.pages().len(), 1);
    assert_eq!(
        HevcArchiveCodec::manifest(first.pages()[0].catalog()).root(),
        root
    );
    Ok(())
}
