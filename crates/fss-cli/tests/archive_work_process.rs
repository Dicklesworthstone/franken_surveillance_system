#![forbid(unsafe_code)]
//! Separate executable invocations restore checkpointed source, not shared Rust objects.
#[path = "../../fss-reference/tests/collector_support/mod.rs"]
mod source;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use fss_cli::ExitIdentity;
use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::recording_archive::{ArchiveLimits, ArchiveNamespace, ArchiveSnapshot, ArchiveWriteProgress, RecordingArchiveWriter};
use fss_reference::rtsp::recording_archive::checkpoint::{ArchiveWorkLimits, PreparedArchiveWork, load_archive_work};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_collector::{CollectorAdmission, CollectorLimits};

type Test = Result<(), Box<dyn std::error::Error>>;
fn storage() -> LocalPublicationLimits {
    LocalPublicationLimits::new(128, 1024, 128, 1024, SpoolLimits::new(1024, 16 * 1024 * 1024, 1024 * 1024, 1024))
}
fn limits() -> ArchiveLimits { ArchiveLimits { max_windows: 8, max_pages: 8, max_scan_roots: 256, windows_per_page: 2 } }
fn namespace() -> Result<ArchiveNamespace, Box<dyn std::error::Error>> {
    Ok(ArchiveNamespace::new(CatalogScope { recording: source::scope()?,
        decode_clock: ContentDigest::sha256(b"CLI work decode clock"), time_scale: 90_000 })?)
}
struct Fixture { path: PathBuf, slot: String, work: ContentDigest, namespace: ContentDigest, window: ContentDigest }
fn recording(at: u64) -> Result<fss_reference::rtsp::recording::PreparedRecording, Box<dyn std::error::Error>> {
    let mut collector = source::collector(CollectorLimits::default())?;
    let sample = source::sample(2, 9000, true, true)?;
    sample.source(&mut collector, 1)?;
    assert!(matches!(collector.push_picture(sample.timed(at), 1), CollectorAdmission::Accepted { .. }));
    assert!(collector.seal(2)?);
    Ok(collector.take_ready().ok_or("fixture did not seal")?)
}
fn fixture(name: &str) -> Result<Fixture, Box<dyn std::error::Error>> { fixture_kind(name, false) }
fn fixture_kind(name: &str, older_page: bool) -> Result<Fixture, Box<dyn std::error::Error>> {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("archive_work_process").join(name);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}, Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}, Err(e) => return Err(e.into()),
    }
    let window = recording(0)?;
    let bytes = window.byte_len();
    let mut p = LocalRootPublisher::open(&path, storage())?;
    let namespace = namespace()?; let identity = namespace.digest();
    let mut writer = RecordingArchiveWriter::open(&mut p, namespace, limits(), 0, 1000, &NeverCancel)?;
    writer.offer(window, bytes, 1)?;
    if older_page {
        assert!(matches!(writer.step(2, &NeverCancel)?, ArchiveWriteProgress::WindowDurable { .. }));
        writer.flush();
        for _ in 0..3 { writer.step(2, &NeverCancel)?; }
    }
    let mut work = writer.retire();
    if older_page {
        assert!(work.prepared_page.is_some());
        work.pending = Some(recording(3600)?);
    }
    let window_root = work.pending.as_ref().ok_or("pending window lost")?.manifest().root();
    let plan = PreparedArchiveWork::prepare(&work, &p, ArchiveWorkLimits::default(), &NeverCancel)?;
    let slot = plan.slot().as_str().to_owned(); let root = plan.root();
    plan.publish(&mut p, 3, 1000, &NeverCancel)?;
    Ok(Fixture { path, slot, work: root, namespace: identity, window: window_root })
}
fn args(f: &Fixture, command: &str) -> Vec<OsString> {
    vec![command.into(), "--root".into(), f.path.as_os_str().to_owned(),
        "--work-slot".into(), f.slot.clone().into(), "--work-root".into(), f.work.to_text().into(),
        "--expected-namespace".into(), f.namespace.to_text().into()]
}
fn run(args: Vec<OsString>) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-archive")).args(args).output()?)
}
fn success(output: Output) -> Result<String, Box<dyn std::error::Error>> {
    assert!(output.status.success(), "operator command failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("\"source_bytes_emitted\":false"));
    assert!(text.contains("\"capture_complete\":false"));
    assert!(text.contains("\"operation_complete\":true"));
    assert!(text.len() <= 4096);
    Ok(text)
}

/// Serializes this binary's tests. Every test holds native flock owner locks in this process and
/// spawns real CLI processes. A child spawned by a concurrent test thread inherits, until its exec
/// closes it, every descriptor open at that instant, including another test's held owner lock; the
/// flock then outlives its owner's drop, and that test's next open or child sees Locked/Busy.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
#[test]
fn new_process_inspection_verifies_work_without_publishing_an_archive_window() -> Test {
    let _serial = serial();
    let f = fixture("inspect")?;
    let text = success(run(args(&f, "inspect-work"))?)?;
    assert!(text.contains("\"publication_requested\":false"));
    assert!(text.contains("\"durable_windows\":0"));
    let p = LocalRootPublisher::open(&f.path, storage())?;
    assert!(ArchiveSnapshot::load(&p, namespace()?, limits(), &NeverCancel)?.windows().is_empty());
    Ok(())
}

#[test]
fn restore_survives_lost_stdout_ack_and_repeated_process_invocation() -> Test {
    let _serial = serial();
    let f = fixture("restore")?;
    let mut command = args(&f, "restore-work"); command.extend(["--commit".into(), "yes".into()]);
    let first = success(run(command.clone())?)?;
    assert!(first.contains("\"window_result\":\"published\""));
    // Discard the first command's result; only the original preexisting independent pin remains.
    drop(first);
    let repeated = success(run(command)?)?;
    assert!(repeated.contains("\"window_result\":\"already_durable\""));
    assert!(repeated.contains("\"durable_windows\":1"));
    // No extra catalog root was authorized by the work pin. Do not claim it was indexed.
    assert!(repeated.contains("\"indexed_windows\":0"));
    assert!(repeated.contains("\"indexing_remaining\":true"));
    let p = LocalRootPublisher::open(&f.path, storage())?;
    let snapshot = ArchiveSnapshot::load(&p, namespace()?, limits(), &NeverCancel)?;
    assert_eq!(snapshot.windows().len(), 1);
    assert_eq!(snapshot.windows()[0].root(), f.window);
    Ok(())
}

#[test]
fn mutation_requires_explicit_commit_and_read_command_refuses_mutation_flags() -> Test {
    let _serial = serial();
    let f = fixture("commit")?;
    let missing = run(args(&f, "restore-work"))?;
    assert_eq!(missing.status.code(), Some(i32::from(ExitIdentity::MALFORMED_VALUE.code)));
    assert!(missing.stdout.is_empty());
    let mut inspect = args(&f, "inspect-work"); inspect.extend(["--commit".into(), "yes".into()]);
    let wrong = run(inspect)?;
    assert_eq!(wrong.status.code(), Some(i32::from(ExitIdentity::MALFORMED_VALUE.code)));
    assert!(wrong.stdout.is_empty());
    let p = LocalRootPublisher::open(&f.path, storage())?;
    assert!(ArchiveSnapshot::load(&p, namespace()?, limits(), &NeverCancel)?.windows().is_empty());
    Ok(())
}

#[test]
fn wrong_namespace_and_tighter_bounds_fail_before_any_normal_publication() -> Test {
    let _serial = serial();
    let f = fixture("scope")?;
    let mut command = args(&f, "restore-work");
    *command.last_mut().ok_or("namespace missing")? = ContentDigest::sha256(b"other archive").to_text().into();
    command.extend(["--commit".into(), "yes".into()]);
    let denied = run(command)?; assert!(!denied.status.success()); assert!(denied.stdout.is_empty());
    let mut bound = args(&f, "restore-work");
    bound.extend(["--commit".into(), "yes".into(), "--max-pending-bytes".into(), "0".into()]);
    let denied = run(bound)?; assert!(!denied.status.success()); assert!(denied.stdout.is_empty());
    let p = LocalRootPublisher::open(&f.path, storage())?;
    assert!(ArchiveSnapshot::load(&p, namespace()?, limits(), &NeverCancel)?.windows().is_empty());
    Ok(())
}

#[test]
fn missing_archive_is_not_created_and_unknown_values_are_not_echoed() -> Test {
    let _serial = serial();
    let missing = Path::new(env!("CARGO_TARGET_TMPDIR")).join("archive_work_process-missing-owner");
    assert!(!missing.exists());
    let digest = ContentDigest::sha256(b"nonsecret pin");
    let f = Fixture { path: missing.clone(), slot: "work".to_owned(), work: digest, namespace: digest, window: digest };
    let out = run(args(&f, "inspect-work"))?;
    assert!(!out.status.success()); assert!(out.stdout.is_empty()); assert!(!missing.exists());
    let out = run(vec!["restore-work".into(), "--password".into(), "PRIVATE_SENTINEL_DO_NOT_ECHO".into()])?;
    assert_eq!(out.status.code(), Some(i32::from(ExitIdentity::MALFORMED_VALUE.code)));
    assert!(out.stdout.is_empty());
    assert!(!String::from_utf8(out.stderr)?.contains("PRIVATE_SENTINEL_DO_NOT_ECHO"));
    Ok(())
}

#[test]
fn help_and_duplicate_or_malformed_values_have_no_storage_side_effects() -> Test {
    let _serial = serial();
    let output = run(vec!["help".into()])?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("inspect-work|restore-work"));
    assert!(text.contains("--commit yes"));
    let f = fixture("arguments")?;
    for extra in [vec!["--work-slot", "other"], vec!["--timeout-ms", "-1"], vec!["--max-graph-objects", "99999999"],
        vec!["--timeout-ms"], vec!["--network", "yes"]] {
        let mut command = args(&f, "inspect-work"); command.extend(extra.into_iter().map(OsString::from));
        let out = run(command)?;
        assert_eq!(out.status.code(), Some(i32::from(ExitIdentity::MALFORMED_VALUE.code)));
        assert!(out.stdout.is_empty());
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_root_is_not_followed_by_recovery_commands() -> Test {
    let _serial = serial();
    let f = fixture("symlink")?;
    let alias = f.path.with_extension("alias");
    if alias.exists() { std::fs::remove_file(&alias)?; }
    std::os::unix::fs::symlink(&f.path, &alias)?;
    let mut command = args(&f, "inspect-work"); command[2] = alias.as_os_str().to_owned();
    let output = run(command)?;
    assert!(!output.status.success()); assert!(output.stdout.is_empty());
    std::fs::remove_file(alias)?;
    Ok(())
}

#[test]
fn interrupted_page_then_window_restore_keeps_original_pin_and_does_not_reindex() -> Test {
    let _serial = serial();
    let f = fixture_kind("older_page", true)?;
    let page_root = {
        let mut p = LocalRootPublisher::open(&f.path, storage())?;
        let work = load_archive_work(&p, &SlotName::parse(&f.slot)?, f.work,
            ArchiveWorkLimits::default(), &NeverCancel)?;
        let page = work.prepared_page.as_ref().ok_or("missing original page")?;
        let root = page.manifest().root();
        // Simulate process loss between the two independently durable publications. Only
        // the original work pin survives; no fabricated new checkpoint or page is used.
        p.stage_object(page.index_bytes())?;
        p.publish_cancellable(&work.snapshot.namespace().page_slot(work.snapshot.indexed_windows())?,
            page.manifest(), &NeverCancel)?;
        root
    };
    let mut command = args(&f, "restore-work"); command.extend(["--commit".into(), "yes".into()]);
    let first = success(run(command.clone())?)?;
    assert!(first.contains("\"catalog_result\":\"already_durable\""));
    assert!(first.contains("\"window_result\":\"published\""));
    let retry = success(run(command)?)?;
    assert!(retry.contains("\"catalog_result\":\"already_durable\""));
    assert!(retry.contains("\"window_result\":\"already_durable\""));
    assert!(retry.contains("\"durable_windows\":2"));
    assert!(retry.contains("\"indexed_windows\":1"));
    assert!(retry.contains("\"indexing_remaining\":true"));
    let p = LocalRootPublisher::open(&f.path, storage())?;
    let snapshot = ArchiveSnapshot::load(&p, namespace()?, limits(), &NeverCancel)?;
    assert_eq!(snapshot.pages().len(), 1);
    assert_eq!(snapshot.pages()[0].catalog().manifest().root(), page_root);
    assert_eq!(snapshot.windows()[1].root(), f.window);
    Ok(())
}
