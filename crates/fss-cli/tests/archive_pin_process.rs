#![forbid(unsafe_code)]
//! Real separate-process operator recovery, not shared memory or replacement persistence.
#[path = "../../fss-reference/tests/collector_support/mod.rs"]
mod source;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use fss_cli::ExitIdentity;
use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::archive_pins::{ArchivePinAnchor, ArchivePinJournal, ArchivePinLimits, ArchivePinScope};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording_archive::{ArchiveLimits, ArchiveNamespace, ArchiveSnapshot};
use fss_reference::rtsp::recording_archive::checkpoint::ArchiveWorkLimits;
use fss_reference::rtsp::recording_archive::checkpoint::write_ahead::{CheckpointedArchiveProgress, CheckpointedArchiveWriter};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_collector::{CollectorAdmission, CollectorLimits};
type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn storage() -> LocalPublicationLimits {
    LocalPublicationLimits::new(128, 1024, 128, 1024, SpoolLimits::new(1024, 16 * 1024 * 1024, 1024 * 1024, 1024))
}
fn limits() -> ArchiveLimits { ArchiveLimits { max_windows: 8, max_pages: 8, max_scan_roots: 256, windows_per_page: 2 } }
fn namespace() -> Test<ArchiveNamespace> {
    Ok(ArchiveNamespace::new(CatalogScope { recording: source::scope()?,
        decode_clock: ContentDigest::sha256(b"CLI pin decode clock"), time_scale: 90_000 })?)
}
fn recording() -> Test<PreparedRecording> {
    let mut collector = source::collector(CollectorLimits::default())?;
    let sample = source::sample(2, 9000, true, true)?;
    sample.source(&mut collector, 1)?;
    assert!(matches!(collector.push_picture(sample.timed(0), 1), CollectorAdmission::Accepted { .. }));
    assert!(collector.seal(2)?);
    Ok(collector.take_ready().ok_or("fixture failed to seal")?)
}
fn fresh(name: &str) -> Test<PathBuf> {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("archive_pin_process").join(name);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}, Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}, Err(e) => return Err(e.into()),
    }
    std::fs::create_dir_all(&path)?;
    Ok(path)
}
struct Fixture { path: PathBuf, scope: ArchivePinScope, anchor: ArchivePinAnchor, work: ContentDigest, window: ContentDigest, source: ContentDigest }
fn fixture(name: &str, durable: bool) -> Test<Fixture> {
    let path = fresh(name)?;
    let scope = ArchivePinScope { journal_id: ContentDigest::sha256(b"CLI independently accepted journal epoch"),
        archive_namespace: namespace()?.digest() };
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = ArchivePinJournal::create(path.join("pins"), scope, ArchivePinLimits::default(), &NeverCancel)?;
    let mut writer = CheckpointedArchiveWriter::open(&mut p, namespace()?, limits(), ArchiveWorkLimits::default(), 256, 0, 1000, &NeverCancel)?;
    let window = recording()?; let root = window.manifest().root(); let source = window.children()[0].1; let bytes = window.byte_len();
    writer.offer(window, bytes, 0)?;
    let CheckpointedArchiveProgress::PinRequired(pin) = writer.step(0, &NeverCancel)? else { return Err("missing pin".into()); };
    pins.persist_candidate(&pin, &NeverCancel)?;
    if durable {
        writer.acknowledge_checkpoint(&pin, 0, &NeverCancel)?;
        assert!(matches!(writer.step(0, &NeverCancel)?, CheckpointedArchiveProgress::WorkDurable { .. }));
    }
    // Deliberately lose the work receipt and every in-memory recording; only disks remain.
    let _retired = writer.retire();
    Ok(Fixture { path, scope, anchor: pins.anchor(), work: pin.root(), window: root, source })
}
fn args(f: &Fixture, restore: bool) -> Vec<OsString> {
    let mut args = vec![if restore { "restore-pins" } else { "inspect-pins" }.into(),
        "--pin-root".into(), f.path.join("pins").into_os_string(),
        "--journal-id".into(), f.scope.journal_id.to_text().into(),
        "--expected-namespace".into(), f.scope.archive_namespace.to_text().into()];
    if restore { args.extend(["--root".into(), f.path.join("media").into_os_string(), "--commit".into(), "yes".into()]); }
    args
}
fn run(args: Vec<OsString>) -> Test<Output> { Ok(Command::new(env!("CARGO_BIN_EXE_fss-archive")).args(args).output()?) }
fn success(output: Output) -> Test<String> {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stderr.is_empty()); let text = String::from_utf8(output.stdout)?;
    for field in ["\"operation_complete\":true", "\"capture_complete\":false", "\"source_bytes_emitted\":false"] {
        assert!(text.contains(field));
    }
    assert!(text.len() <= 8192); Ok(text)
}
fn refused(output: Output, usage: bool) -> Test {
    assert_eq!(output.status.code(), Some(i32::from(if usage { ExitIdentity::MALFORMED_VALUE.code } else { ExitIdentity::RUNTIME_FAILURE.code })));
    assert!(output.stdout.is_empty()); assert!(!output.stderr.is_empty()); Ok(())
}
fn unchanged(f: &Fixture, original: &[u8]) -> Test {
    assert_eq!(std::fs::read(f.path.join("pins/pins.journal"))?, original);
    let p = LocalRootPublisher::open(f.path.join("media"), storage())?;
    assert!(p.root(&namespace()?.window_slot(0)?).is_none()); Ok(())
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
fn inspection_needs_no_media_owner_and_does_not_claim_current_custody() -> Test {
    let _serial = serial();
    let f = fixture("inspect", true)?;
    std::fs::rename(f.path.join("media"), f.path.join("offline-media"))?;
    let before = std::fs::read(f.path.join("pins/pins.journal"))?;
    let text = success(run(args(&f, false))?)?;
    assert!(text.contains(&f.work.to_text())); assert!(text.contains("\"last_confirmed\":null"));
    assert!(text.contains("\"work_custody\":\"not_checked\""));
    assert!(text.contains("\"publication_requested\":false"));
    assert_eq!(std::fs::read(f.path.join("pins/pins.journal"))?, before); Ok(())
}
#[test]
fn new_process_restores_candidate_and_survives_lost_stdout_without_duplicate_roots() -> Test {
    let _serial = serial();
    let f = fixture("restore", true)?;
    let first = success(run(args(&f, true))?)?;
    assert!(first.contains("\"confirmation_recorded\":true")); assert!(first.contains("\"outcome\":\"published\""));
    drop(first);
    let before = std::fs::read(f.path.join("pins/pins.journal"))?;
    let repeated = success(run(args(&f, true))?)?;
    assert!(repeated.contains("\"confirmation_recorded\":false")); assert!(repeated.contains("\"outcome\":\"already_durable\""));
    assert!(repeated.contains("\"candidate\":null")); assert!(repeated.contains("\"durable_windows\":1"));
    assert!(repeated.contains("\"indexed_windows\":0")); assert!(repeated.contains("\"indexing_remaining\":true"));
    assert_eq!(std::fs::read(f.path.join("pins/pins.journal"))?, before);
    let p = LocalRootPublisher::open(f.path.join("media"), storage())?;
    let mut pins = ArchivePinJournal::open_complete(f.path.join("pins"), f.scope, Some(f.anchor), ArchivePinLimits::default(), &NeverCancel)?;
    pins.require_settled(&p, ArchiveWorkLimits::default(), &NeverCancel)?;
    let snapshot = ArchiveSnapshot::load(&p, namespace()?, limits(), &NeverCancel)?;
    assert_eq!(snapshot.windows().len(), 1); assert_eq!(snapshot.windows()[0].root(), f.window); Ok(())
}
#[test]
fn missing_candidate_source_is_never_discarded_or_replaced_by_a_success_report() -> Test {
    let _serial = serial();
    let f = fixture("missing_work", false)?; let before = std::fs::read(f.path.join("pins/pins.journal"))?;
    refused(run(args(&f, true))?, false)?; unchanged(&f, &before)?;
    let text = success(run(args(&f, false))?)?; assert!(text.contains(&f.work.to_text())); Ok(())
}
#[test]
fn commit_consent_is_required_and_inspection_rejects_mutating_options() -> Test {
    let _serial = serial();
    let f = fixture("consent", true)?; let before = std::fs::read(f.path.join("pins/pins.journal"))?;
    let mut no_commit = args(&f, true); no_commit.truncate(no_commit.len() - 2);
    refused(run(no_commit)?, true)?;
    let mut inspect = args(&f, false); inspect.extend(["--commit".into(), "yes".into()]);
    refused(run(inspect)?, true)?; unchanged(&f, &before)
}
#[test]
fn minimum_prefix_and_external_limits_refuse_before_confirmation_or_publication() -> Test {
    let _serial = serial();
    let f = fixture("prefix", true)?; let before = std::fs::read(f.path.join("pins/pins.journal"))?;
    let mut wrong = args(&f, true);
    wrong.extend(["--minimum-sequence".into(), f.anchor.sequence.to_string().into(),
        "--minimum-root".into(), ContentDigest::sha256(b"other journal prefix").to_text().into()]);
    refused(run(wrong)?, false)?; unchanged(&f, &before)?;
    for (key, value) in [("--max-pin-records", "1"), ("--max-pin-bytes", "128"), ("--max-pending-bytes", "0"), ("--max-new-bytes", "0")] {
        let mut bounded = args(&f, true); bounded.extend([key.into(), value.into()]);
        refused(run(bounded)?, false)?; unchanged(&f, &before)?;
    }
    let mut valid = args(&f, true);
    valid.extend(["--minimum-sequence".into(), f.anchor.sequence.to_string().into(), "--minimum-root".into(), f.anchor.root.to_text().into()]);
    assert!(success(run(valid)?)?.contains("\"minimum_prefix_supplied\":true")); Ok(())
}
#[test]
fn torn_and_corrupt_journals_are_refused_without_implicit_repair() -> Test {
    let _serial = serial();
    for corrupt in [false, true] {
        let f = fixture(if corrupt { "corrupt" } else { "torn" }, true)?;
        let file = f.path.join("pins/pins.journal"); let mut bytes = std::fs::read(&file)?;
        if corrupt { bytes[90] ^= 1; } else { bytes.truncate(bytes.len() - 10); }
        std::fs::write(&file, &bytes)?;
        refused(run(args(&f, false))?, false)?; refused(run(args(&f, true))?, false)?;
        unchanged(&f, &bytes)?;
    }
    Ok(())
}
#[test]
fn separate_process_cannot_bypass_an_existing_native_journal_lock() -> Test {
    let _serial = serial();
    let f = fixture("locked", true)?;
    let guard = ArchivePinJournal::open_complete(f.path.join("pins"), f.scope, None, ArchivePinLimits::default(), &NeverCancel)?;
    refused(run(args(&f, false))?, false)?;
    drop(guard); success(run(args(&f, false))?)?; Ok(())
}
#[test]
fn corrupt_original_source_cannot_create_a_confirmation_or_normal_archive_window() -> Test {
    let _serial = serial();
    let f = fixture("corrupt_source", true)?;
    let before = std::fs::read(f.path.join("pins/pins.journal"))?;
    let text = f.source.to_text(); let source = f.path.join("media/spool/objects").join(text.strip_prefix("sha256:").ok_or("digest")?);
    let mut bytes = std::fs::read(&source)?; *bytes.last_mut().ok_or("empty source")? ^= 1; std::fs::write(source, bytes)?;
    refused(run(args(&f, true))?, false)?;
    assert_eq!(std::fs::read(f.path.join("pins/pins.journal"))?, before); Ok(())
}
#[test]
fn malformed_arguments_never_echo_values_or_create_storage() -> Test {
    let _serial = serial();
    let f = fixture("arguments", true)?; let before = std::fs::read(f.path.join("pins/pins.journal"))?;
    for extra in [vec!["--pin-root", "OTHER"], vec!["--minimum-sequence", "2"], vec!["--minimum-root", "sha256:bad"],
        vec!["--timeout-ms", "-1"], vec!["--timeout-ms"], vec!["--max-pin-bytes", "99999999999999"]] {
        let mut command = args(&f, false); command.extend(extra.into_iter().map(OsString::from));
        refused(run(command)?, true)?; unchanged(&f, &before)?;
    }
    let output = run(vec!["restore-pins".into(), "--password".into(), "PRIVATE_SENTINEL_DO_NOT_ECHO".into()])?;
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_SENTINEL_DO_NOT_ECHO")); refused(output, true)?;
    let missing = f.path.join("missing"); let mut command = args(&f, false); command[2] = missing.clone().into_os_string();
    refused(run(command)?, false)?; assert!(!missing.exists()); Ok(())
}
#[test]
fn help_exposes_explicit_reference_and_mutation_boundaries() -> Test {
    let _serial = serial();
    for command in [vec!["help".into()], vec!["inspect-pins".into(), "--help".into()], vec!["restore-pins".into(), "--help".into()]] {
        let out = run(command)?; assert!(out.status.success()); assert!(out.stderr.is_empty());
        let text = String::from_utf8(out.stdout)?;
        for term in ["inspect-pins|restore-pins", "--commit yes", "--minimum-sequence", "NOT checked"] { assert!(text.contains(term)); }
    }
    Ok(())
}
#[cfg(unix)]
#[test]
fn symlinked_or_nested_pin_owners_are_refused_without_publication() -> Test {
    let _serial = serial();
    let f = fixture("layout", true)?; let before = std::fs::read(f.path.join("pins/pins.journal"))?;
    let alias = f.path.join("pin-alias"); std::os::unix::fs::symlink(f.path.join("pins"), &alias)?;
    let mut command = args(&f, false); command[2] = alias.into_os_string();
    refused(run(command)?, false)?; unchanged(&f, &before)?;
    let nested = f.path.join("media/nested-pins"); std::fs::create_dir(&nested)?;
    for name in ["LOCK", "pins.journal"] { std::fs::copy(f.path.join("pins").join(name), nested.join(name))?; }
    let mut command = args(&f, true); command[2] = nested.clone().into_os_string();
    refused(run(command)?, false)?; assert_eq!(std::fs::read(nested.join("pins.journal"))?, before);
    unchanged(&f, &before)
}
