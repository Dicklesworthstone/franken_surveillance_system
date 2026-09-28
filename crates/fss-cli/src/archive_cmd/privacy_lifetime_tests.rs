#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::panic)]
//! No timing races or sleeps: probe the actual deployment lock through an independent handle.
use super::*;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::fs::{File, OpenOptions, TryLockError};
use std::sync::atomic::{AtomicU64, Ordering};

const SITE: &str = "site:archive-privacy-lifetime";
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn context(root: &Path) -> std::result::Result<ReplayCx, Box<dyn std::error::Error>> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:archive-privacy-lifetime-test".into(),
        operation_id: OperationId::parse("operation:archive-privacy-lifetime-test")?,
        principal: "principal:local-operator".into(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

fn fixture(name: &str) -> std::result::Result<ArchiveOptions, Box<dyn std::error::Error>> {
    // Never reuse or clean another run's path. Retain test artifacts for failure inspection.
    let root = std::env::temp_dir().join(format!(
        "fss-export-privacy-lifetime-{}-{}-{name}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root)?;
    let cx = ExportReplayContext(context(&root)?);
    drop(ReferenceDeployment::open(&root, SITE, &cx.0)?);
    let mut options = parse_archive_args(&tests::argv("inspect", &[]))?.ok_or("options")?;
    options.action = Action::Export;
    options.root = root.join("archive-not-created");
    options.output = Some(root.with_extension("export"));
    options.query = Some(0..1);
    options.expected = Some(ContentDigest::sha256(b"unused snapshot"));
    options.privacy = Some((root, SITE.to_owned()));
    Ok(options)
}

fn probe(options: &ArchiveOptions) -> std::io::Result<File> {
    let (root, _) = options.privacy.as_ref().expect("fixture privacy root");
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("objects/LOCK"))
}

fn assert_locked(file: &File) {
    assert!(matches!(file.try_lock(), Err(TryLockError::WouldBlock)));
}

#[test]
fn privacy_authority_is_owned_until_the_export_guard_drops() -> TestResult {
    let options = fixture("success")?;
    let guard = refuse_masked_export(&options)?;
    let contender = probe(&options)?;
    assert_locked(&contender);
    // A real second deployment owner must fail too, before either journal can be changed.
    let (root, site) = options.privacy.as_ref().ok_or("privacy")?;
    let cx = ExportReplayContext(context(root)?);
    assert!(matches!(
        ReferenceDeployment::reopen(root, site, &cx.0),
        Err(fss_reference::ReferenceError::DeploymentLocked { .. })
    ));
    drop(guard);
    assert!(contender.try_lock().is_ok());
    Ok(())
}

#[test]
fn archive_refusal_releases_privacy_authority_without_creating_output() -> TestResult {
    let options = fixture("archive-refusal")?;
    assert!(matches!(
        execute_archive(&options),
        Err(ArchiveCommandError::NotArchive)
    ));
    assert!(!options.root.exists());
    assert!(!options.output.as_ref().ok_or("output")?.exists());
    assert!(probe(&options)?.try_lock().is_ok());
    Ok(())
}

#[test]
fn privacy_authority_is_released_during_unwinding() -> TestResult {
    let options = fixture("unwind")?;
    let guard = refuse_masked_export(&options)?;
    let contender = probe(&options)?;
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard = guard;
        assert_locked(&contender);
        panic!("injected export failure after privacy preflight");
    }));
    assert!(caught.is_err());
    assert!(probe(&options)?.try_lock().is_ok());
    Ok(())
}

#[test]
fn competing_privacy_owner_refuses_before_opening_the_archive() -> TestResult {
    let options = fixture("held-authority")?;
    let contender = probe(&options)?;
    assert!(contender.try_lock().is_ok());
    let error = execute_archive(&options)
        .err()
        .ok_or("export unexpectedly allowed")?;
    assert_eq!(error.code(), ERR_PRIVACY_MASK);
    assert!(!options.root.exists());
    assert!(!options.output.as_ref().ok_or("output")?.exists());
    Ok(())
}

#[test]
fn invalid_privacy_site_releases_any_acquired_lock() -> TestResult {
    let mut options = fixture("wrong-site")?;
    options.privacy.as_mut().ok_or("privacy")?.1 = "site:wrong".to_owned();
    let error = refuse_masked_export(&options)
        .err()
        .ok_or("wrong site accepted")?;
    assert_eq!(error.code(), ERR_PRIVACY_MASK);
    assert!(probe(&options)?.try_lock().is_ok());
    Ok(())
}

#[test]
fn non_export_commands_do_not_acquire_privacy_authority() -> TestResult {
    let mut options = fixture("inspect")?;
    let contender = probe(&options)?;
    assert!(contender.try_lock().is_ok());
    options.action = Action::Inspect;
    assert!(matches!(
        execute_archive(&options),
        Err(ArchiveCommandError::NotArchive)
    ));
    Ok(())
}

#[test]
fn missing_privacy_authority_is_still_a_typed_refusal_before_output() -> TestResult {
    let mut options = fixture("missing-authority")?;
    options.privacy = None;
    let error = execute_archive(&options)
        .err()
        .ok_or("missing authority accepted")?;
    assert_eq!(error.code(), ERR_PRIVACY_UNMASKED_ACCESS_REFUSED);
    assert!(!options.root.exists());
    assert!(!options.output.as_ref().ok_or("output")?.exists());
    Ok(())
}

#[test]
fn exports_cannot_add_files_to_the_privacy_authority() -> TestResult {
    let mut options = fixture("protected-destination")?;
    // Destination preflight needs only a real source directory; no archive or evidence
    // is fabricated, and no raw-byte publication is attempted in this refusal test.
    fs::create_dir(&options.root)?;
    let (privacy_root, _) = options.privacy.as_ref().ok_or("privacy")?;
    let privacy_root = privacy_root.clone();
    let layout_before = fs::read(privacy_root.join("LAYOUT"))?;
    let journal_before = fs::read(privacy_root.join("ledger/journal.fssj"))?;
    let guard = refuse_masked_export(&options)?;
    for parent in [
        "",
        "ledger",
        "effects",
        "objects/roots",
        "objects/spool/staging",
    ] {
        let output = privacy_root.join(parent).join("refused-export");
        options.output = Some(output.clone());
        assert!(matches!(
            export::Destination::begin(
                &options,
                ContentDigest::sha256(b"unused snapshot"),
                0,
                &tests::clock(),
            ),
            Err(ArchiveCommandError::OutputScope)
        ));
        assert!(!output.exists());
    }
    assert_eq!(fs::read(privacy_root.join("LAYOUT"))?, layout_before);
    assert_eq!(
        fs::read(privacy_root.join("ledger/journal.fssj"))?,
        journal_before
    );
    assert_locked(&probe(&options)?);
    drop(guard);
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinked_output_parent_cannot_bypass_privacy_store_exclusion() -> TestResult {
    let mut options = fixture("symlinked-destination")?;
    fs::create_dir(&options.root)?;
    let (privacy_root, _) = options.privacy.as_ref().ok_or("privacy")?;
    let alias = privacy_root.with_extension("alias");
    std::os::unix::fs::symlink(privacy_root.join("objects/roots"), &alias)?;
    let output = alias.join("refused-export");
    options.output = Some(output.clone());
    let _guard = refuse_masked_export(&options)?;
    assert!(matches!(
        export::Destination::begin(
            &options,
            ContentDigest::sha256(b"unused snapshot"),
            0,
            &tests::clock(),
        ),
        Err(ArchiveCommandError::OutputScope)
    ));
    assert!(!output.exists());
    Ok(())
}

struct LockCheckingClock {
    contender: File,
    output: PathBuf,
    checks: std::cell::Cell<usize>,
    pending_seen: std::cell::Cell<bool>,
    fail_after_payload: bool,
}
impl PublishCancellation for LockCheckingClock {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        false
    }
}
impl OperationClock for LockCheckingClock {
    fn now_ns(&self) -> Result<u64> {
        Ok(1)
    }
    fn deadline_ns(&self) -> u64 {
        u64::MAX
    }
    fn check(&self) -> Result<()> {
        assert_locked(&self.contender);
        self.checks.set(self.checks.get() + 1);
        if self.output.join("COMPLETE.json.pending").exists() {
            self.pending_seen.set(true);
        }
        if self.fail_after_payload {
            let has_playback = fs::read_dir(&self.output).is_ok_and(|entries| {
                entries.filter_map(std::result::Result::ok).any(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.ends_with(".playback.mp4"))
                })
            });
            if has_playback {
                return Err(ArchiveCommandError::Deadline);
            }
        }
        Ok(())
    }
}

fn real_export(
    name: &str,
    fail_after_payload: bool,
) -> std::result::Result<(ArchiveOptions, LockCheckingClock), Box<dyn std::error::Error>> {
    let privacy = fixture(name)?;
    let (mut options, publisher) = tests::setup(name)?;
    drop(publisher);
    options.action = Action::Export;
    options.query = Some(0..172_000);
    options.privacy = privacy.privacy;
    options.output = privacy.output;
    let clock = LockCheckingClock {
        contender: probe(&options)?,
        output: options.output.clone().ok_or("output")?,
        checks: std::cell::Cell::new(0),
        pending_seen: std::cell::Cell::new(false),
        fail_after_payload,
    };
    Ok((options, clock))
}

#[test]
fn real_export_holds_privacy_authority_through_payloads_and_completion() -> TestResult {
    let (options, clock) = real_export("completed-export", false)?;
    let report = execute_archive_with_clock(&options, &clock)?;
    assert!(report.contains("\"verified_windows\":2"));
    assert!(clock.checks.get() > 1);
    assert!(clock.pending_seen.get());
    assert_eq!(
        fs::read_to_string(clock.output.join("COMPLETE.json"))?,
        report
    );
    assert!(clock.contender.try_lock().is_ok());
    Ok(())
}

#[test]
fn partial_export_retains_no_completion_and_releases_privacy_authority() -> TestResult {
    let (options, clock) = real_export("interrupted-export", true)?;
    assert!(matches!(
        execute_archive_with_clock(&options, &clock),
        Err(ArchiveCommandError::ExportIncomplete(_))
    ));
    assert!(clock.output.join("REQUEST.json").exists());
    assert!(!clock.output.join("COMPLETE.json").exists());
    assert!(clock.contender.try_lock().is_ok());
    Ok(())
}

fn colocated_export(name: &str) -> std::result::Result<ArchiveOptions, Box<dyn std::error::Error>> {
    let privacy = fixture(name)?;
    let (mut options, publisher) = tests::setup(name)?;
    drop(publisher);
    let (root, _) = privacy.privacy.as_ref().ok_or("privacy")?;
    // Move only this test's newly created empty publisher aside. No deletion,
    // overwrite or production-layout migration is performed.
    fs::rename(root.join("objects"), root.with_extension("empty-publisher"))?;
    fs::rename(&options.root, root.join("objects"))?;
    options.root = root.join("objects");
    options.action = Action::Export;
    options.query = Some(0..172_000);
    options.privacy = privacy.privacy;
    options.output = privacy.output;
    Ok(options)
}

#[test]
fn colocated_export_reuses_authority_without_unlocking_it() -> TestResult {
    let options = colocated_export("colocated-success")?;
    let clock = LockCheckingClock {
        contender: probe(&options)?,
        output: options.output.clone().ok_or("output")?,
        checks: std::cell::Cell::new(0),
        pending_seen: std::cell::Cell::new(false),
        fail_after_payload: false,
    };
    let report = execute_archive_with_clock(&options, &clock)?;
    assert!(report.contains("\"verified_windows\":2"));
    assert!(clock.pending_seen.get());
    assert_eq!(
        fs::read_to_string(clock.output.join("COMPLETE.json"))?,
        report
    );
    assert!(clock.contender.try_lock().is_ok());
    Ok(())
}

#[test]
fn colocated_export_cannot_inherit_wider_storage_budgets() -> TestResult {
    let mut options = colocated_export("colocated-byte-bound")?;
    options.storage_limits.spool = SpoolLimits::new(65_536, 1, MAX_RECORDING_BYTES, 65_536);
    assert!(execute_archive(&options).is_err());
    assert!(!options.output.as_ref().ok_or("output")?.exists());
    assert!(probe(&options)?.try_lock().is_ok());
    Ok(())
}

#[test]
fn colocated_export_cannot_hide_roots_excluded_by_narrower_bounds() -> TestResult {
    let mut options = colocated_export("colocated-child-bound")?;
    options.storage_limits.max_children = 1;
    assert!(execute_archive(&options).is_err());
    assert!(!options.output.as_ref().ok_or("output")?.exists());
    assert!(probe(&options)?.try_lock().is_ok());
    Ok(())
}
