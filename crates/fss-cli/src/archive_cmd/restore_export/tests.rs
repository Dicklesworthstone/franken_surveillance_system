#![forbid(unsafe_code)]
#![cfg(target_env = "gnu")]
//! Copied native exports must become independently queryable without their original owner.
//! These composition tests exercise actual source replay, publication, recovery and refusal.

use super::super::tests::{argv, clock, path};
use super::super::verify_export::tests::copied_export_query;
use super::*;
use fss_core::json_input::{Value, parse_archive_export_report};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId};
use fss_publication::NeverCancel;
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = std::result::Result<T, TestError>;
const SITE: &str = "site:copied-archive-restore";

struct CopiedExport {
    options: ArchiveOptions,
    input: PathBuf,
    output: PathBuf,
    privacy_root: PathBuf,
    files: BTreeMap<OsString, Vec<u8>>,
    completion: Value,
}
impl CopiedExport {
    fn new(name: &str, codec: Codec, query: Option<Range<u64>>) -> TestResult<Self> {
        // This helper physically copies a production export, closes its original publisher,
        // and removes BOTH the source archive and the original export directory.
        let mut options = copied_export_query(&format!("restore-{name}"), codec, query)?;
        let input = options.root.clone();
        let output = path(&format!("restore-{name}-destination"))?;
        let privacy_root = path(&format!("restore-{name}-privacy"))?;
        fs::create_dir(&privacy_root)?;
        let cx = privacy_context(&privacy_root)?;
        drop(ReferenceDeployment::open(&privacy_root, SITE, &cx.0)?);
        drop(cx);
        let files = inventory(&input)?;
        let completion =
            parse_archive_export_report(&fs::read_to_string(input.join("COMPLETE.json"))?)?;
        options.action = Action::RestoreExport;
        options.output = Some(output.clone());
        options.privacy = Some((privacy_root.clone(), SITE.to_owned()));
        Ok(Self {
            options,
            input,
            output,
            privacy_root,
            files,
            completion,
        })
    }

    fn restore(&self) -> Result<String> {
        super::execute(&self.options, Arc::new(clock()))
    }

    fn verify_copy(&mut self) -> TestResult<String> {
        self.options.action = Action::VerifyExport;
        self.options.output = None;
        let privacy = self.options.privacy.take();
        let result = execute_archive_with_clock(&self.options, &clock());
        self.options.action = Action::RestoreExport;
        self.options.output = Some(self.output.clone());
        self.options.privacy = privacy;
        Ok(result?)
    }

    fn assert_input_unchanged(&self) -> TestResult {
        assert_eq!(inventory(&self.input)?, self.files);
        Ok(())
    }

    fn original_windows(&self) -> TestResult<Vec<OriginalWindow>> {
        field(&self.completion, "verified")?
            .array()
            .ok_or("verified windows array")?
            .iter()
            .map(|row| {
                let ordinal = usize::try_from(number(row, "ordinal")?)?;
                let root = ContentDigest::parse(text(row, "root")?)?;
                let returned = field(row, "returned_decode_interval")?
                    .array()
                    .ok_or("returned interval")?;
                let [start, end] = returned else {
                    return Err("returned interval pair".into());
                };
                let interval = u64::try_from(start.integer().ok_or("interval start")?)?
                    ..u64::try_from(end.integer().ok_or("interval end")?)?;
                let prefix = format!("window-{ordinal:016x}-{}", &root.to_text()[7..]);
                let read = |suffix: &str| fs::read(self.input.join(format!("{prefix}.{suffix}")));
                Ok(OriginalWindow {
                    ordinal,
                    root,
                    interval,
                    manifest: read("root.bin")?,
                    objects: [
                        read("source.bin")?,
                        read("init.mp4")?,
                        read("media.m4s")?,
                        read("index.bin")?,
                    ],
                    source: self.input.join(format!("{prefix}.source.bin")),
                })
            })
            .collect()
    }
}
impl Drop for CopiedExport {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.input);
        let _ = fs::remove_dir_all(&self.output);
        let _ = fs::remove_dir_all(&self.privacy_root);
    }
}

fn privacy_context(root: &Path) -> TestResult<ExportReplayContext> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:copied-archive-restore-test".into(),
        operation_id: OperationId::parse("operation:copied-archive-restore-test")?,
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
    Ok(ExportReplayContext(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?))
}

struct OriginalWindow {
    ordinal: usize,
    root: ContentDigest,
    interval: Range<u64>,
    manifest: Vec<u8>,
    objects: [Vec<u8>; 4],
    source: PathBuf,
}

fn inventory(root: &Path) -> TestResult<BTreeMap<OsString, Vec<u8>>> {
    fs::read_dir(root)?
        .map(|entry| {
            let entry = entry?;
            Ok((entry.file_name(), fs::read(entry.path())?))
        })
        .collect()
}

fn field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| "required report field missing".into())
}

fn text<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    field(value, key)?
        .text()
        .ok_or_else(|| "required text field".into())
}

fn number(value: &Value, key: &str) -> TestResult<u64> {
    Ok(u64::try_from(
        field(value, key)?
            .integer()
            .ok_or("required integer field")?,
    )?)
}

fn success_report(fixture: &CopiedExport, result: &str, windows: usize) -> TestResult<Value> {
    let completion_bytes = fs::read_to_string(fixture.output.join("RESTORE_COMPLETE.json"))?;
    let completion = parse_archive_export_report(&completion_bytes)?;
    assert_eq!(
        text(&completion, "schema")?,
        "fss.local_archive_restore_completion.v1"
    );
    assert_eq!(field(&completion, "complete")?.boolean(), Some(true));
    let report = parse_archive_export_report(result)?;
    assert_eq!(
        text(&report, "schema")?,
        "fss.local_archive_export_restoration.v1"
    );
    assert_eq!(
        text(&completion, "request_binding")?,
        "sha256_pinned_by_completion_v2"
    );
    assert_eq!(
        text(&report, "request_binding")?,
        "sha256_pinned_by_completion_v2"
    );
    assert_eq!(text(&report, "command")?, "restore-export");
    assert_eq!(text(&report, "codec")?, fixture.options.codec.name());
    assert_eq!(number(&report, "restored_windows")?, windows as u64);
    assert_eq!(
        text(&report, "completion_sha256")?,
        fixture
            .options
            .expected_completion
            .ok_or("source completion pin")?
            .to_text()
    );
    assert_eq!(
        text(&report, "restore_completion_sha256")?,
        ContentDigest::sha256(completion_bytes.as_bytes()).to_text()
    );
    for key in ["new_snapshot", "restored_windows", "restored_pages"] {
        assert_eq!(field(&report, key)?, field(&completion, key)?);
    }
    assert_eq!(field(&report, "complete")?.boolean(), Some(true));
    assert_eq!(
        field(&report, "original_catalog_reconstructed")?.boolean(),
        Some(false)
    );
    assert_eq!(text(&report, "coverage_claim")?, "not_claimed");
    assert_eq!(
        fs::metadata(&fixture.output)?.permissions().mode() & 0o077,
        0,
        "restored original media must remain in a private directory"
    );
    Ok(report)
}

fn assert_cold_query<C: ArchiveCodec>(
    fixture: &CopiedExport,
    originals: &[OriginalWindow],
    report: &Value,
    query: Range<u64>,
    gaps: &[Range<u64>],
) -> TestResult {
    // No in-memory writer or original archive owner remains. The ordinary archive loader,
    // catalog reader and native source verifier must accept this newly opened directory.
    let publisher = LocalRootPublisher::open(&fixture.output, fixture.options.storage_limits)?;
    let namespace = CodecArchiveNamespace::<C>::new(fixture.options.scope.clone())?;
    let snapshot = CodecArchiveSnapshot::<C>::load(
        &publisher,
        namespace,
        fixture.options.archive_limits,
        &NeverCancel,
    )?;
    assert_eq!(snapshot.windows().len(), originals.len());
    assert_eq!(snapshot.indexed_windows(), originals.len());
    assert!(snapshot.unindexed_windows().is_empty());
    assert_eq!(
        number(report, "restored_pages")?,
        snapshot.pages().len() as u64
    );
    assert_eq!(text(report, "new_snapshot")?, snapshot.digest()?.to_text());
    for (ordinal, (entry, original)) in snapshot.windows().iter().zip(originals).enumerate() {
        assert_eq!(entry.slot(), &snapshot.namespace().window_slot(ordinal)?);
        assert_eq!(entry.root(), original.root);
        assert_eq!(entry.decode_interval(), original.interval);
    }
    let mut reader = CodecArchiveRead::<C>::new(
        &publisher,
        &snapshot,
        query,
        fixture.options.query_limits,
        100,
    )?;
    for (expected_ordinal, original) in originals.iter().enumerate() {
        let ArchiveReadProgress::Window {
            ordinal, recording, ..
        } = reader.step(1, &NeverCancel)?
        else {
            return Err("restored window was not queryable".into());
        };
        assert_eq!(ordinal, expected_ordinal);
        let plan = C::plan(&recording);
        assert_eq!(plan.manifest().root(), original.root);
        assert_eq!(plan.manifest().canonical_bytes(), original.manifest);
        assert_eq!(plan.summary().decode_interval, original.interval);
        let objects = plan.objects();
        for (actual, expected) in [
            objects.source,
            objects.initialization,
            objects.media,
            objects.index,
        ]
        .into_iter()
        .zip(&original.objects)
        {
            assert_eq!(actual, expected);
        }
    }
    let ArchiveReadProgress::Complete(receipt) = reader.step(1, &NeverCancel)? else {
        return Err("restored native query did not complete".into());
    };
    assert_eq!(receipt.windows, originals.len());
    assert_eq!(receipt.unindexed, gaps);
    Ok(())
}

#[test]
fn both_native_codecs_restore_after_source_loss_and_old_verification_stays_read_only() -> TestResult
{
    for codec in [Codec::Avc, Codec::Hevc] {
        let mut fixture = CopiedExport::new(&format!("cold-{}", codec.name()), codec, None)?;
        let original_windows = fixture.original_windows()?;
        assert_eq!(
            original_windows.len(),
            if codec == Codec::Avc { 1 } else { 2 }
        );
        let verified_before = fixture.verify_copy()?;
        let result = fixture.restore()?;
        let report = success_report(&fixture, &result, original_windows.len())?;
        match codec {
            Codec::Avc => assert_cold_query::<AvcArchiveCodec>(
                &fixture,
                &original_windows,
                &report,
                0..210_000,
                &[original_windows[0].interval.end..210_000],
            )?,
            Codec::Hevc => assert_cold_query::<HevcArchiveCodec>(
                &fixture,
                &original_windows,
                &report,
                0..210_000,
                &[72_000..100_000, 172_000..210_000],
            )?,
        }
        assert_eq!(fixture.verify_copy()?, verified_before);
        fixture.assert_input_unchanged()?;
        // A successful restore cannot be merged into, overwritten or silently resumed.
        let completion = fs::read(fixture.output.join("RESTORE_COMPLETE.json"))?;
        assert!(fixture.restore().is_err());
        assert_eq!(
            fs::read(fixture.output.join("RESTORE_COMPLETE.json"))?,
            completion
        );
    }
    Ok(())
}

#[test]
fn selected_original_ordinal_becomes_new_zero_without_resurrecting_missing_windows() -> TestResult {
    let fixture = CopiedExport::new("subset", Codec::Hevc, Some(110_000..110_001))?;
    let originals = fixture.original_windows()?;
    assert_eq!(originals.len(), 1);
    assert_eq!(originals[0].ordinal, 1);
    assert_eq!(originals[0].interval, 100_000..172_000);
    let result = fixture.restore()?;
    let report = success_report(&fixture, &result, 1)?;
    assert_ne!(
        text(&report, "new_snapshot")?,
        text(&fixture.completion, "snapshot")?
    );
    assert_cold_query::<HevcArchiveCodec>(
        &fixture,
        &originals,
        &report,
        0..210_000,
        &[0..100_000, 172_000..210_000],
    )?;
    fixture.assert_input_unchanged()
}

#[test]
fn zero_selected_windows_create_an_empty_archive_without_absence_or_coverage_claim() -> TestResult {
    let fixture = CopiedExport::new("empty", Codec::Avc, Some(100_000..200_000))?;
    assert!(fixture.original_windows()?.is_empty());
    let result = fixture.restore()?;
    let report = success_report(&fixture, &result, 0)?;
    assert_eq!(number(&report, "restored_pages")?, 0);
    assert_cold_query::<AvcArchiveCodec>(
        &fixture,
        &[],
        &report,
        100_000..200_000,
        &[100_000..200_000],
    )?;
    fixture.assert_input_unchanged()
}

#[test]
fn empty_restore_reserves_scan_capacity_for_both_completion_names_before_creation() -> TestResult {
    let mut fixture = CopiedExport::new("empty-scan-bound", Codec::Avc, Some(100_000..200_000))?;
    fixture.options.archive_limits.max_scan_roots = 1;
    fixture.options.storage_limits.max_roots = 1;
    fixture.options.storage_limits.max_tombstones = 1;
    fixture.options.storage_limits.max_scan_entries = 1;
    assert!(matches!(
        fixture.restore(),
        Err(ArchiveCommandError::Archive(ArchiveError::Limit))
    ));
    assert!(!fixture.output.exists());

    fixture.options.archive_limits.max_scan_roots = 2;
    fixture.options.storage_limits.max_roots = 2;
    fixture.options.storage_limits.max_tombstones = 2;
    fixture.options.storage_limits.max_scan_entries = 2;
    let result = fixture.restore()?;
    let report = success_report(&fixture, &result, 0)?;
    // Both receipt names remain ordinary auxiliary files. Their retained presence must
    // fit the caller's SAME scan bound when a later ordinary archive reader reopens it.
    assert!(
        fixture
            .output
            .join("RESTORE_COMPLETE.json.pending")
            .is_file()
    );
    assert_cold_query::<AvcArchiveCodec>(
        &fixture,
        &[],
        &report,
        100_000..200_000,
        &[100_000..200_000],
    )?;
    fixture.assert_input_unchanged()
}

#[test]
fn restoration_and_later_disclosure_require_current_privacy_authority() -> TestResult {
    let mut fixture = CopiedExport::new("privacy", Codec::Avc, None)?;
    let originals = fixture.original_windows()?;
    let privacy = fixture.options.privacy.take();
    assert!(matches!(
        fixture.restore(),
        Err(ArchiveCommandError::Privacy { .. })
    ));
    assert!(!fixture.output.exists());
    fixture.options.privacy = privacy;
    let result = fixture.restore()?;
    let report = success_report(&fixture, &result, 1)?;
    let disclosure = path("restore-privacy-refused-disclosure")?;
    fixture.options.action = Action::Export;
    fixture.options.root = fixture.output.clone();
    fixture.options.output = Some(disclosure.clone());
    fixture.options.expected = Some(ContentDigest::parse(text(&report, "new_snapshot")?)?);
    fixture.options.expected_completion = None;
    fixture.options.query = Some(originals[0].interval.clone());
    fixture.options.privacy = None;
    assert!(matches!(
        execute_archive_with_clock(&fixture.options, &clock()),
        Err(ArchiveCommandError::Privacy { .. })
    ));
    assert!(!disclosure.exists());
    fixture.assert_input_unchanged()
}

#[test]
fn competing_privacy_owner_and_current_mask_refuse_before_output() -> TestResult {
    use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};

    let fixture = CopiedExport::new("privacy-mask", Codec::Avc, None)?;
    let cx = privacy_context(&fixture.privacy_root)?;
    let mut deployment = ReferenceDeployment::reopen(&fixture.privacy_root, SITE, &cx.0)?;
    let error = fixture
        .restore()
        .err()
        .ok_or("competing privacy owner accepted")?;
    assert_eq!(error.code(), ERR_PRIVACY_MASK);
    assert!(!fixture.output.exists());

    let policy = PrivacyMaskPolicy::new(
        fixture.options.scope.recording.sensor.clone(),
        [32, 16],
        &[[0, 0, 8, 8]],
    )?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approval, &cx.0)?;
    drop(deployment);
    drop(cx);
    let journal = fs::read(fixture.privacy_root.join("ledger/journal.fssj"))?;
    let error = fixture
        .restore()
        .err()
        .ok_or("masked original source restored")?;
    assert_eq!(error.code(), ERR_PRIVACY_UNMASKED_ACCESS_REFUSED);
    assert!(!fixture.output.exists());
    assert_eq!(
        fs::read(fixture.privacy_root.join("ledger/journal.fssj"))?,
        journal
    );
    fixture.assert_input_unchanged()
}

#[test]
fn wrong_completion_and_corrupt_final_window_fail_before_creating_destination() -> TestResult {
    let mut fixture = CopiedExport::new("preflight-corruption", Codec::Hevc, None)?;
    let pin = fixture.options.expected_completion;
    fixture.options.expected_completion = Some(ContentDigest::sha256(b"unrelated completion"));
    let error = fixture.restore().err().ok_or("wrong pin accepted")?;
    assert!(matches!(
        error,
        ArchiveCommandError::ExportVerification(ExportVerificationError::CompletionPinMismatch)
    ));
    assert!(!fixture.output.exists());
    fixture.options.expected_completion = pin;
    let last = fixture.original_windows()?.pop().ok_or("final window")?;
    let mut damaged = fs::read(&last.source)?;
    damaged[0] ^= 1;
    fs::write(&last.source, damaged)?;
    let error = fixture
        .restore()
        .err()
        .ok_or("corrupt final window accepted")?;
    assert!(matches!(
        error,
        ArchiveCommandError::ExportVerification(ExportVerificationError::Integrity)
    ));
    assert!(!fixture.output.exists());
    Ok(())
}

#[test]
fn occupied_and_aliased_destinations_preserve_existing_bytes_and_copied_bundle() -> TestResult {
    let mut fixture = CopiedExport::new("destination-scope", Codec::Avc, None)?;
    fs::create_dir(&fixture.output)?;
    fs::write(fixture.output.join("sentinel"), b"owner bytes")?;
    assert!(fixture.restore().is_err());
    assert_eq!(fs::read(fixture.output.join("sentinel"))?, b"owner bytes");
    assert_eq!(fs::read_dir(&fixture.output)?.count(), 1);
    fs::remove_dir_all(&fixture.output)?;

    fs::write(&fixture.output, b"existing ordinary file")?;
    assert!(fixture.restore().is_err());
    assert_eq!(fs::read(&fixture.output)?, b"existing ordinary file");
    fs::remove_file(&fixture.output)?;

    symlink(&fixture.input, &fixture.output)?;
    assert!(fixture.restore().is_err());
    assert_eq!(fs::read_link(&fixture.output)?, fixture.input);
    fs::remove_file(&fixture.output)?;

    let inside = fixture.input.join("forbidden-restoration");
    fixture.options.output = Some(inside.clone());
    assert!(fixture.restore().is_err());
    assert!(!inside.exists());

    let alias = path("restore-destination-scope-parent-alias")?;
    symlink(&fixture.input, &alias)?;
    fixture.options.output = Some(alias.join("forbidden-restoration"));
    assert!(fixture.restore().is_err());
    assert!(!inside.exists());
    fs::remove_file(alias)?;

    fixture.options.output = Some(fixture.input.clone());
    assert!(fixture.restore().is_err());
    fixture.options.output = Some(fixture.input.parent().ok_or("input parent")?.to_owned());
    assert!(fixture.restore().is_err());
    let inside_privacy = fixture.privacy_root.join("forbidden-restoration");
    fixture.options.output = Some(inside_privacy.clone());
    assert!(fixture.restore().is_err());
    assert!(!inside_privacy.exists());
    fixture.assert_input_unchanged()
}

fn assert_incomplete(fixture: &CopiedExport, error: &ArchiveCommandError) -> TestResult {
    assert!(!fixture.output.join("RESTORE_COMPLETE.json").exists());
    let report = error
        .partial_report()
        .ok_or("missing partial restore accounting")?;
    let report = parse_archive_export_report(report)?;
    assert_eq!(field(&report, "complete")?.boolean(), Some(false));
    assert_eq!(
        field(&report, "original_catalog_reconstructed")?.boolean(),
        Some(false)
    );
    Ok(())
}

#[test]
fn independent_bundle_read_and_local_publication_budgets_never_claim_partial_success() -> TestResult
{
    for limited in [
        "read-bytes",
        "read-operations",
        "local-bytes",
        "local-operations",
    ] {
        let mut fixture = CopiedExport::new(&format!("budget-{limited}"), Codec::Avc, None)?;
        match limited {
            "read-bytes" => fixture.options.verify_read_budget = 1,
            "read-operations" => fixture.options.verify_io_budget = 1,
            "local-bytes" => fixture.options.restore_io_bytes = 1,
            "local-operations" => fixture.options.restore_io_operations = 1,
            _ => return Err("unexpected budget fixture".into()),
        }
        let error = fixture
            .restore()
            .err()
            .ok_or("insufficient budget accepted")?;
        if limited.starts_with("read-") {
            assert!(!fixture.output.exists());
        } else if fixture.output.exists() {
            assert_incomplete(&fixture, &error)?;
        }
        assert!(!fixture.output.join("RESTORE_COMPLETE.json").exists());
        fixture.assert_input_unchanged()?;
    }
    Ok(())
}

struct StoppedClock {
    expired: bool,
}
impl PublishCancellation for StoppedClock {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        !self.expired
    }
}
impl OperationClock for StoppedClock {
    fn now_ns(&self) -> Result<u64> {
        Ok(if self.expired { 100 } else { 1 })
    }
    fn deadline_ns(&self) -> u64 {
        100
    }
}

#[test]
fn deadline_and_cancellation_before_input_admission_create_nothing() -> TestResult {
    for expired in [false, true] {
        let fixture = CopiedExport::new(&format!("stopped-{expired}"), Codec::Avc, None)?;
        assert!(super::execute(&fixture.options, Arc::new(StoppedClock { expired })).is_err());
        assert!(!fixture.output.exists());
        fixture.assert_input_unchanged()?;
    }
    Ok(())
}

struct CancelAtPublication {
    point: PublishCutPoint,
    fired: AtomicBool,
}
impl PublishCancellation for CancelAtPublication {
    fn cancel_requested(&self, point: PublishCutPoint) -> bool {
        if point == self.point {
            self.fired.store(true, Ordering::SeqCst);
            true
        } else {
            false
        }
    }
}
impl OperationClock for CancelAtPublication {
    fn now_ns(&self) -> Result<u64> {
        Ok(1)
    }
    fn deadline_ns(&self) -> u64 {
        100
    }
}

#[test]
fn cancellation_during_root_publication_leaves_explicit_incomplete_restore() -> TestResult {
    for point in [
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
    ] {
        let fixture = CopiedExport::new(&format!("cancel-{point}"), Codec::Avc, None)?;
        let clock = Arc::new(CancelAtPublication {
            point,
            fired: AtomicBool::new(false),
        });
        let error = super::execute(&fixture.options, Arc::clone(&clock))
            .err()
            .ok_or("cancelled restore succeeded")?;
        assert!(
            clock.fired.load(Ordering::SeqCst),
            "publication cut was not reached"
        );
        assert!(fixture.output.exists());
        assert_incomplete(&fixture, &error)?;
        fixture.assert_input_unchanged()?;
    }
    Ok(())
}

struct CorruptAfterPreflight {
    trigger: PathBuf,
    source: PathBuf,
    bytes: Vec<u8>,
    fired: AtomicBool,
}
impl PublishCancellation for CorruptAfterPreflight {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        if !self.fired.load(Ordering::SeqCst)
            && self.trigger.exists()
            && self
                .fired
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            // Synthetic external drift after the first restored native root is visible.
            // No producer or background thread owns this mutation in production.
            assert!(fs::write(&self.source, &self.bytes).is_ok());
        }
        false
    }
}
impl OperationClock for CorruptAfterPreflight {
    fn now_ns(&self) -> Result<u64> {
        Ok(1)
    }
    fn deadline_ns(&self) -> u64 {
        100
    }
}

#[test]
fn second_pass_reread_refuses_input_drift_after_preflight_and_private_publication() -> TestResult {
    let fixture = CopiedExport::new("post-preflight-drift", Codec::Hevc, None)?;
    let originals = fixture.original_windows()?;
    let mut changed = originals[0].objects[0].clone();
    changed[0] ^= 1;
    let first_slot = CodecArchiveNamespace::<HevcArchiveCodec>::new(fixture.options.scope.clone())?
        .window_slot(0)?;
    let clock = Arc::new(CorruptAfterPreflight {
        trigger: fixture
            .output
            .join("roots")
            .join(format!("{first_slot}.root")),
        source: originals[0].source.clone(),
        bytes: changed,
        fired: AtomicBool::new(false),
    });
    let error = super::execute(&fixture.options, Arc::clone(&clock))
        .err()
        .ok_or("changed copied source accepted")?;
    assert!(
        clock.fired.load(Ordering::SeqCst),
        "preflight did not reach publication"
    );
    assert_incomplete(&fixture, &error)?;
    // An incomplete prefix is still exact native evidence; it is not aggregate success.
    let publisher = LocalRootPublisher::open(&fixture.output, fixture.options.storage_limits)?;
    let snapshot = CodecArchiveSnapshot::<HevcArchiveCodec>::load(
        &publisher,
        CodecArchiveNamespace::new(fixture.options.scope.clone())?,
        fixture.options.archive_limits,
        &NeverCancel,
    )?;
    assert!(!snapshot.windows().is_empty());
    for window in snapshot.windows() {
        assert!(
            originals
                .iter()
                .any(|original| original.root == window.root())
        );
    }
    Ok(())
}

#[test]
fn parser_requires_independent_completion_and_new_output_with_separate_local_allowances()
-> TestResult {
    let pin = ContentDigest::sha256(b"independently observed export completion").to_text();
    let args = argv(
        "restore-export",
        &[
            "--expected-completion",
            &pin,
            "--output-dir",
            "/unused/new-private-archive",
            "--allow-whole-windows",
            "yes",
            "--privacy-root",
            "/unused/current-privacy-authority",
            "--site",
            SITE,
            "--max-local-bytes",
            "19000000",
            "--max-local-operations",
            "9000",
        ],
    );
    let options = parse_archive_args(&args)?.ok_or("restore options")?;
    assert_eq!(options.action, Action::RestoreExport);
    assert!(options.expected.is_none());
    assert!(options.query.is_none());
    assert_eq!(
        options.privacy.as_ref().map(|(_, site)| site.as_str()),
        Some(SITE)
    );
    assert_eq!(
        options.expected_completion,
        Some(ContentDigest::parse(&pin)?)
    );
    assert_eq!(options.restore_io_bytes, 19_000_000);
    assert_eq!(options.restore_io_operations, 9000);
    assert!(parse_archive_args(&argv("restore-export", &[])).is_err());
    for missing in [
        "--expected-completion",
        "--output-dir",
        "--allow-whole-windows",
        "--privacy-root",
        "--site",
    ] {
        let invalid: Vec<_> = std::iter::once(args[0].clone())
            .chain(
                args[1..]
                    .chunks(2)
                    .filter(|pair| pair[0].as_os_str() != OsStr::new(missing))
                    .flat_map(|pair| pair.iter().cloned()),
            )
            .collect();
        assert!(parse_archive_args(&invalid).is_err());
    }
    for extra in [
        vec!["--expected-snapshot", pin.as_str()],
        vec!["--start", "0"],
        vec!["--max-export-bytes", "1"],
        vec!["--expected-clock-index", pin.as_str()],
        vec!["--max-output-windows", "1"],
    ] {
        let mut invalid = args.clone();
        invalid.extend(extra.into_iter().map(OsString::from));
        assert!(parse_archive_args(&invalid).is_err());
    }
    for (flag, value) in [
        ("--allow-whole-windows", "no"),
        ("--max-local-bytes", "0"),
        ("--max-local-operations", "0"),
    ] {
        let mut invalid = args.clone();
        let at = invalid
            .iter()
            .position(|arg| arg.as_os_str() == OsStr::new(flag))
            .ok_or("flag")?;
        invalid[at + 1] = value.into();
        assert!(parse_archive_args(&invalid).is_err());
    }
    for flag in [
        "--max-local-bytes",
        "--max-local-operations",
        "--allow-whole-windows",
    ] {
        assert!(
            parse_archive_args(&argv(
                "verify-export",
                &["--expected-completion", &pin, flag, "1"],
            ))
            .is_err()
        );
    }
    let mut duplicate = args;
    duplicate.extend(["--expected-completion".into(), pin.into()]);
    assert!(parse_archive_args(&duplicate).is_err());
    Ok(())
}
