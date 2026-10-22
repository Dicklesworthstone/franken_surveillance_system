#![forbid(unsafe_code)]
//! Native root-last campaign metadata, independently selected cold prefixes and refusal barriers.
//! Typed observations below exercise storage/controller semantics; they make no camera-quality claim.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, Generation, ObjectId, OperationId,
    RootAuthoritySpec, TombstoneReason, TombstoneRecord,
};
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, PublishCutPoint, SlotName};
use fss_reference::ReplayCx;
use fss_reference::rtsp::archive_pins::ArchivePinAnchor;
use fss_reference::rtsp::campaign_history::*;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WORK: u64 = 10_000_000_000;
const PRINCIPAL: &str = "principal:rtsp-campaign-contract";
const SOURCE_ERROR: &str = "ERR-CAPTURE-RTSP-SOURCE-001";
const OUTPUT_ERROR: &str = "ERR-CAPTURE-RTSP-OUTPUT-001";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-rtsp-campaign-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("campaign fixture directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn digest(value: &str) -> ContentDigest {
    ContentDigest::sha256(value.as_bytes())
}
fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-campaign-contract".into(),
        operation_id: OperationId::parse("operation:rtsp-campaign-contract")?,
        principal: PRINCIPAL.into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:campaign-metadata".into(),
        retention_scope: "retention:campaign-metadata".into(),
        anchor_universe: digest("campaign metadata test"),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority_read_only(
        &authority,
        root.to_path_buf(),
    )?)
}
fn local_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        33,
        4,
        16,
        4096,
        SpoolLimits::new(4096, 32 * 1024 * 1024, 256 * 1024, 4096),
    )
}
fn tree(root: &Path) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
    let mut result = BTreeMap::new();
    if !root.exists() {
        return Ok(result);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                stack.push(entry.path());
            } else {
                result.insert(entry.path(), fs::read(entry.path())?);
            }
        }
    }
    Ok(result)
}

struct Owner {
    approval: ContentDigest,
    plan: ContentDigest,
    root: PathBuf,
    enabled: AtomicBool,
    calls: AtomicUsize,
    deny_after: AtomicUsize,
}
impl Owner {
    fn new(plan: &CampaignPlan) -> Test<Self> {
        Ok(Self {
            approval: plan.approval,
            plan: plan.digest()?,
            root: PathBuf::from(&plan.history_path),
            enabled: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
            deny_after: AtomicUsize::new(usize::MAX),
        })
    }
    fn allowed(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
            && self.calls.fetch_add(1, Ordering::AcqRel) < self.deny_after.load(Ordering::Acquire)
    }
}
impl CampaignAuthority for Owner {
    fn permit(&self, _: CampaignOperation, plan: &CampaignPlan) -> bool {
        self.allowed()
            && plan.digest().is_ok_and(|actual| actual == self.plan)
            && plan.principal == PRINCIPAL
            && Path::new(&plan.history_path) == self.root
    }
    fn permit_read(&self, pin: CampaignPin, root: &Path, principal: &str) -> bool {
        self.allowed()
            && pin.approval == self.approval
            && pin.plan == self.plan
            && root == self.root
            && principal == PRINCIPAL
    }
}

struct Fixture {
    directory: Directory,
    root: PathBuf,
    plan: CampaignPlan,
    owner: Owner,
    cx: ReplayCx,
    writer: CampaignWriter,
    publisher: Option<LocalRootPublisher>,
    work: WorkBudget<'static>,
}
impl Fixture {
    fn new(label: &str, count: usize, continued: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("history");
        let plan = CampaignPlan {
            approval: digest(&format!("approval {label}")),
            principal: PRINCIPAL.into(),
            history_path: root.to_str().ok_or("UTF-8 root")?.into(),
            continue_after_success: continued,
            retry_interrupted: false,
            progress_supervised: false,
            duration_limited: false,
            attempts: (1..=count)
                .map(|ordinal| CampaignAttempt {
                    ordinal: ordinal as u32,
                    child_approval: digest(&format!("child {ordinal}")),
                    generation: ordinal as u64,
                    archive_namespace: digest(&format!("archive {ordinal}")),
                    journal_id: digest(&format!("journal {ordinal}")),
                    receive_clock: digest("receive-clock"),
                    decode_clock: digest("decode-clock"),
                    archive_path: directory
                        .0
                        .join(format!("archive-{ordinal}"))
                        .to_string_lossy()
                        .into_owned(),
                    pins_path: directory
                        .0
                        .join(format!("pins-{ordinal}"))
                        .to_string_lossy()
                        .into_owned(),
                    source: Some(CampaignSourceBinding {
                        path: directory
                            .0
                            .join(format!("source-{ordinal}"))
                            .to_string_lossy()
                            .into_owned(),
                        scope: digest(&format!("source scope {ordinal}")),
                    }),
                    picture_ceiling: 2,
                })
                .collect(),
        };
        let cx = context(&root)?;
        assert!(
            !root.exists(),
            "read-only context construction must not create a root"
        );
        let owner = Owner::new(&plan)?;
        let writer = CampaignWriter::new(plan.clone(), CampaignHistoryLimits::default())?;
        let publisher = Some(LocalRootPublisher::open(&root, local_limits())?);
        Ok(Self {
            directory,
            root,
            plan,
            owner,
            cx,
            writer,
            publisher,
            work: WorkBudget::new(WORK),
        })
    }
    fn start(&mut self, ordinal: u32) -> Test<CampaignPin> {
        Ok(self.writer.start_attempt(
            self.publisher.as_mut().ok_or("publisher")?,
            ordinal,
            &self.owner,
            &self.cx,
            &mut self.work,
        )?)
    }
    fn finish(&mut self, ordinal: u32, finish: CampaignFinish) -> Test<CampaignPin> {
        Ok(self.writer.finish_attempt(
            self.publisher.as_mut().ok_or("publisher")?,
            ordinal,
            finish,
            &self.owner,
            &self.cx,
            &mut self.work,
        )?)
    }
    fn terminal(&mut self, complete: bool, error: Option<&str>) -> Test<CampaignPin> {
        Ok(self.writer.finish_campaign(
            self.publisher.as_mut().ok_or("publisher")?,
            CampaignTerminal {
                complete,
                error_id: error.map(str::to_owned),
            },
            &self.owner,
            &self.cx,
            &mut self.work,
        )?)
    }
    fn close(&mut self) {
        drop(self.publisher.take());
    }
    fn reopen(&mut self) -> Test {
        self.close();
        self.publisher = Some(LocalRootPublisher::open(&self.root, local_limits())?);
        Ok(())
    }
    fn inspect(&self, pin: CampaignPin) -> Test<VerifiedCampaignHistory> {
        let cx = context(&self.root)?;
        Ok(VerifiedCampaignHistory::inspect(
            &self.root,
            pin,
            CampaignHistoryLimits::default(),
            local_limits(),
            &self.owner,
            &cx,
            &mut WorkBudget::new(WORK),
        )?)
    }
    fn success(&self, ordinal: u32, next: bool) -> CampaignFinish {
        let source = self.plan.attempts[ordinal as usize - 1].source.as_ref();
        CampaignFinish {
            native: Some(NativeAttemptObservation {
                complete: true,
                error_id: None,
                retry: Some(CampaignRetryReason::SettledSuccess),
                durable_pictures: 2,
                recovery_required: false,
                bindings: NativeBindings {
                    snapshot_digest: Some(digest(&format!("native inventory {ordinal}"))),
                    journal_anchor: Some(ArchivePinAnchor {
                        sequence: 3,
                        root: digest(&format!("journal anchor {ordinal}")),
                    }),
                    catalogs: vec![CampaignCatalogBinding {
                        slot: format!("native-page-{ordinal}"),
                        root: digest(&format!("catalog root {ordinal}")),
                    }],
                    source_pin: source.map(|source| CampaignSourcePin {
                        scope: source.scope,
                        head: digest(&format!("native source head {ordinal}")),
                        datagrams: 4,
                        bytes: 128,
                    }),
                },
            }),
            controller_error: None,
            settled_success: true,
            next_attempt_planned: next,
        }
    }
    fn failed(&self, ordinal: u32, reason: CampaignRetryReason, next: bool) -> CampaignFinish {
        let source = self.plan.attempts[ordinal as usize - 1].source.as_ref();
        CampaignFinish {
            native: Some(NativeAttemptObservation {
                complete: false,
                error_id: Some(SOURCE_ERROR.into()),
                retry: Some(reason),
                durable_pictures: 0,
                recovery_required: false,
                bindings: NativeBindings {
                    source_pin: source.map(|source| CampaignSourcePin {
                        scope: source.scope,
                        head: source.scope,
                        datagrams: 0,
                        bytes: 0,
                    }),
                    ..NativeBindings::default()
                },
            }),
            controller_error: None,
            settled_success: false,
            next_attempt_planned: next,
        }
    }
}

#[test]
fn failed_empty_then_usable_attempts_survive_cold_exact_inspection_without_writes() -> Test {
    let mut f = Fixture::new("empty-then-usable", 3, false)?;
    let first_start = f.start(1)?;
    f.finish(
        1,
        f.failed(1, CampaignRetryReason::ConnectionUnavailable, true),
    )?;
    f.start(2)?;
    // A native all-zero-byte malformed datagram prefix is nonempty source history, not an
    // absent source. Exact source identities must survive even though no picture was retained.
    let mut empty = f.failed(2, CampaignRetryReason::SourceEnded, true);
    let pin = empty
        .native
        .as_mut()
        .and_then(|native| native.bindings.source_pin.as_mut())
        .ok_or("source pin")?;
    pin.head = digest("zero-byte datagram head");
    pin.datagrams = 1;
    f.finish(2, empty.clone())?;
    f.start(3)?;
    let success = f.success(3, false);
    let finish_pin = f.finish(3, success.clone())?;
    assert_eq!(finish_pin.records, 6);
    let terminal = f.terminal(true, None)?;
    assert_eq!(terminal.records, 7);
    let original_work = f.work.used();
    assert_eq!(
        f.terminal(true, None)?,
        terminal,
        "exact retained retry must be idempotent"
    );
    assert!(
        f.work.used() > original_work,
        "reverification must use the existing account"
    );
    f.close();
    let before = tree(&f.directory.0)?;
    let verified = f.inspect(terminal)?;
    assert_eq!(verified.pin(), terminal);
    assert_eq!(verified.plan(), &f.plan);
    assert_eq!(verified.attempts().len(), 3);
    assert_eq!(verified.attempts()[1].finish.as_ref(), Some(&empty));
    assert_eq!(verified.attempts()[2].finish.as_ref(), Some(&success));
    assert_eq!(
        verified.terminal(),
        Some(&CampaignTerminal {
            complete: true,
            error_id: None
        })
    );
    assert!(!verified.durability_resynced());
    assert!(
        verified.possibly_stale(),
        "inspection never obtains a writer lock"
    );
    let old = f.inspect(first_start)?;
    assert_eq!(old.attempts().len(), 1);
    assert!(old.attempts()[0].finish.is_none());
    assert!(
        old.terminal().is_none(),
        "selected start is unknown even though a later terminal exists"
    );
    assert_eq!(
        tree(&f.directory.0)?,
        before,
        "cold read must preserve every file byte"
    );
    Ok(())
}

#[test]
fn full_sixteen_attempt_campaign_finishes_under_one_ten_billion_work_account() -> Test {
    let mut f = Fixture::new("maximum-campaign", 16, true)?;
    for ordinal in 1..=16 {
        f.start(ordinal)?;
        f.finish(ordinal, f.success(ordinal, ordinal < 16))?;
    }
    let terminal = f.terminal(true, None)?;
    assert_eq!(terminal.records, 33);
    assert!(
        f.work.used() > 1_000_000_000,
        "test covers the original too-small default"
    );
    assert!(f.work.used() < WORK);
    f.close();
    let before = tree(&f.directory.0)?;
    let verified = f.inspect(terminal)?;
    assert_eq!(verified.attempts().len(), 16);
    assert!(
        verified
            .terminal()
            .is_some_and(|terminal| terminal.complete)
    );
    assert_eq!(tree(&f.directory.0)?, before);
    Ok(())
}

#[test]
fn interrupted_append_blocks_successor_and_only_exact_pending_retry_can_advance() -> Test {
    for cut in [
        PublishCutPoint::AfterRootTempWrite,
        PublishCutPoint::AfterRootRename,
    ] {
        let mut f = Fixture::new(&format!("append-{cut}"), 2, false)?;
        let start = f.start(1)?;
        let finish = f.failed(1, CampaignRetryReason::SourceEnded, true);
        f.publisher
            .as_mut()
            .ok_or("publisher")?
            .inject_crash_at(cut);
        assert!(f.finish(1, finish.clone()).is_err());
        assert_eq!(f.writer.tip(), Some(start));
        f.reopen()?;
        let before = tree(&f.root)?;
        let result = f.writer.start_attempt(
            f.publisher.as_mut().ok_or("publisher")?,
            2,
            &f.owner,
            &f.cx,
            &mut f.work,
        );
        assert_eq!(result, Err(CampaignHistoryError::Pending));
        assert_eq!(tree(&f.root)?, before);
        let finished = f.finish(1, finish)?;
        assert_eq!(finished.records, 2);
        f.start(2)?;
        f.finish(2, f.success(2, false))?;
        let terminal = f.terminal(true, None)?;
        assert_eq!(
            terminal.records, 5,
            "retry must not add another capture observation"
        );
    }
    Ok(())
}

#[test]
fn native_unavailable_and_output_failure_preserve_unknown_or_successful_native_outcome() -> Test {
    let mut f = Fixture::new("native-unavailable", 2, false)?;
    f.start(1)?;
    let unavailable = CampaignFinish {
        native: None,
        controller_error: Some(OUTPUT_ERROR.into()),
        settled_success: false,
        next_attempt_planned: false,
    };
    f.finish(1, unavailable.clone())?;
    let terminal = f.terminal(false, Some(OUTPUT_ERROR))?;
    let verified = f.inspect(terminal)?;
    assert_eq!(verified.attempts()[0].finish.as_ref(), Some(&unavailable));
    assert!(
        verified.attempts()[0]
            .finish
            .as_ref()
            .and_then(|finish| finish.native.as_ref())
            .is_none()
    );
    assert!(f.start(2).is_err());

    let mut f = Fixture::new("native-success-output-failure", 1, false)?;
    f.start(1)?;
    let mut finish = f.success(1, false);
    finish.controller_error = Some(OUTPUT_ERROR.into());
    finish.settled_success = false;
    f.finish(1, finish.clone())?;
    let terminal = f.terminal(false, Some(OUTPUT_ERROR))?;
    let verified = f.inspect(terminal)?;
    assert_eq!(verified.attempts()[0].finish.as_ref(), Some(&finish));
    assert!(finish.native.as_ref().is_some_and(|native| native.complete));
    assert!(!verified.terminal().ok_or("terminal")?.complete);
    Ok(())
}

#[test]
fn separate_campaign_terminal_cannot_hide_an_earlier_failed_independent_session() -> Test {
    let mut f = Fixture::new("earlier-failure", 2, true)?;
    f.start(1)?;
    f.finish(1, f.failed(1, CampaignRetryReason::SourceEnded, true))?;
    f.start(2)?;
    let finished = f.finish(2, f.success(2, false))?;
    let before = tree(&f.root)?;
    assert!(f.terminal(true, None).is_err());
    assert_eq!(f.writer.tip(), Some(finished));
    assert_eq!(tree(&f.root)?, before);
    let terminal = f.terminal(false, Some(SOURCE_ERROR))?;
    let verified = f.inspect(terminal)?;
    assert_eq!(
        verified.terminal(),
        Some(&CampaignTerminal {
            complete: false,
            error_id: Some(SOURCE_ERROR.into())
        })
    );
    assert!(
        verified.attempts()[1]
            .finish
            .as_ref()
            .is_some_and(|finish| finish.settled_success)
    );
    Ok(())
}

#[test]
fn independent_pin_and_narrower_reader_limits_are_enforced_before_disclosure() -> Test {
    let mut f = Fixture::new("independent-pin", 1, false)?;
    f.start(1)?;
    f.finish(1, f.success(1, false))?;
    let pin = f.terminal(true, None)?;
    f.close();
    let before = tree(&f.root)?;
    for wrong in [
        CampaignPin {
            root: digest("wrong independent root"),
            ..pin
        },
        CampaignPin {
            plan: digest("wrong independent plan"),
            ..pin
        },
        CampaignPin {
            approval: digest("wrong independent approval"),
            ..pin
        },
        CampaignPin { records: 2, ..pin },
    ] {
        assert!(f.inspect(wrong).is_err());
    }
    let mut smaller = CampaignHistoryLimits::default();
    smaller.maximum_records = 3;
    smaller.maximum_metadata_bytes = 1024 * 1024;
    let verified = VerifiedCampaignHistory::inspect(
        &f.root,
        pin,
        smaller,
        local_limits(),
        &f.owner,
        &context(&f.root)?,
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(verified.writer_limits(), CampaignHistoryLimits::default());
    assert_eq!(verified.pin(), pin);
    assert_eq!(tree(&f.root)?, before);
    Ok(())
}

#[test]
fn cold_missing_roots_and_malformed_objects_never_create_repair_or_reacquire() -> Test {
    let mut f = Fixture::new("missing-or-corrupt", 1, false)?;
    let start = f.start(1)?;
    f.finish(1, f.success(1, false))?;
    let pin = f.terminal(true, None)?;
    let first_slot = slot(start)?;
    let first_record = f.root.join("roots").join(format!("{first_slot}.root"));
    f.close();
    let removed = fs::read(&first_record)?;
    fs::remove_file(&first_record)?;
    let before = tree(&f.root)?;
    assert!(
        f.inspect(pin).is_err(),
        "missing earlier root cannot be replaced by an unrooted object"
    );
    assert_eq!(tree(&f.root)?, before);
    fs::write(&first_record, removed)?;
    f.reopen()?;
    let object_path = f
        .publisher
        .as_ref()
        .ok_or("publisher")?
        .spool()
        .object_path(pin.plan);
    f.close();
    fs::write(object_path, b"corrupt plan object")?;
    let before = tree(&f.root)?;
    assert!(f.inspect(pin).is_err());
    assert_eq!(tree(&f.root)?, before);

    let missing = f.directory.0.join("never-created-history");
    let cx = context(&missing)?;
    assert!(!missing.exists());
    assert!(
        VerifiedCampaignHistory::inspect(
            &missing,
            pin,
            CampaignHistoryLimits::default(),
            local_limits(),
            &f.owner,
            &cx,
            &mut WorkBudget::new(WORK)
        )
        .is_err()
    );
    assert!(!missing.exists());
    Ok(())
}

#[test]
fn occupied_empty_session_and_deleted_history_cannot_be_silently_restarted() -> Test {
    let mut f = Fixture::new("occupied-empty", 1, false)?;
    let start = f.start(1)?;
    let mut again = CampaignWriter::new(f.plan.clone(), CampaignHistoryLimits::default())?;
    let before = tree(&f.root)?;
    assert_eq!(
        again.start_attempt(
            f.publisher.as_mut().ok_or("publisher")?,
            1,
            &f.owner,
            &f.cx,
            &mut WorkBudget::new(WORK)
        ),
        Err(CampaignHistoryError::Occupied)
    );
    assert_eq!(tree(&f.root)?, before);
    let publisher = f.publisher.as_mut().ok_or("publisher")?;
    let witness = publisher.stage_object(b"test-only explicit history deletion authority")?;
    publisher.verify_object(witness)?;
    publisher.retract_root(&slot(start)?, witness)?;
    publisher.record_tombstone(TombstoneRecord::new(
        ObjectId::parse("object:campaign-history-deleted")?,
        Generation(2),
        Generation(1),
        TombstoneReason::Deleted,
        Some(witness),
        start.root,
    )?)?;
    assert_eq!(
        again.start_attempt(publisher, 1, &f.owner, &f.cx, &mut WorkBudget::new(WORK)),
        Err(CampaignHistoryError::Occupied)
    );
    f.close();
    let before = tree(&f.root)?;
    assert!(f.inspect(start).is_err());
    assert_eq!(tree(&f.root)?, before);
    Ok(())
}

#[test]
fn invalid_first_start_cannot_cache_namespace_admission_then_adopt_another_owner() -> Test {
    let mut f = Fixture::new("namespace-recheck", 2, false)?;
    assert!(f.start(2).is_err());
    assert!(f.writer.tip().is_none());
    let mut other = CampaignWriter::new(f.plan.clone(), CampaignHistoryLimits::default())?;
    other.start_attempt(
        f.publisher.as_mut().ok_or("publisher")?,
        1,
        &f.owner,
        &f.cx,
        &mut WorkBudget::new(WORK),
    )?;
    let before = tree(&f.root)?;
    assert_eq!(
        f.writer.start_attempt(
            f.publisher.as_mut().ok_or("publisher")?,
            1,
            &f.owner,
            &f.cx,
            &mut f.work
        ),
        Err(CampaignHistoryError::Occupied)
    );
    assert!(f.writer.tip().is_none());
    assert_eq!(tree(&f.root)?, before);
    Ok(())
}

#[test]
fn current_authority_cancellation_and_shared_work_never_advance_a_failed_boundary() -> Test {
    let mut f = Fixture::new("work-refusal", 2, false)?;
    f.work = WorkBudget::new(7_000_000);
    let start = f.start(1)?;
    let finish = f.failed(1, CampaignRetryReason::SourceEnded, true);
    assert!(f.finish(1, finish.clone()).is_err());
    assert_eq!(f.writer.tip(), Some(start));
    let used = f.work.used();
    assert!(f.finish(1, finish).is_err());
    assert!(f.work.used() >= used);
    assert_eq!(f.writer.tip(), Some(start));
    assert!(f.start(2).is_err());

    let mut f = Fixture::new("current-authority", 1, false)?;
    let start = f.start(1)?;
    let before = tree(&f.root)?;
    f.owner.enabled.store(false, Ordering::Release);
    assert!(f.finish(1, f.success(1, false)).is_err());
    assert_eq!(f.writer.tip(), Some(start));
    f.owner.enabled.store(true, Ordering::Release);
    f.cx.request_cancellation();
    assert!(f.finish(1, f.success(1, false)).is_err());
    assert_eq!(tree(&f.root)?, before);
    f.close();
    let fresh = context(&f.root)?;
    let owner = Owner::new(&f.plan)?;
    owner.deny_after.store(5, Ordering::Release);
    assert!(matches!(
        VerifiedCampaignHistory::inspect(
            &f.root,
            start,
            CampaignHistoryLimits::default(),
            local_limits(),
            &owner,
            &fresh,
            &mut WorkBudget::new(WORK)
        ),
        Err(CampaignHistoryError::Denied)
    ));
    assert!(owner.calls.load(Ordering::Acquire) >= 5);
    assert_eq!(tree(&f.root)?, before);
    Ok(())
}

#[test]
fn whole_inspection_scan_uses_the_same_byte_and_cancellation_allowance_as_hydration() -> Test {
    let mut f = Fixture::new("scan-bound", 1, false)?;
    let start = f.start(1)?;
    // Even unrelated staged objects belong to the inspector's bounded input scan.
    for index in 0..8_u8 {
        f.publisher
            .as_mut()
            .ok_or("publisher")?
            .stage_object(&vec![index; 128 * 1024])?;
    }
    f.close();
    let before = tree(&f.root)?;
    let mut limits = CampaignHistoryLimits::default();
    limits.maximum_metadata_bytes = 512 * 1024;
    assert!(matches!(
        VerifiedCampaignHistory::inspect(
            &f.root,
            start,
            limits,
            local_limits(),
            &f.owner,
            &context(&f.root)?,
            &mut WorkBudget::new(WORK)
        ),
        Err(CampaignHistoryError::Limit)
    ));
    let cancel = AtomicBool::new(true);
    let mut work = WorkBudget::cancellable(WORK, &cancel);
    assert!(matches!(
        VerifiedCampaignHistory::inspect(
            &f.root,
            start,
            CampaignHistoryLimits::default(),
            local_limits(),
            &f.owner,
            &context(&f.root)?,
            &mut work
        ),
        Err(CampaignHistoryError::Denied)
    ));
    assert_eq!(tree(&f.root)?, before);
    Ok(())
}

fn slot(pin: CampaignPin) -> Test<SlotName> {
    let hex = pin
        .approval
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(SlotName::parse(&format!("fssrtch1-{hex}-{}", pin.records))?)
}
