#![forbid(unsafe_code)]
//! Recovery inventory retains strict journal truth without depending on source-object custody.

use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, EffectIntent, EffectState, IdempotencyKey,
    ObligationId, OperationId, RootAuthoritySpec, TimestampNs,
};
use fss_ledger::{HostJournalReadIo, JournalFileMetadata, JournalReadIo};
use fss_reference::agent_orient::{OrientLimits, read_deployment};
use fss_reference::alert_control::status::{
    StatusError, read_alert_operations, read_alert_operations_with_io,
};
use fss_reference::{REFERENCE_ALERT_TERMINAL_PREDICATE, ReferenceDeployment, ReplayCx};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:alert-operation-status";
const OPERATION: &str = "operation:alert:status-recovery";

struct Directory(PathBuf);

impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-alert-status-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture(root: &Path) -> TestResult {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:alert-status-contract".into(),
        operation_id: OperationId::parse("operation:alert-status-contract")?,
        principal: "principal:local-owner".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(8 * 1024 * 1024)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.to_path_buf())?;
    let mut deployment = ReferenceDeployment::open(root, SITE, &cx)?;
    let id = OperationId::parse(OPERATION)?;
    let journal = deployment.effects_and_ledger().0;
    journal.prepare(
        EffectIntent::new(
            id.clone(),
            IdempotencyKey::parse("idempotency:alert:status-recovery")?,
            "alert.dispatch",
            ContentDigest::sha256(b"request"),
            ContentDigest::sha256(b"preconditions"),
        )?,
        ObligationId::parse("obligation:alert:status-recovery")?,
        REFERENCE_ALERT_TERMINAL_PREDICATE,
        TimestampNs(100),
    )?;
    journal.transition(&id, EffectState::Committed, TimestampNs(101), None, None)?;
    drop(deployment);
    cx.drain_and_finalize();
    Ok(())
}

/// Refuses every payload read outside the three declared inventory files.
struct InventoryIo<'a> {
    root: &'a Path,
    change: Option<&'a str>,
    changed_reads: AtomicUsize,
    reads: AtomicUsize,
}

impl InventoryIo<'_> {
    fn admitted(&self, path: &Path) -> bool {
        ["LAYOUT", "ledger/journal.fssj", "effects/journal.fssj"]
            .iter()
            .any(|relative| path == self.root.join(relative))
    }
}

impl JournalReadIo for InventoryIo<'_> {
    fn symlink_metadata(&self, path: &Path) -> io::Result<JournalFileMetadata> {
        if path != self.root && !self.admitted(path) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        HostJournalReadIo.symlink_metadata(path)
    }

    fn read_bounded(&self, path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
        if !self.admitted(path) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        self.reads.fetch_add(1, Ordering::SeqCst);
        let mut bytes = HostJournalReadIo.read_bounded(path, maximum)?;
        if self
            .change
            .is_some_and(|relative| path == self.root.join(relative))
            && self.changed_reads.fetch_add(1, Ordering::SeqCst) == 1
        {
            bytes.push(0);
        }
        Ok(bytes)
    }
}

#[test]
fn journal_only_inventory_matches_existing_roots_without_triggering_recovery() -> TestResult {
    let directory = Directory::new("journal-only")?;
    fixture(&directory.0)?;
    let full = read_deployment(&directory.0, &OrientLimits::default())?;
    let before = fs::read(directory.0.join("effects/journal.fssj"))?;
    let io = InventoryIo {
        root: &directory.0,
        change: None,
        changed_reads: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
    };
    let snapshot = read_alert_operations_with_io(&io, &directory.0)?;
    assert_eq!(snapshot.anchor, full.anchor);
    assert_eq!(snapshot.effect_journal_root, full.effect_journal_root);
    assert_eq!(snapshot.operations, full.operations);
    assert_eq!(snapshot.obligations, full.obligations);
    assert!(snapshot.complete_committed_snapshot());
    assert_eq!(snapshot.operations.len(), 1);
    assert_eq!(
        snapshot.operations.first().map(|op| op.state),
        Some(EffectState::Committed)
    );
    assert_eq!(io.reads.load(Ordering::SeqCst), 6);
    assert_eq!(before, fs::read(directory.0.join("effects/journal.fssj"))?);
    Ok(())
}

#[test]
fn changes_to_any_snapshot_input_are_refused_before_returning_an_inventory() -> TestResult {
    let directory = Directory::new("changed")?;
    fixture(&directory.0)?;
    for change in ["LAYOUT", "ledger/journal.fssj", "effects/journal.fssj"] {
        let io = InventoryIo {
            root: &directory.0,
            change: Some(change),
            changed_reads: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
        };
        assert!(
            matches!(
                read_alert_operations_with_io(&io, &directory.0),
                Err(StatusError::Changed)
            ),
            "changed {change} was accepted"
        );
    }
    Ok(())
}

#[test]
fn missing_journals_and_uncommitted_tails_never_claim_a_complete_inventory() -> TestResult {
    for relative in ["ledger/journal.fssj", "effects/journal.fssj"] {
        let directory = Directory::new("absent")?;
        fixture(&directory.0)?;
        let path = directory.0.join(relative);
        let original = fs::read(&path)?;
        fs::remove_file(&path)?;
        let absent = read_alert_operations(&directory.0)?;
        assert!(!absent.complete_committed_snapshot());
        assert_eq!(
            absent.ledger_journal_present,
            relative != "ledger/journal.fssj"
        );
        assert_eq!(
            absent.effect_journal_present,
            relative != "effects/journal.fssj"
        );
        assert_eq!(
            absent.operations.len(),
            usize::from(relative != "effects/journal.fssj")
        );
        assert!(!path.exists(), "status recreated the missing journal");
        fs::write(&path, original)?;
        fs::OpenOptions::new()
            .append(true)
            .open(&path)?
            .write_all(b"FSSJRN01")?;
        let before = fs::read(&path)?;
        let torn = read_alert_operations(&directory.0)?;
        assert!(!torn.complete_committed_snapshot());
        assert_eq!(torn.operations.len(), 1);
        assert_eq!(
            torn.ledger_tail_uncommitted,
            relative == "ledger/journal.fssj"
        );
        assert_eq!(
            torn.effect_tail_uncommitted,
            relative == "effects/journal.fssj"
        );
        assert_eq!(
            before,
            fs::read(&path)?,
            "status repaired an uncommitted suffix"
        );
    }
    Ok(())
}

struct OversizedIo<'a> {
    root: &'a Path,
    relative: &'a str,
    grow_after_metadata: bool,
    oversized_reads: AtomicUsize,
}

impl JournalReadIo for OversizedIo<'_> {
    fn symlink_metadata(&self, path: &Path) -> io::Result<JournalFileMetadata> {
        let mut metadata = HostJournalReadIo.symlink_metadata(path)?;
        if path == self.root.join(self.relative) && !self.grow_after_metadata {
            metadata.len = 64 * 1024 * 1024 + 1;
        }
        Ok(metadata)
    }

    fn read_bounded(&self, path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
        if path == self.root.join(self.relative) {
            self.oversized_reads.fetch_add(1, Ordering::SeqCst);
            if self.grow_after_metadata {
                return Ok(vec![0; maximum]);
            }
        }
        HostJournalReadIo.read_bounded(path, maximum)
    }
}

#[test]
fn oversize_inputs_are_refused_before_their_contents_are_allocated() -> TestResult {
    let directory = Directory::new("bounds")?;
    fixture(&directory.0)?;
    for relative in ["LAYOUT", "ledger/journal.fssj", "effects/journal.fssj"] {
        let io = OversizedIo {
            root: &directory.0,
            relative,
            grow_after_metadata: false,
            oversized_reads: AtomicUsize::new(0),
        };
        assert!(matches!(
            read_alert_operations_with_io(&io, &directory.0),
            Err(StatusError::OverBudget)
        ));
        assert_eq!(io.oversized_reads.load(Ordering::SeqCst), 0);
    }
    let growing = OversizedIo {
        root: &directory.0,
        relative: "LAYOUT",
        grow_after_metadata: true,
        oversized_reads: AtomicUsize::new(0),
    };
    assert!(matches!(
        read_alert_operations_with_io(&growing, &directory.0),
        Err(StatusError::OverBudget)
    ));
    assert_eq!(growing.oversized_reads.load(Ordering::SeqCst), 1);
    Ok(())
}
