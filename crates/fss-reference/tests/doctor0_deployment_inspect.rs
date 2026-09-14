#![forbid(unsafe_code)]
//! fss-2h5zq.66: a whole deployment (publication root, canonical ledger with an incomplete tail,
//! effect journal with an indeterminate operation and a torn tail) is inspected through every
//! read-only entry point without changing one byte, mode, or timestamp, and each report names
//! exactly what is on disk.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use fss_core::{
    CaptureInterval, ContentDigest, EffectIntent, EffectState, IdempotencyKey, ObligationId,
    OperationId, TimestampNs,
};
use fss_ledger::{
    DurableLedgerLimits, DurableLedgerStatus, DurableReferenceLedger, IncompleteTailPolicy,
};
use fss_object::{HostSpoolIo, ObjectManifest, SpoolLimits};
use fss_publication::{
    LedgeredRootPublisher, LocalPublicationLimits, LocalPublicationState, LocalRootPublisher,
    SlotName, StringLockTableSource, WriterDetectionOptions, inspect_linkage,
};
use fss_reference::{
    DurableEffectError, DurableEffectJournal, EFFECT_RECONCILE_AFFORDANCE, EffectJournalStatus,
    IndeterminateOperationInfo, ObligationCounts,
};

type TestResult = Result<(), Box<dyn Error>>;

const LINEAGE: &str = "site:doctor0";

fn fresh(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("doctor0_deployment_inspect")
        .join(name);
    match fs::remove_dir_all(&base) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::create_dir_all(&base)?;
    Ok(base)
}

/// Digest over relative path, mode, size, mtime, ctime, inode, link count, content, and listing.
fn tree_digest(root: &Path) -> Result<BTreeMap<PathBuf, String>, Box<dyn Error>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path)?;
        let rel = path.strip_prefix(root)?.to_path_buf();
        let common = format!(
            "mode={:o} size={} mtime={}.{} ctime={}.{} ino={} nlink={}",
            meta.mode(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
            meta.ino(),
            meta.nlink()
        );
        let detail = if meta.file_type().is_dir() {
            let mut names = Vec::new();
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                names.push(entry.file_name().to_string_lossy().into_owned());
                pending.push(entry.path());
            }
            names.sort();
            format!("dir [{}]", names.join(","))
        } else {
            format!("file {}", ContentDigest::sha256(&fs::read(&path)?))
        };
        out.insert(rel, format!("{common} {detail}"));
    }
    Ok(out)
}

fn assert_same_tree(label: &str, before: &BTreeMap<PathBuf, String>, root: &Path) -> TestResult {
    let after = tree_digest(root)?;
    if &after != before {
        return Err(format!("tree changed by {label}: before={before:#?} after={after:#?}").into());
    }
    Ok(())
}

fn append(path: &Path, bytes: &[u8]) -> TestResult {
    OpenOptions::new()
        .append(true)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

struct Deployment {
    base: PathBuf,
    publication: PathBuf,
    ledger: PathBuf,
    effects: PathBuf,
    ledger_committed: u64,
    effects_committed: u64,
    operation: OperationId,
}

fn build_deployment(name: &str) -> Result<Deployment, Box<dyn Error>> {
    let base = fresh(name)?;
    let publication = base.join("publication");
    let ledger_path = base.join("ledger.journal");
    let effects = base.join("effects.fssj");
    {
        let mut ledger =
            DurableReferenceLedger::open(&ledger_path, LINEAGE, IncompleteTailPolicy::Reject)?;
        let limits =
            LocalPublicationLimits::new(8, 16, 8, 64, SpoolLimits::new(64, 1 << 20, 4096, 64));
        let mut local = LocalRootPublisher::open(&publication, limits)?;
        let child = local.stage_object(b"clip-event")?;
        let manifest = ObjectManifest::new("event_archive", [child], None)?;
        let interval = CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?;
        LedgeredRootPublisher::new(&mut local, &mut ledger).publish_and_commit(
            &SlotName::parse("event")?,
            &manifest,
            interval,
        )?;
    }
    let operation = OperationId::parse("op:doctor0:1")?;
    {
        let mut journal = DurableEffectJournal::open(&effects, IncompleteTailPolicy::Reject)?;
        let intent = EffectIntent {
            operation_id: operation.clone(),
            idempotency_key: IdempotencyKey::parse("idempotency:doctor0:1")?,
            effect_class: "alert.dispatch".to_string(),
            request_digest: ContentDigest::sha256(b"request"),
            precondition_digest: ContentDigest::sha256(b"precondition"),
        };
        let obligation = ObligationId::parse("obligation:doctor0:1")?;
        let _ = journal.prepare(intent, obligation, "delivery_ack", TimestampNs(100))?;
        let _ = journal.transition(
            &operation,
            EffectState::Committed,
            TimestampNs(110),
            None,
            None,
        )?;
        let _ = journal.mark_indeterminate(&operation, TimestampNs(120), "timeout")?;
    }
    let ledger_committed = fs::metadata(&ledger_path)?.len();
    let effects_committed = fs::metadata(&effects)?.len();
    let ledger_head = fs::read(&ledger_path)?;
    append(&ledger_path, ledger_head.get(..4).ok_or("short ledger")?)?;
    let effects_head = fs::read(&effects)?;
    append(&effects, effects_head.get(..4).ok_or("short journal")?)?;
    Ok(Deployment {
        base,
        publication,
        ledger: ledger_path,
        effects,
        ledger_committed,
        effects_committed,
        operation,
    })
}

#[test]
fn whole_deployment_inspection_is_read_only_and_exact() -> TestResult {
    let deployment = build_deployment("whole")?;
    let base = &deployment.base;
    let before = tree_digest(base)?;

    let limits = LocalPublicationLimits::new(8, 16, 8, 64, SpoolLimits::new(64, 1 << 20, 4096, 64));
    let local = fss_publication::inspect_with_io(
        &HostSpoolIo,
        &deployment.publication,
        limits,
        Some(&StringLockTableSource(String::new())),
        WriterDetectionOptions::default(),
    )?;
    assert_same_tree("local inspect", &before, base)?;
    let ledger =
        fss_ledger::inspect_durable(&deployment.ledger, LINEAGE, DurableLedgerLimits::default())?;
    assert_same_tree("inspect_durable", &before, base)?;
    let effects =
        DurableEffectJournal::inspect(&deployment.effects, DurableLedgerLimits::default())?;
    assert_same_tree("DurableEffectJournal::inspect", &before, base)?;
    let linkage = inspect_linkage(&local, &ledger);
    assert_same_tree("inspect_linkage", &before, base)?;

    assert_eq!(local.report.roots.len(), 1);
    assert_eq!(
        local.report.roots.first().map(|root| root.state),
        Some(LocalPublicationState::Visible)
    );
    assert!(local.durability_not_resynced);

    assert_eq!(ledger.status, DurableLedgerStatus::Present);
    assert_eq!(ledger.batches.len(), 1);
    assert_eq!(ledger.committed_len, deployment.ledger_committed);
    assert_eq!(ledger.incomplete_tail, Some(deployment.ledger_committed));
    assert_eq!(
        linkage.ledger_tail_incomplete,
        Some(deployment.ledger_committed)
    );
    assert_eq!(
        linkage
            .ledgered
            .iter()
            .map(|root| root.slot.as_str().to_owned())
            .collect::<Vec<_>>(),
        vec!["event".to_owned()]
    );
    assert!(linkage.pending.is_empty());

    assert_eq!(effects.status, EffectJournalStatus::Present);
    assert_eq!(effects.incomplete_tail, Some(deployment.effects_committed));
    assert_eq!(effects.foreign_range, None);
    assert_eq!(
        effects.indeterminate_operations,
        vec![IndeterminateOperationInfo {
            operation_id: deployment.operation.clone(),
            reconcile_affordance: EFFECT_RECONCILE_AFFORDANCE.to_string(),
        }]
    );
    assert_eq!(
        effects.obligation_counts,
        ObligationCounts {
            total: 1,
            pending: 0,
            verified: 0,
            failed: 0,
            cancelled: 0,
            indeterminate: 1,
        }
    );
    assert_eq!(effects.obligation_counts.terminal(), 0);
    assert!(!effects.is_clean());
    Ok(())
}

#[test]
fn effect_journal_cap_holds_at_n_and_refuses_n_plus_one() -> TestResult {
    let deployment = build_deployment("effect_cap")?;
    let len = usize::try_from(fs::metadata(&deployment.effects)?.len())?;
    let before = tree_digest(&deployment.base)?;

    let at_n = DurableEffectJournal::inspect(&deployment.effects, len)?;
    assert_eq!(at_n.status, EffectJournalStatus::Present);
    assert_eq!(at_n.indeterminate_operations.len(), 1);
    match DurableEffectJournal::inspect(&deployment.effects, len - 1) {
        Err(DurableEffectError::OverBudget { limit, actual }) => {
            assert_eq!((limit, actual), (len - 1, len));
        }
        other => return Err(format!("expected OverBudget at N+1, got {other:?}").into()),
    }

    let missing = deployment.base.join("missing.fssj");
    let absent = DurableEffectJournal::inspect(&missing, len)?;
    assert_eq!(absent.status, EffectJournalStatus::Absent);
    assert!(absent.journal.is_none());
    assert!(!missing.exists());
    assert_same_tree("effect cap inspections", &before, &deployment.base)?;
    Ok(())
}
