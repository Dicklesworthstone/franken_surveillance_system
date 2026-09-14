#![forbid(unsafe_code)]
//! Contract probe for fss-2h5zq.66 DurableEffectJournal::inspect.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use fss_core::{
    ContentDigest, EffectIntent, EffectState, IdempotencyKey, ObligationId, OperationId,
    TimestampNs,
};
use fss_ledger::IncompleteTailPolicy;
use fss_reference::{DurableEffectError, DurableEffectJournal, EffectJournalStatus};

fn dir_digest(dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut out = Vec::new();
    let meta = fs::symlink_metadata(dir)?;
    out.push(format!(
        ". mtime={}.{} ctime={}.{}",
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec()
    ));
    let mut entries: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir)? {
        entries.push(entry?.path());
    }
    entries.sort();
    for p in entries {
        let m = fs::symlink_metadata(&p)?;
        out.push(format!(
            "{} mode={:o} size={} mtime={}.{} ctime={}.{} ino={} {}",
            p.display(),
            m.mode(),
            m.size(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
            m.ino(),
            ContentDigest::sha256(&fs::read(&p)?)
        ));
    }
    Ok(out)
}

#[test]
fn r66_effect_inspect_probe() -> Result<(), Box<dyn Error>> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("r66_effect_probe");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    let path = dir.join("effects.fssj");
    let op = OperationId::parse("op:r66:1")?;
    let obl = ObligationId::parse("obligation:r66:1")?;
    let intent = EffectIntent {
        operation_id: op.clone(),
        idempotency_key: IdempotencyKey::parse("idempotency:r66:1")?,
        effect_class: "alert.dispatch".to_string(),
        request_digest: ContentDigest::sha256(b"r"),
        precondition_digest: ContentDigest::sha256(b"p"),
    };
    {
        let mut j = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = j.prepare(intent, obl, "delivery_ack", TimestampNs(100))?;
        let _ = j.transition(&op, EffectState::Committed, TimestampNs(110), None, None)?;
        let _ = j.mark_indeterminate(&op, TimestampNs(120), "timeout")?;
    }
    let head = fs::read(&path)?;
    {
        let mut f = OpenOptions::new().append(true).open(&path)?;
        f.write_all(&head[..4])?; // torn tail
    }
    let before = dir_digest(&dir)?;
    let r = DurableEffectJournal::inspect(&path, 1 << 20)?;
    assert_eq!(r.status, EffectJournalStatus::Present);
    assert!(r.incomplete_tail.is_some());
    assert_eq!(r.obligation_counts.total, 1);
    assert!(!r.indeterminate_operations.is_empty());
    assert_eq!(r.indeterminate_operations[0].operation_id, op);
    assert_eq!(
        r.indeterminate_operations[0].reconcile_affordance,
        fss_reference::EFFECT_RECONCILE_AFFORDANCE
    );

    let after = dir_digest(&dir)?;
    eprintln!("R66 EFFECT tree identical={}", before == after);
    assert_eq!(before, after);

    let missing = dir.join("missing.fssj");
    let r2 = DurableEffectJournal::inspect(&missing, 1 << 20)?;
    assert_eq!(r2.status, EffectJournalStatus::Absent);
    assert!(!missing.exists());

    // Limits at N and N+1
    let tight = DurableEffectJournal::inspect(&path, 10);
    assert!(matches!(tight, Err(DurableEffectError::OverBudget { .. })));

    Ok(())
}
