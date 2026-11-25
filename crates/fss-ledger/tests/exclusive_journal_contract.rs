#![forbid(unsafe_code)]
//! Actual-file writer ownership, same-handle recovery, and lease release contracts.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_ledger::{AppendPhase, AppendReconciliation, IncompleteTailPolicy, Journal, JournalError};

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Result<Self, Box<dyn Error>> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(1);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-exclusive-journal-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn exclusive_owner_reads_appends_and_blocks_independent_alias_handles() -> Result<(), Box<dyn Error>>
{
    let dir = TestDir::new()?;
    let path = dir.path().join("effects.journal");
    let alias = dir.path().join("effects-alias.journal");
    let mut seed = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    let _ = seed.append(11, b"prepared")?;
    drop(seed);
    fs::hard_link(&path, &alias)?;

    let mut owner = Journal::open_exclusive(&path, IncompleteTailPolicy::Reject)?;
    assert_eq!(owner.verify()?.records()[0].payload(), b"prepared");
    let committed = owner.append(12, b"committed")?;
    for candidate in [&path, &alias] {
        assert!(matches!(
            Journal::open_exclusive(candidate, IncompleteTailPolicy::Truncate),
            Err(JournalError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
    // Read through the locked owner; a separate reader is forbidden on mandatory-lock platforms.
    let report = owner.verify()?;
    assert_eq!(report.records().len(), 2);
    assert_eq!(report.last_root(), committed.root());
    assert_eq!(report.records()[1].payload(), b"committed");
    drop(owner);

    // Dropping the owner releases the actual file lock, including through a hard-link alias.
    let mut reopened = Journal::open_exclusive(&alias, IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.verify()?.records().len(), 2);
    assert_eq!(reopened.append(13, b"accepted")?.sequence(), 3);
    assert_eq!(reopened.verify()?.records().len(), 3);
    Ok(())
}

#[test]
fn contending_opener_cannot_truncate_an_owners_incomplete_append() -> Result<(), Box<dyn Error>> {
    let dir = TestDir::new()?;
    let path = dir.path().join("effects.journal");
    let mut owner = Journal::open_exclusive(&path, IncompleteTailPolicy::Reject)?;
    let _ = owner.append(11, b"prepared")?;
    owner.fail_after_phase(AppendPhase::BodyWrite);
    assert!(matches!(
        owner.append(12, b"uncertain"),
        Err(JournalError::AppendIndeterminate { .. })
    ));
    let before = fs::metadata(&path)?.len();
    assert!(before > owner.committed_len());
    assert!(matches!(
        Journal::open_exclusive(&path, IncompleteTailPolicy::Truncate),
        Err(JournalError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    assert_eq!(fs::metadata(&path)?.len(), before);
    assert_eq!(
        owner.reconcile_pending(IncompleteTailPolicy::Truncate)?,
        AppendReconciliation::NotCommitted { sequence: 2 }
    );
    assert_eq!(owner.verify()?.records().len(), 1);
    Ok(())
}

#[test]
fn rejected_exclusive_recovery_preserves_bytes_and_releases_its_lock() -> Result<(), Box<dyn Error>>
{
    let dir = TestDir::new()?;
    let path = dir.path().join("effects.journal");
    let mut seed = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    let _ = seed.append(11, b"prepared")?;
    drop(seed);
    let mut raw = OpenOptions::new().append(true).open(&path)?;
    raw.write_all(b"F")?;
    raw.sync_all()?;
    drop(raw);
    let before = fs::read(&path)?;
    assert!(matches!(
        Journal::open_exclusive(&path, IncompleteTailPolicy::Reject),
        Err(JournalError::IncompleteTail { .. })
    ));
    assert_eq!(fs::read(&path)?, before);

    // The failed constructor must release the lease; only an explicit later repair truncates.
    let mut repaired = Journal::open_exclusive(&path, IncompleteTailPolicy::Truncate)?;
    assert_eq!(repaired.verify()?.records().len(), 1);
    assert_eq!(repaired.append(12, b"committed")?.sequence(), 2);
    assert_eq!(repaired.verify()?.records().len(), 2);
    Ok(())
}
