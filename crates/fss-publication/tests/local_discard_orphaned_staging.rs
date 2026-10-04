#![forbid(unsafe_code)]
//! `LocalRootPublisher::discard_orphaned_staging` (fss-vmau3): the pass-through to
//! `StagingSpool::discard_orphaned_staging` keeps the spool's contract.
//!
//! Exactly the orphaned staging files classified on open are removed; spool objects and foreign
//! entries are untouched; the spool then reports clean on reopen; a second discard removes
//! nothing. A staging-directory fsync failure after removals is indeterminate: it poisons the
//! spool and the publisher, never reports an empty success on retry, and a reopen reclassifies.
//! Every test owns one real directory under `CARGO_TARGET_TMPDIR`, named after the test.

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fss_core::ContentDigest;
use fss_object::{
    FaultInjectingSpoolIo, SPOOL_STAGING_DIR, SpoolError, SpoolFaultPlan, SpoolIoCall,
    SpoolIoOperation, SpoolLimits,
};
use fss_publication::{
    LOCAL_SPOOL_DIR, LocalPublicationError, LocalPublicationGuidance, LocalPublicationLimits,
    LocalRootPublisher,
};

type TestResult = Result<(), Box<dyn Error>>;

fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("local_discard_orphaned_staging")
        .join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(8, 16, 8, 64, SpoolLimits::new(64, 1 << 20, 4096, 64))
}

fn staging_dir(root: &Path) -> PathBuf {
    root.join(LOCAL_SPOOL_DIR).join(SPOOL_STAGING_DIR)
}

/// The staging name an interrupted ingest of `payload` leaves (`<sha256 hex>.<attempt>.tmp`).
fn staging_name(payload: &[u8], attempt: u32) -> String {
    let digest = ContentDigest::sha256(payload).to_text();
    let hex = digest.strip_prefix("sha256:").unwrap_or(&digest);
    format!("{hex}.{attempt}.tmp")
}

fn dir_names(dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

/// A publisher root with one staged object, two orphaned staging files, and one foreign entry in
/// the staging directory. Returns the staged object's digest, the orphan names, and the foreign
/// name.
fn fixture(root: &Path) -> Result<(ContentDigest, Vec<String>, String), Box<dyn Error>> {
    let mut publisher = LocalRootPublisher::open(root, limits())?;
    let object = publisher.stage_object(b"retained-clip-0001")?;
    drop(publisher);
    let mut orphans = vec![
        staging_name(b"interrupted-ingest-one", 0),
        staging_name(b"interrupted-ingest-two", 3),
    ];
    orphans.sort();
    let staging = staging_dir(root);
    for (index, name) in orphans.iter().enumerate() {
        fs::write(staging.join(name), vec![b'x'; 10 + index])?;
    }
    let foreign = "operator-notes.txt".to_owned();
    fs::write(staging.join(&foreign), b"not a staging file")?;
    Ok((object, orphans, foreign))
}

fn orphan_paths(publisher: &LocalRootPublisher) -> Vec<PathBuf> {
    publisher
        .recovery_report()
        .spool
        .orphaned_staging
        .iter()
        .map(|orphan| orphan.path.clone())
        .collect()
}

#[test]
fn discard_removes_exactly_the_classified_orphans_and_a_second_run_removes_nothing() -> TestResult {
    let root = fresh_root("discard_removes_exactly_the_classified_orphans")?;
    let (object, orphans, foreign) = fixture(&root)?;

    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    let expected: Vec<PathBuf> = orphans
        .iter()
        .map(|name| Path::new(SPOOL_STAGING_DIR).join(name))
        .collect();
    assert_eq!(orphan_paths(&publisher), expected);
    assert_eq!(publisher.spool().orphaned_staging().count(), 2);
    let foreign_before = publisher.recovery_report().spool.foreign.clone();
    assert_eq!(foreign_before.len(), 1);

    let receipt = publisher.discard_orphaned_staging()?;
    assert_eq!(receipt.removed, 2);
    assert_eq!(receipt.released_bytes, 10 + 11);
    assert!(!publisher.is_poisoned());
    assert_eq!(publisher.spool().orphaned_staging().count(), 0);
    // Only the orphans went: the foreign entry and the staged object are untouched.
    assert_eq!(dir_names(&staging_dir(&root))?, vec![foreign.clone()]);
    assert_eq!(
        fs::read(staging_dir(&root).join(&foreign))?,
        b"not a staging file"
    );
    assert!(publisher.spool().state(object).is_some());
    assert_eq!(publisher.spool().read(object)?, b"retained-clip-0001");

    // A second discard on the same instance has nothing left to remove.
    let again = publisher.discard_orphaned_staging()?;
    assert_eq!((again.removed, again.released_bytes), (0, 0));
    drop(publisher);

    // A reopen reports no orphaned staging; the foreign entry is still reported, never deleted.
    let mut reopened = LocalRootPublisher::open(&root, limits())?;
    assert!(orphan_paths(&reopened).is_empty());
    assert_eq!(reopened.recovery_report().spool.foreign, foreign_before);
    assert_eq!(
        reopened.recovery_report().spool.admitted,
        vec![object],
        "the staged object is still admitted"
    );
    let third = reopened.discard_orphaned_staging()?;
    assert_eq!((third.removed, third.released_bytes), (0, 0));
    assert_eq!(dir_names(&staging_dir(&root))?, vec![foreign]);
    Ok(())
}

#[test]
fn an_unconfirmed_staging_fsync_is_indeterminate_and_poisons_the_publisher() -> TestResult {
    let root = fresh_root("an_unconfirmed_staging_fsync_is_indeterminate")?;
    let (_, _, foreign) = fixture(&root)?;
    // Count the directory fsyncs a plain open makes, so the fault lands on the discard's.
    let probe = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
    drop(LocalRootPublisher::open_with_io(
        &root,
        limits(),
        probe.clone(),
    )?);
    let plan = SpoolFaultPlan::new().fail(
        SpoolIoCall::SyncDirectory,
        probe.calls(SpoolIoCall::SyncDirectory) + 1,
        io::ErrorKind::Other,
    );
    let io = Arc::new(FaultInjectingSpoolIo::new(plan));
    let mut publisher = LocalRootPublisher::open_with_io(&root, limits(), io.clone())?;
    assert_eq!(publisher.spool().orphaned_staging().count(), 2);

    let error = match publisher.discard_orphaned_staging() {
        Ok(receipt) => {
            return Err(format!("expected an indeterminate discard, got {receipt:?}").into());
        }
        Err(error) => error,
    };
    assert!(io.all_fired());
    assert_eq!(
        error,
        LocalPublicationError::Spool(SpoolError::DiscardIndeterminate {
            path: staging_dir(&root),
            operation: SpoolIoOperation::SyncDirectory,
            kind: io::ErrorKind::Other,
        })
    );
    assert_eq!(
        error.guidance(),
        LocalPublicationGuidance::ReopenAndReconcile
    );
    assert!(
        publisher.is_poisoned(),
        "an unconfirmed discard must poison the publisher"
    );
    // A retry never reports an empty success for removals that may not be durable.
    assert_eq!(
        publisher.discard_orphaned_staging().err(),
        Some(LocalPublicationError::Poisoned)
    );
    drop(publisher);

    // The reopen reclassifies the staging directory from disk: the unlinks took effect.
    let reopened = LocalRootPublisher::open(&root, limits())?;
    assert!(orphan_paths(&reopened).is_empty());
    assert_eq!(dir_names(&staging_dir(&root))?, vec![foreign]);
    Ok(())
}
