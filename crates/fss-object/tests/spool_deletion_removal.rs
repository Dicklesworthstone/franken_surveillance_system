#![forbid(unsafe_code)]
//! `StagingSpool::remove_for_deletion` (FSS-037 deletion closure): the only removal of a
//! verified, held object. The hold goes first, so an interruption between the two unlinks leaves
//! an unheld object a retry removes, never a hold whose object vanished (which a reopen reports
//! as tampering). Removal is local unlinking and releases exactly the charged quota.

use std::error::Error;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use fss_core::ContentDigest;
use fss_object::{
    CorruptionKind, DeletionRemoval, SPOOL_HOLDS_DIR, SPOOL_OBJECTS_DIR, SpoolError, SpoolLimits,
    SpoolObjectState, StagingSpool,
};

type TestResult = Result<(), Box<dyn Error>>;

const PAYLOAD: &[u8] = b"deletion-closure-capsule-payload";

fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("spool_deletion_removal")
        .join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

fn limits() -> SpoolLimits {
    SpoolLimits::new(64, 1 << 20, 4096, 64)
}

fn hex(digest: ContentDigest) -> String {
    digest.to_text().trim_start_matches("sha256:").to_owned()
}

fn verified(root: &Path) -> Result<(StagingSpool, ContentDigest), Box<dyn Error>> {
    let mut spool = StagingSpool::open(root, limits())?;
    let digest = spool.stage_bytes(PAYLOAD)?.digest;
    assert_eq!(spool.verify(digest)?, SpoolObjectState::Verified);
    Ok((spool, digest))
}

#[test]
fn a_verified_held_object_is_unlinked_with_its_hold_and_its_quota() -> TestResult {
    let root = fresh_root("verified")?;
    let (mut spool, digest) = verified(&root)?;
    let object = root.join(SPOOL_OBJECTS_DIR).join(hex(digest));
    let hold = root.join(SPOOL_HOLDS_DIR).join(hex(digest));
    assert!(object.exists() && hold.exists());
    // An ordinary rollback discard refuses a held object; only a deletion may remove it.
    assert!(matches!(
        spool.discard_staged(digest),
        Err(SpoolError::NotDiscardable { .. } | SpoolError::VerificationHeld { .. })
    ));
    let occupied = spool.occupied_bytes()?;
    let DeletionRemoval::Removed { released_bytes } = spool.remove_for_deletion(digest)? else {
        return Err("expected a removal".into());
    };
    assert!(released_bytes >= PAYLOAD.len() as u64);
    assert_eq!(spool.occupied_bytes()?, occupied - released_bytes);
    assert_eq!(spool.state(digest), None);
    assert!(!object.exists() && !hold.exists());
    assert!(!spool.name_present(digest));
    assert!(matches!(spool.read(digest), Err(SpoolError::Missing(_))));
    // Idempotent: a retry touches nothing.
    assert_eq!(
        spool.remove_for_deletion(digest)?,
        DeletionRemoval::AlreadyAbsent
    );
    drop(spool);
    let reopened = StagingSpool::open(&root, limits())?;
    assert_eq!(reopened.state(digest), None);
    assert!(reopened.recovery_report().is_clean());
    Ok(())
}

#[test]
fn an_interruption_after_the_hold_is_completed_by_a_retry() -> TestResult {
    let root = fresh_root("after-hold")?;
    let (spool, digest) = verified(&root)?;
    drop(spool);
    // The state a process death leaves between the two unlinks: hold gone, object present.
    fs::remove_file(root.join(SPOOL_HOLDS_DIR).join(hex(digest)))?;
    let mut spool = StagingSpool::open(&root, limits())?;
    assert_eq!(spool.state(digest), Some(SpoolObjectState::Staged));
    assert!(
        spool.recovery_report().is_clean(),
        "an unheld object is not tampering"
    );
    assert!(spool.name_present(digest));
    assert!(matches!(
        spool.remove_for_deletion(digest)?,
        DeletionRemoval::Removed { .. }
    ));
    drop(spool);
    let reopened = StagingSpool::open(&root, limits())?;
    assert_eq!(reopened.state(digest), None);
    assert!(reopened.recovery_report().is_clean());
    Ok(())
}

#[test]
fn a_vanished_held_object_is_reported_and_its_hold_is_removed_by_deletion() -> TestResult {
    let root = fresh_root("vanished")?;
    let (spool, digest) = verified(&root)?;
    drop(spool);
    // The opposite order (object first) would leave this: a reopen reports tampering.
    fs::remove_file(root.join(SPOOL_OBJECTS_DIR).join(hex(digest)))?;
    let mut spool = StagingSpool::open(&root, limits())?;
    assert_eq!(
        spool.state(digest),
        Some(SpoolObjectState::Corrupt(CorruptionKind::Vanished))
    );
    assert!(!spool.recovery_report().is_clean());
    assert!(matches!(
        spool.remove_for_deletion(digest)?,
        DeletionRemoval::Removed { .. }
    ));
    drop(spool);
    let reopened = StagingSpool::open(&root, limits())?;
    assert_eq!(reopened.state(digest), None);
    assert!(reopened.recovery_report().is_clean());
    Ok(())
}
