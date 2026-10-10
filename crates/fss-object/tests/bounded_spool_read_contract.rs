#![forbid(unsafe_code)]
//! Caller-specific reads narrow allocation without changing spool authority or index state.

use fss_core::ContentDigest;
use fss_object::{SpoolError, SpoolLimits, SpoolObjectState, StagingSpool};
use std::fs;
use std::path::{Path, PathBuf};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn root(name: &str) -> Test<PathBuf> {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("bounded_spool_read").join(name);
    match fs::remove_dir_all(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(path)
}
fn limits() -> SpoolLimits { SpoolLimits::new(16, 64 * 1024, 4096, 64) }

#[test]
fn narrower_read_refuses_oversize_without_poisoning_or_promoting_the_object() -> Test {
    let path = root("narrower")?;
    let mut spool = StagingSpool::open(&path, limits())?;
    let bytes = vec![73; 4096];
    let digest = spool.stage_bytes(&bytes)?.digest;
    assert!(spool.read_bounded(digest, 4095).is_err());
    assert_eq!(spool.state(digest), Some(SpoolObjectState::Staged));
    assert_eq!(spool.read_bounded(digest, 4096)?, bytes);
    assert_eq!(spool.read_bounded(digest, usize::MAX)?, bytes);
    assert_eq!(spool.state(digest), Some(SpoolObjectState::Staged));
    spool.verify(digest)?;
    assert!(spool.read_bounded(digest, 0).is_err());
    assert_eq!(spool.state(digest), Some(SpoolObjectState::Verified));
    assert_eq!(spool.read(digest)?, bytes);
    assert_eq!(spool.object_count(), 1);
    assert_eq!(spool.occupied_bytes()?, 4096);
    Ok(())
}

#[test]
fn bounded_read_rechecks_actual_custody_and_cannot_admit_an_unindexed_file() -> Test {
    let path = root("custody")?;
    let mut spool = StagingSpool::open(&path, limits())?;
    let digest = spool.stage_bytes(b"retained source")?.digest;
    spool.verify(digest)?;
    fs::write(spool.object_path(digest), b"modified after verification")?;
    assert!(spool.read_bounded(digest, 4096).is_err());
    let missing = ContentDigest::sha256(b"not indexed");
    fs::write(spool.object_path(missing), b"not indexed")?;
    assert!(matches!(spool.read_bounded(missing, 4096), Err(SpoolError::Missing(d)) if d == missing));
    assert_eq!(spool.object_count(), 1);
    drop(spool);
    assert!(StagingSpool::open(&path, limits())?.read_bounded(digest, 4096).is_err());
    Ok(())
}
