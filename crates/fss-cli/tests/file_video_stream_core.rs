#![forbid(unsafe_code)]
//! Real file ownership and refusal contracts for the native video streaming exporter.

#[path = "../src/bin/fss-file/pgm_stream.rs"]
mod pgm_stream;

use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::ReplayCx;
use pgm_stream::{DEFAULT_OUTPUT_BYTES, PgmExport};
use std::fs;
use std::io;
use std::path::PathBuf;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        for ordinal in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-pgm-stream-{}-{ordinal}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other("fixture directory allowance exceeded"))
    }
    fn context(&self) -> Test<ReplayCx> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:pgm-stream".into(),
            operation_id: OperationId::parse("operation:pgm-stream")?,
            principal: "principal:pgm-stream".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None, priority: 10,
            budgets: BudgetVector::builder().bytes(1024 * 1024).storage_operations(1000).build()?,
            privacy_scope: "privacy:fixture".into(), retention_scope: "retention:fixture".into(),
            anchor_universe: ContentDigest::sha256(b"pgm-stream fixture"), generation: 1,
        })?;
        Ok(ReplayCx::from_context_authority(&authority, self.0.join("deployment"))?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

#[test]
fn export_is_lazy_private_and_byte_exact() -> Test {
    let directory = Directory::new()?;
    let cx = directory.context()?;
    let path = directory.0.join("frames.pgm");
    let mut export = PgmExport::prepare(&path, &directory.0.join("deployment"), DEFAULT_OUTPUT_BYTES, 2, &cx)?;
    assert!(!path.exists());
    export.frame([1, 1], &[23], &cx)?;
    export.frame([1, 1], &[24], &cx)?;
    let receipt = export.finish(&cx)?;
    let expected = b"P5\n1 1\n255\n\x17P5\n1 1\n255\n\x18";
    assert_eq!(fs::read(&path)?, expected);
    assert_eq!(receipt.digest, ContentDigest::sha256(expected));
    assert_eq!(receipt.bytes, 24);
    assert_eq!(receipt.frames, 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    }
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn budget_and_cancellation_do_not_certify_or_erase_the_prefix() -> Test {
    let directory = Directory::new()?;
    let cx = directory.context()?;
    let path = directory.0.join("small.pgm");
    let root = directory.0.join("deployment");
    let mut too_small = PgmExport::prepare(&path, &root, 11, 2, &cx)?;
    assert!(too_small.frame([1, 1], &[23], &cx).is_err());
    assert!(!path.exists());
    assert!(too_small.finish(&cx).is_err());
    let mut export = PgmExport::prepare(&path, &root, 24, 2, &cx)?;
    export.frame([1, 1], &[23], &cx)?;
    let before = fs::read(&path)?;
    cx.request_cancellation();
    assert!(export.frame([1, 1], &[24], &cx).is_err());
    assert!(export.finish(&cx).is_err());
    assert_eq!(fs::read(&path)?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn existing_targets_and_deployment_aliases_are_never_overwritten() -> Test {
    let directory = Directory::new()?;
    let cx = directory.context()?;
    let root = directory.0.join("deployment");
    let path = directory.0.join("existing.pgm");
    fs::write(&path, b"preserved")?;
    assert!(PgmExport::prepare(&path, &root, 100, 2, &cx).is_err());
    assert_eq!(fs::read(&path)?, b"preserved");
    assert!(PgmExport::prepare(&root.join("inside"), &root, 100, 2, &cx).is_err());
    #[cfg(unix)]
    {
        let alias = directory.0.join("alias");
        std::os::unix::fs::symlink(&root, &alias)?;
        assert!(PgmExport::prepare(&alias.join("inside"), &root, 100, 2, &cx).is_err());
        let target = directory.0.join("symlink.pgm");
        std::os::unix::fs::symlink(&path, &target)?;
        assert!(PgmExport::prepare(&target, &root, 100, 2, &cx).is_err());
    }
    assert!(!root.join("inside").exists());
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn renamed_export_parent_refuses_before_first_write() -> Test {
    let directory = Directory::new()?;
    let cx = directory.context()?;
    let root = directory.0.join("deployment");
    let parent = directory.0.join("export");
    let moved = directory.0.join("moved");
    fs::create_dir(&parent)?;
    let mut export = PgmExport::prepare(&parent.join("frames.pgm"), &root, 100, 1, &cx)?;
    fs::rename(&parent, &moved)?;
    fs::create_dir(&parent)?;
    #[cfg(unix)]
    {
        assert!(export.frame([1, 1], &[7], &cx).is_err());
        assert!(!parent.join("frames.pgm").exists());
        assert!(!moved.join("frames.pgm").exists());
    }
    #[cfg(not(unix))]
    drop(export);
    cx.drain_and_finalize();
    Ok(())
}
