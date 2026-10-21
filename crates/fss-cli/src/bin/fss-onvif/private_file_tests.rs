#![forbid(unsafe_code)]
//! Synthetic native file-boundary tests. Every fixture is create-only beneath a
//! test-owned directory in /tmp; no camera, credentials, or user files are read.

use super::{FILE, InputLease, MAX_FILE_BYTES, Output, absolute_path};
use std::cell::Cell;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

type Test = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Result<Self, std::io::Error> {
        let path = PathBuf::from(format!(
            "/tmp/fss-onvif-private-file-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn file(&self, name: &str, bytes: &[u8]) -> Result<PathBuf, std::io::Error> {
        let path = self.path(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(bytes)?;
        Ok(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn allowed() -> Result<(), &'static str> {
    Ok(())
}

fn private_directory(path: &Path) -> Result<(), std::io::Error> {
    DirBuilder::new().mode(0o700).create(path)
}

#[test]
fn output_roundtrip_is_exact_private_and_revalidated() -> Test {
    let fixture = Fixture::new()?;
    let path = fixture.path("handoff.json");
    let output = Output::prepare(&path, &allowed)?;
    let bytes = b"{\"synthetic_handoff\":\"rtsp://192.0.2.7/live?opaque=canary\"}\n";
    output.write(bytes, &allowed)?;
    let meta = fs::metadata(&path)?;
    assert_eq!(meta.mode() & 0o777, 0o600);
    assert_eq!(meta.nlink(), 1);
    assert_eq!(meta.len(), bytes.len() as u64);
    let input = InputLease::open(&path, &allowed)?;
    assert_eq!(input.bytes(), bytes);
    input.revalidate(&allowed)?;
    Ok(())
}

#[test]
fn existing_or_raced_output_is_never_overwritten() -> Test {
    let fixture = Fixture::new()?;
    let existing = fixture.file("existing.json", b"existing operator data")?;
    assert!(Output::prepare(&existing, &allowed).is_err());
    assert_eq!(fs::read(&existing)?, b"existing operator data");

    let path = fixture.path("raced.json");
    let output = Output::prepare(&path, &allowed)?;
    fixture.file("raced.json", b"another owner's completed output")?;
    assert_eq!(output.write(b"new output", &allowed), Err(FILE));
    assert_eq!(fs::read(&path)?, b"another owner's completed output");
    Ok(())
}

#[test]
fn input_refuses_symlinks_hardlinks_and_nonprivate_permissions() -> Test {
    let fixture = Fixture::new()?;
    let target = fixture.file("target.json", b"synthetic private metadata")?;
    let link = fixture.path("link.json");
    symlink(&target, &link)?;
    assert!(InputLease::open(&link, &allowed).is_err());

    let alias = fixture.path("alias.json");
    fs::hard_link(&target, &alias)?;
    assert!(InputLease::open(&target, &allowed).is_err());
    assert!(InputLease::open(&alias, &allowed).is_err());
    fs::remove_file(&alias)?;

    fs::set_permissions(&target, fs::Permissions::from_mode(0o640))?;
    assert!(InputLease::open(&target, &allowed).is_err());
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        InputLease::open(&target, &allowed)?.bytes(),
        b"synthetic private metadata"
    );

    let parent = fixture.path("private");
    private_directory(&parent)?;
    let child = parent.join("child.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&child)?;
    file.write_all(b"child")?;
    let directory_link = fixture.path("directory-link");
    symlink(&parent, &directory_link)?;
    assert!(InputLease::open(&directory_link.join("child.json"), &allowed).is_err());
    assert!(Output::prepare(&directory_link.join("output.json"), &allowed).is_err());
    Ok(())
}

#[test]
fn input_limit_and_identity_changes_fail_before_use() -> Test {
    let fixture = Fixture::new()?;
    let empty = fixture.file("empty", b"")?;
    assert!(InputLease::open(&empty, &allowed).is_err());
    let too_large = fixture.file("large", &vec![b'x'; MAX_FILE_BYTES + 1])?;
    assert!(InputLease::open(&too_large, &allowed).is_err());
    let maximum = fixture.file("maximum", &vec![b'x'; MAX_FILE_BYTES])?;
    assert_eq!(
        InputLease::open(&maximum, &allowed)?.bytes().len(),
        MAX_FILE_BYTES
    );

    let changed = fixture.file("changed", b"original")?;
    let lease = InputLease::open(&changed, &allowed)?;
    fs::write(&changed, b"changed-length")?;
    assert_eq!(lease.revalidate(&allowed), Err(FILE));
    assert_eq!(lease.bytes(), b"original");

    let replaced = fixture.file("replaced", b"same bytes")?;
    let lease = InputLease::open(&replaced, &allowed)?;
    fs::rename(&replaced, fixture.path("old-inode"))?;
    fixture.file("replaced", b"same bytes")?;
    assert_eq!(lease.revalidate(&allowed), Err(FILE));
    Ok(())
}

#[test]
fn cancellation_never_returns_a_completed_input_or_output() -> Test {
    const CANCELLED: &str = "synthetic-owner-cancelled";
    let fixture = Fixture::new()?;
    let input = fixture.file("input.json", b"synthetic metadata")?;
    let denied = || Err(CANCELLED);
    assert!(matches!(InputLease::open(&input, &denied), Err(CANCELLED)));
    assert!(matches!(
        Output::prepare(&fixture.path("denied"), &denied),
        Err(CANCELLED)
    ));
    assert!(!fixture.path("denied").exists());

    let path = fixture.path("cancelled-after-write.json");
    let output = Output::prepare(&path, &allowed)?;
    let bytes = b"complete bytes do not override cancellation";
    let stopped = Cell::new(false);
    let check = || {
        if fs::metadata(&path).is_ok_and(|meta| meta.len() == bytes.len() as u64) {
            stopped.set(true);
            Err(CANCELLED)
        } else {
            Ok(())
        }
    };
    assert_eq!(output.write(bytes, &check), Err(CANCELLED));
    assert!(stopped.get());
    Ok(())
}

#[test]
fn concurrent_same_inode_tampering_cannot_pass_output_readback() -> Test {
    let fixture = Fixture::new()?;
    let path = fixture.path("tampered.json");
    let output = Output::prepare(&path, &allowed)?;
    let intended = b"intended synthetic handoff bytes";
    let tampered = vec![b'!'; intended.len()];
    let injected = Cell::new(false);
    let check = || {
        if !injected.get()
            && fs::metadata(&path).is_ok_and(|meta| meta.len() == intended.len() as u64)
        {
            injected.set(true);
            // Preserve inode and length. Metadata comparison between held and
            // named handles alone would accept this changed file.
            fs::write(&path, &tampered).map_err(|_| "synthetic-injection-failed")?;
        }
        Ok(())
    };
    assert_eq!(output.write(intended, &check), Err(FILE));
    assert!(injected.get());
    assert_eq!(fs::read(&path)?, tampered);
    Ok(())
}

#[test]
fn write_refuses_permissions_or_hardlinks_changed_after_creation() -> Test {
    let fixture = Fixture::new()?;
    for hardlink in [false, true] {
        let path = fixture.path(if hardlink {
            "linked-output"
        } else {
            "public-output"
        });
        let output = Output::prepare(&path, &allowed)?;
        let injected = Cell::new(false);
        let check = || {
            if !injected.get() && path.exists() {
                injected.set(true);
                if hardlink {
                    fs::hard_link(&path, fixture.path("new-hardlink"))
                        .map_err(|_| "synthetic-injection-failed")?;
                } else {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
                        .map_err(|_| "synthetic-injection-failed")?;
                }
            }
            Ok(())
        };
        assert_eq!(output.write(b"private URI canary", &check), Err(FILE));
        assert!(injected.get());
        assert_eq!(fs::metadata(&path)?.len(), 0);
    }
    Ok(())
}

#[test]
fn parent_replacement_is_refused_and_never_redirects_output() -> Test {
    let fixture = Fixture::new()?;
    let parent = fixture.path("original-parent");
    private_directory(&parent)?;
    let path = parent.join("receipt.json");
    let output = Output::prepare(&path, &allowed)?;
    let moved = fixture.path("moved-parent");
    let injected = Cell::new(false);
    let check = || {
        if !injected.get() && path.exists() {
            injected.set(true);
            fs::rename(&parent, &moved).map_err(|_| "synthetic-injection-failed")?;
            private_directory(&parent).map_err(|_| "synthetic-injection-failed")?;
        }
        Ok(())
    };
    assert_eq!(output.write(b"private URI canary", &check), Err(FILE));
    assert!(injected.get());
    assert!(!path.exists());
    assert_eq!(fs::metadata(moved.join("receipt.json"))?.len(), 0);
    Ok(())
}

#[test]
fn operator_paths_must_be_absolute_and_free_of_traversal() -> Test {
    for path in [
        "",
        "relative.json",
        "/tmp/a/../b",
        "/tmp/./b",
        "/tmp/line\nbreak",
        "/",
    ] {
        assert!(absolute_path(path).is_err());
    }
    assert_eq!(
        absolute_path("/tmp/private-handoff.json")?,
        PathBuf::from("/tmp/private-handoff.json")
    );
    Ok(())
}
