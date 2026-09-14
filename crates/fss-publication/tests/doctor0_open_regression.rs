#![forbid(unsafe_code)]
//! Regression guard for fss-2h5zq.66: splitting a read-only classifier out of
//! `LocalRootPublisher::open` must not change what the mutating open does.
//!
//! Every expectation here is hand-derived from the fixture (payload digests, manifest roots, the
//! record bytes on disk) and the open's documented rules; none of it is computed by the shared
//! classifier. The file uses only API that existed before inspection, so it runs unchanged
//! against the pre-inspection open (main f2f6288) as the independent differential.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{self, DirEntry, File, FileType, Metadata, ReadDir, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::{
    CorruptObject, CorruptionKind, HostSpoolIo, ObjectManifest, OrphanedStaging, SPOOL_STAGING_DIR,
    SpoolError, SpoolIo, SpoolLimits, SpoolObjectState, SpoolRecoveryReport, StagingSpool,
};
use fss_publication::{
    BlockReason, BrokenRoot, BrokenRootReason, LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR,
    LocalPublicationLimits, LocalPublicationState, LocalRecoveryReport, LocalRootPublisher,
    ROOT_INDETERMINATE_SUFFIX, ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, ReferenceRole, SlotName,
    VisibleRoot, root_record_bytes,
};

type TestResult = Result<(), Box<dyn Error>>;

fn fresh_root(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("doctor0_open_regression")
        .join(name);
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

fn slot(name: &str) -> Result<SlotName, Box<dyn Error>> {
    Ok(SlotName::parse(name)?)
}

fn roots_entry(root: &Path, name: &str) -> PathBuf {
    root.join(LOCAL_ROOTS_DIR).join(name)
}

fn hex(digest: ContentDigest) -> String {
    digest
        .to_text()
        .split_once(':')
        .map(|(_, hex)| hex.to_owned())
        .unwrap_or_default()
}

fn flip_last_byte(path: &Path) -> TestResult {
    let mut bytes = fs::read(path)?;
    let last = bytes.last_mut().ok_or("empty object file")?;
    *last ^= 0x01;
    fs::write(path, bytes)?;
    Ok(())
}

/// Digests sorted the way the spool lists object files: by lowercase hex name.
fn by_hex(mut digests: Vec<ContentDigest>) -> Vec<ContentDigest> {
    digests.sort_by_key(|digest| hex(*digest));
    digests
}

/// (b) Byte-for-byte recovery report of the mutating open on a full fixture: a good root, a root
/// whose child is corrupt, a root under an indeterminate marker, an undecodable record, an orphan
/// temp, a redundant temp, orphaned staging, a foreign entry, and an unreferenced object.
#[test]
fn open_recovery_report_matches_hand_derived_literal() -> TestResult {
    let root = fresh_root("full_fixture")?;
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    let a = publisher.stage_object(b"clip-a")?;
    let b = publisher.stage_object(b"clip-b")?;
    let good = ObjectManifest::new("event_archive", [a, b], None)?;
    publisher.publish(&slot("good")?, &good)?;
    let c = publisher.stage_object(b"clip-victim")?;
    let victim = ObjectManifest::new("event_archive", [c], None)?;
    publisher.publish(&slot("victim")?, &victim)?;
    let d = publisher.stage_object(b"clip-limbo")?;
    let limbo = ObjectManifest::new("event_archive", [d], None)?;
    publisher.publish(&slot("limbo")?, &limbo)?;
    let u = publisher.stage_object(b"unreferenced")?;
    let victim_path = publisher.spool().object_path(c);
    drop(publisher);

    // Independent expectations from the payloads themselves.
    assert_eq!(a, ContentDigest::sha256(b"clip-a"));
    assert_eq!(c, ContentDigest::sha256(b"clip-victim"));
    assert_eq!(good.root(), ContentDigest::sha256(&good.canonical_bytes()));

    flip_last_byte(&victim_path)?; // "clip-victim" -> "clip-victil"
    fs::copy(
        roots_entry(&root, &format!("good{ROOT_RECORD_SUFFIX}")),
        roots_entry(
            &root,
            &format!("good{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}"),
        ),
    )?;
    fs::write(
        roots_entry(
            &root,
            &format!("ghost{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}"),
        ),
        b"partial",
    )?;
    fs::write(
        roots_entry(
            &root,
            &format!("limbo{ROOT_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}"),
        ),
        b"",
    )?;
    fs::write(
        roots_entry(&root, &format!("bad{ROOT_RECORD_SUFFIX}")),
        b"not a root record",
    )?;
    fs::write(root.join("junk.txt"), b"x")?;
    let staging_name = format!("{}.0.tmp", hex(u));
    fs::write(
        root.join(LOCAL_SPOOL_DIR)
            .join(SPOOL_STAGING_DIR)
            .join(&staging_name),
        b"orphan",
    )?;
    let good_record = fs::read(roots_entry(&root, &format!("good{ROOT_RECORD_SUFFIX}")))?;

    let publisher = LocalRootPublisher::open(&root, limits())?;

    let expected = LocalRecoveryReport {
        spool: SpoolRecoveryReport {
            admitted: by_hex(vec![a, b, d, u, good.root(), victim.root(), limbo.root()]),
            corrupt: vec![CorruptObject {
                digest: c,
                kind: CorruptionKind::ContentDigestMismatch {
                    computed: ContentDigest::sha256(b"clip-victil"),
                },
            }],
            orphaned_staging: vec![OrphanedStaging {
                path: Path::new(SPOOL_STAGING_DIR).join(&staging_name),
                bytes: 6,
                claimed_digest: u,
            }],
            foreign: Vec::new(),
        },
        roots: vec![VisibleRoot {
            slot: slot("good")?,
            root: good.root(),
            record_digest: ContentDigest::sha256(&good_record),
            child_count: 2,
            state: LocalPublicationState::Durable,
        }],
        broken_roots: vec![
            BrokenRoot {
                path: Path::new(LOCAL_ROOTS_DIR).join(format!("bad{ROOT_RECORD_SUFFIX}")),
                reason: BrokenRootReason::Undecodable,
            },
            BrokenRoot {
                path: Path::new(LOCAL_ROOTS_DIR).join(format!(
                    "limbo{ROOT_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}"
                )),
                reason: BrokenRootReason::VisibilityIndeterminate {
                    record_present: true,
                },
            },
            BrokenRoot {
                path: Path::new(LOCAL_ROOTS_DIR).join(format!("victim{ROOT_RECORD_SUFFIX}")),
                reason: BrokenRootReason::ReferenceBlocked {
                    object: c,
                    role: ReferenceRole::Child,
                    reason: BlockReason::Corrupt,
                },
            },
        ],
        orphaned_temps: vec![
            Path::new(LOCAL_ROOTS_DIR).join(format!("ghost{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}")),
        ],
        unreferenced_objects: [c, d, u, victim.root(), limbo.root()]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        tombstones: Vec::new(),
        foreign: vec![PathBuf::from("junk.txt")],
    };
    assert_eq!(publisher.recovery_report(), &expected);

    // The open deletes the redundant temp and keeps the orphan one.
    assert!(
        !roots_entry(
            &root,
            &format!("good{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}")
        )
        .exists()
    );
    assert!(
        roots_entry(
            &root,
            &format!("ghost{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}")
        )
        .exists()
    );

    // Spool states the open leaves: every reference it checked is verified (and held), the
    // corrupt child is never laundered, and objects it never reached stay staged.
    let spool = publisher.spool();
    assert_eq!(spool.state(a), Some(SpoolObjectState::Verified));
    assert_eq!(spool.state(b), Some(SpoolObjectState::Verified));
    assert_eq!(spool.state(good.root()), Some(SpoolObjectState::Verified));
    assert_eq!(spool.state(victim.root()), Some(SpoolObjectState::Verified));
    assert_eq!(spool.state(limbo.root()), Some(SpoolObjectState::Verified));
    assert_eq!(
        spool.state(c),
        Some(SpoolObjectState::Corrupt(
            CorruptionKind::ContentDigestMismatch {
                computed: ContentDigest::sha256(b"clip-victil"),
            }
        ))
    );
    assert_eq!(spool.state(d), Some(SpoolObjectState::Staged));
    assert_eq!(spool.state(u), Some(SpoolObjectState::Staged));
    Ok(())
}

/// (a) A broken root's manifest is verified, and therefore durably held, by the open even when
/// it never had a hold before. Reopened alone the spool reports it `Staged`: the hold, not the
/// object state, is what refuses the discard.
#[test]
fn open_holds_the_manifest_of_an_indeterminate_root() -> TestResult {
    let root = fresh_root("held_manifest")?;
    drop(LocalRootPublisher::open(&root, limits())?);
    let manifest = {
        let mut spool = StagingSpool::open(root.join(LOCAL_SPOOL_DIR), limits().spool)?;
        let child = spool.stage_bytes(b"held-child")?.digest;
        spool.verify(child)?;
        let manifest = ObjectManifest::new("event_archive", [child], None)?;
        let body = spool.stage_bytes(&manifest.canonical_bytes())?;
        assert_eq!(body.digest, manifest.root());
        // Never verified: no hold exists yet.
        assert_eq!(spool.state(manifest.root()), Some(SpoolObjectState::Staged));
        manifest
    };
    let held = slot("held")?;
    fs::write(
        roots_entry(&root, &format!("held{ROOT_RECORD_SUFFIX}")),
        root_record_bytes(&held, manifest.root(), 1)?,
    )?;
    fs::write(
        roots_entry(
            &root,
            &format!("held{ROOT_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}"),
        ),
        b"",
    )?;

    {
        let publisher = LocalRootPublisher::open(&root, limits())?;
        assert_eq!(
            publisher.recovery_report().broken_roots,
            vec![BrokenRoot {
                path: Path::new(LOCAL_ROOTS_DIR).join(format!(
                    "held{ROOT_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}"
                )),
                reason: BrokenRootReason::VisibilityIndeterminate {
                    record_present: true,
                },
            }]
        );
        assert!(publisher.recovery_report().roots.is_empty());
        assert_eq!(
            publisher.spool().state(manifest.root()),
            Some(SpoolObjectState::Verified)
        );
    }

    let mut spool = StagingSpool::open(root.join(LOCAL_SPOOL_DIR), limits().spool)?;
    assert_eq!(spool.state(manifest.root()), Some(SpoolObjectState::Staged));
    match spool.discard_staged(manifest.root()) {
        Err(SpoolError::VerificationHeld { digest }) => assert_eq!(digest, manifest.root()),
        other => return Err(format!("expected VerificationHeld, got {other:?}").into()),
    }
    Ok(())
}

/// Host I/O that corrupts one object file on disk just before its second open-for-read: after
/// the spool classified it as intact, before the publication open verifies it.
#[derive(Debug)]
struct CorruptOnSecondRead {
    target: PathBuf,
    reads: AtomicU64,
}

impl SpoolIo for CorruptOnSecondRead {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.create_dir_all(path)
    }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        HostSpoolIo.metadata(path)
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        HostSpoolIo.symlink_metadata(path)
    }
    fn open_lock(&self, path: &Path) -> io::Result<File> {
        HostSpoolIo.open_lock(path)
    }
    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        HostSpoolIo.try_lock(file)
    }
    fn create_dir(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.create_dir(path)
    }
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        HostSpoolIo.read_dir(path)
    }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        HostSpoolIo.next_dir_entry(entries)
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        HostSpoolIo.entry_file_type(entry)
    }
    fn create_new(&self, path: &Path) -> io::Result<File> {
        HostSpoolIo.create_new(path)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        HostSpoolIo.write(file, bytes)
    }
    fn sync_file(&self, file: &File) -> io::Result<()> {
        HostSpoolIo.sync_file(file)
    }
    fn open_read(&self, path: &Path) -> io::Result<File> {
        if path == self.target && self.reads.fetch_add(1, Ordering::SeqCst) == 1 {
            let mut bytes = fs::read(path)?;
            if let Some(last) = bytes.last_mut() {
                *last ^= 0x01;
            }
            fs::write(path, bytes)?;
        }
        HostSpoolIo.open_read(path)
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        HostSpoolIo.read_bounded(file, limit)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        HostSpoolIo.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.remove_file(path)
    }
    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.sync_directory(path)
    }
    fn hard_link(&self, from: &Path, to: &Path) -> io::Result<()> {
        HostSpoolIo.hard_link(from, to)
    }
}

/// (c) A reference that fails verification after the spool classified it intact breaks its root;
/// it never fails the whole open.
#[test]
fn verify_failure_after_classification_breaks_the_root_not_the_open() -> TestResult {
    let root = fresh_root("corrupt_after_classification")?;
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    let c = publisher.stage_object(b"clip-late")?;
    let victim = ObjectManifest::new("event_archive", [c], None)?;
    publisher.publish(&slot("victim")?, &victim)?;
    let target = publisher.spool().object_path(c);
    drop(publisher);

    let io = Arc::new(CorruptOnSecondRead {
        target,
        reads: AtomicU64::new(0),
    });
    let publisher = LocalRootPublisher::open_with_io(&root, limits(), io.clone())?;
    assert_eq!(io.reads.load(Ordering::SeqCst), 2);

    let report = publisher.recovery_report();
    assert!(report.roots.is_empty());
    assert_eq!(
        report.broken_roots,
        vec![BrokenRoot {
            path: Path::new(LOCAL_ROOTS_DIR).join(format!("victim{ROOT_RECORD_SUFFIX}")),
            reason: BrokenRootReason::ReferenceBlocked {
                object: c,
                role: ReferenceRole::Child,
                reason: BlockReason::Corrupt,
            },
        }]
    );
    // The spool classified the object before it changed.
    assert_eq!(report.spool.admitted, by_hex(vec![c, victim.root()]));
    assert!(report.spool.corrupt.is_empty());
    assert_eq!(
        publisher.spool().state(c),
        Some(SpoolObjectState::Corrupt(
            CorruptionKind::ContentDigestMismatch {
                computed: ContentDigest::sha256(b"clip-latd"),
            }
        ))
    );
    Ok(())
}
