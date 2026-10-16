#![forbid(unsafe_code)]
//! Publisher recovery reuses one fresh spool scan without weakening later publication.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::ContentDigest;
use fss_object::{
    FaultInjectingSpoolIo, ObjectManifest, SPOOL_HOLDS_DIR, SpoolError, SpoolFaultPlan,
    SpoolIoCall, SpoolLimits, SpoolObjectState,
};
use fss_publication::{
    BlockReason, BrokenRootReason, LOCAL_SPOOL_DIR, LocalPublicationError, LocalPublicationLimits,
    LocalPublicationState, LocalRootPublisher, ReferenceRole, SlotName,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(label: &str) -> io::Result<Self> {
        for _ in 0..16 {
            let ordinal = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "fss-root-recovery-{label}-{}-{ordinal}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "isolated fixture directory attempts exhausted",
        ))
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        16,
        16,
        16,
        128,
        SpoolLimits::new(128, 1024 * 1024, 4096, 128),
    )
}

fn seed_one(
    directory: &TempDirectory,
) -> TestResult<(ContentDigest, SlotName, ObjectManifest, PathBuf)> {
    let mut publisher = LocalRootPublisher::open(&directory.0, limits())?;
    let leaf = publisher.stage_object(b"retained original packet")?;
    let slot = SlotName::parse("recording")?;
    let manifest = ObjectManifest::new("recovery-test", [leaf], None)?;
    publisher.publish(&slot, &manifest)?;
    Ok((leaf, slot, manifest, publisher.spool().object_path(leaf)))
}

#[test]
fn shared_transitive_media_is_read_once_during_recovery() -> TestResult {
    let directory = TempDirectory::new("shared-dag")?;
    let depth = 8_u64;
    let (leaf, final_slot, final_root) = {
        let mut publisher = LocalRootPublisher::open(&directory.0, limits())?;
        let leaf = publisher.stage_object(b"one shared original packet")?;
        let mut previous = None;
        let mut last = None;
        for index in 0..depth {
            let mut children = vec![leaf];
            if let Some(parent) = previous {
                children.push(parent);
            }
            let manifest = ObjectManifest::new(format!("recovery-depth-{index}"), children, None)?;
            let slot = SlotName::parse(&format!("depth-{index}"))?;
            publisher.publish(&slot, &manifest)?;
            previous = Some(manifest.root());
            last = Some((slot, manifest.root()));
        }
        let (slot, root) = last.ok_or("missing final root")?;
        (leaf, slot, root)
    };
    let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
    let publisher = LocalRootPublisher::open_with_io(&directory.0, limits(), io.clone())?;
    // One scan of 1 media object + depth manifest objects; then one root record and one
    // manifest-body read per slot. Shared descendants add no further media reads.
    assert_eq!(io.calls(SpoolIoCall::Read), 1 + 3 * depth);
    assert_eq!(publisher.visible_roots().count(), 8);
    assert!(publisher.recovery_report().broken_roots.is_empty());
    let root = publisher.root(&final_slot).ok_or("missing root")?;
    assert_eq!(root.root, final_root);
    assert_eq!(root.state, LocalPublicationState::Durable);
    assert_eq!(
        publisher
            .root_closure(&final_slot)
            .ok_or("missing root")?
            .len(),
        9
    );
    assert_eq!(
        publisher.spool().state(leaf),
        Some(SpoolObjectState::Verified)
    );
    let before = io.calls(SpoolIoCall::Read);
    assert_eq!(publisher.spool().read(leaf)?, b"one shared original packet");
    assert_eq!(io.calls(SpoolIoCall::Read), before + 1);
    Ok(())
}

#[test]
fn corrupt_held_media_blocks_its_root_on_reopen() -> TestResult {
    let directory = TempDirectory::new("corrupt")?;
    let (leaf, slot, _, path) = seed_one(&directory)?;
    let mut encoded = fs::read(&path)?;
    *encoded.last_mut().ok_or("empty fixture envelope")? ^= 1;
    fs::write(path, encoded)?;
    let publisher = LocalRootPublisher::open(&directory.0, limits())?;
    assert!(publisher.root(&slot).is_none());
    assert!(publisher.is_broken_slot(&slot));
    assert!(
        publisher
            .recovery_report()
            .broken_roots
            .iter()
            .any(|entry| matches!(
                &entry.reason,
                BrokenRootReason::ReferenceBlocked {
                    object,
                    role: ReferenceRole::Child,
                    reason: BlockReason::Corrupt,
                } if *object == leaf
            ))
    );
    assert!(matches!(
        publisher.spool().state(leaf),
        Some(SpoolObjectState::Corrupt(_))
    ));
    Ok(())
}

#[test]
fn post_recovery_corruption_cannot_authorize_new_or_idempotent_publication() -> TestResult {
    let directory = TempDirectory::new("publication")?;
    let (leaf, slot, manifest, path) = seed_one(&directory)?;
    let mut publisher = LocalRootPublisher::open(&directory.0, limits())?;
    let mut encoded = fs::read(&path)?;
    *encoded.last_mut().ok_or("empty fixture envelope")? ^= 1;
    fs::write(path, encoded)?;
    let new_slot = SlotName::parse("new-recording")?;
    for target in [&new_slot, &slot] {
        assert!(matches!(
            publisher.publish(target, &manifest),
            Err(LocalPublicationError::ReferenceBlocked {
                object,
                reason: BlockReason::Corrupt,
                ..
            }) if object == leaf
        ));
    }
    assert!(publisher.root(&new_slot).is_none());
    assert!(matches!(
        publisher.spool().read(leaf),
        Err(SpoolError::Corrupt { digest, .. }) if digest == leaf
    ));
    Ok(())
}

#[test]
fn an_unheld_reference_still_crosses_the_verification_and_hold_barrier() -> TestResult {
    let directory = TempDirectory::new("unheld")?;
    let (leaf, slot, _, path) = seed_one(&directory)?;
    // Simulate an intact root referencing an object whose durable hold is missing. The
    // optimized constructor must not turn the initial digest scan alone into Verified.
    let hold = directory
        .0
        .join(LOCAL_SPOOL_DIR)
        .join(SPOOL_HOLDS_DIR)
        .join(path.file_name().ok_or("missing object filename")?);
    fs::remove_file(&hold)?;
    let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
    let publisher = LocalRootPublisher::open_with_io(&directory.0, limits(), io.clone())?;
    // Two spool objects + root record + manifest body + explicit verification of unheld leaf.
    assert_eq!(io.calls(SpoolIoCall::Read), 5);
    assert!(hold.is_file());
    assert_eq!(
        publisher.spool().state(leaf),
        Some(SpoolObjectState::Verified)
    );
    assert_eq!(
        publisher.root(&slot).ok_or("missing root")?.state,
        LocalPublicationState::Durable
    );
    Ok(())
}

#[test]
fn failing_the_root_directory_sync_never_reports_durable() -> TestResult {
    let directory = TempDirectory::new("directory-sync")?;
    let (_, slot, _, _) = seed_one(&directory)?;
    let baseline = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
    {
        let publisher = LocalRootPublisher::open_with_io(&directory.0, limits(), baseline.clone())?;
        assert_eq!(
            publisher.root(&slot).ok_or("missing root")?.state,
            LocalPublicationState::Durable
        );
    }
    let syncs = baseline.calls(SpoolIoCall::SyncDirectory);
    assert!(syncs >= 2);
    // recover ends with roots/ and tombstones/ syncs, in that order.
    let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new().fail(
        SpoolIoCall::SyncDirectory,
        syncs - 1,
        io::ErrorKind::PermissionDenied,
    )));
    let publisher = LocalRootPublisher::open_with_io(&directory.0, limits(), io.clone())?;
    assert!(io.all_fired());
    assert_eq!(
        publisher.root(&slot).ok_or("missing root")?.state,
        LocalPublicationState::Visible
    );
    Ok(())
}
