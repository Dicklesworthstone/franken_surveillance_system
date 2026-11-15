#![forbid(unsafe_code)]
//! Cold redacted export reads share one immutable owner through final verification.

use super::*;
use fss_reference::agent_orient::OrientLimits;
use fss_reference::ingest::FileIngestError;
use fss_reference::retained_source::{ImmutableRetainedReadLimits, ImmutableRetainedSource};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

fn limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: 64 * 1024 * 1024,
        max_read_objects: 65_536,
    }
}

fn committed(label: &str) -> Test<(Fixture, EventExportPreview)> {
    let mut fixture = Fixture::new(label)?;
    let request = fixture.request();
    let preview = preview_export(&fixture.deployment, &request, &fixture.auth, &fixture.cx)?;
    commit_export(
        &mut fixture.deployment,
        &request,
        preview.approval(),
        &fixture.auth,
        &fixture.cx,
    )?;
    Ok((fixture, preview))
}

fn filesystem(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
    let mut pending = vec![root.to_path_buf()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        if metadata.file_type().is_dir() {
            result.insert(relative, None);
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else if metadata.file_type().is_file() {
            result.insert(relative, Some(fs::read(path)?));
        } else {
            return Err("unexpected fixture file type".into());
        }
    }
    Ok(result)
}

#[test]
fn immutable_export_matches_native_read_with_active_writer_and_unavailable_source_media() -> Test {
    let (fixture, preview) = committed("immutable-parity")?;
    let root = fixture.deployment.root().to_path_buf();
    let cx = ReplayCx::from_context_authority_read_only(&fixture.auth, root.clone())?;
    let expected = read_export(
        &fixture.deployment,
        preview.root(),
        &fixture.auth,
        &fixture.cx,
    )?;
    // The export owns only its redacted record. Unavailable referenced evidence/model payloads
    // cannot require media hydration, and an operational publisher still owns the writer lock.
    for payload in [b"synthetic source assertion".as_slice(), b"model receipt"] {
        fs::write(
            fixture
                .deployment
                .publisher()
                .spool()
                .object_path(ContentDigest::sha256(payload)),
            b"unavailable source payload",
        )?;
    }
    let before = filesystem(&root)?;
    let owner = ImmutableRetainedSource::open(&root, limits(), &cx)?;
    assert_eq!(
        read_export(&owner, preview.root(), &fixture.auth, &cx)?,
        expected
    );
    owner.revalidate()?;
    assert_eq!(filesystem(&root)?, before);
    drop(owner);
    drop(fixture.deployment);
    let before = filesystem(&root)?;
    let owner = ImmutableRetainedSource::open(&root, limits(), &cx)?;
    assert_eq!(
        read_export(&owner, preview.root(), &fixture.auth, &cx)?,
        expected
    );
    owner.revalidate()?;
    assert_eq!(filesystem(&root)?, before);
    Ok(())
}

#[test]
fn export_read_allowance_is_not_renewed_for_final_custody() -> Test {
    let (fixture, preview) = committed("immutable-allowance")?;
    let root = fixture.deployment.root().to_path_buf();
    let cx = ReplayCx::from_context_authority_read_only(&fixture.auth, root.clone())?;
    let before = filesystem(&root)?;
    let owner = ImmutableRetainedSource::open(&root, limits(), &cx)?;
    let expected = read_export(&owner, preview.root(), &fixture.auth, &cx)?;
    let query_usage = owner.usage();
    owner.revalidate()?;
    let complete_usage = owner.usage();
    assert!(complete_usage.read_bytes > query_usage.read_bytes);
    assert!(complete_usage.read_objects > query_usage.read_objects);

    let exact = ImmutableRetainedReadLimits {
        max_read_bytes: usize::try_from(complete_usage.read_bytes)?,
        max_read_objects: usize::try_from(complete_usage.read_objects)?,
        ..limits()
    };
    let owner = ImmutableRetainedSource::open(&root, exact, &cx)?;
    assert_eq!(
        read_export(&owner, preview.root(), &fixture.auth, &cx)?,
        expected
    );
    owner.revalidate()?;
    assert_eq!(owner.usage(), complete_usage);

    let bounded = ImmutableRetainedReadLimits {
        max_read_objects: usize::try_from(query_usage.read_objects)?,
        ..limits()
    };
    let owner = ImmutableRetainedSource::open(&root, bounded, &cx)?;
    assert_eq!(
        read_export(&owner, preview.root(), &fixture.auth, &cx)?,
        expected
    );
    assert!(owner.revalidate().is_err());
    let exhausted = owner.usage();
    assert!(owner.revalidate().is_err());
    assert!(read_export(&owner, preview.root(), &fixture.auth, &cx).is_err());
    assert_eq!(owner.usage(), exhausted);
    assert_eq!(filesystem(&root)?, before);
    Ok(())
}

#[test]
fn late_record_publication_deletion_and_journal_changes_refuse_the_complete_export() -> Test {
    let (fixture, preview) = committed("immutable-late")?;
    let root = fixture.deployment.root().to_path_buf();
    let cx = ReplayCx::from_context_authority_read_only(&fixture.auth, root.clone())?;
    let record = preview.record();
    let owner = ImmutableRetainedSource::open(&root, limits(), &cx)?;
    let objects = owner.history().replay_objects_root().to_path_buf();
    drop(owner);
    let record_path = fixture
        .deployment
        .publisher()
        .spool()
        .object_path(record.digest());
    let pending = objects.join(fss_publication::LOCAL_ROOTS_DIR).join(format!(
        "{}{}{}",
        record.slot()?,
        fss_publication::ROOT_RECORD_SUFFIX,
        fss_publication::ROOT_TEMP_SUFFIX,
    ));
    let deleted = objects
        .join(fss_publication::LOCAL_TOMBSTONES_DIR)
        .join(format!(
            "{}{}",
            record.digest().to_text().replacen(':', "-", 1),
            fss_publication::TOMBSTONE_RECORD_SUFFIX,
        ));
    for path in [
        record_path,
        pending,
        deleted,
        root.join("ledger/journal.fssj"),
        root.join("effects/journal.fssj"),
    ] {
        let original = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let owner = ImmutableRetainedSource::open(&root, limits(), &cx)?;
        let _ = read_export(&owner, preview.root(), &fixture.auth, &cx)?;
        let mut changed = original.clone().unwrap_or_default();
        changed.extend_from_slice(b"uncommitted late change");
        fs::write(&path, changed)?;
        let before = filesystem(&root)?;
        assert!(
            owner.revalidate().is_err(),
            "late change accepted at {path:?}"
        );
        assert_eq!(filesystem(&root)?, before);
        match original {
            Some(bytes) => fs::write(path, bytes)?,
            None => fs::remove_file(path)?,
        }
    }
    Ok(())
}

#[test]
fn cancellation_before_open_or_final_revalidation_revokes_export_reads() -> Test {
    let (fixture, preview) = committed("immutable-cancel")?;
    let root = fixture.deployment.root().to_path_buf();
    let cx = ReplayCx::from_context_authority_read_only(&fixture.auth, root.clone())?;
    let before = filesystem(&root)?;
    let stopped = AtomicBool::new(true);
    let cancelled = || stopped.load(Ordering::SeqCst);
    assert!(matches!(
        ImmutableRetainedSource::open_cancellable(&root, limits(), &cx, &cancelled),
        Err(FileIngestError::CancellationRequested { .. })
    ));
    stopped.store(false, Ordering::SeqCst);
    let owner = ImmutableRetainedSource::open_cancellable(&root, limits(), &cx, &cancelled)?;
    let _ = read_export(&owner, preview.root(), &fixture.auth, &cx)?;
    stopped.store(true, Ordering::SeqCst);
    let usage = owner.usage();
    assert!(matches!(
        owner.revalidate(),
        Err(FileIngestError::CancellationRequested { .. })
    ));
    assert!(matches!(
        read_export(&owner, preview.root(), &fixture.auth, &cx),
        Err(ExportError::Cancelled)
    ));
    assert_eq!(owner.usage(), usage);
    assert_eq!(filesystem(&root)?, before);
    Ok(())
}
